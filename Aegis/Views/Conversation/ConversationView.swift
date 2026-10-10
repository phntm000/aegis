import SwiftUI

/// The conversation thread: day-separated messages, typing indicator,
/// load-more pagination, and the composer. Owns the nav-bar actions
/// (call, video, info, disappearing timer).
struct ConversationView: View {
    @StateObject private var viewModel: ConversationViewModel
    @EnvironmentObject private var appState: AppState

    @State private var showingInfo = false
    @State private var showingTimerSheet = false
    @State private var showingCallChoice = false
    @State private var showingSafetyNumber = false

    init(conversation: Conversation, contact: Contact?, appState: AppState) {
        _viewModel = StateObject(wrappedValue: ConversationViewModel(
            conversation: conversation, contact: contact, appState: appState
        ))
    }

    var body: some View {
        VStack(spacing: 0) {
            ConnectionBannerView()

            if let contact = viewModel.displayContact,
               contact.verification == .identityChanged {
                IdentityChangedBanner(
                    onVerify: { showingSafetyNumber = true },
                    onDismiss: {
                        // Dismiss is offered only while the change is still
                        // pending (not yet dismissed): after dismissal the
                        // banner stays as a warning without the action.
                        guard let pending = viewModel.pendingIdentityChange,
                              !pending.dismissed
                        else { return nil }
                        return { Task { @MainActor in await viewModel.dismissIdentityChangeWarning() } }
                    }()
                )
                .padding(.top, AegisLayout.s)
            }

            threadContent

            if viewModel.conversation.canSend {
                ComposerView(viewModel: viewModel)
            } else {
                announcementNotice
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle(viewModel.conversation.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                navTitle
            }
            ToolbarItemGroup(placement: .primaryAction) {
                if viewModel.conversation.kind == .direct {
                    Button {
                        showingCallChoice = true
                    } label: {
                        Image(systemName: "phone.fill")
                            .accessibilityLabel("Start a call")
                    }
                }
                Button {
                    showingInfo = true
                } label: {
                    Image(systemName: "info.circle")
                        .accessibilityLabel("Conversation info")
                }
            }
        }
        .confirmationDialog("Start a secure call", isPresented: $showingCallChoice, titleVisibility: .visible) {
            Button("Voice call") {
                if let contact = viewModel.contact {
                    Task { @MainActor in await appState.placeCall(to: contact, kind: .audio) }
                }
            }
            Button("Video call") {
                if let contact = viewModel.contact {
                    Task { @MainActor in await appState.placeCall(to: contact, kind: .video) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Calls are end-to-end encrypted.")
        }
        .sheet(isPresented: $showingInfo) {
            ConversationInfoView(viewModel: viewModel)
        }
        .sheet(isPresented: $showingSafetyNumber) {
            if let contact = viewModel.displayContact {
                SafetyNumberView(
                    contact: contact,
                    appState: appState,
                    pendingIdentityKey: viewModel.pendingIdentityChange?.newIdentityKey,
                    conversationID: viewModel.conversation.id
                )
            }
        }
        .sheet(isPresented: $showingTimerSheet) {
            DisappearingTimerSheet(viewModel: viewModel)
        }
        .onAppear {
            viewModel.onAppear()
        }
        .onDisappear {
            viewModel.onDisappear()
        }
        .onChange(of: showingSafetyNumber) { _, showing in
            // Re-verification or dismissal inside the sheet changes the
            // contact and pending state behind this view's back.
            if !showing {
                Task { @MainActor in await viewModel.refreshIdentityChangeState() }
            }
        }
        .task { @MainActor in
            await viewModel.refreshConversation()
        }
    }

    // MARK: - Nav title

    private var navTitle: some View {
        Button {
            showingInfo = true
        } label: {
            HStack(spacing: AegisLayout.xs) {
                VStack(spacing: 0) {
                    Text(viewModel.conversation.title)
                        .font(AegisType.bodyStrong)
                        .foregroundStyle(AegisColors.textPrimary)
                        .lineLimit(1)
                    if let label = viewModel.conversation.disappearingLabel {
                        Text(label)
                            .font(.system(size: 10))
                            .foregroundStyle(AegisColors.textTertiary)
                    }
                }
                if viewModel.conversation.kind == .direct,
                   let contact = viewModel.contact {
                    VerificationShieldView(state: contact.verification, size: 15)
                }
            }
        }
        .accessibilityLabel("Conversation info for \(viewModel.conversation.title)")
    }

    // MARK: - Thread

    private var threadContent: some View {
        Group {
            if viewModel.isLoading {
                LoadingOverlayView(label: "Loading messages…")
            } else if let error = viewModel.loadError, viewModel.visibleMessages.isEmpty {
                EmptyStateView(
                    icon: "exclamationmark.triangle",
                    title: "Couldn't load messages",
                    message: error,
                    actionTitle: "Retry",
                    action: { Task { @MainActor in await viewModel.load() } }
                )
            } else if viewModel.visibleMessages.isEmpty {
                EmptyStateView(
                    icon: "lock.shield",
                    title: "No messages yet",
                    message: "Messages here are end-to-end encrypted. Say hello."
                )
            } else {
                messageList
            }
        }
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: AegisLayout.s) {
                    if viewModel.isLoadingMore {
                        ProgressView()
                            .tint(AegisColors.accent)
                            .padding(.vertical, AegisLayout.s)
                    } else if !viewModel.visibleMessages.isEmpty {
                        // Invisible sentinel that triggers pagination.
                        Color.clear
                            .frame(height: 1)
                            .onAppear { Task { @MainActor in await viewModel.loadMore() } }
                    }

                    ForEach(Array(viewModel.visibleMessages.enumerated()), id: \.element.id) { index, message in
                        let previous = index > 0 ? viewModel.visibleMessages[index - 1] : nil
                        if shouldShowDayHeader(message, after: previous) {
                            dayHeader(for: message.sentAt)
                        }
                        MessageBubbleView(message: message, viewModel: viewModel)
                            .id(message.id)
                    }

                    if !viewModel.typingNames.isEmpty {
                        HStack {
                            TypingIndicatorView()
                            Text(typingText)
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                            Spacer()
                        }
                        .padding(.horizontal, AegisLayout.l)
                        .transition(.opacity)
                    }
                }
                .padding(.horizontal, AegisLayout.l)
                .padding(.vertical, AegisLayout.s)
            }
            .onChange(of: viewModel.visibleMessages.count) { _, _ in
                scrollToBottom(proxy: proxy, animated: true)
            }
            .onChange(of: viewModel.isLoading) { _, loading in
                if !loading { scrollToBottom(proxy: proxy, animated: false) }
            }
            .onChange(of: viewModel.typingNames) { _, _ in
                scrollToBottom(proxy: proxy, animated: true)
            }
        }
    }

    private func scrollToBottom(proxy: ScrollViewProxy, animated: Bool) {
        guard let last = viewModel.visibleMessages.last else { return }
        if animated {
            withAnimation(.easeOut(duration: 0.25)) {
                proxy.scrollTo(last.id, anchor: .bottom)
            }
        } else {
            proxy.scrollTo(last.id, anchor: .bottom)
        }
    }

    private func shouldShowDayHeader(_ message: Message, after previous: Message?) -> Bool {
        guard let previous else { return true }
        return !Calendar.current.isDate(message.sentAt, inSameDayAs: previous.sentAt)
    }

    private func dayHeader(for date: Date) -> some View {
        Text(dayHeaderText(for: date))
            .font(AegisType.captionStrong)
            .foregroundStyle(AegisColors.textSecondary)
            .padding(.horizontal, AegisLayout.m)
            .padding(.vertical, AegisLayout.xs)
            .background(AegisColors.surfaceElevated)
            .clipShape(Capsule())
            .padding(.vertical, AegisLayout.xs)
    }

    private func dayHeaderText(for date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: date)
    }

    private var typingText: String {
        let names = viewModel.typingNames
        switch names.count {
        case 1: return "\(names[0]) is typing…"
        case 2: return "\(names[0]) and \(names[1]) are typing…"
        default: return "Several people are typing…"
        }
    }

    // MARK: - Announcement-only notice

    private var announcementNotice: some View {
        HStack(spacing: AegisLayout.s) {
            Image(systemName: "megaphone.fill")
                .foregroundStyle(AegisColors.textTertiary)
                .accessibilityHidden(true)
            Text("Only admins can post in this channel.")
                .font(AegisType.footnote)
                .foregroundStyle(AegisColors.textSecondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, AegisLayout.m)
        .background(AegisColors.surfaceElevated)
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let conversation = SampleData.previewConversation(title: "Maya Chen")
    return NavigationStack {
        ConversationView(
            conversation: conversation,
            contact: SampleData.previewContact(name: "Maya Chen"),
            appState: appState
        )
        .environmentObject(appState)
    }
}
