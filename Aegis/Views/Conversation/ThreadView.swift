import SwiftUI

/// A thread view anchored to a parent message: the parent on top, replies
/// below, and a thread-scoped composer. Has its own read state (marked
/// read on disappear) and full loading / empty / error / offline states.
struct ThreadView: View {
    let parent: Message
    @ObservedObject var viewModel: ConversationViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var replies: [Message] = []
    @State private var isLoading = true
    @State private var loadError: String?
    @State private var draft = ""
    @State private var isSending = false

    private var canSend: Bool { viewModel.canSend }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if !canSend {
                    offlineNotice
                }
                threadContent
                if canSend {
                    Divider()
                    threadComposer
                }
            }
            .background(AegisColors.background.ignoresSafeArea())
            .navigationTitle("Thread")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { await load() }
            .onDisappear {
                viewModel.markThreadRead(parent.id)
            }
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var threadContent: some View {
        if isLoading {
            LoadingOverlayView(label: "Loading thread…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let loadError {
            EmptyStateView(
                icon: "exclamationmark.triangle",
                title: "Couldn't load replies",
                message: loadError,
                actionTitle: "Retry",
                action: { Task { await load() } }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: AegisLayout.s) {
                    parentCard
                    Divider()
                        .padding(.horizontal, AegisLayout.l)
                    if replies.isEmpty {
                        EmptyStateView(
                            icon: "bubble.left.and.bubble.right",
                            title: "No replies yet",
                            message: "Be the first to reply in this thread."
                        )
                        .padding(.vertical, AegisLayout.xl)
                    } else {
                        ForEach(replies) { reply in
                            MessageBubbleView(message: reply, viewModel: viewModel)
                        }
                    }
                }
                .padding(.horizontal, AegisLayout.l)
                .padding(.vertical, AegisLayout.s)
            }
        }
    }

    private var parentCard: some View {
        VStack(alignment: .leading, spacing: AegisLayout.xs) {
            Label("Original message", systemImage: "arrowshape.turn.up.left")
                .font(AegisType.captionStrong)
                .foregroundStyle(AegisColors.accent)
                .accessibilityLabel("Thread parent message")
            MessageBubbleView(message: parent, viewModel: viewModel)
        }
    }

    private var offlineNotice: some View {
        HStack(spacing: AegisLayout.s) {
            Image(systemName: "wifi.slash")
                .accessibilityHidden(true)
            Text("You're offline — replies will send when you reconnect.")
                .font(AegisType.caption)
        }
        .foregroundStyle(AegisColors.textSecondary)
        .frame(maxWidth: .infinity)
        .padding(.vertical, AegisLayout.s)
        .background(AegisColors.surfaceElevated)
        .accessibilityLabel("Offline. Replies will send when you reconnect.")
    }

    // MARK: - Composer

    private var threadComposer: some View {
        HStack(alignment: .bottom, spacing: AegisLayout.s) {
            TextField("Reply in thread…", text: $draft, axis: .vertical)
                .font(AegisType.body)
                .lineLimit(1...4)
                .disabled(isSending)
                .accessibilityLabel("Thread reply field")
            Button {
                send()
            } label: {
                if isSending {
                    ProgressView()
                        .tint(AegisColors.accent)
                } else {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 30))
                        .foregroundStyle(sendEnabled ? AegisColors.accent : AegisColors.textTertiary)
                }
            }
            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
            .disabled(!sendEnabled)
            .accessibilityLabel("Send thread reply")
        }
        .padding(.horizontal, AegisLayout.s)
        .padding(.vertical, AegisLayout.xs)
        .background(AegisColors.surfaceElevated)
    }

    private var sendEnabled: Bool {
        !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && canSend && !isSending
    }

    // MARK: - Loading

    private func load() async {
        isLoading = true
        loadError = nil
        defer { isLoading = false }
        // Cached replies load offline; only sending needs connectivity.
        replies = await viewModel.threadReplies(for: parent.id)
        // A thread read failure surfaces as an error only when we got
        // nothing and the parent claims replies exist.
        if replies.isEmpty, let summary = viewModel.threadSummaries[parent.id], summary.replyCount > 0 {
            loadError = "Replies couldn't be loaded. Check your connection and try again."
        }
    }

    private func send() {
        guard sendEnabled else { return }
        let text = draft
        draft = ""
        isSending = true
        Task { @MainActor in
            await viewModel.sendThreadReply(to: parent.id, body: text)
            isSending = false
            await load()
            await viewModel.refreshThreadSummaries()
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    let conversation = SampleData.previewConversation(title: "Maya Chen")
    let vm = ConversationViewModel(
        conversation: conversation,
        contact: SampleData.previewContact(name: "Maya Chen"),
        appState: appState
    )
    let parent = SampleData.previewMessages(for: "Maya Chen").first!
    return ThreadView(parent: parent, viewModel: vm)
        .environmentObject(appState)
}
