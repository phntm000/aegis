import SwiftUI

/// Per-conversation settings: verification (DMs), disappearing timer, read
/// receipts, typing indicators, mute, and the danger zone. Groups link out
/// to the full GroupDetailView.
struct ConversationInfoView: View {
    @ObservedObject var viewModel: ConversationViewModel
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var showingSafetyNumber = false
    @State private var showingTimerSheet = false
    @State private var showingGroupDetail = false
    @State private var showingDeleteConfirm = false
    @State private var showingLeaveConfirm = false
    @State private var showingBlockConfirm = false

    var body: some View {
        NavigationStack {
            List {
                headerSection
                if viewModel.conversation.kind == .direct {
                    directMessageSection
                } else {
                    groupSection
                }
                privacySection
                dangerSection
            }
            .navigationTitle("Info")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $showingSafetyNumber) {
                if let contact = viewModel.contact {
                    SafetyNumberView(contact: contact, appState: appState)
                }
            }
            .sheet(isPresented: $showingTimerSheet) {
                DisappearingTimerSheet(viewModel: viewModel)
            }
            .navigationDestination(isPresented: $showingGroupDetail) {
                GroupDetailView(conversation: viewModel.conversation, appState: appState)
            }
            .confirmationDialog("Delete this conversation?", isPresented: $showingDeleteConfirm, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    Task { @MainActor in
                        if await viewModel.deleteConversation() { dismiss() }
                    }
                }
            } message: {
                Text("Message history on this device will be removed. This can't be undone.")
            }
            .confirmationDialog(
                "Leave this \(viewModel.conversation.kind == .channel ? "channel" : "group")?",
                isPresented: $showingLeaveConfirm,
                titleVisibility: .visible
            ) {
                Button("Leave and delete history", role: .destructive) {
                    Task { @MainActor in
                        if await viewModel.leaveAndDelete() { dismiss() }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("You'll stop receiving new messages and your local history will be removed.")
            }
            .confirmationDialog("Block this contact?", isPresented: $showingBlockConfirm, titleVisibility: .visible) {
                Button("Block", role: .destructive) {
                    Task { @MainActor in await blockContact(); dismiss() }
                }
            } message: {
                Text("Blocked contacts can't message or call you.")
            }
        }
    }

    // MARK: - Sections

    private var headerSection: some View {
        Section {
            HStack(spacing: AegisLayout.m) {
                Group {
                    if viewModel.conversation.kind == .direct, let contact = viewModel.contact {
                        AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarL)
                    } else {
                        GroupAvatarView(kind: viewModel.conversation.kind, size: AegisLayout.avatarL)
                    }
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(viewModel.conversation.title)
                        .font(AegisType.titleSmall)
                        .foregroundStyle(AegisColors.textPrimary)
                    Text(viewModel.conversation.kindLabel)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                    if let topic = viewModel.conversation.subtitle, !topic.isEmpty {
                        Text(topic)
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textTertiary)
                            .lineLimit(2)
                    }
                }
            }
            .padding(.vertical, AegisLayout.s)
        }
    }

    private var directMessageSection: some View {
        Section("Contact") {
            if let contact = viewModel.contact {
                Button {
                    showingSafetyNumber = true
                } label: {
                    HStack {
                        VerificationShieldView(state: contact.verification)
                        VStack(alignment: .leading) {
                            Text(verificationLabel(for: contact.verification))
                                .font(AegisType.body)
                                .foregroundStyle(AegisColors.textPrimary)
                            Text("Compare safety numbers to confirm identity")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(AegisType.caption)
                            .foregroundStyle(AegisColors.textTertiary)
                    }
                }
                .accessibilityLabel("Verify safety number")

                Button {
                    Task { @MainActor in await appState.placeCall(to: contact, kind: .audio) }
                    dismiss()
                } label: {
                    Label("Voice call", systemImage: "phone.fill")
                }
                Button {
                    Task { @MainActor in await appState.placeCall(to: contact, kind: .video) }
                    dismiss()
                } label: {
                    Label("Video call", systemImage: "video.fill")
                }
            }
        }
    }

    private var groupSection: some View {
        Section("Group") {
            Button {
                showingGroupDetail = true
            } label: {
                HStack {
                    Label("Members & settings", systemImage: "person.2.fill")
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Text("\(viewModel.conversation.memberIDs.count)")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                    Image(systemName: "chevron.right")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                }
            }
            .accessibilityLabel("Open group members and settings")

            HStack {
                Label("Encryption session", systemImage: "lock.fill")
                    .foregroundStyle(AegisColors.textPrimary)
                Spacer()
                Text(viewModel.conversation.senderKeyStatus.displayName)
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textSecondary)
            }
            .accessibilityLabel("Encryption session: \(viewModel.conversation.senderKeyStatus.displayName)")
        }
    }

    private var privacySection: some View {
        Section("Privacy") {
            Button {
                showingTimerSheet = true
            } label: {
                HStack {
                    Label("Disappearing messages", systemImage: "timer")
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Text(viewModel.conversation.disappearingLabel ?? "Off")
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                    Image(systemName: "chevron.right")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textTertiary)
                }
            }
            .accessibilityLabel("Disappearing messages: \(viewModel.conversation.disappearingLabel ?? "off")")

            Toggle(isOn: Binding(
                get: { viewModel.conversation.readReceiptsEnabled },
                set: { Task { @MainActor in await viewModel.setReadReceipts($0) } }
            )) {
                VStack(alignment: .leading) {
                    Text("Read receipts")
                    Text("Let them know when you've read their messages")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
            }

            Toggle(isOn: Binding(
                get: { viewModel.conversation.typingIndicatorsEnabled },
                set: { Task { @MainActor in await viewModel.setTypingIndicators($0) } }
            )) {
                VStack(alignment: .leading) {
                    Text("Typing indicators")
                    Text("Show when you're typing")
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
            }

            Toggle(isOn: Binding(
                get: { viewModel.conversation.isMuted },
                set: { Task { @MainActor in await viewModel.setMuted($0) } }
            )) {
                Text("Mute notifications")
            }
        }
    }

    private var dangerSection: some View {
        Section {
            if viewModel.conversation.kind == .direct {
                Button(role: .destructive) {
                    showingBlockConfirm = true
                } label: {
                    Label("Block contact", systemImage: "slash.circle")
                }
                Button(role: .destructive) {
                    showingDeleteConfirm = true
                } label: {
                    Label("Delete conversation", systemImage: "trash")
                }
            } else {
                Button(role: .destructive) {
                    showingLeaveConfirm = true
                } label: {
                    Label("Leave and delete history", systemImage: "rectangle.portrait.and.arrow.right")
                }
            }
        }
    }

    // MARK: - Helpers

    private func verificationLabel(for state: VerificationState) -> String {
        switch state {
        case .unverified: return "Not verified"
        case .verified: return "Verified"
        case .identityChanged: return "Safety number changed — verify again"
        }
    }

    private func blockContact() async {
        guard let contact = viewModel.contact else { return }
        var updated = contact
        updated.isBlocked = true
        try? await appState.store.saveContact(updated)
        Haptics.notification(.warning)
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
    return ConversationInfoView(viewModel: vm)
        .environmentObject(appState)
        .task { @MainActor in await vm.load() }
}
