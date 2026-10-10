import SwiftUI

/// Group / channel detail: roster with roles, invite, topic, announcement
/// mode, sender-key session health, and leave. Moderation controls appear only
/// for owners/admins and are all wired to the transport.
struct GroupDetailView: View {
    @StateObject private var viewModel: GroupDetailViewModel
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var showingInvite = false
    @State private var showingTopicEditor = false
    @State private var showingLeaveConfirm = false
    @State private var memberForActions: GroupMember?

    init(conversation: Conversation, appState: AppState) {
        _viewModel = StateObject(wrappedValue: GroupDetailViewModel(conversation: conversation, appState: appState))
    }

    var body: some View {
        Group {
            if viewModel.isLoading {
                LoadingOverlayView(label: "Loading group…")
            } else if let info = viewModel.info {
                groupContent(info)
            } else {
                EmptyStateView(
                    icon: "exclamationmark.triangle",
                    title: "Couldn't load group",
                    message: viewModel.error ?? "Something went wrong.",
                    actionTitle: "Retry",
                    action: { Task { @MainActor in await viewModel.load() } }
                )
            }
        }
        .background(AegisColors.background.ignoresSafeArea())
        .navigationTitle(viewModel.isChannel ? "Channel info" : "Group info")
        .navigationBarTitleDisplayMode(.inline)
        .task { @MainActor in await viewModel.load() }
        .onDisappear { viewModel.stop() }
        .sheet(isPresented: $showingInvite) {
            if let code = viewModel.info?.inviteCode {
                InviteSheetView(inviteCode: code, groupName: viewModel.conversation.title)
            }
        }
        .sheet(isPresented: $showingTopicEditor) {
            TopicEditorSheet(current: viewModel.info?.description) { newTopic in
                Task { @MainActor in await viewModel.setTopic(newTopic) }
            }
        }
        .confirmationDialog(
            memberActionTitle,
            isPresented: Binding(
                get: { memberForActions != nil },
                set: { if !$0 { memberForActions = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let member = memberForActions {
                if member.role != .admin {
                    Button("Make admin") {
                        Task { @MainActor in await viewModel.setRole(member, role: .admin) }
                    }
                }
                if member.role != .member {
                    Button("Make member") {
                        Task { @MainActor in await viewModel.setRole(member, role: .member) }
                    }
                }
                Button("Remove from group", role: .destructive) {
                    Task { @MainActor in await viewModel.removeMember(member) }
                }
                Button("Cancel", role: .cancel) {}
            }
        }
        .confirmationDialog("Leave this \(viewModel.isChannel ? "channel" : "group")?",
                            isPresented: $showingLeaveConfirm, titleVisibility: .visible) {
            Button("Leave", role: .destructive) {
                Task { @MainActor in
                    if await viewModel.leave() { dismiss() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll stop receiving new messages. Your history on this device is removed.")
        }
    }

    private var memberActionTitle: String {
        memberForActions.map { "Manage \($0.displayName)" } ?? ""
    }

    // MARK: - Content

    private func groupContent(_ info: GroupInfo) -> some View {
        List {
            headerSection(info)

            if viewModel.canModerate {
                Section {
                    Button {
                        Task { @MainActor in await viewModel.generateInvite() }
                        showingInvite = true
                    } label: {
                        Label("Invite via QR or link", systemImage: "qrcode")
                    }
                    .disabled(viewModel.isWorking)
                }

                if !viewModel.joinRequests.isEmpty {
                    Section("Join requests (\(viewModel.joinRequests.count))") {
                        ForEach(viewModel.joinRequests) { request in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(request.requesterName)
                                        .font(AegisType.body)
                                        .foregroundStyle(AegisColors.textPrimary)
                                    Text("Wants to join this \(viewModel.isChannel ? "channel" : "group")")
                                        .font(AegisType.caption)
                                        .foregroundStyle(AegisColors.textSecondary)
                                }
                                Spacer()
                                Button("Decline") {
                                    viewModel.declineJoinRequest(request)
                                }
                                .buttonStyle(.bordered)
                                .tint(AegisColors.textSecondary)
                                Button("Approve") {
                                    Task { @MainActor in await viewModel.approveJoinRequest(request) }
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(AegisColors.accent)
                                .disabled(viewModel.isWorking)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
            }

            Section("Members (\(info.memberCount))") {
                ForEach(info.members) { member in
                    MemberRowView(member: member, isSelf: isSelf(member))
                        .contentShape(Rectangle())
                        .onTapGesture {
                            guard viewModel.canModerate, !isSelf(member) else { return }
                            memberForActions = member
                            Haptics.selection()
                        }
                        .accessibilityLabel("\(member.displayName), \(member.role.displayName)")
                }
            }

            if viewModel.isChannel {
                Section("Channel") {
                    Toggle(isOn: Binding(
                        get: { viewModel.conversation.isAnnouncementOnly },
                        set: { newValue in Task { @MainActor in await viewModel.setAnnouncementOnly(newValue) } }
                    )) {
                        VStack(alignment: .leading) {
                            Text("Announcement-only")
                            Text("Only owners and admins can post")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                        }
                    }
                    .disabled(!viewModel.canModerate)
                }
            }

            Section {
                HStack {
                    Label("Sender-key session", systemImage: "lock.fill")
                        .foregroundStyle(AegisColors.textPrimary)
                    Spacer()
                    Text(info.senderKeyStatus.displayName)
                        .font(AegisType.caption)
                        .foregroundStyle(AegisColors.textSecondary)
                }
                Button {
                    Task { @MainActor in await viewModel.rotateSenderKey() }
                } label: {
                    Label("Rotate encryption key", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(viewModel.isWorking)
                .accessibilityHint("Starts a fresh sender-key session for this group")
            } header: {
                Text("Encryption")
            } footer: {
                Text("Group messages use sender keys so large groups stay fast. Rotate if you suspect a member's device was compromised.")
            }

            Section {
                Button(role: .destructive) {
                    showingLeaveConfirm = true
                } label: {
                    Label("Leave \(viewModel.isChannel ? "channel" : "group")",
                          systemImage: "rectangle.portrait.and.arrow.right")
                }
            }
        }
    }

    private func headerSection(_ info: GroupInfo) -> some View {
        Section {
            HStack(spacing: AegisLayout.m) {
                GroupAvatarView(
                    kind: viewModel.isChannel ? .channel : .group,
                    size: AegisLayout.avatarL
                )
                VStack(alignment: .leading, spacing: 4) {
                    Text(viewModel.conversation.title)
                        .font(AegisType.titleSmall)
                        .foregroundStyle(AegisColors.textPrimary)
                    if let description = info.description, !description.isEmpty {
                        Text(description)
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textSecondary)
                            .lineLimit(3)
                    } else if viewModel.canModerate {
                        Text("Add a description")
                            .font(AegisType.callout)
                            .foregroundStyle(AegisColors.textTertiary)
                    }
                }
                Spacer()
                if viewModel.canModerate {
                    Button {
                        showingTopicEditor = true
                    } label: {
                        Image(systemName: "pencil")
                            .foregroundStyle(AegisColors.accent)
                            .frame(minWidth: AegisLayout.minTapTarget, minHeight: AegisLayout.minTapTarget)
                    }
                    .accessibilityLabel("Edit description")
                }
            }
            .padding(.vertical, AegisLayout.s)
        }
    }

    private func isSelf(_ member: GroupMember) -> Bool {
        member.id == appState.identity?.id
    }
}

/// One roster row: avatar, name, role badge.
struct MemberRowView: View {
    let member: GroupMember
    var isSelf: Bool = false

    var body: some View {
        HStack(spacing: AegisLayout.m) {
            AvatarView(displayName: member.displayName, size: AegisLayout.avatarS)
            Text(member.displayName)
                .font(AegisType.body)
                .foregroundStyle(AegisColors.textPrimary)
                .lineLimit(1)
            if isSelf {
                Text("(you)")
                    .font(AegisType.caption)
                    .foregroundStyle(AegisColors.textTertiary)
            }
            Spacer()
            if member.role != .member {
                Text(member.role.displayName)
                    .font(AegisType.captionStrong)
                    .foregroundStyle(AegisColors.accent)
                    .padding(.horizontal, AegisLayout.s)
                    .padding(.vertical, 3)
                    .background(AegisColors.accentSoft)
                    .clipShape(Capsule())
                    .accessibilityLabel("Role: \(member.role.displayName)")
            }
        }
        .padding(.vertical, AegisLayout.xs)
    }
}

/// Small sheet for editing the group/channel description.
private struct TopicEditorSheet: View {
    let current: String?
    var onSave: (String?) -> Void

    @State private var text: String
    @Environment(\.dismiss) private var dismiss

    init(current: String?, onSave: @escaping (String?) -> Void) {
        self.current = current
        self.onSave = onSave
        _text = State(initialValue: current ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Description", text: $text, axis: .vertical)
                        .lineLimit(3...6)
                } header: {
                    EmptyView()
                } footer: {
                    Text("Shown to members at the top of the info screen.")
                }
            }
            .navigationTitle("Description")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(text.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty)
                        dismiss()
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    return NavigationStack {
        GroupDetailView(
            conversation: SampleData.previewConversation(title: "Design sync"),
            appState: appState
        )
        .environmentObject(appState)
    }
}
