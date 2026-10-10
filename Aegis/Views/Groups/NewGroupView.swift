import SwiftUI

/// Create a group: name + member picker from contacts. Creates the sender-key
/// session via the transport, then opens the new conversation.
struct NewGroupView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    var onCreated: (Conversation) -> Void

    @State private var name = ""
    @State private var selectedIDs: Set<UUID> = []
    @State private var contacts: [Contact] = []
    @State private var isLoading = true
    @State private var isCreating = false
    @State private var error: String?
    @FocusState private var nameFocused: Bool

    var body: some View {
        NavigationStack {
            Group {
                if isLoading {
                    LoadingOverlayView(label: "Loading contacts…")
                } else if contacts.isEmpty {
                    EmptyStateView(
                        icon: "person.2",
                        title: "No contacts yet",
                        message: "Add contacts first — groups are built from people you've explicitly added.",
                        actionTitle: "Done",
                        action: { dismiss() }
                    )
                } else {
                    form
                }
            }
            .navigationTitle("New group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") { Task { @MainActor in await create() } }
                        .disabled(!canCreate || isCreating)
                }
            }
            .task { @MainActor in await load() }
        }
        .presentationDetents([.medium, .large])
    }

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !selectedIDs.isEmpty
    }

    private var form: some View {
        List {
            Section("Group name") {
                TextField("e.g. Design sync", text: $name)
                    .focused($nameFocused)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Group name")
            }

            Section("Members (\(selectedIDs.count) selected)") {
                ForEach(contacts) { contact in
                    Button {
                        if selectedIDs.contains(contact.id) {
                            selectedIDs.remove(contact.id)
                        } else {
                            selectedIDs.insert(contact.id)
                        }
                        Haptics.selection()
                    } label: {
                        HStack {
                            AvatarView(displayName: contact.displayName, hue: contact.avatarHue, size: AegisLayout.avatarS)
                            Text(contact.displayName)
                                .font(AegisType.body)
                                .foregroundStyle(AegisColors.textPrimary)
                            Spacer()
                            if selectedIDs.contains(contact.id) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(AegisColors.accent)
                                    .accessibilityLabel("Selected")
                            }
                        }
                    }
                    .accessibilityLabel("\(contact.displayName), \(selectedIDs.contains(contact.id) ? "selected" : "not selected")")
                }
            }

            if let error {
                Section {
                    ErrorBannerView(message: error, onDismiss: { self.error = nil })
                }
            }
        }
    }

    private func load() async {
        defer { isLoading = false }
        contacts = (try? await appState.store.fetchContacts())?.filter { !$0.isBlocked } ?? []
    }

    private func create() async {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !selectedIDs.isEmpty else { return }
        isCreating = true
        defer { isCreating = false }
        do {
            let contacts = try await appState.store.fetchContacts()
            let keys = selectedIDs.compactMap { id in contacts.first(where: { $0.id == id })?.identityKey }
            let groupID = try await appState.transport.createGroup(name: trimmed, memberKeys: keys)
            var memberIDs = Array(selectedIDs)
            if let me = appState.identity { memberIDs.append(me.id) }
            let conversation = Conversation(
                id: groupID,
                kind: .group,
                title: trimmed,
                memberIDs: memberIDs,
                myRole: .owner,
                lastMessageAt: Date()
            )
            try await appState.store.saveConversation(conversation)
            Haptics.notification(.success)
            dismiss()
            onCreated(conversation)
        } catch {
            self.error = error.localizedDescription
            Haptics.notification(.error)
        }
    }
}

#Preview {
    let appState = AppState(factory: PreviewServiceFactory())
    NewGroupView(appState: appState) { _ in }
        .environmentObject(appState)
}
