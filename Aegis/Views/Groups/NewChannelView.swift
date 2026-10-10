import SwiftUI

/// Create a channel: name, topic, and announcement-only mode. Channels are
/// for broadcasts — the audience listens, admins post.
struct NewChannelView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    var onCreated: (Conversation) -> Void

    @State private var name = ""
    @State private var topic = ""
    @State private var announcementOnly = true
    @State private var isCreating = false
    @State private var error: String?
    @FocusState private var nameFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section("Channel") {
                    TextField("Channel name", text: $name)
                        .focused($nameFocused)
                        .autocorrectionDisabled()
                        .accessibilityLabel("Channel name")
                    TextField("Topic (optional)", text: $topic, axis: .vertical)
                        .lineLimit(2...4)
                        .accessibilityLabel("Channel topic")
                }

                Section {
                    Toggle(isOn: $announcementOnly) {
                        VStack(alignment: .leading) {
                            Text("Announcement-only")
                            Text("Only owners and admins can post")
                                .font(AegisType.caption)
                                .foregroundStyle(AegisColors.textSecondary)
                        }
                    }
                } footer: {
                    Text("Turn this off to make a discussion channel where every member can post.")
                }

                if let error {
                    Section {
                        ErrorBannerView(message: error, onDismiss: { self.error = nil })
                    }
                }
            }
            .navigationTitle("New channel")
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
        }
        .presentationDetents([.medium, .large])
    }

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func create() async {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedTopic = topic.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { return }
        isCreating = true
        defer { isCreating = false }
        do {
            let channelID = try await appState.transport.createChannel(
                name: trimmedName,
                topic: trimmedTopic.isEmpty ? nil : trimmedTopic,
                announcementOnly: announcementOnly
            )
            var memberIDs: [UUID] = []
            if let me = appState.identity { memberIDs.append(me.id) }
            let conversation = Conversation(
                id: channelID,
                kind: .channel,
                title: trimmedName,
                subtitle: trimmedTopic.isEmpty ? nil : trimmedTopic,
                memberIDs: memberIDs,
                isAnnouncementOnly: announcementOnly,
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
    NewChannelView { _ in }
        .environmentObject(appState)
}
