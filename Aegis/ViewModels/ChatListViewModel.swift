import Foundation

/// The chat list: pinned / recents / archived, search, and swipe actions.
/// Every row action (pin, mute, archive, delete) is wired to the store.
@MainActor
final class ChatListViewModel: ObservableObject {
    @Published private(set) var conversations: [Conversation] = []
    @Published private(set) var contactsByID: [UUID: Contact] = [:]
    @Published var searchText = ""
    @Published private(set) var isLoading = true
    @Published var error: String?
    @Published var showingArchived = false

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    // MARK: - Derived lists

    private var visible: [Conversation] {
        conversations.filter { !$0.isArchived }
    }

    var pinned: [Conversation] {
        filtered(visible.filter { $0.isPinned })
    }

    var recents: [Conversation] {
        filtered(visible.filter { !$0.isPinned })
    }

    var archived: [Conversation] {
        filtered(conversations.filter { $0.isArchived })
    }

    var totalUnread: Int {
        conversations.reduce(0) { $0 + $1.unreadCount }
    }

    var isEmpty: Bool {
        conversations.isEmpty
    }

    private func filtered(_ list: [Conversation]) -> [Conversation] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let sorted = list.sorted { ($0.lastMessageAt ?? .distantPast) > ($1.lastMessageAt ?? .distantPast) }
        guard !query.isEmpty else { return sorted }
        return sorted.filter {
            $0.title.lowercased().contains(query)
                || ($0.lastMessagePreview?.lowercased().contains(query) ?? false)
        }
    }

    // MARK: - Loading

    func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        do {
            async let conversationsTask = appState.store.fetchConversations()
            async let contactsTask = appState.store.fetchContacts()
            let (fetchedConversations, fetchedContacts) = try await (conversationsTask, contactsTask)
            conversations = fetchedConversations
            contactsByID = Dictionary(uniqueKeysWithValues: fetchedContacts.map { ($0.id, $0) })
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// The 1:1 contact for a DM conversation, if known.
    func contact(for conversation: Conversation) -> Contact? {
        guard conversation.kind == .direct,
              let memberID = conversation.memberIDs.first else { return nil }
        return contactsByID[memberID]
    }

    // MARK: - Row actions

    func togglePin(_ conversation: Conversation) async {
        await update(conversation) { $0.isPinned.toggle() }
        Haptics.selection()
    }

    func toggleMute(_ conversation: Conversation) async {
        await update(conversation) { $0.isMuted.toggle() }
        Haptics.selection()
    }

    func toggleArchive(_ conversation: Conversation) async {
        await update(conversation) {
            $0.isArchived.toggle()
            if $0.isArchived { $0.unreadCount = 0 }
        }
        Haptics.impact(.medium)
    }

    func markAsRead(_ conversation: Conversation) async {
        guard conversation.unreadCount > 0 else { return }
        await update(conversation) { $0.unreadCount = 0 }
    }

    func delete(_ conversation: Conversation) async {
        do {
            try await appState.store.deleteConversation(id: conversation.id)
            conversations.removeAll { $0.id == conversation.id }
            Haptics.notification(.warning)
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func update(_ conversation: Conversation, apply: (inout Conversation) -> Void) async {
        var updated = conversation
        apply(&updated)
        do {
            try await appState.store.saveConversation(updated)
            if let idx = conversations.firstIndex(where: { $0.id == updated.id }) {
                conversations[idx] = updated
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}
