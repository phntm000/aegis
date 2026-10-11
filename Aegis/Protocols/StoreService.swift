import Foundation

// MARK: - StoreService
//
// What the app needs from the AegisStore package.
//
// The store persists DECRYPTED models locally (the device is trusted; the
// network is not). AegisStore owns the encryption-at-rest and schema. The app
// only ever passes model structs across this boundary.

struct StorageUsage: Sendable, Hashable {
    let messagesBytes: Int64
    let attachmentsBytes: Int64
    let voiceNotesBytes: Int64

    var totalBytes: Int64 { messagesBytes + attachmentsBytes + voiceNotesBytes }
}

protocol StoreService: Sendable {
    // MARK: Conversations

    func fetchConversations() async throws -> [Conversation]
    func fetchConversation(id: UUID) async throws -> Conversation?
    func saveConversation(_ conversation: Conversation) async throws
    func deleteConversation(id: UUID) async throws

    // MARK: Messages

    /// Newest-first page; `before` pages backwards for infinite scroll.
    func fetchMessages(conversationID: UUID, limit: Int, before: Date?) async throws -> [Message]
    /// Single message by ID (for jump-to-message, tombstone re-reads).
    func fetchMessage(id: UUID, conversationID: UUID) async throws -> Message?
    func saveMessage(_ message: Message) async throws
    func updateMessage(_ message: Message) async throws
    func deleteMessage(id: UUID, conversationID: UUID) async throws
    /// Remove expired disappearing messages. Returns the count purged.
    func purgeExpiredMessages() async throws -> Int
    /// Full-text search across conversations (for the in-app search UI).
    func searchMessages(query: String, limit: Int) async throws -> [Message]
    /// Outgoing messages stuck in `.sending` (deliveryState `.queued`):
    /// the offline outbox. The app flushes these on launch and when
    /// connectivity returns.
    func pendingOutbox() async throws -> [Message]
    /// All replies in a thread, oldest-first.
    func fetchThreadReplies(conversationID: UUID, threadRootID: UUID) async throws -> [Message]
    /// Per-thread stats (thread root ID -> reply count + last activity).
    func fetchThreadSummaries(conversationID: UUID) async throws -> [UUID: ThreadSummary]
    /// Locally starred messages, newest-first. Nil conversation = all chats.
    func fetchStarredMessages(conversationID: UUID?) async throws -> [Message]

    // MARK: Contacts

    func fetchContacts() async throws -> [Contact]
    func saveContact(_ contact: Contact) async throws
    func deleteContact(id: UUID) async throws

    // MARK: Call history

    func fetchCallHistory(limit: Int) async throws -> [CallRecord]
    func saveCallRecord(_ record: CallRecord) async throws
    func clearCallHistory() async throws

    // MARK: Group memberships

    /// The membership table for a group/channel: fingerprint hex → role.
    /// This is the role truth the roster UI renders (not the conversation
    /// snapshot, which only carries our own role).
    func fetchMembershipRoles(conversationID: UUID) async throws -> [String: MemberRole]

    // MARK: Storage management

    func storageUsage() async throws -> StorageUsage
    /// Drop thumbnails and downloaded blob caches; messages stay.
    func clearCaches() async throws

    // MARK: Encrypted backup

    /// Export every persisted row (conversations, messages, contacts,
    /// memberships, attachment metadata, call records) as one encoded
    /// blob. The app hands this to CryptoService.exportEncryptedBackup
    /// together with the crypto half; see docs/INTEGRATION.md for the
    /// assembly contract. Attachment ciphertext files are copied by the
    /// app separately (see AegisStore.Snapshot).
    func exportAll() async throws -> Data
    /// Replace all persisted state from a blob produced by `exportAll`.
    /// The app must have restored attachment ciphertext files first.
    func importAll(_ data: Data) async throws
}
