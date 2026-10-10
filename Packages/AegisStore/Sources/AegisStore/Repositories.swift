// AegisStore — Repository Protocols
//
// The app codes against these protocols, never against a concrete store.
// This keeps the UI testable (inject `InMemoryAegisStore`) and lets the
// production SQLCipher adapter be swapped in without touching app code.
//
// All operations are async and throwing. Implementations must be thread-safe
// (the SQLCipher adapter serializes on a dedicated queue; the in-memory
// implementation is an actor).
//
// Error semantics: every method throws `AegisStoreError`. Callers should
// treat `.notFound` as a normal control-flow signal (e.g. "no draft") and
// everything else as a genuine failure to surface.

import Foundation

// MARK: - Errors

public enum AegisStoreError: Error, Sendable, Equatable {
    /// The requested row does not exist.
    case notFound(String)
    /// Insert violates a uniqueness invariant (e.g. duplicate message ID).
    case conflict(String)
    /// The arguments are invalid (empty text with no attachments, etc.).
    case invalidArgument(String)
    /// The encrypted store could not be opened (wrong key, corrupted file).
    /// The app must fail closed: do not fall back to plaintext storage.
    case encryptionUnavailable(String)
    /// A schema migration failed. The store is left untouched.
    case migrationFailed(String)
    /// Underlying I/O failure.
    case ioError(String)
}

// MARK: - Conversations

public protocol ConversationRepository: Sendable {
    func create(_ conversation: Conversation) async throws
    func fetch(id: ConversationID) async throws -> Conversation?
    /// Lists conversations for the main chat list.
    /// - Parameters:
    ///   - includeArchived: include archived chats.
    ///   - kind: filter by kind, nil = all.
    ///   - query: optional substring filter over title (NOT full-text; use
    ///     MessageRepository.search for content search).
    func list(
        includeArchived: Bool,
        kind: ConversationKind?,
        query: String?
    ) async throws -> [Conversation]
    func update(_ conversation: Conversation) async throws
    /// Hard-deletes a conversation and cascades to its messages, attachments
    /// (including ciphertext chunks + keychain keys), memberships, and call
    /// records. Prefer per-message tombstones (MessageRepository) for
    /// user-visible deletion; this is for "delete entire chat."
    func delete(id: ConversationID) async throws
    func setDisappearingTimer(id: ConversationID, seconds: Int?) async throws
    func setNetworkPolicy(id: ConversationID, policy: NetworkPolicy) async throws
    /// Marks a conversation read up to a message, adjusting unreadCount.
    func markRead(id: ConversationID, upTo messageID: MessageID) async throws
}

// MARK: - Messages

public struct MessagePage: Sendable, Equatable {
    public var messages: [Message] // newest-first
    public var hasMore: Bool
    public init(messages: [Message], hasMore: Bool) {
        self.messages = messages
        self.hasMore = hasMore
    }
}

public protocol MessageRepository: Sendable {
    /// Inserts a message. Duplicate IDs are a `.conflict` (idempotent
    /// redelivery must be deduped by the caller via `exists` first).
    func insert(_ message: Message) async throws
    func exists(id: MessageID) async throws -> Bool
    func fetch(id: MessageID) async throws -> Message?
    /// Newest-first page. `before`: paginate messages older than this ID.
    func list(
        in conversationID: ConversationID,
        limit: Int,
        before: MessageID?
    ) async throws -> MessagePage
    func update(_ message: Message) async throws
    /// Applies a signed tombstone: wipes content fields, sets
    /// `isTombstone`, preserves position. Attachment ciphertext is deleted
    /// and keychain keys destroyed.
    func applyTombstone(id: MessageID, at: Date) async throws
    /// Full-text search over message text + voice-note transcriptions.
    /// Production: FTS5 MATCH inside the encrypted DB. Excludes tombstones
    /// and expired messages.
    func search(
        query: String,
        in conversationID: ConversationID?,
        limit: Int
    ) async throws -> [Message]
    /// Cryptographically wipes messages whose `disappearAt <= now`
    /// (content, attachments, chunks, keys). Returns the count wiped.
    /// Called on unlock, on timer, and after sync.
    func expungeDisappeared(now: Date) async throws -> Int
    /// Outbox: outgoing messages with `deliveryState == .queued`, plus
    /// messages whose `scheduledFor` fire time has arrived. Ordered oldest-first.
    func pendingOutbox(now: Date) async throws -> [Message]
    /// Marks delivery-state transitions. Invalid transitions
    /// (e.g. `.read` -> `.queued`) throw `.invalidArgument`.
    func setDeliveryState(id: MessageID, state: DeliveryState) async throws
    /// Adds/removes the local user's reaction. Reactions from other users
    /// arrive as events and are applied via `update`.
    func setReaction(id: MessageID, emoji: String?, userID: UserID) async throws
}

// MARK: - Contacts

public protocol ContactRepository: Sendable {
    func upsert(_ contact: Contact) async throws
    func fetch(id: UserID) async throws -> Contact?
    func list(includeBlocked: Bool) async throws -> [Contact]
    func delete(id: UserID) async throws
    /// Records a verification ceremony result. Moving from `.verified` to
    /// `.changedNeedsReverification` must also be exposed to the UI layer
    /// so it can pause sealed-sender and warn (enforced by caller).
    func setVerificationState(id: UserID, state: VerificationState) async throws
    func setBlocked(id: UserID, blocked: Bool) async throws
}

// MARK: - Group membership

public protocol GroupMembershipRepository: Sendable {
    func upsert(_ membership: GroupMembership) async throws
    func remove(conversationID: ConversationID, userID: UserID) async throws
    func members(of conversationID: ConversationID) async throws -> [GroupMembership]
    func role(of userID: UserID, in conversationID: ConversationID) async throws -> MemberRole?
    func setRole(
        conversationID: ConversationID,
        userID: UserID,
        role: MemberRole
    ) async throws
    /// All conversation IDs a user belongs to (for key-rotation fan-out).
    func conversations(containing userID: UserID) async throws -> [ConversationID]
}

// MARK: - Attachments

public protocol AttachmentRepository: Sendable {
    func insert(_ attachment: Attachment) async throws
    func fetch(id: AttachmentID) async throws -> Attachment?
    func list(for messageID: MessageID) async throws -> [Attachment]
    func update(_ attachment: Attachment) async throws
    func setTransferState(id: AttachmentID, state: TransferState) async throws
    /// Advances byte progress; clamps to byteCount; flips to `.complete`
    /// when the count is reached.
    func recordProgress(id: AttachmentID, bytesTransferred: Int64) async throws
    /// Deletes metadata + local ciphertext chunks. The caller destroys the
    /// Keychain key via `keychainKeyID` first (keys never live in the DB).
    func delete(id: AttachmentID) async throws
}

// MARK: - Call records

public protocol CallRecordRepository: Sendable {
    func insert(_ record: CallRecord) async throws
    func fetch(id: CallID) async throws -> CallRecord?
    /// Newest-first call history for a conversation.
    func list(in conversationID: ConversationID, limit: Int) async throws -> [CallRecord]
    func update(_ record: CallRecord) async throws
    func delete(id: CallID) async throws
    /// Records one participant's signed consent acknowledgment.
    func setRecordingConsent(callID: CallID, userID: UserID, consented: Bool) async throws
}

// MARK: - Ratchet sessions

/// Durable Double Ratchet session state, keyed by peer fingerprint hex.
///
/// The stored blob is an opaque versioned snapshot produced by
/// `AegisCrypto.RatchetSessionSnapshot.serialized()` — this repository
/// never inspects it, only stores and returns it. Snapshots hold current
/// chain/root keys (never past message keys); they are stored inside the
/// SQLCipher database, so their at-rest protection equals the messages'.
/// They are deliberately EXCLUDED from the encrypted-backup `StoreSnapshot`:
/// a backup restored to a new device re-establishes sessions via X3DH
/// rather than resurrecting stale session state.
public protocol SessionRepository: Sendable {
    /// Upserts the session snapshot for a peer fingerprint (hex).
    func save(fingerprint: String, snapshot: Data) async throws
    /// Returns the snapshot for a peer, or nil when there is none.
    func load(fingerprint: String) async throws -> Data?
    /// Returns all stored sessions keyed by peer fingerprint hex.
    func loadAll() async throws -> [String: Data]
    func delete(fingerprint: String) async throws
    func deleteAll() async throws
}

/// Durable `GroupSession` snapshots, keyed by groupID hex. Same security
/// posture as `SessionRepository`: current chain keys only, SQLCipher
/// at-rest encryption, excluded from encrypted backups (a restored backup
/// re-joins groups with fresh sender keys).
public protocol GroupSessionRepository: Sendable {
    /// Upserts the snapshot for a group (groupID hex).
    func save(groupID: String, snapshot: Data) async throws
    /// Returns all stored group sessions keyed by groupID hex.
    func loadAll() async throws -> [String: Data]
    func delete(groupID: String) async throws
    func deleteAll() async throws
}

/// Attachment decryption contexts: wrapped-key SHA-256 hex → the
/// conversation context (`unwrapFileKey` needs to know whether the key was
/// wrapped for a group or a 1:1 session). Persisted so inbound attachments
/// remain decryptable after an app restart.
public protocol AttachmentContextRepository: Sendable {
    /// Upserts the context. `groupID` is set for group attachments,
    /// `peer` (fingerprint) for 1:1 attachments; exactly one is non-nil.
    func save(keyHash: String, groupID: Data?, peer: Data?) async throws
    /// Returns the stored context, or nil when unknown.
    func load(keyHash: String) async throws -> (groupID: Data?, peer: Data?)?
    func deleteAll() async throws
}

// MARK: - Composite store

/// The single entry point the app holds. Backed in production by the
/// SQLCipher adapter, in tests/previews by `InMemoryAegisStore`.
public protocol AegisDatabase: Sendable {
    var conversations: any ConversationRepository { get }
    var messages: any MessageRepository { get }
    var contacts: any ContactRepository { get }
    var memberships: any GroupMembershipRepository { get }
    var attachments: any AttachmentRepository { get }
    var calls: any CallRecordRepository { get }
    var sessions: any SessionRepository { get }
    var groupSessions: any GroupSessionRepository { get }
    var attachmentContexts: any AttachmentContextRepository { get }

    /// Runs `work` inside a single transaction. Nested transactions are
    /// flattened (savepoints in SQLCipher; re-entrant lock in memory).
    func transaction<T: Sendable>(
        _ work: @Sendable () async throws -> T
    ) async throws -> T

    /// Captures every persisted row for encrypted backup. Attachment
    /// *ciphertext files* are not included — see Snapshot.swift for the
    /// backup assembly contract.
    func snapshot() async throws -> StoreSnapshot

    /// Replaces all persisted state with `snapshot`. The caller must have
    /// already restored attachment ciphertext blobs; keys are re-derived
    /// from the messages' wrapped keys, never stored here.
    /// - Throws: `.invalidArgument` when `snapshot.version` is newer than
    ///   `StoreSnapshot.currentVersion`.
    func restore(_ snapshot: StoreSnapshot) async throws
}

// MARK: - SQLCipher adapter contract

/// Describes how the production SQLCipher-backed store is constructed.
/// The concrete adapter is `SQLCipherAegisStore`, implemented in this
/// package (vendored SQLCipher amalgamation as the `CSQLCipher` C target —
/// see Docs/SQLCIPHER.md §1 for the rationale), and injected wherever an
/// `AegisDatabase` is required. `InMemoryAegisStore` remains for tests and
/// previews.
///
/// Required integration steps (normative):
/// 1. The `CSQLCipher` target compiles the SQLCipher amalgamation with
///    `SQLITE_HAS_CODEC` + `SQLCIPHER_CRYPTO_CC` (CommonCrypto).
/// 2. `SQLCipherAegisStore` implements `AegisDatabase` + the six repository
///    protocols, serializing all access on its actor isolation (one sqlite
///    handle, single logical thread — the documented-safe model).
/// 3. Key management exactly per Docs/SQLCIPHER.md §2: random 256-bit DB key,
///    held in the Keychain, `PRAGMA key` on open, zeroed after use.
/// 4. Schema + migrations exactly per Docs/SQLCIPHER.md §3, including the
///    FTS5 virtual table and sync triggers.
/// 5. `transaction(_:)` maps to BEGIN/COMMIT (SAVEPOINTs for nesting).
/// 6. Every repository method has a unit test against a temp-file
///    SQLCipher DB in the package test target
///    (Tests/AegisStoreTests/SQLCipherStoreTests.swift).
public protocol SQLCipherStoreDescriptor: Sendable {
    /// Opens (creating if needed) the encrypted database at `path`,
    /// unlocking it with the device keychain / Secure Enclave flow.
    /// Throws `.encryptionUnavailable` if the key cannot be unwrapped or
    /// the key is wrong. Never creates a plaintext database.
    static func open(at path: String) async throws -> any AegisDatabase

    /// Current schema version. Must match Docs/SQLCIPHER.md.
    static var schemaVersion: Int { get }
}
