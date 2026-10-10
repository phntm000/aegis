// AegisStore — SQLCipherAegisStore
//
// The production encrypted store: a SQLCipher database (AES-256) implementing
// the full `AegisDatabase` protocol surface. Replaces `InMemoryAegisStore`
// for the live app; the in-memory store remains for tests and previews.
//
// Threading: this is an actor. Every sqlite handle use is confined to actor
// isolation, so all database access is serialized without a separate queue.
// `transaction(_:)` maps to BEGIN/COMMIT, with SAVEPOINTs for nesting.
//
// Key management: see DatabaseKeyManager — a 256-bit random key generated
// once and kept in the Keychain. The database file never exists in
// plaintext.

import Foundation
import CSQLCipher

public actor SQLCipherAegisStore: AegisDatabase,
    ConversationRepository, MessageRepository, ContactRepository,
    GroupMembershipRepository, AttachmentRepository, CallRecordRepository
{
    let conn: SQLCipherConnection
    private var transactionDepth = 0

    private init(connection: SQLCipherConnection) {
        self.conn = connection
    }

    // MARK: - Opening

    /// Opens (creating if needed) the encrypted database at `path`,
    /// unlocking it with the Keychain-held database key (generated on first
    /// use). Throws `.encryptionUnavailable` when the key is wrong, the
    /// Keychain is unreachable, or the file is not a SQLCipher database.
    /// Never creates or falls back to a plaintext database.
    public static func openSync(at path: String) throws -> SQLCipherAegisStore {
        let key: [UInt8]
        do {
            key = try DatabaseKeyManager.databaseKey()
        } catch {
            throw AegisStoreError.encryptionUnavailable(
                "database key unavailable: \(error)")
        }
        var mutableKey = key
        defer { DatabaseKeyManager.zero(&mutableKey) }
        do {
            let conn = try SQLCipherConnection(path: path, key: mutableKey)
            applyFileProtection(at: path)
            return SQLCipherAegisStore(connection: conn)
        } catch let storeError as AegisStoreError {
            throw storeError
        } catch {
            throw AegisStoreError.ioError("open failed: \(error)")
        }
    }

    /// Test seam: opens the database with an explicit key, bypassing the
    /// Keychain (which is unavailable or undesirable in unit tests).
    public static func openForTesting(
        at path: String,
        key: [UInt8]
    ) throws -> SQLCipherAegisStore {
        var mutableKey = key
        defer { DatabaseKeyManager.zero(&mutableKey) }
        let conn = try SQLCipherConnection(path: path, key: mutableKey)
        return SQLCipherAegisStore(connection: conn)
    }

    /// Resolves the production database path: `Application Support/Aegis/aegis.db`.
    public static func defaultDatabasePath() throws -> String {
        let fm = FileManager.default
        guard let base = fm.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first else {
            throw AegisStoreError.ioError("no application support directory")
        }
        let dir = base.appendingPathComponent("Aegis", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("aegis.db").path
    }

    /// Defense in depth: complete file protection on the database file.
    /// The encryption itself is the primary control; this is belt and
    /// suspenders for the iOS data-protection class.
    private static func applyFileProtection(at path: String) {
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: path
        )
    }

    /// Test hook: returns the SQLCipher build string (e.g. "4.6.0 community").
    /// Used by tests to assert the database is really a SQLCipher build and
    /// not silently-linked plaintext SQLite (SQLCIPHER.md §6.8).
    func cipherVersionForDiagnostics() throws -> String {
        let rows = try conn.query("PRAGMA cipher_version;")
        guard case .text(let v) = rows.first?.values.first, !v.isEmpty else {
            throw AegisStoreError.encryptionUnavailable(
                "PRAGMA cipher_version returned nothing")
        }
        return v
    }

    // MARK: - AegisDatabase

    public nonisolated var conversations: any ConversationRepository { self }
    public nonisolated var messages: any MessageRepository { self }
    public nonisolated var contacts: any ContactRepository { self }
    public nonisolated var memberships: any GroupMembershipRepository { self }
    public nonisolated var attachments: any AttachmentRepository { self }
    public nonisolated var calls: any CallRecordRepository { self }

    public func transaction<T: Sendable>(
        _ work: @Sendable () async throws -> T
    ) async throws -> T {
        let depth = transactionDepth
        if depth == 0 {
            try conn.exec("BEGIN IMMEDIATE;")
        } else {
            try conn.exec("SAVEPOINT aegis_sp_\(depth);")
        }
        transactionDepth = depth + 1
        do {
            let result = try await work()
            transactionDepth = depth
            if depth == 0 {
                try conn.exec("COMMIT;")
            } else {
                try conn.exec("RELEASE SAVEPOINT aegis_sp_\(depth);")
            }
            return result
        } catch {
            transactionDepth = depth
            if depth == 0 {
                try? conn.exec("ROLLBACK;")
            } else {
                // Roll back to the savepoint, then release it so the name
                // can be reused by a later nested transaction.
                try? conn.exec("ROLLBACK TO SAVEPOINT aegis_sp_\(depth);")
                try? conn.exec("RELEASE SAVEPOINT aegis_sp_\(depth);")
            }
            throw error
        }
    }

    // MARK: - Snapshot / restore (encrypted backup)

    public func snapshot() async throws -> StoreSnapshot {
        let conversations = try conn.query("SELECT * FROM conversation;")
            .map { try decodeConversation($0) }
        let messages = try conn.query("SELECT * FROM message;")
            .map { try decodeMessage($0) }
        let contacts = try conn.query("SELECT * FROM contact;")
            .map { try decodeContact($0) }
        let memberships = try conn.query("SELECT * FROM group_membership;")
            .map { try decodeMembership($0) }
        let attachments = try conn.query("SELECT * FROM attachment;")
            .map { try decodeAttachment($0) }
        let callRecords = try conn.query("SELECT * FROM call_record;")
            .map { try decodeCallRecord($0) }
        return StoreSnapshot(
            conversations: conversations,
            messages: messages,
            contacts: contacts,
            memberships: memberships,
            attachments: attachments,
            callRecords: callRecords
        )
    }

    public func restore(_ snapshot: StoreSnapshot) async throws {
        guard snapshot.version <= StoreSnapshot.currentVersion else {
            throw AegisStoreError.invalidArgument(
                "snapshot version \(snapshot.version) is newer than supported \(StoreSnapshot.currentVersion)"
            )
        }
        try await transaction {
            try await self.restoreRows(snapshot)
        }
    }

    /// Actor-isolated restore body. Called inside `transaction(_:)`; kept
    /// separate so the `@Sendable` work closure only hops to the actor once.
    private func restoreRows(_ snapshot: StoreSnapshot) throws {
        // Children before parents (foreign keys are enforced).
        try conn.exec("DELETE FROM attachment;")
        try conn.exec("DELETE FROM call_record;")
        try conn.exec("DELETE FROM group_membership;")
        try conn.exec("DELETE FROM message;")
        try conn.exec("DELETE FROM contact;")
        try conn.exec("DELETE FROM conversation;")
        for c in snapshot.conversations { try insertConversation(c) }
        for m in snapshot.messages { try insertMessage(m, bumpConversation: false) }
        for c in snapshot.contacts { try upsertContact(c) }
        for m in snapshot.memberships { try upsertMembership(m) }
        for a in snapshot.attachments { try insertAttachment(a) }
        for r in snapshot.callRecords { try insertCallRecord(r) }
    }

    // MARK: - JSON helpers

    func encodeJSON<T: Encodable>(_ value: T) throws -> SQLValue {
        do {
            let data = try JSONEncoder().encode(value)
            guard let text = String(data: data, encoding: .utf8) else {
                throw AegisStoreError.ioError("JSON produced non-UTF8")
            }
            return .text(text)
        } catch let storeError as AegisStoreError {
            throw storeError
        } catch {
            throw AegisStoreError.ioError("JSON encode failed: \(error)")
        }
    }

    func decodeJSON<T: Decodable>(
        _ text: String?,
        fallback: T
    ) throws -> T {
        guard let text, !text.isEmpty else { return fallback }
        guard let data = text.data(using: .utf8) else {
            throw AegisStoreError.ioError("JSON column is not UTF-8")
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw AegisStoreError.ioError("JSON decode failed: \(error)")
        }
    }
}

// MARK: - SQLCipherStoreDescriptor

extension SQLCipherAegisStore: SQLCipherStoreDescriptor {
    public static func open(
        at path: String
    ) async throws -> any AegisDatabase {
        try openSync(at: path)
    }

    public static var schemaVersion: Int { StoreSchema.version }
}
