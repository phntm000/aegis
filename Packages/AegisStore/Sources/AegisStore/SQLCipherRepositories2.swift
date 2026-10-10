// AegisStore — SQLCipher repository implementations, part 2.
//
// Contacts, group memberships, attachments, call records. Semantics mirror
// `InMemoryAegisStore` exactly; see Repositories.swift for the contract.

import Foundation

// MARK: - ContactRepository

extension SQLCipherAegisStore {
    private func contactArgs(_ c: Contact) -> [SQLValue] {
        [
            .text(c.id.rawValue),
            .text(c.displayName),
            .text(c.identityKeyFingerprint),
            .text(c.verificationState.rawValue),
            sqlDate(c.verifiedAt),
            sqlBool(c.isBlocked),
            sqlBool(c.isFavorite),
            c.notes.map(SQLValue.text) ?? .null,
            sqlDate(c.createdAt),
            sqlDate(c.updatedAt),
        ]
    }

    func decodeContact(_ r: SQLRow) throws -> Contact {
        Contact(
            id: UserID(try r.reqString("id")),
            displayName: try r.reqString("display_name"),
            identityKeyFingerprint: try r.reqString("identity_key_fingerprint"),
            verificationState: VerificationState(
                rawValue: r.string("verification_state") ?? "") ?? .unverified,
            verifiedAt: r.date("verified_at"),
            isBlocked: r.bool("is_blocked"),
            isFavorite: r.bool("is_favorite"),
            notes: r.string("notes"),
            createdAt: try r.reqDate("created_at"),
            updatedAt: try r.reqDate("updated_at")
        )
    }

    func upsertContact(_ c: Contact) throws {
        let args = contactArgs(c)
        try conn.exec(
            """
            INSERT INTO contact(
              id, display_name, identity_key_fingerprint, verification_state,
              verified_at, is_blocked, is_favorite, notes, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              display_name = excluded.display_name,
              identity_key_fingerprint = excluded.identity_key_fingerprint,
              verification_state = excluded.verification_state,
              verified_at = excluded.verified_at,
              is_blocked = excluded.is_blocked,
              is_favorite = excluded.is_favorite,
              notes = excluded.notes,
              created_at = excluded.created_at,
              updated_at = excluded.updated_at;
            """,
            args
        )
    }

    public func upsert(_ contact: Contact) async throws {
        try upsertContact(contact)
    }

    public func fetch(id: UserID) async throws -> Contact? {
        let rows = try conn.query(
            "SELECT * FROM contact WHERE id = ?;", [.text(id.rawValue)])
        guard let row = rows.first else { return nil }
        return try decodeContact(row)
    }

    public func list(includeBlocked: Bool) async throws -> [Contact] {
        var sql = "SELECT * FROM contact"
        if !includeBlocked { sql += " WHERE is_blocked = 0" }
        sql += " ORDER BY is_favorite DESC, display_name COLLATE NOCASE ASC;"
        return try conn.query(sql).map { try decodeContact($0) }
    }

    public func delete(id: UserID) async throws {
        try conn.exec("DELETE FROM contact WHERE id = ?;", [.text(id.rawValue)])
        guard conn.changes() > 0 else {
            throw AegisStoreError.notFound("contact \(id)")
        }
    }

    public func setVerificationState(
        id: UserID,
        state: VerificationState
    ) async throws {
        guard var c = try await fetch(id: id) else {
            throw AegisStoreError.notFound("contact \(id)")
        }
        c.verificationState = state
        // verifiedAt is set on verification, preserved afterwards (matches
        // the in-memory implementation: never cleared on later transitions).
        if state == .verified { c.verifiedAt = Date() }
        c.updatedAt = Date()
        try await upsert(c)
    }

    public func setBlocked(id: UserID, blocked: Bool) async throws {
        guard var c = try await fetch(id: id) else {
            throw AegisStoreError.notFound("contact \(id)")
        }
        c.isBlocked = blocked
        c.updatedAt = Date()
        try await upsert(c)
    }
}

// MARK: - GroupMembershipRepository

extension SQLCipherAegisStore {
    private func membershipArgs(_ m: GroupMembership) -> [SQLValue] {
        [
            .text(m.conversationID.rawValue),
            .text(m.userID.rawValue),
            .text(m.role.rawValue),
            sqlDate(m.joinedAt),
            m.addedBy.map { SQLValue.text($0.rawValue) } ?? .null,
            .int(Int64(m.joinedAtEpoch)),
            sqlDate(m.updatedAt),
        ]
    }

    func decodeMembership(_ r: SQLRow) throws -> GroupMembership {
        GroupMembership(
            conversationID: ConversationID(try r.reqString("conversation_id")),
            userID: UserID(try r.reqString("user_id")),
            role: MemberRole(rawValue: try r.reqString("role")) ?? .member,
            joinedAt: try r.reqDate("joined_at"),
            addedBy: r.string("added_by").map { UserID($0) },
            joinedAtEpoch: Int(r.int("joined_at_epoch") ?? 0),
            updatedAt: try r.reqDate("updated_at")
        )
    }

    func upsertMembership(_ m: GroupMembership) throws {
        try conn.exec(
            """
            INSERT INTO group_membership(
              conversation_id, user_id, role, joined_at, added_by,
              joined_at_epoch, updated_at
            ) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(conversation_id, user_id) DO UPDATE SET
              role = excluded.role,
              joined_at = excluded.joined_at,
              added_by = excluded.added_by,
              joined_at_epoch = excluded.joined_at_epoch,
              updated_at = excluded.updated_at;
            """,
            membershipArgs(m)
        )
    }

    public func upsert(_ membership: GroupMembership) async throws {
        try upsertMembership(membership)
    }

    public func remove(
        conversationID: ConversationID,
        userID: UserID
    ) async throws {
        try conn.exec(
            "DELETE FROM group_membership WHERE conversation_id = ? AND user_id = ?;",
            [.text(conversationID.rawValue), .text(userID.rawValue)]
        )
        guard conn.changes() > 0 else {
            throw AegisStoreError.notFound(
                "membership \(userID) in \(conversationID)")
        }
    }

    public func members(
        of conversationID: ConversationID
    ) async throws -> [GroupMembership] {
        let rows = try conn.query(
            """
            SELECT * FROM group_membership
            WHERE conversation_id = ?
            ORDER BY joined_at ASC;
            """,
            [.text(conversationID.rawValue)]
        )
        return try rows.map { try decodeMembership($0) }
    }

    public func role(
        of userID: UserID,
        in conversationID: ConversationID
    ) async throws -> MemberRole? {
        let rows = try conn.query(
            """
            SELECT role FROM group_membership
            WHERE conversation_id = ? AND user_id = ?;
            """,
            [.text(conversationID.rawValue), .text(userID.rawValue)]
        )
        guard let raw = rows.first?.string("role") else { return nil }
        return MemberRole(rawValue: raw)
    }

    public func setRole(
        conversationID: ConversationID,
        userID: UserID,
        role: MemberRole
    ) async throws {
        try conn.exec(
            """
            UPDATE group_membership
            SET role = ?, updated_at = ?
            WHERE conversation_id = ? AND user_id = ?;
            """,
            [.text(role.rawValue), sqlDate(Date()),
             .text(conversationID.rawValue), .text(userID.rawValue)]
        )
        guard conn.changes() > 0 else {
            throw AegisStoreError.notFound(
                "membership \(userID) in \(conversationID)")
        }
    }

    public func conversations(
        containing userID: UserID
    ) async throws -> [ConversationID] {
        let rows = try conn.query(
            "SELECT DISTINCT conversation_id FROM group_membership WHERE user_id = ?;",
            [.text(userID.rawValue)]
        )
        return rows.compactMap { $0.string("conversation_id") }.map { ConversationID($0) }
    }
}

// MARK: - AttachmentRepository

extension SQLCipherAegisStore {
    private func attachmentArgs(_ a: Attachment) throws -> [SQLValue] {
        [
            .text(a.id.rawValue),
            .text(a.messageID.rawValue),
            .text(a.conversationID.rawValue),
            .text(a.kind.rawValue),
            .text(a.fileName),
            .text(a.mimeType),
            .int(a.byteCount),
            .int(Int64(a.chunkSize)),
            .int(Int64(a.chunkCount)),
            .int(a.bytesTransferred),
            .text(a.transferState.rawValue),
            a.remoteLocator.map(SQLValue.text) ?? .null,
            a.localRelativePath.map(SQLValue.text) ?? .null,
            .text(a.keychainKeyID),
            a.plaintextSHA256.map(SQLValue.blob) ?? .null,
            a.transcription.map(SQLValue.text) ?? .null,
            sqlDate(a.createdAt),
            sqlDate(a.updatedAt),
        ]
    }

    func decodeAttachment(_ r: SQLRow) throws -> Attachment {
        Attachment(
            id: AttachmentID(try r.reqString("id")),
            messageID: MessageID(try r.reqString("message_id")),
            conversationID: ConversationID(try r.reqString("conversation_id")),
            kind: AttachmentKind(rawValue: try r.reqString("kind")) ?? .file,
            fileName: try r.reqString("file_name"),
            mimeType: try r.reqString("mime_type"),
            byteCount: r.int("byte_count") ?? 0,
            chunkSize: Int(r.int("chunk_size") ?? 262_144),
            chunkCount: Int(r.int("chunk_count") ?? 0),
            bytesTransferred: r.int("bytes_transferred") ?? 0,
            transferState: TransferState(
                rawValue: r.string("transfer_state") ?? "") ?? .pending,
            remoteLocator: r.string("remote_locator"),
            localRelativePath: r.string("local_relative_path"),
            keychainKeyID: try r.reqString("keychain_key_id"),
            plaintextSHA256: r.data("plaintext_sha256"),
            transcription: r.string("transcription"),
            createdAt: try r.reqDate("created_at"),
            updatedAt: try r.reqDate("updated_at")
        )
    }

    func insertAttachment(_ a: Attachment) throws {
        try conn.exec(
            """
            INSERT INTO attachment(
              id, message_id, conversation_id, kind, file_name, mime_type,
              byte_count, chunk_size, chunk_count, bytes_transferred,
              transfer_state, remote_locator, local_relative_path,
              keychain_key_id, plaintext_sha256, transcription,
              created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            attachmentArgs(a)
        )
    }

    public func insert(_ attachment: Attachment) async throws {
        if try await fetch(id: attachment.id) != nil {
            throw AegisStoreError.conflict("attachment \(attachment.id) exists")
        }
        do {
            try insertAttachment(attachment)
        } catch let e as AegisStoreError {
            if case .conflict = e {
                throw AegisStoreError.conflict("attachment \(attachment.id) exists")
            }
            throw e
        }
    }

    public func fetch(id: AttachmentID) async throws -> Attachment? {
        let rows = try conn.query(
            "SELECT * FROM attachment WHERE id = ?;", [.text(id.rawValue)])
        guard let row = rows.first else { return nil }
        return try decodeAttachment(row)
    }

    public func list(for messageID: MessageID) async throws -> [Attachment] {
        // Display order = insertion order.
        let rows = try conn.query(
            "SELECT * FROM attachment WHERE message_id = ? ORDER BY rowid ASC;",
            [.text(messageID.rawValue)]
        )
        return try rows.map { try decodeAttachment($0) }
    }

    public func update(_ attachment: Attachment) async throws {
        guard try await fetch(id: attachment.id) != nil else {
            throw AegisStoreError.notFound("attachment \(attachment.id)")
        }
        let args = try attachmentArgs(attachment)
        try conn.exec(
            """
            UPDATE attachment SET
              message_id = ?, conversation_id = ?, kind = ?, file_name = ?,
              mime_type = ?, byte_count = ?, chunk_size = ?, chunk_count = ?,
              bytes_transferred = ?, transfer_state = ?, remote_locator = ?,
              local_relative_path = ?, keychain_key_id = ?,
              plaintext_sha256 = ?, transcription = ?,
              created_at = ?, updated_at = ?
            WHERE id = ?;
            """,
            Array(args.dropFirst()) + [.text(attachment.id.rawValue)]
        )
    }

    public func setTransferState(
        id: AttachmentID,
        state: TransferState
    ) async throws {
        guard var a = try await fetch(id: id) else {
            throw AegisStoreError.notFound("attachment \(id)")
        }
        a.transferState = state
        a.updatedAt = Date()
        try await update(a)
    }

    public func recordProgress(
        id: AttachmentID,
        bytesTransferred: Int64
    ) async throws {
        guard var a = try await fetch(id: id) else {
            throw AegisStoreError.notFound("attachment \(id)")
        }
        guard bytesTransferred >= 0 else {
            throw AegisStoreError.invalidArgument("negative progress")
        }
        a.bytesTransferred = min(bytesTransferred, a.byteCount)
        if a.bytesTransferred >= a.byteCount, a.byteCount > 0 {
            a.transferState = .complete
        }
        a.updatedAt = Date()
        try await update(a)
    }

    public func delete(id: AttachmentID) async throws {
        try conn.exec("DELETE FROM attachment WHERE id = ?;", [.text(id.rawValue)])
        guard conn.changes() > 0 else {
            throw AegisStoreError.notFound("attachment \(id)")
        }
    }
}

// MARK: - CallRecordRepository

extension SQLCipherAegisStore {
    private func callRecordArgs(_ r: CallRecord) throws -> [SQLValue] {
        [
            .text(r.id.rawValue),
            .text(r.conversationID.rawValue),
            .text(r.kind.rawValue),
            .text(r.direction.rawValue),
            try encodeJSON(r.participants),
            sqlBool(r.wasAnswered),
            sqlDate(r.startedAt),
            sqlDate(r.endedAt),
            try encodeJSON(r.recordingConsent),
            r.localRecordingPath.map(SQLValue.text) ?? .null,
            sqlDate(r.createdAt),
        ]
    }

    func decodeCallRecord(_ r: SQLRow) throws -> CallRecord {
        CallRecord(
            id: CallID(try r.reqString("id")),
            conversationID: ConversationID(try r.reqString("conversation_id")),
            kind: CallKind(rawValue: try r.reqString("kind")) ?? .audio,
            direction: CallDirection(rawValue: try r.reqString("direction")) ?? .incoming,
            participants: try decodeJSON(r.string("participants_json"), fallback: [UserID]()),
            wasAnswered: r.bool("was_answered"),
            startedAt: try r.reqDate("started_at"),
            endedAt: r.date("ended_at"),
            recordingConsent: try decodeJSON(
                r.string("recording_consent_json"), fallback: [UserID: Bool]()),
            localRecordingPath: r.string("local_recording_path"),
            createdAt: try r.reqDate("created_at")
        )
    }

    func insertCallRecord(_ r: CallRecord) throws {
        try conn.exec(
            """
            INSERT INTO call_record(
              id, conversation_id, kind, direction, participants_json,
              was_answered, started_at, ended_at, recording_consent_json,
              local_recording_path, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?);
            """,
            callRecordArgs(r)
        )
    }

    public func insert(_ record: CallRecord) async throws {
        if try await fetch(id: record.id) != nil {
            throw AegisStoreError.conflict("call \(record.id) exists")
        }
        do {
            try insertCallRecord(record)
        } catch let e as AegisStoreError {
            if case .conflict = e {
                throw AegisStoreError.conflict("call \(record.id) exists")
            }
            throw e
        }
    }

    public func fetch(id: CallID) async throws -> CallRecord? {
        let rows = try conn.query(
            "SELECT * FROM call_record WHERE id = ?;", [.text(id.rawValue)])
        guard let row = rows.first else { return nil }
        return try decodeCallRecord(row)
    }

    public func list(
        in conversationID: ConversationID,
        limit: Int
    ) async throws -> [CallRecord] {
        let rows = try conn.query(
            """
            SELECT * FROM call_record
            WHERE conversation_id = ?
            ORDER BY started_at DESC
            LIMIT ?;
            """,
            [.text(conversationID.rawValue), .int(Int64(max(0, limit)))]
        )
        return try rows.map { try decodeCallRecord($0) }
    }

    public func update(_ record: CallRecord) async throws {
        guard try await fetch(id: record.id) != nil else {
            throw AegisStoreError.notFound("call \(record.id)")
        }
        let args = try callRecordArgs(record)
        try conn.exec(
            """
            UPDATE call_record SET
              conversation_id = ?, kind = ?, direction = ?,
              participants_json = ?, was_answered = ?, started_at = ?,
              ended_at = ?, recording_consent_json = ?,
              local_recording_path = ?, created_at = ?
            WHERE id = ?;
            """,
            Array(args.dropFirst()) + [.text(record.id.rawValue)]
        )
    }

    public func delete(id: CallID) async throws {
        // Matches the in-memory implementation: deleting a missing record
        // is a no-op, not an error.
        try conn.exec("DELETE FROM call_record WHERE id = ?;", [.text(id.rawValue)])
    }

    public func setRecordingConsent(
        callID: CallID,
        userID: UserID,
        consented: Bool
    ) async throws {
        guard var r = try await fetch(id: callID) else {
            throw AegisStoreError.notFound("call \(callID)")
        }
        r.recordingConsent[userID] = consented
        try await update(r)
    }
}

// MARK: - SessionRepository

extension SQLCipherAegisStore {
    public func save(fingerprint: String, snapshot: Data) async throws {
        try conn.exec(
            """
            INSERT INTO ratchet_session(fingerprint, snapshot, updated_at)
            VALUES (?,?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET
              snapshot = excluded.snapshot,
              updated_at = excluded.updated_at;
            """,
            [.text(fingerprint), .blob(snapshot), .real(Date().timeIntervalSince1970)]
        )
    }

    public func load(fingerprint: String) async throws -> Data? {
        let rows = try conn.query(
            "SELECT snapshot FROM ratchet_session WHERE fingerprint = ?;",
            [.text(fingerprint)]
        )
        guard let row = rows.first, case .blob(let data) = row["snapshot"] else { return nil }
        return data
    }

    public func loadAll() async throws -> [String: Data] {
        var out: [String: Data] = [:]
        for row in try conn.query("SELECT fingerprint, snapshot FROM ratchet_session;") {
            guard case .text(let fp) = row["fingerprint"],
                  case .blob(let data) = row["snapshot"]
            else { continue }
            out[fp] = data
        }
        return out
    }

    public func delete(fingerprint: String) async throws {
        try conn.exec("DELETE FROM ratchet_session WHERE fingerprint = ?;", [.text(fingerprint)])
    }

    public func deleteAll() async throws {
        try conn.exec("DELETE FROM ratchet_session;")
    }
}

// MARK: - GroupSessionRepository

extension SQLCipherAegisStore {
    public func saveGroupSession(groupID: String, snapshot: Data) async throws {
        try conn.exec(
            """
            INSERT INTO group_session(group_id, snapshot, updated_at)
            VALUES (?,?,?)
            ON CONFLICT(group_id) DO UPDATE SET
              snapshot = excluded.snapshot,
              updated_at = excluded.updated_at;
            """,
            [.text(groupID), .blob(snapshot), .real(Date().timeIntervalSince1970)]
        )
    }

    public func loadAllGroupSessions() async throws -> [String: Data] {
        var out: [String: Data] = [:]
        for row in try conn.query("SELECT group_id, snapshot FROM group_session;") {
            guard case .text(let gid) = row["group_id"],
                  case .blob(let data) = row["snapshot"]
            else { continue }
            out[gid] = data
        }
        return out
    }

    public func deleteGroupSession(groupID: String) async throws {
        try conn.exec("DELETE FROM group_session WHERE group_id = ?;", [.text(groupID)])
    }

    public func deleteAllGroupSessions() async throws {
        try conn.exec("DELETE FROM group_session;")
    }
}

// MARK: - AttachmentContextRepository

extension SQLCipherAegisStore {
    public func saveAttachmentContext(keyHash: String, groupID: Data?, peer: Data?) async throws {
        try conn.exec(
            """
            INSERT INTO attachment_context(key_hash, group_id, peer)
            VALUES (?,?,?)
            ON CONFLICT(key_hash) DO UPDATE SET
              group_id = excluded.group_id,
              peer = excluded.peer;
            """,
            [.text(keyHash), groupID.map(SQLValue.blob) ?? .null, peer.map(SQLValue.blob) ?? .null]
        )
    }

    public func loadAttachmentContext(keyHash: String) async throws -> (groupID: Data?, peer: Data?)? {
        let rows = try conn.query(
            "SELECT group_id, peer FROM attachment_context WHERE key_hash = ?;",
            [.text(keyHash)]
        )
        guard let row = rows.first else { return nil }
        let groupID: Data?
        if case .blob(let data) = row["group_id"] { groupID = data } else { groupID = nil }
        let peer: Data?
        if case .blob(let data) = row["peer"] { peer = data } else { peer = nil }
        return (groupID, peer)
    }

    public func deleteAllAttachmentContexts() async throws {
        try conn.exec("DELETE FROM attachment_context;")
    }
}
