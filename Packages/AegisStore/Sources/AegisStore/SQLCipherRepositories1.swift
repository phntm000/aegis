// AegisStore — SQLCipher repository implementations, part 1.
//
// Conversations and messages. Semantics mirror `InMemoryAegisStore`
// exactly (error cases, ordering, side effects); see the protocol docs in
// Repositories.swift for the contract.

import Foundation

// MARK: - ConversationRepository

extension SQLCipherAegisStore {
    func insertConversation(_ c: Conversation) throws {
        try conn.exec(
            """
            INSERT INTO conversation(
              id, kind, network_policy, title, key_epoch,
              disappearing_timer_seconds, is_archived, is_muted, is_pinned,
              read_receipts, typing_indicators, link_previews,
              last_read_message_id, unread_count, last_message_id,
              created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            conversationArgs(c)
        )
    }

    private func conversationArgs(_ c: Conversation) -> [SQLValue] {
        [
            .text(c.id.rawValue),
            .text(c.kind.rawValue),
            .text(c.networkPolicy.rawValue),
            c.title.map(SQLValue.text) ?? .null,
            .int(Int64(c.keyEpoch)),
            c.disappearingTimerSeconds.map { SQLValue.int(Int64($0)) } ?? .null,
            sqlBool(c.isArchived),
            sqlBool(c.isMuted),
            sqlBool(c.isPinned),
            sqlBool(c.readReceiptsEnabled),
            sqlBool(c.typingIndicatorsEnabled),
            sqlBool(c.linkPreviewsEnabled),
            c.lastReadMessageID.map { SQLValue.text($0.rawValue) } ?? .null,
            .int(Int64(c.unreadCount)),
            c.lastMessageID.map { SQLValue.text($0.rawValue) } ?? .null,
            sqlDate(c.createdAt),
            sqlDate(c.updatedAt),
        ]
    }

    func decodeConversation(_ r: SQLRow) throws -> Conversation {
        Conversation(
            id: ConversationID(try r.reqString("id")),
            kind: ConversationKind(rawValue: try r.reqString("kind")) ?? .direct,
            networkPolicy: NetworkPolicy(rawValue: try r.reqString("network_policy")),
            title: r.string("title"),
            keyEpoch: Int(r.int("key_epoch") ?? 0),
            disappearingTimerSeconds: r.int("disappearing_timer_seconds").map(Int.init),
            isArchived: r.bool("is_archived"),
            isMuted: r.bool("is_muted"),
            isPinned: r.bool("is_pinned"),
            readReceiptsEnabled: r.bool("read_receipts"),
            typingIndicatorsEnabled: r.bool("typing_indicators"),
            linkPreviewsEnabled: r.bool("link_previews"),
            lastReadMessageID: r.string("last_read_message_id").map { MessageID($0) },
            unreadCount: Int(r.int("unread_count") ?? 0),
            lastMessageID: r.string("last_message_id").map { MessageID($0) },
            createdAt: try r.reqDate("created_at"),
            updatedAt: try r.reqDate("updated_at")
        )
    }

    public func create(_ conversation: Conversation) async throws {
        if try await fetch(id: conversation.id) != nil {
            throw AegisStoreError.conflict("conversation \(conversation.id) exists")
        }
        do {
            try insertConversation(conversation)
        } catch let e as AegisStoreError {
            if case .conflict = e {
                throw AegisStoreError.conflict("conversation \(conversation.id) exists")
            }
            throw e
        }
    }

    public func fetch(id: ConversationID) async throws -> Conversation? {
        let rows = try conn.query(
            "SELECT * FROM conversation WHERE id = ?;", [.text(id.rawValue)])
        guard let row = rows.first else { return nil }
        return try decodeConversation(row)
    }

    public func list(
        includeArchived: Bool,
        kind: ConversationKind?,
        query: String?
    ) async throws -> [Conversation] {
        var sql = "SELECT * FROM conversation"
        var clauses: [String] = []
        var args: [SQLValue] = []
        if !includeArchived { clauses.append("is_archived = 0") }
        if let kind {
            clauses.append("kind = ?")
            args.append(.text(kind.rawValue))
        }
        if let query, !query.isEmpty {
            // Substring match over title, case-insensitive.
            clauses.append("title IS NOT NULL AND instr(lower(title), lower(?)) > 0")
            args.append(.text(query))
        }
        if !clauses.isEmpty { sql += " WHERE " + clauses.joined(separator: " AND ") }
        // Pinned first, then most recently updated.
        sql += " ORDER BY is_pinned DESC, updated_at DESC;"
        return try conn.query(sql, args).map { try decodeConversation($0) }
    }

    public func update(_ conversation: Conversation) async throws {
        guard try await fetch(id: conversation.id) != nil else {
            throw AegisStoreError.notFound("conversation \(conversation.id)")
        }
        let args = conversationArgs(conversation)
        // UPDATE all columns except the primary key.
        try conn.exec(
            """
            UPDATE conversation SET
              kind = ?, network_policy = ?, title = ?, key_epoch = ?,
              disappearing_timer_seconds = ?, is_archived = ?, is_muted = ?,
              is_pinned = ?, read_receipts = ?, typing_indicators = ?,
              link_previews = ?, last_read_message_id = ?, unread_count = ?,
              last_message_id = ?, created_at = ?, updated_at = ?
            WHERE id = ?;
            """,
            Array(args.dropFirst()) + [.text(conversation.id.rawValue)]
        )
    }

    public func delete(id: ConversationID) async throws {
        guard try await fetch(id: id) != nil else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        // Cascades (messages, attachments, memberships, call records) are
        // enforced by foreign keys; the FTS triggers clean the search index.
        try conn.exec("DELETE FROM conversation WHERE id = ?;", [.text(id.rawValue)])
    }

    public func setDisappearingTimer(
        id: ConversationID,
        seconds: Int?
    ) async throws {
        guard try await fetch(id: id) != nil else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        if let seconds, seconds <= 0 {
            throw AegisStoreError.invalidArgument("timer must be positive")
        }
        try conn.exec(
            "UPDATE conversation SET disappearing_timer_seconds = ?, updated_at = ? WHERE id = ?;",
            [seconds.map { SQLValue.int(Int64($0)) } ?? .null,
             sqlDate(Date()),
             .text(id.rawValue)]
        )
    }

    public func setNetworkPolicy(
        id: ConversationID,
        policy: NetworkPolicy
    ) async throws {
        guard let c = try await fetch(id: id) else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        // Vault chats can never leave local-only: fail closed.
        if c.kind == .vault, policy != .localOnly {
            throw AegisStoreError.invalidArgument("vault chats are always local-only")
        }
        try conn.exec(
            "UPDATE conversation SET network_policy = ?, updated_at = ? WHERE id = ?;",
            [.text(policy.rawValue), sqlDate(Date()), .text(id.rawValue)]
        )
    }

    public func markRead(id: ConversationID, upTo messageID: MessageID) async throws {
        guard try await fetch(id: id) != nil else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        try conn.exec(
            """
            UPDATE conversation
            SET last_read_message_id = ?, unread_count = 0, updated_at = ?
            WHERE id = ?;
            """,
            [.text(messageID.rawValue), sqlDate(Date()), .text(id.rawValue)]
        )
    }
}

// MARK: - MessageRepository

extension SQLCipherAegisStore {
    func insertMessage(_ m: Message, bumpConversation: Bool) throws {
        try conn.exec(
            """
            INSERT INTO message(
              id, conversation_id, sender_id, is_sealed_sender, direction,
              kind, text, reply_to, thread_root, edit_version, edited_at,
              is_tombstone, tombstoned_at, disappear_at, scheduled_for,
              delivery_state, sent_at, delivered_at, read_at, secrecy_epoch,
              reactions_json, poll_json, attachment_ids_json,
              created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            messageArgs(m)
        )
        if bumpConversation {
            // Mirror the in-memory side effects: conversation preview +
            // unread bump for incoming messages.
            try conn.exec(
                """
                UPDATE conversation
                SET last_message_id = ?,
                    updated_at = ?,
                    unread_count = unread_count + ?
                WHERE id = ?;
                """,
                [.text(m.id.rawValue),
                 sqlDate(m.createdAt),
                 .int(m.direction == .incoming ? Int64(1) : Int64(0)),
                 .text(m.conversationID.rawValue)]
            )
        }
    }

    private func messageArgs(_ m: Message) throws -> [SQLValue] {
        [
            .text(m.id.rawValue),
            .text(m.conversationID.rawValue),
            m.senderID.map { SQLValue.text($0.rawValue) } ?? .null,
            sqlBool(m.isSealedSender),
            .text(m.direction.rawValue),
            .text(m.kind.rawValue),
            m.text.map(SQLValue.text) ?? .null,
            m.replyToMessageID.map { SQLValue.text($0.rawValue) } ?? .null,
            m.threadRootID.map { SQLValue.text($0.rawValue) } ?? .null,
            .int(Int64(m.editVersion)),
            sqlDate(m.editedAt),
            sqlBool(m.isTombstone),
            sqlDate(m.tombstonedAt),
            sqlDate(m.disappearAt),
            sqlDate(m.scheduledFor),
            .text(m.deliveryState.rawValue),
            sqlDate(m.sentAt),
            sqlDate(m.deliveredAt),
            sqlDate(m.readAt),
            .int(Int64(m.secrecyEpoch)),
            try encodeJSON(m.reactions),
            try m.poll.map { try encodeJSON($0) } ?? .null,
            try encodeJSON(m.attachmentIDs),
            sqlDate(m.createdAt),
            sqlDate(m.updatedAt),
        ]
    }

    func decodeMessage(_ r: SQLRow) throws -> Message {
        Message(
            id: MessageID(try r.reqString("id")),
            conversationID: ConversationID(try r.reqString("conversation_id")),
            senderID: r.string("sender_id").map { UserID($0) },
            isSealedSender: r.bool("is_sealed_sender"),
            direction: MessageDirection(rawValue: try r.reqString("direction")) ?? .incoming,
            kind: MessageKind(rawValue: try r.reqString("kind")) ?? .text,
            text: r.string("text"),
            replyToMessageID: r.string("reply_to").map { MessageID($0) },
            threadRootID: r.string("thread_root").map { MessageID($0) },
            editVersion: Int(r.int("edit_version") ?? 0),
            editedAt: r.date("edited_at"),
            isTombstone: r.bool("is_tombstone"),
            tombstonedAt: r.date("tombstoned_at"),
            disappearAt: r.date("disappear_at"),
            scheduledFor: r.date("scheduled_for"),
            deliveryState: DeliveryState(rawValue: try r.reqString("delivery_state")) ?? .queued,
            sentAt: r.date("sent_at"),
            deliveredAt: r.date("delivered_at"),
            readAt: r.date("read_at"),
            secrecyEpoch: Int(r.int("secrecy_epoch") ?? 0),
            reactions: try decodeJSON(r.string("reactions_json"), fallback: [Reaction]()),
            poll: try decodeJSON(r.string("poll_json"), fallback: Poll?.none),
            attachmentIDs: try decodeJSON(r.string("attachment_ids_json"), fallback: [AttachmentID]()),
            createdAt: try r.reqDate("created_at"),
            updatedAt: try r.reqDate("updated_at")
        )
    }

    public func insert(_ message: Message) async throws {
        if try await exists(id: message.id) {
            throw AegisStoreError.conflict("message \(message.id) exists")
        }
        guard try await conversations.fetch(id: message.conversationID) != nil else {
            throw AegisStoreError.invalidArgument(
                "conversation \(message.conversationID) does not exist")
        }
        if message.kind == .text, (message.text ?? "").isEmpty,
            message.attachmentIDs.isEmpty
        {
            throw AegisStoreError.invalidArgument("message has no content")
        }
        do {
            try insertMessage(message, bumpConversation: true)
        } catch let e as AegisStoreError {
            if case .conflict = e {
                throw AegisStoreError.conflict("message \(message.id) exists")
            }
            throw e
        }
    }

    public func exists(id: MessageID) async throws -> Bool {
        let rows = try conn.query(
            "SELECT 1 FROM message WHERE id = ? LIMIT 1;", [.text(id.rawValue)])
        return !rows.isEmpty
    }

    public func fetch(id: MessageID) async throws -> Message? {
        let rows = try conn.query(
            "SELECT * FROM message WHERE id = ?;", [.text(id.rawValue)])
        guard let row = rows.first else { return nil }
        return try decodeMessage(row)
    }

    public func list(
        in conversationID: ConversationID,
        limit: Int,
        before: MessageID?
    ) async throws -> MessagePage {
        guard limit > 0 else {
            throw AegisStoreError.invalidArgument("limit must be positive")
        }
        var sql = "SELECT * FROM message WHERE conversation_id = ?"
        var args: [SQLValue] = [.text(conversationID.rawValue)]
        if let before, let cursor = try await fetch(id: before) {
            // Keyset pagination on (created_at DESC, id DESC).
            sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
            let ts = sqlDate(cursor.createdAt)
            args += [ts, ts, .text(cursor.id.rawValue)]
        }
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?;"
        args.append(.int(Int64(limit + 1)))
        let rows = try conn.query(sql, args)
        let messages = try rows.prefix(limit).map { try decodeMessage($0) }
        return MessagePage(messages: Array(messages), hasMore: rows.count > limit)
    }

    public func update(_ message: Message) async throws {
        guard try await exists(id: message.id) else {
            throw AegisStoreError.notFound("message \(message.id)")
        }
        let args = try messageArgs(message)
        try conn.exec(
            """
            UPDATE message SET
              conversation_id = ?, sender_id = ?, is_sealed_sender = ?,
              direction = ?, kind = ?, text = ?, reply_to = ?,
              thread_root = ?, edit_version = ?, edited_at = ?,
              is_tombstone = ?, tombstoned_at = ?, disappear_at = ?,
              scheduled_for = ?, delivery_state = ?, sent_at = ?,
              delivered_at = ?, read_at = ?, secrecy_epoch = ?,
              reactions_json = ?, poll_json = ?, attachment_ids_json = ?,
              created_at = ?, updated_at = ?
            WHERE id = ?;
            """,
            Array(args.dropFirst()) + [.text(message.id.rawValue)]
        )
    }

    public func applyTombstone(id: MessageID, at: Date) async throws {
        guard try await exists(id: id) else {
            throw AegisStoreError.notFound("message \(id)")
        }
        // Delete attachment metadata first (the caller destroys the Keychain
        // data keys via keychainKeyID — keys never live in the DB).
        try conn.exec(
            "DELETE FROM attachment WHERE message_id = ?;", [.text(id.rawValue)])
        try conn.exec(
            """
            UPDATE message SET
              is_tombstone = 1, tombstoned_at = ?, text = NULL,
              poll_json = NULL, attachment_ids_json = '[]', updated_at = ?
            WHERE id = ?;
            """,
            [sqlDate(at), sqlDate(at), .text(id.rawValue)]
        )
    }

    public func search(
        query: String,
        in conversationID: ConversationID?,
        limit: Int
    ) async throws -> [Message] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return [] }
        var sql = """
            SELECT m.* FROM message_fts f
            JOIN message m ON m.rowid = f.rowid
            WHERE message_fts MATCH ?
              AND m.is_tombstone = 0
              AND (m.disappear_at IS NULL OR m.disappear_at > ?)
            """
        var args: [SQLValue] = [.text(q), sqlDate(Date())]
        if let conversationID {
            sql += " AND m.conversation_id = ?"
            args.append(.text(conversationID.rawValue))
        }
        sql += " ORDER BY m.created_at DESC LIMIT ?;"
        args.append(.int(Int64(max(0, limit))))
        do {
            return try conn.query(sql, args).map { try decodeMessage($0) }
        } catch let e as AegisStoreError {
            // FTS5 query-syntax errors (unbalanced quotes etc. in user
            // input) are not data errors: return no hits rather than fail
            // the search. Bound parameters already prevent injection.
            if case .ioError(let msg) = e, msg.contains("syntax error") {
                return []
            }
            throw e
        }
    }

    public func expungeDisappeared(now: Date) async throws -> Int {
        let rows = try conn.query(
            """
            SELECT id FROM message
            WHERE is_tombstone = 0 AND disappear_at IS NOT NULL
              AND disappear_at <= ?;
            """,
            [sqlDate(now)]
        )
        guard !rows.isEmpty else { return 0 }
        let ids = rows.compactMap { $0.string("id") }
        try await transaction {
            try await self.expungeRows(ids)
        }
        return ids.count
    }

    /// Actor-isolated expunge body. Attachments cascade via foreign keys;
    /// FTS entries are removed by the delete trigger.
    private func expungeRows(_ ids: [String]) throws {
        for id in ids {
            try conn.exec("DELETE FROM message WHERE id = ?;", [.text(id)])
        }
    }

    public func pendingOutbox(now: Date) async throws -> [Message] {
        let rows = try conn.query(
            """
            SELECT * FROM message
            WHERE direction = 'outgoing' AND is_tombstone = 0
              AND delivery_state = 'queued'
              AND (scheduled_for IS NULL OR scheduled_for <= ?)
            ORDER BY created_at ASC;
            """,
            [sqlDate(now)]
        )
        return try rows.map { try decodeMessage($0) }
    }

    public func setDeliveryState(
        id: MessageID,
        state: DeliveryState
    ) async throws {
        guard var m = try await fetch(id: id) else {
            throw AegisStoreError.notFound("message \(id)")
        }
        // Terminal states don't regress.
        if (m.deliveryState == .read || m.deliveryState == .failed),
            state == .queued
        {
            throw AegisStoreError.invalidArgument(
                "cannot requeue terminal state \(m.deliveryState)")
        }
        m.deliveryState = state
        let now = Date()
        switch state {
        case .sent: m.sentAt = now
        case .delivered: m.deliveredAt = now
        case .read: m.readAt = now
        case .queued, .failed: break
        }
        m.updatedAt = now
        try await update(m)
    }

    public func setReaction(
        id: MessageID,
        emoji: String?,
        userID: UserID
    ) async throws {
        guard var m = try await fetch(id: id) else {
            throw AegisStoreError.notFound("message \(id)")
        }
        m.reactions.removeAll { $0.userID == userID }
        if let emoji {
            m.reactions.append(Reaction(emoji: emoji, userID: userID))
        }
        m.updatedAt = Date()
        try await update(m)
    }
}
