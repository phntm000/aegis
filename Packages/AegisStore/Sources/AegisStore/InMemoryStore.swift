// AegisStore — In-memory implementation
//
// A complete, thread-safe (actor-isolated) implementation of every
// repository protocol. Used for unit tests and SwiftUI previews.
//
// Fidelity notes vs. the production SQLCipher adapter:
// - Search is a case-insensitive substring scan (production uses FTS5
//   MATCH inside the encrypted DB). Ranking is recency-only here.
// - "Cryptographic wiping" is modeled as removal from all indexes; the
//   SQLCipher adapter additionally zeroes pages via secure delete.
// - Keychain key destruction on attachment delete is the *caller's*
//   responsibility in both implementations (keys never live in the DB).

import Foundation

public actor InMemoryAegisStore: AegisDatabase, ConversationRepository, MessageRepository, ContactRepository, GroupMembershipRepository, AttachmentRepository, CallRecordRepository, SessionRepository, GroupSessionRepository, AttachmentContextRepository {
    // MARK: - Storage

    private var conversationsByID: [ConversationID: Conversation] = [:]
    private var messagesByID: [MessageID: Message] = [:]
    /// conversationID -> message IDs, newest-first.
    private var messageOrder: [ConversationID: [MessageID]] = [:]
    private var contactsByID: [UserID: Contact] = [:]
    /// conversationID -> userID -> membership
    private var membershipsByConversation: [ConversationID: [UserID: GroupMembership]] = [:]
    private var attachmentsByID: [AttachmentID: Attachment] = [:]
    /// messageID -> attachment IDs in display order
    private var attachmentsByMessage: [MessageID: [AttachmentID]] = [:]
    private var callsByID: [CallID: CallRecord] = [:]
    /// conversationID -> call IDs, newest-first
    private var callsByConversation: [ConversationID: [CallID]] = [:]
    /// peer fingerprint hex -> opaque session snapshot
    private var sessionsByFingerprint: [String: Data] = [:]
    private var groupSessionsByID: [String: Data] = [:]
    private var attachmentContextsByHash: [String: (groupID: Data?, peer: Data?)] = [:]

    public init() {}

    // MARK: - AegisStore

    public nonisolated var conversations: any ConversationRepository { self }
    public nonisolated var messages: any MessageRepository { self }
    public nonisolated var contacts: any ContactRepository { self }
    public nonisolated var memberships: any GroupMembershipRepository { self }
    public nonisolated var attachments: any AttachmentRepository { self }
    public nonisolated var calls: any CallRecordRepository { self }
    public nonisolated var sessions: any SessionRepository { self }
    public nonisolated var groupSessions: any GroupSessionRepository { self }
    public nonisolated var attachmentContexts: any AttachmentContextRepository { self }

    public func transaction<T: Sendable>(
        _ work: @Sendable () async throws -> T
    ) async throws -> T {
        // Actor isolation already serializes; re-entrant by construction.
        try await work()
    }

    // MARK: - Snapshot / restore (encrypted backup)

    public func snapshot() async throws -> StoreSnapshot {
        StoreSnapshot(
            conversations: Array(conversationsByID.values),
            messages: Array(messagesByID.values),
            contacts: Array(contactsByID.values),
            memberships: membershipsByConversation.values.flatMap { Array($0.values) },
            attachments: Array(attachmentsByID.values),
            callRecords: Array(callsByID.values)
        )
    }

    public func restore(_ snapshot: StoreSnapshot) async throws {
        guard snapshot.version <= StoreSnapshot.currentVersion else {
            throw AegisStoreError.invalidArgument(
                "snapshot version \(snapshot.version) is newer than supported \(StoreSnapshot.currentVersion)"
            )
        }
        conversationsByID = Dictionary(
            uniqueKeysWithValues: snapshot.conversations.map { ($0.id, $0) }
        )
        messagesByID = Dictionary(
            uniqueKeysWithValues: snapshot.messages.map { ($0.id, $0) }
        )
        // Rebuild the newest-first per-conversation ordering.
        var order: [ConversationID: [MessageID]] = [:]
        for message in snapshot.messages.sorted(by: {
            ($0.sentAt ?? .distantPast) > ($1.sentAt ?? .distantPast)
        }) {
            order[message.conversationID, default: []].append(message.id)
        }
        messageOrder = order
        contactsByID = Dictionary(
            uniqueKeysWithValues: snapshot.contacts.map { ($0.id, $0) }
        )
        var rebuiltMemberships: [ConversationID: [UserID: GroupMembership]] = [:]
        for membership in snapshot.memberships {
            rebuiltMemberships[membership.conversationID, default: [:]][membership.userID] = membership
        }
        membershipsByConversation = rebuiltMemberships
        attachmentsByID = Dictionary(
            uniqueKeysWithValues: snapshot.attachments.map { ($0.id, $0) }
        )
        var byMessage: [MessageID: [AttachmentID]] = [:]
        for attachment in snapshot.attachments {
            byMessage[attachment.messageID, default: []].append(attachment.id)
        }
        attachmentsByMessage = byMessage
        callsByID = Dictionary(
            uniqueKeysWithValues: snapshot.callRecords.map { ($0.id, $0) }
        )
        var byConversation: [ConversationID: [CallID]] = [:]
        for record in snapshot.callRecords.sorted(by: { $0.startedAt > $1.startedAt }) {
            byConversation[record.conversationID, default: []].append(record.id)
        }
        callsByConversation = byConversation
    }

    // MARK: - ConversationRepository

    public func create(_ conversation: Conversation) async throws {
        guard conversationsByID[conversation.id] == nil else {
            throw AegisStoreError.conflict("conversation \(conversation.id) exists")
        }
        conversationsByID[conversation.id] = conversation
    }

    public func fetch(id: ConversationID) async throws -> Conversation? {
        conversationsByID[id]
    }

    public func list(
        includeArchived: Bool,
        kind: ConversationKind?,
        query: String?
    ) async throws -> [Conversation] {
        var result = Array(conversationsByID.values)
        if !includeArchived { result.removeAll { $0.isArchived } }
        if let kind { result.removeAll { $0.kind != kind } }
        if let query, !query.isEmpty {
            let q = query.lowercased()
            result.removeAll { !($0.title?.lowercased().contains(q) ?? false) }
        }
        // Pinned first, then most recently updated.
        result.sort {
            if $0.isPinned != $1.isPinned { return $0.isPinned }
            return $0.updatedAt > $1.updatedAt
        }
        return result
    }

    public func update(_ conversation: Conversation) async throws {
        guard conversationsByID[conversation.id] != nil else {
            throw AegisStoreError.notFound("conversation \(conversation.id)")
        }
        conversationsByID[conversation.id] = conversation
    }

    public func delete(id: ConversationID) async throws {
        guard conversationsByID.removeValue(forKey: id) != nil else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        // Cascade: messages, attachments, memberships, call records.
        for messageID in messageOrder[id] ?? [] {
            messagesByID.removeValue(forKey: messageID)
            for attachmentID in attachmentsByMessage[messageID] ?? [] {
                attachmentsByID.removeValue(forKey: attachmentID)
            }
            attachmentsByMessage.removeValue(forKey: messageID)
        }
        messageOrder.removeValue(forKey: id)
        membershipsByConversation.removeValue(forKey: id)
        for callID in callsByConversation[id] ?? [] {
            callsByID.removeValue(forKey: callID)
        }
        callsByConversation.removeValue(forKey: id)
    }

    public func setDisappearingTimer(id: ConversationID, seconds: Int?) async throws {
        guard var c = conversationsByID[id] else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        if let seconds, seconds <= 0 {
            throw AegisStoreError.invalidArgument("timer must be positive")
        }
        c.disappearingTimerSeconds = seconds
        c.updatedAt = Date()
        conversationsByID[id] = c
    }

    public func setNetworkPolicy(id: ConversationID, policy: NetworkPolicy) async throws {
        guard var c = conversationsByID[id] else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        // Vault chats can never leave local-only: fail closed.
        if c.kind == .vault, policy != .localOnly {
            throw AegisStoreError.invalidArgument("vault chats are always local-only")
        }
        c.networkPolicy = policy
        c.updatedAt = Date()
        conversationsByID[id] = c
    }

    public func markRead(id: ConversationID, upTo messageID: MessageID) async throws {
        guard var c = conversationsByID[id] else {
            throw AegisStoreError.notFound("conversation \(id)")
        }
        c.lastReadMessageID = messageID
        c.unreadCount = 0
        c.updatedAt = Date()
        conversationsByID[id] = c
    }

    // MARK: - MessageRepository

    public func insert(_ message: Message) async throws {
        guard messagesByID[message.id] == nil else {
            throw AegisStoreError.conflict("message \(message.id) exists")
        }
        guard conversationsByID[message.conversationID] != nil else {
            throw AegisStoreError.invalidArgument(
                "conversation \(message.conversationID) does not exist")
        }
        if message.kind == .text, (message.text ?? "").isEmpty,
            message.attachmentIDs.isEmpty
        {
            throw AegisStoreError.invalidArgument("message has no content")
        }
        messagesByID[message.id] = message
        var order = messageOrder[message.conversationID] ?? []
        order.insert(message.id, at: 0)
        messageOrder[message.conversationID] = order
        // Bump conversation preview + unread for incoming.
        if var c = conversationsByID[message.conversationID] {
            c.lastMessageID = message.id
            c.updatedAt = message.createdAt
            if message.direction == .incoming { c.unreadCount += 1 }
            conversationsByID[c.id] = c
        }
    }

    public func exists(id: MessageID) async throws -> Bool {
        messagesByID[id] != nil
    }

    public func fetch(id: MessageID) async throws -> Message? {
        messagesByID[id]
    }

    public func list(
        in conversationID: ConversationID,
        limit: Int,
        before: MessageID?
    ) async throws -> MessagePage {
        guard limit > 0 else {
            throw AegisStoreError.invalidArgument("limit must be positive")
        }
        var ids = messageOrder[conversationID] ?? []
        if let before, let idx = ids.firstIndex(of: before) {
            ids = Array(ids.dropFirst(idx + 1))
        }
        let page = Array(ids.prefix(limit))
        return MessagePage(
            messages: page.compactMap { messagesByID[$0] },
            hasMore: ids.count > limit
        )
    }

    public func update(_ message: Message) async throws {
        guard messagesByID[message.id] != nil else {
            throw AegisStoreError.notFound("message \(message.id)")
        }
        messagesByID[message.id] = message
    }

    public func applyTombstone(id: MessageID, at: Date) async throws {
        guard var m = messagesByID[id] else {
            throw AegisStoreError.notFound("message \(id)")
        }
        // Delete attachment ciphertext metadata first (the caller destroys
        // the Keychain data keys via keychainKeyID — keys never live in the DB).
        for attachmentID in attachmentsByMessage[id] ?? [] {
            attachmentsByID.removeValue(forKey: attachmentID)
        }
        attachmentsByMessage.removeValue(forKey: id)
        m.isTombstone = true
        m.tombstonedAt = at
        m.text = nil
        m.poll = nil
        m.attachmentIDs = []
        m.updatedAt = at
        messagesByID[id] = m
    }

    public func search(
        query: String,
        in conversationID: ConversationID?,
        limit: Int
    ) async throws -> [Message] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return [] }
        var candidates = messagesByID.values.filter {
            !$0.isTombstone && $0.disappearAt == nil
        }
        if let conversationID {
            candidates = candidates.filter { $0.conversationID == conversationID }
        }
        let now = Date()
        let hits = candidates.filter { m in
            if let disappearAt = m.disappearAt, disappearAt <= now { return false }
            // Voice-note transcriptions are searchable alongside message text.
            let transcriptionText = (attachmentsByMessage[m.id] ?? [])
                .compactMap { attachmentsByID[$0]?.transcription }
                .joined(separator: " ")
            let haystacks = [m.text, transcriptionText]
            return haystacks.compactMap { $0 }.joined(separator: " ")
                .lowercased().contains(q)
        }
        return hits.sorted { $0.createdAt > $1.createdAt }.prefix(limit).map { $0 }
    }

    public func expungeDisappeared(now: Date) async throws -> Int {
        let expired = messagesByID.values.filter {
            !$0.isTombstone && ($0.disappearAt.map { $0 <= now } ?? false)
        }
        for m in expired {
            // Full wipe: content, attachments, ordering entry.
            for attachmentID in attachmentsByMessage[m.id] ?? [] {
                attachmentsByID.removeValue(forKey: attachmentID)
            }
            attachmentsByMessage.removeValue(forKey: m.id)
            messagesByID.removeValue(forKey: m.id)
            messageOrder[m.conversationID]?.removeAll { $0 == m.id }
        }
        return expired.count
    }

    public func pendingOutbox(now: Date) async throws -> [Message] {
        messagesByID.values
            .filter { m in
                guard m.direction == .outgoing, !m.isTombstone,
                    m.deliveryState == .queued || m.deliveryState == .failed
                else { return false }
                // Scheduled messages stay out of the outbox until fire time.
                if let fire = m.scheduledFor { return fire <= now }
                return true
            }
            .sorted { $0.createdAt < $1.createdAt }
    }

    public func setDeliveryState(id: MessageID, state: DeliveryState) async throws {
        guard var m = messagesByID[id] else {
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
        messagesByID[id] = m
    }

    public func setReaction(id: MessageID, emoji: String?, userID: UserID) async throws {
        guard var m = messagesByID[id] else {
            throw AegisStoreError.notFound("message \(id)")
        }
        m.reactions.removeAll { $0.userID == userID }
        if let emoji {
            m.reactions.append(Reaction(emoji: emoji, userID: userID))
        }
        m.updatedAt = Date()
        messagesByID[id] = m
    }

    // MARK: - ContactRepository

    public func upsert(_ contact: Contact) async throws {
        contactsByID[contact.id] = contact
    }

    public func fetch(id: UserID) async throws -> Contact? {
        contactsByID[id]
    }

    public func list(includeBlocked: Bool) async throws -> [Contact] {
        contactsByID.values
            .filter { includeBlocked || !$0.isBlocked }
            .sorted {
                if $0.isFavorite != $1.isFavorite { return $0.isFavorite }
                return $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
                    == .orderedAscending
            }
    }

    public func delete(id: UserID) async throws {
        guard contactsByID.removeValue(forKey: id) != nil else {
            throw AegisStoreError.notFound("contact \(id)")
        }
    }

    public func setVerificationState(id: UserID, state: VerificationState) async throws {
        guard var c = contactsByID[id] else {
            throw AegisStoreError.notFound("contact \(id)")
        }
        c.verificationState = state
        c.verifiedAt = (state == .verified) ? Date() : c.verifiedAt
        c.updatedAt = Date()
        contactsByID[id] = c
    }

    public func setBlocked(id: UserID, blocked: Bool) async throws {
        guard var c = contactsByID[id] else {
            throw AegisStoreError.notFound("contact \(id)")
        }
        c.isBlocked = blocked
        c.updatedAt = Date()
        contactsByID[id] = c
    }

    // MARK: - GroupMembershipRepository

    public func upsert(_ membership: GroupMembership) async throws {
        var members = membershipsByConversation[membership.conversationID] ?? [:]
        members[membership.userID] = membership
        membershipsByConversation[membership.conversationID] = members
    }

    public func remove(conversationID: ConversationID, userID: UserID) async throws {
        guard membershipsByConversation[conversationID]?.removeValue(forKey: userID) != nil else {
            throw AegisStoreError.notFound(
                "membership \(userID) in \(conversationID)")
        }
    }

    public func members(of conversationID: ConversationID) async throws -> [GroupMembership] {
        Array((membershipsByConversation[conversationID] ?? [:]).values)
            .sorted { $0.joinedAt < $1.joinedAt }
    }

    public func role(
        of userID: UserID,
        in conversationID: ConversationID
    ) async throws -> MemberRole? {
        membershipsByConversation[conversationID]?[userID]?.role
    }

    public func setRole(
        conversationID: ConversationID,
        userID: UserID,
        role: MemberRole
    ) async throws {
        guard var m = membershipsByConversation[conversationID]?[userID] else {
            throw AegisStoreError.notFound(
                "membership \(userID) in \(conversationID)")
        }
        m.role = role
        m.updatedAt = Date()
        membershipsByConversation[conversationID]?[userID] = m
    }

    public func conversations(containing userID: UserID) async throws -> [ConversationID] {
        membershipsByConversation.compactMap { conversationID, members in
            members[userID] != nil ? conversationID : nil
        }
    }

    // MARK: - AttachmentRepository

    public func insert(_ attachment: Attachment) async throws {
        guard attachmentsByID[attachment.id] == nil else {
            throw AegisStoreError.conflict("attachment \(attachment.id) exists")
        }
        attachmentsByID[attachment.id] = attachment
        var ids = attachmentsByMessage[attachment.messageID] ?? []
        ids.append(attachment.id)
        attachmentsByMessage[attachment.messageID] = ids
    }

    public func fetch(id: AttachmentID) async throws -> Attachment? {
        attachmentsByID[id]
    }

    public func list(for messageID: MessageID) async throws -> [Attachment] {
        (attachmentsByMessage[messageID] ?? []).compactMap { attachmentsByID[$0] }
    }

    public func update(_ attachment: Attachment) async throws {
        guard attachmentsByID[attachment.id] != nil else {
            throw AegisStoreError.notFound("attachment \(attachment.id)")
        }
        attachmentsByID[attachment.id] = attachment
    }

    public func setTransferState(id: AttachmentID, state: TransferState) async throws {
        guard var a = attachmentsByID[id] else {
            throw AegisStoreError.notFound("attachment \(id)")
        }
        a.transferState = state
        a.updatedAt = Date()
        attachmentsByID[id] = a
    }

    public func recordProgress(id: AttachmentID, bytesTransferred: Int64) async throws {
        guard var a = attachmentsByID[id] else {
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
        attachmentsByID[id] = a
    }

    public func delete(id: AttachmentID) async throws {
        guard let a = attachmentsByID.removeValue(forKey: id) else {
            throw AegisStoreError.notFound("attachment \(id)")
        }
        attachmentsByMessage[a.messageID]?.removeAll { $0 == id }
    }

    // MARK: - CallRecordRepository

    public func insert(_ record: CallRecord) async throws {
        guard callsByID[record.id] == nil else {
            throw AegisStoreError.conflict("call \(record.id) exists")
        }
        callsByID[record.id] = record
        var ids = callsByConversation[record.conversationID] ?? []
        ids.insert(record.id, at: 0)
        callsByConversation[record.conversationID] = ids
    }

    public func fetch(id: CallID) async throws -> CallRecord? {
        callsByID[id]
    }

    public func list(in conversationID: ConversationID, limit: Int) async throws -> [CallRecord] {
        Array((callsByConversation[conversationID] ?? []).prefix(max(0, limit)))
            .compactMap { callsByID[$0] }
    }

    public func update(_ record: CallRecord) async throws {
        guard callsByID[record.id] != nil else {
            throw AegisStoreError.notFound("call \(record.id)")
        }
        callsByID[record.id] = record
    }

    public func delete(id: CallID) async throws {
        guard let record = callsByID.removeValue(forKey: id) else { return }
        callsByConversation[record.conversationID]?.removeAll { $0 == id }
    }

    public func setRecordingConsent(
        callID: CallID,
        userID: UserID,
        consented: Bool
    ) async throws {
        guard var r = callsByID[callID] else {
            throw AegisStoreError.notFound("call \(callID)")
        }
        r.recordingConsent[userID] = consented
        callsByID[callID] = r
    }
}

// MARK: - SessionRepository

extension InMemoryAegisStore {
    public func save(fingerprint: String, snapshot: Data) async throws {
        sessionsByFingerprint[fingerprint] = snapshot
    }

    public func load(fingerprint: String) async throws -> Data? {
        sessionsByFingerprint[fingerprint]
    }

    public func loadAll() async throws -> [String: Data] {
        sessionsByFingerprint
    }

    public func delete(fingerprint: String) async throws {
        sessionsByFingerprint.removeValue(forKey: fingerprint)
    }

    public func deleteAll() async throws {
        sessionsByFingerprint.removeAll()
    }
}

// MARK: - GroupSessionRepository

extension InMemoryAegisStore {
    public func save(groupID: String, snapshot: Data) async throws {
        groupSessionsByID[groupID] = snapshot
    }

    public func loadAll() async throws -> [String: Data] {
        groupSessionsByID
    }

    public func delete(groupID: String) async throws {
        groupSessionsByID.removeValue(forKey: groupID)
    }

    public func deleteAll() async throws {
        groupSessionsByID.removeAll()
    }
}

// MARK: - AttachmentContextRepository

extension InMemoryAegisStore {
    public func save(keyHash: String, groupID: Data?, peer: Data?) async throws {
        attachmentContextsByHash[keyHash] = (groupID, peer)
    }

    public func load(keyHash: String) async throws -> (groupID: Data?, peer: Data?)? {
        attachmentContextsByHash[keyHash]
    }

    public func deleteAll() async throws {
        attachmentContextsByHash.removeAll()
    }
}
