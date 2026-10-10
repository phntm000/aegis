// AegisStoreTests — SQLCipher adapter tests.
//
// These run the behavioral contract against a real temp-file SQLCipher
// database, plus the encryption-specific guarantees:
//  - the build really is SQLCipher (cipher_version guard, §6.8)
//  - wrong key fails closed with .encryptionUnavailable
//  - data survives close/reopen (the Phase 1 persistence requirement)
//  - cascade deletes, FTS search, expunge, transactions, snapshot/restore
//
// The in-memory suite (AegisStoreTests.swift) remains the fast contract
// reference; this suite proves the production adapter honors it.

import XCTest
@testable import AegisStore

final class SQLCipherStoreTests: XCTestCase {

    /// Deterministic 32-byte test key (never the production Keychain path).
    private var testKey: [UInt8] { Array(0..<32).map { UInt8($0) } }
    private var wrongKey: [UInt8] { Array(0..<32).map { UInt8(255 - $0) } }

    private var dbPath: String!
    private var store: SQLCipherAegisStore!

    override func setUp() async throws {
        dbPath = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("db").path
        store = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
    }

    override func tearDown() async throws {
        store = nil
        if let dbPath {
            try? FileManager.default.removeItem(atPath: dbPath)
            try? FileManager.default.removeItem(atPath: dbPath + "-wal")
            try? FileManager.default.removeItem(atPath: dbPath + "-shm")
            try? FileManager.default.removeItem(atPath: dbPath + "-journal")
        }
    }

    // MARK: - Helpers

    private func makeConversation(
        kind: ConversationKind = .direct,
        title: String = "Test"
    ) async throws -> Conversation {
        let c = Conversation(kind: kind, title: title)
        try await store.conversations.create(c)
        return c
    }

    private func makeMessage(
        in conversationID: ConversationID,
        text: String = "hello",
        direction: MessageDirection = .outgoing,
        kind: MessageKind = .text
    ) async throws -> Message {
        let m = Message(
            conversationID: conversationID,
            direction: direction,
            kind: kind,
            text: text
        )
        try await store.messages.insert(m)
        return m
    }

    private func reopen() async throws -> SQLCipherAegisStore {
        store = nil // close the handle
        return try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
    }

    // MARK: - Encryption guarantees

    func testCipherVersionIsSQLCipher() async throws {
        let version = try await store.cipherVersionForDiagnostics()
        XCTAssertFalse(version.isEmpty, "expected a SQLCipher build string")
    }

    func testWrongKeyFailsClosed() async throws {
        let c = try await makeConversation(title: "secret")
        _ = try await makeMessage(in: c.id, text: "classified")
        store = nil // close

        await XCTAssertThrowsErrorAsync(
            try SQLCipherAegisStore.openForTesting(at: dbPath, key: wrongKey)
        ) { error in
            guard let storeError = error as? AegisStoreError,
                  case .encryptionUnavailable = storeError else {
                XCTFail("expected .encryptionUnavailable, got \(error)")
                return
            }
        }

        // The file must still open fine with the right key afterwards.
        let reopened = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
        let fetched = try await reopened.conversations.fetch(id: c.id)
        XCTAssertEqual(fetched?.title, "secret")
    }

    func testDataSurvivesCloseAndReopen() async throws {
        let c = try await makeConversation(title: "persist me")
        let m = try await makeMessage(in: c.id, text: "survive restart", direction: .incoming)
        let contact = Contact(
            id: UserID("user-1"), displayName: "Ada",
            identityKeyFingerprint: "ab12")
        try await store.contacts.upsert(contact)

        let reopened = try await reopen()

        let reopenedTitle = try await reopened.conversations.fetch(id: c.id)?.title
        XCTAssertEqual(reopenedTitle, "persist me")
        let reopenedText = try await reopened.messages.fetch(id: m.id)?.text
        XCTAssertEqual(reopenedText, "survive restart")
        let reopenedUnread = try await reopened.conversations.fetch(id: c.id)?.unreadCount
        XCTAssertEqual(reopenedUnread, 1)
        let reopenedName = try await reopened.contacts.fetch(id: contact.id)?.displayName
        XCTAssertEqual(reopenedName, "Ada")
    }

    // MARK: - Contract: conversations

    func testCreateDuplicateConversationConflicts() async throws {
        let c = try await makeConversation()
        await XCTAssertThrowsErrorAsync(
            try await store.conversations.create(c)
        ) { error in
            XCTAssertEqual(error as? AegisStoreError,
                           .conflict("conversation \(c.id) exists"))
        }
    }

    func testListSortsPinnedFirstThenRecency() async throws {
        let a = try await makeConversation(title: "a")
        var b = try await makeConversation(title: "b")
        b.isPinned = true
        try await store.conversations.update(b)
        let list = try await store.conversations.list(
            includeArchived: true, kind: nil, query: nil)
        XCTAssertEqual(list.first?.id, b.id)
        XCTAssertEqual(list.last?.id, a.id)
    }

    func testVaultPolicyCannotChange() async throws {
        let v = try await makeConversation(kind: .vault, title: "vault")
        await XCTAssertThrowsErrorAsync(
            try await store.conversations.setNetworkPolicy(id: v.id, policy: .default)
        ) { error in
            XCTAssertEqual(error as? AegisStoreError,
                           .invalidArgument("vault chats are always local-only"))
        }
    }

    func testMarkReadZeroesUnread() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id, direction: .incoming)
        let unreadBefore = try await store.conversations.fetch(id: c.id)?.unreadCount
        XCTAssertEqual(unreadBefore, 1)
        try await store.conversations.markRead(id: c.id, upTo: m.id)
        let after = try await store.conversations.fetch(id: c.id)
        XCTAssertEqual(after?.unreadCount, 0)
        XCTAssertEqual(after?.lastReadMessageID, m.id)
    }

    // MARK: - Contract: messages

    func testInsertDuplicateMessageConflicts() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id)
        await XCTAssertThrowsErrorAsync(
            try await store.messages.insert(m)
        ) { error in
            XCTAssertEqual(error as? AegisStoreError,
                           .conflict("message \(m.id) exists"))
        }
    }

    func testInsertIntoMissingConversationIsInvalidArgument() async throws {
        let m = Message(conversationID: ConversationID("nope"),
                        direction: .outgoing, text: "x")
        await XCTAssertThrowsErrorAsync(
            try await store.messages.insert(m)
        ) { error in
            if case .invalidArgument = error as? AegisStoreError { return }
            XCTFail("expected .invalidArgument, got \(error)")
        }
    }

    func testMessagePagination() async throws {
        let c = try await makeConversation()
        var ids: [MessageID] = []
        for i in 0..<5 {
            let m = try await makeMessage(in: c.id, text: "m\(i)")
            ids.append(m.id)
        }
        // Newest first.
        let page1 = try await store.messages.list(in: c.id, limit: 2, before: nil)
        XCTAssertEqual(page1.messages.map(\.id), [ids[4], ids[3]])
        XCTAssertTrue(page1.hasMore)
        let page2 = try await store.messages.list(in: c.id, limit: 2, before: ids[3])
        XCTAssertEqual(page2.messages.map(\.id), [ids[2], ids[1]])
        XCTAssertTrue(page2.hasMore)
        let page3 = try await store.messages.list(in: c.id, limit: 2, before: ids[1])
        XCTAssertEqual(page3.messages.map(\.id), [ids[0]])
        XCTAssertFalse(page3.hasMore)
    }

    func testDeliveryStateTerminalGuard() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id)
        try await store.messages.setDeliveryState(id: m.id, state: .read)
        await XCTAssertThrowsErrorAsync(
            try await store.messages.setDeliveryState(id: m.id, state: .queued)
        ) { error in
            if case .invalidArgument = error as? AegisStoreError { return }
            XCTFail("expected .invalidArgument, got \(error)")
        }
        let readAt = try await store.messages.fetch(id: m.id)?.readAt
        XCTAssertNotNil(readAt)
    }

    func testReactions() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id)
        let user = UserID("u1")
        try await store.messages.setReaction(id: m.id, emoji: "👍", userID: user)
        var fetched = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(fetched?.reactions.count, 1)
        // Re-setting replaces, nil removes.
        try await store.messages.setReaction(id: m.id, emoji: "❤️", userID: user)
        fetched = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(fetched?.reactions.map(\.emoji), ["❤️"])
        try await store.messages.setReaction(id: m.id, emoji: nil, userID: user)
        fetched = try await store.messages.fetch(id: m.id)
        XCTAssertTrue(fetched?.reactions.isEmpty ?? false)
    }

    func testTombstoneWipesContent() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id, text: "delete me")
        try await store.messages.applyTombstone(id: m.id, at: Date())
        let fetched = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(fetched?.isTombstone, true)
        XCTAssertNil(fetched?.text)
        // Tombstones are excluded from search.
        let tombstoneHits = try await store.messages.search(
            query: "delete me", in: nil, limit: 10)
        XCTAssertTrue(tombstoneHits.isEmpty)
    }

    func testPendingOutboxOrdering() async throws {
        let c = try await makeConversation()
        let m1 = try await makeMessage(in: c.id, text: "first")
        let m2 = try await makeMessage(in: c.id, text: "second")
        try await store.messages.setDeliveryState(id: m1.id, state: .sent)
        // m1 is sent; m2 is still .queued so it remains pending.
        let outbox = try await store.messages.pendingOutbox(now: Date())
        XCTAssertEqual(outbox.map(\.id), [m2.id])
        // Scheduled messages stay out until fire time.
        var future = Message(conversationID: c.id, direction: .outgoing,
                             text: "later",
                             scheduledFor: Date().addingTimeInterval(3600))
        try await store.messages.insert(future)
        let scheduledOutbox = try await store.messages.pendingOutbox(now: Date())
        XCTAssertEqual(scheduledOutbox.map(\.id), [m2.id])
        future.scheduledFor = Date().addingTimeInterval(-1)
        try await store.messages.update(future)
        let due = try await store.messages.pendingOutbox(now: Date())
        XCTAssertTrue(due.contains(where: { $0.id == future.id }))
    }

    // MARK: - Search (FTS5 inside the encrypted DB)

    func testSearchFindsTextAndTranscriptions() async throws {
        let c = try await makeConversation()
        _ = try await makeMessage(in: c.id, text: "the quick brown fox")
        _ = try await makeMessage(in: c.id, text: "unrelated chatter")

        let msgWithVoice = try await makeMessage(in: c.id, text: "", kind: .voiceNote)
        let attachment = Attachment(
            messageID: msgWithVoice.id, conversationID: c.id,
            kind: .voiceNote, fileName: "note.m4a", mimeType: "audio/mp4",
            byteCount: 10, chunkCount: 1, keychainKeyID: "k1",
            transcription: "remember to buy milk")
        try await store.attachments.insert(attachment)

        let hits = try await store.messages.search(query: "quick brown", in: nil, limit: 10)
        XCTAssertEqual(hits.count, 1)
        XCTAssertEqual(hits.first?.text, "the quick brown fox")

        let voiceHits = try await store.messages.search(query: "buy milk", in: nil, limit: 10)
        XCTAssertEqual(voiceHits.count, 1)

        // Scoped search.
        let other = try await makeConversation(title: "other")
        _ = try await makeMessage(in: other.id, text: "quick brown elsewhere")
        let scoped = try await store.messages.search(
            query: "quick brown", in: c.id, limit: 10)
        XCTAssertEqual(scoped.count, 1)
    }

    func testSearchExcludesExpired() async throws {
        let c = try await makeConversation()
        let m = Message(conversationID: c.id, direction: .outgoing,
                        text: "ephemeral secret",
                        disappearAt: Date().addingTimeInterval(-5))
        try await store.messages.insert(m)
        let expiredHits = try await store.messages.search(
            query: "ephemeral", in: nil, limit: 10)
        XCTAssertTrue(expiredHits.isEmpty)
    }

    // MARK: - Expunge

    func testExpungeRemovesRowsAndFTSEntries() async throws {
        let c = try await makeConversation()
        let expired = Message(conversationID: c.id, direction: .outgoing,
                              text: "burn after reading",
                              disappearAt: Date().addingTimeInterval(-60))
        try await store.messages.insert(expired)
        _ = try await makeMessage(in: c.id, text: "keep me")

        let wiped = try await store.messages.expungeDisappeared(now: Date())
        XCTAssertEqual(wiped, 1)
        let expunged = try await store.messages.fetch(id: expired.id)
        XCTAssertNil(expunged)
        let burnHits = try await store.messages.search(
            query: "burn after", in: nil, limit: 10)
        XCTAssertTrue(burnHits.isEmpty)
        // Survivor untouched.
        let keepHits = try await store.messages.search(
            query: "keep me", in: nil, limit: 10)
        XCTAssertEqual(keepHits.count, 1)
    }

    // MARK: - Cascade deletes

    func testDeleteConversationCascades() async throws {
        let c = try await makeConversation(title: "doomed")
        let m = try await makeMessage(in: c.id, text: "x")
        let attachment = Attachment(
            messageID: m.id, conversationID: c.id, kind: .file,
            fileName: "f.bin", mimeType: "application/octet-stream",
            byteCount: 5, chunkCount: 1, keychainKeyID: "k2")
        try await store.attachments.insert(attachment)
        try await store.memberships.upsert(GroupMembership(
            conversationID: c.id, userID: UserID("u9")))
        try await store.calls.insert(CallRecord(
            conversationID: c.id, kind: .audio, direction: .outgoing))

        try await store.conversations.delete(id: c.id)

        let deletedConversation = try await store.conversations.fetch(id: c.id)
        XCTAssertNil(deletedConversation)
        let deletedMessage = try await store.messages.fetch(id: m.id)
        XCTAssertNil(deletedMessage)
        let deletedAttachment = try await store.attachments.fetch(id: attachment.id)
        XCTAssertNil(deletedAttachment)
        let remainingMembers = try await store.memberships.members(of: c.id)
        XCTAssertTrue(remainingMembers.isEmpty)
        let remainingCalls = try await store.calls.list(in: c.id, limit: 10)
        XCTAssertTrue(remainingCalls.isEmpty)
    }

    // MARK: - Contacts / memberships / attachments / calls

    func testContactVerificationFlow() async throws {
        let contact = Contact(id: UserID("u1"), displayName: "Zed",
                              identityKeyFingerprint: "ff00")
        try await store.contacts.upsert(contact)
        try await store.contacts.setVerificationState(id: contact.id, state: .verified)
        var fetched = try await store.contacts.fetch(id: contact.id)
        XCTAssertEqual(fetched?.verificationState, .verified)
        XCTAssertNotNil(fetched?.verifiedAt)
        try await store.contacts.setBlocked(id: contact.id, blocked: true)
        fetched = try await store.contacts.fetch(id: contact.id)
        XCTAssertEqual(fetched?.isBlocked, true)
        let visibleContacts = try await store.contacts.list(includeBlocked: false)
        XCTAssertTrue(visibleContacts.isEmpty)
        let allContacts = try await store.contacts.list(includeBlocked: true)
        XCTAssertEqual(allContacts.count, 1)
    }

    func testMembershipRoles() async throws {
        let c = try await makeConversation(kind: .group)
        let user = UserID("member-1")
        try await store.memberships.upsert(GroupMembership(
            conversationID: c.id, userID: user, role: .member))
        let roleAfterUpsert = try await store.memberships.role(of: user, in: c.id)
        XCTAssertEqual(roleAfterUpsert, .member)
        try await store.memberships.setRole(
            conversationID: c.id, userID: user, role: .admin)
        let roleAfterPromote = try await store.memberships.role(of: user, in: c.id)
        XCTAssertEqual(roleAfterPromote, .admin)
        let containingConversations = try await store.memberships.conversations(containing: user)
        XCTAssertEqual(containingConversations, [c.id])
        try await store.memberships.remove(conversationID: c.id, userID: user)
        let roleAfterRemove = try await store.memberships.role(of: user, in: c.id)
        XCTAssertNil(roleAfterRemove)
    }

    func testAttachmentProgressClampsAndCompletes() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id, text: "", kind: .attachment)
        let attachment = Attachment(
            messageID: m.id, conversationID: c.id, kind: .image,
            fileName: "p.png", mimeType: "image/png",
            byteCount: 100, chunkCount: 1, keychainKeyID: "k3")
        try await store.attachments.insert(attachment)
        try await store.attachments.recordProgress(id: attachment.id, bytesTransferred: 150)
        let fetched = try await store.attachments.fetch(id: attachment.id)
        XCTAssertEqual(fetched?.bytesTransferred, 100)
        XCTAssertEqual(fetched?.transferState, .complete)
        await XCTAssertThrowsErrorAsync(
            try await store.attachments.recordProgress(
                id: attachment.id, bytesTransferred: -1)
        ) { error in
            if case .invalidArgument = error as? AegisStoreError { return }
            XCTFail("expected .invalidArgument, got \(error)")
        }
    }

    func testCallRecordConsent() async throws {
        let c = try await makeConversation()
        let user = UserID("caller")
        let record = CallRecord(conversationID: c.id, kind: .video,
                                direction: .outgoing, participants: [user])
        try await store.calls.insert(record)
        try await store.calls.setRecordingConsent(
            callID: record.id, userID: user, consented: true)
        let fetched = try await store.calls.fetch(id: record.id)
        XCTAssertEqual(fetched?.recordingConsent[user], true)
        XCTAssertTrue(fetched?.allPartiesConsentedToRecording ?? false)
        let callList = try await store.calls.list(in: c.id, limit: 5)
        XCTAssertEqual(callList.count, 1)
    }

    // MARK: - Transactions

    func testTransactionRollsBackOnError() async throws {
        let c = try await makeConversation()
        let db = store!
        struct Boom: Error {}
        do {
            try await db.transaction {
                let doomed = Message(conversationID: c.id,
                                     direction: .outgoing, text: "doomed")
                try await db.messages.insert(doomed)
                throw Boom()
            }
            XCTFail("expected throw")
        } catch is Boom { /* expected */ }
        let page = try await db.messages.list(in: c.id, limit: 10, before: nil)
        XCTAssertTrue(page.messages.isEmpty)
    }

    func testNestedTransactionsFlatten() async throws {
        let c = try await makeConversation()
        let db = store!
        try await db.transaction {
            let outer = Message(conversationID: c.id,
                                direction: .outgoing, text: "outer")
            try await db.messages.insert(outer)
            try await db.transaction {
                let inner = Message(conversationID: c.id,
                                    direction: .outgoing, text: "inner")
                try await db.messages.insert(inner)
            }
        }
        let page = try await db.messages.list(in: c.id, limit: 10, before: nil)
        XCTAssertEqual(page.messages.count, 2)
    }

    // MARK: - Snapshot / restore

    func testSnapshotRestoreRoundTrip() async throws {
        let c = try await makeConversation(title: "backup")
        _ = try await makeMessage(in: c.id, text: "saved")
        let snapshot = try await store.snapshot()
        XCTAssertEqual(snapshot.conversations.count, 1)

        // Wipe and restore into a fresh database.
        let path2 = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("db").path
        defer { try? FileManager.default.removeItem(atPath: path2) }
        let fresh = try SQLCipherAegisStore.openForTesting(at: path2, key: testKey)
        try await fresh.restore(snapshot)
        let restoredTitle = try await fresh.conversations.fetch(id: c.id)?.title
        XCTAssertEqual(restoredTitle, "backup")
        let restoredHits = try await fresh.messages.search(
            query: "saved", in: nil, limit: 10)
        XCTAssertEqual(restoredHits.count, 1)

        await XCTAssertThrowsErrorAsync(
            try await fresh.restore(StoreSnapshot(
                version: StoreSnapshot.currentVersion + 1))
        ) { error in
            if case .invalidArgument = error as? AegisStoreError { return }
            XCTFail("expected .invalidArgument, got \(error)")
        }
    }

    // MARK: - Ratchet sessions

    func testSessionSaveLoadRoundTrip() async throws {
        let fp = String(repeating: "ab", count: 32)
        let blob = Data("opaque-snapshot-bytes".utf8)
        try await store.sessions.save(fingerprint: fp, snapshot: blob)
        let loaded = try await store.sessions.load(fingerprint: fp)
        XCTAssertEqual(loaded, blob)
        let missing = try await store.sessions.load(fingerprint: String(repeating: "cd", count: 32))
        XCTAssertNil(missing)
    }

    func testSessionSaveOverwrites() async throws {
        let fp = String(repeating: "ab", count: 32)
        try await store.sessions.save(fingerprint: fp, snapshot: Data([0x01]))
        try await store.sessions.save(fingerprint: fp, snapshot: Data([0x02]))
        let loaded = try await store.sessions.load(fingerprint: fp)
        XCTAssertEqual(loaded, Data([0x02]))
    }

    func testSessionLoadAllAndDelete() async throws {
        let fp1 = String(repeating: "aa", count: 32)
        let fp2 = String(repeating: "bb", count: 32)
        try await store.sessions.save(fingerprint: fp1, snapshot: Data([0x01]))
        try await store.sessions.save(fingerprint: fp2, snapshot: Data([0x02]))
        let all = try await store.sessions.loadAll()
        XCTAssertEqual(all.count, 2)
        XCTAssertEqual(all[fp1], Data([0x01]))

        try await store.sessions.delete(fingerprint: fp1)
        let deleted = try await store.sessions.load(fingerprint: fp1)
        XCTAssertNil(deleted)
        let remaining = try await store.sessions.loadAll()
        XCTAssertEqual(remaining.count, 1)

        try await store.sessions.deleteAll()
        let empty = try await store.sessions.loadAll()
        XCTAssertTrue(empty.isEmpty)
    }

    /// Sessions survive close/reopen — the durability contract Fix 2 needs.
    /// Also proves the v2 migration ran on a fresh database.
    func testSessionsSurviveReopen() async throws {
        let fp = String(repeating: "ef", count: 32)
        let blob = Data("durable".utf8)
        try await store.sessions.save(fingerprint: fp, snapshot: blob)

        let reopened = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
        let loaded = try await reopened.sessions.load(fingerprint: fp)
        XCTAssertEqual(loaded, blob)
    }

    /// A v1 database (no ratchet_session table, user_version=1) migrates
    /// cleanly to v2 on the next open: the table is created and usable.
    func testV1ToV2Migration() async throws {
        // Start at v2 with data, then downgrade the on-disk state to v1.
        try await store.sessions.save(fingerprint: "aa", snapshot: Data([0x01]))
        let conn = await store.conn
        try conn.exec("DROP TABLE ratchet_session;")
        try conn.exec("DELETE FROM schema_migrations WHERE version = 2;")
        try conn.exec("PRAGMA user_version = 1;")
        store = nil // release the old connection before reopening

        // Reopening must re-apply the v2 migration cleanly.
        let migrated = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
        store = migrated
        let afterMigration = try await migrated.sessions.loadAll()
        XCTAssertTrue(afterMigration.isEmpty)
        try await migrated.sessions.save(fingerprint: "aa", snapshot: Data([0x02]))
        let loaded = try await migrated.sessions.load(fingerprint: "aa")
        XCTAssertEqual(loaded, Data([0x02]))
    }

    /// Group sessions and attachment contexts survive close/reopen, and the
    /// v3 tables exist on a fresh database.
    func testGroupSessionsAndAttachmentContextsSurviveReopen() async throws {
        let gid = String(repeating: "ab", count: 32)
        try await store.groupSessions.saveGroupSession(groupID: gid, snapshot: Data("group-snap".utf8))
        try await store.attachmentContexts.saveAttachmentContext(
            keyHash: "deadbeef", groupID: Data(repeating: 0x01, count: 32), peer: nil)

        let reopened = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
        let groups = try await reopened.groupSessions.loadAllGroupSessions()
        XCTAssertEqual(groups[gid], Data("group-snap".utf8))
        let ctx = try await reopened.attachmentContexts.loadAttachmentContext(keyHash: "deadbeef")
        XCTAssertEqual(ctx?.groupID, Data(repeating: 0x01, count: 32))
        XCTAssertNil(ctx?.peer)
        let missingCtx = try await reopened.attachmentContexts.loadAttachmentContext(keyHash: "nope")
        XCTAssertNil(missingCtx)

        // Upsert replaces.
        try await reopened.groupSessions.saveGroupSession(groupID: gid, snapshot: Data("v2".utf8))
        let groups2 = try await reopened.groupSessions.loadAllGroupSessions()
        XCTAssertEqual(groups2[gid], Data("v2".utf8))
        try await reopened.groupSessions.deleteGroupSession(groupID: gid)
        let groupsAfterDelete = try await reopened.groupSessions.loadAllGroupSessions()
        XCTAssertTrue(groupsAfterDelete.isEmpty)
    }

    /// A v2 database (user_version=2, no v3 tables) migrates cleanly to v3.
    func testV2ToV3Migration() async throws {
        try await store.groupSessions.saveGroupSession(groupID: "bb", snapshot: Data([0x01]))
        let conn = await store.conn
        try conn.exec("DROP TABLE group_session;")
        try conn.exec("DROP TABLE attachment_context;")
        try conn.exec("DELETE FROM schema_migrations WHERE version = 3;")
        try conn.exec("PRAGMA user_version = 2;")
        store = nil

        let migrated = try SQLCipherAegisStore.openForTesting(at: dbPath, key: testKey)
        store = migrated
        let migratedGroupsEmpty = try await migrated.groupSessions.loadAllGroupSessions()
        XCTAssertTrue(migratedGroupsEmpty.isEmpty)
        try await migrated.groupSessions.saveGroupSession(groupID: "bb", snapshot: Data([0x02]))
        let loaded = try await migrated.groupSessions.loadAllGroupSessions()
        XCTAssertEqual(loaded["bb"], Data([0x02]))
        try await migrated.attachmentContexts.saveAttachmentContext(keyHash: "k", groupID: nil, peer: Data([0x09]))
        let ctx = try await migrated.attachmentContexts.loadAttachmentContext(keyHash: "k")
        XCTAssertNil(ctx?.groupID)
        XCTAssertEqual(ctx?.peer, Data([0x09]))
    }
}
