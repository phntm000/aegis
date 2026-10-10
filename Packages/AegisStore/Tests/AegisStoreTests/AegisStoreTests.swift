// AegisStoreTests — behavioral contract tests for the store.
//
// These tests run against `InMemoryAegisStore` and define the *contract*
// every AegisStore implementation must satisfy — including the future
// SQLCipher adapter (see Docs/SQLCIPHER.md §6). Keep them green; when the
// SQLCipher adapter lands, point this same suite at it.

import XCTest
@testable import AegisStore

final class AegisStoreTests: XCTestCase {

    var store: InMemoryAegisStore!

    override func setUp() async throws {
        store = InMemoryAegisStore()
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
        sender: UserID? = nil
    ) async throws -> Message {
        let m = Message(
            conversationID: conversationID,
            senderID: sender,
            direction: direction,
            text: text
        )
        try await store.messages.insert(m)
        return m
    }

    // MARK: - Conversations

    func testCreateAndFetchConversation() async throws {
        let created = try await makeConversation(title: "Ops")
        let fetched = try await store.conversations.fetch(id: created.id)
        XCTAssertEqual(fetched?.title, "Ops")
        XCTAssertEqual(fetched?.kind, .direct)
    }

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

    func testListFiltersArchivedAndQuery() async throws {
        var archived = try await makeConversation(title: "Secret project")
        archived.isArchived = true
        try await store.conversations.update(archived)
        _ = try await makeConversation(title: "Lunch plans")

        let noArchived = try await store.conversations.list(
            includeArchived: false, kind: nil, query: nil)
        XCTAssertTrue(noArchived.allSatisfy { !$0.isArchived })

        let queried = try await store.conversations.list(
            includeArchived: true, kind: nil, query: "lunch")
        XCTAssertEqual(queried.count, 1)
    }

    func testVaultChatCannotLeaveLocalOnly() async throws {
        let vault = try await makeConversation(kind: .vault)
        XCTAssertEqual(vault.networkPolicy, .localOnly)
        await XCTAssertThrowsErrorAsync(
            try await store.conversations.setNetworkPolicy(
                id: vault.id, policy: .default)
        ) { error in
            guard case .invalidArgument = error as? AegisStoreError else {
                return XCTFail("expected invalidArgument, got \(error)")
            }
        }
    }

    func testDeleteConversationCascades() async throws {
        let c = try await makeConversation(kind: .group)
        let m = try await makeMessage(in: c.id, text: "bye")
        let att = Attachment(
            messageID: m.id, conversationID: c.id, kind: .file,
            fileName: "a.bin", mimeType: "application/octet-stream",
            byteCount: 10, chunkCount: 1, keychainKeyID: "k1")
        try await store.attachments.insert(att)
        try await store.memberships.upsert(
            GroupMembership(conversationID: c.id, userID: "u1"))
        try await store.calls.insert(
            CallRecord(conversationID: c.id, kind: .audio, direction: .outgoing))

        try await store.conversations.delete(id: c.id)

        let convAfterDelete = try await store.conversations.fetch(id: c.id)
        let msgAfterDelete = try await store.messages.fetch(id: m.id)
        let attAfterDelete = try await store.attachments.fetch(id: att.id)
        let membersAfterDelete = try await store.memberships.members(of: c.id)
        let callsAfterDelete = try await store.calls.list(in: c.id, limit: 10)
        XCTAssertNil(convAfterDelete)
        XCTAssertNil(msgAfterDelete)
        XCTAssertNil(attAfterDelete)
        XCTAssertTrue(membersAfterDelete.isEmpty)
        XCTAssertTrue(callsAfterDelete.isEmpty)
    }

    func testMarkReadClearsUnread() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id, direction: .incoming)
        var after = try await store.conversations.fetch(id: c.id)
        XCTAssertEqual(after?.unreadCount, 1)
        try await store.conversations.markRead(id: c.id, upTo: m.id)
        after = try await store.conversations.fetch(id: c.id)
        XCTAssertEqual(after?.unreadCount, 0)
        XCTAssertEqual(after?.lastReadMessageID, m.id)
    }

    // MARK: - Messages

    func testInsertAndPaginateMessages() async throws {
        let c = try await makeConversation()
        for i in 0..<5 {
            _ = try await makeMessage(in: c.id, text: "m\(i)")
        }
        let page1 = try await store.messages.list(in: c.id, limit: 3, before: nil)
        XCTAssertEqual(page1.messages.count, 3)
        XCTAssertTrue(page1.hasMore)
        XCTAssertEqual(page1.messages.first?.text, "m4") // newest first

        let page2 = try await store.messages.list(
            in: c.id, limit: 3, before: page1.messages.last?.id)
        XCTAssertEqual(page2.messages.count, 2)
        XCTAssertFalse(page2.hasMore)
    }

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

    func testInsertEmptyTextMessageRejected() async throws {
        let c = try await makeConversation()
        let m = Message(conversationID: c.id, direction: .outgoing, text: "")
        await XCTAssertThrowsErrorAsync(
            try await store.messages.insert(m)
        ) { error in
            guard case .invalidArgument = error as? AegisStoreError else {
                return XCTFail("expected invalidArgument")
            }
        }
    }

    func testTombstoneWipesContentPreservesPosition() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id, text: "secret")
        let att = Attachment(
            messageID: m.id, conversationID: c.id, kind: .image,
            fileName: "p.png", mimeType: "image/png",
            byteCount: 100, chunkCount: 1, keychainKeyID: "k9")
        try await store.attachments.insert(att)

        try await store.messages.applyTombstone(id: m.id, at: Date())

        let tomb = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(tomb?.isTombstone, true)
        XCTAssertNil(tomb?.text)
        XCTAssertNotNil(tomb?.tombstonedAt)
        // Position preserved: still listed in conversation order.
        let page = try await store.messages.list(in: c.id, limit: 10, before: nil)
        XCTAssertTrue(page.messages.map(\.id).contains(m.id))
        // Attachment metadata gone (keys destroyed by caller).
        let attAfterDelete2 = try await store.attachments.fetch(id: att.id)
        XCTAssertNil(attAfterDelete2)
    }

    func testSearchFindsTextExcludesTombstones() async throws {
        let c = try await makeConversation()
        _ = try await makeMessage(in: c.id, text: "the renewal quote is 42k")
        let dead = try await makeMessage(in: c.id, text: "renewal canceled")
        try await store.messages.applyTombstone(id: dead.id, at: Date())

        let hits = try await store.messages.search(
            query: "renewal", in: c.id, limit: 10)
        XCTAssertEqual(hits.count, 1)
        XCTAssertTrue(hits.first?.text?.contains("42k") ?? false)
    }

    func testSearchFindsVoiceNoteTranscriptions() async throws {
        let c = try await makeConversation()
        let m = Message(conversationID: c.id, direction: .incoming,
                        kind: .voiceNote)
        try await store.messages.insert(m)
        try await store.attachments.insert(Attachment(
            messageID: m.id, conversationID: c.id, kind: .voiceNote,
            fileName: "note.opus", mimeType: "audio/opus",
            byteCount: 5000, chunkCount: 1, keychainKeyID: "kv",
            transcription: "perimeter check complete at dawn"))

        let hits = try await store.messages.search(
            query: "perimeter", in: nil, limit: 10)
        XCTAssertEqual(hits.count, 1)
        XCTAssertEqual(hits.first?.id, m.id)
    }

    func testExpungeDisappearedWipesExpired() async throws {
        let c = try await makeConversation()
        var gone = Message(conversationID: c.id, direction: .incoming,
                           text: "ephemeral")
        gone.disappearAt = Date().addingTimeInterval(-60)
        try await store.messages.insert(gone)
        _ = try await makeMessage(in: c.id, text: "kept")

        let wiped = try await store.messages.expungeDisappeared(now: Date())
        XCTAssertEqual(wiped, 1)
        let goneAfterDelete = try await store.messages.fetch(id: gone.id)
        XCTAssertNil(goneAfterDelete)
        let remaining = try await store.messages.list(in: c.id, limit: 10, before: nil)
        XCTAssertEqual(remaining.messages.count, 1)
    }

    func testOutboxQueuesAndGatesScheduled() async throws {
        let c = try await makeConversation()
        let now = Date()
        _ = try await makeMessage(in: c.id, text: "now")
        var future = Message(conversationID: c.id, direction: .outgoing,
                             text: "later")
        future.scheduledFor = now.addingTimeInterval(3600)
        try await store.messages.insert(future)
        var past = Message(conversationID: c.id, direction: .outgoing,
                           text: "fired")
        past.scheduledFor = now.addingTimeInterval(-10)
        try await store.messages.insert(past)

        var outbox = try await store.messages.pendingOutbox(now: now)
        XCTAssertEqual(outbox.count, 2) // "now" + "fired"; "later" gated
        XCTAssertFalse(outbox.map(\.text).contains("later"))

        outbox = try await store.messages.pendingOutbox(
            now: now.addingTimeInterval(7200))
        XCTAssertEqual(outbox.count, 3)
    }

    func testDeliveryStateTransitions() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id)
        try await store.messages.setDeliveryState(id: m.id, state: .sent)
        try await store.messages.setDeliveryState(id: m.id, state: .delivered)
        try await store.messages.setDeliveryState(id: m.id, state: .read)
        let done = try await store.messages.fetch(id: m.id)
        XCTAssertNotNil(done?.readAt)
        // Terminal state must not regress to queued.
        await XCTAssertThrowsErrorAsync(
            try await store.messages.setDeliveryState(id: m.id, state: .queued)
        ) { error in
            guard case .invalidArgument = error as? AegisStoreError else {
                return XCTFail("expected invalidArgument")
            }
        }
    }

    func testReactionsAddAndRemove() async throws {
        let c = try await makeConversation()
        let m = try await makeMessage(in: c.id)
        try await store.messages.setReaction(id: m.id, emoji: "👍", userID: "u1")
        try await store.messages.setReaction(id: m.id, emoji: "🔥", userID: "u2")
        var fetched = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(fetched?.reactions.count, 2)
        // Re-reacting replaces; nil removes.
        try await store.messages.setReaction(id: m.id, emoji: "🎉", userID: "u1")
        try await store.messages.setReaction(id: m.id, emoji: nil, userID: "u2")
        fetched = try await store.messages.fetch(id: m.id)
        XCTAssertEqual(fetched?.reactions.count, 1)
        XCTAssertEqual(fetched?.reactions.first?.emoji, "🎉")
    }

    // MARK: - Contacts

    func testContactVerificationLifecycle() async throws {
        let contact = Contact(id: "alice", displayName: "Alice",
                              identityKeyFingerprint: "SHA256:abc123")
        try await store.contacts.upsert(contact)
        try await store.contacts.setVerificationState(
            id: "alice", state: .verified)
        var fetched = try await store.contacts.fetch(id: "alice")
        XCTAssertEqual(fetched?.verificationState, .verified)
        XCTAssertNotNil(fetched?.verifiedAt)
        // Key change → needs re-verification.
        try await store.contacts.setVerificationState(
            id: "alice", state: .changedNeedsReverification)
        fetched = try await store.contacts.fetch(id: "alice")
        XCTAssertEqual(fetched?.verificationState, .changedNeedsReverification)
    }

    func testBlockIsSilentAndLocal() async throws {
        let contact = Contact(id: "spammer", displayName: "Spammer",
                              identityKeyFingerprint: "SHA256:zzz")
        try await store.contacts.upsert(contact)
        try await store.contacts.setBlocked(id: "spammer", blocked: true)
        let visible = try await store.contacts.list(includeBlocked: false)
        XCTAssertFalse(visible.map(\.id).contains("spammer"))
        let all = try await store.contacts.list(includeBlocked: true)
        XCTAssertTrue(all.map(\.id).contains("spammer"))
    }

    // MARK: - Memberships

    func testMembershipRoles() async throws {
        let c = try await makeConversation(kind: .group)
        try await store.memberships.upsert(GroupMembership(
            conversationID: c.id, userID: "owner1", role: .owner))
        try await store.memberships.upsert(GroupMembership(
            conversationID: c.id, userID: "mod1", role: .moderator))

        let ownerRole = try await store.memberships.role(of: "owner1", in: c.id)
        XCTAssertEqual(ownerRole, .owner)
        try await store.memberships.setRole(
            conversationID: c.id, userID: "mod1", role: .admin)
        let modRole = try await store.memberships.role(of: "mod1", in: c.id)
        XCTAssertEqual(modRole, .admin)
        XCTAssertTrue(MemberRole.admin > MemberRole.moderator)

        try await store.memberships.remove(
            conversationID: c.id, userID: "mod1")
        let modRoleAfterRemove = try await store.memberships.role(of: "mod1", in: c.id)
        XCTAssertNil(modRoleAfterRemove)
    }

    func testConversationsContainingUser() async throws {
        let g1 = try await makeConversation(kind: .group)
        let g2 = try await makeConversation(kind: .group)
        try await store.memberships.upsert(
            GroupMembership(conversationID: g1.id, userID: "u9"))
        try await store.memberships.upsert(
            GroupMembership(conversationID: g2.id, userID: "u9"))
        let convos = try await store.memberships.conversations(containing: "u9")
        XCTAssertEqual(Set(convos), [g1.id, g2.id])
    }

    // MARK: - Attachments

    func testAttachmentProgressAndCompletion() async throws {
        let c = try await makeConversation()
        // Pre-assign the attachment ID so the message passes the
        // "has content" validation at insert time.
        let attID: AttachmentID = .generate()
        let m = Message(conversationID: c.id, direction: .outgoing,
                        kind: .attachment, attachmentIDs: [attID])
        try await store.messages.insert(m)
        let att = Attachment(
            id: attID,
            messageID: m.id, conversationID: c.id, kind: .file,
            fileName: "report.pdf", mimeType: "application/pdf",
            byteCount: 1000, chunkCount: 4, keychainKeyID: "k2")
        try await store.attachments.insert(att)

        try await store.attachments.setTransferState(
            id: att.id, state: .downloading)
        try await store.attachments.recordProgress(
            id: att.id, bytesTransferred: 250)
        var fetched = try await store.attachments.fetch(id: att.id)
        XCTAssertEqual(fetched?.progress ?? -1, 0.25, accuracy: 0.001)
        XCTAssertEqual(fetched?.transferState, .downloading)

        // Overshoot clamps; completion flips state.
        try await store.attachments.recordProgress(
            id: att.id, bytesTransferred: 5000)
        fetched = try await store.attachments.fetch(id: att.id)
        XCTAssertEqual(fetched?.bytesTransferred, 1000)
        XCTAssertEqual(fetched?.transferState, .complete)
    }

    // MARK: - Calls

    func testCallRecordAndRecordingConsent() async throws {
        let c = try await makeConversation()
        let record = CallRecord(
            conversationID: c.id, kind: .video, direction: .outgoing,
            participants: ["alice", "bob"])
        try await store.calls.insert(record)

        // Recording must not start until ALL parties consent.
        try await store.calls.setRecordingConsent(
            callID: record.id, userID: "alice", consented: true)
        var fetched = try await store.calls.fetch(id: record.id)
        XCTAssertEqual(fetched?.allPartiesConsentedToRecording, false)

        try await store.calls.setRecordingConsent(
            callID: record.id, userID: "bob", consented: true)
        fetched = try await store.calls.fetch(id: record.id)
        XCTAssertEqual(fetched?.allPartiesConsentedToRecording, true)

        var ended = fetched!
        ended.endedAt = ended.startedAt.addingTimeInterval(125)
        ended.wasAnswered = true
        try await store.calls.update(ended)
        let history = try await store.calls.list(in: c.id, limit: 10)
        XCTAssertEqual(history.first?.durationSeconds, 125)
    }

    // MARK: - Transactions

    func testTransactionGroupsWrites() async throws {
        let c = Conversation(kind: .direct, title: "tx")
        try await store.transaction {
            try await store.conversations.create(c)
            try await store.contacts.upsert(Contact(
                id: "txuser", displayName: "Tx",
                identityKeyFingerprint: "SHA256:tx"))
        }
        let txConv = try await store.conversations.fetch(id: c.id)
        let txContact = try await store.contacts.fetch(id: "txuser")
        XCTAssertNotNil(txConv)
        XCTAssertNotNil(txContact)
    }
}

// MARK: - Async XCTAssertThrowsError helper

/// XCTest has no built-in async throwing-assertion; this is the standard shim.
func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    verify: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error, got success. \(message)", file: file, line: line)
    } catch {
        verify(error)
    }
}
