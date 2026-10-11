import Foundation
import XCTest
@testable import Aegis
@testable import AegisStore

/// Unit tests for messaging richness: polls, edit windows, quote
/// snapshots, pins, reaction keys, and signed wire events. All pure
/// Swift — no network, keychain, or database required.
final class MessagingRichnessTests: XCTestCase {

    // MARK: - Poll voting

    private func makePoll(
        allowsMultipleChoice: Bool = false,
        isAnonymous: Bool = false,
        closesAt: Date? = nil
    ) -> PollMessage {
        PollMessage(
            question: "Lunch?",
            options: ["Pizza", "Sushi", "Tacos"],
            allowsMultipleChoice: allowsMultipleChoice,
            isAnonymous: isAnonymous,
            closesAt: closesAt,
            tally: [:],
            voters: [],
            voterChoices: [:],
            myChoices: [],
            eligibleVoterCount: 5
        )
    }

    func testSingleChoiceBallotTallies() {
        var poll = makePoll()
        let alice = UUID(), bob = UUID()
        XCTAssertTrue(poll.applyBallot(voter: alice, choices: [0]))
        XCTAssertTrue(poll.applyBallot(voter: bob, choices: [1]))
        XCTAssertEqual(poll.count(for: 0), 1)
        XCTAssertEqual(poll.count(for: 1), 1)
        XCTAssertEqual(poll.count(for: 2), 0)
        XCTAssertEqual(poll.totalVotes, 2)
        XCTAssertEqual(poll.uniqueVoterCount, 2)
    }

    func testSingleChoiceChangeRetractsPrevious() {
        var poll = makePoll()
        let alice = UUID()
        XCTAssertTrue(poll.applyBallot(voter: alice, choices: [0]))
        XCTAssertTrue(poll.applyBallot(voter: alice, choices: [2]))
        XCTAssertEqual(poll.count(for: 0), 0)
        XCTAssertEqual(poll.count(for: 2), 1)
        XCTAssertEqual(poll.totalVotes, 1, "re-vote must not double-count")
        XCTAssertEqual(poll.previousChoices(of: alice), [2])
    }

    func testMultiChoiceBallot() {
        var poll = makePoll(allowsMultipleChoice: true)
        let alice = UUID()
        XCTAssertTrue(poll.applyBallot(voter: alice, choices: [0, 2]))
        XCTAssertEqual(poll.totalVotes, 2)
        // Single-choice poll rejects multi ballots.
        var single = makePoll()
        XCTAssertFalse(single.applyBallot(voter: alice, choices: [0, 1]))
    }

    func testAnonymousDoubleVoteRejected() {
        var poll = makePoll(isAnonymous: true)
        let alice = UUID()
        XCTAssertTrue(poll.applyBallot(voter: alice, choices: [1]))
        XCTAssertFalse(poll.applyBallot(voter: alice, choices: [0]))
        XCTAssertEqual(poll.totalVotes, 1)
        XCTAssertNil(poll.previousChoices(of: alice), "anonymous polls keep no choice mapping")
        XCTAssertTrue(poll.voters.contains(alice), "voter set still detects stuffing")
    }

    func testClosedPollRejectsVotes() {
        var poll = makePoll(closesAt: Date().addingTimeInterval(-60))
        XCTAssertTrue(poll.isClosed)
        XCTAssertFalse(poll.applyBallot(voter: UUID(), choices: [0]))
        var open = makePoll(closesAt: Date().addingTimeInterval(3600))
        XCTAssertFalse(open.isClosed)
        XCTAssertTrue(open.applyBallot(voter: UUID(), choices: [0]))
    }

    func testOutOfRangeChoicesRejected() {
        var poll = makePoll()
        XCTAssertFalse(poll.applyBallot(voter: UUID(), choices: [99]))
        XCTAssertFalse(poll.applyBallot(voter: UUID(), choices: []))
        XCTAssertFalse(poll.applyBallot(voter: UUID(), choices: [-1]))
    }

    func testQuorumText() {
        var poll = makePoll()
        XCTAssertEqual(poll.quorumText, "0 of 5 voted")
        _ = poll.applyBallot(voter: UUID(), choices: [0])
        XCTAssertEqual(poll.quorumText, "1 of 5 voted")
        var unknown = makePoll()
        unknown.eligibleVoterCount = nil
        _ = unknown.applyBallot(voter: UUID(), choices: [0])
        XCTAssertEqual(unknown.quorumText, "1 voted")
    }

    func testPollShare() {
        var poll = makePoll()
        _ = poll.applyBallot(voter: UUID(), choices: [0])
        _ = poll.applyBallot(voter: UUID(), choices: [0])
        _ = poll.applyBallot(voter: UUID(), choices: [1])
        XCTAssertEqual(poll.share(for: 0), 2.0 / 3.0, accuracy: 0.001)
        XCTAssertEqual(poll.share(for: 2), 0)
    }

    // MARK: - Edit window

    private func sentMessage(sentAt: Date, isFromMe: Bool = true) -> Aegis.Message {
        Aegis.Message(
            conversationID: UUID(),
            senderID: UUID(),
            isFromMe: isFromMe,
            body: "hello",
            sentAt: sentAt
        )
    }

    func testEditWindowDefault48h() {
        let now = Date()
        XCTAssertTrue(canEditMessage(
            sentMessage(sentAt: now.addingTimeInterval(-3600)),
            at: now, windowSeconds: defaultEditWindowSeconds
        ))
        XCTAssertEqual(defaultEditWindowSeconds, 48 * 3600)
    }

    func testEditWindowExpiry() {
        let now = Date()
        XCTAssertFalse(canEditMessage(
            sentMessage(sentAt: now.addingTimeInterval(-49 * 3600)),
            at: now, windowSeconds: defaultEditWindowSeconds
        ))
    }

    func testEditWindowDisabled() {
        XCTAssertFalse(canEditMessage(
            sentMessage(sentAt: Date()),
            windowSeconds: 0
        ))
    }

    func testEditWindowNotOwnMessage() {
        XCTAssertFalse(canEditMessage(
            sentMessage(sentAt: Date(), isFromMe: false),
            windowSeconds: defaultEditWindowSeconds
        ))
    }

    func testEditWindowDeletedMessage() {
        var message = sentMessage(sentAt: Date())
        message.deletedAt = Date()
        XCTAssertFalse(canEditMessage(message, windowSeconds: defaultEditWindowSeconds))
    }

    // MARK: - Quote snapshots

    func testQuoteSnapshotFallbackText() {
        let text = QuoteSnapshot(senderID: UUID(), senderName: "Maya", bodyExcerpt: "hello there", sentAt: Date())
        XCTAssertEqual(text.fallbackText, "hello there")
        let poll = QuoteSnapshot(senderID: UUID(), senderName: "Maya", isPoll: true, sentAt: Date())
        XCTAssertEqual(poll.fallbackText, "📊 Poll")
        let voice = QuoteSnapshot(senderID: UUID(), senderName: "Maya", hasVoiceNote: true, sentAt: Date())
        XCTAssertEqual(voice.fallbackText, "🎤 Voice note")
        let attachment = QuoteSnapshot(senderID: UUID(), senderName: "Maya", hasAttachment: true, sentAt: Date())
        XCTAssertEqual(attachment.fallbackText, "📎 Attachment")
    }

    func testQuoteSnapshotSurvivesOriginalDeletion() throws {
        // The snapshot is a frozen copy: encoding it and decoding it back
        // (as the wire/store do) preserves the quoted text even though the
        // original message is gone.
        let snapshot = QuoteSnapshot(
            senderID: UUID(), senderName: "Maya",
            bodyExcerpt: "meet at 8", sentAt: Date()
        )
        let roundTripped = try JSONDecoder().decode(
            QuoteSnapshot.self, from: JSONEncoder().encode(snapshot)
        )
        XCTAssertEqual(roundTripped.bodyExcerpt, "meet at 8")
        XCTAssertEqual(roundTripped.senderName, "Maya")
    }

    // MARK: - Pins

    func testPinExpiry() {
        let live = MessagePin(pinnedBy: UUID(), pinnedByName: "Maya", expiresAt: Date().addingTimeInterval(3600))
        XCTAssertFalse(live.isExpired)
        let expired = MessagePin(pinnedBy: UUID(), pinnedByName: "Maya", expiresAt: Date().addingTimeInterval(-1))
        XCTAssertTrue(expired.isExpired)
        let forever = MessagePin(pinnedBy: UUID(), pinnedByName: "Maya", expiresAt: nil)
        XCTAssertFalse(forever.isExpired)
    }

    // MARK: - Reaction keys

    func testCustomEmojiKeyRoundTrip() {
        let packID = UUID()
        let key = ReactionKey.customEmoji(packID: packID, emojiID: "party_parrot")
        let parsed = ReactionKey.parseCustomEmoji(key)
        XCTAssertEqual(parsed?.packID, packID)
        XCTAssertEqual(parsed?.emojiID, "party_parrot")
        XCTAssertTrue(ReactionKey.isCustomEmoji(key))
    }

    func testPlainEmojiIsNotCustom() {
        XCTAssertNil(ReactionKey.parseCustomEmoji("❤️"))
        XCTAssertFalse(ReactionKey.isCustomEmoji("👍"))
        XCTAssertNil(ReactionKey.parseCustomEmoji("pack:not-a-uuid:x"))
        XCTAssertNil(ReactionKey.parseCustomEmoji("pack:"))
    }

    // MARK: - Signed wire events

    func testSignableBytesAreDeterministic() {
        let id = UUID()
        let a = WirePayload.reaction(targetMessageID: id, emoji: "👍").signableBytes()
        let b = WirePayload.reaction(targetMessageID: id, emoji: "👍").signableBytes()
        XCTAssertEqual(a, b)
    }

    func testSignableBytesAreDomainSeparatedByKind() {
        let id = UUID()
        // Same target, different kinds: a reaction signature must never
        // verify as a delete.
        let reaction = WirePayload.reaction(targetMessageID: id, emoji: "👍").signableBytes()
        let delete = WirePayload.delete(targetMessageID: id).signableBytes()
        XCTAssertNotEqual(reaction, delete)
        let ballot = WirePayload.ballot(targetMessageID: id, choices: [0]).signableBytes()
        XCTAssertNotEqual(reaction, ballot)
    }

    func testSignedKinds() {
        for kind in [WirePayload.Kind.reaction, .edit, .delete, .ballot, .pin, .unpin] {
            XCTAssertTrue(WirePayload.signedKinds.contains(kind), "\(kind) must be signature-gated")
        }
        XCTAssertFalse(WirePayload.signedKinds.contains(.text))
        XCTAssertFalse(WirePayload.signedKinds.contains(.poll))
    }

    func testUnsignedGatedEventFailsVerification() {
        var payload = WirePayload.reaction(targetMessageID: UUID(), emoji: "👍")
        XCTAssertFalse(payload.verifySignature(signingPublicKey: Data(repeating: 0, count: 32)))
        // Wrong key size also fails closed.
        payload.attachSignature(Data(repeating: 1, count: 64))
        XCTAssertFalse(payload.verifySignature(signingPublicKey: Data(repeating: 0, count: 16)))
    }

    func testWirePayloadRoundTrips() throws {
        var poll = WirePayload.poll(
            id: UUID(), question: "Q?", options: ["A", "B"],
            allowsMultipleChoice: true, anonymous: false,
            closesAt: Date().addingTimeInterval(3600),
            eligibleVoterCount: 4, expiresIn: 60, disappearAfterRead: true
        )
        poll.signature = Data(repeating: 7, count: 64)
        let decoded = try WirePayload.decoded(from: poll.encoded())
        XCTAssertEqual(decoded.kind, .poll)
        XCTAssertEqual(decoded.pollOptions, ["A", "B"])
        XCTAssertEqual(decoded.pollAllowsMultipleChoice, true)
        XCTAssertEqual(decoded.disappearAfterRead, true)
        XCTAssertEqual(decoded.signature, Data(repeating: 7, count: 64))
    }

    // MARK: - Store model round-trips (JSON columns)

    func testStoreQuoteSnapshotRoundTrip() throws {
        let snapshot = AegisStore.QuoteSnapshot(
            senderID: "local", senderName: "Me",
            bodyExcerpt: "hi", hasAttachment: false,
            hasVoiceNote: false, isPoll: false, sentAt: Date()
        )
        let decoded = try JSONDecoder().decode(
            AegisStore.QuoteSnapshot.self, from: JSONEncoder().encode(snapshot)
        )
        XCTAssertEqual(decoded, snapshot)
    }

    func testStorePinRoundTrip() throws {
        let pin = AegisStore.MessagePin(
            pinnedBy: "local", pinnedByName: "Me",
            expiresAt: Date().addingTimeInterval(100)
        )
        let decoded = try JSONDecoder().decode(
            AegisStore.MessagePin.self, from: JSONEncoder().encode(pin)
        )
        XCTAssertEqual(decoded, pin)
        XCTAssertFalse(decoded.isExpired)
    }

    func testThreadSummaryValueSemantics() {
        let a = Aegis.ThreadSummary(replyCount: 3, lastActivityAt: Date())
        let b = Aegis.ThreadSummary(replyCount: 3, lastActivityAt: a.lastActivityAt)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.hashValue, b.hashValue)
    }
}
