import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

/// Tests for `GroupSession.adoptMembershipChange` — the epoch-adoption path
/// a member takes when ANOTHER member announces a membership change.
final class GroupAdoptionTests: XCTestCase {
    private func makeIdentities() throws -> (alice: Identity, bob: Identity, carol: Identity) {
        (
            try Identity(provider: testProvider),
            try Identity(provider: testProvider),
            try Identity(provider: testProvider)
        )
    }

    private func member(_ id: Identity, name: String) -> GroupMember {
        GroupMember(fingerprint: id.fingerprint, displayName: name)
    }

    /// Alice (member) adopts Bob's (admin) announcement that Carol joined.
    func testAdoptMemberAdded() throws {
        let (alice, bob, carol) = try makeIdentities()
        let groupID = try Random.bytes(count: 32)

        // Alice's view: group at epoch 0 with Alice + Bob.
        let aliceSession = try GroupSession(
            groupID: groupID, epoch: 0, joiner: alice,
            members: [member(alice, name: "Alice"), member(bob, name: "Bob")],
            provider: testProvider
        )
        // Exchange keys at epoch 0.
        for dist in try aliceSession.initialDistributions() {
            _ = dist // (Bob's session is not modeled; we only need Alice's side.)
        }

        // Bob announces: epoch 1, roster Alice + Bob + Carol.
        let distributions = try aliceSession.adoptMembershipChange(
            newEpoch: 1,
            members: [member(alice, name: "Alice"), member(bob, name: "Bob"), member(carol, name: "Carol")]
        )
        XCTAssertEqual(aliceSession.epoch, 1)
        XCTAssertEqual(aliceSession.members.count, 3)
        XCTAssertNotNil(aliceSession.members[carol.fingerprint])
        // Our fresh key is distributed to every OTHER member.
        XCTAssertEqual(distributions.count, 2)
        XCTAssertTrue(distributions.allSatisfy { $0.distribution.epoch == 1 })
        XCTAssertTrue(distributions.allSatisfy { $0.distribution.senderID == alice.fingerprint })
    }

    /// Stale or duplicate announcements are ignored (no epoch change, no
    /// rotation, no distributions).
    func testAdoptStaleAnnouncementIgnored() throws {
        let (alice, bob, _) = try makeIdentities()
        let groupID = try Random.bytes(count: 32)
        let aliceSession = try GroupSession(
            groupID: groupID, epoch: 2, joiner: alice,
            members: [member(alice, name: "Alice"), member(bob, name: "Bob")],
            provider: testProvider
        )
        let distributions = try aliceSession.adoptMembershipChange(
            newEpoch: 2,
            members: [member(alice, name: "Alice")]
        )
        XCTAssertTrue(distributions.isEmpty)
        XCTAssertEqual(aliceSession.epoch, 2)
        XCTAssertEqual(aliceSession.members.count, 2)
    }

    /// On member removal, the removed member's sender states are dropped
    /// immediately — their late messages must not decrypt even within the
    /// grace window.
    func testAdoptMemberRemovedDropsStates() throws {
        let (alice, bob, carol) = try makeIdentities()
        let groupID = try Random.bytes(count: 32)
        let aliceSession = try GroupSession(
            groupID: groupID, epoch: 0, joiner: alice,
            members: [member(alice, name: "A"), member(bob, name: "B"), member(carol, name: "C")],
            provider: testProvider
        )
        // Carol's session: she sends a message Alice can read.
        let carolSession = try GroupSession(
            groupID: groupID, epoch: 0, joiner: carol,
            members: [member(alice, name: "A"), member(bob, name: "B"), member(carol, name: "C")],
            provider: testProvider
        )
        for dist in try carolSession.initialDistributions() where dist.recipientFingerprint == alice.fingerprint {
            try aliceSession.ingestDistribution(dist.distribution, fromSender: carol.fingerprint)
        }
        let before = try carolSession.encrypt(plaintext: Data("before".utf8))
        XCTAssertEqual(try aliceSession.decrypt(before.message), Data("before".utf8))

        // Bob announces Carol's removal at epoch 1.
        _ = try aliceSession.adoptMembershipChange(
            newEpoch: 1,
            members: [member(alice, name: "A"), member(bob, name: "B")]
        )
        XCTAssertNil(aliceSession.members[carol.fingerprint])
        // Carol's old-epoch message no longer decrypts: her state is gone.
        let late = try carolSession.encrypt(plaintext: Data("late".utf8))
        XCTAssertThrowsError(try aliceSession.decrypt(late.message))
    }

    /// Adopting rotates OUR sender key: the distributions carry a fresh
    /// chain key, so a removed member holding our old key cannot read our
    /// new messages (forward secrecy).
    func testAdoptRotatesOurSenderKey() throws {
        let (alice, bob, _) = try makeIdentities()
        let groupID = try Random.bytes(count: 32)
        let aliceSession = try GroupSession(
            groupID: groupID, epoch: 0, joiner: alice,
            members: [member(alice, name: "A"), member(bob, name: "B")],
            provider: testProvider
        )
        let before = try aliceSession.initialDistributions()
        let oldChainKey = before.first(where: { $0.recipientFingerprint == bob.fingerprint })?
            .distribution.chainKey

        _ = try aliceSession.adoptMembershipChange(
            newEpoch: 1,
            members: [member(alice, name: "A"), member(bob, name: "B")]
        )
        let after = try aliceSession.initialDistributions()
        let newChainKey = after.first(where: { $0.recipientFingerprint == bob.fingerprint })?
            .distribution.chainKey
        XCTAssertNotNil(oldChainKey)
        XCTAssertNotNil(newChainKey)
        XCTAssertNotEqual(oldChainKey, newChainKey)
    }
}
