import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

/// GroupSession snapshot round-trips: a serialized session must resume
/// sending AND receiving across an (imaginary) app restart, including
/// out-of-order message keys stashed before the snapshot.
final class GroupSnapshotTests: XCTestCase {
    private func makeGroup() throws -> (alice: Identity, bob: Identity, groupID: Data, aliceSession: GroupSession, bobSession: GroupSession) {
        let alice = try Identity(provider: testProvider)
        let bob = try Identity(provider: testProvider)
        let groupID = try Random.bytes(count: 32)
        let aliceSession = try GroupSession(
            groupID: groupID, founder: alice,
            initialMembers: [GroupMember(fingerprint: bob.fingerprint, displayName: "Bob")],
            provider: testProvider
        )
        let bobSession = try GroupSession(
            groupID: groupID, epoch: 0, joiner: bob,
            members: [
                GroupMember(fingerprint: alice.fingerprint, displayName: "Alice"),
                GroupMember(fingerprint: bob.fingerprint, displayName: "Bob"),
            ],
            provider: testProvider
        )
        for dist in try aliceSession.initialDistributions() {
            try bobSession.ingestDistribution(dist.distribution, fromSender: alice.fingerprint)
        }
        for dist in try bobSession.initialDistributions() {
            try aliceSession.ingestDistribution(dist.distribution, fromSender: bob.fingerprint)
        }
        return (alice, bob, groupID, aliceSession, bobSession)
    }

    func testSnapshotRoundTripPreservesMessaging() throws {
        let g = try makeGroup()
        // Warm up both directions and stash an out-of-order key on Bob.
        let warm = try g.aliceSession.encrypt(plaintext: Data("warm".utf8))
        XCTAssertEqual(try g.bobSession.decrypt(warm.message), Data("warm".utf8))
        let m0 = try g.aliceSession.encrypt(plaintext: Data("zero".utf8))
        let m2 = try g.aliceSession.encrypt(plaintext: Data("two".utf8))
        // Bob receives m2 first (m0's key is stashed), then we snapshot.
        XCTAssertEqual(try g.bobSession.decrypt(m2.message), Data("two".utf8))

        let data = try g.bobSession.snapshot().serialized()
        let restored = try GroupSession(restoring: GroupSessionSnapshot.parse(data), provider: testProvider)

        // The stashed out-of-order key survived: m0 still decrypts.
        XCTAssertEqual(try restored.decrypt(m0.message), Data("zero".utf8))
        // New inbound traffic decrypts.
        let m3 = try g.aliceSession.encrypt(plaintext: Data("three".utf8))
        XCTAssertEqual(try restored.decrypt(m3.message), Data("three".utf8))
        // And the restored session can still SEND (signing seed survived).
        let reply = try restored.encrypt(plaintext: Data("reply".utf8))
        XCTAssertEqual(try g.aliceSession.decrypt(reply.message), Data("reply".utf8))
    }

    func testSnapshotPreservesEpochAndRoster() throws {
        let g = try makeGroup()
        // Membership change bumps the epoch before the snapshot.
        let carol = try Identity(provider: testProvider)
        let dists = try g.aliceSession.addMember(GroupMember(fingerprint: carol.fingerprint, displayName: "Carol"))
        XCTAssertEqual(g.aliceSession.epoch, 1)
        XCTAssertFalse(dists.isEmpty)

        let restored = try GroupSession(
            restoring: GroupSessionSnapshot.parse(try g.aliceSession.snapshot().serialized()),
            provider: testProvider
        )
        XCTAssertEqual(restored.epoch, 1)
        XCTAssertEqual(restored.members.count, 3)
        XCTAssertNotNil(restored.members[carol.fingerprint])
    }

    func testCorruptSnapshotThrowsInsteadOfHalfRestoring() throws {
        let g = try makeGroup()
        var snap = g.aliceSession.snapshot()
        // A snapshot without our signing seed could receive but never
        // send — it must be rejected, not half-restored.
        snap.ourSigningSeed = nil
        XCTAssertThrowsError(try GroupSession(restoring: snap, provider: testProvider))

        // Garbage bytes never decode.
        XCTAssertThrowsError(try GroupSessionSnapshot.parse(Data("not a snapshot".utf8)))
    }

    func testSnapshotSurvivesJSONRoundTrip() throws {
        let g = try makeGroup()
        let snap = g.aliceSession.snapshot()
        let restored = try GroupSessionSnapshot.parse(try snap.serialized())
        XCTAssertEqual(restored, snap)
    }
}
