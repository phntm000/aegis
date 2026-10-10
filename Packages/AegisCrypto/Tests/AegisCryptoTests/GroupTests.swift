import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class GroupTests: XCTestCase {
    private struct Fixture {
        let alice: Identity
        let bob: Identity
        let groupID: Data
        let aliceSession: GroupSession
        let bobSession: GroupSession
    }

    /// Two members with exchanged sender keys.
    private func makeTwoMemberGroup() throws -> Fixture {
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
        // Exchange sender keys (transport would encrypt these 1:1).
        for dist in try aliceSession.initialDistributions() {
            try bobSession.ingestDistribution(dist.distribution, fromSender: alice.fingerprint)
        }
        for dist in try bobSession.initialDistributions() {
            try aliceSession.ingestDistribution(dist.distribution, fromSender: bob.fingerprint)
        }
        return Fixture(alice: alice, bob: bob, groupID: groupID, aliceSession: aliceSession, bobSession: bobSession)
    }

    // MARK: - Basic messaging

    func testGroupEncryptDecrypt() throws {
        let f = try makeTwoMemberGroup()
        let sent = try f.aliceSession.encrypt(plaintext: Data("hello group".utf8))
        XCTAssertTrue(sent.keyRotation.isEmpty)
        let received = try f.bobSession.decrypt(sent.message)
        XCTAssertEqual(received, Data("hello group".utf8))
        // And back.
        let reply = try f.bobSession.encrypt(plaintext: Data("hi alice".utf8))
        XCTAssertEqual(try f.aliceSession.decrypt(reply.message), Data("hi alice".utf8))
    }

    func testOutOfOrderGroupMessages() throws {
        let f = try makeTwoMemberGroup()
        let m0 = try f.aliceSession.encrypt(plaintext: Data("zero".utf8))
        let m1 = try f.aliceSession.encrypt(plaintext: Data("one".utf8))
        let m2 = try f.aliceSession.encrypt(plaintext: Data("two".utf8))
        XCTAssertEqual(try f.bobSession.decrypt(m2.message), Data("two".utf8))
        XCTAssertEqual(try f.bobSession.decrypt(m0.message), Data("zero".utf8))
        XCTAssertEqual(try f.bobSession.decrypt(m1.message), Data("one".utf8))
    }

    func testGroupMessageWireRoundTrip() throws {
        let f = try makeTwoMemberGroup()
        let sent = try f.aliceSession.encrypt(plaintext: Data("wire".utf8))
        let parsed = try GroupMessage.parse(sent.message.serialized())
        XCTAssertEqual(try f.bobSession.decrypt(parsed), Data("wire".utf8))
    }

    // MARK: - Membership changes

    func testRemoveMemberRotatesEpoch() throws {
        let f = try makeTwoMemberGroup()
        let distributions = try f.aliceSession.removeMember(fingerprint: f.bob.fingerprint)
        XCTAssertTrue(distributions.isEmpty) // no remaining members to notify

        // Alice's new messages are in epoch 1; bob only holds epoch-0 keys.
        let sent = try f.aliceSession.encrypt(plaintext: Data("after removal".utf8))
        XCTAssertEqual(sent.message.epoch, 1)
        XCTAssertThrowsError(try f.bobSession.decrypt(sent.message)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .staleEpoch)
        }
    }

    func testAddMember() throws {
        let f = try makeTwoMemberGroup()
        let carol = try Identity(provider: testProvider)
        let distributions = try f.aliceSession.addMember(GroupMember(fingerprint: carol.fingerprint, displayName: "Carol"))
        // Both remaining members (bob and carol) get the new epoch's key.
        XCTAssertEqual(distributions.count, 2)
        XCTAssertTrue(distributions.contains { $0.recipientFingerprint == carol.fingerprint })
        XCTAssertTrue(distributions.allSatisfy { $0.distribution.epoch == 1 })
    }

    func testNewMemberCannotReadHistory() throws {
        var f = try makeTwoMemberGroup()
        let history = try f.aliceSession.encrypt(plaintext: Data("before carol".utf8))

        let carol = try Identity(provider: testProvider)
        _ = try f.aliceSession.addMember(GroupMember(fingerprint: carol.fingerprint, displayName: "Carol"))
        let carolSession = try GroupSession(
            groupID: f.groupID, epoch: 1, joiner: carol,
            members: [
                GroupMember(fingerprint: f.alice.fingerprint, displayName: "Alice"),
                GroupMember(fingerprint: f.bob.fingerprint, displayName: "Bob"),
                GroupMember(fingerprint: carol.fingerprint, displayName: "Carol"),
            ],
            provider: testProvider
        )
        // Carol never received epoch-0 sender keys: history is opaque.
        XCTAssertThrowsError(try carolSession.decrypt(history.message)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .unknownSenderKey)
        }
    }

    // MARK: - Authentication

    func testSignatureTamperFails() throws {
        let f = try makeTwoMemberGroup()
        let sent = try f.aliceSession.encrypt(plaintext: Data("signed".utf8))
        // NOTE: `data[0] ^= ...` directly on Data traps (SIGTRAP) on this
        // toolchain even with valid bounds — route through [UInt8].
        var badSigBytes = [UInt8](sent.message.signature)
        badSigBytes[0] ^= 0x01
        let badSig = Data(badSigBytes)
        let forged = GroupMessage(
            groupID: sent.message.groupID, epoch: sent.message.epoch,
            senderID: sent.message.senderID, index: sent.message.index,
            nonce: sent.message.nonce, ciphertext: sent.message.ciphertext,
            signature: badSig
        )
        XCTAssertThrowsError(try f.bobSession.decrypt(forged)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidSignature)
        }
    }

    func testDistributionSenderBindingEnforced() throws {
        let f = try makeTwoMemberGroup()
        let carol = try Identity(provider: testProvider)
        // Take alice's distribution but claim it arrived from carol's 1:1
        // session: the binding check must reject it.
        let dist = try XCTUnwrap(try f.aliceSession.initialDistributions().first).distribution
        XCTAssertThrowsError(try f.bobSession.ingestDistribution(dist, fromSender: carol.fingerprint)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidSignature)
        }
    }

    func testUnknownSenderKeyFails() throws {
        let f = try makeTwoMemberGroup()
        // A message from a sender whose distribution we never ingested.
        let stranger = try Identity(provider: testProvider)
        var strangerSession = try GroupSession(
            groupID: f.groupID, epoch: 0, joiner: stranger,
            members: [GroupMember(fingerprint: stranger.fingerprint, displayName: "S")],
            provider: testProvider
        )
        let forged = try strangerSession.encrypt(plaintext: Data("x".utf8))
        // Bob has never seen this sender's key.
        XCTAssertThrowsError(try f.bobSession.decrypt(forged.message)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .unknownSenderKey)
        }
    }
}
