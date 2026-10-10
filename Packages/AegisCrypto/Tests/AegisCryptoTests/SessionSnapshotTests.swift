import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

/// Round-trip and corruption tests for Double Ratchet session snapshots
/// (durable session persistence).
final class SessionSnapshotTests: XCTestCase {
    private struct Fixtures {
        let alice: Identity
        let bob: Identity
        let aliceSession: AegisDoubleRatchet
        let bobSession: AegisDoubleRatchet
        let ephPub: Data
    }

    private func makeFixtures() throws -> Fixtures {
        let aliceID = try Identity(provider: testProvider)
        let bobID = try Identity(provider: testProvider)
        let bobKeys = try PreKeyManager(identity: bobID, provider: testProvider)
        let bundle = try bobKeys.currentBundle()
        let initiated = try SessionEstablishment.initiate(
            ourIdentity: aliceID, bundle: bundle,
            plaintext: Data("hello bob".utf8), provider: testProvider
        )
        let opk = initiated.usedOneTimePreKeyID.flatMap { bobKeys.consumeOneTimePreKey($0) }
        let responded = try SessionEstablishment.respond(
            preKeyMessageWire: initiated.preKeyMessage,
            ourIdentity: bobID,
            ourSignedPreKey: bobKeys.signedPreKey,
            usedOneTimePreKey: opk,
            provider: testProvider
        )
        let preKey = try PreKeyMessage.parse(initiated.preKeyMessage)
        return Fixtures(
            alice: aliceID, bob: bobID,
            aliceSession: initiated.session, bobSession: responded.session,
            ephPub: preKey.ephemeralPublicKey
        )
    }

    /// Snapshot → restore → continued conversation, both directions.
    func testRoundTripContinuesConversation() throws {
        let f = try makeFixtures()
        // Advance both sides so the snapshot covers non-trivial state.
        for i in 0 ..< 3 {
            let m = try f.aliceSession.encrypt(plaintext: Data("a\(i)".utf8))
            XCTAssertEqual(try f.bobSession.decrypt(m), Data("a\(i)".utf8))
        }
        for i in 0 ..< 2 {
            let m = try f.bobSession.encrypt(plaintext: Data("b\(i)".utf8))
            XCTAssertEqual(try f.aliceSession.decrypt(m), Data("b\(i)".utf8))
        }

        let snapA = f.aliceSession.snapshot(peerIdentity: f.bob.publicView, ephemeralPublicKey: f.ephPub)
        let snapB = f.bobSession.snapshot(peerIdentity: f.alice.publicView, ephemeralPublicKey: f.ephPub)
        let restoredA = try AegisDoubleRatchet(snapshot: snapA, provider: testProvider)
        let restoredB = try AegisDoubleRatchet(snapshot: snapB, provider: testProvider)

        for i in 0 ..< 5 {
            let m = try restoredA.encrypt(plaintext: Data("after-a\(i)".utf8))
            XCTAssertEqual(try restoredB.decrypt(m), Data("after-a\(i)".utf8))
            let r = try restoredB.encrypt(plaintext: Data("after-b\(i)".utf8))
            XCTAssertEqual(try restoredA.decrypt(r), Data("after-b\(i)".utf8))
        }
    }

    /// Serialized form round-trips through encode/decode and still resumes.
    func testSerializedFormRoundTrip() throws {
        let f = try makeFixtures()
        let wire = try f.aliceSession
            .snapshot(peerIdentity: f.bob.publicView, ephemeralPublicKey: f.ephPub)
            .serialized()
        let decoded = try RatchetSessionSnapshot(serialized: wire)
        XCTAssertEqual(decoded.version, RatchetSessionSnapshot.currentVersion)
        let restored = try AegisDoubleRatchet(snapshot: decoded, provider: testProvider)
        let m = try restored.encrypt(plaintext: Data("resumed".utf8))
        XCTAssertEqual(try f.bobSession.decrypt(m), Data("resumed".utf8))
    }

    /// Out-of-order (skipped) message keys survive the snapshot.
    func testSkippedKeysSurvive() throws {
        let f = try makeFixtures()
        // Alice sends 3; Bob receives #2 first (out of order), stashing #0 and #1.
        let m0 = try f.aliceSession.encrypt(plaintext: Data("m0".utf8))
        let m1 = try f.aliceSession.encrypt(plaintext: Data("m1".utf8))
        let m2 = try f.aliceSession.encrypt(plaintext: Data("m2".utf8))
        XCTAssertEqual(try f.bobSession.decrypt(m2), Data("m2".utf8))

        let snap = f.bobSession.snapshot(peerIdentity: f.alice.publicView, ephemeralPublicKey: f.ephPub)
        XCTAssertEqual(snap.skippedKeys.count, 2)
        let restoredB = try AegisDoubleRatchet(snapshot: snap, provider: testProvider)
        XCTAssertEqual(try restoredB.decrypt(m0), Data("m0".utf8))
        XCTAssertEqual(try restoredB.decrypt(m1), Data("m1".utf8))
    }

    /// A future snapshot version is rejected loudly (caller re-establishes).
    func testFutureVersionRejected() throws {
        let f = try makeFixtures()
        var snap = f.aliceSession.snapshot(peerIdentity: f.bob.publicView, ephemeralPublicKey: f.ephPub)
        snap.version = RatchetSessionSnapshot.currentVersion + 1
        XCTAssertThrowsError(try AegisDoubleRatchet(snapshot: snap, provider: testProvider)) { error in
            guard case AegisCryptoError.unsupportedSnapshotVersion(let v) = error else {
                return XCTFail("wrong error: \(error)")
            }
            XCTAssertEqual(v, RatchetSessionSnapshot.currentVersion + 1)
        }
        // Same through the serialized form.
        let wire = try snap.serialized()
        XCTAssertThrowsError(try RatchetSessionSnapshot(serialized: wire)) { error in
            guard case AegisCryptoError.unsupportedSnapshotVersion = error else {
                return XCTFail("wrong error: \(error)")
            }
        }
    }

    /// Corrupted key material is rejected — never a silently wrong session.
    func testCorruptedSnapshotRejected() throws {
        let f = try makeFixtures()
        var snap = f.aliceSession.snapshot(peerIdentity: f.bob.publicView, ephemeralPublicKey: f.ephPub)
        // Corrupt the root key length.
        snap.rootKey = Data(repeating: 0xAA, count: 16)
        XCTAssertThrowsError(try AegisDoubleRatchet(snapshot: snap, provider: testProvider)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidKeyData)
        }
        // Corrupt the ratchet public key so re-derivation mismatches.
        var snap2 = f.aliceSession.snapshot(peerIdentity: f.bob.publicView, ephemeralPublicKey: f.ephPub)
        snap2.sendingRatchetPublicKey = Data(repeating: 0xBB, count: 32)
        XCTAssertThrowsError(try AegisDoubleRatchet(snapshot: snap2, provider: testProvider)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidKeyData)
        }
    }

    /// Garbage bytes do not decode as a snapshot.
    func testGarbageRejected() {
        XCTAssertThrowsError(try RatchetSessionSnapshot(serialized: Data("not a snapshot".utf8)))
        XCTAssertThrowsError(try RatchetSessionSnapshot(serialized: Data()))
    }
}
