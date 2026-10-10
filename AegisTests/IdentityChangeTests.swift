import CryptoKit
import Foundation
import XCTest
@testable import Aegis
@testable import AegisCrypto

/// Simulates a mid-conversation identity change at the crypto-engine layer.
///
/// Scenario: Alice has an established session with Bob@K1. Bob's identity is
/// replaced by K2 (reinstall / new device without backup). Bob@K2's next
/// message is a prekey. The engine must authenticate K2 as the real sender —
/// never silently pin it to K1 — so the app layer can show the
/// "safety number changed" warning.
final class IdentityChangeTests: XCTestCase {
    private func makeEngine() -> CryptoEngine {
        CryptoEngine(contactIdentity: { _ in nil })
    }

    /// Prekey from the new identity, presented on the old peer's route:
    /// decrypt must succeed (X3DH) and report the NEW identity as sender.
    func testPreKeyFromChangedIdentityReportsNewSender() async throws {
        // Sealed sender is ON by default in the app host; this test covers
        // the unsealed route, so pin it off for determinism.
        UserDefaults.standard.set(false, forKey: SettingsKeys.sealedSender)
        defer { UserDefaults.standard.removeObject(forKey: SettingsKeys.sealedSender) }

        let alice = makeEngine()
        let bob1 = makeEngine()
        let bob2 = makeEngine()
        let alicePub = try await alice.createIdentity(displayName: "Alice")
        let bob1Pub = try await bob1.createIdentity(displayName: "Bob")
        let bob2Pub = try await bob2.createIdentity(displayName: "Bob")

        // Bob@K1 establishes a session with Alice via her invite.
        let invite = try await alice.invitePayload(displayName: "Alice")
        _ = try await bob1.parseInvite(invite)
        let (wire1, _) = try await bob1.encryptDirect(Data("hello".utf8), to: alicePub)
        let (pt1, initiator1) = try await alice.decryptPreKeyFromUnknownSender(wire1)
        XCTAssertEqual(pt1, Data("hello".utf8))
        XCTAssertEqual(initiator1.fingerprint, bob1Pub.fingerprint)

        // Bob's identity is replaced. Bob@K2 gets a fresh invite bundle and
        // sends a prekey (no session exists on his side).
        let invite2 = try await alice.invitePayload(displayName: "Alice")
        _ = try await bob2.parseInvite(invite2)
        let (wire2, _) = try await bob2.encryptDirect(Data("new phone".utf8), to: alicePub)

        // The frame arrives where Bob@K1's route was: decrypt must still
        // succeed via X3DH, but the reported sender must be K2, not K1.
        let (pt2, sender2) = try await alice.decryptDirect(wire2, from: initiator1)
        XCTAssertEqual(pt2, Data("new phone".utf8))
        XCTAssertEqual(sender2.fingerprint, bob2Pub.fingerprint)
        XCTAssertNotEqual(sender2.fingerprint, bob1Pub.fingerprint)
    }

    /// The sealed-sender rendezvous path: a sealed prekey from an unknown
    /// sender opens anonymously and authenticates via X3DH.
    func testSealedPreKeyFromUnknownSender() async throws {
        UserDefaults.standard.set(true, forKey: SettingsKeys.sealedSender)
        defer { UserDefaults.standard.removeObject(forKey: SettingsKeys.sealedSender) }

        let alice = makeEngine()
        let bob = makeEngine()
        let alicePub = try await alice.createIdentity(displayName: "Alice")
        let bobPub = try await bob.createIdentity(displayName: "Bob")

        let invite = try await alice.invitePayload(displayName: "Alice")
        _ = try await bob.parseInvite(invite)
        let (wire, _) = try await bob.encryptDirect(Data("first contact".utf8), to: alicePub)

        let (plaintext, initiator) = try await alice.decryptPreKeyFromUnknownSender(wire)
        XCTAssertEqual(plaintext, Data("first contact".utf8))
        XCTAssertEqual(initiator.fingerprint, bobPub.fingerprint)
    }

    /// A forged sender claim fails closed: the sealed certificate claims
    /// Bob's fingerprint, but the inner prekey is X3DH-bound to Mallory.
    /// The engine must reject it — the certificate fingerprint does not
    /// match the authenticated sender.
    func testMismatchedSealedCertificateFailsClosed() async throws {
        UserDefaults.standard.set(false, forKey: SettingsKeys.sealedSender)
        defer { UserDefaults.standard.removeObject(forKey: SettingsKeys.sealedSender) }

        let alice = makeEngine()
        let malloryEngine = makeEngine()
        let alicePub = try await alice.createIdentity(displayName: "Alice")
        _ = try await malloryEngine.createIdentity(displayName: "Mallory")
        // Bob exists only as a fingerprint to impersonate.
        let bobFP = Data(SHA256.hash(data: Data("bob".utf8)))

        // Mallory's real prekey to Alice (X3DH-bound to Mallory).
        let invite = try await alice.invitePayload(displayName: "Alice")
        _ = try await malloryEngine.parseInvite(invite)
        let (prekeyWire, _) = try await malloryEngine.encryptDirect(Data("forged".utf8), to: alicePub)

        // Forge the sealed envelope: certificate claims Bob, inner is
        // Mallory's prekey. (Signature bytes are irrelevant — the engine
        // rejects on the fingerprint mismatch before any signature check.)
        let mailboxID = CryptoEngine.identityMailbox(of: alicePub)
        let eph = try X25519KeyPair.generate(provider: CryptoKitProvider.shared)
        let key = try SealedSender.sealedSenderKey(
            privateKey: eph.privateKey.toData(),
            peerPublicKey: alicePub.agreementPublicKey,
            mailboxID: mailboxID,
            provider: CryptoKitProvider.shared
        )
        let cert = SenderCertificate(
            senderFingerprint: bobFP,
            timestamp: UInt64(Date().timeIntervalSince1970)
        )
        let certBytes = cert.serialized(
            signature: Data(repeating: 0, count: 64),
            innerMessage: prekeyWire
        )
        let aad = SealedEnvelope.aad(mailboxID: mailboxID, ephemeralPublicKey: eph.publicKey)
        let sealed = try AEAD.seal(plaintext: Padding.pad(certBytes), key: key, associatedData: aad)
        let forged = SealedEnvelope(
            mailboxID: mailboxID,
            ephemeralPublicKey: eph.publicKey,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )

        do {
            _ = try await alice.decryptPreKeyFromUnknownSender(forged.serialized())
            XCTFail("forged sender claim must fail closed")
        } catch let error as AegisCryptoError {
            XCTAssertEqual(error, .invalidSignature)
        }
    }

    /// Ratchet messages keep reporting the pinned session peer.
    func testRatchetMessageReportsSessionPeer() async throws {
        UserDefaults.standard.set(false, forKey: SettingsKeys.sealedSender)
        defer { UserDefaults.standard.removeObject(forKey: SettingsKeys.sealedSender) }

        let alice = makeEngine()
        let bob = makeEngine()
        let alicePub = try await alice.createIdentity(displayName: "Alice")
        let bobPub = try await bob.createIdentity(displayName: "Bob")

        let invite = try await alice.invitePayload(displayName: "Alice")
        _ = try await bob.parseInvite(invite)
        let (wire1, _) = try await bob.encryptDirect(Data("one".utf8), to: alicePub)
        let (_, initiator) = try await alice.decryptPreKeyFromUnknownSender(wire1)
        XCTAssertEqual(initiator.fingerprint, bobPub.fingerprint)

        // Bob's second message is a ratchet message in the live session.
        let (wire2, _) = try await bob.encryptDirect(Data("two".utf8), to: alicePub)
        let (pt2, sender2) = try await alice.decryptDirect(wire2, from: initiator)
        XCTAssertEqual(pt2, Data("two".utf8))
        XCTAssertEqual(sender2.fingerprint, bobPub.fingerprint)
    }
}
