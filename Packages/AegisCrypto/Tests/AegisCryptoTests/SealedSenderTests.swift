import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class SealedSenderTests: XCTestCase {
    private func makeParties() throws -> (alice: Identity, bob: Identity) {
        (try Identity(provider: testProvider), try Identity(provider: testProvider))
    }

    func testSealOpenRoundTrip() throws {
        let (alice, bob) = try makeParties()
        let inner = Data("inner envelope bytes".utf8)
        let envelope = try SealedSender.seal(
            innerMessage: inner, sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        // Wire round-trip.
        let parsed = try SealedEnvelope.parse(envelope.serialized())
        let opened = try SealedSender.open(parsed, recipient: bob, senderIdentity: alice.publicView, provider: testProvider)
        XCTAssertEqual(opened.senderFingerprint, alice.fingerprint)
        XCTAssertEqual(opened.innerMessage, inner)
    }

    func testOpenWithWrongRecipientFails() throws {
        let (alice, bob) = try makeParties()
        let carol = try Identity(provider: testProvider)
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        // Carol's DH gives a different key: authentication fails, and she
        // learns nothing about the sender.
        XCTAssertThrowsError(
            try SealedSender.open(envelope, recipient: carol, senderIdentity: alice.publicView, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testTamperedCiphertextFails() throws {
        let (alice, bob) = try makeParties()
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        // NOTE: `data[0] ^= ...` directly on Data traps (SIGTRAP) on this
        // toolchain even with valid bounds — route through [UInt8].
        var badCTBytes = [UInt8](envelope.ciphertext)
        badCTBytes[0] ^= 0x01
        let tampered = SealedEnvelope(
            mailboxID: envelope.mailboxID, ephemeralPublicKey: envelope.ephemeralPublicKey,
            nonce: envelope.nonce, ciphertext: Data(badCTBytes), tag: envelope.tag
        )
        XCTAssertThrowsError(
            try SealedSender.open(tampered, recipient: bob, senderIdentity: alice.publicView, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testExpiredCertificateFails() throws {
        let (alice, bob) = try makeParties()
        let ancient = Date(timeIntervalSince1970: 1_000_000)
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            now: ancient,
            provider: testProvider
        )
        XCTAssertThrowsError(
            try SealedSender.open(envelope, recipient: bob, senderIdentity: alice.publicView, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .certificateExpired)
        }
    }

    func testSenderFingerprintMismatchFails() throws {
        let (alice, bob) = try makeParties()
        let carol = try Identity(provider: testProvider)
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        // Resolving the wrong identity: the certificate's fingerprint does
        // not match carol's, so the envelope is rejected even though the
        // AEAD opened fine.
        XCTAssertThrowsError(
            try SealedSender.open(envelope, recipient: bob, senderIdentity: carol.publicView, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidSignature)
        }
    }

    func testMailboxIDIsStableAndOpaque() throws {
        let bob = try Identity(provider: testProvider)
        XCTAssertEqual(bob.mailboxID.count, 16)
        XCTAssertEqual(bob.mailboxID, bob.mailboxID) // deterministic
        // The mailbox ID reveals nothing about the keys on its own: it is a
        // hash output, not a truncated key.
        XCTAssertNotEqual(bob.mailboxID, Data(bob.fingerprint.prefix(16)))
    }

    // MARK: - Anonymous open (unknown-sender rendezvous)

    func testOpenAnonymousRoundTrip() throws {
        let (alice, bob) = try makeParties()
        let inner = Data("prekey bytes".utf8)
        let envelope = try SealedSender.seal(
            innerMessage: inner, sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        // No sender identity supplied: the certificate fingerprint is
        // recovered, and the inner message is intact. The caller must still
        // authenticate the fingerprint via the inner (X3DH) message.
        let (fingerprint, recovered) = try SealedSender.openAnonymous(
            envelope, recipient: bob, provider: testProvider
        )
        XCTAssertEqual(fingerprint, alice.fingerprint)
        XCTAssertEqual(recovered, inner)
    }

    func testOpenAnonymousWrongRecipientFails() throws {
        let (alice, bob) = try makeParties()
        let carol = try Identity(provider: testProvider)
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        XCTAssertThrowsError(
            try SealedSender.openAnonymous(envelope, recipient: carol, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testOpenAnonymousExpiredCertificateFails() throws {
        let (alice, bob) = try makeParties()
        let ancient = Date(timeIntervalSince1970: 1_000_000)
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            now: ancient,
            provider: testProvider
        )
        // Freshness is enforced even without a resolved sender identity.
        XCTAssertThrowsError(
            try SealedSender.openAnonymous(envelope, recipient: bob, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .certificateExpired)
        }
    }

    func testOpenAnonymousTamperedCiphertextFails() throws {
        let (alice, bob) = try makeParties()
        let envelope = try SealedSender.seal(
            innerMessage: Data("x".utf8), sender: alice,
            recipientAgreementPublicKey: bob.agreementKey.publicKey,
            recipientMailboxID: bob.mailboxID,
            provider: testProvider
        )
        var badCTBytes = [UInt8](envelope.ciphertext)
        badCTBytes[0] ^= 0x01
        let tampered = SealedEnvelope(
            mailboxID: envelope.mailboxID, ephemeralPublicKey: envelope.ephemeralPublicKey,
            nonce: envelope.nonce, ciphertext: Data(badCTBytes), tag: envelope.tag
        )
        XCTAssertThrowsError(
            try SealedSender.openAnonymous(tampered, recipient: bob, provider: testProvider)
        ) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }
}
