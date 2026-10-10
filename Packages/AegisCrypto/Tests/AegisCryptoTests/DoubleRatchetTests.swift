import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class DoubleRatchetTests: XCTestCase {
    /// Establishes a live session pair via X3DH + prekey message.
    private func makeSessionPair() throws -> (alice: AegisDoubleRatchet, bob: AegisDoubleRatchet) {
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
        XCTAssertEqual(responded.plaintext, Data("hello bob".utf8))
        return (initiated.session, responded.session)
    }

    // MARK: - Basic round trips

    func testMultipleMessagesInOrder() throws {
        let (alice, bob) = try makeSessionPair()
        for i in 0 ..< 10 {
            let plaintext = Data("message \(i)".utf8)
            let encrypted = try alice.encrypt(plaintext: plaintext)
            XCTAssertEqual(try bob.decrypt(encrypted), plaintext)
        }
        for i in 0 ..< 10 {
            let plaintext = Data("reply \(i)".utf8)
            let encrypted = try bob.encrypt(plaintext: plaintext)
            XCTAssertEqual(try alice.decrypt(encrypted), plaintext)
        }
    }

    func testAssociatedDataBinding() throws {
        let (alice, bob) = try makeSessionPair()
        let encrypted = try alice.encrypt(plaintext: Data("x".utf8), associatedData: Data("ctx-a".utf8))
        XCTAssertEqual(try bob.decrypt(encrypted, associatedData: Data("ctx-a".utf8)), Data("x".utf8))
        // Fresh message: wrong associated data must fail authentication.
        // (Re-decrypting `encrypted` would hit "key already consumed" —
        // forward secrecy deletes the key after first use, which is correct.)
        let tampered = try alice.encrypt(plaintext: Data("y".utf8), associatedData: Data("ctx-a".utf8))
        XCTAssertThrowsError(try bob.decrypt(tampered, associatedData: Data("ctx-b".utf8))) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    // MARK: - Out-of-order delivery

    func testOutOfOrderMessages() throws {
        let (alice, bob) = try makeSessionPair()
        let m0 = try alice.encrypt(plaintext: Data("zero".utf8))
        let m1 = try alice.encrypt(plaintext: Data("one".utf8))
        let m2 = try alice.encrypt(plaintext: Data("two".utf8))
        // Delivered 2, 0, 1.
        XCTAssertEqual(try bob.decrypt(m2), Data("two".utf8))
        XCTAssertEqual(try bob.decrypt(m0), Data("zero".utf8))
        XCTAssertEqual(try bob.decrypt(m1), Data("one".utf8))
    }

    func testOutOfOrderAcrossRatchetStep() throws {
        let (alice, bob) = try makeSessionPair()
        // Alice sends two messages on her first chain.
        let a0 = try alice.encrypt(plaintext: Data("a0".utf8))
        let a1 = try alice.encrypt(plaintext: Data("a1".utf8))
        XCTAssertEqual(try bob.decrypt(a0), Data("a0".utf8))
        // Bob replies: this carries his new ratchet key.
        let b0 = try bob.encrypt(plaintext: Data("b0".utf8))
        XCTAssertEqual(try alice.decrypt(b0), Data("b0".utf8))
        // Alice's next message has pn=2 (two messages on her old chain).
        // Deliver it BEFORE a1: bob must stash a1's key via pn, ratchet,
        // decrypt a2, then decrypt the late a1 from the skipped store.
        let a2 = try alice.encrypt(plaintext: Data("a2".utf8))
        XCTAssertEqual(try bob.decrypt(a2), Data("a2".utf8))
        XCTAssertEqual(try bob.decrypt(a1), Data("a1".utf8))
    }

    // MARK: - Forward secrecy

    func testForwardSecrecyOldKeysDeleted() throws {
        let (alice, bob) = try makeSessionPair()
        let m0 = try alice.encrypt(plaintext: Data("zero".utf8))
        _ = try alice.encrypt(plaintext: Data("one".utf8))
        XCTAssertEqual(try bob.decrypt(m0), Data("zero".utf8))
        // The message key for m0 was consumed on use: re-decrypting the
        // same ciphertext fails — the key no longer exists.
        XCTAssertThrowsError(try bob.decrypt(m0)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .messageTooOld)
        }
    }

    // MARK: - Tampering

    func testTamperedCiphertextFails() throws {
        let (alice, bob) = try makeSessionPair()
        let message = try alice.encrypt(plaintext: Data("secret".utf8))
        var tampered = message.ciphertext
        tampered[0] ^= 0x01
        let forged = RatchetMessage(header: message.header, nonce: message.nonce, ciphertext: tampered, tag: message.tag)
        XCTAssertThrowsError(try bob.decrypt(forged)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .authenticationFailed)
        }
    }

    func testTamperedHeaderFails() throws {
        let (alice, bob) = try makeSessionPair()
        let message = try alice.encrypt(plaintext: Data("secret".utf8))
        // Flip pn: the header is authenticated (AAD), so this must fail.
        let badHeader = RatchetHeader(
            ratchetPublicKey: message.header.ratchetPublicKey,
            previousChainLength: message.header.previousChainLength ^ 0xFF,
            messageNumber: message.header.messageNumber
        )
        let forged = RatchetMessage(header: badHeader, nonce: message.nonce, ciphertext: message.ciphertext, tag: message.tag)
        XCTAssertThrowsError(try bob.decrypt(forged))
    }

    // MARK: - Bounds

    func testMessageTooFarInFuture() throws {
        let (alice, bob) = try makeSessionPair()
        let first = try alice.encrypt(plaintext: Data("first".utf8))
        XCTAssertEqual(try bob.decrypt(first), Data("first".utf8))
        // Forge a header 5000 messages ahead on the same chain: the gap
        // check must fire before any AEAD work.
        let forged = RatchetMessage(
            header: RatchetHeader(
                ratchetPublicKey: first.header.ratchetPublicKey,
                previousChainLength: 0,
                messageNumber: 5_000
            ),
            nonce: Data(repeating: 0, count: 12),
            ciphertext: Data(),
            tag: Data(repeating: 0, count: 16)
        )
        XCTAssertThrowsError(try bob.decrypt(forged)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .messageTooFarInFuture)
        }
    }

    // MARK: - Wire format

    func testRatchetMessageWireRoundTrip() throws {
        let (alice, _) = try makeSessionPair()
        let message = try alice.encrypt(plaintext: Data("wire".utf8))
        let parsed = try RatchetMessage.parse(message.serialized())
        XCTAssertEqual(parsed.header, message.header)
        XCTAssertEqual(parsed.nonce, message.nonce)
        XCTAssertEqual(parsed.ciphertext, message.ciphertext)
        XCTAssertEqual(parsed.tag, message.tag)
    }

    func testPreKeyMessageWireRoundTrip() throws {
        let aliceID = try Identity(provider: testProvider)
        let bobID = try Identity(provider: testProvider)
        let bobKeys = try PreKeyManager(identity: bobID, provider: testProvider)
        let initiated = try SessionEstablishment.initiate(
            ourIdentity: aliceID, bundle: try bobKeys.currentBundle(),
            plaintext: Data("first".utf8), provider: testProvider
        )
        let parsed = try PreKeyMessage.parse(initiated.preKeyMessage)
        XCTAssertEqual(parsed.ephemeralPublicKey.count, 32)
        XCTAssertEqual(parsed.senderIdentity.fingerprint, aliceID.fingerprint)
    }
}
