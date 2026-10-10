import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class X3DHTests: XCTestCase {
    private func rootFingerprint(_ key: SymmetricKey) -> Data {
        HKDF.hmac(key: key, message: Data("test-compare".utf8))
    }

    private func makeParties() throws -> (alice: Identity, bob: Identity, bobKeys: PreKeyManager) {
        let alice = try Identity(provider: testProvider)
        let bob = try Identity(provider: testProvider)
        let bobKeys = try PreKeyManager(identity: bob, provider: testProvider)
        return (alice, bob, bobKeys)
    }

    // MARK: - Agreement

    func testHandshakeAgreementWithOneTimePreKey() throws {
        let (alice, _, bobKeys) = try makeParties()
        let bundle = try bobKeys.currentBundle()

        let initiated = try X3DH.initiate(ourIdentity: alice, bundle: bundle, provider: testProvider)
        XCTAssertNotNil(initiated.usedOneTimePreKeyID)

        let opk = try XCTUnwrap(initiated.usedOneTimePreKeyID.flatMap { bobKeys.consumeOneTimePreKey($0) })
        let bobRoot = try X3DH.respond(
            ourIdentity: bobKeys.identity,
            ourSignedPreKey: bobKeys.signedPreKey,
            usedOneTimePreKey: opk,
            initiator: alice.publicView,
            ephemeralPublicKey: initiated.ephemeralPublicKey,
            provider: testProvider
        )
        XCTAssertEqual(rootFingerprint(initiated.rootKey), rootFingerprint(bobRoot))
    }

    func testHandshakeAgreementWithoutOneTimePreKey() throws {
        let (alice, bob, bobKeys) = try makeParties()
        // A bundle with no one-time prekey (contact ran out).
        let bundle = try PreKeyBundle.build(
            identity: bob.publicView,
            signedPreKey: bobKeys.signedPreKey,
            oneTimePreKey: nil,
            provider: testProvider
        )
        let initiated = try X3DH.initiate(ourIdentity: alice, bundle: bundle, provider: testProvider)
        XCTAssertNil(initiated.usedOneTimePreKeyID)

        let bobRoot = try X3DH.respond(
            ourIdentity: bob,
            ourSignedPreKey: bobKeys.signedPreKey,
            usedOneTimePreKey: nil,
            initiator: alice.publicView,
            ephemeralPublicKey: initiated.ephemeralPublicKey,
            provider: testProvider
        )
        XCTAssertEqual(rootFingerprint(initiated.rootKey), rootFingerprint(bobRoot))
    }

    func testTamperedBundleFails() throws {
        let (alice, _, bobKeys) = try makeParties()
        var wire = try bobKeys.currentBundle().serialized()
        // Flip a byte in the signed-prekey public key region.
        wire[70] ^= 0xFF
        let tampered = try PreKeyBundle(serialized: wire)
        XCTAssertFalse(tampered.verify(provider: testProvider))
        XCTAssertThrowsError(try X3DH.initiate(ourIdentity: alice, bundle: tampered, provider: testProvider)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidSignature)
        }
    }

    func testWrongResponderKeyDisagrees() throws {
        let (alice, _, bobKeys) = try makeParties()
        let bundle = try bobKeys.currentBundle()
        let initiated = try X3DH.initiate(ourIdentity: alice, bundle: bundle, provider: testProvider)

        // A different responder keypair answers: the handshake completes
        // (X3DH has no live authentication) but derives a different key —
        // which is why the first Double-Ratchet message must authenticate.
        let impostorSPK = try SignedPreKey.generate(id: 999, identity: bobKeys.identity, provider: testProvider)
        let opk = initiated.usedOneTimePreKeyID.flatMap { bobKeys.consumeOneTimePreKey($0) }
        let impostorRoot = try X3DH.respond(
            ourIdentity: bobKeys.identity,
            ourSignedPreKey: impostorSPK,
            usedOneTimePreKey: opk,
            initiator: alice.publicView,
            ephemeralPublicKey: initiated.ephemeralPublicKey,
            provider: testProvider
        )
        XCTAssertNotEqual(rootFingerprint(initiated.rootKey), rootFingerprint(impostorRoot))
    }

    // MARK: - PreKeyManager

    func testBundleVerifies() throws {
        let (_, _, bobKeys) = try makeParties()
        let bundle = try bobKeys.currentBundle()
        XCTAssertTrue(bundle.verify(provider: testProvider))
        // Wire round-trip preserves verifiability.
        XCTAssertTrue(try PreKeyBundle(serialized: bundle.serialized()).verify(provider: testProvider))
    }

    func testOneTimePreKeyConsumptionIsSingleUse() throws {
        let (_, _, bobKeys) = try makeParties()
        let bundle = try bobKeys.currentBundle()
        let opkID = try XCTUnwrap(bundle.oneTimePreKey?.id)
        XCTAssertNotNil(bobKeys.consumeOneTimePreKey(opkID))
        // Second consumption fails: the key is gone (replay protection).
        XCTAssertNil(bobKeys.consumeOneTimePreKey(opkID))
    }
}
