import CryptoKit
import Foundation
import XCTest
@testable import Aegis
@testable import AegisCrypto

/// Identity-sealed sender-key distributions: the fallback path used when a
/// group member shares no 1:1 session (and no bundle) with the recipient —
/// e.g. a new joiner exchanging keys with existing members they never added
/// as contacts.
///
/// Security properties under test:
/// - Roundtrip: seal(open(x)) == x, with sender binding intact.
/// - Forgery: a tampered signature fails closed.
/// - Unknown sender: no roster-attested identity key → fail closed.
/// - Wrong recipient: sealed for Bob does not open for Carol.
final class IdentitySealedDistributionTests: XCTestCase {
    private func makeEngine() -> CryptoEngine {
        CryptoEngine(contactIdentity: { _ in nil })
    }

    private func makePair() async throws -> (
        alice: CryptoEngine, bob: CryptoEngine,
        alicePub: IdentityPublic, bobPub: IdentityPublic
    ) {
        let alice = makeEngine()
        let bob = makeEngine()
        let alicePub = try await alice.createIdentity(displayName: "Alice")
        let bobPub = try await bob.createIdentity(displayName: "Bob")
        // Roster-attested identity keys (as a group invite/announcement
        // would provide).
        await alice.cacheKnownIdentity(bobPub)
        await bob.cacheKnownIdentity(alicePub)
        return (alice, bob, alicePub, bobPub)
    }

    private func aliceDistributionForBob(
        alice: CryptoEngine, bobPub: IdentityPublic
    ) async throws -> SenderKeyDistribution {
        var groupID = Data(count: 32)
        for i in 0..<32 { groupID[i] = UInt8.random(in: 0...255) }
        let distributions = try await alice.createGroup(groupID: groupID, members: [bobPub])
        XCTAssertEqual(distributions.count, 1)
        return distributions[0].distribution
    }

    func testSealOpenRoundtrip() async throws {
        let (alice, bob, _, bobPub) = try await makePair()
        let dist = try await aliceDistributionForBob(alice: alice, bobPub: bobPub)

        let sealed = try await alice.sealDistributionForIdentityKey(dist, recipient: bobPub)
        // Magic prefix for identity-route detection.
        XCTAssertTrue(sealed.prefix(4) == Data("AKD1".utf8))

        let opened = try await bob.openIdentitySealedDistribution(sealed)
        XCTAssertEqual(opened.groupID, dist.groupID)
        XCTAssertEqual(opened.senderID, dist.senderID)
        XCTAssertEqual(opened.chainKey, dist.chainKey)
        XCTAssertEqual(opened.signingPublicKey, dist.signingPublicKey)
    }

    func testTamperedSignatureFailsClosed() async throws {
        let (alice, bob, _, bobPub) = try await makePair()
        let dist = try await aliceDistributionForBob(alice: alice, bobPub: bobPub)
        var sealed = try await alice.sealDistributionForIdentityKey(dist, recipient: bobPub)
        // Flip a byte in the trailing signature.
        sealed[sealed.count - 1] ^= 0xFF
        do {
            _ = try await bob.openIdentitySealedDistribution(sealed)
            XCTFail("tampered signature must fail")
        } catch {
            // Expected: invalidSignature (or authenticationFailed).
        }
    }

    func testUnknownSenderFailsClosed() async throws {
        let (alice, bob, _, bobPub) = try await makePair()
        let dist = try await aliceDistributionForBob(alice: alice, bobPub: bobPub)
        let sealed = try await alice.sealDistributionForIdentityKey(dist, recipient: bobPub)

        // Carol never received Alice's roster-attested identity key.
        let carol = makeEngine()
        _ = try await carol.createIdentity(displayName: "Carol")
        do {
            _ = try await carol.openIdentitySealedDistribution(sealed)
            XCTFail("unknown sender must fail")
        } catch {
            // Expected.
        }
    }

    func testWrongRecipientFailsClosed() async throws {
        let (alice, bob, _, bobPub) = try await makePair()
        let dist = try await aliceDistributionForBob(alice: alice, bobPub: bobPub)
        // Sealed for Bob...
        let sealed = try await alice.sealDistributionForIdentityKey(dist, recipient: bobPub)

        // ...Carol tries to open it. (Carol knows Alice's key, but the
        // envelope is bound to Bob's fingerprint.)
        let carol = makeEngine()
        let carolPub = try await carol.createIdentity(displayName: "Carol")
        await carol.cacheKnownIdentity(bobPub)
        _ = carolPub
        // Carol does NOT know Alice; even if she did, recipient binding fails.
        await carol.cacheKnownIdentity(try await alice.localPublicIdentity())
        do {
            _ = try await carol.openIdentitySealedDistribution(sealed)
            XCTFail("wrong recipient must fail")
        } catch {
            // Expected: authenticationFailed (recipient fingerprint mismatch).
        }
    }
}
