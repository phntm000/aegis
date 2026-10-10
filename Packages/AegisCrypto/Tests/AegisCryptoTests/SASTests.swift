import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class SASTests: XCTestCase {
    func testSafetyNumberIsOrderIndependent() throws {
        let alice = try Identity(provider: testProvider)
        let bob = try Identity(provider: testProvider)
        let ab = SafetyNumber.compute(localFingerprint: alice.fingerprint, remoteFingerprint: bob.fingerprint)
        let ba = SafetyNumber.compute(localFingerprint: bob.fingerprint, remoteFingerprint: alice.fingerprint)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab.count, 30)
    }

    func testSafetyNumberDisplayFormat() throws {
        let alice = try Identity(provider: testProvider)
        let bob = try Identity(provider: testProvider)
        let number = SafetyNumber.compute(localFingerprint: alice.fingerprint, remoteFingerprint: bob.fingerprint)
        let display = SafetyNumber.displayString(number)
        let groups = display.split(separator: " ")
        XCTAssertEqual(groups.count, 15)
        for group in groups {
            XCTAssertEqual(group.count, 5)
            XCTAssertNotNil(UInt(group))
        }
    }

    func testSafetyNumberDiffersAcrossPairs() throws {
        let alice = try Identity(provider: testProvider)
        let bob = try Identity(provider: testProvider)
        let carol = try Identity(provider: testProvider)
        let ab = SafetyNumber.compute(localFingerprint: alice.fingerprint, remoteFingerprint: bob.fingerprint)
        let ac = SafetyNumber.compute(localFingerprint: alice.fingerprint, remoteFingerprint: carol.fingerprint)
        XCTAssertNotEqual(ab, ac)
    }

    func testVerificationQRRoundTrip() throws {
        let alice = try Identity(provider: testProvider)
        let payload = VerificationQR.payload(for: alice)
        XCTAssertEqual(payload.count, 97)
        let parsed = try VerificationQR.parse(payload)
        XCTAssertEqual(parsed.fingerprint, alice.fingerprint)
        XCTAssertEqual(parsed.signingPublicKey, alice.signingKey.publicKey)
    }

    func testVerificationQRForgedFingerprintFails() throws {
        let alice = try Identity(provider: testProvider)
        var payload = VerificationQR.payload(for: alice)
        // Corrupt the trailing fingerprint bytes: the binding check fails.
        payload[payload.count - 1] ^= 0xFF
        XCTAssertThrowsError(try VerificationQR.parse(payload)) { error in
            XCTAssertEqual(error as? AegisCryptoError, .invalidSignature)
        }
    }

    func testVerificationStateCodable() throws {
        let encoded = try JSONEncoder().encode(VerificationState.changed)
        XCTAssertEqual(try JSONDecoder().decode(VerificationState.self, from: encoded), .changed)
    }
}
