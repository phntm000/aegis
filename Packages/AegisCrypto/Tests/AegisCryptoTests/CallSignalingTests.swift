import CryptoKit
import Foundation
import XCTest
@testable import AegisCrypto

final class CallSignalingTests: XCTestCase {
    private func roundTrip(_ signal: CallSignal) throws -> CallSignal {
        let data = try JSONEncoder().encode(signal)
        return try JSONDecoder().decode(CallSignal.self, from: data)
    }

    func testOfferRoundTrip() throws {
        let offer = CallOffer(
            callID: "call-1", sdp: "v=0\r\n…",
            dtlsFingerprint: "SHA-256:AA:BB:CC",
            callerFingerprintHex: "deadbeef"
        )
        let decoded = try roundTrip(.offer(offer))
        XCTAssertEqual(decoded, .offer(offer))
    }

    func testAnswerRoundTrip() throws {
        let answer = CallAnswer(callID: "call-1", sdp: "v=0\r\n…", dtlsFingerprint: "SHA-256:DD:EE:FF")
        XCTAssertEqual(try roundTrip(.answer(answer)), .answer(answer))
    }

    func testIceRoundTrip() throws {
        let ice = IceCandidate(callID: "call-1", candidate: "candidate:1 …", sdpMLineIndex: 0, sdpMid: "audio")
        XCTAssertEqual(try roundTrip(.ice(ice)), .ice(ice))
    }

    func testControlRoundTrip() throws {
        for control in [CallControl.ringing, .reject, .busy, .hangup, .acceptedElsewhere] as [CallControl] {
            XCTAssertEqual(
                try roundTrip(.control(callID: "call-1", control: control)),
                .control(callID: "call-1", control: control)
            )
        }
    }

    func testCallSASIsDeterministicAndOrderIndependent() throws {
        let a = try Random.bytes(count: 32)
        let b = try Random.bytes(count: 32)
        let ab = CallSAS.shortAuthString(localDTLSFingerprint: a, remoteDTLSFingerprint: b)
        let ba = CallSAS.shortAuthString(localDTLSFingerprint: b, remoteDTLSFingerprint: a)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab.count, 4)
        for char in ab {
            XCTAssertTrue(CallSAS.alphabet.contains(char), "SAS char \(char) not in alphabet")
        }
    }

    func testCallSASDiffersAcrossFingerprints() throws {
        let a = try Random.bytes(count: 32)
        let b = try Random.bytes(count: 32)
        let c = try Random.bytes(count: 32)
        XCTAssertNotEqual(
            CallSAS.shortAuthString(localDTLSFingerprint: a, remoteDTLSFingerprint: b),
            CallSAS.shortAuthString(localDTLSFingerprint: a, remoteDTLSFingerprint: c)
        )
    }
}
