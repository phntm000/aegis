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

    // MARK: - KnockInfo (canonical knock type)

    func testKnockInfoRoundTrip() throws {
        let offer = CallOffer(
            callID: "call-9", sdp: "v=0\r\n…",
            dtlsFingerprint: "SHA-256:AA:BB:CC",
            callerFingerprintHex: "deadbeef"
        )
        let knock = KnockInfo(callID: "call-9", offer: offer, mediaKind: "video")
        let data = try JSONEncoder().encode(knock)
        let decoded = try JSONDecoder().decode(KnockInfo.self, from: data)
        XCTAssertEqual(decoded, knock)
        XCTAssertEqual(decoded.offer, offer)
        XCTAssertEqual(decoded.mediaKind, "video")
    }

    func testKnockInfoDefaults() throws {
        let offer = CallOffer(
            callID: "call-9", sdp: "", dtlsFingerprint: "", callerFingerprintHex: "")
        let knock = KnockInfo(callID: "call-9", offer: offer)
        XCTAssertEqual(knock.v, 1)
        XCTAssertEqual(knock.mediaKind, "audio")
    }

    // MARK: - Wire format stability

    /// The package's `"type"` discriminator is the canonical wire format.
    /// Pins it so an accidental rename breaks loudly instead of silently
    /// forking the protocol.
    func testCallSignalWireFormatPinsTypeDiscriminator() throws {
        let json = """
        {"type":"offer","offer":{"callID":"c1","sdp":"s","dtlsFingerprint":"SHA-256:AA","callerFingerprintHex":"ff","timestamp":123}}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(CallSignal.self, from: json)
        guard case .offer(let offer) = decoded else {
            return XCTFail("expected .offer, got \(decoded)")
        }
        XCTAssertEqual(offer.callID, "c1")
        XCTAssertEqual(offer.dtlsFingerprint, "SHA-256:AA")
        XCTAssertEqual(offer.timestamp, 123)

        // The legacy app-local "t" discriminator must NOT decode: the two
        // formats are intentionally distinct, and the package one wins.
        let legacy = """
        {"t":"offer","offer":{"callID":"c1","sdp":"s","dtlsFingerprint":"SHA-256:AA","callerFingerprintHex":"ff"}}
        """.data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(CallSignal.self, from: legacy))
    }

    // MARK: - SAS from hex fingerprint strings

    func testCallSASFromHexStringsIsOrderIndependent() throws {
        let a = "SHA-256:AA:BB:CC:DD"
        let b = "SHA-256:11:22:33:44"
        let ab = CallSAS.shortAuthString(localHex: a, remoteHex: b)
        let ba = CallSAS.shortAuthString(localHex: b, remoteHex: a)
        XCTAssertNotNil(ab)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab?.count, 4)
    }

    func testCallSASFromHexStringsMatchesDataForm() throws {
        let aHex = "SHA-256:AA:BB:CC"
        let bHex = "11:22:33"
        let fromHex = CallSAS.shortAuthString(localHex: aHex, remoteHex: bHex)
        let aData = Data([0xAA, 0xBB, 0xCC])
        let bData = Data([0x11, 0x22, 0x33])
        let fromData = CallSAS.shortAuthString(localDTLSFingerprint: aData, remoteDTLSFingerprint: bData)
        XCTAssertEqual(fromHex, fromData)
    }

    func testCallSASFromHexStringsRejectsEmptyAndMalformed() throws {
        XCTAssertNil(CallSAS.shortAuthString(localHex: "", remoteHex: "SHA-256:AA"))
        XCTAssertNil(CallSAS.shortAuthString(localHex: "SHA-256:AA", remoteHex: ""))
        // Odd-length hex.
        XCTAssertNil(CallSAS.shortAuthString(localHex: "SHA-256:ABC", remoteHex: "SHA-256:AA"))
        // Non-hex characters.
        XCTAssertNil(CallSAS.shortAuthString(localHex: "SHA-256:ZZ", remoteHex: "SHA-256:AA"))
    }

    func testParseDTLSFingerprintHex() throws {
        XCTAssertEqual(
            CallSAS.parseDTLSFingerprintHex("SHA-256:AA:BB:cc"),
            Data([0xAA, 0xBB, 0xCC]))
        // Bare hex without algorithm prefix also parses.
        XCTAssertEqual(
            CallSAS.parseDTLSFingerprintHex("AABBCC"),
            Data([0xAA, 0xBB, 0xCC]))
        XCTAssertNil(CallSAS.parseDTLSFingerprintHex(""))
        XCTAssertNil(CallSAS.parseDTLSFingerprintHex("SHA-256:ABC"))
        XCTAssertNil(CallSAS.parseDTLSFingerprintHex("not-hex!!"))
    }
}
