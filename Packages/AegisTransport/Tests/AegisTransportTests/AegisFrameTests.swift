import XCTest
@testable import AegisTransport

final class AegisFrameTests: XCTestCase {

    private func sampleFrame(payload: Data = Data("hello aegis".utf8)) -> AegisFrame {
        AegisFrame(
            mailbox: MailboxID(Data(repeating: 0x01, count: 32)),
            envelopeID: Data(repeating: 0x02, count: 16),
            ttl: 60,
            flags: 0,
            payload: payload
        )
    }

    // MARK: - Round trips

    func testEncodeDecodeRoundTrip() throws {
        for size in [0, 1, 1_000, 65_536] {
            let frame = sampleFrame(payload: Data((0..<size).map { UInt8($0 & 0xFF) }))
            let decoded = try AegisFrame.decode(frame.encode())
            XCTAssertEqual(decoded, frame, "round trip failed for payload size \(size)")
        }
    }

    func testKnownVectorDecodes() throws {
        // mailbox = 32×0x01, envelopeID = 16×0x02, ttl = 60, flags = 0,
        // payload = "hi"
        var hex = "4147" + "01" + "00"
        hex += String(repeating: "01", count: 32)
        hex += String(repeating: "02", count: 16)
        hex += "0000003c" // ttl = 60
        hex += "00000002" // len = 2
        hex += "6869"    // "hi"
        let data = Data(hexBytes: hex)!
        let frame = try AegisFrame.decode(data)
        XCTAssertEqual(frame.mailbox.bytes, Data(repeating: 0x01, count: 32))
        XCTAssertEqual(frame.envelopeID, Data(repeating: 0x02, count: 16))
        XCTAssertEqual(frame.ttl, 60)
        XCTAssertEqual(frame.flags, 0)
        XCTAssertEqual(frame.payload, Data("hi".utf8))
        // And it re-encodes to the identical bytes (relay compatibility).
        XCTAssertEqual(try frame.encode(), data)
    }

    func testFlagsSurviveRoundTrip() throws {
        var frame = sampleFrame()
        frame.flags = AegisFrame.flagFinalChunk
        let decoded = try AegisFrame.decode(frame.encode())
        XCTAssertEqual(decoded.flags, AegisFrame.flagFinalChunk)
        XCTAssertTrue(decoded.isFinalChunk)
        XCTAssertFalse(decoded.isKnock)
    }

    func testKnockFlagSurvivesRoundTrip() throws {
        // A knock is an ordinary sealed envelope with bit 1 set and a short
        // TTL — the relay forwards it opaquely like any other frame.
        var frame = sampleFrame(payload: Data("sealed-knock".utf8))
        frame.flags = AegisFrame.flagKnock
        frame.ttl = 300
        let decoded = try AegisFrame.decode(frame.encode())
        XCTAssertTrue(decoded.isKnock)
        XCTAssertFalse(decoded.isFinalChunk)
        XCTAssertEqual(decoded.ttl, 300)
        XCTAssertEqual(decoded.payload, Data("sealed-knock".utf8))
    }

    func testKnockAndFinalChunkBitsAreIndependent() {
        XCTAssertEqual(AegisFrame.flagKnock & AegisFrame.flagFinalChunk, 0)
    }

    // MARK: - Rejection

    func testRejectsBadMagic() {
        var data = try! sampleFrame().encode()
        data[0] = 0xFF
        XCTAssertThrowsError(try AegisFrame.decode(data))
    }

    func testRejectsWrongVersion() {
        var data = try! sampleFrame().encode()
        data[2] = 0x02
        XCTAssertThrowsError(try AegisFrame.decode(data))
    }

    func testRejectsTruncatedHeader() {
        let data = try! sampleFrame().encode()
        XCTAssertThrowsError(try AegisFrame.decode(data.prefix(59)))
    }

    func testRejectsTruncatedPayload() {
        var data = try! sampleFrame().encode()
        data.removeLast(3)
        XCTAssertThrowsError(try AegisFrame.decode(data))
    }

    func testRejectsTrailingGarbage() {
        var data = try! sampleFrame().encode()
        data.append(0x00)
        XCTAssertThrowsError(try AegisFrame.decode(data))
    }

    func testRejectsDeclaredLengthMismatch() {
        var data = try! sampleFrame().encode()
        // Claim a 1 MB payload while only carrying 10 bytes.
        data[56] = 0x00; data[57] = 0x10; data[58] = 0x00; data[59] = 0x00
        XCTAssertThrowsError(try AegisFrame.decode(data))
    }

    func testEncodeRejectsOversizePayload() {
        let frame = sampleFrame(payload: Data(repeating: 0xAA, count: AegisFrame.maxPayloadSize + 1))
        XCTAssertThrowsError(try frame.encode()) { error in
            XCTAssertEqual(error as? TransportError, .frameTooLarge(AegisFrame.maxPayloadSize + 1))
        }
    }

    func testEncodeAcceptsExactlyMaxPayload() throws {
        let frame = sampleFrame(payload: Data(repeating: 0xAA, count: AegisFrame.maxPayloadSize))
        let decoded = try AegisFrame.decode(frame.encode())
        XCTAssertEqual(decoded.payload.count, AegisFrame.maxPayloadSize)
    }

    // MARK: - MailboxID

    func testMailboxHexRoundTrip() {
        let id = MailboxID(Data((0..<32).map { UInt8($0) }))
        XCTAssertEqual(MailboxID(hex: id.hex), id)
    }

    func testMailboxHexRejectsGarbage() {
        XCTAssertNil(MailboxID(hex: "zz"))
        XCTAssertNil(MailboxID(hex: String(repeating: "ab", count: 31)))
        XCTAssertNil(MailboxID(hex: String(repeating: "ab", count: 33)))
    }

    func testMailboxDescriptionIsRedacted() {
        let id = MailboxID(Data(repeating: 0xAB, count: 32))
        XCTAssertFalse(id.description.contains(id.hex))
        XCTAssertTrue(id.description.hasPrefix("mailbox:"))
    }
}

// MARK: - Test helper

private extension Data {
    init?(hexBytes hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
