import XCTest
import WebRTCBridge

/// Unit tests for the SDP DTLS fingerprint parser used by the WebRTC media
/// engine. The parser is pure Swift (no native framework), so these run on
/// the simulator without camera or network.
final class SDPFingerprintTests: XCTestCase {

    private let sampleSDP = """
        v=0\r
        o=- 1234 2 IN IP4 127.0.0.1\r
        s=-\r
        t=0 0\r
        a=fingerprint:sha-256 4A:5B:6C:7D:8E:9F:0A:1B:2C:3D:4E:5F:6A:7B:8C:9D:0E:1F:2A:3B:4C:5D:6E:7F:8A:9B:0C:1D:2E:3F:4A:5B\r
        a=setup:actpass\r
        """

    func testExtractsSHA256Fingerprint() {
        let result = SDPFingerprint.extract(from: sampleSDP)
        XCTAssertEqual(
            result,
            "SHA-256:4A:5B:6C:7D:8E:9F:0A:1B:2C:3D:4E:5F:6A:7B:8C:9D:0E:1F:2A:3B:4C:5D:6E:7F:8A:9B:0C:1D:2E:3F:4A:5B"
        )
    }

    func testNilWhenNoFingerprintLine() {
        XCTAssertNil(SDPFingerprint.extract(from: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n"))
        XCTAssertNil(SDPFingerprint.extract(from: ""))
    }

    func testNilForMalformedHex() {
        XCTAssertNil(SDPFingerprint.extract(from: "a=fingerprint:sha-256 NOT-HEX-AT-ALL"))
        XCTAssertNil(SDPFingerprint.extract(from: "a=fingerprint:sha-256 4A:5B:ZZ"))
    }

    func testNormalizesAlgorithmCasing() {
        let sdp = "a=fingerprint:SHA-256 4A:5B"
        XCTAssertEqual(SDPFingerprint.extract(from: sdp), "SHA-256:4A:5B")
    }

    func testLowercaseHexIsUppercased() {
        let sdp = "a=fingerprint:sha-256 4a:5b:6c"
        XCTAssertEqual(SDPFingerprint.extract(from: sdp), "SHA-256:4A:5B:6C")
    }

    func testIgnoresNonFingerprintLines() {
        let sdp = "a=setup:actpass\r\na=fingerprint:sha-1 11:22:33\r\n"
        XCTAssertEqual(SDPFingerprint.extract(from: sdp), "SHA-1:11:22:33")
    }
}
