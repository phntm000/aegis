import XCTest
@testable import AegisTransport

final class RelayEndpointTests: XCTestCase {

    // MARK: - URL validation / normalization

    func testBareHostBecomesWSS() throws {
        let url = try RelayURLValidator.normalize("relay.example.com").get()
        XCTAssertEqual(url.scheme, "wss")
        XCTAssertEqual(url.host, "relay.example.com")
    }

    func testWSSAccepted() throws {
        let url = try RelayURLValidator.normalize("wss://relay.example.com:8443/path").get()
        XCTAssertEqual(url.scheme, "wss")
        XCTAssertEqual(url.host, "relay.example.com")
        XCTAssertEqual(url.port, 8443)
    }

    func testHTTPSNormalizedToWSS() throws {
        let url = try RelayURLValidator.normalize("https://relay.example.com").get()
        XCTAssertEqual(url.scheme, "wss")
    }

    func testHTTPBecomesWSButRejectedForNonLoopback() {
        let result = RelayURLValidator.normalize("http://relay.example.com")
        XCTAssertEqual(result, .failure(.cleartextNonLoopback))
    }

    func testWSAllowedForLocalhost() throws {
        let url = try RelayURLValidator.normalize("ws://localhost:8080").get()
        XCTAssertEqual(url.scheme, "ws")
        XCTAssertEqual(url.host, "localhost")
    }

    func testWSAllowedForLoopbackIP() throws {
        let url = try RelayURLValidator.normalize("ws://127.0.0.1:8080").get()
        XCTAssertEqual(url.scheme, "ws")
    }

    func testWSRejectedForNonLoopback() {
        XCTAssertEqual(
            RelayURLValidator.normalize("ws://relay.example.com"),
            .failure(.cleartextNonLoopback)
        )
    }

    func testEmptyRejected() {
        XCTAssertEqual(RelayURLValidator.normalize("   "), .failure(.empty))
    }

    func testUnsupportedSchemeRejected() {
        XCTAssertEqual(
            RelayURLValidator.normalize("ftp://relay.example.com"),
            .failure(.unsupportedScheme("ftp"))
        )
    }

    func testMissingHostRejected() {
        XCTAssertEqual(
            RelayURLValidator.normalize("wss://"),
            .failure(.missingHost)
        )
    }

    func testWhitespaceTrimmed() throws {
        let url = try RelayURLValidator.normalize("  wss://relay.example.com\n").get()
        XCTAssertEqual(url.host, "relay.example.com")
    }

    func testErrorDescriptionsAreUserFacing() {
        XCTAssertFalse(RelayURLValidationError.empty.description.isEmpty)
        XCTAssertFalse(RelayURLValidationError.unsupportedScheme("ftp").description.isEmpty)
        XCTAssertFalse(RelayURLValidationError.cleartextNonLoopback.description.isEmpty)
        XCTAssertFalse(RelayURLValidationError.missingHost.description.isEmpty)
        XCTAssertFalse(RelayURLValidationError.unparseable("x").description.isEmpty)
        // No raw values or jargon leak into user-facing text.
        XCTAssertFalse(RelayURLValidationError.cleartextNonLoopback.description.contains("TransportError"))
    }

    // MARK: - Mode resolution

    func testAutomaticWithNothingVerifiedResolvesToNil() {
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "automatic", customURL: nil, lastKnownGoodURL: nil
        ))
    }

    func testAutomaticNeverInventsAnEndpoint() {
        // Even with a custom URL set, automatic uses ONLY last-known-good.
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "automatic",
            customURL: "wss://relay.example.com",
            lastKnownGoodURL: nil
        ))
    }

    func testAutomaticFallsBackToLastKnownGood() {
        let url = RelayEndpointResolver.resolveURL(
            mode: "automatic", customURL: nil, lastKnownGoodURL: "wss://relay.example.com"
        )
        XCTAssertEqual(url?.absoluteString, "wss://relay.example.com")
    }

    func testAutomaticIgnoresStaleLastKnownGood() {
        // A last-known-good that no longer validates must not be used.
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "automatic", customURL: nil, lastKnownGoodURL: "not a url at all !!!"
        ))
    }

    func testCustomRelayUsesCustomURL() {
        let url = RelayEndpointResolver.resolveURL(
            mode: "customRelay",
            customURL: "relay.example.com",
            lastKnownGoodURL: nil
        )
        XCTAssertEqual(url?.scheme, "wss")
        XCTAssertEqual(url?.host, "relay.example.com")
    }

    func testCustomRelayWithInvalidURLResolvesToNil() {
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "customRelay", customURL: "ws://relay.example.com", lastKnownGoodURL: nil
        ))
    }

    func testLanOnlyAlwaysResolvesToNil() {
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "lanOnly",
            customURL: "wss://relay.example.com",
            lastKnownGoodURL: "wss://relay.example.com"
        ))
    }

    func testUnknownModeResolvesToNil() {
        XCTAssertNil(RelayEndpointResolver.resolveURL(
            mode: "something-else", customURL: nil, lastKnownGoodURL: nil
        ))
    }
}
