import XCTest
@testable import AegisTransport

final class RelayWireTests: XCTestCase {

    private let mailboxHex = String(repeating: "ab", count: 32)
    private var mailbox: MailboxID { MailboxID(hex: mailboxHex)! }

    // MARK: - Client ops (must match relay.py's expected JSON)

    func testBindEncodes() {
        XCTAssertEqual(
            RelayClientOp.bind(mailbox).encode(),
            #"{"op":"bind","mailbox":""# + mailboxHex + #""}"#
        )
    }

    func testUnbindEncodes() {
        XCTAssertEqual(
            RelayClientOp.unbind(mailbox).encode(),
            #"{"op":"unbind","mailbox":""# + mailboxHex + #""}"#
        )
    }

    func testAuthEncodesAndEscapes() {
        // Token with characters that would break naive string interpolation.
        let encoded = RelayClientOp.auth(token: #"a"b\c"#).encode()
        XCTAssertEqual(encoded, #"{"op":"auth","token":"a\"b\\c"}"#)
    }

    func testPingEncodes() {
        XCTAssertEqual(RelayClientOp.ping.encode(), #"{"op":"ping"}"#)
    }

    // MARK: - Server messages (must match relay.py's emitted JSON)

    func testParsesHello() {
        let msg = RelayServerMessage.parse(
            #"{"hello":{"v":1,"max_payload":5242880,"ttl_default":604800,"ttl_max":1209600,"send_burst":40,"send_rate":8.0,"auth_required":false}}"#
        )
        XCTAssertEqual(msg, .hello(maxPayload: 5_242_880, ttlDefault: 604_800, ttlMax: 1_209_600, authRequired: false))
    }

    func testParsesHelloAuthRequired() {
        let msg = RelayServerMessage.parse(#"{"hello":{"auth_required":true}}"#)
        if case .hello(_, _, _, let required) = msg {
            XCTAssertTrue(required)
        } else {
            XCTFail("expected hello, got \(msg)")
        }
    }

    func testParsesAck() {
        let id = String(repeating: "cd", count: 16)
        XCTAssertEqual(
            RelayServerMessage.parse(#"{"ack":{"id":"\#(id)"}}"#),
            .ack(envelopeIDHex: id)
        )
    }

    func testParsesDrained() {
        XCTAssertEqual(
            RelayServerMessage.parse(#"{"drained":{"mailbox":"\#(mailboxHex)"}}"#),
            .drained(mailboxHex: mailboxHex)
        )
    }

    func testParsesPong() {
        XCTAssertEqual(RelayServerMessage.parse(#"{"pong":true}"#), .pong)
    }

    func testParsesErrors() {
        for code in ["rate_limited", "bad_frame", "bad_mailbox", "unauthorized", "unknown_op"] {
            XCTAssertEqual(
                RelayServerMessage.parse(#"{"error":{"code":"\#(code)"}}"#),
                .error(code: code)
            )
        }
    }

    func testParsesGarbageAsUnknown() {
        XCTAssertEqual(RelayServerMessage.parse("not json"), .unknown)
        XCTAssertEqual(RelayServerMessage.parse(#"{"weird":1}"#), .unknown)
    }
}
