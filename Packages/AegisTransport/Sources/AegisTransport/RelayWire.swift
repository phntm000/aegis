import Foundation

// MARK: - Relay control channel
//
// The relay speaks WebSocket. Two message kinds:
//   - binary frames: AegisFrame envelopes (client→relay = store+forward,
//     relay→client = delivery of queued/live envelopes)
//   - text frames: JSON control messages defined here.
//
// Client → relay:
//   {"op":"auth","token":"…"}        optional; only if the relay requires it
//   {"op":"bind","mailbox":"<hex64>"}   subscribe; relay drains the queue, then streams live
//   {"op":"unbind","mailbox":"<hex64>"}
//   {"op":"ping"}
//
// Relay → client:
//   {"hello":{"v":1,"max_payload":5242880,"ttl_default":604800,"ttl_max":1209600,
//              "send_burst":40,"send_rate":8.0,"auth_required":false}}
//   {"ack":{"id":"<envelope hex>"}}
//   {"drained":{"mailbox":"<hex64>"}}
//   {"pong":true}
//   {"error":{"code":"rate_limited"|"bad_frame"|"bad_mailbox"|"unauthorized"|"unknown_op"}}

/// Operations the client sends to the relay.
public enum RelayClientOp: Sendable {
    case auth(token: String)
    case bind(MailboxID)
    case unbind(MailboxID)
    case ping

    func encode() -> String {
        switch self {
        case .auth(let token):
            return #"{"op":"auth","token":"\#(jsonEscape(token))"}"#
        case .bind(let mailbox):
            return #"{"op":"bind","mailbox":"\#(mailbox.hex)"}"#
        case .unbind(let mailbox):
            return #"{"op":"unbind","mailbox":"\#(mailbox.hex)"}"#
        case .ping:
            return #"{"op":"ping"}"#
        }
    }
}

/// Messages the relay sends to the client.
public enum RelayServerMessage: Sendable, Equatable {
    case hello(maxPayload: Int, ttlDefault: UInt32, ttlMax: UInt32, authRequired: Bool)
    case ack(envelopeIDHex: String)
    case drained(mailboxHex: String)
    case pong
    case error(code: String)
    case unknown

    public static func parse(_ text: String) -> RelayServerMessage {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return .unknown }

        if let hello = json["hello"] as? [String: Any] {
            return .hello(
                maxPayload: hello["max_payload"] as? Int ?? 0,
                ttlDefault: (hello["ttl_default"] as? NSNumber)?.uint32Value ?? 0,
                ttlMax: (hello["ttl_max"] as? NSNumber)?.uint32Value ?? 0,
                authRequired: hello["auth_required"] as? Bool ?? false
            )
        }
        if let ack = json["ack"] as? [String: Any], let id = ack["id"] as? String {
            return .ack(envelopeIDHex: id)
        }
        if let drained = json["drained"] as? [String: Any], let mb = drained["mailbox"] as? String {
            return .drained(mailboxHex: mb)
        }
        if json["pong"] != nil { return .pong }
        if let err = json["error"] as? [String: Any], let code = err["code"] as? String {
            return .error(code: code)
        }
        return .unknown
    }
}

private func jsonEscape(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
}
