import Foundation

// CallSignaling — the sealed knock-and-rendezvous signaling wire types.
//
// Calls in Aegis are WebRTC media over DTLS-SRTP with the signaling channel
// being the existing E2EE 1:1 session (or the group channel). The relay only
// ever sees opaque frames addressed to rotating mailboxes. These types carry
// SDP offers/answers, ICE candidates, and call-control messages; the actual
// media pipeline is the app's WebRTC stack behind CallMediaDelegate (see
// AegisCore), which is the macOS-gated seam.
//
// Privacy note: no push tokens, no call servers, no metadata beyond what
// the relay already sees (timing/size per rotating mailbox).

/// SDP offer from the caller. DTLS fingerprint binds the media to this
/// signaling; the callee verifies it out-of-band via safety numbers.
struct CallOffer: Codable, Sendable {
    var callID: String
    var sdp: String
    var dtlsFingerprint: String
    /// Fingerprint hex of the caller's identity — lets the callee confirm
    /// the offer came from the expected contact before ringing.
    var callerFingerprintHex: String
}

/// SDP answer from the callee.
struct CallAnswer: Codable, Sendable {
    var callID: String
    var sdp: String
    var dtlsFingerprint: String
}

/// Trickled ICE candidate.
struct IceCandidate: Codable, Sendable {
    var callID: String
    var candidate: String
    var sdpMid: String?
    var sdpMLineIndex: Int?
}

/// Call lifecycle control messages (no media involved).
enum CallControl: String, Codable, Sendable {
    case ringing
    case reject
    case busy
    case hangup
    case acceptedElsewhere
}

/// The signaling envelope. Manually Codable: a "t" discriminator keeps the
/// wire stable and parseable without Swift type metadata.
enum CallSignal: Sendable {
    case offer(CallOffer)
    case answer(CallAnswer)
    case ice(IceCandidate)
    case control(callID: String, control: CallControl)

    private enum Discriminator: String, Codable {
        case offer, answer, ice, control
    }

    private enum Keys: String, CodingKey {
        case t, offer, answer, ice, callID, control
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Keys.self)
        switch try container.decode(Discriminator.self, forKey: .t) {
        case .offer:
            self = .offer(try container.decode(CallOffer.self, forKey: .offer))
        case .answer:
            self = .answer(try container.decode(CallAnswer.self, forKey: .answer))
        case .ice:
            self = .ice(try container.decode(IceCandidate.self, forKey: .ice))
        case .control:
            self = .control(
                callID: try container.decode(String.self, forKey: .callID),
                control: try container.decode(CallControl.self, forKey: .control)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Keys.self)
        switch self {
        case .offer(let offer):
            try container.encode(Discriminator.offer, forKey: .t)
            try container.encode(offer, forKey: .offer)
        case .answer(let answer):
            try container.encode(Discriminator.answer, forKey: .t)
            try container.encode(answer, forKey: .answer)
        case .ice(let candidate):
            try container.encode(Discriminator.ice, forKey: .t)
            try container.encode(candidate, forKey: .ice)
        case .control(let callID, let control):
            try container.encode(Discriminator.control, forKey: .t)
            try container.encode(callID, forKey: .callID)
            try container.encode(control, forKey: .control)
        }
    }
}

// Codable conformance must be declared explicitly (manual implementation).
extension CallSignal: Codable {}
