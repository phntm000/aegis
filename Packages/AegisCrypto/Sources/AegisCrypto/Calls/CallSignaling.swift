// Call signaling — the encrypted control plane for voice/video calls.
//
// Media encryption is NOT done here: voice/video frames are protected by
// WebRTC's DTLS-SRTP (each peer's DTLS certificate fingerprint is exchanged
// inside these E2EE signaling messages and pinned during the DTLS
// handshake). This module defines the signaling payloads that ride inside
// the E2EE envelopes (1:1 ratchet messages or sealed-sender envelopes —
// the "knock" that wakes the callee), plus the ZRTP-style Short
// Authentication String for voice-verifying that no one is in the middle
// of the media path.
//
// Message flow (see docs/CRYPTO.md § "Calls"):
//   caller --offer(sealed)--> callee --answer--> caller --ICE--> …
//   Either side may send `control` (.hangup/.reject/.busy/.ringing).
// All of these are `Codable` so the message layer can serialize them into
// envelope payloads; the envelope itself provides confidentiality and
// authentication.

import CryptoKit
import Foundation

// MARK: - Payloads

/// SDP offer + the caller's DTLS certificate fingerprint for pinning.
public struct CallOffer: Codable, Equatable, Sendable {
    /// Random call identifier, shared by all signaling for this call.
    public let callID: String
    public let sdp: String
    /// The caller's DTLS certificate fingerprint, e.g. `"SHA-256:AA:BB:…"`.
    /// The callee pins this during the DTLS handshake.
    public let dtlsFingerprint: String
    /// Hex of the caller's identity fingerprint (for UI display binding).
    public let callerFingerprintHex: String
    public let timestamp: UInt64

    public init(callID: String = UUID().uuidString, sdp: String, dtlsFingerprint: String, callerFingerprintHex: String, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        self.callID = callID
        self.sdp = sdp
        self.dtlsFingerprint = dtlsFingerprint
        self.callerFingerprintHex = callerFingerprintHex
        self.timestamp = timestamp
    }
}

/// SDP answer + the callee's DTLS certificate fingerprint for pinning.
public struct CallAnswer: Codable, Equatable, Sendable {
    public let callID: String
    public let sdp: String
    public let dtlsFingerprint: String
    public let timestamp: UInt64

    public init(callID: String, sdp: String, dtlsFingerprint: String, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        self.callID = callID
        self.sdp = sdp
        self.dtlsFingerprint = dtlsFingerprint
        self.timestamp = timestamp
    }
}

/// A trickled ICE candidate.
public struct IceCandidate: Codable, Equatable, Sendable {
    public let callID: String
    public let candidate: String
    public let sdpMLineIndex: Int32
    public let sdpMid: String?
    public let timestamp: UInt64

    public init(callID: String, candidate: String, sdpMLineIndex: Int32, sdpMid: String? = nil, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        self.callID = callID
        self.candidate = candidate
        self.sdpMLineIndex = sdpMLineIndex
        self.sdpMid = sdpMid
        self.timestamp = timestamp
    }
}

/// Call control messages.
public enum CallControl: String, Codable, Equatable, Sendable {
    /// The other side is ringing.
    case ringing
    /// Callee declined.
    case reject
    /// Callee is in another call.
    case busy
    /// Either side hung up.
    case hangup
    /// The call was accepted on another device.
    case acceptedElsewhere
}

// MARK: - Envelope

/// A tagged union of signaling payloads, serialized into E2EE envelopes.
public enum CallSignal: Equatable, Sendable {
    case offer(CallOffer)
    case answer(CallAnswer)
    case ice(IceCandidate)
    case control(callID: String, control: CallControl)
}

extension CallSignal: Codable {
    private enum TypeTag: String, Codable {
        case offer, answer, ice, control
    }

    private enum CodingKeys: String, CodingKey {
        case type, offer, answer, ice, callID, control
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(TypeTag.self, forKey: .type) {
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

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .offer(let offer):
            try container.encode(TypeTag.offer, forKey: .type)
            try container.encode(offer, forKey: .offer)
        case .answer(let answer):
            try container.encode(TypeTag.answer, forKey: .type)
            try container.encode(answer, forKey: .answer)
        case .ice(let candidate):
            try container.encode(TypeTag.ice, forKey: .type)
            try container.encode(candidate, forKey: .ice)
        case .control(let callID, let control):
            try container.encode(TypeTag.control, forKey: .type)
            try container.encode(callID, forKey: .callID)
            try container.encode(control, forKey: .control)
        }
    }
}

// MARK: - Knock

/// Call knock body: the sealed "knock" that wakes the callee.
///
/// Sent as a short-TTL frame addressed to the callee's rotating mailbox. It
/// embeds the SDP offer so the callee can ring with full context before any
/// session message round-trips. This is the single canonical knock type —
/// the app layer must not define its own.
public struct KnockInfo: Codable, Equatable, Sendable {
    public var v: Int = 1
    public var callID: String
    public var offer: CallOffer
    /// "audio" | "video"
    public var mediaKind: String = "audio"

    public init(v: Int = 1, callID: String, offer: CallOffer, mediaKind: String = "audio") {
        self.v = v
        self.callID = callID
        self.offer = offer
        self.mediaKind = mediaKind
    }
}

// MARK: - Short Authentication String

/// ZRTP-style voice verification for the media path.
///
/// Both sides independently compute the SAS from the two DTLS certificate
/// fingerprints (exchanged inside the E2EE signaling) and read the four
/// characters aloud. If they match, no one is relaying/tampering with the
/// media — even though the signaling itself was already E2EE, this binds
/// the *media* keys to the verified conversation.
public enum CallSAS {
    /// Characters are unambiguous (no 0/O, 1/I/L confusion).
    public static let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    static let sasBits = 20

    /// Computes the 4-character SAS. Order-independent: both sides agree.
    public static func shortAuthString(localDTLSFingerprint: Data, remoteDTLSFingerprint: Data) -> String {
        let (first, second): (Data, Data) =
            localDTLSFingerprint.lexicographicallyPrecedes(remoteDTLSFingerprint)
            ? (localDTLSFingerprint, remoteDTLSFingerprint)
            : (remoteDTLSFingerprint, localDTLSFingerprint)
        var input = Data("AegisCallSAS_v1".utf8)
        input.append(first)
        input.append(second)
        let digest = Data(SHA256.hash(data: input))
        // First 20 bits → four 5-bit characters.
        var value = (UInt32(digest[0]) << 12) | (UInt32(digest[1]) << 4) | (UInt32(digest[2]) >> 4)
        var chars: [Character] = []
        let alphabetArray = Array(alphabet)
        for _ in 0 ..< 4 {
            chars.append(alphabetArray[Int(value & 0x1F)])
            value >>= 5
        }
        return String(chars.reversed())
    }

    /// Computes the SAS from `"SHA-256:AA:BB:…"` hex fingerprint strings
    /// (the form carried in `CallOffer`/`CallAnswer`).
    ///
    /// - Returns: the 4-character SAS, or `nil` when either fingerprint is
    ///   empty or malformed. A `nil` result means the media stack has not
    ///   provided real DTLS fingerprints yet — callers must not present a
    ///   verification ceremony for a SAS that binds nothing.
    public static func shortAuthString(localHex: String, remoteHex: String) -> String? {
        guard let local = parseDTLSFingerprintHex(localHex), !local.isEmpty,
              let remote = parseDTLSFingerprintHex(remoteHex), !remote.isEmpty
        else { return nil }
        return shortAuthString(localDTLSFingerprint: local, remoteDTLSFingerprint: remote)
    }

    /// Parses `"SHA-256:AA:BB:…"` (or a bare hex string) into bytes.
    /// Returns `nil` for malformed input.
    static func parseDTLSFingerprintHex(_ s: String) -> Data? {
        var hex = s
        if let range = hex.range(of: ":", options: .caseInsensitive) {
            // Drop a "SHA-256" style algorithm prefix when present.
            let prefix = hex[..<range.lowerBound]
            if prefix.caseInsensitiveCompare("SHA-256") == .orderedSame {
                hex = String(hex[range.upperBound...])
            }
        }
        hex = hex.replacingOccurrences(of: ":", with: "")
        hex = hex.replacingOccurrences(of: " ", with: "")
        guard !hex.isEmpty, hex.count % 2 == 0,
              hex.allSatisfy({ $0.isHexDigit })
        else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}
