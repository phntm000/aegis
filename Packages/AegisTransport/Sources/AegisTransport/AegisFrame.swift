import Foundation

// MARK: - AegisFrame: the sealed envelope as the network sees it
//
// Wire layout (big-endian), identical to relay.py's `HEADER` struct:
//
//   offset  size  field
//   0       2     magic "AG" (0x41 0x47)
//   2       1     version (1)
//   3       1     flags (bit 0: 1 = final chunk of a multi-chunk attachment)
//   4       32    mailbox ID (opaque routing label, NOT an identity)
//   36      16    envelope ID (random nonce; app layer dedupes on this)
//   52      4     ttl_seconds (0 = relay default)
//   56      4     payload length N
//   60      N     payload: opaque ciphertext from AegisCrypto
//
// There is deliberately NO sender field anywhere on the wire. The relay sees
// (mailbox, envelope-id, ttl, length) and nothing else — sealed sender.

public struct AegisFrame: Sendable, Equatable {
    public static let magic0: UInt8 = 0x41 // "A"
    public static let magic1: UInt8 = 0x47 // "G"
    public static let version: UInt8 = 1
    public static let headerSize = 60

    /// Maximum ciphertext payload per frame. Attachments are chunked by the
    /// app layer; each chunk is its own sealed frame with flags bit 0 set
    /// on the final chunk.
    public static let maxPayloadSize = 5 * 1024 * 1024

    /// Bit 0 of `flags`: final chunk of a multi-chunk attachment.
    public static let flagFinalChunk: UInt8 = 0b0000_0001
    /// Bit 1 of `flags`: call knock — a sealed rendezvous invitation.
    /// A knock is an ordinary sealed envelope; the bit is only a *hint* so
    /// the receiver can prioritize it during a short background wake. It is
    /// NOT authenticated: the app must decrypt and verify the payload via
    /// AegisCrypto before ringing or notifying. A malicious relay can set
    /// this bit on any envelope; all it buys is a wasted decrypt.
    /// Convention: knocks use a short TTL (≤ 300 s) — a knock is an
    /// invitation, not a message.
    public static let flagKnock: UInt8 = 0b0000_0010
    /// Bit 2 of `flags`: transport-internal control envelope (sender-key
    /// distributions, call signaling, group invites — never user messages).
    /// The session plaintext is a `TransportControl` JSON envelope, defined
    /// in the app layer. Visible to the relay as metadata (like the other
    /// flag bits); the payload itself stays sealed.
    public static let flagTransportControl: UInt8 = 0b0000_0100

    public var mailbox: MailboxID
    /// 16 random bytes, unique per envelope. Receivers dedupe on this.
    public var envelopeID: Data
    public var ttl: UInt32
    public var flags: UInt8
    public var payload: Data

    public init(mailbox: MailboxID, envelopeID: Data, ttl: UInt32, flags: UInt8 = 0, payload: Data) {
        precondition(envelopeID.count == 16, "envelopeID must be 16 bytes")
        self.mailbox = mailbox
        self.envelopeID = envelopeID
        self.ttl = ttl
        self.flags = flags
        self.payload = payload
    }

    /// True when the knock hint bit is set. See `flagKnock`.
    public var isKnock: Bool { flags & Self.flagKnock != 0 }

    /// True when the final-chunk bit is set. See `flagFinalChunk`.
    public var isFinalChunk: Bool { flags & Self.flagFinalChunk != 0 }

    public func encode() throws -> Data {
        guard envelopeID.count == 16 else { throw TransportError.malformedFrame }
        guard payload.count <= Self.maxPayloadSize else {
            throw TransportError.frameTooLarge(payload.count)
        }
        var out = Data(capacity: Self.headerSize + payload.count)
        out.append(Self.magic0)
        out.append(Self.magic1)
        out.append(Self.version)
        out.append(flags)
        out.append(mailbox.bytes)
        out.append(envelopeID)
        appendUInt32BE(&out, ttl)
        appendUInt32BE(&out, UInt32(payload.count))
        out.append(payload)
        return out
    }

    public static func decode(_ data: Data) throws -> AegisFrame {
        guard data.count >= headerSize else { throw TransportError.malformedFrame }
        guard data[0] == magic0, data[1] == magic1 else { throw TransportError.malformedFrame }
        guard data[2] == version else { throw TransportError.malformedFrame }
        let flags = data[3]
        let mailbox = MailboxID(data.subdata(in: 4..<36))
        let envelopeID = data.subdata(in: 36..<52)
        let ttl = readUInt32BE(data, at: 52)
        let length = readUInt32BE(data, at: 56)
        guard length <= maxPayloadSize else { throw TransportError.malformedFrame }
        guard data.count == headerSize + Int(length) else { throw TransportError.malformedFrame }
        let payload = data.subdata(in: headerSize..<(headerSize + Int(length)))
        return AegisFrame(mailbox: mailbox, envelopeID: envelopeID, ttl: ttl, flags: flags, payload: payload)
    }
}

// MARK: - Byte helpers (alignment-safe; no unaligned loads)

private func appendUInt32BE(_ data: inout Data, _ value: UInt32) {
    data.append(UInt8((value >> 24) & 0xFF))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

private func readUInt32BE(_ data: Data, at offset: Int) -> UInt32 {
    (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
}
