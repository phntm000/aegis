// Wire — a minimal big-endian binary codec for protocol envelopes.
//
// Design rules:
//  - Every field is fixed-width or length-prefixed. No delimiters, no
//    text parsing, no optional fields on the wire.
//  - The decoder is strictly bounds-checked and throws
//    `invalidWireFormat` on truncation instead of trapping, so hostile
//    input from the relay cannot crash the client.
//  - A one-byte `version` always leads, so future formats fail closed.

import Foundation

public struct WireEncoder {
    public private(set) var data = Data()

    public init() {}

    public mutating func u8(_ value: UInt8) {
        data.append(value)
    }

    public mutating func u16(_ value: UInt16) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    public mutating func u32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    public mutating func u64(_ value: UInt64) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }

    public mutating func bytes(_ value: Data) {
        data.append(value)
    }

    /// Length-prefixed blob (u16 length). For blobs that can exceed 64 KiB,
    /// use `u32` + `bytes` explicitly at the call site.
    public mutating func prefixed(_ value: Data) {
        precondition(value.count <= UInt16.max, "wire blob exceeds u16 length prefix")
        u16(UInt16(value.count))
        bytes(value)
    }
}

/// Strict bounds-checked decoder for the versioned wire formats.
/// All reads reject trailing bytes and out-of-range offsets so malformed
/// input fails closed.
/// TODO(security-audit): fuzz with hostile inputs alongside the envelope
/// parsers and the backup importer (CRYPTO.md §15.8).
public struct WireDecoder {
    private let data: Data
    private var offset: Int = 0

    public init(_ data: Data) {
        self.data = data
    }

    public var isAtEnd: Bool { offset == data.count }
    public var remaining: Int { data.count - offset }

    private mutating func read(_ count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.count else {
            throw AegisCryptoError.invalidWireFormat
        }
        let slice = data[offset ..< offset + count]
        offset += count
        return Data(slice)
    }

    public mutating func u8() throws -> UInt8 {
        let bytes = try read(1)
        guard let value = bytes.first else {
            throw AegisCryptoError.invalidWireFormat
        }
        return value
    }

    public mutating func u16() throws -> UInt16 {
        var value: UInt16 = 0
        for byte in try read(2) {
            value = (value << 8) | UInt16(byte)
        }
        return value
    }

    public mutating func u32() throws -> UInt32 {
        var value: UInt32 = 0
        for byte in try read(4) {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    public mutating func u64() throws -> UInt64 {
        var value: UInt64 = 0
        for byte in try read(8) {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }

    public mutating func bytes(count: Int) throws -> Data {
        try read(count)
    }

    public mutating func prefixed() throws -> Data {
        let count = Int(try u16())
        return try read(count)
    }

    /// Fails if any trailing bytes remain. Call at the end of every
    /// top-level decode so appended garbage is rejected, not ignored.
    public mutating func expectEnd() throws {
        guard isAtEnd else {
            throw AegisCryptoError.invalidWireFormat
        }
    }
}
