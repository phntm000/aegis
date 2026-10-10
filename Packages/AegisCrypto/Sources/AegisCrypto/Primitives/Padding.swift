// Padding — length-hiding for encrypted payloads.
//
// Ciphertext length leaks plaintext length to the relay. Before encryption,
// payloads are padded up to fixed buckets so the relay learns only a coarse
// size class. The length prefix makes unpadding unambiguous (ISO 7816-4
// style padding has an edge case when plaintext itself ends in 0x80/0x00;
// an explicit length avoids it entirely).

import Foundation

public enum Padding {
    /// Bucket sizes in bytes. The largest bucket is 64 KiB; anything bigger
    /// is padded to a 64 KiB multiple (attachments are chunked by the
    /// transport layer before they reach this code).
    public static let buckets: [Int] = [256, 1_024, 4_096, 16_384, 65_536]

    /// Pads `data` to the smallest bucket that fits `4 + data.count` bytes.
    public static func pad(_ data: Data) -> Data {
        let needed = 4 + data.count
        let target = buckets.first(where: { $0 >= needed })
            ?? ((needed + 65_535) / 65_536) * 65_536
        var encoder = WireEncoder()
        encoder.u32(UInt32(data.count))
        encoder.bytes(data)
        var padded = encoder.data
        padded.append(contentsOf: repeatElement(0, count: target - padded.count))
        return padded
    }

    /// Reverses `pad(_:)`. Throws on truncation or a length prefix that
    /// disagrees with the buffer size — both indicate corruption/tampering
    /// (this runs after AES-GCM authentication, so in practice it only
    /// fires on implementation bugs).
    public static func unpad(_ data: Data) throws -> Data {
        var decoder = WireDecoder(data)
        let length = Int(try decoder.u32())
        let payload = try decoder.bytes(count: length)
        // Everything after the payload must be zero padding.
        while !decoder.isAtEnd {
            guard try decoder.u8() == 0 else {
                throw AegisCryptoError.invalidWireFormat
            }
        }
        return payload
    }
}
