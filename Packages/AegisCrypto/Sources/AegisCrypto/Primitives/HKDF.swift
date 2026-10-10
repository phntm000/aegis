// HKDF-SHA256 (RFC 5869), implemented over CryptoKit's HMAC.
//
// Used everywhere a raw byte-string needs to become key material:
// message-key derivation from chain outputs, X3DH-adjacent mixing, and
// backup KDF output expansion. The DH-secret inputs themselves stay behind
// the `DHSecret` seam; this operates only on extractable byte strings.

import CryptoKit
import Foundation

public enum HKDF {
    /// HKDF-Extract: `PRK = HMAC-SHA256(salt, IKM)`.
    /// An empty salt is replaced with 32 zero bytes per RFC 5869 §2.2.
    public static func extract(salt: Data, inputKeyMaterial: Data) -> Data {
        let saltKey = salt.isEmpty
            ? SymmetricKey(data: Data(repeating: 0, count: SHA256.byteCount))
            : SymmetricKey(data: salt)
        return Data(
            HMAC<SHA256>.authenticationCode(for: inputKeyMaterial, using: saltKey)
                .withUnsafeBytes { Data($0) }
        )
    }

    /// HKDF-Expand: `OKM = T(1) || T(2) || …` truncated to `outputByteCount`.
    /// - Precondition: `1 <= outputByteCount <= 255 * 32`.
    public static func expand(pseudoRandomKey: Data, info: Data, outputByteCount: Int) -> Data {
        precondition(
            outputByteCount > 0 && outputByteCount <= 255 * SHA256.byteCount,
            "HKDF output length out of range"
        )
        let prk = SymmetricKey(data: pseudoRandomKey)
        var okm = Data()
        okm.reserveCapacity(outputByteCount)
        var previous = Data()
        var counter: UInt8 = 1
        while okm.count < outputByteCount {
            var input = previous
            input.append(contentsOf: info)
            input.append(counter)
            previous = Data(
                HMAC<SHA256>.authenticationCode(for: input, using: prk)
                    .withUnsafeBytes { Data($0) }
            )
            okm.append(previous)
            counter &+= 1
        }
        return okm.prefix(outputByteCount)
    }

    /// Convenience: extract-then-expand in one call.
    public static func deriveKey(
        inputKeyMaterial: Data,
        salt: Data,
        info: Data,
        outputByteCount: Int
    ) -> SymmetricKey {
        let prk = extract(salt: salt, inputKeyMaterial: inputKeyMaterial)
        return SymmetricKey(data: expand(pseudoRandomKey: prk, info: info, outputByteCount: outputByteCount))
    }

    /// HMAC-SHA256 with a `SymmetricKey`, returned as raw bytes. Used by the
    /// ratchet KDFs, which keep chain keys in opaque `SymmetricKey` handles
    /// and only ever extract HMAC outputs.
    public static func hmac(key: SymmetricKey, message: Data) -> Data {
        Data(
            HMAC<SHA256>.authenticationCode(for: message, using: key)
                .withUnsafeBytes { Data($0) }
        )
    }
}
