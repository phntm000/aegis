// Randomness. Single choke point: every nonce, salt, ephemeral key, and IV
// in this module comes from here, which is the platform CSPRNG
// (SecRandomCopyBytes). There is no fallback and no seeded PRNG anywhere.

import Foundation
import Security

public enum Random {
    /// `count` cryptographically random bytes.
    /// - Throws: `AegisCryptoError.randomnessFailure` — callers must treat
    ///   this as fatal and abort the operation, never retry with weaker
    ///   randomness.
    public static func bytes(count: Int) throws -> Data {
        precondition(count >= 0, "random byte count must be non-negative")
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status: OSStatus = data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw AegisCryptoError.randomnessFailure
        }
        return data
    }

    /// A fresh 96-bit nonce, as required by the AES-GCM nonce discipline
    /// (see docs/CRYPTO.md § "Nonce discipline").
    public static func nonce96() throws -> Data {
        try bytes(count: 12)
    }

    /// A fresh 128-bit salt.
    public static func salt128() throws -> Data {
        try bytes(count: 16)
    }
}
