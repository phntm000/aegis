// Ed25519 key pairs.
//
// The 32-byte seed lives in a `SecureBytes` buffer (wiped on release); the
// 32-byte public key is plain `Data`.

import Foundation

public struct Ed25519KeyPair {
    /// 32-byte seed. Wiped when the last reference is released.
    public let seed: SecureBytes
    /// 32-byte public key.
    public let publicKey: Data

    public init(seed: SecureBytes, publicKey: Data) {
        precondition(seed.count == 32, "Ed25519 seed must be 32 bytes")
        precondition(publicKey.count == 32, "Ed25519 public key must be 32 bytes")
        self.seed = seed
        self.publicKey = publicKey
    }

    public static func generate(
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Ed25519KeyPair {
        try provider.generateEd25519KeyPair()
    }

    /// Signs `message`, returning the 64-byte signature.
    public func sign(
        _ message: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        try provider.ed25519Sign(seed: seed.toData(), message: message)
    }

    /// Verifies a 64-byte signature. Returns `false` (never throws) on any
    /// malformed input.
    public static func verify(
        signature: Data,
        for message: Data,
        publicKey: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) -> Bool {
        provider.ed25519Verify(publicKey: publicKey, signature: signature, message: message)
    }
}
