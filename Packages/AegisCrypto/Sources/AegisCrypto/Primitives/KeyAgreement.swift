// X25519 key pairs.
//
// The private scalar lives in a `SecureBytes` buffer (wiped on release);
// the public key is plain `Data` (32 bytes, safe to share).

import Foundation

public struct X25519KeyPair {
    /// 32-byte private scalar. Wiped when the last reference is released.
    public let privateKey: SecureBytes
    /// 32-byte public key.
    public let publicKey: Data

    public init(privateKey: SecureBytes, publicKey: Data) {
        precondition(privateKey.count == 32, "X25519 private key must be 32 bytes")
        precondition(publicKey.count == 32, "X25519 public key must be 32 bytes")
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    public static func generate(
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> X25519KeyPair {
        try provider.generateX25519KeyPair()
    }

    /// Derives the public key for a raw 32-byte private scalar.
    public static func publicKey(
        forPrivateKey privateKey: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        guard privateKey.count == 32 else {
            throw AegisCryptoError.invalidKeyData
        }
        return try provider.x25519PublicKey(fromPrivateKey: privateKey)
    }

    /// Scoped access to a transient copy of the private scalar, for DH.
    /// The copy is short-lived; it is released (not wiped) when `body`
    /// returns — an accepted, documented limitation of Swift's memory model.
    func withPrivateKeyBytes<R>(_ body: (Data) throws -> R) rethrows -> R {
        try body(privateKey.toData())
    }
}
