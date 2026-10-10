// CryptoProvider — the seam between the protocol logic and the underlying
// cryptographic library.
//
// Every session type in this module (X3DH, Double Ratchet, sender keys,
// sealed sender) depends only on `CryptoProvider`, never on CryptoKit
// directly. `CryptoKitProvider` is the production adapter. Replacing the
// pure-Swift protocol core with libsignal-client later means writing one new
// adapter conforming to these two protocols — not rewriting session logic.
//
// What lives behind the seam, and why:
//  - Key generation / DH / signatures / AEAD: provided, because raw private
//    key bytes must never cross into session logic more than necessary.
//  - The KDF *equations* (X3DH cascade, root KDF, chain KDF) live in shared
//    protocol code in this module and are specified in docs/CRYPTO.md. The
//    only DH-dependent operation they need is `DHSecret.derivedKey`, so any
//    adapter implementing HKDF over its DH output plugs in cleanly.
//
// TODO(security-audit): verify that no adapter logs, persists, or otherwise
// leaks raw secret bytes, and that `derivedKey` is always called with a
// fresh domain-separation `info` per call site (see CRYPTO.md §4).

import CryptoKit
import Foundation

// MARK: - DHSecret

/// An opaque Diffie-Hellman shared secret.
///
/// The raw secret bytes are never exposed. The single permitted operation is
/// HKDF derivation into a `SymmetricKey`. This keeps session code honest:
/// it cannot accidentally serialize, log, or concatenate raw DH output.
public protocol DHSecret {
    /// HKDF-SHA256 over the shared secret.
    /// - Parameters:
    ///   - salt: domain-bound salt (fingerprints, chaining MACs, …).
    ///   - info: unique domain-separation string per call site.
    ///   - outputByteCount: requested output length in bytes.
    func derivedKey(salt: Data, info: Data, outputByteCount: Int) -> SymmetricKey
}

/// CryptoKit's `SharedSecret` behind the `DHSecret` seam.
public struct CryptoKitDHSecret: DHSecret {
    let secret: SharedSecret

    public init(secret: SharedSecret) {
        self.secret = secret
    }

    public func derivedKey(salt: Data, info: Data, outputByteCount: Int) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }
}

// MARK: - CryptoProvider

/// The cryptographic primitive provider behind AegisCrypto.
///
/// Implementations must source randomness from the platform CSPRNG and must
/// not retain copies of private key material beyond the call.
public protocol CryptoProvider {
    // MARK: Randomness
    func randomBytes(count: Int) throws -> Data

    // MARK: X25519 key agreement
    func generateX25519KeyPair() throws -> X25519KeyPair
    func x25519PublicKey(fromPrivateKey privateKey: Data) throws -> Data
    func x25519DH(privateKey: Data, peerPublicKey: Data) throws -> any DHSecret

    // MARK: Ed25519 signatures
    func generateEd25519KeyPair() throws -> Ed25519KeyPair
    func ed25519PublicKey(fromSeed seed: Data) throws -> Data
    func ed25519Sign(seed: Data, message: Data) throws -> Data
    /// - Returns: `true` iff the signature is valid. Never throws: malformed
    ///   inputs simply fail verification.
    func ed25519Verify(publicKey: Data, signature: Data, message: Data) -> Bool

    // MARK: AES-256-GCM
    func aesGCMSeal(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        associatedData: Data
    ) throws -> (ciphertext: Data, tag: Data)

    func aesGCMOpen(
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        associatedData: Data
    ) throws -> Data
}

// MARK: - CryptoKitProvider

/// CryptoKit-backed `CryptoProvider`. This is what ships on iOS 17+.
public struct CryptoKitProvider: CryptoProvider {
    public static let shared = CryptoKitProvider()

    public init() {}

    // MARK: Randomness

    public func randomBytes(count: Int) throws -> Data {
        try Random.bytes(count: count)
    }

    // MARK: X25519

    public func generateX25519KeyPair() throws -> X25519KeyPair {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return X25519KeyPair(
            privateKey: SecureBytes(privateKey.rawRepresentation),
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    public func x25519PublicKey(fromPrivateKey privateKey: Data) throws -> Data {
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            return priv.publicKey.rawRepresentation
        } catch {
            throw AegisCryptoError.invalidKeyData
        }
    }

    public func x25519DH(privateKey: Data, peerPublicKey: Data) throws -> any DHSecret {
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            return CryptoKitDHSecret(secret: priv.sharedSecretFromKeyAgreement(with: pub))
        } catch {
            throw AegisCryptoError.invalidKeyData
        }
    }

    // MARK: Ed25519

    public func generateEd25519KeyPair() throws -> Ed25519KeyPair {
        let privateKey = Curve25519.Signing.PrivateKey()
        return Ed25519KeyPair(
            seed: SecureBytes(privateKey.rawRepresentation),
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    public func ed25519PublicKey(fromSeed seed: Data) throws -> Data {
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return priv.publicKey.rawRepresentation
        } catch {
            throw AegisCryptoError.invalidKeyData
        }
    }

    public func ed25519Sign(seed: Data, message: Data) throws -> Data {
        do {
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return try priv.signature(for: message)
        } catch {
            throw AegisCryptoError.invalidKeyData
        }
    }

    public func ed25519Verify(publicKey: Data, signature: Data, message: Data) -> Bool {
        guard signature.count == 64,
              let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        else { return false }
        return pub.isValidSignature(signature, for: message)
    }

    // MARK: AES-256-GCM

    public func aesGCMSeal(
        plaintext: Data,
        key: SymmetricKey,
        nonce: Data,
        associatedData: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.seal(plaintext, using: key, nonce: gcmNonce, authenticating: associatedData)
            return (box.ciphertext, box.tag)
        } catch {
            // Deliberately coarse: never distinguish seal-input errors from
            // randomness failures at this layer.
            throw AegisCryptoError.authenticationFailed
        }
    }

    public func aesGCMOpen(
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        associatedData: Data
    ) throws -> Data {
        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: key, authenticating: associatedData)
        } catch {
            throw AegisCryptoError.authenticationFailed
        }
    }
}
