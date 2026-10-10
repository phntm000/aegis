// AEAD — AES-256-GCM through the `CryptoProvider` seam.
//
// Nonce discipline (see docs/CRYPTO.md): every encryption uses a fresh
// 96-bit random nonce, and every (key, nonce) pair is used exactly once —
// message keys are single-use by construction (ratchet chains, sender-key
// chains), so random nonces are safe and no nonce state is needed.

import CryptoKit
import Foundation

/// The output of one AES-GCM encryption: nonce, ciphertext, and tag are
/// kept separate so the wire format stays explicit.
public struct SealedMessage {
    /// 96-bit nonce.
    public let nonce: Data
    public let ciphertext: Data
    /// 128-bit authentication tag.
    public let tag: Data

    public init(nonce: Data, ciphertext: Data, tag: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }
}

public enum AEAD {
    /// Encrypts `plaintext` with AES-256-GCM.
    /// - Parameters:
    ///   - associatedData: authenticated but not encrypted (headers, etc.).
    ///   - nonce: 12 bytes. Defaults to fresh randomness; pass an explicit
    ///     value only in tests.
    public static func seal(
        plaintext: Data,
        key: SymmetricKey,
        associatedData: Data,
        nonce: Data? = nil,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SealedMessage {
        let resolvedNonce = try nonce ?? provider.randomBytes(count: 12)
        guard resolvedNonce.count == 12 else {
            throw AegisCryptoError.invalidWireFormat
        }
        let (ciphertext, tag) = try provider.aesGCMSeal(
            plaintext: plaintext,
            key: key,
            nonce: resolvedNonce,
            associatedData: associatedData
        )
        return SealedMessage(nonce: resolvedNonce, ciphertext: ciphertext, tag: tag)
    }

    /// Decrypts and authenticates. Any failure — wrong key, tampered
    /// ciphertext, tampered associated data — throws `authenticationFailed`
    /// with no further distinction.
    public static func open(
        _ sealed: SealedMessage,
        key: SymmetricKey,
        associatedData: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        guard sealed.nonce.count == 12, sealed.tag.count == 16 else {
            throw AegisCryptoError.invalidWireFormat
        }
        do {
            return try provider.aesGCMOpen(
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                tag: sealed.tag,
                key: key,
                associatedData: associatedData
            )
        } catch {
            throw AegisCryptoError.authenticationFailed
        }
    }
}
