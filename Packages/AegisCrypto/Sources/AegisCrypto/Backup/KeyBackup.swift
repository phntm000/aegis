// KeyBackup — passphrase-encrypted export of identity key material.
//
// The backup file contains everything needed to restore an identity on a
// new device: the Ed25519 seed, the X25519 agreement private key, and the
// current signed prekey. It is encrypted with AES-256-GCM under a key
// derived from the user's passphrase via Argon2id (see `Argon2.swift` for
// why Argon2id and not PBKDF2).
//
// Wire format:
//   magic "AEGISBK1"(8) || kdfID u8 || paramLen u8 || params ||
//   saltLen u8 || salt || nonce(12) || ctLen u32 || ct || tag(16)
// AAD = everything before `nonce`. Inner plaintext:
//   version u8 || exportedAt u64 || signingSeed(32) || agreementPriv(32) ||
//   spkID u32 || spkPriv(32) || spkCreatedAt u64
//
// What backup does NOT cover: 1:1 sessions are intentionally NOT backed
// up — they are re-established via X3DH on first contact after restore
// (forward secrecy means old session keys are gone by design). Group
// sender keys are re-distributed by peers on demand.
//
// Duress: `exportDecoy` creates a backup of a fresh, empty identity under
// a second password. Unlocking with the duress password yields a working
// but empty identity. Honest limits: a decoy cannot prove you have no
// other identities, and an adversary who already knows your contacts will
// not be fooled — see THREAT_MODEL.md. It raises the cost of casual
// coercion, nothing more.

import CryptoKit
import Foundation

/// A passphrase-based key derivation function usable for key backup.
public protocol PassphraseKDF {
    /// Human-readable identifier, e.g. "argon2id".
    var identifier: String { get }
    /// Human-readable parameters, e.g. "m=65536,t=3,p=1,v=19".
    var parametersDescription: String { get }
    /// Wire identifier byte in the backup header.
    var wireIdentifier: UInt8 { get }
    /// Canonical binary encoding of the parameters for the backup header.
    func serializedParameters() -> Data
    /// Derives `outputLength` bytes from the passphrase and salt.
    func deriveKey(password: SecureBytes, salt: Data, outputLength: Int) throws -> SymmetricKey
}

public enum KeyBackup {
    public static let magic = Data("AEGISBK1".utf8)

    public struct BackupContents {
        public let identity: Identity
        public let signedPreKey: SignedPreKey
        public let exportedAt: Date
    }

    // MARK: - Export

    /// Encrypts identity key material under `password`.
    ///
    /// - Parameter password: the user's passphrase as bytes. The caller
    ///   owns the buffer and should zero it after this returns.
    public static func export(
        identity: Identity,
        signedPreKey: SignedPreKey,
        password: SecureBytes,
        exportedAt: Date = Date(),
        kdf: any PassphraseKDF = Argon2id.default,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        var inner = WireEncoder()
        inner.u8(AegisCrypto.protocolVersion)
        inner.u64(UInt64(exportedAt.timeIntervalSince1970))
        inner.bytes(identity.signingKey.seed.toData())
        inner.bytes(identity.agreementKey.privateKey.toData())
        inner.u32(signedPreKey.id)
        inner.bytes(signedPreKey.keyPair.privateKey.toData())
        inner.u64(UInt64(signedPreKey.createdAt.timeIntervalSince1970))

        let salt = try provider.randomBytes(count: 16)
        let key = try kdf.deriveKey(password: password, salt: salt, outputLength: 32)
        let params = kdf.serializedParameters()

        var aad = WireEncoder()
        aad.bytes(magic)
        aad.u8(kdf.wireIdentifier)
        aad.u8(UInt8(params.count))
        aad.bytes(params)
        aad.u8(UInt8(salt.count))
        aad.bytes(salt)

        let sealed = try AEAD.seal(plaintext: inner.data, key: key, associatedData: aad.data, provider: provider)

        var outer = WireEncoder()
        outer.bytes(aad.data)
        outer.bytes(sealed.nonce)
        outer.u32(UInt32(sealed.ciphertext.count))
        outer.bytes(sealed.ciphertext)
        outer.bytes(sealed.tag)
        return outer.data
    }

    // MARK: - Import

    /// Decrypts a backup. Throws `authenticationFailed` on a wrong
    /// password — deliberately indistinguishable from a corrupted file, so
    /// an offline attacker learns nothing from error messages.
    public static func `import`(
        _ data: Data,
        password: SecureBytes,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> BackupContents {
        var decoder = WireDecoder(data)
        let magic = try decoder.bytes(count: 8)
        guard constantTimeEqual(magic, Self.magic) else {
            throw AegisCryptoError.invalidWireFormat
        }
        let kdfID = try decoder.u8()
        let params = try decoder.bytes(count: Int(try decoder.u8()))
        let salt = try decoder.bytes(count: Int(try decoder.u8()))
        let nonce = try decoder.bytes(count: 12)
        let ctLength = Int(try decoder.u32())
        let ciphertext = try decoder.bytes(count: ctLength)
        let tag = try decoder.bytes(count: 16)
        try decoder.expectEnd()

        let kdf: any PassphraseKDF
        switch kdfID {
        case Argon2id.backupWireIdentifier:
            kdf = try Argon2id.parameters(serialized: params)
        default:
            throw AegisCryptoError.unsupportedVersion(kdfID)
        }

        var aad = WireEncoder()
        aad.bytes(Self.magic)
        aad.u8(kdfID)
        aad.u8(UInt8(params.count))
        aad.bytes(params)
        aad.u8(UInt8(salt.count))
        aad.bytes(salt)

        let key = try kdf.deriveKey(password: password, salt: salt, outputLength: 32)
        let sealed = SealedMessage(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let inner = try AEAD.open(sealed, key: key, associatedData: aad.data, provider: provider)

        var innerDecoder = WireDecoder(inner)
        let version = try innerDecoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let exportedAt = Date(timeIntervalSince1970: TimeInterval(try innerDecoder.u64()))
        let signingSeed = try innerDecoder.bytes(count: 32)
        let agreementPriv = try innerDecoder.bytes(count: 32)
        let spkID = try innerDecoder.u32()
        let spkPriv = try innerDecoder.bytes(count: 32)
        let spkCreatedAt = Date(timeIntervalSince1970: TimeInterval(try innerDecoder.u64()))
        try innerDecoder.expectEnd()

        let identity = try Identity(
            signingSeed: signingSeed,
            agreementPrivateKey: agreementPriv,
            createdAt: exportedAt,
            provider: provider
        )
        // Rebuild the signed prekey: the public half is re-derived from the
        // private scalar, and the identity signature is recomputed over the
        // canonical input (deterministic given the same key material).
        let spkPublic = try X25519KeyPair.publicKey(forPrivateKey: spkPriv, provider: provider)
        let spkSignature = try identity.signingKey.sign(
            SignedPreKey.signingInput(id: spkID, publicKey: spkPublic),
            provider: provider
        )
        let signedPreKey = SignedPreKey(
            id: spkID,
            keyPair: X25519KeyPair(privateKey: SecureBytes(spkPriv), publicKey: spkPublic),
            signature: spkSignature,
            createdAt: spkCreatedAt
        )
        guard signedPreKey.verify(identityPublicKey: identity.signingKey.publicKey, provider: provider) else {
            // Should be unreachable (we just signed it); defense in depth.
            throw AegisCryptoError.invalidSignature
        }

        return BackupContents(identity: identity, signedPreKey: signedPreKey, exportedAt: exportedAt)
    }

    // MARK: - Duress / decoy

    /// Exports a backup of a fresh, empty identity under a duress password.
    /// Unlocking with the duress password yields a working identity with no
    /// contacts, no groups, no history. See the file header for the honest
    /// limits of this mechanism.
    public static func exportDecoy(
        password: SecureBytes,
        kdf: any PassphraseKDF = Argon2id.default,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        let decoyIdentity = try Identity(provider: provider)
        let decoySPK = try SignedPreKey.generate(id: 0, identity: decoyIdentity, provider: provider)
        return try export(
            identity: decoyIdentity,
            signedPreKey: decoySPK,
            password: password,
            kdf: kdf,
            provider: provider
        )
    }
}

// MARK: - Argon2id backup wiring

extension Argon2id {
    /// Wire identifier for Argon2id in backup headers.
    public static let backupWireIdentifier: UInt8 = 0x01

    public var wireIdentifier: UInt8 { Self.backupWireIdentifier }
}
