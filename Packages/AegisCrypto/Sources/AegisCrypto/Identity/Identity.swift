// Identity — the user's cryptographic self.
//
// There is no username, phone number, or central account. The identity IS
// the keypair:
//
//  - `signingKey` (Ed25519): the fingerprint identity. Its public key is
//    what contacts verify (safety numbers, QR codes) and what signs
//    prekey bundles, sender certificates, and group messages' key
//    distributions.
//  - `agreementKey` (X25519): the Diffie-Hellman identity used inside X3DH.
//
// Why two keys instead of one? Signal uses a single Curve25519 key for both
// via XEdDSA point conversion. CryptoKit exposes no XEdDSA conversion, and
// hand-rolling ed25519 curve arithmetic in Swift to get it would be exactly
// the kind of duct tape this module refuses. Two purpose-separated keys is
// the conservative choice; the `CryptoProvider` seam exists precisely so a
// future libsignal-client adapter can collapse them back to one.
//
// The 32-byte fingerprint binds both public keys:
//   fingerprint = SHA256("AegisIdentityFP_v1" || ed25519_pub || x25519_pub)
// Fingerprints are public values — they are exchanged out-of-band (QR,
// invite string) to add contacts. There is no directory to look anyone up
// in; that is the point.

import CryptoKit
import Foundation

public struct Identity {
    public let signingKey: Ed25519KeyPair
    public let agreementKey: X25519KeyPair
    public let createdAt: Date

    // MARK: Creation

    /// Generates a fresh identity. This is the only moment the private keys
    /// ever exist in the clear; persist them via `KeyBackup` / the Keychain
    /// immediately.
    public init(provider: any CryptoProvider = CryptoKitProvider.shared) throws {
        self.signingKey = try Ed25519KeyPair.generate(provider: provider)
        self.agreementKey = try X25519KeyPair.generate(provider: provider)
        self.createdAt = Date()
    }

    /// Restores an identity from backed-up key material.
    public init(
        signingSeed: Data,
        agreementPrivateKey: Data,
        createdAt: Date,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        guard signingSeed.count == 32, agreementPrivateKey.count == 32 else {
            throw AegisCryptoError.invalidKeyData
        }
        // Re-derive the public halves rather than trusting stored copies:
        // a corrupted backup fails here instead of silently forking identity.
        let signingPublic = try provider.ed25519PublicKey(fromSeed: signingSeed)
        let agreementPublic = try X25519KeyPair.publicKey(forPrivateKey: agreementPrivateKey, provider: provider)
        self.signingKey = Ed25519KeyPair(seed: SecureBytes(signingSeed), publicKey: signingPublic)
        self.agreementKey = X25519KeyPair(privateKey: SecureBytes(agreementPrivateKey), publicKey: agreementPublic)
        self.createdAt = createdAt
    }

    // MARK: Fingerprint

    /// 32-byte fingerprint binding both public keys. This is the value shown
    /// in safety numbers and QR codes.
    public var fingerprint: Data {
        var context = Data("AegisIdentityFP_v1".utf8)
        context.append(signingKey.publicKey)
        context.append(agreementKey.publicKey)
        return Data(SHA256.hash(data: context))
    }

    /// Human-readable fingerprint: 64 hex chars in groups of 8.
    public var fingerprintDisplayString: String {
        let hex = fingerprint.map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 8).map { i in
            let end = hex.index(hex.startIndex, offsetBy: min(i + 8, hex.count))
            let start = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[start ..< end])
        }.joined(separator: " ")
    }

    /// The relay's routing handle for this identity: the first 16 bytes of
    /// `SHA256("AegisMailbox_v1" || fingerprint)`. The relay learns nothing
    /// beyond "a sealed envelope is addressed to this mailbox".
    public var mailboxID: Data {
        var context = Data("AegisMailbox_v1".utf8)
        context.append(fingerprint)
        return Data(SHA256.hash(data: context).prefix(16))
    }

    // MARK: Public view

    /// The shareable half of an identity: both public keys plus the
    /// fingerprint that binds them.
    public var publicView: IdentityPublic {
        IdentityPublic(
            signingPublicKey: signingKey.publicKey,
            agreementPublicKey: agreementKey.publicKey
        )
    }
}

/// The public half of an identity. Safe to publish in prekey bundles and
/// invite strings.
public struct IdentityPublic: Equatable, Sendable {
    public let signingPublicKey: Data
    public let agreementPublicKey: Data

    public init(signingPublicKey: Data, agreementPublicKey: Data) {
        precondition(signingPublicKey.count == 32 && agreementPublicKey.count == 32)
        self.signingPublicKey = signingPublicKey
        self.agreementPublicKey = agreementPublicKey
    }

    /// Recomputes the fingerprint; use to check a received public view
    /// against an out-of-band fingerprint before trusting it.
    public var fingerprint: Data {
        var context = Data("AegisIdentityFP_v1".utf8)
        context.append(signingPublicKey)
        context.append(agreementPublicKey)
        return Data(SHA256.hash(data: context))
    }

    // MARK: Wire format

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(signingPublicKey)
        encoder.bytes(agreementPublicKey)
        return encoder.data
    }

    public init(serialized data: Data) throws {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let signingPublicKey = try decoder.bytes(count: 32)
        let agreementPublicKey = try decoder.bytes(count: 32)
        try decoder.expectEnd()
        self.init(signingPublicKey: signingPublicKey, agreementPublicKey: agreementPublicKey)
    }
}
