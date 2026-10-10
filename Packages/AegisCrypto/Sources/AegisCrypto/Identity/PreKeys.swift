// Prekeys — the publishable key material that makes X3DH possible without
// both parties being online.
//
//  - `SignedPreKey`: a medium-lived X25519 keypair, re-signed by the
//    identity key. Rotated weekly (see `PreKeyManager`). Its public half
//    doubles as the responder's *initial* Double-Ratchet key — this is what
//    lets the initiator DH-ratchet into her first sending chain before the
//    responder has generated any ratchet key of her own.
//  - `OneTimePreKey`: single-use X25519 keypairs. The responder deletes the
//    private half the moment it is used in a session; this is what gives
//    X3DH its forward secrecy for the *first* message.
//  - `PreKeyBundle`: the signed, versioned, self-contained package a
//    contact publishes (via the relay's dumb key-value slot, or handed
//    over directly in an invite). The initiator verifies the identity
//    signature over the whole bundle before running X3DH.
//
// Wire formats are fixed-width and versioned; see `serialized()`.

import Foundation

// MARK: - Signed prekey

/// A medium-lived X25519 keypair signed by the identity key.
public struct SignedPreKey {
    public let id: UInt32
    public let keyPair: X25519KeyPair
    /// Ed25519 signature over `"AegisSPK_v1" || id_BE || publicKey`.
    public let signature: Data
    public let createdAt: Date

    public init(
        id: UInt32,
        keyPair: X25519KeyPair,
        signature: Data,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.keyPair = keyPair
        self.signature = signature
        self.createdAt = createdAt
    }

    /// Generates and self-signs a new signed prekey.
    public static func generate(
        id: UInt32,
        identity: Identity,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SignedPreKey {
        let keyPair = try X25519KeyPair.generate(provider: provider)
        let signature = try identity.signingKey.sign(signingInput(id: id, publicKey: keyPair.publicKey), provider: provider)
        return SignedPreKey(id: id, keyPair: keyPair, signature: signature)
    }

    /// The canonical bytes covered by the identity signature. Shared by
    /// `generate`, `verify`, and key-backup import (which re-signs a
    /// restored prekey deterministically).
    public static func signingInput(id: UInt32, publicKey: Data) -> Data {
        var message = Data("AegisSPK_v1".utf8)
        var encoder = WireEncoder()
        encoder.u32(id)
        encoder.bytes(publicKey)
        message.append(encoder.data)
        return message
    }

    /// Verifies the identity signature over this prekey.
    public func verify(identityPublicKey: Data, provider: any CryptoProvider = CryptoKitProvider.shared) -> Bool {
        Ed25519KeyPair.verify(
            signature: signature,
            for: Self.signingInput(id: id, publicKey: keyPair.publicKey),
            publicKey: identityPublicKey,
            provider: provider
        )
    }

    public var `public`: PublishedSignedPreKey {
        PublishedSignedPreKey(id: id, publicKey: keyPair.publicKey, signature: signature)
    }
}

/// The publishable half of a signed prekey (no private key).
public struct PublishedSignedPreKey: Equatable {
    public let id: UInt32
    public let publicKey: Data
    public let signature: Data
}

// MARK: - One-time prekeys

/// A single-use X25519 keypair. The private half MUST be deleted immediately
/// after it is consumed by `X3DH.respond` — `PreKeyManager` enforces this.
public struct OneTimePreKey {
    public let id: UInt32
    public let keyPair: X25519KeyPair

    public static func generate(
        id: UInt32,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> OneTimePreKey {
        OneTimePreKey(id: id, keyPair: try X25519KeyPair.generate(provider: provider))
    }

    public var `public`: PublishedOneTimePreKey {
        PublishedOneTimePreKey(id: id, publicKey: keyPair.publicKey)
    }
}

/// The publishable half of a one-time prekey.
public struct PublishedOneTimePreKey: Equatable {
    public let id: UInt32
    public let publicKey: Data
}

// MARK: - Bundle

/// Everything an initiator needs to run X3DH against a contact, signed by
/// the contact's identity key. Published to the relay's key slot or handed
/// over in an invite; the relay cannot forge it.
public struct PreKeyBundle {
    public static let noOneTimePreKey: UInt32 = 0xFFFF_FFFF

    public let identity: IdentityPublic
    public let signedPreKey: PublishedSignedPreKey
    /// `nil` when the contact is out of one-time prekeys; X3DH still works
    /// (without the DH4 term) but the initiator should warn the UI that
    /// forward secrecy for the first message is reduced.
    public let oneTimePreKey: PublishedOneTimePreKey?
    /// Ed25519 signature over the canonical bundle encoding below.
    public let bundleSignature: Data

    public init(
        identity: IdentityPublic,
        signedPreKey: PublishedSignedPreKey,
        oneTimePreKey: PublishedOneTimePreKey?,
        bundleSignature: Data
    ) {
        self.identity = identity
        self.signedPreKey = signedPreKey
        self.oneTimePreKey = oneTimePreKey
        self.bundleSignature = bundleSignature
    }

    /// Builds and signs a bundle from live key material.
    public static func build(
        identity: Identity,
        signedPreKey: SignedPreKey,
        oneTimePreKey: OneTimePreKey?,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> PreKeyBundle {
        let published = PreKeyBundle(
            identity: identity.publicView,
            signedPreKey: signedPreKey.public,
            oneTimePreKey: oneTimePreKey?.public,
            bundleSignature: Data()
        )
        let signature = try identity.signingKey.sign(published.signingInput(), provider: provider)
        return PreKeyBundle(
            identity: published.identity,
            signedPreKey: published.signedPreKey,
            oneTimePreKey: published.oneTimePreKey,
            bundleSignature: signature
        )
    }

    /// Verifies the bundle signature AND the signed-prekey signature.
    /// Returns `false` on any failure; initiators must abort X3DH when this
    /// returns `false`.
    public func verify(provider: any CryptoProvider = CryptoKitProvider.shared) -> Bool {
        let bundleOK = Ed25519KeyPair.verify(
            signature: bundleSignature,
            for: signingInput(),
            publicKey: identity.signingPublicKey,
            provider: provider
        )
        guard bundleOK else { return false }
        var spkMessage = Data("AegisSPK_v1".utf8)
        var encoder = WireEncoder()
        encoder.u32(signedPreKey.id)
        encoder.bytes(signedPreKey.publicKey)
        spkMessage.append(encoder.data)
        return Ed25519KeyPair.verify(
            signature: signedPreKey.signature,
            for: spkMessage,
            publicKey: identity.signingPublicKey,
            provider: provider
        )
    }

    private func signingInput() -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(identity.signingPublicKey)
        encoder.bytes(identity.agreementPublicKey)
        encoder.u32(signedPreKey.id)
        encoder.bytes(signedPreKey.publicKey)
        encoder.bytes(signedPreKey.signature)
        if let opk = oneTimePreKey {
            encoder.u8(1)
            encoder.u32(opk.id)
            encoder.bytes(opk.publicKey)
        } else {
            encoder.u8(0)
        }
        return encoder.data
    }

    // MARK: Wire format
    //
    //   version u8 | identity(64) | spk_id u32 | spk_pub 32 | spk_sig 64 |
    //   has_opk u8 | [opk_id u32 | opk_pub 32] | bundle_sig 64

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(identity.signingPublicKey)
        encoder.bytes(identity.agreementPublicKey)
        encoder.u32(signedPreKey.id)
        encoder.bytes(signedPreKey.publicKey)
        encoder.bytes(signedPreKey.signature)
        if let opk = oneTimePreKey {
            encoder.u8(1)
            encoder.u32(opk.id)
            encoder.bytes(opk.publicKey)
        } else {
            encoder.u8(0)
        }
        encoder.bytes(bundleSignature)
        return encoder.data
    }

    public init(serialized data: Data) throws {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let identity = IdentityPublic(
            signingPublicKey: try decoder.bytes(count: 32),
            agreementPublicKey: try decoder.bytes(count: 32)
        )
        let signedPreKey = PublishedSignedPreKey(
            id: try decoder.u32(),
            publicKey: try decoder.bytes(count: 32),
            signature: try decoder.bytes(count: 64)
        )
        let hasOPK = try decoder.u8()
        let oneTimePreKey: PublishedOneTimePreKey?
        switch hasOPK {
        case 1:
            oneTimePreKey = PublishedOneTimePreKey(id: try decoder.u32(), publicKey: try decoder.bytes(count: 32))
        case 0:
            oneTimePreKey = nil
        default:
            throw AegisCryptoError.invalidWireFormat
        }
        let bundleSignature = try decoder.bytes(count: 64)
        try decoder.expectEnd()
        self.init(
            identity: identity,
            signedPreKey: signedPreKey,
            oneTimePreKey: oneTimePreKey,
            bundleSignature: bundleSignature
        )
    }
}

// MARK: - PreKeyManager

/// Owns an identity's live prekey material: rotation of the signed prekey,
/// the one-time-prekey pool, and bundle vending.
///
/// This manager is in-memory. Persisting private halves across launches is
/// the store layer's job (`Packages/AegisStore`); this type documents the
/// exact material that must be persisted and the deletion discipline for
/// one-time prekeys.
public final class PreKeyManager {
    /// Rotate the signed prekey at least this often.
    public static let signedPreKeyMaxAge: TimeInterval = 7 * 24 * 3_600
    /// Keep at least this many one-time prekeys published.
    public static let oneTimePreKeyTargetCount = 100
    /// Refill when the pool drops below this.
    public static let oneTimePreKeyRefillThreshold = 20

    public let identity: Identity
    public private(set) var signedPreKey: SignedPreKey
    private var oneTimePreKeys: [UInt32: OneTimePreKey] = [:]
    private var nextSignedPreKeyID: UInt32 = 1
    private var nextOneTimePreKeyID: UInt32 = 1
    private let provider: any CryptoProvider

    public init(identity: Identity, provider: any CryptoProvider = CryptoKitProvider.shared) throws {
        self.identity = identity
        self.provider = provider
        self.signedPreKey = try SignedPreKey.generate(id: 0, identity: identity, provider: provider)
        try refillOneTimePreKeys()
    }

    /// Restores a manager from backup: keeps the backed-up signed prekey so
    /// bundles peers already hold keep working, and refills the one-time
    /// prekey pool (one-time keys are never backed up by design).
    public init(
        restoring signedPreKey: SignedPreKey,
        identity: Identity,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        self.identity = identity
        self.provider = provider
        self.signedPreKey = signedPreKey
        self.nextSignedPreKeyID = signedPreKey.id &+ 1
        try refillOneTimePreKeys()
    }

    /// The number of unpublished one-time prekeys currently held.
    public var oneTimePreKeyCount: Int { oneTimePreKeys.count }

    /// Vends a signed bundle for publication. The vended one-time prekey is
    /// NOT consumed here — consumption happens in `X3DH.respond`, which must
    /// call `consumeOneTimePreKey(_:)`.
    public func currentBundle() throws -> PreKeyBundle {
        if oneTimePreKeys.count < Self.oneTimePreKeyRefillThreshold {
            try refillOneTimePreKeys()
        }
        let opk = oneTimePreKeys.values.sorted(by: { $0.id < $1.id }).first
        return try PreKeyBundle.build(
            identity: identity,
            signedPreKey: signedPreKey,
            oneTimePreKey: opk,
            provider: provider
        )
    }

    /// Deletes a one-time prekey's private half after use. Called by the
    /// session-establishment path; the `SecureBytes` deinit wipes the bytes.
    /// - Returns: the prekey, or `nil` if the id was unknown (replay or a
    ///   race between two initiators — the responder must then fail the
    ///   handshake rather than reuse the key).
    @discardableResult
    public func consumeOneTimePreKey(_ id: UInt32) -> OneTimePreKey? {
        guard id != PreKeyBundle.noOneTimePreKey else { return nil }
        return oneTimePreKeys.removeValue(forKey: id)
    }

    /// Rotates the signed prekey if it is older than `signedPreKeyMaxAge`.
    /// - Returns: `true` if a rotation happened (caller should republish).
    @discardableResult
    public func rotateSignedPreKeyIfNeeded() throws -> Bool {
        guard Date().timeIntervalSince(signedPreKey.createdAt) >= Self.signedPreKeyMaxAge else {
            return false
        }
        signedPreKey = try SignedPreKey.generate(id: nextSignedPreKeyID, identity: identity, provider: provider)
        nextSignedPreKeyID &+= 1
        return true
    }

    private func refillOneTimePreKeys() throws {
        while oneTimePreKeys.count < Self.oneTimePreKeyTargetCount {
            let opk = try OneTimePreKey.generate(id: nextOneTimePreKeyID, provider: provider)
            oneTimePreKeys[opk.id] = opk
            nextOneTimePreKeyID &+= 1
        }
    }
}
