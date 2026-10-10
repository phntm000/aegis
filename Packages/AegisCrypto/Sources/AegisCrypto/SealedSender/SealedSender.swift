// Sealed sender — hides the sender's identity from the relay.
//
// A sealed envelope is addressed only by the recipient's 16-byte mailbox
// ID (see `Identity.mailboxID`). The sender's fingerprint travels *inside*
// the encrypted payload, in a signed sender certificate. The relay learns:
//  - that *some* sealed envelope is addressed to mailbox M,
//  - its size class (payloads are padded) and timing.
// It does NOT learn who sent it. The recipient, of course, learns the
// sender — sealed sender is sender-anonymity from the *infrastructure*,
// not from the conversation partner.
//
// Construction:
//   eph = fresh X25519 keypair (per envelope — never reused)
//   dh  = DH(ephPriv, recipientAgreementPub)
//   key = HKDF(dh, salt: mailboxID, info: "AegisSealed_v1")
//   ct  = AES-GCM(key, nonce: random 96-bit,
//                 aad: version || mailboxID || ephPub,
//                 pt: pad(cert || innerMessage))
//   cert = fingerprint(32) || timestamp(u64) ||
//          Ed25519(senderSigningKey,
//                  "AegisSealedCert_v1" || ephPub || mailboxID ||
//                  timestamp || SHA256(innerMessage))
//
// The inner message must itself be an authenticated envelope (a
// `RatchetMessage`, `PreKeyMessage`, or `GroupMessage` wire blob): the
// certificate binds the sender to this envelope, the inner envelope binds
// the sender to the content.
//
// Opening requires the sender's *public identity*, resolved from the
// certificate's fingerprint via the contact list. That resolution is a
// trust decision — unknown fingerprints must surface in the UI as
// "unknown sender", never as a contact — so it deliberately lives outside
// this function: the caller passes the resolved `IdentityPublic`.
//
// What this does NOT hide: IP addresses / network timing (use Tor or a VPN
// if that matters — see THREAT_MODEL.md), or the fact that two mailboxes
// exchange traffic.

import CryptoKit
import Foundation

/// A sealed envelope (wire type `0x20`).
///
/// Wire: `version u8 || mailboxID(16) || ephPub(32) || nonce(12) ||`
///       `ctLen u32 || ct || tag(16)`.
public struct SealedEnvelope {
    public static let wireType: UInt8 = 0x20

    public let mailboxID: Data
    public let ephemeralPublicKey: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(mailboxID: Data, ephemeralPublicKey: Data, nonce: Data, ciphertext: Data, tag: Data) {
        precondition(mailboxID.count == 16 && ephemeralPublicKey.count == 32 && nonce.count == 12 && tag.count == 16)
        self.mailboxID = mailboxID
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    /// The AES-GCM associated data: version, type, and routing fields.
    /// The sender's identity appears nowhere in it.
    static func aad(mailboxID: Data, ephemeralPublicKey: Data) -> Data {
        var aad = Data([AegisCrypto.protocolVersion, Self.wireType])
        aad.append(mailboxID)
        aad.append(ephemeralPublicKey)
        return aad
    }

    var aad: Data {
        Self.aad(mailboxID: mailboxID, ephemeralPublicKey: ephemeralPublicKey)
    }

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(mailboxID)
        encoder.bytes(ephemeralPublicKey)
        encoder.bytes(nonce)
        encoder.u32(UInt32(ciphertext.count))
        encoder.bytes(ciphertext)
        encoder.bytes(tag)
        return encoder.data
    }

    public static func parse(_ data: Data) throws -> SealedEnvelope {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let mailboxID = try decoder.bytes(count: 16)
        let ephemeralPublicKey = try decoder.bytes(count: 32)
        let nonce = try decoder.bytes(count: 12)
        let ctLength = Int(try decoder.u32())
        let ciphertext = try decoder.bytes(count: ctLength)
        let tag = try decoder.bytes(count: 16)
        try decoder.expectEnd()
        return SealedEnvelope(
            mailboxID: mailboxID,
            ephemeralPublicKey: ephemeralPublicKey,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
}

/// The sender certificate carried inside a sealed envelope:
/// `fingerprint(32) || timestamp(u64 BE) || signature(64) || innerMessage…`.
struct SenderCertificate {
    let senderFingerprint: Data
    let timestamp: UInt64

    func serialized(signature: Data, innerMessage: Data) -> Data {
        var encoder = WireEncoder()
        encoder.bytes(senderFingerprint)
        encoder.u64(timestamp)
        encoder.bytes(signature)
        encoder.bytes(innerMessage)
        return encoder.data
    }

    static func parse(_ data: Data) throws -> (certificate: SenderCertificate, signature: Data, innerMessage: Data) {
        var decoder = WireDecoder(data)
        let fingerprint = try decoder.bytes(count: 32)
        let timestamp = try decoder.u64()
        let signature = try decoder.bytes(count: 64)
        let innerMessage = try decoder.bytes(count: decoder.remaining)
        return (
            SenderCertificate(senderFingerprint: fingerprint, timestamp: timestamp),
            signature,
            innerMessage
        )
    }

    /// The exact bytes the signature covers.
    static func signingInput(
        ephemeralPublicKey: Data,
        mailboxID: Data,
        timestamp: UInt64,
        innerMessageHash: Data
    ) -> Data {
        var input = Data("AegisSealedCert_v1".utf8)
        input.append(ephemeralPublicKey)
        input.append(mailboxID)
        var encoder = WireEncoder()
        encoder.u64(timestamp)
        input.append(encoder.data)
        input.append(innerMessageHash)
        return input
    }
}

public enum SealedSender {
    /// Certificates older than this are rejected (replay bound).
    public static let maxCertificateAge: TimeInterval = 48 * 3_600
    /// Tolerance for clock skew into the future.
    public static let maxClockSkew: TimeInterval = 5 * 60

    // MARK: - Seal

    /// Seals `innerMessage` (an already-encrypted `RatchetMessage`,
    /// `PreKeyMessage`, or `GroupMessage` wire blob) for the recipient.
    public static func seal(
        innerMessage: Data,
        sender: Identity,
        recipientAgreementPublicKey: Data,
        recipientMailboxID: Data,
        now: Date = Date(),
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SealedEnvelope {
        guard recipientAgreementPublicKey.count == 32, recipientMailboxID.count == 16 else {
            throw AegisCryptoError.invalidKeyData
        }
        let ephemeral = try X25519KeyPair.generate(provider: provider)
        let key = try sealedSenderKey(
            privateKey: ephemeral.privateKey.toData(),
            peerPublicKey: recipientAgreementPublicKey,
            mailboxID: recipientMailboxID,
            provider: provider
        )

        let timestamp = UInt64(now.timeIntervalSince1970)
        let innerHash = Data(SHA256.hash(data: innerMessage))
        let signingInput = SenderCertificate.signingInput(
            ephemeralPublicKey: ephemeral.publicKey,
            mailboxID: recipientMailboxID,
            timestamp: timestamp,
            innerMessageHash: innerHash
        )
        let signature = try sender.signingKey.sign(signingInput, provider: provider)

        let cert = SenderCertificate(senderFingerprint: sender.fingerprint, timestamp: timestamp)
        let padded = Padding.pad(cert.serialized(signature: signature, innerMessage: innerMessage))

        let aad = SealedEnvelope.aad(mailboxID: recipientMailboxID, ephemeralPublicKey: ephemeral.publicKey)
        let sealed = try AEAD.seal(plaintext: padded, key: key, associatedData: aad, provider: provider)
        return SealedEnvelope(
            mailboxID: recipientMailboxID,
            ephemeralPublicKey: ephemeral.publicKey,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }

    // MARK: - Open

    public struct OpenedEnvelope {
        /// The sender's identity fingerprint, authenticated by the
        /// certificate and checked against the resolved sender identity.
        public let senderFingerprint: Data
        /// The inner encrypted message, still to be decrypted by the
        /// session layer.
        public let innerMessage: Data
    }

    /// Opens a sealed envelope addressed to `recipient`.
    ///
    /// - Parameter senderIdentity: the sender's public identity, resolved
    ///   from the certificate's fingerprint via the contact list. Unknown
    ///   fingerprints must NOT be resolved to a contact — surface them as
    ///   unknown senders in the UI.
    /// - Throws: `authenticationFailed` (wrong recipient or tampering),
    ///   `invalidSignature` (forged certificate or fingerprint mismatch),
    ///   `certificateExpired` (replay outside the validity window).
    public static func open(
        _ envelope: SealedEnvelope,
        recipient: Identity,
        senderIdentity: IdentityPublic,
        now: Date = Date(),
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> OpenedEnvelope {
        let key = try sealedSenderKey(
            privateKey: recipient.agreementKey.privateKey.toData(),
            peerPublicKey: envelope.ephemeralPublicKey,
            mailboxID: envelope.mailboxID,
            provider: provider
        )

        let sealed = SealedMessage(nonce: envelope.nonce, ciphertext: envelope.ciphertext, tag: envelope.tag)
        let padded = try AEAD.open(sealed, key: key, associatedData: envelope.aad, provider: provider)
        let plaintext = try Padding.unpad(padded)

        let (cert, signature, innerMessage) = try SenderCertificate.parse(plaintext)

        // The certificate's claimed fingerprint must match the resolved
        // sender identity — otherwise anyone could claim to be anyone.
        guard constantTimeEqual(cert.senderFingerprint, senderIdentity.fingerprint) else {
            throw AegisCryptoError.invalidSignature
        }

        // Freshness: replay bound.
        let nowSeconds = now.timeIntervalSince1970
        let certTime = TimeInterval(cert.timestamp)
        guard certTime <= nowSeconds + maxClockSkew,
              nowSeconds - certTime <= maxCertificateAge + maxClockSkew
        else {
            throw AegisCryptoError.certificateExpired
        }

        // Authenticate the certificate against the sender's identity key.
        let innerHash = Data(SHA256.hash(data: innerMessage))
        let signingInput = SenderCertificate.signingInput(
            ephemeralPublicKey: envelope.ephemeralPublicKey,
            mailboxID: envelope.mailboxID,
            timestamp: cert.timestamp,
            innerMessageHash: innerHash
        )
        guard provider.ed25519Verify(
            publicKey: senderIdentity.signingPublicKey,
            signature: signature,
            message: signingInput
        ) else {
            throw AegisCryptoError.invalidSignature
        }

        return OpenedEnvelope(senderFingerprint: cert.senderFingerprint, innerMessage: innerMessage)
    }

    /// Opens a sealed envelope WITHOUT a pre-resolved sender identity.
    ///
    /// This is the rendezvous path: a prekey message arriving on our stable
    /// identity route from a sender we have never met (first contact) or
    /// whose identity changed (reinstall). The envelope is addressed only to
    /// us, so the AEAD open needs no sender information.
    ///
    /// What IS enforced here: envelope authenticity (AEAD), certificate
    /// freshness (replay bound). What is NOT verified here: the certificate
    /// signature — that requires the sender's public identity, which the
    /// caller does not have yet. The caller MUST authenticate the returned
    /// `senderFingerprint` via the inner message before trusting it or
    /// acting on it: for a prekey message, the X3DH exchange authenticates
    /// `PreKeyMessage.senderIdentity`, and the caller must check
    /// `senderIdentity.fingerprint == senderFingerprint` (constant-time)
    /// after — and only after — the X3DH/AEAD decrypt succeeds. A forged
    /// inner identity fails X3DH authentication; a mismatched certificate
    /// fingerprint must be rejected.
    ///
    /// - Throws: `authenticationFailed` (wrong recipient or tampering),
    ///   `certificateExpired` (replay outside the validity window).
    public static func openAnonymous(
        _ envelope: SealedEnvelope,
        recipient: Identity,
        now: Date = Date(),
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> (senderFingerprint: Data, innerMessage: Data) {
        let key = try sealedSenderKey(
            privateKey: recipient.agreementKey.privateKey.toData(),
            peerPublicKey: envelope.ephemeralPublicKey,
            mailboxID: envelope.mailboxID,
            provider: provider
        )

        let sealed = SealedMessage(nonce: envelope.nonce, ciphertext: envelope.ciphertext, tag: envelope.tag)
        let padded = try AEAD.open(sealed, key: key, associatedData: envelope.aad, provider: provider)
        let plaintext = try Padding.unpad(padded)

        let (cert, _, innerMessage) = try SenderCertificate.parse(plaintext)

        // Freshness: replay bound (no identity needed for this check).
        let nowSeconds = now.timeIntervalSince1970
        let certTime = TimeInterval(cert.timestamp)
        guard certTime <= nowSeconds + maxClockSkew,
              nowSeconds - certTime <= maxCertificateAge + maxClockSkew
        else {
            throw AegisCryptoError.certificateExpired
        }

        return (cert.senderFingerprint, innerMessage)
    }

    // MARK: - Internal

    /// Visible for tests (forgery tests need to mint envelopes with
    /// mismatched certificates); not public API.
    static func sealedSenderKey(
        privateKey: Data,
        peerPublicKey: Data,
        mailboxID: Data,
        provider: any CryptoProvider
    ) throws -> SymmetricKey {
        // DH is symmetric: seal computes DH(ephPriv, recipientPub), open
        // computes DH(recipientPriv, ephPub) — same shared secret.
        let dh = try provider.x25519DH(privateKey: privateKey, peerPublicKey: peerPublicKey)
        return dh.derivedKey(
            salt: mailboxID,
            info: Data("AegisSealed_v1".utf8),
            outputByteCount: 32
        )
    }
}
