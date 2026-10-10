// Double Ratchet (Signal's algorithm, Aegis KDF instantiation).
//
// Security properties, briefly:
//  - Forward secrecy: every message key is derived fresh from its chain
//    key and deleted after use. Compromising today's chain key does not
//    reveal yesterday's messages.
//  - Post-compromise security: every received message carrying a new
//    ratchet public key triggers a DH ratchet step, healing the session
//    after a transient compromise.
//
// This implementation is NOT thread-safe: confine each session to one
// serial dispatch queue (the store layer owns session caching and queueing).
//
// KDFs (specified in docs/CRYPTO.md §6):
//   Root:  stepSalt = HMAC(RK, "AegisRatchetStep_v1")
//          mixKey   = HKDF(DH, salt: stepSalt, info: "AegisRatchetDH_v1")
//          RK'      = HMAC(mixKey, "AegisRatchetRoot_v1")
//          CK'      = HMAC(mixKey, "AegisRatchetChain_v1")
//   Chain: CK_{n+1} = HMAC(CK_n, 0x01)
//          MK_n     = HKDF(HMAC(CK_n, 0x02), info: "AegisMessageKey_v1")
// The cascade shape (rather than Signal's HKDF(RK || DH)) is forced by
// CryptoKit's opaque `SharedSecret`; see X3DH.swift for why the cascade is
// sound. Chain keys and root keys stay in opaque `SymmetricKey` handles;
// only HMAC *outputs* are ever extracted as bytes.
// TODO(security-audit): confirm the "all inputs required" property holds
// under the cascade adaptation of Signal's HKDF(RK || DH) (CRYPTO.md §15.3).

import CryptoKit
import Foundation

// MARK: - Header & message types

/// The plaintext-but-authenticated header of a ratchet message.
/// 40 bytes on the wire: `ratchetPub(32) || pn(u32 BE) || n(u32 BE)`.
public struct RatchetHeader: Equatable {
    /// Exact serialized size. Used by message parsers; kept as a constant
    /// so encode and decode can never drift apart again.
    public static let wireSize = 32 + 4 + 4
    /// The sender's current DH ratchet public key.
    public let ratchetPublicKey: Data
    /// Length of the sender's *previous* sending chain: tells the receiver
    /// how many skipped keys to stash before ratcheting.
    public let previousChainLength: UInt32
    /// Index of this message in the sender's current sending chain.
    public let messageNumber: UInt32

    public init(ratchetPublicKey: Data, previousChainLength: UInt32, messageNumber: UInt32) {
        precondition(ratchetPublicKey.count == 32, "ratchet public key must be 32 bytes")
        self.ratchetPublicKey = ratchetPublicKey
        self.previousChainLength = previousChainLength
        self.messageNumber = messageNumber
    }

    func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.bytes(ratchetPublicKey)
        encoder.u32(previousChainLength)
        encoder.u32(messageNumber)
        return encoder.data
    }

    init(serialized data: Data) throws {
        var decoder = WireDecoder(data)
        let ratchetPublicKey = try decoder.bytes(count: 32)
        let previousChainLength = try decoder.u32()
        let messageNumber = try decoder.u32()
        try decoder.expectEnd()
        self.init(
            ratchetPublicKey: ratchetPublicKey,
            previousChainLength: previousChainLength,
            messageNumber: messageNumber
        )
    }
}

/// A 1:1 ratchet message (wire type `0x01`).
///
/// Wire: `version u8 || 0x01 || header(40) || nonce(12) || ctLen u32 || ct || tag(16)`.
/// AAD = `version || 0x01 || header` (+ application associated data).
public struct RatchetMessage {
    public static let wireType: UInt8 = 0x01

    public let header: RatchetHeader
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(header: RatchetHeader, nonce: Data, ciphertext: Data, tag: Data) {
        precondition(nonce.count == 12 && tag.count == 16)
        self.header = header
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    var sealedMessage: SealedMessage {
        SealedMessage(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    /// The authenticated prefix: version, type, and header. The AEAD AAD is
    /// this prefix followed by application associated data.
    static func authenticatedPrefix(header: RatchetHeader) -> Data {
        var prefix = Data([AegisCrypto.protocolVersion, wireType])
        prefix.append(header.serialized())
        return prefix
    }

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.bytes(Self.authenticatedPrefix(header: header))
        encoder.bytes(nonce)
        encoder.u32(UInt32(ciphertext.count))
        encoder.bytes(ciphertext)
        encoder.bytes(tag)
        return encoder.data
    }

    public static func parse(_ data: Data) throws -> RatchetMessage {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        guard try decoder.u8() == wireType else {
            throw AegisCryptoError.invalidWireFormat
        }
        let header = try RatchetHeader(serialized: decoder.bytes(count: RatchetHeader.wireSize))
        let nonce = try decoder.bytes(count: 12)
        let ctLength = Int(try decoder.u32())
        let ciphertext = try decoder.bytes(count: ctLength)
        let tag = try decoder.bytes(count: 16)
        try decoder.expectEnd()
        return RatchetMessage(header: header, nonce: nonce, ciphertext: ciphertext, tag: tag)
    }
}

/// The first message of a session (wire type `0x02`): carries the X3DH
/// parameters alongside the first ratchet message.
///
/// Wire: `version u8 || 0x02 || ephPub(32) || usedOPK u32 || senderIdentity(65) ||`
///       `header(40) || nonce(12) || ctLen u32 || ct || tag(16)`.
/// AAD covers the X3DH parameters too, so a relay cannot swap the ephemeral
/// key or the claimed sender identity without failing authentication.
public struct PreKeyMessage {
    public static let wireType: UInt8 = 0x02

    public let ephemeralPublicKey: Data
    /// `PreKeyBundle.noOneTimePreKey` (0xFFFF_FFFF) when the bundle had none.
    public let usedOneTimePreKeyID: UInt32
    public let senderIdentity: IdentityPublic
    public let header: RatchetHeader
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data

    public init(
        ephemeralPublicKey: Data,
        usedOneTimePreKeyID: UInt32,
        senderIdentity: IdentityPublic,
        header: RatchetHeader,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) {
        precondition(ephemeralPublicKey.count == 32 && nonce.count == 12 && tag.count == 16)
        self.ephemeralPublicKey = ephemeralPublicKey
        self.usedOneTimePreKeyID = usedOneTimePreKeyID
        self.senderIdentity = senderIdentity
        self.header = header
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    var sealedMessage: SealedMessage {
        SealedMessage(nonce: nonce, ciphertext: ciphertext, tag: tag)
    }

    static func authenticatedPrefix(
        ephemeralPublicKey: Data,
        usedOneTimePreKeyID: UInt32,
        senderIdentity: IdentityPublic,
        header: RatchetHeader
    ) -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.u8(wireType)
        encoder.bytes(ephemeralPublicKey)
        encoder.u32(usedOneTimePreKeyID)
        encoder.bytes(senderIdentity.serialized())
        encoder.bytes(header.serialized())
        return encoder.data
    }

    func authenticatedPrefix() -> Data {
        Self.authenticatedPrefix(
            ephemeralPublicKey: ephemeralPublicKey,
            usedOneTimePreKeyID: usedOneTimePreKeyID,
            senderIdentity: senderIdentity,
            header: header
        )
    }

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.bytes(authenticatedPrefix())
        encoder.bytes(nonce)
        encoder.u32(UInt32(ciphertext.count))
        encoder.bytes(ciphertext)
        encoder.bytes(tag)
        return encoder.data
    }

    public static func parse(_ data: Data) throws -> PreKeyMessage {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        guard try decoder.u8() == wireType else {
            throw AegisCryptoError.invalidWireFormat
        }
        let ephemeralPublicKey = try decoder.bytes(count: 32)
        let usedOneTimePreKeyID = try decoder.u32()
        let senderIdentity = try IdentityPublic(serialized: decoder.bytes(count: 65))
        let header = try RatchetHeader(serialized: decoder.bytes(count: RatchetHeader.wireSize))
        let nonce = try decoder.bytes(count: 12)
        let ctLength = Int(try decoder.u32())
        let ciphertext = try decoder.bytes(count: ctLength)
        let tag = try decoder.bytes(count: 16)
        try decoder.expectEnd()
        return PreKeyMessage(
            ephemeralPublicKey: ephemeralPublicKey,
            usedOneTimePreKeyID: usedOneTimePreKeyID,
            senderIdentity: senderIdentity,
            header: header,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
}

// MARK: - Session

/// The Double Ratchet session: one instance per 1:1 conversation per device.
public final class AegisDoubleRatchet: RatchetEngine {
    /// Maximum messages we will skip ahead on a chain (DoS bound).
    public static let maxSkip: UInt32 = 1_000
    /// Maximum skipped message keys retained across all chains.
    public static let maxSkippedMessageKeys = 2_000

    private let provider: any CryptoProvider
    private var rootKey: SymmetricKey
    private var sendingChainKey: SymmetricKey?
    private var receivingChainKey: SymmetricKey?
    private var sendingRatchetKeyPair: X25519KeyPair
    private var receivingRatchetPublicKey: Data?
    private var sendMessageNumber: UInt32 = 0
    private var receiveMessageNumber: UInt32 = 0
    private var previousSendChainLength: UInt32 = 0

    private struct SkippedKeyID: Hashable {
        let ratchetPublicKey: Data
        let messageNumber: UInt32
    }

    private struct SkippedKey {
        let messageKey: SymmetricKey
        let insertionOrder: UInt64
    }

    private var skippedKeys: [SkippedKeyID: SkippedKey] = [:]
    private var skippedInsertionCounter: UInt64 = 0

    // MARK: Initialization

    /// Initiator side. `remoteRatchetPublicKey` is the responder's
    /// signed-prekey public key, which serves as her initial ratchet key:
    /// the first sending chain is derived immediately via
    /// `DH(ourRatchetPriv, theirSignedPrekeyPub)`.
    public init(
        initiatorRootKey: SymmetricKey,
        remoteRatchetPublicKey: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        guard remoteRatchetPublicKey.count == 32 else {
            throw AegisCryptoError.invalidKeyData
        }
        self.provider = provider
        let ratchetKeyPair = try X25519KeyPair.generate(provider: provider)
        self.sendingRatchetKeyPair = ratchetKeyPair
        let dh = try provider.x25519DH(
            privateKey: ratchetKeyPair.privateKey.toData(),
            peerPublicKey: remoteRatchetPublicKey
        )
        let (newRootKey, newChainKey) = Self.rootKDF(rootKey: initiatorRootKey, dhSecret: dh)
        self.rootKey = newRootKey
        self.sendingChainKey = newChainKey
        // No receiving chain yet; created on the responder's first message.
    }

    /// Responder side. `ratchetKeyPair` is the keypair whose public half the
    /// initiator used as the initial ratchet key — the signed prekey pair.
    /// Keep it alive until the first message arrives.
    public init(
        responderRootKey: SymmetricKey,
        ratchetKeyPair: X25519KeyPair,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) {
        self.provider = provider
        self.rootKey = responderRootKey
        self.sendingRatchetKeyPair = ratchetKeyPair
    }

    // MARK: KDFs

    static func rootKDF(rootKey: SymmetricKey, dhSecret: any DHSecret) -> (rootKey: SymmetricKey, chainKey: SymmetricKey) {
        let stepSalt = HKDF.hmac(key: rootKey, message: Data("AegisRatchetStep_v1".utf8))
        let mixKey = dhSecret.derivedKey(
            salt: stepSalt,
            info: Data("AegisRatchetDH_v1".utf8),
            outputByteCount: 32
        )
        let newRootKey = SymmetricKey(data: HKDF.hmac(key: mixKey, message: Data("AegisRatchetRoot_v1".utf8)))
        let newChainKey = SymmetricKey(data: HKDF.hmac(key: mixKey, message: Data("AegisRatchetChain_v1".utf8)))
        return (newRootKey, newChainKey)
    }

    private static func nextChainKey(_ chainKey: SymmetricKey) -> SymmetricKey {
        SymmetricKey(data: HKDF.hmac(key: chainKey, message: Data([0x01])))
    }

    private static func messageKey(from chainKey: SymmetricKey) -> SymmetricKey {
        let seed = HKDF.hmac(key: chainKey, message: Data([0x02]))
        return HKDF.deriveKey(
            inputKeyMaterial: seed,
            salt: Data(),
            info: Data("AegisMessageKey_v1".utf8),
            outputByteCount: 32
        )
    }

    // MARK: Encrypt

    public func encrypt(plaintext: Data, associatedData: Data = Data()) throws -> RatchetMessage {
        let header = nextHeader()
        var aad = RatchetMessage.authenticatedPrefix(header: header)
        aad.append(associatedData)
        let sealed = try seal(plaintext: plaintext, aad: aad)
        return RatchetMessage(
            header: header,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }

    /// Same-module encryption with a fully caller-specified AAD. Used by
    /// `SessionEstablishment` for prekey messages, whose AAD covers the
    /// X3DH parameters rather than the plain ratchet prefix.
    func encryptPreKeyInner(plaintext: Data, aad: Data) throws -> (header: RatchetHeader, sealed: SealedMessage) {
        let header = nextHeader()
        return (header, try seal(plaintext: plaintext, aad: aad))
    }

    private func nextHeader() -> RatchetHeader {
        let header = RatchetHeader(
            ratchetPublicKey: sendingRatchetKeyPair.publicKey,
            previousChainLength: previousSendChainLength,
            messageNumber: sendMessageNumber
        )
        sendMessageNumber &+= 1
        return header
    }

    private func seal(plaintext: Data, aad: Data) throws -> SealedMessage {
        guard let chainKey = sendingChainKey else {
            throw AegisCryptoError.noSendingChain
        }
        let mk = Self.messageKey(from: chainKey)
        sendingChainKey = Self.nextChainKey(chainKey)
        return try AEAD.seal(plaintext: plaintext, key: mk, associatedData: aad, provider: provider)
    }

    // MARK: Decrypt

    public func decrypt(_ message: RatchetMessage, associatedData: Data = Data()) throws -> Data {
        var aad = RatchetMessage.authenticatedPrefix(header: message.header)
        aad.append(associatedData)
        return try decrypt(header: message.header, sealed: message.sealedMessage, aad: aad)
    }

    /// Same-module decryption with explicit AAD (prekey-message path).
    func decrypt(header: RatchetHeader, sealed: SealedMessage, aad: Data) throws -> Data {
        let skipID = SkippedKeyID(ratchetPublicKey: header.ratchetPublicKey, messageNumber: header.messageNumber)

        // 1. Out-of-order keys stashed earlier.
        if let skipped = skippedKeys.removeValue(forKey: skipID) {
            return try decryptSealed(sealed, key: skipped.messageKey, aad: aad)
        }

        // 2. Current receiving chain.
        if let current = receivingRatchetPublicKey,
           constantTimeEqual(current, header.ratchetPublicKey)
        {
            return try decryptWithChainAdvance(header: header, sealed: sealed, aad: aad)
        }

        // 3. New ratchet public key: stash skipped keys for the old chain up
        //    to pn, DH-ratchet, then decrypt on the new chain.
        try skipMessageKeys(until: header.previousChainLength)
        try performDHRatchet(theirNewPublicKey: header.ratchetPublicKey)
        if let skipped = skippedKeys.removeValue(forKey: skipID) {
            return try decryptSealed(sealed, key: skipped.messageKey, aad: aad)
        }
        return try decryptWithChainAdvance(header: header, sealed: sealed, aad: aad)
    }

    private func decryptSealed(_ sealed: SealedMessage, key: SymmetricKey, aad: Data) throws -> Data {
        try AEAD.open(sealed, key: key, associatedData: aad, provider: provider)
    }

    /// Advances the receiving chain to `header.messageNumber`, stashing
    /// skipped keys for the gap, then decrypts.
    private func decryptWithChainAdvance(header: RatchetHeader, sealed: SealedMessage, aad: Data) throws -> Data {
        guard let chainKey = receivingChainKey else {
            throw AegisCryptoError.noReceivingChain
        }
        let n = header.messageNumber
        guard n >= receiveMessageNumber else {
            throw AegisCryptoError.messageTooOld
        }
        let gap = n - receiveMessageNumber
        guard gap <= Self.maxSkip else {
            throw AegisCryptoError.messageTooFarInFuture
        }
        var ck = chainKey
        if let ratchetPub = receivingRatchetPublicKey {
            for skippedNumber in receiveMessageNumber ..< n {
                storeSkippedKey(
                    ratchetPublicKey: ratchetPub,
                    messageNumber: skippedNumber,
                    messageKey: Self.messageKey(from: ck)
                )
                ck = Self.nextChainKey(ck)
            }
        }
        let mk = Self.messageKey(from: ck)
        // State advances before the AEAD check, per the Double Ratchet spec:
        // a failed authentication consumes the message key, making the
        // forgery un-replayable. The message is then lost; the peer cannot
        // re-send it (its chain has also advanced).
        receivingChainKey = Self.nextChainKey(ck)
        receiveMessageNumber = n &+ 1
        return try decryptSealed(sealed, key: mk, aad: aad)
    }

    /// Stashes skipped message keys for the current receiving chain up to
    /// (excluding) `messageNumber`. No-op when there is no receiving chain
    /// yet (responder's first message) or when already past it.
    private func skipMessageKeys(until messageNumber: UInt32) throws {
        guard let chainKey = receivingChainKey,
              let ratchetPub = receivingRatchetPublicKey,
              messageNumber > receiveMessageNumber
        else { return }
        let gap = messageNumber - receiveMessageNumber
        guard gap <= Self.maxSkip else {
            throw AegisCryptoError.messageTooFarInFuture
        }
        var ck = chainKey
        for skippedNumber in receiveMessageNumber ..< messageNumber {
            storeSkippedKey(
                ratchetPublicKey: ratchetPub,
                messageNumber: skippedNumber,
                messageKey: Self.messageKey(from: ck)
            )
            ck = Self.nextChainKey(ck)
        }
        receivingChainKey = ck
        receiveMessageNumber = messageNumber
    }

    /// The DH ratchet step: new receiving chain from
    /// `DH(ourRatchetPriv, theirNewPub)`, then a fresh sending keypair and
    /// new sending chain from `DH(newPriv, theirNewPub)`.
    private func performDHRatchet(theirNewPublicKey: Data) throws {
        guard theirNewPublicKey.count == 32 else {
            throw AegisCryptoError.invalidKeyData
        }
        previousSendChainLength = sendMessageNumber
        sendMessageNumber = 0
        receiveMessageNumber = 0

        let receiveDH = try provider.x25519DH(
            privateKey: sendingRatchetKeyPair.privateKey.toData(),
            peerPublicKey: theirNewPublicKey
        )
        let (rootAfterReceive, newReceivingChain) = Self.rootKDF(rootKey: rootKey, dhSecret: receiveDH)
        rootKey = rootAfterReceive
        receivingChainKey = newReceivingChain
        receivingRatchetPublicKey = theirNewPublicKey

        let newPair = try X25519KeyPair.generate(provider: provider)
        let sendDH = try provider.x25519DH(
            privateKey: newPair.privateKey.toData(),
            peerPublicKey: theirNewPublicKey
        )
        let (rootAfterSend, newSendingChain) = Self.rootKDF(rootKey: rootKey, dhSecret: sendDH)
        rootKey = rootAfterSend
        sendingChainKey = newSendingChain
        sendingRatchetKeyPair = newPair
    }

    private func storeSkippedKey(ratchetPublicKey: Data, messageNumber: UInt32, messageKey: SymmetricKey) {
        if skippedKeys.count >= Self.maxSkippedMessageKeys {
            // Evict the oldest-inserted key. Bounded memory wins over
            // retaining undecryptable out-of-order messages indefinitely;
            // forward secrecy prefers dropping them anyway.
            if let oldest = skippedKeys.min(by: { $0.value.insertionOrder < $1.value.insertionOrder })?.key {
                skippedKeys.removeValue(forKey: oldest)
            }
        }
        skippedInsertionCounter &+= 1
        skippedKeys[SkippedKeyID(ratchetPublicKey: ratchetPublicKey, messageNumber: messageNumber)] =
            SkippedKey(messageKey: messageKey, insertionOrder: skippedInsertionCounter)
    }
}

// MARK: - Session establishment

/// Wires X3DH and the first ratchet message together.
public enum SessionEstablishment {
    public struct InitiatedSession {
        /// The live session. Cache it in the store layer keyed by the
        /// contact's fingerprint.
        public let session: AegisDoubleRatchet
        /// Wire bytes to send (a `PreKeyMessage`).
        public let preKeyMessage: Data
        /// The one-time prekey id the initiator consumed, if any. Sent so
        /// the responder can delete the right private half.
        public let usedOneTimePreKeyID: UInt32?
    }

    /// Initiator: X3DH + first ratchet message, wrapped as a prekey message.
    public static func initiate(
        ourIdentity: Identity,
        bundle: PreKeyBundle,
        plaintext: Data,
        associatedData: Data = Data(),
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> InitiatedSession {
        let x3dh = try X3DH.initiate(ourIdentity: ourIdentity, bundle: bundle, provider: provider)
        let session = try AegisDoubleRatchet(
            initiatorRootKey: x3dh.rootKey,
            remoteRatchetPublicKey: bundle.signedPreKey.publicKey,
            provider: provider
        )
        let usedOPKID = x3dh.usedOneTimePreKeyID ?? PreKeyBundle.noOneTimePreKey
        // AAD covers the X3DH parameters: computed from fields both sides
        // agree on, before encryption.
        let (header, sealed) = try session.encryptPreKeyInner(
            plaintext: plaintext,
            aad: PreKeyMessage.authenticatedPrefix(
                ephemeralPublicKey: x3dh.ephemeralPublicKey,
                usedOneTimePreKeyID: usedOPKID,
                senderIdentity: ourIdentity.publicView,
                header: sessionNextHeaderPreview(session)
            ).appending(associatedData)
        )
        let message = PreKeyMessage(
            ephemeralPublicKey: x3dh.ephemeralPublicKey,
            usedOneTimePreKeyID: usedOPKID,
            senderIdentity: ourIdentity.publicView,
            header: header,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
        return InitiatedSession(
            session: session,
            preKeyMessage: message.serialized(),
            usedOneTimePreKeyID: x3dh.usedOneTimePreKeyID
        )
    }

    public struct RespondedSession {
        public let session: AegisDoubleRatchet
        public let plaintext: Data
        /// The initiator's fingerprint, for session-cache lookup.
        public let initiatorFingerprint: Data
        /// The one-time prekey id the initiator consumed, if any. The
        /// caller MUST pass this to `PreKeyManager.consumeOneTimePreKey`
        /// immediately — before returning the plaintext, ideally.
        public let usedOneTimePreKeyID: UInt32?
    }

    /// Responder: parses the prekey message, runs X3DH, decrypts the first
    /// ratchet message.
    public static func respond(
        preKeyMessageWire: Data,
        ourIdentity: Identity,
        ourSignedPreKey: SignedPreKey,
        usedOneTimePreKey: OneTimePreKey?,
        associatedData: Data = Data(),
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> RespondedSession {
        let message = try PreKeyMessage.parse(preKeyMessageWire)

        // The claimed sender identity must match the fingerprint the user
        // verified out-of-band; the transport layer checks this against the
        // expected contact before calling here. We additionally require the
        // bundle-less identity to be well-formed (parse already enforced).
        let rootKey = try X3DH.respond(
            ourIdentity: ourIdentity,
            ourSignedPreKey: ourSignedPreKey,
            usedOneTimePreKey: usedOneTimePreKey,
            initiator: message.senderIdentity,
            ephemeralPublicKey: message.ephemeralPublicKey,
            provider: provider
        )
        let session = AegisDoubleRatchet(
            responderRootKey: rootKey,
            ratchetKeyPair: ourSignedPreKey.keyPair,
            provider: provider
        )
        var aad = message.authenticatedPrefix()
        aad.append(associatedData)
        let plaintext = try session.decrypt(header: message.header, sealed: message.sealedMessage, aad: aad)

        let usedOPKID: UInt32? = message.usedOneTimePreKeyID == PreKeyBundle.noOneTimePreKey
            ? nil
            : message.usedOneTimePreKeyID
        return RespondedSession(
            session: session,
            plaintext: plaintext,
            initiatorFingerprint: message.senderIdentity.fingerprint,
            usedOneTimePreKeyID: usedOPKID
        )
    }

    // MARK: - Internal helper

    /// Peeks at the header the session will use for its next encryption
    /// without advancing state, so the prekey AAD can commit to it before
    /// `encryptPreKeyInner` runs.
    private static func sessionNextHeaderPreview(_ session: AegisDoubleRatchet) -> RatchetHeader {
        session.nextHeaderPreview()
    }
}

// MARK: - AegisDoubleRatchet internal preview (same module)

extension AegisDoubleRatchet {
    /// The header the next `encrypt` call will emit, without mutating state.
    func nextHeaderPreview() -> RatchetHeader {
        RatchetHeader(
            ratchetPublicKey: sendingRatchetKeyPair.publicKey,
            previousChainLength: previousSendChainLength,
            messageNumber: sendMessageNumber
        )
    }
}

// MARK: - Session snapshots (durable persistence)
//
// The versioned Codable structs live in SessionSnapshot.swift. This
// extension lives here (same file as the class) because it touches the
// ratchet's private state.

extension AegisDoubleRatchet {
    /// Captures the session's full resumable state. The caller supplies the
    /// peer identity and X3DH ephemeral key (they live in the session cache
    /// entry, not the ratchet itself).
    public func snapshot(peerIdentity: IdentityPublic, ephemeralPublicKey: Data) -> RatchetSessionSnapshot {
        RatchetSessionSnapshot(
            peerIdentity: peerIdentity.serialized(),
            ephemeralPublicKey: ephemeralPublicKey,
            rootKey: rootKey.withUnsafeBytes { Data($0) },
            sendingChainKey: sendingChainKey?.withUnsafeBytes { Data($0) },
            receivingChainKey: receivingChainKey?.withUnsafeBytes { Data($0) },
            sendingRatchetPrivateKey: sendingRatchetKeyPair.privateKey.toData(),
            sendingRatchetPublicKey: sendingRatchetKeyPair.publicKey,
            receivingRatchetPublicKey: receivingRatchetPublicKey,
            sendMessageNumber: sendMessageNumber,
            receiveMessageNumber: receiveMessageNumber,
            previousSendChainLength: previousSendChainLength,
            skippedKeys: skippedKeys.map { (id, key) in
                SkippedKeySnapshot(
                    ratchetPublicKey: id.ratchetPublicKey,
                    messageNumber: id.messageNumber,
                    messageKey: key.messageKey.withUnsafeBytes { Data($0) },
                    insertionOrder: key.insertionOrder
                )
            }
        )
    }

    /// Restores a session from a snapshot. Validates the version and every
    /// key length; re-derives the sending ratchet public key from the
    /// private scalar and cross-checks it against the stored copy so a
    /// corrupted snapshot can never silently resume a wrong session.
    public convenience init(
        snapshot: RatchetSessionSnapshot,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        guard snapshot.version <= RatchetSessionSnapshot.currentVersion else {
            throw AegisCryptoError.unsupportedSnapshotVersion(snapshot.version)
        }
        // v1 is the only version so far; the switch is the migration point
        // for future formats.
        switch snapshot.version {
        case 1: break
        default: throw AegisCryptoError.unsupportedSnapshotVersion(snapshot.version)
        }
        guard snapshot.rootKey.count == 32,
              snapshot.ephemeralPublicKey.count == 32,
              snapshot.sendingRatchetPrivateKey.count == 32,
              snapshot.sendingRatchetPublicKey.count == 32,
              snapshot.sendingChainKey.map({ $0.count == 32 }) ?? true,
              snapshot.receivingChainKey.map({ $0.count == 32 }) ?? true,
              snapshot.receivingRatchetPublicKey.map({ $0.count == 32 }) ?? true
        else {
            throw AegisCryptoError.invalidKeyData
        }
        // The peer identity must parse — a snapshot for a malformed peer is
        // corrupt by definition.
        _ = try IdentityPublic(serialized: snapshot.peerIdentity)

        let derivedPub = try X25519KeyPair.publicKey(
            forPrivateKey: snapshot.sendingRatchetPrivateKey,
            provider: provider
        )
        guard derivedPub == snapshot.sendingRatchetPublicKey else {
            throw AegisCryptoError.invalidKeyData
        }
        let keyPair = X25519KeyPair(
            privateKey: SecureBytes(snapshot.sendingRatchetPrivateKey),
            publicKey: snapshot.sendingRatchetPublicKey
        )

        // Route through the responder initializer to set the provider,
        // rootKey, and sendingRatchetKeyPair, then overwrite the rest.
        // (The responder init leaves both chains nil, which we then fill.)
        self.init(
            responderRootKey: SymmetricKey(data: snapshot.rootKey),
            ratchetKeyPair: keyPair,
            provider: provider
        )
        self.sendingChainKey = snapshot.sendingChainKey.map { SymmetricKey(data: $0) }
        self.receivingChainKey = snapshot.receivingChainKey.map { SymmetricKey(data: $0) }
        self.receivingRatchetPublicKey = snapshot.receivingRatchetPublicKey
        self.sendMessageNumber = snapshot.sendMessageNumber
        self.receiveMessageNumber = snapshot.receiveMessageNumber
        self.previousSendChainLength = snapshot.previousSendChainLength
        var restored: [SkippedKeyID: SkippedKey] = [:]
        var maxOrder: UInt64 = 0
        for sk in snapshot.skippedKeys {
            guard sk.ratchetPublicKey.count == 32, sk.messageKey.count == 32 else {
                throw AegisCryptoError.invalidKeyData
            }
            restored[SkippedKeyID(ratchetPublicKey: sk.ratchetPublicKey, messageNumber: sk.messageNumber)] =
                SkippedKey(messageKey: SymmetricKey(data: sk.messageKey), insertionOrder: sk.insertionOrder)
            maxOrder = max(maxOrder, sk.insertionOrder)
        }
        self.skippedKeys = restored
        self.skippedInsertionCounter = maxOrder &+ 1
    }
}

private extension Data {
    func appending(_ other: Data) -> Data {
        var copy = self
        copy.append(other)
        return copy
    }
}
