// Sender keys — the group/channel message ratchet.
//
// One encryption per group message (not one per member): each sender owns
// a *sender key* — a symmetric chain plus a per-distribution Ed25519
// signing key — and advances it for every message she sends. The sender
// key is distributed to members once, encrypted inside each member's 1:1
// session (see `SenderKeyDistribution`); afterwards, group messages are
// pure symmetric crypto.
//
// Security properties, stated honestly:
//  - Forward secrecy *within* a sender key: each message key is deleted
//    after use; the chain ratchets forward.
//  - A member who is removed does not receive the *next* epoch's sender
//    keys, so she cannot read new messages. She can still read messages
//    sent while she was a member — no E2EE protocol can retroactively
//    revoke ciphertext someone already holds.
//  - Post-compromise security is weaker than the 1:1 Double Ratchet: there
//    is no DH ratchet per message. Mitigations: sender keys rotate on
//    every membership change and periodically (message-count and time
//    based; see `GroupSession`), bounding a compromised sender key's blast
//    radius.
//  - Every group message is signed with the sender's per-distribution
//    Ed25519 key, so members authenticate the sender even though the
//    encryption key is shared.
//
// The 32-byte chain key is *inherently exportable* — it is shared with
// every member — so it lives in `SecureBytes` (wiped on release,
// best-effort) rather than an opaque handle. The distribution payload is
// the crown jewels: it MUST travel inside the pairwise E2EE session.

import CryptoKit
import Foundation

// MARK: - SenderKeyState

/// One sender's ratchet state for one group epoch. Used for our own
/// sending key (holds the private signing seed) and for peers' keys
/// (public signing key only — we never hold a peer's signing seed).
public struct SenderKeyState {
    /// The sender's identity fingerprint.
    public let senderID: Data
    public let epoch: UInt32
    /// 32-byte chain key. Shared with all members — handle accordingly.
    public private(set) var chainKey: SecureBytes
    public private(set) var messageIndex: UInt32
    /// Ed25519 public key authenticating this sender's messages for the epoch.
    public let signingPublicKey: Data
    /// Private signing seed. `nil` for peer states.
    /// Internal (not private) so `GroupSession.snapshot()` can persist it;
    /// the seed never leaves the process except into the encrypted store.
    let signingSeed: SecureBytes?

    public init(
        senderID: Data,
        epoch: UInt32,
        chainKey: SecureBytes,
        messageIndex: UInt32 = 0,
        signingPublicKey: Data,
        signingSeed: SecureBytes? = nil
    ) {
        precondition(senderID.count == 32 && chainKey.count == 32 && signingPublicKey.count == 32)
        self.senderID = senderID
        self.epoch = epoch
        self.chainKey = chainKey
        self.messageIndex = messageIndex
        self.signingPublicKey = signingPublicKey
        self.signingSeed = signingSeed
    }

    /// Generates a fresh sender key for our own sending.
    public static func generate(
        senderID: Data,
        epoch: UInt32,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> SenderKeyState {
        let signing = try Ed25519KeyPair.generate(provider: provider)
        return SenderKeyState(
            senderID: senderID,
            epoch: epoch,
            chainKey: SecureBytes(try provider.randomBytes(count: 32)),
            signingPublicKey: signing.publicKey,
            signingSeed: signing.seed
        )
    }

    /// Builds a peer's state from a received (and 1:1-decrypted)
    /// distribution. No signing seed — peers' messages are verified, never
    /// signed, by us.
    public static func peerState(from distribution: SenderKeyDistribution) -> SenderKeyState {
        SenderKeyState(
            senderID: distribution.senderID,
            epoch: distribution.epoch,
            chainKey: SecureBytes(distribution.chainKey),
            signingPublicKey: distribution.signingPublicKey
        )
    }

    /// Signs `message` with our per-distribution signing key.
    /// - Throws: `invalidKeyData` when called on a peer state (programmer error).
    public func sign(
        _ message: Data,
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws -> Data {
        guard let seed = signingSeed else {
            throw AegisCryptoError.invalidKeyData
        }
        return try provider.ed25519Sign(seed: seed.toData(), message: message)
    }

    /// Derives the next message key and ratchets the chain forward.
    /// - Returns: the message index and the single-use AES-256 key.
    public mutating func nextMessageKey() -> (index: UInt32, key: SymmetricKey) {
        let ck = SymmetricKey(data: chainKey.toData())
        let seed = HKDF.hmac(key: ck, message: Data([0x02]))
        let key = HKDF.deriveKey(
            inputKeyMaterial: seed,
            salt: Data(),
            info: Data("AegisGroupMsgKey_v1".utf8),
            outputByteCount: 32
        )
        chainKey = SecureBytes(HKDF.hmac(key: ck, message: Data([0x01])))
        let index = messageIndex
        messageIndex &+= 1
        return (index, key)
    }

    /// Advances the chain to `index`, returning the message keys for the
    /// skipped positions (for out-of-order receives).
    public mutating func keysUpTo(index: UInt32) -> [(index: UInt32, key: SymmetricKey)] {
        var keys: [(UInt32, SymmetricKey)] = []
        while messageIndex < index {
            let (i, key) = nextMessageKey()
            keys.append((i, key))
        }
        return keys
    }
}

// MARK: - SenderKeyDistribution

/// The plaintext sender-key distribution payload.
///
/// **WARNING:** This struct is plaintext. It must be encrypted with the
/// recipient's 1:1 session (`RatchetEngine.encrypt`) before transmission —
/// anyone holding it can read the sender's group messages for the epoch.
/// The transport layer owns that step; this type just makes the payload
/// explicit and versioned.
///
/// Wire: `version u8 || groupID(32) || epoch u32 || senderID(32) ||`
///       `chainKey(32) || signingPub(32)`.
public struct SenderKeyDistribution: Equatable, Sendable {
    public let groupID: Data
    public let epoch: UInt32
    public let senderID: Data
    public let chainKey: Data
    public let signingPublicKey: Data

    public init(groupID: Data, epoch: UInt32, senderID: Data, chainKey: Data, signingPublicKey: Data) {
        precondition(groupID.count == 32 && senderID.count == 32 && chainKey.count == 32 && signingPublicKey.count == 32)
        self.groupID = groupID
        self.epoch = epoch
        self.senderID = senderID
        self.chainKey = chainKey
        self.signingPublicKey = signingPublicKey
    }

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.bytes(groupID)
        encoder.u32(epoch)
        encoder.bytes(senderID)
        encoder.bytes(chainKey)
        encoder.bytes(signingPublicKey)
        return encoder.data
    }

    public init(serialized data: Data) throws {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        let groupID = try decoder.bytes(count: 32)
        let epoch = try decoder.u32()
        let senderID = try decoder.bytes(count: 32)
        let chainKey = try decoder.bytes(count: 32)
        let signingPublicKey = try decoder.bytes(count: 32)
        try decoder.expectEnd()
        self.init(
            groupID: groupID,
            epoch: epoch,
            senderID: senderID,
            chainKey: chainKey,
            signingPublicKey: signingPublicKey
        )
    }
}

// MARK: - GroupMessage

/// One encrypted group message (wire type `0x10`).
///
/// Wire: `version u8 || 0x10 || groupID(32) || epoch u32 || senderID(32) ||`
///       `index u32 || nonce(12) || ctLen u32 || ct || sig(64)`.
///
/// AAD (AES-GCM) = `version || 0x10 || groupID || epoch || senderID || index`.
/// Signature = `Ed25519(senderSigningKey, AAD || nonce || ct)` — verified
/// before any chain operation, so forgeries fail fast without touching
/// ratchet state.
public struct GroupMessage {
    public static let wireType: UInt8 = 0x10

    public let groupID: Data
    public let epoch: UInt32
    public let senderID: Data
    public let index: UInt32
    public let nonce: Data
    public let ciphertext: Data
    public let signature: Data

    public init(
        groupID: Data,
        epoch: UInt32,
        senderID: Data,
        index: UInt32,
        nonce: Data,
        ciphertext: Data,
        signature: Data
    ) {
        precondition(groupID.count == 32 && senderID.count == 32 && nonce.count == 12 && signature.count == 64)
        self.groupID = groupID
        self.epoch = epoch
        self.senderID = senderID
        self.index = index
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.signature = signature
    }

    /// The authenticated header bytes (also the AES-GCM AAD prefix).
    static func headerBytes(groupID: Data, epoch: UInt32, senderID: Data, index: UInt32) -> Data {
        var encoder = WireEncoder()
        encoder.u8(AegisCrypto.protocolVersion)
        encoder.u8(wireType)
        encoder.bytes(groupID)
        encoder.u32(epoch)
        encoder.bytes(senderID)
        encoder.u32(index)
        return encoder.data
    }

    func headerBytes() -> Data {
        Self.headerBytes(groupID: groupID, epoch: epoch, senderID: senderID, index: index)
    }

    /// The exact bytes covered by the Ed25519 signature.
    func signedBytes() -> Data {
        var bytes = headerBytes()
        bytes.append(nonce)
        bytes.append(ciphertext)
        return bytes
    }

    public func serialized() -> Data {
        var encoder = WireEncoder()
        encoder.bytes(headerBytes())
        encoder.bytes(nonce)
        encoder.u32(UInt32(ciphertext.count))
        encoder.bytes(ciphertext)
        encoder.bytes(signature)
        return encoder.data
    }

    public static func parse(_ data: Data) throws -> GroupMessage {
        var decoder = WireDecoder(data)
        let version = try decoder.u8()
        guard version == AegisCrypto.protocolVersion else {
            throw AegisCryptoError.unsupportedVersion(version)
        }
        guard try decoder.u8() == wireType else {
            throw AegisCryptoError.invalidWireFormat
        }
        let groupID = try decoder.bytes(count: 32)
        let epoch = try decoder.u32()
        let senderID = try decoder.bytes(count: 32)
        let index = try decoder.u32()
        let nonce = try decoder.bytes(count: 12)
        let ctLength = Int(try decoder.u32())
        let ciphertext = try decoder.bytes(count: ctLength)
        let signature = try decoder.bytes(count: 64)
        try decoder.expectEnd()
        return GroupMessage(
            groupID: groupID,
            epoch: epoch,
            senderID: senderID,
            index: index,
            nonce: nonce,
            ciphertext: ciphertext,
            signature: signature
        )
    }
}
