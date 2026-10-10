// GroupSession — membership, epochs, and sender-key rotation for a group.
//
// Epoch model:
//  - Every membership change (add or remove) bumps the epoch. The changer
//    generates a fresh sender key for the new epoch and distributes it to
//    the remaining members (encrypted in their 1:1 sessions by the
//    transport layer).
//  - A removed member never receives the new epoch's sender keys, so new
//    messages are unreadable to her. An added member never receives old
//    epochs' keys, so history stays private.
//  - Sender keys also rotate periodically (message count / wall clock) to
//    bound the blast radius of a compromised sender key — the group's
//    substitute for the 1:1 DH ratchet.
//
// Out-of-order group messages are handled per (sender, epoch) with a
// bounded skipped-key store, mirroring the 1:1 ratchet.
//
// Not thread-safe: confine to one serial queue per group.

import CryptoKit
import Foundation

/// A group member, as known to the crypto layer. `displayName` is a UI hint
/// only — it is never authenticated; the fingerprint is the identity.
/// Alias: the `AegisCrypto` enum shadows the module name, so clients
/// outside the package cannot write `AegisCrypto.GroupMember`.
public typealias CryptoGroupMember = GroupMember

public struct GroupMember: Equatable {
    /// 32-byte identity fingerprint.
    public let fingerprint: Data
    public let displayName: String

    public init(fingerprint: Data, displayName: String) {
        precondition(fingerprint.count == 32, "fingerprint must be 32 bytes")
        self.fingerprint = fingerprint
        self.displayName = displayName
    }
}

/// A plaintext sender-key distribution paired with its intended recipient.
/// The transport layer encrypts `distribution.serialized()` with the
/// recipient's 1:1 session before sending.
public struct OutgoingDistribution: Sendable {
    public let recipientFingerprint: Data
    public let distribution: SenderKeyDistribution
}

public final class GroupSession {
    /// Rotate our sender key after this many sent messages (post-compromise
    /// bound for the symmetric-only group ratchet).
    public static let senderKeyMessageRotationInterval: UInt32 = 1_000
    /// …or after this much wall-clock time, whichever comes first.
    public static let senderKeyTimeRotationInterval: TimeInterval = 7 * 24 * 3_600
    /// Maximum out-of-order gap per (sender, epoch).
    public static let maxGroupSkip: UInt32 = 500
    /// Maximum retained (sender, epoch) states; oldest evicted first.
    public static let maxPeerSenderStates = 256

    public let groupID: Data
    public private(set) var epoch: UInt32
    public private(set) var members: [Data: GroupMember] = [:]

    private let ourFingerprint: Data
    private let provider: any CryptoProvider
    private var ourSenderKey: SenderKeyState?
    private var ourSenderKeyCreatedAt: Date?
    private var messagesSentOnCurrentKey: UInt32 = 0

    private struct PeerKeyID: Hashable {
        let senderID: Data
        let epoch: UInt32
    }

    private struct PeerSenderState {
        var senderKey: SenderKeyState
        var skipped: [UInt32: SymmetricKey] = [:]
        var lastUsed: Date
    }

    private var peerSenderStates: [PeerKeyID: PeerSenderState] = [:]

    // MARK: - Creation

    /// Creates a group. `groupID` should be 32 fresh random bytes generated
    /// by the founder (not derived from member lists — membership changes,
    /// the id must not).
    public init(
        groupID: Data,
        founder: Identity,
        initialMembers: [GroupMember],
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        precondition(groupID.count == 32, "groupID must be 32 bytes")
        self.groupID = groupID
        self.epoch = 0
        self.ourFingerprint = founder.fingerprint
        self.provider = provider
        for member in initialMembers where member.fingerprint != founder.fingerprint {
            members[member.fingerprint] = member
        }
        members[founder.fingerprint] = GroupMember(fingerprint: founder.fingerprint, displayName: "You")
        try rotateOurSenderKey()
    }

    /// Joins an existing group from an invite carrying `groupID`, `epoch`,
    /// and the member list. The invite itself must arrive over an
    /// authenticated channel (the inviter's 1:1 session) — the crypto layer
    /// cannot authenticate a bare invite, so the transport layer must.
    /// The joiner generates her own sender key for the current epoch;
    /// distribute it with `initialDistributions()`.
    public init(
        groupID: Data,
        epoch: UInt32,
        joiner: Identity,
        members: [GroupMember],
        provider: any CryptoProvider = CryptoKitProvider.shared
    ) throws {
        precondition(groupID.count == 32, "groupID must be 32 bytes")
        self.groupID = groupID
        self.epoch = epoch
        self.ourFingerprint = joiner.fingerprint
        self.provider = provider
        for member in members {
            self.members[member.fingerprint] = member
        }
        self.members[joiner.fingerprint] = GroupMember(fingerprint: joiner.fingerprint, displayName: "You")
        try rotateOurSenderKey()
    }

    /// Sender-key distributions for the current member set, for our
    /// current-epoch key. Call once after `init` (founder or joiner) and
    /// after every rotation that returns distributions; deliver each one
    /// encrypted in the recipient's 1:1 session.
    public func initialDistributions() throws -> [OutgoingDistribution] {
        try distributionsForAllMembers()
    }

    // MARK: - Membership

    /// Adds a member. Bumps the epoch and rotates our sender key; the
    /// caller distributes the returned payloads (encrypted 1:1) to every
    /// member, including the new one. The new member cannot read history:
    /// she only ever receives current-epoch sender keys.
    @discardableResult
    public func addMember(_ member: GroupMember) throws -> [OutgoingDistribution] {
        guard members[member.fingerprint] == nil else { return [] }
        members[member.fingerprint] = member
        return try bumpEpoch()
    }

    /// Removes a member. Bumps the epoch and rotates our sender key; the
    /// removed member gets no distribution, so she cannot read subsequent
    /// messages. (She retains ciphertext from while she was a member —
    /// unavoidable, see the file header.)
    @discardableResult
    public func removeMember(fingerprint: Data) throws -> [OutgoingDistribution] {
        guard members.removeValue(forKey: fingerprint) != nil else { return [] }
        // Drop her sender state immediately: a removed member's late
        // messages must not decrypt, even within the grace window.
        peerSenderStates = peerSenderStates.filter { $0.key.senderID != fingerprint }
        return try bumpEpoch()
    }

    private func bumpEpoch() throws -> [OutgoingDistribution] {
        epoch &+= 1
        try rotateOurSenderKey()
        return try distributionsForAllMembers()
    }

    // MARK: - Sender-key rotation

    /// Rotates our sender key when the message-count or time policy says
    /// so. Returns distributions if a rotation happened, else `[]`.
    @discardableResult
    public func rotateOurSenderKeyIfNeeded() throws -> [OutgoingDistribution] {
        let timeExceeded = ourSenderKeyCreatedAt
            .map { Date().timeIntervalSince($0) >= Self.senderKeyTimeRotationInterval } ?? true
        guard messagesSentOnCurrentKey >= Self.senderKeyMessageRotationInterval || timeExceeded else {
            return []
        }
        // Policy rotation does NOT bump the epoch: members keep their
        // states; only our sending key changes. (Epoch bumps are reserved
        // for membership changes, which must invalidate *everyone's* keys.)
        try rotateOurSenderKey()
        return try distributionsForAllMembers()
    }

    private func rotateOurSenderKey() throws {
        ourSenderKey = try SenderKeyState.generate(senderID: ourFingerprint, epoch: epoch, provider: provider)
        ourSenderKeyCreatedAt = Date()
        messagesSentOnCurrentKey = 0
    }

    private func distributionsForAllMembers() throws -> [OutgoingDistribution] {
        guard let ourKey = ourSenderKey else { return [] }
        let distribution = SenderKeyDistribution(
            groupID: groupID,
            epoch: epoch,
            senderID: ourFingerprint,
            chainKey: ourKey.chainKey.toData(),
            signingPublicKey: ourKey.signingPublicKey
        )
        return members.keys
            .filter { $0 != ourFingerprint }
            .map { OutgoingDistribution(recipientFingerprint: $0, distribution: distribution) }
    }

    /// Forced sender-key rotation without a membership change
    /// (user-triggered re-key or compromise response). Does NOT bump the
    /// epoch: members retain old states for history and gain the new key
    /// for future messages. The caller distributes the result encrypted in
    /// each member's 1:1 session.
    @discardableResult
    public func forcedRotate() throws -> [OutgoingDistribution] {
        try rotateOurSenderKey()
        return try distributionsForAllMembers()
    }

    // MARK: - Sending

    /// An encrypted group message plus any sender-key rotation it triggered.
    public struct EncryptedGroupMessage {
        public let message: GroupMessage
        /// Non-empty when our sender key rotated for this message. The
        /// transport MUST deliver these distributions — each encrypted in
        /// the recipient's 1:1 session — *before* `message`, or recipients
        /// cannot decrypt it.
        public let keyRotation: [OutgoingDistribution]
    }

    /// Encrypts one group message under our current sender key. Applies the
    /// periodic rotation policy first, so long-lived groups automatically
    /// bound a compromised sender key's blast radius.
    public func encrypt(plaintext: Data, associatedData: Data = Data()) throws -> EncryptedGroupMessage {
        let keyRotation = try rotateOurSenderKeyIfNeeded()
        guard var senderKey = ourSenderKey else {
            throw AegisCryptoError.noSendingChain
        }
        let (index, key) = senderKey.nextMessageKey()
        ourSenderKey = senderKey
        messagesSentOnCurrentKey &+= 1

        var aad = GroupMessage.headerBytes(groupID: groupID, epoch: epoch, senderID: ourFingerprint, index: index)
        aad.append(associatedData)
        let padded = Padding.pad(plaintext)
        let sealed = try AEAD.seal(plaintext: padded, key: key, associatedData: aad, provider: provider)

        // Wire format carries AES-GCM in combined mode: ciphertext || 16-byte
        // tag. The signature covers exactly these wire bytes.
        let wireCiphertext = sealed.ciphertext + sealed.tag
        var signingInput = GroupMessage.headerBytes(groupID: groupID, epoch: epoch, senderID: ourFingerprint, index: index)
        signingInput.append(sealed.nonce)
        signingInput.append(wireCiphertext)
        let signature = try senderKey.sign(signingInput, provider: provider)

        let message = GroupMessage(
            groupID: groupID,
            epoch: epoch,
            senderID: ourFingerprint,
            index: index,
            nonce: sealed.nonce,
            ciphertext: wireCiphertext,
            signature: signature
        )
        return EncryptedGroupMessage(message: message, keyRotation: keyRotation)
    }

    // MARK: - Receiving

    /// Ingests a decrypted `SenderKeyDistribution` for a peer. Validates
    /// that the distribution's group, epoch, and sender binding are sane
    /// before storing. The caller is responsible for having decrypted it
    /// via the sender's 1:1 session and for checking that `senderID`
    /// matches the 1:1 peer's fingerprint (sender binding).
    public func ingestDistribution(_ distribution: SenderKeyDistribution, fromSender senderFingerprint: Data) throws {
        guard distribution.groupID == groupID else {
            throw AegisCryptoError.invalidWireFormat
        }
        guard distribution.senderID == senderFingerprint else {
            // The distribution claims a different sender than the 1:1 peer
            // who sent it: someone is mixing keys across identities.
            throw AegisCryptoError.invalidSignature
        }
        guard members[senderFingerprint] != nil else {
            throw AegisCryptoError.unknownSenderKey
        }
        // Never install our own sender key as a peer's.
        guard senderFingerprint != ourFingerprint else {
            throw AegisCryptoError.invalidWireFormat
        }
        let id = PeerKeyID(senderID: senderFingerprint, epoch: distribution.epoch)
        peerSenderStates[id] = PeerSenderState(
            senderKey: SenderKeyState.peerState(from: distribution),
            lastUsed: Date()
        )
        evictExcessPeerStates()
    }

    /// Decrypts a group message.
    public func decrypt(_ message: GroupMessage, associatedData: Data = Data()) throws -> Data {
        guard message.groupID == groupID else {
            throw AegisCryptoError.invalidWireFormat
        }
        // Accept the current epoch and the immediately previous one, so
        // in-flight messages sent just before a rotation still decrypt.
        // Anything older is gone.
        guard message.epoch == epoch || (epoch > 0 && message.epoch == epoch - 1) else {
            throw AegisCryptoError.staleEpoch
        }
        guard members[message.senderID] != nil else {
            throw AegisCryptoError.unknownSenderKey
        }
        let id = PeerKeyID(senderID: message.senderID, epoch: message.epoch)
        guard var state = peerSenderStates[id] else {
            throw AegisCryptoError.unknownSenderKey
        }

        // 1. Authenticate the sender BEFORE touching ratchet state.
        guard provider.ed25519Verify(
            publicKey: state.senderKey.signingPublicKey,
            signature: message.signature,
            message: message.signedBytes()
        ) else {
            throw AegisCryptoError.invalidSignature
        }

        // 2. Resolve the message key: skipped store, in-order, or advance.
        let messageKey: SymmetricKey
        if let skipped = state.skipped.removeValue(forKey: message.index) {
            messageKey = skipped
        } else {
            guard message.index >= state.senderKey.messageIndex else {
                throw AegisCryptoError.messageTooOld
            }
            let gap = message.index - state.senderKey.messageIndex
            guard gap <= Self.maxGroupSkip else {
                throw AegisCryptoError.messageTooFarInFuture
            }
            // Stash keys for the gap, then take this message's key. The
            // chain advances even if AEAD fails below — same rationale as
            // the 1:1 ratchet (failed forgeries are un-replayable).
            let skippedKeys = state.senderKey.keysUpTo(index: message.index)
            for (skippedIndex, skippedKey) in skippedKeys {
                state.skipped[skippedIndex] = skippedKey
            }
            while state.skipped.count > Int(Self.maxGroupSkip) {
                guard let oldest = state.skipped.keys.min() else { break }
                state.skipped.removeValue(forKey: oldest)
            }
            let (usedIndex, key) = state.senderKey.nextMessageKey()
            precondition(usedIndex == message.index, "sender-key chain drifted")
            messageKey = key
        }
        state.lastUsed = Date()
        peerSenderStates[id] = state

        // 3. Decrypt + unpad.
        var aad = message.headerBytes()
        aad.append(associatedData)
        // Wire format carries AES-GCM in combined mode: ciphertext || 16-byte tag.
        guard message.ciphertext.count >= 16 else { throw AegisCryptoError.invalidWireFormat }
        let sealed = SealedMessage(
            nonce: message.nonce,
            ciphertext: message.ciphertext.dropLast(16),
            tag: message.ciphertext.suffix(16)
        )
        let padded = try AEAD.open(sealed, key: messageKey, associatedData: aad, provider: provider)
        return try Padding.unpad(padded)
    }

    private func evictExcessPeerStates() {
        while peerSenderStates.count > Self.maxPeerSenderStates {
            guard let oldest = peerSenderStates.min(by: { $0.value.lastUsed < $1.value.lastUsed })?.key else {
                break
            }
            peerSenderStates.removeValue(forKey: oldest)
        }
    }
}
