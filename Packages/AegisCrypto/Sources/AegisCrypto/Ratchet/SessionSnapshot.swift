// Double Ratchet session snapshots — durable session persistence.
//
// A snapshot captures everything needed to resume a 1:1 session after an
// app restart: root/chain keys, the sending ratchet keypair, counters, and
// stashed out-of-order message keys, plus the peer identity and the X3DH
// ephemeral public key (needed to rebuild the routing mailbox).
//
// Security notes (read before "optimizing" this away):
//  - Snapshots contain CURRENT chain/root keys only. Past message keys are
//    deleted as messages are decrypted (forward secrecy is preserved for
//    everything already received). A snapshot thief learns the present and
//    future of the session, never its past.
//  - Snapshots are stored in the SQLCipher database, encrypted under the
//    Keychain-held database key — the same protection as the messages
//    themselves. They never touch disk unencrypted and never leave the
//    device except inside the passphrase-encrypted backup (which
//    deliberately EXCLUDES sessions: a backup restored to a new device
//    re-establishes sessions via X3DH instead of resurrecting stale state).
//  - Skipped (out-of-order) message keys ARE persisted: dropping them would
//    make legitimately delayed messages undecryptable after a restart.
//
// Versioning: `version` is checked on decode. Older versions decode through
// the migration switch in `init(snapshot:)`; newer versions throw
// `unsupportedSnapshotVersion` and the caller falls back to X3DH
// re-establishment (never a crash, never silent corruption).

import CryptoKit
import Foundation

/// One stashed out-of-order message key.
public struct SkippedKeySnapshot: Codable, Sendable, Equatable {
    public var ratchetPublicKey: Data
    public var messageNumber: UInt32
    public var messageKey: Data
    public var insertionOrder: UInt64

    public init(ratchetPublicKey: Data, messageNumber: UInt32, messageKey: Data, insertionOrder: UInt64) {
        self.ratchetPublicKey = ratchetPublicKey
        self.messageNumber = messageNumber
        self.messageKey = messageKey
        self.insertionOrder = insertionOrder
    }
}

/// Versioned, Codable capture of an `AegisDoubleRatchet`'s full state.
public struct RatchetSessionSnapshot: Codable, Sendable, Equatable {
    /// Current snapshot format. Bump when fields change; add a migration
    /// arm in `AegisDoubleRatchet.init(snapshot:)`.
    public static let currentVersion = 1

    public var version: Int
    /// `IdentityPublic.serialized()` of the peer.
    public var peerIdentity: Data
    /// 32-byte X3DH ephemeral public key (routing-mailbox derivation).
    public var ephemeralPublicKey: Data
    /// 32-byte root key.
    public var rootKey: Data
    /// 32-byte sending chain key, nil when no sending chain exists yet
    /// (fresh responder who has not replied).
    public var sendingChainKey: Data?
    /// 32-byte receiving chain key, nil until the first inbound message.
    public var receivingChainKey: Data?
    /// 32-byte sending ratchet private scalar.
    public var sendingRatchetPrivateKey: Data
    /// 32-byte sending ratchet public key (cross-checked by re-derivation).
    public var sendingRatchetPublicKey: Data
    /// 32-byte current receiving ratchet public key, nil until first inbound.
    public var receivingRatchetPublicKey: Data?
    public var sendMessageNumber: UInt32
    public var receiveMessageNumber: UInt32
    public var previousSendChainLength: UInt32
    public var skippedKeys: [SkippedKeySnapshot]

    public init(
        version: Int = currentVersion,
        peerIdentity: Data,
        ephemeralPublicKey: Data,
        rootKey: Data,
        sendingChainKey: Data?,
        receivingChainKey: Data?,
        sendingRatchetPrivateKey: Data,
        sendingRatchetPublicKey: Data,
        receivingRatchetPublicKey: Data?,
        sendMessageNumber: UInt32,
        receiveMessageNumber: UInt32,
        previousSendChainLength: UInt32,
        skippedKeys: [SkippedKeySnapshot]
    ) {
        self.version = version
        self.peerIdentity = peerIdentity
        self.ephemeralPublicKey = ephemeralPublicKey
        self.rootKey = rootKey
        self.sendingChainKey = sendingChainKey
        self.receivingChainKey = receivingChainKey
        self.sendingRatchetPrivateKey = sendingRatchetPrivateKey
        self.sendingRatchetPublicKey = sendingRatchetPublicKey
        self.receivingRatchetPublicKey = receivingRatchetPublicKey
        self.sendMessageNumber = sendMessageNumber
        self.receiveMessageNumber = receiveMessageNumber
        self.previousSendChainLength = previousSendChainLength
        self.skippedKeys = skippedKeys
    }

    /// Canonical wire encoding for storage (JSON; Data fields are base64).
    public func serialized() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public init(serialized data: Data) throws {
        let decoded = try JSONDecoder().decode(RatchetSessionSnapshot.self, from: data)
        guard decoded.version <= Self.currentVersion else {
            throw AegisCryptoError.unsupportedSnapshotVersion(decoded.version)
        }
        self = decoded
    }
}

// MARK: - AegisDoubleRatchet snapshot support
//
// NOTE: this extension lives in DoubleRatchet.swift (same file as the
// class) because it touches the ratchet's private state. The versioned
// Codable structs live in SessionSnapshot.swift.
