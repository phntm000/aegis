// GroupSnapshot — durable sender-key group session persistence.
//
// A snapshot captures everything needed to resume a GroupSession after an
// app restart: the epoch, the member roster, OUR sender key (chain key +
// Ed25519 signing seed — required to keep sending without a rotation),
// and every peer's sender-key state including stashed out-of-order message
// keys. Without this, every group/channel silently stopped working after a
// relaunch (encrypt/decrypt threw `unknownGroup`, routing fell back to the
// epoch-0 mailbox).
//
// Security notes:
//  - Snapshots contain CURRENT chain keys only — never past message keys
//    (deleted on use) and never other members' signing seeds (we never
//    hold those). A snapshot thief learns the present/future of the
//    group's traffic, never its past.
//  - Snapshots are stored in the SQLCipher database, encrypted under the
//    Keychain-held database key — the same protection as the messages
//    themselves. They are deliberately EXCLUDED from the encrypted backup
//    `StoreSnapshot`: a backup restored to a new device re-joins groups
//    (fresh sender keys, fresh distributions) instead of resurrecting
//    stale group state.
//  - Peer skipped (out-of-order) message keys ARE persisted: dropping them
//    would make legitimately delayed messages undecryptable after a
//    restart.
//
// Versioning: `version` is checked on decode. Older versions decode through
// the migration switch in `GroupSession.init(restoring:)`; newer versions
// throw `unsupportedSnapshotVersion` and the caller treats the group as
// unknown (the user re-joins / the next rotation heals it) — never a crash,
// never silent corruption.

import CryptoKit
import Foundation

/// One group member as persisted.
public struct GroupMemberSnapshot: Codable, Sendable, Equatable {
    public var fingerprint: Data
    public var displayName: String

    public init(fingerprint: Data, displayName: String) {
        self.fingerprint = fingerprint
        self.displayName = displayName
    }
}

/// One peer's sender-key state as persisted. `skippedKeys` maps
/// stringified message index → 32-byte message key (string keys keep the
/// encoding stable across JSON and plist coders).
public struct PeerSenderKeySnapshot: Codable, Sendable, Equatable {
    public var senderID: Data
    public var epoch: UInt32
    public var chainKey: Data
    public var messageIndex: UInt32
    public var signingPublicKey: Data
    /// Stringified index → raw 32-byte message key.
    public var skippedKeys: [String: Data]
    public var lastUsed: Date

    public init(
        senderID: Data,
        epoch: UInt32,
        chainKey: Data,
        messageIndex: UInt32,
        signingPublicKey: Data,
        skippedKeys: [String: Data],
        lastUsed: Date
    ) {
        self.senderID = senderID
        self.epoch = epoch
        self.chainKey = chainKey
        self.messageIndex = messageIndex
        self.signingPublicKey = signingPublicKey
        self.skippedKeys = skippedKeys
        self.lastUsed = lastUsed
    }
}

/// Versioned, Codable capture of a `GroupSession`'s full state.
public struct GroupSessionSnapshot: Codable, Sendable, Equatable {
    /// Current snapshot format. Bump when fields change; add a migration
    /// arm in `GroupSession.init(restoring:)`.
    public static let currentVersion = 1

    public var version: Int
    public var groupID: Data
    public var epoch: UInt32
    public var ourFingerprint: Data
    public var members: [GroupMemberSnapshot]
    /// Our current sender key: 32-byte chain key.
    public var ourChainKey: Data
    public var ourMessageIndex: UInt32
    public var ourSigningPublicKey: Data
    /// Our Ed25519 signing seed. Present because WE generated this
    /// distribution's signing key; absent only for corrupt snapshots.
    public var ourSigningSeed: Data?
    public var ourKeyCreatedAt: Date?
    public var messagesSentOnCurrentKey: UInt32
    public var peers: [PeerSenderKeySnapshot]

    public init(
        version: Int = currentVersion,
        groupID: Data,
        epoch: UInt32,
        ourFingerprint: Data,
        members: [GroupMemberSnapshot],
        ourChainKey: Data,
        ourMessageIndex: UInt32,
        ourSigningPublicKey: Data,
        ourSigningSeed: Data?,
        ourKeyCreatedAt: Date?,
        messagesSentOnCurrentKey: UInt32,
        peers: [PeerSenderKeySnapshot]
    ) {
        self.version = version
        self.groupID = groupID
        self.epoch = epoch
        self.ourFingerprint = ourFingerprint
        self.members = members
        self.ourChainKey = ourChainKey
        self.ourMessageIndex = ourMessageIndex
        self.ourSigningPublicKey = ourSigningPublicKey
        self.ourSigningSeed = ourSigningSeed
        self.ourKeyCreatedAt = ourKeyCreatedAt
        self.messagesSentOnCurrentKey = messagesSentOnCurrentKey
        self.peers = peers
    }

    /// Validates lengths and version before the session trusts it.
    public func validated() throws {
        guard version <= Self.currentVersion else {
            throw AegisCryptoError.unsupportedVersion(UInt8(min(version, 255)))
        }
        guard groupID.count == 32, ourFingerprint.count == 32,
              ourChainKey.count == 32, ourSigningPublicKey.count == 32
        else { throw AegisCryptoError.invalidKeyData }
        for m in members { guard m.fingerprint.count == 32 else { throw AegisCryptoError.invalidKeyData } }
        for p in peers {
            guard p.senderID.count == 32, p.chainKey.count == 32,
                  p.signingPublicKey.count == 32
            else { throw AegisCryptoError.invalidKeyData }
            for key in p.skippedKeys.values { guard key.count == 32 else { throw AegisCryptoError.invalidKeyData } }
        }
    }

    public func serialized() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func parse(_ data: Data) throws -> GroupSessionSnapshot {
        let snapshot = try JSONDecoder().decode(GroupSessionSnapshot.self, from: data)
        try snapshot.validated()
        return snapshot
    }
}
