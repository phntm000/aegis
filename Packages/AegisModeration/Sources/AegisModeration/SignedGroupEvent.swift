import Foundation

// MARK: - Audit cryptography (injected)
//
// The package is crypto-agnostic so the logic stays portable and testable:
// the app wires SHA-256 + Ed25519 (identity key); tests wire fakes. The
// hash MUST be a 32-byte collision-resistant digest and sign/verify an
// Ed25519-class signature scheme in production.

/// Crypto operations for the audit log, supplied by the host app.
public struct AuditCrypto: Sendable {
    /// 32-byte digest of the input.
    public var hash: @Sendable (Data) -> Data
    /// Signs the 32-byte digest with the actor's long-term identity key.
    /// Async because private key material lives behind the crypto actor —
    /// only the signature crosses the boundary.
    public var sign: @Sendable (Data) async throws -> Data
    /// Verifies `signature` over `digest` with the actor's 32-byte public key.
    public var verify: @Sendable (_ digest: Data, _ signature: Data, _ publicKey: Data) -> Bool

    public init(
        hash: @escaping @Sendable (Data) -> Data,
        sign: @escaping @Sendable (Data) async throws -> Data,
        verify: @escaping @Sendable (Data, Data, Data) -> Bool
    ) {
        self.hash = hash
        self.sign = sign
        self.verify = verify
    }
}

// MARK: - Admin events

/// Every administrative action in a group/channel, as a signed event.
/// The log contains administrative events only — never message content.
public enum GroupAdminEventKind: String, Sendable, Codable, CaseIterable {
    case memberAdded
    case memberRemoved
    case roleChanged
    case permissionChanged
    case slowModeChanged
    case inviteIssued
    case inviteRevoked
    case groupInfoEdited
    case announcementModeChanged
    case joinRequestApproved
    case joinRequestDeclined
    case ownershipTransferred
    /// A peer's action violated the signed policy (e.g. slow-mode bypass,
    /// unauthorized post). Recorded by the observing honest client.
    case invalidEventObserved
    /// Exporting the audit log requires an admin role and is itself logged.
    case auditExported

    public var displayName: String {
        switch self {
        case .memberAdded: return "Member added"
        case .memberRemoved: return "Member removed"
        case .roleChanged: return "Role changed"
        case .permissionChanged: return "Permission changed"
        case .slowModeChanged: return "Slow mode changed"
        case .inviteIssued: return "Invite issued"
        case .inviteRevoked: return "Invite revoked"
        case .groupInfoEdited: return "Group info edited"
        case .announcementModeChanged: return "Announcement mode changed"
        case .joinRequestApproved: return "Join request approved"
        case .joinRequestDeclined: return "Join request declined"
        case .ownershipTransferred: return "Ownership transferred"
        case .invalidEventObserved: return "Policy violation observed"
        case .auditExported: return "Audit log exported"
        }
    }

    public var systemImage: String {
        switch self {
        case .memberAdded: return "person.badge.plus"
        case .memberRemoved: return "person.badge.minus"
        case .roleChanged: return "person.2.badge.gearshape"
        case .permissionChanged: return "key"
        case .slowModeChanged: return "timer"
        case .inviteIssued: return "qrcode"
        case .inviteRevoked: return "qrcode.viewfinder"
        case .groupInfoEdited: return "pencil"
        case .announcementModeChanged: return "megaphone"
        case .joinRequestApproved: return "checkmark.seal"
        case .joinRequestDeclined: return "xmark.seal"
        case .ownershipTransferred: return "crown"
        case .invalidEventObserved: return "exclamationmark.shield"
        case .auditExported: return "square.and.arrow.up"
        }
    }
}

/// One administrative event. `detail` is a short human-readable summary
/// ("Slow mode set to 5 minutes"); structured payloads stay out — the
/// signed group control messages already carry the authoritative values.
public struct GroupAdminEvent: Sendable, Codable, Equatable {
    public var kind: GroupAdminEventKind
    /// 32-byte crypto group ID.
    public var groupID: Data
    /// 32-byte identity fingerprint of the actor.
    public var actorFingerprint: Data
    public var actorDisplayName: String?
    /// 32-byte identity fingerprint of the affected member, if any.
    public var targetFingerprint: Data?
    public var targetDisplayName: String?
    public var detail: String?
    public var occurredAt: Date

    public init(
        kind: GroupAdminEventKind,
        groupID: Data,
        actorFingerprint: Data,
        actorDisplayName: String? = nil,
        targetFingerprint: Data? = nil,
        targetDisplayName: String? = nil,
        detail: String? = nil,
        occurredAt: Date = Date()
    ) {
        self.kind = kind
        self.groupID = groupID
        self.actorFingerprint = actorFingerprint
        self.actorDisplayName = actorDisplayName
        self.targetFingerprint = targetFingerprint
        self.targetDisplayName = targetDisplayName
        self.detail = detail
        self.occurredAt = occurredAt
    }
}

// MARK: - Signed, hash-chained envelope

/// A `GroupAdminEvent` sealed into the hash chain: sequence number,
/// previous-entry hash, and the actor's identity-key signature over all of
/// it. Anyone holding the roster (fingerprint → Ed25519 public key) can
/// verify the chain; gaps and tampering are detectable.
public struct SignedGroupEvent: Sendable, Codable, Equatable {
    /// Domain separation for the signed digest.
    public static let domain = "AegisGroupAudit_v1"

    public var event: GroupAdminEvent
    public var seq: UInt64
    /// Chain hash of the previous entry; empty for the genesis entry.
    public var prevHash: Data
    /// Actor's identity-key signature over `signingDigest`.
    public var signature: Data

    public init(event: GroupAdminEvent, seq: UInt64, prevHash: Data, signature: Data) {
        self.event = event
        self.seq = seq
        self.prevHash = prevHash
        self.signature = signature
    }

    /// The 32-byte digest the signature covers: domain || prevHash ||
    /// seq (big-endian u64) || canonical event JSON, hashed.
    public func signingDigest(using crypto: AuditCrypto) throws -> Data {
        var input = Data(Self.domain.utf8)
        input.append(prevHash)
        var seqBE = seq.bigEndian
        withUnsafeBytes(of: &seqBE) { input.append(contentsOf: $0) }
        input.append(try canonicalEventJSON())
        return crypto.hash(input)
    }

    private func canonicalEventJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        return try encoder.encode(event)
    }
}

// MARK: - The hash-chained log

public enum AuditVerification: Sendable, Equatable {
    /// Every entry's signature verified and the chain is unbroken.
    case ok(eventCount: Int)
    case empty
    /// `prevHash` at `seq` does not match the hash of entry `seq - 1`:
    /// entries were removed, reordered, or altered.
    case brokenChain(at: UInt64)
    /// The signature at `seq` does not verify against the actor's key.
    case badSignature(at: UInt64)
    /// No Ed25519 public key known for the actor at `seq`.
    case unknownActorKey(at: UInt64)
}

/// Per-group, append-only, hash-chained, signed audit log. Stored on each
/// member's device; replicates to members sealed inside group control
/// messages (never to the relay in plaintext).
public struct GroupAuditLog: Sendable, Codable, Equatable {
    public private(set) var events: [SignedGroupEvent]
    /// Chain hash of the latest entry; empty when the log is empty.
    public private(set) var headHash: Data

    public init(events: [SignedGroupEvent] = [], headHash: Data = Data()) {
        self.events = events
        self.headHash = headHash
    }

    public var isEmpty: Bool { events.isEmpty }
    public var count: Int { events.count }

    /// Appends an event signed by the local actor. Throws when signing fails.
    public mutating func append(_ event: GroupAdminEvent, crypto: AuditCrypto) async throws {
        let seq = UInt64(events.count)
        var entry = SignedGroupEvent(event: event, seq: seq, prevHash: headHash, signature: Data())
        let digest = try entry.signingDigest(using: crypto)
        entry.signature = try await crypto.sign(digest)
        headHash = crypto.hash(Self.chainInput(for: entry, digest: digest))
        events.append(entry)
    }

    /// Appends an entry received from a peer (sealed in a group control
    /// message). The entry is verified before appending: wrong `seq`,
    /// wrong `prevHash`, or a bad signature are rejected. Returns the
    /// verification result; the log is unchanged on failure.
    public mutating func appendReceived(
        _ entry: SignedGroupEvent,
        crypto: AuditCrypto,
        actorKeys: [Data: Data]
    ) -> AuditVerification {
        guard entry.seq == UInt64(events.count) else {
            return .brokenChain(at: entry.seq)
        }
        guard entry.prevHash == headHash else {
            return .brokenChain(at: entry.seq)
        }
        guard let publicKey = actorKeys[entry.event.actorFingerprint] else {
            return .unknownActorKey(at: entry.seq)
        }
        guard let digest = try? entry.signingDigest(using: crypto),
              crypto.verify(digest, entry.signature, publicKey)
        else {
            return .badSignature(at: entry.seq)
        }
        headHash = crypto.hash(Self.chainInput(for: entry, digest: digest))
        events.append(entry)
        return .ok(eventCount: events.count)
    }

    /// Full verification of the log against the roster's public keys.
    public func verify(with crypto: AuditCrypto, actorKeys: [Data: Data]) -> AuditVerification {
        if events.isEmpty { return .empty }
        var prev = Data()
        for entry in events {
            guard entry.prevHash == prev else { return .brokenChain(at: entry.seq) }
            guard let publicKey = actorKeys[entry.event.actorFingerprint] else {
                return .unknownActorKey(at: entry.seq)
            }
            guard let digest = try? entry.signingDigest(using: crypto),
                  crypto.verify(digest, entry.signature, publicKey)
            else {
                return .badSignature(at: entry.seq)
            }
            prev = crypto.hash(Self.chainInput(for: entry, digest: digest))
        }
        guard prev == headHash else { return .brokenChain(at: UInt64(events.count)) }
        return .ok(eventCount: events.count)
    }

    // MARK: - Private

    /// Chain input: domain || prevHash || seq BE || signature. The signature
    /// is included so the chain commits to *who* attested each entry, not
    /// just its content.
    private static func chainInput(for entry: SignedGroupEvent, digest: Data) -> Data {
        var input = Data(SignedGroupEvent.domain.utf8)
        input.append(entry.prevHash)
        var seqBE = entry.seq.bigEndian
        withUnsafeBytes(of: &seqBE) { input.append(contentsOf: $0) }
        input.append(digest)
        input.append(entry.signature)
        return input
    }
}
