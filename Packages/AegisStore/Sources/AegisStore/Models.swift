// AegisStore — Data Models
//
// Clean, Codable, Sendable value types describing everything Aegis persists
// locally. These models are *transport-agnostic*: they describe application
// state, not wire format. All fields that hold user content are stored as
// plaintext *in memory*; at-rest encryption is the persistence layer's job
// (SQLCipher — see Docs/SQLCIPHER.md). Never serialize these models to disk
// or network outside the encrypted store or a sealed envelope.
//
// Conventions:
// - Identifiers are phantom-typed `ID<Kind>` wrappers to prevent mixing up
//   e.g. a MessageID with a ConversationID at compile time.
// - Timestamps are `Date` (UTC internally; formatting is a UI concern).
// - Every model carries `updatedAt` for sync/merge bookkeeping.

import Foundation

// MARK: - Phantom-typed identifiers

/// A type-safe identifier. `ID<ConversationTag>` and `ID<MessageTag>` are
/// distinct types that both serialize as plain strings.
public struct ID<Kind>: Hashable, Codable, Sendable, CustomStringConvertible,
    ExpressibleByStringLiteral
{
    public let rawValue: String

    public init(_ rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { self.rawValue = value }

    /// Generates a new random identifier (UUID-based).
    public static func generate() -> ID<Kind> { ID(UUID().uuidString) }

    public var description: String { rawValue }
}

public enum ConversationTag {}
public enum MessageTag {}
public enum UserTag {}
public enum AttachmentTag {}
public enum CallTag {}
public enum DeviceTag {}

public typealias ConversationID = ID<ConversationTag>
public typealias MessageID = ID<MessageTag>
public typealias UserID = ID<UserTag>
public typealias AttachmentID = ID<AttachmentTag>
public typealias CallID = ID<CallTag>
public typealias DeviceID = ID<DeviceTag>

// MARK: - CodingKeyRepresentable

/// String coding key so phantom-typed IDs can serve as dictionary keys in
/// JSON payloads (e.g. `CallRecord.recordingConsent: [UserID: Bool]`).
public struct AnyStringCodingKey: CodingKey, Sendable {
    public var stringValue: String
    public var intValue: Int?
    public init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    public init?(intValue: Int) { nil }
}

extension ID: CodingKeyRepresentable {
    public typealias CodingKey = AnyStringCodingKey
    // Note: `Swift.CodingKey` is qualified because the typealias above
    // would otherwise shadow the stdlib protocol in this constraint.
    public init?<T: Swift.CodingKey>(codingKey: T) {
        self.rawValue = codingKey.stringValue
    }
    public var codingKey: any Swift.CodingKey {
        AnyStringCodingKey(stringValue: rawValue)
    }
}

// MARK: - Shared enums

/// The kind of conversation. Determines UI treatment and network policy.
public enum ConversationKind: String, Codable, Sendable, CaseIterable {
    /// 1:1 encrypted chat.
    case direct
    /// E2EE group chat.
    case group
    /// Broadcast channel (admins post, subscribers read).
    case channel
    /// Announcement channel with opt-in discussion threads.
    case announcement
    /// Local-only vault chat: never touches any relay or network.
    case vault
}

/// Network policy for a conversation. `lanOnly` and `vault` never use a relay.
public enum NetworkPolicy: String, Codable, Sendable, CaseIterable {
    /// Sync via relay and/or LAN, whichever is available.
    case `default`
    /// LAN / direct device-to-device only. Never touches a relay.
    case lanOnly
    /// No network at all. Manual export/import only (vault chats).
    case localOnly
}

/// Trust state of a contact's identity keys.
public enum VerificationState: String, Codable, Sendable, CaseIterable {
    /// Never verified.
    case unverified
    /// Safety number verified by the user.
    case verified
    /// Keys changed since verification — needs re-verification ceremony.
    case changedNeedsReverification
}

/// Group role. Ordered by privilege; enforced client-side from the signed
/// group log (see FEATURES.md A36).
public enum MemberRole: String, Codable, Sendable, CaseIterable, Comparable {
    case guest
    case member
    case moderator
    case admin
    case owner

    private var rank: Int {
        switch self {
        case .guest: return 0
        case .member: return 1
        case .moderator: return 2
        case .admin: return 3
        case .owner: return 4
        }
    }

    public static func < (lhs: MemberRole, rhs: MemberRole) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// Delivery lifecycle of an outgoing message.
public enum DeliveryState: String, Codable, Sendable, CaseIterable {
    /// Durably queued in the outbox; not yet handed to transport.
    case queued
    /// Handed to transport (relay/LAN), no ack yet.
    case sent
    /// Relay/device acknowledged receipt.
    case delivered
    /// Recipient's client marked it read (only if receipts enabled).
    case read
    /// Permanently failed (e.g. recipient revoked); surfaced to the user.
    case failed
}

/// Payload kind of a message.
public enum MessageKind: String, Codable, Sendable, CaseIterable {
    case text
    case attachment
    case voiceNote
    case poll
    case callEvent
    case system
}

/// Direction relative to the local user.
public enum MessageDirection: String, Codable, Sendable {
    case incoming
    case outgoing
}

/// Attachment media kind.
public enum AttachmentKind: String, Codable, Sendable, CaseIterable {
    case image
    case video
    case audio
    case voiceNote
    case file
}

/// Chunked transfer state machine.
public enum TransferState: String, Codable, Sendable, CaseIterable {
    case pending
    case uploading
    case paused
    case uploaded
    case downloading
    case complete
    case failed
}

/// Call media kind.
public enum CallKind: String, Codable, Sendable {
    case audio
    case video
}

/// Call direction relative to the local user.
public enum CallDirection: String, Codable, Sendable {
    case incoming
    case outgoing
}

// MARK: - Conversation

/// A 1:1 chat, group, channel, announcement channel, or vault chat.
public struct Conversation: Codable, Sendable, Identifiable, Equatable {
    public var id: ConversationID
    public var kind: ConversationKind
    public var networkPolicy: NetworkPolicy
    /// Local display title. For DMs this mirrors the contact's display name.
    public var title: String?
    /// Symmetric group key epoch; bumped on membership changes / re-key.
    /// For DMs this tracks the ratchet epoch instead.
    public var keyEpoch: Int
    /// Disappearing-message timer in seconds; nil = off.
    public var disappearingTimerSeconds: Int?
    public var isArchived: Bool
    public var isMuted: Bool
    public var isPinned: Bool
    /// Per-chat privacy toggles.
    public var readReceiptsEnabled: Bool
    public var typingIndicatorsEnabled: Bool
    public var linkPreviewsEnabled: Bool
    /// Read-state bookkeeping.
    public var lastReadMessageID: MessageID?
    public var unreadCount: Int
    /// ID of the newest message (for list previews).
    public var lastMessageID: MessageID?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: ConversationID = .generate(),
        kind: ConversationKind,
        networkPolicy: NetworkPolicy? = nil,
        title: String? = nil,
        keyEpoch: Int = 0,
        disappearingTimerSeconds: Int? = nil,
        isArchived: Bool = false,
        isMuted: Bool = false,
        isPinned: Bool = false,
        readReceiptsEnabled: Bool? = nil,
        typingIndicatorsEnabled: Bool? = nil,
        linkPreviewsEnabled: Bool = true,
        lastReadMessageID: MessageID? = nil,
        unreadCount: Int = 0,
        lastMessageID: MessageID? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.kind = kind
        // Vault chats are local-only by construction; LAN default otherwise.
        self.networkPolicy = networkPolicy
            ?? (kind == .vault ? .localOnly : .default)
        self.title = title
        self.keyEpoch = keyEpoch
        self.disappearingTimerSeconds = disappearingTimerSeconds
        self.isArchived = isArchived
        self.isMuted = isMuted
        self.isPinned = isPinned
        // Receipts/typing default on for 1:1, off for groups/channels.
        self.readReceiptsEnabled = readReceiptsEnabled ?? (kind == .direct)
        self.typingIndicatorsEnabled = typingIndicatorsEnabled ?? (kind == .direct)
        self.linkPreviewsEnabled = linkPreviewsEnabled
        self.lastReadMessageID = lastReadMessageID
        self.unreadCount = unreadCount
        self.lastMessageID = lastMessageID
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - Message

/// A single chat message. Content fields are plaintext in memory; the store
/// encrypts them at rest. Tombstones preserve position while erasing content.
public struct Message: Codable, Sendable, Identifiable, Equatable {
    public var id: MessageID
    public var conversationID: ConversationID
    /// Nil when sealed sender hides the sender from the local view's
    /// metadata path (content still attributes via sealed cert at decrypt).
    public var senderID: UserID?
    public var isSealedSender: Bool
    public var direction: MessageDirection
    public var kind: MessageKind
    public var text: String?
    public var replyToMessageID: MessageID?
    public var threadRootID: MessageID?
    /// Edit bookkeeping. `editVersion` 0 = original.
    public var editVersion: Int
    public var editedAt: Date?
    /// Tombstone: content wiped, position preserved.
    public var isTombstone: Bool
    public var tombstonedAt: Date?
    /// Disappearing-message deadline; nil = keep.
    public var disappearAt: Date?
    /// Scheduled send fire time; nil = send immediately / already sent.
    public var scheduledFor: Date?
    public var deliveryState: DeliveryState
    public var sentAt: Date?
    public var deliveredAt: Date?
    public var readAt: Date?
    /// Forward-secrecy re-key epoch this message was sealed under.
    public var secrecyEpoch: Int
    public var reactions: [Reaction]
    public var poll: Poll?
    /// Attachment IDs in display order (populated for kind == .attachment).
    public var attachmentIDs: [AttachmentID]
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: MessageID = .generate(),
        conversationID: ConversationID,
        senderID: UserID? = nil,
        isSealedSender: Bool = true,
        direction: MessageDirection,
        kind: MessageKind = .text,
        text: String? = nil,
        replyToMessageID: MessageID? = nil,
        threadRootID: MessageID? = nil,
        editVersion: Int = 0,
        editedAt: Date? = nil,
        isTombstone: Bool = false,
        tombstonedAt: Date? = nil,
        disappearAt: Date? = nil,
        scheduledFor: Date? = nil,
        deliveryState: DeliveryState = .queued,
        sentAt: Date? = nil,
        deliveredAt: Date? = nil,
        readAt: Date? = nil,
        secrecyEpoch: Int = 0,
        reactions: [Reaction] = [],
        poll: Poll? = nil,
        attachmentIDs: [AttachmentID] = [],
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.conversationID = conversationID
        self.senderID = senderID
        self.isSealedSender = isSealedSender
        self.direction = direction
        self.kind = kind
        self.text = text
        self.replyToMessageID = replyToMessageID
        self.threadRootID = threadRootID
        self.editVersion = editVersion
        self.editedAt = editedAt
        self.isTombstone = isTombstone
        self.tombstonedAt = tombstonedAt
        self.disappearAt = disappearAt
        self.scheduledFor = scheduledFor
        self.deliveryState = deliveryState
        self.sentAt = sentAt
        self.deliveredAt = deliveredAt
        self.readAt = readAt
        self.secrecyEpoch = secrecyEpoch
        self.reactions = reactions
        self.poll = poll
        self.attachmentIDs = attachmentIDs
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// A single emoji reaction on a message.
public struct Reaction: Codable, Sendable, Equatable, Hashable {
    public var emoji: String
    public var userID: UserID
    public var reactedAt: Date

    public init(emoji: String, userID: UserID, reactedAt: Date = Date()) {
        self.emoji = emoji
        self.userID = userID
        self.reactedAt = reactedAt
    }
}

/// A poll attached to a message. Ballots are separate sealed events;
/// this struct holds the question, options, and locally-computed tally.
public struct Poll: Codable, Sendable, Equatable {
    public var question: String
    public var options: [PollOption]
    public var allowsMultipleChoice: Bool
    public var isAnonymous: Bool
    public var closesAt: Date?
    /// Locally computed tally: option index -> vote count.
    public var tally: [Int: Int]
    /// Voter set (user IDs) — visible even for anonymous polls so
    /// ballot-stuffing is detectable; voter->choice mapping stays hidden.
    public var voters: Set<UserID>

    public init(
        question: String,
        options: [PollOption],
        allowsMultipleChoice: Bool = false,
        isAnonymous: Bool = false,
        closesAt: Date? = nil,
        tally: [Int: Int] = [:],
        voters: Set<UserID> = []
    ) {
        self.question = question
        self.options = options
        self.allowsMultipleChoice = allowsMultipleChoice
        self.isAnonymous = isAnonymous
        self.closesAt = closesAt
        self.tally = tally
        self.voters = voters
    }
}

public struct PollOption: Codable, Sendable, Equatable, Hashable {
    public var text: String
    public init(_ text: String) { self.text = text }
}

// MARK: - Contact

/// A known identity: a person (or service) the user communicates with.
/// Identity here is a *public key*, never a phone number or username.
public struct Contact: Codable, Sendable, Identifiable, Equatable {
    public var id: UserID
    public var displayName: String
    /// Fingerprint of the contact's identity public key (safety number input).
    public var identityKeyFingerprint: String
    public var verificationState: VerificationState
    public var verifiedAt: Date?
    public var isBlocked: Bool
    public var isFavorite: Bool
    /// Free-form local notes. Never synced.
    public var notes: String?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: UserID,
        displayName: String,
        identityKeyFingerprint: String,
        verificationState: VerificationState = .unverified,
        verifiedAt: Date? = nil,
        isBlocked: Bool = false,
        isFavorite: Bool = false,
        notes: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.displayName = displayName
        self.identityKeyFingerprint = identityKeyFingerprint
        self.verificationState = verificationState
        self.verifiedAt = verifiedAt
        self.isBlocked = isBlocked
        self.isFavorite = isFavorite
        self.notes = notes
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - GroupMembership

/// One row of the signed group membership log, projected into the store.
/// The log itself is the authority; this is the queryable projection.
public struct GroupMembership: Codable, Sendable, Equatable, Hashable {
    public var conversationID: ConversationID
    public var userID: UserID
    public var role: MemberRole
    public var joinedAt: Date
    /// Who added this member (nil for the founder).
    public var addedBy: UserID?
    /// Key epoch at which this member joined (bounds what they can read).
    public var joinedAtEpoch: Int
    public var updatedAt: Date

    public init(
        conversationID: ConversationID,
        userID: UserID,
        role: MemberRole = .member,
        joinedAt: Date = Date(),
        addedBy: UserID? = nil,
        joinedAtEpoch: Int = 0,
        updatedAt: Date = Date()
    ) {
        self.conversationID = conversationID
        self.userID = userID
        self.role = role
        self.joinedAt = joinedAt
        self.addedBy = addedBy
        self.joinedAtEpoch = joinedAtEpoch
        self.updatedAt = updatedAt
    }
}

// MARK: - Attachment

/// Metadata for an encrypted attachment. The bytes live as ciphertext
/// chunks (relay blob storage or local cache); the per-attachment data key
/// is referenced here but the raw key material lives in the Keychain,
/// never in the database.
public struct Attachment: Codable, Sendable, Identifiable, Equatable {
    public var id: AttachmentID
    public var messageID: MessageID
    public var conversationID: ConversationID
    public var kind: AttachmentKind
    public var fileName: String
    public var mimeType: String
    public var byteCount: Int64
    /// Chunking for upload/download with resume.
    public var chunkSize: Int
    public var chunkCount: Int
    public var bytesTransferred: Int64
    public var transferState: TransferState
    /// Opaque locator for the ciphertext chunks at the storage endpoint.
    public var remoteLocator: String?
    /// Local cache path for completed downloads (app sandbox).
    public var localRelativePath: String?
    /// Keychain identifier for the per-attachment data key. The key itself
    /// is NEVER stored in the database.
    public var keychainKeyID: String
    /// SHA-256 of the plaintext, for whole-file integrity verification.
    public var plaintextSHA256: Data?
    /// On-device transcription (voice notes). Inherits message expiry.
    public var transcription: String?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: AttachmentID = .generate(),
        messageID: MessageID,
        conversationID: ConversationID,
        kind: AttachmentKind,
        fileName: String,
        mimeType: String,
        byteCount: Int64,
        chunkSize: Int = 262_144, // 256 KiB
        chunkCount: Int,
        bytesTransferred: Int64 = 0,
        transferState: TransferState = .pending,
        remoteLocator: String? = nil,
        localRelativePath: String? = nil,
        keychainKeyID: String,
        plaintextSHA256: Data? = nil,
        transcription: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.messageID = messageID
        self.conversationID = conversationID
        self.kind = kind
        self.fileName = fileName
        self.mimeType = mimeType
        self.byteCount = byteCount
        self.chunkSize = chunkSize
        self.chunkCount = chunkCount
        self.bytesTransferred = bytesTransferred
        self.transferState = transferState
        self.remoteLocator = remoteLocator
        self.localRelativePath = localRelativePath
        self.keychainKeyID = keychainKeyID
        self.plaintextSHA256 = plaintextSHA256
        self.transcription = transcription
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// Fraction complete, 0...1. Guards against zero-byte files.
    public var progress: Double {
        guard byteCount > 0 else { return transferState == .complete ? 1 : 0 }
        return min(1, Double(bytesTransferred) / Double(byteCount))
    }
}

// MARK: - CallRecord

/// Local record of a voice/video call. Media is never stored unless the
/// user recorded with all-party consent (see `localRecordingPath`).
public struct CallRecord: Codable, Sendable, Identifiable, Equatable {
    public var id: CallID
    public var conversationID: ConversationID
    public var kind: CallKind
    public var direction: CallDirection
    public var participants: [UserID]
    public var wasAnswered: Bool
    public var startedAt: Date
    public var endedAt: Date?
    /// Signed consent acknowledgments per participant (user ID -> consented).
    /// Recording must not start until all participants consented.
    public var recordingConsent: [UserID: Bool]
    /// Sandbox-relative path of the local recording, if any.
    public var localRecordingPath: String?
    public var createdAt: Date

    public init(
        id: CallID = .generate(),
        conversationID: ConversationID,
        kind: CallKind,
        direction: CallDirection,
        participants: [UserID] = [],
        wasAnswered: Bool = false,
        startedAt: Date = Date(),
        endedAt: Date? = nil,
        recordingConsent: [UserID: Bool] = [:],
        localRecordingPath: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.conversationID = conversationID
        self.kind = kind
        self.direction = direction
        self.participants = participants
        self.wasAnswered = wasAnswered
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.recordingConsent = recordingConsent
        self.localRecordingPath = localRecordingPath
        self.createdAt = createdAt
    }

    /// Call duration in seconds, if the call ended.
    public var durationSeconds: Int? {
        guard let endedAt else { return nil }
        return max(0, Int(endedAt.timeIntervalSince(startedAt)))
    }

    /// True only when every participant explicitly consented.
    public var allPartiesConsentedToRecording: Bool {
        !participants.isEmpty
            && participants.allSatisfy { recordingConsent[$0] == true }
    }
}
