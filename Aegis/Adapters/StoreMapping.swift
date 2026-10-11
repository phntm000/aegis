// StoreMapping — bidirectional app ↔ AegisStore model conversion.
//
// The app's models (Aegis/Models, UUID identifiers, UI-convenient shapes)
// and the package's models (phantom-typed IDs, persistence-oriented shapes)
// are intentionally different types. This file is the only place that
// translates between them.
//
// Field policy:
//  - Every durable field has a counterpart mapping below.
//  - App-only UI/ephemeral fields (list previews, senderKeyStatus, …) live
//    in `ConversationSidecar`, one JSON file per conversation under
//    Application Support, `.completeFileProtection`.
//  - The contact's full public key (66-byte serialized IdentityPublic)
//    lives in `ContactKeyDirectory` (one JSON file); the package Contact
//    stores only the fingerprint hex, as designed.
//  - Wrapped attachment file keys live in the Keychain (never in the DB,
//    never in a sidecar) under `keychainKeyID`.

import AegisStore
import Foundation

// MARK: - Identifier bridging

/// The package generates UUID-string IDs, and the adapter always creates
/// package IDs from app UUIDs, so this round-trips. The fallback (fresh
/// UUID) is defensive only and is logged by the caller.
func packageID<K>(_ uuid: UUID) -> ID<K> { ID(uuid.uuidString) }

func appUUID<K>(_ id: ID<K>) -> UUID {
    UUID(uuidString: id.rawValue) ?? UUID()
}

// MARK: - Conversation sidecar

/// App-only conversation state with no package counterpart.
struct ConversationSidecar: Codable, Sendable {
    var subtitle: String?
    var memberIDs: [UUID] = []
    var isAnnouncementOnly: Bool = false
    var myRole: MemberRole?
    var senderKeyStatus: SenderKeyStatus = .active
    var lastMessagePreview: String?
    var lastMessageAt: Date?
    var lastMessageIsFromMe: Bool = false
    /// The true package kind when it is `.announcement` or `.vault`
    /// (the app kind collapses those to channel/group).
    var originalKind: String?
    /// 32-byte crypto group ID for groups/channels.
    var cryptoGroupID: Data?
    /// 32-byte peer fingerprint for DMs.
    var dmPeerFingerprint: Data?
    /// Set while the peer's identity change is unverified: the app banners
    /// and pauses display of new peer messages until resolved.
    var pendingIdentityChange: PendingIdentityChange?
    /// Voice-note UI metadata keyed by attachment UUID string.
    var voiceNoteExtras: [String: VoiceNoteExtra]?

    struct VoiceNoteExtra: Codable, Sendable {
        var duration: TimeInterval
        var levels: [Float]
    }
}

/// Persists sidecars as one JSON file per conversation.
actor ConversationSidecarStore {
    private let directory: URL

    init() throws {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        directory = base.appendingPathComponent("AegisSidecars", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func url(for id: UUID) -> URL {
        directory.appendingPathComponent(id.uuidString).appendingPathExtension("json")
    }

    func load(id: UUID) -> ConversationSidecar {
        guard let data = try? Data(contentsOf: url(for: id)),
              let sidecar = try? JSONDecoder().decode(ConversationSidecar.self, from: data)
        else { return ConversationSidecar() }
        return sidecar
    }

    func save(id: UUID, sidecar: ConversationSidecar) throws {
        let data = try JSONEncoder().encode(sidecar)
        try data.write(to: url(for: id), options: .completeFileProtection)
    }

    func delete(id: UUID) {
        try? FileManager.default.removeItem(at: url(for: id))
    }
}

// MARK: - Contact key directory

/// Fingerprint hex → full serialized IdentityPublic (66 bytes). The package
/// Contact intentionally stores only the fingerprint; crypto needs the keys.
actor ContactKeyDirectory {
    private let file: URL
    private var cache: [String: Data] = [:]

    init() throws {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        file = base.appendingPathComponent("contact-keys.json")
        if let data = try? Data(contentsOf: file),
           let decoded = try? JSONDecoder().decode([String: Data].self, from: data) {
            cache = decoded
        }
    }

    func store(fingerprintHex: String, identityPublic: Data) throws {
        cache[fingerprintHex] = identityPublic
        try persist()
    }

    func load(fingerprintHex: String) -> Data? { cache[fingerprintHex] }

    func remove(fingerprintHex: String) throws {
        cache.removeValue(forKey: fingerprintHex)
        try persist()
    }

    private func persist() throws {
        try JSONEncoder().encode(cache).write(to: file, options: .completeFileProtection)
    }
}

// MARK: - Conversation mapping

enum StoreMapping {
    // MARK: Conversation

    static func toPackage(_ app: Conversation) -> (AegisStore.Conversation, ConversationSidecar) {
        let kind: AegisStore.ConversationKind
        switch app.kind {
        case .direct: kind = .direct
        case .group: kind = .group
        case .channel: kind = .channel
        case .vault: kind = .vault
        }
        let sidecar = ConversationSidecar(
            subtitle: app.subtitle,
            memberIDs: app.memberIDs,
            isAnnouncementOnly: app.isAnnouncementOnly,
            myRole: app.myRole,
            senderKeyStatus: app.senderKeyStatus,
            lastMessagePreview: app.lastMessagePreview,
            lastMessageAt: app.lastMessageAt,
            lastMessageIsFromMe: app.lastMessageIsFromMe
        )
        var pkg = AegisStore.Conversation(kind: kind)
        pkg.id = packageID(app.id)
        pkg.title = app.title
        pkg.disappearingTimerSeconds = app.disappearingInterval.map { Int($0) }
        pkg.isArchived = app.isArchived
        pkg.isMuted = app.isMuted
        pkg.isPinned = app.isPinned
        pkg.readReceiptsEnabled = app.readReceiptsEnabled
        pkg.typingIndicatorsEnabled = app.typingIndicatorsEnabled
        pkg.unreadCount = app.unreadCount
        return (pkg, sidecar)
    }

    static func toApp(_ pkg: AegisStore.Conversation, sidecar: ConversationSidecar) -> Conversation {
        let kind: ConversationKind
        switch pkg.kind {
        case .direct: kind = .direct
        case .group: kind = .group
        case .channel, .announcement: kind = .channel
        case .vault: kind = .vault
        }
        return Conversation(
            id: appUUID(pkg.id),
            kind: kind,
            title: pkg.title ?? "Unknown",
            subtitle: sidecar.subtitle,
            memberIDs: sidecar.memberIDs,
            isMuted: pkg.isMuted,
            isPinned: pkg.isPinned,
            isArchived: pkg.isArchived,
            unreadCount: pkg.unreadCount,
            disappearingInterval: pkg.disappearingTimerSeconds.map { TimeInterval($0) },
            readReceiptsEnabled: pkg.readReceiptsEnabled,
            typingIndicatorsEnabled: pkg.typingIndicatorsEnabled,
            isAnnouncementOnly: sidecar.isAnnouncementOnly,
            myRole: sidecar.myRole,
            senderKeyStatus: sidecar.senderKeyStatus,
            lastMessagePreview: sidecar.lastMessagePreview,
            lastMessageAt: sidecar.lastMessageAt,
            lastMessageIsFromMe: sidecar.lastMessageIsFromMe
        )
    }

    // MARK: Message

    static func toPackage(_ app: Message, localUserID: UUID) -> AegisStore.Message {
        let reactions: [AegisStore.Reaction] = app.reactions.flatMap { emoji, uuids in
            uuids.map { uuid in
                AegisStore.Reaction(
                    emoji: emoji,
                    userID: uuid == localUserID ? "local" : AegisStore.UserID(uuid.uuidString),
                    reactedAt: Date()
                )
            }
        }
        var attachmentIDs: [AegisStore.AttachmentID] = []
        if app.attachment != nil { attachmentIDs.append(packageID(app.id)) }
        if app.voiceNote != nil { attachmentIDs.append(packageID(app.id)) }
        return AegisStore.Message(
            id: packageID(app.id),
            conversationID: packageID(app.conversationID),
            senderID: app.isFromMe ? "local" : AegisStore.UserID(app.senderID.uuidString),
            direction: app.isFromMe ? .outgoing : .incoming,
            kind: app.attachment != nil ? .attachment : (app.voiceNote != nil ? .voiceNote : .text),
            text: app.body,
            replyToMessageID: app.replyToID.map { packageID($0) },
            editVersion: app.editedAt == nil ? 0 : 1,
            editedAt: app.editedAt,
            isTombstone: app.deletedAt != nil,
            tombstonedAt: app.deletedAt,
            disappearAt: app.expiresAt,
            deliveryState: deliveryState(from: app.status),
            sentAt: app.sentAt,
            reactions: reactions,
            attachmentIDs: attachmentIDs
        )
    }

    static func toApp(
        _ pkg: AegisStore.Message,
        localUserID: UUID,
        attachment: Attachment?,
        voiceNote: VoiceNote?
    ) -> Message {
        let isFromMe = pkg.direction == .outgoing
        var reactions: [String: [UUID]] = [:]
        for reaction in pkg.reactions {
            let uuid: UUID = reaction.userID.rawValue == "local"
                ? localUserID
                : (UUID(uuidString: reaction.userID.rawValue) ?? UUID())
            reactions[reaction.emoji, default: []].append(uuid)
        }
        return Message(
            id: appUUID(pkg.id),
            conversationID: appUUID(pkg.conversationID),
            senderID: isFromMe ? localUserID : (pkg.senderID.map { appUUID($0) } ?? UUID()),
            isFromMe: isFromMe,
            body: pkg.isTombstone ? nil : pkg.text,
            replyToID: pkg.replyToMessageID.map { appUUID($0) },
            reactions: reactions,
            status: messageStatus(from: pkg.deliveryState),
            editedAt: pkg.editedAt,
            deletedAt: pkg.tombstonedAt,
            expiresAt: pkg.disappearAt,
            attachment: attachment,
            voiceNote: voiceNote,
            sentAt: pkg.sentAt ?? Date()
        )
    }

    // MARK: Attachment

    static func attachmentKeychainID(_ id: UUID) -> String { "wk-\(id.uuidString)" }

    static func toPackage(
        _ app: Attachment,
        messageID: UUID,
        conversationID: UUID
    ) -> AegisStore.Attachment {
        let kind: AegisStore.AttachmentKind
        if app.mimeType.hasPrefix("image/") { kind = .image }
        else if app.mimeType.hasPrefix("video/") { kind = .video }
        else if app.mimeType.hasPrefix("audio/") { kind = .audio }
        else { kind = .file }
        return AegisStore.Attachment(
            id: packageID(app.id),
            messageID: packageID(messageID),
            conversationID: packageID(conversationID),
            kind: kind,
            fileName: app.filename,
            mimeType: app.mimeType,
            byteCount: app.byteCount,
            chunkCount: 0,
            remoteLocator: app.remoteLocator,
            localRelativePath: app.localRelativePath,
            keychainKeyID: attachmentKeychainID(app.id)
        )
    }

    static func voiceNoteToPackage(
        _ app: VoiceNote,
        messageID: UUID,
        conversationID: UUID
    ) -> (AegisStore.Attachment, ConversationSidecar.VoiceNoteExtra) {
        let attachment = Attachment(
            id: app.id,
            filename: "voice-note.m4a",
            mimeType: "audio/mp4",
            byteCount: 0,
            wrappedKey: app.wrappedKey,
            remoteLocator: app.remoteLocator,
            localRelativePath: app.localRelativePath
        )
        var pkg = toPackage(attachment, messageID: messageID, conversationID: conversationID)
        pkg.kind = .voiceNote
        let extra = ConversationSidecar.VoiceNoteExtra(duration: app.duration, levels: app.levels)
        return (pkg, extra)
    }

    static func toApp(
        _ pkg: AegisStore.Attachment,
        wrappedKey: Data?,
        voiceNoteExtra: ConversationSidecar.VoiceNoteExtra?
    ) -> (attachment: Attachment?, voiceNote: VoiceNote?) {
        if pkg.kind == .voiceNote, let extra = voiceNoteExtra {
            let note = VoiceNote(
                id: appUUID(pkg.id),
                duration: extra.duration,
                levels: extra.levels,
                wrappedKey: wrappedKey,
                remoteLocator: pkg.remoteLocator,
                localRelativePath: pkg.localRelativePath
            )
            return (nil, note)
        }
        let attachment = Attachment(
            id: appUUID(pkg.id),
            filename: pkg.fileName,
            mimeType: pkg.mimeType,
            byteCount: pkg.byteCount,
            wrappedKey: wrappedKey,
            remoteLocator: pkg.remoteLocator,
            localRelativePath: pkg.localRelativePath
        )
        return (attachment, nil)
    }

    // MARK: Contact

    static func toPackage(_ app: Contact, fingerprintHex: String) -> AegisStore.Contact {
        AegisStore.Contact(
            id: packageID(app.id),
            displayName: app.displayName,
            identityKeyFingerprint: fingerprintHex,
            verificationState: verificationState(from: app.verification),
            isBlocked: app.isBlocked,
            notes: app.notes
        )
    }

    static func toApp(_ pkg: AegisStore.Contact, identityKey: Data, id: UUID) -> Contact {
        Contact(
            id: id,
            displayName: pkg.displayName,
            identityKey: identityKey,
            verification: verificationState(from: pkg.verificationState),
            isBlocked: pkg.isBlocked,
            addedAt: pkg.createdAt,
            notes: pkg.notes
        )
    }

    // MARK: Call record

    static func toPackage(_ app: CallRecord) -> AegisStore.CallRecord {
        AegisStore.CallRecord(
            id: packageID(app.id),
            conversationID: app.conversationID.map { packageID($0) } ?? packageID(app.contactID),
            kind: app.kind == .video ? .video : .audio,
            direction: app.direction == .incoming ? .incoming : .outgoing,
            participants: [AegisStore.UserID(app.contactID.uuidString)],
            wasAnswered: app.endReason != .declined && app.endReason != .missed,
            startedAt: app.startedAt,
            endedAt: app.duration.map { app.startedAt.addingTimeInterval($0) }
        )
    }

    // MARK: - Enum bridges (fully qualified: these names collide with app enums)

    static func deliveryState(from status: MessageStatus) -> AegisStore.DeliveryState {
        switch status {
        case .sending: return .queued
        case .sent: return .sent
        case .delivered: return .delivered
        case .read: return .read
        case .failed: return .failed
        }
    }

    static func messageStatus(from state: AegisStore.DeliveryState) -> MessageStatus {
        switch state {
        case .queued: return .sending
        case .sent: return .sent
        case .delivered: return .delivered
        case .read: return .read
        case .failed: return .failed
        }
    }

    static func verificationState(from app: VerificationState) -> AegisStore.VerificationState {
        switch app {
        case .unverified: return .unverified
        case .verified: return .verified
        case .identityChanged: return .changedNeedsReverification
        }
    }

    static func verificationState(from pkg: AegisStore.VerificationState) -> VerificationState {
        switch pkg {
        case .unverified: return .unverified
        case .verified: return .verified
        case .changedNeedsReverification: return .identityChanged
        }
    }

    static func memberRole(from app: MemberRole) -> AegisStore.MemberRole {
        switch app {
        case .owner: return .owner
        case .admin: return .admin
        case .moderator: return .moderator
        case .member: return .member
        case .guest: return .guest
        }
    }

    static func memberRole(from pkg: AegisStore.MemberRole) -> MemberRole {
        switch pkg {
        case .owner: return .owner
        case .admin: return .admin
        case .moderator: return .moderator
        case .member: return .member
        case .guest: return .guest
        }
    }
}
