import Foundation

/// A single message. Bodies are stored decrypted in the local encrypted store;
/// only ciphertext ever leaves the device via the transport.
struct Message: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    let conversationID: UUID
    /// Sender: the local identity id for outbound, contact id for inbound.
    let senderID: UUID
    let isFromMe: Bool

    var body: String?
    var replyToID: UUID?
    /// Frozen quote of the replied-to message, captured at reply time.
    /// Survives the original being edited or deleted.
    var quoteSnapshot: QuoteSnapshot?
    /// Emoji -> sender ids who reacted.
    var reactions: [String: [UUID]]
    var status: MessageStatus

    var editedAt: Date?
    /// Local version history (previous bodies), oldest-first.
    var editHistory: [MessageEdit]
    var deletedAt: Date?
    /// When set, the message self-destructs locally (and peers honor it).
    var expiresAt: Date?
    /// "Disappear after read" mode: when set, `expiresAt` is computed as
    /// read-time + this interval instead of send-time + chat timer.
    var disappearAfterReadInterval: TimeInterval?

    /// Threading: nil for top-level messages; set to the parent message's
    /// id for replies inside a thread.
    var threadRootID: UUID?

    /// Poll attached to this message (kind == .text with a poll set).
    var poll: PollMessage?

    /// Local-only star. Never synced, never leaves the device.
    var isStarred: Bool
    /// Shared pin record. Propagated to participants via signed pin events.
    var pin: MessagePin?

    var attachment: Attachment?
    var voiceNote: VoiceNote?

    let sentAt: Date

    init(
        id: UUID = UUID(),
        conversationID: UUID,
        senderID: UUID,
        isFromMe: Bool,
        body: String? = nil,
        replyToID: UUID? = nil,
        quoteSnapshot: QuoteSnapshot? = nil,
        reactions: [String: [UUID]] = [:],
        status: MessageStatus = .sending,
        editedAt: Date? = nil,
        editHistory: [MessageEdit] = [],
        deletedAt: Date? = nil,
        expiresAt: Date? = nil,
        disappearAfterReadInterval: TimeInterval? = nil,
        threadRootID: UUID? = nil,
        poll: PollMessage? = nil,
        isStarred: Bool = false,
        pin: MessagePin? = nil,
        attachment: Attachment? = nil,
        voiceNote: VoiceNote? = nil,
        sentAt: Date = Date()
    ) {
        self.id = id
        self.conversationID = conversationID
        self.senderID = senderID
        self.isFromMe = isFromMe
        self.body = body
        self.replyToID = replyToID
        self.quoteSnapshot = quoteSnapshot
        self.reactions = reactions
        self.status = status
        self.editedAt = editedAt
        self.editHistory = editHistory
        self.deletedAt = deletedAt
        self.expiresAt = expiresAt
        self.disappearAfterReadInterval = disappearAfterReadInterval
        self.threadRootID = threadRootID
        self.poll = poll
        self.isStarred = isStarred
        self.pin = pin
        self.attachment = attachment
        self.voiceNote = voiceNote
        self.sentAt = sentAt
    }
}

extension Message {
    var isDeleted: Bool { deletedAt != nil }
    var isEdited: Bool { editedAt != nil }
    var isEphemeral: Bool { expiresAt != nil || disappearAfterReadInterval != nil }
    var hasContent: Bool { body != nil || attachment != nil || voiceNote != nil }
    var isThreadReply: Bool { threadRootID != nil }
    var isPoll: Bool { poll != nil }
    /// A pin is active when set and not expired.
    var isPinned: Bool {
        guard let pin else { return false }
        return !pin.isExpired
    }

    /// Builds a quote snapshot of this message for use as `quoteSnapshot`
    /// on a reply.
    func makeQuoteSnapshot(senderName: String) -> QuoteSnapshot {
        let excerpt: String?
        if let body, !body.isEmpty {
            excerpt = String(body.prefix(140))
        } else {
            excerpt = nil
        }
        return QuoteSnapshot(
            senderID: senderID,
            senderName: senderName,
            bodyExcerpt: excerpt,
            hasAttachment: attachment != nil,
            hasVoiceNote: voiceNote != nil,
            isPoll: poll != nil,
            sentAt: sentAt,
            expiresAt: expiresAt
        )
    }

    /// Total reaction count across all emoji.
    var reactionCount: Int { reactions.values.reduce(0) { $0 + $1.count } }

    /// Sorted for stable rendering.
    var sortedReactions: [(emoji: String, count: Int)] {
        reactions.map { (emoji: $0.key, count: $0.value.count) }
            .sorted { $0.count > $1.count }
    }

    /// Whether a given identity reacted with the given emoji.
    func didReact(_ emoji: String, senderID: UUID) -> Bool {
        reactions[emoji]?.contains(senderID) ?? false
    }
}
