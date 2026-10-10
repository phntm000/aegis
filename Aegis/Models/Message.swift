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
    /// Emoji -> sender ids who reacted.
    var reactions: [String: [UUID]]
    var status: MessageStatus

    var editedAt: Date?
    var deletedAt: Date?
    /// When set, the message self-destructs locally (and peers honor it).
    var expiresAt: Date?

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
        reactions: [String: [UUID]] = [:],
        status: MessageStatus = .sending,
        editedAt: Date? = nil,
        deletedAt: Date? = nil,
        expiresAt: Date? = nil,
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
        self.reactions = reactions
        self.status = status
        self.editedAt = editedAt
        self.deletedAt = deletedAt
        self.expiresAt = expiresAt
        self.attachment = attachment
        self.voiceNote = voiceNote
        self.sentAt = sentAt
    }
}

extension Message {
    var isDeleted: Bool { deletedAt != nil }
    var isEdited: Bool { editedAt != nil }
    var isEphemeral: Bool { expiresAt != nil }
    var hasContent: Bool { body != nil || attachment != nil || voiceNote != nil }

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
