import Foundation

/// The app's own envelope payload format.
///
/// Flow: app builds a `WirePayload` → JSON-encodes → AegisCrypto encrypts →
/// AegisTransport sends ciphertext. Inbound is the reverse. The transport and
/// crypto layers are agnostic to this schema; it is versioned so future app
/// releases can evolve it without breaking the other packages.
struct WirePayload: Codable, Sendable {
    static let currentVersion = 1

    enum Kind: String, Codable, Sendable {
        case text
        case reaction
        case edit
        case delete
        case readReceipt
        case typing
        case screenshotNotice
    }

    var version: Int
    var kind: Kind

    // Message fields
    var messageID: UUID?
    var body: String?
    var replyToID: UUID?
    var attachment: Attachment?
    var voiceNote: VoiceNote?
    var expiresIn: TimeInterval?

    // Reaction / edit / delete fields
    var targetMessageID: UUID?
    var emoji: String?
    var editedBody: String?

    // Read receipt fields
    var messageIDs: [UUID]?

    // Typing fields
    var isTyping: Bool?

    /// Identity-rotation hint: fingerprint (32 bytes) of the sender's
    /// previous identity, included (encrypted) when this device replaced its
    /// identity. Lets the recipient link the new key to the existing contact
    /// and show "safety number changed" instead of an unknown sender. It is
    /// only a hint — the recipient still verifies out-of-band before trusting
    /// the new key.
    var previousFingerprint: Data?

    init(kind: Kind) {
        self.version = Self.currentVersion
        self.kind = kind
    }

    // MARK: - Constructors

    static func text(
        id: UUID,
        body: String?,
        replyToID: UUID?,
        attachment: Attachment?,
        voiceNote: VoiceNote?,
        expiresIn: TimeInterval?
    ) -> WirePayload {
        var p = WirePayload(kind: .text)
        p.messageID = id
        p.body = body
        p.replyToID = replyToID
        p.attachment = attachment
        p.voiceNote = voiceNote
        p.expiresIn = expiresIn
        return p
    }

    static func reaction(targetMessageID: UUID, emoji: String) -> WirePayload {
        var p = WirePayload(kind: .reaction)
        p.targetMessageID = targetMessageID
        p.emoji = emoji
        return p
    }

    static func edit(targetMessageID: UUID, editedBody: String) -> WirePayload {
        var p = WirePayload(kind: .edit)
        p.targetMessageID = targetMessageID
        p.editedBody = editedBody
        return p
    }

    static func delete(targetMessageID: UUID) -> WirePayload {
        var p = WirePayload(kind: .delete)
        p.targetMessageID = targetMessageID
        return p
    }

    static func readReceipt(messageIDs: [UUID]) -> WirePayload {
        var p = WirePayload(kind: .readReceipt)
        p.messageIDs = messageIDs
        return p
    }

    static func typing(isTyping: Bool) -> WirePayload {
        var p = WirePayload(kind: .typing)
        p.isTyping = isTyping
        return p
    }

    static func screenshotNotice() -> WirePayload {
        WirePayload(kind: .screenshotNotice)
    }

    // MARK: - Coders

    func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func decoded(from data: Data) throws -> WirePayload {
        try JSONDecoder().decode(WirePayload.self, from: data)
    }
}
