import Foundation

// MARK: - MessageRichness
//
// Domain types for messaging richness: quoted replies, threads, polls,
// edit history, stars, pins, and custom emoji packs. All types are
// Codable/Sendable value types; the store persists them (see StoreMapping)
// and the wire carries them inside WirePayload.

/// A frozen snapshot of the message being quoted, captured at reply time.
/// The live pointer is `Message.replyToID`; this snapshot survives the
/// original being edited or deleted.
struct QuoteSnapshot: Codable, Sendable, Hashable {
    /// Sender of the quoted message (local identity id for own messages).
    var senderID: UUID
    var senderName: String
    /// Excerpt of the quoted body (first ~140 chars), nil for media-only.
    var bodyExcerpt: String?
    var hasAttachment: Bool = false
    var hasVoiceNote: Bool = false
    var isPoll: Bool = false
    var sentAt: Date
    /// The quoted message's own expiry, if it was disappearing. The quote
    /// inherits it: quoting doesn't resurrect content the timer killed.
    var expiresAt: Date? = nil

    var fallbackText: String {
        if let bodyExcerpt, !bodyExcerpt.isEmpty { return bodyExcerpt }
        if isPoll { return "📊 Poll" }
        if hasVoiceNote { return "🎤 Voice note" }
        if hasAttachment { return "📎 Attachment" }
        return "Message"
    }
}

/// One entry of a message's local version history. `body` is the text the
/// message had before the edit that produced this entry.
struct MessageEdit: Codable, Sendable, Hashable {
    var body: String
    var editedAt: Date
}

/// A signed pin record on a message. Pins are shared (propagated to
/// participants) and admin-controlled in groups/channels.
struct MessagePin: Codable, Sendable, Hashable {
    /// Who pinned it (local identity id for our own pins).
    var pinnedBy: UUID
    var pinnedByName: String
    var pinnedAt: Date = Date()
    /// Optional expiry; nil = pinned until unpinned.
    var expiresAt: Date? = nil

    var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt <= Date()
    }
}

/// A poll attached to a message. Ballots arrive as separate signed
/// `WirePayload.Kind.ballot` events; this struct holds the question,
/// options, configuration, and the locally-computed tally.
struct PollMessage: Codable, Sendable, Hashable {
    var question: String
    var options: [String]
    var allowsMultipleChoice: Bool
    var isAnonymous: Bool
    /// Nil = never auto-closes.
    var closesAt: Date?
    /// Option index -> vote count. Computed client-side from ballots.
    var tally: [Int: Int]
    /// Voter identity ids (prevents double voting; the voter->choice
    /// mapping is hidden for anonymous polls).
    var voters: [UUID]
    /// Voter -> chosen option indices. Populated only for NON-anonymous
    /// polls (anonymous polls keep only the voter set, so ballot-stuffing
    /// is detectable but choices stay secret).
    var voterChoices: [UUID: [Int]]
    /// Our own current choices (option indices). Empty = not voted.
    var myChoices: [Int]
    /// Total eligible voters (group member count at creation); nil when
    /// unknown (1:1 chats).
    var eligibleVoterCount: Int?

    var isClosed: Bool {
        guard let closesAt else { return false }
        return closesAt <= Date()
    }

    var totalVotes: Int { tally.values.reduce(0, +) }

    var uniqueVoterCount: Int { voters.count }

    /// Quorum display: "3 of 5 voted" (or "3 voted" when eligible unknown).
    var quorumText: String {
        if let eligible = eligibleVoterCount {
            return "\(uniqueVoterCount) of \(eligible) voted"
        }
        return uniqueVoterCount == 1 ? "1 voted" : "\(uniqueVoterCount) voted"
    }

    func count(for option: Int) -> Int { tally[option] ?? 0 }

    func share(for option: Int) -> Double {
        guard totalVotes > 0 else { return 0 }
        return Double(count(for: option)) / Double(totalVotes)
    }

    /// Whether `voter` may cast `choices` right now.
    func canVote(voter: UUID, choices: [Int]) -> Bool {
        guard !isClosed else { return false }
        guard !choices.isEmpty else { return false }
        guard choices.allSatisfy({ $0 >= 0 && $0 < options.count }) else { return false }
        if !allowsMultipleChoice && choices.count > 1 { return false }
        // Anonymous polls: one ballot per voter, no changes.
        if isAnonymous && voters.contains(voter) { return false }
        return true
    }

    /// Applies a verified ballot. Returns false when the ballot is invalid
    /// (double vote on anonymous poll, closed, out-of-range).
    mutating func applyBallot(voter: UUID, choices: [Int]) -> Bool {
        guard canVote(voter: voter, choices: choices) else { return false }
        // Non-anonymous re-vote: retract the previous ballot first.
        if !isAnonymous, voters.contains(voter), let previous = previousChoices(of: voter) {
            for option in previous {
                tally[option] = max(0, (tally[option] ?? 1) - 1)
            }
        }
        for option in choices {
            tally[option, default: 0] += 1
        }
        if !voters.contains(voter) { voters.append(voter) }
        if !isAnonymous {
            voterChoices[voter] = choices
        }
        return true
    }

    /// Previous choices of a voter (non-anonymous polls only).
    func previousChoices(of voter: UUID) -> [Int]? {
        voterChoices[voter]
    }
}

// MARK: - Custom emoji packs

/// One custom emoji: a short name plus PNG image data. Rendered as an
/// image everywhere; never as text (so a hostile pack can't inject text
/// shaping attacks into the chat).
struct CustomEmoji: Codable, Sendable, Hashable, Identifiable {
    var id: String
    var imageData: Data
}

/// A user-created pack of custom emoji. Packs are local-only (never synced
/// over the wire); reactions referencing a pack use the key
/// "pack:\(packID):\(emojiID)" and render as images when the pack exists.
struct CustomEmojiPack: Codable, Sendable, Hashable, Identifiable {
    var id: UUID
    var name: String
    var emojis: [CustomEmoji]
    var createdAt: Date

    init(id: UUID = UUID(), name: String, emojis: [CustomEmoji] = [], createdAt: Date = Date()) {
        self.id = id
        self.name = name
        self.emojis = emojis
        self.createdAt = createdAt
    }
}

// MARK: - Reaction keys

/// Reaction dictionary keys. Plain emoji stay as-is; custom emoji use
/// "pack:<packID>:<emojiID>".
enum ReactionKey {
    static func customEmoji(packID: UUID, emojiID: String) -> String {
        "pack:\(packID.uuidString):\(emojiID)"
    }

    /// Parses a custom-emoji reaction key. Returns nil for plain emoji.
    static func parseCustomEmoji(_ key: String) -> (packID: UUID, emojiID: String)? {
        guard key.hasPrefix("pack:") else { return nil }
        let rest = key.dropFirst("pack:".count)
        guard let colon = rest.firstIndex(of: ":") else { return nil }
        let packPart = String(rest[..<colon])
        let emojiPart = String(rest[rest.index(after: colon)...])
        guard let packID = UUID(uuidString: packPart), !emojiPart.isEmpty else { return nil }
        return (packID, emojiPart)
    }

    static func isCustomEmoji(_ key: String) -> Bool { parseCustomEmoji(key) != nil }
}

// MARK: - Edit window

extension SettingsKeys {
    /// How long after sending a message may be edited (seconds).
    /// Default 48h. 0 = edits disabled.
    static let editWindowSeconds = "messaging.editWindowSeconds"
}

/// Default edit window: 48 hours.
let defaultEditWindowSeconds: TimeInterval = 48 * 3600

/// Whether `message` may still be edited at `now` under `windowSeconds`.
func canEditMessage(_ message: Message, at now: Date = Date(), windowSeconds: TimeInterval) -> Bool {
    guard message.isFromMe, !message.isDeleted, message.body != nil else { return false }
    guard windowSeconds > 0 else { return false }
    return now.timeIntervalSince(message.sentAt) <= windowSeconds
}

// MARK: - Thread summary

/// Denormalized per-thread stats for the main list (reply count +
/// last activity), so the thread view doesn't page the whole store.
struct ThreadSummary: Sendable, Hashable {
    var replyCount: Int
    var lastActivityAt: Date
}
