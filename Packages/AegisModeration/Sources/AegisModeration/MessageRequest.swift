import Foundation

// MARK: - Message requests
//
// Messages from identities the user has never contacted land in the
// Requests inbox — the client-side spam boundary for an account-less
// system (no phone-number reputation, no server-side filters).
//
// Policy, enforced by the app:
//  - The sender gets NO read receipts, NO typing indicators, and NO
//    online/last-seen presence until the request is accepted.
//  - Requests never badge the main chat list, never notify, and never
//    bump unread counts.
//  - One-tap accept (the conversation joins the chat list), block
//    (local and silent), or report (local heuristics only).

/// A pending first-contact request from an unknown identity.
public struct MessageRequestItem: Sendable, Codable, Equatable, Identifiable {
    public var id: UUID
    public var conversationID: UUID
    /// 32-byte identity fingerprint of the requester.
    public var senderFingerprint: Data
    /// Self-asserted display name (untrusted until verified).
    public var senderName: String
    /// First-message preview for the inbox row.
    public var preview: String?
    public var receivedAt: Date
    /// Number of messages received while the request is pending.
    public var messageCount: Int

    public init(
        id: UUID = UUID(),
        conversationID: UUID,
        senderFingerprint: Data,
        senderName: String,
        preview: String? = nil,
        receivedAt: Date = Date(),
        messageCount: Int = 1
    ) {
        self.id = id
        self.conversationID = conversationID
        self.senderFingerprint = senderFingerprint
        self.senderName = senderName
        self.preview = preview
        self.receivedAt = receivedAt
        self.messageCount = messageCount
    }
}

extension MessageRequestItem {
    /// Display name for the inbox row: the sender's self-asserted name,
    /// or a fingerprint suffix when the sender is unknown.
    public var displayName: String {
        let trimmed = senderName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "···" + senderFingerprint.suffix(8).map { String(format: "%02x", $0) }.joined()
        }
        return trimmed
    }
}

/// The user's decision on a message request.
public enum MessageRequestDecision: Sendable, Equatable {
    /// Accept: the conversation joins the chat list; receipts/typing/
    /// presence resume for this conversation from now on.
    case accept
    /// Block: local and silent. The conversation is deleted, the identity
    /// is blocklisted, and nothing is ever sent to the blocked party.
    case block
    /// Report then block: files a local-only report and blocks.
    case report(reason: ReportReason, detail: String?)
}
