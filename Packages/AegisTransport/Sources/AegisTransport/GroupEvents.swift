// GroupEvents — membership/role/topic change vocabulary.
//
// Group control traffic (invites, removals, role changes, topic edits,
// announcement-mode flips) travels as sealed `groupControl` envelopes on
// the conversation's routing mailbox. The app-layer transport adapter
// decrypts those envelopes and publishes these events so views like
// GroupDetailView can refresh live instead of on-appear.
//
// These types are deliberately network-shaped: they carry the routing
// `mailbox`, not an app-level conversation ID. The adapter maps
// mailbox → conversation. The crypto layer authenticates every control
// message (group admin signatures); the adapter drops anything that does
// not verify before emitting.

import Foundation

/// The kind of group/channel change. Fingerprints are 32-byte identity
/// fingerprints; roles are the app's role strings ("owner"/"admin"/"member").
public enum GroupEventKind: Sendable, Equatable {
    case memberJoined(fingerprint: Data, role: String)
    case memberRemoved(fingerprint: Data)
    case roleChanged(fingerprint: Data, role: String)
    case topicChanged(String?)
    case announcementModeChanged(Bool)
}

/// A verified group membership event, addressed by routing mailbox.
public struct GroupMembershipEvent: Sendable, Equatable {
    /// The conversation's current routing mailbox (see RoutingMailbox).
    public let mailbox: MailboxID
    public let kind: GroupEventKind
    /// When the adapter observed it.
    public let receivedAt: Date

    public init(mailbox: MailboxID, kind: GroupEventKind, receivedAt: Date = Date()) {
        self.mailbox = mailbox
        self.kind = kind
        self.receivedAt = receivedAt
    }
}
