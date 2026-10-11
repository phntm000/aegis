import AegisModeration
import Foundation

// MARK: - Shared domain enums

/// Delivery/read state of an outbound message.
enum MessageStatus: String, Sendable, Codable, CaseIterable {
    case sending
    case sent
    case delivered
    case read
    case failed

    var accessibilityLabel: String {
        switch self {
        case .sending: return "Sending"
        case .sent: return "Sent"
        case .delivered: return "Delivered"
        case .read: return "Read"
        case .failed: return "Failed to send"
        }
    }
}

/// Trust state of a contact's identity key.
enum VerificationState: String, Sendable, Codable {
    /// Never verified — show the neutral shield.
    case unverified
    /// Safety number confirmed out-of-band — show the filled shield.
    case verified
    /// Key changed after verification — show a prominent warning until re-verified.
    case identityChanged
}

/// Role inside a group or channel. Raw values are the wire strings used in
/// group control messages — they must stay stable.
enum MemberRole: String, Sendable, Codable, CaseIterable {
    case owner
    case admin
    case moderator
    case member
    case guest

    var displayName: String {
        switch self {
        case .owner: return "Owner"
        case .admin: return "Admin"
        case .moderator: return "Moderator"
        case .member: return "Member"
        case .guest: return "Guest"
        }
    }

    /// Whether this role may administer the group: assign/revoke roles,
    /// edit permissions, manage invites, edit group info. Owner/admin only.
    /// (Existing call sites keep their behavior: moderators do NOT gain
    /// admin powers through this flag.)
    var canModerate: Bool { self == .owner || self == .admin }

    /// Whether this role may perform day-to-day moderation: remove members,
    /// approve join requests, pin, manage slow mode. Owner/admin/moderator.
    var canModerateMembers: Bool { canModerate || self == .moderator }

    /// Lower rank = more privilege.
    var rank: Int {
        switch self {
        case .owner: return 0
        case .admin: return 1
        case .moderator: return 2
        case .member: return 3
        case .guest: return 4
        }
    }

    var moderationRole: ModerationRole {
        switch self {
        case .owner: return .owner
        case .admin: return .admin
        case .moderator: return .moderator
        case .member: return .member
        case .guest: return .guest
        }
    }
}

extension ModerationRole {
    var memberRole: MemberRole {
        switch self {
        case .owner: return .owner
        case .admin: return .admin
        case .moderator: return .moderator
        case .member: return .member
        case .guest: return .guest
        }
    }
}

enum ConversationKind: String, Sendable, Codable {
    case direct
    case group
    case channel
    /// Local-only vault: never touches any relay or network.
    case vault
}

/// Network reachability from the app's perspective.
enum ConnectionState: String, Sendable, Codable {
    /// No usable path (airplane mode / no LAN peers and no relay).
    case offline
    /// LAN-only mode: peers reachable on the local network, relay disabled by choice.
    case lanOnly
    /// Attempting to reach the configured relay.
    case relayConnecting
    /// Fully connected through the relay.
    case relayConnected
    /// Relay unreachable; LAN peers may still work.
    case relayUnreachable
    /// Automatic mode with no verified relay: honest local-network operation.
    /// Not a failure — LAN peers work; nothing was silently misconfigured.
    case localNetworkOnly

    var displayName: String {
        switch self {
        case .offline: return "Offline"
        case .lanOnly: return "LAN only"
        case .localNetworkOnly: return "Local network only"
        case .relayConnecting: return "Connecting…"
        case .relayConnected: return "Connected"
        case .relayUnreachable: return "Relay unreachable"
        }
    }

    /// Whether envelopes can currently be sent.
    var canSend: Bool {
        switch self {
        case .lanOnly, .localNetworkOnly, .relayConnected, .relayUnreachable: return true
        case .offline, .relayConnecting: return false
        }
    }

    /// Whether the banner UI should draw attention.
    var needsAttention: Bool {
        self == .offline || self == .relayUnreachable
    }
}

// MARK: - Calls

enum CallKind: String, Sendable, Codable {
    case audio
    case video
}

enum CallDirection: String, Sendable, Codable {
    case incoming
    case outgoing
}

enum CallEndReason: String, Sendable, Codable {
    case completed
    case missed
    case declined
    case failed
    case busy

    var displayName: String {
        switch self {
        case .completed: return "Completed"
        case .missed: return "Missed"
        case .declined: return "Declined"
        case .failed: return "Failed"
        case .busy: return "Busy"
        }
    }
}

/// Live state of an in-progress call shown in the call UI.
enum ActiveCallState: String, Sendable {
    case dialing
    case ringing
    case connecting
    case connected
    case ended
}

// MARK: - Transfers

/// UI-observed state of an attachment upload/download. Not persisted —
/// progress is tracked in-memory by view models keyed on attachment id.
enum TransferState: Sendable, Equatable {
    case idle
    case preparing
    case inProgress(Double) // 0...1
    case done
    case failed(String)
}

/// Health of a group's sender-key session (Sealed Sender group ratchet).
enum SenderKeyStatus: String, Sendable, Codable {
    case active
    case refreshing
    case failed

    var displayName: String {
        switch self {
        case .active: return "Encrypted session active"
        case .refreshing: return "Refreshing encryption session…"
        case .failed: return "Encryption session failed — rotate the key"
        }
    }
}
