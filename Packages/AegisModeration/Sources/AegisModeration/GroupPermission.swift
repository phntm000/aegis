import Foundation

/// Granular per-channel permissions. Every action an honest client takes in
/// a group/channel is checked against the actor's role and the channel's
/// permission policy; unauthorized actions are rejected locally and, when
/// observed from a peer, recorded as invalid events in the audit log.
public enum GroupPermission: String, Sendable, Codable, CaseIterable, Hashable {
    /// Send text/voice/media messages to the channel.
    case post
    /// Create invites (QR / link) for the group.
    case invite
    /// Pin and unpin messages.
    case pin
    /// Create, rename, archive, and delete discussion threads.
    case manageThreads
    /// Start voice rooms in the channel.
    case startVoiceRooms
    /// Record calls / voice rooms (still requires per-party consent UX).
    case recordCalls
    /// Add and remove members.
    case manageMembers
    /// Edit the group's name, description, and avatar.
    case editGroupInfo
    /// Approve or decline join requests.
    case approveJoinRequests

    public var displayName: String {
        switch self {
        case .post: return "Post messages"
        case .invite: return "Create invites"
        case .pin: return "Pin messages"
        case .manageThreads: return "Manage threads"
        case .startVoiceRooms: return "Start voice rooms"
        case .recordCalls: return "Record calls"
        case .manageMembers: return "Add / remove members"
        case .editGroupInfo: return "Edit group info"
        case .approveJoinRequests: return "Approve join requests"
        }
    }

    public var description: String {
        switch self {
        case .post:
            return "Send messages, voice notes, and attachments."
        case .invite:
            return "Generate QR and link invites for new members."
        case .pin:
            return "Pin important messages to the top of the channel."
        case .manageThreads:
            return "Create, rename, archive, and delete discussion threads."
        case .startVoiceRooms:
            return "Open a live voice room in this channel."
        case .recordCalls:
            return "Record calls and voice rooms. Everyone is still notified and consent is required."
        case .manageMembers:
            return "Add new members and remove existing ones."
        case .editGroupInfo:
            return "Change the name, description, and avatar."
        case .approveJoinRequests:
            return "Approve or decline people asking to join."
        }
    }

    public var systemImage: String {
        switch self {
        case .post: return "bubble.left"
        case .invite: return "person.badge.plus"
        case .pin: return "pin"
        case .manageThreads: return "bubble.left.and.bubble.right"
        case .startVoiceRooms: return "phone"
        case .recordCalls: return "record.circle"
        case .manageMembers: return "person.2"
        case .editGroupInfo: return "pencil"
        case .approveJoinRequests: return "checkmark.seal"
        }
    }
}
