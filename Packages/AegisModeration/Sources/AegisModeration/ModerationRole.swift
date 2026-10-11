import Foundation

/// Canonical group/channel role. Raw values are the wire strings used in
/// group control messages and the membership table — they must stay stable.
///
/// The permission model is enforced by every honest client from the signed
/// group state: there is no server to appeal to, so the signed log *is* the
/// authority. A malicious client can ignore permissions locally, but cannot
/// forge another member's signature to escalate itself; honest clients
/// reject its unauthorized actions as invalid events.
public enum ModerationRole: String, Sendable, Codable, CaseIterable, Hashable {
    case owner
    case admin
    case moderator
    case member
    case guest

    /// Lower rank = more privilege. Used for roster ordering and for the
    /// "can only manage roles strictly below your own" rule.
    public var rank: Int {
        switch self {
        case .owner: return 0
        case .admin: return 1
        case .moderator: return 2
        case .member: return 3
        case .guest: return 4
        }
    }

    public var displayName: String {
        switch self {
        case .owner: return "Owner"
        case .admin: return "Admin"
        case .moderator: return "Moderator"
        case .member: return "Member"
        case .guest: return "Guest"
        }
    }

    /// Whether this role may perform day-to-day moderation: remove members,
    /// approve join requests, pin, manage slow mode. Owner/admin/moderator.
    public var canModerate: Bool {
        self == .owner || self == .admin || self == .moderator
    }

    /// Whether this role may administer the group: assign/revoke roles,
    /// edit the permission matrix, edit group info, revoke invites,
    /// transfer ownership. Owner/admin only.
    public var canAdminister: Bool {
        self == .owner || self == .admin
    }

    /// Whether `self` may change another member's role to `target`.
    /// Owners can manage anyone; admins can manage anyone below owner;
    /// nobody can promote someone to a rank equal-or-above their own, and
    /// only an owner can create another owner (ownership transfer, which
    /// demotes the previous owner).
    public func canManageRole(of other: ModerationRole, assigning target: ModerationRole) -> Bool {
        guard canAdminister else { return false }
        // Cannot touch anyone at your rank or above…
        guard other.rank > rank else { return false }
        // …and cannot grant a rank equal-or-above your own, except the
        // owner transferring ownership (which demotes themselves).
        if target == .owner { return self == .owner }
        return target.rank > rank
    }

    public var accessibilityLabel: String { "Role: \(displayName)" }
}
