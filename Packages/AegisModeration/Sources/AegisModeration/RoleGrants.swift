import Foundation

/// The per-channel permission policy: role defaults, per-channel overrides,
/// announcement mode, and slow mode. This is the signed group state every
/// honest client enforces from.
public struct ChannelPermissionPolicy: Sendable, Codable, Equatable {
    /// When true, the channel is broadcast-only: posting additionally
    /// requires a moderating role, regardless of the `.post` grant.
    public var announcementOnly: Bool
    /// Per-role grant overrides for THIS channel. A role present here uses
    /// exactly this grant set instead of the role default; a role absent
    /// here uses the default. Stored sparsely — only edited roles appear.
    public var overrides: [ModerationRole: Set<GroupPermission>]
    /// Slow mode interval in seconds; nil = off. Valid range 5s…6h.
    public var slowModeInterval: TimeInterval?
    /// Roles exempt from slow mode. Defaults to owner/admin/moderator.
    public var slowModeExemptRoles: Set<ModerationRole>

    public init(
        announcementOnly: Bool = false,
        overrides: [ModerationRole: Set<GroupPermission>] = [:],
        slowModeInterval: TimeInterval? = nil,
        slowModeExemptRoles: Set<ModerationRole> = [.owner, .admin, .moderator]
    ) {
        self.announcementOnly = announcementOnly
        self.overrides = overrides
        // Clamp slow mode into the valid range; nil stays off.
        if let interval = slowModeInterval {
            self.slowModeInterval = min(
                max(interval, SlowModeEnforcer.minimumInterval),
                SlowModeEnforcer.maximumInterval
            )
        } else {
            self.slowModeInterval = nil
        }
        self.slowModeExemptRoles = slowModeExemptRoles
    }

    public static func `default`(announcementOnly: Bool = false) -> ChannelPermissionPolicy {
        ChannelPermissionPolicy(announcementOnly: announcementOnly)
    }
}

/// Evaluates permissions against role defaults and channel overrides.
/// Pure logic — no I/O — so every client computes identical answers from
/// identical signed state.
public enum PermissionEvaluator {
    /// The default grant set for a role, before channel overrides.
    public static func defaultGrants(for role: ModerationRole) -> Set<GroupPermission> {
        switch role {
        case .owner, .admin:
            return Set(GroupPermission.allCases)
        case .moderator:
            return [
                .post, .invite, .pin, .manageThreads,
                .startVoiceRooms, .manageMembers, .approveJoinRequests,
            ]
        case .member:
            return [.post, .invite, .startVoiceRooms]
        case .guest:
            // Guests are read-only observers by default.
            return []
        }
    }

    /// The effective grant set for `role` in this channel: the override
    /// when present, else the role default.
    public static func grants(for role: ModerationRole, in policy: ChannelPermissionPolicy) -> Set<GroupPermission> {
        policy.overrides[role] ?? defaultGrants(for: role)
    }

    /// Whether `role` may exercise `permission` in this channel.
    ///
    /// Announcement-only channels additionally require a moderating role
    /// for `.post`, even if the grant set would allow it — broadcast
    /// channels stay broadcast.
    public static func can(
        _ role: ModerationRole,
        _ permission: GroupPermission,
        in policy: ChannelPermissionPolicy
    ) -> Bool {
        guard grants(for: role, in: policy).contains(permission) else { return false }
        if permission == .post, policy.announcementOnly {
            return role.canModerate
        }
        return true
    }

    /// Whether `role` is exempt from this channel's slow mode.
    public static func isSlowModeExempt(_ role: ModerationRole, in policy: ChannelPermissionPolicy) -> Bool {
        policy.slowModeExemptRoles.contains(role)
    }
}
