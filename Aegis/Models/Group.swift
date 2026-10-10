import Foundation

/// A member of a group or channel, with their role.
struct GroupMember: Identifiable, Sendable, Codable, Hashable {
    /// Contact id.
    let id: UUID
    var displayName: String
    var role: MemberRole
    var joinedAt: Date
}

/// Detail model for the group/channel info screen. Membership truth lives
/// with the transport's group state; this is the UI-facing projection.
struct GroupInfo: Sendable, Codable {
    let conversationID: UUID
    var description: String?
    var members: [GroupMember]
    var inviteCode: String?
    var senderKeyStatus: SenderKeyStatus

    var memberCount: Int { members.count }

    var owners: [GroupMember] { members.filter { $0.role == .owner } }
    var admins: [GroupMember] { members.filter { $0.role == .admin } }
    var regularMembers: [GroupMember] { members.filter { $0.role == .member } }
}
