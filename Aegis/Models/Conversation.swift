import Foundation

/// A 1:1 DM, group, or channel. The list row, the thread, and the settings
/// all read from this single source of truth.
struct Conversation: Identifiable, Sendable, Codable, Hashable {
    let id: UUID
    var kind: ConversationKind
    var title: String
    /// Channel topic / group description.
    var subtitle: String?
    var memberIDs: [UUID]

    // List behavior
    var isMuted: Bool
    var isPinned: Bool
    var isArchived: Bool
    var unreadCount: Int

    // Privacy behavior
    /// Disappearing-message interval in seconds; nil = off.
    var disappearingInterval: TimeInterval?
    var readReceiptsEnabled: Bool
    var typingIndicatorsEnabled: Bool

    // Channel behavior
    var isAnnouncementOnly: Bool
    /// The local user's role in groups/channels (nil for DMs).
    var myRole: MemberRole?
    var senderKeyStatus: SenderKeyStatus

    // List preview
    var lastMessagePreview: String?
    var lastMessageAt: Date?
    var lastMessageIsFromMe: Bool

    init(
        id: UUID = UUID(),
        kind: ConversationKind,
        title: String,
        subtitle: String? = nil,
        memberIDs: [UUID] = [],
        isMuted: Bool = false,
        isPinned: Bool = false,
        isArchived: Bool = false,
        unreadCount: Int = 0,
        disappearingInterval: TimeInterval? = nil,
        readReceiptsEnabled: Bool = true,
        typingIndicatorsEnabled: Bool = true,
        isAnnouncementOnly: Bool = false,
        myRole: MemberRole? = nil,
        senderKeyStatus: SenderKeyStatus = .active,
        lastMessagePreview: String? = nil,
        lastMessageAt: Date? = nil,
        lastMessageIsFromMe: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.title = title
        self.subtitle = subtitle
        self.memberIDs = memberIDs
        self.isMuted = isMuted
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.unreadCount = unreadCount
        self.disappearingInterval = disappearingInterval
        self.readReceiptsEnabled = readReceiptsEnabled
        self.typingIndicatorsEnabled = typingIndicatorsEnabled
        self.isAnnouncementOnly = isAnnouncementOnly
        self.myRole = myRole
        self.senderKeyStatus = senderKeyStatus
        self.lastMessagePreview = lastMessagePreview
        self.lastMessageAt = lastMessageAt
        self.lastMessageIsFromMe = lastMessageIsFromMe
    }
}

extension Conversation {
    var kindLabel: String {
        switch kind {
        case .direct: return "Direct message"
        case .group: return "Group"
        case .channel: return "Channel"
        case .vault: return "Vault"
        }
    }

    /// Whether the local user may send into this conversation right now.
    /// Guests are read-only observers and can never post; announcement-only
    /// channels additionally require a moderating role. (The transport
    /// layer re-checks this from the signed group state on every send —
    /// this is the UI-facing projection, not the enforcement.)
    var canSend: Bool {
        if let role = myRole, role == .guest { return false }
        guard kind != .channel || !isAnnouncementOnly else {
            return myRole?.canModerate ?? false
        }
        return true
    }

    var disappearingLabel: String? {
        guard let interval = disappearingInterval else { return nil }
        return "Disappears after \(Formatters.duration(interval))"
    }
}
