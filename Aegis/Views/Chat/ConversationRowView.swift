import SwiftUI

/// One row in the chat list: avatar, title + verification shield, preview,
/// timestamp, unread badge, and status icons. The whole row is the tap target.
struct ConversationRowView: View {
    let conversation: Conversation
    let contact: Contact?

    var body: some View {
        HStack(spacing: AegisLayout.m) {
            avatar
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: AegisLayout.xs) {
                    Text(conversation.title)
                        .font(AegisType.bodyStrong)
                        .foregroundStyle(AegisColors.textPrimary)
                        .lineLimit(1)

                    if conversation.kind == .direct, let contact {
                        VerificationShieldView(state: contact.verification, size: 14)
                    }
                    if conversation.kind == .group {
                        Image(systemName: "person.2.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(AegisColors.textTertiary)
                            .accessibilityLabel("Group")
                    }
                    if conversation.kind == .channel {
                        Image(systemName: "megaphone.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(AegisColors.textTertiary)
                            .accessibilityLabel("Channel")
                    }
                    if conversation.disappearingInterval != nil {
                        Image(systemName: "timer")
                            .font(.system(size: 11))
                            .foregroundStyle(AegisColors.textTertiary)
                            .accessibilityLabel("Disappearing messages on")
                    }
                    if conversation.isMuted {
                        Image(systemName: "bell.slash.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(AegisColors.textTertiary)
                            .accessibilityLabel("Muted")
                    }

                    Spacer()

                    if let at = conversation.lastMessageAt {
                        Text(Formatters.chatListTimestamp(at))
                            .font(AegisType.caption)
                            .foregroundStyle(conversation.unreadCount > 0 ? AegisColors.accent : AegisColors.textTertiary)
                    }
                }

                HStack(spacing: AegisLayout.xs) {
                    Text(conversation.lastMessagePreview ?? defaultPreview)
                        .font(AegisType.callout)
                        .foregroundStyle(AegisColors.textSecondary)
                        .lineLimit(1)

                    Spacer(minLength: AegisLayout.s)

                    if conversation.unreadCount > 0 {
                        Text("\(min(conversation.unreadCount, 99))")
                            .font(AegisType.captionStrong)
                            .foregroundStyle(AegisColors.textOnAccent)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2)
                            .background(AegisColors.accent)
                            .clipShape(Capsule())
                            .accessibilityLabel("\(conversation.unreadCount) unread messages")
                    }
                }
            }
        }
        .padding(.vertical, AegisLayout.xs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(conversation.title)\(unreadSuffix), \(conversation.lastMessagePreview ?? defaultPreview)")
    }

    /// Spoken unread count for the row's VoiceOver label; empty when none.
    private var unreadSuffix: String {
        conversation.unreadCount > 0 ? ", \(conversation.unreadCount) unread" : ""
    }

    private var defaultPreview: String {
        switch conversation.kind {
        case .direct: return "Say hello — messages are end-to-end encrypted."
        case .group: return "Group created"
        case .channel: return "Channel created"
        case .vault: return "Private vault — device only"
        }
    }

    @ViewBuilder
    private var avatar: some View {
        switch conversation.kind {
        case .direct:
            if let contact {
                AvatarView(
                    displayName: contact.displayName,
                    hue: contact.avatarHue,
                    size: AegisLayout.avatarM,
                    verification: contact.verification == .verified ? .verified : nil
                )
            } else {
                AvatarView(displayName: conversation.title, size: AegisLayout.avatarM)
            }
        case .group, .channel, .vault:
            GroupAvatarView(kind: conversation.kind, size: AegisLayout.avatarM)
        }
    }
}

#Preview {
    List {
        ConversationRowView(
            conversation: SampleData.previewConversation(title: "Maya Chen"),
            contact: SampleData.previewContact(name: "Maya Chen")
        )
        ConversationRowView(
            conversation: SampleData.previewConversation(title: "Design sync"),
            contact: nil
        )
        ConversationRowView(
            conversation: SampleData.previewConversation(title: "Announcements"),
            contact: nil
        )
    }
}
