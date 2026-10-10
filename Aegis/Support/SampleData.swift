import Foundation

/// Deterministic, tasteful sample data for Xcode previews. Fictional people,
/// realistic shapes: pinned/muted/archived chats, reactions, edits, tombstones,
/// attachments, voice notes, an identity-change warning, and call history.
enum SampleData {
    struct Seed {
        var conversations: [Conversation]
        var messages: [UUID: [Message]] // conversationID -> newest-first
        var contacts: [Contact]
        var callRecords: [CallRecord]
        var identity: LocalIdentity
        var groupInfos: [UUID: GroupInfo]
    }

    static func seed() -> Seed {
        let identity = LocalIdentity(
            id: UUID(),
            displayName: "Alex",
            publicKey: Data((0..<32).map { UInt8($0) }),
            createdAt: Date().addingTimeInterval(-90 * 86400)
        )

        let maya = Contact(
            displayName: "Maya Chen",
            identityKey: Data((0..<32).map { UInt8(100 + $0) }),
            verification: .verified,
            lastSeenAt: Date().addingTimeInterval(-300)
        )
        let jonas = Contact(
            displayName: "Jonas Weber",
            identityKey: Data((0..<32).map { UInt8(150 + $0) }),
            verification: .unverified,
            lastSeenAt: Date().addingTimeInterval(-7200)
        )
        let priya = Contact(
            displayName: "Priya Nair",
            identityKey: Data((0..<32).map { UInt8(200 + $0) }),
            verification: .verified,
            lastSeenAt: Date().addingTimeInterval(-60)
        )
        let sam = Contact(
            displayName: "Sam Okafor",
            identityKey: Data((0..<32).map { UInt8(50 + $0) }),
            verification: .identityChanged,
            lastSeenAt: Date().addingTimeInterval(-86400)
        )
        let blocked = Contact(
            displayName: "Unknown number",
            identityKey: Data((0..<32).map { UInt8(10 + $0) }),
            verification: .unverified,
            isBlocked: true
        )
        let contacts = [maya, jonas, priya, sam, blocked]

        let now = Date()

        // MARK: Conversations

        var dmMaya = Conversation(
            kind: .direct,
            title: "Maya Chen",
            memberIDs: [maya.id],
            isPinned: true,
            unreadCount: 2,
            disappearingInterval: 24 * 3600,
            lastMessagePreview: "Sending the encrypted designs now",
            lastMessageAt: now.addingTimeInterval(-120),
            lastMessageIsFromMe: false
        )
        var groupDesign = Conversation(
            kind: .group,
            title: "Design sync",
            subtitle: "Weekly critique · Thursdays",
            memberIDs: [maya.id, priya.id, jonas.id],
            myRole: .admin,
            lastMessagePreview: "Priya: The new empty states look great",
            lastMessageAt: now.addingTimeInterval(-3600),
            lastMessageIsFromMe: false
        )
        var channelAnnounce = Conversation(
            kind: .channel,
            title: "Announcements",
            subtitle: "Release notes and status",
            memberIDs: [maya.id, priya.id, jonas.id, sam.id],
            isMuted: true,
            isAnnouncementOnly: true,
            myRole: .member,
            lastMessagePreview: "v2.4 is rolling out this week",
            lastMessageAt: now.addingTimeInterval(-86400),
            lastMessageIsFromMe: false
        )
        var dmJonas = Conversation(
            kind: .direct,
            title: "Jonas Weber",
            memberIDs: [jonas.id],
            isArchived: true,
            lastMessagePreview: "Talk next week?",
            lastMessageAt: now.addingTimeInterval(-3 * 86400),
            lastMessageIsFromMe: true
        )
        let dmSam = Conversation(
            kind: .direct,
            title: "Sam Okafor",
            memberIDs: [sam.id],
            unreadCount: 1,
            lastMessagePreview: "Hey — new phone, same me",
            lastMessageAt: now.addingTimeInterval(-90000),
            lastMessageIsFromMe: false
        )
        let conversations = [dmMaya, groupDesign, channelAnnounce, dmJonas, dmSam]

        // MARK: Messages — DM with Maya (newest first)

        let m1 = Message(
            conversationID: dmMaya.id, senderID: maya.id, isFromMe: false,
            body: "Sending the encrypted designs now",
            status: .read,
            sentAt: now.addingTimeInterval(-120)
        )
        let m2 = Message(
            conversationID: dmMaya.id, senderID: identity.id, isFromMe: true,
            body: "Perfect — I'll review them on the flight. The disappearing timer is on for this chat, right?",
            status: .read,
            sentAt: now.addingTimeInterval(-300)
        )
        var m3 = Message(
            conversationID: dmMaya.id, senderID: maya.id, isFromMe: false,
            body: "Yes — 24 hours. Anything sensitive evaporates on both sides.",
            reactions: ["👍": [identity.id]],
            status: .read,
            sentAt: now.addingTimeInterval(-420)
        )
        let m4 = Message(
            conversationID: dmMaya.id, senderID: maya.id, isFromMe: false,
            body: "Also: can you double-check the safety number when we meet Thursday?",
            replyToID: m2.id,
            status: .read,
            sentAt: now.addingTimeInterval(-600)
        )
        var m5 = Message(
            conversationID: dmMaya.id, senderID: identity.id, isFromMe: true,
            body: "Will do. Bringing the QR too.",
            status: .read,
            editedAt: now.addingTimeInterval(-700),
            sentAt: now.addingTimeInterval(-780)
        )
        let m6 = Message(
            conversationID: dmMaya.id, senderID: identity.id, isFromMe: true,
            body: "Draft of the announcement — ignore this",
            status: .read,
            deletedAt: now.addingTimeInterval(-900),
            sentAt: now.addingTimeInterval(-960)
        )
        let voice = Message(
            conversationID: dmMaya.id, senderID: maya.id, isFromMe: false,
            status: .read,
            expiresAt: now.addingTimeInterval(24 * 3600 - 1500),
            voiceNote: VoiceNote(
                duration: 14,
                levels: [0.2, 0.4, 0.7, 0.5, 0.9, 0.6, 0.3, 0.8, 0.5, 0.4, 0.7, 0.6, 0.3, 0.2]
            ),
            sentAt: now.addingTimeInterval(-1500)
        )
        dmMaya.unreadCount = 2

        // MARK: Messages — Design sync group

        let g1 = Message(
            conversationID: groupDesign.id, senderID: priya.id, isFromMe: false,
            body: "The new empty states look great",
            status: .read,
            sentAt: now.addingTimeInterval(-3600)
        )
        let g2 = Message(
            conversationID: groupDesign.id, senderID: maya.id, isFromMe: false,
            body: "Agreed. Ship the checklist after lunch?",
            reactions: ["✅": [priya.id, jonas.id]],
            status: .read,
            sentAt: now.addingTimeInterval(-3900)
        )
        let g3 = Message(
            conversationID: groupDesign.id, senderID: identity.id, isFromMe: true,
            body: "Checklist is ready — sending the file",
            status: .delivered,
            attachment: Attachment(
                filename: "launch-checklist.pdf",
                mimeType: "application/pdf",
                byteCount: 184_320,
                remoteLocator: "blob-sample-1"
            ),
            sentAt: now.addingTimeInterval(-4200)
        )

        // MARK: Messages — Announcements channel

        let c1 = Message(
            conversationID: channelAnnounce.id, senderID: maya.id, isFromMe: false,
            body: "v2.4 is rolling out this week. Full changelog in the pinned message.",
            status: .read,
            sentAt: now.addingTimeInterval(-86400)
        )

        // MARK: Messages — Sam (identity changed)

        let s1 = Message(
            conversationID: dmSam.id, senderID: sam.id, isFromMe: false,
            body: "Hey — new phone, same me",
            status: .delivered,
            sentAt: now.addingTimeInterval(-90000)
        )

        let messages: [UUID: [Message]] = [
            dmMaya.id: [m1, m2, m3, m4, m5, m6, voice],
            groupDesign.id: [g1, g2, g3],
            channelAnnounce.id: [c1],
            dmSam.id: [s1],
            dmJonas.id: [],
        ]

        // MARK: Group info

        let groupInfo = GroupInfo(
            conversationID: groupDesign.id,
            description: "Weekly design critique. Be kind, be specific.",
            members: [
                GroupMember(id: maya.id, displayName: "Maya Chen", role: .owner, joinedAt: now.addingTimeInterval(-60 * 86400)),
                GroupMember(id: identity.id, displayName: "Alex (you)", role: .admin, joinedAt: now.addingTimeInterval(-60 * 86400)),
                GroupMember(id: priya.id, displayName: "Priya Nair", role: .member, joinedAt: now.addingTimeInterval(-30 * 86400)),
                GroupMember(id: jonas.id, displayName: "Jonas Weber", role: .member, joinedAt: now.addingTimeInterval(-14 * 86400)),
            ],
            inviteCode: "aegis-group-sample-invite",
            senderKeyStatus: .active
        )

        // MARK: Call history

        let calls = [
            CallRecord(
                contactID: maya.id, contactName: "Maya Chen",
                kind: .video, direction: .outgoing,
                startedAt: now.addingTimeInterval(-7200),
                duration: 754, endReason: .completed
            ),
            CallRecord(
                contactID: priya.id, contactName: "Priya Nair",
                kind: .audio, direction: .incoming,
                startedAt: now.addingTimeInterval(-86400),
                duration: 182, endReason: .completed
            ),
            CallRecord(
                contactID: jonas.id, contactName: "Jonas Weber",
                kind: .audio, direction: .incoming,
                startedAt: now.addingTimeInterval(-2 * 86400),
                duration: nil, endReason: .missed
            ),
        ]

        return Seed(
            conversations: conversations,
            messages: messages,
            contacts: contacts,
            callRecords: calls,
            identity: identity,
            groupInfos: [groupDesign.id: groupInfo]
        )
    }

    // MARK: - Convenience accessors for previews

    static var previewIdentity: LocalIdentity { seed().identity }
    static var previewContacts: [Contact] { seed().contacts }
    static var previewConversations: [Conversation] { seed().conversations }
    static var previewCallRecords: [CallRecord] { seed().callRecords }

    static func previewMessages(for title: String) -> [Message] {
        let s = seed()
        guard let conv = s.conversations.first(where: { $0.title == title }) else { return [] }
        return (s.messages[conv.id] ?? []).reversed() // oldest-first for the thread view
    }

    static func previewConversation(title: String) -> Conversation {
        seed().conversations.first(where: { $0.title == title })
            ?? seed().conversations.first
            ?? Conversation(kind: .direct, title: title)
    }

    static func previewContact(name: String) -> Contact {
        seed().contacts.first(where: { $0.displayName == name })
            ?? seed().contacts.first
            ?? Contact(displayName: name, identityKey: Data())
    }
}
