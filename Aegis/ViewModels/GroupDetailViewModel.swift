import Foundation

/// Group / channel detail: members, roles, invite, topic, announcement mode,
/// and sender-key session health. Every moderation control is wired to the
/// transport's group operations.
@MainActor
final class GroupDetailViewModel: ObservableObject {
    @Published private(set) var info: GroupInfo?
    @Published private(set) var isLoading = true
    @Published var error: String?
    @Published var isWorking = false

    private(set) var conversation: Conversation
    private let appState: AppState
    private var groupEventObserver: NSObjectProtocol?

    private var transport: any TransportService { appState.transport }
    private var store: any StoreService { appState.store }

    init(conversation: Conversation, appState: AppState) {
        self.conversation = conversation
        self.appState = appState
    }

    deinit {
        if let observer = groupEventObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var myRole: MemberRole? { conversation.myRole }
    var canModerate: Bool { myRole?.canModerate ?? false }
    var isChannel: Bool { conversation.kind == .channel }

    func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        do {
            try await refreshRoster()
            // Live roster updates: AppState re-broadcasts the transport's
            // verified group events on NotificationCenter (see below).
            // Re-entrant: drop any previous observer first.
            stop()
            groupEventObserver = NotificationCenter.default.addObserver(
                forName: .aegisGroupEvent,
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self,
                      let event = note.object as? GroupEvent,
                      event.conversationID == self.conversation.id
                else { return }
                Task { @MainActor in await self.applyGroupEvent(event) }
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Stops live roster updates. Called by the view on disappear.
    func stop() {
        if let observer = groupEventObserver {
            NotificationCenter.default.removeObserver(observer)
            groupEventObserver = nil
        }
    }

    private func applyGroupEvent(_ event: GroupEvent) async {
        switch event.kind {
        case .memberJoined, .memberRemoved, .roleChanged:
            try? await refreshRoster()
        case .topicChanged:
            conversation.subtitle = event.topic
            info?.description = event.topic
        case .announcementModeChanged:
            if let value = event.announcementOnly {
                var updated = conversation
                updated.isAnnouncementOnly = value
                conversation = updated
            }
        }
    }

    private func refreshRoster() async throws {
        let contacts = try await store.fetchContacts()
        let me = try? await appState.crypto.loadIdentity()
        var members = conversation.memberIDs.compactMap { id -> GroupMember? in
            guard let contact = contacts.first(where: { $0.id == id }) else { return nil }
            // Role truth comes from the transport in production; the
            // conversation snapshot carries our own role.
            let role: MemberRole = (id == conversation.memberIDs.first) ? .owner : .member
            return GroupMember(id: id, displayName: contact.displayName, role: role, joinedAt: contact.addedAt)
        }
        if let me {
            // Ensure the local user appears in the roster.
            if !members.contains(where: { $0.displayName == me.displayName }) {
                members.insert(
                    GroupMember(id: me.id, displayName: "\(me.displayName) (you)",
                                role: conversation.myRole ?? .member, joinedAt: me.createdAt),
                    at: 0
                )
            }
        }
        info = GroupInfo(
            conversationID: conversation.id,
            description: conversation.subtitle,
            members: members,
            inviteCode: nil,
            senderKeyStatus: conversation.senderKeyStatus
        )
    }

    // MARK: - Moderation

    func setRole(_ member: GroupMember, role: MemberRole) async {
        guard canModerate, member.role != role else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.setMemberRole(member.id, role: role, in: conversation.id)
            updateMember(member.id) { $0.role = role }
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func removeMember(_ member: GroupMember) async {
        guard canModerate else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.removeMember(member.id, from: conversation.id)
            info?.members.removeAll { $0.id == member.id }
            Haptics.impact(.medium)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func setAnnouncementOnly(_ enabled: Bool) async {
        guard canModerate else { return }
        do {
            try await transport.setAnnouncementOnly(enabled, conversationID: conversation.id)
            var updated = conversation
            updated.isAnnouncementOnly = enabled
            try await store.saveConversation(updated)
            conversation = updated
            Haptics.selection()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func setTopic(_ topic: String?) async {
        guard canModerate else { return }
        let trimmed = topic?.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            try await transport.setGroupTopic(trimmed?.isEmpty == true ? nil : trimmed, conversationID: conversation.id)
            var updated = conversation
            updated.subtitle = trimmed?.isEmpty == true ? nil : trimmed
            try await store.saveConversation(updated)
            conversation = updated
            info?.description = updated.subtitle
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func rotateSenderKey() async {
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.rotateSenderKey(conversationID: conversation.id)
            var updated = conversation
            updated.senderKeyStatus = .refreshing
            try await store.saveConversation(updated)
            conversation = updated
            info?.senderKeyStatus = .refreshing
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func generateInvite() async {
        isWorking = true
        defer { isWorking = false }
        do {
            // The invite encodes the group id + our identity for the join flow.
            let identity = try await appState.crypto.loadIdentity()
            let code = try await appState.crypto.inviteCode(for: identity)
            info?.inviteCode = "aegis-group:\(conversation.id.uuidString):\(code)"
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Leave the group/channel. Returns true when the caller should dismiss.
    func leave() async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.leaveConversation(conversation.id)
            try await store.deleteConversation(id: conversation.id)
            return true
        } catch {
            self.error = error.localizedDescription
            return false
        }
    }

    // MARK: - Private

    private func updateMember(_ id: UUID, apply: (inout GroupMember) -> Void) {
        guard var members = info?.members,
              let idx = members.firstIndex(where: { $0.id == id }) else { return }
        apply(&members[idx])
        info?.members = members
    }
}

/// Posted by AppState (the single consumer of the transport's group-event
/// stream) for every verified group membership change. `object` is the
/// `GroupEvent`. Any number of views may observe; no stream contention.
extension Notification.Name {
    static let aegisGroupEvent = Notification.Name("aegis.groupEvent")
}
