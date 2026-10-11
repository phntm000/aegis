import AegisModeration
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
    /// Pending join requests for this group/channel (moderators only).
    @Published private(set) var joinRequests: [JoinRequest] = []

    private(set) var conversation: Conversation
    private let appState: AppState
    // NSObjectProtocol isn't Sendable; deinit is nonisolated. The token is only
    // ever touched on the main actor (or in deinit), so this is safe.
    nonisolated(unsafe) private var groupEventObserver: NSObjectProtocol?
    nonisolated(unsafe) private var joinRequestObserver: NSObjectProtocol?

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
        if let observer = joinRequestObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var myRole: MemberRole? { conversation.myRole }
    var canModerate: Bool { myRole?.canModerate ?? false }
    /// Day-to-day moderation (remove members, approve join requests):
    /// owners, admins, and moderators.
    var canManageMembers: Bool { myRole?.canModerateMembers ?? false }
    var isChannel: Bool { conversation.kind == .channel }
    /// The channel's moderation snapshot (policy, audit log). Loaded lazily
    /// for the permissions UI.
    @Published private(set) var moderation: ChannelModerationSnapshot?

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
            let conversationID = conversation.id
            groupEventObserver = NotificationCenter.default.addObserver(
                forName: .aegisGroupEvent,
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self,
                      let event = note.object as? GroupEvent,
                      event.conversationID == conversationID
                else { return }
                Task { @MainActor in await self.applyGroupEvent(event) }
            }
            if joinRequestObserver == nil { // stop() above cleared it; re-add once
                joinRequestObserver = NotificationCenter.default.addObserver(
                    forName: .aegisJoinRequest,
                    object: nil,
                    queue: .main
                ) { [weak self] _ in
                    guard let self else { return }
                    Task { @MainActor in self.refreshJoinRequests() }
                }
            }
            refreshJoinRequests()
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
        if let observer = joinRequestObserver {
            NotificationCenter.default.removeObserver(observer)
            joinRequestObserver = nil
        }
    }

    private func refreshJoinRequests() {
        joinRequests = appState.joinRequests(for: conversation.id)
    }

    /// Approves a join request: the requester becomes a contact and is
    /// invited with a real invite + sender-key distributions. Moderators
    /// may approve; only owners/admins manage roles.
    func approveJoinRequest(_ request: JoinRequest) async {
        guard canManageMembers else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await appState.approveJoinRequest(request)
            refreshJoinRequests()
            try? await refreshRoster()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func declineJoinRequest(_ request: JoinRequest) {
        appState.declineJoinRequest(request)
        refreshJoinRequests()
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
        case .slowModeChanged, .permissionsChanged:
            await refreshModeration()
        }
    }

    private func refreshRoster() async throws {
        let contacts = try await store.fetchContacts()
        // Role truth comes from the membership table (updated by inbound
        // group control messages and invites) — never hardcoded.
        let roles = (try? await store.fetchMembershipRoles(conversationID: conversation.id)) ?? [:]
        let crypto = appState.crypto
        // Fingerprint hex → contact, for name resolution.
        var contactByFingerprint: [String: Contact] = [:]
        contactByFingerprint.reserveCapacity(contacts.count)
        for contact in contacts {
            contactByFingerprint[crypto.fingerprint(of: contact.identityKey)] = contact
        }
        var members: [GroupMember] = []
        members.reserveCapacity(roles.count)
        let localFingerprintHex: String?
        if let me = try? await appState.crypto.loadIdentity() {
            localFingerprintHex = crypto.fingerprint(of: me.publicKey)
        } else {
            localFingerprintHex = nil
        }
        for (fingerprintHex, role) in roles {
            if let contact = contactByFingerprint[fingerprintHex] {
                let isMe = fingerprintHex == localFingerprintHex
                members.append(GroupMember(
                    id: contact.id,
                    displayName: isMe ? "\(contact.displayName) (you)" : contact.displayName,
                    role: isMe ? (conversation.myRole ?? role) : role,
                    joinedAt: contact.addedAt,
                    fingerprintHex: fingerprintHex
                ))
            } else if fingerprintHex != localFingerprintHex {
                // Member with no contact row yet (e.g. invited by someone
                // else): show a fingerprint suffix until they are added.
                members.append(GroupMember(
                    id: UUID(),
                    displayName: "···" + fingerprintHex.suffix(8),
                    role: role,
                    joinedAt: Date(),
                    fingerprintHex: fingerprintHex
                ))
            }
        }
        // Stable order: owners, admins, then members, alphabetically.
        members.sort {
            if $0.role != $1.role { return roleRank($0.role) < roleRank($1.role) }
            return $0.displayName < $1.displayName
        }
        info = GroupInfo(
            conversationID: conversation.id,
            description: conversation.subtitle,
            members: members,
            inviteCode: info?.inviteCode,
            senderKeyStatus: conversation.senderKeyStatus
        )
    }

    private func roleRank(_ role: MemberRole) -> Int {
        switch role {
        case .owner: return 0
        case .admin: return 1
        case .moderator: return 2
        case .member: return 3
        case .guest: return 4
        }
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
        guard canManageMembers else { return }
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

    /// Transfers ownership to another member. The current owner becomes an
    /// admin. Destructive + irreversible — the UI confirms first.
    func transferOwnership(to member: GroupMember) async {
        guard myRole == .owner else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.transferOwnership(to: member.id, conversationID: conversation.id)
            var updated = conversation
            updated.myRole = .admin
            try await store.saveConversation(updated)
            conversation = updated
            try? await refreshRoster()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Revokes the active invite: already-issued codes stop working.
    /// Destructive — the UI confirms first.
    func revokeInvite() async {
        guard canModerate else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.revokeInvite(conversationID: conversation.id)
            info?.inviteCode = nil
            await refreshModeration()
            Haptics.notification(.success)
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
            // The invite encodes the group id + generation + our identity
            // for the join flow. The generation is the revocation mechanism:
            // revokeInvite() bumps it, and older codes stop redeeming.
            await refreshModeration()
            let generation = moderation?.inviteGeneration ?? 0
            let identity = try await appState.crypto.loadIdentity()
            let code = try await appState.crypto.inviteCode(for: identity)
            info?.inviteCode = "aegis-group:\(conversation.id.uuidString):\(generation):\(code)"
            await transport.noteLocalAuditEvent(
                kind: .inviteIssued, conversationID: conversation.id, detail: "Invite generated."
            )
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Loads the channel's moderation snapshot (permission policy, slow
    /// mode, audit log) for the permissions UI.
    func refreshModeration() async {
        moderation = await transport.channelModerationSnapshot(conversationID: conversation.id)
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
    /// Posted when a group/channel join request arrives or the pending
    /// list changes. `object` is the `JoinRequest` for arrivals, nil for
    /// list changes (approve/decline).
    static let aegisJoinRequest = Notification.Name("aegis.joinRequest")
    /// Posted when the message-requests inbox changes (new request,
    /// accept, block). `object` is nil; observers re-read
    /// `AppState.messageRequests`.
    static let aegisMessageRequests = Notification.Name("aegis.messageRequests")
}
