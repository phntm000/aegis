import AegisModeration
import Foundation

/// Permission matrix + slow mode editor for one group/channel. Every toggle
/// is a signed group event: the transport replicates it to members and
/// appends it to the hash-chained audit log. Only owners/admins can edit.
@MainActor
final class ChannelPermissionsViewModel: ObservableObject {
    @Published private(set) var snapshot: ChannelModerationSnapshot?
    @Published private(set) var isLoading = true
    @Published var error: String?
    @Published var isWorking = false

    private let conversation: Conversation
    private let appState: AppState

    private var transport: any TransportService { appState.transport }

    init(conversation: Conversation, appState: AppState) {
        self.conversation = conversation
        self.appState = appState
    }

    var canEdit: Bool { (snapshot?.myRole ?? conversation.myRole)?.canModerate ?? false }
    var channelName: String { conversation.title }
    var isChannel: Bool { conversation.kind == .channel }

    /// Roles shown in the matrix. Owners always have every permission, so
    /// they are listed for reference but not editable.
    var editableRoles: [MemberRole] { [.admin, .moderator, .member, .guest] }

    func load() async {
        isLoading = true
        error = nil
        defer { isLoading = false }
        snapshot = await transport.channelModerationSnapshot(conversationID: conversation.id)
        if snapshot == nil {
            error = "Couldn't load channel permissions."
        }
    }

    func grants(for role: MemberRole) -> Set<GroupPermission> {
        guard let policy = snapshot?.policy else {
            return PermissionEvaluator.defaultGrants(for: role.moderationRole)
        }
        return PermissionEvaluator.grants(for: role.moderationRole, in: policy)
    }

    func isOverridden(_ role: MemberRole) -> Bool {
        snapshot?.policy.overrides[role.moderationRole] != nil
    }

    func setPermission(_ permission: GroupPermission, granted: Bool, for role: MemberRole) async {
        guard canEdit else { return }
        // Optimistic UI: the control message round-trips; rollback on error.
        let previous = grants(for: role)
        applyLocal(permission: permission, granted: granted, for: role)
        do {
            try await transport.setChannelPermission(
                permission, granted: granted, for: role, conversationID: conversation.id
            )
            await load()
            Haptics.selection()
        } catch {
            applyLocalSet(previous, for: role)
            self.error = error.localizedDescription
        }
    }

    func resetPermissions(for role: MemberRole) async {
        guard canEdit else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.resetChannelPermissions(for: role, conversationID: conversation.id)
            await load()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func setSlowMode(_ interval: TimeInterval?) async {
        guard canEdit else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            try await transport.setSlowMode(interval, conversationID: conversation.id)
            await load()
            Haptics.notification(.success)
        } catch {
            self.error = error.localizedDescription
        }
    }

    var slowModeInterval: TimeInterval? { snapshot?.policy.slowModeInterval }

    var auditEvents: [SignedGroupEvent] { snapshot?.auditEvents ?? [] }
    var auditVerification: AuditVerification? { snapshot?.auditVerification }

    /// Builds a JSON export of the audit log for sharing. Exporting
    /// requires an admin role and is itself audit-logged (turtles, but
    /// honest, all the way down).
    func makeAuditExport() -> URL? {
        guard canEdit, let snapshot else { return nil }
        struct Export: Codable {
            var exportedAt: Date
            var channelName: String
            var events: [SignedGroupEvent]
        }
        let export = Export(
            exportedAt: Date(), channelName: channelName, events: snapshot.auditEvents
        )
        guard let data = try? JSONEncoder().encode(export) else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("aegis-audit-log-\(conversation.id.uuidString).json")
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            return nil
        }
        return url
    }

    /// Notes the export in the audit log, then refreshes so the export
    /// entry itself appears.
    func noteAuditExported() async {
        await transport.noteLocalAuditEvent(
            kind: .auditExported, conversationID: conversation.id, detail: "Audit log exported."
        )
        await load()
    }

    // MARK: - Private

    private func applyLocal(permission: GroupPermission, granted: Bool, for role: MemberRole) {
        guard let current = snapshot else { return }
        var policy = current.policy
        var grants = policy.overrides[role.moderationRole]
            ?? PermissionEvaluator.defaultGrants(for: role.moderationRole)
        if granted { grants.insert(permission) } else { grants.remove(permission) }
        policy.overrides[role.moderationRole] = grants
        snapshot = ChannelModerationSnapshot(
            policy: policy,
            auditEvents: current.auditEvents,
            auditVerification: current.auditVerification,
            myRole: current.myRole,
            inviteGeneration: current.inviteGeneration
        )
    }

    private func applyLocalSet(_ grants: Set<GroupPermission>, for role: MemberRole) {
        guard let current = snapshot else { return }
        var policy = current.policy
        policy.overrides[role.moderationRole] = grants
        snapshot = ChannelModerationSnapshot(
            policy: policy,
            auditEvents: current.auditEvents,
            auditVerification: current.auditVerification,
            myRole: current.myRole,
            inviteGeneration: current.inviteGeneration
        )
    }
}
