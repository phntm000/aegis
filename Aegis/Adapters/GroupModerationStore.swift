import AegisModeration
import Foundation

// MARK: - GroupModerationStore
//
// Per-conversation moderation state owned by AegisCore: the signed channel
// permission policy, the slow-mode enforcer, the invite generation counter,
// and the hash-chained audit log. Persisted as one JSON file per
// conversation under Application Support/AegisModeration (mirroring
// ConversationSidecarStore). The device is trusted; the network is not —
// this state is the local replica of the signed group state, reconciled
// with peers through signed group control messages.

/// All moderation state for one group/channel conversation.
struct ModeratedChannelState: Codable, Sendable {
    var policy: ChannelPermissionPolicy
    var slowMode: SlowModeEnforcer
    /// Incremented by every invite revocation; invites embed the
    /// generation they were issued at, so revoked codes are recognizable.
    var inviteGeneration: Int
    var auditLog: GroupAuditLog

    init(
        policy: ChannelPermissionPolicy = .default(),
        slowMode: SlowModeEnforcer = SlowModeEnforcer(),
        inviteGeneration: Int = 0,
        auditLog: GroupAuditLog = GroupAuditLog()
    ) {
        self.policy = policy
        self.slowMode = slowMode
        self.inviteGeneration = inviteGeneration
        self.auditLog = auditLog
    }
}

actor GroupModerationStore {
    private let directory: URL
    private var cache: [UUID: ModeratedChannelState] = [:]

    init() throws {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        directory = base.appendingPathComponent("AegisModeration", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func url(for id: UUID) -> URL {
        directory.appendingPathComponent(id.uuidString).appendingPathExtension("json")
    }

    /// Loads the state, returning defaults for a conversation with no
    /// stored moderation state yet.
    func load(id: UUID) -> ModeratedChannelState {
        if let cached = cache[id] { return cached }
        let state: ModeratedChannelState
        if let data = try? Data(contentsOf: url(for: id)),
           let decoded = try? JSONDecoder().decode(ModeratedChannelState.self, from: data)
        {
            state = decoded
        } else {
            state = ModeratedChannelState()
        }
        cache[id] = state
        return state
    }

    func save(id: UUID, state: ModeratedChannelState) throws {
        cache[id] = state
        let data = try JSONEncoder().encode(state)
        try data.write(to: url(for: id), options: .atomic)
    }

    /// Loads, mutates, and persists in one step.
    func mutate(id: UUID, apply: (inout ModeratedChannelState) -> Void) throws {
        var state = load(id: id)
        apply(&state)
        try save(id: id, state: state)
    }

    func delete(id: UUID) {
        cache.removeValue(forKey: id)
        try? FileManager.default.removeItem(at: url(for: id))
    }
}
