import AegisModeration
import AegisTransport
import Foundation

// MARK: - TransportService
//
// What the app needs from the AegisTransport package.
//
// The transport owns: peer discovery (LAN mDNS + relay WebSocket), envelope
// delivery, encrypted blob upload/download, call signaling + WebRTC media, and
// group membership operations. It never sees plaintext — envelopes carry only
// ciphertext produced by AegisCrypto.

enum EnvelopeKind: String, Sendable, Codable {
    case message
    case reaction
    case edit
    case delete
    case readReceipt
    case typing
    case screenshotNotice
    case callSignal
    case groupControl
}

/// Ciphertext headed to the network.
struct OutgoingEnvelope: Sendable, Hashable {
    let id: UUID
    let conversationID: UUID
    let ciphertext: Data
    let kind: EnvelopeKind
}

/// A message the transport layer already decrypted (unknown-sender prekey
/// rendezvous): the app must use `plaintext`/`senderIdentity` directly and
/// MUST NOT decrypt `ciphertext` again (the prekey was consumed).
struct PreDecryptedEnvelope: Sendable, Hashable {
    let plaintext: Data
    /// Serialized `IdentityPublic` of the X3DH-authenticated sender.
    let senderIdentity: Data
    /// When the sender hinted a previous identity the recipient knows
    /// (identity rotation), the superseded fingerprint. The app links this
    /// message to that contact's conversation and shows the identity-change
    /// warning. Untrusted metadata — verification is still out-of-band.
    let supersedesFingerprint: Data?
}

/// Ciphertext arrived from the network, awaiting decryption by AegisCrypto.
struct IncomingEnvelope: Sendable, Hashable {
    let id: UUID
    let conversationID: UUID
    let senderKey: Data
    let ciphertext: Data
    let receivedAt: Date
    let kind: EnvelopeKind
    /// Set only for the unknown-sender rendezvous path (see above).
    /// When non-nil, `ciphertext` is empty and the app must use this.
    let preDecrypted: PreDecryptedEnvelope?

    init(
        id: UUID,
        conversationID: UUID,
        senderKey: Data,
        ciphertext: Data,
        receivedAt: Date,
        kind: EnvelopeKind,
        preDecrypted: PreDecryptedEnvelope? = nil
    ) {
        self.id = id
        self.conversationID = conversationID
        self.senderKey = senderKey
        self.ciphertext = ciphertext
        self.receivedAt = receivedAt
        self.kind = kind
        self.preDecrypted = preDecrypted
    }
}

struct RelayConfig: Sendable, Codable, Hashable {
    enum Mode: String, Sendable, Codable {
        /// Try LAN first, fall back to the last verified relay (if any).
        /// With no verified relay this is honest local-network operation —
        /// it never invents an endpoint.
        case automatic
        /// Never touch the internet; LAN peers only. Bannered in the UI.
        case lanOnly
        /// A self-hosted relay. 100% free, user-operated.
        case customRelay
    }

    var mode: Mode
    var customRelayURL: String?

    static let `default` = RelayConfig(mode: .automatic, customRelayURL: nil)
}

struct RelayTestResult: Sendable, Hashable {
    let reachable: Bool
    let latencyMs: Int?
    let detail: String
}

/// A live-call state transition pushed by the transport's signaling layer.
struct CallStateEvent: Sendable, Hashable {
    let callID: UUID
    let state: ActiveCallState
    /// ZRTP-style Short Authentication String for the call, computed from
    /// both sides' DTLS fingerprints. Non-nil only once both fingerprints
    /// are known; nil means no verification ceremony should be shown.
    let sas: String?

    init(callID: UUID, state: ActiveCallState, sas: String? = nil) {
        self.callID = callID
        self.state = state
        self.sas = sas
    }
}

/// A live group/channel membership change, translated by the transport
/// adapter from the verified wire event into app concepts.
struct GroupEvent: Sendable, Hashable {
    enum Kind: String, Sendable, Codable {
        case memberJoined
        case memberRemoved
        case roleChanged
        case topicChanged
        case announcementModeChanged
        case slowModeChanged
        case permissionsChanged
    }

    let conversationID: UUID
    let kind: Kind
    /// Identity fingerprint for member-scoped events.
    let memberKey: Data?
    /// New role for memberJoined / roleChanged.
    let role: MemberRole?
    /// New topic for topicChanged (nil = cleared).
    let topic: String?
    /// New value for announcementModeChanged.
    let announcementOnly: Bool?
    /// New slow-mode interval for slowModeChanged (nil = off).
    let slowModeInterval: TimeInterval?

    init(
        conversationID: UUID,
        kind: Kind,
        memberKey: Data? = nil,
        role: MemberRole? = nil,
        topic: String? = nil,
        announcementOnly: Bool? = nil,
        slowModeInterval: TimeInterval? = nil
    ) {
        self.conversationID = conversationID
        self.kind = kind
        self.memberKey = memberKey
        self.role = role
        self.topic = topic
        self.announcementOnly = announcementOnly
        self.slowModeInterval = slowModeInterval
    }
}

/// A point-in-time view of a channel's moderation state for the settings UI:
/// the signed permission policy, the hash-chained audit log, and its
/// verification result.
struct ChannelModerationSnapshot: Sendable {
    /// The channel's permission policy (signed group state).
    let policy: ChannelPermissionPolicy
    /// The per-group audit log, newest last.
    let auditEvents: [SignedGroupEvent]
    /// Verification of the audit chain against the roster's keys.
    let auditVerification: AuditVerification
    /// Our role, for gating which controls are shown.
    let myRole: MemberRole?
    /// Current invite generation: invites embed the generation they were
    /// issued at; the UI stamps new invites with this.
    let inviteGeneration: Int

    init(
        policy: ChannelPermissionPolicy,
        auditEvents: [SignedGroupEvent],
        auditVerification: AuditVerification,
        myRole: MemberRole?,
        inviteGeneration: Int = 0
    ) {
        self.policy = policy
        self.auditEvents = auditEvents
        self.auditVerification = auditVerification
        self.myRole = myRole
        self.inviteGeneration = inviteGeneration
    }
}

/// A pending request to join a group/channel, received after someone
/// redeemed an `aegis-group:` invite code. The requester is NOT a member
/// yet — nothing is decrypted for them and they appear nowhere until a
/// moderator approves.
struct JoinRequest: Sendable, Hashable, Identifiable {
    let id: UUID
    /// The group/channel conversation the request targets.
    let conversationID: UUID
    /// The requester's 32-byte identity fingerprint.
    let requesterFingerprint: Data
    let requesterName: String
    let receivedAt: Date
    /// The invite generation the requester's code was issued at (nil for
    /// legacy codes, which predate revocation and are always honored).
    let inviteGeneration: Int?

    init(
        id: UUID = UUID(),
        conversationID: UUID,
        requesterFingerprint: Data,
        requesterName: String,
        receivedAt: Date = Date(),
        inviteGeneration: Int? = nil
    ) {
        self.id = id
        self.conversationID = conversationID
        self.requesterFingerprint = requesterFingerprint
        self.requesterName = requesterName
        self.receivedAt = receivedAt
        self.inviteGeneration = inviteGeneration
    }
}

/// Identity-change state for a 1:1 conversation: the peer's authenticated
/// messages now come from `newFingerprint`, which differs from the contact's
/// stored (verified) key. While set, the app shows the "safety number
/// changed" banner and pauses display of new peer messages until the user
/// re-verifies (adopting the new key) or explicitly dismisses.
struct PendingIdentityChange: Sendable, Hashable, Codable {
    /// Fingerprint of the previously verified identity.
    let previousFingerprint: Data
    /// Fingerprint of the new, not-yet-verified identity.
    let newFingerprint: Data
    /// Full serialized `IdentityPublic` of the new identity (for the
    /// re-verification UI).
    let newIdentityKey: Data
    let detectedAt: Date
    /// The user explicitly dismissed the banner: held messages are shown,
    /// but the contact stays flagged until re-verified.
    var dismissed: Bool = false
}

protocol TransportService: Sendable {
    // MARK: Event streams

    var connectionEvents: AsyncStream<ConnectionState> { get }
    var incomingEnvelopes: AsyncStream<IncomingEnvelope> { get }
    var incomingCallEvents: AsyncStream<IncomingCall> { get }
    var callStateEvents: AsyncStream<CallStateEvent> { get }
    /// Verified group membership changes (member join/remove, role, topic,
    /// announcement mode). Powers live roster updates in GroupDetailView.
    var groupEvents: AsyncStream<GroupEvent> { get }

    // MARK: Connectivity

    func currentConnectionState() async -> ConnectionState
    func configureRelay(_ config: RelayConfig) async throws
    func currentRelayConfig() async -> RelayConfig
    func retryConnection() async
    /// Probe a relay URL from settings; never blocks the UI.
    func testRelay(url: String) async -> RelayTestResult
    /// The relay URL the current mode resolved to, if any. Nil means no relay
    /// is in use (local-network operation).
    func effectiveRelayURL() async -> String?
    /// Latest health assessment of the effective relay. Nil when no relay is
    /// configured.
    func relayHealth() async -> RelayHealth?

    // MARK: Messaging

    func sendEnvelope(_ envelope: OutgoingEnvelope) async throws
    func sendTypingIndicator(conversationID: UUID, isTyping: Bool) async throws
    func sendReadReceipt(conversationID: UUID, messageIDs: [UUID]) async throws
    /// Notify peers that the local user took a screenshot (opt-in setting).
    func sendScreenshotNotice(conversationID: UUID) async throws

    // MARK: Encrypted blobs (ciphertext only on the wire)

    /// Upload; the returned stream reports 0...1 progress and finishes on completion.
    func uploadBlob(from fileURL: URL, conversationID: UUID, id: UUID) -> AsyncStream<Double>
    func downloadBlob(locator: String, id: UUID, to fileURL: URL) -> AsyncStream<Double>
    /// Locator string to store with the attachment so recipients can fetch
    /// the blob. Format: `<routing-mailbox hex>:<attachment UUID hex>`.
    func blobLocator(attachmentID: UUID, conversationID: UUID) async throws -> String

    // MARK: Calls (signaling + media owned by the transport)

    /// Returns the new call id. Throws when the peer is unreachable.
    func placeCall(to contactID: UUID, kind: CallKind) async throws -> UUID
    func answerCall(_ callID: UUID) async throws
    func declineCall(_ callID: UUID) async throws
    func endCall(_ callID: UUID) async throws
    func setCallMuted(_ muted: Bool, callID: UUID) async throws
    func setCallVideoEnabled(_ enabled: Bool, callID: UUID) async throws
    func setCallSpeaker(_ enabled: Bool, callID: UUID) async throws
    func startScreenShare(callID: UUID) async throws
    func stopScreenShare(callID: UUID) async throws
    /// False on platforms/transports without a capture pipeline; the UI then
    /// explains instead of showing a dead button.
    var screenShareSupported: Bool { get }
    /// Register the view that renders decoded remote video frames for a
    /// call (see AegisTransport.CallMediaRouter / VideoSink). Pass nil to
    /// unregister. Dropped silently when the call has no media pipeline.
    func setVideoSink(_ sink: (any VideoSink)?, for callID: UUID)

    // MARK: Groups & channels

    func createGroup(name: String, memberKeys: [Data]) async throws -> UUID
    func createChannel(name: String, topic: String?, announcementOnly: Bool) async throws -> UUID
    func inviteMember(_ contactID: UUID, to conversationID: UUID) async throws
    func removeMember(_ contactID: UUID, from conversationID: UUID) async throws
    func setMemberRole(_ contactID: UUID, role: MemberRole, in conversationID: UUID) async throws
    func setAnnouncementOnly(_ enabled: Bool, conversationID: UUID) async throws
    func setGroupTopic(_ topic: String?, conversationID: UUID) async throws
    /// Sets the channel's slow-mode interval (nil = off). Valid range is
    /// 5s…6h; values outside are clamped. Owner/admin only. The change is
    /// a signed group event, replicated to members and audit-logged.
    func setSlowMode(_ interval: TimeInterval?, conversationID: UUID) async throws
    /// Grants or revokes one permission for one role in this channel only
    /// (a channel override on top of the role default). Owner/admin only.
    /// Signed group event, replicated + audit-logged.
    func setChannelPermission(
        _ permission: GroupPermission,
        granted: Bool,
        for role: MemberRole,
        conversationID: UUID
    ) async throws
    /// Clears a role's channel override, restoring role defaults.
    /// Owner/admin only. Signed group event, replicated + audit-logged.
    func resetChannelPermissions(for role: MemberRole, conversationID: UUID) async throws
    /// Revokes the group's active invite: the current invite code stops
    /// working immediately. Owner/admin only. Signed + audit-logged.
    func revokeInvite(conversationID: UUID) async throws
    /// Transfers ownership to another member; the current owner becomes an
    /// admin. Only the owner can do this. Signed + audit-logged.
    func transferOwnership(to contactID: UUID, conversationID: UUID) async throws
    /// Suppresses presence signals (read receipts, typing indicators)
    /// for a conversation. Used by the message-requests inbox: unknown
    /// senders get no receipts/typing/online status until accepted, and
    /// blocked contacts never get them.
    func setPresenceSuppressed(_ suppressed: Bool, conversationID: UUID) async
    /// The channel's current moderation snapshot for the settings UI.
    func channelModerationSnapshot(conversationID: UUID) async -> ChannelModerationSnapshot?
    /// Records a local-only signed audit entry (no replication to peers):
    /// invite issued, join request declined, audit log exported. The entry
    /// still chains into the local log and verifies like any other.
    func noteLocalAuditEvent(kind: GroupAdminEventKind, conversationID: UUID, detail: String?) async
    func rotateSenderKey(conversationID: UUID) async throws
    func leaveConversation(_ conversationID: UUID) async throws
    /// Redeems an `aegis-group:` invite code: establishes a 1:1 session
    /// with the inviter from the embedded prekey bundle and sends a join
    /// request. The requester becomes a member only after a moderator
    /// approves (see `approveJoinRequest`).
    func requestGroupJoin(code: String) async throws
    /// Approves a pending join request: ensures the requester is a contact
    /// and runs the normal invite flow (real invite + sender-key
    /// distributions). Throws when the local user is not a moderator.
    func approveJoinRequest(_ request: JoinRequest) async throws

    // MARK: Identity-change tracking

    /// Records that a 1:1 conversation's peer presented a new identity.
    /// Also repoints the conversation's routing to the new identity so
    /// replies use the fresh session. The app shows the "safety number
    /// changed" banner and pauses display of new peer messages until
    /// `resolveIdentityChange` is called.
    func noteIdentityChange(_ change: PendingIdentityChange, conversationID: UUID) async
    /// Clears the identity-change state. `adoptNewKey=true` keeps the new
    /// identity as the peer (the contact record was already updated);
    /// `false` repoints routing back to the previous identity.
    func resolveIdentityChange(conversationID: UUID, adoptNewKey: Bool) async
    /// Current identity-change state for a conversation, if any.
    func pendingIdentityChange(for conversationID: UUID) async -> PendingIdentityChange?
}
