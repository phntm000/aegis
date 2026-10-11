// AegisCore — the live integration hub.
//
// The three app protocols (CryptoService, TransportService, StoreService)
// are implemented by thin adapters (LiveAdapters.swift) that all share one
// AegisCore actor. The core owns the real packages and the wiring between
// them:
//
//   CryptoEngine ── sessions/groups/sealed-sender ──┐
//   any AegisDatabase ── encrypted persistence ─────────┼──▶ AegisCore
//   TransportHub ── LAN + relay WebSocket ───────────┘
//
// Layering (see docs/INTEGRATION.md §2):
//   AegisFrame (32-byte routing mailbox) → optional SealedEnvelope (16-byte
//   identity mailbox) → RatchetMessage/PreKeyMessage/GroupMessage →
//   app payload (WirePayload JSON) or TransportControl JSON.
//
// The transport layer NEVER sees message plaintext: user messages are
// emitted as session-layer ciphertext for the app to decrypt. Transport-
// internal kinds (distributions, call signaling, group invites, group
// control) are decrypted by the core because the app has no API for them.

import AegisCrypto
import AegisModeration
import AegisStore
import AegisTransport
import CryptoKit
import Foundation
import Security

/// Errors from the transport integration hub.
enum AegisCoreError: Error, LocalizedError {
    /// The local user is not a moderator of this group/channel.
    case notModerator
    /// The local user's role lacks the granular permission for an action.
    case notPermitted(String)
    /// Slow mode blocked a send; the user may retry after the interval.
    case slowModeLimited(retryAfter: TimeInterval)
    /// A malformed invite code was presented for redemption.
    case malformedInviteCode
    /// No group conversation matches the invite's group reference.
    case unknownInviteGroup

    var errorDescription: String? {
        switch self {
        case .notModerator: return "Only admins can change group membership."
        case .notPermitted(let what): return what
        case .slowModeLimited(let retryAfter):
            return "Slow mode is on — wait \(Int(retryAfter.rounded(.up)))s before posting again."
        case .malformedInviteCode: return "That invite code isn't valid."
        case .unknownInviteGroup: return "That invite is for a group this device doesn't know."
        }
    }
}

// MARK: - Transport-internal control envelope

/// Kinds the core consumes itself. NEVER used for user messages: those
/// travel as raw WirePayload JSON so the app's decrypt path is unchanged.
/// Flagged on the wire with AegisFrame bit 2 (0x04).
struct TransportControl: Codable, Sendable {
    var v: Int = 1
    /// "callSignal" | "groupInvite" | "knock" | "sessionReset". Sender-key
    /// distributions are NOT wrapped here — they travel as
    /// encryptDirect(distribution.serialized()) and are detected by parse.
    var kind: String
    var body: Data
}

/// Group-channel inner payload (sender-key encrypted on the group mailbox).
struct GroupInnerPayload: Codable, Sendable {
    var v: Int = 1
    /// "message" | "control"
    var kind: String
    var body: Data
}

/// Wire control message for membership/role/topic/announcement changes.
/// Sent on the PRE-CHANGE mailbox (all current members are listening there)
/// and encrypted under the sender's pre-change sender key, so every member
/// — not just the changer — learns the new epoch and can adopt it.
struct GroupControlMessage: Codable, Sendable {
    var v: Int = 1
    var groupID: Data
    var epoch: UInt32
    /// "memberAdded" | "memberRemoved" | "roleChanged" | "topicChanged" |
    /// "announcementModeChanged" | "slowModeChanged" | "permissionChanged" |
    /// "inviteRevoked" | "blobRequest"
    var kind: String
    var fingerprint: Data?
    var role: String?
    var topic: String?
    var announcementOnly: Bool?
    /// Serialized `IdentityPublic` of the added member (memberAdded only).
    /// Lets every member resolve the new member's identity keys without a
    /// contact relationship — required for sender-key exchange.
    var memberIdentityKey: Data?
    /// Full roster at the new epoch (fingerprint → entry). Makes adoption
    /// idempotent and self-healing: a member that missed intermediate
    /// changes reconciles to the announcer's truth instead of forking.
    var roster: [String: GroupRosterEntry]?
    /// For "blobRequest": uploadID hex the requester is missing.
    var blobUploadID: String? = nil
    /// For "voiceRoom": JSON-encoded `VoiceRoomSignal`.
    var voiceRoomSignal: Data? = nil
    /// For "slowModeChanged": new interval in seconds (nil = off).
    var slowModeInterval: Double? = nil
    /// For "permissionChanged": permission raw value, the new grant, and
    /// the affected role's raw value. `permissionReset` clears the role's
    /// channel override back to role defaults.
    var permissionName: String? = nil
    var permissionGranted: Bool? = nil
    var permissionRole: String? = nil
    var permissionReset: Bool? = nil
    /// For moderation kinds ("slowModeChanged", "permissionChanged",
    /// "inviteRevoked", "roleChanged", …): JSON-encoded `SignedGroupEvent`
    /// replicating the actor's audit-log entry to every member.
    var auditEvent: Data? = nil
    /// For "inviteRevoked": the new invite generation. Invites embed the
    /// generation they were issued at; older generations no longer redeem.
    var inviteGeneration: Int? = nil
    /// For "memberAdded": JSON-encoded `ChannelPermissionPolicy` so the
    /// joiner adopts the current policy instead of role defaults.
    var policy: Data? = nil
}

/// One roster entry in a membership announcement.
struct GroupRosterEntry: Codable, Sendable {
    /// Serialized `IdentityPublic`.
    var identityKey: Data
    var displayName: String
    var role: String
}

/// Request to re-transmit missed blob chunks. Sent 1:1 when a peer
/// detects gaps in a chunked attachment/voice-note upload.
struct BlobRequestBody: Codable, Sendable {
    var uploadID: String
}

/// Invitation for a new group member (1:1 encrypted, alongside the sender-
/// key distribution). The member needs the roster to construct GroupSession.
struct GroupInviteInfo: Codable, Sendable {    var v: Int = 1
    var groupID: Data
    var epoch: UInt32
    var name: String
    var topic: String?
    /// Fingerprint hex → display name.
    var members: [String: String]
    /// Fingerprint hex → role string ("owner"/"admin"/"member"). Optional
    /// for wire compatibility with older invites; defaults to "member".
    /// The inviter is authoritative for the roster it sends — recipients
    /// record these roles in their membership tables.
    var roles: [String: String]?
    /// Fingerprint hex → serialized `IdentityPublic`. Lets the joiner
    /// resolve every member's identity keys for sender-key exchange without
    /// needing them as contacts. Absent on older invites, in which case the
    /// joiner falls back to resolving via its contact list.
    var memberKeys: [String: Data]?
}

/// Chunk header for blob transfers: uploadID(16) || index u32 || count u32.
struct BlobChunkHeader {
    static let size = 24

    static func encode(uploadID: Data, index: UInt32, count: UInt32) -> Data {
        var out = Data()
        out.append(uploadID)
        var i = index.bigEndian, c = count.bigEndian
        withUnsafeBytes(of: &i) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &c) { out.append(contentsOf: $0) }
        return out
    }

    static func decode(_ data: Data) -> (uploadID: Data, index: UInt32, count: UInt32)? {
        guard data.count >= size else { return nil }
        let uploadID = data.prefix(16)
        let index = data.subdata(in: 16..<20).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let count = data.subdata(in: 20..<24).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        return (Data(uploadID), index, count)
    }
}

// MARK: - Call media delegate

/// Media-layer delegate: the app's WebRTC stack plugs in here. Without it,
/// signaling still runs (knock/offer/answer/ICE/control) but SDP is empty
/// and no media flows — the honest seam for the macOS-gated WebRTC work.
protocol CallMediaDelegate: AnyObject, Sendable {
    func createOffer(for callID: UUID) async throws -> (sdp: String, dtlsFingerprint: String)
    func createAnswer(for callID: UUID, offerSDP: String) async throws -> (sdp: String, dtlsFingerprint: String)
    func setRemoteSDP(_ sdp: String, for callID: UUID) async throws
    func addIceCandidate(_ candidate: IceCandidate, for callID: UUID) async throws
}

/// Media controls surfaced to the UI. Implemented by the WebRTC engine;
/// AegisCore forwards to whichever media layer is attached.
protocol CallMediaControl: AnyObject, Sendable {
    /// Informs the engine of the call kind (audio/video) before SDP is created.
    func noteCallKind(_ kind: CallKind, for callID: UUID)
    func setMuted(_ muted: Bool, callID: UUID) async throws
    func setVideoEnabled(_ enabled: Bool, callID: UUID) async throws
    func setSpeaker(_ enabled: Bool, callID: UUID) async throws
    func startScreenShare(callID: UUID) async throws
    func stopScreenShare(callID: UUID) async throws
    var screenShareSupported: Bool { get }
    /// Tears down the peer connection and capturers for a finished call.
    func endCallMedia(_ callID: UUID)
    /// Enables/disables remote audio rendering on one peer connection
    /// (voice-room "deafen"). Does not affect the local microphone.
    func setRemoteAudioEnabled(_ enabled: Bool, for callID: UUID)
}

/// Thrown when a media control is invoked with no media engine attached.
enum CallMediaError: Error, LocalizedError {
    case engineUnavailable
    var errorDescription: String? {
        "Call media engine is unavailable."
    }
}

// MARK: - AegisCore

actor AegisCore {
    enum RouteTarget {
        case direct(fingerprint: Data)
        case group(groupID: Data, conversationID: UUID)
        /// Linked-device traffic: pairing handshake or paired channel.
        case deviceLink(channel: DeviceLinkChannel)
    }

    // MARK: Owned packages

    let engine: CryptoEngine
    let pkgStore: any AegisDatabase
    let sidecars: ConversationSidecarStore
    let keyDirectory: ContactKeyDirectory
    /// Per-conversation moderation state: permission policy, slow mode,
    /// invite generations, and the signed audit log.
    let moderation: GroupModerationStore
    /// Conversations with presence signals suppressed (message-requests
    /// inbox, blocked contacts): no read receipts or typing indicators
    /// are emitted for these.
    private var presenceSuppressedConversations: Set<UUID> = []

    // MARK: Transport

    var hub: TransportHub
    var lan: LANTransport
    var relay: RelayTransport?
    var delivery: DeliveryCoordinator
    let mediaRouter = CallMediaRouter()
    private(set) var relayConfig: RelayConfig = .default

    /// The relay URL the current mode resolved to, if any. Nil means no relay
    /// is in use (local-network operation) — never a placeholder.
    private(set) var effectiveRelayURL: String?
    /// Latest health assessment of the effective relay. Nil when no relay is
    /// configured.
    private(set) var relayHealth: RelayHealth?

    /// A relay URL that previously proved it speaks our protocol (live hello)
    /// or passed a handshake probe. The only thing automatic mode falls back
    /// to — automatic mode never invents an endpoint.
    private var lastKnownGoodRelayURL: String? {
        get { UserDefaults.standard.string(forKey: SettingsKeys.relayLastKnownGoodURL) }
        set { UserDefaults.standard.set(newValue, forKey: SettingsKeys.relayLastKnownGoodURL) }
    }

    // MARK: Routing

    /// mailbox hex → target. The relay routes on the mailbox; we resolve it
    /// to a conversation/peer without decrypting anything.
    private var routes: [String: RouteTarget] = [:]
    /// Group frames that arrived before their sender-key distribution.
    /// Retried when the distribution lands. Bounded: 50 per group.
    private var pendingGroupFrames: [String: [AegisFrame]] = [:]
    /// Sender-key distributions that arrived before the group invite that
    /// creates our session (the reverse race). Flushed by
    /// handleGroupInvite right after joining. Bounded: 16 per group.
    private var pendingDistributions: [String: [SenderKeyDistribution]] = [:]

    // MARK: Streams (adapters expose these)

    let connectionEvents: AsyncStream<ConnectionState>
    let incomingEnvelopes: AsyncStream<IncomingEnvelope>
    let incomingCallEvents: AsyncStream<IncomingCall>
    let callStateEvents: AsyncStream<CallStateEvent>
    let groupEvents: AsyncStream<GroupEvent>
    private let connectionCont: AsyncStream<ConnectionState>.Continuation
    private let envelopeCont: AsyncStream<IncomingEnvelope>.Continuation
    private let incomingCallCont: AsyncStream<IncomingCall>.Continuation
    private let callStateCont: AsyncStream<CallStateEvent>.Continuation
    private let groupCont: AsyncStream<GroupEvent>.Continuation

    // MARK: Identity

    /// Stable app-level UUID for the local identity (senderID mapping).
    let localIdentityUUID: UUID

    // MARK: Calls

    struct ActiveCallContext {
        var callID: UUID
        var conversationID: UUID
        var contactID: UUID
        var peerFingerprint: Data
        var direction: CallDirection
        /// DTLS fingerprints exchanged in signaling, for SAS computation.
        /// Empty until the media stack (or signaling) provides them.
        var localDTLSFingerprint: String = ""
        var remoteDTLSFingerprint: String = ""
        /// The inbound SDP offer, stored when the knock arrives so the
        /// media engine can answer against the real remote description.
        var remoteOfferSDP: String = ""
    }

    private var activeCalls: [UUID: ActiveCallContext] = [:]

    // MARK: Init

    init(
        engine: CryptoEngine,
        pkgStore: any AegisDatabase,
        sidecars: ConversationSidecarStore,
        keyDirectory: ContactKeyDirectory
    ) throws {
        self.engine = engine
        self.pkgStore = pkgStore
        self.sidecars = sidecars
        self.keyDirectory = keyDirectory
        self.moderation = try GroupModerationStore()

        let (cs, cc) = AsyncStream<ConnectionState>.makeStream()
        let (es, ec) = AsyncStream<IncomingEnvelope>.makeStream()
        let (is_, ic) = AsyncStream<IncomingCall>.makeStream()
        let (ss, sc) = AsyncStream<CallStateEvent>.makeStream()
        let (gs, gc) = AsyncStream<GroupEvent>.makeStream()
        self.connectionEvents = cs
        self.incomingEnvelopes = es
        self.incomingCallEvents = is_
        self.callStateEvents = ss
        self.groupEvents = gs
        self.connectionCont = cc
        self.envelopeCont = ec
        self.incomingCallCont = ic
        self.callStateCont = sc
        self.groupCont = gc

        let storedUUID = UserDefaults.standard.string(forKey: "aegis.localIdentityUUID")
        if let storedUUID, let uuid = UUID(uuidString: storedUUID) {
            self.localIdentityUUID = uuid
        } else {
            let uuid = UUID()
            UserDefaults.standard.set(uuid.uuidString, forKey: "aegis.localIdentityUUID")
            self.localIdentityUUID = uuid
        }

        self.lan = LANTransport()
        self.hub = TransportHub(transports: [lan])
        self.delivery = DeliveryCoordinator(hub: hub, lan: lan, relay: nil)

        // Self-boot: the ServiceFactory protocol has no async hook, so the
        // core starts its transports and inbound dispatch on creation. The
        // app's AppState.bootstrap() then drives relay configuration.
        self.voiceRooms = VoiceRoomManager()
        self.deviceLink = DeviceLinkManager()
        Task { [weak self] in
            guard let self else { return }
            // Cross-actor wiring must happen after init completes.
            await self.voiceRooms.setCore(self)
            await self.deviceLink.setCore(self)
            try? await self.start()
        }
    }

    // MARK: - Voice rooms

    /// The app's voice-room session manager (one active room at a time).
    let voiceRooms: VoiceRoomManager
    /// Linked-device manager (paired-device relay model).
    let deviceLink: DeviceLinkManager

    /// Media stack accessors for the voice-room manager.
    func voiceRoomMedia() -> (any CallMediaDelegate)? { mediaDelegate }
    func voiceRoomMediaControl() -> (any CallMediaControl)? {
        mediaDelegate as? any CallMediaControl
    }
    func voiceRoomLocalFingerprintHex() async -> String? {
        try? await engine.localPublicIdentity().fingerprint.hexString
    }
    func voiceRoomLocalDisplayName() async -> String {
        await engine.displayName()
    }

    /// Sends a voice-room signal on the room's group E2EE channel.
    func sendVoiceRoomSignal(_ signal: VoiceRoomSignal, conversationID: UUID) async throws {
        guard let groupID = await groupIDForConversation(conversationID) else { return }
        let message = GroupControlMessage(
            groupID: groupID,
            epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
            kind: "voiceRoom",
            voiceRoomSignal: try JSONEncoder().encode(signal)
        )
        try await sendGroupControl(
            conversationID: conversationID,
            groupID: groupID,
            message: message
        )
    }

    /// Routes one inbound voice-room signal to the room manager.
    private func handleVoiceRoomSignal(_ signal: VoiceRoomSignal) async {
        await voiceRooms.handle(signal: signal)
    }

    // MARK: - Linked devices (transport)

    /// Binds a device-link mailbox (pairing handshake or paired channel).
    func bindDeviceLinkMailbox(_ mailbox: Data, channel: DeviceLinkChannel) async {
        await bind(mailbox: mailbox, route: .deviceLink(channel: channel))
    }

    func unbindDeviceLinkMailbox(_ mailbox: Data) async {
        await unbind(mailbox: mailbox)
    }

    /// Sends one frame on a device-link mailbox. Pairing and paired-channel
    /// payloads are already encrypted by the DeviceLinkManager; the relay
    /// only sees opaque bytes on an unguessable mailbox.
    func sendDeviceLinkFrame(_ payload: Data, mailbox: Data) async throws {
        try await sendRaw(payload, mailbox: mailbox, ttl: 300, flags: 0)
    }

    // MARK: - Startup

    private var didStart = false
    private var consumeGeneration = 0

    /// Builds routes from the store, binds mailboxes, starts transports.
    /// Retried automatically until it succeeds (didStart flips only then).
    func start() async throws {
        guard !didStart else { return }
        _ = try await engine.restoreIdentity()
        // Durable sessions: the engine persists Double Ratchet snapshots to
        // the SQLCipher store (debounced writes + guaranteed flush on
        // backgrounding) and resumes them here, so existing conversations
        // continue without re-running X3DH after a restart.
        let sessionRepo = pkgStore.sessions
        await engine.configureSessionPersistence(SessionPersistence(
            save: { fingerprint, snapshot in
                try? await sessionRepo.save(fingerprint: fingerprint, snapshot: snapshot)
            },
            loadAll: {
                (try? await sessionRepo.loadAll()) ?? [:]
            },
            delete: { fingerprint in
                try? await sessionRepo.delete(fingerprint: fingerprint)
            },
            deleteAll: {
                try? await sessionRepo.deleteAll()
            }
        ))
        await engine.restoreSessions()
        // Group sender-key sessions: without this every group/channel
        // silently stopped working after an app restart.
        let groupSessionRepo = pkgStore.groupSessions
        await engine.configureGroupPersistence(CryptoEngine.GroupPersistence(
            save: { groupID, envelope in
                try? await groupSessionRepo.saveGroupSession(groupID: groupID, snapshot: envelope)
            },
            loadAll: {
                (try? await groupSessionRepo.loadAllGroupSessions()) ?? [:]
            },
            delete: { groupID in
                try? await groupSessionRepo.deleteGroupSession(groupID: groupID)
            }
        ))
        await engine.restoreGroupSessions()
        try await rebuildRoutesFromStore()
        // Resolves the relay for the current mode (honestly — automatic never
        // invents an endpoint), rebuilds the hub, and starts health tracking.
        await applyRelayConfigToTransports(relayConfig)
        didStart = true
    }

    /// (Re)builds mailbox routes for every known conversation.
    func rebuildRoutesFromStore() async throws {
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        for conversation in conversations {
            let id = appUUID(conversation.id)
            let sidecar = await sidecars.load(id: id)
            if let groupID = sidecar.cryptoGroupID {
                try await bindGroup(groupID: groupID, conversationID: id)
            } else if let fp = sidecar.dmPeerFingerprint,
                      let peer = await engine.identityPublic(forFingerprint: fp)
            {
                try await bindDirect(peer: peer)
            }
        }
        // Always bind the identity route: pre-session first contact.
        await bindIdentityRoute()
    }

    // MARK: - Mailbox binding

    private func bind(mailbox: Data, route: RouteTarget) async {
        let id = MailboxID(mailbox)
        routes[id.hex] = route
        await hub.bind(id)
        delivery.trackMailbox(id)
    }

    private func unbind(mailbox: Data) async {
        let id = MailboxID(mailbox)
        routes.removeValue(forKey: id.hex)
        await hub.unbind(id)
        delivery.untrackMailbox(id)
    }

    func bindDirect(peer: IdentityPublic) async throws {
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        await bind(mailbox: mailbox, route: .direct(fingerprint: peer.fingerprint))
    }

    func bindGroup(groupID: Data, conversationID: UUID) async throws {
        // Bind the current epoch's mailbox AND the previous epoch's: the
        // crypto layer accepts both (grace window for in-flight messages),
        // so the transport must listen on both — otherwise a membership
        // change partitions the group while members adopt the new epoch.
        for mailbox in await engine.groupRoutingMailboxes(groupID: groupID) {
            await bind(mailbox: mailbox, route: .group(groupID: groupID, conversationID: conversationID))
        }
    }

    /// Rebinds group mailboxes after an epoch bump: binds the new epoch's
    /// mailbox (keeping the previous for the grace window) and releases
    /// mailboxes outside that window.
    func rebindGroup(groupID: Data, conversationID: UUID, oldMailboxes: [Data]) async throws {
        let wanted = Set(await engine.groupRoutingMailboxes(groupID: groupID).map { $0.hexString })
        for old in oldMailboxes where !wanted.contains(old.hexString) {
            await unbind(mailbox: old)
        }
        try await bindGroup(groupID: groupID, conversationID: conversationID)
    }

    /// Backward-compatible single-mailbox rebind (epoch 0 groups).
    func rebindGroup(groupID: Data, conversationID: UUID, oldMailbox: Data) async throws {
        try await rebindGroup(groupID: groupID, conversationID: conversationID, oldMailboxes: [oldMailbox])
    }

    /// Binds the local identity route (pre-session first contact). Called
    /// after identity creation and on every route rebuild.
    func bindIdentityRoute() async {
        if let local = try? await engine.localPublicIdentity() {
            let mailbox = RoutingMailbox.identityRoute(fingerprint: local.fingerprint)
            await bind(mailbox: mailbox, route: .direct(fingerprint: local.fingerprint))
        }
    }

    // MARK: - Relay configuration

    func configureRelay(_ config: RelayConfig) async throws {
        relayConfig = config
        await applyRelayConfigToTransports(config)
    }

    /// Resolves the relay URL for `config` (never inventing one), rebuilds
    /// the transport hub around it, re-binds every known mailbox, and starts
    /// health tracking. Shared by start() and configureRelay().
    private func applyRelayConfigToTransports(_ config: RelayConfig) async {
        // Generation bump retires the old consume/health tasks before rebuild.
        consumeGeneration &+= 1
        await hub.stop()
        var transports: [any Transport] = [lan]
        // Honest resolution: automatic uses only a previously verified relay
        // (or nothing); customRelay uses the validated custom URL; lanOnly
        // uses nothing. There is no default community relay.
        let resolved = RelayEndpointResolver.resolveURL(
            mode: config.mode.rawValue,
            customURL: config.customRelayURL,
            lastKnownGoodURL: lastKnownGoodRelayURL
        )
        var newRelay: RelayTransport? = nil
        if let url = resolved {
            let relay = RelayTransport(url: url)
            transports.append(relay)
            newRelay = relay
            effectiveRelayURL = url.absoluteString
        } else {
            effectiveRelayURL = nil
        }
        self.relay = newRelay
        self.hub = TransportHub(transports: transports)
        self.delivery = DeliveryCoordinator(hub: hub, lan: lan, relay: newRelay)
        // Re-bind every known mailbox on the new hub.
        let known = routes
        routes.removeAll()
        await hub.start()
        delivery.start()
        for (hex, route) in known {
            guard let mailbox = MailboxID(hex: hex) else { continue }
            routes[hex] = route
            await hub.bind(mailbox)
            delivery.trackMailbox(mailbox)
        }
        let generation = consumeGeneration
        Task { await self.consumeInbound(generation: generation) }
        Task { await self.consumeCoordinatorEvents(generation: generation) }
        Task { await self.watchTransportStates(generation: generation) }
        Task { await self.watchRelayHealth(generation: generation) }
        if let urlString = effectiveRelayURL, let url = URL(string: urlString) {
            relayHealth = RelayHealth(
                url: urlString, status: .checking,
                detail: "Probing relay…"
            )
            // Immediate one-shot probe on a transient socket: a definitive
            // reachable/unreachable verdict without disturbing the live
            // transport. watchRelayHealth keeps the readout honest afterwards.
            Task { [weak self] in
                let result = await RelayProbe.handshake(url: url)
                guard let self else { return }
                await self.applyProbeResult(urlString: urlString, result: result, generation: generation)
            }
        } else {
            relayHealth = nil
        }
        connectionCont.yield(currentConnectionStateSync())
    }

    /// Latest health assessment of the effective relay (nil when no relay is
    /// configured). Surfaced in Settings.
    func getRelayHealth() async -> RelayHealth? { relayHealth }

    /// The relay URL the current mode resolved to, if any.
    func getEffectiveRelayURL() async -> String? { effectiveRelayURL }

    /// Applies a probe result to the health readout. Generation-guarded so a
    /// stale probe can never overwrite a newer configuration. A verified relay
    /// becomes automatic mode's fallback.
    private func applyProbeResult(urlString: String, result: RelayProbeResult, generation: Int) async {
        guard generation == consumeGeneration else { return }
        relayHealth = RelayHealth(
            url: urlString,
            status: result.reachable ? .reachable : .unreachable,
            latencyMs: result.latencyMs,
            lastCheckedAt: Date(),
            detail: result.detail
        )
        if result.reachable { lastKnownGoodRelayURL = urlString }
        connectionCont.yield(currentConnectionStateSync())
    }

    /// Periodic one-shot handshake probe on a transient socket — never
    /// disturbs the live connection. Keeps the Settings health readout honest
    /// when the live transport is down or still checking.
    private func watchRelayHealth(generation: Int) async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 60_000_000_000)
            guard generation == consumeGeneration else { return }
            guard let urlString = effectiveRelayURL, let url = URL(string: urlString) else { continue }
            if relayHealth?.status == .reachable, relay?.currentState == .connected { continue }
            let result = await RelayProbe.handshake(url: url)
            await applyProbeResult(urlString: urlString, result: result, generation: generation)
        }
    }

    func currentConnectionStateSync() -> ConnectionState {
        let relayState = relay?.currentState ?? .idle
        let lanState = lan.currentState
        switch (relayConfig.mode, relayState, lanState) {
        case (.lanOnly, _, .connected): return .lanOnly
        case (.lanOnly, _, _): return .offline
        case (.automatic, _, .connected) where relay == nil: return .localNetworkOnly
        case (.automatic, _, _) where relay == nil: return .offline
        case (_, .connected, _): return .relayConnected
        case (_, .connecting, _): return .relayConnecting
        case (_, _, .connected): return .relayUnreachable
        default: return .offline
        }
    }

    private func watchTransportStates(generation: Int) async {
        // Coarse polling: transport state streams are per-transport; the
        // adapter-level ConnectionState is derived. 5s cadence is plenty.
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard generation == consumeGeneration else { return }
            connectionCont.yield(currentConnectionStateSync())
        }
    }

    // MARK: - Inbound dispatch

    private func consumeInbound(generation: Int) async {
        for await frame in hub.inbound {
            guard generation == consumeGeneration else { return }
            await handleFrame(frame)
        }
    }

    private func consumeCoordinatorEvents(generation: Int) async {
        for await event in delivery.events {
            guard generation == consumeGeneration else { return }
            switch event {
            case .knockReceived(let frame):
                await handleFrame(frame)
            case .modeChanged:
                connectionCont.yield(currentConnectionStateSync())
            case .messagesDrained:
                break
            }
        }
    }

    private func handleFrame(_ frame: AegisFrame) async {
        guard let route = routes[frame.mailbox.hex] else { return } // not ours
        do {
            switch route {
            case .direct(let fingerprint):
                try await handleDirectFrame(frame: frame, peerFingerprint: fingerprint)
            case .group(let groupID, let conversationID):
                try await handleGroupFrame(frame: frame, groupID: groupID, conversationID: conversationID)
            case .deviceLink(let channel):
                await deviceLink.handleDeviceLinkFrame(frame.payload, channel: channel)
            }
        } catch {
            // Untrusted network: drop undecryptable frames silently.
            // (A real UI signal for "session reset needed" is emitted by
            // the app when ITS decrypt fails, not here.)
        }
    }

    private func handleDirectFrame(frame: AegisFrame, peerFingerprint: Data) async throws {
        guard let peer = await engine.identityPublic(forFingerprint: peerFingerprint) else {
            // No known identity for this route's peer. The only legitimate
            // case is our own identity route: a prekey rendezvous from a
            // sender we have never met (first contact) or whose identity
            // changed (reinstall). Anything else is dropped.
            try await handleUnknownSenderFrame(frame: frame, routeFingerprint: peerFingerprint)
            return
        }
        if frame.flags & AegisFrame.flagTransportControl != 0 {
            // Transport-internal: the core consumes it fully.
            // Identity-sealed distributions (magic prefix) are
            // self-authenticating and need no 1:1 session — this covers the
            // race where a session was established after sealing.
            let magic = CryptoEngine.identitySealedDistributionMagic
            if frame.payload.prefix(magic.count) == magic {
                await handleIdentitySealedDistribution(frame.payload)
                return
            }
            let plaintext = try await engine.decryptDirect(frame.payload, from: peer).plaintext
            // Distributions are detected by parse (the engine sends them
            // as encryptDirect(distribution.serialized()) with no JSON
            // wrapper); everything else is a TransportControl envelope.
            if let dist = try? SenderKeyDistribution(serialized: plaintext) {
                do {
                    try await engine.ingestDistribution(dist, groupID: dist.groupID, fromSender: dist.senderID)
                } catch CryptoEngineError.unknownGroup {
                    // Race: the distribution arrived before the group invite
                    // that creates our session (transports may reorder).
                    // Stash it; handleGroupInvite flushes after joining.
                    var pending = pendingDistributions[dist.groupID.hexString] ?? []
                    if pending.count < 16 { pending.append(dist) }
                    pendingDistributions[dist.groupID.hexString] = pending
                    return
                }
                // Retry any group frames that were waiting on this key.
                let key = dist.groupID.hexString
                if let pending = pendingGroupFrames[key] {
                    pendingGroupFrames[key] = nil
                    for frame in pending { await handleFrame(frame) }
                }
                return
            }
            let control = try JSONDecoder().decode(TransportControl.self, from: plaintext)
            try await handleTransportControl(control, from: peer)
            return
        }
        // User message: emit session-layer ciphertext opaquely. The app
        // decrypts via CryptoService.decryptMessage — the transport never
        // sees message plaintext.
        let conversationID = try await directConversationID(for: peerFingerprint)
        envelopeCont.yield(IncomingEnvelope(
            id: UUID(),
            conversationID: conversationID,
            senderKey: peerFingerprint,
            ciphertext: frame.payload,
            receivedAt: Date(),
            kind: frame.flags & AegisFrame.flagKnock != 0 ? .callSignal : .message
        ))
    }

    /// Handles a frame on a route whose peer we cannot resolve. The only
    /// legitimate case is our own identity route: a prekey rendezvous from a
    /// sender we have never met (first contact) or whose identity changed
    /// (reinstall). Transport-control frames from unknown senders are
    /// dropped — only user messages are surfaced, and the app (never the
    /// transport) decides what they mean.
    ///
    /// NOTE (documented layering exception): this path must decrypt, because
    /// no session exists yet. The core extracts exactly one routing field
    /// from the plaintext — the sender's rotation hint (`previousFingerprint`)
    /// — to link the message to an existing conversation when the sender
    /// replaced their identity. Everything else travels opaquely to the app
    /// via `preDecrypted`.
    private func handleUnknownSenderFrame(frame: AegisFrame, routeFingerprint: Data) async throws {
        guard frame.flags & AegisFrame.flagTransportControl == 0,
              frame.flags & AegisFrame.flagKnock == 0,
              let local = try? await engine.localPublicIdentity(),
              routeFingerprint == local.fingerprint
        else { return }
        // Identity-sealed sender-key distributions (from group members we
        // share no 1:1 session with) land on the identity route too.
        // Detect by magic prefix BEFORE attempting prekey rendezvous. They
        // carry the transport-control flag (like 1:1 distributions), which
        // is explicitly allowed here when the magic matches.
        let magic = CryptoEngine.identitySealedDistributionMagic
        let isSealedDistribution = frame.payload.prefix(magic.count) == magic
        guard (frame.flags & AegisFrame.flagTransportControl == 0) || isSealedDistribution,
              frame.flags & AegisFrame.flagKnock == 0,
              let local = try? await engine.localPublicIdentity(),
              routeFingerprint == local.fingerprint
        else { return }
        if isSealedDistribution {
            await handleIdentitySealedDistribution(frame.payload)
            return
        }
        let (plaintext, initiator) = try await engine.decryptPreKeyFromUnknownSender(frame.payload)
        let initiatorFP = initiator.fingerprint
        // Cache the initiator's key so the identity resolves going forward.
        try? await keyDirectory.store(fingerprintHex: initiatorFP.hexString, identityPublic: initiator.serialized())
        // Bind the session route so replies and follow-up messages use it.
        try await bindDirect(peer: initiator)
        // Link to an existing conversation when the sender hints a previous
        // identity we know. The hint is untrusted metadata — the app still
        // requires out-of-band verification before trusting the new key.
        let conversationID: UUID
        var supersedes: Data? = nil
        if let previous = Self.rotationHint(in: plaintext),
           let target = await linkTargetForHint(previous)
        {
            conversationID = target
            supersedes = previous
        } else {
            conversationID = try await directConversationID(for: initiatorFP)
        }
        envelopeCont.yield(IncomingEnvelope(
            id: UUID(),
            conversationID: conversationID,
            senderKey: initiatorFP,
            ciphertext: Data(),
            receivedAt: Date(),
            kind: .message,
            preDecrypted: PreDecryptedEnvelope(
                plaintext: plaintext,
                senderIdentity: initiator.serialized(),
                supersedesFingerprint: supersedes
            )
        ))
    }

    /// Ingests an identity-sealed sender-key distribution: opens the
    /// envelope (verifying the sender's identity signature against the
    /// roster-authenticated key), ingests the distribution, and retries any
    /// group frames that were waiting on the key.
    private func handleIdentitySealedDistribution(_ payload: Data) async {
        do {
            let dist = try await engine.openIdentitySealedDistribution(payload)
            do {
                try await engine.ingestDistribution(
                    dist, groupID: dist.groupID, fromSender: dist.senderID)
            } catch CryptoEngineError.unknownGroup {
                // Race: the distribution arrived before the group invite
                // that creates our session (transports may reorder). Stash
                // it; handleGroupInvite flushes after joining.
                var pending = pendingDistributions[dist.groupID.hexString] ?? []
                if pending.count < 16 { pending.append(dist) }
                pendingDistributions[dist.groupID.hexString] = pending
                return
            }
            // Retry any group frames that were waiting on this key.
            let key = dist.groupID.hexString
            if let pending = pendingGroupFrames[key] {
                pendingGroupFrames[key] = nil
                for pendingFrame in pending { await handleFrame(pendingFrame) }
            }
        } catch {
            // Authentication failed: drop. The membership announcement
            // carrying the roster may still be in flight; its arrival
            // populates the roster and the sender re-distributes on the
            // next rotation.
        }
    }

    /// Extracts the sender's rotation hint from a decrypted payload, if any.
    private static func rotationHint(in plaintext: Data) -> Data? {
        guard let payload = try? WirePayload.decoded(from: plaintext),
              let hint = payload.previousFingerprint,
              hint.count == 32
        else { return nil }
        return hint
    }

    /// Whether a fingerprint belongs to a known contact (store-backed).
    private func isKnownContact(fingerprint: Data) async -> Bool {
        let hex = fingerprint.hexString
        let contacts = (try? await pkgStore.contacts.list(includeBlocked: true)) ?? []
        return contacts.contains { $0.identityKeyFingerprint == hex }
    }

    /// Finds the conversation a rotation hint links to: the hinted contact's
    /// DM conversation, or the conversation already tracking that hint as a
    /// pending new identity (rotations chain instead of forking).
    private func linkTargetForHint(_ hint: Data) async -> UUID? {
        if await isKnownContact(fingerprint: hint) {
            return try? await directConversationID(for: hint)
        }
        let conversations = (try? await pkgStore.conversations.list(includeArchived: true, kind: .direct, query: nil)) ?? []
        for conversation in conversations {
            let id = appUUID(conversation.id)
            if await sidecars.load(id: id).pendingIdentityChange?.newFingerprint == hint {
                return id
            }
        }
        return nil
    }

    // MARK: - Identity-change tracking (TransportService)

    /// Records a peer identity change: repoints the conversation's routing
    /// to the new identity (replies must use the fresh session — the old
    /// identity can no longer decrypt) and stores the pending state the app
    /// banners on.
    func noteIdentityChange(_ change: PendingIdentityChange, conversationID: UUID) async {
        var sidecar = await sidecars.load(id: conversationID)
        sidecar.dmPeerFingerprint = change.newFingerprint
        sidecar.pendingIdentityChange = change
        try? await sidecars.save(id: conversationID, sidecar: sidecar)
        if let peer = await engine.identityPublic(forFingerprint: change.newFingerprint) {
            try? await bindDirect(peer: peer)
        }
    }

    /// Clears the identity-change state after the user re-verified (adopting
    /// the new key). With `adoptNewKey=false` the user dismissed the banner:
    /// the pending state is kept (marked dismissed) so the new key stays
    /// available for later re-verification, held messages are shown, and
    /// routing stays on the new identity — but the contact remains flagged.
    func resolveIdentityChange(conversationID: UUID, adoptNewKey: Bool) async {
        var sidecar = await sidecars.load(id: conversationID)
        guard var change = sidecar.pendingIdentityChange else { return }
        if adoptNewKey {
            sidecar.pendingIdentityChange = nil
        } else {
            if let peer = await engine.identityPublic(forFingerprint: change.newFingerprint) {
                try? await bindDirect(peer: peer)
            }
            sidecar.dmPeerFingerprint = change.newFingerprint
            change.dismissed = true
            sidecar.pendingIdentityChange = change
        }
        try? await sidecars.save(id: conversationID, sidecar: sidecar)
    }

    func pendingIdentityChange(for conversationID: UUID) async -> PendingIdentityChange? {
        await sidecars.load(id: conversationID).pendingIdentityChange
    }

    private func handleTransportControl(_ control: TransportControl, from peer: IdentityPublic) async throws {
        switch control.kind {
        case "callSignal":
            let signal = try JSONDecoder().decode(CallSignal.self, from: control.body)
            try await handleCallSignal(signal, from: peer)
        case "knock":
            let knock = try JSONDecoder().decode(KnockInfo.self, from: control.body)
            try await handleKnock(knock, from: peer)
        case "groupInvite":
            let invite = try JSONDecoder().decode(GroupInviteInfo.self, from: control.body)
            try await handleGroupInvite(invite, from: peer)
        case "blobRequest":
            // A 1:1 peer missed blob chunks we uploaded. Re-transmit from
            // the sent-blob cache to the conversation's direct mailbox.
            if let body = try? JSONDecoder().decode(BlobRequestBody.self, from: control.body),
               let uploadID = Data(hexString: body.uploadID),
               let mailbox = try? await engine.directRoutingMailbox(peer: peer)
            {
                _ = await retransmitBlob(uploadID: uploadID, mailbox: mailbox)
            }
        case "sessionReset":
            break // peer re-establishes on next outbound; nothing to do
        default:
            break
        }
    }

    private func handleGroupFrame(frame: AegisFrame, groupID: Data, conversationID: UUID) async throws {
        let groupMessage = try GroupMessage.parse(frame.payload)
        // A removed (or never-added) sender's messages are dropped, not
        // stashed: no future distribution will ever make them decryptable.
        // Our own echoed frames are dropped here too (we applied the send
        // locally); controls from self are additionally skipped below.
        let localFP = try? await engine.localPublicIdentity().fingerprint
        guard await engine.isGroupMember(groupID: groupID, fingerprint: groupMessage.senderID),
              groupMessage.senderID != localFP
        else { return }
        do {
            let plaintext = try await engine.decryptGroup(frame.payload, groupID: groupID)
            let inner = try JSONDecoder().decode(GroupInnerPayload.self, from: plaintext)
            switch inner.kind {
            case "control":
                let control = try JSONDecoder().decode(GroupControlMessage.self, from: inner.body)
                try await handleGroupControl(control, conversationID: conversationID, senderFingerprint: groupMessage.senderID)
            default:
                // Inbound group enforcement, from the signed channel policy:
                // granular post permission + slow mode. A poster's client
                // should never send here unauthorized (outbound is refused
                // in sendCiphertext), but a modified client can — honest
                // recipients drop such messages and record the bypass as an
                // invalid event in the local audit log. Control messages are
                // NOT gated here — each control kind carries its own
                // authorization in handleGroupControl.
                let members = (try? await pkgStore.memberships.members(of: packageID(conversationID))) ?? []
                let posterRoleString = members.first(where: { $0.userID.rawValue == groupMessage.senderID.hexString })?.role
                let posterRole: ModerationRole
                switch posterRoleString {
                case .owner: posterRole = .owner
                case .admin: posterRole = .admin
                case .moderator: posterRole = .moderator
                case .guest: posterRole = .guest
                default: posterRole = .member
                }
                // Legacy groups predate the policy store: converge the
                // policy's announcement flag from the sidecar once.
                let sidecar = await sidecars.load(id: conversationID)
                var modState = await moderation.load(id: conversationID)
                if modState.policy.announcementOnly != sidecar.isAnnouncementOnly {
                    let enabled = sidecar.isAnnouncementOnly
                    try? await moderation.mutate(id: conversationID) {
                        $0.policy.announcementOnly = enabled
                    }
                    modState = await moderation.load(id: conversationID)
                }
                guard PermissionEvaluator.can(posterRole, .post, in: modState.policy) else {
                    await recordInvalidEvent(
                        conversationID: conversationID,
                        groupID: groupID,
                        targetFingerprint: groupMessage.senderID,
                        detail: "Rejected a message from a member without post permission."
                    )
                    return
                }
                let senderKey = groupMessage.senderID.hexString
                switch modState.slowMode.evaluate(memberKey: senderKey, role: posterRole, in: modState.policy) {
                case .denied:
                    await recordInvalidEvent(
                        conversationID: conversationID,
                        groupID: groupID,
                        targetFingerprint: groupMessage.senderID,
                        detail: "Rejected a message that violated slow mode."
                    )
                    return
                case .allowed, .exempt:
                    try? await moderation.mutate(id: conversationID) {
                        $0.slowMode.recordSend(memberKey: senderKey)
                    }
                }
                envelopeCont.yield(IncomingEnvelope(
                    id: UUID(),
                    conversationID: conversationID,
                    senderKey: groupMessage.senderID,
                    ciphertext: frame.payload,
                    receivedAt: Date(),
                    kind: .message
                ))
            }
        } catch {
            // Likely a missing sender key: stash and retry on distribution.
            var pending = pendingGroupFrames[groupID.hexString] ?? []
            if pending.count < 50 { pending.append(frame); pendingGroupFrames[groupID.hexString] = pending }
        }
    }

    private func handleGroupControl(_ control: GroupControlMessage, conversationID: UUID, senderFingerprint: Data) async throws {
        // Moderation controls (membership/role changes) are honored only
        // from members whose LOCALLY-KNOWN role can moderate. This stops a
        // non-admin member's modified client from silently churning the
        // roster on everyone else's device. Honest limit: roles are
        // advisory in the dumb-relay design — there is no server to be
        // authoritative (see docs/THREAT_MODEL.md) — so a determined
        // attacker who socially engineers an admin role still wins; this
        // check only closes the trivial self-promotion hole.
        let moderationKinds = ["memberAdded", "memberRemoved", "roleChanged", "topicChanged", "announcementModeChanged",
                                 "slowModeChanged", "permissionChanged", "inviteRevoked"]
        if moderationKinds.contains(control.kind) {
            let members = (try? await pkgStore.memberships.members(of: packageID(conversationID))) ?? []
            let senderRole = members.first(where: { $0.userID.rawValue == senderFingerprint.hexString })?.role
            let senderCanModerate: Bool
            switch senderRole {
            case .owner, .admin, .moderator: senderCanModerate = true
            default: senderCanModerate = false
            }
            guard senderCanModerate else { return }
        }
        // Update the package memberships so roles survive restarts.
        let cid: AegisStore.ConversationID = packageID(conversationID)
        switch control.kind {
        case "memberAdded", "memberRemoved":
            // Epoch adoption: the announcer bumped the epoch and rotated.
            // Adopt their roster wholesale (self-healing if we missed
            // intermediate changes), rotate OUR sender key for the new
            // epoch (forward secrecy — a removed member must not read our
            // future messages), re-bind mailboxes, and publish our fresh
            // key to every remaining member. The moderation gate above
            // already rejected unauthorized announcers.
            if let roster = control.roster, !roster.isEmpty,
               let groupID = await groupIDForConversation(conversationID)
            {
                try await adoptAnnouncedRoster(
                    roster, groupID: groupID, conversationID: conversationID,
                    newEpoch: control.epoch)
            } else if let fp = control.fingerprint {
                // Legacy control without a roster: apply the delta only.
                // (No epoch adoption — legacy announcers predate it.)
                if control.kind == "memberAdded" {
                    let membership = AegisStore.GroupMembership(
                        conversationID: cid,
                        userID: AegisStore.UserID(fp.hexString),
                        role: roleFromString(control.role)
                    )
                    try await pkgStore.memberships.upsert(membership)
                } else {
                    try await pkgStore.memberships.remove(conversationID: cid, userID: AegisStore.UserID(fp.hexString))
                }
            }
            // A joiner adopts the announcer's current permission policy so
            // their local enforcement matches the group's signed state from
            // the start (instead of role defaults until the next change).
            if control.kind == "memberAdded",
               let policyData = control.policy,
               let policy = try? JSONDecoder().decode(ChannelPermissionPolicy.self, from: policyData)
            {
                try? await moderation.mutate(id: conversationID) {
                    $0.policy = policy
                }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "roleChanged":
            if let fp = control.fingerprint {
                try await pkgStore.memberships.setRole(
                    conversationID: cid, userID: AegisStore.UserID(fp.hexString),
                    role: roleFromString(control.role)
                )
                // If WE were re-roled, update the sidecar so the
                // moderation UI unlocks (or locks) immediately.
                if let local = try? await engine.localPublicIdentity(),
                   fp == local.fingerprint,
                   let appRole = control.role.flatMap(appRoleFromString)
                {
                    var sidecar = await sidecars.load(id: conversationID)
                    sidecar.myRole = appRole
                    try await sidecars.save(id: conversationID, sidecar: sidecar)
                }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "announcementModeChanged":
            // Keep the moderation policy's announcement flag in sync with
            // the sidecar so the granular post check sees one truth.
            if let enabled = control.announcementOnly {
                var sidecar = await sidecars.load(id: conversationID)
                sidecar.isAnnouncementOnly = enabled
                try? await sidecars.save(id: conversationID, sidecar: sidecar)
                try? await moderation.mutate(id: conversationID) {
                    $0.policy.announcementOnly = enabled
                }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "slowModeChanged":
            let interval = control.slowModeInterval.map { TimeInterval($0) }
            try? await moderation.mutate(id: conversationID) {
                $0.policy.slowModeInterval = interval
                if interval == nil { $0.slowMode.resetAll() }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "permissionChanged":
            if let roleString = control.permissionRole,
               let role = ModerationRole(rawValue: roleString)
            {
                try? await moderation.mutate(id: conversationID) { state in
                    if control.permissionReset == true {
                        state.policy.overrides.removeValue(forKey: role)
                    } else if let name = control.permissionName,
                              let permission = GroupPermission(rawValue: name),
                              let granted = control.permissionGranted
                    {
                        var grants = state.policy.overrides[role] ?? PermissionEvaluator.defaultGrants(for: role)
                        if granted { grants.insert(permission) } else { grants.remove(permission) }
                        state.policy.overrides[role] = grants
                    }
                }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "inviteRevoked":
            if let generation = control.inviteGeneration {
                try? await moderation.mutate(id: conversationID) { state in
                    state.inviteGeneration = max(state.inviteGeneration, generation)
                }
            }
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "topicChanged":
            await appendReceivedAuditEvent(conversationID: conversationID, control: control)
        case "blobRequest":
            // A member missed some (or all) chunks of a blob we uploaded.
            // Re-transmit from the sent-blob cache; the downloader merges
            // by chunk index. Anyone may request; the blob is ciphertext.
            if let uploadHex = control.blobUploadID,
               let uploadID = Data(hexString: uploadHex),
               let groupID = await groupIDForConversation(conversationID),
               let mailbox = try? await engine.groupRoutingMailbox(groupID: groupID)
            {
                _ = await retransmitBlob(uploadID: uploadID, mailbox: mailbox)
            }
        case "voiceRoom":
            // Voice-room mesh signaling. The sender-key channel already
            // authenticates group membership; senderFingerprint is the
            // Ed25519-verified sender of this control message. Bind the
            // signal's claimed sender to it so a group member cannot forge
            // join/leave/muteState/offer signals attributed to another
            // member (the signal body is self-claimed JSON). Mismatches are
            // dropped rather than processed.
            if let body = control.voiceRoomSignal,
               let signal = try? JSONDecoder().decode(VoiceRoomSignal.self, from: body),
               signal.senderFingerprintHex.lowercased() == senderFingerprint.hexString.lowercased()
            {
                await handleVoiceRoomSignal(signal)
            }
        default:
            break
        }
        let kind: GroupEvent.Kind
        switch control.kind {
        case "memberAdded": kind = .memberJoined
        case "memberRemoved": kind = .memberRemoved
        case "roleChanged": kind = .roleChanged
        case "topicChanged": kind = .topicChanged
        case "announcementModeChanged": kind = .announcementModeChanged
        case "slowModeChanged": kind = .slowModeChanged
        case "permissionChanged": kind = .permissionsChanged
        default:
            // Non-membership controls (e.g. "blobRequest") are fully
            // handled above; there is no UI event to emit.
            return
        }
        groupCont.yield(GroupEvent(
            conversationID: conversationID,
            kind: kind,
            memberKey: control.fingerprint,
            role: control.role.flatMap { appRoleFromString($0) },
            topic: control.kind == "topicChanged" ? control.topic : nil,
            announcementOnly: control.announcementOnly,
            slowModeInterval: control.slowModeInterval.map { TimeInterval($0) }
        ))
    }

    private func groupIDForConversation(_ conversationID: UUID) async -> Data? {
        await sidecars.load(id: conversationID).cryptoGroupID
    }

    /// Adopts a roster announced in a membership control. See
    /// `GroupSession.adoptMembershipChange` for the crypto semantics.
    private func adoptAnnouncedRoster(
        _ roster: [String: GroupRosterEntry],
        groupID: Data,
        conversationID: UUID,
        newEpoch: UInt32
    ) async throws {
        let localFP = try await engine.localPublicIdentity().fingerprint
        guard roster[localFP.hexString] != nil else {
            // We are not in the announced roster: we were removed.
            await handleSelfRemovedFromGroup(groupID: groupID, conversationID: conversationID)
            return
        }
        // Resolve identity keys, fail-closed per entry: an entry whose key
        // does not hash to its fingerprint is dropped, never trusted.
        var identities: [IdentityPublic] = []
        for (hex, entry) in roster {
            guard let fp = Data(hexString: hex),
                  let pub = try? IdentityPublic(serialized: entry.identityKey),
                  pub.fingerprint == fp
            else { continue }
            identities.append(pub)
        }
        let distributions = try await engine.adoptGroupMembershipChange(
            groupID: groupID, newEpoch: newEpoch, members: identities)
        try await reconcileGroupMailboxes(groupID: groupID, conversationID: conversationID)
        // Publish our fresh sender key to every remaining member (1:1
        // session where one exists, else identity-sealed to their identity
        // route — the new member included).
        try await distribute(distributions)
        // Replace the membership table with the announced roster so roles
        // survive restarts and the UI shows the announcer's truth.
        let cid: AegisStore.ConversationID = packageID(conversationID)
        let current = (try? await pkgStore.memberships.members(of: cid)) ?? []
        let rosterHexes = Set(roster.keys)
        for member in current where !rosterHexes.contains(member.userID.rawValue) {
            try? await pkgStore.memberships.remove(conversationID: cid, userID: member.userID)
        }
        for (hex, entry) in roster {
            guard let fp = Data(hexString: hex) else { continue }
            try await upsertMembership(conversationID: conversationID, fingerprint: fp, role: entry.role)
            if fp == localFP, let appRole = appRoleFromString(entry.role) {
                var sidecar = await sidecars.load(id: conversationID)
                sidecar.myRole = appRole
                try await sidecars.save(id: conversationID, sidecar: sidecar)
            }
        }
    }

    /// Binds the mailboxes for the epochs the engine will now accept and
    /// releases group mailboxes for this conversation outside that window.
    private func reconcileGroupMailboxes(groupID: Data, conversationID: UUID) async throws {
        let wanted = Set(await engine.groupRoutingMailboxes(groupID: groupID).map { $0.hexString })
        for (hex, route) in routes {
            if case .group(let gid, let cid) = route,
               gid == groupID, cid == conversationID, !wanted.contains(hex),
               let mailbox = MailboxID(hex: hex)
            {
                await unbind(mailbox: mailbox.bytes)
            }
        }
        try await bindGroup(groupID: groupID, conversationID: conversationID)
    }

    /// We were removed from the group: drop the session (and its persisted
    /// snapshot), unbind the group mailboxes, and leave the conversation
    /// visible — the UI reads the membership table to show "removed".
    private func handleSelfRemovedFromGroup(groupID: Data, conversationID: UUID) async {
        await engine.leaveGroup(groupID: groupID)
        await engine.deletePersistedGroupSession(groupID: groupID)
        for (hex, route) in routes {
            if case .group(let gid, let cid) = route,
               gid == groupID, cid == conversationID,
               let mailbox = MailboxID(hex: hex)
            {
                await unbind(mailbox: mailbox.bytes)
            }
        }
        let cid: AegisStore.ConversationID = packageID(conversationID)
        if let local = try? await engine.localPublicIdentity() {
            try? await pkgStore.memberships.remove(
                conversationID: cid, userID: AegisStore.UserID(local.fingerprint.hexString))
        }
        var sidecar = await sidecars.load(id: conversationID)
        sidecar.cryptoGroupID = nil
        try? await sidecars.save(id: conversationID, sidecar: sidecar)
    }

    // MARK: - Conversation resolution

    /// Finds (or creates the mapping for) the DM conversation with a peer.
    func directConversationID(for peerFingerprint: Data) async throws -> UUID {
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: .direct, query: nil)
        for conversation in conversations {
            let id = appUUID(conversation.id)
            let sidecar = await sidecars.load(id: id)
            if sidecar.dmPeerFingerprint == peerFingerprint { return id }
        }
        // No conversation yet (first contact): create a shell the app fills in.
        let id = UUID()
        var pkg = AegisStore.Conversation(kind: .direct)
        pkg.id = packageID(id)
        try await pkgStore.conversations.create(pkg)
        var sidecar = ConversationSidecar()
        sidecar.dmPeerFingerprint = peerFingerprint
        try await sidecars.save(id: id, sidecar: sidecar)
        return id
    }

    // MARK: - Outbound

    /// Wraps ciphertext in a frame and sends it on the conversation's mailbox.
    func sendCiphertext(
        _ ciphertext: Data,
        conversationID: UUID,
        kind: EnvelopeKind,
        flags: UInt8 = 0
    ) async throws {
        // Outbound group enforcement, from the signed channel policy:
        // granular post permission + slow mode. (Control messages —
        // membership, topic, moderation — always flow; they carry their own
        // authorization in the group ops below.) The composer UI already
        // hides the input for unauthorized roles; this is the backstop so
        // a UI bug can't leak a post, and so a modified client is visible
        // as an invalid event to honest recipients.
        if kind == .message {
            let sidecar = await sidecars.load(id: conversationID)
            if sidecar.cryptoGroupID != nil {
                // Legacy groups predate the policy store: converge the
                // policy's announcement flag from the sidecar once.
                var state = await moderation.load(id: conversationID)
                if state.policy.announcementOnly != sidecar.isAnnouncementOnly {
                    let enabled = sidecar.isAnnouncementOnly
                    try? await moderation.mutate(id: conversationID) {
                        $0.policy.announcementOnly = enabled
                    }
                    state = await moderation.load(id: conversationID)
                }
                let myRole = (sidecar.myRole ?? .member).moderationRole
                guard PermissionEvaluator.can(myRole, .post, in: state.policy) else {
                    throw AegisCoreError.notPermitted("You don't have permission to post in this channel.")
                }
                let localFP = try? await engine.localPublicIdentity().fingerprint
                let memberKey = localFP?.hexString ?? "local"
                switch state.slowMode.evaluate(memberKey: memberKey, role: myRole, in: state.policy) {
                case .allowed, .exempt:
                    try? await moderation.mutate(id: conversationID) {
                        $0.slowMode.recordSend(memberKey: memberKey)
                    }
                case .denied(let retryAfter):
                    throw AegisCoreError.slowModeLimited(retryAfter: retryAfter)
                }
            }
        }
        let (mailbox, policy) = try await mailboxForConversation(conversationID, kind: kind)
        let envelopeID = try randomBytes(count: 16)
        let frame = AegisFrame(
            mailbox: MailboxID(mailbox),
            envelopeID: envelopeID,
            ttl: ttlForKind(kind),
            flags: flags,
            payload: ciphertext
        )
        try await hub.send(frame, policy: policy)
    }

    private func mailboxForConversation(_ conversationID: UUID, kind: EnvelopeKind) async throws -> (Data, SendPolicy) {
        let sidecar = await sidecars.load(id: conversationID)
        if let groupID = sidecar.cryptoGroupID {
            let mailbox = try await engine.groupRoutingMailbox(groupID: groupID)
            return (mailbox, .allConnected)
        }
        if let fp = sidecar.dmPeerFingerprint,
           let peer = await engine.identityPublic(forFingerprint: fp)
        {
            let mailbox = try await engine.directRoutingMailbox(peer: peer)
            return (mailbox, .allConnected)
        }
        throw CryptoEngineError.unknownSession
    }

    private func ttlForKind(_ kind: EnvelopeKind) -> UInt32 {
        switch kind {
        case .message, .reaction, .edit, .delete: return 0 // relay default (7d)
        case .typing: return 60
        case .readReceipt, .screenshotNotice: return 300
        case .callSignal: return 300
        case .groupControl: return 0
        }
    }

    /// Encrypts sender-key distributions inside each recipient's 1:1
    /// session and sends them to the recipients' DM mailboxes. THE crypto
    /// rule: distributions never travel under only the sender key. The
    /// engine already encrypted each wire; the core frames it directly as
    /// a transport-control envelope (no TransportControl wrapper — the
    /// receiver detects distributions by parse, see handleDirectFrame).
    func distribute(_ distributions: [OutgoingDistribution]) async throws {
        // The engine picks the delivery path per recipient: the 1:1 session
        // mailbox when a session (or bundle) exists, else the recipient's
        // identity route carrying an identity-sealed distribution.
        let triples = try await engine.distributeEncrypted(distributions)
        for (_, wire, mailbox) in triples {
            try await sendRaw(wire, mailbox: mailbox, ttl: 0, flags: AegisFrame.flagTransportControl)
        }
    }

    // MARK: - Group operations

    func createGroup(name: String, topic: String?, announcementOnly: Bool, memberKeys: [Data]) async throws -> UUID {
        var members: [IdentityPublic] = []
        for keyData in memberKeys {
            let pub = try IdentityPublic(serialized: keyData)
            members.append(pub)
        }
        let groupID = try randomBytes(count: 32)
        let distributions = try await engine.createGroup(groupID: groupID, members: members)
        let conversationID = UUID()
        var pkg = AegisStore.Conversation(kind: announcementOnly ? .announcement : .group)
        pkg.id = packageID(conversationID)
        pkg.title = name
        try await pkgStore.conversations.create(pkg)
        var sidecar = ConversationSidecar()
        sidecar.cryptoGroupID = groupID
        sidecar.isAnnouncementOnly = announcementOnly
        sidecar.subtitle = topic
        sidecar.myRole = .owner
        try await sidecars.save(id: conversationID, sidecar: sidecar)
        // The moderation policy mirrors announcement mode so the granular
        // post check sees the same truth as the sidecar-fed UI.
        try? await moderation.mutate(id: conversationID) {
            $0.policy.announcementOnly = announcementOnly
        }
        try await bindGroup(groupID: groupID, conversationID: conversationID)
        // Membership rows for the roster UI.
        if let local = try? await engine.localPublicIdentity() {
            try await upsertMembership(conversationID: conversationID, fingerprint: local.fingerprint, role: "owner")
        }
        for member in members {
            try await upsertMembership(conversationID: conversationID, fingerprint: member.fingerprint, role: "member")
        }
        try await distribute(distributions)
        // 1:1 group invites so members can construct their GroupSession.
        let local = try await engine.localPublicIdentity()
        var roster: [String: String] = [local.fingerprint.hexString: "You"]
        var memberKeys: [String: Data] = [local.fingerprint.hexString: local.serialized()]
        for member in members {
            roster[member.fingerprint.hexString] = ""
            memberKeys[member.fingerprint.hexString] = member.serialized()
        }
        let invite = GroupInviteInfo(
            groupID: groupID,
            epoch: 0,
            name: name,
            topic: topic,
            members: roster,
            roles: await membershipRoles(conversationID: conversationID),
            memberKeys: memberKeys
        )
        let inviteBody = try JSONEncoder().encode(invite)
        for peer in members {
            let control = TransportControl(kind: "groupInvite", body: inviteBody)
            let body = try JSONEncoder().encode(control)
            let inner = try await engine.encryptDirect(body, to: peer)
            let mailbox = try await engine.directRoutingMailbox(peer: peer)
            try await sendRaw(inner.wire, mailbox: mailbox, ttl: 0, flags: AegisFrame.flagTransportControl)
        }
        return conversationID
    }

    private func upsertMembership(conversationID: UUID, fingerprint: Data, role: String) async throws {
        let membership = AegisStore.GroupMembership(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(fingerprint.hexString),
            role: roleFromString(role)
        )
        try await pkgStore.memberships.upsert(membership)
    }

    /// Fingerprint hex → role string for the current membership table.
    /// Sent inside group invites so joiners record the inviter's roster
    /// roles instead of defaulting everyone to "member".
    private func membershipRoles(conversationID: UUID) async -> [String: String] {
        guard let members = try? await pkgStore.memberships.members(of: packageID(conversationID)) else {
            return [:]
        }
        var out: [String: String] = [:]
        for member in members {
            switch member.role {
            case .owner: out[member.userID.rawValue] = "owner"
            case .admin: out[member.userID.rawValue] = "admin"
            case .moderator: out[member.userID.rawValue] = "moderator"
            case .guest: out[member.userID.rawValue] = "guest"
            case .member: out[member.userID.rawValue] = "member"
            }
        }
        return out
    }

    private func handleGroupInvite(_ invite: GroupInviteInfo, from peer: IdentityPublic) async throws {
        // Ignore duplicates.
        let conversations = try await pkgStore.conversations.list(includeArchived: true, kind: nil, query: nil)
        for conversation in conversations {
            let id = appUUID(conversation.id)
            let sidecar = await sidecars.load(id: id)
            if sidecar.cryptoGroupID == invite.groupID { return }
        }
        var members: [IdentityPublic] = []
        for (hex, _) in invite.members {
            guard let data = Data(hexString: hex) else { continue }
            if let keyData = invite.memberKeys?[hex],
               let pub = try? IdentityPublic(serialized: keyData),
               pub.fingerprint == data
            {
                // v2 invite: the inviter attests this identity key for the
                // fingerprint (the invite itself arrived over the inviter's
                // authenticated 1:1 session). Cache it so sender-key
                // exchange works without a contact relationship.
                await engine.cacheKnownIdentity(pub)
                members.append(pub)
            } else if let pub = await engine.identityPublic(forFingerprint: data) {
                members.append(pub)
            }
        }
        let distributions = try await engine.joinGroup(groupID: invite.groupID, epoch: invite.epoch, members: members)
        // Flush any sender-key distributions that beat the invite here.
        let pendingKey = invite.groupID.hexString
        if let stashed = pendingDistributions[pendingKey] {
            pendingDistributions[pendingKey] = nil
            for dist in stashed {
                try? await engine.ingestDistribution(dist, groupID: dist.groupID, fromSender: dist.senderID)
            }
        }
        let conversationID = UUID()
        var pkg = AegisStore.Conversation(kind: .group)
        pkg.id = packageID(conversationID)
        pkg.title = invite.name
        try await pkgStore.conversations.create(pkg)
        var sidecar = ConversationSidecar()
        sidecar.cryptoGroupID = invite.groupID
        sidecar.subtitle = invite.topic
        sidecar.myRole = .member
        try await sidecars.save(id: conversationID, sidecar: sidecar)
        try await bindGroup(groupID: invite.groupID, conversationID: conversationID)
        for (hex, _) in invite.members {
            if let data = Data(hexString: hex) {
                // The inviter is authoritative for roster roles; default to
                // "member" for invites that predate the roles field.
                let role = invite.roles?[hex] ?? "member"
                try await upsertMembership(conversationID: conversationID, fingerprint: data, role: role)
            }
        }
        // Publish our sender key to the group.
        try await distribute(distributions)
    }

    /// contactID is accepted for the app-layer signature and intentionally
    /// unused here (the crypto identity is the peer fingerprint).

    /// Redeems an `aegis-group:<conversation-uuid>:<invite-payload>` code.
    /// Establishes a 1:1 session with the inviter from the embedded prekey
    /// bundle (X3DH — no prior contact needed) and sends a join request as
    /// an ordinary user message. The request is X3DH-authenticated; the
    /// inviter's app surfaces it for moderator approval. Nothing about
    /// group membership changes on this device — the requester waits for
    /// the real `groupInvite` + sender-key distributions after approval.
    func requestGroupJoin(code: String) async throws {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = "aegis-group:"
        guard trimmed.hasPrefix(prefix) else { throw AegisCoreError.malformedInviteCode }
        let rest = trimmed.dropFirst(prefix.count)
        // Format: aegis-group:<conversation UUID>:[<generation>:]<invite payload>.
        // New invites carry a pure-digit generation segment right after the
        // UUID (0 for the first generation); legacy codes omit it. The
        // payload itself always starts with a scheme marker ("AEGIS1",
        // "aegis-invite-"), never bare digits, so the two forms are
        // unambiguous.
        let components = rest.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        var inviteGeneration: Int? = nil
        var payloadStart = 1
        if components.count >= 3,
           !components[1].isEmpty,
           components[1].allSatisfy(\.isNumber),
           let generation = Int(components[1])
        {
            inviteGeneration = generation
            payloadStart = 2
        }
        guard components.count > payloadStart,
              UUID(uuidString: components[0]) != nil
        else { throw AegisCoreError.malformedInviteCode }
        let groupReference = components[0]
        let invitePayload = components[payloadStart...].joined(separator: ":")
        guard !invitePayload.isEmpty else { throw AegisCoreError.malformedInviteCode }
        // parseInvite caches the inviter's prekey bundle, so encryptDirect
        // below can establish the 1:1 session from the code alone.
        let (inviter, _) = try await engine.parseInvite(invitePayload)
        let (_, displayName, _) = try await engine.loadIdentity()
        var payload = WirePayload(kind: .groupJoinRequest)
        payload.joinGroupReference = groupReference
        payload.joinRequesterName = displayName
        payload.joinInviteGeneration = inviteGeneration
        let inner = try await engine.encryptDirect(try payload.encoded(), to: inviter)
        let mailbox = try await engine.directRoutingMailbox(peer: inviter)
        // No session exists yet on the inviter's side: this lands on their
        // identity route and is surfaced via the prekey rendezvous path.
        // Generous TTL — the inviter may be offline for days.
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 7 * 24 * 3600, flags: 0)
    }

    /// contactID is accepted for the app-layer signature and intentionally
    /// unused here (the crypto identity is the peer fingerprint).
    ///
    /// Membership-change protocol (every member observes it, or the group
    /// partitions):
    ///  1. Announce `memberAdded` on the PRE-CHANGE mailboxes, encrypted
    ///     under the pre-change sender key — every current member is
    ///     listening there. The announcement carries the new epoch and the
    ///     full identity-keyed roster so recipients adopt atomically.
    ///  2. Bump the epoch locally, rotate our sender key, rebind mailboxes
    ///     (keeping the previous epoch's for the crypto grace window).
    ///  3. Send the 1:1 invite with the full identity-keyed roster so the
    ///     joiner can resolve every member and exchange sender keys.
    ///  4. Distribute our fresh sender key (1:1 where a session exists,
    ///     else identity-sealed to the new member's identity route).
    func inviteMember(_ contactID: UUID, conversationID: UUID, peer: IdentityPublic) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        // Only moderators may change membership. Roles are advisory (no
        // server exists to enforce them in the dumb-relay design — see
        // docs/THREAT_MODEL.md), but a well-behaved client refuses to send
        // membership changes it is not entitled to make, and recipients
        // ignore moderation controls from non-moderators (handleGroupControl).
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        let oldMailboxes = await engine.groupRoutingMailboxes(groupID: groupID)
        let oldEpoch = await engine.groupEpoch(groupID: groupID) ?? 0
        let newEpoch = oldEpoch + 1
        // 1. Announce first, on the mailboxes everyone is listening on.
        var roster = await fullRoster(conversationID: conversationID)
        let displayName = await resolveContactName(for: peer.fingerprint) ?? ""
        roster[peer.fingerprint.hexString] = GroupRosterEntry(
            identityKey: peer.serialized(), displayName: displayName, role: "member")
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .memberAdded,
            targetFingerprint: peer.fingerprint,
            targetDisplayName: displayName.isEmpty ? nil : displayName,
            detail: "Invited to the group."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID, epoch: newEpoch, kind: "memberAdded",
                fingerprint: peer.fingerprint, role: "member",
                memberIdentityKey: peer.serialized(), roster: roster,
                auditEvent: audit, policy: await encodedPolicy(conversationID: conversationID)),
            onMailboxes: oldMailboxes)
        // 2. Bump locally.
        let distributions = try await engine.updateGroupMembership(groupID: groupID, add: [peer], remove: [])
        try await rebindGroup(groupID: groupID, conversationID: conversationID, oldMailboxes: oldMailboxes)
        try await upsertMembership(conversationID: conversationID, fingerprint: peer.fingerprint, role: "member")
        // 3. The invite MUST travel before the sender-key distributions: the
        // joiner cannot ingest a distribution for a group whose session
        // does not exist yet. (A pending-distribution buffer covers
        // transports that reorder.)
        let groupName = (try? await pkgStore.conversations.fetch(id: packageID(conversationID)))?.title
        let invite = GroupInviteInfo(
            groupID: groupID,
            epoch: newEpoch,
            name: groupName ?? "",
            topic: sidecar.subtitle,
            members: Dictionary(uniqueKeysWithValues: roster.map { ($0.key, $0.value.displayName) }),
            roles: Dictionary(uniqueKeysWithValues: roster.map { ($0.key, $0.value.role) }),
            memberKeys: Dictionary(uniqueKeysWithValues: roster.map { ($0.key, $0.value.identityKey) })
        )
        let control = TransportControl(kind: "groupInvite", body: try JSONEncoder().encode(invite))
        let inner = try await engine.encryptDirect(try JSONEncoder().encode(control), to: peer)
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 0, flags: AegisFrame.flagTransportControl)
        // 4. Publish our fresh sender key to every member.
        try await distribute(distributions)
    }

    /// Full roster for announcements: fingerprint hex → entry with identity
    /// key, display name, and role. Built from the membership table;
    /// identity keys resolve via the engine's known identities.
    private func fullRoster(conversationID: UUID) async -> [String: GroupRosterEntry] {
        var roster: [String: GroupRosterEntry] = [:]
        let members = (try? await pkgStore.memberships.members(of: packageID(conversationID))) ?? []
        for member in members {
            let hex = member.userID.rawValue
            guard let fp = Data(hexString: hex),
                  let identity = await engine.identityPublic(forFingerprint: fp)
            else { continue }
            let role: String
            switch member.role {
            case .owner: role = "owner"
            case .admin: role = "admin"
            case .moderator: role = "moderator"
            case .guest: role = "guest"
            case .member: role = "member"
            }
            let name: String
            if let local = try? await engine.localPublicIdentity(), fp == local.fingerprint {
                name = "You"
            } else {
                name = await resolveContactName(for: fp) ?? ""
            }
            roster[hex] = GroupRosterEntry(identityKey: identity.serialized(), displayName: name, role: role)
        }
        // Ensure we are in the roster even if our membership row is missing.
        if let local = try? await engine.localPublicIdentity(),
           roster[local.fingerprint.hexString] == nil
        {
            roster[local.fingerprint.hexString] = GroupRosterEntry(
                identityKey: local.serialized(), displayName: "You", role: "owner")
        }
        return roster
    }

    /// Removes a member: announces `memberRemoved` on the pre-change
    /// mailboxes FIRST (the removed member is still listening there, so
    /// their client learns it was removed instead of silently stalling),
    /// then bumps the epoch, rotates, rebinds, and distributes fresh keys
    /// to the remaining members. Forward secrecy: nobody — including the
    /// remover — keeps using a key the removed member ever held.
    func removeMember(_ fingerprint: Data, conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        let oldMailboxes = await engine.groupRoutingMailboxes(groupID: groupID)
        let oldEpoch = await engine.groupEpoch(groupID: groupID) ?? 0
        let newEpoch = oldEpoch + 1
        // 1. Announce first: the roster WITHOUT the removed member.
        var roster = await fullRoster(conversationID: conversationID)
        roster.removeValue(forKey: fingerprint.hexString)
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .memberRemoved,
            targetFingerprint: fingerprint,
            detail: "Removed from the group."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID, epoch: newEpoch, kind: "memberRemoved",
                fingerprint: fingerprint, roster: roster, auditEvent: audit),
            onMailboxes: oldMailboxes)
        // 2. Bump locally.
        let distributions = try await engine.updateGroupMembership(groupID: groupID, add: [], remove: [fingerprint])
        try await rebindGroup(groupID: groupID, conversationID: conversationID, oldMailboxes: oldMailboxes)
        try await pkgStore.memberships.remove(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(fingerprint.hexString)
        )
        // 3. Fresh keys to the remaining members only.
        try await distribute(distributions)
    }

    // MARK: - Group moderation (permissions, slow mode, invites, audit log)

    /// The audit-log crypto wiring: SHA-256 chain hash, Ed25519
    /// identity-key signatures. Private key material never leaves the
    /// crypto engine — `sign` only crosses the boundary as a closure.
    private func auditCrypto() -> AuditCrypto {
        AuditCrypto(
            hash: { data in
                var hasher = SHA256()
                hasher.update(data: data)
                return Data(hasher.finalize())
            },
            sign: { [engine] digest in try await engine.signWithIdentity(digest) },
            verify: { digest, signature, publicKey in
                Ed25519KeyPair.verify(signature: signature, for: digest, publicKey: publicKey)
            }
        )
    }

    /// Fingerprint → Ed25519 public key for every roster member (plus us),
    /// used to verify replicated audit entries.
    private func auditActorKeys(conversationID: UUID) async -> [Data: Data] {
        let members = (try? await pkgStore.memberships.members(of: packageID(conversationID))) ?? []
        var keys: [Data: Data] = [:]
        for member in members {
            guard let fp = Data(hexString: member.userID.rawValue),
                  let identity = await engine.identityPublic(forFingerprint: fp)
            else { continue }
            keys[fp] = identity.signingPublicKey
        }
        if let local = try? await engine.localPublicIdentity() {
            keys[local.fingerprint] = local.signingPublicKey
        }
        return keys
    }

    private func makeAuditEvent(
        kind: GroupAdminEventKind,
        groupID: Data,
        targetFingerprint: Data? = nil,
        targetDisplayName: String? = nil,
        detail: String? = nil
    ) async -> GroupAdminEvent? {
        guard let local = try? await engine.localPublicIdentity() else { return nil }
        return GroupAdminEvent(
            kind: kind,
            groupID: groupID,
            actorFingerprint: local.fingerprint,
            actorDisplayName: await engine.displayName(),
            targetFingerprint: targetFingerprint,
            targetDisplayName: targetDisplayName,
            detail: detail
        )
    }

    /// Appends a signed audit entry for OUR OWN admin action. Returns the
    /// JSON-encoded `SignedGroupEvent` for replication inside the group
    /// control message (nil when signing/storage failed — the control
    /// still goes out; the local log records the action on retry).
    func recordAdminAction(
        conversationID: UUID,
        kind: GroupAdminEventKind,
        targetFingerprint: Data? = nil,
        targetDisplayName: String? = nil,
        detail: String? = nil
    ) async -> Data? {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID,
              let event = await makeAuditEvent(
                  kind: kind, groupID: groupID,
                  targetFingerprint: targetFingerprint,
                  targetDisplayName: targetDisplayName,
                  detail: detail
              )
        else { return nil }
        var state = await moderation.load(id: conversationID)
        do {
            try await state.auditLog.append(event, crypto: auditCrypto())
        } catch {
            return nil
        }
        try? await moderation.save(id: conversationID, state: state)
        return try? JSONEncoder().encode(state.auditLog.events.last)
    }

    /// Records a peer's policy violation observed by this honest client
    /// (e.g. slow-mode bypass, unauthorized post). Signed by us as the
    /// observer; the entry lives in our local log.
    private func recordInvalidEvent(
        conversationID: UUID,
        groupID: Data,
        targetFingerprint: Data,
        detail: String
    ) async {
        guard let event = await makeAuditEvent(
            kind: .invalidEventObserved, groupID: groupID,
            targetFingerprint: targetFingerprint, detail: detail
        ) else { return }
        var state = await moderation.load(id: conversationID)
        try? await state.auditLog.append(event, crypto: auditCrypto())
        try? await moderation.save(id: conversationID, state: state)
    }

    /// Appends a peer's replicated audit entry after verifying its
    /// signature and chain position. Gaps and forgeries are rejected —
    /// the local log never accepts an entry it cannot verify.
    private func appendReceivedAuditEvent(conversationID: UUID, control: GroupControlMessage) async {
        guard let data = control.auditEvent,
              let entry = try? JSONDecoder().decode(SignedGroupEvent.self, from: data)
        else { return }
        var state = await moderation.load(id: conversationID)
        let keys = await auditActorKeys(conversationID: conversationID)
        let result = state.auditLog.appendReceived(entry, crypto: auditCrypto(), actorKeys: keys)
        guard case .ok = result else {
            #if DEBUG
            print("[Aegis] Rejected replicated audit entry: \(result)")
            #endif
            return
        }
        try? await moderation.save(id: conversationID, state: state)
    }

    /// Keeps the moderation policy's announcement flag in sync with the
    /// sidecar (the sidecar feeds the existing UI paths).
    func syncAnnouncementPolicy(_ enabled: Bool, conversationID: UUID) async {
        try? await moderation.mutate(id: conversationID) {
            $0.policy.announcementOnly = enabled
        }
    }

    /// Sets the channel's slow-mode interval (nil = off). Owner/admin only.
    /// A signed group event, replicated to members and audit-logged.
    func setSlowMode(_ interval: TimeInterval?, conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        let clamped = interval.map {
            min(max($0, SlowModeEnforcer.minimumInterval), SlowModeEnforcer.maximumInterval)
        }
        try? await moderation.mutate(id: conversationID) {
            $0.policy.slowModeInterval = clamped
            if clamped == nil { $0.slowMode.resetAll() }
        }
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .slowModeChanged,
            detail: clamped.map { "Slow mode set to \(SlowModeEnforcer.label(for: $0))." }
                ?? "Slow mode turned off."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "slowModeChanged",
                slowModeInterval: clamped,
                auditEvent: audit
            )
        )
        groupCont.yield(GroupEvent(
            conversationID: conversationID,
            kind: .slowModeChanged,
            slowModeInterval: clamped
        ))
    }

    /// Grants/revokes one permission for one role in this channel only.
    /// Owner/admin only. Signed group event, replicated + audit-logged.
    func setChannelPermission(
        _ permission: GroupPermission,
        granted: Bool,
        for role: MemberRole,
        conversationID: UUID
    ) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        let modRole = role.moderationRole
        try? await moderation.mutate(id: conversationID) { state in
            var grants = state.policy.overrides[modRole] ?? PermissionEvaluator.defaultGrants(for: modRole)
            if granted { grants.insert(permission) } else { grants.remove(permission) }
            state.policy.overrides[modRole] = grants
        }
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .permissionChanged,
            detail: "\(permission.displayName) \(granted ? "granted to" : "revoked from") \(modRole.displayName)s."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "permissionChanged",
                permissionName: permission.rawValue,
                permissionGranted: granted,
                permissionRole: modRole.rawValue,
                auditEvent: audit
            )
        )
        groupCont.yield(GroupEvent(conversationID: conversationID, kind: .permissionsChanged))
    }

    /// Clears a role's channel permission override, restoring role
    /// defaults. Owner/admin only. Signed group event, replicated +
    /// audit-logged.
    func resetChannelPermissions(for role: MemberRole, conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        let modRole = role.moderationRole
        try? await moderation.mutate(id: conversationID) { state in
            state.policy.overrides.removeValue(forKey: modRole)
        }
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .permissionChanged,
            detail: "\(modRole.displayName) permissions reset to role defaults."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "permissionChanged",
                permissionRole: modRole.rawValue,
                permissionReset: true,
                auditEvent: audit
            )
        )
        groupCont.yield(GroupEvent(conversationID: conversationID, kind: .permissionsChanged))
    }

    /// Revokes the group's active invite: the generation bumps, and join
    /// requests referencing older generations are declined. Owner/admin
    /// only. Signed + audit-logged.
    func revokeInvite(conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole?.canModerate == true else { throw AegisCoreError.notModerator }
        var generation = 0
        try? await moderation.mutate(id: conversationID) { state in
            state.inviteGeneration += 1
            generation = state.inviteGeneration
        }
        let audit = await recordAdminAction(
            conversationID: conversationID,
            kind: .inviteRevoked,
            detail: "Invite revoked."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID,
                epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "inviteRevoked",
                inviteGeneration: generation,
                auditEvent: audit
            )
        )
    }

    /// Transfers ownership to another member; the current owner becomes an
    /// admin. Only the owner can do this. Signed + audit-logged.
    func transferOwnership(to fingerprint: Data, conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        guard sidecar.myRole == .owner else { throw AegisCoreError.notModerator }
        guard let local = try? await engine.localPublicIdentity(),
              fingerprint != local.fingerprint
        else {
            throw AegisCoreError.notPermitted("You already own this group.")
        }
        let members = (try? await pkgStore.memberships.members(of: packageID(conversationID))) ?? []
        guard members.contains(where: { $0.userID.rawValue == fingerprint.hexString }) else {
            throw AegisCoreError.notPermitted("That member is not in this group.")
        }
        let epoch = await engine.groupEpoch(groupID: groupID) ?? 0
        // Promote first, demote second: the group is never ownerless on
        // any honest client's screen.
        try await pkgStore.memberships.setRole(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(fingerprint.hexString),
            role: .owner
        )
        let auditNew = await recordAdminAction(
            conversationID: conversationID,
            kind: .ownershipTransferred,
            targetFingerprint: fingerprint,
            detail: "Ownership transferred."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID, epoch: epoch, kind: "roleChanged",
                fingerprint: fingerprint, role: "owner", auditEvent: auditNew
            )
        )
        try await pkgStore.memberships.setRole(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(local.fingerprint.hexString),
            role: .admin
        )
        var updated = await sidecars.load(id: conversationID)
        updated.myRole = .admin
        try? await sidecars.save(id: conversationID, sidecar: updated)
        let auditSelf = await recordAdminAction(
            conversationID: conversationID,
            kind: .roleChanged,
            targetFingerprint: local.fingerprint,
            detail: "Previous owner demoted to admin."
        )
        try await sendGroupControl(
            conversationID: conversationID, groupID: groupID,
            message: GroupControlMessage(
                groupID: groupID, epoch: epoch, kind: "roleChanged",
                fingerprint: local.fingerprint, role: "admin", auditEvent: auditSelf
            )
        )
        groupCont.yield(GroupEvent(
            conversationID: conversationID, kind: .roleChanged,
            memberKey: fingerprint, role: .owner
        ))
    }

    /// The channel's moderation snapshot for the settings UI.
    func moderationSnapshot(conversationID: UUID) async -> ChannelModerationSnapshot {
        let state = await moderation.load(id: conversationID)
        let keys = await auditActorKeys(conversationID: conversationID)
        let verification = state.auditLog.verify(with: auditCrypto(), actorKeys: keys)
        let myRole = await sidecars.load(id: conversationID).myRole
        return ChannelModerationSnapshot(
            policy: state.policy,
            auditEvents: state.auditLog.events,
            auditVerification: verification,
            myRole: myRole,
            inviteGeneration: state.inviteGeneration
        )
    }

    /// Records a local-only signed audit entry (see TransportService).
    func noteLocalAuditEvent(kind: GroupAdminEventKind, conversationID: UUID, detail: String?) async {
        _ = await recordAdminAction(
            conversationID: conversationID, kind: kind, detail: detail
        )
    }

    /// Presence suppression for the message-requests inbox and blocklist:
    /// while suppressed, no read receipts or typing indicators go out on
    /// this conversation.
    func setPresenceSuppressed(_ suppressed: Bool, conversationID: UUID) {
        if suppressed {
            presenceSuppressedConversations.insert(conversationID)
        } else {
            presenceSuppressedConversations.remove(conversationID)
        }
    }

    func isPresenceSuppressed(conversationID: UUID) -> Bool {
        presenceSuppressedConversations.contains(conversationID)
    }

    /// Encoded channel policy for inclusion in member-added announcements
    /// so joiners adopt the current policy instead of defaults.
    func encodedPolicy(conversationID: UUID) async -> Data? {
        let state = await moderation.load(id: conversationID)
        return try? JSONEncoder().encode(state.policy)
    }

    /// Sends a group control message. When `onMailboxes` is given, the
    /// ciphertext goes to exactly those mailboxes instead of the
    /// conversation's current one — used for membership announcements,
    /// which must reach members on the PRE-CHANGE mailboxes while they
    /// are still listening there.
    func sendGroupControl(
        conversationID: UUID,
        groupID: Data,
        message: GroupControlMessage,
        onMailboxes: [Data]? = nil
    ) async throws {
        let inner = GroupInnerPayload(kind: "control", body: try JSONEncoder().encode(message))
        let (wire, rotation) = try await engine.encryptGroup(try JSONEncoder().encode(inner), groupID: groupID)
        if !rotation.isEmpty { try await distribute(rotation) }
        if let mailboxes = onMailboxes {
            for mailbox in mailboxes {
                let frame = AegisFrame(
                    mailbox: MailboxID(mailbox),
                    envelopeID: try randomBytes(count: 16),
                    ttl: ttlForKind(.groupControl),
                    flags: 0,
                    payload: wire
                )
                try await hub.send(frame, policy: .allConnected)
            }
        } else {
            try await sendCiphertext(wire, conversationID: conversationID, kind: .groupControl)
        }
    }

    private func sendRaw(_ payload: Data, mailbox: Data, ttl: UInt32, flags: UInt8) async throws {
        let envelopeID = try randomBytes(count: 16)
        try await hub.send(
            AegisFrame(mailbox: MailboxID(mailbox), envelopeID: envelopeID, ttl: ttl, flags: flags, payload: payload),
            policy: .allConnected
        )
    }

    // MARK: - Calls

    func placeCall(to peer: IdentityPublic, conversationID: UUID, contactID: UUID, kind: CallKind) async throws -> UUID {
        let callID = UUID()
        // The media layer needs the kind before creating the offer so it
        // knows whether to start camera capture for the local tracks.
        (mediaDelegate as? any CallMediaControl)?.noteCallKind(kind, for: callID)
        // SDP comes from the app's WebRTC layer via the media delegate.
        // Without it the knock still goes out (signaling works, media waits).
        var sdp = "", dtlsFingerprint = ""
        if let delegate = mediaDelegate {
            let offer = try await delegate.createOffer(for: callID)
            sdp = offer.sdp
            dtlsFingerprint = offer.dtlsFingerprint
        }
        let offer = CallOffer(
            callID: callID.uuidString,
            sdp: sdp,
            dtlsFingerprint: dtlsFingerprint,
            callerFingerprintHex: (try await engine.localPublicIdentity()).fingerprint.hexString
        )
        let knock = KnockInfo(callID: callID.uuidString, offer: offer, mediaKind: kind == .video ? "video" : "audio")
        let control = TransportControl(kind: "knock", body: try JSONEncoder().encode(knock))
        let inner = try await engine.encryptDirect(try JSONEncoder().encode(control), to: peer)
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 300, flags: AegisFrame.flagKnock)
        activeCalls[callID] = ActiveCallContext(
            callID: callID, conversationID: conversationID, contactID: contactID,
            peerFingerprint: peer.fingerprint, direction: .outgoing,
            localDTLSFingerprint: dtlsFingerprint
        )
        callStateCont.yield(CallStateEvent(callID: callID, state: .dialing))
        return callID
    }

    private func handleKnock(_ knock: KnockInfo, from peer: IdentityPublic) async throws {
        guard let callID = UUID(uuidString: knock.callID) else { return }
        let conversationID = try await directConversationID(for: peer.fingerprint)
        // Resolve the app contact for display.
        let contactID = await resolveContactID(for: peer.fingerprint) ?? UUID()
        activeCalls[callID] = ActiveCallContext(
            callID: callID, conversationID: conversationID, contactID: contactID,
            peerFingerprint: peer.fingerprint, direction: .incoming,
            remoteDTLSFingerprint: knock.offer.dtlsFingerprint,
            remoteOfferSDP: knock.offer.sdp
        )
        (mediaDelegate as? any CallMediaControl)?.noteCallKind(
            knock.mediaKind == "video" ? .video : .audio, for: callID
        )
        incomingCallCont.yield(IncomingCall(
            id: callID,
            contactID: contactID,
            contactName: await resolveContactName(for: peer.fingerprint) ?? "Unknown",
            kind: knock.mediaKind == "video" ? .video : .audio,
            receivedAt: Date()
        ))
    }

    private func handleCallSignal(_ signal: CallSignal, from peer: IdentityPublic) async throws {
        let callIDString: String
        switch signal {
        case .offer(let offer): callIDString = offer.callID
        case .answer(let answer): callIDString = answer.callID
        case .ice(let ice): callIDString = ice.callID
        case .control(let id, let control):
            callIDString = id
            if let callID = UUID(uuidString: id) {
                switch control {
                case .reject, .busy, .hangup:
                    activeCalls.removeValue(forKey: callID)
                    teardownMedia(for: callID)
                    callStateCont.yield(CallStateEvent(callID: callID, state: .ended))
                case .ringing:
                    callStateCont.yield(CallStateEvent(callID: callID, state: .ringing))
                case .acceptedElsewhere:
                    activeCalls.removeValue(forKey: callID)
                    teardownMedia(for: callID)
                    callStateCont.yield(CallStateEvent(callID: callID, state: .ended))
                }
            }
            return
        }
        guard let callID = UUID(uuidString: callIDString) else { return }
        // The app's WebRTC layer consumes signaling via callStateEvents;
        // here we surface offers as state transitions the UI binds to.
        if case .offer = signal {
            // Already surfaced as incomingCallEvents via the knock path;
            // a repeated offer (LAN + relay duplicate) is deduped by the hub.
            _ = peer
        } else if case .answer(let answer) = signal {
            // The callee's DTLS fingerprint arrives with the answer: both
            // sides now have what they need for the SAS. Hand the SDP to
            // the media engine so the peer connection can complete.
            activeCalls[callID]?.remoteDTLSFingerprint = answer.dtlsFingerprint
            try await mediaDelegate?.setRemoteSDP(answer.sdp, for: callID)
            let sas = callSAS(for: callID)
            callStateCont.yield(CallStateEvent(callID: callID, state: .connected, sas: sas))
        } else if case .ice(let ice) = signal {
            try await mediaDelegate?.addIceCandidate(ice, for: callID)
        }
    }

    func sendCallSignal(_ signal: CallSignal, to peer: IdentityPublic) async throws {
        let control = TransportControl(kind: "callSignal", body: try JSONEncoder().encode(signal))
        let inner = try await engine.encryptDirect(try JSONEncoder().encode(control), to: peer)
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 300, flags: AegisFrame.flagTransportControl)
    }

    /// Trickle-ICE: sends a locally gathered candidate to the peer inside
    /// an E2EE envelope. Called by the media engine's ICE callback.
    func sendIceCandidate(_ candidate: IceCandidate, for callID: UUID) async throws {
        // 1:1 calls resolve the peer from the call context.
        if let context = activeCalls[callID],
           let peer = await engine.identityPublic(forFingerprint: context.peerFingerprint)
        {
            try await sendCallSignal(.ice(candidate), to: peer)
            return
        }
        // Voice-room mesh peers route by the room manager's per-peer table.
        let routes = await voiceRooms.peerRoutes
        if let route = routes[callID] {
            let localFP = await voiceRoomLocalFingerprintHex() ?? ""
            var signal = VoiceRoomSignal(
                kind: .ice,
                roomID: route.roomID.uuidString,
                senderFingerprintHex: localFP
            )
            signal.targetFingerprintHex = route.peerFingerprintHex
            signal.callID = callID.uuidString
            signal.ice = candidate
            try await sendVoiceRoomSignal(signal, conversationID: route.roomID)
        }
    }

    // MARK: - Media controls (forwarded to the attached WebRTC engine)

    private func mediaControl() throws -> any CallMediaControl {
        guard let control = mediaDelegate as? any CallMediaControl else {
            throw CallMediaError.engineUnavailable
        }
        return control
    }

    func setCallMuted(_ muted: Bool, callID: UUID) async throws {
        try await mediaControl().setMuted(muted, callID: callID)
    }

    func setCallVideoEnabled(_ enabled: Bool, callID: UUID) async throws {
        try await mediaControl().setVideoEnabled(enabled, callID: callID)
    }

    func setCallSpeaker(_ enabled: Bool, callID: UUID) async throws {
        try await mediaControl().setSpeaker(enabled, callID: callID)
    }

    func startScreenShare(callID: UUID) async throws {
        try await mediaControl().startScreenShare(callID: callID)
    }

    func stopScreenShare(callID: UUID) async throws {
        try await mediaControl().stopScreenShare(callID: callID)
    }

    /// Tears down the media session for a finished call. Called from every
    /// path that removes a call from `activeCalls`.
    private func teardownMedia(for callID: UUID) {
        (mediaDelegate as? any CallMediaControl)?.endCallMedia(callID)
        mediaRouter.setVideoSink(nil, for: callID)
    }

    func endCall(_ callID: UUID) async throws {
        guard let context = activeCalls[callID] else { return }
        if let peer = await engine.identityPublic(forFingerprint: context.peerFingerprint) {
            try await sendCallSignal(.control(callID: callID.uuidString, control: .hangup), to: peer)
        }
        activeCalls.removeValue(forKey: callID)
        teardownMedia(for: callID)
        callStateCont.yield(CallStateEvent(callID: callID, state: .ended))
    }

    // MARK: - Attachment contexts (unwrap needs the conversation)

    struct AttachmentContext: Sendable {
        var groupID: Data?
        var peerFingerprint: Data?
    }

    /// wrappedKey SHA-256 hex → context. Recorded at encrypt time (and when
    /// received messages are saved) because `decryptAttachment` has no
    /// conversation parameter.
    private var attachmentContexts: [String: AttachmentContext] = [:]

    func noteAttachmentContext(wrappedKey: Data, groupID: Data?, peerFingerprint: Data?) {
        let hash = Data(SHA256.hash(data: wrappedKey)).map { String(format: "%02x", $0) }.joined()
        attachmentContexts[hash] = AttachmentContext(groupID: groupID, peerFingerprint: peerFingerprint)
        // Persist: the in-memory dict does not survive an app restart, and
        // without the context inbound attachments can never be decrypted.
        // Fire-and-forget — persistence failures never break the send path.
        let repo = pkgStore.attachmentContexts
        Task.detached {
            try? await repo.saveAttachmentContext(keyHash: hash, groupID: groupID, peer: peerFingerprint)
        }
    }

    func attachmentContext(for wrappedKey: Data) async -> AttachmentContext? {
        let hash = Data(SHA256.hash(data: wrappedKey)).map { String(format: "%02x", $0) }.joined()
        if let context = attachmentContexts[hash] { return context }
        // Restart path: the in-memory dict is empty; fall back to the
        // persisted context, then warm the cache.
        if let stored = try? await pkgStore.attachmentContexts.loadAttachmentContext(keyHash: hash) {
            let context = AttachmentContext(groupID: stored.groupID, peerFingerprint: stored.peer)
            attachmentContexts[hash] = context
            return context
        }
        return nil
    }

    // MARK: - Attachment file keys

    /// The wrapped file key is only unwrappable while the sender's sender
    /// key is current (epoch window) — after rotations or a restart the
    /// unwrap fails even though the ciphertext blob is still on the relay.
    /// So we cache the RAW file key at the moment we know it (send time,
    /// or inbound receipt while the epoch is current) in the Keychain,
    /// keyed by the wrapped-key hash. The Keychain is device-encrypted;
    /// storing file keys there is no weaker than the SQLCipher database
    /// that already holds decrypted message bodies.
    func noteFileKey(_ fileKey: Data, wrappedKey: Data) {
        let hash = Data(SHA256.hash(data: wrappedKey)).map { String(format: "%02x", $0) }.joined()
        try? KeychainHelper.save(fileKey, service: "app.aegis.filekeys", account: hash)
    }

    func fileKey(forWrappedKey wrappedKey: Data) -> Data? {
        let hash = Data(SHA256.hash(data: wrappedKey)).map { String(format: "%02x", $0) }.joined()
        return try? KeychainHelper.load(service: "app.aegis.filekeys", account: hash)
    }

    // MARK: - Blob transfer (chunked sealed frames)

    /// uploadID hex → cached ciphertext blob, kept for re-transmission when
    /// a downloader's chunks never arrive (LAN transports don't retain
    /// frames; the relay inbox does, but only for 7 days). Bounded: 64
    /// blobs, oldest evicted first (files deleted with the entry).
    private var sentBlobCache: [String: URL] = [:]
    private static let maxSentBlobCache = 64

    private func rememberSentBlob(uploadID: Data, fileURL: URL) {
        let key = uploadID.hexString
        let cached = AegisPaths.sentBlobDirectory.appendingPathComponent(key, isDirectory: false)
        try? FileManager.default.removeItem(at: cached)
        guard (try? FileManager.default.copyItem(at: fileURL, to: cached)) != nil else { return }
        if let old = sentBlobCache[key] { try? FileManager.default.removeItem(at: old) }
        sentBlobCache[key] = cached
        while sentBlobCache.count > Self.maxSentBlobCache, let oldest = sentBlobCache.keys.sorted().first {
            if let url = sentBlobCache.removeValue(forKey: oldest) {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }

    /// Locator format: `<routing-mailbox hex>:<attachment UUID hex>`.
    /// The downloader parses it back to (mailbox, uploadID).
    func blobLocator(attachmentID: UUID, conversationID: UUID) async throws -> String {
        let (mailbox, _) = try await mailboxForConversation(conversationID, kind: .message)
        let uuidHex = attachmentID.uuidString.replacingOccurrences(of: "-", with: "")
        return mailbox.map { String(format: "%02x", $0) }.joined() + ":" + uuidHex
    }

    /// Uploads a ciphertext blob as chunked sealed frames. Chunk payload:
    /// `BlobChunkHeader(uploadID || index || count) || ciphertext-chunk`.
    /// The blob itself is already ciphertext (AttachmentCrypto) — the
    /// transport never sees plaintext.
    func uploadBlob(from fileURL: URL, id: UUID, conversationID: UUID) -> AsyncStream<Double> {
        let (stream, continuation) = AsyncStream<Double>.makeStream()
        // Cache for re-transmission before detaching (actor-isolated).
        let uuidHex = id.uuidString.replacingOccurrences(of: "-", with: "")
        let uploadID = Data(hexString: uuidHex) ?? Data(count: 16)
        rememberSentBlob(uploadID: uploadID, fileURL: fileURL)
        // Detached: chunked uploads must not serialize on the core actor.
        Task.detached { [hub] in
            do {
                let data = try Data(contentsOf: fileURL)
                let (mailbox, _) = try await self.mailboxForConversation(conversationID, kind: .message)
                for await progress in Self.sendBlobChunks(data: data, uploadID: uploadID, mailbox: mailbox, hub: hub) {
                    continuation.yield(progress)
                }
                continuation.finish()
            } catch {
                continuation.finish()
            }
        }
        return stream
    }

    /// Sends chunk frames for one blob. Static so both the initial upload
    /// and re-transmissions share the exact wire format.
    private static func sendBlobChunks(
        data: Data, uploadID: Data, mailbox: Data, hub: TransportHub
    ) -> AsyncStream<Double> {
        let (stream, continuation) = AsyncStream<Double>.makeStream()
        Task.detached {
            do {
                let chunkSize = AegisFrame.maxPayloadSize - BlobChunkHeader.size
                let count = max(1, (data.count + chunkSize - 1) / chunkSize)
                for index in 0..<count {
                    let start = index * chunkSize
                    let end = min(start + chunkSize, data.count)
                    var payload = BlobChunkHeader.encode(
                        uploadID: uploadID,
                        index: UInt32(index),
                        count: UInt32(count)
                    )
                    payload.append(data.subdata(in: start..<end))
                    let frame = AegisFrame(
                        mailbox: MailboxID(mailbox),
                        envelopeID: try randomBytes(count: 16),
                        ttl: 7 * 24 * 3600,
                        flags: index == count - 1 ? AegisFrame.flagFinalChunk : 0,
                        payload: payload
                    )
                    try await hub.send(frame, policy: .allConnected)
                    continuation.yield(Double(index + 1) / Double(count))
                }
                continuation.finish()
            } catch {
                continuation.finish()
            }
        }
        return stream
    }

    /// Re-transmits a cached blob (same uploadID, so the downloader's
    /// in-flight reassembly merges the chunks). Returns false when the
    /// blob is no longer cached.
    private func retransmitBlob(uploadID: Data, mailbox: Data) async -> Bool {
        guard let url = sentBlobCache[uploadID.hexString],
              let data = try? Data(contentsOf: url)
        else { return false }
        for await _ in Self.sendBlobChunks(data: data, uploadID: uploadID, mailbox: mailbox, hub: hub) {}
        return true
    }

    /// Asks whoever uploaded a blob to re-transmit its chunks. Used by
    /// downloadBlob before listening (covers LAN transports with no frame
    /// retention) and after a stall. Anyone holding the blob may answer;
    /// chunk reassembly deduplicates by index.
    private func requestBlobRedelivery(uploadID: Data, mailbox: Data) async {
        guard let route = routes[MailboxID(mailbox).hex] else { return }
        switch route {
        case .group(let groupID, let conversationID):
            let message = GroupControlMessage(
                groupID: groupID,
                epoch: await engine.groupEpoch(groupID: groupID) ?? 0,
                kind: "blobRequest",
                blobUploadID: uploadID.hexString
            )
            // Best-effort: the uploader may be offline; the relay inbox or
            // a later retry covers it.
            try? await sendGroupControl(conversationID: conversationID, groupID: groupID, message: message)
        case .direct(let fingerprint):
            guard let peer = await engine.identityPublic(forFingerprint: fingerprint) else { return }
            let body = BlobRequestBody(uploadID: uploadID.hexString)
            guard let bodyData = try? JSONEncoder().encode(body),
                  let control = try? JSONEncoder().encode(TransportControl(kind: "blobRequest", body: bodyData)),
                  let inner = try? await engine.encryptDirect(control, to: peer),
                  let mailbox = try? await engine.directRoutingMailbox(peer: peer)
            else { return }
            try? await sendRaw(inner.wire, mailbox: mailbox, ttl: 7 * 24 * 3600, flags: AegisFrame.flagTransportControl)
        case .deviceLink:
            break // blob redelivery is not a device-link concern
        }
    }

    /// Downloads a blob previously uploaded with `uploadBlob`. Detached so a
    /// long download never serializes on the core actor (`hub.inbound` is a
    /// broadcast — every consumer sees every frame).
    func downloadBlob(locator: String, to fileURL: URL) -> AsyncStream<Double> {
        let (stream, continuation) = AsyncStream<Double>.makeStream()
        Task.detached { [hub] in
            do {
                let parts = locator.split(separator: ":")
                guard parts.count == 2,
                      let mailbox = MailboxID(hex: String(parts[0])),
                      let uploadID = Data(hexString: String(parts[1]))
                else { throw TransportError.malformedFrame }
                // Bind the source mailbox for the duration of the download.
                await hub.bind(mailbox)
                defer { Task.detached { [hub] in await hub.unbind(mailbox) } }
                // Ask the uploader to re-transmit: on transports without
                // frame retention (LAN) the chunks would otherwise never
                // arrive, and this download would hang to the deadline.
                // Best-effort and idempotent — reassembly dedupes by index.
                await self.requestBlobRedelivery(uploadID: uploadID, mailbox: mailbox.bytes)
                var chunks: [UInt32: Data] = [:]
                var expectedCount: UInt32? = nil
                let deadline = Date().addingTimeInterval(300)
                for await frame in hub.inbound {
                    guard frame.mailbox == mailbox,
                          let header = BlobChunkHeader.decode(frame.payload),
                          header.uploadID == uploadID
                    else { continue }
                    expectedCount = header.count
                    chunks[header.index] = frame.payload.dropFirst(BlobChunkHeader.size)
                    if let count = expectedCount {
                        continuation.yield(Double(chunks.count) / Double(count))
                        if chunks.count == Int(count) { break }
                    }
                    if Date() > deadline { break }
                }
                guard let count = expectedCount, chunks.count == Int(count) else {
                    throw TransportError.timeout
                }
                var assembled = Data()
                for index in 0..<count { assembled.append(chunks[index] ?? Data()) }
                try assembled.write(to: fileURL, options: .completeFileProtection)
                continuation.finish()
            } catch {
                continuation.finish()
            }
        }
        return stream
    }

    // MARK: - Calls (media delegate seam)

    /// The app's WebRTC stack. Without it, signaling runs with empty SDP —
    /// the knock/offer/answer/ICE state machine works, media does not.
    var mediaDelegate: (any CallMediaDelegate)?

    func setMediaDelegate(_ delegate: (any CallMediaDelegate)?) {
        mediaDelegate = delegate
    }

    func activeCallContext(_ callID: UUID) -> ActiveCallContext? {
        activeCalls[callID]
    }

    /// Records the local DTLS fingerprint once the media stack (or the
    /// answer path) produces it. For the callee this is the moment both
    /// fingerprints may be known, so the SAS is emitted if computable.
    func noteLocalDTLSFingerprint(_ fingerprint: String, for callID: UUID) {
        activeCalls[callID]?.localDTLSFingerprint = fingerprint
        if let sas = callSAS(for: callID) {
            // The callee's UI already shows .connecting (set when answering);
            // re-yield it with the SAS attached rather than inventing a
            // state transition.
            callStateCont.yield(CallStateEvent(callID: callID, state: .connecting, sas: sas))
        }
    }

    /// The ZRTP-style Short Authentication String for this call, or nil
    /// when either DTLS fingerprint is missing. Both sides compute the same
    /// value independently; the UI ceremony (read aloud, compare) binds the
    /// *media* keys to the verified conversation.
    private func callSAS(for callID: UUID) -> String? {
        guard let context = activeCalls[callID] else { return nil }
        return CallSAS.shortAuthString(
            localHex: context.localDTLSFingerprint,
            remoteHex: context.remoteDTLSFingerprint
        )
    }

    func dropCall(_ callID: UUID) {
        activeCalls.removeValue(forKey: callID)
        teardownMedia(for: callID)
    }

    /// The inbound SDP offer stored when the knock arrived. The media
    /// engine answers against this real remote description.
    func remoteOfferSDP(for callID: UUID) -> String {
        activeCalls[callID]?.remoteOfferSDP ?? ""
    }

    func retryConnection() async {
        await hub.start()
        connectionCont.yield(currentConnectionStateSync())
    }

    func unbindAndForget(mailbox: Data) async {
        await unbind(mailbox: mailbox)
    }

    // MARK: - Contact resolution

    func resolveContactID(for fingerprint: Data) async -> UUID? {
        let contacts = (try? await pkgStore.contacts.list(includeBlocked: true)) ?? []
        for contact in contacts where contact.identityKeyFingerprint == fingerprint.hexString {
            return UUID(uuidString: contact.id.rawValue)
        }
        return nil
    }

    func resolveContactName(for fingerprint: Data) async -> String? {
        let contacts = (try? await pkgStore.contacts.list(includeBlocked: true)) ?? []
        return contacts.first { $0.identityKeyFingerprint == fingerprint.hexString }?.displayName
    }

    // MARK: - Helpers

    private func roleFromString(_ role: String?) -> AegisStore.MemberRole {
        switch role {
        case "owner": return .owner
        case "admin": return .admin
        case "moderator": return .moderator
        case "guest": return .guest
        default: return .member
        }
    }

    private func appRoleFromString(_ role: String) -> MemberRole? {
        switch role {
        case "owner": return .owner
        case "admin": return .admin
        case "moderator": return .moderator
        case "guest": return .guest
        default: return .member
        }
    }
}

// MARK: - Private helpers

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}

/// 32 bytes from the platform CSPRNG. Fails loudly, never silently.
private func randomBytes(count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else { throw AegisCryptoError.randomnessFailure }
    return Data(bytes)
}
