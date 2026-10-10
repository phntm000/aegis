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
import AegisStore
import AegisTransport
import CryptoKit
import Foundation
import Security

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
struct GroupControlMessage: Codable, Sendable {
    var v: Int = 1
    var groupID: Data
    var epoch: UInt32
    /// "memberAdded" | "memberRemoved" | "roleChanged" | "topicChanged" | "announcementModeChanged"
    var kind: String
    var fingerprint: Data?
    var role: String?
    var topic: String?
    var announcementOnly: Bool?
}

/// Invitation for a new group member (1:1 encrypted, alongside the sender-
/// key distribution). The member needs the roster to construct GroupSession.
struct GroupInviteInfo: Codable, Sendable {
    var v: Int = 1
    var groupID: Data
    var epoch: UInt32
    var name: String
    var topic: String?
    /// Fingerprint hex → display name.
    var members: [String: String]
}

/// Call knock body (flagKnock frame, short TTL).
struct KnockInfo: Codable, Sendable {
    var v: Int = 1
    var callID: String
    var offer: CallOffer
    /// "audio" | "video"
    var mediaKind: String = "audio"
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

// MARK: - AegisCore

actor AegisCore {
    enum RouteTarget {
        case direct(fingerprint: Data)
        case group(groupID: Data, conversationID: UUID)
    }

    // MARK: Owned packages

    let engine: CryptoEngine
    let pkgStore: any AegisDatabase
    let sidecars: ConversationSidecarStore
    let keyDirectory: ContactKeyDirectory

    // MARK: Transport

    var hub: TransportHub
    var lan: LANTransport
    var relay: RelayTransport?
    var delivery: DeliveryCoordinator
    let mediaRouter = CallMediaRouter()
    private(set) var relayConfig: RelayConfig = .default

    // MARK: Routing

    /// mailbox hex → target. The relay routes on the mailbox; we resolve it
    /// to a conversation/peer without decrypting anything.
    private var routes: [String: RouteTarget] = [:]
    /// Group frames that arrived before their sender-key distribution.
    /// Retried when the distribution lands. Bounded: 50 per group.
    private var pendingGroupFrames: [String: [AegisFrame]] = [:]

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
    }

    private var activeCalls: [UUID: ActiveCallContext] = [:]

    // MARK: Init

    init(
        engine: CryptoEngine,
        pkgStore: any AegisDatabase,
        sidecars: ConversationSidecarStore,
        keyDirectory: ContactKeyDirectory
    ) {
        self.engine = engine
        self.pkgStore = pkgStore
        self.sidecars = sidecars
        self.keyDirectory = keyDirectory

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
        Task { [weak self] in try? await self?.start() }
    }

    // MARK: - Startup

    private var didStart = false
    private var consumeGeneration = 0

    /// Builds routes from the store, binds mailboxes, starts transports.
    /// Retried automatically until it succeeds (didStart flips only then).
    func start() async throws {
        guard !didStart else { return }
        _ = try await engine.restoreIdentity()
        try await rebuildRoutesFromStore()
        await hub.start()
        delivery.start()
        connectionCont.yield(currentConnectionStateSync())
        didStart = true
        let generation = consumeGeneration
        Task { await self.consumeInbound(generation: generation) }
        Task { await self.consumeCoordinatorEvents(generation: generation) }
        Task { await self.watchTransportStates(generation: generation) }
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
        let mailbox = try await engine.groupRoutingMailbox(groupID: groupID)
        await bind(mailbox: mailbox, route: .group(groupID: groupID, conversationID: conversationID))
    }

    /// Rebinds a group mailbox after an epoch bump (membership change).
    func rebindGroup(groupID: Data, conversationID: UUID, oldMailbox: Data) async throws {
        await unbind(mailbox: oldMailbox)
        try await bindGroup(groupID: groupID, conversationID: conversationID)
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
        // Generation bump retires the old consume tasks before the rebuild.
        consumeGeneration &+= 1
        // Rebuild the hub with the right relay transport.
        await hub.stop()
        var transports: [any Transport] = [lan]
        var newRelay: RelayTransport? = nil
        switch config.mode {
        case .automatic:
            if let url = URL(string: "wss://relay.aegis.example") {
                newRelay = RelayTransport(url: url)
                transports.append(newRelay!)
            }
        case .customRelay:
            if let raw = config.customRelayURL, let url = URL(string: raw) {
                newRelay = RelayTransport(url: url)
                transports.append(newRelay!)
            }
        case .lanOnly:
            break
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
        connectionCont.yield(currentConnectionStateSync())
    }

    func currentConnectionStateSync() -> ConnectionState {
        let relayState = relay?.currentState ?? .idle
        let lanState = lan.currentState
        switch (relayConfig.mode, relayState, lanState) {
        case (.lanOnly, _, .connected): return .lanOnly
        case (.lanOnly, _, _): return .offline
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
                try await handleDirectFrame(frame, peerFingerprint: fingerprint)
            case .group(let groupID, let conversationID):
                try await handleGroupFrame(frame, groupID: groupID, conversationID: conversationID)
            }
        } catch {
            // Untrusted network: drop undecryptable frames silently.
            // (A real UI signal for "session reset needed" is emitted by
            // the app when ITS decrypt fails, not here.)
        }
    }

    private func handleDirectFrame(_ frame: AegisFrame, peerFingerprint: Data) async throws {
        guard let peer = await engine.identityPublic(forFingerprint: peerFingerprint) else { return }
        if frame.flags & AegisFrame.flagTransportControl != 0 {
            // Transport-internal: the core consumes it fully.
            let plaintext = try engine.decryptDirect(frame.payload, from: peer)
            // Distributions are detected by parse (the engine sends them
            // as encryptDirect(distribution.serialized()) with no JSON
            // wrapper); everything else is a TransportControl envelope.
            if let dist = try? SenderKeyDistribution(serialized: plaintext) {
                try await engine.ingestDistribution(dist, groupID: dist.groupID, fromSender: dist.senderID)
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
        case "sessionReset":
            break // peer re-establishes on next outbound; nothing to do
        default:
            break
        }
    }

    private func handleGroupFrame(frame: AegisFrame, groupID: Data, conversationID: UUID) async throws {
        let groupMessage = try GroupMessage.parse(frame.payload)
        do {
            let plaintext = try await engine.decryptGroup(frame.payload, groupID: groupID)
            let inner = try JSONDecoder().decode(GroupInnerPayload.self, from: plaintext)
            switch inner.kind {
            case "control":
                let control = try JSONDecoder().decode(GroupControlMessage.self, from: inner.body)
                try await handleGroupControl(control, conversationID: conversationID)
            default:
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

    private func handleGroupControl(_ control: GroupControlMessage, conversationID: UUID) async throws {
        // Update the package memberships so roles survive restarts.
        let cid: AegisStore.ConversationID = packageID(conversationID)
        switch control.kind {
        case "memberAdded":
            if let fp = control.fingerprint {
                let membership = AegisStore.GroupMembership(
                    conversationID: cid,
                    userID: AegisStore.UserID(fp.hexString),
                    role: roleFromString(control.role)
                )
                try await pkgStore.memberships.upsert(membership)
            }
        case "memberRemoved":
            if let fp = control.fingerprint {
                try await pkgStore.memberships.remove(conversationID: cid, userID: AegisStore.UserID(fp.hexString))
            }
        case "roleChanged":
            if let fp = control.fingerprint {
                try await pkgStore.memberships.setRole(
                    conversationID: cid, userID: AegisStore.UserID(fp.hexString),
                    role: roleFromString(control.role)
                )
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
        default: kind = .announcementModeChanged
        }
        groupCont.yield(GroupEvent(
            conversationID: conversationID,
            kind: kind,
            memberKey: control.fingerprint,
            role: control.role.flatMap { appRoleFromString($0) },
            topic: control.kind == "topicChanged" ? control.topic : nil,
            announcementOnly: control.announcementOnly
        ))
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
        let pairs = try await engine.distributeEncrypted(distributions)
        for (peer, wire) in pairs {
            let mailbox = try await engine.directRoutingMailbox(peer: peer)
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
        for member in members { roster[member.fingerprint.hexString] = "" }
        let invite = GroupInviteInfo(
            groupID: groupID,
            epoch: 0,
            name: name,
            topic: topic,
            members: roster
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
            if let data = Data(hexString: hex),
               let pub = await engine.identityPublic(forFingerprint: data)
            {
                members.append(pub)
            }
        }
        let distributions = try await engine.joinGroup(groupID: invite.groupID, epoch: invite.epoch, members: members)
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
                try await upsertMembership(conversationID: conversationID, fingerprint: data, role: "member")
            }
        }
        // Publish our sender key to the group.
        try await distribute(distributions)
    }

    /// contactID is accepted for the app-layer signature and intentionally
    /// unused here (the crypto identity is the peer fingerprint).
    func inviteMember(_ contactID: UUID, conversationID: UUID, peer: IdentityPublic) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        let oldMailbox = try await engine.groupRoutingMailbox(groupID: groupID)
        let distributions = try await engine.updateGroupMembership(groupID: groupID, add: [peer], remove: [])
        try await rebindGroup(groupID: groupID, conversationID: conversationID, oldMailbox: oldMailbox)
        try await upsertMembership(conversationID: conversationID, fingerprint: peer.fingerprint, role: "member")
        try await distribute(distributions)
        // Invite + control message.
        let invite = GroupInviteInfo(
            groupID: groupID,
            epoch: engine.groupEpoch(groupID: groupID) ?? 0,
            name: "", topic: nil,
            members: [peer.fingerprint.hexString: ""]
        )
        let control = TransportControl(kind: "groupInvite", body: try JSONEncoder().encode(invite))
        let inner = try await engine.encryptDirect(try JSONEncoder().encode(control), to: peer)
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 0, flags: AegisFrame.flagTransportControl)
        try await sendGroupControl(conversationID: conversationID, groupID: groupID,
                                   message: GroupControlMessage(groupID: groupID,
                                                                epoch: engine.groupEpoch(groupID: groupID) ?? 0,
                                                                kind: "memberAdded",
                                                                fingerprint: peer.fingerprint,
                                                                role: "member"))
    }

    func removeMember(_ fingerprint: Data, conversationID: UUID) async throws {
        let sidecar = await sidecars.load(id: conversationID)
        guard let groupID = sidecar.cryptoGroupID else { throw CryptoEngineError.unknownGroup }
        let oldMailbox = try await engine.groupRoutingMailbox(groupID: groupID)
        let distributions = try await engine.updateGroupMembership(groupID: groupID, add: [], remove: [fingerprint])
        try await rebindGroup(groupID: groupID, conversationID: conversationID, oldMailbox: oldMailbox)
        try await pkgStore.memberships.remove(
            conversationID: packageID(conversationID),
            userID: AegisStore.UserID(fingerprint.hexString)
        )
        try await distribute(distributions)
        try await sendGroupControl(conversationID: conversationID, groupID: groupID,
                                   message: GroupControlMessage(groupID: groupID,
                                                                epoch: engine.groupEpoch(groupID: groupID) ?? 0,
                                                                kind: "memberRemoved",
                                                                fingerprint: fingerprint))
    }

    func sendGroupControl(conversationID: UUID, groupID: Data, message: GroupControlMessage) async throws {
        let inner = GroupInnerPayload(kind: "control", body: try JSONEncoder().encode(message))
        let (wire, rotation) = try await engine.encryptGroup(try JSONEncoder().encode(inner), groupID: groupID)
        if !rotation.isEmpty { try await distribute(rotation) }
        try await sendCiphertext(wire, conversationID: conversationID, kind: .groupControl)
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
            peerFingerprint: peer.fingerprint, direction: .outgoing
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
            peerFingerprint: peer.fingerprint, direction: .incoming
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
                    callStateCont.yield(CallStateEvent(callID: callID, state: .ended))
                case .ringing:
                    callStateCont.yield(CallStateEvent(callID: callID, state: .ringing))
                case .acceptedElsewhere:
                    activeCalls.removeValue(forKey: callID)
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
        } else if case .answer = signal {
            callStateCont.yield(CallStateEvent(callID: callID, state: .connected))
        }
    }

    func sendCallSignal(_ signal: CallSignal, to peer: IdentityPublic) async throws {
        let control = TransportControl(kind: "callSignal", body: try JSONEncoder().encode(signal))
        let inner = try await engine.encryptDirect(try JSONEncoder().encode(control), to: peer)
        let mailbox = try await engine.directRoutingMailbox(peer: peer)
        try await sendRaw(inner.wire, mailbox: mailbox, ttl: 300, flags: AegisFrame.flagTransportControl)
    }

    func endCall(_ callID: UUID) async throws {
        guard let context = activeCalls[callID] else { return }
        if let peer = await engine.identityPublic(forFingerprint: context.peerFingerprint) {
            try await sendCallSignal(.control(callID: callID.uuidString, control: .hangup), to: peer)
        }
        activeCalls.removeValue(forKey: callID)
        mediaRouter.setVideoSink(nil, for: callID)
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
    }

    func attachmentContext(for wrappedKey: Data) -> AttachmentContext? {
        let hash = Data(SHA256.hash(data: wrappedKey)).map { String(format: "%02x", $0) }.joined()
        return attachmentContexts[hash]
    }

    // MARK: - Blob transfer (chunked sealed frames)

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
        // Detached: chunked uploads must not serialize on the core actor.
        Task.detached { [hub] in
            do {
                let data = try Data(contentsOf: fileURL)
                let chunkSize = AegisFrame.maxPayloadSize - BlobChunkHeader.size
                let count = max(1, (data.count + chunkSize - 1) / chunkSize)
                let (mailbox, _) = try await self.mailboxForConversation(conversationID, kind: .message)
                var uploadID = Data(count: 16)
                let uuidBytes = id.uuidString.replacingOccurrences(of: "-", with: "")
                if let parsed = Data(hexString: uuidBytes) { uploadID = parsed }
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

    func dropCall(_ callID: UUID) {
        activeCalls.removeValue(forKey: callID)
        mediaRouter.setVideoSink(nil, for: callID)
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
        case "admin", "moderator": return .admin
        default: return .member
        }
    }
}

// MARK: - Private helpers

private extension Data {
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
