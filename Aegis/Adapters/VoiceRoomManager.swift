import AegisCrypto
import AVFAudio
import Foundation
import OSLog
import WebRTCBridge

// MARK: - VoiceRoomManager
//
// Owns voice-room sessions for the app. One room is active at a time (the
// Discord voice-channel model: joining a second room leaves the first).
//
// The manager is a plain class whose methods are only ever invoked from
// `AegisCore`'s actor context, so its mutable state needs no extra
// synchronization. Signaling rides the group's existing E2EE sender-key
// channel via `GroupControlMessage` kind "voiceRoom"; audio is a full WebRTC
// mesh with one peer connection per remote participant, reusing
// `WebRTCMediaEngine`'s per-UUID peer sessions.
//
// Video: every mesh peer connection negotiates a video m-line (the local
// video track exists but stays disabled until the user enables the camera),
// so toggling the camera needs no renegotiation — one shared
// AVCaptureSession fans out to all peers (see CameraFrameFanOut).
//
// Forward secrecy for membership changes: every join/leave/expiry bumps a
// membership epoch. All members tear down their mesh peer connections, the
// engine drops its cached peer-connection factory (fresh DTLS certificate),
// and the mesh is re-established with fresh DTLS-SRTP handshakes — a
// departed member's keys can't decrypt anything negotiated after they left.
//
// Speaking indicators are computed LOCALLY from WebRTC audio levels polled
// on this device. Levels and audio never leave the device; the only thing
// that changes on the wire is nothing at all.

/// Routing entry so trickle-ICE candidates gathered by the media engine find
/// their voice-room peer (the 1:1 call path uses `activeCalls` instead).
struct VoiceRoomPeerRoute: Sendable {
    let roomID: UUID
    let peerFingerprintHex: String
}

actor VoiceRoomManager {

    private let log = Logger(subsystem: "app.aegis.ios", category: "voiceroom")

    /// Back-reference to the core for group-channel sends, the media
    /// engine, and local identity. Weak to avoid a retain cycle. Assigned
    /// via setCore after AegisCore finishes init.
    private weak var core: AegisCore?

    private var room: VoiceRoom?
    /// fingerprintHex → per-peer WebRTC session UUID (this side's key into
    /// the media engine; the offerer chooses it and the answerer echoes it).
    private var peerCallIDs: [String: UUID] = [:]
    /// Membership epoch for forward secrecy (see header). Bumped on every
    /// locally observed join/leave/expiry; adopted from `epochBump`
    /// signals when a peer saw a change we missed.
    private var mediaEpoch: UInt64 = 0
    /// Local-only per-user output gain, 0.0–1.0, keyed by fingerprint hex.
    /// Applied to the engine whenever the peer's session (re)starts.
    private var peerMuted: [String: Bool] = [:]
    /// Speaking-detection hysteresis over locally polled audio levels.
    private var speakingDetector = SpeakingDetector()
    private var heartbeatTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?

    private let eventCont: AsyncStream<VoiceRoomEvent>.Continuation
    let events: AsyncStream<VoiceRoomEvent>

    init() {
        let (stream, cont) = AsyncStream<VoiceRoomEvent>.makeStream()
        self.events = stream
        self.eventCont = cont
    }

    /// Called once by AegisCore after its init completes.
    func setCore(_ core: AegisCore) {
        self.core = core
    }

    private func media() async -> (any CallMediaDelegate)? {
        await core?.voiceRoomMedia()
    }

    private func mediaControl() async -> (any CallMediaControl)? {
        await core?.voiceRoomMediaControl()
    }

    private func localFingerprintHex() async -> String? {
        guard let core else { return nil }
        return await core.voiceRoomLocalFingerprintHex()
    }

    private func localDisplayName() async -> String {
        await core?.voiceRoomLocalDisplayName() ?? "Unknown"
    }

    private func sendSignal(_ signal: VoiceRoomSignal, conversationID: UUID) async throws {
        guard let core else { return }
        try await core.sendVoiceRoomSignal(signal, conversationID: conversationID)
    }

    // MARK: - Public state

    var currentRoom: VoiceRoom? { room }

    /// Called from AegisCore (also an actor) when routing ICE candidates.
    var peerRoutes: [UUID: VoiceRoomPeerRoute] {
        guard let room else { return [:] }
        var out: [UUID: VoiceRoomPeerRoute] = [:]
        for (fp, callID) in peerCallIDs {
            out[callID] = VoiceRoomPeerRoute(roomID: room.conversationID, peerFingerprintHex: fp)
        }
        return out
    }

    // MARK: - Join / leave

    /// Joins the voice room attached to a group conversation. Joining a
    /// second room leaves the first.
    func joinRoom(conversationID: UUID, groupName: String) async {
        if let current = room, current.conversationID != conversationID {
            await leaveRoom()
        }
        guard room?.conversationID != conversationID else { return }
        guard let localFP = await localFingerprintHex() else {
            log.error("Voice room join aborted: no local identity")
            room = VoiceRoom(
                conversationID: conversationID,
                groupName: groupName,
                participants: [],
                localMuted: false,
                localDeafened: false,
                joinedAt: nil,
                joinState: .failed("Couldn't load your identity. Check your connection and try again.")
            )
            emit()
            return
        }
        // The joiner becomes the room creator and initial stage host.
        // Late joiners learn the creator/host from join/heartbeat signals.
        var me = VoiceRoomParticipant(
            fingerprintHex: localFP,
            displayName: await localDisplayName(),
            isMuted: false,
            isDeafened: false,
            joinedAt: Date(),
            lastHeartbeat: Date(),
            isLocal: true
        )
        me.isSpeaker = true // the creator can always talk
        room = VoiceRoom(
            conversationID: conversationID,
            groupName: groupName,
            participants: [me],
            localMuted: false,
            localDeafened: false,
            joinedAt: Date(),
            stageHostFingerprintHex: localFP,
            createdByFingerprintHex: localFP,
            joinState: .joining
        )
        checkMicrophonePermission()
        wireEngineCallbacks()
        (await mediaControl())?.setAudioLevelPolling(true)
        startHeartbeat()
        startExpirySweep()
        emit()
        // Announce presence; mesh offers to already-present peers follow
        // when their heartbeats arrive (or immediately for known members —
        // the roster only fills via signaling, so join is the trigger).
        do {
            try await broadcast(kind: .join)
        } catch {
            log.error("Voice room join broadcast failed: \(error.localizedDescription)")
            setJoinState(.failed("Couldn't reach the room. Check your connection and try again."))
            return
        }
        // Offer to everyone already listed (rejoin race: they re-announce).
        for p in room?.participants ?? [] where !p.isLocal {
            await ensureOffer(to: p.fingerprintHex)
        }
        setJoinState(.joined)
        log.info("Joined voice room \(conversationID.uuidString.prefix(8))")
    }

    /// Retries a failed join.
    func retryJoin() async {
        guard let current = room, case .failed = current.joinState else { return }
        let conversationID = current.conversationID
        let groupName = current.groupName
        await leaveRoom(silent: true)
        await joinRoom(conversationID: conversationID, groupName: groupName)
    }

    private func setJoinState(_ state: RoomJoinState) {
        guard var current = room else { return }
        current.joinState = state
        room = current
        emit()
    }

    func leaveRoom() async {
        await leaveRoom(silent: false)
    }

    private func leaveRoom(silent: Bool) async {
        guard let current = room else { return }
        heartbeatTask?.cancel(); heartbeatTask = nil
        expiryTask?.cancel(); expiryTask = nil
        let control = await mediaControl()
        control?.setAudioLevelPolling(false)
        control?.onAudioLevels = nil
        control?.onPeerConnectionStateChanged = nil
        control?.onCameraPermissionDenied = nil
        if !silent {
            try? await broadcast(kind: .leave)
        }
        for (_, callID) in peerCallIDs {
            control?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        peerMuted.removeAll()
        speakingDetector = SpeakingDetector()
        mediaEpoch = 0
        room = nil
        emit()
        log.info("Left voice room")
        _ = current
    }

    /// Wires the engine's voice-room callbacks for this session.
    private func wireEngineCallbacks() {
        Task { [weak self] in
            guard let control = await self?.mediaControl() else { return }
            control.onAudioLevels = { [weak self] levels in
                Task { await self?.handleAudioLevels(levels) }
            }
            control.onPeerConnectionStateChanged = { [weak self] callID, state in
                Task { await self?.handlePeerConnectionState(callID, state) }
            }
            control.onCameraPermissionDenied = { [weak self] in
                Task { await self?.handleCameraPermissionDenied() }
            }
        }
    }

    private func checkMicrophonePermission() {
        // Deployment target is iOS 17: AVAudioApplication is always available.
        let denied = AVAudioApplication.shared.recordPermission == .denied
        guard denied, var current = room else { return }
        current.micPermissionDenied = true
        room = current
        emit()
    }

    private func handleCameraPermissionDenied() {
        guard var current = room else { return }
        current.cameraPermissionDenied = true
        current.localCameraOn = false
        if let idx = current.participants.firstIndex(where: \.isLocal) {
            current.participants[idx].isCameraOn = false
        }
        room = current
        eventCont.yield(.cameraPermissionDenied)
        emit()
    }

    // MARK: - Local audio/video state

    func setLocalMuted(_ muted: Bool) async {
        guard var current = room else { return }
        if !muted, current.mode == .stage,
           let local = current.participants.first(where: \.isLocal),
           !canTransmit(mode: .stage, participant: local)
        {
            // Stage mode: the audience can't unmute themselves. The UI
            // disables the button; this is the backstop.
            log.info("Unmute blocked: stage audience member")
            emit()
            return
        }
        current.localMuted = muted
        if let idx = current.participants.firstIndex(where: \.isLocal) {
            current.participants[idx].isMuted = muted
        }
        room = current
        for (_, callID) in peerCallIDs {
            try? await (await mediaControl())?.setMuted(muted, callID: callID)
        }
        try? await broadcast(kind: .muteState)
        emit()
    }

    func setLocalDeafened(_ deafened: Bool) async {
        guard var current = room else { return }
        current.localDeafened = deafened
        if let idx = current.participants.firstIndex(where: \.isLocal) {
            current.participants[idx].isDeafened = deafened
        }
        room = current
        for (_, callID) in peerCallIDs {
            (await mediaControl())?.setRemoteAudioEnabled(!deafened, for: callID)
        }
        try? await broadcast(kind: .muteState)
        emit()
    }

    // MARK: - Local camera

    /// Enables/disables camera publishing. The video m-line already exists
    /// on every mesh peer connection (negotiated disabled), so no
    /// renegotiation is needed — the shared camera fan-out just starts or
    /// stops feeding frames.
    func setLocalCameraEnabled(_ enabled: Bool) async {
        guard var current = room else { return }
        current.localCameraOn = enabled
        if let idx = current.participants.firstIndex(where: \.isLocal) {
            current.participants[idx].isCameraOn = enabled
        }
        room = current
        for (_, callID) in peerCallIDs {
            try? await (await mediaControl())?.setVideoEnabled(enabled, callID: callID)
        }
        try? await broadcast(kind: .cameraState)
        emit()
    }

    func attachLocalPreview(_ renderer: RTCVideoRenderer) {
        Task { [weak self] in
            await self?.mediaControl()?.attachLocalVideoRenderer(renderer)
        }
    }

    func detachLocalPreview(_ renderer: RTCVideoRenderer) {
        Task { [weak self] in
            await self?.mediaControl()?.detachLocalVideoRenderer(renderer)
        }
    }

    // MARK: - Per-user mute

    /// Mutes/unmutes one participant locally (their audio track is disabled
    /// on this device only; never signaled). The stock WebRTC iOS SDK
    /// exposes no per-track gain, so mute is the per-user control;
    /// continuous volume is a documented limitation.
    func setParticipantMuted(fingerprintHex: String, muted: Bool) async {
        peerMuted[fingerprintHex] = muted
        if let callID = peerCallIDs[fingerprintHex] {
            (await mediaControl())?.setRemoteMuted(muted, for: callID)
        }
        if var current = room,
           let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        {
            current.participants[idx].isMutedByMe = muted
            room = current
            emit()
        }
    }

    // MARK: - Stage mode

    /// Switches the room between open floor and stage. Host-only.
    func setRoomMode(_ mode: VoiceRoomMode) async {
        guard var current = room, current.isLocalHost, current.mode != mode else { return }
        current.mode = mode
        room = current
        try? await broadcast(kind: .modeChanged)
        // Entering stage mode capture-mutes the audience immediately.
        await applyStageMutePolicy()
        emit()
        log.info("Voice room mode changed to \(mode.rawValue)")
    }

    /// Raises or lowers the local user's hand (stage mode audience).
    func raiseHand(_ raised: Bool) async {
        guard var current = room else { return }
        if let idx = current.participants.firstIndex(where: \.isLocal) {
            current.participants[idx].hasHandRaised = raised
        }
        room = current
        try? await broadcast(kind: .handRaise)
        emit()
    }

    /// Approves or denies a raised hand (host-only). Approval grants the
    /// floor; denial just lowers the hand. Revoking an approved speaker
    /// also signals their client to capture-mute.
    func setSpeakerApproval(fingerprintHex: String, approved: Bool) async {
        guard let current = room, current.isLocalHost else { return }
        guard let localFP = await localFingerprintHex() else { return }
        var signal = VoiceRoomSignal(
            kind: .speakerApproval,
            roomID: current.conversationID.uuidString,
            senderFingerprintHex: localFP
        )
        signal.targetFingerprintHex = fingerprintHex
        signal.speakerApproved = approved
        try? await sendSignal(signal, conversationID: current.conversationID)
        if var updated = room,
           let idx = updated.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        {
            updated.participants[idx].hasHandRaised = false
            updated.participants[idx].isSpeaker = approved
            room = updated
            emit()
        }
    }

    /// In stage mode, anyone who may not transmit is capture-muted.
    private func applyStageMutePolicy() async {
        guard let current = room, current.mode == .stage,
              let local = current.participants.first(where: \.isLocal),
              !canTransmit(mode: .stage, participant: local),
              !current.localMuted
        else { return }
        await setLocalMuted(true)
    }

    /// This side's WebRTC session UUID for a peer (for per-participant
    /// video sinks). Nil when no session exists yet.
    func videoCallID(for fingerprintHex: String) -> UUID? {
        peerCallIDs[fingerprintHex]
    }

    // MARK: - Inbound signaling

    /// Handles one voice-room signal from the group's E2EE channel.
    func handle(signal: VoiceRoomSignal) async {
        guard let current = room,
              signal.roomID == current.conversationID.uuidString
        else { return }
        let localFP = await localFingerprintHex() ?? ""
        guard signal.senderFingerprintHex != localFP else { return } // own echo
        switch signal.kind {
        case .join, .heartbeat:
            let isNew = upsertParticipant(from: signal)
            if isNew {
                // A new member changes the trusted set: re-key the whole
                // mesh (teardown + fresh DTLS identities + re-offer).
                await rotateMembershipEpoch()
            } else {
                await ensureOffer(to: signal.senderFingerprintHex)
            }
        case .leave:
            await removeParticipant(fingerprintHex: signal.senderFingerprintHex)
            await rotateMembershipEpoch()
        case .muteState:
            updateMuteState(
                fingerprintHex: signal.senderFingerprintHex,
                isMuted: signal.isMuted ?? false,
                isDeafened: signal.isDeafened ?? false
            )
        case .cameraState:
            updateCameraState(
                fingerprintHex: signal.senderFingerprintHex,
                isCameraOn: signal.isCameraOn ?? false
            )
        case .modeChanged:
            updateRoomMode(from: signal)
        case .handRaise:
            updateHandRaise(
                fingerprintHex: signal.senderFingerprintHex,
                raised: signal.handRaised ?? false
            )
        case .speakerApproval:
            await handleSpeakerApproval(signal, localFP: localFP)
        case .epochBump:
            await handleEpochBump(signal)
        case .offer:
            await handleOffer(signal, localFP: localFP)
        case .answer:
            await handleAnswer(signal, localFP: localFP)
        case .ice:
            await handleIce(signal, localFP: localFP)
        }
        emit()
    }

    // MARK: - Membership re-key (forward secrecy)

    /// Bumps the membership epoch: tears down every mesh peer connection,
    /// rotates the engine's DTLS identity (fresh certificate → fresh SRTP
    /// keys on re-handshake), broadcasts the bump, and re-establishes the
    /// mesh. Called on every locally observed join/leave/expiry.
    private func rotateMembershipEpoch() async {
        guard let current = room else { return }
        mediaEpoch += 1
        let control = await mediaControl()
        for (_, callID) in peerCallIDs {
            control?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        control?.rotateMediaIdentity()
        markAllPeersConnecting()
        var signal = VoiceRoomSignal(
            kind: .epochBump,
            roomID: current.conversationID.uuidString,
            senderFingerprintHex: await localFingerprintHex() ?? ""
        )
        signal.mediaEpoch = mediaEpoch
        try? await sendSignal(signal, conversationID: current.conversationID)
        for p in room?.participants ?? [] where !p.isLocal {
            await ensureOffer(to: p.fingerprintHex)
        }
        let epochNow = mediaEpoch
        log.info("Voice room membership epoch \(epochNow): mesh re-keyed")
    }

    /// Adopts a peer's epoch bump when it's newer than ours (we missed the
    /// underlying join/leave). Re-establishes without rebroadcasting, so
    /// bumps converge instead of looping.
    private func handleEpochBump(_ signal: VoiceRoomSignal) async {
        guard let epoch = signal.mediaEpoch, epoch > mediaEpoch, room != nil else { return }
        mediaEpoch = epoch
        let control = await mediaControl()
        for (_, callID) in peerCallIDs {
            control?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        control?.rotateMediaIdentity()
        markAllPeersConnecting()
        for p in room?.participants ?? [] where !p.isLocal {
            await ensureOffer(to: p.fingerprintHex)
        }
        log.info("Adopted voice room epoch \(epoch)")
    }

    /// After a mesh re-key every peer connection renegotiates; reset the
    /// tiles to "connecting" until the new handshakes complete.
    private func markAllPeersConnecting() {
        guard var current = room else { return }
        for i in current.participants.indices where !current.participants[i].isLocal {
            current.participants[i].mediaState = .connecting
        }
        room = current
    }

    // MARK: - Presence

    /// Inserts or refreshes a participant from a join/heartbeat signal.
    /// Returns true when the participant is newly seen (a membership
    /// change, which triggers a mesh re-key).
    private func upsertParticipant(from signal: VoiceRoomSignal) -> Bool {
        guard var current = room else { return false }
        let fingerprintHex = signal.senderFingerprintHex
        let isNew = !current.participants.contains(where: { $0.fingerprintHex == fingerprintHex })
        if let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex }) {
            current.participants[idx].displayName = signal.senderDisplayName ?? current.participants[idx].displayName
            current.participants[idx].isMuted = signal.isMuted ?? current.participants[idx].isMuted
            current.participants[idx].isDeafened = signal.isDeafened ?? current.participants[idx].isDeafened
            if let cameraOn = signal.isCameraOn { current.participants[idx].isCameraOn = cameraOn }
            if let isSpeaker = signal.isSpeaker { current.participants[idx].isSpeaker = isSpeaker }
            if let raised = signal.handRaised { current.participants[idx].hasHandRaised = raised }
            current.participants[idx].lastHeartbeat = Date()
        } else {
            var participant = VoiceRoomParticipant(
                fingerprintHex: fingerprintHex,
                displayName: signal.senderDisplayName ?? "Unknown",
                isMuted: signal.isMuted ?? false,
                isDeafened: signal.isDeafened ?? false,
                joinedAt: Date(),
                lastHeartbeat: Date()
            )
            participant.isCameraOn = signal.isCameraOn ?? false
            participant.isSpeaker = signal.isSpeaker ?? false
            participant.hasHandRaised = signal.handRaised ?? false
            // Adopt a stored per-user mute for returning participants.
            participant.isMutedByMe = peerMuted[fingerprintHex] ?? false
            current.participants.append(participant)
            log.info("Voice room peer joined: \(participant.displayName)")
        }
        // Converge the room creator (first joiner wins; deterministic).
        if current.createdByFingerprintHex == nil {
            current.createdByFingerprintHex = signal.createdByFingerprintHex ?? fingerprintHex
        }
        // The host's mode/host fields are authoritative for late joiners.
        let senderIsHost = signal.senderFingerprintHex == current.stageHostFingerprintHex
        if let mode = signal.roomMode, (senderIsHost || current.stageHostFingerprintHex == nil) {
            current.mode = mode
        }
        if let host = signal.stageHostFingerprintHex, (senderIsHost || current.stageHostFingerprintHex == nil) {
            current.stageHostFingerprintHex = host
        }
        current.stageHostFingerprintHex = electStageHost(
            participants: current.participants,
            createdBy: current.createdByFingerprintHex
        )
        ensureHostIsSpeaker(&current)
        room = current
        return isNew
    }

    /// The stage host must always be able to transmit; a newly elected host
    /// (e.g. after the previous host left) gets the floor automatically.
    private func ensureHostIsSpeaker(_ current: inout VoiceRoom) {
        guard let host = current.stageHostFingerprintHex,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == host })
        else { return }
        current.participants[idx].isSpeaker = true
    }

    private func updateMuteState(fingerprintHex: String, isMuted: Bool, isDeafened: Bool) {
        guard var current = room,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        else { return }
        current.participants[idx].isMuted = isMuted
        current.participants[idx].isDeafened = isDeafened
        room = current
    }

    private func updateCameraState(fingerprintHex: String, isCameraOn: Bool) {
        guard var current = room,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        else { return }
        current.participants[idx].isCameraOn = isCameraOn
        room = current
    }

    private func updateHandRaise(fingerprintHex: String, raised: Bool) {
        guard var current = room,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        else { return }
        current.participants[idx].hasHandRaised = raised
        room = current
    }

    /// Applies a host's mode change (host-authenticated by roster position).
    private func updateRoomMode(from signal: VoiceRoomSignal) {
        guard var current = room else { return }
        // Only the elected host may change the mode; ignore forgeries from
        // anyone else. (Signaling is E2EE but any member could craft one.)
        guard signal.senderFingerprintHex == current.stageHostFingerprintHex,
              let mode = signal.roomMode
        else { return }
        current.mode = mode
        if let host = signal.stageHostFingerprintHex {
            current.stageHostFingerprintHex = host
        }
        room = current
        Task { [weak self] in await self?.applyStageMutePolicy() }
    }

    /// Handles an addressed speaker-approval: grants/revokes the floor for
    /// the local user, or (for observers) updates the roster copy.
    private func handleSpeakerApproval(_ signal: VoiceRoomSignal, localFP: String) async {
        guard let approved = signal.speakerApproved,
              let target = signal.targetFingerprintHex,
              var current = room
        else { return }
        // Only the host's approvals count.
        guard signal.senderFingerprintHex == current.stageHostFingerprintHex else { return }
        if target == localFP {
            if let idx = current.participants.firstIndex(where: \.isLocal) {
                current.participants[idx].isSpeaker = approved
                current.participants[idx].hasHandRaised = false
                room = current
                if !approved {
                    // Revoked: capture-mute immediately.
                    await setLocalMuted(true)
                } else {
                    emit()
                }
            }
        } else if let idx = current.participants.firstIndex(where: { $0.fingerprintHex == target }) {
            current.participants[idx].isSpeaker = approved
            current.participants[idx].hasHandRaised = false
            room = current
        }
    }

    private func removeParticipant(fingerprintHex: String) async {
        guard var current = room else { return }
        current.participants.removeAll { $0.fingerprintHex == fingerprintHex }
        speakingDetector.remove(id: fingerprintHex)
        // The host may have left: re-elect deterministically.
        current.stageHostFingerprintHex = electStageHost(
            participants: current.participants,
            createdBy: current.createdByFingerprintHex
        )
        ensureHostIsSpeaker(&current)
        room = current
        if let callID = peerCallIDs.removeValue(forKey: fingerprintHex) {
            (await mediaControl())?.endCallMedia(callID)
        }
        log.info("Voice room peer left")
    }

    // MARK: - Mesh signaling

    /// Deterministic glare avoidance: the lower fingerprint offers.
    private func shouldOffer(to fingerprintHex: String, localFP: String) -> Bool {
        localFP < fingerprintHex
    }

    private func ensureOffer(to fingerprintHex: String) async {
        guard peerCallIDs[fingerprintHex] == nil,
              let current = room,
              let media = await media()
        else { return }
        guard let localFP = await localFingerprintHex() else { return }
        guard shouldOffer(to: fingerprintHex, localFP: localFP) else { return }
        let callID = UUID()
        peerCallIDs[fingerprintHex] = callID
        let control = await mediaControl()
        control?.noteCallKind(.audio, for: callID)
        // Voice-room mesh extras: speaking-indicator polling and any
        // stored per-user mute for this peer.
        control?.noteVoiceRoomPeer(callID)
        if let muted = peerMuted[fingerprintHex] {
            control?.setRemoteMuted(muted, for: callID)
        }
        do {
            let offer = try await media.createOffer(for: callID)
            var signal = VoiceRoomSignal(
                kind: .offer,
                roomID: current.conversationID.uuidString,
                senderFingerprintHex: localFP
            )
            signal.targetFingerprintHex = fingerprintHex
            signal.callID = callID.uuidString
            signal.sdp = offer.sdp
            try await sendSignal(signal, conversationID: current.conversationID)
        } catch {
            peerCallIDs.removeValue(forKey: fingerprintHex)
            log.error("Voice room offer failed: \(error.localizedDescription)")
        }
    }

    private func handleOffer(_ signal: VoiceRoomSignal, localFP: String) async {
        guard signal.isForLocal(localFP),
              let callIDString = signal.callID,
              let callID = UUID(uuidString: callIDString),
              let sdp = signal.sdp, !sdp.isEmpty,
              let current = room,
              let media = await media()
        else { return }
        // Glare race: if we already have a session for this peer (e.g. both
        // sides offered simultaneously), keep the offerer's callID and tear
        // down our orphaned peer connection.
        if let existing = peerCallIDs[signal.senderFingerprintHex], existing != callID {
            (await mediaControl())?.endCallMedia(existing)
        }
        peerCallIDs[signal.senderFingerprintHex] = callID
        let control = await mediaControl()
        control?.noteCallKind(.audio, for: callID)
        control?.noteVoiceRoomPeer(callID)
        if let muted = peerMuted[signal.senderFingerprintHex] {
            control?.setRemoteMuted(muted, for: callID)
        }
        do {
            let answer = try await media.createAnswer(for: callID, offerSDP: sdp)
            var reply = VoiceRoomSignal(
                kind: .answer,
                roomID: current.conversationID.uuidString,
                senderFingerprintHex: localFP
            )
            reply.targetFingerprintHex = signal.senderFingerprintHex
            reply.callID = callIDString
            reply.sdp = answer.sdp
            try await sendSignal(reply, conversationID: current.conversationID)
        } catch {
            peerCallIDs.removeValue(forKey: signal.senderFingerprintHex)
            log.error("Voice room answer failed: \(error.localizedDescription)")
        }
    }

    private func handleAnswer(_ signal: VoiceRoomSignal, localFP: String) async {
        guard signal.isForLocal(localFP),
              let callIDString = signal.callID,
              let callID = UUID(uuidString: callIDString),
              let sdp = signal.sdp, !sdp.isEmpty,
              peerCallIDs[signal.senderFingerprintHex] == callID
        else { return }
        let media = await media()
        try? await media?.setRemoteSDP(sdp, for: callID)
    }

    private func handleIce(_ signal: VoiceRoomSignal, localFP: String) async {
        guard signal.isForLocal(localFP),
              let callIDString = signal.callID,
              let callID = UUID(uuidString: callIDString),
              let ice = signal.ice,
              peerCallIDs[signal.senderFingerprintHex] == callID
        else { return }
        let media = await media()
        try? await media?.addIceCandidate(ice, for: callID)
    }

    // MARK: - Timers

    private func startHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(VoiceRoom.heartbeatInterval * 1_000_000_000))
                guard let self, !Task.isCancelled else { return }
                await self.sendHeartbeat()
            }
        }
    }

    private func sendHeartbeat() async {
        try? await broadcast(kind: .heartbeat)
    }

    private func startExpirySweep() {
        expiryTask?.cancel()
        expiryTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.expireStaleParticipants()
            }
        }
    }

    private func expireStaleParticipants() async {
        guard let current = room else { return }
        let stale = current.participants.filter { !$0.isLocal && $0.isStale }
        guard !stale.isEmpty else { return }
        for p in stale { await removeParticipant(fingerprintHex: p.fingerprintHex) }
        // Stale members are membership changes too: re-key.
        await rotateMembershipEpoch()
        emit()
    }

    // MARK: - Speaking indicators (local audio levels)

    /// Maps polled WebRTC audio levels to participants and runs the
    /// hysteresis detector. Levels are computed on this device from decoded
    /// audio; nothing is transmitted — the detector input never leaves the
    /// device, and neither does its output.
    private func handleAudioLevels(_ levels: [UUID: CallAudioLevels]) async {
        guard room != nil else { return }
        var callIDToFingerprint: [UUID: String] = [:]
        for (fingerprint, callID) in peerCallIDs {
            callIDToFingerprint[callID] = fingerprint
        }
        var inputs: [(id: String, level: Float)] = []
        var localLevel: Float = 0
        for (callID, lv) in levels {
            localLevel = max(localLevel, lv.local)
            if let fingerprint = callIDToFingerprint[callID] {
                inputs.append((fingerprint, lv.remote))
            }
        }
        if let localFP = await localFingerprintHex() {
            inputs.append((localFP, localLevel))
        }
        let changes = speakingDetector.update(levels: inputs)
        guard !changes.isEmpty, var current = room else { return }
        for (fingerprint, isSpeaking) in changes {
            if let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprint }) {
                current.participants[idx].isSpeaking = isSpeaking
            }
            eventCont.yield(.speakingChanged(fingerprintHex: fingerprint, isSpeaking: isSpeaking))
        }
        room = current
        emit()
    }

    private func handlePeerConnectionState(_ callID: UUID, _ state: PeerConnectionState) async {
        guard var current = room else { return }
        let mapped: ParticipantMediaState
        switch state {
        case .connecting: mapped = .connecting
        case .connected: mapped = .connected
        case .reconnecting: mapped = .reconnecting
        case .failed: mapped = .failed
        case .closed: mapped = .connecting
        }
        guard let fingerprint = peerCallIDs.first(where: { $0.value == callID })?.key,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprint })
        else { return }
        // A re-established mesh (post re-key) briefly passes through
        // connecting again; the tile shows it honestly.
        current.participants[idx].mediaState = mapped
        room = current
        emit()
    }

    // MARK: - Helpers

    private func broadcast(kind: VoiceRoomSignalKind) async throws {
        guard let current = room else { return }
        let localFP = await localFingerprintHex() ?? ""
        var signal = VoiceRoomSignal(
            kind: kind,
            roomID: current.conversationID.uuidString,
            senderFingerprintHex: localFP,
            senderDisplayName: await localDisplayName()
        )
        signal.isMuted = current.localMuted
        signal.isDeafened = current.localDeafened
        signal.isCameraOn = current.localCameraOn
        signal.roomMode = current.mode
        signal.stageHostFingerprintHex = current.stageHostFingerprintHex
        signal.createdByFingerprintHex = current.createdByFingerprintHex
        if let local = current.participants.first(where: \.isLocal) {
            signal.isSpeaker = local.isSpeaker
            signal.handRaised = local.hasHandRaised
        }
        try await sendSignal(signal, conversationID: current.conversationID)
    }

    private func emit() {
        // Publish this side's session UUIDs so the UI can register
        // per-participant video sinks.
        if var current = room {
            current.videoCallIDs = peerCallIDs
            eventCont.yield(.updated(current))
        } else {
            eventCont.yield(.updated(nil))
        }
    }

    /// Stops timers without signaling (used at teardown).
    func shutdown() async {
        heartbeatTask?.cancel(); heartbeatTask = nil
        expiryTask?.cancel(); expiryTask = nil
        let control = await mediaControl()
        control?.setAudioLevelPolling(false)
        control?.onAudioLevels = nil
        control?.onPeerConnectionStateChanged = nil
        control?.onCameraPermissionDenied = nil
        for (_, callID) in peerCallIDs {
            control?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        peerMuted.removeAll()
        speakingDetector = SpeakingDetector()
        mediaEpoch = 0
        room = nil
    }
}
