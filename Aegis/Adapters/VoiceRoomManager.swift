import AegisCrypto
import Foundation
import OSLog

// MARK: - VoiceRoomManager
//
// Owns voice-room sessions for the app. One room is active at a time (the
// Discord voice-channel model: joining a second room leaves the first).
//
// The manager is a plain class whose methods are only ever invoked from
// `AegisCore`'s actor context, so its mutable state needs no extra
// synchronization. Signaling rides the group's existing E2EE sender-key
// channel via `GroupControlMessage` kind "voiceRoom"; audio is a full WebRTC
// mesh with one audio-only peer connection per remote participant, reusing
// `WebRTCMediaEngine`'s per-UUID peer sessions.

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
            return
        }
        let me = VoiceRoomParticipant(
            fingerprintHex: localFP,
            displayName: await localDisplayName(),
            isMuted: false,
            isDeafened: false,
            joinedAt: Date(),
            lastHeartbeat: Date(),
            isLocal: true
        )
        room = VoiceRoom(
            conversationID: conversationID,
            groupName: groupName,
            participants: [me],
            localMuted: false,
            localDeafened: false,
            joinedAt: Date()
        )
        startHeartbeat()
        startExpirySweep()
        // Announce presence; mesh offers to already-present peers follow
        // when their heartbeats arrive (or immediately for known members —
        // the roster only fills via signaling, so join is the trigger).
        try? await broadcast(kind: .join)
        // Offer to everyone already listed (rejoin race: they re-announce).
        for p in room?.participants ?? [] where !p.isLocal {
            await ensureOffer(to: p.fingerprintHex)
        }
        emit()
        log.info("Joined voice room \(conversationID.uuidString.prefix(8))")
    }

    func leaveRoom() async {
        guard let current = room else { return }
        heartbeatTask?.cancel(); heartbeatTask = nil
        expiryTask?.cancel(); expiryTask = nil
        try? await broadcast(kind: .leave)
        for (_, callID) in peerCallIDs {
            (await mediaControl())?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        room = nil
        emit()
        log.info("Left voice room")
        _ = current
    }

    // MARK: - Local audio state

    func setLocalMuted(_ muted: Bool) async {
        guard var current = room else { return }
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
            upsertParticipant(
                fingerprintHex: signal.senderFingerprintHex,
                displayName: signal.senderDisplayName ?? "Unknown",
                isMuted: signal.isMuted ?? false,
                isDeafened: signal.isDeafened ?? false
            )
            await ensureOffer(to: signal.senderFingerprintHex)
        case .leave:
            removeParticipant(fingerprintHex: signal.senderFingerprintHex)
        case .muteState:
            updateMuteState(
                fingerprintHex: signal.senderFingerprintHex,
                isMuted: signal.isMuted ?? false,
                isDeafened: signal.isDeafened ?? false
            )
        case .offer:
            await handleOffer(signal, localFP: localFP)
        case .answer:
            await handleAnswer(signal, localFP: localFP)
        case .ice:
            await handleIce(signal, localFP: localFP)
        }
        emit()
    }

    // MARK: - Presence

    private func upsertParticipant(fingerprintHex: String, displayName: String, isMuted: Bool, isDeafened: Bool) {
        guard var current = room else { return }
        if let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex }) {
            current.participants[idx].displayName = displayName
            current.participants[idx].isMuted = isMuted
            current.participants[idx].isDeafened = isDeafened
            current.participants[idx].lastHeartbeat = Date()
        } else {
            current.participants.append(VoiceRoomParticipant(
                fingerprintHex: fingerprintHex,
                displayName: displayName,
                isMuted: isMuted,
                isDeafened: isDeafened,
                joinedAt: Date(),
                lastHeartbeat: Date()
            ))
            log.info("Voice room peer joined: \(displayName)")
        }
        room = current
    }

    private func updateMuteState(fingerprintHex: String, isMuted: Bool, isDeafened: Bool) {
        guard var current = room,
              let idx = current.participants.firstIndex(where: { $0.fingerprintHex == fingerprintHex })
        else { return }
        current.participants[idx].isMuted = isMuted
        current.participants[idx].isDeafened = isDeafened
        room = current
    }

    private func removeParticipant(fingerprintHex: String) {
        guard var current = room else { return }
        current.participants.removeAll { $0.fingerprintHex == fingerprintHex }
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
        (await mediaControl())?.noteCallKind(.audio, for: callID)
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
            try await sendSignal(current.conversationID, signal)
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
        (await mediaControl())?.noteCallKind(.audio, for: callID)
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
            try await sendSignal(current.conversationID, reply)
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
        guard var current = room else { return }
        let stale = current.participants.filter { !$0.isLocal && $0.isStale }
        guard !stale.isEmpty else { return }
        for p in stale { removeParticipant(fingerprintHex: p.fingerprintHex) }
        _ = current
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
        try await sendSignal(current.conversationID, signal)
    }

    private func emit() {
        eventCont.yield(.updated(room))
    }

    /// Stops timers without signaling (used at teardown).
    func shutdown() {
        heartbeatTask?.cancel(); heartbeatTask = nil
        expiryTask?.cancel(); expiryTask = nil
        for (_, callID) in peerCallIDs {
            (await mediaControl())?.endCallMedia(callID)
        }
        peerCallIDs.removeAll()
        room = nil
    }
}
