// WebRTCMediaEngine — the app's real-time audio/video layer for calls.
//
// Signaling (knock/offer/answer/ICE) travels over the existing E2EE
// call-signaling path (AegisCore). This engine owns everything media:
//
//   - one RTCPeerConnectionFactory, one RTCPeerConnection per call
//   - local microphone capture + camera capture (RTCCameraVideoCapturer)
//   - remote video frames → CMSampleBuffer → CallMediaRouter → app's VideoSink
//   - the five media controls: mute, video on/off, speaker, screen share
//   - real SDP offer/answer and real DTLS fingerprints (parsed from the
//     local SDP's a=fingerprint line), which is what makes the SAS
//     verification ceremony in the call UI actually appear.
//
// Threading: WebRTC's native peer connection serializes its own work
// internally; this engine guards its Swift-side state (peers, router,
// call kinds) with a single NSLock. The WebRTC ObjC API is invoked from
// whatever thread the async call site runs on, and completion handlers
// only resume their continuation — they never touch shared state.
// RTCVideoRenderer callbacks arrive on WebRTC-internal threads and only
// touch the thread-safe CallMediaRouter.
//
// NAT traversal uses Google's public STUN server (stun.l.google.com:19302)
// — the standard free default; host candidates alone cover LAN calls.

import AVFoundation
import CoreMedia
import Foundation
import os.log
import UIKit
// WebRTC API (RTCPeerConnection et al.) is re-exported by WebRTCBridge,
// so the app target needs only this one import.
import WebRTCBridge
import AegisCrypto
import AegisTransport

/// Real media backend implementing the app's `CallMediaDelegate` (SDP/ICE)
/// and `CallMediaControl` (the five media controls) protocols.
final class WebRTCMediaEngine: NSObject, @unchecked Sendable {

    enum EngineError: Error, LocalizedError {
        case noSuchCall
        case sdpFailure(String)
        case captureUnavailable
        case emptyRemoteOffer

        var errorDescription: String? {
            switch self {
            case .noSuchCall: return "No active media session for this call."
            case .sdpFailure(let detail): return "WebRTC negotiation failed: \(detail)"
            case .captureUnavailable: return "Camera capture is unavailable."
            case .emptyRemoteOffer: return "Empty remote offer."
            }
        }
    }

    /// Emitted when ICE gathering produces a local candidate. Wired at
    /// startup to `AegisCore.sendIceCandidate`, which signals it to the
    /// peer inside an E2EE envelope (trickle ICE).
    var onLocalIceCandidate: ((IceCandidate, UUID) -> Void)?

    private let log = Logger(subsystem: "app.aegis.ios", category: "webrtc")
    private let lock = NSLock()
    private var factory: RTCPeerConnectionFactory?
    /// Bumped by `rotateMediaIdentity()`. The cached factory is dropped and
    /// the next created peer connection gets a fresh DTLS certificate, so
    /// re-established mesh connections after a membership change derive
    /// fresh SRTP keys (forward secrecy for join/leave).
    private var factoryGeneration = 0
    private var activeFactoryGeneration = -1
    private var peers: [UUID: PeerMedia] = [:]
    private var pcToCallID: [ObjectIdentifier: UUID] = [:]
    private var renderers: [UUID: RemoteFrameRenderer] = [:]
    private var frameRouter: CallMediaRouter?
    private var callKinds: [UUID: CallKind] = [:]

    // MARK: Shared camera (one AVCaptureSession feeding every peer)

    /// A voice-room mesh has one peer connection per remote participant but
    /// the device has one camera. The fan-out owns the single
    /// RTCCameraVideoCapturer and forwards each frame to every registered
    /// peer connection's own RTCVideoSource, so per-PC screen sharing can
    /// still take over a single PC's source without renegotiation.
    private var cameraFanOut: CameraFrameFanOut?
    /// callIDs whose video source is currently registered with the fan-out.
    private var cameraUsers: Set<UUID> = []

    // MARK: Voice-room audio (per-user mute + speaking indicators)

    /// Peer connections that belong to the voice-room mesh (vs 1:1 calls).
    /// Room peers render remote audio through WebRTC's normal output mix
    /// like everyone else; per-user control is mute (track disabling).
    ///
    /// Ground truth (verified against the pinned WebRTC M154 headers):
    /// the iOS SDK exposes no per-track audio tap and no per-track gain.
    /// An earlier design assumed an `RTCAudioSink` PCM tap — that type does
    /// not exist in the SDK, so it was replaced with this honest subset:
    /// per-user mute via `RTCAudioTrack.isEnabled`, master deafen by
    /// muting every room track, and speaking indicators from polled
    /// `audioLevel` stats. Continuous per-user volume is documented as
    /// infeasible with stock WebRTC (see docs/FEATURES.md limitation).
    private var roomPeers: Set<UUID> = []
    /// Local-only per-user mute for room peers, keyed by callID. Applied
    /// to (re-)attached audio tracks; never signaled.
    private var roomPeerMuted: [UUID: Bool] = [:]

    // MARK: Audio-level polling (speaking indicators)

    private var levelTimer: DispatchSourceTimer?
    private var lastLevels: [UUID: CallAudioLevels] = [:]

    // MARK: Engine callbacks (CallMediaControl)

    private var _onAudioLevels: (([UUID: CallAudioLevels]) -> Void)?
    private var _onPeerConnectionStateChanged: ((UUID, PeerConnectionState) -> Void)?
    private var _onCameraPermissionDenied: (() -> Void)?

    // MARK: Local camera preview

    private var localPreviewRenderers: [WeakVideoRenderer] = []

    /// Assumes the engine lock is held. Keeps the room UI's local preview
    /// attached to the first camera-active peer connection's video track.
    private func refreshLocalPreviewLocked() {
        localPreviewRenderers.removeAll { $0.value == nil }
        let renderers = localPreviewRenderers.compactMap(\.value)
        for media in peers.values {
            guard let track = media.videoTrack else { continue }
            for renderer in renderers { track.remove(renderer) }
        }
        guard let target = peers.values.first(where: { cameraUsers.contains($0.callID) }),
              let track = target.videoTrack
        else { return }
        for renderer in renderers { track.add(renderer) }
    }

    /// Connects the engine to the transport's frame router. Called once at
    /// startup (after AegisCore exists); remote frames are dropped until
    /// attached, matching the router's own drop-silently contract.
    func attachFrameRouter(_ router: CallMediaRouter) {
        lock.withLock { frameRouter = router }
    }

    // MARK: - Peer sessions (lock-guarded)

    private func makeFactoryLocked() -> RTCPeerConnectionFactory {
        // A rotated identity drops the cached factory: the next factory
        // generates a fresh DTLS certificate, so re-established peer
        // connections after a membership change handshake fresh SRTP keys.
        // Live peer connections keep their old factory (and keys) until
        // the caller tears them down — rotation only affects new ones.
        if let factory, activeFactoryGeneration == factoryGeneration { return factory }
        let created = RTCPeerConnectionFactory(
            encoderFactory: RTCDefaultVideoEncoderFactory(),
            decoderFactory: RTCDefaultVideoDecoderFactory()
        )
        factory = created
        activeFactoryGeneration = factoryGeneration
        configureAudioSessionLocked()
        return created
    }

    private func configureAudioSessionLocked() {
        let session = RTCAudioSession.sharedInstance()
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        do {
            try session.setCategory(
                .playAndRecord,
                with: [.allowBluetooth, .allowBluetoothA2DP]
            )
            try session.setMode(.voiceChat)
            try session.setActive(true)
        } catch {
            log.error("Audio session configuration failed: \(error.localizedDescription)")
        }
    }

    private func peerLocked(for callID: UUID) throws -> PeerMedia {
        if let existing = peers[callID] { return existing }
        let config = RTCConfiguration()
        config.iceServers = [RTCIceServer(urlStrings: ["stun:stun.l.google.com:19302"])]
        config.sdpSemantics = .unifiedPlan
        let constraints = RTCMediaConstraints(
            mandatoryConstraints: nil,
            optionalConstraints: ["DtlsSrtpKeyAgreement": "true"]
        )
        let factory = makeFactoryLocked()
        // The engine is its own peer-connection delegate.
        guard let connection = factory.peerConnection(
            with: config, constraints: constraints, delegate: self
        ) else {
            throw EngineError.sdpFailure("RTCPeerConnection creation failed")
        }
        let media = PeerMedia(callID: callID, connection: connection)
        peers[callID] = media
        pcToCallID[ObjectIdentifier(connection)] = callID
        return media
    }

    /// Adds local audio/video tracks. Video capture starts only for video
    /// calls and only after the user grants camera access; denial degrades
    /// gracefully to audio-only instead of failing the call.
    private func addLocalTracksLocked(to media: PeerMedia) {
        let factory = makeFactoryLocked()
        if media.audioTrack == nil {
            let source = factory.audioSource(with: nil)
            let track = factory.audioTrack(with: source, trackId: "aegis-audio-\(media.callID.uuidString)")
            media.connection.add(track, streamIds: ["aegis-stream"])
            media.audioTrack = track
        }
        let wantVideo = callKinds[media.callID] == .video
        media.videoEnabled = wantVideo
        if media.videoTrack == nil {
            let source = factory.videoSource()
            let track = factory.videoTrack(with: source, trackId: "aegis-video-\(media.callID.uuidString)")
            media.connection.add(track, streamIds: ["aegis-stream"])
            media.videoSource = source
            media.videoTrack = track
        }
        media.videoTrack?.isEnabled = wantVideo
        if wantVideo {
            requestCameraAndStartLocked(for: media.callID)
        }
    }

    private func requestCameraAndStartLocked(for callID: UUID) {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startCameraLocked(for: callID)
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                guard let self else { return }
                if granted {
                    self.startCamera(for: callID)
                } else {
                    self.lock.withLock {
                        self.peers[callID]?.videoTrack?.isEnabled = false
                    }
                    self.onCameraPermissionDenied?()
                }
            }
        case .denied, .restricted:
            log.error("Camera access denied; continuing audio-only")
            peers[callID]?.videoTrack?.isEnabled = false
            // Read the callback without re-entering the engine lock
            // (NSLock is not recursive) and hop to main for the UI.
            let callback = _onCameraPermissionDenied
            DispatchQueue.main.async { callback?() }
        @unknown default:
            break
        }
    }

    /// Lock-taking wrapper for use outside the engine's lock (e.g. the
    /// camera-permission callback, which runs on an arbitrary thread).
    private func startCamera(for callID: UUID) {
        lock.withLock { startCameraLocked(for: callID) }
    }

    /// Assumes the engine lock is held. Registers this peer connection's
    /// video source with the shared camera fan-out and starts the single
    /// AVCaptureSession (idempotent across mesh peers).
    private func startCameraLocked(for callID: UUID) {
        guard let media = peers[callID], let source = media.videoSource else { return }
        let fanOut = cameraFanOut ?? {
            let created = CameraFrameFanOut()
            cameraFanOut = created
            return created
        }()
        fanOut.addSource(source)
        cameraUsers.insert(callID)
        fanOut.start()
        refreshLocalPreviewLocked()
    }

    /// Assumes the engine lock is held. Unregisters this peer connection
    /// from the shared camera; stops the capture session when the last
    /// user leaves.
    private func stopCameraLocked(for callID: UUID) {
        guard let media = peers[callID] else { return }
        if let source = media.videoSource {
            cameraFanOut?.removeSource(source)
        }
        cameraUsers.remove(callID)
        if cameraUsers.isEmpty {
            cameraFanOut?.stop()
        }
        refreshLocalPreviewLocked()
    }
}

// MARK: - Shared camera fan-out

/// One RTCCameraVideoCapturer feeding many RTCVideoSources.
///
/// A voice-room mesh negotiates one peer connection per remote participant,
/// each with its own local RTCVideoSource/RTCVideoTrack — but the device
/// has a single camera. The fan-out owns the one AVCaptureSession and
/// forwards every captured frame to each registered source, so all mesh
/// peers publish the same camera frames. Per-PC screen sharing still works:
/// a sharing peer unregisters its source from the fan-out and points a
/// WindowSnapshotCapturer at it instead, with no renegotiation.
final class CameraFrameFanOut: NSObject, RTCVideoCapturerDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var capturer: RTCCameraVideoCapturer?
    private var sources: [ObjectIdentifier: RTCVideoSource] = [:]
    private let log = Logger(subsystem: "app.aegis.ios", category: "webrtc")

    func addSource(_ source: RTCVideoSource) {
        lock.withLock { sources[ObjectIdentifier(source)] = source }
    }

    func removeSource(_ source: RTCVideoSource) {
        lock.withLock { sources.removeValue(forKey: ObjectIdentifier(source)) }
    }

    /// Starts the shared capture session (no-op when already running).
    func start() {
        lock.withLock {
            if capturer != nil { return }
            let created = RTCCameraVideoCapturer(delegate: self)
            capturer = created
            let devices = RTCCameraVideoCapturer.captureDevices()
            guard let device = devices.first(where: { $0.position == .front }) ?? devices.first
            else {
                log.error("No camera device found")
                capturer = nil
                return
            }
            let formats = RTCCameraVideoCapturer.supportedFormats(for: device)
            guard let format = formats.first(where: {
                CMVideoFormatDescriptionGetDimensions($0.formatDescription).width == 640
            }) ?? formats.first else {
                log.error("No suitable camera format")
                capturer = nil
                return
            }
            let fps = min(Int(format.videoSupportedFrameRateRanges.first?.maxFrameRate ?? 30), 24)
            created.startCapture(with: device, format: format, fps: fps)
        }
    }

    func stop() {
        lock.withLock {
            capturer?.stopCapture()
            capturer = nil
        }
    }

    // MARK: RTCVideoCapturerDelegate

    func capturer(_ capturer: RTCVideoCapturer, didCapture frame: RTCVideoFrame) {
        // Fan out to every registered peer connection's source.
        // RTCVideoSource is thread-safe for capturer callbacks.
        let targets = lock.withLock { Array(sources.values) }
        for source in targets {
            source.capturer(capturer, didCapture: frame)
        }
    }
}

// MARK: - CallMediaDelegate (SDP / ICE)

extension WebRTCMediaEngine: CallMediaDelegate {

    func createOffer(for callID: UUID) async throws -> (sdp: String, dtlsFingerprint: String) {
        let media = try lock.withLock { try peerLocked(for: callID) }
        lock.withLock { addLocalTracksLocked(to: media) }
        lock.withLock { media.createdOffer = true }
        let offerSDP: String = try await withCheckedThrowingContinuation { cont in
            media.connection.offer(
                for: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
            ) { sdp, error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else if let sdpString = sdp?.sdp {
                    // Extract the Sendable String inside the callback:
                    // RTCSessionDescription is not Sendable in M154, so the
                    // object itself must not cross the continuation boundary.
                    cont.resume(returning: sdpString)
                } else {
                    cont.resume(throwing: EngineError.sdpFailure("empty offer"))
                }
            }
        }
        let offer = RTCSessionDescription(type: .offer, sdp: offerSDP)
        try await setLocalDescription(offer, for: callID)
        return (offerSDP, SDPFingerprint.extract(from: offerSDP) ?? "")
    }

    func createAnswer(for callID: UUID, offerSDP: String) async throws -> (sdp: String, dtlsFingerprint: String) {
        guard !offerSDP.isEmpty else { throw EngineError.emptyRemoteOffer }
        try await setRemoteDescription(RTCSessionDescription(type: .offer, sdp: offerSDP), for: callID)
        let media = try lock.withLock { try peerLocked(for: callID) }
        lock.withLock { addLocalTracksLocked(to: media) }
        let answerSDP: String = try await withCheckedThrowingContinuation { cont in
            media.connection.answer(
                for: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
            ) { sdp, error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else if let sdpString = sdp?.sdp {
                    // See createOffer: don't send the non-Sendable
                    // RTCSessionDescription across the continuation.
                    cont.resume(returning: sdpString)
                } else {
                    cont.resume(throwing: EngineError.sdpFailure("empty answer"))
                }
            }
        }
        let answer = RTCSessionDescription(type: .answer, sdp: answerSDP)
        try await setLocalDescription(answer, for: callID)
        return (answerSDP, SDPFingerprint.extract(from: answerSDP) ?? "")
    }

    func setRemoteSDP(_ sdp: String, for callID: UUID) async throws {
        // Only the offerer reaches this path (the answerer sets the remote
        // offer inside createAnswer). Track which side we are on per call.
        let createdOffer = lock.withLock { peers[callID]?.createdOffer == true }
        let type: RTCSdpType = createdOffer ? .answer : .offer
        try await setRemoteDescription(RTCSessionDescription(type: type, sdp: sdp), for: callID)
    }

    func addIceCandidate(_ candidate: IceCandidate, for callID: UUID) async throws {
        let media = try lock.withLock { try peerLocked(for: callID) }
        // M154's addIceCandidate is async/throws.
        try await media.connection.add(RTCIceCandidate(
            sdp: candidate.candidate,
            sdpMLineIndex: candidate.sdpMLineIndex,
            sdpMid: candidate.sdpMid
        ))
    }

    private func setLocalDescription(_ sdp: RTCSessionDescription, for callID: UUID) async throws {
        let media = try lock.withLock { try peerLocked(for: callID) }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            media.connection.setLocalDescription(sdp) { error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else {
                    cont.resume()
                }
            }
        }
    }

    private func setRemoteDescription(_ sdp: RTCSessionDescription, for callID: UUID) async throws {
        let media = try lock.withLock { try peerLocked(for: callID) }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            media.connection.setRemoteDescription(sdp) { error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else {
                    cont.resume()
                }
            }
        }
    }
}

// MARK: - CallMediaControl (the five media controls)

extension WebRTCMediaEngine: CallMediaControl {

    func noteCallKind(_ kind: CallKind, for callID: UUID) {
        lock.withLock {
            callKinds[callID] = kind
            // If the kind arrives after the peer connection already exists
            // (e.g. noted after createOffer), bring the video track up now.
            guard kind == .video, let media = peers[callID] else { return }
            media.videoEnabled = true
            media.videoTrack?.isEnabled = true
            if !media.isScreenSharing { requestCameraAndStartLocked(for: callID) }
        }
    }

    func setMuted(_ muted: Bool, callID: UUID) async throws {
        try lock.withLock {
            let media = try peerLocked(for: callID)
            media.audioTrack?.isEnabled = !muted
        }
    }

    func setRemoteAudioEnabled(_ enabled: Bool, for callID: UUID) {
        lock.withLock {
            guard let media = peers[callID] else { return }
            media.remoteAudioMuted = !enabled
            // Deafen mutes every remote track; a per-user mute stays in
            // force underneath (un-deafening restores the peer's own mute
            // state rather than unmuting everyone).
            let peerMuted = roomPeerMuted[callID] ?? false
            for track in media.remoteAudioTracks {
                track.isEnabled = enabled && !peerMuted
            }
        }
    }

    func setVideoEnabled(_ enabled: Bool, callID: UUID) async throws {
        lock.withLock {
            guard let media = peers[callID] else { return }
            media.videoEnabled = enabled
            media.videoTrack?.isEnabled = enabled
            if enabled {
                // Screen share owns the video track while active; don't
                // restart the camera underneath it.
                if !media.isScreenSharing { requestCameraAndStartLocked(for: callID) }
            } else {
                stopCameraLocked(for: callID)
            }
        }
    }

    func setSpeaker(_ enabled: Bool, callID: UUID) async throws {
        let session = RTCAudioSession.sharedInstance()
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        // Throws when the route change is rejected; the error propagates
        // to the caller (the call UI surfaces it) instead of silently
        // doing nothing.
        try session.overrideOutputAudioPort(enabled ? .speaker : .none)
    }

    func startScreenShare(callID: UUID) async throws {
        try lock.withLock {
            let media = try peerLocked(for: callID)
            guard let source = media.videoSource, let track = media.videoTrack
            else { throw EngineError.noSuchCall }
            guard media.screenCapturer == nil else { return }
            // Pause the camera; the screen capturer takes over the same
            // video source so the peer sees our app content instead.
            stopCameraLocked(for: callID)
            let capturer = WindowSnapshotCapturer(delegate: source)
            capturer.start()
            media.screenCapturer = capturer
            media.isScreenSharing = true
            track.isEnabled = true
        }
    }

    func stopScreenShare(callID: UUID) async throws {
        lock.withLock {
            guard let media = peers[callID] else { return }
            media.screenCapturer?.stop()
            media.screenCapturer = nil
            media.isScreenSharing = false
            if media.videoEnabled { requestCameraAndStartLocked(for: callID) }
        }
    }

    var screenShareSupported: Bool { true }

    func endCallMedia(_ callID: UUID) {
        lock.withLock {
            guard let media = peers.removeValue(forKey: callID) else { return }
            stopCameraLocked(for: callID)
            media.screenCapturer?.stop()
            media.broadcastController?.stop()
            roomPeers.remove(callID)
            roomPeerMuted.removeValue(forKey: callID)
            refreshLocalPreviewLocked()
            media.connection.close()
            pcToCallID = pcToCallID.filter { $0.value != callID }
            renderers.removeValue(forKey: callID)
            callKinds.removeValue(forKey: callID)
            lastLevels.removeValue(forKey: callID)
        }
    }
}

// MARK: - Voice-room mesh extras (CallMediaControl)

extension WebRTCMediaEngine {
    var onAudioLevels: (([UUID: CallAudioLevels]) -> Void)? {
        get { lock.withLock { _onAudioLevels } }
        set { lock.withLock { _onAudioLevels = newValue } }
    }

    var onPeerConnectionStateChanged: ((UUID, PeerConnectionState) -> Void)? {
        get { lock.withLock { _onPeerConnectionStateChanged } }
        set { lock.withLock { _onPeerConnectionStateChanged = newValue } }
    }

    var onCameraPermissionDenied: (() -> Void)? {
        get { lock.withLock { _onCameraPermissionDenied } }
        set { lock.withLock { _onCameraPermissionDenied = newValue } }
    }

    func noteVoiceRoomPeer(_ callID: UUID) {
        lock.withLock { roomPeers.insert(callID) }
    }

    /// Local-only per-user mute for a voice-room peer. Disables the peer's
    /// remote audio track(s) on this device; nothing is signaled. Combines
    /// with deafen (`setRemoteAudioEnabled`): a peer muted here stays
    /// muted when the room is un-deafened.
    func setRemoteMuted(_ muted: Bool, for callID: UUID) {
        lock.withLock {
            roomPeerMuted[callID] = muted
            guard let media = peers[callID] else { return }
            for track in media.remoteAudioTracks {
                track.isEnabled = !muted && !media.remoteAudioMuted
            }
        }
    }

    func rotateMediaIdentity() {
        // The next peer connection gets a fresh DTLS certificate from a
        // new factory; existing connections are unaffected until the caller
        // tears them down (VoiceRoomManager's membership-epoch rotation).
        lock.withLock { factoryGeneration += 1 }
    }

    func setAudioLevelPolling(_ enabled: Bool) {
        lock.withLock {
            levelTimer?.cancel()
            levelTimer = nil
            guard enabled else { return }
            let timer = DispatchSource.makeTimerSource()
            timer.schedule(deadline: .now() + .milliseconds(300), repeating: .milliseconds(300))
            timer.setEventHandler { [weak self] in self?.pollAudioLevels() }
            timer.resume()
            levelTimer = timer
        }
    }

    func attachLocalVideoRenderer(_ renderer: RTCVideoRenderer) {
        lock.withLock {
            if !localPreviewRenderers.contains(where: { $0.value === renderer }) {
                localPreviewRenderers.append(WeakVideoRenderer(renderer))
            }
            refreshLocalPreviewLocked()
        }
    }

    func detachLocalVideoRenderer(_ renderer: RTCVideoRenderer) {
        lock.withLock {
            localPreviewRenderers.removeAll { $0.value == nil || $0.value === renderer }
            refreshLocalPreviewLocked()
        }
    }

    // MARK: Audio-level polling internals

    private func pollAudioLevels() {
        let snapshot: [(UUID, RTCPeerConnection)] = lock.withLock {
            peers.map { ($0.key, $0.value.connection) }
        }
        for (callID, connection) in snapshot {
            // M154: `statistics(completionHandler:)` delivers a single
            // RTCStatisticsReport. The manager maps callIDs to voice-room
            // peers; 1:1 calls never enable polling, so their stats are
            // simply never requested.
            connection.statistics { [weak self] report in
                self?.handleStatsReport(report, callID: callID)
            }
        }
    }

    private func handleStatsReport(_ report: RTCStatisticsReport, callID: UUID) {
        var local: Float = 0
        var remote: Float = 0
        // report.statistics is [String: RTCStatistics]; each RTCStatistics
        // carries W3C stats keys in `values`. Per RFC 6464 / the W3C stats
        // spec, "track"-type audio stats expose `audioLevel` (0.0–1.0
        // linear energy); `remoteSource` distinguishes the peer's track
        // from the local microphone track. Levels are absent when the
        // audio-level header extension isn't negotiated — indicators then
        // stay silent rather than guessing.
        for stat in report.statistics.values {
            guard stat.type == "track" else { continue }
            let values = stat.values as [String: Any]
            guard let level = (values["audioLevel"] as? NSNumber)?.floatValue else { continue }
            let isRemote = (values["remoteSource"] as? NSNumber)?.boolValue ?? false
            if isRemote {
                remote = max(remote, level)
            } else {
                local = max(local, level)
            }
        }
        let (callback, snapshot): (([UUID: CallAudioLevels]) -> Void)?, [UUID: CallAudioLevels] =
            lock.withLock {
                lastLevels[callID] = CallAudioLevels(local: local, remote: remote)
                return (_onAudioLevels, lastLevels)
            }
        callback?(snapshot)
    }
}

// MARK: - Screen-share extras (CallMediaControl)

extension WebRTCMediaEngine {
    func setScreenSharePaused(_ paused: Bool, callID: UUID) async throws {
        try lock.withLock {
            guard let capturer = peers[callID]?.screenCapturer else { throw EngineError.noSuchCall }
            capturer.setPaused(paused)
        }
    }

    func setScreenShareRedactionRegions(_ regions: [CGRect], callID: UUID) async throws {
        try lock.withLock {
            guard let capturer = peers[callID]?.screenCapturer else { throw EngineError.noSuchCall }
            capturer.setRedactionRegions(regions)
        }
    }

    func startBroadcastShare(callID: UUID) async throws {
        try lock.withLock {
            let media = try peerLocked(for: callID)
            guard let source = media.videoSource, let track = media.videoTrack
            else { throw EngineError.noSuchCall }
            guard media.broadcastController == nil else { return }
            // The broadcast owns the video track while active, like the
            // in-app screen capturer.
            stopCameraLocked(for: callID)
            media.screenCapturer?.stop()
            media.screenCapturer = nil
            media.isScreenSharing = false
            let controller = BroadcastShareController()
            controller.onFirstFrame = { [weak self] in
                self?.log.info("Broadcast extension frames arriving; video track is live")
            }
            controller.start(source: source)
            media.broadcastController = controller
            media.isBroadcastSharing = true
            track.isEnabled = true
            refreshLocalPreviewLocked()
        }
    }

    func stopBroadcastShare(callID: UUID) async throws {
        lock.withLock {
            guard let media = peers[callID] else { return }
            media.broadcastController?.stop()
            media.broadcastController = nil
            media.isBroadcastSharing = false
            if media.videoEnabled { requestCameraAndStartLocked(for: callID) }
            refreshLocalPreviewLocked()
        }
    }

    var broadcastShareSupported: Bool {
        // The Broadcast Upload Extension ships inside the app bundle's
        // PlugIns directory. Absent (e.g. simulator, sideload without the
        // extension), the UI offers in-app sharing only — never a dead
        // button.
        guard let plugins = Bundle.main.builtInPlugInsURL else { return false }
        return (try? FileManager.default.contentsOfDirectory(
            at: plugins, includingPropertiesForKeys: nil
        ))?.contains(where: { $0.pathExtension == "appex" }) ?? false
    }
}

/// Weak box for local-preview renderers so a dismissed room view can't be
/// kept alive by the engine.
private final class WeakVideoRenderer {
    weak var value: (any RTCVideoRenderer)?
    init(_ value: any RTCVideoRenderer) { self.value = value }
}

// MARK: - RTCPeerConnectionDelegate

extension WebRTCMediaEngine: RTCPeerConnectionDelegate {
    func peerConnection(_ peerConnection: RTCPeerConnection, didChange stateChanged: RTCSignalingState) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didAdd stream: RTCMediaStream) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didRemove stream: RTCMediaStream) {}
    func peerConnectionShouldNegotiate(_ peerConnection: RTCPeerConnection) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceGatheringState) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didRemove candidates: [RTCIceCandidate]) {}
    func peerConnection(_ peerConnection: RTCPeerConnection, didOpen dataChannel: RTCDataChannel) {}

    func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCIceConnectionState) {
        log.info("ICE connection state: \(String(describing: newState))")
    }

    func peerConnection(_ peerConnection: RTCPeerConnection, didChange newState: RTCPeerConnectionState) {
        // The aggregate connection state: .connected here means media is
        // actually flowing (DTLS handshake done), beyond ICE alone.
        log.info("Peer connection state: \(String(describing: newState))")
        let mapped: PeerConnectionState
        switch newState {
        case .new, .connecting:
            mapped = .connecting
        case .connected:
            mapped = .connected
        case .disconnected:
            mapped = .reconnecting
        case .failed:
            mapped = .failed
        case .closed:
            mapped = .closed
        @unknown default:
            mapped = .connecting
        }
        if let callID = lock.withLock({ pcToCallID[ObjectIdentifier(peerConnection)] }) {
            onPeerConnectionStateChanged?(callID, mapped)
        }
    }

    func peerConnection(_ peerConnection: RTCPeerConnection, didGenerate candidate: RTCIceCandidate) {
        // Extract Sendable values synchronously; the signaling hop happens
        // on the engine's callback without touching WebRTC objects.
        let sdp = candidate.sdp
        let lineIndex = candidate.sdpMLineIndex
        let mid = candidate.sdpMid
        guard let callID = lock.withLock({ pcToCallID[ObjectIdentifier(peerConnection)] })
        else { return }
        let ice = IceCandidate(
            callID: callID.uuidString,
            candidate: sdp,
            sdpMLineIndex: lineIndex,
            sdpMid: mid
        )
        onLocalIceCandidate?(ice, callID)
    }

    func peerConnection(
        _ peerConnection: RTCPeerConnection,
        didAdd rtpReceiver: RTCRtpReceiver,
        streams: [RTCMediaStream]
    ) {
        // Remote audio tracks are remembered so deafen (voice rooms) can
        // disable them without tearing down the peer connection. Remote
        // Remote audio renders through WebRTC's normal output mix. Per-user
        // control is mute (track disabling); the stock iOS SDK exposes no
        // per-track gain (see the voice-room audio note at the top of this
        // file). A stored per-user mute or deafen state applies to tracks
        // that attach later.
        if let audioTrack = rtpReceiver.track as? RTCAudioTrack {
            lock.withLock {
                guard let callID = pcToCallID[ObjectIdentifier(peerConnection)],
                      let media = peers[callID]
                else { return }
                media.remoteAudioTracks.append(audioTrack)
                audioTrack.isEnabled = !media.remoteAudioMuted && !(roomPeerMuted[callID] ?? false)
            }
            return
        }
        guard let videoTrack = rtpReceiver.track as? RTCVideoTrack else { return }
        let (callID, router) = lock.withLock({
            (pcToCallID[ObjectIdentifier(peerConnection)], frameRouter)
        })
        guard let callID = callID, let router = router else { return }
        let renderer = RemoteFrameRenderer(callID: callID)
        renderer.router = router
        videoTrack.add(renderer)
        lock.withLock { renderers[callID] = renderer }
        log.info("Remote video track attached")
    }
}

// MARK: - Per-call media state (NSLock-guarded, never leaves the engine)

/// Mutable WebRTC state for one call. Only touched under the engine's lock.
private final class PeerMedia {
    let callID: UUID
    let connection: RTCPeerConnection
    var audioTrack: RTCAudioTrack?
    var videoTrack: RTCVideoTrack?
    var videoSource: RTCVideoSource?
    /// Per-PC screen capturer (1:1 screen share takes over videoSource).
    var screenCapturer: WindowSnapshotCapturer?
    /// Broadcast-upload controller (full-device sharing); takes over
    /// videoSource like the screen capturer.
    var broadcastController: BroadcastShareController?
    var videoEnabled = true
    var isScreenSharing = false
    var isBroadcastSharing = false
    var createdOffer = false
    /// Remote audio tracks received on this connection (1:1 calls and
    /// non-mixer paths). Voice-room peers render through the mixer instead.
    var remoteAudioTracks: [RTCAudioTrack] = []
    /// Deafen state: when true, remote audio tracks stay disabled.
    var remoteAudioMuted = false

    init(callID: UUID, connection: RTCPeerConnection) {
        self.callID = callID
        self.connection = connection
    }
}

// MARK: - Remote frame delivery

/// Receives decoded remote video frames from WebRTC and forwards them as
/// CMSampleBuffer into the transport's CallMediaRouter, which fans out to
/// the app's registered VideoSink (see RemoteVideoView).
private final class RemoteFrameRenderer: NSObject, RTCVideoRenderer, @unchecked Sendable {
    let callID: UUID
    var router: CallMediaRouter?

    init(callID: UUID) { self.callID = callID }

    func setSize(_ size: CGSize) {}

    func renderFrame(_ frame: RTCVideoFrame?) {
        guard let frame = frame,
              let router = router,
              let sampleBuffer = frame.cmsSampleBuffer
        else { return }
        router.deliverFrame(sampleBuffer, forCall: callID)
    }
}

extension RTCVideoFrame {
    /// Converts a decoded WebRTC frame to CMSampleBuffer for the app's
    /// video pipeline. Handles both CVPixelBuffer-backed frames (zero
    /// copy) and I420 frames (planar copy into a fresh pixel buffer).
    fileprivate var cmsSampleBuffer: CMSampleBuffer? {
        let pixelBuffer: CVPixelBuffer
        if let cv = buffer as? RTCCVPixelBuffer {
            pixelBuffer = cv.pixelBuffer
        } else if let converted = buffer.toI420().makePixelBuffer() {
            // M154: toI420() returns a non-optional RTCI420BufferProtocol.
            pixelBuffer = converted
        } else {
            return nil
        }
        var formatDescription: CMVideoFormatDescription?
        guard CMVideoFormatDescriptionCreateForImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pixelBuffer,
            formatDescriptionOut: &formatDescription
        ) == noErr, let formatDescription = formatDescription else { return nil }
        var timing = CMSampleTimingInfo(
            duration: .invalid,
            presentationTimeStamp: CMTime(value: CMTimeValue(timeStampNs), timescale: 1_000_000_000),
            decodeTimeStamp: .invalid
        )
        var sampleBuffer: CMSampleBuffer?
        guard CMSampleBufferCreateForImageBuffer(
            allocator: kCFAllocatorDefault,
            imageBuffer: pixelBuffer,
            dataReady: true,
            makeDataReadyCallback: nil,
            refcon: nil,
            formatDescription: formatDescription,
            sampleTiming: &timing,
            sampleBufferOut: &sampleBuffer
        ) == noErr else { return nil }
        return sampleBuffer
    }
}

extension RTCI420BufferProtocol {
    /// Copies planar I420 data into a CoreVideo pixel buffer.
    /// M154: dataY/U/V are non-optional UnsafePointers on the protocol.
    fileprivate func makePixelBuffer() -> CVPixelBuffer? {
        let width = Int(self.width), height = Int(self.height)
        guard width > 0, height > 0 else { return nil }
        var pixelBuffer: CVPixelBuffer?
        let attributes = [kCVPixelBufferIOSurfacePropertiesKey: [:]] as CFDictionary
        guard CVPixelBufferCreate(
            kCFAllocatorDefault, width, height,
            kCVPixelFormatType_420YpCbCr8Planar, attributes, &pixelBuffer
        ) == kCVReturnSuccess, let pixelBuffer = pixelBuffer else { return nil }
        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }
        guard let dstY = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0),
              let dstU = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 1),
              let dstV = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 2)
        else { return nil }
        copyPlane(src: self.dataY, srcStride: Int(self.strideY),
                  dst: dstY,
                  dstStride: CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0),
                  width: width, height: height)
        copyPlane(src: self.dataU, srcStride: Int(self.strideU),
                  dst: dstU,
                  dstStride: CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 1),
                  width: width / 2, height: height / 2)
        copyPlane(src: self.dataV, srcStride: Int(self.strideV),
                  dst: dstV,
                  dstStride: CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 2),
                  width: width / 2, height: height / 2)
        return pixelBuffer
    }

    private func copyPlane(src: UnsafePointer<UInt8>, srcStride: Int,
                           dst: UnsafeMutableRawPointer, dstStride: Int,
                           width: Int, height: Int) {
        for row in 0..<height {
            dst.advanced(by: row * dstStride)
                .copyMemory(from: src.advanced(by: row * srcStride), byteCount: width)
        }
    }
}

// MARK: - App-content screen sharing

/// Shares the app's own window content as the call's video track.
///
/// Implementation note: full-device screen capture on iOS requires a
/// ReplayKit Broadcast Upload Extension (a separate app extension with its
/// own entitlements — see docs for the roadmap). This capturer instead
/// snapshots the app's key window a few times per second, which covers the
/// real use case ("show them what's on my screen in this app") with no
/// extra entitlements and works in the simulator.
final class WindowSnapshotCapturer: RTCVideoCapturer, @unchecked Sendable {
    private var timer: DispatchSourceTimer?
    private let log = Logger(subsystem: "app.aegis.ios", category: "webrtc")
    private let stateLock = NSLock()
    private var _isPaused = false
    /// Opaque redaction rectangles in normalized unit coordinates (0–1)
    /// relative to the window bounds, painted on-device before encoding.
    private var _redactionRegions: [CGRect] = []

    /// Pauses frame capture; the peer keeps seeing the last frame and the
    /// video track stays live, so resume needs no renegotiation.
    func setPaused(_ paused: Bool) {
        stateLock.withLock { _isPaused = paused }
    }

    /// Sets the on-device redaction regions (normalized 0–1 rects).
    func setRedactionRegions(_ regions: [CGRect]) {
        stateLock.withLock { _redactionRegions = regions.map { $0.clampedToUnit() } }
    }

    func start() {
        stop()
        // Capture on the main queue: window snapshotting must run on main.
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now(), repeating: .milliseconds(250))
        timer.setEventHandler { [weak self] in self?.captureOnce() }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private func captureOnce() {
        // UIKit window access is @MainActor; the timer only guarantees the
        // main queue, so hop to the actor explicitly (Swift 6).
        Task { @MainActor [weak self] in
            self?.captureOnceOnMain()
        }
    }

    @MainActor
    private func captureOnceOnMain() {
        let (isPaused, regions) = stateLock.withLock { (_isPaused, _redactionRegions) }
        guard !isPaused else { return }
        guard let window = UIApplication.shared.firstKeyWindow,
              window.bounds.width > 1, window.bounds.height > 1 else { return }
        let format = UIGraphicsImageRendererFormat()
        format.scale = 0.5 // Half resolution keeps the bitrate reasonable.
        var image = UIGraphicsImageRenderer(bounds: window.bounds, format: format).image { _ in
            _ = window.drawHierarchy(in: window.bounds, afterScreenUpdates: false)
        }
        if !regions.isEmpty {
            image = image.redacted(regions: regions)
        }
        guard let cgImage = image.cgImage,
              let pixelBuffer = cgImage.makePixelBuffer(),
              let delegate = self.delegate else { return }
        let rtcBuffer = RTCCVPixelBuffer(pixelBuffer: pixelBuffer)
        let frame = RTCVideoFrame(
            buffer: rtcBuffer,
            rotation: ._0,
            timeStampNs: Int64(Date().timeIntervalSince1970 * 1_000_000_000)
        )
        delegate.capturer(self, didCapture: frame)
    }
}

// MARK: - Redaction helpers

extension CGRect {
    /// Clamps to normalized unit coordinates (0–1), dropping degenerate rects.
    func clampedToUnit() -> CGRect {
        let x = max(0, min(1, origin.x))
        let y = max(0, min(1, origin.y))
        let w = max(0, min(1 - x, size.width))
        let h = max(0, min(1 - y, size.height))
        return CGRect(x: x, y: y, width: w, height: h)
    }

    var isDegenerate: Bool { width <= 0.01 || height <= 0.01 }
}

extension UIImage {
    /// Paints opaque black rectangles over the image. Redaction is applied
    /// on-device before the frame is encoded — redacted pixels never leave
    /// the device in any form.
    func redacted(regions: [CGRect]) -> UIImage {
        let format = UIGraphicsImageRendererFormat()
        format.scale = scale
        return UIGraphicsImageRenderer(size: size, format: format).image { _ in
            draw(at: .zero)
            UIColor.black.setFill()
            for region in regions where !region.isDegenerate {
                let rect = CGRect(
                    x: region.origin.x * size.width,
                    y: region.origin.y * size.height,
                    width: region.width * size.width,
                    height: region.height * size.height
                )
                UIRectFill(rect)
            }
        }
    }
}

extension UIApplication {
    fileprivate var firstKeyWindow: UIWindow? {
        connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
    }
}

extension CGImage {
    fileprivate func makePixelBuffer() -> CVPixelBuffer? {
        var pixelBuffer: CVPixelBuffer?
        let attributes = [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true,
        ] as CFDictionary
        guard CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                                  kCVPixelFormatType_32BGRA, attributes, &pixelBuffer) == kCVReturnSuccess,
              let pixelBuffer = pixelBuffer else { return nil }
        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }
        guard let context = CGContext(
            data: CVPixelBufferGetBaseAddress(pixelBuffer),
            width: width, height: height,
            bitsPerComponent: 8,
            bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer),
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
        ) else { return nil }
        context.draw(self, in: CGRect(x: 0, y: 0, width: width, height: height))
        return pixelBuffer
    }
}
