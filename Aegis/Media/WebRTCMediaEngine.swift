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
    private var peers: [UUID: PeerMedia] = [:]
    private var pcToCallID: [ObjectIdentifier: UUID] = [:]
    private var renderers: [UUID: RemoteFrameRenderer] = [:]
    private var frameRouter: CallMediaRouter?
    private var callKinds: [UUID: CallKind] = [:]

    /// Connects the engine to the transport's frame router. Called once at
    /// startup (after AegisCore exists); remote frames are dropped until
    /// attached, matching the router's own drop-silently contract.
    func attachFrameRouter(_ router: CallMediaRouter) {
        lock.withLock { frameRouter = router }
    }

    // MARK: - Peer sessions (lock-guarded)

    private func makeFactoryLocked() -> RTCPeerConnectionFactory {
        if let factory { return factory }
        let created = RTCPeerConnectionFactory(
            encoderFactory: RTCDefaultVideoEncoderFactory(),
            decoderFactory: RTCDefaultVideoDecoderFactory()
        )
        factory = created
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
                if granted { self?.startCamera(for: callID) }
            }
        case .denied, .restricted:
            log.error("Camera access denied; continuing audio-only")
            peers[callID]?.videoTrack?.isEnabled = false
        @unknown default:
            break
        }
    }

    /// Lock-taking wrapper for use outside the engine's lock (e.g. the
    /// camera-permission callback, which runs on an arbitrary thread).
    private func startCamera(for callID: UUID) {
        lock.withLock { startCameraLocked(for: callID) }
    }

    /// Assumes the engine lock is held.
    private func startCameraLocked(for callID: UUID) {
        guard let media = peers[callID], let source = media.videoSource else { return }
        let capturer: RTCCameraVideoCapturer
        if let existing = media.cameraCapturer {
            capturer = existing
        } else {
            capturer = RTCCameraVideoCapturer(delegate: source)
            media.cameraCapturer = capturer
        }
        let devices = RTCCameraVideoCapturer.captureDevices()
        guard let device = devices.first(where: { $0.position == .front }) ?? devices.first
        else {
            log.error("No camera device found")
            return
        }
        let formats = RTCCameraVideoCapturer.supportedFormats(for: device)
        guard let format = formats.first(where: {
            CMVideoFormatDescriptionGetDimensions($0.formatDescription).width == 640
        }) ?? formats.first else {
            log.error("No suitable camera format")
            return
        }
        let fps = min(Int(format.videoSupportedFrameRateRanges.first?.maxFrameRate ?? 30), 24)
        capturer.startCapture(with: device, format: format, fps: fps)
    }
}

// MARK: - CallMediaDelegate (SDP / ICE)

extension WebRTCMediaEngine: CallMediaDelegate {

    func createOffer(for callID: UUID) async throws -> (sdp: String, dtlsFingerprint: String) {
        let media = try lock.withLock { try peerLocked(for: callID) }
        lock.withLock { addLocalTracksLocked(to: media) }
        lock.withLock { media.createdOffer = true }
        let offer: RTCSessionDescription = try await withCheckedThrowingContinuation { cont in
            media.connection.offer(
                for: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
            ) { sdp, error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else if let sdp = sdp {
                    cont.resume(returning: sdp)
                } else {
                    cont.resume(throwing: EngineError.sdpFailure("empty offer"))
                }
            }
        }
        try await setLocalDescription(offer, for: callID)
        return (offer.sdp, SDPFingerprint.extract(from: offer.sdp) ?? "")
    }

    func createAnswer(for callID: UUID, offerSDP: String) async throws -> (sdp: String, dtlsFingerprint: String) {
        guard !offerSDP.isEmpty else { throw EngineError.emptyRemoteOffer }
        try await setRemoteDescription(RTCSessionDescription(type: .offer, sdp: offerSDP), for: callID)
        let media = try lock.withLock { try peerLocked(for: callID) }
        lock.withLock { addLocalTracksLocked(to: media) }
        let answer: RTCSessionDescription = try await withCheckedThrowingContinuation { cont in
            media.connection.answer(
                for: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
            ) { sdp, error in
                if let error = error {
                    cont.resume(throwing: EngineError.sdpFailure(error.localizedDescription))
                } else if let sdp = sdp {
                    cont.resume(returning: sdp)
                } else {
                    cont.resume(throwing: EngineError.sdpFailure("empty answer"))
                }
            }
        }
        try await setLocalDescription(answer, for: callID)
        return (answer.sdp, SDPFingerprint.extract(from: answer.sdp) ?? "")
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
                media.cameraCapturer?.stopCapture()
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
            media.cameraCapturer?.stopCapture()
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
            media.cameraCapturer?.stopCapture()
            media.screenCapturer?.stop()
            media.connection.close()
            pcToCallID = pcToCallID.filter { $0.value != callID }
            renderers.removeValue(forKey: callID)
            callKinds.removeValue(forKey: callID)
        }
    }
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
    var cameraCapturer: RTCCameraVideoCapturer?
    var screenCapturer: WindowSnapshotCapturer?
    var videoEnabled = true
    var isScreenSharing = false
    var createdOffer = false

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
        guard let window = UIApplication.shared.firstKeyWindow,
              window.bounds.width > 1, window.bounds.height > 1 else { return }
        let format = UIGraphicsImageRendererFormat()
        format.scale = 0.5 // Half resolution keeps the bitrate reasonable.
        let image = UIGraphicsImageRenderer(bounds: window.bounds, format: format).image { _ in
            _ = window.drawHierarchy(in: window.bounds, afterScreenUpdates: false)
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
