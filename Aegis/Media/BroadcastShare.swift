// BroadcastShare — full-device screen sharing via the ReplayKit Broadcast
// Upload Extension.
//
// iOS forbids in-app full-device capture; only a Broadcast Upload Extension
// (the AegisBroadcastUpload target) may capture the whole screen. The
// extension's SampleHandler downscales frames to JPEG and writes the latest
// one into the shared App Group container, posting a Darwin notification
// per frame. This file is the app side:
//
//   BroadcastFrameReader ──CVPixelBuffer──▶ BroadcastCapturer ──▶
//       (Darwin notify + App Group)        (RTCVideoCapturer feeding the
//                                           call's existing RTCVideoSource)
//
// The broadcast takes over the call's video track with no renegotiation,
// exactly like the in-app screen capturer. View-only by design: there is no
// remote-control channel anywhere in this pipeline.
//
// On-device QA required: the extension only runs on a real device with the
// app installed (never in the simulator), and the user starts it through
// the system broadcast picker.

import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation
import WebRTCBridge

/// Shared constants between the app and the Broadcast Upload Extension.
/// Both sides must agree on the App Group id (see the entitlements files).
enum BroadcastShare {
    static let appGroupID = "group.app.aegis.ios"
    static let frameFileName = "broadcast/latest.jpg"
    static let notificationName = "app.aegis.ios.broadcastframe"

    static var frameURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)?
            .appendingPathComponent(frameFileName)
    }
}

/// An RTCVideoCapturer fed by frames arriving from the broadcast extension.
final class BroadcastCapturer: RTCVideoCapturer, @unchecked Sendable {
    func deliver(pixelBuffer: CVPixelBuffer) {
        let rtcBuffer = RTCCVPixelBuffer(pixelBuffer: pixelBuffer)
        let frame = RTCVideoFrame(
            buffer: rtcBuffer,
            rotation: ._0,
            timeStampNs: Int64(Date().timeIntervalSince1970 * 1_000_000_000)
        )
        delegate?.capturer(self, didCapture: frame)
    }
}

/// Watches the App Group container for frames written by the broadcast
/// extension and delivers them as pixel buffers.
final class BroadcastFrameReader: @unchecked Sendable {
    /// Called on an arbitrary queue for each decoded frame.
    var onFrame: ((CVPixelBuffer) -> Void)?

    private let lock = NSLock()
    private var observing = false
    private var lastRead = Date.distantPast
    /// At most ~12 fps; the extension writes faster than the call needs.
    private let minInterval: TimeInterval = 1.0 / 12.0

    func start() {
        lock.withLock {
            guard !observing else { return }
            observing = true
            let center = CFNotificationCenterGetDarwinNotifyCenter()
            let observer = Unmanaged.passUnretained(self).toOpaque()
            CFNotificationCenterAddObserver(
                center,
                observer,
                { _, observer, _, _, _ in
                    guard let observer else { return }
                    Unmanaged<BroadcastFrameReader>.fromOpaque(observer)
                        .takeUnretainedValue()
                        .readLatest()
                },
                CFNotificationName(BroadcastShare.notificationName as CFString),
                nil,
                .deliverImmediately
            )
        }
    }

    func stop() {
        lock.withLock {
            guard observing else { return }
            observing = false
            CFNotificationCenterRemoveObserver(
                CFNotificationCenterGetDarwinNotifyCenter(),
                Unmanaged.passUnretained(self).toOpaque(),
                CFNotificationName(BroadcastShare.notificationName as CFString),
                nil
            )
        }
        onFrame = nil
    }

    private func readLatest() {
        let now = Date()
        let shouldRead = lock.withLock { () -> Bool in
            guard now.timeIntervalSince(lastRead) >= minInterval else { return false }
            lastRead = now
            return true
        }
        guard shouldRead else { return }
        guard let url = BroadcastShare.frameURL,
              let data = try? Data(contentsOf: url),
              let image = BroadcastShare.cgImage(fromJPEG: data),
              let pixelBuffer = BroadcastShare.pixelBuffer(from: image)
        else { return }
        onFrame?(pixelBuffer)
    }
}

/// Owns the app side of one broadcast-share session for a call.
final class BroadcastShareController {
    private let lock = NSLock()
    private var capturer: BroadcastCapturer?
    private let reader = BroadcastFrameReader()
    private var didDeliverFirstFrame = false

    /// Called once the first extension frame reaches the video track, so
    /// the UI can flip to the "sharing" state.
    var onFirstFrame: (() -> Void)?

    /// Arms the frame reader; frames take over `source` as they arrive.
    func start(source: RTCVideoSource) {
        lock.withLock {
            guard capturer == nil else { return }
            let created = BroadcastCapturer(delegate: source)
            capturer = created
            reader.onFrame = { [weak self, weak created] pixelBuffer in
                guard let self, let created else { return }
                created.deliver(pixelBuffer: pixelBuffer)
                let first = self.lock.withLock { () -> Bool in
                    defer { self.didDeliverFirstFrame = true }
                    return !self.didDeliverFirstFrame
                }
                if first { self.onFirstFrame?() }
            }
            reader.start()
        }
    }

    func stop() {
        lock.withLock {
            reader.stop()
            capturer = nil
            didDeliverFirstFrame = false
        }
    }
}

// MARK: - Frame decoding helpers

extension BroadcastShare {
    fileprivate static func cgImage(fromJPEG data: Data) -> CGImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(source, 0, nil)
    }

    fileprivate static func pixelBuffer(from image: CGImage) -> CVPixelBuffer? {
        var pixelBuffer: CVPixelBuffer?
        let attributes = [
            kCVPixelBufferCGImageCompatibilityKey: true,
            kCVPixelBufferCGBitmapContextCompatibilityKey: true,
        ] as CFDictionary
        guard CVPixelBufferCreate(
            kCFAllocatorDefault, image.width, image.height,
            kCVPixelFormatType_32BGRA, attributes, &pixelBuffer
        ) == kCVReturnSuccess, let pixelBuffer = pixelBuffer else { return nil }
        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }
        guard let context = CGContext(
            data: CVPixelBufferGetBaseAddress(pixelBuffer),
            width: image.width, height: image.height,
            bitsPerComponent: 8,
            bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer),
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                | CGBitmapInfo.byteOrder32Little.rawValue
        ) else { return nil }
        context.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
        return pixelBuffer
    }
}
