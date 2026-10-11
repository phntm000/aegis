// SampleHandler — Aegis Broadcast Upload Extension.
//
// Full-device screen sharing for Aegis calls. iOS only lets a Broadcast
// Upload Extension capture the whole screen, so this target exists solely
// to bridge extension frames into the app:
//
//   ReplayKit ──CMSampleBuffer──▶ SampleHandler ──JPEG──▶ App Group
//       (extension process)        (downscale+encode)    (shared container)
//
// The app side (Aegis/Media/BroadcastShare.swift) watches the container
// via a Darwin notification, decodes the latest JPEG, and feeds it into the
// call's RTCVideoSource — the peer sees the device screen over the same
// DTLS-SRTP video track as in-app sharing.
//
// Notes:
// - Audio sample buffers are ignored: call audio already flows through the
//   WebRTC peer connection; capturing it here would double it.
// - Frames are downscaled to 720p and JPEG-encoded at moderate quality to
//   keep the extension's memory/CPU inside its budget.
// - View-only by design: the extension only reads pixels; there is no
//   remote-control channel anywhere in this pipeline.
// - This target must stay dependency-free (no WebRTC, no Aegis packages):
//   extensions have strict memory limits and the frame handoff is files,
//   not APIs.

import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation
import ImageIO
import ReplayKit
import UniformTypeIdentifiers

final class SampleHandler: RPBroadcastSampleHandler {

    private static let appGroupID = "group.app.aegis.ios"
    private static let frameFileName = "broadcast/latest.jpg"
    private static let notificationName = "app.aegis.ios.broadcastframe" as CFString
    /// Max output dimension (720p). Keeps encode cost and file size sane.
    private static let maxDimension: CGFloat = 720
    /// Write at most ~10 fps; the call pipeline doesn't need more.
    private static let minInterval: TimeInterval = 0.1

    private var frameCount = 0
    private var lastWrite = Date.distantPast

    override func broadcastStarted(withSetupInfo setupInfo: [String: NSObject]? = nil) {
        // Nothing to set up: frames flow through processSampleBuffer.
    }

    override func processSampleBuffer(
        _ sampleBuffer: CMSampleBuffer,
        with sampleBufferType: RPSampleBufferType
    ) {
        guard sampleBufferType == .video else { return }
        frameCount += 1
        // ReplayKit can deliver 60fps; throttle before the expensive path.
        let now = Date()
        guard now.timeIntervalSince(lastWrite) >= Self.minInterval else { return }
        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        lastWrite = now
        autoreleasepool {
            guard let jpeg = Self.jpegFrame(from: pixelBuffer),
                  let url = Self.frameURL
            else { return }
            try? FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            // Atomic write so the app never reads a half-written frame.
            try? jpeg.write(to: url, options: .atomic)
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                Self.notificationName,
                nil,
                nil,
                true
            )
        }
    }

    override func broadcastFinished() {
        // Best-effort cleanup so a stale frame can't be picked up by a
        // later session.
        if let url = Self.frameURL {
            try? FileManager.default.removeItem(at: url)
        }
    }

    // MARK: - Frame encoding

    private static var frameURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)?
            .appendingPathComponent(frameFileName)
    }

    /// Downscales the pixel buffer to 720p and JPEG-encodes it.
    private static func jpegFrame(from pixelBuffer: CVPixelBuffer) -> Data? {
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        guard width > 0, height > 0 else { return nil }
        let scale = min(1.0, maxDimension / CGFloat(max(width, height)))
        let outWidth = max(2, Int(CGFloat(width) * scale))
        let outHeight = max(2, Int(CGFloat(height) * scale))

        CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }
        guard let base = CVPixelBufferGetBaseAddress(pixelBuffer) else { return nil }
        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)
        guard let colorSpace = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
        guard let context = CGContext(
            data: base,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: bytesPerRow,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                | CGBitmapInfo.byteOrder32Little.rawValue
        ), let image = context.makeImage() else { return nil }

        // Downscale draw.
        let outSize = CGSize(width: outWidth, height: outHeight)
        guard let outContext = CGContext(
            data: nil,
            width: outWidth,
            height: outHeight,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                | CGBitmapInfo.byteOrder32Little.rawValue
        ) else { return nil }
        outContext.interpolationQuality = .medium
        outContext.draw(image, in: CGRect(origin: .zero, size: outSize))
        guard let scaled = outContext.makeImage() else { return nil }

        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            data as CFMutableData, UTType.jpeg.identifier as CFString, 1, nil
        ) else { return nil }
        CGImageDestinationAddImage(destination, scaled, [
            kCGImageDestinationLossyCompressionQuality: 0.6
        ] as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
    }
}
