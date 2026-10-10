// CallMedia — the remote-video rendering seam.
//
// Call signaling travels as sealed envelopes (see docs/NETWORKING.md §6);
// media is a WebRTC peer connection owned by the app layer (WebRTC is not
// vendored in this package). This file is the handoff between the two:
//
//   app's WebRTC layer ──CMSampleBuffer──▶ CallMediaRouter ──▶ VideoSink
//                                                             (app's view)
//
// The transport adapter owns one `CallMediaRouter`. When a call becomes
// active, the app registers its preview view as the sink via
// `setVideoSink(_:for:)`; the WebRTC layer (or its replacement) pushes
// decoded remote frames into `deliverFrame(_:forCall:)`. No frames are
// retained, recorded, or inspected here — the router is a dumb,
// thread-safe fan-out of exactly one sink per call.

import CoreMedia
import Foundation

/// Renders decoded remote video frames. Implemented by the app (typically
/// a `UIView` wrapping a `VTDecompressionSession` output or WebRTC's
/// `RTCVideoRenderer`). Frames arrive on an arbitrary queue — the sink
/// must dispatch to main itself if it touches UIKit.
public protocol VideoSink: AnyObject, Sendable {
    /// A decoded remote video frame for `callID`. The router never retains
    /// the buffer beyond this call.
    func renderRemoteFrame(_ sampleBuffer: CMSampleBuffer, forCall callID: UUID)
}

/// Routes remote video frames to the per-call sink. One sink per call;
/// registering a second sink replaces the first.
///
/// Manually synchronized: every access to `sinks` goes through `lock`,
/// hence `@unchecked Sendable`.
public final class CallMediaRouter: @unchecked Sendable {
    private let lock = NSLock()
    private var sinks: [UUID: WeakVideoSink] = [:]

    public init() {}

    /// Register (or replace) the sink for a call. Pass `nil` to unregister.
    public func setVideoSink(_ sink: (any VideoSink)?, for callID: UUID) {
        lock.withLock {
            if let sink {
                sinks[callID] = WeakVideoSink(sink)
            } else {
                sinks.removeValue(forKey: callID)
            }
        }
    }

    /// The currently registered sink for a call, if any.
    public func sink(for callID: UUID) -> (any VideoSink)? {
        lock.withLock { sinks[callID]?.value }
    }

    /// Push a decoded remote frame toward the call's sink. Dropped silently
    /// when no sink is registered (e.g. audio-only call, view dismissed).
    public func deliverFrame(_ sampleBuffer: CMSampleBuffer, forCall callID: UUID) {
        let target = lock.withLock { sinks[callID]?.value }
        target?.renderRemoteFrame(sampleBuffer, forCall: callID)
    }

    /// Drop all sinks (call teardown).
    public func removeAll() {
        lock.withLock { sinks.removeAll() }
    }
}

// MARK: - Internal

/// Weak box so a dismissed call view cannot be kept alive by the router.
private final class WeakVideoSink: @unchecked Sendable {
    weak var value: (any VideoSink)?
    init(_ value: any VideoSink) { self.value = value }
}
