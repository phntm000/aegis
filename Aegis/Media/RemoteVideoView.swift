// RemoteVideoView — renders the peer's video during a call.
//
// The WebRTC layer decodes remote frames and hands them to the transport's
// CallMediaRouter as CMSampleBuffer; this view implements the VideoSink
// protocol and displays them with AVSampleBufferDisplayLayer. Frames are
// dropped (not queued) when the layer isn't ready, matching the router's
// drop-silently contract — live video prefers fresh frames over backlog.

import AVFoundation
import CoreMedia
import SwiftUI
import AegisTransport

struct RemoteVideoView: UIViewRepresentable {
    /// Called once the underlying sink exists so the caller can register
    /// it with `TransportService.setVideoSink(_:for:)`.
    var onSinkReady: ((any VideoSink) -> Void)?

    func makeUIView(context: Context) -> RemoteVideoUIView {
        let view = RemoteVideoUIView()
        onSinkReady?(view)
        return view
    }

    func updateUIView(_ uiView: RemoteVideoUIView, context: Context) {}

    static func dismantleUIView(_ uiView: RemoteVideoUIView, coordinator: ()) {
        uiView.shutdown()
    }
}

/// CMSampleBuffer isn't marked Sendable in the SDK, but sample buffers are
/// immutable after creation and CoreMedia hands them safely across queues;
/// this box records that contract for the main-actor hop below.
private struct SendableSampleBuffer: @unchecked Sendable {
    let value: CMSampleBuffer
}

final class RemoteVideoUIView: UIView, VideoSink {
    private var displayLayer = AVSampleBufferDisplayLayer()
    override init(frame: CGRect) {
        super.init(frame: frame)
        displayLayer.videoGravity = .resizeAspectFill
        layer.addSublayer(displayLayer)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) not supported") }

    override func layoutSubviews() {
        super.layoutSubviews()
        displayLayer.frame = bounds
    }

    /// Main-actor hop is inside: the VideoSink contract delivers frames on an
    /// arbitrary queue and requires the sink to reach the main thread
    /// itself, so this witness is `nonisolated` and hops explicitly.
    /// CMSampleBuffer isn't marked Sendable in the SDK, but sample buffers
    /// are immutable after creation and CoreMedia documents them as safe
    /// to hand across queues — the @unchecked box records exactly that.
    nonisolated func renderRemoteFrame(_ sampleBuffer: CMSampleBuffer, forCall callID: UUID) {
        let box = SendableSampleBuffer(sampleBuffer)
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.enqueueRemoteFrame(box.value)
        }
    }

    @MainActor
    private func enqueueRemoteFrame(_ sampleBuffer: CMSampleBuffer) {
        if displayLayer.status == .failed {
            // A failed layer never recovers; rebuild it so video
            // resumes with the next frame instead of staying black.
            rebuildDisplayLayer()
        }
        guard displayLayer.isReadyForMoreMediaData else { return }
        displayLayer.enqueue(sampleBuffer)
    }

    private func rebuildDisplayLayer() {
        displayLayer.flush()
        displayLayer.removeFromSuperlayer()
        let fresh = AVSampleBufferDisplayLayer()
        fresh.videoGravity = .resizeAspectFill
        fresh.frame = bounds
        layer.addSublayer(fresh)
        displayLayer = fresh
    }

    /// Stops rendering. The caller should also unregister the sink via
    /// `setVideoSink(nil, for:)`; this just releases the layer.
    func shutdown() {
        DispatchQueue.main.async { [weak self] in
            self?.displayLayer.flush()
            self?.displayLayer.removeFromSuperlayer()
        }
    }
}
