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

    func renderRemoteFrame(_ sampleBuffer: CMSampleBuffer, forCall callID: UUID) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if self.displayLayer.status == .failed {
                // A failed layer never recovers; rebuild it so video
                // resumes with the next frame instead of staying black.
                self.rebuildDisplayLayer()
            }
            guard self.displayLayer.isReadyForMoreMediaData else { return }
            self.displayLayer.enqueue(sampleBuffer)
        }
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
