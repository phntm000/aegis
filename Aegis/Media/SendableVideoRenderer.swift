import Foundation
import WebRTCBridge

/// A video-renderer reference that may cross Swift concurrency domains.
///
/// Why this exists: `RTCVideoRenderer` is an Objective-C protocol and therefore
/// not `Sendable`, but the local-preview attach path has to carry the
/// renderer from the UI (main thread) through `AppState` into the WebRTC
/// engine, which crosses actor isolations. Swift 6 treats the argument as
/// `sending` and rejects the raw protocol type.
///
/// The `unchecked` is honest about where thread-safety comes from: WebRTC's
/// own API contract. A renderer added to a track receives `renderFrame:`
/// on WebRTC's internal threads by design — this is true in every WebRTC
/// iOS sample app, and the engine's `RemoteFrameRenderer` already carries
/// the same `@unchecked Sendable` for the same reason. Before the renderer
/// is handed to the engine, the box is only ever touched on the main
/// thread (it is created in the SwiftUI view hierarchy). The box must not
/// be used to smuggle any other threading assumptions.
struct SendableVideoRenderer: @unchecked Sendable {
    let renderer: RTCVideoRenderer
}
