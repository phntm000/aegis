/// WebRTCBridge — SwiftPM access to the WebRTC native framework.
///
/// `import WebRTCBridge` gives the app's media layer the full Google WebRTC
/// ObjC API (`RTCPeerConnection`, `RTCAudioSession`,
/// `RTCCameraVideoCapturer`, …), re-exported from the pinned binary target
/// below so app targets need only this one import. This target also adds
/// small pure-Swift helpers that don't need the native framework to compile
/// or test:
///
/// - `SDPFingerprint` — extracts the DTLS certificate fingerprint from SDP,
///   which the signaling layer exchanges so both parties can run the SAS
///   verification ceremony on the *media* keys.
///
/// The binary itself is fetched at build time from the pinned release in
/// `Package.swift` (checksum-verified by SwiftPM); nothing native is
/// committed to this repo.
@_exported import WebRTC

public enum WebRTCBridge {
    /// The pinned upstream WebRTC milestone this package resolves to.
    public static let upstreamMilestone = "M154"
}
