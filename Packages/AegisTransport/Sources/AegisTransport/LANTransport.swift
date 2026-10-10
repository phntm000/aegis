import Foundation

// MARK: - LANTransport: genuinely networkless nearby messaging
//
// Uses MultipeerConnectivity (BLE + Wi-Fi Direct/AWDL + infrastructure Wi-Fi)
// with Bonjour/mDNS discovery. Two devices on the same network — or in
// Bluetooth range with no network at all — exchange sealed AegisFrames with
// ZERO internet: no relay, no server, no account, no cell signal.
//
// Frames are broadcast to all connected LAN peers; each receiver filters by
// its bound mailboxes. Envelopes are sealed before they reach this layer, so
// broadcast-to-nearby-peers leaks nothing but (mailbox, length, timing).
//
// Honest limits (see NETWORKING.md for the full table):
//   - Range: ~10 m BLE, ~30–100 m Wi-Fi depending on environment.
//   - Throughput: practically 1–5 Mbps; 5 MB attachments take seconds.
//   - iOS background: discovery/advertising is throttled within ~30–60 s of
//     backgrounding. LAN is a foreground-first transport.
//   - Peer identity: an ephemeral random ID rotated on every start(). There
//     is no stable device fingerprint by design.
//   - Invitations are auto-accepted: link-layer authentication would imply
//     identities, which Aegis refuses to have. MCSession encryption is set
//     to .required as defense-in-depth, but the security model does not
//     depend on it — envelopes are sealed end-to-end above this layer.

#if canImport(MultipeerConnectivity)
import MultipeerConnectivity

public final class LANTransport: NSObject, Transport, @unchecked Sendable {
    public let transportID = "lan"

    /// Bonjour service type. ≤15 chars, lowercase alphanumerics + hyphen.
    private let serviceType = "aegis-lan"

    private let state = BroadcastState<TransportState>(.idle)
    public var currentState: TransportState { state.value }
    public var stateStream: AsyncStream<TransportState> { state.stream() }

    private let inboundBox = Broadcast<AegisFrame>()
    public var inbound: AsyncStream<AegisFrame> { inboundBox.stream() }

    private let lock = NSLock()
    private var session: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var boundMailboxes = Set<MailboxID>()
    private var running = false

    /// Mailboxes this device listens for on the LAN. Frames for other
    /// mailboxes are dropped at the link edge.
    public func bind(_ mailbox: MailboxID) {
        lock.withLock { _ = boundMailboxes.insert(mailbox) }
    }

    public func unbind(_ mailbox: MailboxID) {
        lock.withLock { boundMailboxes.remove(mailbox) }
    }

    // MARK: Transport

    public func start() async {
        let shouldStart = lock.withLock { () -> Bool in
            guard !running else { return false }
            running = true
            return true
        }
        guard shouldStart else { return }

        // Ephemeral peer ID, rotated every start. Never reuse across launches.
        let peerID = MCPeerID(displayName: "aegis-\(String(format: "%08x", UInt32.random(in: 0...UInt32.max)))")
        let session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self
        let advertiser = MCNearbyServiceAdvertiser(
            peer: peerID, discoveryInfo: ["v": "1", "proto": "aegis/1"], serviceType: serviceType
        )
        advertiser.delegate = self
        let browser = MCNearbyServiceBrowser(peer: peerID, serviceType: serviceType)
        browser.delegate = self

        lock.withLock {
            self.session = session
            self.advertiser = advertiser
            self.browser = browser
        }
        state.set(.connecting)
        advertiser.startAdvertisingPeer()
        browser.startBrowsingForPeers()
    }

    public func stop() async {
        let parts = lock.withLock { () -> (MCNearbyServiceAdvertiser?, MCNearbyServiceBrowser?, MCSession?) in
            running = false
            let p = (advertiser, browser, session)
            advertiser = nil; browser = nil; session = nil
            return p
        }
        parts.0?.stopAdvertisingPeer()
        parts.1?.stopBrowsingForPeers()
        parts.2?.disconnect()
        state.set(.idle)
    }

    public func send(_ frame: AegisFrame) async throws {
        let session = lock.withLock { self.session }
        guard let session, !session.connectedPeers.isEmpty else {
            throw TransportError.notConnected
        }
        let data = try frame.encode()
        try session.send(data, toPeers: session.connectedPeers, with: .reliable)
    }
}

// MARK: - MCSessionDelegate

extension LANTransport: MCSessionDelegate {
    public func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        switch state {
        case .connected:
            self.state.set(.connected)
        case .connecting:
            if self.state.value != .connected { self.state.set(.connecting) }
        case .notConnected:
            if session.connectedPeers.isEmpty, self.state.value == .connected {
                self.state.set(.connecting)
            }
        @unknown default:
            break
        }
    }

    public func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        // Decode, then filter by bound mailboxes. Anything malformed or
        // unbound is dropped — nearby attackers can't probe us with junk.
        guard let frame = try? AegisFrame.decode(data) else { return }
        let bound = lock.withLock { boundMailboxes.contains(frame.mailbox) }
        guard bound else { return }
        inboundBox.yield(frame)
    }

    public func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    public func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    public func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
    public func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        // No link-layer identity in Aegis. Accept; envelope sealing is the
        // authentication. MCSession encryption (.required) still applies.
        certificateHandler(true)
    }
}

// MARK: - Advertiser / Browser delegates

extension LANTransport: MCNearbyServiceAdvertiserDelegate {
    public func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        let session = lock.withLock { self.session }
        invitationHandler(session != nil, session)
    }

    public func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
        state.set(.failed)
    }
}

extension LANTransport: MCNearbyServiceBrowserDelegate {
    public func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        guard info?["proto"] == "aegis/1" || info == nil else { return }
        let session = lock.withLock { self.session }
        if let session, !session.connectedPeers.contains(peerID) {
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 20)
        }
    }

    public func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {}

    public func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {
        state.set(.failed)
    }
}

#else

// MARK: - Fallback for platforms without MultipeerConnectivity

/// Compiles on platforms without MultipeerConnectivity (e.g. Linux CI).
/// Every operation fails with `.unsupportedPlatform` — never silently.
public final class LANTransport: Transport, @unchecked Sendable {
    public let transportID = "lan"
    private let state = BroadcastState<TransportState>(.failed)
    public var currentState: TransportState { state.value }
    public var stateStream: AsyncStream<TransportState> { state.stream() }
    private let inboundBox = Broadcast<AegisFrame>()
    public var inbound: AsyncStream<AegisFrame> { inboundBox.stream() }

    public init() {}

    public func bind(_ mailbox: MailboxID) {}
    public func unbind(_ mailbox: MailboxID) {}
    public func start() async {}
    public func stop() async {}

    public func send(_ frame: AegisFrame) async throws {
        throw TransportError.unsupportedPlatform
    }
}

#endif
