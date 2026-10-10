import Foundation

// MARK: - OnionTransport: the anonymity seam (interface only)
//
// This file is deliberately NOT an implementation. Shipping a fake "Tor mode"
// that isn't actually Tor would be worse than no Tor mode at all — it would
// lie to users about their anonymity. So this file defines the seam a real
// anonymity transport plugs into, and documents exactly how.
//
// How a real implementation slots in:
//   1. Embed a Tor client on-device. The realistic 2026 path on iOS is Arti
//      (the Rust Tor implementation) compiled as a static library and exposed
//      over a local SOCKS5 / Arti RPC interface. There is no supported way to
//      run the C tor daemon inside an iOS app sandbox.
//   2. Implement `AnonymityTransport`: open the relay WebSocket *through* a
//      Tor circuit (the relay then sees only the exit node's IP), or run the
//      relay itself as a Tor onion service (then nobody sees any IP).
//   3. The framing is identical — AegisFrame bytes are transport-agnostic —
//      so the rest of the app (hub, crypto, UI) changes not at all.
//   4. Set `isolateCircuitsPerMailbox = true` so each conversation's mailbox
//      gets its own circuit; otherwise the relay (or a network observer)
//      can correlate mailboxes by shared circuit.
//   5. Expect costs: +1–3 s handshake latency, higher battery use, and
//      Apple may throttle background circuits aggressively. Anonymity is a
//      tradeoff, not a free upgrade — the UI must say so.
//
// Until an implementation exists, `UnavailableOnionTransport` is what the app
// wires in: it reports `.unsupportedPlatform`-style errors instead of
// pretending.

/// Circuit lifecycle for an anonymity transport.
public enum OnionCircuitState: Sendable, Equatable {
    case noCircuit
    case bootstrapping(progress: Double) // 0.0 … 1.0
    case ready
    case failed(String)
}

public struct OnionTransportConfig: Sendable {
    /// Local SOCKS5 port where the on-device Tor client listens.
    public var socksPort: Int
    /// One circuit per mailbox (prevents cross-conversation correlation).
    public var isolateCircuitsPerMailbox: Bool
    /// Prefer onion service over exit-node routing when the relay offers one.
    public var preferOnionService: Bool

    public init(socksPort: Int = 19050, isolateCircuitsPerMailbox: Bool = true, preferOnionService: Bool = true) {
        self.socksPort = socksPort
        self.isolateCircuitsPerMailbox = isolateCircuitsPerMailbox
        self.preferOnionService = preferOnionService
    }
}

/// A transport that additionally hides *network-level* metadata (IP
/// addresses, coarse location) from the relay and observers.
public protocol AnonymityTransport: Transport {
    var circuitState: AsyncStream<OnionCircuitState> { get }
    var currentCircuitState: OnionCircuitState { get }
}

/// Placeholder wired into the app until a real Tor-backed implementation
/// exists. Fails loudly; never pretends to anonymize.
public final class UnavailableOnionTransport: AnonymityTransport, @unchecked Sendable {
    public let transportID = "onion:unavailable"

    private let state = BroadcastState<TransportState>(.failed)
    public var currentState: TransportState { state.value }
    public var stateStream: AsyncStream<TransportState> { state.stream() }

    private let circuit = BroadcastState<OnionCircuitState>(.failed("no Tor client embedded in this build"))
    public var currentCircuitState: OnionCircuitState { circuit.value }
    public var circuitState: AsyncStream<OnionCircuitState> { circuit.stream() }

    private let inboundBox = Broadcast<AegisFrame>()
    public var inbound: AsyncStream<AegisFrame> { inboundBox.stream() }

    public let config: OnionTransportConfig
    public init(config: OnionTransportConfig = OnionTransportConfig()) {
        self.config = config
    }

    public func start() async {}
    public func stop() async {}

    public func send(_ frame: AegisFrame) async throws {
        throw TransportError.underlying("Onion transport not available: embed an Arti-based Tor client and implement AnonymityTransport")
    }
}
