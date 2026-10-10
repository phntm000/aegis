import Foundation

// MARK: - TransportHub: multiplexes LAN + relay (+ onion, when real)
//
// The hub owns the set of transports and presents one logical pipe to the app:
//   - inbound: merged stream of frames from all transports, deduplicated by
//     envelope ID (a frame arriving over LAN *and* relay is delivered once).
//   - send: policy-driven fan-out across connected transports.
//   - bind: subscribes every capable transport to a mailbox.
//
// Fan-out rationale: envelopes are sealed and idempotent (receivers dedupe),
// so sending over every usable path maximizes delivery probability — LAN when
// you're next to each other, relay when you're not. The cost is duplicate
// bandwidth for large attachments; the app layer should prefer `.preferLAN`
// for multi-MB frames when a LAN peer is connected.

/// Which transports a send should use.
public enum SendPolicy: Sendable {
    /// Every connected transport (default: best delivery odds).
    case allConnected
    /// LAN if any LAN peer is connected, else relay.
    case preferLAN
    /// Relay only (e.g. the peer is known to be remote).
    case relayOnly
    /// LAN only (explicit offline / LAN-only mode).
    case lanOnly
}

public final class TransportHub: Sendable {
    private let transports: [any Transport]
    private let dedupe = EnvelopeDedupe()
    private let inboundBox = Broadcast<AegisFrame>()
    private let fanInTask = BroadcastState<Task<Void, Never>?>(nil)

    public var inbound: AsyncStream<AegisFrame> { inboundBox.stream() }
    public var transportsByID: [String: any Transport] {
        Dictionary(uniqueKeysWithValues: transports.map { ($0.transportID, $0) })
    }

    public init(transports: [any Transport]) {
        self.transports = transports
    }

    public func start() async {
        for transport in transports { await transport.start() }
        let task = Task { [weak self] in
            await withTaskGroup(of: Void.self) { group in
                guard let self else { return }
                for transport in self.transports {
                    group.addTask { [weak self] in
                        for await frame in transport.inbound {
                            guard let self else { return }
                            if await self.dedupe.insert(frame.envelopeID) {
                                self.inboundBox.yield(frame)
                            }
                        }
                    }
                }
            }
        }
        fanInTask.set(task)
    }

    public func stop() async {
        if let task = fanInTask.value { task.cancel(); await task.value }
        fanInTask.set(nil)
        for transport in transports { await transport.stop() }
        inboundBox.finish()
    }

    /// Subscribe all capable transports to a mailbox.
    public func bind(_ mailbox: MailboxID) async {
        for transport in transports {
            if let relay = transport as? RelayTransport {
                await relay.bind(mailbox)
            } else if let lan = transport as? LANTransport {
                lan.bind(mailbox)
            } else if (transport as? any AnonymityTransport) != nil {
                // A real onion transport would bind its relay-over-Tor socket here.
            }
        }
    }

    public func unbind(_ mailbox: MailboxID) async {
        for transport in transports {
            if let relay = transport as? RelayTransport {
                await relay.unbind(mailbox)
            } else if let lan = transport as? LANTransport {
                lan.unbind(mailbox)
            }
        }
    }

    /// Send one sealed frame according to the policy. Succeeds if *any*
    /// selected transport accepted it; throws the last error otherwise.
    public func send(_ frame: AegisFrame, policy: SendPolicy = .allConnected) async throws {
        let targets = selectTargets(for: policy)
        var lastError: Error = TransportError.notConnected
        var sentCount = 0
        for transport in targets {
            do {
                try await transport.send(frame)
                sentCount += 1
            } catch {
                lastError = error
            }
        }
        if sentCount == 0 { throw lastError }
    }

    // MARK: - Selection

    private func selectTargets(for policy: SendPolicy) -> [any Transport] {
        let connected = transports.filter { $0.currentState == .connected }
        func isLAN(_ t: any Transport) -> Bool { t is LANTransport }
        func isRelay(_ t: any Transport) -> Bool { t is RelayTransport }

        switch policy {
        case .allConnected:
            return connected
        case .preferLAN:
            let lan = connected.filter(isLAN)
            return lan.isEmpty ? connected.filter(isRelay) : lan
        case .relayOnly:
            return connected.filter(isRelay)
        case .lanOnly:
            return connected.filter(isLAN)
        }
    }
}

// MARK: - Envelope dedupe

/// Remembers recent envelope IDs so a frame received over two transports is
/// delivered once. Bounded LRU-ish eviction; 20k entries ≈ 320 KB.
private actor EnvelopeDedupe {
    private var seen = Set<Data>()
    private var order: [Data] = []
    private let cap = 20_000

    /// Returns true if this ID is new (caller should deliver the frame).
    func insert(_ id: Data) -> Bool {
        if seen.contains(id) { return false }
        seen.insert(id)
        order.append(id)
        if order.count > cap {
            seen.remove(order.removeFirst())
        }
        return true
    }
}
