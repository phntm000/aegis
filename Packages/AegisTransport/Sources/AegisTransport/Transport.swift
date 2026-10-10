import Foundation

// MARK: - Transport abstraction
//
// A Transport moves sealed, opaque frames between this device and anonymous
// destinations. It knows nothing about identities, plaintext, or conversation
// semantics — those live in AegisCrypto and the app layer. The network is
// assumed hostile: every transport below treats the medium as untrusted.

/// Connectivity state of a single transport.
public enum TransportState: String, Sendable, Equatable {
    case idle        // never started, or stopped
    case connecting  // dialing / discovering
    case connected   // usable now
    case suspended   // OS backgrounded us; will resume when foregrounded
    case failed      // backing off before the next attempt
}

/// Errors a transport can surface. Never leaks peer identity or content.
public enum TransportError: Error, Sendable, Equatable {
    case notConnected
    case unsupportedPlatform
    case frameTooLarge(Int)
    case malformedFrame
    case rateLimited
    case unauthorized
    case timeout
    case underlying(String)
}

/// An opaque, unlinkable destination: 32 bytes chosen by the crypto layer
/// (per conversation, per epoch). The transport treats it as a routing label
/// only — it carries no identity semantics and must never be logged.
public struct MailboxID: Hashable, Sendable, Codable, CustomStringConvertible {
    public let bytes: Data

    public init(_ bytes: Data) {
        precondition(bytes.count == 32, "MailboxID must be 32 bytes")
        self.bytes = bytes
    }

    public init?(hex: String) {
        guard hex.count == 64 else { return nil }
        var data = Data(capacity: 32)
        var index = hex.startIndex
        for _ in 0..<32 {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self.bytes = data
    }

    /// Lowercase hex, the canonical form used on the wire control channel.
    public var hex: String { bytes.map { String(format: "%02x", $0) }.joined() }

    /// Redacted for logs: never print a full mailbox ID.
    public var description: String { "mailbox:" + hex.prefix(12) + "…" }
}

/// A transport moves sealed frames. Implementations: LAN (Multipeer),
/// Relay (WebSocket to a dumb relay), Onion (anonymity seam).
public protocol Transport: AnyObject, Sendable {
    /// Stable identifier, e.g. "lan", "relay:wss://relay.example".
    var transportID: String { get }

    /// Latest connectivity state (synchronous read).
    var currentState: TransportState { get }

    /// Emits the current state immediately, then every change.
    var stateStream: AsyncStream<TransportState> { get }

    /// Sealed frames arriving over this transport.
    var inbound: AsyncStream<AegisFrame> { get }

    func start() async
    func stop() async

    /// Best-effort send of one sealed frame. Throws `TransportError`.
    /// Delivery is at-least-once at the app layer via envelope IDs;
    /// transports may duplicate or drop under failure.
    func send(_ frame: AegisFrame) async throws
}

// MARK: - Broadcast helpers

/// Thread-safe broadcast of values to any number of AsyncStream subscribers.
final class BroadcastState<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [UUID: AsyncStream<Value>.Continuation] = [:]
    private var current: Value

    init(_ initial: Value) { self.current = initial }

    var value: Value { lock.withLock { current } }

    func set(_ newValue: Value) {
        lock.withLock {
            current = newValue
            for cont in continuations.values { cont.yield(newValue) }
        }
    }

    func stream() -> AsyncStream<Value> {
        AsyncStream { [weak self] continuation in
            guard let self else { continuation.finish(); return }
            let id = UUID()
            self.lock.withLock {
                self.continuations[id] = continuation
                continuation.yield(self.current)
            }
            continuation.onTermination = { [weak self] _ in
                _ = self?.lock.withLock { self?.continuations.removeValue(forKey: id) }
            }
        }
    }
}

/// Broadcast without an initial value (for event/firehose streams).
final class Broadcast<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [UUID: AsyncStream<Value>.Continuation] = [:]

    func yield(_ value: Value) {
        lock.withLock { for cont in continuations.values { cont.yield(value) } }
    }

    func stream() -> AsyncStream<Value> {
        AsyncStream { [weak self] continuation in
            guard let self else { continuation.finish(); return }
            let id = UUID()
            self.lock.withLock { self.continuations[id] = continuation }
            continuation.onTermination = { [weak self] _ in
                _ = self?.lock.withLock { self?.continuations.removeValue(forKey: id) }
            }
        }
    }

    func finish() {
        lock.withLock {
            for cont in continuations.values { cont.finish() }
            continuations.removeAll()
        }
    }
}
