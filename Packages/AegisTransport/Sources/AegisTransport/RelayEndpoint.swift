import Foundation

// MARK: - Relay endpoint policy (pure, testable)
//
// Decides *which* relay URL a configuration mode should use and whether a
// user-typed URL is acceptable — without doing any networking. The transports
// (RelayTransport) do the actual connecting; this file is the policy they and
// the app share, so "valid URL" means the same thing everywhere.
//
// Honesty rule: automatic mode NEVER invents an endpoint. It uses a relay URL
// only if one was previously verified (handshake probe or real hello); with
// nothing verified it resolves to nil and the app runs on the local network.

// MARK: Validation

/// Why a user-typed relay URL was rejected. Descriptions are user-facing.
public enum RelayURLValidationError: Error, Sendable, Equatable, CustomStringConvertible {
    case empty
    case unparseable(String)
    case unsupportedScheme(String)
    case cleartextNonLoopback
    case missingHost

    public var description: String {
        switch self {
        case .empty:
            return "Enter a relay URL first."
        case .unparseable(let raw):
            return "“\(raw)” isn't a valid URL."
        case .unsupportedScheme(let scheme):
            return "“\(scheme)://” isn't supported — use wss:// (or https://, which becomes wss://)."
        case .cleartextNonLoopback:
            return "Relay connections must be encrypted (wss://). Unencrypted ws:// is only allowed for local testing (localhost)."
        case .missingHost:
            return "That URL has no host — e.g. wss://relay.example.com."
        }
    }
}

public enum RelayURLValidator {
    /// Hosts where cleartext ws:// is tolerated (local development only).
    public static let loopbackHosts: Set<String> = ["localhost", "127.0.0.1", "::1"]

    /// Normalizes user input into a relay WebSocket URL.
    /// - Trims whitespace.
    /// - Bare hosts ("relay.example.com") become wss://relay.example.com.
    /// - https:// → wss://, http:// → ws:// (then subject to the loopback rule).
    /// - wss:// accepted everywhere; ws:// only for loopback hosts.
    public static func normalize(_ raw: String) -> Result<URL, RelayURLValidationError> {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .failure(.empty) }

        let withScheme = trimmed.contains("://") ? trimmed : "wss://\(trimmed)"
        guard var components = URLComponents(string: withScheme) else {
            return .failure(.unparseable(trimmed))
        }
        let scheme = (components.scheme ?? "").lowercased()
        switch scheme {
        case "wss":
            break
        case "https":
            components.scheme = "wss"
        case "http":
            components.scheme = "ws"
        case "ws":
            break
        default:
            return .failure(.unsupportedScheme(scheme.isEmpty ? "(none)" : scheme))
        }

        guard let host = components.host, !host.isEmpty else {
            return .failure(.missingHost)
        }
        if components.scheme == "ws", !loopbackHosts.contains(host.lowercased()) {
            return .failure(.cleartextNonLoopback)
        }
        guard let url = components.url else {
            return .failure(.unparseable(trimmed))
        }
        return .success(url)
    }
}

// MARK: Resolution

public enum RelayEndpointResolver {
    /// Resolves which relay URL (if any) a mode should connect to.
    ///
    /// - Parameters:
    ///   - mode: a `RelayConfig.Mode` raw value ("automatic", "lanOnly", "customRelay").
    ///   - customURL: the user-configured custom relay URL (customRelay mode).
    ///   - lastKnownGoodURL: a relay URL that previously verified (handshake
    ///     probe or a real protocol hello). The only thing automatic mode will
    ///     fall back to.
    /// - Returns: the URL to connect, or nil for LAN-only operation.
    public static func resolveURL(
        mode: String,
        customURL: String?,
        lastKnownGoodURL: String?
    ) -> URL? {
        switch mode {
        case "customRelay":
            guard let raw = customURL else { return nil }
            return (try? RelayURLValidator.normalize(raw).get())
        case "automatic":
            guard let raw = lastKnownGoodURL else { return nil }
            return (try? RelayURLValidator.normalize(raw).get())
        default:
            return nil
        }
    }
}

// MARK: Health

/// A point-in-time assessment of one relay URL.
public struct RelayHealth: Sendable, Hashable {
    public enum Status: String, Sendable, Hashable {
        /// A probe or connection attempt is in flight.
        case checking
        /// The relay answered a handshake (probe or live hello).
        case reachable
        /// The relay did not answer; the transport keeps retrying in background.
        case unreachable
    }

    public let url: String
    public var status: Status
    public var latencyMs: Int?
    public var lastCheckedAt: Date?
    public var detail: String

    public init(
        url: String,
        status: Status,
        latencyMs: Int? = nil,
        lastCheckedAt: Date? = nil,
        detail: String
    ) {
        self.url = url
        self.status = status
        self.latencyMs = latencyMs
        self.lastCheckedAt = lastCheckedAt
        self.detail = detail
    }
}

/// Result of a one-shot relay handshake probe.
public struct RelayProbeResult: Sendable {
    public let reachable: Bool
    public let latencyMs: Int?
    public let detail: String

    public init(reachable: Bool, latencyMs: Int?, detail: String) {
        self.reachable = reachable
        self.latencyMs = latencyMs
        self.detail = detail
    }
}

// MARK: - One-shot handshake probe

public enum RelayProbe {
    /// Opens a transient WebSocket, sends the protocol ping (the same opening
    /// move `RelayTransport` makes), waits for the server's hello — proof it
    /// speaks our protocol — then tears everything down. Never touches the
    /// live transport, so it is safe for URL validation and periodic health
    /// checks.
    ///
    /// Implementation note: the watcher task cannot be cancelled out of a
    /// suspended `URLSessionWebSocketTask.receive()` via task cancellation
    /// alone, so the timeout arm cancels the *socket*, which forces
    /// `receive()` to throw and lets the task group finish. No leaked tasks.
    ///
    /// The probe does not do certificate pinning — it only asserts protocol
    /// reachability. The live `RelayTransport` owns authenticated/pinned
    /// connections.
    public static func handshake(url: URL, timeout: TimeInterval = 15) async -> RelayProbeResult {
        let session = URLSession(configuration: .default)
        let socket = session.webSocketTask(with: url)
        socket.resume()
        let start = Date()
        // URLSessionTask is thread-safe per Apple, but not formally Sendable;
        // box it for the @Sendable group tasks.
        final class SocketBox: @unchecked Sendable {
            let socket: URLSessionWebSocketTask
            init(_ socket: URLSessionWebSocketTask) { self.socket = socket }
        }
        let box = SocketBox(socket)

        let outcome: RelayProbeResult = await withTaskGroup(of: RelayProbeResult?.self) { group in
            group.addTask {
                do {
                    try await box.socket.send(.string(RelayClientOp.ping.encode()))
                    let deadline = Date().addingTimeInterval(timeout)
                    while Date() < deadline {
                        let message = try await box.socket.receive()
                        guard case .string(let text) = message else { continue }
                        if case .hello = RelayServerMessage.parse(text) {
                            let ms = Int(Date().timeIntervalSince(start) * 1000)
                            return RelayProbeResult(
                                reachable: true,
                                latencyMs: ms,
                                detail: "Relay handshake OK"
                            )
                        }
                        // acks/pongs/etc. are not the handshake; keep waiting.
                    }
                    return RelayProbeResult(
                        reachable: false,
                        latencyMs: nil,
                        detail: "No handshake from relay (\(Int(timeout))s timeout)"
                    )
                } catch {
                    return RelayProbeResult(
                        reachable: false,
                        latencyMs: nil,
                        detail: "Connection failed: \(error.localizedDescription)"
                    )
                }
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                // Force any suspended receive() to throw so the watcher ends.
                box.socket.cancel(with: .goingAway, reason: nil)
                return RelayProbeResult(
                    reachable: false,
                    latencyMs: nil,
                    detail: "No handshake from relay (\(Int(timeout))s timeout)"
                )
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            // If the watcher won, the socket is still open: close it so the
            // cancelled timeout task cannot linger on a live socket.
            box.socket.cancel(with: .goingAway, reason: nil)
            return first ?? RelayProbeResult(
                reachable: false,
                latencyMs: nil,
                detail: "Probe ended without a handshake"
            )
        }
        session.finishTasksAndInvalidate()
        return outcome
    }
}
