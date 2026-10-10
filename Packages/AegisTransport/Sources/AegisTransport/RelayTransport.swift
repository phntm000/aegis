import Foundation
import CryptoKit
import Security

// MARK: - RelayTransport: WebSocket client for the dumb relay
//
// Speaks the framed protocol in RelayWire.swift to relay.py (or any compatible
// dumb relay). Automatic reconnect with exponential backoff + jitter, WebSocket
// ping keepalive, re-bind of mailboxes after every reconnect, optional
// certificate-hash pinning.
//
// Background reality (documented honestly in NETWORKING.md): iOS suspends the
// socket when the app backgrounds. This transport reconnects aggressively on
// foreground and the relay holds envelopes for up to the TTL, so nothing is
// lost — but sub-minute background delivery needs push infrastructure that
// Aegis deliberately does not require.

/// Diagnostic events from the relay connection (no identities, no content).
public enum RelayEvent: Sendable {
    case hello(maxPayload: Int, ttlDefault: UInt32)
    case acknowledged(envelopeID: Data)
    case drained(mailbox: MailboxID)
    case serverError(code: String)
}

public final class RelayTransport: NSObject, Transport, @unchecked Sendable {
    public let transportID: String

    private let url: URL
    private let authToken: String?
    /// SHA-256 of the relay's leaf certificate DER. When set, the TLS
    /// handshake is pinned to this hash; anything else fails closed.
    private let pinnedCertificateSHA256: Data?

    private let state = BroadcastState<TransportState>(.idle)
    public var currentState: TransportState { state.value }
    public var stateStream: AsyncStream<TransportState> { state.stream() }

    private let inboundBox = Broadcast<AegisFrame>()
    public var inbound: AsyncStream<AegisFrame> { inboundBox.stream() }

    private let eventsBox = Broadcast<RelayEvent>()
    public var events: AsyncStream<RelayEvent> { eventsBox.stream() }

    private let lock = NSLock()
    private var session: URLSession!
    private var socket: URLSessionWebSocketTask?
    private var runTask: Task<Void, Never>?
    private var pingTask: Task<Void, Never>?
    private var boundMailboxes = Set<MailboxID>()
    private var connectedAt: Date?

    /// - Parameters:
    ///   - url: `wss://` URL of the relay. Plain `ws://` is accepted only for
    ///     loopback (development); anything else fails closed.
    ///   - authToken: relay operator token, if the relay requires one.
    ///   - pinnedCertificateSHA256: 32-byte SHA-256 of the relay's leaf
    ///     certificate DER. Strongly recommended for any relay you don't
    ///     operate — see SELF_HOSTING.md for how to obtain it.
    public init(url: URL, authToken: String? = nil, pinnedCertificateSHA256: Data? = nil) {
        self.url = url
        self.authToken = authToken
        self.pinnedCertificateSHA256 = pinnedCertificateSHA256
        self.transportID = "relay:\(url.host ?? url.absoluteString)"
        super.init()
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    // MARK: Transport

    public func start() async {
        let shouldStart = lock.withLock { () -> Bool in
            guard runTask == nil else { return false }
            runTask = Task { [weak self] in await self?.runLoop() }
            return true
        }
        if shouldStart { state.set(.connecting) }
    }

    public func stop() async {
        let task: Task<Void, Never>? = lock.withLock {
            let t = runTask; runTask = nil; return t
        }
        task?.cancel()
        if let task { await task.value }
        lock.withLock { socket?.cancel(with: .goingAway, reason: nil); socket = nil }
        stopPing()
        state.set(.idle)
    }

    public func send(_ frame: AegisFrame) async throws {
        let ws = lock.withLock { socket }
        guard let ws, state.value == .connected else { throw TransportError.notConnected }
        let data = try frame.encode()
        try await ws.send(.data(data))
    }

    /// Subscribe this connection to a mailbox. The relay drains anything
    /// queued, then streams live envelopes until `unbind`.
    public func bind(_ mailbox: MailboxID) async {
        lock.withLock { _ = boundMailboxes.insert(mailbox) }
        if state.value == .connected, let ws = lock.withLock({ socket }) {
            try? await ws.send(.string(RelayClientOp.bind(mailbox).encode()))
        }
    }

    public func unbind(_ mailbox: MailboxID) async {
        lock.withLock { boundMailboxes.remove(mailbox) }
        if state.value == .connected, let ws = lock.withLock({ socket }) {
            try? await ws.send(.string(RelayClientOp.unbind(mailbox).encode()))
        }
    }

    // MARK: Connection loop

    private func runLoop() async {
        var backoff: TimeInterval = 1
        while !Task.isCancelled {
            state.set(.connecting)
            do {
                try await connectOnce()
                // connectOnce only returns when the socket died.
                let uptime = connectedAt.map { Date().timeIntervalSince($0) } ?? 0
                backoff = uptime > 30 ? 1 : min(backoff * 2, 60)
            } catch {
                backoff = min(backoff * 2, 60)
            }
            guard !Task.isCancelled else { break }
            state.set(.failed)
            let jitter = 0.8 + 0.4 * Double.random(in: 0...1)
            try? await Task.sleep(nanoseconds: UInt64(backoff * jitter * 1_000_000_000))
            backoff = min(backoff * 2, 60)
        }
    }

    private func connectOnce() async throws {
        // Fail closed on cleartext to non-loopback hosts.
        if url.scheme == "ws",
           let host = url.host, host != "localhost", host != "127.0.0.1", host != "::1"
        {
            throw TransportError.underlying("refusing cleartext relay for non-loopback host")
        }

        let ws = session.webSocketTask(with: url)
        lock.withLock { socket = ws }
        ws.resume()

        do {
            // First send triggers the handshake; bound it so a black-holed
            // relay can't hang us forever.
            try await withTimeout(seconds: 15) {
                if let token = self.authToken {
                    try await ws.send(.string(RelayClientOp.auth(token: token).encode()))
                } else {
                    try await ws.send(.string(RelayClientOp.ping.encode()))
                }
                let bound = self.lock.withLock { self.boundMailboxes }
                for mailbox in bound {
                    try await ws.send(.string(RelayClientOp.bind(mailbox).encode()))
                }
            }
        } catch {
            ws.cancel()
            throw error
        }

        connectedAt = Date()
        state.set(.connected)
        startPing(on: ws)
        defer {
            stopPing()
            lock.withLock { if socket === ws { socket = nil } }
        }

        while !Task.isCancelled {
            let message = try await ws.receive()
            switch message {
            case .data(let data):
                if let frame = try? AegisFrame.decode(data) {
                    inboundBox.yield(frame)
                }
                // Malformed binaries are dropped silently: the relay is
                // untrusted and must not be able to probe us with junk.
            case .string(let text):
                handleServerMessage(text)
            @unknown default:
                break
            }
        }
    }

    private func handleServerMessage(_ text: String) {
        switch RelayServerMessage.parse(text) {
        case .hello(let maxPayload, let ttlDefault, _, _):
            eventsBox.yield(.hello(maxPayload: maxPayload, ttlDefault: ttlDefault))
        case .ack(let hex):
            if let data = Data(hexString: hex) { eventsBox.yield(.acknowledged(envelopeID: data)) }
        case .drained(let hex):
            if let mailbox = MailboxID(hex: hex) { eventsBox.yield(.drained(mailbox: mailbox)) }
        case .error(let code):
            eventsBox.yield(.serverError(code: code))
        case .pong, .unknown:
            break
        }
    }

    // MARK: Keepalive

    private func startPing(on ws: URLSessionWebSocketTask) {
        stopPing()
        pingTask = Task { [weak self, weak ws] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 25_000_000_000)
                guard !Task.isCancelled, let ws else { return }
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    ws.sendPing { error in
                        if error != nil { ws.cancel() } // receive() throws → reconnect
                        cont.resume()
                    }
                }
                _ = self
            }
        }
    }

    private func stopPing() {
        let t = lock.withLock { () -> Task<Void, Never>? in
            let p = pingTask; pingTask = nil; return p
        }
        t?.cancel()
    }
}

// MARK: - Certificate pinning (TLS)

extension RelayTransport: URLSessionDelegate {
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard let pin = pinnedCertificateSHA256,
              let trust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(trust, 0)
        else {
            // No pin configured: default system trust. Operators and users
            // are strongly encouraged to set a pin (see SELF_HOSTING.md).
            return (.performDefaultHandling, nil)
        }
        let certData = SecCertificateCopyData(certificate) as Data
        let digest = Data(SHA256.hash(data: certData))
        // Constant-time compare would be theater here (network attacker
        // already knows which hash we expect); a plain compare is fine.
        if digest == pin, SecTrustGetCertificateCount(trust) > 0 {
            return (.useCredential, URLCredential(trust: trust))
        }
        return (.cancelAuthenticationChallenge, nil)
    }
}

// MARK: - Helpers

private func withTimeout<T: Sendable>(seconds: TimeInterval, operation: @Sendable @escaping () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TransportError.timeout
        }
        guard let result = try await group.next() else { throw TransportError.timeout }
        group.cancelAll()
        return result
    }
}

private extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
