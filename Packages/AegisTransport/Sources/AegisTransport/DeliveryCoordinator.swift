import Foundation
#if os(iOS) && canImport(BackgroundTasks)
import BackgroundTasks
#endif
#if canImport(UserNotifications)
import UserNotifications
#endif
#if canImport(CoreLocation)
import CoreLocation
#endif

// MARK: - DeliveryCoordinator: free delivery without APNs
//
// Aegis never registers an APNs device token — Apple never learns who uses
// Aegis or when their messages arrive. The price is that iOS will not wake
// the app on incoming data. This coordinator implements the honest,
// App-Store-legal alternative:
//
//   Tier 1 — app open or LAN-nearby: true real-time. WebSocket relay or
//            Multipeer frames arrive in ~seconds and are delivered instantly.
//   Tier 2 — app closed: async store-and-forward. The relay holds sealed
//            envelopes until their TTL; iOS wakes the app opportunistically
//            (BGAppRefreshTask, significant location changes) and the
//            coordinator drains bound mailboxes, then the *app* posts LOCAL
//            notifications for anything worth interrupting the user.
//   Tier 3 — calls without push: sealed "knock" envelopes (see
//            AegisFrame.flagKnock) + rendezvous. The caller sends a knock
//            with a short TTL; the callee's next wake fires a local
//            notification ("tap to join"); scheduled calls additionally get
//            exact-time local reminders. On LAN, knocking rings in real time.
//
// What this coordinator deliberately does NOT do (see NETWORKING.md):
//   - silent-audio background keepalive (App Store rejection + battery fraud)
//   - VoIP push / any APNs usage (needs a paid developer account)
//   - fake "push" via polling a helper server every N seconds in background
//     (iOS suspends it; pretending otherwise is duct tape)
//
// Layering contract: the coordinator detects knock-flagged *frames*; it can
// never read them. On `.knockReceived` the app MUST decrypt and verify the
// payload through AegisCrypto before ringing — the knock bit is a hint, not
// authentication. The app then builds the notification content (it alone
// knows names and conversation titles) and hands it back via
// `postLocalNotification(_:)`.

/// Delivery quality the UI can show per conversation.
public enum DeliveryMode: String, Sendable, CaseIterable {
    /// Relay socket (or nearby LAN peer) is up: seconds.
    case live
    /// Reachable over LAN right now: sub-second, no internet.
    case lan
    /// Background: OS-scheduled wakes drain the dead drop; minutes.
    case polling
    /// No usable transport; outbound queues until reconnect.
    case offline

    /// Short user-facing label. The app owns copy; this is a sane default.
    public var label: String {
        switch self {
        case .live: return "Live"
        case .lan: return "Nearby"
        case .polling: return "Checking periodically"
        case .offline: return "Offline"
        }
    }
}

/// Events the app layer acts on. None carry identities or plaintext.
public enum DeliveryEvent: Sendable {
    case modeChanged(DeliveryMode)
    /// A knock-flagged frame arrived. Decrypt + verify before notifying.
    case knockReceived(frame: AegisFrame)
    /// A background drain finished.
    case messagesDrained(mailbox: MailboxID, newFrames: Int)
}

/// Content for a local notification, filled in by the app *after* it has
/// decrypted and verified the underlying envelope.
public struct LocalNotificationContent: Sendable {
    public var identifier: String
    public var title: String
    public var body: String
    /// Conversation/thread grouping, e.g. a conversation ID.
    public var threadIdentifier: String
    public var userInfo: [String: String]
    /// Seconds from now; 0 = immediately.
    public var delay: TimeInterval

    public init(
        identifier: String = UUID().uuidString,
        title: String, body: String,
        threadIdentifier: String = "",
        userInfo: [String: String] = [:],
        delay: TimeInterval = 0
    ) {
        self.identifier = identifier
        self.title = title
        self.body = body
        self.threadIdentifier = threadIdentifier
        self.userInfo = userInfo
        self.delay = delay
    }
}

public struct DeliveryConfiguration: Sendable {
    /// BGTaskScheduler identifier. Must ALSO be listed in the app's
    /// Info.plist under `BGTaskSchedulerPermittedIdentifiers`.
    public static let refreshTaskIdentifier = "com.aegis.delivery.refresh"

    /// Poll cadence while conversation is active (a frame arrived recently).
    public var activePollInterval: TimeInterval = 5 * 60
    /// Poll cadence while quiet.
    public var quietPollInterval: TimeInterval = 30 * 60
    /// "Active" means a frame arrived within this window.
    public var activityWindow: TimeInterval = 15 * 60
    /// Max seconds a background drain may spend waiting for the relay.
    public var drainTimeout: TimeInterval = 20
    /// Opt-in: drain the dead drop on significant location changes.
    /// Requires "Always" location permission + Info.plist usage strings.
    public var enableLocationWakes: Bool = false

    public init() {}
}

public final class DeliveryCoordinator: NSObject, @unchecked Sendable {
    private let hub: TransportHub
    private let lan: LANTransport?
    private let relay: RelayTransport?
    private let configuration: DeliveryConfiguration

    private let eventsBox = Broadcast<DeliveryEvent>()
    public var events: AsyncStream<DeliveryEvent> { eventsBox.stream() }

    private let lock = NSLock()
    private var trackedMailboxes = Set<MailboxID>()
    private var backgrounded = false
    private var lastInboundAt: Date?
    private var lastLANSeen: [MailboxID: Date] = [:]
    private var lastMode: DeliveryMode = .offline
    private var knockDedupe = Set<Data>()
    private var knockDedupeOrder: [Data] = []
    private var framesReceived: Int = 0

    private var consumeTask: Task<Void, Never>?
    private var watchTask: Task<Void, Never>?
    #if canImport(CoreLocation)
    private var locationManager: CLLocationManager?
    #endif

    public init(
        hub: TransportHub,
        lan: LANTransport? = nil,
        relay: RelayTransport? = nil,
        configuration: DeliveryConfiguration = DeliveryConfiguration()
    ) {
        self.hub = hub
        self.lan = lan
        self.relay = relay
        self.configuration = configuration
        super.init()
    }

    // MARK: Lifecycle

    /// Call once at app launch (foreground). Starts frame consumption and
    /// transport-state watching. Does NOT start the transports themselves —
    /// the app owns `hub.start()` / `hub.stop()`.
    public func start() {
        // Per-transport streams give LAN attribution for the per-conversation
        // mode heuristic; with hub only, the merged stream still feeds knock
        // detection (without LAN attribution).
        let lanInbound: AsyncStream<AegisFrame>? = lan?.inbound
        let relayInbound: AsyncStream<AegisFrame>? = relay?.inbound
        let hubInbound: AsyncStream<AegisFrame>? =
            (lanInbound == nil && relayInbound == nil) ? hub.inbound : nil
        let task = Task { [weak self] in
            await withTaskGroup(of: Void.self) { group in
                if let lanInbound {
                    group.addTask { [weak self] in
                        for await frame in lanInbound { self?.handleFrame(frame, viaLAN: true) }
                    }
                }
                if let relayInbound {
                    group.addTask { [weak self] in
                        for await frame in relayInbound { self?.handleFrame(frame, viaLAN: false) }
                    }
                }
                if let hubInbound {
                    group.addTask { [weak self] in
                        for await frame in hubInbound { self?.handleFrame(frame, viaLAN: false) }
                    }
                }
            }
        }
        let watch = Task { [weak self] in
            guard let self else { return }
            await withTaskGroup(of: Void.self) { group in
                for transport in [self.lan as (any Transport)?, self.relay as (any Transport)?].compactMap({ $0 }) {
                    group.addTask { [weak self] in
                        for await _ in transport.stateStream { self?.recomputeMode() }
                    }
                }
            }
        }
        // Task creation has no suspension points, so check-and-set is atomic.
        let shouldKeep = lock.withLock { () -> Bool in
            guard consumeTask == nil else { return false }
            consumeTask = task
            watchTask = watch
            return true
        }
        if !shouldKeep { task.cancel(); watch.cancel(); return }
        recomputeMode()
    }

    public func stop() {
        let tasks = lock.withLock { () -> [Task<Void, Never>] in
            let t = [consumeTask, watchTask].compactMap { $0 }
            consumeTask = nil; watchTask = nil
            return t
        }
        for task in tasks { task.cancel() }
        #if canImport(CoreLocation)
        locationManager?.stopMonitoringSignificantLocationChanges()
        locationManager = nil
        #endif
    }

    /// Mailboxes the coordinator keeps bound and drains on wakes.
    public func trackMailbox(_ mailbox: MailboxID) {
        lock.withLock { _ = trackedMailboxes.insert(mailbox) }
        Task { await self.hub.bind(mailbox) }
    }

    public func untrackMailbox(_ mailbox: MailboxID) {
        lock.withLock { trackedMailboxes.remove(mailbox) }
        Task { await self.hub.unbind(mailbox) }
    }

    /// The app calls these from its scene/session lifecycle.
    public func noteForeground() {
        lock.withLock { backgrounded = false }
        recomputeMode()
    }

    public func noteBackground() {
        lock.withLock { backgrounded = true }
        recomputeMode()
        #if os(iOS) && canImport(BackgroundTasks)
        scheduleBackgroundRefresh()
        #endif
    }

    // MARK: Delivery mode

    /// Global mode for the status UI.
    public func currentMode() -> DeliveryMode {
        if lan?.currentState == .connected { return .lan }
        if relay?.currentState == .connected { return .live }
        if lock.withLock({ backgrounded }) { return .polling }
        return .offline
    }

    /// Per-conversation indicator for the UI. Heuristic, documented as such:
    /// `.lan` requires having *heard* this mailbox over LAN recently — a
    /// connected LAN session alone doesn't prove the peer is still near.
    public func deliveryMode(for mailbox: MailboxID) -> DeliveryMode {
        let mode = currentMode()
        if mode == .lan {
            let recent = lock.withLock { lastLANSeen[mailbox] }
            if let recent, Date().timeIntervalSince(recent) < 120 { return .lan }
            if relay?.currentState == .connected { return .live }
            return .polling
        }
        return mode
    }

    private func recomputeMode() {
        let mode = currentMode()
        let changed = lock.withLock { () -> Bool in
            guard mode != lastMode else { return false }
            lastMode = mode
            return true
        }
        if changed { eventsBox.yield(.modeChanged(mode)) }
    }

    // MARK: Frame handling

    private func handleFrame(_ frame: AegisFrame, viaLAN: Bool) {
        let isNewKnock = lock.withLock { () -> Bool in
            framesReceived += 1
            lastInboundAt = Date()
            if viaLAN { lastLANSeen[frame.mailbox] = Date() }
            guard frame.isKnock else { return false }
            // Knock dedupe: the same knock routinely arrives via LAN *and*
            // relay. Ring once.
            if knockDedupe.contains(frame.envelopeID) { return false }
            knockDedupe.insert(frame.envelopeID)
            knockDedupeOrder.append(frame.envelopeID)
            if knockDedupeOrder.count > 5_000 {
                knockDedupe.remove(knockDedupeOrder.removeFirst())
            }
            return true
        }
        if isNewKnock {
            // The app decrypts + verifies via AegisCrypto, then notifies.
            // The flag is unauthenticated — never ring on the flag alone.
            eventsBox.yield(.knockReceived(frame: frame))
        }
    }

    // MARK: Background refresh (BGAppRefreshTask)

    #if os(iOS) && canImport(BackgroundTasks)
    /// Call once at launch, before `scheduleBackgroundRefresh()`.
    /// Also add the identifier to Info.plist `BGTaskSchedulerPermittedIdentifiers`.
    public func registerBackgroundTasks() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: DeliveryConfiguration.refreshTaskIdentifier,
            using: nil
        ) { [weak self] task in
            Task { await self?.handleBackgroundRefresh(task: task) }
        }
    }

    /// Queue the next opportunistic wake. iOS decides the real fire time —
    /// treat `earliestBeginDate` as a wish, not an appointment. (Honest:
    /// expect minutes-to-an-hour cadence, longer in Low Power Mode.)
    public func scheduleBackgroundRefresh() {
        let interval: TimeInterval = lock.withLock {
            if let last = lastInboundAt, Date().timeIntervalSince(last) < configuration.activityWindow {
                return configuration.activePollInterval
            }
            return configuration.quietPollInterval
        }
        let request = BGAppRefreshTaskRequest(identifier: DeliveryConfiguration.refreshTaskIdentifier)
        request.earliestBeginDate = Date().addingTimeInterval(interval)
        try? BGTaskScheduler.shared.submit(request)
    }

    /// Entry point the app calls from its BGTaskScheduler handler, or call
    /// `registerBackgroundTasks()` and let the coordinator own it.
    public func handleBackgroundRefresh(task: BGTask) async {
        // Schedule the next wake FIRST — if we're killed mid-drain, the
        // next wake is already queued.
        scheduleBackgroundRefresh()
        guard let refresh = task as? BGAppRefreshTask else {
            task.setTaskCompleted(success: false)
            return
        }
        let completed = Locked(false)
        refresh.expirationHandler = { [weak self] in
            // If the OS kills us, don't lie about success.
            if !completed.value { refresh.setTaskCompleted(success: false) }
            self?.scheduleBackgroundRefresh()
        }
        let result = await drainOnce()
        for (mailbox, count) in result.perMailbox where count > 0 {
            eventsBox.yield(.messagesDrained(mailbox: mailbox, newFrames: count))
        }
        completed.value = true
        refresh.setTaskCompleted(success: true)
    }
    #endif

    /// Result of one dead-drop drain.
    public struct DrainResult: Sendable {
        public var perMailbox: [MailboxID: Int]
        public var knocks: Int
        public var timedOut: Bool
    }

    /// Connect the relay briefly, collect everything queued for tracked
    /// mailboxes, then disconnect if we connected just for this drain.
    /// Must be called from a background task (or foreground pull-to-refresh).
    public func drainOnce() async -> DrainResult {
        guard let relay else { return DrainResult(perMailbox: [:], knocks: 0, timedOut: false) }
        let tracked = lock.withLock { trackedMailboxes }
        let baseline = lock.withLock { framesReceived }
        let knockBaseline = lock.withLock { knockDedupeOrder.count }

        let startedHere = relay.currentState != .connected && relay.currentState != .connecting
        if startedHere { await relay.start() }
        for mailbox in tracked { await relay.bind(mailbox) }

        // Wait for the relay's per-mailbox drain confirmations, or timeout.
        // (The consume task is already counting frames + knocks for us.)
        // The waiter self-terminates when every tracked mailbox has drained,
        // so no task leaks past the drain window.
        let drained = Locked(Set<MailboxID>())
        let deadline = Date().addingTimeInterval(configuration.drainTimeout)
        let waiter = Task {
            for await event in relay.events {
                if case .drained(let mailbox) = event {
                    let done = drained.withLock { (drainedSet: inout Set<MailboxID>) -> Bool in
                        drainedSet.insert(mailbox)
                        return tracked.isSubset(of: drainedSet)
                    }
                    if done { break }
                }
            }
        }
        while Date() < deadline {
            if drained.withLock({ tracked.isSubset(of: $0) }) { break }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        let timedOut = Date() >= deadline && !drained.withLock({ tracked.isSubset(of: $0) })
        waiter.cancel()
        _ = await waiter.result

        if startedHere { await relay.stop() }

        let newFrames = lock.withLock { framesReceived - baseline }
        let newKnocks = lock.withLock { knockDedupeOrder.count - knockBaseline }
        // Attribute crudely: frames arrived during the drain window belong
        // to whatever we drained. Per-mailbox precision isn't needed for a
        // "3 new messages" badge; the app recounts from its store anyway.
        var perMailbox: [MailboxID: Int] = [:]
        if newFrames > 0 {
            let share = max(1, newFrames / max(1, tracked.count))
            for mailbox in tracked { perMailbox[mailbox] = share }
        }
        return DrainResult(perMailbox: perMailbox, knocks: newKnocks, timedOut: timedOut)
    }

    // MARK: Location wakes (opt-in)

    /// Drain on significant location changes (e.g. arriving home). Requires
    /// "Always" authorization and `NSLocationAlwaysAndWhenInUseUsageDescription`
    /// in Info.plist. The permission prompt must happen while foregrounded.
    public func startLocationWakes() {
        #if os(iOS) && canImport(CoreLocation)
        guard configuration.enableLocationWakes else { return }
        let manager = CLLocationManager()
        manager.delegate = self
        lock.withLock { locationManager = manager }
        if manager.authorizationStatus == .notDetermined {
            manager.requestAlwaysAuthorization()
        }
        manager.startMonitoringSignificantLocationChanges()
        #endif
    }

    // MARK: Local-notification handoff

    /// Post a local notification built by the app after it decrypted and
    /// verified the underlying envelope. The coordinator never sees names,
    /// message text, or caller identity — it only fires what it's given.
    public func postLocalNotification(_ content: LocalNotificationContent) async throws {
        #if canImport(UserNotifications)
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        guard settings.authorizationStatus == .authorized
                || settings.authorizationStatus == .provisional
        else { throw TransportError.underlying("local notifications not authorized") }
        let notification = UNMutableNotificationContent()
        notification.title = content.title
        notification.body = content.body
        notification.threadIdentifier = content.threadIdentifier
        notification.userInfo = content.userInfo
        notification.sound = .default
        let trigger: UNNotificationTrigger? = content.delay > 0
            ? UNTimeIntervalNotificationTrigger(timeInterval: max(1, content.delay), repeats: false)
            : nil
        try await center.add(UNNotificationRequest(
            identifier: content.identifier,
            content: notification,
            trigger: trigger
        ))
        #else
        throw TransportError.unsupportedPlatform
        #endif
    }
}

// MARK: - Tiny locked box (for values shared with non-async closures)

private final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value
    init(_ value: Value) { _value = value }
    var value: Value {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
    @discardableResult
    func withLock<T>(_ body: (inout Value) throws -> T) rethrows -> T {
        try lock.withLock { try body(&_value) }
    }
}

// MARK: - Location delegate

#if canImport(CoreLocation)
extension DeliveryCoordinator: CLLocationManagerDelegate {
    public func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        // A location wake is a free, OS-blessed reason to run. Drain now.
        Task { _ = await self.drainOnce() }
    }

    public func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // Location is best-effort; polling continues without it.
    }
}
#endif
