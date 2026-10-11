import Foundation

/// Per-channel slow mode: at most one message per member per interval.
/// Enforced client-side from the signed channel policy; attempts to bypass
/// are visible as invalid events to honest clients (the sender's timestamps
/// are observable by every recipient).
///
/// The enforcer tracks one clock per member key (identity fingerprint hex).
/// It is deliberately dumb: the policy (interval, exemptions) lives in
/// `ChannelPermissionPolicy`, the timestamps live here, and the caller
/// supplies the actor's role.
public struct SlowModeEnforcer: Sendable, Codable, Equatable {
    /// Slow mode range: 5 seconds … 6 hours, matching the product spec.
    public static let minimumInterval: TimeInterval = 5
    public static let maximumInterval: TimeInterval = 6 * 3_600

    /// Last accepted send per member key. Bounded in practice by group size.
    public private(set) var lastSentAt: [String: Date]

    public init(lastSentAt: [String: Date] = [:]) {
        self.lastSentAt = lastSentAt
    }

    public enum Decision: Sendable, Equatable {
        /// The send is within policy.
        case allowed
        /// The actor's role is exempt from slow mode.
        case exempt
        /// Too soon: the caller must wait `retryAfter` seconds.
        case denied(retryAfter: TimeInterval)
    }

    /// Evaluates whether `memberKey` may send now. Pure — does not mutate.
    public func evaluate(
        memberKey: String,
        role: ModerationRole,
        in policy: ChannelPermissionPolicy,
        now: Date = Date()
    ) -> Decision {
        guard let interval = policy.slowModeInterval else { return .allowed }
        if PermissionEvaluator.isSlowModeExempt(role, in: policy) { return .exempt }
        guard let last = lastSentAt[memberKey] else { return .allowed }
        let elapsed = now.timeIntervalSince(last)
        guard elapsed < interval else { return .allowed }
        return .denied(retryAfter: interval - elapsed)
    }

    /// Records an accepted send. Call only after `evaluate` allowed it.
    public mutating func recordSend(memberKey: String, at date: Date = Date()) {
        lastSentAt[memberKey] = date
    }

    /// Clears a member's slow-mode clock (e.g. after removal, or when slow
    /// mode is turned off — callers should reset all clocks then).
    public mutating func reset(memberKey: String) {
        lastSentAt.removeValue(forKey: memberKey)
    }

    public mutating func resetAll() {
        lastSentAt.removeAll()
    }

    /// Human-readable interval label for the settings UI.
    public static func label(for interval: TimeInterval) -> String {
        if interval < 60 {
            return "\(Int(interval)) seconds"
        } else if interval < 3_600 {
            let minutes = Int(interval / 60)
            return minutes == 1 ? "1 minute" : "\(minutes) minutes"
        } else {
            let hours = Int(interval / 3_600)
            return hours == 1 ? "1 hour" : "\(hours) hours"
        }
    }

    /// The preset choices offered in the slow-mode picker (5s … 6h).
    public static let presets: [TimeInterval] = [
        5, 10, 30,
        60, 5 * 60, 15 * 60,
        3_600, 2 * 3_600, 6 * 3_600,
    ]
}
