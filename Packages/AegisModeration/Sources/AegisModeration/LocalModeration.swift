import Foundation

// MARK: - Local blocklist
//
// Blocking is LOCAL AND SILENT by design: the blocked identity is never
// told. No "blocked" signal is emitted — emitting one would confirm to a
// harasser that the mailbox is active. Messages from blocked identities
// are dropped on receipt; no notification, no unread, no receipt.

/// The device-local set of blocked identity fingerprints (32 bytes each).
public struct LocalBlocklist: Sendable, Codable, Equatable {
    private var blocked: Set<Data>

    public init(blocked: Set<Data> = []) {
        self.blocked = blocked
    }

    public var isEmpty: Bool { blocked.isEmpty }
    public var count: Int { blocked.count }
    public var fingerprints: [Data] { Array(blocked) }

    public func isBlocked(_ fingerprint: Data) -> Bool {
        blocked.contains(fingerprint)
    }

    /// Blocks an identity. Returns true when it was newly added.
    /// Silent by contract: callers MUST NOT emit any signal to the
    /// blocked party.
    @discardableResult
    public mutating func block(_ fingerprint: Data) -> Bool {
        blocked.insert(fingerprint).inserted
    }

    @discardableResult
    public mutating func unblock(_ fingerprint: Data) -> Bool {
        blocked.remove(fingerprint) != nil
    }
}

// MARK: - Local-only abuse reports
//
// Reports feed LOCAL heuristics only. There is no central abuse desk to
// send them to — by design: a global abuse pipeline would be a metadata
// honeypot and a censorship choke point. The UI states this honestly.

public enum ReportReason: String, Sendable, Codable, CaseIterable {
    case spam
    case harassment
    case impersonation
    case scam
    case unwantedContact
    case other

    public var displayName: String {
        switch self {
        case .spam: return "Spam"
        case .harassment: return "Harassment"
        case .impersonation: return "Impersonation"
        case .scam: return "Scam or fraud"
        case .unwantedContact: return "Unwanted contact"
        case .other: return "Something else"
        }
    }

    public var systemImage: String {
        switch self {
        case .spam: return "envelope.badge"
        case .harassment: return "exclamationmark.bubble"
        case .impersonation: return "person.badge.shield.exclamationmark"
        case .scam: return "banknote"
        case .unwantedContact: return "person.slash"
        case .other: return "flag"
        }
    }
}

/// A report about an identity. Stored on-device only; the reporter's
/// heuristics (repeat offenders across requests) are computed locally.
public struct AbuseReport: Sendable, Codable, Equatable, Identifiable {
    public var id: UUID
    public var reportedFingerprint: Data
    public var reportedName: String?
    /// The last message preview, kept locally as context for the report.
    /// Never transmitted anywhere.
    public var messagePreview: String?
    public var reason: ReportReason
    public var detail: String?
    public var createdAt: Date
    /// Whether the reported identity was also blocked at report time.
    public var alsoBlocked: Bool

    public init(
        id: UUID = UUID(),
        reportedFingerprint: Data,
        reportedName: String? = nil,
        messagePreview: String? = nil,
        reason: ReportReason,
        detail: String? = nil,
        createdAt: Date = Date(),
        alsoBlocked: Bool = true
    ) {
        self.id = id
        self.reportedFingerprint = reportedFingerprint
        self.reportedName = reportedName
        self.messagePreview = messagePreview
        self.reason = reason
        self.detail = detail
        self.createdAt = createdAt
        self.alsoBlocked = alsoBlocked
    }
}

/// Device-local report store with simple heuristics: how many times an
/// identity was reported, and when. All computation is local.
public struct LocalReportStore: Sendable, Codable, Equatable {
    public private(set) var reports: [AbuseReport]

    public init(reports: [AbuseReport] = []) {
        self.reports = reports
    }

    public var isEmpty: Bool { reports.isEmpty }
    public var count: Int { reports.count }

    public mutating func add(_ report: AbuseReport) {
        reports.append(report)
    }

    public mutating func remove(id: UUID) {
        reports.removeAll { $0.id == id }
    }

    /// Number of reports filed against this identity on this device.
    public func reportCount(for fingerprint: Data) -> Int {
        reports.count { $0.reportedFingerprint == fingerprint }
    }

    /// Identities reported more than once — the local heuristic for
    /// "repeat offender". Sorted by report count, descending.
    public func repeatOffenders() -> [(fingerprint: Data, count: Int)] {
        var counts: [Data: Int] = [:]
        for report in reports {
            counts[report.reportedFingerprint, default: 0] += 1
        }
        return counts
            .filter { $0.value > 1 }
            .sorted { $0.value > $1.value }
            .map { (fingerprint: $0.key, count: $0.value) }
    }

    public func reports(for fingerprint: Data) -> [AbuseReport] {
        reports.filter { $0.reportedFingerprint == fingerprint }
    }
}
