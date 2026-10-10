import Foundation

/// Display formatting shared across views. Kept in one place so timestamps,
/// sizes, and durations read identically everywhere in the app.
enum Formatters {
    // MARK: - Time

    /// "14:32" today, "Yesterday", "Tue", or "12/03/2026" — like iMessage.
    static func chatListTimestamp(_ date: Date, now: Date = Date()) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) {
            return timeFormatter.string(from: date)
        }
        if calendar.isDateInYesterday(date) {
            return "Yesterday"
        }
        if let weekAgo = calendar.date(byAdding: .day, value: -7, to: now), date > weekAgo {
            return weekdayFormatter.string(from: date)
        }
        return dateFormatter.string(from: date)
    }

    /// "14:32" for in-bubble timestamps.
    static func bubbleTime(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    /// "2h 14m" / "45s" for call durations and timers.
    static func duration(_ interval: TimeInterval) -> String {
        let total = Int(interval.rounded())
        if total < 60 { return "\(total)s" }
        let minutes = total / 60
        if minutes < 60 { return "\(minutes)m" }
        let hours = minutes / 60
        let rem = minutes % 60
        return rem == 0 ? "\(hours)h" : "\(hours)h \(rem)m"
    }

    /// "1h 23m 45s" for the active-call timer.
    static func callElapsed(_ interval: TimeInterval) -> String {
        let total = Int(interval)
        let h = total / 3600
        let m = (total % 3600) / 60
        let s = total % 60
        if h > 0 {
            return String(format: "%d:%02d:%02d", h, m, s)
        }
        return String(format: "%d:%02d", m, s)
    }

    // MARK: - Sizes

    /// "2.4 MB", "812 KB" via the system byte-count formatter.
    static func bytes(_ count: Int64) -> String {
        byteFormatter.string(fromByteCount: count)
    }

    // MARK: - Fingerprints

    /// Group a fingerprint into readable 5-char blocks: "12345 67890 …".
    static func groupedFingerprint(_ fingerprint: String, groupSize: Int = 5) -> String {
        let cleaned = fingerprint.filter { $0.isNumber || $0.isLetter }
        return stride(from: 0, to: cleaned.count, by: groupSize)
            .map { start in
                let from = cleaned.index(cleaned.startIndex, offsetBy: start)
                let to = cleaned.index(from, offsetBy: groupSize, limitedBy: cleaned.endIndex) ?? cleaned.endIndex
                return String(cleaned[from..<to])
            }
            .joined(separator: " ")
    }

    // MARK: - Private formatters (created once)

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .short
        f.dateStyle = .none
        return f
    }()

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .none
        f.dateStyle = .short
        return f
    }()

    private static let weekdayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "EEE"
        return f
    }()

    private static var byteFormatter: ByteCountFormatter {
        let f = ByteCountFormatter()
        f.allowedUnits = [.useKB, .useMB, .useGB]
        f.countStyle = .file
        return f
    }
}
