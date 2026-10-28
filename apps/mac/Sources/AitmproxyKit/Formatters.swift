import Foundation

/// Text for the data columns (foundation §2.8: zero prints as zero, missing
/// as a grey dash, a real 0 B body as `0 B`).
public enum Format {
    public static let dash = "—"

    /// `412 B`, `1.1 KB`, `18.2 KB`, `196 MB` — decimal units, one decimal under 100.
    public static func bytes(_ n: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(n)
        var unit = 0
        while value >= 1000, unit < units.count - 1 {
            value /= 1000
            unit += 1
        }
        if unit == 0 { return "\(n) B" }
        let text = value < 100 ? String(format: "%.1f", value) : String(format: "%.0f", value)
        return "\(text.replacingOccurrences(of: ".0", with: "")) \(units[unit])"
    }

    public static func bytes(_ n: Int64?) -> String { n.map(bytes) ?? dash }

    /// `89 ms`, `1.21 s`, `2.4 s`, `1m 05s`.
    public static func duration(_ d: Duration) -> String {
        let seconds = Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
        switch seconds {
        case ..<1: return "\(Int((seconds * 1000).rounded())) ms"
        case ..<10: return String(format: "%.2f s", seconds)
        case ..<60: return String(format: "%.1f s", seconds)
        default:
            let m = Int(seconds) / 60
            let s = Int(seconds) % 60
            return String(format: "%dm %02ds", m, s)
        }
    }

    public static func duration(_ d: Duration?) -> String { d.map(duration) ?? dash }

    /// `11:04:58.120` — wall-clock time with milliseconds, local zone.
    public static func time(_ date: Date, zone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        let c = calendar.dateComponents([.hour, .minute, .second, .nanosecond], from: date)
        return String(format: "%02d:%02d:%02d.%03d", c.hour ?? 0, c.minute ?? 0, c.second ?? 0,
                      (c.nanosecond ?? 0) / 1_000_000)
    }

    public static func time(_ date: Date?) -> String { date.map { time($0) } ?? dash }

    /// `6 KB/s`.
    public static func rate(_ bytesPerSecond: Int64) -> String { "\(bytes(bytesPerSecond))/s" }

    /// An RFC 3339 / ISO 8601 timestamp with fractional seconds, as the core emits
    /// for WebSocket frames. A local formatter, since `ISO8601DateFormatter` is not Sendable.
    public static func rfc3339(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }

    /// `11:04:58.120` for a frame's RFC 3339 timestamp, or nil when it does not parse.
    public static func clock(rfc3339 string: String) -> String? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = f.date(from: string) ?? ISO8601DateFormatter().date(from: string) else { return nil }
        return time(date)
    }
}
