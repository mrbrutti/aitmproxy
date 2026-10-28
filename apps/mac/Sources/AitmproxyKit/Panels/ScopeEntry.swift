import Foundation

/// A host's rate limit and back-off, shown read-only beside its scope entry
/// (foundation §2.7 "Scope panel", §3.9; the core's `LimitConfig`, F5).
public struct RateLimit: Hashable, Sendable {
    public var requestsPerSecond: Double
    public var burst: Int
    public var backoffFactor: Double
    /// Errors allowed before the proxy backs off; nil when the host has none.
    public var errorBudget: Int?

    public init(requestsPerSecond: Double, burst: Int, backoffFactor: Double, errorBudget: Int? = nil) {
        self.requestsPerSecond = requestsPerSecond
        self.burst = burst
        self.backoffFactor = backoffFactor
        self.errorBudget = errorBudget
    }

    /// `10 req/s · burst 20` — the Limit column.
    public var limitText: String { "\(Self.number(requestsPerSecond)) req/s · burst \(burst)" }

    /// `2×` — the Back-off column.
    public var backoffText: String { "\(Self.number(backoffFactor))×" }

    /// `10 req/s · burst 20 · back-off 2×`, plus `· budget 50` when the host has one.
    public var readout: String {
        var parts = [limitText, "back-off \(backoffText)"]
        if let errorBudget { parts.append("budget \(errorBudget)") }
        return parts.joined(separator: " · ")
    }

    /// Whole numbers print whole; the rest keep one decimal (`0.5`, `1.5`).
    static func number(_ value: Double) -> String {
        value == value.rounded() ? String(Int(value)) : String(format: "%.1f", value)
    }
}

/// One row of the Scope panel: a `host`, `host:port` or `*.wildcard` entry
/// and its limit when the bus has one.
public struct ScopeEntry: Identifiable, Hashable, Sendable {
    public var host: String
    public var limit: RateLimit?

    public var id: String { host }

    public init(host: String, limit: RateLimit? = nil) {
        self.host = host
        self.limit = limit
    }

    /// How many of `rows` this entry covers (`Scope.matches`: wildcard and port aware).
    public func flowCount(in rows: [FlowRow]) -> Int {
        rows.reduce(0) { $0 + (Scope.matches($1.authority, host) ? 1 : 0) }
    }

    /// nil when `text` can be added; otherwise why not (`Scope.validate`, plus duplicates).
    public static func validate(_ text: String, existing: [String]) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if let error = Scope.validate(trimmed) { return error }
        if existing.contains(trimmed) { return "\(trimmed) is already in scope" }
        return nil
    }

    /// The bus's host list paired with whatever limits are known.
    public static func entries(hosts: [String], limits: [String: RateLimit] = [:]) -> [ScopeEntry] {
        hosts.map { ScopeEntry(host: $0, limit: limits[$0]) }
    }
}
