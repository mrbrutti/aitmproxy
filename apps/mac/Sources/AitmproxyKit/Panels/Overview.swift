import Foundation

/// The Overview dashboard's numbers (S-063): session counts, the status-class
/// split, the busiest hosts and timing percentiles, all derived from the rows
/// the flow list already holds, so they always agree with the status bar.
public struct OverviewStats: Hashable, Sendable {
    /// One status class and how many flows ended in it; `statusClass == nil`
    /// is the "no status" bucket (pending, paused, killed).
    public struct StatusCount: Hashable, Sendable {
        public var statusClass: StatusClass?
        public var count: Int
        public init(_ statusClass: StatusClass?, _ count: Int) {
            self.statusClass = statusClass
            self.count = count
        }
    }

    public struct HostCount: Hashable, Sendable {
        public var host: String
        public var count: Int
        public init(_ host: String, _ count: Int) {
            self.host = host
            self.count = count
        }
    }

    /// Nearest-rank percentiles of completed flows' durations.
    public struct Percentiles: Hashable, Sendable {
        public var p50: Duration
        public var p90: Duration
        public var p99: Duration
        public init(p50: Duration, p90: Duration, p99: Duration) {
            self.p50 = p50
            self.p90 = p90
            self.p99 = p99
        }
    }

    public var flows: Int
    public var hosts: Int
    public var clients: Int
    public var paused: Int
    /// 5xx responses, transport failures and killed flows.
    public var errors: Int
    public var requestBytes: Int64
    public var responseBytes: Int64
    /// 1xx … 5xx in order, then the no-status bucket; every class is present, zero or not.
    public var statusClasses: [StatusCount]
    /// The busiest hosts, most flows first, ties by name; at most `topHostLimit`.
    public var topHosts: [HostCount]
    /// nil when fewer than two completed flows carry a duration.
    public var percentiles: Percentiles?

    public static let topHostLimit = 8
    static let classOrder: [StatusClass?] = [.informational, .success, .redirect, .clientError, .serverError, nil]

    public init(rows: [FlowRow]) {
        flows = rows.count
        hosts = Set(rows.map(\.authority)).count
        clients = Set(rows.compactMap { $0.client?.name }).count
        paused = rows.filter { $0.state == .paused }.count
        errors = rows.filter { row in
            row.state == .failed || row.state == .killed || row.status.flatMap(StatusClass.init) == .serverError
        }.count
        // Sizes come from the bus: saturating sums, so a hostile size cannot trap the app.
        requestBytes = rows.reduce(0) { ThroughputMeter.saturatingSum($0, max($1.requestBytes ?? 0, 0)) }
        responseBytes = rows.reduce(0) { ThroughputMeter.saturatingSum($0, max($1.responseBytes ?? 0, 0)) }

        var byClass: [StatusClass?: Int] = [:]
        for row in rows { byClass[row.status.flatMap(StatusClass.init), default: 0] += 1 }
        statusClasses = Self.classOrder.map { StatusCount($0, byClass[$0] ?? 0) }

        var byHost: [String: Int] = [:]
        for row in rows { byHost[row.authority, default: 0] += 1 }
        topHosts = byHost
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .prefix(Self.topHostLimit)
            .map { HostCount($0.key, $0.value) }

        let durations = rows.compactMap { $0.state == .complete ? $0.duration : nil }.sorted()
        if durations.count >= 2 {
            percentiles = Percentiles(p50: Self.nearestRank(durations, 50),
                                      p90: Self.nearestRank(durations, 90),
                                      p99: Self.nearestRank(durations, 99))
        } else {
            percentiles = nil
        }
    }

    /// The nearest-rank method: the value at rank ⌈p/100 · n⌉ of the sorted sample.
    static func nearestRank(_ sorted: [Duration], _ percent: Double) -> Duration {
        let rank = Int((percent / 100 * Double(sorted.count)).rounded(.up))
        return sorted[max(0, min(sorted.count - 1, rank - 1))]
    }

    /// The largest count among the status classes, for scaling the bars.
    public var statusMax: Int { statusClasses.map(\.count).max() ?? 0 }
    /// The largest count among the top hosts.
    public var hostMax: Int { topHosts.map(\.count).max() ?? 0 }
}

extension StatusClass {
    /// `1xx` … `5xx`, the Overview's row label.
    public var rangeLabel: String {
        switch self {
        case .informational: "1xx"
        case .success: "2xx"
        case .redirect: "3xx"
        case .clientError: "4xx"
        case .serverError: "5xx"
        }
    }
}
