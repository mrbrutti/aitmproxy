import Foundation

/// The Overview page's lower half (review 2026-10-31, B9 + wave 2): the method
/// and client splits, the raw-L4 sessions, and three short lists — slowest,
/// recent errors, largest responses. A sibling of `OverviewStats`, derived
/// from the same rows, so the numbers always agree with the flow list.
///
/// L4 sockets are not HTTP flows: `httpOnly` strips them so the Flows / Hosts
/// tiles and the Methods split count HTTP and WebSocket only, and `l4Sessions`
/// carries them as their own number.
public struct OverviewBreakdowns: Hashable, Sendable {
    public struct MethodCount: Hashable, Sendable {
        public var method: HTTPMethod
        public var count: Int
        public init(_ method: HTTPMethod, _ count: Int) {
            self.method = method
            self.count = count
        }
    }

    public struct ClientCount: Hashable, Sendable {
        public var name: String
        public var count: Int
        public init(_ name: String, _ count: Int) {
            self.name = name
            self.count = count
        }
    }

    /// Flows per HTTP method (HTTP and WebSocket rows only), most first, ties by label.
    public var methods: [MethodCount]
    /// Flows per attributed client, most first, ties by name; rows without a client are skipped.
    public var clients: [ClientCount]
    /// Every raw-L4 row (`FlowRow.l4 != nil`), in capture order.
    public var l4Sessions: [FlowRow]
    /// Completed HTTP flows with a duration, slowest first; at most `listLimit`.
    public var slowest: [FlowRow]
    /// Flows with a 4xx/5xx status or a transport failure, newest first; at most `listLimit`.
    public var recentErrors: [FlowRow]
    /// Flows by response size, largest first (zero and unknown sizes skipped); at most `listLimit`.
    public var largest: [FlowRow]

    public static let listLimit = 5
    /// How many L4 sessions the Overview lists before "and n more".
    public static let l4PreviewLimit = 3

    /// The rows that are HTTP or WebSocket flows — what `OverviewStats` should count.
    public static func httpOnly(_ rows: [FlowRow]) -> [FlowRow] {
        rows.filter { $0.l4 == nil }
    }

    public init(rows: [FlowRow]) {
        let http = Self.httpOnly(rows)

        var byMethod: [HTTPMethod: Int] = [:]
        for row in http { byMethod[row.method, default: 0] += 1 }
        methods = byMethod
            .sorted { $0.value == $1.value ? $0.key.label < $1.key.label : $0.value > $1.value }
            .map { MethodCount($0.key, $0.value) }

        var byClient: [String: Int] = [:]
        for row in rows { if let name = row.client?.name { byClient[name, default: 0] += 1 } }
        clients = byClient
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .map { ClientCount($0.key, $0.value) }

        l4Sessions = rows.filter { $0.l4 != nil }

        slowest = Array(
            http.filter { $0.state == .complete && $0.duration != nil }
                .sorted { a, b in
                    let da = a.duration ?? .zero, db = b.duration ?? .zero
                    return da == db ? a.seq < b.seq : da > db
                }
                .prefix(Self.listLimit))

        recentErrors = Array(
            http.filter { ($0.status ?? 0) >= 400 || $0.state == .failed }
                .sorted { a, b in
                    switch (a.startedAt, b.startedAt) {
                    case let (ta?, tb?) where ta != tb: return ta > tb
                    case (nil, .some): return false
                    case (.some, nil): return true
                    default: return a.seq > b.seq
                    }
                }
                .prefix(Self.listLimit))

        largest = Array(
            http.filter { ($0.responseBytes ?? 0) > 0 }
                .sorted { a, b in
                    let sa = a.responseBytes ?? 0, sb = b.responseBytes ?? 0
                    return sa == sb ? a.seq < b.seq : sa > sb
                }
                .prefix(Self.listLimit))
    }

    /// The largest method count, for scaling the bars.
    public var methodMax: Int { methods.map(\.count).max() ?? 0 }
    /// The largest client count.
    public var clientMax: Int { clients.map(\.count).max() ?? 0 }
    /// The first `l4PreviewLimit` L4 sessions.
    public var l4Preview: [FlowRow] { Array(l4Sessions.prefix(Self.l4PreviewLimit)) }

    /// `UDP · lo0 · udp port 9 · 4 pkt` — the one-line L4 session summary.
    public static func l4Summary(_ row: FlowRow) -> String {
        guard let l4 = row.l4 else { return row.authority }
        return "\(l4.subLabel) · \(l4.target) · \(l4.packetCount) pkt"
    }
}
