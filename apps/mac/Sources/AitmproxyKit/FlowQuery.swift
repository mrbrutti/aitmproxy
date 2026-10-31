import Foundation

/// A sidebar narrowing: one client or one host (foundation §2.6 Apps / Domains).
public enum FlowGroup: Hashable, Sendable {
    case host(String)
    case client(String)
}

/// Everything that decides which rows a flow list shows, in which order
/// (architecture review card 3): the sidebar's scope page and group, the
/// content-type chip, the filter bar's expression, the sort. One value per
/// list, so a split view (S-062) is two queries over one capture.
public struct FlowQuery: Hashable, Sendable {
    public var inScopeOnly = false
    public var group: FlowGroup?
    /// The sidebar's Pinned page with no sub-item: only flows whose host or client app is pinned.
    public var pins: Pins?
    public var chip: ContentCategory = .all
    public var filter: FilterExpression = .matchAll
    public var sort: FlowSort = .captureOrder

    public init(inScopeOnly: Bool = false, group: FlowGroup? = nil, pins: Pins? = nil, chip: ContentCategory = .all,
                filter: FilterExpression = .matchAll, sort: FlowSort = .captureOrder) {
        self.inScopeOnly = inScopeOnly
        self.group = group
        self.pins = pins
        self.chip = chip
        self.filter = filter
        self.sort = sort
    }

    public var isNarrowing: Bool { inScopeOnly || group != nil || pins != nil || chip != .all || filter != .matchAll }

    /// The rows this list shows. Compiles the filter once per call; callers
    /// that run on every keystroke should cache via `compiled()`.
    public func apply(_ rows: [FlowRow], details: [FlowID: FlowDetail]) -> [FlowRow] {
        compiled().apply(rows, details: details)
    }

    public func compiled() -> Compiled { Compiled(query: self) }

    /// A query with its filter compiled, for repeated application.
    public struct Compiled: Sendable {
        public let query: FlowQuery
        private let matcher: CompiledFilter?

        init(query: FlowQuery) {
            self.query = query
            matcher = query.filter == .matchAll ? nil : CompiledFilter(query.filter)
        }

        public func apply(_ rows: [FlowRow], details: [FlowID: FlowDetail]) -> [FlowRow] {
            var out = rows
            if query.inScopeOnly { out = out.filter(\.inScope) }
            switch query.group {
            case .host(let host)?: out = out.filter { $0.authority == host }
            case .client(let name)?: out = out.filter { $0.client?.name == name }
            case nil: break
            }
            if let pins = query.pins {
                let hosts = Set(pins.hosts), apps = Set(pins.apps)
                out = out.filter { hosts.contains($0.authority) || $0.client.map { apps.contains($0.name) } == true }
            }
            if query.chip != .all {
                out = out.filter { row in
                    let detail = details[row.id]
                    return query.chip.matches(row: row, contentType: detail?.response?.contentType ?? detail?.request.contentType,
                                              httpVersion: detail?.connection.httpVersion)
                }
            }
            if let matcher {
                out = out.filter { matcher.matches(FilterSubject(row: $0, detail: details[$0.id])) }
            }
            return query.sort.sorted(out)
        }
    }
}
