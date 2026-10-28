import Foundation

/// How the flow list is ordered. Capture order (`#` ascending) is the
/// default and shows no indicator. Rows without a value for the key
/// (no status yet, no duration) sort last in either direction.
public struct FlowSort: Hashable, Sendable {
    public enum Key: String, CaseIterable, Hashable, Sendable {
        case seq, url, client, method, status, time, duration, request, response, ssl, edited, origin, mark

        public var title: String {
            switch self {
            case .seq: "Capture Order"
            case .url: "URL"
            case .client: "Client"
            case .method: "Method"
            case .status: "Status"
            case .time: "Time"
            case .duration: "Duration"
            case .request: "Request Size"
            case .response: "Response Size"
            case .ssl: "SSL"
            case .edited: "Edited"
            case .origin: "Origin"
            case .mark: "Mark"
            }
        }
    }

    public var key: Key
    public var ascending: Bool

    public init(key: Key, ascending: Bool = true) {
        self.key = key
        self.ascending = ascending
    }

    public static let captureOrder = FlowSort(key: .seq, ascending: true)
    public var isCaptureOrder: Bool { key == .seq && ascending }

    /// A stable sort: equal keys keep capture order.
    public func sorted(_ rows: [FlowRow]) -> [FlowRow] {
        if isCaptureOrder { return rows }
        let indexed = rows.enumerated().map { ($0.offset, $0.element) }
        let ordered = indexed.sorted { a, b in
            switch compare(a.1, b.1) {
            case .orderedSame: return a.0 < b.0
            case .orderedAscending: return ascending
            case .orderedDescending: return !ascending
            }
        }
        return ordered.map(\.1)
    }

    /// `nil` values compare as "after" regardless of direction.
    private func compare(_ a: FlowRow, _ b: FlowRow) -> ComparisonResult {
        switch key {
        case .seq: return cmp(a.seq, b.seq)
        case .url:
            let host = a.authority.localizedCaseInsensitiveCompare(b.authority)
            return host == .orderedSame ? a.path.localizedCaseInsensitiveCompare(b.path) : host
        case .client: return cmpOptional(a.client?.name.lowercased(), b.client?.name.lowercased())
        case .method: return cmp(a.method.label, b.method.label)
        case .status: return cmpOptional(a.state == .complete ? a.status : nil, b.state == .complete ? b.status : nil)
        case .time: return cmpOptional(a.startedAt, b.startedAt)
        case .duration: return cmpOptional(a.duration, b.duration)
        case .request: return cmpOptional(a.requestBytes, b.requestBytes)
        case .response: return cmpOptional(a.responseBytes, b.responseBytes)
        case .ssl: return cmp(a.tls.rank, b.tls.rank)
        case .edited: return cmp(a.edited ? 0 : 1, b.edited ? 0 : 1)
        case .origin: return cmp(a.origin.rank, b.origin.rank)
        case .mark: return cmpOptional(a.mark?.rawValue, b.mark?.rawValue)
        }
    }

    private func cmp<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
        a == b ? .orderedSame : (a < b ? .orderedAscending : .orderedDescending)
    }

    /// nil last in both directions: a nil "wins" the slot that ends up at the bottom.
    private func cmpOptional<T: Comparable>(_ a: T?, _ b: T?) -> ComparisonResult {
        switch (a, b) {
        case (nil, nil): return .orderedSame
        case (nil, _): return ascending ? .orderedDescending : .orderedAscending
        case (_, nil): return ascending ? .orderedAscending : .orderedDescending
        case let (x?, y?): return cmp(x, y)
        }
    }
}

extension TLSState {
    var rank: Int {
        switch self {
        case .decrypted: 0
        case .tunnelled: 1
        case .pinnedOrFailed: 2
        case .none: 3
        }
    }
}

extension FlowOrigin {
    var rank: Int {
        switch self {
        case .agent: 0
        case .human: 1
        case .client: 2
        }
    }
}
