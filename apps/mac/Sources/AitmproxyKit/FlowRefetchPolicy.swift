import AitmBusClient
import Foundation

/// Which listed flows the bus poll asks `flow.get` about again, and which it leaves
/// cached. Pure, so the poll loop's decisions are unit-tested; `BusService` only
/// wires it (`shouldFetch` before each `flow.get`, `didFetch` after, `retain` once
/// the list is known, `markStale` from an operator action, `reset` per connection).
///
/// A flow is fetched again while it can still change: never seen, parked by
/// interception, no response head yet, marked stale by Resume/Kill, or — on a core
/// that reports sizes — a body still streaming after the response head
/// (`FlowSummary.awaitsBodySize`). That last wait is bounded as a safety net: a core
/// that finalises an abandoned response (buffered, truncated, with a duration) makes
/// its size land and the wait end on its own; an older core left such a response
/// `Streamed` for good, and there the flow is left alone after `bodySizePollLimit`
/// polls rather than asked about every poll for the life of the session.
public struct FlowRefetchPolicy: Sendable {
    /// Polls a flow may spend waiting for a streaming body's size; a minute at the
    /// 500 ms poll. Long enough for any download that finishes, short enough that an
    /// abandoned one costs one `flow.get` a poll for a minute, not forever.
    public let bodySizePollLimit: Int
    /// Flows an operator action changed on the core since their cached summary.
    private var stale: Set<FlowID> = []
    /// Polls spent waiting on a streaming body, per flow.
    private var waited: [FlowID: Int] = [:]

    public init(bodySizePollLimit: Int = 120) {
        precondition(bodySizePollLimit > 0, "a flow must be allowed at least one poll")
        self.bodySizePollLimit = bodySizePollLimit
    }

    /// Resume / Kill changed the flow on the core: its next poll must refresh it.
    public mutating func markStale(_ id: FlowID) {
        stale.insert(id)
    }

    /// Whether this poll fetches `id`, given the summary cached for it (`nil` when it
    /// has never been fetched). Call once per listed flow per poll: a wait on a
    /// streaming body is counted here.
    public mutating func shouldFetch(_ id: FlowID, cached: FlowSummary?) -> Bool {
        guard let cached else { return true }
        if stale.contains(id) { return true }
        if cached.intercept == .intercepted || (cached.status == nil && cached.kind == .http) { return true }
        if cached.awaitsBodySize {
            let polls = waited[id, default: 0]
            guard polls < bodySizePollLimit else { return false }
            waited[id] = polls + 1
            return true
        }
        return false
    }

    /// The summary a fetch brought back: the flow is fresh again, and once its
    /// sizes are known it no longer counts as waiting.
    public mutating func didFetch(_ id: FlowID, summary: FlowSummary) {
        stale.remove(id)
        if !summary.awaitsBodySize { waited[id] = nil }
    }

    /// Forget flows the core no longer lists.
    public mutating func retain(_ listed: Set<FlowID>) {
        stale.formIntersection(listed)
        waited = waited.filter { listed.contains($0.key) }
    }

    /// Forget everything (a new connection starts from nothing).
    public mutating func reset() {
        stale.removeAll()
        waited.removeAll()
    }
}
