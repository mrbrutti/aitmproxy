import Foundation

/// Turns the bytes the bus poll sees arriving into the status bar's ↑ / ↓
/// bytes-per-second reading.
///
/// `record(previous:current:)` is called for every `flow.get` summary the poll
/// fetches: the growth of that flow's `request_bytes` / `response_bytes` since the
/// summary it replaces joins two running totals. A flow seen for the first time
/// contributes its whole size; one that leaves the core's list (evicted from the
/// store, `flow.clear`) is simply never offered again, so the totals only ever grow
/// and eviction cannot read as negative traffic. `sample(at:)` then measures the
/// totals over a sliding window of at least `window` (a 500 ms poll would otherwise
/// flicker between zero and a spike), decaying to zero when traffic stops.
///
/// Pure, with the clock passed in (`ContinuousClock.Instant`, monotonic: a wall-clock
/// step cannot produce a negative or stalled rate), so it is unit-tested. The sizes
/// come from a bus peer the app does not authenticate, so nothing here trusts them
/// with Swift's trapping arithmetic: a negative or unknown size counts as nothing,
/// sums saturate at `Int64.max`, and a rate too large for `Int64` reads as `Int64.max`.
/// A hostile core can show an absurd number, never crash the app.
public struct ThroughputMeter: Sendable {
    public struct Rate: Equatable, Sendable {
        public var up: Int64
        public var down: Int64
        public static let zero = Rate(up: 0, down: 0)

        public init(up: Int64, down: Int64) {
            self.up = up
            self.down = down
        }
    }

    private struct Sample: Sendable {
        let at: ContinuousClock.Instant
        let up: Int64
        let down: Int64
    }

    /// The shortest span a rate is measured over.
    public let window: Duration
    /// Bytes accounted so far on this connection: request bodies (↑) and response
    /// bodies (↓). Monotone and saturating.
    public private(set) var upTotal: Int64 = 0
    public private(set) var downTotal: Int64 = 0
    private var samples: [Sample] = []

    public init(window: Duration = .seconds(3)) {
        precondition(window > .zero, "a throughput window must be positive")
        self.window = window
    }

    /// Account for one flow's latest summary: the growth of its sizes since
    /// `previous` (nil for a flow seen for the first time, which contributes its
    /// whole size). Only growth counts; a size that is unknown (`nil`), negative, or
    /// smaller than before adds nothing.
    public mutating func record(previous: FlowSummary?, current: FlowSummary) {
        upTotal = Self.saturatingSum(upTotal, Self.growth(from: previous?.requestBytes, to: current.requestBytes))
        downTotal = Self.saturatingSum(downTotal, Self.growth(from: previous?.responseBytes, to: current.responseBytes))
    }

    /// The rate over the window ending at `at`, from the totals recorded so far.
    public mutating func sample(at: ContinuousClock.Instant) -> Rate {
        sample(up: upTotal, down: downTotal, at: at)
    }

    /// The window arithmetic on explicit totals (what `sample(at:)` feeds; tests use
    /// it directly). Totals are expected to grow; one that went backwards starts a
    /// new baseline rather than reading as negative traffic.
    public mutating func sample(up: Int64, down: Int64, at: ContinuousClock.Instant) -> Rate {
        let up = max(up, 0)
        let down = max(down, 0)
        if let last = samples.last, up < last.up || down < last.down {
            samples.removeAll()
        }
        samples.append(Sample(at: at, up: up, down: down))
        // Keep the newest sample that is already `window` old as the baseline and drop
        // everything older; until the window has passed, the very first sample is it.
        while samples.count > 2, samples[1].at.duration(to: at) >= window {
            samples.removeFirst()
        }
        guard samples.count > 1, let first = samples.first else { return .zero }
        let elapsed = first.at.duration(to: at)
        guard elapsed > .zero else { return .zero }
        let seconds = Self.seconds(elapsed)
        return Rate(
            up: Self.rate(from: first.up, to: up, over: seconds),
            down: Self.rate(from: first.down, to: down, over: seconds))
    }

    /// Forget everything (a new connection starts from nothing).
    public mutating func reset() {
        samples.removeAll()
        upTotal = 0
        downTotal = 0
    }

    /// How much `current` grew past `previous`; zero for an unknown, negative or
    /// shrunken size. Both operands are clamped non-negative first, so the
    /// difference cannot overflow.
    static func growth(from previous: Int64?, to current: Int64?) -> Int64 {
        guard let current, current > 0 else { return 0 }
        let before = max(previous ?? 0, 0)
        return current > before ? current - before : 0
    }

    /// `a + b` saturating at `Int64.max` instead of trapping. For byte counts, so the
    /// operands are expected non-negative.
    public static func saturatingSum(_ a: Int64, _ b: Int64) -> Int64 {
        let (sum, overflowed) = a.addingReportingOverflow(b)
        return overflowed ? Int64.max : sum
    }

    /// `(to - from) / seconds` in whole bytes per second, saturating at `Int64.max`
    /// and never below zero. `seconds` must be positive.
    static func rate(from: Int64, to: Int64, over seconds: Double) -> Int64 {
        let (delta, overflowed) = to.subtractingReportingOverflow(from)
        let bytes = overflowed ? Int64.max : max(delta, 0)
        let perSecond = (Double(bytes) / seconds).rounded()
        // `Double(Int64.max)` rounds up to 2^63, which `Int64(_:)` would trap on.
        return perSecond >= Double(Int64.max) ? Int64.max : Int64(perSecond)
    }

    static func seconds(_ duration: Duration) -> Double {
        let (seconds, attoseconds) = duration.components
        return Double(seconds) + Double(attoseconds) / 1e18
    }
}
