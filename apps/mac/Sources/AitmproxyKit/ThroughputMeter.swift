import Foundation

/// Turns the cumulative request/response byte totals the bus poll sees into the
/// status bar's ↑ / ↓ bytes-per-second reading.
///
/// Pure and clock-free (the caller passes `at`), so it is unit-tested. The totals
/// are the sum of `request_bytes` / `response_bytes` over every flow the core lists;
/// they grow as flows arrive and complete, so the rate is measured over a sliding
/// window of at least `window` seconds (a 500 ms poll would otherwise flicker
/// between zero and a spike). A total that shrinks — `flow.clear`, a reconnect to
/// another core, the store evicting old flows — starts a new baseline instead of
/// producing a negative rate. With no second sample yet, or no time elapsed, the
/// rate is zero.
///
/// The totals come from a bus peer the app does not authenticate, so nothing here
/// trusts them with Swift's trapping arithmetic: a negative total counts as zero,
/// sums and differences saturate at `Int64.max`, and a rate too large for `Int64`
/// reads as `Int64.max`. A hostile core can show an absurd number, never crash the app.
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
        let at: Date
        let up: Int64
        let down: Int64
    }

    /// The shortest span a rate is measured over, in seconds.
    public let window: TimeInterval
    private var samples: [Sample] = []

    public init(window: TimeInterval = 3) {
        self.window = max(window, 0.1)
    }

    /// Record the totals seen at `at` and return the rate over the window ending there.
    public mutating func sample(up: Int64, down: Int64, at: Date) -> Rate {
        // A peer-supplied negative total is nonsense; it counts as nothing seen.
        let up = max(up, 0)
        let down = max(down, 0)
        if let last = samples.last, up < last.up || down < last.down {
            // The totals went backwards: whatever they now count is a new baseline.
            samples.removeAll()
        }
        samples.append(Sample(at: at, up: up, down: down))
        // Keep the newest sample that is already `window` old as the baseline and drop
        // everything older; until the window has passed, the very first sample is it.
        while samples.count > 2, at.timeIntervalSince(samples[1].at) >= window {
            samples.removeFirst()
        }
        guard samples.count > 1, let first = samples.first else { return .zero }
        let elapsed = at.timeIntervalSince(first.at)
        guard elapsed > 0 else { return .zero }
        return Rate(
            up: Self.rate(from: first.up, to: up, over: elapsed),
            down: Self.rate(from: first.down, to: down, over: elapsed))
    }

    /// Forget every sample (a new connection starts from nothing).
    public mutating func reset() {
        samples.removeAll()
    }

    /// `(to - from) / seconds` in whole bytes per second, saturating at `Int64.max`
    /// and never below zero. `seconds` must be positive.
    static func rate(from: Int64, to: Int64, over seconds: TimeInterval) -> Int64 {
        let (delta, overflowed) = to.subtractingReportingOverflow(from)
        let bytes = overflowed ? Int64.max : max(delta, 0)
        let perSecond = (Double(bytes) / seconds).rounded()
        // `Double(Int64.max)` rounds up to 2^63, which `Int64(_:)` would trap on.
        return perSecond >= Double(Int64.max) ? Int64.max : Int64(perSecond)
    }

    /// The sum of the sizes present, saturating at `Int64.max` instead of trapping on
    /// a peer-supplied value; a `nil` (unknown size) adds nothing and a negative one
    /// counts as zero.
    public static func total(_ sizes: some Sequence<Int64?>) -> Int64 {
        var sum: Int64 = 0
        for case let size? in sizes {
            let (next, overflowed) = sum.addingReportingOverflow(max(size, 0))
            if overflowed { return Int64.max }
            sum = next
        }
        return sum
    }
}
