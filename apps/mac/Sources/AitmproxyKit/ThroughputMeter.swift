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
            up: Int64((Double(up - first.up) / elapsed).rounded()),
            down: Int64((Double(down - first.down) / elapsed).rounded()))
    }

    /// Forget every sample (a new connection starts from nothing).
    public mutating func reset() {
        samples.removeAll()
    }
}
