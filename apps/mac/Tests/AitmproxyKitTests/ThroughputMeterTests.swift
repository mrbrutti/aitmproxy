import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The status bar's ↑ / ↓ rate is computed from the bytes the bus poll sees arrive:
/// zero until there is a second sample, bytes over elapsed time across a sliding
/// window that spans at least the configured seconds, decaying back to zero when
/// traffic stops, never negative, and immune to hostile sizes.
@Suite struct ThroughputMeterTests {
    private let t0 = ContinuousClock.now

    private func at(_ seconds: Double) -> ContinuousClock.Instant {
        t0.advanced(by: .milliseconds(Int(seconds * 1_000)))
    }

    /// An HTTP summary from a core that reports sizes.
    private func http(_ id: String, request: Int64? = nil, response: Int64? = nil, status: Int? = 200) -> FlowSummary {
        FlowSummary(
            id: FlowID(id), kind: .http, intercept: .observed, isReplay: false, method: "GET", scheme: "https",
            authority: "h", path: "/", status: status, requestBytes: request, responseBytes: response,
            reportsBodySizes: true)
    }

    @Test func defaultWindowIsThreeSeconds() {
        #expect(ThroughputMeter().window == .seconds(3))
    }

    @Test func firstSampleIsZero() {
        var meter = ThroughputMeter(window: .seconds(3))
        #expect(meter.sample(up: 5_000, down: 90_000, at: at(0)) == .zero)
    }

    @Test func rateIsBytesOverElapsedTime() {
        var meter = ThroughputMeter(window: .seconds(3))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        let rate = meter.sample(up: 1_000, down: 4_000, at: at(0.5))
        #expect(rate == ThroughputMeter.Rate(up: 2_000, down: 8_000))
    }

    @Test func burstIsMeasuredOverTheWholeWindowNotTheLastPoll() {
        // 10 000 bytes arrive in the first half second, then nothing. Measured over the
        // window (1.5 s so far) that is 6 667 B/s; a meter that only compared the last
        // two polls would already read 0 — the flicker the window exists to prevent.
        var meter = ThroughputMeter(window: .seconds(3))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        _ = meter.sample(up: 10_000, down: 0, at: at(0.5))
        _ = meter.sample(up: 10_000, down: 0, at: at(1.0))
        #expect(meter.sample(up: 10_000, down: 0, at: at(1.5)) == ThroughputMeter.Rate(up: 6_667, down: 0))
    }

    @Test func baselineSlidesToTheNewestSampleOlderThanTheWindow() {
        // Window 2 s: 1 KiB at 0.5 s and 1.0 s, then flat. At 2.5 s the baseline is the
        // sample at 0.5 s (exactly 2 s old): (2048 − 1024) / 2 s = 512 B/s. The whole
        // history would read 819, the last poll alone 0 — only the window gives 512.
        var meter = ThroughputMeter(window: .seconds(2))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        _ = meter.sample(up: 1_024, down: 0, at: at(0.5))
        _ = meter.sample(up: 2_048, down: 0, at: at(1.0))
        _ = meter.sample(up: 2_048, down: 0, at: at(1.5))
        _ = meter.sample(up: 2_048, down: 0, at: at(2.0))
        #expect(meter.sample(up: 2_048, down: 0, at: at(2.5)) == ThroughputMeter.Rate(up: 512, down: 0))
    }

    @Test func idleTrafficDecaysToZero() {
        var meter = ThroughputMeter(window: .seconds(1))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        _ = meter.sample(up: 10_000, down: 10_000, at: at(0.5))
        // Nothing new for the next three seconds: the burst leaves the window.
        var rate = ThroughputMeter.Rate.zero
        for tick in 1...6 {
            rate = meter.sample(up: 10_000, down: 10_000, at: at(0.5 + Double(tick) * 0.5))
        }
        #expect(rate == .zero)
    }

    @Test func shrinkingTotalsStartANewBaselineNeverNegative() {
        var meter = ThroughputMeter(window: .seconds(3))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        _ = meter.sample(up: 8_000, down: 8_000, at: at(1))
        let cleared = meter.sample(up: 0, down: 0, at: at(1.5))
        #expect(cleared == .zero)
        let next = meter.sample(up: 500, down: 1_500, at: at(2))
        #expect(next == ThroughputMeter.Rate(up: 1_000, down: 3_000))
    }

    @Test func sameInstantIsZeroNotDivisionByZero() {
        var meter = ThroughputMeter(window: .seconds(3))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        #expect(meter.sample(up: 999, down: 999, at: at(0)) == .zero)
    }

    @Test func recordCountsOnlyTheGrowthOfEachFlow() {
        var meter = ThroughputMeter()
        let opened = http("a", request: 400, response: nil)
        meter.record(previous: nil, current: opened)
        #expect(meter.upTotal == 400)
        #expect(meter.downTotal == 0)
        // The response body finishes buffering: its size arrives once.
        let done = http("a", request: 400, response: 2_048)
        meter.record(previous: opened, current: done)
        #expect(meter.downTotal == 2_048)
        // Re-fetched unchanged: nothing new.
        meter.record(previous: done, current: done)
        #expect(meter.upTotal == 400)
        #expect(meter.downTotal == 2_048)
        // A size that shrank, or is nonsense, adds nothing.
        meter.record(previous: done, current: http("a", request: 400, response: 100))
        meter.record(previous: nil, current: http("b", request: -5, response: -5))
        #expect(meter.upTotal == 400)
        #expect(meter.downTotal == 2_048)
    }

    @Test func evictedFlowsDoNotReadAsNegativeTraffic() {
        // Two 4 000-byte responses are on the board at t=0. By t=1 the store has
        // evicted one and a 2 000-byte response arrived: the rate is the new traffic,
        // not "−2 000" from the total shrinking.
        var meter = ThroughputMeter(window: .seconds(3))
        meter.record(previous: nil, current: http("a", request: 0, response: 4_000))
        meter.record(previous: nil, current: http("b", request: 0, response: 4_000))
        #expect(meter.sample(at: at(0)) == .zero)
        meter.record(previous: nil, current: http("c", request: 0, response: 2_000))
        #expect(meter.sample(at: at(1)) == ThroughputMeter.Rate(up: 0, down: 2_000))
    }

    @Test func resetForgetsEverything() {
        var meter = ThroughputMeter(window: .seconds(3))
        meter.record(previous: nil, current: http("a", request: 10, response: 20))
        _ = meter.sample(at: at(0))
        meter.reset()
        #expect(meter.upTotal == 0)
        #expect(meter.downTotal == 0)
        #expect(meter.sample(up: 5_000, down: 5_000, at: at(1)) == .zero)
    }

    // The sizes come from a bus peer the app does not authenticate: absurd values
    // must read as absurd numbers, never trap the process (security review).

    @Test func hostileTotalsSaturateInsteadOfTrapping() {
        var meter = ThroughputMeter(window: .seconds(3))
        _ = meter.sample(up: 0, down: 0, at: at(0))
        // 2^63-1 bytes in half a second: the rate would be 2^64, beyond Int64.
        let burst = meter.sample(up: Int64.max, down: Int64.max, at: at(0.5))
        #expect(burst == ThroughputMeter.Rate(up: Int64.max, down: Int64.max))
        // Int64.min after Int64.max: a negative total counts as zero, which is a
        // shrink, so it re-baselines rather than subtracting across the whole range.
        #expect(meter.sample(up: Int64.min, down: Int64.min, at: at(1)) == .zero)
        #expect(meter.sample(up: 1_000, down: 0, at: at(1.5)) == ThroughputMeter.Rate(up: 2_000, down: 0))
    }

    @Test func rateSaturatesAndNeverGoesNegative() {
        #expect(ThroughputMeter.rate(from: 0, to: 1_000, over: 0.5) == 2_000)
        #expect(ThroughputMeter.rate(from: Int64.min, to: Int64.max, over: 1) == Int64.max)
        #expect(ThroughputMeter.rate(from: 0, to: Int64.max, over: 0.001) == Int64.max)
        #expect(ThroughputMeter.rate(from: 10, to: 5, over: 1) == 0)
    }

    @Test func saturatingSumCapsAtInt64Max() {
        #expect(ThroughputMeter.saturatingSum(1, 2) == 3)
        #expect(ThroughputMeter.saturatingSum(Int64.max, 1) == Int64.max)
        #expect(ThroughputMeter.saturatingSum(Int64.max, Int64.max) == Int64.max)
    }

    @Test func growthIgnoresUnknownNegativeAndShrunkSizes() {
        #expect(ThroughputMeter.growth(from: nil, to: 500) == 500)
        #expect(ThroughputMeter.growth(from: 500, to: 500) == 0)
        #expect(ThroughputMeter.growth(from: 500, to: 100) == 0)
        #expect(ThroughputMeter.growth(from: nil, to: nil) == 0)
        #expect(ThroughputMeter.growth(from: nil, to: -3) == 0)
        #expect(ThroughputMeter.growth(from: -9, to: 10) == 10)
        #expect(ThroughputMeter.growth(from: 0, to: Int64.max) == Int64.max)
    }

    @Test func recordedTotalsSaturate() {
        var meter = ThroughputMeter()
        meter.record(previous: nil, current: http("a", request: Int64.max, response: Int64.max))
        meter.record(previous: nil, current: http("b", request: 1, response: 1))
        #expect(meter.upTotal == Int64.max)
        #expect(meter.downTotal == Int64.max)
    }
}
