import Foundation
import Testing
@testable import AitmproxyKit

/// The status bar's ↑ / ↓ rate is computed from the byte totals the bus poll sees:
/// zero until there is a second sample, bytes over elapsed time across a sliding
/// window, decaying back to zero when traffic stops, and never negative.
@Suite struct ThroughputMeterTests {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    @Test func firstSampleIsZero() {
        var meter = ThroughputMeter(window: 3)
        #expect(meter.sample(up: 5_000, down: 90_000, at: t0) == .zero)
    }

    @Test func rateIsBytesOverElapsedTime() {
        var meter = ThroughputMeter(window: 3)
        _ = meter.sample(up: 0, down: 0, at: t0)
        let rate = meter.sample(up: 1_000, down: 4_000, at: t0.addingTimeInterval(0.5))
        #expect(rate == ThroughputMeter.Rate(up: 2_000, down: 8_000))
    }

    @Test func slidingWindowSpansAtLeastTheConfiguredSeconds() {
        var meter = ThroughputMeter(window: 2)
        // 1 KiB up every half second for four seconds.
        var rate = ThroughputMeter.Rate.zero
        for tick in 0...8 {
            rate = meter.sample(up: Int64(tick) * 1_024, down: 0, at: t0.addingTimeInterval(Double(tick) * 0.5))
        }
        // Steady traffic reads as its steady rate (2 KiB/s), measured over ~2 s, not
        // over the whole 4 s history and not over the last 500 ms alone.
        #expect(rate.up == 2_048)
        #expect(rate.down == 0)
    }

    @Test func idleTrafficDecaysToZero() {
        var meter = ThroughputMeter(window: 1)
        _ = meter.sample(up: 0, down: 0, at: t0)
        _ = meter.sample(up: 10_000, down: 10_000, at: t0.addingTimeInterval(0.5))
        // Nothing new for the next three seconds: the burst leaves the window.
        var rate = ThroughputMeter.Rate.zero
        for tick in 1...6 {
            rate = meter.sample(up: 10_000, down: 10_000, at: t0.addingTimeInterval(0.5 + Double(tick) * 0.5))
        }
        #expect(rate == .zero)
    }

    @Test func shrinkingTotalsStartANewBaselineNeverNegative() {
        var meter = ThroughputMeter(window: 3)
        _ = meter.sample(up: 0, down: 0, at: t0)
        _ = meter.sample(up: 8_000, down: 8_000, at: t0.addingTimeInterval(1))
        // flow.clear: the store is empty again.
        let cleared = meter.sample(up: 0, down: 0, at: t0.addingTimeInterval(1.5))
        #expect(cleared == .zero)
        let next = meter.sample(up: 500, down: 1_500, at: t0.addingTimeInterval(2))
        #expect(next == ThroughputMeter.Rate(up: 1_000, down: 3_000))
    }

    @Test func sameInstantIsZeroNotDivisionByZero() {
        var meter = ThroughputMeter(window: 3)
        _ = meter.sample(up: 0, down: 0, at: t0)
        #expect(meter.sample(up: 999, down: 999, at: t0) == .zero)
    }

    @Test func resetForgetsTheBaseline() {
        var meter = ThroughputMeter(window: 3)
        _ = meter.sample(up: 0, down: 0, at: t0)
        meter.reset()
        #expect(meter.sample(up: 5_000, down: 5_000, at: t0.addingTimeInterval(1)) == .zero)
    }
}
