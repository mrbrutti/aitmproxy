import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Task 8 (spec C4): the embedded core's status maps to a three-state health
/// dot (running / restarting / failed) and the captured stdout/stderr feeds a
/// bounded log buffer. Both are pure, so the view stays thin and testable.
@Suite struct CoreHealthTests {
    private func endpoint() -> BusEndpoint { BusEndpoint(port: 0, token: "") }

    @Test func statusMapsToThreeHealthStates() {
        #expect(CoreHealth(.ready) == .running)
        #expect(CoreHealth(.starting) == .restarting)
        #expect(CoreHealth(.connecting) == .restarting)
        #expect(CoreHealth(.degraded(reason: "boom")) == .failed)
        #expect(CoreHealth(.stopped) == .failed)
    }

    @Test func everyHealthStateHasAWord() {
        #expect(CoreHealth.running.statusWord == "core running")
        #expect(CoreHealth.restarting.statusWord == "restarting…")
        #expect(CoreHealth.failed.statusWord == "core failed")
    }

    @Test func statusTitleIsPreciseWhereHealthIsCoarse() {
        // The dot's colour buckets .starting and .connecting both into
        // `.restarting`, but the word stays honest: a first launch is not a restart.
        #expect(CoreConnection.Status.starting.healthTitle == "Starting")
        #expect(CoreConnection.Status.connecting.healthTitle == "Connecting")
        #expect(CoreConnection.Status.ready.healthTitle == "Running")
        #expect(CoreConnection.Status.degraded(reason: "x").healthTitle == "Failed")
        #expect(CoreConnection.Status.stopped.healthTitle == "Stopped")
    }

    @Test func degradedReasonIsReadableOnlyWhenDegraded() {
        #expect(CoreConnection.Status.degraded(reason: "port in use").degradedReason == "port in use")
        #expect(CoreConnection.Status.ready.degradedReason == nil)
        #expect(CoreConnection.Status.starting.degradedReason == nil)
    }

    @Test func aConnectionExposesItsHealth() {
        let conn = CoreConnection(kind: .embedded, endpoint: endpoint(), status: .ready, label: "Embedded core")
        #expect(conn.health == .running)
    }

    @Test func logBufferKeepsLinesInOrderWithStableIDs() {
        var buffer = CoreLogBuffer(capacity: 8)
        buffer.append("proxy listening on 127.0.0.1:8080")
        buffer.append("bus ready")
        #expect(buffer.lines.map(\.text) == ["proxy listening on 127.0.0.1:8080", "bus ready"])
        #expect(buffer.lines.map(\.id) == [0, 1])
        #expect(!buffer.isEmpty)
    }

    @Test func logBufferTrimsToCapacityOldestFirst() {
        var buffer = CoreLogBuffer(capacity: 3)
        for n in 0..<5 { buffer.append("line \(n)") }
        #expect(buffer.lines.map(\.text) == ["line 2", "line 3", "line 4"])
        // IDs keep climbing so SwiftUI never reuses one across a trim.
        #expect(buffer.lines.map(\.id) == [2, 3, 4])
    }

    @Test func logBufferClears() {
        var buffer = CoreLogBuffer()
        buffer.append("a")
        buffer.removeAll()
        #expect(buffer.isEmpty)
        // A fresh id continues the sequence after a clear, never collides with a stale row.
        buffer.append("b")
        #expect(buffer.lines.map(\.id) == [1])
    }
}
