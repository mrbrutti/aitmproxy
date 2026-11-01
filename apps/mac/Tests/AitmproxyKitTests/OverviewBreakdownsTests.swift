import Foundation
import Testing
@testable import AitmproxyKit

/// The Overview's lower half over the sample rows (HTTP/WS rows plus L4 rows).
@Suite struct OverviewBreakdownsTests {
    static let rows = Fixtures.rows + Fixtures.l4Rows
    static let breakdowns = OverviewBreakdowns(rows: rows)

    @Test func httpOnlyDropsTheL4Sockets() {
        let http = OverviewBreakdowns.httpOnly(Self.rows)
        // httpOnly drops exactly the L4 rows, whatever the sample set's size.
        #expect(http.count == Self.rows.count - Fixtures.l4Rows.count)
        #expect(http.allSatisfy { $0.l4 == nil })
        // The tiles built over it read HTTP/WS only: 4 hosts, not 4 + the L4 targets.
        let stats = OverviewStats(rows: http)
        #expect(stats.flows == http.count)
        #expect(stats.hosts == 4)
        #expect(OverviewStats(rows: Self.rows).hosts == 7)
    }

    @Test func countsMethodsMostFirstThenByLabel() {
        let b = Self.breakdowns
        // GET ×7, POST ×2, then DELETE · HEAD · PATCH · PUT · WS once each; the L4 rows' `L4` pseudo-method is absent.
        #expect(b.methods.map(\.method) == [.get, .post, .delete, .head, .patch, .put, .ws])
        #expect(b.methods.map(\.count) == [7, 2, 1, 1, 1, 1, 1])
        #expect(b.methods.map(\.count).reduce(0, +) == 14)
        #expect(b.methodMax == 7)
    }

    @Test func countsClientsMostFirstThenByName() {
        let b = Self.breakdowns
        #expect(b.clients.map(\.name) == ["obscura", "curl", "aitm", "python3", "Safari"])
        #expect(b.clients.map(\.count) == [6, 3, 2, 2, 1])
        #expect(b.clientMax == 6)
        // L4 rows carry no client and add nothing.
        #expect(OverviewBreakdowns(rows: Fixtures.l4Rows).clients.isEmpty)
    }

    @Test func listsL4SessionsInCaptureOrder() {
        let b = Self.breakdowns
        #expect(b.l4Sessions.map(\.seq) == [60, 61, 62])
        #expect(b.l4Preview.count == 3)
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[0]) == "UDP · lo0 · udp port 9 · 4 pkt")
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[1]) == "TCP · en0 · tcp port 80 · 2 pkt")
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[2]) == "UDP · lo0 · 1 pkt")
        // The preview is capped; the section says "and n more".
        var many = Fixtures.l4Rows
        many.append(Fixtures.l4Rows[0].withID("l4-extra", seq: 63))
        let capped = OverviewBreakdowns(rows: many)
        #expect(capped.l4Sessions.count == 4)
        #expect(capped.l4Preview.map(\.seq) == [60, 61, 62])
    }

    @Test func slowestAreCompletedFlowsByDuration() {
        // Completed with a duration: 1210 (45) · 412 (46) · 149 (48) · 143 (44) · 121 (53) · 89 · 67 · 25 · 21.
        #expect(Self.breakdowns.slowest.map(\.seq) == [45, 46, 48, 44, 53])
        #expect(Self.breakdowns.slowest.first?.duration == .milliseconds(1210))
    }

    @Test func recentErrorsAreNewestFirst() {
        // 422 at 36.694 s (53), 502 at 5.77 s (45); the killed and paused rows are not errors here.
        #expect(Self.breakdowns.recentErrors.map(\.seq) == [53, 45])
        var failed = Fixtures.rows[0].withID("failed", seq: 90)
        failed.state = .failed
        failed.status = nil
        failed.startedAt = Fixtures.rows[12].startedAt?.addingTimeInterval(1)
        let withFailure = OverviewBreakdowns(rows: Fixtures.rows + [failed])
        #expect(withFailure.recentErrors.map(\.seq) == [90, 53, 45])
    }

    @Test func largestResponsesSkipEmptyAndUnknownBodies() {
        // 22.7 KB (46) · 18.2 KB (41) · 9.3 KB (48) · 1.9 KB (45) · 640 B (42); 0 B and nil are skipped.
        #expect(Self.breakdowns.largest.map(\.seq) == [46, 41, 48, 45, 42])
        #expect(Self.breakdowns.largest.map(\.responseBytes) == [22_700, 18_200, 9_300, 1_900, 640])
    }

    @Test func emptySessionIsEmptyEverywhere() {
        let b = OverviewBreakdowns(rows: [])
        #expect(b.methods.isEmpty)
        #expect(b.clients.isEmpty)
        #expect(b.l4Sessions.isEmpty)
        #expect(b.slowest.isEmpty)
        #expect(b.recentErrors.isEmpty)
        #expect(b.largest.isEmpty)
        #expect(b.methodMax == 0)
        #expect(b.clientMax == 0)
    }
}
