import Foundation
import Testing
@testable import AitmproxyKit

/// Ten HTTP/WS rows and three raw-L4 sessions for `OverviewBreakdownsTests`: five methods,
/// five clients with two ties on the count, eight completed durations, two error statuses
/// and five non-empty responses.
private enum OverviewBreakdownInputs {
    static let obscura = ClientInfo(name: "obscura")
    static let curl = ClientInfo(name: "curl")
    static let safari = ClientInfo(name: "Safari")
    static let python = ClientInfo(name: "python3")
    static let aitm = ClientInfo(name: "aitm")

    /// Capture time: `at(n)` is `n` seconds after a fixed instant.
    static func at(_ seconds: Double) -> Date { Date(timeIntervalSince1970: 1_793_185_498 + seconds) }

    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200, client: obscura,
                 startedAt: at(0), duration: .milliseconds(89), requestBytes: 412, responseBytes: 18_200),
        Make.row(seq: 2, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304, client: obscura,
                 startedAt: at(2), duration: .milliseconds(21), requestBytes: 388, responseBytes: 0),
        Make.row(seq: 3, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 client: safari, startedAt: at(3), duration: .milliseconds(143), requestBytes: 6_400, responseBytes: 0,
                 tls: .tunnelled, inScope: false),
        Make.row(seq: 4, host: "api.shop-staging.test", path: "/api/orders", status: 502, client: curl,
                 startedAt: at(5), duration: .milliseconds(1_210), requestBytes: 402, responseBytes: 1_900),
        Make.row(seq: 5, host: "api.shop-staging.test", path: "/api/orders", status: 200, isReplay: true, origin: .agent,
                 client: aitm, startedAt: at(6), duration: .milliseconds(412), requestBytes: 402, responseBytes: 22_700),
        Make.row(seq: 6, host: "api.shop-staging.test", path: "/api/search", status: 200, origin: .agent, client: aitm,
                 startedAt: at(15), duration: .milliseconds(149), requestBytes: 511, responseBytes: 9_300),
        Make.row(seq: 7, method: .delete, host: "api.shop-staging.test", path: "/api/account/delete", state: .killed,
                 client: curl, startedAt: at(21), requestBytes: 298),
        Make.row(seq: 8, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused,
                 client: curl, startedAt: at(25), requestBytes: 186),
        Make.row(seq: 9, method: .patch, host: "api.shop-staging.test", path: "/api/cart", status: 422, client: python,
                 startedAt: at(36), duration: .milliseconds(121), requestBytes: 903, responseBytes: 212),
        Make.row(seq: 10, method: .head, host: "api.shop-staging.test", path: "/api/health", status: 200, client: python,
                 startedAt: at(37), duration: .milliseconds(25), requestBytes: 120, responseBytes: 0),
    ]

    /// Three L4 sessions: a loopback UDP capture with one injected packet, a TCP capture on
    /// en0, and a crafted UDP packet with no filter.
    static let l4Flows: [L4Flow] = [
        L4Flow(id: FlowID("l4-1"), sessionState: .capture, interface: "lo0", filter: "udp port 9", packetCount: 4,
               injectedCount: 1,
               packets: [L4Packet(index: 0, dir: .outbound, length: 42, injected: false, layers: ["IPv4", "UDP"])]),
        L4Flow(id: FlowID("l4-2"), sessionState: .capture, interface: "en0", filter: "tcp port 80", packetCount: 2,
               injectedCount: 0,
               packets: [L4Packet(index: 0, dir: .outbound, length: 60, injected: false, layers: ["IPv4", "TCP"])]),
        L4Flow(id: FlowID("l4-3"), sessionState: .craft, interface: "lo0", packetCount: 1, injectedCount: 1,
               packets: [L4Packet(index: 0, dir: .outbound, length: 46, injected: true, layers: ["IPv4", "UDP"])]),
    ]

    /// The sessions as flow-list rows, `#` 11–13.
    static let l4Rows: [FlowRow] = l4Flows.enumerated().map { $0.element.row(seq: 11 + $0.offset, inScope: true) }
}

/// The Overview's lower half over HTTP/WS rows plus L4 rows.
@Suite struct OverviewBreakdownsTests {
    static let rows = OverviewBreakdownInputs.rows + OverviewBreakdownInputs.l4Rows
    static let breakdowns = OverviewBreakdowns(rows: rows)

    @Test func httpOnlyDropsTheL4Sockets() {
        let http = OverviewBreakdowns.httpOnly(Self.rows)
        // httpOnly drops exactly the three L4 rows.
        #expect(http.count == 10)
        #expect(http.allSatisfy { $0.l4 == nil })
        // The tiles built over it read HTTP/WS only: 4 hosts, not 4 + the 3 L4 targets.
        let stats = OverviewStats(rows: http)
        #expect(stats.flows == 10)
        #expect(stats.hosts == 4)
        #expect(OverviewStats(rows: Self.rows).hosts == 7)
    }

    @Test func countsMethodsMostFirstThenByLabel() {
        let b = Self.breakdowns
        // GET ×5, POST ×2, then DELETE · HEAD · PATCH once each; the L4 rows' `L4` pseudo-method is absent.
        #expect(b.methods.map(\.method) == [.get, .post, .delete, .head, .patch])
        #expect(b.methods.map(\.count) == [5, 2, 1, 1, 1])
        #expect(b.methods.map(\.count).reduce(0, +) == 10)
        #expect(b.methodMax == 5)
    }

    @Test func countsClientsMostFirstThenByName() {
        let b = Self.breakdowns
        // curl ×3; aitm, obscura and python3 ×2 each, ranked by name; Safari once.
        #expect(b.clients.map(\.name) == ["curl", "aitm", "obscura", "python3", "Safari"])
        #expect(b.clients.map(\.count) == [3, 2, 2, 2, 1])
        #expect(b.clientMax == 3)
        // L4 rows carry no client and add nothing.
        #expect(OverviewBreakdowns(rows: OverviewBreakdownInputs.l4Rows).clients.isEmpty)
    }

    @Test func listsL4SessionsInCaptureOrder() {
        let b = Self.breakdowns
        #expect(b.l4Sessions.map(\.seq) == [11, 12, 13])
        #expect(b.l4Preview.count == 3)
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[0]) == "UDP · lo0 · udp port 9 · 4 pkt")
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[1]) == "TCP · en0 · tcp port 80 · 2 pkt")
        #expect(OverviewBreakdowns.l4Summary(b.l4Sessions[2]) == "UDP · lo0 · 1 pkt")
        // The preview is capped; the section says "and n more".
        var many = OverviewBreakdownInputs.l4Rows
        many.append(OverviewBreakdownInputs.l4Rows[0].withID("l4-extra", seq: 14))
        let capped = OverviewBreakdowns(rows: many)
        #expect(capped.l4Sessions.count == 4)
        #expect(capped.l4Preview.map(\.seq) == [11, 12, 13])
    }

    @Test func slowestAreCompletedFlowsByDuration() {
        // Completed with a duration: 1210 (4) · 412 (5) · 149 (6) · 143 (3) · 121 (9) · 89 · 25 · 21.
        #expect(Self.breakdowns.slowest.map(\.seq) == [4, 5, 6, 3, 9])
        #expect(Self.breakdowns.slowest.first?.duration == .milliseconds(1210))
    }

    @Test func recentErrorsAreNewestFirst() {
        // 422 at 36 s (9), 502 at 5 s (4); the killed and paused rows are not errors here.
        #expect(Self.breakdowns.recentErrors.map(\.seq) == [9, 4])
        var failed = OverviewBreakdownInputs.rows[0].withID("failed", seq: 90)
        failed.state = .failed
        failed.status = nil
        failed.startedAt = OverviewBreakdownInputs.at(38)
        let withFailure = OverviewBreakdowns(rows: OverviewBreakdownInputs.rows + [failed])
        #expect(withFailure.recentErrors.map(\.seq) == [90, 9, 4])
    }

    @Test func largestResponsesSkipEmptyAndUnknownBodies() {
        // 22.7 KB (5) · 18.2 KB (1) · 9.3 KB (6) · 1.9 KB (4) · 212 B (9); 0 B and nil are skipped.
        #expect(Self.breakdowns.largest.map(\.seq) == [5, 1, 6, 4, 9])
        #expect(Self.breakdowns.largest.map(\.responseBytes) == [22_700, 18_200, 9_300, 1_900, 212])
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
