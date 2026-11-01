import Foundation
import Testing
@testable import AitmproxyKit

/// Eight rows for `OverviewTests` and `ConnectionRecordTests`: four hosts (one tunnelled and
/// out of scope), four clients, a status in every class plus three rows with none, five
/// completed durations, and one detail per row with its own client port.
private enum OverviewInputs {
    static let obscura = ClientInfo(name: "obscura")
    static let curl = ClientInfo(name: "curl")
    static let safari = ClientInfo(name: "Safari")
    static let python = ClientInfo(name: "python3")

    /// Capture time: `at(n)` is `n` seconds after a fixed instant.
    static func at(_ seconds: Double) -> Date { Date(timeIntervalSince1970: 1_793_185_498 + seconds) }

    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200, client: obscura,
                 startedAt: at(0), duration: .milliseconds(89), requestBytes: 412, responseBytes: 18_200),
        Make.row(seq: 2, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304, client: obscura,
                 startedAt: at(1), duration: .milliseconds(21), requestBytes: 388, responseBytes: 0),
        Make.row(seq: 3, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 client: safari, startedAt: at(2), duration: .milliseconds(143), requestBytes: 6_400, responseBytes: 0,
                 tls: .tunnelled, inScope: false),
        Make.row(seq: 4, host: "api.shop-staging.test", path: "/api/orders", status: 502, client: curl,
                 startedAt: at(3), duration: .milliseconds(1_210), requestBytes: 402, responseBytes: 1_900),
        Make.row(seq: 5, kind: .websocket, method: .ws, scheme: "wss", host: "api.shop-staging.test",
                 path: "/ws/notifications", status: 101, client: obscura, startedAt: at(4)),
        Make.row(seq: 6, method: .delete, host: "api.shop-staging.test", path: "/api/account/delete", state: .killed,
                 client: curl, startedAt: at(5), requestBytes: 298),
        Make.row(seq: 7, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused,
                 client: curl, startedAt: at(6), requestBytes: 186),
        Make.row(seq: 8, method: .patch, host: "api.shop-staging.test", path: "/api/cart", status: 422, client: python,
                 startedAt: at(7), duration: .milliseconds(121), requestBytes: 903, responseBytes: 212),
    ]

    /// A row's detail: a bare request, a response when the row has a status, and the TLS 1.3 /
    /// h2 connection it arrived on from `clientPort`.
    static func detail(_ row: FlowRow, clientPort: Int) -> FlowDetail {
        Make.detail(
            id: row.id.raw,
            request: Make.message("\(row.method.label) \(row.path) HTTP/2", [("host", row.authority)]),
            response: row.status.map { Make.response($0, [("server", "envoy")]) },
            connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2", sni: row.authority,
                                       clientAddress: "127.0.0.1:\(clientPort)", serverAddress: "10.0.4.12:443"))
    }

    /// Every row on its own client port, 52001 … 52008.
    static let details: [FlowID: FlowDetail] = Dictionary(uniqueKeysWithValues: [
        detail(rows[0], clientPort: 52_001), detail(rows[1], clientPort: 52_002), detail(rows[2], clientPort: 52_003),
        detail(rows[3], clientPort: 52_004), detail(rows[4], clientPort: 52_005), detail(rows[5], clientPort: 52_006),
        detail(rows[6], clientPort: 52_007), detail(rows[7], clientPort: 52_008),
    ].map { ($0.id, $0) })
}

@Suite struct OverviewTests {
    @Test func countsTheSession() {
        let stats = OverviewStats(rows: OverviewInputs.rows)
        #expect(stats.flows == 8)
        #expect(stats.hosts == 4)
        #expect(stats.clients == 4)
        #expect(stats.paused == 1)
        // One 502, one killed, nothing failed.
        #expect(stats.errors == 2)
        // 412 + 388 + 6 400 + 402 + 298 + 186 + 903; the WebSocket row reports no sizes.
        #expect(stats.requestBytes == 8_989)
        // 18 200 + 1 900 + 212; the 304 and 204 are empty, the rest have no response yet.
        #expect(stats.responseBytes == 20_312)
    }

    @Test func splitsStatusClassesInOrderThenNone() {
        let stats = OverviewStats(rows: OverviewInputs.rows)
        #expect(stats.statusClasses.map(\.statusClass) == [.informational, .success, .redirect, .clientError, .serverError, nil])
        // 101 · 200 + 204 · 304 · 422 · 502 · killed + paused.
        #expect(stats.statusClasses.map(\.count) == [1, 2, 1, 1, 1, 2])
        #expect(stats.statusClasses.map(\.count).reduce(0, +) == stats.flows)
        #expect(stats.statusMax == 2)
    }

    @Test func ranksTopHostsByCountThenName() {
        let stats = OverviewStats(rows: OverviewInputs.rows)
        // api five times; the other three once each, so they rank by name.
        #expect(stats.topHosts.map(\.host) == [
            "api.shop-staging.test", "auth.shop-staging.test", "cdn.shop-staging.test", "telemetry.vendor-analytics.example",
        ])
        #expect(stats.topHosts.map(\.count) == [5, 1, 1, 1])
        #expect(stats.hostMax == 5)
        var many = OverviewInputs.rows
        for i in 0..<10 {
            var row = OverviewInputs.rows[0].withID("host-\(i)", seq: 100 + i)
            row.authority = "h\(i).test"
            many.append(row)
        }
        #expect(OverviewStats(rows: many).topHosts.count == OverviewStats.topHostLimit)
    }

    @Test func percentilesUseNearestRankOverCompletedFlows() throws {
        // Completed with a duration: 21 89 121 143 1210 ms (the WebSocket flow and the
        // paused / killed rows have none).
        let p = try #require(OverviewStats(rows: OverviewInputs.rows).percentiles)
        #expect(p.p50 == .milliseconds(121))
        #expect(p.p90 == .milliseconds(1210))
        #expect(p.p99 == .milliseconds(1210))
        let sorted: [Duration] = [.milliseconds(10), .milliseconds(20), .milliseconds(30), .milliseconds(40)]
        #expect(OverviewStats.nearestRank(sorted, 50) == .milliseconds(20))
        #expect(OverviewStats.nearestRank(sorted, 90) == .milliseconds(40))
        #expect(OverviewStats.nearestRank(sorted, 1) == .milliseconds(10))
    }

    @Test func fewerThanTwoDurationsGiveNoPercentiles() {
        #expect(OverviewStats(rows: []).percentiles == nil)
        #expect(OverviewStats(rows: [OverviewInputs.rows[0]]).percentiles == nil)
        // A pending row with a duration is not complete, so it does not count.
        var pending = OverviewInputs.rows[0].withID("pending", seq: 99)
        pending.state = .pending
        pending.duration = .milliseconds(5)
        #expect(OverviewStats(rows: [OverviewInputs.rows[0], pending]).percentiles == nil)
    }

    @Test func emptySessionReadsZero() {
        let stats = OverviewStats(rows: [])
        #expect(stats.flows == 0)
        #expect(stats.hosts == 0)
        #expect(stats.clients == 0)
        #expect(stats.errors == 0)
        #expect(stats.requestBytes == 0)
        #expect(stats.statusClasses.map(\.count) == [0, 0, 0, 0, 0, 0])
        #expect(stats.topHosts.isEmpty)
    }

    @Test func rangeLabels() {
        #expect(StatusClass.informational.rangeLabel == "1xx")
        #expect(StatusClass.serverError.rangeLabel == "5xx")
    }
}

@Suite struct ConnectionRecordTests {
    let rows = OverviewInputs.rows
    let details = OverviewInputs.details

    @Test func derivesOneRecordPerClientPortAndHostInTimeOrder() {
        let records = ConnectionRecord.derive(rows: rows, details: details)
        // Every row has its own client port, so records are 1:1 with rows.
        #expect(records.count == rows.count)
        #expect(records.map(\.at) == records.map(\.at).sorted())
        #expect(records.map(\.flowIDs) == rows.map { [$0.id] })
        let first = records[0]
        #expect(first.client == "127.0.0.1:52001")
        #expect(first.authority == "api.shop-staging.test")
        #expect(first.tls == "TLS 1.3")
        #expect(first.alpn == "h2")
        #expect(first.sni == "api.shop-staging.test")
        #expect(first.result == .ok)
        #expect(first.id == "127.0.0.1:52001 api.shop-staging.test")
    }

    @Test func fiveHundredsAndFailuresAreErrors() {
        let records = ConnectionRecord.derive(rows: rows, details: details)
        let errors = records.filter(\.result.isError)
        #expect(errors.count == 1)
        #expect(errors.first?.result == .error("502 Bad Gateway"))
        #expect(errors.first?.result.text == "502 Bad Gateway")
        #expect(errors.first?.flowIDs == [rows[3].id])
        var failed = rows[0].withID("failed", seq: 90)
        failed.state = .failed
        failed.status = nil
        #expect(ConnectionRecord.derive(rows: [failed], details: [:]).first?.result == .error("failed"))
    }

    @Test func tunnelledConnectionsShowNoTLS() {
        let records = ConnectionRecord.derive(rows: rows, details: details)
        let tunnelled = records.first { $0.authority == "telemetry.vendor-analytics.example" }
        #expect(tunnelled?.tls == nil)
        #expect(tunnelled?.alpn == nil)
        #expect(tunnelled?.sni == "telemetry.vendor-analytics.example")
    }

    @Test func flowsOnOneConnectionShareARecord() throws {
        let a = rows[0]
        let b = rows[3].withID("second", seq: 2)
        let shared = ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                    sni: "api.shop-staging.test", clientAddress: "127.0.0.1:60000")
        var detailA = try #require(details[a.id]); detailA.connection = shared
        var detailB = try #require(details[rows[3].id]); detailB.id = b.id; detailB.connection = shared
        let records = ConnectionRecord.derive(rows: [a, b], details: [a.id: detailA, b.id: detailB])
        #expect(records.count == 1)
        #expect(records[0].flowIDs == [a.id, b.id])
        #expect(records[0].result == .error("502 Bad Gateway"))
        #expect(records[0].at == a.startedAt)
        // Missing detail: the client reads as a dash, the record still exists.
        #expect(ConnectionRecord.derive(rows: [a], details: [:]).first?.client == Format.dash)
        #expect(ConnectionRecord.derive(rows: [], details: [:]).isEmpty)
    }
}
