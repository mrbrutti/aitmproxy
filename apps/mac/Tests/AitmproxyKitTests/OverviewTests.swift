import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct OverviewTests {
    @Test func countsTheFixtureSession() {
        let stats = OverviewStats(rows: Fixtures.rows)
        #expect(stats.flows == 14)
        #expect(stats.hosts == 4)
        #expect(stats.clients == 5)
        #expect(stats.paused == 2)
        // One 502, one killed, nothing failed.
        #expect(stats.errors == 2)
        #expect(stats.requestBytes == 11_837)
        #expect(stats.responseBytes == 52_952)
    }

    @Test func splitsStatusClassesInOrderThenNone() {
        let stats = OverviewStats(rows: Fixtures.rows)
        #expect(stats.statusClasses.map(\.statusClass) == [.informational, .success, .redirect, .clientError, .serverError, nil])
        // 101 · 200×5 + 204 · 304 · 422 · 502 · killed + 2 paused + pending.
        #expect(stats.statusClasses.map(\.count) == [1, 6, 1, 1, 1, 4])
        #expect(stats.statusClasses.map(\.count).reduce(0, +) == stats.flows)
        #expect(stats.statusMax == 6)
    }

    @Test func ranksTopHostsByCountThenName() {
        let stats = OverviewStats(rows: Fixtures.rows)
        #expect(stats.topHosts.map(\.host) == [
            "api.shop-staging.test", "cdn.shop-staging.test", "auth.shop-staging.test", "telemetry.vendor-analytics.example",
        ])
        #expect(stats.topHosts.map(\.count) == [10, 2, 1, 1])
        #expect(stats.hostMax == 10)
        var many = Fixtures.rows
        for i in 0..<10 {
            var row = Fixtures.rows[0].withID("host-\(i)", seq: 100 + i)
            row.authority = "h\(i).test"
            many.append(row)
        }
        #expect(OverviewStats(rows: many).topHosts.count == OverviewStats.topHostLimit)
    }

    @Test func percentilesUseNearestRankOverCompletedFlows() throws {
        // Completed with a duration: 21 25 67 89 121 143 149 412 1210 ms (the WS flow and the
        // paused / pending / killed rows have none).
        let p = try #require(OverviewStats(rows: Fixtures.rows).percentiles)
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
        #expect(OverviewStats(rows: [Fixtures.rows[0]]).percentiles == nil)
        // A pending row with a duration is not complete, so it does not count.
        var pending = Fixtures.rows[0].withID("pending", seq: 99)
        pending.state = .pending
        pending.duration = .milliseconds(5)
        #expect(OverviewStats(rows: [Fixtures.rows[0], pending]).percentiles == nil)
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
    static var details: [FlowID: FlowDetail] {
        Dictionary(uniqueKeysWithValues: Fixtures.rows.map { ($0.id, Fixtures.detail(for: $0)) })
    }

    @Test func derivesOneRecordPerClientPortAndHostInTimeOrder() {
        let records = ConnectionRecord.derive(rows: Fixtures.rows, details: Self.details)
        // Every fixture row has its own client port, so records are 1:1 with rows.
        #expect(records.count == Fixtures.rows.count)
        #expect(records.map(\.at) == records.map(\.at).sorted())
        #expect(records.map(\.flowIDs) == Fixtures.rows.map { [$0.id] })
        let first = records[0]
        #expect(first.client == "127.0.0.1:52041")
        #expect(first.authority == "api.shop-staging.test")
        #expect(first.tls == "TLS 1.3")
        #expect(first.alpn == "h2")
        #expect(first.sni == "api.shop-staging.test")
        #expect(first.result == .ok)
        #expect(first.id == "127.0.0.1:52041 api.shop-staging.test")
    }

    @Test func fiveHundredsAndFailuresAreErrors() {
        let records = ConnectionRecord.derive(rows: Fixtures.rows, details: Self.details)
        let errors = records.filter(\.result.isError)
        #expect(errors.count == 1)
        #expect(errors.first?.result == .error("502 Bad Gateway"))
        #expect(errors.first?.result.text == "502 Bad Gateway")
        #expect(errors.first?.flowIDs == [Fixtures.rows[4].id])
        var failed = Fixtures.rows[0].withID("failed", seq: 90)
        failed.state = .failed
        failed.status = nil
        #expect(ConnectionRecord.derive(rows: [failed], details: [:]).first?.result == .error("failed"))
    }

    @Test func tunnelledConnectionsShowNoTLS() {
        let records = ConnectionRecord.derive(rows: Fixtures.rows, details: Self.details)
        let tunnelled = records.first { $0.authority == "telemetry.vendor-analytics.example" }
        #expect(tunnelled?.tls == nil)
        #expect(tunnelled?.alpn == nil)
        #expect(tunnelled?.sni == "telemetry.vendor-analytics.example")
    }

    @Test func flowsOnOneConnectionShareARecord() {
        let a = Fixtures.rows[0]
        let b = Fixtures.rows[4].withID("second", seq: 2)
        let shared = ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                    sni: "api.shop-staging.test", clientAddress: "127.0.0.1:60000")
        var detailA = Fixtures.detail(for: a); detailA.connection = shared
        var detailB = Fixtures.detail(for: b); detailB.connection = shared
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
