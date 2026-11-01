import Foundation
import Testing
@testable import AitmproxyKit

/// Nine rows for `FlowSortTests`: six finished with a status (101 … 502), three with none
/// (killed, paused, pending); a duration and a response size on five of them.
private enum FlowSortInputs {
    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200,
                 duration: .milliseconds(89), responseBytes: 18_200),
        Make.row(seq: 2, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304,
                 duration: .milliseconds(21), responseBytes: 0),
        Make.row(seq: 3, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 duration: .milliseconds(143), responseBytes: 0, inScope: false),
        Make.row(seq: 4, host: "api.shop-staging.test", path: "/api/orders", status: 502,
                 duration: .milliseconds(1_210), responseBytes: 1_900),
        Make.row(seq: 5, host: "api.shop-staging.test", path: "/api/orders", status: 200, isReplay: true,
                 duration: .milliseconds(412), responseBytes: 22_700),
        Make.row(seq: 6, kind: .websocket, method: .ws, scheme: "wss", host: "api.shop-staging.test",
                 path: "/ws/notifications", status: 101),
        Make.row(seq: 7, method: .delete, host: "api.shop-staging.test", path: "/api/account/delete", state: .killed),
        Make.row(seq: 8, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused),
        Make.row(seq: 9, host: "cdn.shop-staging.test", path: "/assets/hero.webp", state: .pending),
    ]
}

@Suite struct FlowSortTests {
    let rows = FlowSortInputs.rows

    @Test func captureOrderIsIdentity() {
        #expect(FlowSort.captureOrder.sorted(rows).map(\.seq) == rows.map(\.seq))
        #expect(FlowSort.captureOrder.isCaptureOrder)
    }

    @Test func statusPutsRowsWithoutACodeLast() {
        let asc = FlowSort(key: .status, ascending: true).sorted(rows)
        #expect(asc.first?.status == 101)
        #expect(asc.suffix(3).allSatisfy { $0.state != .complete })
        let desc = FlowSort(key: .status, ascending: false).sorted(rows)
        #expect(desc.first?.status == 502)
        #expect(desc.suffix(3).allSatisfy { $0.state != .complete })
    }

    @Test func numericColumnsSortNumericallyWithDashesLast() {
        let asc = FlowSort(key: .duration, ascending: true).sorted(rows)
        #expect(asc.first?.duration == .milliseconds(21))
        #expect(asc.last?.duration == nil)
        let desc = FlowSort(key: .response, ascending: false).sorted(rows)
        #expect(desc.first?.responseBytes == 22_700)
        #expect(desc.last?.responseBytes == nil)
    }

    @Test func urlSortsByHostThenPath() {
        let asc = FlowSort(key: .url, ascending: true).sorted(rows)
        #expect(asc.first?.authority == "api.shop-staging.test")
        #expect(asc.first?.path == "/api/account/delete")
        #expect(asc.last?.authority == "telemetry.vendor-analytics.example")
    }

    @Test func sortIsStable() {
        let byMethod = FlowSort(key: .method, ascending: true).sorted(rows)
        let gets = byMethod.filter { $0.method == .get }.map(\.seq)
        #expect(gets == gets.sorted())
    }
}
