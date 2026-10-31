import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct FlowSortTests {
    let rows = Fixtures.rows

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
