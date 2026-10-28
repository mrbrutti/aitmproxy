import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ColumnLayoutTests {
    @Test func unknownIdsAreIgnoredAndMissingOnesAppended() {
        let layout = ColumnLayout(order: ["url", "ghost", "seq"], widths: ["url": 320, "ghost": 50], hidden: ["ghost", "ssl"])
        #expect(layout.resolvedOrder(known: ["dot", "seq", "url", "ssl"]) == ["url", "seq", "dot", "ssl"])
        #expect(layout.width(for: "url", default: 100) == 320)
        #expect(layout.width(for: "seq", default: 52) == 52)
        #expect(layout.isHidden("ssl"))
        #expect(!layout.isHidden("url"))
    }

    @Test func roundTripsThroughAFile() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "columns-\(UUID().uuidString).json")
        let layout = ColumnLayout(order: ["seq", "url"], widths: ["url": 240.5], hidden: ["mark"])
        try layout.save(to: url)
        #expect(ColumnLayout.load(from: url) == layout)
        #expect(ColumnLayout.load(from: url.appendingPathExtension("missing")) == nil)
    }
}

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
