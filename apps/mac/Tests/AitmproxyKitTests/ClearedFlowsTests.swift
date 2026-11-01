import Foundation
import Testing
@testable import AitmproxyKit

/// Clear with Undo: the restored rows lead, newer rows follow with monotonic `#`.
@Suite struct ClearedFlowsTests {
    /// The three rows Clear dropped, `#` 1–3.
    static let restored = [
        Make.row(id: "r1", seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200),
        Make.row(id: "r2", seq: 2, method: .put, host: "api.shop-staging.test", path: "/api/cart/items/42", status: 200),
        Make.row(id: "r3", seq: 3, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304),
    ]

    /// A row that arrived after the clear.
    private func row(_ id: String, seq: Int) -> FlowRow {
        Make.row(id: id, seq: seq, host: "api.shop-staging.test", path: "/api/me", status: 200)
    }

    @Test func restoredRowsLeadAndNewerRowsRenumber() {
        let newer = [row("n1", seq: 1), row("n2", seq: 2)]
        let merged = ClearedFlows.merge(restored: Self.restored, newer: newer)
        #expect(merged.map(\.seq) == [1, 2, 3, 4, 5])
        #expect(merged.map(\.id.raw) == ["r1", "r2", "r3", "n1", "n2"])
    }

    @Test func nothingRestoredLeavesTheListAlone() {
        let newer = [row("n1", seq: 1)]
        #expect(ClearedFlows.merge(restored: [], newer: newer) == newer)
    }

    @Test func nothingNewerKeepsTheRestoredRows() {
        #expect(ClearedFlows.merge(restored: Self.restored, newer: []) == Self.restored)
    }

    @Test func aNewerRowWithARestoredIDIsDropped() {
        let duplicate = row("r2", seq: 1)
        let merged = ClearedFlows.merge(restored: Self.restored, newer: [duplicate, row("n2", seq: 2)])
        #expect(merged.map(\.seq) == [1, 2, 3, 4])
        #expect(merged.last?.id.raw == "n2")
    }

    @Test func noticeTextCountsFlows() {
        #expect(ClearNotice(count: 1).text == "Cleared 1 flow")
        #expect(ClearNotice(count: 17).text == "Cleared 17 flows")
        #expect(ClearedFlows(rows: Self.restored).count == 3)
    }
}
