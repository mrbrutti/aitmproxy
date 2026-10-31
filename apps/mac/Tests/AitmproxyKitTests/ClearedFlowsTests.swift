import Foundation
import Testing
@testable import AitmproxyKit

/// Clear with Undo: the restored rows lead, newer rows follow with monotonic `#`.
@Suite struct ClearedFlowsTests {
    static let restored = Array(Fixtures.rows.prefix(3))  // seq 41, 42, 43

    private func row(_ id: String, seq: Int) -> FlowRow { Fixtures.rows[0].withID(id, seq: seq) }

    @Test func restoredRowsLeadAndNewerRowsRenumber() {
        let newer = [row("n1", seq: 1), row("n2", seq: 2)]
        let merged = ClearedFlows.merge(restored: Self.restored, newer: newer)
        #expect(merged.map(\.seq) == [41, 42, 43, 44, 45])
        #expect(merged.map(\.id.raw) == Self.restored.map(\.id.raw) + ["n1", "n2"])
    }

    @Test func nothingRestoredLeavesTheListAlone() {
        let newer = [row("n1", seq: 1)]
        #expect(ClearedFlows.merge(restored: [], newer: newer) == newer)
    }

    @Test func nothingNewerKeepsTheRestoredRows() {
        #expect(ClearedFlows.merge(restored: Self.restored, newer: []) == Self.restored)
    }

    @Test func aNewerRowWithARestoredIDIsDropped() {
        let duplicate = row(Self.restored[1].id.raw, seq: 1)
        let merged = ClearedFlows.merge(restored: Self.restored, newer: [duplicate, row("n2", seq: 2)])
        #expect(merged.map(\.seq) == [41, 42, 43, 44])
        #expect(merged.last?.id.raw == "n2")
    }

    @Test func noticeTextCountsFlows() {
        #expect(ClearNotice(count: 1).text == "Cleared 1 flow")
        #expect(ClearNotice(count: 17).text == "Cleared 17 flows")
        #expect(ClearedFlows(rows: Self.restored).count == 3)
    }
}
