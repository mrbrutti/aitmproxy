import Testing
@testable import AitmproxyKit

/// The self-test's count checks, replayed on the Kit value.
@Suite struct FlowQueryTests {
    let rows = Fixtures.rows
    let details = Dictionary(uniqueKeysWithValues: Fixtures.rows.map { ($0.id, Fixtures.detail(for: $0)) })

    @Test func emptyQueryIsIdentity() {
        #expect(FlowQuery().apply(rows, details: details) == rows)
        #expect(!FlowQuery().isNarrowing)
    }

    @Test func scopeGroupAndChip() {
        #expect(FlowQuery(inScopeOnly: true).apply(rows, details: details).count == 13)
        #expect(FlowQuery(group: .client("curl")).apply(rows, details: details).count == 3)
        #expect(FlowQuery(group: .host("cdn.shop-staging.test")).apply(rows, details: details).map(\.seq) == [43, 52])
        #expect(FlowQuery(chip: .websocket).apply(rows, details: details).map(\.seq) == [47])
        let json = FlowQuery(chip: .json).apply(rows, details: details)
        #expect(!json.isEmpty && json.count < rows.count)
    }

    @Test func filterAndSortCompose() throws {
        let expr = try FilterExpression.parse("~m POST | ~c 502")
        let q = FlowQuery(filter: expr, sort: FlowSort(key: .status, ascending: false))
        #expect(q.apply(rows, details: details).map(\.seq) == [45, 44, 50])
        let compiled = q.compiled()
        #expect(compiled.apply(rows, details: details).count == 3)
        #expect(q.isNarrowing)
    }
}
