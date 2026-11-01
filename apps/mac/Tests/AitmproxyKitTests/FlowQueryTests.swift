import Testing
@testable import AitmproxyKit

/// `FlowQuery` on the sample rows: scope, group, chip, filter, sort and pins.
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

    @Test func pinnedQueryNarrowsToPinnedHostsAndApps() {
        let pins = Pins(hosts: ["auth.shop-staging.test"], apps: ["curl"])
        let rows = FlowQuery(pins: pins).apply(Fixtures.rows + Fixtures.l4Rows, details: [:])
        // curl's three flows (45, 49, 50) plus the auth host (50, already in): capture order.
        #expect(rows.map(\.seq) == [45, 49, 50])
        #expect(FlowQuery(pins: Pins()).apply(Fixtures.rows, details: [:]).isEmpty)
    }
}
