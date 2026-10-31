import Testing
@testable import AitmproxyKit

/// The fixture set is what the snapshots, the self-test and the mockup all show; pin its shape
/// here so a change to it fails loudly in one place instead of drifting the self-test.
@Suite struct FixturesTests {
    @Test func rowCounts() {
        #expect(Fixtures.rows.count == 14)
        #expect(Fixtures.l4Rows.count == 3)
        #expect((Fixtures.rows + Fixtures.l4Rows).filter(\.inScope).count == 15)
    }

    @Test func scriptsActiveCountMatchesThePanelPredicate() {
        // Enabled with an error is not active: the Scripts page and the sidebar must agree.
        #expect(Fixtures.scripts.filter(\.isActive).count == 1)
        #expect(Fixtures.scripts.filter(\.enabled).count == 2)
    }

    @Test func pinnedQueryNarrowsToPinnedHostsAndApps() {
        let pins = Pins(hosts: ["auth.shop-staging.test"], apps: ["curl"])
        let rows = FlowQuery(pins: pins).apply(Fixtures.rows + Fixtures.l4Rows, details: [:])
        #expect(!rows.isEmpty)
        #expect(rows.allSatisfy { $0.authority == "auth.shop-staging.test" || $0.client?.name == "curl" })
        #expect(FlowQuery(pins: Pins()).apply(Fixtures.rows, details: [:]).isEmpty)
    }
}
