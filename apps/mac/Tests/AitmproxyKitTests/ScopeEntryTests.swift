import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ScopeEntryTests {
    @Test func readoutPrintsLimitBurstAndBackoff() {
        let limit = RateLimit(requestsPerSecond: 10, burst: 20, backoffFactor: 2)
        #expect(limit.readout == "10 req/s · burst 20 · back-off 2×")
        #expect(limit.limitText == "10 req/s · burst 20")
        #expect(limit.backoffText == "2×")
    }

    @Test func readoutAppendsTheErrorBudgetAndKeepsFractions() {
        let limit = RateLimit(requestsPerSecond: 0.5, burst: 1, backoffFactor: 1.5, errorBudget: 10)
        #expect(limit.readout == "0.5 req/s · burst 1 · back-off 1.5× · budget 10")
    }

    @Test func countsFlowsPerFixtureHost() {
        let rows = Fixtures.rows
        let counts = Dictionary(uniqueKeysWithValues: Fixtures.scopeEntries.map { ($0.host, $0.flowCount(in: rows)) })
        #expect(counts["api.shop-staging.test"] == 10)
        #expect(counts["auth.shop-staging.test"] == 1)
        #expect(counts["cdn.shop-staging.test"] == 2)
        #expect(counts.values.reduce(0, +) == rows.count - 1, "only the telemetry row is outside the three hosts")
    }

    @Test func wildcardAndPortEntriesCount() {
        let rows = Fixtures.rows
        #expect(ScopeEntry(host: "*.shop-staging.test").flowCount(in: rows) == rows.count - 1)
        #expect(ScopeEntry(host: "api.shop-staging.test:8443").flowCount(in: rows) == 0)
        #expect(ScopeEntry(host: "telemetry.vendor-analytics.example").flowCount(in: rows) == 1)
    }

    @Test func fixturesCoverTheScopeHostsWithLimits() {
        #expect(Fixtures.scopeEntries.map(\.host) == Fixtures.scope)
        #expect(Fixtures.scopeLimits.count == 3)
        #expect(Fixtures.scopeEntries.allSatisfy { $0.limit != nil })
        #expect(Fixtures.scopeEntries.map(\.id) == Fixtures.scope)
    }

    @Test func validationReusesScopeAndRejectsDuplicates() {
        let existing = Fixtures.scope
        #expect(ScopeEntry.validate("new.shop-staging.test", existing: existing) == nil)
        #expect(ScopeEntry.validate("new.shop-staging.test:8443", existing: existing) == nil)
        #expect(ScopeEntry.validate("*.shop-staging.test", existing: existing) == nil)
        #expect(ScopeEntry.validate("https://new.shop-staging.test", existing: existing) == Scope.validate("https://new.shop-staging.test"))
        #expect(ScopeEntry.validate("new.shop-staging.test/path", existing: existing) != nil)
        #expect(ScopeEntry.validate("", existing: existing) != nil)
        #expect(ScopeEntry.validate("  api.shop-staging.test ", existing: existing) == "api.shop-staging.test is already in scope")
    }

    @Test func entriesPairHostsWithKnownLimits() {
        let entries = ScopeEntry.entries(hosts: ["api.shop-staging.test", "other.test"], limits: Fixtures.scopeLimits)
        #expect(entries.count == 2)
        #expect(entries[0].limit?.readout == "10 req/s · burst 20 · back-off 2× · budget 50")
        #expect(entries[1].limit == nil)
    }
}
