import Foundation
import Testing
@testable import AitmproxyKit

/// Inputs for `ScopeEntryTests`: five rows over four hosts (one outside the three scope
/// entries), the entries with their limits, and the bare host list the bus reports.
private enum ScopeEntryInputs {
    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200),
        Make.row(seq: 2, host: "api.shop-staging.test", path: "/api/orders", status: 502),
        Make.row(seq: 3, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused),
        Make.row(seq: 4, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304),
        Make.row(seq: 5, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 inScope: false),
    ]

    static let scope = ["api.shop-staging.test", "auth.shop-staging.test", "cdn.shop-staging.test"]

    /// The three hosts with plausible limits (S-047): the API throttled hard with an error
    /// budget, auth harder still, the CDN loose and budgetless.
    static let entries: [ScopeEntry] = [
        ScopeEntry(host: "api.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 10, burst: 20, backoffFactor: 2, errorBudget: 50)),
        ScopeEntry(host: "auth.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 2, burst: 5, backoffFactor: 4, errorBudget: 10)),
        ScopeEntry(host: "cdn.shop-staging.test",
                   limit: RateLimit(requestsPerSecond: 50, burst: 100, backoffFactor: 1.5)),
    ]

    /// Limits by host, for pairing with the live `scope.list`.
    static let limits: [String: RateLimit] = Dictionary(uniqueKeysWithValues: entries.compactMap { entry in
        entry.limit.map { (entry.host, $0) }
    })
}

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

    @Test func countsFlowsPerHost() {
        let rows = ScopeEntryInputs.rows
        let counts = Dictionary(uniqueKeysWithValues: ScopeEntryInputs.entries.map { ($0.host, $0.flowCount(in: rows)) })
        #expect(counts["api.shop-staging.test"] == 2)
        #expect(counts["auth.shop-staging.test"] == 1)
        #expect(counts["cdn.shop-staging.test"] == 1)
        #expect(counts.values.reduce(0, +) == rows.count - 1, "only the telemetry row is outside the three hosts")
    }

    @Test func wildcardAndPortEntriesCount() {
        let rows = ScopeEntryInputs.rows
        #expect(ScopeEntry(host: "*.shop-staging.test").flowCount(in: rows) == rows.count - 1)
        #expect(ScopeEntry(host: "api.shop-staging.test:8443").flowCount(in: rows) == 0)
        #expect(ScopeEntry(host: "telemetry.vendor-analytics.example").flowCount(in: rows) == 1)
    }

    @Test func entryIDIsItsHost() {
        #expect(ScopeEntryInputs.entries.map(\.id) == ScopeEntryInputs.entries.map(\.host))
        #expect(ScopeEntry(host: "api.shop-staging.test:8443").id == "api.shop-staging.test:8443")
    }

    @Test func validationReusesScopeAndRejectsDuplicates() {
        let existing = ScopeEntryInputs.scope
        #expect(ScopeEntry.validate("new.shop-staging.test", existing: existing) == nil)
        #expect(ScopeEntry.validate("new.shop-staging.test:8443", existing: existing) == nil)
        #expect(ScopeEntry.validate("*.shop-staging.test", existing: existing) == nil)
        #expect(ScopeEntry.validate("https://new.shop-staging.test", existing: existing) == Scope.validate("https://new.shop-staging.test"))
        #expect(ScopeEntry.validate("new.shop-staging.test/path", existing: existing) != nil)
        #expect(ScopeEntry.validate("", existing: existing) != nil)
        #expect(ScopeEntry.validate("  api.shop-staging.test ", existing: existing) == "api.shop-staging.test is already in scope")
    }

    @Test func entriesPairHostsWithKnownLimits() {
        let entries = ScopeEntry.entries(hosts: ["api.shop-staging.test", "other.test"], limits: ScopeEntryInputs.limits)
        #expect(entries.count == 2)
        #expect(entries[0].limit?.readout == "10 req/s · burst 20 · back-off 2× · budget 50")
        #expect(entries[1].limit == nil)
    }
}
