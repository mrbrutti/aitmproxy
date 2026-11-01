import Foundation
import Testing
@testable import AitmproxyKit

/// Seven rows for the URL-pattern tests: six under `*.shop-staging.test` and one telemetry
/// POST on another host, with the paths and methods the patterns below pick out.
private enum BreakpointRuleInputs {
    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", query: "category=electronics", status: 200),
        Make.row(seq: 2, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 inScope: false),
        Make.row(seq: 3, host: "api.shop-staging.test", path: "/api/orders", query: "page=3", status: 502),
        Make.row(seq: 4, host: "api.shop-staging.test", path: "/api/orders", query: "page=3", status: 200, isReplay: true),
        Make.row(seq: 5, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused),
        Make.row(seq: 6, host: "api.shop-staging.test", path: "/api/me", state: .paused),
        Make.row(seq: 7, method: .patch, host: "api.shop-staging.test", path: "/api/cart", status: 422),
    ]
}

@Suite struct BreakpointRulesTests {
    @Test func validation() {
        #expect(BreakpointRule(url: "").validationError != nil)
        #expect(BreakpointRule(url: "(", matching: .regex).validationError != nil)
        #expect(BreakpointRule(url: "*/api/*", onRequest: false, onResponse: false).validationError != nil)
        #expect(BreakpointRule(url: "*/api/*").validationError == nil)
    }

    @Test func wildcardAndRegexMatching() {
        let rows = BreakpointRuleInputs.rows
        let login = BreakpointRule(url: "*/api/auth/*")
        #expect(rows.filter(login.matches).map(\.seq) == [5])
        let substring = BreakpointRule(url: "api/orders")
        #expect(rows.filter(substring.matches).map(\.seq) == [3, 4])
        let posts = BreakpointRule(url: "*", method: "post")
        #expect(rows.filter(posts.matches).map(\.seq) == [2, 5])
        let regex = BreakpointRule(url: #"/api/(cart|me)$"#, matching: .regex)
        #expect(rows.filter(regex.matches).map(\.seq) == [6, 7])
        // `?` is literal (it starts a query), as in the core; it is not a one-character wildcard.
        #expect(BreakpointRule.wildcardMatches(pattern: "https://?pi.*", text: "https://api.x") == false)
        #expect(BreakpointRule.wildcardMatches(pattern: "*/search?q=*", text: "https://h/search?q=1"))
    }

    @Test func emptyPatternMatchesNoRow() {
        // One literal row, so the result does not depend on the rows above.
        let row = FlowRow(id: FlowID("empty"), seq: 1, method: .get, scheme: "https", authority: "h.test", path: "/x")
        // Positive control: the row is matchable, so the two `false`s below come
        // from the empty-pattern guard rather than from an unmatchable row.
        #expect(BreakpointRule(url: "*h.test*").matches(row) == true)
        #expect(BreakpointRule(url: "").matches(row) == false)
        #expect(BreakpointRule(url: "", matching: .regex).matches(row) == false)
    }

    @Test func noticeAndWireForm() throws {
        var set = BreakpointRules()
        #expect(set.armedNotice == "Intercept armed — every request pauses here")
        set.rules = [BreakpointRule(name: "login", url: "*/login", onResponse: true, flag: .red), BreakpointRule(url: "x", enabled: false)]
        #expect(set.armedNotice == "Intercept armed — 1 rule")
        // Only the core's rule fields travel (`match` and `flag` would reject the whole call); a
        // wildcard goes as typed in the core's `{wildcard}` object, whose semantics the preview mirrors.
        #expect(set.rules[0].arguments == ["id": .string(set.rules[0].id.uuidString), "url": ["wildcard": "*/login"],
                                            "phase": "any", "name": "login"])
        #expect(BreakpointRule(url: "login").arguments["url"] == ["wildcard": "login"])
        #expect(BreakpointRule(url: "/api/?", onRequest: false, onResponse: true).arguments["url"] == ["wildcard": "/api/?"])
        #expect(BreakpointRule(url: "/api/?", onRequest: false, onResponse: true).arguments["phase"] == "response")
        // Regex metacharacters in a wildcard are literal in the preview, as in the core.
        #expect(BreakpointRule.wildcardMatches(pattern: "*/search?q=(1+1)", text: "https://a.test/search?q=(1+1)"))
        #expect(!BreakpointRule.wildcardMatches(pattern: "*/search?q=(1+1)", text: "https://a.test/search?q=11"))
        #expect(BreakpointRule(url: "^/x$", matching: .regex, method: "post").arguments["url"] == ["regex": "^/x$"])
        #expect(BreakpointRule(url: "^/x$", matching: .regex, method: "post").arguments["method"] == "POST")
        // Six of the seven rows are under shop-staging.test; the telemetry POST is not.
        #expect(set.matchCount(of: BreakpointRule(url: "*shop-staging*"), in: BreakpointRuleInputs.rows) == 6)
        let url = FileManager.default.temporaryDirectory.appending(path: "rules-\(UUID().uuidString).json")
        try set.save(to: url)
        #expect(BreakpointRules.load(from: url) == set)
    }
}
