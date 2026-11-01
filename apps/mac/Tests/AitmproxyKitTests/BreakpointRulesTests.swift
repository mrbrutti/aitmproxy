import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct BreakpointRulesTests {
    @Test func validation() {
        #expect(BreakpointRule(url: "").validationError != nil)
        #expect(BreakpointRule(url: "(", matching: .regex).validationError != nil)
        #expect(BreakpointRule(url: "*/api/*", onRequest: false, onResponse: false).validationError != nil)
        #expect(BreakpointRule(url: "*/api/*").validationError == nil)
    }

    @Test func wildcardAndRegexMatching() {
        let rows = Fixtures.rows
        let login = BreakpointRule(url: "*/api/auth/*")
        #expect(rows.filter(login.matches).map(\.seq) == [50])
        let substring = BreakpointRule(url: "api/orders")
        #expect(rows.filter(substring.matches).map(\.seq) == [45, 46])
        let posts = BreakpointRule(url: "*", method: "post")
        #expect(rows.filter(posts.matches).map(\.seq) == [44, 50])
        let regex = BreakpointRule(url: #"/api/(cart|me)$"#, matching: .regex)
        #expect(rows.filter(regex.matches).map(\.seq) == [51, 53])
        // `?` is literal (it starts a query), as in the core; it is not a one-character wildcard.
        #expect(BreakpointRule.wildcardMatches(pattern: "https://?pi.*", text: "https://api.x") == false)
        #expect(BreakpointRule.wildcardMatches(pattern: "*/search?q=*", text: "https://h/search?q=1"))
    }

    @Test func emptyPatternMatchesNoRow() {
        // One literal row, not `Fixtures.rows`, so the result does not depend
        // on the fixture set.
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
        #expect(set.rules[0].arguments == ["url": "*/login", "match": "wildcard", "phase": "both", "flag": "red", "name": "login"])
        #expect(set.matchCount(of: BreakpointRule(url: "*shop-staging*"), in: Fixtures.rows) == 13)
        let url = FileManager.default.temporaryDirectory.appending(path: "rules-\(UUID().uuidString).json")
        try set.save(to: url)
        #expect(BreakpointRules.load(from: url) == set)
    }
}
