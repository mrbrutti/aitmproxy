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
        #expect(BreakpointRule.wildcardMatches(pattern: "https://?pi.*", text: "https://api.x"))
    }

    @Test func noticeAndWireForm() throws {
        var set = BreakpointRules()
        #expect(set.armedNotice == "Intercept armed — every request pauses here")
        set.rules = [BreakpointRule(name: "login", url: "*/login", onResponse: true, flag: .red), BreakpointRule(url: "x", enabled: false)]
        #expect(set.armedNotice == "Intercept armed — 1 rule")
        // Only the core's rule fields travel (`match` and `flag` would reject the whole call),
        // and `url` is the core's object form, so a regex is a regex on the core too.
        #expect(set.rules[0].arguments == ["id": .string(set.rules[0].id.uuidString), "url": ["wildcard": "*/login"],
                                            "phase": "any", "name": "login"])
        // A substring wildcard is anchored on the core, so it travels wrapped in `*`.
        #expect(BreakpointRule(url: "login").arguments["url"] == ["wildcard": "*login*"])
        #expect(BreakpointRule(url: "/api/?", onRequest: false, onResponse: true).arguments["phase"] == "response")
        #expect(BreakpointRule(url: "^/x$", matching: .regex, method: "post").arguments["url"] == ["regex": "^/x$"])
        #expect(BreakpointRule(url: "^/x$", matching: .regex, method: "post").arguments["method"] == "POST")
        #expect(set.matchCount(of: BreakpointRule(url: "*shop-staging*"), in: Fixtures.rows) == 13)
        let url = FileManager.default.temporaryDirectory.appending(path: "rules-\(UUID().uuidString).json")
        try set.save(to: url)
        #expect(BreakpointRules.load(from: url) == set)
    }
}
