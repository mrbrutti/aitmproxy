import Foundation
import Testing
@testable import AitmproxyKit

/// The "Test Against List" preview must give the core's answer for every `url`
/// clause case. `crates/aitm-rules/tests/url_match_cases.rs` reads the same
/// case table, so whichever side drifts fails its own test.
@Suite struct BreakpointRuleCasesTests {
    private struct CaseTable: Decodable {
        var cases: [Case]
    }

    private struct Case: Decodable {
        var ac: String
        /// Decoded straight into `Matching` so a misspelt kind fails the decode
        /// instead of silently running as a wildcard.
        var kind: BreakpointRule.Matching
        var pattern: String
        var scheme: String
        var authority: String
        var path: String
        var query: String?
        var expect: Bool
    }

    /// The URL-clause case table, five levels up from this file.
    private static var caseTableURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // AitmproxyKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // apps/mac
            .deletingLastPathComponent() // apps
            .deletingLastPathComponent() // repo root
            .appending(path: "crates/aitm-rules/tests/cases/url-match-cases.json")
    }

    @Test func everyCaseAgreesWithTheCore() throws {
        let url = Self.caseTableURL
        try #require(FileManager.default.fileExists(atPath: url.path),
                     "case table missing at \(url.path); crates/aitm-rules owns it")
        let table = try JSONDecoder().decode(CaseTable.self, from: Data(contentsOf: url))
        try #require(!table.cases.isEmpty, "case table has no cases: \(url.path)")

        for (n, c) in table.cases.enumerated() {
            let row = FlowRow(id: FlowID("case-\(n)"), seq: n, method: .get,
                              scheme: c.scheme, authority: c.authority, path: c.path, query: c.query)
            let rule = BreakpointRule(url: c.pattern, matching: c.kind)
            #expect(rule.matches(row) == c.expect, "\(c.ac) \(c.kind.rawValue) \(c.pattern) vs \(row.url)")
        }
    }
}
