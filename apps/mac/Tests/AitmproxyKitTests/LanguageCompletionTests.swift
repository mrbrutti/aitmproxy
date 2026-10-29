import Foundation
import Testing
@testable import AitmproxyKit

/// Autocomplete for Rhai and PoC-YAML (UI-ext spec AC3/AC4), proven against the
/// shared conformance fixtures so macOS offers the same candidates as web/TUI.
struct LanguageCompletionTests {
    /// The shared definitions directory, four levels up from this test file.
    private static var languagesDir: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // AitmproxyKitTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // apps/mac
            .deletingLastPathComponent() // apps
            .deletingLastPathComponent() // worktree root
            .appending(path: "docs/design/languages")
    }

    private struct Case: Decodable {
        var name: String
        var context: String
        var caret: Int
        var kind: String
        var path: String
        var expected_candidates: [String]
    }

    private static func cases(_ file: String) throws -> [Case] {
        let data = try Data(contentsOf: languagesDir.appending(path: file))
        return try JSONDecoder().decode([Case].self, from: data)
    }

    @Test func rhaiCompletionMatchesConformanceFixtures() throws {
        for c in try Self.cases("rhai.completion.conformance.json") {
            let got = LanguageCompletion.rhai(source: c.context, caret: c.caret)
            #expect(Set(got) == Set(c.expected_candidates), "rhai fixture: \(c.name) — got \(got)")
        }
    }

    @Test func pocYAMLCompletionMatchesConformanceFixtures() throws {
        for c in try Self.cases("poc.completion.conformance.json") {
            let got = LanguageCompletion.pocYAML(source: c.context, caret: c.caret)
            #expect(Set(got) == Set(c.expected_candidates), "poc fixture: \(c.name) — got \(got)")
        }
    }

    // MARK: Catalog sanity — the generated defs decoded as expected.

    @Test func rhaiCatalogCarriesKeywordsAndHooks() {
        #expect(LanguageCatalog.rhai.keywords.contains("fn"))
        #expect(LanguageCatalog.rhai.keywords.contains("let"))
        #expect(LanguageCatalog.rhai.hookNames.contains("on_request"))
        #expect(LanguageCatalog.rhai.hookNames.count == 10)
    }
}
