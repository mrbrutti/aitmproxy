import Foundation
import Testing
@testable import AitmproxyKit

/// Rhai + PoC-YAML colouring in the edit path (UI-ext spec AC1/AC2). The token
/// sets come from the shared `docs/design/languages/*.json`; a tolerant
/// colorizer must never throw on partial input.
struct SyntaxLanguagesTests {
    /// The kind a run covering `needle` carries, or nil when no single run is exactly `needle`.
    private func kind(of needle: String, in runs: [SyntaxRun]) -> SyntaxKind? {
        runs.first { $0.text == needle }?.kind
    }

    private func concat(_ runs: [SyntaxRun]) -> String { runs.map(\.text).joined() }

    // MARK: Rhai tokenizer

    @Test func rhaiColoursKeywordsStringsNumbersComments() {
        let runs = Syntax.rhai(line: #"let x = "a"; // c"#)
        #expect(concat(runs) == #"let x = "a"; // c"#)
        #expect(kind(of: "let", in: runs) == .keyword)
        #expect(kind(of: #""a""#, in: runs) == .string)
        #expect(kind(of: "// c", in: runs) == .comment)
    }

    @Test func rhaiColoursFunctionDeclaration() {
        let runs = Syntax.rhai(line: "fn on_request(flow) {")
        #expect(kind(of: "fn", in: runs) == .keyword)
        // The hook name and parameter are identifiers (plain), not keywords.
        #expect(kind(of: "on_request", in: runs) != .keyword)
    }

    @Test func rhaiColoursNumbersAndBooleans() {
        let runs = Syntax.rhai(line: "let n = 0xFF; let b = true;")
        #expect(kind(of: "0xFF", in: runs) == .number)
        #expect(kind(of: "true", in: runs) == .boolean)
    }

    @Test func rhaiTolerantOnUnterminatedString() {
        // Must colour to end of line and not throw (Review Focus: tolerance).
        let runs = Syntax.rhai(line: #"let x = "unterminated"#)
        #expect(concat(runs) == #"let x = "unterminated"#)
        #expect(kind(of: #""unterminated"#, in: runs) == .string)
    }

    @Test func rhaiTolerantOnHalfWrittenMember() {
        // A half-typed `flow.` must still render (does not throw).
        let runs = Syntax.rhai(line: "    flow.")
        #expect(concat(runs) == "    flow.")
    }

    // MARK: Rhai block comments span lines (editor whole-text path)

    @Test func rhaiEditorColoursBlockCommentAcrossLines() {
        let text = "let a = 1; /* open\nstill comment\nclosed */ let b = 2;"
        let result = CodeAnalysis.analyseNow(text: text, contentType: "text/rhai")
        // The middle line is entirely inside the block comment.
        let midStart = text.utf16.distance(from: text.utf16.startIndex,
                                           to: ("let a = 1; /* open\n" as String).utf16.endIndex)
        let midRun = result.runs.first { $0.range.location >= midStart && $0.kind == .comment }
        #expect(midRun != nil)
    }

    // MARK: PoC YAML in the edit path (same token set as the read-only Config view)

    @Test func yamlEditorColoursKeysAndStrings() {
        let text = "info:\n  severity: high\n  name: \"demo\""
        let result = CodeAnalysis.analyseNow(text: text, contentType: "text/yaml")
        #expect(result.runs.contains { $0.kind == .key })
        #expect(result.runs.contains { $0.kind == .string })
    }
}
