import Foundation

extension Syntax {
    /// Where a line ends for the Rhai tokenizer, so the whole-text editor path
    /// can carry a block comment across lines (an unterminated `/* …` colours to
    /// the end of the buffer, per `rhai.grammar.json`).
    public enum RhaiState: Hashable, Sendable {
        case code
        /// Inside a `/* … */` block comment, nesting `depth` deep.
        case blockComment(depth: Int)
    }

    /// One Rhai line, started fresh (no inherited block comment). Tolerant:
    /// an unterminated string or comment colours to end of line and never throws.
    public static func rhai(line: String) -> [SyntaxRun] {
        rhai(line: line, continuing: .code).runs
    }

    /// One Rhai line continuing from `state`. Keywords → `.keyword`, `true`/
    /// `false` → `.boolean`, strings → `.string`, numbers → `.number`, comments
    /// → `.comment`, operators/punctuation → `.punct`, identifiers → `.plain`.
    /// Token classes come from `rhai.grammar.json` via `LanguageCatalog.rhai`.
    public static func rhai(line: String, continuing state: RhaiState) -> (runs: [SyntaxRun], next: RhaiState) {
        let catalog = LanguageCatalog.rhai
        let chars = Array(line)
        var runs: [SyntaxRun] = []
        var plain = ""
        var i = 0

        func flushPlain() {
            if !plain.isEmpty { runs.append(SyntaxRun(.plain, plain)); plain = "" }
        }

        // Resume an open block comment from the previous line.
        if case var .blockComment(depth) = state {
            let start = i
            while i < chars.count {
                if chars[i] == "*", i + 1 < chars.count, chars[i + 1] == "/" {
                    depth -= 1; i += 2
                    if depth == 0 { break }
                } else if chars[i] == "/", i + 1 < chars.count, chars[i + 1] == "*" {
                    depth += 1; i += 2
                } else {
                    i += 1
                }
            }
            runs.append(SyntaxRun(.comment, String(chars[start..<i])))
            if depth > 0 { return (runs, .blockComment(depth: depth)) }
        }

        while i < chars.count {
            let c = chars[i]
            // Line comment to end of line.
            if c == "/", i + 1 < chars.count, chars[i + 1] == "/" {
                flushPlain()
                runs.append(SyntaxRun(.comment, String(chars[i...])))
                i = chars.count
                break
            }
            // Block comment (may run past this line).
            if c == "/", i + 1 < chars.count, chars[i + 1] == "*" {
                flushPlain()
                var depth = 1
                let start = i
                i += 2
                while i < chars.count {
                    if chars[i] == "*", i + 1 < chars.count, chars[i + 1] == "/" {
                        depth -= 1; i += 2
                        if depth == 0 { break }
                    } else if chars[i] == "/", i + 1 < chars.count, chars[i + 1] == "*" {
                        depth += 1; i += 2
                    } else {
                        i += 1
                    }
                }
                runs.append(SyntaxRun(.comment, String(chars[start..<i])))
                if depth > 0 { return (runs, .blockComment(depth: depth)) }
                continue
            }
            // Strings: double, char, backtick, and raw (`#"… "#`). Unterminated
            // forms colour to end of line (tolerant).
            if c == "\"" || c == "'" || c == "`" {
                flushPlain()
                let quote = c
                var j = i + 1
                var escaped = false
                while j < chars.count {
                    if chars[j] == "\\", !escaped { escaped = true; j += 1; continue }
                    if chars[j] == quote, !escaped { j += 1; break }
                    escaped = false
                    j += 1
                }
                runs.append(SyntaxRun(.string, String(chars[i..<j])))
                i = j
                continue
            }
            if c == "#", i + 1 < chars.count, chars[i + 1] == "\"" {
                flushPlain()
                var j = i + 2
                while j < chars.count {
                    if chars[j] == "\"", j + 1 < chars.count, chars[j + 1] == "#" { j += 2; break }
                    j += 1
                }
                runs.append(SyntaxRun(.string, String(chars[i..<j])))
                i = j
                continue
            }
            // Numbers: decimal, hex, octal, binary, float, exponent.
            if c.isNumber {
                var j = i + 1
                while j < chars.count {
                    let d = chars[j]
                    if d.isHexDigit || "._xXoObBeE+-".contains(d) { j += 1 } else { break }
                }
                flushPlain()
                runs.append(SyntaxRun(.number, String(chars[i..<j])))
                i = j
                continue
            }
            // Identifiers / keywords / literals.
            if c.isLetter || c == "_" {
                var j = i + 1
                while j < chars.count, chars[j].isLetter || chars[j].isNumber || chars[j] == "_" { j += 1 }
                let word = String(chars[i..<j])
                flushPlain()
                let kind: SyntaxKind
                if catalog.keywords.contains(word) { kind = .keyword }
                else if catalog.literals.contains(word) { kind = .boolean }
                else { kind = .plain }
                runs.append(SyntaxRun(kind, word))
                i = j
                continue
            }
            // Operators and punctuation.
            if !c.isWhitespace {
                flushPlain()
                runs.append(SyntaxRun(.punct, String(c)))
                i += 1
                continue
            }
            plain.append(c)
            i += 1
        }
        flushPlain()
        return (runs, .code)
    }
}
