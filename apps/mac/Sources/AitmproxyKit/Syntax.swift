import Foundation

/// Syntax roles for the body viewers and header tables (tokens `color.syntax.*`).
public enum SyntaxKind: Hashable, Sendable {
    case plain, key, string, number, boolean, punct, bracket, method, version
}

public struct SyntaxRun: Hashable, Sendable {
    public var kind: SyntaxKind
    public var text: String
    public init(_ kind: SyntaxKind, _ text: String) {
        self.kind = kind
        self.text = text
    }
}

/// Line-at-a-time tokenizers. Stateless per line on purpose: they colour a
/// 5 MB body one visible line at a time and never need the whole document.
public enum Syntax {
    /// JSON: keys (a string followed by `:`), strings, numbers, literals,
    /// outer brackets and punctuation.
    public static func json(line: String) -> [SyntaxRun] {
        var runs: [SyntaxRun] = []
        var plain = ""
        let chars = Array(line)
        var i = 0
        func flushPlain() {
            if !plain.isEmpty { runs.append(SyntaxRun(.plain, plain)); plain = "" }
        }
        while i < chars.count {
            let c = chars[i]
            if c == "\"" {
                var j = i + 1
                var escaped = false
                while j < chars.count {
                    if chars[j] == "\\" && !escaped { escaped = true; j += 1; continue }
                    if chars[j] == "\"" && !escaped { break }
                    escaped = false
                    j += 1
                }
                let end = min(j, chars.count - 1)
                let text = String(chars[i...end])
                var k = end + 1
                while k < chars.count, chars[k] == " " { k += 1 }
                let isKey = k < chars.count && chars[k] == ":"
                flushPlain()
                runs.append(SyntaxRun(isKey ? .key : .string, text))
                i = end + 1
            } else if c.isNumber || (c == "-" && i + 1 < chars.count && chars[i + 1].isNumber) {
                var j = i + 1
                while j < chars.count, chars[j].isNumber || ".eE+-".contains(chars[j]) { j += 1 }
                flushPlain()
                runs.append(SyntaxRun(.number, String(chars[i..<j])))
                i = j
            } else if c.isLetter {
                var j = i + 1
                while j < chars.count, chars[j].isLetter { j += 1 }
                let word = String(chars[i..<j])
                flushPlain()
                runs.append(SyntaxRun(["true", "false", "null"].contains(word) ? .boolean : .plain, word))
                i = j
            } else if "{}[]".contains(c) {
                flushPlain()
                runs.append(SyntaxRun(.bracket, String(c)))
                i += 1
            } else if ":,".contains(c) {
                flushPlain()
                runs.append(SyntaxRun(.punct, String(c)))
                i += 1
            } else {
                plain.append(c)
                i += 1
            }
        }
        flushPlain()
        return runs
    }

    /// `name: value` header lines, and a request/status line.
    public static func header(line: String) -> [SyntaxRun] {
        if let colon = line.firstIndex(of: ":"), !line.hasPrefix("HTTP/"), !line.contains(" HTTP/") {
            let name = String(line[..<colon])
            let rest = String(line[line.index(after: colon)...])
            return [SyntaxRun(.key, name), SyntaxRun(.punct, ":"), SyntaxRun(.plain, rest)]
        }
        return startLine(line)
    }

    /// `POST /path HTTP/2` or `HTTP/2 200 OK`.
    public static func startLine(_ line: String) -> [SyntaxRun] {
        let parts = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2 else { return [SyntaxRun(.plain, line)] }
        var runs: [SyntaxRun] = []
        for (n, part) in parts.enumerated() {
            if n > 0 { runs.append(SyntaxRun(.plain, " ")) }
            if part.hasPrefix("HTTP/") {
                runs.append(SyntaxRun(.version, part))
            } else if n == 0 {
                runs.append(SyntaxRun(.method, part))
            } else if n == 1, parts[0].hasPrefix("HTTP/"), Int(part) != nil {
                runs.append(SyntaxRun(.number, part))
            } else {
                runs.append(SyntaxRun(.plain, part))
            }
        }
        return runs
    }

    /// Picks a tokenizer for a content type.
    public static func runs(for line: String, contentType: String?) -> [SyntaxRun] {
        let type = contentType?.lowercased() ?? ""
        if type.contains("json") || type.contains("graphql") { return json(line: line) }
        return [SyntaxRun(.plain, line)]
    }
}
