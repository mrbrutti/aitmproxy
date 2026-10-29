import Foundation

/// Context-aware autocomplete candidates for the two languages an operator
/// edits — Rhai and PoC-YAML — from the shared catalogs (UI-ext spec AC3/AC4).
/// Pure over `(source, caret)` so it is identical across surfaces and testable
/// against the shared completion conformance fixtures.
public enum LanguageCompletion {
    /// Rhai candidates at `caret`: members after a `receiver.`, else the hook
    /// names at top level or the body globals/DSL inside a hook body.
    public static func rhai(source: String, caret: Int) -> [String] {
        let catalog = LanguageCatalog.rhai
        let chars = Array(source.prefix(max(0, min(caret, source.count))))

        func isWord(_ c: Character) -> Bool { c.isLetter || c.isNumber || c == "_" }

        // The identifier being typed, and where it starts.
        var wordStart = chars.count
        while wordStart > 0, isWord(chars[wordStart - 1]) { wordStart -= 1 }
        let prefix = String(chars[wordStart...])

        // Member completion: an identifier (possibly empty) right after a `.`.
        if wordStart > 0, chars[wordStart - 1] == "." {
            let dot = wordStart - 1
            var start = dot
            while start > 0, isWord(chars[start - 1]) || chars[start - 1] == "." { start -= 1 }
            let receiver = String(chars[start..<dot])
            let candidates = catalog.members[receiver] ?? []
            return candidates.filter { prefix.isEmpty || $0.hasPrefix(prefix) }
        }

        // Otherwise an identifier: hooks at top level, globals/DSL inside a body.
        let openBraces = chars.reduce(0) { $0 + ($1 == "{" ? 1 : ($1 == "}" ? -1 : 0)) }
        let pool = openBraces > 0 ? catalog.bodyGlobals : catalog.hookNames
        return pool.filter { prefix.isEmpty || $0.hasPrefix(prefix) }
    }

    /// PoC-YAML candidates at `caret`: enum values after `key:`, else the keys
    /// valid at the current YAML nesting, walked through `poc-yaml.schema.json`.
    public static func pocYAML(source: String, caret: Int) -> [String] {
        let catalog = LanguageCatalog.poc
        let upToCaret = String(source.prefix(max(0, min(caret, source.count))))
        var lines = upToCaret.components(separatedBy: "\n")
        let current = Line(lines.removeLast())
        let container = resolveContainer(before: lines, current: current, catalog: catalog)
        guard let container else { return [] }

        if let key = current.valueKey {
            // Value position: the enum values (or booleans) of that key.
            guard let node = container.keys?[key].map({ catalog.resolve($0) }) else { return [] }
            let values: [String]
            if let enums = node.enumValues { values = enums }
            else if node.type == "boolean" { values = ["true", "false"] }
            else { values = [] }
            return values.filter { current.valuePrefix.isEmpty || $0.hasPrefix(current.valuePrefix) }
        }

        // Key position: the keys of the enclosing map.
        let keys = container.keys.map { Array($0.keys) } ?? []
        return keys.filter { current.keyPrefix.isEmpty || $0.hasPrefix(current.keyPrefix) }
    }

    // MARK: - PoC-YAML nesting walk

    /// One parsed YAML line (up to the caret for the current line).
    private struct Line {
        /// Leading-space indent, before any `- `.
        let indent: Int
        /// The line opens a list element (`- `).
        let isList: Bool
        /// The column where this line's key sits (`indent`, plus 2 for `- `).
        let keyColumn: Int
        /// The declared key, when the line has a `key:`.
        let key: String?
        /// Non-structural (blank or comment-only).
        let ignore: Bool
        /// For the current line only: the key whose value is being typed.
        let valueKey: String?
        let valuePrefix: String
        /// For the current line only: the partial key being typed.
        let keyPrefix: String

        init(_ raw: String) {
            let spaces = raw.prefix { $0 == " " }.count
            indent = spaces
            var content = String(raw.dropFirst(spaces))
            if content.hasPrefix("- ") {
                isList = true
                content = String(content.dropFirst(2))
            } else if content == "-" {
                isList = true
                content = ""
            } else {
                isList = false
            }
            keyColumn = indent + (isList ? 2 : 0)
            let rawTrimmed = raw.trimmingCharacters(in: .whitespaces)
            ignore = rawTrimmed.isEmpty || rawTrimmed.hasPrefix("#")

            if let colon = content.firstIndex(of: ":") {
                let name = String(content[..<colon]).trimmingCharacters(in: .whitespaces)
                key = name.isEmpty ? nil : name
                valueKey = name.isEmpty ? nil : name
                valuePrefix = String(content[content.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                keyPrefix = ""
            } else {
                key = nil
                valueKey = nil
                valuePrefix = ""
                keyPrefix = content.trimmingCharacters(in: .whitespaces)
            }
        }
    }

    /// A frame: `node` is a map whose child keys sit at column `column`.
    private struct Frame {
        let column: Int
        let node: PocNode
        var lastChild: PocNode?
    }

    /// Walks the lines before `current`, maintaining a frame stack, and returns
    /// the map node whose keys (or whose key's enum) are valid at `current`.
    private static func resolveContainer(before precedingLines: [String], current: Line,
                                         catalog: PocCatalog) -> PocNode? {
        var frames: [Frame] = [Frame(column: 0, node: catalog.root, lastChild: nil)]

        func descend(into line: Line) {
            // Dedent to the shallowest frame still enclosing this column.
            while frames.count > 1, frames[frames.count - 1].column > line.keyColumn { frames.removeLast() }
            var top = frames[frames.count - 1]

            if line.keyColumn > top.column {
                // Entering the value of the frame's last key (a nested block).
                guard let pending = top.lastChild else { return }
                var child = catalog.resolve(pending)
                if child.type == "list" || line.isList { child = catalog.resolve(child.items ?? child) }
                frames.append(Frame(column: line.keyColumn, node: child, lastChild: nil))
                top = frames[frames.count - 1]
            } else if line.isList {
                // A new list element at the same column: reset to its first key.
                frames[frames.count - 1].lastChild = nil
            }

            if let key = line.key {
                frames[frames.count - 1].lastChild = frames[frames.count - 1].node.keys?[key]
            }
        }

        for raw in precedingLines {
            let line = Line(raw)
            if line.ignore { continue }
            descend(into: line)
        }

        // Resolve the current line's enclosing container the same way.
        while frames.count > 1, frames[frames.count - 1].column > current.keyColumn { frames.removeLast() }
        var top = frames[frames.count - 1]
        if current.keyColumn > top.column {
            guard let pending = top.lastChild else { return nil }
            var child = catalog.resolve(pending)
            if child.type == "list" || current.isList { child = catalog.resolve(child.items ?? child) }
            return child
        }
        if current.isList, top.column == current.keyColumn {
            return top.node
        }
        return top.node
    }
}
