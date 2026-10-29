import Foundation

/// What a JSON node holds. Containers carry their member count so a collapsed
/// row can show `{3}` / `[2]` without visiting the children.
public enum JSONKind: Hashable, Sendable {
    case object(count: Int)
    case array(count: Int)
    case string
    case number
    case bool
    case null

    public var isContainer: Bool {
        switch self {
        case .object, .array: true
        case .string, .number, .bool, .null: false
        }
    }
}

/// One node of a parsed JSON document, for the inspector's tree viewer
/// (foundation §2.7: fold, copy node, JSONPath of node, filter, sort keys).
public struct JSONNode: Identifiable, Hashable, Sendable {
    /// The node's path; stable across re-parses of the same document.
    public var id: String { path }
    /// Object member name, or the array index as `[0]`. Nil for the root.
    public var key: String?
    /// `$`, `$.user.roles[0]`, `$["odd key"]`.
    public var path: String
    public var kind: JSONKind
    /// The leaf's display text: decoded string, the number as written in the
    /// source (`3600`, not `3600.0`), `true`/`false`/`null`. Empty for containers.
    public var scalarText: String
    public var children: [JSONNode]

    public init(key: String?, path: String, kind: JSONKind, scalarText: String = "", children: [JSONNode] = []) {
        self.key = key
        self.path = path
        self.kind = kind
        self.scalarText = scalarText
        self.children = children
    }

    /// `3 keys`, `2 items`, or the scalar text — what a collapsed row shows after the key.
    public var summary: String {
        switch kind {
        case .object(let n): n == 1 ? "1 key" : "\(n) keys"
        case .array(let n): n == 1 ? "1 item" : "\(n) items"
        case .string, .number, .bool, .null: scalarText
        }
    }

    /// The `SyntaxKind` the leaf's text is coloured with.
    public var syntaxKind: SyntaxKind {
        switch kind {
        case .object, .array: .bracket
        case .string: .string
        case .number: .number
        case .bool, .null: .boolean
        }
    }

    /// The visible rows of an outline whose expanded nodes are `expanded`
    /// (a set of paths). The root is always the first row.
    public func flatten(expanded: Set<String>) -> [JSONTreeRow] {
        var rows: [JSONTreeRow] = []
        appendRows(depth: 0, expanded: expanded, into: &rows)
        return rows
    }

    private func appendRows(depth: Int, expanded: Set<String>, into rows: inout [JSONTreeRow]) {
        let open = kind.isContainer && expanded.contains(path)
        rows.append(JSONTreeRow(depth: depth, node: self, isExpanded: open))
        guard open else { return }
        for child in children {
            child.appendRows(depth: depth + 1, expanded: expanded, into: &rows)
        }
    }

    /// Paths of every node whose key or scalar text contains `query`
    /// (case-insensitive), plus all their ancestors so the matches stay reachable.
    public func filter(_ query: String) -> Set<String> {
        var hits = Set<String>()
        _ = collectMatches(query.lowercased(), into: &hits)
        return hits
    }

    /// Returns whether this subtree holds a match; adds matching paths and their ancestors to `hits`.
    private func collectMatches(_ needle: String, into hits: inout Set<String>) -> Bool {
        var matched = false
        if needle.isEmpty {
            matched = true
        } else if let key, key.lowercased().contains(needle) {
            matched = true
        } else if !kind.isContainer, scalarText.lowercased().contains(needle) {
            matched = true
        }
        for child in children where child.collectMatches(needle, into: &hits) {
            matched = true
        }
        if matched { hits.insert(path) }
        return matched
    }

    /// A copy with every object's members sorted by key. Paths do not change
    /// (they name keys, not positions), so an expansion set keeps working.
    public func sortedKeys() -> JSONNode {
        var copy = self
        copy.children = children.map { $0.sortedKeys() }
        if case .object = kind {
            copy.children.sort { ($0.key ?? "") < ($1.key ?? "") }
        }
        return copy
    }

    /// Every path in the subtree, for "expand all".
    public var allPaths: Set<String> {
        var set = Set<String>()
        collectPaths(into: &set)
        return set
    }

    private func collectPaths(into set: inout Set<String>) {
        set.insert(path)
        for child in children { child.collectPaths(into: &set) }
    }
}

/// One visible row of the tree outline.
public struct JSONTreeRow: Identifiable, Hashable, Sendable {
    public var id: String { node.path }
    public var depth: Int
    public var node: JSONNode
    public var isExpanded: Bool

    public init(depth: Int, node: JSONNode, isExpanded: Bool) {
        self.depth = depth
        self.node = node
        self.isExpanded = isExpanded
    }
}

/// Malformed JSON: where (UTF-8 byte offset) and what.
public struct JSONTreeError: Error, Hashable, Sendable, CustomStringConvertible {
    public var offset: Int
    public var message: String

    public init(offset: Int, message: String) {
        self.offset = offset
        self.message = message
    }

    public var description: String { "\(message) at byte \(offset)" }
}

/// Order-preserving JSON parsing and printing. `JSONSerialization` returns
/// unordered dictionaries, so the tree and the pretty printer use this small
/// parser instead; it keeps keys in source order and numbers as written.
public enum JSONTree {
    /// Parses a document (or a bare scalar). Forgiving about a BOM, surrounding
    /// whitespace and trailing commas; strict about everything else.
    public static func parse(_ data: Data) throws -> JSONNode {
        var parser = Parser(bytes: Array(data))
        return try parser.parseDocument()
    }

    public static func parse(_ text: String) throws -> JSONNode {
        try parse(Data(text.utf8))
    }

    /// The node's JSON, pretty-printed with `indent` spaces per level.
    public static func copyText(for node: JSONNode, indent: Int = 2) -> String {
        var out = ""
        write(node, indent: indent, depth: 0, into: &out)
        return out
    }

    /// Reformats a document keeping key order; nil when it is not JSON.
    public static func pretty(_ data: Data, indent: Int = 2) -> String? {
        guard let root = try? parse(data) else { return nil }
        return copyText(for: root, indent: indent)
    }

    /// The document on one line, keeping key order; nil when it is not JSON.
    public static func minified(_ data: Data) -> String? {
        guard let root = try? parse(data) else { return nil }
        var out = ""
        writeCompact(root, into: &out)
        return out
    }

    // MARK: Printing

    private static func write(_ node: JSONNode, indent: Int, depth: Int, into out: inout String) {
        switch node.kind {
        case .object:
            if node.children.isEmpty { out += "{}"; return }
            out += "{\n"
            let pad = String(repeating: " ", count: indent * (depth + 1))
            for (i, child) in node.children.enumerated() {
                out += pad
                out += quote(child.key ?? "")
                out += ": "
                write(child, indent: indent, depth: depth + 1, into: &out)
                out += i == node.children.count - 1 ? "\n" : ",\n"
            }
            out += String(repeating: " ", count: indent * depth)
            out += "}"
        case .array:
            if node.children.isEmpty { out += "[]"; return }
            out += "[\n"
            let pad = String(repeating: " ", count: indent * (depth + 1))
            for (i, child) in node.children.enumerated() {
                out += pad
                write(child, indent: indent, depth: depth + 1, into: &out)
                out += i == node.children.count - 1 ? "\n" : ",\n"
            }
            out += String(repeating: " ", count: indent * depth)
            out += "]"
        case .string:
            out += quote(node.scalarText)
        case .number, .bool, .null:
            out += node.scalarText
        }
    }

    private static func writeCompact(_ node: JSONNode, into out: inout String) {
        switch node.kind {
        case .object:
            out += "{"
            for (i, child) in node.children.enumerated() {
                if i > 0 { out += "," }
                out += quote(child.key ?? "")
                out += ":"
                writeCompact(child, into: &out)
            }
            out += "}"
        case .array:
            out += "["
            for (i, child) in node.children.enumerated() {
                if i > 0 { out += "," }
                writeCompact(child, into: &out)
            }
            out += "]"
        case .string:
            out += quote(node.scalarText)
        case .number, .bool, .null:
            out += node.scalarText
        }
    }

    /// A JSON string literal: escapes the quote, the backslash and control characters; leaves Unicode as is.
    public static func quote(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
        return out
    }

    /// `$.a.b` for identifier-like keys, `$["a b"]` otherwise.
    static func childPath(parent: String, key: String) -> String {
        if isIdentifier(key) { return "\(parent).\(key)" }
        return "\(parent)[\(quote(key))]"
    }

    private static func isIdentifier(_ key: String) -> Bool {
        guard let first = key.unicodeScalars.first else { return false }
        guard first == "_" || first.properties.isAlphabetic else { return false }
        return key.unicodeScalars.allSatisfy { $0 == "_" || $0.properties.isAlphabetic || ("0"..."9").contains($0) }
    }

    // MARK: Parser

    private struct Parser {
        let bytes: [UInt8]
        var pos = 0

        init(bytes: [UInt8]) {
            self.bytes = bytes
        }

        mutating func parseDocument() throws -> JSONNode {
            if bytes.count >= 3, bytes[0] == 0xEF, bytes[1] == 0xBB, bytes[2] == 0xBF { pos = 3 }
            skipWhitespace()
            guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Empty document") }
            let root = try parseValue(key: nil, path: "$")
            skipWhitespace()
            if pos < bytes.count {
                throw JSONTreeError(offset: pos, message: "Unexpected trailing content")
            }
            return root
        }

        private mutating func skipWhitespace() {
            while pos < bytes.count {
                switch bytes[pos] {
                case 0x20, 0x09, 0x0A, 0x0D: pos += 1
                default: return
                }
            }
        }

        private mutating func parseValue(key: String?, path: String) throws -> JSONNode {
            skipWhitespace()
            guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Unexpected end of input") }
            switch bytes[pos] {
            case UInt8(ascii: "{"): return try parseObject(key: key, path: path)
            case UInt8(ascii: "["): return try parseArray(key: key, path: path)
            case UInt8(ascii: "\""):
                let text = try parseString()
                return JSONNode(key: key, path: path, kind: .string, scalarText: text)
            case UInt8(ascii: "t"):
                try expectLiteral("true")
                return JSONNode(key: key, path: path, kind: .bool, scalarText: "true")
            case UInt8(ascii: "f"):
                try expectLiteral("false")
                return JSONNode(key: key, path: path, kind: .bool, scalarText: "false")
            case UInt8(ascii: "n"):
                try expectLiteral("null")
                return JSONNode(key: key, path: path, kind: .null, scalarText: "null")
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
                let text = try parseNumber()
                return JSONNode(key: key, path: path, kind: .number, scalarText: text)
            default:
                throw JSONTreeError(offset: pos, message: "Unexpected character '\(Character(UnicodeScalar(bytes[pos])))'")
            }
        }

        private mutating func parseObject(key: String?, path: String) throws -> JSONNode {
            pos += 1 // {
            var children: [JSONNode] = []
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "}") {
                pos += 1
                return JSONNode(key: key, path: path, kind: .object(count: 0))
            }
            while true {
                skipWhitespace()
                guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Unterminated object") }
                if bytes[pos] == UInt8(ascii: "}") { // trailing comma
                    pos += 1
                    break
                }
                guard bytes[pos] == UInt8(ascii: "\"") else {
                    throw JSONTreeError(offset: pos, message: "Expected a string key")
                }
                let name = try parseString()
                skipWhitespace()
                guard pos < bytes.count, bytes[pos] == UInt8(ascii: ":") else {
                    throw JSONTreeError(offset: pos, message: "Expected ':' after key")
                }
                pos += 1
                let child = try parseValue(key: name, path: JSONTree.childPath(parent: path, key: name))
                children.append(child)
                skipWhitespace()
                guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Unterminated object") }
                if bytes[pos] == UInt8(ascii: ",") {
                    pos += 1
                    continue
                }
                if bytes[pos] == UInt8(ascii: "}") {
                    pos += 1
                    break
                }
                throw JSONTreeError(offset: pos, message: "Expected ',' or '}'")
            }
            return JSONNode(key: key, path: path, kind: .object(count: children.count), children: children)
        }

        private mutating func parseArray(key: String?, path: String) throws -> JSONNode {
            pos += 1 // [
            var children: [JSONNode] = []
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "]") {
                pos += 1
                return JSONNode(key: key, path: path, kind: .array(count: 0))
            }
            while true {
                skipWhitespace()
                guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Unterminated array") }
                if bytes[pos] == UInt8(ascii: "]") { // trailing comma
                    pos += 1
                    break
                }
                let index = children.count
                let child = try parseValue(key: "[\(index)]", path: "\(path)[\(index)]")
                children.append(child)
                skipWhitespace()
                guard pos < bytes.count else { throw JSONTreeError(offset: pos, message: "Unterminated array") }
                if bytes[pos] == UInt8(ascii: ",") {
                    pos += 1
                    continue
                }
                if bytes[pos] == UInt8(ascii: "]") {
                    pos += 1
                    break
                }
                throw JSONTreeError(offset: pos, message: "Expected ',' or ']'")
            }
            return JSONNode(key: key, path: path, kind: .array(count: children.count), children: children)
        }

        private mutating func expectLiteral(_ word: String) throws {
            let start = pos
            for expected in word.utf8 {
                guard pos < bytes.count, bytes[pos] == expected else {
                    throw JSONTreeError(offset: start, message: "Invalid literal")
                }
                pos += 1
            }
        }

        /// Returns the number exactly as written; validates the JSON grammar loosely.
        private mutating func parseNumber() throws -> String {
            let start = pos
            if bytes[pos] == UInt8(ascii: "-") { pos += 1 }
            var digits = 0
            while pos < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[pos]) {
                pos += 1
                digits += 1
            }
            guard digits > 0 else { throw JSONTreeError(offset: start, message: "Invalid number") }
            if pos < bytes.count, bytes[pos] == UInt8(ascii: ".") {
                pos += 1
                var fraction = 0
                while pos < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[pos]) {
                    pos += 1
                    fraction += 1
                }
                guard fraction > 0 else { throw JSONTreeError(offset: pos, message: "Invalid number") }
            }
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "e") || bytes[pos] == UInt8(ascii: "E") {
                pos += 1
                if pos < bytes.count, bytes[pos] == UInt8(ascii: "+") || bytes[pos] == UInt8(ascii: "-") { pos += 1 }
                var exponent = 0
                while pos < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[pos]) {
                    pos += 1
                    exponent += 1
                }
                guard exponent > 0 else { throw JSONTreeError(offset: pos, message: "Invalid number") }
            }
            return String(decoding: bytes[start..<pos], as: UTF8.self)
        }

        /// Decodes a string literal (the cursor is on the opening quote).
        private mutating func parseString() throws -> String {
            let start = pos
            pos += 1 // "
            var out: [UInt8] = []
            while true {
                guard pos < bytes.count else { throw JSONTreeError(offset: start, message: "Unterminated string") }
                let b = bytes[pos]
                if b == UInt8(ascii: "\"") {
                    pos += 1
                    return String(decoding: out, as: UTF8.self)
                }
                if b == UInt8(ascii: "\\") {
                    pos += 1
                    guard pos < bytes.count else { throw JSONTreeError(offset: start, message: "Unterminated string") }
                    let e = bytes[pos]
                    pos += 1
                    switch e {
                    case UInt8(ascii: "\""): out.append(0x22)
                    case UInt8(ascii: "\\"): out.append(0x5C)
                    case UInt8(ascii: "/"): out.append(0x2F)
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0C)
                    case UInt8(ascii: "n"): out.append(0x0A)
                    case UInt8(ascii: "r"): out.append(0x0D)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"):
                        let escapeStart = pos - 2
                        var code = try parseHex4()
                        if (0xD800...0xDBFF).contains(code) {
                            // High surrogate: needs a \uDC00–\uDFFF right after.
                            if pos + 1 < bytes.count, bytes[pos] == UInt8(ascii: "\\"), bytes[pos + 1] == UInt8(ascii: "u") {
                                pos += 2
                                let low = try parseHex4()
                                guard (0xDC00...0xDFFF).contains(low) else {
                                    throw JSONTreeError(offset: escapeStart, message: "Invalid surrogate pair")
                                }
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                            } else {
                                throw JSONTreeError(offset: escapeStart, message: "Lone high surrogate")
                            }
                        } else if (0xDC00...0xDFFF).contains(code) {
                            throw JSONTreeError(offset: escapeStart, message: "Lone low surrogate")
                        }
                        guard let scalar = UnicodeScalar(code) else {
                            throw JSONTreeError(offset: escapeStart, message: "Invalid code point")
                        }
                        out.append(contentsOf: Array(String(Character(scalar)).utf8))
                    default:
                        throw JSONTreeError(offset: pos - 2, message: "Invalid escape")
                    }
                    continue
                }
                if b < 0x20 {
                    throw JSONTreeError(offset: pos, message: "Control character in string")
                }
                out.append(b)
                pos += 1
            }
        }

        private mutating func parseHex4() throws -> UInt32 {
            guard pos + 4 <= bytes.count else { throw JSONTreeError(offset: pos, message: "Truncated \\u escape") }
            var value: UInt32 = 0
            for _ in 0..<4 {
                let b = bytes[pos]
                let digit: UInt32
                switch b {
                case UInt8(ascii: "0")...UInt8(ascii: "9"): digit = UInt32(b - UInt8(ascii: "0"))
                case UInt8(ascii: "a")...UInt8(ascii: "f"): digit = UInt32(b - UInt8(ascii: "a")) + 10
                case UInt8(ascii: "A")...UInt8(ascii: "F"): digit = UInt32(b - UInt8(ascii: "A")) + 10
                default: throw JSONTreeError(offset: pos, message: "Invalid hex digit in \\u escape")
                }
                value = value * 16 + digit
                pos += 1
            }
            return value
        }
    }
}
