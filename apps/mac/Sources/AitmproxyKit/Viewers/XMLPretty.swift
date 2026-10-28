import Foundation

/// A small, forgiving XML indenter for the Body viewer (S-021). No parser
/// dependency: it tokenizes tags, self-closing tags, comments, CDATA,
/// processing instructions, doctypes and text, then writes one node per
/// line at `indent` spaces per depth. A leaf element with only text stays on
/// one line (`<name>Headphones</name>`). Input whose tags do not pair up, or
/// that has an unterminated construct, comes back unchanged: the viewer
/// never loses bytes to the pretty printer.
public enum XMLPretty {
    /// The indented document, or `text` itself when it is not well-formed enough to indent.
    public static func pretty(_ text: String, indent: Int = 2) -> String {
        prettyIfWellFormed(text, indent: indent) ?? text
    }

    /// Nil when a tag is unterminated or a closing tag does not match its opener.
    public static func prettyIfWellFormed(_ text: String, indent: Int = 2) -> String? {
        guard let tokens = tokenize(text), !tokens.isEmpty else { return nil }
        var out = ""
        var depth = 0
        var stack: [String] = []
        var i = 0
        func pad(_ d: Int) -> String { String(repeating: " ", count: max(0, indent * d)) }
        while i < tokens.count {
            let token = tokens[i]
            switch token.kind {
            case .open:
                // `<a>text</a>`, `<a><![CDATA[x]]></a>` and `<a></a>` stay on one line.
                if i + 2 < tokens.count, tokens[i + 1].kind == .text || tokens[i + 1].kind == .cdata,
                   tokens[i + 2].kind == .close, tokens[i + 2].name == token.name {
                    out += pad(depth) + token.text + trimmed(tokens[i + 1].text) + tokens[i + 2].text + "\n"
                    i += 3
                    continue
                }
                if i + 1 < tokens.count, tokens[i + 1].kind == .close, tokens[i + 1].name == token.name {
                    out += pad(depth) + token.text + tokens[i + 1].text + "\n"
                    i += 2
                    continue
                }
                out += pad(depth) + token.text + "\n"
                stack.append(token.name)
                depth += 1
            case .close:
                guard let opener = stack.popLast(), opener == token.name else { return nil }
                depth -= 1
                out += pad(depth) + token.text + "\n"
            case .selfClosing, .comment, .cdata, .instruction, .doctype:
                out += pad(depth) + token.text + "\n"
            case .text:
                let body = trimmed(token.text)
                if !body.isEmpty { out += pad(depth) + body + "\n" }
            }
            i += 1
        }
        guard stack.isEmpty else { return nil }
        if out.hasSuffix("\n") { out.removeLast() }
        return out
    }

    // MARK: Tokens

    enum Kind: Equatable { case open, close, selfClosing, comment, cdata, instruction, doctype, text }

    struct Token: Equatable {
        var kind: Kind
        /// The element name for open / close / self-closing tags; empty otherwise.
        var name: String
        var text: String
    }

    /// Splits the document into markup and text. Nil on an unterminated construct.
    static func tokenize(_ text: String) -> [Token]? {
        let bytes = Array(text.utf8)
        var tokens: [Token] = []
        var pos = 0
        let lt = UInt8(ascii: "<")
        while pos < bytes.count {
            if bytes[pos] == lt {
                guard let end = markupEnd(bytes, from: pos) else { return nil }
                let raw = String(decoding: bytes[pos..<end], as: UTF8.self)
                tokens.append(classify(raw))
                pos = end
            } else {
                var end = pos
                while end < bytes.count, bytes[end] != lt { end += 1 }
                tokens.append(Token(kind: .text, name: "", text: String(decoding: bytes[pos..<end], as: UTF8.self)))
                pos = end
            }
        }
        return tokens
    }

    /// Index just past the markup that starts at `start` (which is `<`), honouring
    /// comment / CDATA / PI terminators and quoted attribute values.
    private static func markupEnd(_ b: [UInt8], from start: Int) -> Int? {
        func terminated(by suffix: String) -> Int? {
            let needle = Array(suffix.utf8)
            var i = start + 1
            while i + needle.count <= b.count {
                if Array(b[i..<(i + needle.count)]) == needle { return i + needle.count }
                i += 1
            }
            return nil
        }
        if hasPrefix(b, at: start, "<!--") { return terminated(by: "-->") }
        if hasPrefix(b, at: start, "<![CDATA[") { return terminated(by: "]]>") }
        if hasPrefix(b, at: start, "<?") { return terminated(by: "?>") }
        var quote: UInt8?
        var i = start + 1
        while i < b.count {
            let c = b[i]
            if let q = quote {
                if c == q { quote = nil }
            } else if c == UInt8(ascii: "\"") || c == UInt8(ascii: "'") {
                quote = c
            } else if c == UInt8(ascii: ">") {
                return i + 1
            } else if c == UInt8(ascii: "<") {
                return nil // a stray `<` inside a tag: not markup we can trust
            }
            i += 1
        }
        return nil
    }

    private static func hasPrefix(_ b: [UInt8], at start: Int, _ prefix: String) -> Bool {
        let p = Array(prefix.utf8)
        guard start + p.count <= b.count else { return false }
        return Array(b[start..<(start + p.count)]) == p
    }

    private static func classify(_ raw: String) -> Token {
        if raw.hasPrefix("<!--") { return Token(kind: .comment, name: "", text: raw) }
        if raw.hasPrefix("<![CDATA[") { return Token(kind: .cdata, name: "", text: raw) }
        if raw.hasPrefix("<?") { return Token(kind: .instruction, name: "", text: raw) }
        if raw.hasPrefix("<!") { return Token(kind: .doctype, name: "", text: raw) }
        if raw.hasPrefix("</") { return Token(kind: .close, name: elementName(raw.dropFirst(2)), text: raw) }
        if raw.hasSuffix("/>") { return Token(kind: .selfClosing, name: elementName(raw.dropFirst()), text: raw) }
        return Token(kind: .open, name: elementName(raw.dropFirst()), text: raw)
    }

    private static func elementName(_ s: Substring) -> String {
        String(s.prefix { !$0.isWhitespace && $0 != ">" && $0 != "/" })
    }

    private static func trimmed(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
