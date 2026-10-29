import Foundation

// The mitmproxy-style text form of a filter (foundation §2.7, §3.2).
//
//   expression := or
//   or         := and ('|' and)*
//   and        := not (['&'] not)*          -- juxtaposition is AND, as in mitmproxy
//   not        := '!' not | primary
//   primary    := '(' expression ')' | term [value] | value   -- a bare value is `~u value`
//   term       := '~' key [':' op]
//   value      := bare word (no whitespace, `(`, `)`, `&`, `|`, `"`) | "quoted" (\" and \\ escapes)
//
// Keys: the mitmproxy subset `u d q s m c h hq hs b bq bs t marked comment replay`,
// aitmproxy's `origin scope client`, and the row fields mitmproxy has no word for:
// `path query duration size mark ws`, plus `text` for full-text search. Each key
// has a default operator (regex for text, equals for enumerated fields, greater-
// than for duration and size); `:op` overrides it with one of
// `contains eq glob re json gt lt`.

/// Where and why an expression failed to parse. `offset` counts characters from
/// the start of the text.
public struct FilterParseError: Error, Hashable, Sendable, CustomStringConvertible {
    public enum Kind: Hashable, Sendable {
        /// The text ended where a filter was expected.
        case unexpectedEnd
        /// An operator or `)` where a filter was expected.
        case unexpectedToken
        /// `~` followed by a name this grammar does not know.
        case unknownTerm
        /// `~key:op` with an unknown `op`.
        case unknownOperator
        /// `:op` on a key that takes no operator (`~s`, `~q`, `~marked`, `~replay`, `~text`).
        case operatorNotAllowed
        /// A key that needs a value had none.
        case missingValue
        /// A `"` with no closing `"`.
        case unterminatedQuote
        /// `(` with no matching `)`.
        case expectedClosingParenthesis
        /// Text left over after a complete expression.
        case trailingInput
    }

    public var kind: Kind
    public var offset: Int
    public var message: String

    public init(_ kind: Kind, offset: Int, message: String) {
        self.kind = kind
        self.offset = offset
        self.message = message
    }

    public var description: String { "\(message) (at \(offset))" }
}

// MARK: - Parsing

extension FilterExpression {
    /// Parses the text form. Empty or blank text is `.matchAll`.
    public static func parse(_ text: String) throws(FilterParseError) -> FilterExpression {
        var parser = FilterParser(tokens: try FilterLexer.tokenize(text))
        return try parser.parseExpression()
    }
}

/// What a `~key` means.
enum FilterKey {
    /// A field test; the value is required.
    case field(FilterField)
    case anyHeader
    case anyBody
    /// A fixed term that takes neither value nor operator (`~s`, `~q`, `~marked`, `~replay`).
    case flag(FilterExpression)
    /// `~text value`: full-text search; takes no operator.
    case fullText

    static func named(_ key: String) -> FilterKey? {
        switch key {
        case "h": .anyHeader
        case "b": .anyBody
        case "s": .flag(.term(.hasResponse))
        case "q": .flag(.not(.term(.hasResponse)))
        case "marked": .flag(.term(.marked))
        case "replay": .flag(.term(.replay))
        case "text": .fullText
        default: FilterField.named(key).map { .field($0) }
        }
    }
}

struct FilterToken: Equatable {
    enum Kind: Equatable {
        case leftParen, rightParen, and, or, not
        /// `~key` or `~key:op`; `opOffset` is where the op name starts.
        case term(key: String, op: String?, opOffset: Int)
        case value(String)
        case end
    }

    var kind: Kind
    var offset: Int
}

enum FilterLexer {
    static func tokenize(_ text: String) throws(FilterParseError) -> [FilterToken] {
        let chars = Array(text)
        var tokens: [FilterToken] = []
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            if ch.isWhitespace {
                i += 1
                continue
            }
            let start = i
            switch ch {
            case "(": tokens.append(FilterToken(kind: .leftParen, offset: start)); i += 1
            case ")": tokens.append(FilterToken(kind: .rightParen, offset: start)); i += 1
            case "&": tokens.append(FilterToken(kind: .and, offset: start)); i += 1
            case "|": tokens.append(FilterToken(kind: .or, offset: start)); i += 1
            case "!": tokens.append(FilterToken(kind: .not, offset: start)); i += 1
            case "\"":
                var value = ""
                i += 1
                var closed = false
                while i < chars.count {
                    let c = chars[i]
                    if c == "\\", i + 1 < chars.count, chars[i + 1] == "\"" || chars[i + 1] == "\\" {
                        value.append(chars[i + 1])
                        i += 2
                    } else if c == "\"" {
                        closed = true
                        i += 1
                        break
                    } else {
                        value.append(c)
                        i += 1
                    }
                }
                guard closed else {
                    throw FilterParseError(.unterminatedQuote, offset: start, message: "Missing closing quote")
                }
                tokens.append(FilterToken(kind: .value(value), offset: start))
            case "~":
                i += 1
                var key = ""
                while i < chars.count, chars[i].isLetter || chars[i].isNumber || chars[i] == "_" {
                    key.append(chars[i])
                    i += 1
                }
                guard !key.isEmpty else {
                    throw FilterParseError(.unknownTerm, offset: start, message: "Expected a filter name after ~")
                }
                var op: String?
                var opOffset = i
                if i < chars.count, chars[i] == ":" {
                    i += 1
                    opOffset = i
                    var name = ""
                    while i < chars.count, chars[i].isLetter {
                        name.append(chars[i])
                        i += 1
                    }
                    op = name
                }
                tokens.append(FilterToken(kind: .term(key: key, op: op, opOffset: opOffset), offset: start))
            default:
                var word = ""
                while i < chars.count, !chars[i].isWhitespace, !"()&|\"".contains(chars[i]) {
                    word.append(chars[i])
                    i += 1
                }
                tokens.append(FilterToken(kind: .value(word), offset: start))
            }
        }
        tokens.append(FilterToken(kind: .end, offset: chars.count))
        return tokens
    }
}

struct FilterParser {
    private let tokens: [FilterToken]
    private var position = 0

    init(tokens: [FilterToken]) {
        self.tokens = tokens
    }

    private var current: FilterToken {
        // The lexer always appends `.end`, so the position never runs past it.
        tokens[min(position, tokens.count - 1)]
    }

    private mutating func advance() { position += 1 }

    mutating func parseExpression() throws(FilterParseError) -> FilterExpression {
        if case .end = current.kind { return .matchAll }
        let expression = try parseOr()
        guard case .end = current.kind else {
            throw FilterParseError(.trailingInput, offset: current.offset, message: "Unexpected text after the filter")
        }
        return expression
    }

    private mutating func parseOr() throws(FilterParseError) -> FilterExpression {
        var children = [try parseAnd()]
        while case .or = current.kind {
            advance()
            children.append(try parseAnd())
        }
        return children.count == 1 ? children[0] : .or(children)
    }

    private mutating func parseAnd() throws(FilterParseError) -> FilterExpression {
        var children = [try parseNot()]
        while true {
            switch current.kind {
            case .and:
                advance()
                children.append(try parseNot())
            case .leftParen, .not, .term, .value:
                children.append(try parseNot())
            case .or, .rightParen, .end:
                return children.count == 1 ? children[0] : .and(children)
            }
        }
    }

    private mutating func parseNot() throws(FilterParseError) -> FilterExpression {
        if case .not = current.kind {
            advance()
            return .not(try parseNot())
        }
        return try parsePrimary()
    }

    private mutating func parsePrimary() throws(FilterParseError) -> FilterExpression {
        let token = current
        switch token.kind {
        case .leftParen:
            advance()
            let inner = try parseOr()
            guard case .rightParen = current.kind else {
                throw FilterParseError(.expectedClosingParenthesis, offset: current.offset, message: "Expected )")
            }
            advance()
            return inner
        case .value(let word):
            advance()
            return .term(.field(.url, .regex, word))
        case .term(let key, let op, let opOffset):
            advance()
            return try parseTerm(key: key, op: op, opOffset: opOffset, at: token.offset)
        case .end:
            throw FilterParseError(.unexpectedEnd, offset: token.offset, message: "Expected a filter")
        case .rightParen, .and, .or, .not:
            throw FilterParseError(.unexpectedToken, offset: token.offset, message: "Expected a filter")
        }
    }

    private mutating func parseTerm(key: String, op opName: String?, opOffset: Int,
                                    at offset: Int) throws(FilterParseError) -> FilterExpression {
        guard let filterKey = FilterKey.named(key) else {
            throw FilterParseError(.unknownTerm, offset: offset, message: "Unknown filter ~\(key)")
        }
        var op: FilterOperator?
        if let opName {
            guard let known = FilterOperator.named(opName), known != .fullText else {
                throw FilterParseError(.unknownOperator, offset: opOffset, message: "Unknown operator :\(opName)")
            }
            op = known
        }

        switch filterKey {
        case .flag(let expression):
            guard op == nil else {
                throw FilterParseError(.operatorNotAllowed, offset: opOffset, message: "~\(key) takes no operator")
            }
            return expression
        case .fullText:
            guard op == nil else {
                throw FilterParseError(.operatorNotAllowed, offset: opOffset, message: "~text takes no operator")
            }
            return .term(.field(.url, .fullText, try requireValue(for: key)))
        case .anyHeader:
            return .term(.anyHeader(op ?? .regex, try requireValue(for: key)))
        case .anyBody:
            return .term(.anyBody(op ?? .regex, try requireValue(for: key)))
        case .field(let field):
            return .term(.field(field, op ?? field.defaultOperator, try requireValue(for: key)))
        }
    }

    private mutating func takeValue() -> String? {
        guard case .value(let value) = current.kind else { return nil }
        advance()
        return value
    }

    private mutating func requireValue(for key: String) throws(FilterParseError) -> String {
        guard let value = takeValue() else {
            throw FilterParseError(.missingValue, offset: current.offset, message: "~\(key) needs a value")
        }
        return value
    }
}

// MARK: - Printing

extension FilterExpression {
    /// The canonical text form: `~m POST & ~s`, `!(~d cdn | ~c 304)`, …
    public var text: String {
        switch self {
        case .term(let term):
            return term.text
        case .not(let child):
            if child == .term(.hasResponse) { return "~q" }
            switch child {
            case .and, .or: return "!(\(child.text))"
            case .term, .not: return "!\(child.text)"
            }
        case .and(let children):
            return children.map { child in
                switch child {
                case .and, .or: "(\(child.text))"
                case .term, .not: child.text
                }
            }.joined(separator: " & ")
        case .or(let children):
            return children.map { child in
                switch child {
                case .or: "(\(child.text))"
                case .and, .term, .not: child.text
                }
            }.joined(separator: " | ")
        }
    }
}

extension FilterTerm {
    /// The term as text: a mitmproxy spelling where one exists, else `~key:op value`.
    public var text: String {
        switch self {
        case .replay:
            return "~replay"
        case .anyHeader(let op, let value):
            return "~h\(Self.suffix(op, default: .regex)) \(Self.quote(value))"
        case .anyBody(let op, let value):
            return "~b\(Self.suffix(op, default: .regex)) \(Self.quote(value))"
        case .field(let field, let op, let value):
            if self == .hasResponse { return "~s" }
            if self == .marked { return "~marked" }
            if op == .fullText { return "~text \(Self.quote(value))" }
            return "~\(field.key)\(Self.suffix(op, default: field.defaultOperator)) \(Self.quote(value))"
        }
    }

    private static func suffix(_ op: FilterOperator, default defaultOp: FilterOperator) -> String {
        op == defaultOp ? "" : ":\(op.key)"
    }

    /// Bare when the lexer would read it back as one word; quoted otherwise.
    static func quote(_ value: String) -> String {
        let bare = !value.isEmpty
            && !value.contains { $0.isWhitespace || "()&|\"".contains($0) }
            && !value.hasPrefix("~") && !value.hasPrefix("!")
        if bare { return value }
        var out = "\""
        for ch in value {
            if ch == "\"" || ch == "\\" { out.append("\\") }
            out.append(ch)
        }
        out.append("\"")
        return out
    }
}
