import Foundation

// The flow filter (foundation §2.7 "Filter bar & search", §3.2). One filter has
// two equivalent forms: the GUI's stacked rows (`FilterStack`) and the portable
// mitmproxy-style expression (`FilterExpression`, see FilterExpressionSyntax.swift).
// Matching lives in FilterMatching.swift; saved filters in FilterStore.swift.

/// What a filter row looks at.
public enum FilterField: String, CaseIterable, Hashable, Sendable, Codable {
    case url, host, path, query, method, status
    case requestHeader, responseHeader, requestBody, responseBody, contentType
    case client, duration, size, mark, comment, origin, scope, state
    /// WebSocket frame direction (`sent` / `received`). Frames are not part of
    /// `FlowDetail` yet, so terms on this field match nothing until they are.
    case wsDirection

    public var title: String {
        switch self {
        case .url: "URL"
        case .host: "Host"
        case .path: "Path"
        case .query: "Query"
        case .method: "Method"
        case .status: "Status"
        case .requestHeader: "Request header"
        case .responseHeader: "Response header"
        case .requestBody: "Request body"
        case .responseBody: "Response body"
        case .contentType: "Content-type"
        case .client: "Client"
        case .duration: "Duration"
        case .size: "Size"
        case .mark: "Colour"
        case .comment: "Comment"
        case .origin: "Origin"
        case .scope: "Scope"
        case .state: "State"
        case .wsDirection: "WebSocket direction"
        }
    }

    /// `status`, `duration` (ms) and `size` (bytes) compare as numbers under
    /// `greaterThan` / `lessThan`.
    public var isNumeric: Bool {
        switch self {
        case .status, .duration, .size: true
        default: false
        }
    }

    public var isBody: Bool { self == .requestBody || self == .responseBody }
    public var isHeader: Bool { self == .requestHeader || self == .responseHeader }

    /// The operators that make sense for this field, in menu order.
    public var operators: [FilterOperator] {
        if isNumeric { return [.equals, .greaterThan, .lessThan, .contains, .wildcard, .regex] }
        if isBody { return [.contains, .equals, .wildcard, .regex, .jsonPath, .fullText] }
        switch self {
        case .method, .mark, .origin, .scope, .state, .wsDirection:
            return [.equals, .contains, .wildcard, .regex]
        default:
            return [.contains, .equals, .wildcard, .regex, .fullText]
        }
    }

    /// The term name in the expression form (`~u`, `~d`, …).
    var key: String {
        switch self {
        case .url: "u"
        case .host: "d"
        case .path: "path"
        case .query: "query"
        case .method: "m"
        case .status: "c"
        case .requestHeader: "hq"
        case .responseHeader: "hs"
        case .requestBody: "bq"
        case .responseBody: "bs"
        case .contentType: "t"
        case .client: "client"
        case .duration: "duration"
        case .size: "size"
        case .mark: "mark"
        case .comment: "comment"
        case .origin: "origin"
        case .scope: "scope"
        case .state: "state"
        case .wsDirection: "ws"
        }
    }

    /// The operator a bare `~key value` means: regex for text (as mitmproxy),
    /// equals for enumerated fields, greater-than for duration and size.
    var defaultOperator: FilterOperator {
        switch self {
        case .method, .status, .mark, .origin, .scope, .state, .wsDirection: .equals
        case .duration, .size: .greaterThan
        default: .regex
        }
    }

    static func named(_ key: String) -> FilterField? {
        allCases.first { $0.key == key }
    }
}

/// How a filter row compares its value.
public enum FilterOperator: String, CaseIterable, Hashable, Sendable, Codable {
    /// Case-insensitive substring.
    case contains
    /// Case-insensitive equality. On `status`, a one- or two-digit value is a
    /// class prefix: `5` matches 502, `20` matches 204.
    case equals
    /// Glob over the whole value: `*` any run, `?` one character.
    case wildcard
    /// Case-insensitive regular expression (NSRegularExpression), searched.
    case regex
    /// Bodies only. `path` or `path=expected` where path is dotted / bracketed
    /// (`user.role`, `items[0].id`); the leaf is stringified and compared with
    /// `equals` semantics. Not full JSONPath.
    case jsonPath
    /// `contains` across the URL, all headers and both bodies; the field is ignored.
    case fullText
    /// Numeric fields only.
    case greaterThan, lessThan

    public var title: String {
        switch self {
        case .contains: "contains"
        case .equals: "equals"
        case .wildcard: "wildcard"
        case .regex: "regex"
        case .jsonPath: "JSON path"
        case .fullText: "full text"
        case .greaterThan: "greater than"
        case .lessThan: "less than"
        }
    }

    /// The `:op` suffix in the expression form.
    var key: String {
        switch self {
        case .contains: "contains"
        case .equals: "eq"
        case .wildcard: "glob"
        case .regex: "re"
        case .jsonPath: "json"
        case .fullText: "text"
        case .greaterThan: "gt"
        case .lessThan: "lt"
        }
    }

    static func named(_ key: String) -> FilterOperator? {
        allCases.first { $0.key == key || $0.rawValue.lowercased() == key.lowercased() }
    }
}

/// One row of the stacked filter: `Field · Operator · Value`, optionally negated.
public struct FilterRow: Hashable, Sendable, Codable {
    public var field: FilterField
    public var op: FilterOperator
    public var value: String
    public var negated: Bool

    public init(_ field: FilterField, _ op: FilterOperator, _ value: String = "", negated: Bool = false) {
        self.field = field
        self.op = op
        self.value = value
        self.negated = negated
    }

    public var term: FilterTerm { .field(field, op, value) }

    public var expression: FilterExpression {
        negated ? .not(.term(term)) : .term(term)
    }

    /// Why this row can never match, or nil when it is well formed. A row with a
    /// validation error matches nothing.
    public var validationError: String? { term.validationError }
}

/// The GUI's filter: rows combined with one AND / OR.
public struct FilterStack: Hashable, Sendable, Codable {
    public enum Combinator: String, CaseIterable, Hashable, Sendable, Codable {
        case and, or

        public var title: String {
            switch self {
            case .and: "All"
            case .or: "Any"
            }
        }
    }

    public var rows: [FilterRow]
    public var combinator: Combinator

    public init(rows: [FilterRow] = [], combinator: Combinator = .and) {
        self.rows = rows
        self.combinator = combinator
    }

    /// The stack for a flat expression: one term, or one AND / OR of terms, each
    /// optionally negated. Nil when the expression nests (`a & (b | c)`) or uses
    /// a term the row model cannot show (`~h`, `~b`, `~replay`).
    public init?(expression: FilterExpression) {
        switch expression {
        case .term, .not:
            guard let row = FilterRow(expression: expression) else { return nil }
            self.init(rows: [row], combinator: .and)
        case .and(let children):
            guard let rows = FilterStack.rows(from: children) else { return nil }
            self.init(rows: rows, combinator: .and)
        case .or(let children):
            guard !children.isEmpty, let rows = FilterStack.rows(from: children) else { return nil }
            self.init(rows: rows, combinator: .or)
        }
    }

    private static func rows(from children: [FilterExpression]) -> [FilterRow]? {
        var rows: [FilterRow] = []
        rows.reserveCapacity(children.count)
        for child in children {
            guard let row = FilterRow(expression: child) else { return nil }
            rows.append(row)
        }
        return rows
    }

    public var isEmpty: Bool { rows.isEmpty }

    /// The portable form. Empty → `.matchAll`; one row → that row's expression.
    public var expression: FilterExpression {
        if rows.count == 1, let row = rows.first { return row.expression }
        let children = rows.map(\.expression)
        switch combinator {
        case .and: return .and(children)
        case .or: return children.isEmpty ? .matchAll : .or(children)
        }
    }

    /// The expression as text, for the "advanced" view and for copying between surfaces.
    public var text: String { expression.text }

    /// Convenience for one-off checks; hold a `CompiledFilter` when matching many rows.
    public func matches(_ subject: FilterSubject) -> Bool {
        CompiledFilter(self).matches(subject)
    }
}

extension FilterRow {
    /// A row for `term` or `!term` when the term is a field test.
    init?(expression: FilterExpression) {
        switch expression {
        case .term(.field(let field, let op, let value)):
            self.init(field, op, value)
        case .not(.term(.field(let field, let op, let value))):
            self.init(field, op, value, negated: true)
        default:
            return nil
        }
    }
}

/// One test in an expression. Field tests are what rows hold; the other cases
/// are mitmproxy terms the row model has no place for.
public enum FilterTerm: Hashable, Sendable {
    case field(FilterField, FilterOperator, String)
    /// `~h`: any request or response header.
    case anyHeader(FilterOperator, String)
    /// `~b`: request or response body.
    case anyBody(FilterOperator, String)
    /// `~replay`: the flow was replayed.
    case replay

    /// `~s`: the flow has a response. Spelled as "status contains empty", which
    /// is true exactly when a status exists.
    public static let hasResponse: FilterTerm = .field(.status, .contains, "")
    /// `~marked`: the flow has a colour mark.
    public static let marked: FilterTerm = .field(.mark, .contains, "")

    /// Why this term can never match, or nil when it is well formed.
    public var validationError: String? {
        switch self {
        case .replay:
            return nil
        case .field(let field, let op, let value):
            return FilterTerm.validate(op: op, value: value, numeric: field.isNumeric, body: field.isBody,
                                       fieldTitle: field.title)
        case .anyHeader(let op, let value):
            return FilterTerm.validate(op: op, value: value, numeric: false, body: false, fieldTitle: "Header")
        case .anyBody(let op, let value):
            return FilterTerm.validate(op: op, value: value, numeric: false, body: true, fieldTitle: "Body")
        }
    }

    private static func validate(op: FilterOperator, value: String, numeric: Bool, body: Bool,
                                 fieldTitle: String) -> String? {
        switch op {
        case .contains, .equals, .wildcard, .fullText:
            return nil
        case .regex:
            do {
                _ = try NSRegularExpression(pattern: value, options: [.caseInsensitive])
                return nil
            } catch {
                return "Invalid regular expression: \(value)"
            }
        case .jsonPath:
            guard body else { return "JSON path applies to request and response bodies only" }
            return JSONPath(value) == nil ? "Invalid JSON path: \(value)" : nil
        case .greaterThan, .lessThan:
            guard numeric else { return "\(fieldTitle) is not numeric" }
            return FilterTerm.number(value) == nil ? "Expected a number, got \(value)" : nil
        }
    }

    /// Numeric values are plain decimals (`500`, `1.5`); no unit suffixes.
    static func number(_ value: String) -> Double? {
        Double(value.trimmingCharacters(in: .whitespaces))
    }
}

/// The portable filter: a boolean tree of terms. `!` binds tighter than `&`,
/// which binds tighter than `|`. Parenthesised groups stay as nested nodes, so
/// `(a & b) & c` is `.and([.and([a, b]), c])`, not flattened.
///
/// Canonical values round-trip through `text` and `parse`: no empty or
/// single-child `.and` / `.or` except `.matchAll`, and `fullText` terms on
/// `.url` (the printer writes every `fullText` term as `~text`, which parses
/// back onto `.url`).
public indirect enum FilterExpression: Hashable, Sendable, CustomStringConvertible {
    case term(FilterTerm)
    case and([FilterExpression])
    case or([FilterExpression])
    case not(FilterExpression)

    /// The empty filter: matches every flow and prints as "".
    public static let matchAll: FilterExpression = .and([])

    public var description: String { text }

    /// The stacked form, when this expression is flat enough to show as rows.
    public var stack: FilterStack? { FilterStack(expression: self) }

    /// Every term's `validationError`, in reading order.
    public var validationErrors: [String] {
        switch self {
        case .term(let term): term.validationError.map { [$0] } ?? []
        case .and(let children), .or(let children): children.flatMap(\.validationErrors)
        case .not(let child): child.validationErrors
        }
    }

    /// Convenience for one-off checks; hold a `CompiledFilter` when matching many rows.
    public func matches(_ subject: FilterSubject) -> Bool {
        CompiledFilter(self).matches(subject)
    }
}

/// A minimal dotted / bracketed path into parsed JSON: `user.role`,
/// `items[0].id`, `$.a.b`, `[2]`. Keys are bare identifiers (anything but `.`,
/// `[`, `]`); indexes are non-negative integers.
struct JSONPath: Hashable, Sendable {
    enum Step: Hashable, Sendable {
        case key(String)
        case index(Int)
    }

    let steps: [Step]

    init?(_ text: String) {
        var rest = Substring(text.trimmingCharacters(in: .whitespaces))
        if rest.hasPrefix("$") { rest = rest.dropFirst() }
        if rest.hasPrefix(".") { rest = rest.dropFirst() }
        var steps: [Step] = []
        var key = ""
        var index = rest.startIndex
        while index < rest.endIndex {
            let ch = rest[index]
            switch ch {
            case ".":
                // A dot ends a key, or follows a `]` as in `items[0].id`; `a..b` is malformed.
                if key.isEmpty {
                    guard case .index? = steps.last else { return nil }
                } else {
                    steps.append(.key(key))
                    key = ""
                }
                index = rest.index(after: index)
            case "[":
                if !key.isEmpty {
                    steps.append(.key(key))
                    key = ""
                }
                guard let close = rest[index...].firstIndex(of: "]") else { return nil }
                let inner = rest[rest.index(after: index)..<close]
                guard let n = Int(inner), n >= 0 else { return nil }
                steps.append(.index(n))
                index = rest.index(after: close)
            case "]":
                return nil
            default:
                key.append(ch)
                index = rest.index(after: index)
            }
        }
        if !key.isEmpty { steps.append(.key(key)) }
        guard !steps.isEmpty else { return nil }
        self.steps = steps
    }

    /// The leaf at this path in a `JSONSerialization` object graph, or nil.
    func resolve(in root: Any) -> Any? {
        var current: Any = root
        for step in steps {
            switch step {
            case .key(let key):
                guard let dict = current as? [String: Any], let next = dict[key] else { return nil }
                current = next
            case .index(let i):
                guard let array = current as? [Any], i < array.count else { return nil }
                current = array[i]
            }
        }
        return current
    }

    /// The text a leaf compares as: strings as-is, numbers in their shortest
    /// form, booleans `true` / `false`, null `null`. Objects and arrays have no text.
    static func leafText(_ leaf: Any) -> String? {
        if let s = leaf as? String { return s }
        if leaf is NSNull { return "null" }
        if let n = leaf as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue ? "true" : "false" }
            return n.stringValue
        }
        return nil
    }
}
