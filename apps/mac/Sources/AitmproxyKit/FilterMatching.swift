import Foundation

/// What a filter can see of one flow. `detail` may be absent (not fetched yet,
/// or evicted); header, body, content-type and JSON-path terms then evaluate
/// false rather than crash.
public struct FilterSubject: Sendable {
    public var row: FlowRow
    public var detail: FlowDetail?

    public init(row: FlowRow, detail: FlowDetail? = nil) {
        self.row = row
        self.detail = detail
    }
}

/// A filter ready to run over many rows: every regex compiled once, every
/// number parsed once. Build one per filter change and keep it; `matches` is
/// cheap enough to run over 10k rows per keystroke.
public struct CompiledFilter: Sendable {
    /// Bodies are decoded and scanned up to this many bytes (1 MiB).
    public static let bodyScanLimit = 1 << 20

    public let expression: FilterExpression
    let root: Node

    public init(_ expression: FilterExpression) {
        self.expression = expression
        self.root = Node(expression)
    }

    public init(_ stack: FilterStack) {
        self.init(stack.expression)
    }

    public init(parsing text: String) throws(FilterParseError) {
        self.init(try FilterExpression.parse(text))
    }

    public func matches(_ subject: FilterSubject) -> Bool {
        var context = MatchContext(subject: subject)
        return root.matches(&context)
    }

    /// Where the filter's `contains`, `regex` and `fullText` terms hit in text
    /// shown for `field`, for the viewers to highlight. Ranges are sorted and
    /// merged. Negated terms contribute nothing; scanning stops at `bodyScanLimit`.
    public func matchRanges(in text: String, field: FilterField) -> [Range<String.Index>] {
        var ranges: [Range<String.Index>] = []
        root.collectRanges(in: text, field: field, negated: false, into: &ranges)
        ranges.sort { $0.lowerBound < $1.lowerBound }
        var merged: [Range<String.Index>] = []
        for range in ranges {
            if let last = merged.last, range.lowerBound <= last.upperBound {
                merged[merged.count - 1] = last.lowerBound..<max(last.upperBound, range.upperBound)
            } else {
                merged.append(range)
            }
        }
        return merged
    }

    indirect enum Node: Sendable {
        case term(CompiledTerm)
        case and([Node])
        case or([Node])
        case not(Node)

        init(_ expression: FilterExpression) {
            switch expression {
            case .term(let term): self = .term(CompiledTerm(term))
            case .and(let children): self = .and(children.map(Node.init))
            case .or(let children): self = .or(children.map(Node.init))
            case .not(let child): self = .not(Node(child))
            }
        }

        func matches(_ context: inout MatchContext) -> Bool {
            switch self {
            case .term(let term):
                return term.matches(&context)
            case .and(let children):
                for child in children where !child.matches(&context) { return false }
                return true
            case .or(let children):
                for child in children where child.matches(&context) { return true }
                return false
            case .not(let child):
                return !child.matches(&context)
            }
        }

        func collectRanges(in text: String, field: FilterField, negated: Bool, into ranges: inout [Range<String.Index>]) {
            switch self {
            case .term(let term):
                if !negated { term.collectRanges(in: text, field: field, into: &ranges) }
            case .and(let children), .or(let children):
                for child in children { child.collectRanges(in: text, field: field, negated: negated, into: &ranges) }
            case .not(let child):
                child.collectRanges(in: text, field: field, negated: !negated, into: &ranges)
            }
        }
    }
}

/// One term with its regex, number and JSON path prepared.
struct CompiledTerm: Sendable {
    enum Target: Sendable {
        case field(FilterField)
        case anyHeader
        case anyBody
        case replay
    }

    let target: Target
    let op: FilterOperator
    let value: String
    /// For `regex` (searched) and `wildcard` (anchored). Nil when invalid.
    let regex: NSRegularExpression?
    /// For `greaterThan` / `lessThan`.
    let number: Double?
    /// For `jsonPath`: the path, and the expected leaf text (nil = exists).
    let jsonPath: JSONPath?
    let jsonExpected: String?
    /// False when `validationError` is set: the term matches nothing.
    let isValid: Bool

    init(_ term: FilterTerm) {
        let op: FilterOperator
        let value: String
        switch term {
        case .field(let field, let fieldOp, let fieldValue):
            target = .field(field)
            op = fieldOp
            value = fieldValue
        case .anyHeader(let headerOp, let headerValue):
            target = .anyHeader
            op = headerOp
            value = headerValue
        case .anyBody(let bodyOp, let bodyValue):
            target = .anyBody
            op = bodyOp
            value = bodyValue
        case .replay:
            target = .replay
            op = .equals
            value = ""
        }
        self.op = op
        self.value = value
        isValid = term.validationError == nil

        switch op {
        case .regex:
            regex = try? NSRegularExpression(pattern: value, options: [.caseInsensitive])
        case .wildcard:
            regex = try? NSRegularExpression(pattern: CompiledTerm.wildcardPattern(value),
                                             options: [.caseInsensitive, .dotMatchesLineSeparators])
        default:
            regex = nil
        }
        number = (op == .greaterThan || op == .lessThan) ? FilterTerm.number(value) : nil
        if op == .jsonPath {
            let parts = value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            jsonPath = parts.first.flatMap { JSONPath(String($0)) }
            jsonExpected = parts.count == 2 ? parts[1].trimmingCharacters(in: .whitespaces) : nil
        } else {
            jsonPath = nil
            jsonExpected = nil
        }
    }

    /// `*` → any run, `?` → one character, everything else literal; anchored.
    static func wildcardPattern(_ glob: String) -> String {
        var pattern = "^"
        for ch in glob {
            switch ch {
            case "*": pattern += ".*"
            case "?": pattern += "."
            default: pattern += NSRegularExpression.escapedPattern(for: String(ch))
            }
        }
        return pattern + "$"
    }

    // MARK: Matching

    func matches(_ context: inout MatchContext) -> Bool {
        guard isValid else { return false }
        if op == .fullText { return matchesText(context.fullText(), status: false) }
        switch target {
        case .replay:
            return context.subject.row.isReplay
        case .anyHeader:
            return matchesHeaders(context.headers(response: false))
                || matchesHeaders(context.headers(response: true))
        case .anyBody:
            return matchesBody(context.bodyText(response: false), data: context.bodyData(response: false))
                || matchesBody(context.bodyText(response: true), data: context.bodyData(response: true))
        case .field(let field):
            switch field {
            case .requestHeader:
                return matchesHeaders(context.headers(response: false))
            case .responseHeader:
                return matchesHeaders(context.headers(response: true))
            case .requestBody:
                return matchesBody(context.bodyText(response: false), data: context.bodyData(response: false))
            case .responseBody:
                return matchesBody(context.bodyText(response: true), data: context.bodyData(response: true))
            case .contentType:
                return context.contentTypes().contains { matchesText($0, status: false) }
            case .wsDirection:
                // Frames are not in FlowDetail yet; nothing to compare against.
                return false
            case .status, .duration, .size:
                if op == .greaterThan || op == .lessThan {
                    guard let number, let actual = context.number(for: field) else { return false }
                    return op == .greaterThan ? actual > number : actual < number
                }
                guard let text = context.text(for: field) else { return false }
                return matchesText(text, status: field == .status)
            case .url, .host, .path, .query, .method, .client, .mark, .comment, .origin, .scope, .state:
                guard let text = context.text(for: field) else { return false }
                return matchesText(text, status: false)
            }
        }
    }

    /// `contains` / `equals` / `wildcard` / `regex` against one piece of text.
    private func matchesText(_ text: String, status: Bool) -> Bool {
        switch op {
        case .contains, .fullText:
            return value.isEmpty || text.range(of: value, options: [.caseInsensitive]) != nil
        case .equals:
            if status, value.count < 3, !value.isEmpty, value.allSatisfy(\.isNumber) {
                return text.hasPrefix(value)
            }
            return text.caseInsensitiveCompare(value) == .orderedSame
        case .wildcard, .regex:
            guard let regex else { return false }
            return regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
        case .jsonPath, .greaterThan, .lessThan:
            return false
        }
    }

    /// Headers are matched as `name: value` lines. `equals` takes `name` (a header
    /// of that name exists) or `name: value` (that header has that value).
    private func matchesHeaders(_ headers: [HTTPMessage.Header]?) -> Bool {
        guard let headers else { return false }
        switch op {
        case .equals:
            let parts = value.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let name = parts.first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            let expected = parts.count == 2 ? parts[1].trimmingCharacters(in: .whitespaces) : nil
            return headers.contains { header in
                header.name.caseInsensitiveCompare(name) == .orderedSame
                    && (expected.map { header.value.caseInsensitiveCompare($0) == .orderedSame } ?? true)
            }
        case .contains, .wildcard, .regex:
            return headers.contains { matchesText("\($0.name): \($0.value)", status: false) }
        case .jsonPath, .greaterThan, .lessThan, .fullText:
            return false
        }
    }

    private func matchesBody(_ text: String?, data: Data?) -> Bool {
        if op == .jsonPath {
            guard let jsonPath, let data,
                  let root = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
                  let leaf = jsonPath.resolve(in: root)
            else { return false }
            guard let jsonExpected else { return true }
            guard let actual = JSONPath.leafText(leaf) else { return false }
            return actual.caseInsensitiveCompare(jsonExpected) == .orderedSame
        }
        guard let text else { return false }
        return matchesText(text, status: false)
    }

    // MARK: Highlighting

    func collectRanges(in text: String, field: FilterField, into ranges: inout [Range<String.Index>]) {
        guard isValid, !value.isEmpty else { return }
        let applies: Bool
        switch target {
        case .replay: applies = false
        case .anyHeader: applies = field.isHeader
        case .anyBody: applies = field.isBody
        case .field(let termField): applies = termField == field
        }
        guard applies || op == .fullText else { return }

        let scanned = text.prefix(CompiledFilter.bodyScanLimit)
        switch op {
        case .contains, .fullText:
            var searchRange = scanned.startIndex..<scanned.endIndex
            while let found = text.range(of: value, options: [.caseInsensitive], range: searchRange) {
                ranges.append(found)
                guard found.upperBound < scanned.endIndex else { break }
                searchRange = found.upperBound..<scanned.endIndex
            }
        case .regex:
            guard let regex else { return }
            let nsRange = NSRange(scanned.startIndex..<scanned.endIndex, in: text)
            for match in regex.matches(in: text, range: nsRange) where match.range.length > 0 {
                if let range = Range(match.range, in: text) { ranges.append(range) }
            }
        case .equals, .wildcard, .jsonPath, .greaterThan, .lessThan:
            return
        }
    }
}

/// Per-subject caches so a filter with several body or header terms decodes
/// each message once.
struct MatchContext {
    let subject: FilterSubject
    private var requestBodyText: String??
    private var responseBodyText: String??
    private var fullTextCache: String?

    init(subject: FilterSubject) {
        self.subject = subject
    }

    private var request: HTTPMessage? { subject.detail?.request }
    private var response: HTTPMessage? { subject.detail?.response }

    func headers(response isResponse: Bool) -> [HTTPMessage.Header]? {
        (isResponse ? response : request)?.headers
    }

    func bodyData(response isResponse: Bool) -> Data? {
        guard let body = (isResponse ? response : request)?.body else { return nil }
        return body.count > CompiledFilter.bodyScanLimit ? body.prefix(CompiledFilter.bodyScanLimit) : body
    }

    /// The body's first `bodyScanLimit` bytes as text (invalid UTF-8 repaired), nil when there is no body.
    mutating func bodyText(response isResponse: Bool) -> String? {
        if isResponse, let cached = responseBodyText { return cached }
        if !isResponse, let cached = requestBodyText { return cached }
        let text = bodyData(response: isResponse).map { String(decoding: $0, as: UTF8.self) }
        if isResponse { responseBodyText = .some(text) } else { requestBodyText = .some(text) }
        return text
    }

    func contentTypes() -> [String] {
        [response?.contentType, request?.contentType].compactMap { $0 }
    }

    /// URL, every header line and both bodies, for `fullText`.
    mutating func fullText() -> String {
        if let fullTextCache { return fullTextCache }
        var parts = [subject.row.url]
        for isResponse in [false, true] {
            for header in headers(response: isResponse) ?? [] { parts.append("\(header.name): \(header.value)") }
            if let body = bodyText(response: isResponse) { parts.append(body) }
        }
        let joined = parts.joined(separator: "\n")
        fullTextCache = joined
        return joined
    }

    /// Row-level fields as text; nil when the row has no value for the field.
    func text(for field: FilterField) -> String? {
        let row = subject.row
        switch field {
        case .url: return row.url
        case .host: return row.authority
        case .path: return row.path
        case .query: return row.query
        case .method: return row.method.label
        case .status: return row.status.map(String.init)
        case .client: return row.client?.name
        case .duration, .size: return number(for: field).map { String(Int64($0)) }
        case .mark: return row.mark?.rawValue
        case .comment: return row.comment
        case .origin:
            switch row.origin {
            case .client: return "client"
            case .human: return "human"
            case .agent: return "agent"
            case .imported: return "imported"
            }
        case .scope: return row.inScope ? "in" : "out"
        case .state: return row.state.label
        case .requestHeader, .responseHeader, .requestBody, .responseBody, .contentType, .wsDirection:
            return nil
        }
    }

    /// `status` as-is, `duration` in milliseconds, `size` as request + response bytes.
    func number(for field: FilterField) -> Double? {
        let row = subject.row
        switch field {
        case .status:
            return row.status.map(Double.init)
        case .duration:
            guard let duration = row.duration else { return nil }
            let (seconds, attoseconds) = duration.components
            return Double(seconds) * 1_000 + Double(attoseconds) / 1e15
        case .size:
            guard row.requestBytes != nil || row.responseBytes != nil else { return nil }
            return Double((row.requestBytes ?? 0) + (row.responseBytes ?? 0))
        default:
            return nil
        }
    }
}
