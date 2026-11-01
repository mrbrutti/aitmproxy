import AitmBusClient
import Foundation

/// A breakpoint rule (foundation §2.7 "Rules…", Proxyman's form; F3 carries
/// them to the core as `flow.intercept {enabled, rules}`): which requests pause.
public struct BreakpointRule: Identifiable, Hashable, Sendable, Codable {
    public enum Matching: String, CaseIterable, Hashable, Sendable, Codable {
        case wildcard, regex
        public var title: String { self == .wildcard ? "Wildcard" : "Regex" }
    }

    public var id: UUID
    public var name: String
    public var url: String
    public var matching: Matching
    /// Empty = any method.
    public var method: String
    public var onRequest: Bool
    public var onResponse: Bool
    public var enabled: Bool
    /// Marks matching flows with this colour.
    public var flag: MarkColor?

    public init(id: UUID = UUID(), name: String = "", url: String = "", matching: Matching = .wildcard, method: String = "",
                onRequest: Bool = true, onResponse: Bool = false, enabled: Bool = true, flag: MarkColor? = nil) {
        self.id = id
        self.name = name
        self.url = url
        self.matching = matching
        self.method = method
        self.onRequest = onRequest
        self.onResponse = onResponse
        self.enabled = enabled
        self.flag = flag
    }

    /// nil when the rule can be saved.
    public var validationError: String? {
        if url.trimmingCharacters(in: .whitespaces).isEmpty { return "Enter a URL pattern" }
        if matching == .regex, (try? NSRegularExpression(pattern: url)) == nil { return "That regex does not compile" }
        if !onRequest, !onResponse { return "Choose Request, Response or both" }
        return nil
    }

    /// Whether a flow matches this rule's URL and method.
    public func matches(_ row: FlowRow) -> Bool {
        if !method.isEmpty, method.uppercased() != row.method.label { return false }
        switch matching {
        case .wildcard:
            return Self.wildcardMatches(pattern: url, text: row.url)
        case .regex:
            guard let re = try? NSRegularExpression(pattern: url, options: [.caseInsensitive]) else { return false }
            return re.firstMatch(in: row.url, range: NSRange(row.url.startIndex..., in: row.url)) != nil
        }
    }

    /// `*` any run, `?` one character; a pattern without `*` or `?` matches as a
    /// substring, as Proxyman does. Case-insensitive. The same conversion gives the
    /// wire form (`wildcardRegex`), so the preview and the core agree.
    public static func wildcardMatches(pattern: String, text: String) -> Bool {
        guard let re = try? NSRegularExpression(pattern: wildcardRegex(pattern), options: [.caseInsensitive]) else { return false }
        return re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    /// The anchored regex a wildcard pattern means: `*` → `.*`, `?` → `.`, every
    /// other character literal; no `*`/`?` → a substring (`.*pat.*`). Plain ASCII
    /// escapes only, so ICU (the preview) and Rust's `regex` (the core) read it alike.
    public static func wildcardRegex(_ pattern: String) -> String {
        let substring = !pattern.contains("*") && !pattern.contains("?")
        var body = substring ? ".*" : ""
        for ch in pattern {
            switch ch {
            case "*": body += ".*"
            case "?": body += "."
            case "\\", ".", "+", "(", ")", "|", "[", "]", "{", "}", "^", "$": body += "\\\(ch)"
            default: body.append(ch)
            }
        }
        if substring { body += ".*" }
        return "^" + body + "$"
    }

    /// The wire form of one `flow.intercept {rules}` entry: only the fields the core
    /// knows (`crates/aitm-plugins/src/intercept.rs::rule_param_fields`), since one
    /// unknown key rejects the whole call and leaves intercept armed on the old
    /// rules — `match` and `flag` stay in the app. Phases are `request`, `response`
    /// and `any` (both). `url` is always the core's `{regex}` object
    /// (`crates/aitm-rules/src/bus.rs::parse_url_match`): a wildcard travels as the
    /// regex `wildcardRegex` builds, case-insensitive like the preview, because the
    /// core's own wildcard form has no `?`, no substring match and is case-sensitive.
    public var arguments: [String: JSONValue] {
        var a: [String: JSONValue] = [
            "id": .string(id.uuidString),
            "phase": .string(onRequest && onResponse ? "any" : onResponse ? "response" : "request"),
        ]
        switch matching {
        case .wildcard: a["url"] = .object(["regex": .string("(?i)" + Self.wildcardRegex(url))])
        case .regex: a["url"] = .object(["regex": .string(url)])
        }
        if !method.isEmpty { a["method"] = .string(method.uppercased()) }
        if !name.isEmpty { a["name"] = .string(name) }
        return a
    }
}

/// The rule set, kept in `rules.json` until F3 moves it into the proxy.
public struct BreakpointRules: Codable, Hashable, Sendable {
    public var rules: [BreakpointRule]

    public init(rules: [BreakpointRule] = []) { self.rules = rules }

    public var enabled: [BreakpointRule] { rules.filter(\.enabled) }

    public static func load(from url: URL) -> BreakpointRules {
        guard let data = try? Data(contentsOf: url), let r = try? JSONDecoder().decode(BreakpointRules.self, from: data) else {
            return BreakpointRules()
        }
        return r
    }

    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(self).write(to: url)
    }

    /// How many of `rows` a rule would pause right now ("Test your rule").
    public func matchCount(of rule: BreakpointRule, in rows: [FlowRow]) -> Int {
        rows.filter(rule.matches).count
    }

    /// `Intercept armed — 2 rules` / `Intercept armed — every request pauses here`.
    public var armedNotice: String {
        let n = enabled.count
        return n == 0 ? "Intercept armed — every request pauses here" : "Intercept armed — \(n) rule\(n == 1 ? "" : "s")"
    }
}
