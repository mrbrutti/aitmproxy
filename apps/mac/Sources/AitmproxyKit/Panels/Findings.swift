import AitmBusClient
import Foundation

/// PoC finding severity (aitm-poc `Severity`, serialized lowercase).
public enum Severity: String, CaseIterable, Codable, Sendable {
    case critical, high, medium, low, info

    public var title: String { rawValue.prefix(1).uppercased() + rawValue.dropFirst() }
}

/// One evaluated `success` leaf of a run: `status == 200` · matched.
public struct Assertion: Hashable, Sendable, Codable {
    public var text: String
    public var matched: Bool

    public init(text: String, matched: Bool) {
        self.text = text
        self.matched = matched
    }
}

/// One PoC run and its result (foundation §2.7 "PoC panel"; S-050–S-052).
/// A PoC that was built but never run has no assertions.
public struct Finding: Identifiable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var severity: Severity
    public var target: String
    public var passed: Bool
    public var ranAt: Date
    public var origin: FlowOrigin
    public var pocPath: String
    public var yaml: String
    public var captureID: FlowID?
    public var screenshotPath: String?
    /// Loaded lazily by the app from `screenshotPath`; never persisted.
    public var screenshot: Data?
    public var assertions: [Assertion]

    public init(id: UUID = UUID(), title: String, severity: Severity, target: String, passed: Bool, ranAt: Date,
                origin: FlowOrigin, pocPath: String, yaml: String, captureID: FlowID? = nil,
                screenshotPath: String? = nil, screenshot: Data? = nil, assertions: [Assertion] = []) {
        self.id = id
        self.title = title
        self.severity = severity
        self.target = target
        self.passed = passed
        self.ranAt = ranAt
        self.origin = origin
        self.pocPath = pocPath
        self.yaml = yaml
        self.captureID = captureID
        self.screenshotPath = screenshotPath
        self.screenshot = screenshot
        self.assertions = assertions
    }

    /// True once `poc.run` has judged it; a freshly built PoC is neither passed nor failed.
    public var hasRun: Bool { !assertions.isEmpty }

    /// `passed` / `failed` / `not run` — the words the UX block uses.
    public var resultText: String { hasRun ? (passed ? "passed" : "failed") : "not run" }

    /// A filesystem-safe name derived from the title, the way aitm-poc slugs ids.
    public var slug: String {
        var out = ""
        var dash = false
        for c in title {
            if c.isASCII, c.isLetter || c.isNumber { out.append(c.lowercased()); dash = false }
            else if !out.isEmpty, !dash { out.append("-"); dash = true }
        }
        while out.hasSuffix("-") { out.removeLast() }
        return out.isEmpty ? "reproduced-finding" : out
    }

    /// Decodes the `poc.run` result (`crates/aitm-poc/src/runner.rs`):
    /// `{passed, finding_capture, poc_path, screenshot_path, evaluated: [{assertion, matched}]}`.
    public static func fromRunResult(_ json: JSONValue, pocPath: String, target: String, yaml: String,
                                     origin: FlowOrigin, ranAt: Date = Date()) -> Finding {
        let info = PocYAML.info(in: yaml)
        let screenshot = json["screenshot_path"]?.stringValue
        return Finding(
            title: info["name"] ?? PocYAML.title(fromPath: json["poc_path"]?.stringValue ?? pocPath),
            severity: info["severity"].flatMap(Severity.init(rawValue:)) ?? .medium,
            target: target,
            passed: json["passed"]?.boolValue ?? false,
            ranAt: ranAt,
            origin: origin,
            pocPath: json["poc_path"]?.stringValue ?? pocPath,
            yaml: yaml,
            captureID: json["finding_capture"]?.stringValue.map(FlowID.init),
            screenshotPath: (screenshot ?? "").isEmpty ? nil : screenshot,
            assertions: json["evaluated"]?.arrayValue?.map {
                Assertion(text: $0["assertion"]?.stringValue ?? "", matched: $0["matched"]?.boolValue ?? false)
            } ?? [])
    }
}

extension Finding: Codable {
    private enum Key: String, CodingKey {
        case id, title, severity, target, passed, ranAt, origin, pocPath, yaml, captureID, screenshotPath, assertions
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        let origin: FlowOrigin = switch try c.decodeIfPresent(String.self, forKey: .origin) {
        case "agent": .agent
        case "client": .client
        default: .human
        }
        self.init(
            id: try c.decode(UUID.self, forKey: .id), title: try c.decode(String.self, forKey: .title),
            severity: try c.decodeIfPresent(Severity.self, forKey: .severity) ?? .medium,
            target: try c.decode(String.self, forKey: .target), passed: try c.decode(Bool.self, forKey: .passed),
            ranAt: try c.decode(Date.self, forKey: .ranAt), origin: origin,
            pocPath: try c.decode(String.self, forKey: .pocPath), yaml: try c.decodeIfPresent(String.self, forKey: .yaml) ?? "",
            captureID: try c.decodeIfPresent(String.self, forKey: .captureID).map(FlowID.init),
            screenshotPath: try c.decodeIfPresent(String.self, forKey: .screenshotPath),
            assertions: try c.decodeIfPresent([Assertion].self, forKey: .assertions) ?? [])
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(id, forKey: .id)
        try c.encode(title, forKey: .title)
        try c.encode(severity, forKey: .severity)
        try c.encode(target, forKey: .target)
        try c.encode(passed, forKey: .passed)
        try c.encode(ranAt, forKey: .ranAt)
        try c.encode(origin == .agent ? "agent" : origin == .client ? "client" : "human", forKey: .origin)
        try c.encode(pocPath, forKey: .pocPath)
        try c.encode(yaml, forKey: .yaml)
        try c.encodeIfPresent(captureID?.raw, forKey: .captureID)
        try c.encodeIfPresent(screenshotPath, forKey: .screenshotPath)
        try c.encode(assertions, forKey: .assertions)
    }
}

/// Just enough YAML reading for the PoC panel: the `info:` block's scalars and
/// the `variables:` list. Line-based on purpose; the proxy owns the real parser.
public enum PocYAML {
    /// `name`, `severity`, … under `info:` (quotes stripped). Falls back to the first top-level match.
    public static func info(in yaml: String) -> [String: String] {
        var out: [String: String] = [:]
        var infoIndent: Int?
        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            let indent = line.prefix { $0 == " " }.count
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") || trimmed.isEmpty { continue }
            if let infoIndent {
                if indent <= infoIndent { break }
                if let (key, value) = scalar(trimmed), !value.isEmpty { out[key] = value }
            } else if trimmed == "info:" {
                infoIndent = indent
            } else if indent == 0, let (key, value) = scalar(trimmed), out[key] == nil, !value.isEmpty {
                out[key] = value
            }
        }
        return out
    }

    /// `[(name, default)]` from the `variables:` list, in file order.
    public static func variables(in yaml: String) -> [(name: String, defaultValue: String?)] {
        var out: [(name: String, defaultValue: String?)] = []
        var inBlock = false
        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "variables:" { inBlock = true; continue }
            guard inBlock else { continue }
            if !line.hasPrefix(" ") && !line.hasPrefix("-") && !trimmed.isEmpty { break }
            let item = trimmed.hasPrefix("- ") ? String(trimmed.dropFirst(2)) : trimmed
            guard let (key, value) = scalar(item) else { continue }
            if key == "name" { out.append((value, nil)) }
            else if key == "default", !out.isEmpty { out[out.count - 1].defaultValue = value }
        }
        return out
    }

    /// `/tmp/pocs/reflected-xss.poc.yaml` → `reflected xss`.
    public static func title(fromPath path: String) -> String {
        var name = path.split(separator: "/").last.map(String.init) ?? path
        for suffix in [".poc.yaml", ".poc.yml", ".yaml", ".yml"] where name.hasSuffix(suffix) {
            name.removeLast(suffix.count)
            break
        }
        return name.replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " ")
    }

    /// `key: value` with surrounding quotes removed; nil for anything else.
    static func scalar(_ text: String) -> (String, String)? {
        guard let colon = text.firstIndex(of: ":") else { return nil }
        let key = text[..<colon].trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty, !key.contains(" ") else { return nil }
        var value = text[text.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        if value.count >= 2, let first = value.first, first == "\"" || first == "'", value.last == first {
            value = String(value.dropFirst().dropLast())
        }
        return (key, value)
    }
}

/// The names a Build PoC sheet offers as the parameter to vary (S-053).
public enum PocParameters {
    /// Query keys, then header names, then the request body's top-level JSON keys; deduplicated, in that order.
    public static func candidates(for detail: FlowDetail, row: FlowRow) -> [String] {
        var out: [String] = []
        func add(_ name: String) { if !name.isEmpty, !out.contains(name) { out.append(name) } }
        for pair in (row.query ?? "").split(separator: "&") {
            let key = String(pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
            add(key.removingPercentEncoding ?? key)
        }
        for header in detail.request.headers where header.name.lowercased() != "host" { add(header.name) }
        if let body = detail.request.body, let root = try? JSONTree.parse(body), case .object = root.kind {
            for child in root.children { add(child.key ?? "") }
        }
        return out
    }
}

/// The Run again form (S-052), built from `poc.run`'s schema: `poc_path` is
/// fixed, `target` is a field, `vars` edits as key : value rows prefilled
/// from the PoC's own `variables:` defaults.
public struct PocRunForm: Hashable, Sendable {
    public struct Var: Hashable, Sendable, Identifiable {
        public var id = UUID()
        public var key: String
        public var value: String
        public init(key: String = "", value: String = "") {
            self.key = key
            self.value = value
        }
    }

    /// The schema's parameter names, in schema order (`poc_path`, `target`, `vars` when the tool is unknown).
    public var fields: [String]
    public var pocPath: String
    public var target: String
    public var vars: [Var]

    public init(tool: ToolDescriptor?, finding: Finding) {
        fields = tool.map { $0.parameters.map(\.name) } ?? ["poc_path", "target", "vars"]
        pocPath = finding.pocPath
        target = finding.target
        vars = PocYAML.variables(in: finding.yaml).filter { $0.name != "target" }
            .map { Var(key: $0.name, value: $0.defaultValue ?? "") }
    }

    public var hasVars: Bool { fields.contains("vars") }

    /// Typed arguments; blank var keys are dropped and an empty `vars` is omitted.
    public func arguments() -> [String: JSONValue] {
        var args: [String: JSONValue] = ["poc_path": .string(pocPath), "target": .string(target)]
        let kept = vars.filter { !$0.key.trimmingCharacters(in: .whitespaces).isEmpty }
        if hasVars, !kept.isEmpty {
            args["vars"] = .object(Dictionary(kept.map { ($0.key.trimmingCharacters(in: .whitespaces), JSONValue.string($0.value)) },
                                              uniquingKeysWith: { _, last in last }))
        }
        return args
    }
}

/// `findings.json` under the app's state directory: every run this surface
/// has seen, newest first. A missing file is an empty list.
public struct FindingsStore: Sendable {
    public static let fileName = "findings.json"
    public let fileURL: URL

    public init(fileURL: URL) { self.fileURL = fileURL }

    public init(stateDirectory: URL) {
        self.init(fileURL: stateDirectory.appending(path: FindingsStore.fileName))
    }

    public func load() throws -> [Finding] {
        guard FileManager.default.fileExists(atPath: fileURL.path(percentEncoded: false)) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([Finding].self, from: Data(contentsOf: fileURL)).sorted { $0.ranAt > $1.ranAt }
    }

    public func save(_ findings: [Finding]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(findings.sorted { $0.ranAt > $1.ranAt }).write(to: fileURL, options: [.atomic])
    }
}
