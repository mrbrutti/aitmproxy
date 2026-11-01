import AitmBusClient
import Foundation

/// What the CA panel shows (S-058), read from `ca.status`
/// (`crates/aitm-ca/src/commands.rs`): `{exists, dir, path, fingerprint_sha256,
/// fingerprint_sha1, platform, stores: {user|system: {installed, trusted,
/// location}}, detail: [String]}`. The result carries no subject, expiry or
/// agent-gate flag; those come from the certificate file and the config.
public struct CAStatus: Hashable, Sendable {
    /// SHA-256, colon-separated uppercase hex; empty when there is no certificate.
    public var fingerprint: String
    public var subject: String
    public var installed: Bool
    public var trusted: Bool
    public var expires: Date?
    public var path: String?
    public var allowAgentInstall: Bool
    public var exists: Bool
    public var platform: String
    /// The user-scope store's keychain / anchor file, for the confirmation text.
    public var location: String?
    public var detail: [String]
    /// The first store whose `trusted` is `yes`, user before system (`"user"` | `"system"`); nil when none.
    public var trustedScope: String?
    /// Some store answered `yes` or `no` (spec D17.5): false when every store says `unknown`, so an
    /// older core or a failed evaluation tool never renders as "not trusted".
    public var trustReported: Bool

    public init(fingerprint: String, subject: String = "aitmproxy root CA", installed: Bool, trusted: Bool,
                expires: Date? = nil, path: String? = nil, allowAgentInstall: Bool = false, exists: Bool = true,
                platform: String = "macos", location: String? = nil, detail: [String] = [],
                trustedScope: String? = nil, trustReported: Bool = false) {
        self.fingerprint = fingerprint
        self.subject = subject
        self.installed = installed
        self.trusted = trusted
        self.expires = expires
        self.path = path
        self.allowAgentInstall = allowAgentInstall
        self.exists = exists
        self.platform = platform
        self.location = location
        self.detail = detail
        self.trustedScope = trustedScope
        self.trustReported = trustReported
    }

    /// Nil unless `json` is a `ca.status` object (it always carries `exists`).
    public init?(json: JSONValue) {
        guard let exists = json["exists"]?.boolValue else { return nil }
        let stores = json["stores"]?.objectValue ?? [:]
        let user = stores["user"] ?? stores.values.first
        let trust = { (scope: String) in stores[scope]?["trusted"]?.stringValue }
        self.init(
            fingerprint: json["fingerprint_sha256"]?.stringValue ?? "",
            subject: json["subject"]?.stringValue ?? "aitmproxy root CA",
            installed: stores.values.contains { $0["installed"]?.stringValue == "present" },
            trusted: stores.values.contains { $0["trusted"]?.stringValue == "yes" },
            expires: json["not_after"]?.stringValue.flatMap { ISO8601DateFormatter().date(from: $0) },
            path: json["path"]?.stringValue,
            allowAgentInstall: json["allow_agent_install"]?.boolValue ?? false,
            exists: exists,
            platform: json["platform"]?.stringValue ?? "unknown",
            location: user?["location"]?.stringValue,
            detail: json["detail"]?.arrayValue?.compactMap(\.stringValue) ?? [],
            trustedScope: ["user", "system"].first { trust($0) == "yes" },
            trustReported: stores.values.contains { ["yes", "no"].contains($0["trusted"]?.stringValue ?? "") })
    }

    /// `Installed · trusted` / `Installed · not trusted` / `Not installed` / `No certificate`.
    public var statusText: String {
        guard exists else { return "No certificate" }
        guard installed else { return "Not installed" }
        return trusted ? "Installed · trusted" : "Installed · not trusted"
    }

    /// The question the proxy asks before `ca.install` / `ca.uninstall`
    /// (`Op::prompt` in the Rust crate, user scope), built from this status.
    public func confirmPrompt(install: Bool) -> String {
        let where_ = location ?? "the login keychain"
        return install
            ? "Install the aitmproxy root CA (SHA-256 \(fingerprint)) into \(where_) (scope user)? Every TLS client that uses that store will then trust certificates this proxy mints. (The embedded obscura browser is unaffected; it trusts the CA via --ca-cert.)"
            : "Remove the aitmproxy root CA (SHA-256 \(fingerprint)) from \(where_) (scope user)?"
    }

    /// Short setup notes for the panel's guide sections, in reading order.
    public static let guides: [(title: String, body: String)] = [
        ("iOS", "Export PEM, send the file to the device (AirDrop or Mail) and accept it in Settings as a profile; then enable full trust for it under General ▸ About ▸ Certificate Trust Settings. Point the device's Wi-Fi proxy at the listening address."),
        ("Android", "Export PEM and add it as a user CA in the device's security settings. Apps targeting API 24+ ignore user CAs unless their network security config opts in, so use a debug build or an emulator with the proxy flag."),
        ("Browsers", "Firefox keeps its own store: Settings ▸ Privacy & Security ▸ Certificates ▸ Import the PEM and tick identify websites. Chrome and Safari use the system keychain, so Install… is enough. The embedded obscura browser trusts the CA on its own through --ca-cert."),
        ("Terminal", "curl: --cacert ca.pem. OpenSSL-based tools: SSL_CERT_FILE=ca.pem. Python requests: REQUESTS_CA_BUNDLE=ca.pem. Node: NODE_EXTRA_CA_CERTS=ca.pem. Set HTTPS_PROXY to the listening address."),
    ]
}

/// The effective proxy configuration as the Configuration panel shows it
/// (S-059): every line with its dotted key, `env` for keys an environment
/// variable overrides, and a highlight on the listen and bus address lines.
public struct ConfigDocument: Hashable, Sendable {
    public struct Line: Hashable, Sendable, Identifiable {
        public var id: Int
        public var text: String
        /// `mcp.transport.loopback_tcp.port`; empty for blank and comment lines.
        public var key: String
        public var isEnv: Bool
        public var highlight: Bool
    }

    public var yaml: String
    public var path: String
    public var lines: [Line]

    public init(yaml: String, path: String, envOverrides: [String]) {
        self.yaml = yaml
        self.path = path
        var stack: [(indent: Int, key: String)] = []
        lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).enumerated().map { index, raw in
            let text = String(raw)
            let trimmed = text.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else {
                return Line(id: index, text: text, key: "", isEnv: false, highlight: false)
            }
            let indent = text.prefix { $0 == " " }.count
            while let last = stack.last, last.indent >= indent { stack.removeLast() }
            let item = trimmed.hasPrefix("- ")
            var key = stack.last?.key ?? ""
            if !item, let (name, _) = PocYAML.scalar(trimmed) {
                key = key.isEmpty ? name : key + "." + name
                stack.append((indent, key))
            }
            let leaf = key.split(separator: ".").last.map(String.init) ?? key
            let isEnv = envOverrides.contains(key) || (!leaf.isEmpty && envOverrides.contains(leaf))
            let highlight = key == "listen" || (key.contains("loopback_tcp") && (leaf == "host" || leaf == "port"))
            return Line(id: index, text: text, key: key, isEnv: isEnv, highlight: highlight)
        }
    }

    /// The scalar at a dotted key (`browser.engine`), quotes stripped.
    public func value(_ dottedKey: String) -> String? {
        for line in lines where line.key == dottedKey {
            if let (_, value) = PocYAML.scalar(line.text.trimmingCharacters(in: .whitespaces)), !value.isEmpty { return value }
        }
        return nil
    }

    public var engine: String? { value("browser.engine") }
    public var listen: String? { value("listen") }
    public var allowAgentInstall: Bool { value("ca.allow_agent_install") == "true" }
    public var sslInsecure: Bool? { value("upstream.ssl_insecure").map { $0 == "true" } }
}

extension Syntax {
    /// One YAML line: keys in `.key`, quoted scalars `.string`, numbers
    /// `.number`, `true`/`false`/`null`/`~` `.boolean`, `- ` and `:` `.punct`,
    /// a `#` comment `.punct`. Unquoted scalars stay plain.
    public static func yaml(line: String) -> [SyntaxRun] {
        var runs: [SyntaxRun] = []
        var rest = Substring(line)
        let indent = rest.prefix { $0 == " " }
        if !indent.isEmpty { runs.append(SyntaxRun(.plain, String(indent))); rest = rest.dropFirst(indent.count) }
        if rest.hasPrefix("- ") { runs.append(SyntaxRun(.punct, "- ")); rest = rest.dropFirst(2) }
        if rest.hasPrefix("#") { runs.append(SyntaxRun(.punct, String(rest))); return runs }
        var comment = ""
        if let hash = rest.firstIndex(of: "#"), hash == rest.startIndex || rest[rest.index(before: hash)] == " ",
           !rest.hasPrefix("\""), !rest.hasPrefix("'") {
            comment = String(rest[hash...])
            rest = rest[..<hash]
        }
        if let colon = rest.firstIndex(of: ":"), colon == rest.index(before: rest.endIndex) || rest[rest.index(after: colon)] == " ",
           !rest.hasPrefix("\""), !rest.hasPrefix("'"), !rest.hasPrefix("{{") {
            runs.append(SyntaxRun(.key, String(rest[..<colon])))
            runs.append(SyntaxRun(.punct, ":"))
            rest = rest[rest.index(after: colon)...]
        }
        let spaces = rest.prefix { $0 == " " }
        if !spaces.isEmpty { runs.append(SyntaxRun(.plain, String(spaces))); rest = rest.dropFirst(spaces.count) }
        let value = String(rest)
        let trailingCount = value.reversed().prefix { $0 == " " }.count
        let scalar = String(value.dropLast(trailingCount))
        let trailing = String(value.suffix(trailingCount))
        if !scalar.isEmpty { runs.append(SyntaxRun(kind(ofScalar: scalar), scalar)) }
        if !trailing.isEmpty { runs.append(SyntaxRun(.plain, trailing)) }
        if !comment.isEmpty { runs.append(SyntaxRun(.punct, comment)) }
        return runs
    }

    private static func kind(ofScalar s: String) -> SyntaxKind {
        if let first = s.first, (first == "\"" || first == "'"), s.count >= 2, s.last == first { return .string }
        if ["true", "false", "null", "~", "yes", "no"].contains(s.lowercased()) { return .boolean }
        if Double(s) != nil { return .number }
        return .plain
    }
}
