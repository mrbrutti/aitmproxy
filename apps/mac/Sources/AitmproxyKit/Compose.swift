import Foundation

/// Scope entries: `host`, `host:port`, `*.wildcard` (foundation §2.7 "Scope panel").
public enum Scope {
    /// Whether `authority` (host[:port]) is covered by `entry`.
    public static func matches(_ authority: String, _ entry: String) -> Bool {
        let host = authority.split(separator: ":").first.map(String.init) ?? authority
        if entry.hasPrefix("*.") {
            let suffix = String(entry.dropFirst(1))
            return host.hasSuffix(suffix) || host == String(entry.dropFirst(2))
        }
        return authority == entry || host == entry
    }

    public static func contains(_ authority: String, in entries: [String]) -> Bool {
        entries.contains { matches(authority, $0) }
    }

    /// Accepts the three forms; rejects schemes, paths and empty strings.
    public static func validate(_ entry: String) -> String? {
        let e = entry.trimmingCharacters(in: .whitespaces)
        if e.isEmpty { return "Enter a host, host:port or *.wildcard" }
        if e.contains("://") { return "Enter a host without the scheme" }
        if e.contains("/") { return "Enter a host without a path" }
        if e.contains(" ") { return "A host has no spaces" }
        let host = e.hasPrefix("*.") ? String(e.dropFirst(2)) : e.split(separator: ":").first.map(String.init) ?? e
        if host.isEmpty || host.hasPrefix(".") || host.hasSuffix(".") { return "That is not a valid host" }
        if let port = e.split(separator: ":").dropFirst().first, Int(port) == nil || Int(port)! <= 0 || Int(port)! > 65_535 {
            return "The port must be 1–65535"
        }
        return nil
    }
}

/// What the compose sheet edits (S-042). Headers are bulk text, one `name: value` per line.
public struct ComposeDraft: Hashable, Sendable, Codable {
    public enum BodyKind: String, CaseIterable, Hashable, Sendable, Codable {
        case raw, json, form, multipart
        public var title: String {
            switch self {
            case .raw: "Raw"
            case .json: "JSON"
            case .form: "Form"
            case .multipart: "Multipart"
            }
        }
        public var contentType: String? {
            switch self {
            case .raw: nil
            case .json: "application/json"
            case .form: "application/x-www-form-urlencoded"
            case .multipart: "multipart/form-data"
            }
        }
    }

    public var method: String
    public var url: String
    public var headersText: String
    public var body: String
    public var bodyKind: BodyKind
    public var sentAt: Date?

    public init(method: String = "GET", url: String = "", headersText: String = "", body: String = "",
                bodyKind: BodyKind = .raw, sentAt: Date? = nil) {
        self.method = method
        self.url = url
        self.headersText = headersText
        self.body = body
        self.bodyKind = bodyKind
        self.sentAt = sentAt
    }

    public static let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

    // MARK: Templates

    public enum Template: String, CaseIterable, Hashable, Sendable {
        case empty = "Empty", get = "GET", postJSON = "POST JSON", postForm = "POST Form", multipart = "Multipart", webSocket = "WebSocket"

        public var draft: ComposeDraft {
            switch self {
            case .empty: ComposeDraft()
            case .get: ComposeDraft(method: "GET", url: "https://", headersText: "accept: application/json")
            case .postJSON: ComposeDraft(method: "POST", url: "https://", headersText: "content-type: application/json\naccept: application/json",
                                         body: "{\n  \n}", bodyKind: .json)
            case .postForm: ComposeDraft(method: "POST", url: "https://", headersText: "content-type: application/x-www-form-urlencoded",
                                         body: "field=value", bodyKind: .form)
            case .multipart: ComposeDraft(method: "POST", url: "https://", headersText: "content-type: multipart/form-data",
                                          body: "--boundary\ncontent-disposition: form-data; name=\"field\"\n\nvalue\n--boundary--", bodyKind: .multipart)
            case .webSocket: ComposeDraft(method: "GET", url: "wss://", headersText: "upgrade: websocket\nconnection: Upgrade")
            }
        }

        /// WebSocket compose needs ws.send (F9).
        public var isAvailable: Bool { self != .webSocket }
    }

    // MARK: Parsing

    public var headers: [(String, String)] {
        headersText.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, !parts[0].isEmpty else { return nil }
            return (parts[0].lowercased(), parts[1])
        }
    }

    public var components: URLComponents? {
        guard let c = URLComponents(string: url.trimmingCharacters(in: .whitespaces)), let host = c.host, !host.isEmpty else { return nil }
        return c
    }

    /// `host[:port]` as the proxy sees it.
    public var authority: String? {
        guard let c = components, let host = c.host else { return nil }
        if let port = c.port { return "\(host):\(port)" }
        return host
    }

    public var queryItems: [(String, String)] {
        components?.queryItems?.map { ($0.name, $0.value ?? "") } ?? []
    }

    /// nil when the draft can be sent; otherwise why not.
    public func validationError(scope: [String]) -> String? {
        guard let c = components, let authority else { return "Enter a URL with a host" }
        guard ["http", "https"].contains(c.scheme?.lowercased() ?? "") else { return "Only http and https can be sent" }
        if !scope.isEmpty, !Scope.contains(authority, in: scope) {
            return "Out of scope — add \(authority.split(separator: ":").first.map(String.init) ?? authority) to scope to send"
        }
        return nil
    }

    /// The `request.send` arguments.
    public func requestEdits() -> RequestEdits {
        var edits = RequestEdits()
        edits.method = method
        if let c = components {
            edits.scheme = c.scheme?.lowercased()
            edits.authority = authority
            var path = c.percentEncodedPath.isEmpty ? "/" : c.percentEncodedPath
            if let q = c.percentEncodedQuery, !q.isEmpty { path += "?\(q)" }
            edits.path = path
        }
        var headerMap: [String: String] = [:]
        for (name, value) in headers { headerMap[name] = value }
        if headerMap["content-type"] == nil, let type = bodyKind.contentType, !body.isEmpty { headerMap["content-type"] = type }
        if !headerMap.isEmpty { edits.headers = headerMap }
        if !body.isEmpty { edits.body = Data(body.utf8) }
        return edits
    }

    // MARK: From elsewhere

    /// Prefilled from a captured flow (Edit & Replay, S-044).
    public static func from(detail: FlowDetail, row: FlowRow) -> ComposeDraft {
        let headers = detail.request.headers.filter { !["host", "content-length"].contains($0.name.lowercased()) }
        let kind: BodyKind = {
            let type = detail.request.contentType?.lowercased() ?? ""
            if type.contains("json") { return .json }
            if type.contains("x-www-form-urlencoded") { return .form }
            if type.contains("multipart") { return .multipart }
            return .raw
        }()
        return ComposeDraft(method: row.method.label, url: row.url,
                            headersText: headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n"),
                            body: detail.request.bodyText ?? "", bodyKind: kind)
    }

    /// From a pasted `curl …` command (S-043); nil when it is not one.
    public static func from(curl command: String) -> (draft: ComposeDraft, unknownFlags: [String])? {
        guard command.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("curl"),
              let edits = CodeExport.parseCurl(command) else { return nil }
        var draft = ComposeDraft()
        draft.method = edits.method ?? "GET"
        var url = "\(edits.scheme ?? "https")://\(edits.authority ?? "")\(edits.path ?? "/")"
        if edits.authority == nil, let bare = CodeExport.shellTokens(command).first(where: { $0.hasPrefix("http") }) { url = bare }
        draft.url = url
        draft.headersText = (edits.headers ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: "\n")
        if let body = edits.body { draft.body = String(decoding: body, as: UTF8.self) }
        let type = (edits.headers ?? [:])["content-type"]?.lowercased() ?? ""
        draft.bodyKind = type.contains("json") ? .json : type.contains("form-urlencoded") ? .form : type.contains("multipart") ? .multipart : .raw
        let known: Set<String> = ["-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                                  "--json", "-u", "--user", "-A", "--user-agent", "-b", "--cookie", "-e", "--referer", "--url", "-G", "--get",
                                  "-I", "--head", "-F", "--form", "-s", "-S", "-k", "--insecure", "-L", "--location", "--compressed", "-v",
                                  "-i", "-o", "--output", "-x", "--proxy", "--max-time", "-m"]
        let unknown = CodeExport.shellTokens(command).dropFirst().filter { $0.hasPrefix("-") && !known.contains($0.split(separator: "=").first.map(String.init) ?? $0) }
            .map { String($0.split(separator: "=").first ?? Substring($0)) }
        return (draft, Array(Set(unknown)).sorted())
    }
}

/// Sent composes, newest first, capped (S-042: `compose.json`, 200).
public struct ComposeHistory: Codable, Hashable, Sendable {
    public static let capacity = 200
    public var entries: [ComposeDraft]

    public init(entries: [ComposeDraft] = []) { self.entries = entries }

    public static func load(from url: URL) -> ComposeHistory {
        guard let data = try? Data(contentsOf: url), let h = try? JSONDecoder().decode(ComposeHistory.self, from: data) else {
            return ComposeHistory()
        }
        return h
    }

    public func save(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(self).write(to: url)
    }

    public mutating func record(_ draft: ComposeDraft, at date: Date = .now) {
        var sent = draft
        sent.sentAt = date
        entries.insert(sent, at: 0)
        if entries.count > Self.capacity { entries.removeLast(entries.count - Self.capacity) }
    }
}

/// The abort modes `flow.kill {id, mode}` will take (F3); reset is what the core does today.
public enum KillMode: String, CaseIterable, Hashable, Sendable {
    case reset, respond429 = "429", respond503 = "503"

    public var title: String {
        switch self {
        case .reset: "Reset connection"
        case .respond429: "Respond 429"
        case .respond503: "Respond 503"
        }
    }

    public var syntheticStatus: Int? {
        switch self {
        case .reset: nil
        case .respond429: 429
        case .respond503: 503
        }
    }
}
