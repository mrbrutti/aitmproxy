import AitmBusClient
import Foundation

/// PoC findings, their YAML, and the CA / config documents for the Findings,
/// CA and Configuration panels (S-050–S-053, S-058, S-059), so every panel can
/// be built and snapshotted without a live bus.
extension Fixtures {
    /// Three findings: a failed High XSS reflecting into `/api/search`
    /// (capture = flow 48), a passed Medium IDOR on `/api/orders`, and an Info
    /// run the agent kicked off. Newest first.
    public static let findings: [Finding] = [
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000001")!,
            title: "Reflected XSS in search",
            severity: .high, target: "https://api.shop-staging.test", passed: false, ranAt: at(15.2),
            origin: .human, pocPath: "/tmp/aitm/pocs/reflected-xss-in-search.poc.yaml",
            yaml: pocYAML(name: "Reflected XSS in search", param: "q", severity: "high"),
            captureID: id(48), screenshotPath: "/tmp/aitm/pocs/reflected-xss-in-search.png", screenshot: tinyPNG,
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: <img src=x onerror=alert(1)>", matched: false),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000002")!,
            title: "IDOR on orders listing",
            severity: .medium, target: "https://api.shop-staging.test", passed: true, ranAt: at(9.4),
            origin: .human, pocPath: "/tmp/aitm/pocs/idor-on-orders-listing.poc.yaml",
            yaml: pocYAML(name: "IDOR on orders listing", param: "page", severity: "medium"),
            captureID: id(45), screenshotPath: "/tmp/aitm/pocs/idor-on-orders-listing.png", screenshot: tinyPNG,
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: \"total\"", matched: true),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000003")!,
            title: "Verbose error on cart patch",
            severity: .info, target: "https://api.shop-staging.test", passed: true, ranAt: at(2.1),
            origin: .agent, pocPath: "/tmp/aitm/pocs/verbose-error-on-cart-patch.poc.yaml",
            yaml: pocYAML(name: "Verbose error on cart patch", param: "quantity", severity: "info"),
            captureID: id(53), screenshotPath: nil, screenshot: nil,
            assertions: [Assertion(text: "status == 422", matched: true)]),
    ]

    /// A nuclei-style PoC document the way `aitm-poc` serializes one
    /// (`crates/aitm-poc`): `id`, `info`, `variables`, one `http` step, `success`.
    public static func pocYAML(name: String, param: String, severity: String = "medium") -> String {
        """
        id: \(slug(name))
        info:
          name: \(name)
          severity: \(severity)
          description: Reproduces the finding by replaying the parameterized request.
          author: operator
        variables:
          - name: target
            description: Base URL of the target
          - name: param
            default: \(param)
            description: The parameter to vary
        steps:
          - http:
              method: GET
              url: "{{target}}/api/search?{{param}}=payload"
              headers:
                accept: application/json
        success:
          type: status
          status: 200
        """
    }

    private static func slug(_ name: String) -> String {
        var out = ""
        var dash = false
        for c in name {
            if c.isASCII, c.isLetter || c.isNumber { out.append(Character(c.lowercased())); dash = false }
            else if !out.isEmpty, !dash { out.append("-"); dash = true }
        }
        while out.hasSuffix("-") { out.removeLast() }
        return out.isEmpty ? "reproduced-finding" : out
    }

    /// The CA installed and trusted in the user keychain, expiring in 2027.
    public static let caStatus = CAStatus(
        fingerprint: "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08",
        subject: "aitmproxy root CA", installed: true, trusted: true,
        expires: {
            var c = DateComponents(); c.year = 2027; c.month = 10; c.day = 27
            return Calendar(identifier: .gregorian).date(from: c)
        }(),
        path: "~/Library/Application Support/aitmproxy/ca/ca.crt",
        allowAgentInstall: false, exists: true, platform: "macos",
        location: "the login keychain",
        detail: [
            "a certificate with this fingerprint is present in the login keychain and trusted for SSL",
            "the embedded browser (obscura) does not use the OS trust store; it trusts this CA through --ca-cert at launch",
        ])

    /// The proxy's effective config.yaml, with the keys the panel highlights
    /// (listen, the loopback_tcp bus port) and the agent-install gate set false.
    public static let configYAML = """
    # aitmproxy configuration
    listen: 127.0.0.1:8080
    upstream:
      ssl_insecure: false
    scope:
      - api.shop-staging.test
      - auth.shop-staging.test
      - "*.shop-staging.test"
    mcp:
      transport:
        loopback_tcp:
          host: 127.0.0.1
          port: 9090
          token: file:~/Library/Application Support/aitmproxy/bus.token
    browser:
      engine: obscura
    ca:
      allow_agent_install: false
    """
}

/// A minimal HAR 1.2 log for one captured flow (foundation §2.7 PoC Export:
/// YAML + PNG + HAR). Just the one entry the finding's capture carries; enough
/// for curl/Burp/DevTools to replay it.
public enum HAR {
    /// The HAR JSON text for `detail` (one entry). `startedAt` stamps the entry.
    public static func string(for detail: FlowDetail, row: FlowRow? = nil, startedAt: Date = Date()) -> String {
        log(entries: [entry(for: detail, row: row, startedAt: startedAt)])
    }

    /// A whole log: `FlowTransfer.export` joins one entry per selected flow.
    public static func log(entries: [JSONValue]) -> String {
        let log: JSONValue = .object([
            "log": .object([
                "version": .string("1.2"),
                "creator": .object(["name": .string("aitmproxy"), "version": .string("0.1")]),
                "entries": .array(entries),
            ]),
        ])
        return log.serialized(prettyPrinted: true)
    }

    /// One HAR entry for `detail`.
    public static func entry(for detail: FlowDetail, row: FlowRow? = nil, startedAt: Date = Date()) -> JSONValue {
        let req = detail.request
        let resp = detail.response
        let url = row?.url ?? requestURL(detail)
        var entry: [String: JSONValue] = [
            "startedDateTime": .string(ISO8601DateFormatter().string(from: startedAt)),
            "time": .number(row?.duration.map(milliseconds) ?? 0),
            "request": .object([
                "method": .string(method(req.startLine)),
                "url": .string(url),
                "httpVersion": .string(httpVersion(detail.connection.httpVersion)),
                "headers": headers(req.headers),
                "queryString": query(row?.query),
                "cookies": .array([]),
                "headersSize": .number(-1),
                "bodySize": .number(Double(req.body?.count ?? 0)),
                "postData": postData(req),
            ]),
            "response": response(resp),
            "cache": .object([:]),
            "timings": .object(["send": .number(0), "wait": .number(0), "receive": .number(0)]),
        ]
        if let id = row?.id.raw ?? Optional(detail.id.raw) { entry["_flowId"] = .string(id) }
        return .object(entry)
    }

    private static func response(_ message: HTTPMessage?) -> JSONValue {
        guard let message else {
            return .object(["status": .number(0), "statusText": .string(""), "httpVersion": .string(""),
                            "headers": .array([]), "cookies": .array([]), "content": .object(["size": .number(0), "mimeType": .string("")]),
                            "redirectURL": .string(""), "headersSize": .number(-1), "bodySize": .number(-1)])
        }
        let parts = message.startLine.split(separator: " ", maxSplits: 2).map(String.init)
        let status = parts.count > 1 ? Int(parts[1]) ?? 0 : 0
        let body = message.body ?? Data()
        return .object([
            "status": .number(Double(status)),
            "statusText": .string(parts.count > 2 ? parts[2] : ""),
            "httpVersion": .string(httpVersion(parts.first ?? "")),
            "headers": headers(message.headers),
            "cookies": .array([]),
            "content": .object([
                "size": .number(Double(body.count)),
                "mimeType": .string(message.contentType ?? "application/octet-stream"),
                "text": .string(String(data: body, encoding: .utf8) ?? body.base64EncodedString()),
            ]),
            "redirectURL": .string(message.header("location") ?? ""),
            "headersSize": .number(-1),
            "bodySize": .number(Double(body.count)),
        ])
    }

    private static func headers(_ headers: [HTTPMessage.Header]) -> JSONValue {
        .array(headers.map { .object(["name": .string($0.name), "value": .string($0.value)]) })
    }

    private static func query(_ query: String?) -> JSONValue {
        .array(QueryPairs.pairs(query).map { .object(["name": .string($0.0), "value": .string($0.1)]) })
    }

    private static func postData(_ message: HTTPMessage) -> JSONValue {
        guard let body = message.body, !body.isEmpty else { return .object([:]) }
        return .object([
            "mimeType": .string(message.contentType ?? "application/octet-stream"),
            "text": .string(String(data: body, encoding: .utf8) ?? body.base64EncodedString()),
        ])
    }

    private static func method(_ startLine: String) -> String { String(startLine.split(separator: " ").first ?? "GET") }
    private static func httpVersion(_ raw: String) -> String {
        let v = raw.replacingOccurrences(of: "HTTP/", with: "")
        return v.isEmpty ? "HTTP/1.1" : "HTTP/\(v)"
    }
    private static func milliseconds(_ d: Duration) -> Double {
        let (s, attos) = d.components
        return Double(s) * 1000 + Double(attos) / 1_000_000_000_000_000
    }
    private static func requestURL(_ detail: FlowDetail) -> String {
        let path = detail.request.startLine.split(separator: " ").dropFirst().first.map(String.init) ?? "/"
        let host = detail.request.header("host") ?? detail.connection.sni ?? "host"
        return "https://\(host)\(path)"
    }
}

/// Query-string splitting shared by HAR and the panels (same rules as the
/// inspector's Query tab): percent-decoded `name=value` pairs.
public enum QueryPairs {
    public static func pairs(_ query: String?) -> [(String, String)] {
        guard let query, !query.isEmpty else { return [] }
        return query.split(separator: "&", omittingEmptySubsequences: true).map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            let name = parts.first ?? ""
            let value = parts.count > 1 ? parts[1] : ""
            return (name.removingPercentEncoding ?? name, value.removingPercentEncoding ?? value)
        }
    }
}
