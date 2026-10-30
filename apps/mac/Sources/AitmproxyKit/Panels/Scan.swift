import AitmBusClient
import Foundation

// The Scan page's model (scanner-integration Stage 1). `scan.discover` crawls
// one operator-authorised, in-scope target and lists the endpoints it reached
// and the injection points visible in the traffic it captured. The scanner
// engine is `aitm-plugin-scanner`; this file only decodes its result and holds
// what the panel shows. No SwiftUI, so tests run without the app.

/// One discovered injection point: an entry of `scan.discover`'s
/// `injection_points` (`{flow, location, name, example}`).
///
/// `example` is whatever the scanner handed us. It redacts at the source (a
/// secret-named parameter or a cookie arrives as `<redacted>`), so the panel
/// shows it verbatim and never reconstructs a value.
public struct InjectionPoint: Hashable, Sendable, Codable {
    /// The id of the flow this point was seen in. Required: every row opens its flow.
    public var flow: String
    /// Where it lives: `query`, `body_param`, `header`, `cookie`, `path_segment` or `redirect`.
    public var location: String
    /// The parameter, header or segment name.
    public var name: String
    /// The observed (already redacted) value.
    public var example: String

    public init(flow: String, location: String, name: String, example: String) {
        self.flow = flow
        self.location = location
        self.name = name
        self.example = example
    }

    /// The flow this point opens in the inspector.
    public var flowID: FlowID { FlowID(flow) }

    private enum Key: String, CodingKey { case flow, location, name, example }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        let flow = try c.decode(String.self, forKey: .flow)
        guard !flow.isEmpty else {
            throw DecodingError.dataCorruptedError(forKey: .flow, in: c, debugDescription: "an injection point needs a flow id")
        }
        self.init(flow: flow, location: try c.decode(String.self, forKey: .location),
                  name: try c.decode(String.self, forKey: .name),
                  example: try c.decodeIfPresent(String.self, forKey: .example) ?? "")
    }
}

/// The `scan.discover` result (`crates/aitm-plugin-scanner/src/commands.rs`):
/// `{endpoints, endpoint_flows, injection_points, pages_crawled, stopped_reason}`.
public struct ScanResult: Hashable, Sendable, Codable {
    /// The URLs the crawl reached, scrubbed by the scanner and shown verbatim.
    public var endpoints: [String]
    /// The flow each endpoint was fetched in: `endpoints` entry (the same scrubbed
    /// URL string) → flow id. An endpoint with no entry has no flow to open. Read
    /// it through `flowID(forEndpoint:)`.
    public var endpointFlows: [String: String]
    public var injectionPoints: [InjectionPoint]
    public var pagesCrawled: Int
    /// Why the crawl stopped early (`max_pages`, `left_scope`, `navigation_failed`, …); nil when it ran out of links.
    public var stoppedReason: String?

    public init(endpoints: [String], endpointFlows: [String: String] = [:], injectionPoints: [InjectionPoint],
                pagesCrawled: Int, stoppedReason: String? = nil) {
        self.endpoints = endpoints
        self.endpointFlows = endpointFlows
        self.injectionPoints = injectionPoints
        self.pagesCrawled = pagesCrawled
        self.stoppedReason = stoppedReason
    }

    private enum CodingKeys: String, CodingKey {
        case endpoints
        case endpointFlows = "endpoint_flows"
        case injectionPoints = "injection_points"
        case pagesCrawled = "pages_crawled"
        case stoppedReason = "stopped_reason"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(endpoints: try c.decodeIfPresent([String].self, forKey: .endpoints) ?? [],
                  endpointFlows: Self.links(in: c),
                  injectionPoints: try c.decodeIfPresent([InjectionPoint].self, forKey: .injectionPoints) ?? [],
                  pagesCrawled: try c.decodeIfPresent(Int.self, forKey: .pagesCrawled) ?? 0,
                  stoppedReason: try c.decodeIfPresent(String.self, forKey: .stoppedReason))
    }

    /// The flow an endpoint opens, or nil when the crawl recorded none for it. The
    /// key is the endpoint's own text, matched exactly (the scanner keys the map by
    /// the same scrubbed string it lists in `endpoints`).
    public func flowID(forEndpoint url: String) -> FlowID? { Self.flowID(for: url, in: endpointFlows) }

    static func flowID(for url: String, in flows: [String: String]) -> FlowID? {
        guard let raw = flows[url], !raw.isEmpty else { return nil }
        return FlowID(raw)
    }

    /// Reads `endpoint_flows` defensively. A core that predates the field, a null,
    /// or a value that is not an object reads as no links; inside the object, an
    /// entry whose value is not a non-empty string is dropped on its own. Links are
    /// a convenience on top of the endpoint list, so a bad one never fails the result.
    private static func links(in c: KeyedDecodingContainer<CodingKeys>) -> [String: String] {
        let raw = (try? c.decodeIfPresent([String: LinkValue].self, forKey: .endpointFlows)) ?? [:]
        return raw.compactMapValues { value in value.id.flatMap { $0.isEmpty ? nil : $0 } }
    }

    /// One `endpoint_flows` value: the flow id when it is a string, nil for anything else.
    private struct LinkValue: Decodable {
        let id: String?

        init(from decoder: any Decoder) throws {
            id = try? decoder.singleValueContainer().decode(String.self)
        }
    }

    /// Decodes what the bus returned. Throws for anything but an object, or for
    /// an injection point with no flow id.
    public init(json: JSONValue) throws {
        guard case .object = json else { throw BusError.malformed("scan.discover returned a result that is not an object") }
        self = try JSONDecoder().decode(ScanResult.self, from: Data(json.serialized().utf8))
    }
}

/// The Scan launch form, built from `scan.discover`'s schema the way `PocRunForm`
/// is built from `poc.run`'s: the schema's parameter names say which fields exist,
/// `target` is the one required field, and the optional budget fields are sent only
/// when the schema has them and they hold a number.
///
/// The target is bound to the authorised scope: `scopeError` refuses anything the
/// scope does not cover, so an out-of-scope target never reaches the bus.
public struct ScanForm: Hashable, Sendable {
    public static let toolName = "scan.discover"

    /// The schema's parameter names, in schema order (`target`, `max_depth`, `max_pages` when the tool is unknown).
    public var fields: [String]
    /// The seed URL: an in-scope host as a URL, or a bare host (read as `http://host`).
    public var target: String
    /// Link depth to follow; blank leaves the configured cap.
    public var maxDepth = ""
    /// Pages to visit; blank leaves the configured cap.
    public var maxPages = ""

    public init(tool: ToolDescriptor?, scopeHosts: [String]) {
        fields = Self.fields(for: tool)
        target = Self.seed(scopeHosts)
    }

    public var hasMaxDepth: Bool { fields.contains("max_depth") }
    public var hasMaxPages: Bool { fields.contains("max_pages") }

    /// Re-reads the schema (the bus may list its tools after the form exists) and
    /// seeds a blank target; a target the operator typed is never overwritten.
    public mutating func sync(tool: ToolDescriptor?, scopeHosts: [String]) {
        fields = Self.fields(for: tool)
        if target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { target = Self.seed(scopeHosts) }
    }

    /// The Scan page is offered exactly when the bus lists `scan.discover`.
    public static func isOffered(in tools: [ToolDescriptor]) -> Bool {
        tools.contains { $0.name == toolName }
    }

    /// The scope entries a scan can start from: concrete hosts, never a `*.wildcard`.
    public static func concreteHosts(in scopeHosts: [String]) -> [String] {
        scopeHosts.filter { !$0.isEmpty && !$0.hasPrefix("*.") }
    }

    /// The seed URL for an in-scope host entry.
    public static func seedURL(for entry: String) -> String { "http://\(entry)/" }

    private static func fields(for tool: ToolDescriptor?) -> [String] {
        tool.map { $0.parameters.map(\.name) } ?? ["target", "max_depth", "max_pages"]
    }

    private static func seed(_ scopeHosts: [String]) -> String {
        concreteHosts(in: scopeHosts).first.map(seedURL(for:)) ?? ""
    }

    /// The target as sent: a bare host gets `http://`.
    public var normalizedTarget: String {
        let trimmed = target.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.contains("://") ? trimmed : "http://" + trimmed
    }

    /// `host[:port]` the browser will connect to, lower-cased; nil unless the
    /// target is an http(s) URL with a host. Reads the real host: userinfo before
    /// the last `@` is dropped, and `/`, `\`, `?` and `#` each end the authority.
    public var authority: String? { Self.authority(of: normalizedTarget) }

    public static func authority(of url: String) -> String? {
        guard let separator = url.range(of: "://") else { return nil }
        let scheme = url[..<separator.lowerBound].lowercased()
        guard scheme == "http" || scheme == "https" else { return nil }
        let component = url[separator.upperBound...].prefix { !"/\\?#".contains($0) }
        let host = component.split(separator: "@", omittingEmptySubsequences: false).last.map(String.init) ?? ""
        return host.isEmpty ? nil : host.lowercased()
    }

    /// nil when the target may be scanned; otherwise why not. Deny-by-default: an
    /// empty scope covers nothing.
    public func scopeError(scopeHosts: [String]) -> String? {
        if target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Choose an in-scope host to scan" }
        guard let authority else { return "A scan target is an http:// or https:// URL" }
        guard Scope.contains(authority, in: scopeHosts) else {
            return "Out of scope — add \(authority) to scope to scan it"
        }
        return nil
    }

    /// Typed arguments for `scan.discover`; a budget field the schema lacks, or
    /// that is blank or not a non-negative whole number, is left out.
    public func arguments() -> [String: JSONValue] {
        var args: [String: JSONValue] = ["target": .string(normalizedTarget)]
        if hasMaxDepth, let depth = Self.count(maxDepth) { args["max_depth"] = .number(Double(depth)) }
        if hasMaxPages, let pages = Self.count(maxPages) { args["max_pages"] = .number(Double(pages)) }
        return args
    }

    private static func count(_ text: String) -> Int? {
        Int(text.trimmingCharacters(in: .whitespaces)).flatMap { $0 >= 0 ? $0 : nil }
    }
}

/// What the Scan page shows: whether a crawl is in flight, and what the last one
/// reported. Plain data; the app's `ScanPanelState` holds one and drives it.
public struct ScanState: Equatable, Sendable {
    /// A `scan.discover` is in flight; disables re-launch until it settles.
    public var running = false
    /// The seed URL the last launch sent.
    public var target: String?
    /// The URLs the last crawl reached.
    public var endpoints: [String] = []
    /// Endpoint URL → the flow it was fetched in, from the last crawl (see `ScanResult.endpointFlows`).
    public var endpointFlows: [String: String] = [:]
    public var points: [InjectionPoint] = []
    /// The selected injection point (an index into `points`).
    public var selected: Int?
    public var pagesCrawled = 0
    public var stoppedReason: String?
    /// True once a crawl has reported, so an empty result reads differently from none yet.
    public var hasResult = false
    /// The last launch failure or refusal, shown until the next launch.
    public var error: String?

    public init() {}

    public var selectedPoint: InjectionPoint? {
        selected.flatMap { points.indices.contains($0) ? points[$0] : nil }
    }

    /// The flow an endpoint row opens, or nil when the last crawl recorded none for it.
    public func flowID(forEndpoint url: String) -> FlowID? { ScanResult.flowID(for: url, in: endpointFlows) }

    /// `2 endpoints · 4 injection points · 2 pages`.
    public var summary: String {
        [Self.counted(endpoints.count, "endpoint"), Self.counted(points.count, "injection point"),
         Self.counted(pagesCrawled, "page")].joined(separator: " · ")
    }

    private static func counted(_ n: Int, _ noun: String) -> String { "\(n) \(noun)\(n == 1 ? "" : "s")" }

    public mutating func begin(target: String) {
        running = true
        error = nil
        self.target = target
    }

    public mutating func finish(_ result: ScanResult) {
        running = false
        error = nil
        endpoints = result.endpoints
        endpointFlows = result.endpointFlows
        points = result.injectionPoints
        pagesCrawled = result.pagesCrawled
        stoppedReason = result.stoppedReason
        hasResult = true
        selected = points.isEmpty ? nil : min(selected ?? 0, points.count - 1)
    }

    public mutating func fail(_ message: String) {
        running = false
        error = message
    }

    /// The one gate every launch passes. Returns the arguments to send, or nil when
    /// nothing may be sent: a crawl is already running (no second one), the bus does
    /// not offer `scan.discover`, or the target is not in scope (the reason lands in
    /// `error`). Only an allowed launch sets `running`.
    public mutating func beginLaunch(form: ScanForm, scopeHosts: [String], tools: [ToolDescriptor]) -> [String: JSONValue]? {
        guard !running else { return nil }
        guard ScanForm.isOffered(in: tools) else {
            fail("scan.discover is not on this bus (needs the scanner plugin)")
            return nil
        }
        if let refusal = form.scopeError(scopeHosts: scopeHosts) {
            fail(refusal)
            return nil
        }
        begin(target: form.normalizedTarget)
        return form.arguments()
    }
}

extension Fixtures {
    /// A `scan.discover` result over the fixture capture: every endpoint and every
    /// injection point names a fixture flow (`endpoint_flows` is keyed by the same
    /// URL string `endpoints` lists), and the secret-named points arrive redacted,
    /// as the scanner returns them. The fixture session answers `scan.discover` with it.
    public static let scanDiscover: JSONValue = {
        func point(_ n: Int, _ location: String, _ name: String, _ example: String) -> JSONValue {
            ["flow": .string(id(n).raw), "location": .string(location), "name": .string(name), "example": .string(example)]
        }
        let products = "http://api.shop-staging.test/api/products?category=electronics&limit=20"
        let orders = "http://api.shop-staging.test/api/orders?page=3"
        let login = "http://auth.shop-staging.test/api/auth/login"
        return [
            "endpoints": [.string(products), .string(orders), .string(login)],
            "endpoint_flows": [
                products: .string(id(41).raw),
                orders: .string(id(45).raw),
                login: .string(id(50).raw),
            ],
            "injection_points": [
                point(41, "query", "category", "electronics"),
                point(41, "query", "limit", "20"),
                point(45, "query", "page", "3"),
                point(50, "body_param", "email", "ops@shop-staging.test"),
                point(50, "body_param", "password", "<redacted>"),
                point(50, "cookie", "session", "<redacted>"),
            ],
            "pages_crawled": 3,
            "stopped_reason": nil,
        ]
    }()
}
