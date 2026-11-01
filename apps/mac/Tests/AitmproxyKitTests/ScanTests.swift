import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Inputs for `ScanTests`: the authorised hosts, the bus's tool list with and without the
/// scanner, three captured flows, and a `scan.discover` answer that links to them.
private enum ScanInputs {
    static let scope = ["api.shop-staging.test", "auth.shop-staging.test"]

    /// `scan.discover` as `tools/list` describes it: `target` required, two optional budgets.
    static let discoverTool = ToolDescriptor(
        name: "scan.discover",
        description: "Discover reachable in-scope URLs under target and enumerate the injection points visible in captured requests. No injection or fuzzing is performed.",
        inputSchema: [
            "type": "object",
            "properties": [
                "target": ["type": "string", "description": "The in-scope seed URL, e.g. https://app.example/."],
                "max_depth": ["type": "integer", "description": "Link depth to follow (clamped to the configured cap)."],
                "max_pages": ["type": "integer", "description": "Pages to visit (clamped to the configured cap)."],
            ],
            "required": ["target"],
            "additionalProperties": false,
        ])
    static let flowList = ToolDescriptor(
        name: "flow.list", description: "List captured flow ids, oldest first.",
        inputSchema: ["type": "object", "properties": [:], "additionalProperties": false])

    /// A bus with the scanner plugin, and one without.
    static let tools = [flowList, discoverTool]
    static let toolsWithoutScan = [flowList]

    static let productsID = "00000041-0000-4000-8000-000000000041"
    static let ordersID = "00000045-0000-4000-8000-000000000045"
    static let loginID = "00000050-0000-4000-8000-000000000050"

    /// The three flows the answer below links to: a product listing with a query, an orders
    /// page, and the login.
    static let rows: [FlowRow] = [
        Make.row(id: productsID, seq: 1, host: "api.shop-staging.test", path: "/api/products",
                 query: "category=electronics&limit=20", status: 200),
        Make.row(id: ordersID, seq: 2, host: "api.shop-staging.test", path: "/api/orders", query: "page=3", status: 502),
        Make.row(id: loginID, seq: 3, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused),
    ]

    /// A `scan.discover` result over those rows: every endpoint and every injection point
    /// names one of them (`endpoint_flows` is keyed by the same URL string `endpoints` lists),
    /// and the secret-named points arrive redacted, as the scanner returns them.
    static let discover: JSONValue = {
        func point(_ flow: String, _ location: String, _ name: String, _ example: String) -> JSONValue {
            ["flow": .string(flow), "location": .string(location), "name": .string(name), "example": .string(example)]
        }
        let products = "http://api.shop-staging.test/api/products?category=electronics&limit=20"
        let orders = "http://api.shop-staging.test/api/orders?page=3"
        let login = "http://auth.shop-staging.test/api/auth/login"
        return [
            "endpoints": [.string(products), .string(orders), .string(login)],
            "endpoint_flows": [
                products: .string(productsID),
                orders: .string(ordersID),
                login: .string(loginID),
            ],
            "injection_points": [
                point(productsID, "query", "category", "electronics"),
                point(productsID, "query", "limit", "20"),
                point(ordersID, "query", "page", "3"),
                point(loginID, "body_param", "email", "ops@shop-staging.test"),
                point(loginID, "body_param", "password", "<redacted>"),
                point(loginID, "cookie", "session", "<redacted>"),
            ],
            "pages_crawled": 3,
            "stopped_reason": nil,
        ]
    }()
}

/// The Scan panel's model (scanner-integration Stage 1, AC5/AC6): the
/// `scan.discover` result decoded as the bus delivers it, the launch form built
/// from the tool schema, and the scope-bound, deny-by-default launch. The
/// scanner engine is `aitm-plugin-scanner`; these only exercise what the macOS
/// operator surface does with its result.
@Suite struct ScanTests {
    /// A `scan.discover` result exactly as the core serialises it: reached
    /// endpoints, the flow each one was fetched in (keyed by the same scrubbed
    /// URL string as `endpoints`), injection points (one secret-named param and
    /// one cookie already redacted at the source), the crawl budget used, and no
    /// stop reason.
    static let resultJSON = """
    {
      "endpoints": [
        "http://auth.shop-staging.test/",
        "http://auth.shop-staging.test/login?next=%2Fdashboard"
      ],
      "endpoint_flows": {
        "http://auth.shop-staging.test/": "00000041-0000-4000-8000-000000000041",
        "http://auth.shop-staging.test/login?next=%2Fdashboard": "00000050-0000-4000-8000-000000000050"
      },
      "injection_points": [
        { "flow": "00000050-0000-4000-8000-000000000050", "location": "query", "name": "next", "example": "/dashboard" },
        { "flow": "00000050-0000-4000-8000-000000000050", "location": "body_param", "name": "password", "example": "<redacted>" },
        { "flow": "00000050-0000-4000-8000-000000000050", "location": "cookie", "name": "session", "example": "<redacted>" },
        { "flow": "00000041-0000-4000-8000-000000000041", "location": "header", "name": "x-trace", "example": "abc" }
      ],
      "pages_crawled": 2,
      "stopped_reason": null
    }
    """

    static func decoded() throws -> ScanResult {
        try ScanResult(json: JSONValue.parse(resultJSON))
    }

    // MARK: Decoding

    @Test func decodesADiscoverResult() throws {
        let result = try Self.decoded()

        #expect(result.endpoints == ["http://auth.shop-staging.test/", "http://auth.shop-staging.test/login?next=%2Fdashboard"])
        #expect(result.injectionPoints.count == 4)
        #expect(result.pagesCrawled == 2)
        #expect(result.stoppedReason == nil)

        let next = result.injectionPoints[0]
        #expect(next.flow == "00000050-0000-4000-8000-000000000050")
        #expect(next.flowID == FlowID("00000050-0000-4000-8000-000000000050"))
        #expect(next.location == "query")
        #expect(next.name == "next")
        #expect(next.example == "/dashboard")
        #expect(result.injectionPoints[3].location == "header")
        #expect(result.injectionPoints[3].flowID == FlowID("00000041-0000-4000-8000-000000000041"))
    }

    /// The scanner redacts at the source; the panel shows what it is handed and
    /// never reconstructs a value, so a redacted example survives verbatim.
    @Test func redactedExamplesArriveVerbatim() throws {
        let points = try Self.decoded().injectionPoints
        #expect(points[1].name == "password")
        #expect(points[1].example == "<redacted>")
        #expect(points[2].name == "session")
        #expect(points[2].example == "<redacted>")
    }

    @Test func aStoppedCrawlKeepsItsReason() throws {
        let json: JSONValue = ["endpoints": [], "injection_points": [], "pages_crawled": 7, "stopped_reason": "left_scope"]
        let result = try ScanResult(json: json)
        #expect(result.stoppedReason == "left_scope")
        #expect(result.pagesCrawled == 7)
        #expect(result.endpoints.isEmpty)
    }

    /// Every injection point carries the flow it was seen in; a point without one
    /// is not a result the panel can open, so the whole result is refused.
    @Test func anInjectionPointWithoutAFlowIsRefused() {
        let json: JSONValue = [
            "endpoints": [], "pages_crawled": 1,
            "injection_points": [["location": "query", "name": "q", "example": "x"]],
        ]
        #expect(throws: (any Error).self) { try ScanResult(json: json) }
    }

    /// A misbehaving core can hand back a bare string.
    @Test func aNonObjectResultIsRefused() {
        #expect(throws: (any Error).self) { try ScanResult(json: .string("ok")) }
    }

    /// A result built as a `JSONValue` (not parsed from text) decodes the same way, and every
    /// injection point names one of the captured rows.
    @Test func aJSONValueResultDecodesAndItsPointsNameCapturedFlows() throws {
        let result = try ScanResult(json: ScanInputs.discover)
        #expect(result.endpoints.count == 3)
        #expect(result.injectionPoints.count == 6)
        let known = Set(ScanInputs.rows.map(\.id))
        #expect(result.injectionPoints.allSatisfy { known.contains($0.flowID) })
        #expect(result.injectionPoints.contains { $0.example == "<redacted>" })
    }

    // MARK: Endpoint flows (AC3: an endpoint links to the flow it was fetched in)

    /// `endpoint_flows` is keyed by the same scrubbed URL string `endpoints`
    /// carries, so an endpoint row resolves its flow by looking up its own text.
    @Test func decodesEndpointFlowsKeyedByTheEndpointURL() throws {
        let result = try Self.decoded()

        #expect(result.endpointFlows == [
            "http://auth.shop-staging.test/": "00000041-0000-4000-8000-000000000041",
            "http://auth.shop-staging.test/login?next=%2Fdashboard": "00000050-0000-4000-8000-000000000050",
        ])
        #expect(result.flowID(forEndpoint: "http://auth.shop-staging.test/") == FlowID("00000041-0000-4000-8000-000000000041"))
        #expect(result.flowID(forEndpoint: "http://auth.shop-staging.test/login?next=%2Fdashboard")
                == FlowID("00000050-0000-4000-8000-000000000050"))
        // Every endpoint stays verbatim; linking never rewrites the URL.
        #expect(result.endpoints == ["http://auth.shop-staging.test/", "http://auth.shop-staging.test/login?next=%2Fdashboard"])
    }

    /// An endpoint the map does not list (the crawl reached it but no flow was
    /// recorded, or the flow was evicted) has no link; the row stays plain.
    @Test func anEndpointAbsentFromTheMapHasNoFlow() throws {
        let result = try Self.decoded()
        #expect(result.flowID(forEndpoint: "http://auth.shop-staging.test/not-crawled") == nil)
        #expect(result.flowID(forEndpoint: "") == nil)
        // The key is matched exactly, not by prefix or after normalising.
        #expect(result.flowID(forEndpoint: "http://auth.shop-staging.test") == nil)
        #expect(result.flowID(forEndpoint: "HTTP://auth.shop-staging.test/") == nil)
    }

    /// A core that predates `endpoint_flows` (or a null / mistyped value) still
    /// yields a usable result: no links, every other field intact.
    @Test func aMissingOrMalformedEndpointFlowsMapIsEmptyNotFatal() throws {
        func result(_ flows: JSONValue?) throws -> ScanResult {
            var json: [String: JSONValue] = ["endpoints": ["http://a.test/"], "injection_points": [], "pages_crawled": 1]
            if let flows { json["endpoint_flows"] = flows }
            return try ScanResult(json: .object(json))
        }
        for flows: JSONValue? in [nil, .null, ["http://a.test/"], .string("f1"), .number(3), [:]] {
            let decoded = try result(flows)
            #expect(decoded.endpointFlows.isEmpty, "endpoint_flows = \(String(describing: flows))")
            #expect(decoded.flowID(forEndpoint: "http://a.test/") == nil)
            #expect(decoded.endpoints == ["http://a.test/"])
            #expect(decoded.pagesCrawled == 1)
        }
    }

    /// Only a non-empty string flow id is a link; a bad entry is dropped without
    /// taking its neighbours (or the injection points) with it.
    @Test func aBadEndpointFlowEntryIsDroppedAndTheRestKept() throws {
        let json: JSONValue = [
            "endpoints": ["http://a.test/", "http://a.test/b", "http://a.test/c", "http://a.test/d"],
            "endpoint_flows": [
                "http://a.test/": "f1", "http://a.test/b": "", "http://a.test/c": 7, "http://a.test/d": .null,
            ],
            "injection_points": [["flow": "f1", "location": "query", "name": "q", "example": "1"]],
            "pages_crawled": 4,
        ]
        let result = try ScanResult(json: json)
        #expect(result.endpointFlows == ["http://a.test/": "f1"])
        #expect(result.flowID(forEndpoint: "http://a.test/") == FlowID("f1"))
        #expect(result.flowID(forEndpoint: "http://a.test/b") == nil)
        #expect(result.flowID(forEndpoint: "http://a.test/c") == nil)
        #expect(result.flowID(forEndpoint: "http://a.test/d") == nil)
        #expect(result.injectionPoints.count == 1)
    }

    /// The state the panel binds to carries the links, and a new result replaces
    /// them rather than merging with the last crawl's.
    @Test func stateResolvesEndpointFlowsAndReplacesThemOnANewResult() throws {
        var state = ScanState()
        #expect(state.endpointFlows.isEmpty)
        #expect(state.flowID(forEndpoint: "http://auth.shop-staging.test/") == nil)

        state.finish(try Self.decoded())
        #expect(state.endpointFlows.count == 2)
        #expect(state.flowID(forEndpoint: "http://auth.shop-staging.test/") == FlowID("00000041-0000-4000-8000-000000000041"))
        #expect(state.flowID(forEndpoint: "http://auth.shop-staging.test/login?next=%2Fdashboard")
                == FlowID("00000050-0000-4000-8000-000000000050"))
        #expect(state.flowID(forEndpoint: "http://elsewhere.test/") == nil)

        state.finish(try ScanResult(json: ["endpoints": ["http://a.test/"], "endpoint_flows": ["http://a.test/": "f9"], "pages_crawled": 1]))
        #expect(state.endpointFlows == ["http://a.test/": "f9"])
        #expect(state.flowID(forEndpoint: "http://auth.shop-staging.test/") == nil, "the last crawl's links are gone")
        #expect(state.flowID(forEndpoint: "http://a.test/") == FlowID("f9"))
    }

    /// A `scan.discover` answer whose `endpoint_flows` link every endpoint decodes with
    /// one link per endpoint, and each link names the captured flow whose URL the endpoint is.
    @Test func everyLinkedEndpointResolvesToTheRowWhoseURLItIs() throws {
        let result = try ScanResult(json: ScanInputs.discover)
        let rows = Dictionary(uniqueKeysWithValues: ScanInputs.rows.map { ($0.id, $0) })

        #expect(result.endpointFlows.count == result.endpoints.count)
        for endpoint in result.endpoints {
            let flow = try #require(result.flowID(forEndpoint: endpoint), "\(endpoint) has a flow")
            let row = try #require(rows[flow], "\(endpoint) links to a captured flow")
            let tail = row.query.map { "\(row.path)?\($0)" } ?? row.path
            #expect(endpoint.hasSuffix("://\(row.authority)\(tail)"), "\(endpoint) is the URL of flow \(row.seq)")
        }
        #expect(result.flowID(forEndpoint: "http://api.shop-staging.test/api/orders?page=3") == FlowID(ScanInputs.ordersID))
    }

    // MARK: ScanState

    @Test func stateStartsIdleAndPopulatesFromAResult() throws {
        var state = ScanState()
        #expect(!state.running)
        #expect(state.endpoints.isEmpty && state.points.isEmpty)
        #expect(state.selectedPoint == nil)

        state.begin(target: "http://auth.shop-staging.test/")
        #expect(state.running)
        #expect(state.target == "http://auth.shop-staging.test/")

        state.finish(try Self.decoded())
        #expect(!state.running, "the result clears the running flag")
        #expect(state.error == nil)
        #expect(state.endpoints.count == 2)
        #expect(state.points.count == 4)
        #expect(state.pagesCrawled == 2)
        #expect(state.selected == 0, "the first injection point is selected")
        #expect(state.selectedPoint?.name == "next")
        #expect(state.summary == "2 endpoints · 4 injection points · 2 pages")
    }

    @Test func aFailedCrawlSettlesTheFlagAndKeepsTheReason() {
        var state = ScanState()
        state.begin(target: "http://auth.shop-staging.test/")
        state.fail("out of scope")
        #expect(!state.running)
        #expect(state.error == "out of scope")
    }

    @Test func aNewResultClampsTheSelection() throws {
        var state = ScanState()
        state.finish(try Self.decoded())
        state.selected = 3
        let smaller: JSONValue = [
            "endpoints": ["http://a.test/"], "pages_crawled": 1,
            "injection_points": [["flow": "f1", "location": "query", "name": "q", "example": "1"]],
        ]
        state.finish(try ScanResult(json: smaller))
        #expect(state.selected == 0)
        state.finish(try ScanResult(json: ["endpoints": [], "injection_points": [], "pages_crawled": 0]))
        #expect(state.selected == nil)
        #expect(state.selectedPoint == nil)
    }

    // MARK: Launch (deny-by-default, scope-bound)

    @Test func anInScopeTargetLaunchesOneScopeBoundDiscover() {
        var state = ScanState()
        let form = ScanForm(tool: ScanInputs.discoverTool, scopeHosts: ScanInputs.scope)
        let args = state.beginLaunch(form: form, scopeHosts: ScanInputs.scope, tools: ScanInputs.tools)
        #expect(args == ["target": .string("http://api.shop-staging.test/")])
        #expect(state.running)
        #expect(state.error == nil)

        // The running flag disables re-launch while the crawl is in flight.
        #expect(state.beginLaunch(form: form, scopeHosts: ScanInputs.scope, tools: ScanInputs.tools) == nil)
        #expect(state.running)
    }

    @Test func anOutOfScopeTargetNeverLaunches() {
        var state = ScanState()
        var form = ScanForm(tool: ScanInputs.discoverTool, scopeHosts: ScanInputs.scope)
        form.target = "https://telemetry.vendor-analytics.example/v2"
        let args = state.beginLaunch(form: form, scopeHosts: ScanInputs.scope, tools: ScanInputs.tools)
        #expect(args == nil, "nothing reaches the wire for an out-of-scope host")
        #expect(!state.running)
        #expect(state.error == "Out of scope — add telemetry.vendor-analytics.example to scope to scan it")
    }

    @Test func anEmptyScopeRefusesEveryTarget() {
        var state = ScanState()
        var form = ScanForm(tool: ScanInputs.discoverTool, scopeHosts: [])
        #expect(form.target.isEmpty, "nothing in scope to seed the target with")
        form.target = "http://api.shop-staging.test/"
        #expect(state.beginLaunch(form: form, scopeHosts: [], tools: ScanInputs.tools) == nil)
        #expect(!state.running)
        #expect(state.error?.hasPrefix("Out of scope") == true)
    }

    @Test func aBlankTargetNeverLaunches() {
        var state = ScanState()
        var form = ScanForm(tool: ScanInputs.discoverTool, scopeHosts: [])
        form.target = "   "
        #expect(state.beginLaunch(form: form, scopeHosts: ScanInputs.scope, tools: ScanInputs.tools) == nil)
        #expect(state.error == "Choose an in-scope host to scan")
    }

    @Test func aBusWithoutTheScannerNeverLaunches() {
        var state = ScanState()
        let form = ScanForm(tool: nil, scopeHosts: ScanInputs.scope)
        let withoutScan = ScanInputs.toolsWithoutScan
        #expect(state.beginLaunch(form: form, scopeHosts: ScanInputs.scope, tools: withoutScan) == nil)
        #expect(!state.running)
        #expect(state.error == "scan.discover is not on this bus (needs the scanner plugin)")
    }

    /// The scope check reads the host the browser will actually connect to, so a
    /// userinfo, backslash or fragment trick cannot smuggle an out-of-scope host.
    @Test func theScopeCheckReadsTheRealHost() {
        let scope = ["api.shop-staging.test", "*.cdn.test"]
        func refusal(_ target: String) -> String? {
            var form = ScanForm(tool: nil, scopeHosts: [])
            form.target = target
            return form.scopeError(scopeHosts: scope)
        }
        #expect(refusal("http://api.shop-staging.test/") == nil)
        #expect(refusal("https://api.shop-staging.test:8443/admin?x=1") == nil)
        #expect(refusal("api.shop-staging.test") == nil, "a bare host is read as http://host")
        #expect(refusal("http://img.cdn.test/") == nil, "a wildcard entry covers its subdomains")
        #expect(refusal("http://evil.example@api.shop-staging.test/") == nil, "userinfo is not the host")
        #expect(refusal("http://api.shop-staging.test@evil.example/") != nil)
        #expect(refusal("http://evil.example\\@api.shop-staging.test/") != nil, "a backslash ends the authority")
        #expect(refusal("http://evil.example#.cdn.test/") != nil)
        #expect(refusal("http://evil.example/api.shop-staging.test") != nil)
        #expect(refusal("file:///etc/passwd") == "A scan target is an http:// or https:// URL")
    }

    // MARK: ScanForm

    @Test func theFormIsBuiltFromTheToolSchema() throws {
        let tool = ScanInputs.discoverTool
        var form = ScanForm(tool: tool, scopeHosts: ScanInputs.scope)
        #expect(form.fields == ["max_depth", "max_pages", "target"], "the schema's parameters, sorted by name")
        #expect(form.hasMaxDepth && form.hasMaxPages)
        #expect(form.target == "http://api.shop-staging.test/", "seeded with the first concrete in-scope host")

        #expect(form.arguments() == ["target": .string("http://api.shop-staging.test/")])
        form.maxDepth = "2"
        form.maxPages = " 30 "
        #expect(form.arguments() == [
            "target": .string("http://api.shop-staging.test/"), "max_depth": .number(2), "max_pages": .number(30),
        ])
        form.maxDepth = "-1"
        form.maxPages = "many"
        #expect(form.arguments() == ["target": .string("http://api.shop-staging.test/")], "a bad number is left to the configured cap")
    }

    @Test func aFieldTheSchemaLacksIsNeverSent() {
        let narrow = ToolDescriptor(
            name: "scan.discover", description: "",
            inputSchema: ["type": "object", "properties": ["target": ["type": "string"]], "required": ["target"]])
        var form = ScanForm(tool: narrow, scopeHosts: ["api.shop-staging.test"])
        #expect(form.fields == ["target"])
        form.maxDepth = "3"
        #expect(!form.hasMaxDepth)
        #expect(form.arguments() == ["target": .string("http://api.shop-staging.test/")])
    }

    @Test func theSeedSkipsWildcardScopeEntries() {
        #expect(ScanForm.concreteHosts(in: ["*.shop-staging.test", "", "api.shop-staging.test:8443", "auth.shop-staging.test"])
                == ["api.shop-staging.test:8443", "auth.shop-staging.test"])
        #expect(ScanForm(tool: nil, scopeHosts: ["*.shop-staging.test"]).target.isEmpty)
        #expect(ScanForm(tool: nil, scopeHosts: ["*.shop-staging.test", "api.shop-staging.test:8443"]).target
                == "http://api.shop-staging.test:8443/")
    }

    /// The form is built before the bus lists its tools and scope; it re-reads
    /// both when they arrive but never overwrites a target the operator typed.
    @Test func syncPicksUpALateSchemaWithoutTouchingATypedTarget() {
        var form = ScanForm(tool: nil, scopeHosts: [])
        #expect(form.target.isEmpty)
        #expect(form.fields == ["target", "max_depth", "max_pages"], "the documented fields until the schema is known")

        let narrow = ToolDescriptor(
            name: "scan.discover", description: "",
            inputSchema: ["type": "object", "properties": ["target": ["type": "string"]]])
        form.sync(tool: narrow, scopeHosts: ScanInputs.scope)
        #expect(form.fields == ["target"])
        #expect(form.target == "http://api.shop-staging.test/", "a blank target is seeded once scope arrives")

        form.target = "http://auth.shop-staging.test/login"
        form.sync(tool: ScanInputs.discoverTool, scopeHosts: ["cdn.shop-staging.test"])
        #expect(form.fields == ["max_depth", "max_pages", "target"])
        #expect(form.target == "http://auth.shop-staging.test/login")
    }

    @Test func authorityIsTheLowerCasedHostAndPort() {
        #expect(ScanForm.authority(of: "HTTP://User@API.Shop-Staging.test:8443/x?y#z") == "api.shop-staging.test:8443")
        #expect(ScanForm.authority(of: "https://api.shop-staging.test") == "api.shop-staging.test")
        #expect(ScanForm.authority(of: "ftp://api.shop-staging.test/") == nil)
        #expect(ScanForm.authority(of: "http:///path") == nil)
        #expect(ScanForm.authority(of: "api.shop-staging.test") == nil, "authority(of:) wants a URL; the form adds http:// first")
        var form = ScanForm(tool: nil, scopeHosts: [])
        form.target = "api.shop-staging.test:8443"
        #expect(form.normalizedTarget == "http://api.shop-staging.test:8443")
        #expect(form.authority == "api.shop-staging.test:8443")
    }

    // MARK: The sidebar section

    /// The Scan sidebar section is offered exactly when the bus lists `scan.discover`
    /// (`Session.scanEnabled`): present when the list has it, absent without it.
    @Test func theScanSectionIsOfferedOnlyWhenTheToolIs() {
        #expect(ScanInputs.tools.contains { $0.name == "scan.discover" })
        #expect(ScanForm.isOffered(in: ScanInputs.tools))
        #expect(!ScanForm.isOffered(in: []))
        #expect(!ScanForm.isOffered(in: ScanInputs.toolsWithoutScan))
    }
}
