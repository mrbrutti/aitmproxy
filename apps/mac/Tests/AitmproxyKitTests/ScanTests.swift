import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The Scan panel's model (scanner-integration Stage 1, AC5/AC6): the
/// `scan.discover` result decoded as the bus delivers it, the launch form built
/// from the tool schema, and the scope-bound, deny-by-default launch. The
/// scanner engine is `aitm-plugin-scanner`; these only exercise what the macOS
/// operator surface does with its result.
@Suite struct ScanTests {
    /// A `scan.discover` result exactly as the core serialises it: reached
    /// endpoints, injection points (one secret-named param and one cookie
    /// already redacted at the source), the crawl budget used, and no stop reason.
    static let resultJSON = """
    {
      "endpoints": [
        "http://auth.shop-staging.test/",
        "http://auth.shop-staging.test/login?next=%2Fdashboard"
      ],
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

    static var discoverTool: ToolDescriptor? { Fixtures.tools.first { $0.name == "scan.discover" } }

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

    /// The fixture runner (and a misbehaving core) can hand back a bare string.
    @Test func aNonObjectResultIsRefused() {
        #expect(throws: (any Error).self) { try ScanResult(json: .string("ok (fixture)")) }
    }

    @Test func theFixtureResultDecodesAndReferencesFixtureFlows() throws {
        let result = try ScanResult(json: Fixtures.scanDiscover)
        #expect(!result.endpoints.isEmpty)
        #expect(!result.injectionPoints.isEmpty)
        let known = Set(Fixtures.rows.map(\.id))
        #expect(result.injectionPoints.allSatisfy { known.contains($0.flowID) })
        #expect(result.injectionPoints.contains { $0.example == "<redacted>" })
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
        let form = ScanForm(tool: Self.discoverTool, scopeHosts: Fixtures.scope)
        let args = state.beginLaunch(form: form, scopeHosts: Fixtures.scope, tools: Fixtures.tools)
        #expect(args == ["target": .string("http://api.shop-staging.test/")])
        #expect(state.running)
        #expect(state.error == nil)

        // The running flag disables re-launch while the crawl is in flight.
        #expect(state.beginLaunch(form: form, scopeHosts: Fixtures.scope, tools: Fixtures.tools) == nil)
        #expect(state.running)
    }

    @Test func anOutOfScopeTargetNeverLaunches() {
        var state = ScanState()
        var form = ScanForm(tool: Self.discoverTool, scopeHosts: Fixtures.scope)
        form.target = "https://telemetry.vendor-analytics.example/v2"
        let args = state.beginLaunch(form: form, scopeHosts: Fixtures.scope, tools: Fixtures.tools)
        #expect(args == nil, "nothing reaches the wire for an out-of-scope host")
        #expect(!state.running)
        #expect(state.error == "Out of scope — add telemetry.vendor-analytics.example to scope to scan it")
    }

    @Test func anEmptyScopeRefusesEveryTarget() {
        var state = ScanState()
        var form = ScanForm(tool: Self.discoverTool, scopeHosts: [])
        #expect(form.target.isEmpty, "nothing in scope to seed the target with")
        form.target = "http://api.shop-staging.test/"
        #expect(state.beginLaunch(form: form, scopeHosts: [], tools: Fixtures.tools) == nil)
        #expect(!state.running)
        #expect(state.error?.hasPrefix("Out of scope") == true)
    }

    @Test func aBlankTargetNeverLaunches() {
        var state = ScanState()
        var form = ScanForm(tool: Self.discoverTool, scopeHosts: [])
        form.target = "   "
        #expect(state.beginLaunch(form: form, scopeHosts: Fixtures.scope, tools: Fixtures.tools) == nil)
        #expect(state.error == "Choose an in-scope host to scan")
    }

    @Test func aBusWithoutTheScannerNeverLaunches() {
        var state = ScanState()
        let form = ScanForm(tool: nil, scopeHosts: Fixtures.scope)
        let withoutScan = Fixtures.tools.filter { $0.name != "scan.discover" }
        #expect(state.beginLaunch(form: form, scopeHosts: Fixtures.scope, tools: withoutScan) == nil)
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
        let tool = try #require(Self.discoverTool)
        var form = ScanForm(tool: tool, scopeHosts: Fixtures.scope)
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
        form.sync(tool: narrow, scopeHosts: Fixtures.scope)
        #expect(form.fields == ["target"])
        #expect(form.target == "http://api.shop-staging.test/", "a blank target is seeded once scope arrives")

        form.target = "http://auth.shop-staging.test/login"
        form.sync(tool: Self.discoverTool, scopeHosts: ["cdn.shop-staging.test"])
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

    // MARK: Fixtures and the sidebar section

    /// The Scan sidebar section is offered exactly when the bus lists `scan.discover`
    /// (`Session.scanEnabled`): present with the fixture tool list, absent without it.
    @Test func theScanSectionIsOfferedOnlyWhenTheToolIs() {
        #expect(Fixtures.tools.contains { $0.name == "scan.discover" })
        #expect(ScanForm.isOffered(in: Fixtures.tools))
        #expect(!ScanForm.isOffered(in: []))
        #expect(!ScanForm.isOffered(in: Fixtures.tools.filter { $0.name != "scan.discover" }))
    }

    @Test func fixtureToolsIncludeScanDiscoverAndBrowserConfineAsTheBackendShipsThem() throws {
        let names = Fixtures.tools.map(\.name)
        #expect(names.filter { $0 == "scan.discover" }.count == 1)
        #expect(names.filter { $0 == "browser.confine" }.count == 1)

        let scan = try #require(Self.discoverTool)
        let target = try #require(scan.parameters.first { $0.name == "target" })
        #expect(target.type == .string && target.required)
        let depth = try #require(scan.parameters.first { $0.name == "max_depth" })
        #expect(depth.type == .int && !depth.required)
        let pages = try #require(scan.parameters.first { $0.name == "max_pages" })
        #expect(pages.type == .int && !pages.required)

        let confine = try #require(Fixtures.tools.first { $0.name == "browser.confine" })
        #expect(confine.parameters.map(\.name) == ["on"])
        #expect(confine.parameters.first?.type == .bool)
        #expect(confine.parameters.first?.required == true)
    }
}
