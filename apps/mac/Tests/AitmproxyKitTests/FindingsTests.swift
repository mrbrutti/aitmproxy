import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// Inputs for `FindingsTests`: a parked login to pick parameters from, a product listing with
/// a query, three findings for the store round trip, and the proxy's effective config.
private enum FindingsInputs {
    static let loginRow = Make.row(seq: 1, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login",
                                   state: .paused)
    static let loginDetail = Make.detail(
        id: "flow-1",
        request: Make.message(
            "POST /api/auth/login HTTP/2",
            [("host", "auth.shop-staging.test"), ("content-type", "application/json"), ("accept", "*/*")],
            body: "{\n  \"email\": \"ops@shop-staging.test\",\n  \"password\": \"correct-horse-battery\",\n  \"remember\": true\n}"))

    static let productsRow = Make.row(seq: 2, host: "api.shop-staging.test", path: "/api/products",
                                      query: "category=electronics&limit=20", status: 200)
    static let productsDetail = Make.detail(
        id: "flow-2",
        request: Make.message("GET /api/products?category=electronics&limit=20 HTTP/2",
                              [("host", "api.shop-staging.test"), ("accept", "application/json")]),
        response: Make.response(200, [("content-type", "application/json")], body: "{\"ok\": true}"))

    /// A nuclei-style PoC document the way `aitm-poc` serializes one (`crates/aitm-poc`):
    /// `id`, `info`, `variables`, one `http` step, `success`.
    static func pocYAML(name: String, param: String, severity: String) -> String {
        """
        id: \(name.lowercased().replacingOccurrences(of: " ", with: "-"))
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

    /// The flow the XSS run captured.
    static let xssCapture = "00000048-0000-4000-8000-000000000048"

    /// Three findings: a failed High XSS reflecting into `/api/search`, a passed Medium IDOR on
    /// `/api/orders`, and an Info run the agent kicked off. Newest first.
    static let findings: [Finding] = [
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000001")!,
            title: "Reflected XSS in search",
            severity: .high, target: "https://api.shop-staging.test", passed: false,
            ranAt: Date(timeIntervalSince1970: 1_793_185_515),
            origin: .human, pocPath: "/tmp/aitm/pocs/reflected-xss-in-search.poc.yaml",
            yaml: pocYAML(name: "Reflected XSS in search", param: "q", severity: "high"),
            captureID: FlowID(xssCapture), screenshotPath: "/tmp/aitm/pocs/reflected-xss-in-search.png",
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: <img src=x onerror=alert(1)>", matched: false),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000002")!,
            title: "IDOR on orders listing",
            severity: .medium, target: "https://api.shop-staging.test", passed: true,
            ranAt: Date(timeIntervalSince1970: 1_793_185_509),
            origin: .human, pocPath: "/tmp/aitm/pocs/idor-on-orders-listing.poc.yaml",
            yaml: pocYAML(name: "IDOR on orders listing", param: "page", severity: "medium"),
            captureID: FlowID("00000045-0000-4000-8000-000000000045"),
            screenshotPath: "/tmp/aitm/pocs/idor-on-orders-listing.png",
            assertions: [
                Assertion(text: "status == 200", matched: true),
                Assertion(text: "word: \"total\"", matched: true),
            ]),
        Finding(
            id: UUID(uuidString: "F1000000-0000-4000-8000-000000000003")!,
            title: "Verbose error on cart patch",
            severity: .info, target: "https://api.shop-staging.test", passed: true,
            ranAt: Date(timeIntervalSince1970: 1_793_185_502),
            origin: .agent, pocPath: "/tmp/aitm/pocs/verbose-error-on-cart-patch.poc.yaml",
            yaml: pocYAML(name: "Verbose error on cart patch", param: "quantity", severity: "info"),
            captureID: FlowID("00000053-0000-4000-8000-000000000053"),
            assertions: [Assertion(text: "status == 422", matched: true)]),
    ]

    /// The proxy's effective config.yaml, with the keys the panel highlights (listen, the
    /// loopback_tcp bus port) and the agent-install gate set false.
    static let configYAML = """
    # aitmproxy configuration
    listen: 127.0.0.1:8080
    upstream:
      ssl_insecure: false
    scope:
      - api.shop-staging.test
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

@Suite struct FindingsTests {
    // MARK: poc.run decoding

    @Test func decodesARunResult() {
        let json: JSONValue = .object([
            "passed": .bool(false),
            "finding_capture": .string(FindingsInputs.xssCapture),
            "poc_path": .string("/tmp/pocs/reflected-xss.poc.yaml"),
            "screenshot_path": .string("/tmp/pocs/reflected-xss.png"),
            "evaluated": .array([
                .object(["assertion": .string("status == 200"), "matched": .bool(true)]),
                .object(["assertion": .string("word: <script>"), "matched": .bool(false)]),
            ]),
        ])
        let finding = Finding.fromRunResult(
            json, pocPath: "/tmp/pocs/reflected-xss.poc.yaml", target: "https://api.shop-staging.test",
            yaml: FindingsInputs.pocYAML(name: "Reflected XSS", param: "q", severity: "high"), origin: .agent)

        #expect(finding.title == "Reflected XSS")      // from the YAML's info.name, not the path
        #expect(finding.severity == .high)
        #expect(finding.passed == false)
        #expect(finding.resultText == "failed")
        #expect(finding.captureID?.raw == FindingsInputs.xssCapture)
        #expect(finding.screenshotPath == "/tmp/pocs/reflected-xss.png")
        #expect(finding.target == "https://api.shop-staging.test")
        #expect(finding.origin == .agent)
        #expect(finding.assertions.count == 2)
        #expect(finding.assertions[0] == Assertion(text: "status == 200", matched: true))
        #expect(finding.assertions[1].matched == false)
    }

    @Test func emptyScreenshotPathBecomesNil() {
        let json: JSONValue = .object([
            "passed": .bool(true), "finding_capture": .string("00000045-0000-4000-8000-000000000045"),
            "poc_path": .string("/tmp/p.yaml"), "screenshot_path": .string(""), "evaluated": .array([]),
        ])
        let finding = Finding.fromRunResult(json, pocPath: "/tmp/p.yaml", target: "https://t", yaml: "", origin: .human)
        #expect(finding.screenshotPath == nil)
        #expect(finding.hasRun == false)        // no evaluated assertions → built, not judged
        #expect(finding.resultText == "not run")
    }

    // MARK: severity from the YAML

    @Test func readsSeverityFromYAML() {
        for severity in Severity.allCases {
            let yaml = FindingsInputs.pocYAML(name: "N", param: "q", severity: severity.rawValue)
            #expect(PocYAML.info(in: yaml)["severity"] == severity.rawValue)
        }
    }

    @Test func defaultsToMediumWithoutASeverity() {
        let yaml = "id: x\ninfo:\n  name: nameless\nsteps: []\nsuccess:\n  type: status\n"
        let json: JSONValue = .object(["passed": .bool(true), "evaluated": .array([])])
        let finding = Finding.fromRunResult(json, pocPath: "/tmp/x.poc.yaml", target: "https://t", yaml: yaml, origin: .human)
        #expect(finding.severity == .medium)
        #expect(finding.title == "nameless")
    }

    // MARK: parameter candidates

    @Test func candidatesSpanQueryHeadersAndBody() {
        let candidates = PocParameters.candidates(for: FindingsInputs.loginDetail, row: FindingsInputs.loginRow)
        #expect(candidates.contains("content-type"))
        #expect(candidates.contains("email"))
        #expect(candidates.contains("password"))
        #expect(candidates.contains("remember"))
        #expect(!candidates.contains("host"))      // Host is implied by {{target}}, never offered
    }

    @Test func candidatesTakeQueryKeysFirst() {
        let row = FindingsInputs.productsRow                  // GET /api/products?category=…&limit=…
        let candidates = PocParameters.candidates(for: FindingsInputs.productsDetail, row: row)
        #expect(candidates.first == "category")
        #expect(candidates.contains("limit"))
    }

    // MARK: findings.json round trip

    @Test func storeRoundTripsNewestFirst() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "findings-\(UUID().uuidString).json")
        let store = FindingsStore(fileURL: url)
        try store.save(FindingsInputs.findings.shuffled())
        let loaded = try store.load()

        #expect(loaded.count == 3)
        #expect(loaded[0].title == "Reflected XSS in search")    // newest ranAt first
        #expect(loaded.map(\.ranAt) == loaded.map(\.ranAt).sorted(by: >))
        #expect(loaded[0].severity == .high)
        #expect(loaded[0].captureID?.raw == FindingsInputs.xssCapture)
        #expect(loaded[0].assertions.count == 2)
        #expect(loaded[0].origin == .human)
        #expect(loaded[2].origin == .agent)
        try? FileManager.default.removeItem(at: url)
    }

    @Test func missingStoreFileIsEmpty() throws {
        let store = FindingsStore(fileURL: FileManager.default.temporaryDirectory.appending(path: "none-\(UUID().uuidString).json"))
        #expect(try store.load().isEmpty)
    }

    // MARK: CA status + config document

    @Test func decodesCaStatus() {
        let json: JSONValue = .object([
            "exists": .bool(true), "path": .string("/ca/ca.crt"), "platform": .string("macos"),
            "fingerprint_sha256": .string("AA:BB"),
            "stores": .object([
                "user": .object(["installed": .string("present"), "trusted": .string("yes"), "location": .string("the login keychain")]),
                "system": .object(["installed": .string("absent"), "trusted": .string("no"), "location": .string("the System keychain")]),
            ]),
            "detail": .array([.string("present and trusted")]),
        ])
        let status = CAStatus(json: json)
        #expect(status?.installed == true)
        #expect(status?.trusted == true)
        #expect(status?.location == "the login keychain")
        #expect(status?.statusText == "Installed · trusted")
        #expect(CAStatus(json: .object([:])) == nil)       // not a ca.status object
    }

    @Test func configMarksEnvAndHighlights() {
        let doc = ConfigDocument(yaml: FindingsInputs.configYAML, path: "/etc/aitm/config.yaml", envOverrides: ["listen"])
        let listen = doc.lines.first { $0.key == "listen" }
        #expect(listen?.highlight == true)
        #expect(listen?.isEnv == true)
        #expect(doc.lines.first { $0.key == "mcp.transport.loopback_tcp.port" }?.highlight == true)
        #expect(doc.engine == "obscura")
        #expect(doc.allowAgentInstall == false)
        #expect(doc.sslInsecure == false)
    }
}
