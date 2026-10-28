import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct FindingsTests {
    // MARK: poc.run decoding

    @Test func decodesARunResult() {
        let json: JSONValue = .object([
            "passed": .bool(false),
            "finding_capture": .string(Fixtures.id(48).raw),
            "poc_path": .string("/tmp/pocs/reflected-xss.poc.yaml"),
            "screenshot_path": .string("/tmp/pocs/reflected-xss.png"),
            "evaluated": .array([
                .object(["assertion": .string("status == 200"), "matched": .bool(true)]),
                .object(["assertion": .string("word: <script>"), "matched": .bool(false)]),
            ]),
        ])
        let finding = Finding.fromRunResult(
            json, pocPath: "/tmp/pocs/reflected-xss.poc.yaml", target: "https://api.shop-staging.test",
            yaml: Fixtures.pocYAML(name: "Reflected XSS", param: "q", severity: "high"), origin: .agent)

        #expect(finding.title == "Reflected XSS")      // from the YAML's info.name, not the path
        #expect(finding.severity == .high)
        #expect(finding.passed == false)
        #expect(finding.resultText == "failed")
        #expect(finding.captureID?.raw == Fixtures.id(48).raw)
        #expect(finding.screenshotPath == "/tmp/pocs/reflected-xss.png")
        #expect(finding.target == "https://api.shop-staging.test")
        #expect(finding.origin == .agent)
        #expect(finding.assertions.count == 2)
        #expect(finding.assertions[0] == Assertion(text: "status == 200", matched: true))
        #expect(finding.assertions[1].matched == false)
    }

    @Test func emptyScreenshotPathBecomesNil() {
        let json: JSONValue = .object([
            "passed": .bool(true), "finding_capture": .string(Fixtures.id(45).raw),
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
            let yaml = Fixtures.pocYAML(name: "N", param: "q", severity: severity.rawValue)
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
        let candidates = PocParameters.candidates(for: Fixtures.pausedLogin, row: Fixtures.rows[9])
        #expect(candidates.contains("content-type"))
        #expect(candidates.contains("email"))
        #expect(candidates.contains("password"))
        #expect(candidates.contains("remember"))
        #expect(!candidates.contains("host"))      // Host is implied by {{target}}, never offered
    }

    @Test func candidatesTakeQueryKeysFirst() {
        let row = Fixtures.rows[0]                  // GET /api/products?category=…&limit=…
        let candidates = PocParameters.candidates(for: Fixtures.detail(for: row), row: row)
        #expect(candidates.first == "category")
        #expect(candidates.contains("limit"))
    }

    // MARK: findings.json round trip

    @Test func storeRoundTripsNewestFirst() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "findings-\(UUID().uuidString).json")
        let store = FindingsStore(fileURL: url)
        try store.save(Fixtures.findings.shuffled())
        let loaded = try store.load()

        #expect(loaded.count == 3)
        #expect(loaded[0].title == "Reflected XSS in search")    // newest ranAt first
        #expect(loaded.map(\.ranAt) == loaded.map(\.ranAt).sorted(by: >))
        #expect(loaded[0].severity == .high)
        #expect(loaded[0].captureID?.raw == Fixtures.id(48).raw)
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
        let doc = ConfigDocument(yaml: Fixtures.configYAML, path: "/etc/aitm/config.yaml", envOverrides: ["listen"])
        let listen = doc.lines.first { $0.key == "listen" }
        #expect(listen?.highlight == true)
        #expect(listen?.isEnv == true)
        #expect(doc.lines.first { $0.key == "mcp.transport.loopback_tcp.port" }?.highlight == true)
        #expect(doc.engine == "obscura")
        #expect(doc.allowAgentInstall == false)
        #expect(doc.sslInsecure == false)
    }
}
