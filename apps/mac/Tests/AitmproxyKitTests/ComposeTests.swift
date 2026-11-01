import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ScopeTests {
    @Test func matchesTheThreeForms() {
        #expect(Scope.matches("api.shop-staging.test", "api.shop-staging.test"))
        #expect(Scope.matches("api.shop-staging.test:8443", "api.shop-staging.test"))
        #expect(Scope.matches("api.shop-staging.test:8443", "api.shop-staging.test:8443"))
        #expect(!Scope.matches("api.shop-staging.test:8443", "api.shop-staging.test:443"))
        #expect(Scope.matches("cdn.shop-staging.test", "*.shop-staging.test"))
        #expect(Scope.matches("shop-staging.test", "*.shop-staging.test"))
        #expect(!Scope.matches("evil-shop-staging.test", "*.shop-staging.test"))
    }

    @Test func validatesEntries() {
        #expect(Scope.validate("api.example.test") == nil)
        #expect(Scope.validate("api.example.test:8443") == nil)
        #expect(Scope.validate("*.example.test") == nil)
        #expect(Scope.validate("https://api.example.test") != nil)
        #expect(Scope.validate("api.example.test/path") != nil)
        #expect(Scope.validate("api.example.test:99999") != nil)
        #expect(Scope.validate("") != nil)
    }
}

/// Inputs for `ComposeDraftTests`: the authorised hosts, and a parked login to prefill from.
private enum ComposeInputs {
    static let scope = ["api.shop-staging.test", "auth.shop-staging.test"]
    static let loginRow = Make.row(seq: 1, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login",
                                   state: .paused)
    static let loginDetail = Make.detail(
        id: "flow-1",
        request: Make.message(
            "POST /api/auth/login HTTP/2",
            [("host", "auth.shop-staging.test"), ("content-type", "application/json"), ("accept", "*/*")],
            body: "{\"email\": \"ops@shop-staging.test\", \"password\": \"correct-horse-battery\"}"))
}

@Suite struct ComposeDraftTests {
    @Test func buildsRequestEditsFromTheURL() {
        let draft = ComposeDraft(method: "POST", url: "https://api.shop-staging.test:8443/api/cart?x=1&y=two",
                                 headersText: "Accept: application/json\nX-Trace: 1", body: "{\"a\":1}", bodyKind: .json)
        let edits = draft.requestEdits()
        #expect(edits.scheme == "https")
        #expect(edits.authority == "api.shop-staging.test:8443")
        #expect(edits.path == "/api/cart?x=1&y=two")
        #expect(edits.headers?["accept"] == "application/json")
        #expect(edits.headers?["content-type"] == "application/json")
        #expect(edits.body == Data("{\"a\":1}".utf8))
        #expect(draft.queryItems.map(\.0) == ["x", "y"])
    }

    @Test func scopeDisablesSend() {
        let draft = ComposeDraft(url: "https://telemetry.vendor-analytics.example/v2/batch")
        #expect(draft.validationError(scope: ComposeInputs.scope)?.hasPrefix("Out of scope") == true)
        #expect(ComposeDraft(url: "https://api.shop-staging.test/x").validationError(scope: ComposeInputs.scope) == nil)
        #expect(ComposeDraft(url: "not a url").validationError(scope: []) != nil)
        #expect(ComposeDraft(url: "ftp://api.shop-staging.test/").validationError(scope: []) != nil)
    }

    @Test func prefillsFromAFlow() {
        let draft = ComposeDraft.from(detail: ComposeInputs.loginDetail, row: ComposeInputs.loginRow)
        #expect(draft.method == "POST")
        #expect(draft.url == "https://auth.shop-staging.test/api/auth/login")
        #expect(!draft.headersText.contains("host:"))
        #expect(draft.headersText.contains("content-type: application/json"))
        #expect(draft.bodyKind == .json)
        #expect(draft.body.contains("correct-horse-battery"))
    }

    @Test func importsCurl() throws {
        let command = """
        curl -X POST 'https://api.shop-staging.test/api/cart' \\
          -H 'content-type: application/json' \\
          --data-raw '{"quantity": 2}' --frobnicate
        """
        let imported = try #require(ComposeDraft.from(curl: command))
        #expect(imported.draft.method == "POST")
        #expect(imported.draft.url == "https://api.shop-staging.test/api/cart")
        #expect(imported.draft.bodyKind == .json)
        #expect(imported.draft.body == "{\"quantity\": 2}")
        #expect(imported.unknownFlags == ["--frobnicate"])
        #expect(ComposeDraft.from(curl: "GET /x") == nil)
    }

    @Test func historyIsNewestFirstAndCapped() throws {
        var history = ComposeHistory()
        for i in 0..<(ComposeHistory.capacity + 5) {
            history.record(ComposeDraft(url: "https://h.test/\(i)"), at: Date(timeIntervalSince1970: Double(i)))
        }
        #expect(history.entries.count == ComposeHistory.capacity)
        #expect(history.entries.first?.url == "https://h.test/204")
        let url = FileManager.default.temporaryDirectory.appending(path: "compose-\(UUID().uuidString).json")
        try history.save(to: url)
        #expect(ComposeHistory.load(from: url).entries.count == ComposeHistory.capacity)
    }

    @Test func templatesAndKillModes() {
        #expect(ComposeDraft.Template.postJSON.draft.bodyKind == .json)
        #expect(!ComposeDraft.Template.webSocket.isAvailable)
        #expect(KillMode.respond429.syntheticStatus == 429)
        #expect(KillMode.reset.syntheticStatus == nil)
    }
}
