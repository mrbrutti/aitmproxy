import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct ActivityTests {
    @Test func decodesTheAgentNotification() throws {
        let params: JSONValue = [
            "origin": "mcp", "command": "flow.replay",
            "args": ["id": "00000045-0000-4000-8000-000000000045"],
            "result": "ok", "at": "2026-10-27T11:04:58.120Z",
        ]
        let entry = try #require(ActivityEntry(notification: params))
        #expect(entry.origin == .agent)
        #expect(entry.command == "flow.replay")
        #expect(entry.argsSummary == "id=00000045-0000-4000-8000-000000000045")
        #expect(entry.result == .ok)
        #expect(entry.args["id"] == "00000045-0000-4000-8000-000000000045")
        let expected = try #require(ISO8601DateFormatter().date(from: "2026-10-27T11:04:58Z"))
        #expect(abs(entry.at.timeIntervalSince(expected) - 0.12) < 0.001)
    }

    @Test func mapsOriginsErrorsAndPending() throws {
        let error = try #require(ActivityEntry(notification: [
            "origin": "cli", "command": "scope.add", "args": ["host": "x.test"], "result": "error", "error": "out of scope",
        ]))
        #expect(error.origin == .cli)
        #expect(error.result == .error("out of scope"))
        let pending = try #require(ActivityEntry(notification: ["origin": "mcp", "command": "ca.install", "result": "pending", "at": 1_700_000_000]))
        #expect(pending.result == .pending)
        #expect(pending.at == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(ActivityEntry.Origin(wire: "mac") == .operator)
        #expect(ActivityEntry.Origin(wire: "tui") == .operator)
        #expect(ActivityEntry.Origin(wire: "lua") == .other("lua"))
        #expect(ActivityEntry(notification: ["origin": "mcp"]) == nil)
    }

    @Test func summarisesArgumentsSortedAndTruncated() {
        let short = ActivityEntry.summary(of: ["url": "https://a.test", "enabled": true, "n": 3, "none": nil])
        #expect(short == "enabled=true n=3 none=null url=https://a.test")
        let long = ActivityEntry.summary(of: ["path": .string(String(repeating: "x", count: 100))])
        #expect(long.count == 60)
        #expect(long.hasSuffix("…"))
        #expect(long.hasPrefix("path=xxxx"))
        #expect(ActivityEntry.summary(of: ["edits": ["headers": ["a": "b"]]]) == "edits={\"headers\":{\"a\":\"b\"}}")
        #expect(ActivityEntry.summary(of: .null) == "")
    }

    /// A confirm token is a capability: the log names the key and elides the value.
    @Test func summaryElidesConfirmTokens() {
        let summary = ActivityEntry.summary(of: ["_confirm": "7f3a9c1e-token", "scope": "user"])
        #expect(summary == "_confirm=… scope=user")
        #expect(!summary.contains("7f3a9c1e"))
        let entry = ActivityEntry(origin: .operator, command: "ca.install", args: ["_confirm": "7f3a9c1e-token"], result: .ok)
        #expect(entry.argsSummary == "_confirm=…")
        #expect(entry.args["_confirm"] == "7f3a9c1e-token")
        #expect(ActivityEntry.summary(of: ["l4_confirm": "abc", "id": "1"]) == "id=1 l4_confirm=…")
    }

    @Test func ringKeepsTheLastFiveHundredAndCountsAgentActions() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        var ring = ActivityRing()
        for i in 0..<600 {
            let origin: ActivityEntry.Origin = i.isMultiple(of: 2) ? .agent : .operator
            ring.append(ActivityEntry(at: now.addingTimeInterval(Double(i - 599)), origin: origin, command: "flow.list", result: .ok))
        }
        #expect(ring.entries.count == 500)
        #expect(ring.entries.first?.at == now.addingTimeInterval(-499))
        // The last 60 seconds hold 60 entries, every other one from the agent.
        #expect(ring.actionsLastMinute(now: now) == 30)
        #expect(ring.actionsLastMinute(now: now.addingTimeInterval(120)) == 0)
        var small = ActivityRing(capacity: 2)
        small.append(ActivityEntry(origin: .cli, command: "a", result: .ok))
        small.append(ActivityEntry(origin: .cli, command: "b", result: .ok))
        small.append(ActivityEntry(origin: .cli, command: "c", result: .ok))
        #expect(small.entries.map(\.command) == ["b", "c"])
    }

    @Test func readsAgentStatus() {
        let status = AgentStatus(json: ["policy": "readonly", "actions_last_minute": 14, "connected_clients": 2])
        #expect(status == AgentStatus(policy: "readonly", actionsLastMinute: 14, connectedClients: 2))
        #expect(AgentStatus(json: ["actions_last_minute": 1]) == nil)
    }
}

/// Three scripts as `script.list` could report them — one active, one switched off, one that
/// failed to compile — for `ScriptInfoTests.statusTextFollowsEnabledAndError`.
private enum ScriptInfoInputs {
    static let active = ScriptInfo(id: "strip-hsts", name: "Strip HSTS", ruleSummary: "*.shop-staging.test · response",
                                   phases: ["response"], enabled: true)
    static let disabled = ScriptInfo(id: "tag-agent-replays", name: "Tag agent replays",
                                     ruleSummary: "api.shop-staging.test/api/* · GET POST", phases: ["request", "response"],
                                     enabled: false)
    static let broken = ScriptInfo(id: "ws-logger", name: "WebSocket frame logger",
                                   ruleSummary: "wss://api.shop-staging.test/ws/*", phases: ["websocket"], enabled: true,
                                   error: "line 12: unknown function 'frame.len' — did you mean 'frame.length'?")
}

@Suite struct ScriptInfoTests {
    @Test func statusTextFollowsEnabledAndError() {
        #expect(ScriptInfoInputs.active.statusText == "Saved and active")
        #expect(ScriptInfoInputs.disabled.statusText == "Disabled")
        #expect(ScriptInfoInputs.broken.statusText.hasPrefix("Error: line 12"))
        // Enabled with an error is not active: the Scripts page and the sidebar must agree.
        #expect(ScriptInfoInputs.active.isActive)
        #expect(!ScriptInfoInputs.disabled.isActive)
        #expect(!ScriptInfoInputs.broken.isActive)
    }

    @Test func decodesAScriptListItem() throws {
        let script = try #require(ScriptInfo(json: [
            "id": "strip-hsts", "name": "Strip HSTS", "rule": ["url": "*.shop-staging.test", "method": "GET"],
            "run_on": ["response"], "enabled": false, "last_error": "",
        ]))
        #expect(script.id == "strip-hsts")
        #expect(script.ruleSummary == "*.shop-staging.test · GET")
        #expect(script.phases == ["response"])
        #expect(script.enabled == false)
        #expect(script.error == nil)
        #expect(ScriptInfo(json: ["enabled": true]) == nil)
        let bare = try #require(ScriptInfo(json: ["name": "x", "error": "boom"]))
        #expect(bare.statusText == "Error: boom")
        #expect(bare.ruleSummary == "*")
    }
}
