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

@Suite struct ScriptInfoTests {
    @Test func statusTextFollowsEnabledAndError() {
        #expect(Fixtures.scripts[0].statusText == "Saved and active")
        #expect(Fixtures.scripts[1].statusText == "Disabled")
        #expect(Fixtures.scripts[2].statusText.hasPrefix("Error: line 12"))
        // Enabled with an error is not active: the Scripts page and the sidebar must agree.
        #expect(Fixtures.scripts[0].isActive)
        #expect(!Fixtures.scripts[1].isActive)
        #expect(!Fixtures.scripts[2].isActive)
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
