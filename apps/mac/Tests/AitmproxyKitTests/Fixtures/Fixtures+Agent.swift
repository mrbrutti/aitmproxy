@testable import AitmproxyKit
import AitmBusClient
import Foundation

/// Inputs for the Agent-page activity log and the Scripts-page unit tests
/// (S-054–S-057).
extension Fixtures {
    /// Twelve invocations over the three minutes before `base`: the agent
    /// probing, the operator replaying, the CLI listing; one gated
    /// `ca.install` from the agent still pending, one error.
    static let activity: [ActivityEntry] = {
        func entry(_ seconds: Double, _ origin: ActivityEntry.Origin, _ command: String,
                   _ args: [String: JSONValue] = [:], _ result: ActivityEntry.Result = .ok) -> ActivityEntry {
            ActivityEntry(at: at(seconds), origin: origin, command: command, args: args, result: result)
        }
        let orders: JSONValue = .string(id(45).raw)
        return [
            entry(-176, .cli, "scope.list"),
            entry(-171, .cli, "scope.add", ["host": "api.shop-staging.test"]),
            entry(-150, .agent, "flow.list"),
            entry(-147, .agent, "flow.get", ["id": orders]),
            entry(-131, .agent, "flow.replay", ["id": orders]),
            entry(-118, .operator, "flow.intercept", ["enabled": true]),
            entry(-92, .agent, "browser.navigate", ["url": "https://api.shop-staging.test/api/search?q=%22%3E%3Cimg+src%3Dx%3E"]),
            entry(-74, .agent, "request.send",
                  ["authority": "api.shop-staging.test", "method": "GET", "path": "/api/search?q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"]),
            entry(-55, .operator, "flow.resume", ["id": .string(id(50).raw)]),
            entry(-38, .agent, "scope.add", ["host": "internal.shop-staging.test"],
                  .error("scope.add is operator-only: the agent cannot widen the scope")),
            entry(-21, .cli, "flow.list"),
            entry(-6, .agent, "ca.install", [:], .pending),
        ]
    }()

    /// Three scripts: one active, one switched off, one that failed to compile.
    static let scripts: [ScriptInfo] = [
        ScriptInfo(id: "strip-hsts", name: "Strip HSTS", ruleSummary: "*.shop-staging.test · response",
                   phases: ["response"], enabled: true),
        ScriptInfo(id: "tag-agent-replays", name: "Tag agent replays", ruleSummary: "api.shop-staging.test/api/* · GET POST",
                   phases: ["request", "response"], enabled: false),
        ScriptInfo(id: "ws-logger", name: "WebSocket frame logger", ruleSummary: "wss://api.shop-staging.test/ws/*",
                   phases: ["websocket"], enabled: true,
                   error: "line 12: unknown function 'frame.len' — did you mean 'frame.length'?"),
    ]
}
