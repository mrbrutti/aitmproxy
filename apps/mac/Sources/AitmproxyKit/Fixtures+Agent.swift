import AitmBusClient
import Foundation

/// A page the fixture browser shows: title, URL and the last frame as PNG.
public struct BrowserPage: Hashable, Sendable {
    public var title: String
    public var url: String
    public var png: Data

    public init(title: String, url: String, png: Data) {
        self.title = title
        self.url = url
        self.png = png
    }
}

/// The Agent page, the activity log, the Scripts page and the Browser view
/// without a live bus (S-054–S-057, S-060).
extension Fixtures {
    /// Twelve invocations over the three minutes before `base`: the agent
    /// probing, the operator replaying, the CLI listing; one gated
    /// `ca.install` from the agent still pending, one error.
    public static let activity: [ActivityEntry] = {
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
    public static let scripts: [ScriptInfo] = [
        ScriptInfo(id: "strip-hsts", name: "Strip HSTS", ruleSummary: "*.shop-staging.test · response",
                   phases: ["response"], enabled: true),
        ScriptInfo(id: "tag-agent-replays", name: "Tag agent replays", ruleSummary: "api.shop-staging.test/api/* · GET POST",
                   phases: ["request", "response"], enabled: false),
        ScriptInfo(id: "ws-logger", name: "WebSocket frame logger", ruleSummary: "wss://api.shop-staging.test/ws/*",
                   phases: ["websocket"], enabled: true,
                   error: "line 12: unknown function 'frame.len' — did you mean 'frame.length'?"),
    ]

    /// The fixture browser's one tab. The 4×4 PNG scales to fill the viewport.
    public static let browserPage = BrowserPage(
        title: "Shop staging — Sign in",
        url: "https://auth.shop-staging.test/login?next=%2Faccount",
        png: tinyPNG)

    /// `browser.get_dom` as the Browser view's DOM drawer outlines it.
    public static let domOutline: [String] = [
        "html lang=\"en\"",
        "  head",
        "    title  Shop staging — Sign in",
        "    link rel=\"stylesheet\" href=\"/assets/app.3f1c.css\"",
        "  body.theme-light",
        "    header#top",
        "      a.logo href=\"/\"",
        "    main",
        "      form#login method=\"post\" action=\"/api/auth/login\"",
        "        input#email name=\"email\" type=\"email\"",
        "        input#password name=\"password\" type=\"password\"",
        "        button.primary type=\"submit\"  Sign in",
        "    script src=\"/assets/app.3f1c.js\"",
    ]
}
