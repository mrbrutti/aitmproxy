import AitmBusClient
import Foundation

extension Fixtures {
    /// The 22 M2 commands as `tools/list` reports them, so the palette and its
    /// forms work on fixtures exactly as on the live bus.
    public static let tools: [ToolDescriptor] = {
        func tool(_ name: String, _ description: String, _ params: [(String, JSONValue, Bool)] = []) -> ToolDescriptor {
            var properties: [String: JSONValue] = [:]
            var required: [JSONValue] = []
            for (pname, schema, isRequired) in params {
                properties[pname] = schema
                if isRequired { required.append(.string(pname)) }
            }
            var schema: [String: JSONValue] = ["type": "object", "properties": .object(properties), "additionalProperties": false]
            if !required.isEmpty { schema["required"] = .array(required) }
            return ToolDescriptor(name: name, description: description, inputSchema: .object(schema))
        }
        let flowID: JSONValue = ["type": "string", "format": "uuid", "description": "The flow id."]
        let str: (String) -> JSONValue = { ["type": "string", "description": .string($0)] }
        let bool: (String) -> JSONValue = { ["type": "boolean", "description": .string($0)] }
        let int: (String) -> JSONValue = { ["type": "integer", "description": .string($0)] }
        return [
            tool("flow.list", "List captured flow ids, oldest first."),
            tool("flow.get", "Summarise one flow.", [("id", flowID, true)]),
            tool("flow.intercept", "Arm (default) or disarm interception: while armed, every request is parked until flow.resume or flow.kill releases it.",
                 [("enabled", bool("true to arm (default), false to disarm."), false)]),
            tool("flow.resume", "Release an intercepted flow so its (possibly mutated) request is forwarded.", [("id", flowID, true)]),
            tool("flow.kill", "Abort an intercepted flow; the client sees a reset.", [("id", flowID, true)]),
            tool("flow.mutate", "Edit a parked request before it continues.",
                 [("id", flowID, true), ("edits", ["type": "object", "description": "Fields to change: method, scheme, authority, path, headers, body."], true)]),
            tool("flow.replay", "Send a captured flow again, unchanged; returns the new flow id.", [("id", flowID, true)]),
            tool("request.send", "Send a crafted request through the proxy's guarded client.",
                 [("method", str("HTTP method."), false), ("scheme", str("http or https."), false),
                  ("authority", str("Target host[:port]."), true), ("path", str("Request path and query."), false),
                  ("headers", ["type": "object", "additionalProperties": ["type": "string"], "description": "Header name→value."], false),
                  ("body", ["description": "Request body as a string or bytes."], false)]),
            tool("scope.add", "Authorise a host for testing.", [("host", str("host, host:port or *.wildcard."), true)]),
            tool("scope.list", "List the current scope entries."),
            tool("browser.navigate", "Open a URL in the embedded browser.", [("url", str("The URL to open."), true)]),
            tool("browser.click", "Click an element.", [("selector", str("CSS selector."), true)]),
            tool("browser.type", "Type into an element.", [("selector", str("CSS selector."), true), ("text", str("Text to type."), true)]),
            tool("browser.screenshot", "Capture the page as PNG bytes."),
            tool("browser.eval", "Evaluate JavaScript in the page.", [("expr", str("JavaScript expression."), true)]),
            tool("browser.get_dom", "Return the page's DOM as text."),
            tool("poc.build", "Build a PoC YAML from a flow.",
                 [("flow_id", flowID, true), ("name", str("PoC name."), true), ("param", str("The parameter to vary."), false)]),
            tool("poc.run", "Run a PoC against a target.",
                 [("poc_path", str("Path to the PoC YAML."), true), ("target", str("Target base URL."), true),
                  ("vars", ["type": "object", "additionalProperties": ["type": "string"], "description": "Template variables."], false)]),
            tool("ca.export", "Export the CA certificate.", [("format", str("pem or der."), false), ("path", str("Where to write it."), false)]),
            tool("ca.status", "Report whether the CA is installed and trusted."),
            tool("ca.install", "Install the CA into the login keychain (asks for confirmation)."),
            tool("ca.uninstall", "Remove the CA from the login keychain (asks for confirmation)."),
            tool("ratelimit.status", "Show the per-host rate limit and back-off state.", [("host", str("Host to inspect."), false), ("limit", int("Requests per second."), false)]),
        ]
    }()
}
