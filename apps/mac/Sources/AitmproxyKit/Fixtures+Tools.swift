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
            // Raw-L4 (M5 aitm-proto-l4), advertised when `l4.enabled`. The surface
            // feature-detects these by name from tools/list.
            tool("l4.interfaces", "List the host's capturable network interfaces."),
            tool("l4.scope.add", "Add a deny-by-default L4 scope entry (operator-confirmed; agent needs l4.allow_agent_widen).",
                 [("cidr", str("addr/prefix."), true), ("interface", str("Interface, e.g. lo0."), true),
                  ("direction", str("inbound or outbound."), true), ("capability", str("capture, inject or intercept."), true),
                  ("ports", str("lo-hi, a port, or * for any."), false)]),
            tool("l4.scope.list", "List the current L4 scope entries."),
            tool("l4.capture.start", "Start capturing on an interface, bound to the L4 scope.",
                 [("interface", str("Interface to capture on."), true)]),
            tool("l4.capture.stop", "Stop a capture session.", [("id", flowID, true)]),
            tool("l4.capture.status", "Report the active L4 capture sessions."),
            tool("l4.flow.list", "List captured / crafted / intercepted L4 flow ids, oldest first."),
            tool("l4.flow.get", "Summarise one L4 flow: kind, bind, and its packets.", [("id", flowID, true)]),
            tool("l4.craft", "Build a layered PacketSpec into on-wire bytes and a structural summary.",
                 [("spec", ["type": "object", "description": "A PacketSpec: { layers: [ {ipv4|udp|tcp|icmp|…: {…}} ] }."], true)]),
            tool("l4.inject", "Inject a crafted PacketSpec (guarded; operator-confirmed over the wire).",
                 [("spec", ["type": "object", "description": "The PacketSpec to inject."], true),
                  ("dst", str("Destination IP."), true), ("interface", str("Interface."), true),
                  ("port", int("Destination port."), false), ("count", int("How many copies (default 1)."), false)]),
            tool("l4.send_recv", "Send a crafted packet and return the reply(s) (guarded, operator-confirmed).",
                 [("spec", ["type": "object", "description": "The PacketSpec to send."], true),
                  ("dst", str("Destination IP."), true), ("interface", str("Interface."), true), ("port", int("Destination port."), false)]),
            tool("l4.agent.status", "Report the four per-capability agent gate states (capture, inject, intercept, widen)."),
            tool("l4.agent.set", "Open or close one per-capability agent gate (operator-only).",
                 [("capability", str("capture, inject, intercept or widen."), true), ("allowed", bool("true opens, false closes."), true)]),
        ]
    }()
}
