import AitmBusClient
import Foundation

/// One Rhai script as the Scripts page lists it (foundation §2.7 "Script
/// editor"; S-060). The bus commands are F8 (`script.list/enable/disable`).
public struct ScriptInfo: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    /// The matching rule in one line: `*.shop-staging.test/api/* · POST`.
    public var ruleSummary: String
    /// `request`, `response`, `websocket`.
    public var phases: [String]
    public var enabled: Bool
    /// The last compile or run error, when there is one.
    public var error: String?

    public init(id: String, name: String, ruleSummary: String, phases: [String], enabled: Bool, error: String? = nil) {
        self.id = id
        self.name = name
        self.ruleSummary = ruleSummary
        self.phases = phases
        self.enabled = enabled
        self.error = error
    }

    /// `● Saved and active` · `Disabled` · `Error: …` — the error wins.
    public var statusText: String {
        if let error, !error.isEmpty { return "Error: \(error)" }
        return enabled ? "Saved and active" : "Disabled"
    }

    /// Enabled with no error: what the sidebar's `N active` counts.
    public var isActive: Bool { enabled && (error ?? "").isEmpty }

    /// A plausible F8 `script.list` item: `{id|name, name, rule: string | {url, method}, phases|run_on,
    /// enabled, error|last_error}`.
    public init?(json: JSONValue) {
        guard let name = json["name"]?.stringValue ?? json["id"]?.stringValue else { return nil }
        let id = json["id"]?.stringValue ?? name
        let rule: String
        if let text = json["rule"]?.stringValue {
            rule = text
        } else if let members = json["rule"]?.objectValue {
            let url = members["url"]?.stringValue ?? members["pattern"]?.stringValue ?? "*"
            let method = members["method"]?.stringValue
            rule = [url, method].compactMap { $0 }.joined(separator: " · ")
        } else {
            rule = "*"
        }
        let phases = (json["phases"] ?? json["run_on"])?.arrayValue?.compactMap(\.stringValue) ?? []
        let error = json["error"]?.stringValue ?? json["last_error"]?.stringValue
        self.init(id: id, name: name, ruleSummary: rule, phases: phases,
                  enabled: json["enabled"]?.boolValue ?? true, error: (error ?? "").isEmpty ? nil : error)
    }
}
