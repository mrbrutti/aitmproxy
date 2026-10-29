import AitmBusClient
import Foundation

/// One command invocation from any frontend (foundation §4.4
/// `notifications/aitm/agent`, F2): the activity log's row.
public struct ActivityEntry: Identifiable, Hashable, Sendable {
    /// Who asked: the agent over MCP, a human in a GUI, the CLI, or a frontend we do not know.
    public enum Origin: Hashable, Sendable {
        case agent, `operator`, cli, other(String)

        /// `mcp` is the agent; `mac`, `web`, `tui` are the operator; `cli` is the CLI.
        public init(wire: String) {
            switch wire.lowercased() {
            case "mcp", "agent": self = .agent
            case "mac", "web", "tui", "operator", "human": self = .operator
            case "cli": self = .cli
            default: self = .other(wire)
            }
        }

        public var title: String {
            switch self {
            case .agent: "agent"
            case .operator: "operator"
            case .cli: "cli"
            case .other(let name): name
            }
        }
    }

    public enum Result: Hashable, Sendable {
        case ok
        case error(String)
        /// A gated command waiting for the operator's approval (e.g. `ca.install` from the agent).
        case pending

        public var text: String {
            switch self {
            case .ok: "ok"
            case .error: "error"
            case .pending: "pending"
            }
        }
    }

    public var id: UUID
    public var at: Date
    public var origin: Origin
    public var command: String
    /// The arguments, kept so an approved pending command can run as sent.
    public var args: [String: JSONValue]
    public var argsSummary: String
    public var result: Result

    public init(id: UUID = UUID(), at: Date = Date(), origin: Origin, command: String,
                args: [String: JSONValue] = [:], argsSummary: String? = nil, result: Result) {
        self.id = id
        self.at = at
        self.origin = origin
        self.command = command
        self.args = args
        self.argsSummary = argsSummary ?? Self.summary(of: .object(args))
        self.result = result
    }

    /// The §4.4 shape: `{origin, command, args, result: "ok"|"error"|"pending", at}`;
    /// an error's text may ride in `error` or `message`. `at` is RFC 3339 or Unix seconds.
    public init?(notification params: JSONValue) {
        guard let command = params["command"]?.stringValue, !command.isEmpty else { return nil }
        let origin = Origin(wire: params["origin"]?.stringValue ?? "")
        let args = params["args"]?.objectValue ?? [:]
        let at = params["at"].flatMap(Self.date) ?? Date()
        let result: Result
        switch params["result"] {
        case .string(let text)?:
            switch text.lowercased() {
            case "ok", "success": result = .ok
            case "pending", "awaiting_confirmation", "confirm": result = .pending
            default:
                let message = params["error"]?.stringValue ?? params["message"]?.stringValue
                result = .error(message ?? (text.lowercased() == "error" ? "error" : text))
            }
        case .object(let members)?:
            if let message = members["error"]?.stringValue ?? members["message"]?.stringValue {
                result = .error(message)
            } else {
                result = .ok
            }
        default:
            result = params["error"]?.stringValue.map(Result.error) ?? .ok
        }
        self.init(at: at, origin: origin, command: command, args: args, result: result)
    }

    /// `id=0000… format=pem` — sorted keys, scalars as written, nested values compact; cut at `limit` with an ellipsis.
    public static func summary(of args: JSONValue, limit: Int = 60) -> String {
        let text: String
        if let members = args.objectValue {
            text = members.keys.sorted().map { "\($0)=\(scalar(members[$0] ?? .null))" }.joined(separator: " ")
        } else if args.isNull {
            text = ""
        } else {
            text = scalar(args)
        }
        guard text.count > limit else { return text }
        return String(text.prefix(max(limit - 1, 0))) + "…"
    }

    private static func scalar(_ value: JSONValue) -> String {
        switch value {
        case .null: "null"
        case .bool(let b): b ? "true" : "false"
        case .number(let n): Int(exactly: n).map(String.init) ?? String(n)
        case .string(let s): s
        case .array, .object: value.serialized()
        }
    }

    private static func date(_ value: JSONValue) -> Date? {
        if let seconds = value.doubleValue { return Date(timeIntervalSince1970: seconds) }
        guard let text = value.stringValue else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: text) { return date }
        return ISO8601DateFormatter().date(from: text)
    }
}

/// `agent.status` → `{policy, actions_last_minute, connected_clients}` (foundation §4.8, F1).
public struct AgentStatus: Hashable, Sendable {
    /// `all`, `readonly` or `paused`, as the bus spells it.
    public var policy: String
    public var actionsLastMinute: Int
    public var connectedClients: Int

    public init(policy: String, actionsLastMinute: Int = 0, connectedClients: Int = 0) {
        self.policy = policy
        self.actionsLastMinute = actionsLastMinute
        self.connectedClients = connectedClients
    }

    public init?(json: JSONValue) {
        guard let policy = json["policy"]?.stringValue else { return nil }
        self.init(policy: policy,
                  actionsLastMinute: json["actions_last_minute"]?.intValue ?? 0,
                  connectedClients: json["connected_clients"]?.intValue ?? 0)
    }
}

/// The last `capacity` entries, oldest first; the Agent toggle's count comes from here.
public struct ActivityRing: Hashable, Sendable {
    public let capacity: Int
    public private(set) var entries: [ActivityEntry] = []

    public init(capacity: Int = 500) {
        self.capacity = max(capacity, 1)
    }

    public mutating func append(_ entry: ActivityEntry) {
        entries.append(entry)
        if entries.count > capacity { entries.removeFirst(entries.count - capacity) }
    }

    public mutating func removeAll() { entries.removeAll() }

    /// Agent-originated entries in the minute before `now`.
    public func actionsLastMinute(now: Date = Date()) -> Int {
        let since = now.addingTimeInterval(-60)
        return entries.lazy.filter { $0.origin == .agent && $0.at > since && $0.at <= now }.count
    }
}
