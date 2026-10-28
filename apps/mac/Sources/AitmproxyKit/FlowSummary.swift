import AitmBusClient
import Foundation

/// What `flow.get` returns today (foundation §4.3): a summary with no headers,
/// bodies, timing or client. Everything else on a row waits for F5.
public struct FlowSummary: Hashable, Sendable {
    public var id: FlowID
    public var kind: FlowKind
    public var intercept: InterceptLabel
    public var isReplay: Bool
    public var method: String?
    public var scheme: String?
    /// `host[:port]`.
    public var authority: String?
    /// Path and query, as one string.
    public var path: String?
    public var status: Int?
    /// The upgrade flow of a WebSocket flow.
    public var handshake: FlowID?
    public var messages: Int?

    public init(
        id: FlowID, kind: FlowKind, intercept: InterceptLabel, isReplay: Bool, method: String? = nil,
        scheme: String? = nil, authority: String? = nil, path: String? = nil, status: Int? = nil,
        handshake: FlowID? = nil, messages: Int? = nil
    ) {
        self.id = id
        self.kind = kind
        self.intercept = intercept
        self.isReplay = isReplay
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.status = status
        self.handshake = handshake
        self.messages = messages
    }

    /// Decodes the `structuredContent` of a `flow.get` result. Unknown
    /// intercept labels decode as `observed`, so a newer core still lists.
    public init?(json: JSONValue) {
        guard let id = json["id"]?.stringValue, let kindRaw = json["kind"]?.stringValue,
              let kind = FlowKind(rawValue: kindRaw) else { return nil }
        self.id = FlowID(id)
        self.kind = kind
        self.intercept = json["intercept"]?.stringValue.flatMap(InterceptLabel.init(rawValue:)) ?? .observed
        self.isReplay = json["is_replay"]?.boolValue ?? false
        self.method = json["method"]?.stringValue
        self.scheme = json["scheme"]?.stringValue
        self.authority = json["authority"]?.stringValue
        self.path = json["path"]?.stringValue
        self.status = json["status"]?.intValue
        self.handshake = json["handshake"]?.stringValue.map(FlowID.init)
        self.messages = json["messages"]?.intValue
    }

    /// A row with the fields the summary carries; the rest stay nil and draw as dashes.
    public func row(seq: Int) -> FlowRow {
        let (p, q) = Self.splitQuery(path ?? "/")
        let state: FlowState
        switch intercept {
        case .intercepted: state = .paused
        case .killed: state = .killed
        case .observed, .resumed: state = status == nil ? .pending : .complete
        }
        let scheme = scheme ?? (kind == .websocket ? "wss" : "https")
        return FlowRow(
            id: id, seq: seq, kind: kind,
            method: kind == .websocket ? .ws : HTTPMethod(method ?? "GET"),
            scheme: scheme, authority: authority ?? "", path: p, query: q,
            status: kind == .websocket && status == nil ? 101 : status,
            state: state, isReplay: isReplay, origin: isReplay ? .human : .client,
            tls: scheme == "https" || scheme == "wss" ? .decrypted : .none,
            edited: intercept == .resumed,
            wsFrames: messages.map { (sent: $0, received: 0) }
        )
    }

    /// Splits `/a/b?x=1` into (`/a/b`, `x=1`).
    public static func splitQuery(_ pathAndQuery: String) -> (String, String?) {
        guard let mark = pathAndQuery.firstIndex(of: "?") else { return (pathAndQuery, nil) }
        let query = String(pathAndQuery[pathAndQuery.index(after: mark)...])
        return (String(pathAndQuery[..<mark]), query.isEmpty ? nil : query)
    }
}
