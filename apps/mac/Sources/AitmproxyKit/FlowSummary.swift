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
    /// Buffered body sizes in bytes (`request_bytes` / `response_bytes`): nil while a
    /// body is still streaming, before the response arrives, and for a WebSocket flow.
    /// The status bar's ↑ / ↓ rate is the change in their totals over time.
    public var requestBytes: Int64?
    public var responseBytes: Int64?
    /// Whether the core's `flow.get` carried the body-size fields at all (present,
    /// even as `null`): an older core omits them, and then a nil size is unknown for
    /// good rather than still streaming.
    public var reportsBodySizes: Bool

    /// No body a real core buffers approaches this (the default cap is 10 MiB); a size
    /// past it is a lie from the peer, read as unknown so it is neither shown nor summed.
    public static let maxBodyBytes: Int64 = 1 << 40

    /// An HTTP flow whose response head is here while a body is still streaming: the
    /// core reports sizes and one of them is still unknown. The poll keeps re-fetching
    /// such a flow so the final sizes land once the core buffers them. Never true for
    /// an older core that reports no sizes — there is nothing to wait for.
    public var awaitsBodySize: Bool {
        kind == .http && reportsBodySizes && status != nil && (requestBytes == nil || responseBytes == nil)
    }

    public init(
        id: FlowID, kind: FlowKind, intercept: InterceptLabel, isReplay: Bool, method: String? = nil,
        scheme: String? = nil, authority: String? = nil, path: String? = nil, status: Int? = nil,
        handshake: FlowID? = nil, messages: Int? = nil, requestBytes: Int64? = nil, responseBytes: Int64? = nil,
        reportsBodySizes: Bool = false
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
        self.requestBytes = requestBytes
        self.responseBytes = responseBytes
        self.reportsBodySizes = reportsBodySizes || requestBytes != nil || responseBytes != nil
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
        // A size is a count: a negative or absurd value from the wire is not one and
        // reads as unknown (nil), so it is neither shown nor counted. The keys being
        // present at all (even as null) says this core reports sizes.
        self.requestBytes = Self.size(json["request_bytes"])
        self.responseBytes = Self.size(json["response_bytes"])
        self.reportsBodySizes = json["request_bytes"] != nil || json["response_bytes"] != nil
    }

    private static func size(_ value: JSONValue?) -> Int64? {
        guard let size = value?.intValue, size >= 0, Int64(size) <= Self.maxBodyBytes else { return nil }
        return Int64(size)
    }

    /// A row with the fields the summary carries; the rest stay nil and draw as
    /// dashes. `coreID` stamps the originating connection (Task 5).
    public func row(seq: Int, coreID: CoreID = .fixture) -> FlowRow {
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
            requestBytes: requestBytes, responseBytes: responseBytes,
            tls: scheme == "https" || scheme == "wss" ? .decrypted : .none,
            edited: intercept == .resumed,
            wsFrames: messages.map { (sent: $0, received: 0) },
            coreID: coreID
        )
    }

    /// Splits `/a/b?x=1` into (`/a/b`, `x=1`).
    public static func splitQuery(_ pathAndQuery: String) -> (String, String?) {
        guard let mark = pathAndQuery.firstIndex(of: "?") else { return (pathAndQuery, nil) }
        let query = String(pathAndQuery[pathAndQuery.index(after: mark)...])
        return (String(pathAndQuery[..<mark]), query.isEmpty ? nil : query)
    }
}
