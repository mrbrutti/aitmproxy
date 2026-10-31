import AitmBusClient
import Foundation

/// What `flow.get` returns today (foundation §4.3): a summary with body sizes,
/// timing and the source app, but no headers or bodies. Everything else on a row waits for F5.
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
    /// The signing identifier of the app that opened the connection, as the capture
    /// backend observed it (`source_app`, e.g. `com.apple.Safari`). Nil for a proxied flow
    /// (`null`), an older core that sends no key, and a provider that sent nothing (`""`):
    /// none of those is an app, so none makes an Apps group.
    public var sourceApp: String?
    /// The capture backend that delivered the connection (`capture_interface`, `macos-ne`).
    /// Nil for a proxied flow. Decoded as the wire's mirror; the row does not carry it.
    public var captureInterface: String?
    /// When the core created the flow (`started_at`, milliseconds since the Unix
    /// epoch): the request head for HTTP, the upgrade for WebSocket. Nil from an
    /// older core, or when the core's clock was before the epoch.
    public var startedAt: Date?
    /// Start to the end of the response, or to where a failed response was abandoned
    /// (`duration_ms`, whole milliseconds). Nil while in flight, from an older core,
    /// and for a WebSocket flow, which has no end marker yet.
    public var duration: Duration?

    /// No body a real core buffers approaches this (the default cap is 10 MiB); a size
    /// past it is a lie from the peer, read as unknown so it is neither shown nor summed.
    static let maxBodyBytes: Int64 = 1 << 40

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
        startedAt: Date? = nil, duration: Duration? = nil, reportsBodySizes: Bool = false,
        sourceApp: String? = nil, captureInterface: String? = nil
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
        self.startedAt = startedAt
        self.duration = duration
        self.reportsBodySizes = reportsBodySizes || requestBytes != nil || responseBytes != nil
        self.sourceApp = sourceApp
        self.captureInterface = captureInterface
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
        // Who opened the connection and which backend saw it. Absent, null and "" all
        // read as nil: a proxied flow is no app, and the UI never shows a fake group.
        self.sourceApp = Self.identifier(json["source_app"])
        self.captureInterface = Self.identifier(json["capture_interface"])
        // Timing is a count of milliseconds: a negative or fractional value from the
        // wire is not one and reads as unknown (nil), never as a date before 1970.
        self.startedAt = Self.wholeMillis(json["started_at"]).map { Date(timeIntervalSince1970: Double($0) / 1000) }
        self.duration = Self.wholeMillis(json["duration_ms"]).map { .milliseconds($0) }
    }

    private static func size(_ value: JSONValue?) -> Int64? {
        guard let size = value?.intValue, size >= 0, Int64(size) <= Self.maxBodyBytes else { return nil }
        return Int64(size)
    }

    /// A non-empty string from the wire; nil when the key is absent, null, or `""`.
    private static func identifier(_ value: JSONValue?) -> String? {
        guard let text = value?.stringValue, !text.isEmpty else { return nil }
        return text
    }

    /// A non-negative whole number of milliseconds, else nil: absent, `null`, negative
    /// or fractional (`intValue` already rejects a non-integral number).
    private static func wholeMillis(_ value: JSONValue?) -> Int? {
        guard let ms = value?.intValue, ms >= 0 else { return nil }
        return ms
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
            client: sourceApp.map { ClientInfo(sourceApp: $0) },
            startedAt: startedAt, duration: duration,
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
