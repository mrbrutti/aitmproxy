import Foundation

/// A flow id as the bus reports it (a UUID string).
public struct FlowID: Hashable, Sendable, Codable, CustomStringConvertible {
    public let raw: String
    public init(_ raw: String) { self.raw = raw }
    public var description: String { raw }
}

public enum FlowKind: String, Sendable, Codable, CaseIterable {
    case http, websocket, l4
}

/// HTTP methods carry their own badge colour (foundation §2.7). `ws` is the
/// WebSocket pseudo-method.
public enum HTTPMethod: Hashable, Sendable {
    case get, post, put, patch, delete, head, options, connect, ws
    case other(String)

    public init(_ raw: String) {
        switch raw.uppercased() {
        case "GET": self = .get
        case "POST": self = .post
        case "PUT": self = .put
        case "PATCH": self = .patch
        case "DELETE": self = .delete
        case "HEAD": self = .head
        case "OPTIONS": self = .options
        case "CONNECT": self = .connect
        case "WS": self = .ws
        default: self = .other(raw.uppercased())
        }
    }

    public var label: String {
        switch self {
        case .get: "GET"
        case .post: "POST"
        case .put: "PUT"
        case .patch: "PATCH"
        case .delete: "DELETE"
        case .head: "HEAD"
        case .options: "OPTIONS"
        case .connect: "CONNECT"
        case .ws: "WS"
        case .other(let s): s
        }
    }
}

/// The core's `InterceptState` as `flow.get` labels it.
public enum InterceptLabel: String, Sendable, Codable {
    case observed, intercepted, resumed, killed
}

/// What the row's dot and Status cell show (foundation §2.7 "States").
public enum FlowState: Hashable, Sendable {
    /// No response yet.
    case pending
    /// Response received.
    case complete
    /// Parked by an armed intercept; waiting for resume or kill.
    case paused
    /// Killed by the operator or the agent.
    case killed
    /// Transport-level failure (no HTTP status).
    case failed

    /// The one-word name used for the `~state` filter and compact labels.
    public var label: String {
        switch self {
        case .pending: "pending"
        case .complete: "complete"
        case .paused: "paused"
        case .killed: "killed"
        case .failed: "failed"
        }
    }
}

/// Who produced the flow: a client through the proxy, or the agent via
/// replay / request.send / poc.run (teal tick). Needs F2 for the live bus.
public enum FlowOrigin: Hashable, Sendable {
    case client, human, agent
    /// Read from a file (S-065), never on the wire.
    case imported
}

/// The SSL column.
public enum TLSState: Hashable, Sendable {
    /// Plain HTTP.
    case none
    /// MITM'd: the proxy decrypted it.
    case decrypted
    /// CONNECT tunnel passed through; not decrypted.
    case tunnelled
    /// Pinned upstream or handshake failed.
    case pinnedOrFailed
}

/// Proxyman's 11 mark colours (foundation §2.7, open question 8).
public enum MarkColor: String, CaseIterable, Hashable, Sendable, Codable {
    case red, orange, yellow, green, mint, teal, cyan, blue, indigo, purple, pink
}

/// The client process behind a flow (F5 resolves peer → process in the core).
public struct ClientInfo: Hashable, Sendable {
    public var name: String
    /// One character for the monogram disc when there is no app icon.
    public var monogram: String
    public var bundleID: String?
    public var pid: Int32?

    public init(name: String, monogram: String? = nil, bundleID: String? = nil, pid: Int32? = nil) {
        self.name = name
        self.monogram = monogram ?? String(name.prefix(1))
        self.bundleID = bundleID
        self.pid = pid
    }
}

/// `source_app` on the wire (spec 2026-10-31-ne-source-app-on-the-wire, D5): the signing
/// identifier the capture backend observed for the process that opened the connection,
/// turned into the client the sidebar's Apps group keys on.
extension ClientInfo {
    /// Identifiers whose last dotted component is not the app's name. Safari opens its
    /// sockets from the WebKit networking process, so without the entry a Safari visit
    /// would group as `Networking`. The raw identifier stays in `bundleID` either way.
    public static let knownSourceApps: [String: String] = [
        "com.apple.WebKit.Networking": "Safari",
        "org.mozilla.firefox": "Firefox",
    ]

    /// The client for a flow whose `source_app` is `identifier`: the name from
    /// `displayName(forSourceApp:)`, the default monogram (its first character), the
    /// identifier as `bundleID`, no pid. Equal identifiers give equal clients, so
    /// `Session.clients` counts them as one group.
    public init(sourceApp identifier: String) {
        self.init(name: ClientInfo.displayName(forSourceApp: identifier), bundleID: identifier)
    }

    /// The name shown for a source-app identifier: `knownSourceApps` first; else the text
    /// after the last `.`, casing kept as sent (`com.apple.curl` → `curl`,
    /// `com.apple.Safari` → `Safari`); with no `.`, or nothing after the last one
    /// (`trailing.`), the whole identifier.
    public static func displayName(forSourceApp identifier: String) -> String {
        if let known = knownSourceApps[identifier] { return known }
        guard let dot = identifier.lastIndex(of: ".") else { return identifier }
        let tail = identifier[identifier.index(after: dot)...]
        return tail.isEmpty ? identifier : String(tail)
    }
}

/// One row of the flow list: everything the columns show. Fields the bus
/// does not report yet (F5) are optional and render as a grey dash.
public struct FlowRow: Identifiable, Hashable, Sendable {
    public var id: FlowID
    /// The core connection this flow came from (Task 5). One connection today,
    /// so it is a constant per launch, but it is present on every stored flow so
    /// a second connection is additive, not a migration.
    public var coreID: CoreID
    /// 1-based position in the capture (the `#` column).
    public var seq: Int
    public var kind: FlowKind
    public var method: HTTPMethod
    /// `http`, `https`, `ws`, `wss`.
    public var scheme: String
    /// `host[:port]`.
    public var authority: String
    /// Path without the query.
    public var path: String
    /// Query string without the `?`, when there is one.
    public var query: String?
    public var status: Int?
    public var state: FlowState
    public var isReplay: Bool
    public var origin: FlowOrigin
    public var client: ClientInfo?
    public var startedAt: Date?
    public var duration: Duration?
    public var requestBytes: Int64?
    public var responseBytes: Int64?
    public var tls: TLSState
    public var edited: Bool
    public var comment: String?
    public var mark: MarkColor?
    public var inScope: Bool
    /// WebSocket frames so far (sent, received).
    public var wsFrames: (sent: Int, received: Int)?
    /// Raw-L4 row fields (target, session state, protocol sub-label, counts) when
    /// `kind == .l4`; nil for HTTP/WebSocket.
    public var l4: L4RowInfo?

    public init(
        id: FlowID, seq: Int, kind: FlowKind = .http, method: HTTPMethod, scheme: String,
        authority: String, path: String, query: String? = nil, status: Int? = nil,
        state: FlowState = .pending, isReplay: Bool = false, origin: FlowOrigin = .client,
        client: ClientInfo? = nil, startedAt: Date? = nil, duration: Duration? = nil,
        requestBytes: Int64? = nil, responseBytes: Int64? = nil, tls: TLSState = .decrypted,
        edited: Bool = false, comment: String? = nil, mark: MarkColor? = nil, inScope: Bool = true,
        wsFrames: (sent: Int, received: Int)? = nil, l4: L4RowInfo? = nil,
        coreID: CoreID = .fixture
    ) {
        self.id = id
        self.coreID = coreID
        self.seq = seq
        self.kind = kind
        self.method = method
        self.scheme = scheme
        self.authority = authority
        self.path = path
        self.query = query
        self.status = status
        self.state = state
        self.isReplay = isReplay
        self.origin = origin
        self.client = client
        self.startedAt = startedAt
        self.duration = duration
        self.requestBytes = requestBytes
        self.responseBytes = responseBytes
        self.tls = tls
        self.edited = edited
        self.comment = comment
        self.mark = mark
        self.inScope = inScope
        self.wsFrames = wsFrames
        self.l4 = l4
    }

    /// `https://host` — the part drawn in ink.
    public var site: String { "\(scheme)://\(authority)" }
    /// The full URL as text.
    public var url: String {
        var s = "\(scheme)://\(authority)\(path)"
        if let query { s += "?\(query)" }
        return s
    }

    /// Equality covers the fields a live row can change after it first appears, so the
    /// table and SwiftUI redraw a row exactly when one of them moves. `client` is in the
    /// set: the sidebar's Apps groups and the Apps page derive from it, and a row whose
    /// client changes while everything else stays put (attribution arriving late, or the
    /// `apps-noattribution` snapshot scene) must not compare equal to its old self —
    /// SwiftUI skips the update for an equal value, and so does the table's own diff.
    public static func == (lhs: FlowRow, rhs: FlowRow) -> Bool {
        lhs.id == rhs.id && lhs.seq == rhs.seq && lhs.status == rhs.status && lhs.state == rhs.state
            && lhs.edited == rhs.edited && lhs.comment == rhs.comment && lhs.mark == rhs.mark
            && lhs.duration == rhs.duration && lhs.requestBytes == rhs.requestBytes
            && lhs.responseBytes == rhs.responseBytes
            && lhs.inScope == rhs.inScope && lhs.wsFrames?.sent == rhs.wsFrames?.sent
            && lhs.wsFrames?.received == rhs.wsFrames?.received && lhs.l4 == rhs.l4
            && lhs.client == rhs.client
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(seq)
    }
}

/// The HTTP status class (text colour + leading dot).
public enum StatusClass: Hashable, Sendable {
    case informational, success, redirect, clientError, serverError

    public init?(_ status: Int) {
        switch status {
        case 100..<200: self = .informational
        case 200..<300: self = .success
        case 300..<400: self = .redirect
        case 400..<500: self = .clientError
        case 500..<600: self = .serverError
        default: return nil
        }
    }
}

/// Reason phrases for the summary strip's status pill.
public enum StatusText {
    public static func reason(_ status: Int) -> String {
        switch status {
        case 100: "Continue"
        case 101: "Switching Protocols"
        case 200: "OK"
        case 201: "Created"
        case 202: "Accepted"
        case 204: "No Content"
        case 206: "Partial Content"
        case 301: "Moved Permanently"
        case 302: "Found"
        case 303: "See Other"
        case 304: "Not Modified"
        case 307: "Temporary Redirect"
        case 308: "Permanent Redirect"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 409: "Conflict"
        case 422: "Unprocessable Content"
        case 429: "Too Many Requests"
        case 500: "Internal Server Error"
        case 502: "Bad Gateway"
        case 503: "Service Unavailable"
        case 504: "Gateway Timeout"
        default: ""
        }
    }
}
