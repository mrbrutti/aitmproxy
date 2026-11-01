import AitmBusClient
import Foundation

/// Decoders for `flow.detail` (F5). The core returns the full flow — request
/// and response objects with `headers` as `[[name, value]]` and base64 bodies,
/// plus `client_conn` / `server_conn`, `meta`, `intercept` and `edited`; a
/// WebSocket flow returns `handshake` + `messages`. Shapes mirror
/// `crates/aitm-plugins/src/detail.rs`.
extension FlowDetail {
    /// Decodes a `flow.detail` HTTP result (the `structuredContent`). Returns
    /// nil for a WebSocket flow (its frames are decoded separately, S-045).
    public init?(detailJSON json: JSONValue, coreID: CoreID = .fixture) {
        guard let idRaw = json["id"]?.stringValue else { return nil }
        guard (json["kind"]?.stringValue ?? "http") == "http", let requestObj = json["request"] else { return nil }
        let request = HTTPMessage(requestObject: requestObj)
        let response = json["response"].flatMap { $0.isNull ? nil : HTTPMessage(responseObject: $0) }
        let connection = ConnectionInfo(
            detailJSON: json, requestVersion: requestObj["version"]?.stringValue ?? "HTTP/1.1")
        // Per-host decryption (#228): `meta.passive` and `meta.tunnel`, both absent from an
        // older core, `tunnel` null for a flow that is not a tunnel.
        let meta = json["meta"]
        self.init(id: FlowID(idRaw), request: request, response: response, connection: connection,
                  tunnel: TunnelInfo(metaTunnel: meta?["tunnel"]),
                  passive: meta?["passive"]?.boolValue ?? false,
                  coreID: coreID)
    }
}

extension TunnelInfo {
    /// Decodes `meta.tunnel` (`{mode, reason, bytes_up, bytes_down}`,
    /// `crates/aitm-plugins/src/detail.rs` `tunnel`). Nil for null, absent, or a `mode`
    /// this build does not know; an unknown `reason` keeps the mode and reads as nil. The
    /// byte counts take the same guards as the body sizes (`FlowSummary.size`).
    init?(metaTunnel json: JSONValue?) {
        guard let json, let mode = json["mode"]?.stringValue.flatMap(TunnelMode.init(rawValue:)) else { return nil }
        self.init(
            mode: mode,
            reason: json["reason"]?.stringValue.flatMap(TunnelReason.init(rawValue:)),
            bytesUp: FlowSummary.size(json["bytes_up"]),
            bytesDown: FlowSummary.size(json["bytes_down"]))
    }
}

extension HTTPMessage {
    /// A request object from `flow.detail`: `{method, scheme, authority, path, version, headers, body}`.
    init(requestObject json: JSONValue) {
        let method = json["method"]?.stringValue ?? "GET"
        let path = json["path"]?.stringValue ?? "/"
        let version = json["version"]?.stringValue ?? "HTTP/1.1"
        self.init(startLine: "\(method) \(path) \(version)",
                  headers: HTTPMessage.headers(json["headers"]),
                  body: HTTPMessage.body(json["body"]))
    }

    /// A response object from `flow.detail`: `{status, version, headers, body}`.
    init(responseObject json: JSONValue) {
        let version = json["version"]?.stringValue ?? "HTTP/1.1"
        let status = json["status"]?.intValue ?? 0
        let reason = status > 0 ? StatusText.reason(status) : ""
        let line = "\(version) \(status) \(reason)".trimmingCharacters(in: .whitespaces)
        self.init(startLine: line,
                  headers: HTTPMessage.headers(json["headers"]),
                  body: HTTPMessage.body(json["body"]))
    }

    /// `[[name, value], …]` → ordered headers (duplicates kept).
    static func headers(_ json: JSONValue?) -> [Header] {
        (json?.arrayValue ?? []).compactMap { pair in
            guard let a = pair.arrayValue, a.count == 2,
                  let name = a[0].stringValue, let value = a[1].stringValue else { return nil }
            return Header(name, value)
        }
    }

    /// Bodies cross as a base64 string (`Value::Bytes`), or null when absent / `body: none`.
    static func body(_ json: JSONValue?) -> Data? {
        guard let s = json?.stringValue, !s.isEmpty else { return nil }
        return Data(base64Encoded: s)
    }
}

extension ConnectionInfo {
    init(detailJSON json: JSONValue, requestVersion: String) {
        let client = json["client_conn"]
        let server = json["server_conn"]
        self.init(
            httpVersion: requestVersion,
            tlsVersion: nil,
            alpn: client?["alpn"]?.stringValue,
            sni: client?["sni"]?.stringValue,
            clientAddress: client?["peer"]?.stringValue,
            serverAddress: server?.isNull == false ? server?["peer"]?.stringValue : nil)
    }
}

/// One WebSocket frame from `flow.detail` `messages[]` (S-045).
public struct WSFrameDetail: Hashable, Sendable {
    public enum Direction: String, Sendable { case clientToServer = "client_to_server", serverToClient = "server_to_client" }
    public var direction: Direction
    public var opcode: String
    public var length: Int
    public var injected: Bool
    public var timestamp: String?
    public var data: Data?

    public init(direction: Direction, opcode: String, length: Int, injected: Bool = false,
                timestamp: String? = nil, data: Data? = nil) {
        self.direction = direction
        self.opcode = opcode
        self.length = length
        self.injected = injected
        self.timestamp = timestamp
        self.data = data
    }

    public init?(json: JSONValue) {
        guard let dir = json["dir"]?.stringValue.flatMap(Direction.init(rawValue:)) else { return nil }
        self.direction = dir
        self.opcode = json["opcode"]?.stringValue ?? "binary"
        self.length = json["length"]?.intValue ?? 0
        self.injected = json["injected"]?.boolValue ?? false
        self.timestamp = json["timestamp"]?.stringValue
        self.data = HTTPMessage.body(json["data"])
    }

    /// Decodes the `messages` array of a WebSocket `flow.detail` result.
    public static func frames(in json: JSONValue) -> [WSFrameDetail] {
        (json["messages"]?.arrayValue ?? []).compactMap(WSFrameDetail.init(json:))
    }

    /// `data` as UTF-8 for a text frame, nil for binary or empty.
    public var text: String? {
        guard opcode == "text", let data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// A one-line summary for the frames table: the first line of a text frame,
    /// a control-frame note, or a byte count for binary.
    public var preview: String {
        switch opcode {
        case "text":
            if let text, !text.isEmpty {
                return text.split(whereSeparator: \.isNewline).first.map(String.init) ?? text
            }
            // A text frame whose bytes are not valid UTF-8 still has a payload.
            return length == 0 ? "(empty)" : "\(length) bytes"
        case "ping": return "Ping"
        case "pong": return "Pong"
        case "close": return "Close"
        default:
            return length == 0 ? "(empty)" : "\(length) bytes"
        }
    }

    /// Which body viewer the payload gets. A WebSocket frame carries no content
    /// type, so the kind is sniffed from the bytes: a JSON text frame reads as
    /// JSON, other text as text, binary as binary.
    public var bodyKind: BodyKind {
        guard let data, !data.isEmpty else { return .text }
        return BodyKind.detect(contentType: nil, data: data)
    }

    /// A content type to feed the body viewer so a JSON text frame pretty-prints.
    /// Binary and empty control frames carry none (the viewer sniffs → hex / no body).
    public var contentTypeHint: String? {
        switch bodyKind {
        case .json: "application/json"
        case .xml: "application/xml"
        case .html: "text/html"
        case .javascript: "application/javascript"
        case .css: "text/css"
        case .text: opcode == "text" ? "text/plain" : nil
        default: nil
        }
    }
}

/// Everything the inspector needs for one WebSocket flow (S-045): the handshake
/// flow it upgraded from, the ordered message stream, and the connection.
/// A WebSocket flow is a different shape from an HTTP request/response, so it is
/// its own type rather than a variant of `FlowDetail`.
public struct WSDetail: Hashable, Sendable {
    public var id: FlowID
    /// The id of the HTTP upgrade flow (`handshake` in the detail JSON), if the core gave one.
    public var handshakeFlowID: String?
    public var frames: [WSFrameDetail]
    public var connection: ConnectionInfo

    public init(id: FlowID, handshakeFlowID: String? = nil, frames: [WSFrameDetail], connection: ConnectionInfo) {
        self.id = id
        self.handshakeFlowID = handshakeFlowID
        self.frames = frames
        self.connection = connection
    }

    /// Decodes a `flow.detail` WebSocket result (`kind == "websocket"`). Returns
    /// nil for an HTTP flow (decode that with `FlowDetail(detailJSON:)`).
    public init?(detailJSON json: JSONValue) {
        guard let idRaw = json["id"]?.stringValue, json["kind"]?.stringValue == "websocket" else { return nil }
        self.init(
            id: FlowID(idRaw),
            handshakeFlowID: json["handshake"]?.stringValue,
            frames: WSFrameDetail.frames(in: json),
            connection: ConnectionInfo(detailJSON: json, requestVersion: "HTTP/1.1"))
    }

    public var sentCount: Int { frames.filter { $0.direction == .clientToServer }.count }
    public var receivedCount: Int { frames.filter { $0.direction == .serverToClient }.count }
}

/// The Sent | Received | Both filter over a WebSocket frame stream (S-045).
public enum WSDirectionFilter: String, CaseIterable, Identifiable, Sendable {
    case both = "Both", sent = "Sent", received = "Received"
    public var id: String { rawValue }
    public func keeps(_ frame: WSFrameDetail) -> Bool {
        switch self {
        case .both: true
        case .sent: frame.direction == .clientToServer
        case .received: frame.direction == .serverToClient
        }
    }
}
