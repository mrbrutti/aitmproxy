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
        self.init(id: FlowID(idRaw), request: request, response: response, connection: connection, coreID: coreID)
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

/// One WebSocket frame from `flow.detail` `messages[]` (S-045 will render these).
public struct WSFrameDetail: Hashable, Sendable {
    public enum Direction: String, Sendable { case clientToServer = "client_to_server", serverToClient = "server_to_client" }
    public var direction: Direction
    public var opcode: String
    public var length: Int
    public var injected: Bool
    public var timestamp: String?
    public var data: Data?

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
}
