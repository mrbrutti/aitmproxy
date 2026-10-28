import Foundation

/// A JSON-RPC 2.0 request the client sends. Encodes as one line.
public struct JSONRPCRequest: Hashable, Sendable {
    public let id: Int
    public let method: String
    public let params: JSONValue?

    public init(id: Int, method: String, params: JSONValue? = nil) {
        self.id = id
        self.method = method
        self.params = params
    }

    /// `{"jsonrpc":"2.0","id":..,"method":..,"params":..}\n`
    public func encodedLine() -> Data {
        var members: [String: JSONValue] = ["jsonrpc": "2.0", "id": .number(Double(id)), "method": .string(method)]
        if let params { members["params"] = params }
        return Data((JSONValue.object(members).serialized() + "\n").utf8)
    }
}

/// A JSON-RPC 2.0 message without an id: sent by the client (`notifications/initialized`)
/// or pushed by the server (a future `flow.subscribe` stream).
public struct JSONRPCNotification: Hashable, Sendable {
    public let method: String
    public let params: JSONValue

    public init(method: String, params: JSONValue = .object([:])) {
        self.method = method
        self.params = params
    }

    /// `{"jsonrpc":"2.0","method":..,"params":..}\n`
    public func encodedLine() -> Data {
        let members: [String: JSONValue] = ["jsonrpc": "2.0", "method": .string(method), "params": params]
        return Data((JSONValue.object(members).serialized() + "\n").utf8)
    }
}

/// The `error` member of a failed JSON-RPC response.
public struct JSONRPCErrorBody: Hashable, Sendable {
    public let code: Int
    public let message: String
    public let data: JSONValue?
}

/// A JSON-RPC 2.0 response. `id` is kept as JSON because the server answers a
/// refused token line (and parse errors) with `"id": null`.
public struct JSONRPCResponse: Hashable, Sendable {
    public let id: JSONValue
    public let result: JSONValue?
    public let error: JSONRPCErrorBody?
}

/// One parsed inbound line.
public enum JSONRPCMessage: Hashable, Sendable {
    case response(JSONRPCResponse)
    case notification(JSONRPCNotification)

    /// Parses one line (without its newline). A message with `method` and no
    /// `id` is a notification; one with `result` or `error` is a response.
    public static func parse(_ line: Data) throws(BusError) -> JSONRPCMessage {
        let value = try JSONValue.parse(line)
        guard let members = value.objectValue else { throw BusError.malformed("message is not a JSON object") }
        if let method = members["method"]?.stringValue {
            return .notification(JSONRPCNotification(method: method, params: members["params"] ?? .object([:])))
        }
        guard let id = members["id"], members["result"] != nil || members["error"] != nil else {
            throw BusError.malformed("message is neither a response nor a notification")
        }
        var error: JSONRPCErrorBody?
        if let body = members["error"] {
            guard let code = body["code"]?.intValue else { throw BusError.malformed("error without an integer code") }
            error = JSONRPCErrorBody(code: code, message: body["message"]?.stringValue ?? "", data: body["data"])
        }
        return .response(JSONRPCResponse(id: id, result: members["result"], error: error))
    }
}

/// Splits a byte stream into newline-terminated lines, enforcing the server's
/// 16 MiB line limit. Blank lines are dropped; a trailing `\r` is stripped.
public struct LineFramer: Sendable {
    /// Matches `MAX_MESSAGE_BYTES` in `crates/aitm-mcp/src/transport.rs`.
    public static let maxLineBytes = 16 * 1024 * 1024

    private var buffer = Data()

    public init() {}

    /// Appends `data` and returns every complete line it closed off (without
    /// the terminator). Throws `.malformed` once a line passes the limit;
    /// the framer is then unusable and the connection should be dropped.
    public mutating func append(_ data: Data) throws(BusError) -> [Data] {
        buffer.append(data)
        var lines: [Data] = []
        while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
            var line = buffer[buffer.startIndex..<newline]
            buffer.removeSubrange(buffer.startIndex...newline)
            if line.last == UInt8(ascii: "\r") { line = line.dropLast() }
            if !line.isEmpty { lines.append(Data(line)) }
        }
        if buffer.count > Self.maxLineBytes {
            buffer = Data()
            throw BusError.malformed("line exceeds \(Self.maxLineBytes) bytes")
        }
        return lines
    }
}
