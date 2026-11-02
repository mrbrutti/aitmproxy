import Foundation
import Network

@testable import AitmBusClient

/// One `tools/call` as the server received it: the tool name and the
/// `arguments` object exactly as it came off the wire.
struct RecordedCall: Hashable, Sendable {
    let name: String
    let arguments: JSONValue
}

/// A stand-in for `aitm`'s loopback MCP transport: token line, `initialize`,
/// `ping`, `tools/list`, `tools/call`, plus knobs the tests need (push a
/// notification, a tool that hangs, a tool that drops the connection, a
/// scripted reply queue per tool).
actor FakeBusServer {
    let token: String
    private(set) var port: UInt16 = 0
    private(set) var receivedMethods: [String] = []
    /// Every `tools/call`, in arrival order, with its full `arguments`.
    private(set) var receivedCalls: [RecordedCall] = []
    /// Scripted `tools/call` results by tool name, consumed front to back.
    private var scripted: [String: [JSONValue]] = [:]

    private struct Peer {
        let connection: NWConnection
        var framer = LineFramer()
        var authenticated = false
    }

    private let queue = DispatchQueue(label: "fake-bus-server")
    private var listener: NWListener?
    private var peers: [UUID: Peer] = [:]
    private var readyContinuation: CheckedContinuation<Void, any Error>?

    init(token: String = "secret-token") {
        self.token = token
    }

    /// Binds 127.0.0.1 on a free port and returns the endpoint to dial.
    func start() async throws -> BusEndpoint {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            Task { await self?.accept(connection) }
        }
        listener.stateUpdateHandler = { [weak self] state in
            Task { await self?.listenerStateChanged(state) }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            readyContinuation = continuation
            listener.start(queue: queue)
        }
        port = listener.port?.rawValue ?? 0
        return BusEndpoint(port: port, token: token)
    }

    func stop() {
        listener?.cancel()
        listener = nil
        dropAllConnections()
    }

    /// Closes every accepted connection (the server "going away" mid-call).
    func dropAllConnections() {
        for peer in peers.values { peer.connection.cancel() }
        peers.removeAll()
    }

    /// Queues tool results for `tool`: each `tools/call` of that name takes the
    /// next one (the whole result object: `content`, `structuredContent`,
    /// `isError`). Once the queue is empty the built-in tools answer again.
    func script(_ tool: String, _ results: [JSONValue]) {
        scripted[tool, default: []].append(contentsOf: results)
    }

    /// Writes one notification line to every authenticated peer.
    func pushNotification(_ method: String, params: JSONValue) {
        let line = JSONRPCNotification(method: method, params: params).encodedLine()
        for peer in peers.values where peer.authenticated {
            peer.connection.send(content: line, completion: .contentProcessed { _ in })
        }
    }

    // MARK: Connections

    private func listenerStateChanged(_ state: NWListener.State) {
        switch state {
        case .ready:
            readyContinuation?.resume()
            readyContinuation = nil
        case .failed(let error), .waiting(let error):
            readyContinuation?.resume(throwing: error)
            readyContinuation = nil
        default:
            break
        }
    }

    private func accept(_ connection: NWConnection) {
        let id = UUID()
        peers[id] = Peer(connection: connection)
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed = state { Task { await self?.forget(id) } }
            if case .cancelled = state { Task { await self?.forget(id) } }
        }
        connection.start(queue: queue)
        Task { await readLoop(id) }
    }

    private func forget(_ id: UUID) {
        peers[id] = nil
    }

    private func readLoop(_ id: UUID) async {
        while let connection = peers[id]?.connection {
            let chunk: (Data?, Bool, NWError?) = await withCheckedContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, isComplete, error in
                    continuation.resume(returning: (data, isComplete, error))
                }
            }
            guard peers[id] != nil else { return }
            if let data = chunk.0, !data.isEmpty {
                guard let lines = try? peers[id]?.framer.append(data) else {
                    connection.cancel()
                    return
                }
                for line in lines { handle(line, from: id) }
            }
            if chunk.1 || chunk.2 != nil {
                connection.cancel()
                forget(id)
                return
            }
        }
    }

    private func write(_ value: JSONValue, to connection: NWConnection, thenClose: Bool = false) {
        let line = Data((value.serialized() + "\n").utf8)
        connection.send(
            content: line,
            completion: .contentProcessed { _ in
                if thenClose { connection.cancel() }
            })
    }

    // MARK: Protocol

    private func handle(_ line: Data, from id: UUID) {
        guard let peer = peers[id] else { return }
        guard let message = try? JSONValue.parse(line) else { return }
        if !peer.authenticated {
            if message["token"]?.stringValue == token {
                peers[id]?.authenticated = true
            } else {
                write(
                    ["jsonrpc": "2.0", "id": nil, "error": ["code": -32001, "message": "unauthorized"]],
                    to: peer.connection, thenClose: true)
                forget(id)
            }
            return
        }
        guard let method = message["method"]?.stringValue else { return }
        receivedMethods.append(method)
        guard let requestID = message["id"], !requestID.isNull else { return }  // notification
        let params = message["params"] ?? [:]
        let outcome: Result<JSONValue, JSONRPCErrorBody>
        switch method {
        case "initialize":
            outcome = .success([
                "protocolVersion": message["params"]?["protocolVersion"] ?? "2025-06-18",
                "capabilities": ["tools": [:]],
                "serverInfo": ["name": "fake-aitmproxy", "version": "0.0.1"],
            ])
        case "ping":
            outcome = .success([:])
        case "tools/list":
            outcome = .success(["tools": .array(Self.tools)])
        case "tools/call":
            guard let result = callTool(params, peer: id) else { return }
            outcome = result
        default:
            outcome = .failure(JSONRPCErrorBody(code: -32601, message: "unknown method `\(method)`", data: nil))
        }
        switch outcome {
        case .success(let result):
            write(["jsonrpc": "2.0", "id": requestID, "result": result], to: peer.connection)
        case .failure(let error):
            write(
                [
                    "jsonrpc": "2.0", "id": requestID,
                    "error": ["code": .number(Double(error.code)), "message": .string(error.message)],
                ], to: peer.connection)
        }
    }

    /// `nil` means "send no reply" (the hang and drop tools).
    private func callTool(_ params: JSONValue, peer id: UUID) -> Result<JSONValue, JSONRPCErrorBody>? {
        let name = params["name"]?.stringValue ?? ""
        let arguments = params["arguments"] ?? [:]
        receivedCalls.append(RecordedCall(name: name, arguments: arguments))
        if var queue = scripted[name], !queue.isEmpty {
            let result = queue.removeFirst()
            scripted[name] = queue
            return .success(result)
        }
        switch name {
        case "fake.echo":
            return .success([
                "content": [["type": "text", "text": .string(arguments.serialized())]],
                "structuredContent": arguments,
                "isError": false,
            ])
        case "fake.text":
            return .success(["content": [["type": "text", "text": "{\"plain\":true}"]], "isError": false])
        case "fake.fail":
            return .success(["content": [["type": "text", "text": "boom: the tool refused"]], "isError": true])
        case "fake.hang":
            return nil
        case "fake.drop":
            peers[id]?.connection.cancel()
            forget(id)
            return nil
        default:
            return .failure(JSONRPCErrorBody(code: -32602, message: "unknown tool `\(name)`", data: nil))
        }
    }

    static let tools: [JSONValue] = [
        [
            "name": "fake.echo", "description": "Echo typed arguments back.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "id": ["type": "string", "format": "uuid", "description": "a flow id"],
                    "limit": ["type": "integer"],
                    "ratio": ["type": "number"],
                    "verbose": ["type": "boolean"],
                    "raw": ["type": "string", "contentEncoding": "base64"],
                    "tags": ["type": "array", "items": ["type": "string"]],
                    "edits": [
                        "type": "object", "properties": ["method": ["type": "string"]],
                        "additionalProperties": false,
                    ],
                    "vars": ["type": "object", "additionalProperties": ["type": "string"]],
                    "blob": [:],
                ],
                "required": ["id"],
                "additionalProperties": false,
            ],
        ],
        [
            "name": "fake.fail", "description": "Always fails.",
            "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false],
        ],
        [
            "name": "fake.hang", "description": "Never replies.",
            "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false],
        ],
        // The confirm-over-the-wire shape the real core lists (`aitm-mcp` schema.rs): the
        // schema declares the tool's own arguments with `additionalProperties: false` and
        // never `_confirm` (the core strips it before schema enforcement), and the entry
        // carries `confirmable: true`. Listed here so the `_confirm` pins run against a tool
        // whose schema a pruning client *would* prune to, and so `ToolDescriptor.confirmable`
        // is decoded from a real `tools/list` line.
        [
            "name": "l4.inject", "description": "Inject a crafted packet (operator confirm).",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "spec": ["type": "object"],
                    "dst": ["type": "string"],
                    "interface": ["type": "string"],
                    "count": ["type": "integer"],
                ],
                "required": ["spec", "dst"],
                "additionalProperties": false,
            ],
            "confirmable": true,
        ],
    ]
}

extension JSONRPCErrorBody: Error {}
