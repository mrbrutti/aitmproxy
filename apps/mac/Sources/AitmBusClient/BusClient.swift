import Foundation
import Network

/// A client for aitmproxy's command bus: the MCP server in `crates/aitm-mcp`
/// over loopback TCP, newline-delimited JSON-RPC 2.0.
///
/// One `BusClient` owns at most one connection. `connect()` performs the
/// token line and the `initialize` handshake; `call` runs `tools/call`.
/// Reconnecting is the caller's job: watch `states()` and call `connect()`
/// again with whatever back-off suits the app. Every Network.framework
/// callback is bridged onto the actor before it touches state.
public actor BusClient {
    /// The connection's lifecycle. Terminal states (`failed`, `closed`) are
    /// left by the next `connect()`.
    public enum State: Sendable, Equatable {
        case idle
        case connecting
        case authenticating
        case ready(ServerInfo)
        case failed(BusError)
        case closed
    }

    public nonisolated let endpoint: BusEndpoint
    public nonisolated let clientName: String
    public nonisolated let clientVersion: String
    /// How long one request may wait for its reply.
    public nonisolated let timeout: Duration

    /// Server-initiated messages (anything without an `id`), in arrival
    /// order, across reconnects. A single consumer; iterate it once.
    public nonisolated let notifications: AsyncStream<JSONRPCNotification>

    public private(set) var state: State = .idle

    private let notificationSink: AsyncStream<JSONRPCNotification>.Continuation
    private let queue = DispatchQueue(label: "aitmproxy.bus-client")
    private var connection: NWConnection?
    /// Bumped whenever the connection changes so stale callbacks are ignored.
    private var generation = 0
    private var nextID = 1
    private var pending: [Int: CheckedContinuation<JSONRPCResponse, any Error>] = [:]
    private var deadlines: [Int: Task<Void, any Error>] = [:]
    private var connectContinuation: CheckedContinuation<Void, any Error>?
    private var framer = LineFramer()
    private var stateObservers: [UUID: AsyncStream<State>.Continuation] = [:]

    public init(
        endpoint: BusEndpoint, clientName: String = "aitm-mac", clientVersion: String,
        timeout: Duration = .seconds(30)
    ) {
        self.endpoint = endpoint
        self.clientName = clientName
        self.clientVersion = clientVersion
        self.timeout = timeout
        (notifications, notificationSink) = AsyncStream.makeStream(of: JSONRPCNotification.self)
    }

    // MARK: Lifecycle

    /// Every state change from now on, starting with the current state. Each
    /// call returns an independent stream, so any number of observers may watch.
    public func states() -> AsyncStream<State> {
        let (stream, continuation) = AsyncStream.makeStream(of: State.self)
        let id = UUID()
        stateObservers[id] = continuation
        continuation.yield(state)
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeStateObserver(id) }
        }
        return stream
    }

    private func removeStateObserver(_ id: UUID) {
        stateObservers[id] = nil
    }

    private func setState(_ new: State) {
        state = new
        for observer in stateObservers.values { observer.yield(new) }
    }

    /// Opens the TCP connection, writes the token line, runs `initialize`, and
    /// sends `notifications/initialized`. Returns the server's identity.
    /// Throws `.unauthorized`, `.transport`, `.timeout` or `.malformed`.
    public func connect() async throws -> ServerInfo {
        switch state {
        case .ready(let info): return info
        case .connecting, .authenticating: throw BusError.transport("a connect is already in progress")
        case .idle, .failed, .closed: break
        }
        generation += 1
        let gen = generation
        do {
            return try await open(generation: gen)
        } catch {
            let failure = error as? BusError ?? .transport(String(describing: error))
            if gen == generation { tearDown(.failed(failure), failing: failure) }
            throw failure
        }
    }

    /// Closes the connection. Pending calls fail with `.disconnected`.
    public func disconnect() {
        guard connection != nil else {
            if state != .idle { setState(.closed) }
            return
        }
        tearDown(.closed, failing: .disconnected)
    }

    private func open(generation gen: Int) async throws -> ServerInfo {
        guard let port = NWEndpoint.Port(rawValue: endpoint.port) else {
            throw BusError.transport("invalid port \(endpoint.port)")
        }
        let conn = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: .tcp)
        connection = conn
        framer = LineFramer()
        setState(.connecting)
        conn.stateUpdateHandler = { [weak self] connectionState in
            Task { await self?.connectionStateChanged(connectionState, generation: gen) }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connectContinuation = continuation
            conn.start(queue: queue)
        }
        guard gen == generation else { throw BusError.disconnected }
        setState(.authenticating)
        Task { await readLoop(conn, generation: gen) }
        send(Data((JSONValue.object(["token": .string(endpoint.token)]).serialized() + "\n").utf8), over: conn, generation: gen)
        let result = try await request(
            "initialize",
            params: [
                "protocolVersion": "2025-06-18",
                "capabilities": [:],
                "clientInfo": ["name": .string(clientName), "version": .string(clientVersion)],
            ])
        let info = try ServerInfo(initializeResult: result)
        guard gen == generation else { throw BusError.disconnected }
        send(JSONRPCNotification(method: "notifications/initialized").encodedLine(), over: conn, generation: gen)
        setState(.ready(info))
        return info
    }

    /// Cancels the connection and fails everything waiting on it.
    private func tearDown(_ terminal: State, failing failure: BusError) {
        generation += 1
        connection?.cancel()
        connection = nil
        framer = LineFramer()
        for deadline in deadlines.values { deadline.cancel() }
        deadlines.removeAll()
        let waiting = pending.values
        pending.removeAll()
        for continuation in waiting { continuation.resume(throwing: failure) }
        connectContinuation?.resume(throwing: failure)
        connectContinuation = nil
        setState(terminal)
    }

    private func connectionStateChanged(_ connectionState: NWConnection.State, generation gen: Int) {
        guard gen == generation else { return }
        switch connectionState {
        case .ready:
            connectContinuation?.resume()
            connectContinuation = nil
        case .waiting(let error), .failed(let error):
            // `.waiting` is how a refused loopback connect shows up; the
            // framework would retry forever, so treat it as a failure and let
            // the app back off.
            let failure: BusError = connectContinuation == nil ? .disconnected : .transport(error.localizedDescription)
            tearDown(.failed(failure), failing: failure)
        case .cancelled:
            if connection != nil { tearDown(.closed, failing: .disconnected) }
        case .setup, .preparing:
            break
        @unknown default:
            break
        }
    }

    // MARK: I/O

    private func send(_ data: Data, over conn: NWConnection, generation gen: Int) {
        conn.send(
            content: data,
            completion: .contentProcessed { [weak self] error in
                guard let error else { return }
                Task { await self?.sendFailed(error, generation: gen) }
            })
    }

    private func sendFailed(_ error: NWError, generation gen: Int) {
        guard gen == generation else { return }
        let failure: BusError = state == .authenticating || state == .connecting
            ? .transport(error.localizedDescription) : .disconnected
        tearDown(.failed(failure), failing: failure)
    }

    /// Reads until the connection ends. Runs on the actor; each chunk is
    /// processed before the next receive is issued, so lines stay ordered.
    private func readLoop(_ conn: NWConnection, generation gen: Int) async {
        while gen == generation {
            let chunk = await Self.receive(from: conn)
            guard gen == generation else { return }
            if let data = chunk.data, !data.isEmpty {
                let lines: [Data]
                do {
                    lines = try framer.append(data)
                } catch {
                    tearDown(.failed(error), failing: error)
                    return
                }
                for line in lines {
                    handleLine(line)
                    guard gen == generation else { return }
                }
            }
            if chunk.error != nil || chunk.isComplete {
                let failure: BusError = connectContinuation == nil && state != .authenticating
                    ? .disconnected : .transport(chunk.error?.localizedDescription ?? "connection closed")
                tearDown(.failed(failure), failing: failure)
                return
            }
        }
    }

    private nonisolated static func receive(from conn: NWConnection) async -> (data: Data?, isComplete: Bool, error: NWError?) {
        await withCheckedContinuation { continuation in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, isComplete, error in
                continuation.resume(returning: (data, isComplete, error))
            }
        }
    }

    private func handleLine(_ line: Data) {
        let message: JSONRPCMessage
        do {
            message = try JSONRPCMessage.parse(line)
        } catch {
            tearDown(.failed(error), failing: error)
            return
        }
        switch message {
        case .notification(let notification):
            notificationSink.yield(notification)
        case .response(let response):
            if let id = response.id.intValue, let continuation = pending.removeValue(forKey: id) {
                deadlines.removeValue(forKey: id)?.cancel()
                continuation.resume(returning: response)
            } else if response.id.isNull, let error = response.error {
                // The server's only null-id replies: the token refusal (then it
                // closes) or a parse error for a line we sent.
                let failure: BusError = error.code == -32001 ? .unauthorized : .rpc(code: error.code, message: error.message)
                tearDown(.failed(failure), failing: failure)
            }
            // A reply for an id nobody waits on (timed out) is dropped.
        }
    }

    // MARK: Requests

    private func request(_ method: String, params: JSONValue) async throws -> JSONValue {
        guard let conn = connection else { throw BusError.disconnected }
        let gen = generation
        let id = nextID
        nextID += 1
        let line = JSONRPCRequest(id: id, method: method, params: params).encodedLine()
        let response: JSONRPCResponse = try await withCheckedThrowingContinuation { continuation in
            pending[id] = continuation
            deadlines[id] = Task { [timeout] in
                try await Task.sleep(for: timeout)
                expire(id)
            }
            send(line, over: conn, generation: gen)
        }
        if let error = response.error { throw BusError.rpc(code: error.code, message: error.message) }
        return response.result ?? .null
    }

    private func expire(_ id: Int) {
        deadlines[id] = nil
        pending.removeValue(forKey: id)?.resume(throwing: BusError.timeout)
    }

    /// `ping` → `{}`.
    public func ping() async throws {
        _ = try await request("ping", params: [:])
    }

    /// `tools/list`, with each tool's parameters classified from its schema.
    public func listTools() async throws -> [ToolDescriptor] {
        let result = try await request("tools/list", params: [:])
        guard let tools = result["tools"]?.arrayValue else {
            throw BusError.malformed("tools/list result has no `tools` array")
        }
        return try tools.map { (tool) throws(BusError) in try ToolDescriptor(json: tool) }
    }

    /// `tools/call`. Returns `structuredContent` when present, else the text
    /// content parsed as JSON (or as a string). Throws `.tool` when the
    /// command reported `isError`, `.rpc` for an unknown tool or bad arguments.
    public func call(_ tool: String, _ arguments: [String: JSONValue] = [:]) async throws -> JSONValue {
        let result = try await request("tools/call", params: ["name": .string(tool), "arguments": .object(arguments)])
        let text = (result["content"]?.arrayValue ?? [])
            .compactMap { $0["type"]?.stringValue == "text" ? $0["text"]?.stringValue : nil }
            .joined(separator: "\n")
        if result["isError"]?.boolValue == true { throw BusError.tool(message: text) }
        if let structured = result["structuredContent"] { return structured }
        if let parsed = try? JSONValue.parse(text) { return parsed }
        return .string(text)
    }
}
