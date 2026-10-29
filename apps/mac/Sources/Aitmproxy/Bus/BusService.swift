import AitmBusClient
import AitmproxyKit
import Foundation
import Observation

/// The app's connection to a running `aitm` (foundation §4.2): resolve the
/// endpoint, connect with back-off, poll `flow.list` + `flow.get` until F4's
/// subscription lands, and run every operator action as a bus command.
@Observable
final class BusService: FlowActions {
    unowned let session: Session
    private(set) var tools: [ToolDescriptor] = []
    private(set) var serverInfo: ServerInfo?
    /// How often the list is polled while connected.
    var pollInterval: Duration = .milliseconds(500)

    @ObservationIgnored private var client: BusClient?
    @ObservationIgnored private var runTask: Task<Void, Never>?
    @ObservationIgnored private var notificationTask: Task<Void, Never>?
    @ObservationIgnored private var summaries: [FlowID: FlowSummary] = [:]

    init(session: Session) { self.session = session }

    // MARK: Lifecycle

    /// Connects (and keeps reconnecting with back-off) until `stop()`.
    func start() {
        stop()
        runTask = Task { await run() }
    }

    func stop() {
        runTask?.cancel()
        runTask = nil
        if let client { Task { await client.disconnect() } }
        client = nil
        session.bus = .disconnected
        session.applyResolvedRole(nil)
    }

    private func run() async {
        var backoff: Duration = .seconds(1)
        while !Task.isCancelled {
            guard let endpoint = Self.resolveEndpoint() else {
                session.bus = .failed("no bus configured")
                try? await Task.sleep(for: .seconds(5))
                continue
            }
            let address = "\(endpoint.host):\(endpoint.port)"
            session.bus = .connecting(address)
            let client = BusClient(endpoint: endpoint, clientName: "aitm-mac", clientVersion: session.version)
            self.client = client
            // Server push (F2 agent activity, F4 flow events) lands on the session's sink.
            notificationTask?.cancel()
            notificationTask = Task { [weak self] in
                for await note in client.notifications {
                    guard let self else { return }
                    session.notificationSink?(note.method, note.params)
                }
            }
            do {
                let info = try await client.connect()
                serverInfo = info
                session.bus = .connected(address)
                session.applyResolvedRole(info.role)
                session.listenAddress = Self.listenAddress() ?? session.listenAddress
                tools = (try? await client.listTools()) ?? []
                session.tools = tools
                session.commandRunner = { [weak self] name, args in
                    guard let self, let client = self.client else { throw BusError.disconnected }
                    return try await client.call(name, args)
                }
                await refreshScope()
                backoff = .seconds(1)
                try await pollLoop(client)
            } catch {
                session.bus = .failed(Self.describe(error))
                session.applyResolvedRole(nil)
            }
            await client.disconnect()
            self.client = nil
            if Task.isCancelled { break }
            try? await Task.sleep(for: backoff)
            backoff = min(backoff * 2, .seconds(30))
        }
    }

    /// Polls `flow.list`, fetches summaries for new and in-flight flows, and
    /// rebuilds the rows oldest-first. Finished flows are not re-fetched.
    private func pollLoop(_ client: BusClient) async throws {
        while !Task.isCancelled {
            let ids = try await client.call("flow.list").arrayValue?.compactMap { $0.stringValue }.map(FlowID.init) ?? []
            for id in ids {
                let cached = summaries[id]
                let inFlight = cached.map { $0.intercept == .intercepted || ($0.status == nil && $0.kind == .http) } ?? true
                guard cached == nil || inFlight else { continue }
                if let json = try? await client.call("flow.get", ["id": .string(id.raw)]), let summary = FlowSummary(json: json) {
                    summaries[id] = summary
                }
            }
            let known = Set(ids)
            summaries = summaries.filter { known.contains($0.key) }
            let rows = ids.enumerated().compactMap { index, id in summaries[id]?.row(seq: index + 1) }
                .map { row in
                    var row = row
                    row.inScope = session.scopeHosts.isEmpty || session.scopeHosts.contains { Self.hostMatches(row.authority, $0) }
                    return row
                }
            if rows != session.rows { session.rows = rows }
            try await Task.sleep(for: pollInterval)
        }
    }

    private func refreshScope() async {
        guard let client else { return }
        if let entries = try? await client.call("scope.list").arrayValue?.compactMap(\.stringValue) {
            session.scopeHosts = entries
        }
    }

    // MARK: FlowActions

    private func live() throws -> BusClient {
        guard let client else { throw BusError.disconnected }
        return client
    }

    /// One call, recorded for the activity log whatever the outcome.
    private func call(_ name: String, _ args: [String: JSONValue] = [:]) async throws -> JSONValue {
        do {
            let value = try await live().call(name, args)
            session.commandRecorder?(name, args, nil)
            return value
        } catch {
            session.commandRecorder?(name, args, Self.describe(error))
            throw error
        }
    }

    func setIntercept(_ enabled: Bool, rules: [BreakpointRule]) async throws {
        // `rules` is F3; the core rejects unknown arguments, so they travel only when there are any.
        var args: [String: JSONValue] = ["enabled": .bool(enabled)]
        if enabled, !rules.isEmpty {
            args["rules"] = .array(rules.map { .object($0.arguments.mapValues { .string($0) }) })
        }
        let armed = try await call("flow.intercept", args).boolValue ?? enabled
        session.interceptArmed = armed
    }

    func resume(_ id: FlowID) async throws {
        _ = try await call("flow.resume", ["id": .string(id.raw)])
        summaries[id] = nil
    }

    func kill(_ id: FlowID, mode: KillMode) async throws {
        // `mode` is F3; the core resets today and rejects unknown arguments, so send it only when asked for.
        var args: [String: JSONValue] = ["id": .string(id.raw)]
        if mode != .reset { args["mode"] = .string(mode.rawValue) }
        _ = try await call("flow.kill", args)
        summaries[id] = nil
    }

    func mutate(_ id: FlowID, edits: RequestEdits) async throws {
        _ = try await call("flow.mutate", ["id": .string(id.raw), "edits": .object(edits.arguments)])
    }

    func replay(_ id: FlowID) async throws -> FlowID? {
        try await call("flow.replay", ["id": .string(id.raw)]).stringValue.map(FlowID.init)
    }

    func send(_ request: RequestEdits) async throws -> FlowID? {
        try await call("request.send", request.arguments).stringValue.map(FlowID.init)
    }

    func addScope(_ host: String) async throws {
        _ = try await call("scope.add", ["host": .string(host)])
        await refreshScope()
    }

    func removeScope(_ host: String) async throws {
        _ = try await call("scope.remove", ["host": .string(host)])
        await refreshScope()
    }

    func mark(_ id: FlowID, color: MarkColor?) async throws {
        let marks: JSONValue = color.map { .array([.string($0.rawValue)]) } ?? .array([])
        _ = try await call("flow.mark", ["id": .string(id.raw), "marks": marks])
    }

    func comment(_ id: FlowID, text: String) async throws {
        _ = try await call("flow.comment", ["id": .string(id.raw), "text": .string(text)])
    }

    func setCapturing(_ on: Bool) async throws {
        _ = try await call(on ? "proxy.resume" : "proxy.pause")
        session.capturing = on
    }

    func clear() async throws {
        _ = try await call("flow.clear")
        summaries = [:]
        session.rows = []
        session.details = [:]
        session.select(nil)
    }

    // MARK: Endpoint

    /// The proxy's config.yaml (`AITM_CONFIG`, as the `aitm` binary reads it,
    /// else the default path) by default; else Settings > Bus host/port/token file.
    static func resolveEndpoint() -> BusEndpoint? {
        let defaults = UserDefaults.standard
        // A pasted operator token overrides the config/agent token; its class
        // makes the server resolve the connection to operator (spec Decision E).
        // Empty ⇒ not configured, so the app stays an agent by default.
        let operatorToken = (defaults.string(forKey: "bus.operatorToken") ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let fromConfig = defaults.object(forKey: "bus.fromConfig") as? Bool ?? true
        if fromConfig, var endpoint = try? BusEndpoint.fromConfigFile(configURL) {
            if !operatorToken.isEmpty { endpoint.token = operatorToken }
            return endpoint
        }
        let host = defaults.string(forKey: "bus.host") ?? "127.0.0.1"
        let port = UInt16(clamping: defaults.integer(forKey: "bus.port"))
        var token = operatorToken
        if token.isEmpty {
            let tokenFile = (defaults.string(forKey: "bus.tokenFile") ?? "") as NSString
            if tokenFile.length > 0, let text = try? String(contentsOfFile: tokenFile.expandingTildeInPath, encoding: .utf8) {
                token = text.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        guard port > 0, !token.isEmpty else { return nil }
        return BusEndpoint(host: host, port: port, token: token)
    }

    static var configURL: URL {
        if let path = ProcessInfo.processInfo.environment["AITM_CONFIG"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return BusEndpoint.defaultConfigURL
    }

    /// `listen: 127.0.0.1:8080` from the same config.yaml, for the toolbar pill.
    static func listenAddress() -> String? {
        guard let text = try? String(contentsOf: configURL, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("listen:") {
                return trimmed.dropFirst("listen:".count).trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
            }
        }
        return nil
    }

    /// `host`, `host:port`, `*.wildcard` against a row's authority.
    static func hostMatches(_ authority: String, _ entry: String) -> Bool {
        let host = authority.split(separator: ":").first.map(String.init) ?? authority
        if entry.hasPrefix("*.") { return host.hasSuffix(String(entry.dropFirst(1))) || host == String(entry.dropFirst(2)) }
        return authority == entry || host == entry
    }

    static func describe(_ error: Error) -> String {
        if let bus = error as? BusError { return bus.description }
        return error.localizedDescription
    }
}
