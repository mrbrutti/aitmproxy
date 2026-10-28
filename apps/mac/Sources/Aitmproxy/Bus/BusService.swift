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
            do {
                serverInfo = try await client.connect()
                session.bus = .connected(address)
                session.listenAddress = Self.listenAddress() ?? session.listenAddress
                tools = (try? await client.listTools()) ?? []
                await refreshScope()
                backoff = .seconds(1)
                try await pollLoop(client)
            } catch {
                session.bus = .failed(Self.describe(error))
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
            if session.autoSelect, let last = rows.last, session.focused != last.id { session.select(last.id) }
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

    func setIntercept(_ enabled: Bool) async throws {
        let armed = try await live().call("flow.intercept", ["enabled": .bool(enabled)]).boolValue ?? enabled
        session.interceptArmed = armed
    }

    func resume(_ id: FlowID) async throws {
        _ = try await live().call("flow.resume", ["id": .string(id.raw)])
        summaries[id] = nil
    }

    func kill(_ id: FlowID) async throws {
        _ = try await live().call("flow.kill", ["id": .string(id.raw)])
        summaries[id] = nil
    }

    func mutate(_ id: FlowID, edits: RequestEdits) async throws {
        _ = try await live().call("flow.mutate", ["id": .string(id.raw), "edits": .object(edits.arguments)])
    }

    func replay(_ id: FlowID) async throws -> FlowID? {
        try await live().call("flow.replay", ["id": .string(id.raw)]).stringValue.map(FlowID.init)
    }

    func send(_ request: RequestEdits) async throws -> FlowID? {
        try await live().call("request.send", request.arguments).stringValue.map(FlowID.init)
    }

    func addScope(_ host: String) async throws {
        _ = try await live().call("scope.add", ["host": .string(host)])
        await refreshScope()
    }

    // MARK: Endpoint

    /// The proxy's config.yaml (`AITM_CONFIG`, as the `aitm` binary reads it,
    /// else the default path) by default; else Settings > Bus host/port/token file.
    static func resolveEndpoint() -> BusEndpoint? {
        let defaults = UserDefaults.standard
        let fromConfig = defaults.object(forKey: "bus.fromConfig") as? Bool ?? true
        if fromConfig, let endpoint = try? BusEndpoint.fromConfigFile(configURL) { return endpoint }
        let host = defaults.string(forKey: "bus.host") ?? "127.0.0.1"
        let port = UInt16(clamping: defaults.integer(forKey: "bus.port"))
        var token = ""
        let tokenFile = (defaults.string(forKey: "bus.tokenFile") ?? "") as NSString
        if tokenFile.length > 0, let text = try? String(contentsOfFile: tokenFile.expandingTildeInPath, encoding: .utf8) {
            token = text.trimmingCharacters(in: .whitespacesAndNewlines)
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
