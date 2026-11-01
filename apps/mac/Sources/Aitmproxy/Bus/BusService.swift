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
    /// The status bar's ↑ / ↓ rate, from the change in the summaries' byte totals
    /// between polls. Reset with each connection so a new core starts from zero.
    @ObservationIgnored private var throughput = ThroughputMeter()
    /// Which cached flows each poll asks about again (parked, headless, stale, or a
    /// body still streaming — for a bounded number of polls). Reset per connection.
    @ObservationIgnored private var refetch = FlowRefetchPolicy()
    /// The embedded core's bus (Task 6), once it has published its address. When
    /// set it supersedes the config.yaml / Settings endpoint resolution.
    @ObservationIgnored private var endpointOverride: BusEndpoint?
    /// While the embedded core is the active connection (Task 7), the bus connects
    /// only to the embedded endpoint and never falls back to a `config.yaml` /
    /// Settings core — so waiting for the embedded core to come up does not latch
    /// onto some other core the operator happens to be running.
    @ObservationIgnored private var preferEmbedded = false

    init(session: Session) { self.session = session }

    /// Wait for the embedded core before connecting (Task 7): connect only once it
    /// publishes its endpoint, never to an external core in the meantime. Used when
    /// embedded is the active choice but the core has not finished starting.
    func awaitEmbeddedEndpoint() {
        preferEmbedded = true
        endpointOverride = nil
        start()
    }

    /// Point the client at the embedded core's bus and reconnect at once, rather
    /// than wait for the next back-off cycle.
    func useEmbeddedEndpoint(_ endpoint: BusEndpoint) {
        preferEmbedded = true
        endpointOverride = endpoint
        start()
    }

    /// Point the client at the operator's external core (Task 7): drop any
    /// embedded override and resolve the endpoint from `config.yaml` / Settings.
    func useExternalEndpoint() {
        preferEmbedded = false
        endpointOverride = nil
        start()
    }

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
            let resolved = preferEmbedded ? endpointOverride : (endpointOverride ?? Self.resolveEndpoint())
            guard let endpoint = resolved else {
                session.bus = preferEmbedded ? .connecting("embedded core") : .failed("no bus configured")
                try? await Task.sleep(for: .seconds(preferEmbedded ? 1 : 5))
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
        throughput.reset()
        refetch.reset()
        // However this connection ends — stop(), or a core that went away — no
        // connection means no traffic: a stale rate must not sit under a failed badge.
        defer {
            session.upBytesPerSecond = 0
            session.downBytesPerSecond = 0
        }
        while !Task.isCancelled {
            // Scope first: `inScope` below and the capture advice (Settings ▸ Capture, the Apps
            // banner) read `scopeHosts`, and a host added from the CLI or another client must
            // not leave them claiming an empty scope.
            await refreshScope()
            // The proxy's recording state is the core's fact, not this client's memory: a pause
            // from any other client (agent, TUI, web) reaches the toolbar's Proxy switch within
            // one poll, and a relaunch against an already-paused core starts out saying so.
            await refreshProxyStatus()
            let ids = try await client.call("flow.list").arrayValue?.compactMap { $0.stringValue }.map(FlowID.init) ?? []
            for id in ids {
                let cached = summaries[id]
                guard refetch.shouldFetch(id, cached: cached) else { continue }
                if let json = try? await client.call("flow.get", ["id": .string(id.raw)]), let summary = FlowSummary(json: json) {
                    // ↑ is what clients sent (request bodies), ↓ what came back (response
                    // bodies): each flow's growth since its last summary joins the totals.
                    throughput.record(previous: cached, current: summary)
                    summaries[id] = summary
                    refetch.didFetch(id, summary: summary)
                }
            }
            let known = Set(ids)
            summaries = summaries.filter { known.contains($0.key) }
            refetch.retain(known)
            let coreID = session.activeCoreID
            func scoped(_ row: FlowRow) -> FlowRow {
                var row = row
                row.inScope = session.scopeHosts.isEmpty || Scope.contains(row.authority, in: session.scopeHosts)
                return row
            }
            let polled = ids.enumerated().compactMap { index, id in summaries[id]?.row(seq: index + 1, coreID: coreID) }.map(scoped)
            // Rows an undone Clear put back stay ahead of the core's list and follow the live
            // scope like any other row; new flows number after them.
            let restored = session.restoredFlows.map(scoped)
            if restored != session.restoredFlows { session.restoredFlows = restored }
            let rows = ClearedFlows.merge(restored: restored, newer: polled)
            if rows != session.rows { session.rows = rows }
            let rate = throughput.sample(at: .now)
            if session.upBytesPerSecond != rate.up { session.upBytesPerSecond = rate.up }
            if session.downBytesPerSecond != rate.down { session.downBytesPerSecond = rate.down }
            try await Task.sleep(for: pollInterval)
        }
    }

    /// Re-reads the core's `scope.list` into `session.scopeHosts`. True iff the call
    /// succeeded and the list was assigned, so a caller never persists a stale list
    /// after a verb whose follow-up refresh failed (SP-AC19).
    @discardableResult
    private func refreshScope() async -> Bool {
        guard let client else { return false }
        guard let entries = try? await client.call("scope.list").arrayValue?.compactMap(\.stringValue) else { return false }
        session.scopeHosts = entries
        return true
    }

    /// The only writer of `scope.json` (D4). Snapshot semantics: the file is the embedded
    /// core's `scope.list` as of the operator's last Scope action — written from
    /// `addScope`/`removeScope` only after the verb and the refresh both succeeded; never
    /// on connect or poll, never while the client points at an external core (the callers
    /// also require that intent to have held across the whole round trip). A failed save
    /// is an error of the action: it throws `BusError.tool("Scope change not saved: …")`,
    /// which `Session.perform` lands in `lastError`, because a silently failed save after
    /// a remove would resurrect the host at the next launch. By then the core has accepted
    /// the change and the refresh has set `session.scopeHosts`, so the in-memory scope
    /// stays right for this run.
    private func persistEmbeddedScope() throws {
        guard preferEmbedded else { return }
        do {
            try EmbeddedScope(hosts: session.scopeHosts).save(to: session.scopeURL)
        } catch {
            throw BusError.tool(message: "Scope change not saved: \(error.localizedDescription)")
        }
    }

    /// `proxy.status` → `Session.capturing` and `Session.interceptArmed`: both are the core's
    /// facts (another client can pause or arm), so the Proxy switch and the pill's "intercept
    /// armed" follow the core, not this client's memory. A core without the verb leaves both alone.
    private func refreshProxyStatus() async {
        guard let client, let status = try? await client.call("proxy.status") else { return }
        if let capturing = status["capturing"]?.boolValue, capturing != session.capturing {
            session.capturing = capturing
        }
        if let armed = status["intercept_armed"]?.boolValue, armed != session.interceptArmed {
            session.interceptArmed = armed
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
            args["rules"] = .array(rules.map { .object($0.arguments) })
        }
        let armed = try await call("flow.intercept", args).boolValue ?? enabled
        session.interceptArmed = armed
    }

    // Resume / Kill change the flow on the core: the next poll refreshes its summary.
    // The cached one is kept (not dropped) so the row does not blink out and the
    // throughput meter still has the flow's baseline — a re-fetch counts growth, not
    // the whole body again.

    func resume(_ id: FlowID) async throws {
        _ = try await call("flow.resume", ["id": .string(id.raw)])
        refetch.markStale(id)
    }

    func kill(_ id: FlowID, mode: KillMode) async throws {
        // `mode` is F3; the core resets today and rejects unknown arguments, so send it only when asked for.
        var args: [String: JSONValue] = ["id": .string(id.raw)]
        if mode != .reset { args["mode"] = .string(mode.rawValue) }
        _ = try await call("flow.kill", args)
        refetch.markStale(id)
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

    func addScope(_ host: String) async throws { try await scopeVerb("scope.add", host: host) }

    func removeScope(_ host: String) async throws { try await scopeVerb("scope.remove", host: host) }

    /// Snapshot the embedded intent before the round trip (a Settings ▸ Bus switch mid-flight
    /// must not persist the other core's list), run the verb, refresh, then persist only for
    /// the embedded core. A verb the embedded core applied must either reach `scope.json` or be
    /// reported: a failed refresh, or a Bus switch to External inside the round trip, leaves the
    /// file stale, and a stale file reported as success would resurrect a removed host at the
    /// next launch, so both throw. An external core has no file, so its refresh failure stays a
    /// poll-recoverable display lag, as before.
    private func scopeVerb(_ name: String, host: String) async throws {
        let embedded = preferEmbedded
        _ = try await call(name, ["host": .string(host)])
        let refreshed = await refreshScope()
        guard embedded else { return }
        guard preferEmbedded, refreshed else {
            throw BusError.tool(message: "Scope change applied but not saved: \(preferEmbedded ? "scope.list failed" : "the active core changed")")
        }
        try persistEmbeddedScope()
    }

    func mark(_ id: FlowID, color: MarkColor?) async throws {
        let marks: JSONValue = color.map { .array([.string($0.rawValue)]) } ?? .array([])
        _ = try await call("flow.mark", ["id": .string(id.raw), "marks": marks])
    }

    func comment(_ id: FlowID, text: String) async throws {
        _ = try await call("flow.comment", ["id": .string(id.raw), "text": .string(text)])
    }

    func setCapturing(_ on: Bool) async throws {
        // The reply carries the state the core actually took; believe it over the request.
        let reply = try await call(on ? "proxy.resume" : "proxy.pause")
        session.capturing = reply["capturing"]?.boolValue ?? on
    }

    func clear() async throws {
        _ = try await call("flow.clear")
        // The cache is not wiped here: the core keeps in-flight and parked flows, and
        // the next poll prunes the cleared ids itself. Wiping would make the survivors
        // "never seen" and count their whole size as traffic a second time.
        session.rows = []
        session.details = [:]
        session.select(nil)
    }

    // MARK: Endpoint

    /// The proxy's config.yaml (`AITM_CONFIG`, as the `aitm` binary reads it,
    /// else the default path) by default; else Settings > Bus host/port/token file.
    /// Settings come from `Store.defaults`, so a self-test never sees the
    /// operator's pasted token.
    static func resolveEndpoint() -> BusEndpoint? {
        BusEndpointSettings(defaults: Store.defaults).endpoint(configURL: configURL)
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

    static func describe(_ error: Error) -> String {
        if let bus = error as? BusError { return bus.description }
        return error.localizedDescription
    }
}
