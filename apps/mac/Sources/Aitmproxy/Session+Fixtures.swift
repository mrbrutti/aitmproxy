import AitmproxyKit
import Foundation

/// The session on fixture data (`Store.usesFixtures`: `APP_FIXTURES=1`, snapshots, the
/// self-test): the mockup's state, the inspector's extra flows, and the fixture L4 agent
/// gates. The fixture bus that answers commands against it is `Bus/FixtureBus.swift`.
extension Session {
    /// The mockup's state: armed intercept, two paused, the login selected.
    func loadFixtures() {
        details = Dictionary(uniqueKeysWithValues:
            Fixtures.rows.filter { $0.kind != .websocket }.map { ($0.id, Fixtures.detail(for: $0)) })
        wsDetails = Dictionary(uniqueKeysWithValues:
            Fixtures.rows.filter { $0.kind == .websocket }.map { ($0.id, Fixtures.wsDetail(for: $0)) })
        l4Details = Dictionary(uniqueKeysWithValues:
            Fixtures.l4Rows.compactMap { row in Fixtures.l4Detail(for: row).map { (row.id, $0) } })
        l4AgentGates = L4AgentGates(capture: true, inject: false, intercept: false, widen: false)
        // AC18 CUA affordance: APP_L4_EMBEDDED=1 launches the fixture session as the
        // self-contained app's embedded user-level core, which cannot do raw L4. This
        // flips the already-built honest-degradation surface (banner + disabled wire
        // verbs) so the macOS CUA harness can drive it with real clicks. Test-only:
        // the real connection model sets `l4EmbeddedCore` from the core it drives.
        if ProcessInfo.processInfo.environment["APP_L4_EMBEDDED"] == "1" { l4EmbeddedCore = true }
        rows = Fixtures.rows + Fixtures.l4Rows
        interceptArmed = true
        scopeHosts = Fixtures.scope
        pins = Pins(hosts: ["api.shop-staging.test", "auth.shop-staging.test"])
        // No saved sessions exist until the core can save a capture (S-066); say so.
        savedSessions = 0
        findingsCount = 2
        browserTabs = 1
        // The same predicate the Scripts page uses (enabled and no error), so the sidebar count never disagrees with it.
        activeScripts = Fixtures.scripts.filter(\.isActive).count
        agentActionsLastMinute = 14
        memoryBytes = 196_000_000
        upBytesPerSecond = 6_000
        downBytesPerSecond = 3_000
        bus = .connected("127.0.0.1:9090")
        resolvedRole = "operator"
        select(Fixtures.rows[9].id)
        poc.load()
        findingsCount = poc.findings.count
        scan.loadFixture()
    }

    /// Flip one fixture L4 agent gate (the operator act `l4.agent.set` performs).
    func setL4Gate(_ capability: String, _ allowed: Bool) {
        guard var gates = l4AgentGates, let cap = L4AgentGates.Capability(rawValue: capability) else { return }
        switch cap {
        case .capture: gates.capture = allowed
        case .inject: gates.inject = allowed
        case .intercept: gates.intercept = allowed
        case .widen: gates.widen = allowed
        }
        l4AgentGates = gates
    }

    /// Flows beyond the mockup's fourteen, for the inspector's viewer scenes
    /// (image, protobuf, MessagePack, SSE, cookies, timing, truncated). Each
    /// fixture extension picked its own ids, so they are re-keyed here.
    func loadFixtureExtras() {
        guard !rows.contains(where: { $0.id.raw.hasPrefix("extra-") }) else { return }
        add(Fixtures.sseRow, Fixtures.sseDetail)
        add(Fixtures.cookieRow, Fixtures.cookieDetail)
        add(nil, Fixtures.imageDetail)
        add(nil, Fixtures.protobufDetail)
        add(nil, Fixtures.msgpackDetail)
        add(nil, Fixtures.timedDetail)
        add(nil, Fixtures.truncatedDetail)
        // A plain binary body, for the hex viewer.
        var octets = Fixtures.imageDetail
        octets.response = HTTPMessage(startLine: "HTTP/2 200 OK",
                                      headers: [.init("content-type", "application/octet-stream"), .init("content-length", "512")],
                                      body: Data((0..<512).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) }))
        add(nil, octets)
    }

    /// The extra row for a scene, by what its detail carries.
    func extraRow(matching predicate: (FlowDetail) -> Bool) -> FlowRow? {
        rows.first { $0.id.raw.hasPrefix("extra-") && details[$0.id].map(predicate) == true }
    }

    private func add(_ row: FlowRow?, _ detail: FlowDetail) {
        let seq = (rows.map(\.seq).max() ?? 0) + 1
        var newRow = (row ?? Session.derivedRow(from: detail)).withID("extra-\(seq)", seq: seq)
        newRow.inScope = scopeHosts.isEmpty || Scope.contains(newRow.authority, in: scopeHosts)
        var newDetail = detail
        newDetail.id = newRow.id
        details[newRow.id] = newDetail
        rows.append(newRow)
    }

    /// A row from a detail alone: method and path from the start line, host from the header,
    /// status from the response line, sizes from the bodies, timing's total as the duration.
    static func derivedRow(from detail: FlowDetail) -> FlowRow {
        let parts = detail.request.startLine.split(separator: " ").map(String.init)
        let method = HTTPMethod(parts.first ?? "GET")
        let (path, query) = FlowSummary.splitQuery(parts.count > 1 ? parts[1] : "/")
        let authority = detail.request.header("host") ?? detail.connection.sni ?? "api.shop-staging.test"
        let status = detail.response?.startLine.split(separator: " ").dropFirst().first.flatMap { Int($0) }
        return FlowRow(
            id: detail.id, seq: 0, method: method, scheme: "https", authority: authority, path: path, query: query,
            status: status, state: status == nil ? .pending : .complete, client: Fixtures.obscura,
            startedAt: Fixtures.rows.last?.startedAt?.addingTimeInterval(60), duration: detail.timing.map(\.total) ?? .milliseconds(88),
            requestBytes: detail.request.bodyBytes, responseBytes: detail.response?.bodyBytes)
    }
}
