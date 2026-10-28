import AitmproxyKit
import Foundation
import Observation

/// The sidebar's entries (foundation §2.6). Snapshot mode walks every case.
enum SidebarPage: String, CaseIterable, Identifiable {
    case pinned, saved, apps, domains, scope, findings, browser, scripts, agent

    var id: String { rawValue }

    var title: String {
        switch self {
        case .pinned: "Pinned"
        case .saved: "Saved"
        case .apps: "Apps"
        case .domains: "Domains"
        case .scope: "Scope"
        case .findings: "Findings"
        case .browser: "Browser"
        case .scripts: "Scripts"
        case .agent: "Agent"
        }
    }

    var symbol: String {
        switch self {
        case .pinned: Tok.Glyph.pin
        case .saved: "tray.full"
        case .apps: "app.badge"
        case .domains: Tok.Glyph.browser
        case .scope: Tok.Glyph.scope
        case .findings: Tok.Glyph.poc
        case .browser: Tok.Glyph.browser
        case .scripts: "chevron.left.forwardslash.chevron.right"
        case .agent: Tok.Glyph.agent
        }
    }

    /// Pages that show the flow list (the rest open their own panel).
    var showsFlows: Bool {
        switch self {
        case .pinned, .saved, .apps, .domains, .scope: true
        case .findings, .browser, .scripts, .agent: false
        }
    }
}

/// Where the inspector sits (Proxyman's layouts).
enum InspectorLayout: String, CaseIterable {
    case horizontal, vertical
}

/// The agent policy (foundation §4.8, F1).
enum AgentPolicy: String, CaseIterable {
    case all, readOnly, paused

    var title: String {
        switch self {
        case .all: "Allow all tools"
        case .readOnly: "Read-only"
        case .paused: "Paused"
        }
    }
}

enum BusState: Hashable {
    case disconnected
    case connecting(String)
    case connected(String)
    case failed(String)
}

/// Everything the shell shows. One object, shared through the environment.
@Observable
final class Session {
    var rows: [FlowRow] = []
    var details: [FlowID: FlowDetail] = [:]
    var selection: Set<FlowID> = []
    /// The flow the inspector shows: the last clicked row.
    var focused: FlowID?
    var page: SidebarPage? = .apps
    var chip: ContentCategory = .all
    var layout: InspectorLayout = .horizontal
    var interceptArmed = false
    var capturing = true
    var autoSelect = false
    var listenAddress = "127.0.0.1:8080"
    var agentPolicy: AgentPolicy = .all
    var agentActionsLastMinute = 0
    var bus: BusState = .disconnected
    var scopeHosts: [String] = []
    var findingsCount = 0
    var browserTabs = 0
    var activeScripts = 0
    var pinnedHosts: [String] = []
    var savedSessions = 0
    var memoryBytes: Int64 = 0
    var upBytesPerSecond: Int64 = 0
    var downBytesPerSecond: Int64 = 0
    var version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1"
    /// Settings reopens on the last tab. Test and snapshot runs leave it alone.
    var settingsTab: SettingsTab = SettingsTab(rawValue: UserDefaults.standard.string(forKey: "settings.tab") ?? "") ?? .general {
        didSet { if !Store.isOverridden { UserDefaults.standard.set(settingsTab.rawValue, forKey: "settings.tab") } }
    }

    /// Where actions go: the bus, or the fixture session itself.
    @ObservationIgnored lazy var actions: any FlowActions = FixtureActions(session: self)
    /// The last failed action, shown in the status bar until the next one succeeds.
    var lastError: String?

    var paused: [FlowRow] { rows.filter { $0.state == .paused } }
    var focusedRow: FlowRow? { rows.first { $0.id == focused } }
    var focusedDetail: FlowDetail? { focused.flatMap { details[$0] } }

    /// Rows after the sidebar page and the chip (the filter bar stacks on top later).
    var visibleRows: [FlowRow] {
        var out = rows
        if page == .scope { out = out.filter(\.inScope) }
        if chip != .all {
            out = out.filter { row in
                let detail = details[row.id]
                return chip.matches(row: row, contentType: detail?.response?.contentType ?? detail?.request.contentType,
                                    httpVersion: detail?.connection.httpVersion)
            }
        }
        return out
    }

    /// Clients and hosts for the sidebar's Apps / Domains groups, most flows first.
    var clients: [(ClientInfo, Int)] {
        var counts: [ClientInfo: Int] = [:]
        for row in rows { if let c = row.client { counts[c, default: 0] += 1 } }
        return counts.sorted { $0.value == $1.value ? $0.key.name < $1.key.name : $0.value > $1.value }
    }

    var hosts: [(String, Int)] {
        var counts: [String: Int] = [:]
        for row in rows { counts[row.authority, default: 0] += 1 }
        return counts.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
    }

    func select(_ id: FlowID?) {
        selection = id.map { [$0] } ?? []
        focused = id
    }

    // MARK: Intents (foundation §4.5, §4.6)

    /// Runs an action; a failure lands in `lastError` instead of being lost.
    private func perform(_ what: String, _ work: @escaping () async throws -> Void) {
        Task {
            do {
                try await work()
                lastError = nil
            } catch {
                lastError = "\(what): \(BusService.describe(error))"
            }
        }
    }

    func arm(_ on: Bool) {
        perform(on ? "arm intercept" : "disarm intercept") { [self] in try await actions.setIntercept(on) }
    }

    /// The bar's target: the focused paused row, else the oldest paused.
    var interceptTarget: FlowRow? {
        if let focusedRow, focusedRow.state == .paused { return focusedRow }
        return paused.first
    }

    func resume(_ id: FlowID) {
        perform("resume") { [self] in try await actions.resume(id) }
    }

    func resumeAll() {
        let ids = paused.map(\.id)
        perform("resume all") { [self] in for id in ids { try await actions.resume(id) } }
    }

    func kill(_ id: FlowID) {
        perform("kill") { [self] in try await actions.kill(id) }
    }

    func replay(_ id: FlowID) {
        perform("replay") { [self] in
            if let newID = try await actions.replay(id) { select(newID) }
        }
    }

    /// `Apply & Resume`: mutate with the pending edits, then resume (§4.5).
    func applyAndResume(_ id: FlowID) {
        let edits = details[id].flatMap { detail in
            detail.originalRequest.map { RequestEdits.diff(from: $0, to: detail.request) }
        } ?? RequestEdits()
        perform("apply & resume") { [self] in
            if !edits.isEmpty { try await actions.mutate(id, edits: edits) }
            try await actions.resume(id)
        }
    }

    func addScope(_ host: String) {
        perform("add to scope") { [self] in try await actions.addScope(host) }
    }

    /// The mockup's state: armed intercept, two paused, the login selected.
    func loadFixtures() {
        rows = Fixtures.rows
        details = Dictionary(uniqueKeysWithValues: rows.map { ($0.id, Fixtures.detail(for: $0)) })
        interceptArmed = true
        scopeHosts = Fixtures.scope
        pinnedHosts = ["api.shop-staging.test", "auth.shop-staging.test"]
        savedSessions = 3
        findingsCount = 2
        browserTabs = 1
        activeScripts = 2
        agentActionsLastMinute = 14
        memoryBytes = 196_000_000
        upBytesPerSecond = 6_000
        downBytesPerSecond = 3_000
        bus = .connected("127.0.0.1:9090")
        select(Fixtures.rows[9].id)
    }
}
