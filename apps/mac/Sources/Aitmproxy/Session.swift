import AitmBusClient
import AitmproxyKit
import AppKit
import Foundation
import Observation

/// The sidebar's entries (foundation §2.6). Snapshot mode walks every case.
enum SidebarPage: String, CaseIterable, Identifiable {
    case pinned, saved, apps, domains, overview, connections, scope, findings, browser, scripts, agent, ca, config

    var id: String { rawValue }

    var title: String {
        switch self {
        case .pinned: "Pinned"
        case .saved: "Saved"
        case .apps: "Apps"
        case .domains: "Domains"
        case .overview: "Overview"
        case .connections: "Connection Log"
        case .scope: "Scope"
        case .findings: "Findings"
        case .browser: "Browser"
        case .scripts: "Scripts"
        case .agent: "Agent"
        case .ca: "Certificate Authority"
        case .config: "Configuration"
        }
    }

    var symbol: String {
        switch self {
        case .pinned: Tok.Glyph.pin
        case .saved: "tray.full"
        case .apps: "app.badge"
        case .domains: Tok.Glyph.browser
        case .overview: "chart.bar"
        case .connections: "point.3.connected.trianglepath.dotted"
        case .scope: Tok.Glyph.scope
        case .findings: Tok.Glyph.poc
        case .browser: Tok.Glyph.browser
        case .scripts: "chevron.left.forwardslash.chevron.right"
        case .agent: Tok.Glyph.agent
        case .ca: Tok.Glyph.lock
        case .config: "doc.text"
        }
    }

    /// Pages that show the flow list (the rest open their own panel).
    var showsFlows: Bool {
        switch self {
        case .pinned, .saved, .apps, .domains, .scope, .connections: true
        case .overview, .findings, .browser, .scripts, .agent, .ca, .config: false
        }
    }

    /// CA and Configuration open from the Proxy menu and the palette, not the sidebar list.
    var isInSidebar: Bool { self != .ca && self != .config }
}

/// Where the inspector sits (Proxyman's layouts): below, right, or in its own window.
enum InspectorLayout: String, CaseIterable {
    case horizontal, vertical, detached

    var title: String {
        switch self {
        case .horizontal: "Inspector Below"
        case .vertical: "Inspector Right"
        case .detached: "Inspector Detached"
        }
    }

    var symbol: String {
        switch self {
        case .horizontal: "rectangle.split.1x2"
        case .vertical: Tok.Glyph.split
        case .detached: "macwindow.on.rectangle"
        }
    }
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
/// This file holds the state; the actions sit in one extension file per
/// concern: `Session+Verbs` (row and proxy intents), `Session+Editing`
/// (compose, paused-request drafts), `Session+Filters`, `Session+Palette`.
@Observable
final class Session {
    var rows: [FlowRow] = [] {
        didSet {
            rowsVersion &+= 1
            // Auto-select follows the newest flow, but never steals a paused row being edited (S-015).
            guard autoSelect, rows.count > oldValue.count, let last = rows.last else { return }
            if focusedRow?.state == .paused { return }
            select(last.id)
        }
    }
    /// The sidebar sub-item narrowing the list, if any.
    var group: FlowGroup?
    var details: [FlowID: FlowDetail] = [:] {
        didSet { rowsVersion &+= 1 }
    }
    var selection: Set<FlowID> = []
    /// The flow the inspector shows: the last clicked row.
    var focused: FlowID?
    var page: SidebarPage? = .apps
    var chip: ContentCategory = .all
    var layout: InspectorLayout = Store.isOverridden ? .horizontal
        : InspectorLayout(rawValue: UserDefaults.standard.string(forKey: "layout") ?? "") ?? .horizontal {
        didSet {
            if oldValue != .detached { attachedLayout = oldValue }
            if !Store.isOverridden { UserDefaults.standard.set(layout.rawValue, forKey: "layout") }
            if layout == .detached { detachRequestTick += 1 }
        }
    }
    /// The layout to return to when the detached window closes.
    var attachedLayout: InspectorLayout = .horizontal
    /// Bumped when the inspector should open in its own window (the shell owns `openWindow`).
    var detachRequestTick = 0
    var requestTab: RequestTab = .raw
    var responseTab: ResponseTab = .body
    var sort: FlowSort = .captureOrder
    var density: Density = Density(rawValue: UserDefaults.standard.string(forKey: "density") ?? "") ?? .dense {
        didSet { if !Store.isOverridden { UserDefaults.standard.set(density.rawValue, forKey: "density") } }
    }
    var interceptArmed = false
    var capturing = true
    var autoSelect = Store.isOverridden ? false : UserDefaults.standard.bool(forKey: "autoSelect") {
        didSet { if !Store.isOverridden { UserDefaults.standard.set(autoSelect, forKey: "autoSelect") } }
    }
    /// Column order/widths/hidden set (S-008).
    var columnsURL: URL { Store.url.appending(path: "columns.json") }

    // MARK: Filters (S-031–S-034)

    var filterBarVisible = false
    var filterStack = FilterStack() {
        didSet { if !filterAdvanced { recompileFilter(from: filterStack.expression) } }
    }
    /// The Advanced text; authoritative while `filterAdvanced`.
    var filterText = "" {
        didSet { if filterAdvanced { parseFilterText() } }
    }
    var filterAdvanced = false
    var filterError: FilterParseError?
    @ObservationIgnored var compiledFilter: CompiledFilter?
    /// The active filter expression (observed, so the list re-queries on change).
    var filterExpression: FilterExpression = .matchAll
    var savedFilters: [SavedFilter] = []
    @ObservationIgnored lazy var savedFilterStore = SavedFilterStore(stateDirectory: Store.url)
    /// The sidebar's quick filter (⌘⇧F).
    var sidebarQuery = ""
    /// Bumped to move focus into the sidebar filter field.
    var sidebarFilterFocusTick = 0
    /// Bumped by ⌥⌘F to open Find in the focused pane's body viewer.
    var findRequestTick = 0

    // MARK: Menu bar coverage (S-069)

    /// View ▸ Toggle Sidebar (⌃⌘S) and the toolbar button share this.
    var sidebarVisible = true
    /// Bumped when the list should show Quick Look for the body `BodyQuickLook` holds.
    var quickLookTick = 0
    /// Typed into the Scope sheet's field when Flow ▸ Add Host to Scope… opens it.
    var scopeSheetHost: String?
    /// A file is being dragged over the window (S-065): the "Drop to import" face shows.
    var dropTargeted = false

    // MARK: Palette (S-035, S-036)

    var paletteVisible = false
    /// Opened with the mouse → animates; with ⌘K → does not (foundation §2.8).
    var paletteOpenedByKeyboard = true
    var tools: [ToolDescriptor] = Store.usesFixtures ? Fixtures.tools : []
    var recentPaletteIDs: [String] = UserDefaults.standard.stringArray(forKey: "palette.recent") ?? []
    /// A generic bus call for the palette; nil until a bus is attached.
    @ObservationIgnored var commandRunner: ((String, [String: JSONValue]) async throws -> JSONValue)?
    /// Every command this app runs, for the activity log (S-057): name, args, result text or nil on success.
    @ObservationIgnored var commandRecorder: ((String, [String: JSONValue], String?) -> Void)?
    /// Unsolicited bus notifications (`notifications/aitm/*`, F2/F4), fed by BusService.
    @ObservationIgnored var notificationSink: ((String, JSONValue) -> Void)?

    var listenAddress = "127.0.0.1:8080"
    var agentPolicy: AgentPolicy = .all
    var agentActionsLastMinute = 0
    var bus: BusState = .disconnected
    /// The single active core connection's id this launch (Task 5). Every flow
    /// ingested over the bus is stamped with it; fixture/offline data uses the
    /// well-known `.fixture` id. The seam for multi-core: a second connection is
    /// additive because every stored flow already carries its originating id.
    let activeCoreID: CoreID = Store.usesFixtures ? .fixture : CoreID()
    var scopeHosts: [String] = []
    var findingsCount = 0
    var browserTabs = 0
    var activeScripts = 0
    var pins = Pins() {
        didSet { if pins != oldValue { try? pins.save(to: pinsURL) } }
    }
    var pinsURL: URL { Store.url.appending(path: "pins.json") }
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

    init() {
        if !Store.usesFixtures { pins = Pins.load(from: pinsURL) }
        composeHistory = ComposeHistory.load(from: composeURL)
        if !Store.usesFixtures { breakpointRules = BreakpointRules.load(from: rulesURL) }
        loadSavedFilters()
        if Store.usesFixtures {
            // Fixture commands: the ones the shell already models act; the rest echo.
            commandRunner = { [weak self] name, args in
                guard let self else { throw BusError.disconnected }
                switch name {
                case "flow.intercept": interceptArmed = args["enabled"]?.boolValue ?? true; return .bool(interceptArmed)
                case "flow.resume": if let id = args["id"]?.stringValue { resume(FlowID(id)) }; return .null
                case "flow.kill": if let id = args["id"]?.stringValue { kill(FlowID(id)) }; return .null
                case "flow.replay": if let id = args["id"]?.stringValue { replay(FlowID(id)) }; return .string("replayed")
                case "flow.list": return .array(rows.map { .string($0.id.raw) })
                case "scope.list": return .array(scopeHosts.map { .string($0) })
                case "scope.add": if let h = args["host"]?.stringValue { addScope(h) }; return .string(args["host"]?.stringValue ?? "")
                default: return .string("ok (fixture)")
                }
            }
        }
    }

    var paused: [FlowRow] { rows.filter { $0.state == .paused } }
    var focusedRow: FlowRow? { rows.first { $0.id == focused } }
    var focusedDetail: FlowDetail? { focused.flatMap { details[$0] } }

    /// The list's query: scope page, group, chip, filter expression, sort (one Kit value, S-062 ready).
    var query: FlowQuery {
        FlowQuery(inScopeOnly: page == .scope, group: group, chip: chip, filter: filterExpression, sort: sort)
    }

    /// Rows after the query. Compiled once per query change, not per access.
    var visibleRows: [FlowRow] {
        let q = query
        if cachedQuery != q || cachedRows == nil || cachedRowsVersion != rowsVersion {
            cachedQuery = q
            cachedCompiled = q.compiled()
            cachedRows = cachedCompiled?.apply(rows, details: details)
            cachedRowsVersion = rowsVersion
        }
        return cachedRows ?? rows
    }

    // MARK: Panels (M5): each panel owns its state; the session holds one of each.

    @ObservationIgnored lazy var poc = PocPanelState(session: self)
    @ObservationIgnored lazy var browser = BrowserState(session: self)
    @ObservationIgnored lazy var activity = ActivityState(session: self)
    var activityLogVisible = false
    /// The embedded core's health and captured logs (Task 8): the status-bar
    /// health dot and the on-demand core-log panel read this. The
    /// `EmbeddedCoreController` fills it; `nil` connection means no embedded core.
    @ObservationIgnored lazy var coreHealth = CoreHealthState()
    /// Proxy ▸ Core Log (⌃⌘L) toggles the on-demand core-log panel.
    var coreLogVisible = false
    /// The flow a Build PoC sheet is for (S-053).
    var buildPoCFlowID: FlowID?

    /// Routes the app's own commands and the bus's notifications into the activity log (S-057).
    func attachActivityHooks() {
        commandRecorder = { [weak self] name, args, failure in
            self?.activity.record(command: name, args: args, result: failure.map { .error($0) } ?? .ok)
        }
        notificationSink = { [weak self] method, params in
            if method == "notifications/aitm/agent" { self?.activity.ingest(params) }
        }
    }

    // MARK: Split view (S-062): a second list over the same capture.

    var splitView = false {
        didSet { if !splitView { focusedPane = 0 } }
    }
    /// The second pane's chip, group and sort; the filter bar stays on the first pane.
    var secondQuery = FlowQuery()
    var secondSelection: Set<FlowID> = []
    /// Which pane the inspector follows (0 or 1).
    var focusedPane = 0

    var secondVisibleRows: [FlowRow] { secondQuery.apply(rows, details: details) }

    /// Selecting in a pane makes it the focused one and leads the inspector.
    func focus(pane: Int, on id: FlowID?) {
        focusedPane = pane
        focused = id
        ensureDetail(for: id)
    }

    @ObservationIgnored private var cachedQuery: FlowQuery?
    @ObservationIgnored private var cachedCompiled: FlowQuery.Compiled?
    @ObservationIgnored private var cachedRows: [FlowRow]?
    @ObservationIgnored private var cachedRowsVersion = 0
    /// Bumped whenever `rows` or `details` change, so the cache knows.
    @ObservationIgnored private var rowsVersion = 0

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
        ensureDetail(for: id)
    }

    /// `3 selected · 24.1 KB · 1.47 s` while more than one row is selected (S-012).
    var selectionSummary: SelectionSummary? {
        guard selection.count > 1 else { return nil }
        return SelectionSummary(rows: rows.filter { selection.contains($0.id) })
    }

    /// Choose a sidebar page; a sub-item narrows to its group, the group header clears it.
    func show(_ page: SidebarPage, group: FlowGroup? = nil) {
        self.page = page
        self.group = group
    }

    func pin(_ group: FlowGroup) {
        switch group {
        case .host(let h): pins.pinHost(h)
        case .client(let c): pins.pinApp(c)
        }
    }

    func unpin(_ group: FlowGroup) {
        switch group {
        case .host(let h): pins.unpinHost(h)
        case .client(let c): pins.unpinApp(c)
        }
        if self.group == group { self.group = nil }
    }

    func isPinned(_ group: FlowGroup) -> Bool {
        switch group {
        case .host(let h): pins.hosts.contains(h)
        case .client(let c): pins.apps.contains(c)
        }
    }

    // MARK: Intents — state (the actions live in Session+Verbs.swift)

    /// Remembered for the session (S-039).
    var killMode: KillMode = .reset
    var rulesVisible = false
    var scopeSheetVisible = false
    var breakpointRules = BreakpointRules()
    var rulesURL: URL { Store.url.appending(path: "rules.json") }

    // MARK: Compose and editing — state (the actions live in Session+Editing.swift)

    var composeVisible = false
    var composeDraft = ComposeDraft()
    var composeHistory = ComposeHistory()
    var composeURL: URL { Store.url.appending(path: "compose.json") }
    /// The operator's unsent edits per paused flow; nil = as the proxy holds it.
    var editDrafts: [FlowID: HTTPMessage] = [:]

    /// The mockup's state: armed intercept, two paused, the login selected.
    func loadFixtures() {
        details = Dictionary(uniqueKeysWithValues: Fixtures.rows.map { ($0.id, Fixtures.detail(for: $0)) })
        rows = Fixtures.rows
        interceptArmed = true
        scopeHosts = Fixtures.scope
        pins = Pins(hosts: ["api.shop-staging.test", "auth.shop-staging.test"])
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
        poc.load()
        findingsCount = poc.findings.count
    }
}
