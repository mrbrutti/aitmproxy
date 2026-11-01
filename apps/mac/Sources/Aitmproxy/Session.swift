import AitmBusClient
import AitmproxyKit
import AppKit
import Foundation
import Observation

// `BusState` lives in AitmproxyKit (ConnectionSummary.swift) so the connection indicators share it.

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
    /// Rows an undone Clear put back. The core no longer holds them, so the live poll keeps them
    /// ahead of what it lists (`ClearedFlows.merge`); a later Clear or Delete drops them for good.
    var restoredFlows: [FlowRow] = []
    /// "Cleared n flows — Undo" in the status bar, for a few seconds after a Clear.
    var clearNotice: ClearNotice?
    /// What the last Clear dropped, until it is undone or the notice lapses (then it is released).
    @ObservationIgnored var clearedFlows: ClearedFlows?
    @ObservationIgnored var clearNoticeTask: Task<Void, Never>?
    /// The flow list's undo manager: Clear's one step lives here, and `FlowKeyTable` hands it to
    /// AppKit as the list's responder, so Edit ▸ Undo Clear (⌘Z) reaches it while the list has
    /// focus and a text field keeps its own typing undo. No event grouping: a step is registered
    /// and withdrawn whole, which the headless self-test can prove.
    @ObservationIgnored let flowUndoManager: UndoManager = {
        let manager = UndoManager()
        manager.groupsByEvent = false
        return manager
    }()
    /// The sidebar sub-item narrowing the list, if any.
    var group: FlowGroup?
    var details: [FlowID: FlowDetail] = [:] {
        didSet { rowsVersion &+= 1 }
    }
    /// WebSocket details keyed by flow id (S-045). A WebSocket flow has no
    /// `FlowDetail`; its handshake and message stream live here instead.
    var wsDetails: [FlowID: WSDetail] = [:] {
        didSet { rowsVersion &+= 1 }
    }
    /// Raw-L4 flow details keyed by flow id (M5 `l4.flow.get`). An L4 flow has no
    /// `FlowDetail`; its packet log and bind live here instead.
    var l4Details: [FlowID: L4Flow] = [:] {
        didSet { rowsVersion &+= 1 }
    }
    /// Whether this app is driving its own embedded user-level core, which cannot do
    /// raw L4 (AC18) — set by the connection model. The self-contained embedded core
    /// degrades every wire verb to `L4Unavailable`; a privileged / remote core over
    /// the bus drives L4 fully.
    var l4EmbeddedCore = false
    /// The last `L4Unavailable` reason a wire verb returned, surfaced in the banner.
    var l4LastWireError: String?
    /// The four per-capability agent gates read from `l4.agent.status` (AC11).
    var l4AgentGates: L4AgentGates?

    /// Whether the macOS L4 surface can drive the wire against the current core.
    var l4Availability: L4Availability {
        L4Availability.resolve(embeddedCore: l4EmbeddedCore, wireError: l4LastWireError)
    }
    /// The L4 commands are advertised by the current core (feature-detected).
    var l4Enabled: Bool { tools.contains { $0.name == "l4.flow.list" } }
    var l4HasSetter: Bool { tools.contains { $0.name == "l4.agent.set" } }
    var l4HasIntercept: Bool { tools.contains { $0.name == "l4.intercept.start" } }
    /// `scan.discover` is advertised by the current core (feature-detected): the Scan page is offered, else hidden.
    var scanEnabled: Bool { ScanForm.isOffered(in: tools) }
    var selection: Set<FlowID> = []
    /// The flow the inspector shows: the last clicked row.
    var focused: FlowID?
    /// The landing page (spec §3): the list page the operator last used; Status until they
    /// have navigated once (a fresh install has nothing to show yet, so show what is running
    /// and what to do first). Only list pages are remembered, so a session that ends on Status
    /// or Saved comes back on Flows. Fixture, snapshot and self-test runs start on Apps so their
    /// scenes stay deterministic.
    static func landingPage(saved: String?) -> SidebarPage {
        guard let saved, let page = SidebarPage(rawValue: saved) else { return .status }
        return page.isInSidebar ? page : .flows
    }

    var page: SidebarPage? = Store.isOverridden ? .apps : Session.landingPage(saved: UserDefaults.standard.string(forKey: "page")) {
        didSet {
            guard !Store.isOverridden, let page else { return }
            UserDefaults.standard.set((page.isInSidebar ? page : .flows).rawValue, forKey: "page")
        }
    }
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
    var density: Density = Store.isOverridden ? .dense
        : Density(rawValue: UserDefaults.standard.string(forKey: "density") ?? "") ?? .dense {
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
    /// A query the palette starts with the next time it opens (snapshot scenes); cleared on use.
    var paletteSeedQuery: String?
    var tools: [ToolDescriptor] = Store.usesFixtures ? Fixtures.tools : []
    var recentPaletteIDs: [String] = Store.isOverridden ? [] : UserDefaults.standard.stringArray(forKey: "palette.recent") ?? []
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
    /// The role the live connection resolved to (`"operator"`/`"agent"`), from
    /// the server's `initialize` echo (spec Decision C). `nil` while
    /// disconnected or when the server echoed no role. Surfaced in the status bar.
    var resolvedRole: String?
    /// Set when the operator's Expected role (Settings ▸ Bus) disagrees with the
    /// resolved role, or the server echoed no role to confirm it (spec AC8).
    var roleWarning = false
    /// Bumped by Proxy ▸ Reconnect Bus (⌃⌘R) so the shell re-resolves the
    /// endpoint and reconnects — picking up a newly pasted operator token.
    var reconnectTick = 0
    /// Bumped by Settings ▸ Proxy "Apply & Restart Core" to restart the embedded core so
    /// edited proxy settings (listen port, upstream-TLS) take effect.
    var restartCoreTick = 0
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
    /// The embedded core's persisted operator scope (`scope.json`, beside `pins.json`).
    var scopeURL: URL { EmbeddedScope.url(in: Store.url) }
    var savedSessions = 0
    var memoryBytes: Int64 = 0
    var upBytesPerSecond: Int64 = 0
    var downBytesPerSecond: Int64 = 0
    var version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1"
    /// Settings reopens on the last tab. Test and snapshot runs neither read nor write it.
    var settingsTab: SettingsTab = Store.isOverridden ? .general
        : SettingsTab(rawValue: UserDefaults.standard.string(forKey: "settings.tab") ?? "") ?? .general {
        didSet { if !Store.isOverridden { UserDefaults.standard.set(settingsTab.rawValue, forKey: "settings.tab") } }
    }

    /// The switchable, persistent active-core choice (Task 7, AC10): embedded vs
    /// external, driven from Settings ▸ Bus. Set once the live stack is built
    /// (`ShellView`); `nil` in fixture/snapshot runs, where Bus settings show the
    /// persisted default without a live core to switch.
    @ObservationIgnored var connection: ActiveConnectionModel?

    /// Where actions go: the bus, or the fixture session itself.
    @ObservationIgnored lazy var actions: any FlowActions = FixtureActions(session: self)
    /// The last failed action, shown in the status bar until the next one succeeds.
    var lastError: String?

    init() {
        if !Store.usesFixtures { pins = Pins.load(from: pinsURL) }
        // The Scope page shows the embedded core's persisted scope before the bus
        // connects; `refreshScope()` replaces it with the core's `scope.list` on connect (D5).
        if EmbeddedScope.seedsAtLaunch(activeKind: UserDefaultsActiveKindPersistence(defaults: Store.defaults).load() ?? .embedded,
                                       bundledCorePresent: EmbeddedCore.discoverBundled() != nil,
                                       usesFixtures: Store.usesFixtures) {
            scopeHosts = EmbeddedScope.load(from: scopeURL).hosts
        }
        composeHistory = ComposeHistory.load(from: composeURL)
        if !Store.usesFixtures { breakpointRules = BreakpointRules.load(from: rulesURL) }
        loadSavedFilters()
        if Store.usesFixtures {
            // The fixture bus (Bus/FixtureBus.swift): what `BusService.call` is live.
            let bus = FixtureBus(session: self)
            commandRunner = { name, args in try await bus.call(name, args) }
        }
    }

    var paused: [FlowRow] { rows.filter { $0.state == .paused } }
    var focusedRow: FlowRow? { rows.first { $0.id == focused } }
    var focusedDetail: FlowDetail? { focused.flatMap { details[$0] } }
    /// The WebSocket detail for the focused flow (S-045), when it is a WebSocket.
    var focusedWSDetail: WSDetail? { focused.flatMap { wsDetails[$0] } }
    /// The L4 detail for the focused flow, when it is an L4 flow.
    var focusedL4Detail: L4Flow? { focused.flatMap { l4Details[$0] } }

    /// The list's query: scope page, group, chip, filter expression, sort (one Kit value, S-062 ready).
    var query: FlowQuery {
        FlowQuery(inScopeOnly: page == .scope, group: group,
                  pins: page == .pinned && group == nil ? pins : nil,
                  chip: chip, filter: filterExpression, sort: sort)
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
    @ObservationIgnored lazy var scan = ScanPanelState(session: self)
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

    /// Records the role the bus reported for this connection and flags a mismatch
    /// against the operator's Expected-role setting (client-side only, never sent
    /// to the server). Called by the bus service on connect; `nil` on disconnect.
    func applyResolvedRole(_ role: String?) {
        resolvedRole = role
        let expected = ExpectedRole(rawValue: Store.defaults.string(forKey: BusEndpointSettings.Key.expectedRole) ?? "")
        // The embedded core always connects the app as operator; the Expected-role setting
        // describes an external core. Suppressed only while the embedded core is the ACTIVE
        // connection (a stale "agent" default would otherwise show a permanent triangle on a
        // plain install); an external connection keeps the warning even though the dormant
        // embedded controller still reports a connection.
        let applies = roleWarningApplies(activeKind: connection?.activeKind ?? .embedded,
                                         embeddedConnectionPresent: coreHealth.connection?.kind == .embedded)
        roleWarning = applies && roleMismatch(expected: expected, resolved: role)
    }

    /// Proxy ▸ Reconnect Bus: drop and re-open the connection so a newly pasted
    /// operator token takes effect without restarting the app.
    func reconnectBus() { reconnectTick += 1 }

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
}
