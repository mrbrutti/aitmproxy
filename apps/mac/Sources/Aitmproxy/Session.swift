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
    @ObservationIgnored private var compiledFilter: CompiledFilter?
    /// The active filter expression (observed, so the list re-queries on change).
    private(set) var filterExpression: FilterExpression = .matchAll
    var savedFilters: [SavedFilter] = []
    @ObservationIgnored private lazy var savedFilterStore = SavedFilterStore(stateDirectory: Store.url)
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

    /// Flow ▸ Add Host to Scope… (⇧S): the Scope sheet with the focused row's host typed in.
    func addFocusedHostToScope() {
        guard let row = focusedRow else { return }
        scopeSheetHost = row.authority
        scopeSheetVisible = true
    }

    /// Flow ▸ Copy as … (⇧⌘C): the focused flow as a command or snippet.
    func copyFocused(as kind: ExportKind) {
        guard let row = focusedRow, let detail = focusedDetail else { return }
        ExportMenu.copy(kind, detail: detail, row: row)
    }

    /// Flow ▸ Diff Selected (⌘D): exactly two selected flows open the Diff tab.
    var canDiffSelected: Bool { selection.count == 2 }
    func diffSelected() {
        guard canDiffSelected else { return }
        responseTab = .diff
    }

    /// Agent ▸ Approve Pending Request (⌥⏎): the oldest gated command runs.
    func approvePendingRequest() {
        guard let entry = activity.pending.first else { return }
        activity.approve(entry)
    }

    /// Fetches the next body range (F5 `flow.detail {body: range}`); until then it says so.
    func loadMoreBody(for id: FlowID) async throws {
        _ = try await runCommand("flow.detail", ["id": .string(id.raw), "body": .string("range")])
        throw BusError.tool(message: "Paged bodies need flow.detail (F5)")
    }

    /// The text form of whatever is filtering right now.
    var currentFilterExpressionText: String { filterAdvanced ? filterText : filterStack.text }

    /// The rows view of the Advanced text, when the expression is flat.
    var filterStackFromText: FilterStack? {
        guard filterAdvanced, filterError == nil else { return nil }
        return filterExpression.stack
    }

    func setFilterAdvanced(_ advanced: Bool) {
        if advanced {
            filterText = filterStack.text
            filterAdvanced = true
            parseFilterText()
        } else {
            if let stack = filterExpression.stack { filterStack = stack }
            filterAdvanced = false
            recompileFilter(from: filterStack.expression)
        }
    }

    private func parseFilterText() {
        do {
            let expression = try FilterExpression.parse(filterText)
            filterError = nil
            recompileFilter(from: expression)
        } catch {
            filterError = error
            compiledFilter = nil
            filterExpression = .matchAll
        }
    }

    private func recompileFilter(from expression: FilterExpression) {
        filterExpression = expression
        compiledFilter = expression == .matchAll ? nil : CompiledFilter(expression)
    }

    func clearFilter() {
        filterStack = FilterStack(rows: [FilterRow(.url, .contains)])
        filterText = ""
        filterError = nil
        compiledFilter = nil
        filterExpression = .matchAll
    }

    func loadSavedFilters() {
        savedFilters = (try? savedFilterStore.load()) ?? []
    }

    func saveFilter(named name: String) {
        let expression = currentFilterExpressionText
        guard !name.isEmpty, !expression.isEmpty else { return }
        savedFilters.removeAll { $0.name == name }
        savedFilters.append(SavedFilter(name: name, expression: expression))
        try? savedFilterStore.save(savedFilters)
    }

    func deleteSavedFilter(_ saved: SavedFilter) {
        savedFilters.removeAll { $0.id == saved.id }
        try? savedFilterStore.save(savedFilters)
    }

    /// Sets both the rows and the Advanced text (S-033).
    func applySavedFilter(_ saved: SavedFilter) {
        guard let expression = try? FilterExpression.parse(saved.expression) else { return }
        if let stack = expression.stack {
            filterAdvanced = false
            filterStack = stack
        } else {
            filterAdvanced = true
            filterText = saved.expression
        }
        filterBarVisible = true
    }

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

    func runCommand(_ name: String, _ args: [String: JSONValue]) async throws -> JSONValue {
        guard let commandRunner else { throw BusError.disconnected }
        do {
            let value = try await commandRunner(name, args)
            commandRecorder?(name, args, nil)
            return value
        } catch {
            commandRecorder?(name, args, BusService.describe(error))
            throw error
        }
    }

    func rememberPaletteUse(_ item: PaletteItem) {
        recentPaletteIDs.removeAll { $0 == item.id }
        recentPaletteIDs.insert(item.id, at: 0)
        recentPaletteIDs = Array(recentPaletteIDs.prefix(5))
        if !Store.isOverridden { UserDefaults.standard.set(recentPaletteIDs, forKey: "palette.recent") }
    }

    func paletteItems(for query: String) -> [PaletteItem] {
        var all: [PaletteItem] = []
        for tool in tools {
            all.append(PaletteItem(id: "cmd:\(tool.name)", section: .commands, title: tool.name, subtitle: tool.description,
                                   shortcut: nil, method: nil, kind: .command(tool)))
        }
        let locals: [(String, String, String?, () -> Void)] = [
            (interceptArmed ? "Disarm Intercept" : "Arm Intercept", "Stop or start parking every request", "i", { [self] in arm(!interceptArmed) }),
            ("Compose Request…", "Write and send a new request", "⌘N", { [self] in openCompose() }),
            (capturing ? "Pause Capture" : "Resume Capture", "Stop or start recording flows", "⇧⌘R", { [self] in setCapturing(!capturing) }),
            ("Clear Session", "Drop every flow", "⌘⌫", { [self] in clearSession(confirm: ClearConfirmation.ask) }),
            (autoSelect ? "Stop Auto-select" : "Auto-select New Flows", "Follow the newest flow as it arrives", "⇧⌘A", { [self] in autoSelect.toggle() }),
            ("Filter Bar", "Stack filters over the list", "⌘F", { [self] in filterBarVisible.toggle() }),
            ("Inspector Below", "Horizontal layout", "⌥⌘1", { [self] in layout = .horizontal }),
            ("Inspector Right", "Vertical layout", "⌥⌘2", { [self] in layout = .vertical }),
            ("Inspector Detached", "The inspector in its own window", "⌥⌘3", { [self] in layout = .detached }),
            (splitView ? "Single List" : "Split View", "Two lists over one capture", "⌥⌘4", { [self] in splitView.toggle() }),
        ]
        for (title, subtitle, shortcut, action) in locals {
            all.append(PaletteItem(id: "local:\(title)", section: .local, title: title, subtitle: subtitle, shortcut: shortcut, method: nil, kind: .local(action)))
        }
        let setup: [(String, String, () -> Void)] = [
            ("Certificate Authority…", "Status, export, install the proxy's CA", { [self] in show(.ca) }),
            ("Configuration…", "The proxy's effective config", { [self] in show(.config) }),
            ("Overview", "Session statistics", { [self] in show(.overview) }),
            ("Connection Log", "CONNECTs, TLS, ALPN, SNI", { [self] in show(.connections) }),
            ("Activity Log", "Every command from every frontend", { [self] in activityLogVisible.toggle() }),
            ("Add Host to Scope…", "Authorise a host for testing", { [self] in scopeSheetVisible = true }),
            ("Open Browser", "Show the embedded browser", { [self] in show(.browser) }),
        ]
        for (title, subtitle, action) in setup {
            all.append(PaletteItem(id: "setup:\(title)", section: .setup, title: title, subtitle: subtitle, shortcut: nil, method: nil, kind: .local(action)))
        }
        for saved in savedFilters {
            all.append(PaletteItem(id: "filter:\(saved.id)", section: .filters, title: "Filter: \(saved.name)", subtitle: saved.expression,
                                   shortcut: nil, method: nil, kind: .savedFilter(saved)))
        }
        if !query.isEmpty {
            for row in rows {
                all.append(PaletteItem(id: "flow:\(row.id.raw)", section: .flows, title: row.url,
                                       subtitle: "\(row.status.map(String.init) ?? (row.state == .paused ? "paused" : "—")) · \(row.client?.name ?? "")",
                                       shortcut: nil, method: row.method, kind: .flow(row.id)))
            }
        }
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        var ranked: [(PaletteItem, Int)] = all.compactMap { item in
            if trimmed.isEmpty { return (item, 1) }
            let score = Fuzzy.score(trimmed, name: item.title, description: item.subtitle)
            return score > 0 ? (item, score) : nil
        }
        // Recent on top (only when nothing is typed), then by score within section order.
        if trimmed.isEmpty {
            let recent = ranked.filter { recentPaletteIDs.contains($0.0.id) }.map { item, score -> (PaletteItem, Int) in
                var r = item; r.section = .recent; r.id = "recent:" + item.id; return (r, score)
            }
            ranked = recent.sorted { recentPaletteIDs.firstIndex(of: String($0.0.id.dropFirst(7))) ?? 0 < recentPaletteIDs.firstIndex(of: String($1.0.id.dropFirst(7))) ?? 0 } + ranked
        }
        let order = PaletteSection.allCases
        return ranked
            .sorted { a, b in
                let sa = order.firstIndex(of: a.0.section) ?? 0, sb = order.firstIndex(of: b.0.section) ?? 0
                return sa == sb ? a.1 > b.1 : sa < sb
            }
            .prefix(60).map(\.0)
    }
    var listenAddress = "127.0.0.1:8080"
    var agentPolicy: AgentPolicy = .all
    var agentActionsLastMinute = 0
    var bus: BusState = .disconnected
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
        let rules = breakpointRules.enabled
        perform(on ? "arm intercept" : "disarm intercept") { [self] in try await actions.setIntercept(on, rules: rules) }
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

    /// Remembered for the session (S-039).
    var killMode: KillMode = .reset

    func kill(_ id: FlowID) {
        let mode = killMode
        perform("kill") { [self] in try await actions.kill(id, mode: mode) }
    }

    // MARK: Breakpoint rules (S-040, F3)

    var rulesVisible = false
    var scopeSheetVisible = false
    var breakpointRules = BreakpointRules()
    var rulesURL: URL { Store.url.appending(path: "rules.json") }

    /// Saves the set; re-arms with the rules when intercept is on (the core takes them after F3).
    func setBreakpointRules(_ rules: BreakpointRules) {
        breakpointRules = rules
        try? rules.save(to: rulesURL)
        if interceptArmed {
            perform("set rules") { [self] in try await actions.setIntercept(true, rules: rules.enabled) }
        }
    }

    // MARK: Compose (S-042–S-044)

    var composeVisible = false
    var composeDraft = ComposeDraft()
    var composeHistory = ComposeHistory()
    var composeURL: URL { Store.url.appending(path: "compose.json") }

    func openCompose(_ draft: ComposeDraft? = nil) {
        if let draft { composeDraft = draft }
        composeVisible = true
    }

    /// Edit & Replay (⇧R): Compose prefilled from the flow's detail.
    func editAndReplay(_ id: FlowID) {
        guard let row = rows.first(where: { $0.id == id }) else { return }
        guard row.inScope else { lastError = "Out of scope — add \(row.authority) to scope to act"; return }
        let detail = details[id] ?? Fixtures.detail(for: row)
        openCompose(ComposeDraft.from(detail: detail, row: row))
    }

    func sendCompose(completion: @escaping (Bool) -> Void) {
        let draft = composeDraft
        guard draft.validationError(scope: scopeHosts) == nil else { completion(false); return }
        Task {
            do {
                let newID = try await actions.send(draft.requestEdits())
                composeHistory.record(draft)
                try? composeHistory.save(to: composeURL)
                lastError = nil
                if let newID { select(newID) }
                completion(true)
            } catch {
                lastError = "send: \(BusService.describe(error))"
                completion(false)
            }
        }
    }

    // MARK: Bulk (S-046)

    /// Resume or kill every paused row in the selection, in capture order; reports skips.
    func resumeSelected() { bulk("Resumed") { [self] id in resume(id) } }
    func killSelected() { bulk("Killed") { [self] id in kill(id) } }

    private func bulk(_ verb: String, _ act: (FlowID) -> Void) {
        let chosen = rows.filter { selection.contains($0.id) }
        let paused = chosen.filter { $0.state == .paused }
        for row in paused { act(row.id) }
        let skipped = chosen.count - paused.count
        lastError = skipped > 0 ? "\(verb) \(paused.count) · skipped \(skipped) (not paused)" : nil
    }

    var selectedRows: [FlowRow] { rows.filter { selection.contains($0.id) } }

    func replay(_ id: FlowID) {
        perform("replay") { [self] in
            if let newID = try await actions.replay(id) { select(newID) }
        }
    }

    // MARK: Editing a paused request (S-037, S-038)

    /// The operator's unsent edits per paused flow; nil = as the proxy holds it.
    var editDrafts: [FlowID: HTTPMessage] = [:]

    func updateDraft(_ id: FlowID, _ message: HTTPMessage) {
        editDrafts[id] = message
    }

    func revertDraft(_ id: FlowID) {
        editDrafts[id] = nil
    }

    /// Edits the draft would send, against what the proxy currently holds.
    func pendingEdits(_ id: FlowID) -> RequestEdits {
        guard let draft = editDrafts[id], let detail = details[id] else { return RequestEdits() }
        return RequestEdits.diff(from: detail.request, to: draft)
    }

    func pendingEditCount(_ id: FlowID) -> Int { pendingEdits(id).changeCount }

    /// `Apply & Resume`: mutate with the pending edits, then resume (§4.5).
    func applyAndResume(_ id: FlowID) {
        let edits = pendingEdits(id)
        perform("apply & resume") { [self] in
            if !edits.isEmpty { try await actions.mutate(id, edits: edits) }
            editDrafts[id] = nil
            try await actions.resume(id)
        }
    }

    /// `e`: the paused row's Raw tab, editable.
    func editPaused(_ id: FlowID) {
        select(id)
        requestTab = .raw
    }

    func addScope(_ host: String) {
        perform("add to scope") { [self] in try await actions.addScope(host) }
    }

    func removeScope(_ host: String, confirm: (Int) -> Bool = { _ in true }) {
        let pausedOnHost = paused.filter { Scope.matches($0.authority, host) }.count
        if pausedOnHost > 0, !confirm(pausedOnHost) { return }
        perform("remove from scope") { [self] in try await actions.removeScope(host) }
    }

    /// Marks and comments apply locally at once; the bus call (F6) follows.
    func mark(_ id: FlowID, _ color: MarkColor?) {
        if let i = rows.firstIndex(where: { $0.id == id }) { rows[i].mark = color }
        perform("mark") { [self] in try await actions.mark(id, color: color) }
    }

    func comment(_ id: FlowID, _ text: String) {
        if let i = rows.firstIndex(where: { $0.id == id }) { rows[i].comment = text.isEmpty ? nil : text }
        perform("comment") { [self] in try await actions.comment(id, text: text) }
    }

    func setCapturing(_ on: Bool) {
        perform(on ? "resume capture" : "pause capture") { [self] in try await actions.setCapturing(on) }
    }

    /// Clear asks first when flows are paused (they would be dropped mid-flight).
    func clearSession(confirm: (Int) -> Bool = { _ in true }) {
        let pausedCount = paused.count
        if pausedCount > 0, !confirm(pausedCount) { return }
        perform("clear") { [self] in try await actions.clear() }
    }

    /// A row verb from the keyboard, the context menu or the Flow menu (S-010).
    func perform(_ action: FlowRowAction, on id: FlowID) {
        guard let row = rows.first(where: { $0.id == id }) else { return }
        guard row.inScope else {
            lastError = "Out of scope — add \(row.authority) to scope to act"
            return
        }
        switch action {
        case .resume: row.edited ? applyAndResume(id) : resume(id)
        case .kill: kill(id)
        case .delete: deleteOrKill(id)
        case .replay: replay(id)
        case .editAndReplay: editAndReplay(id)
        case .resumeSelected: resumeSelected()
        case .killSelected: killSelected()
        case .edit:
            if row.state == .paused { editPaused(id) } else { lastError = "Only a paused flow can be edited" }
        case .mark(let color): mark(id, color)
        case .comment: select(id)
        case .buildPoC: buildPoCFlowID = id
        case .pinHost: isPinned(.host(row.authority)) ? unpin(.host(row.authority)) : pin(.host(row.authority))
        case .copyURL:
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(row.url, forType: .string)
        case .quickLook:
            if let detail = details[id], BodyQuickLook.shared.prepare(detail, row: row) {
                quickLookTick += 1
            } else {
                lastError = "No body to Quick Look"
            }
        }
    }

    /// Deleting a finished flow only hides it from this view; a pending or paused one is killed.
    func deleteOrKill(_ id: FlowID) {
        guard let row = rows.first(where: { $0.id == id }) else { return }
        if row.state == .paused || row.state == .pending {
            kill(id)
        } else {
            rows.removeAll { $0.id == id }
            selection.remove(id)
            if focused == id { focused = nil }
        }
    }

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
