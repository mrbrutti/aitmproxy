import AitmBusClient
import AitmproxyKit
import AppKit
import Foundation

/// States that are not sidebar pages but have a `Screens:` entry in
/// docs/STORIES.md: panels, bars and selections. Snapshot mode applies one,
/// captures, and resets before the next. `APP_SNAPSHOT_PAGES=filter-bar,palette`.
enum SnapshotScene: String, CaseIterable {
    case filterBar = "filter-bar"
    case filterAdvanced = "filter-advanced"
    case savedFilters = "saved-filters"
    case sidebarFilter = "sidebar-filter"
    case palette
    case paletteFlows = "palette-flows"
    case multiSelect = "multi-select"
    case rulesSheet = "rules-sheet"
    case editPaused = "edit-paused"
    case scopeSheet = "scope-sheet"
    case importDrop = "import-drop"
    case detached
    case split
    case activityLog = "activity-log"
    case buildPoC = "build-poc"
    case findingDetail = "finding-detail"
    case composeSheet = "compose-sheet"
    case inspectHeaders = "inspect-headers"
    case inspectCookies = "inspect-cookies"
    case inspectBody = "inspect-body"
    case inspectJSON = "inspect-json"
    case inspectImage = "inspect-image"
    case inspectHex = "inspect-hex"
    case inspectSSE = "inspect-sse"
    case inspectDiff = "inspect-diff"
    case inspectTiming = "inspect-timing"
    case inspectFind = "inspect-find"
    case coreRunning = "core-running"
    case coreRestarting = "core-restarting"
    case coreFailed = "core-failed"
    case coreLog = "core-log"
    case inspectWebSocket = "inspect-websocket"
    case inspectL4 = "inspect-l4"
    case inspectL4OutOfScope = "inspect-l4-oos"
    case appsNoAttribution = "apps-noattribution"

    /// The fixture rows the `appsNoAttribution` scene strips of their client, restored by `reset`.
    private static var savedRows: [FlowRow]?

    /// Task 8: a seeded embedded `CoreConnection` so the health dot and the
    /// core-log panel render without a live core (snapshots use fixtures).
    static func core(_ status: CoreConnection.Status, label: String, proxyAddress: String? = nil) -> CoreConnection {
        CoreConnection(id: .fixture, kind: .embedded, endpoint: BusEndpoint(port: 0, token: ""), status: status,
                       label: label, proxyAddress: proxyAddress,
                       appliedPort: 8080, appliedVerifyUpstreamTLS: true)
    }

    func apply(to session: Session) {
        session.page = .apps
        switch self {
        case .filterBar:
            session.filterBarVisible = true
            session.filterStack = FilterStack(rows: [FilterRow(.method, .equals, "POST"), FilterRow(.status, .regex, "(")], combinator: .or)
        case .filterAdvanced:
            session.filterBarVisible = true
            session.setFilterAdvanced(true)
            session.filterText = "~m POST & ~c 2 | ~scope out"
        case .savedFilters:
            session.filterBarVisible = true
            session.saveFilter(named: "cdn only")
            session.filterStack = FilterStack(rows: [FilterRow(.host, .contains, "cdn")])
            session.saveFilter(named: "cdn only")
        case .sidebarFilter:
            session.sidebarQuery = "shop"
            session.sidebarFilterFocusTick += 1
        case .palette:
            session.paletteOpenedByKeyboard = true
            session.paletteVisible = true
        case .paletteFlows:
            session.paletteOpenedByKeyboard = true
            session.paletteVisible = true
        case .multiSelect:
            session.selection = Set(session.rows.prefix(3).map(\.id))
        case .editPaused:
            let id = Fixtures.rows[9].id
            session.editPaused(id)
            if var m = session.details[id]?.request {
                m.headers.append(.init("x-debug", "1"))
                m.body = Data("{\n  \"email\": \"ops@shop-staging.test\",\n  \"password\": \"' OR 1=1 --\",\n  \"remember\": true\n}".utf8)
                session.updateDraft(id, m)
            }
        case .appsNoAttribution:
            // Live reality (NS-AC8): captured flows carry no source app, so the Apps page
            // cannot group them. The table must stay, with the capture-state banner above it.
            Self.savedRows = session.rows
            session.rows = session.rows.map { var row = $0; row.client = nil; return row }
            session.page = .apps
            CaptureSnapshotState.noscope.apply(to: session)
        case .scopeSheet:
            session.scopeSheetVisible = true
        case .importDrop:
            session.dropTargeted = true
        case .detached:
            session.layout = .detached
        case .activityLog:
            session.activityLogVisible = true
        case .buildPoC:
            session.select(Fixtures.rows[7].id)
            session.buildPoCFlowID = Fixtures.rows[7].id
        case .findingDetail:
            session.page = .findings
            session.poc.load()
            session.poc.select(session.poc.findings.first?.id)
        case .split:
            session.splitView = true
            session.secondQuery.chip = .json
            session.secondSelection = [Fixtures.rows[0].id]
            session.focus(pane: 1, on: Fixtures.rows[0].id)
        case .rulesSheet:
            session.breakpointRules = BreakpointRules(rules: [
                BreakpointRule(name: "Login requests", url: "*/api/auth/*", method: "POST", onResponse: true, flag: .red),
                BreakpointRule(name: "Cart writes", url: #"/api/cart(/|$)"#, matching: .regex, enabled: false),
            ])
            session.rulesVisible = true
        case .composeSheet:
            session.composeDraft = ComposeDraft.Template.postJSON.draft
            session.composeDraft.url = "https://api.shop-staging.test/api/cart"
            session.composeDraft.body = "{\n  \"quantity\": 2,\n  \"note\": \"gift wrap\"\n}"
            session.composeVisible = true
        case .inspectHeaders:
            session.select(session.rows.first { $0.seq == 41 }?.id)
            session.requestTab = .headers
            session.responseTab = .headers
        case .inspectCookies:
            session.loadFixtureExtras()
            session.select(session.extraRow { $0.request.header("cookie") != nil }?.id)
            session.requestTab = .cookies
            session.responseTab = .setCookie
        case .inspectBody:
            if var detail = session.details[Fixtures.rows[5].id] {
                detail.response = Fixtures.prettyJSON
                session.details[Fixtures.rows[5].id] = detail
            }
            session.select(Fixtures.rows[5].id)
            session.requestTab = .body
            session.responseTab = .body
        case .inspectJSON:
            if var detail = session.details[Fixtures.rows[5].id] {
                detail.response = Fixtures.prettyJSON
                session.details[Fixtures.rows[5].id] = detail
            }
            session.select(Fixtures.rows[5].id)
            session.responseTab = .json
        case .inspectImage:
            session.loadFixtureExtras()
            session.select(session.extraRow { ($0.response?.contentType ?? "").hasPrefix("image/") }?.id)
            session.responseTab = .body
        case .inspectHex:
            session.loadFixtureExtras()
            session.select(session.extraRow { ($0.response?.contentType ?? "").hasPrefix("application/octet-stream") }?.id)
            session.responseTab = .body
        case .inspectSSE:
            session.loadFixtureExtras()
            session.select(session.extraRow { ($0.response?.contentType ?? "").hasPrefix("text/event-stream") }?.id)
            session.responseTab = .body
        case .inspectDiff:
            session.selection = Set(session.rows.filter { $0.seq == 45 || $0.seq == 46 }.map(\.id))
            session.focused = session.rows.first { $0.seq == 46 }?.id
            session.responseTab = .diff
        case .inspectFind:
            if var detail = session.details[Fixtures.rows[5].id] {
                detail.response = Fixtures.prettyJSON
                session.details[Fixtures.rows[5].id] = detail
            }
            session.select(Fixtures.rows[5].id)
            session.responseTab = .body
            session.findRequestTick += 1
        case .inspectTiming:
            session.loadFixtureExtras()
            session.select(session.extraRow { $0.timing != nil }?.id)
            session.requestTab = .timing
            session.responseTab = .headers
        case .coreRunning:
            session.coreHealth.connection = Self.core(.ready, label: "Embedded core · proxy 127.0.0.1:8080", proxyAddress: "127.0.0.1:8080")
        case .coreRestarting:
            session.coreHealth.connection = Self.core(.starting, label: "Embedded core")
        case .coreFailed:
            session.coreHealth.connection = Self.core(
                .degraded(reason: "the core exited unexpectedly (status 1)\naitm: address already in use (os error 48)"),
                label: "Embedded core")
        case .coreLog:
            session.coreHealth.connection = Self.core(.ready, label: "Embedded core · proxy 127.0.0.1:8081", proxyAddress: "127.0.0.1:8081")
            for line in [
                "aitm 0.1.0 starting",
                "proxy listening on 127.0.0.1:8081 (8080 was in use)",
                "browser proxy listening on 127.0.0.1:8083",
                "bus listening on 127.0.0.1:52118",
                "obscura engine ready",
                "proxy: GET https://api.shop-staging.test/api/health → 200",
            ] { session.coreHealth.record(line) }
            session.coreLogVisible = true
        case .inspectWebSocket:
            session.select(session.rows.first { $0.kind == .websocket }?.id)
        case .inspectL4:
            // The in-scope loopback capture: packet list, layer tree, craft editor.
            session.select(session.rows.first { $0.kind == .l4 && $0.inScope }?.id)
        case .inspectL4OutOfScope:
            // The out-of-L4-scope session: dimmed, mutating actions disabled (AC9).
            session.select(session.rows.first { $0.kind == .l4 && !$0.inScope }?.id)
        }
    }

    static func reset(_ session: Session) {
        session.filterBarVisible = false
        session.setFilterAdvanced(false)
        session.clearFilter()
        session.sidebarQuery = ""
        session.paletteVisible = false
        if session.layout == .detached {
            NSApp.windows.first { $0.title == "Inspector" }?.close()
            session.layout = .horizontal
        }
        session.activityLogVisible = false
        session.buildPoCFlowID = nil
        session.splitView = false
        session.secondQuery = FlowQuery()
        session.secondSelection = []
        session.rulesVisible = false
        session.scopeSheetVisible = false
        session.dropTargeted = false
        session.composeVisible = false
        session.requestTab = .raw
        session.responseTab = .body
        session.editDrafts = [:]
        session.coreLogVisible = false
        session.coreHealth.connection = nil
        session.coreHealth.log.removeAll()
        if let rows = savedRows {
            session.rows = rows
            savedRows = nil
            CaptureSnapshotState.reset(session)
        }
        session.select(session.rows.first { $0.seq == 50 }?.id)
    }
}

/// The states Settings ▸ Capture shows the operator, walked by snapshot mode (TG-AC11):
/// off, awaiting approval, capturing, failed. Each seeds what the `ExtensionController`
/// and the persisted capture choice would give the tab. A snapshot run embeds no
/// extension, so the seed also marks capture supported, and it seeds the toggle position
/// through `captureChoice` instead of writing the operator's real preference.
/// The raw value names the file: `settings-capture-<state>-<mode>.png`.
enum CaptureSnapshotState: String, CaseIterable {
    case off, awaiting, active, failed, noscope

    func apply(to session: Session) {
        session.coreHealth.captureSupported = true
        switch self {
        case .off:
            session.coreHealth.captureCapability = .inactive
            session.coreHealth.captureChoice = false
        case .awaiting:
            session.coreHealth.captureCapability = .pendingApproval
            session.coreHealth.captureChoice = true
        case .active:
            session.coreHealth.captureCapability = .capturing
            session.coreHealth.captureChoice = true
        case .failed:
            session.coreHealth.captureCapability = .degraded(
                "Could not start the capture tunnel after 4 attempts: the proxy configuration was not allowed")
            session.coreHealth.captureChoice = true
        case .noscope:
            // The trap: capture on, scope empty, so nothing is captured. The tab must say so.
            session.coreHealth.captureCapability = .capturing
            session.coreHealth.captureChoice = true
            session.scopeHosts = []
        }
    }

    /// Back to what a snapshot run starts with: no extension, nothing seeded.
    static func reset(_ session: Session) {
        session.coreHealth.captureSupported = false
        session.coreHealth.captureCapability = .extensionNotInstalled
        session.coreHealth.captureChoice = nil
        session.scopeHosts = Fixtures.scope
    }
}
