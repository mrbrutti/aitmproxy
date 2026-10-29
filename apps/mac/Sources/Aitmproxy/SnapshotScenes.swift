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
    case inspectWebSocket = "inspect-websocket"
    case inspectL4 = "inspect-l4"
    case inspectL4OutOfScope = "inspect-l4-oos"

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
        session.select(session.rows.first { $0.seq == 50 }?.id)
    }
}
