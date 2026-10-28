import AitmproxyKit
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
    case inspectHeaders = "inspect-headers"
    case inspectBody = "inspect-body"
    case inspectJSON = "inspect-json"
    case inspectDiff = "inspect-diff"
    case inspectTiming = "inspect-timing"

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
        case .inspectHeaders:
            session.select(session.rows.first { $0.seq == 41 }?.id)
            session.requestTab = .headers
            session.responseTab = .headers
        case .inspectBody:
            session.select(session.rows.first { $0.seq == 46 }?.id)
            session.requestTab = .body
            session.responseTab = .body
        case .inspectJSON:
            session.select(session.rows.first { $0.seq == 46 }?.id)
            session.responseTab = .json
        case .inspectDiff:
            session.selection = Set(session.rows.filter { $0.seq == 45 || $0.seq == 46 }.map(\.id))
            session.focused = session.rows.first { $0.seq == 46 }?.id
            session.responseTab = .diff
        case .inspectTiming:
            session.select(session.rows.first { $0.seq == 41 }?.id)
            session.requestTab = .connection
        }
    }

    static func reset(_ session: Session) {
        session.filterBarVisible = false
        session.setFilterAdvanced(false)
        session.clearFilter()
        session.sidebarQuery = ""
        session.paletteVisible = false
        session.requestTab = .raw
        session.responseTab = .body
        session.select(session.rows.first { $0.seq == 50 }?.id)
    }
}
