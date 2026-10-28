import AitmproxyKit
import AppKit
import SwiftUI

/// The flow list (foundation §2.10a): an `NSTableView`, because SwiftUI's
/// `Table` cannot hold 28px rows at 50 appends/s. Columns per §2.7; rows
/// append without animation; selection is the `active` tint. Column
/// order/width/visibility persist in `columns.json`; headers sort.
struct FlowTableView: NSViewRepresentable {
    var rows: [FlowRow]
    @Binding var selection: Set<FlowID>
    @Binding var sort: FlowSort
    var density: Density
    /// Where the column layout is kept; nil keeps it in memory only.
    var layoutURL: URL?
    /// Whether a host is pinned (for the context menu's Pin/Unpin label).
    var isPinned: (String) -> Bool = { _ in false }
    /// A comment saved from the popover.
    var onComment: ((FlowID, String) -> Void)?
    /// The row the inspector should follow (the last clicked one).
    var onFocus: (FlowID?) -> Void
    /// A verb from the keyboard or the context menu, with the row it targets.
    var onAction: (FlowRowAction, FlowID) -> Void = { _, _ in }
    var onToggleIntercept: () -> Void = {}
    var onCompose: () -> Void = {}

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let coordinator = context.coordinator
        let table = FlowKeyTable()
        table.onVerb = { [weak coordinator] verb in coordinator?.perform(verb) }
        table.onToggleIntercept = { [weak coordinator] in coordinator?.parent.onToggleIntercept() }
        table.onCompose = { [weak coordinator] in coordinator?.parent.onCompose() }
        table.menu = coordinator.makeRowMenu()
        table.rowHeight = density.rowHeight
        table.intercellSpacing = .zero
        table.style = .plain
        table.usesAlternatingRowBackgroundColors = false
        table.gridStyleMask = []
        table.backgroundColor = Tok.Ground.surface.nsColor
        table.selectionHighlightStyle = .regular
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = true
        table.allowsColumnResizing = true
        table.allowsColumnSelection = false
        table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.focusRingType = .none
        table.headerView = FlowHeaderView(frame: NSRect(x: 0, y: 0, width: 0, height: Tok.Size.columnHeader))

        let layout = layoutURL.flatMap(ColumnLayout.load) ?? ColumnLayout()
        let order = layout.resolvedOrder(known: FlowColumn.allCases.map(\.rawValue)).compactMap(FlowColumn.init(rawValue:))
        for column in order {
            let c = NSTableColumn(identifier: column.identifier)
            c.title = column.title
            c.width = layout.width(for: column.rawValue, default: column.width)
            c.minWidth = column.minWidth
            c.resizingMask = column == .url ? .autoresizingMask : .userResizingMask
            c.headerCell = FlowHeaderCell(textCell: column.title)
            c.headerCell.alignment = column.numeric ? .right : .left
            c.headerToolTip = column.sortKey.map { "Sort by \($0.title)" }
            c.isHidden = (layout.widths.isEmpty ? column.defaultHidden : layout.isHidden(column.rawValue)) && !column.alwaysVisible
            if let key = column.sortKey {
                c.sortDescriptorPrototype = NSSortDescriptor(key: key.rawValue, ascending: true)
            }
            table.addTableColumn(c)
        }
        table.dataSource = coordinator
        table.delegate = coordinator
        table.target = coordinator
        table.doubleAction = #selector(Coordinator.doubleClick)
        table.headerView?.menu = coordinator.makeColumnsMenu()
        coordinator.table = table
        coordinator.applySortDescriptors(sort)
        coordinator.observeColumns(table)

        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = Tok.Ground.surface.nsColor
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let coordinator = context.coordinator
        coordinator.parent = self
        guard let table = coordinator.table else { return }
        if coordinator.density != density {
            coordinator.density = density
            table.rowHeight = density.rowHeight
            table.reloadData()
        }
        if coordinator.rows != rows {
            let old = coordinator.rows
            coordinator.rows = rows
            // Appends land without animation (motion.rowArrive = 0); anything else reloads.
            if rows.count > old.count, zip(old, rows).allSatisfy({ $0 == $1 }) {
                table.insertRows(at: IndexSet(old.count..<rows.count), withAnimation: [])
            } else {
                table.reloadData()
            }
        }
        if coordinator.appliedSort != sort {
            coordinator.applySortDescriptors(sort)
        }
        let wanted = IndexSet(rows.indices.filter { selection.contains(rows[$0].id) })
        if wanted != table.selectedRowIndexes {
            coordinator.syncing = true
            table.selectRowIndexes(wanted, byExtendingSelection: false)
            coordinator.syncing = false
        }
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var parent: FlowTableView
        var rows: [FlowRow] = []
        var density: Density
        var appliedSort: FlowSort = .captureOrder
        weak var table: NSTableView?
        /// True while `updateNSView` pushes SwiftUI's selection or sort into the table.
        var syncing = false
        private var saveTask: Task<Void, Never>?

        init(_ parent: FlowTableView) {
            self.parent = parent
            self.density = parent.density
        }

        // MARK: Rows

        func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
            let id = NSUserInterfaceItemIdentifier("row")
            let view = tableView.makeView(withIdentifier: id, owner: nil) as? FlowRowView ?? FlowRowView()
            view.identifier = id
            view.leftEdge = rows[row].leftEdge?.nsColor
            return view
        }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard let tableColumn, let column = FlowColumn(rawValue: tableColumn.identifier.rawValue) else { return nil }
            let view = tableView.makeView(withIdentifier: tableColumn.identifier, owner: nil) as? FlowCellView
                ?? FlowCellView(column: column)
            view.identifier = tableColumn.identifier
            view.configure(rows[row], density: density)
            return view
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !syncing, let table else { return }
            let ids = Set(table.selectedRowIndexes.compactMap { rows.indices.contains($0) ? rows[$0].id : nil })
            parent.selection = ids
            // The clicked row leads the inspector; with several selected, the last one.
            let focus = table.clickedRow >= 0 && rows.indices.contains(table.clickedRow)
                ? rows[table.clickedRow].id
                : table.selectedRowIndexes.last.flatMap { rows.indices.contains($0) ? rows[$0].id : nil }
            parent.onFocus(focus)
        }

        @objc func doubleClick() {
            // Enter / double-click focuses the inspector; wired when the inspector takes focus.
        }

        // MARK: Row actions (S-010, S-014, S-017)

        /// The row a verb targets: the clicked row for the context menu, else the focused/last selected one.
        private var targetRow: FlowRow? {
            guard let table else { return nil }
            if table.clickedRow >= 0, rows.indices.contains(table.clickedRow) { return rows[table.clickedRow] }
            if let last = table.selectedRowIndexes.last, rows.indices.contains(last) { return rows[last] }
            return nil
        }

        func perform(_ action: FlowRowAction) {
            guard let row = targetRow else { return }
            if case .mark(nil) = action, let table, let index = rows.firstIndex(of: row) {
                // `m` opens the mark menu at the row.
                let menu = markMenu(for: row)
                let rect = table.rect(ofRow: index)
                menu.popUp(positioning: nil, at: NSPoint(x: rect.minX + 60, y: rect.maxY), in: table)
                return
            }
            if case .comment = action, let table, let index = rows.firstIndex(of: row) {
                showCommentPopover(for: row, at: table.rect(ofRow: index), in: table)
                return
            }
            parent.onAction(action, row.id)
        }

        private var rowMenu: NSMenu?

        func makeRowMenu() -> NSMenu {
            let menu = NSMenu(title: "Flow")
            menu.delegate = self
            rowMenu = menu
            return menu
        }

        private func markMenu(for row: FlowRow) -> NSMenu {
            let menu = NSMenu(title: "Mark")
            for color in MarkColor.allCases {
                let item = NSMenuItem(title: color.title, action: #selector(markChosen(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = color.rawValue
                item.state = row.mark == color ? .on : .off
                let swatch = NSImage(size: NSSize(width: 12, height: 12), flipped: false) { rect in
                    color.color.setFill()
                    NSBezierPath(roundedRect: rect, xRadius: 3, yRadius: 3).fill()
                    return true
                }
                item.image = swatch
                menu.addItem(item)
            }
            menu.addItem(.separator())
            let clear = NSMenuItem(title: "Clear Mark", action: #selector(markChosen(_:)), keyEquivalent: "")
            clear.target = self
            clear.isEnabled = row.mark != nil
            menu.addItem(clear)
            return menu
        }

        @objc private func markChosen(_ sender: NSMenuItem) {
            guard let row = targetRow else { return }
            let color = (sender.representedObject as? String).flatMap(MarkColor.init(rawValue:))
            parent.onAction(.mark(color), row.id)
        }

        private var commentPopover: NSPopover?

        private func showCommentPopover(for row: FlowRow, at rect: NSRect, in table: NSTableView) {
            let popover = NSPopover()
            popover.behavior = .transient
            let id = row.id
            popover.contentViewController = NSHostingController(rootView: CommentPopover(initial: row.comment ?? "") { [weak self] text in
                self?.parent.onAction(.comment, id)
                self?.commentText = (id, text)
                self?.parent.onComment?(id, text)
            })
            commentPopover = popover
            popover.show(relativeTo: rect, of: table, preferredEdge: .maxY)
        }

        var commentText: (FlowID, String)?

        // MARK: Sort (S-009)

        func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
            guard !syncing else { return }
            guard let first = tableView.sortDescriptors.first, let key = first.key.flatMap(FlowSort.Key.init(rawValue:)) else {
                appliedSort = .captureOrder
                parent.sort = .captureOrder
                return
            }
            var sort = FlowSort(key: key, ascending: first.ascending)
            // `#` ascending is capture order: no descriptor, no indicator.
            if sort.isCaptureOrder { sort = .captureOrder }
            appliedSort = sort
            if sort.isCaptureOrder { applySortDescriptors(sort) }
            parent.sort = sort
        }

        func applySortDescriptors(_ sort: FlowSort) {
            guard let table else { return }
            syncing = true
            table.sortDescriptors = sort.isCaptureOrder ? [] : [NSSortDescriptor(key: sort.key.rawValue, ascending: sort.ascending)]
            syncing = false
            appliedSort = sort
        }

        // MARK: Columns (S-008)

        func makeColumnsMenu() -> NSMenu {
            let menu = NSMenu(title: "Columns")
            menu.delegate = self
            return menu
        }

        /// Rebuilt on open, so check marks follow the current layout.
        func menuNeedsUpdate(_ menu: NSMenu) {
            if menu === rowMenu { return buildRowMenu(menu) }
            menu.removeAllItems()
            for column in FlowColumn.allCases {
                let item = NSMenuItem(title: column.menuTitle, action: #selector(toggleColumn(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = column.rawValue
                item.state = isVisible(column) ? .on : .off
                item.isEnabled = !column.alwaysVisible
                menu.addItem(item)
            }
            menu.addItem(.separator())
            let reset = NSMenuItem(title: "Reset Columns", action: #selector(resetColumns), keyEquivalent: "")
            reset.target = self
            menu.addItem(reset)
        }

        /// The row's context menu: every verb, with its key printed (foundation §2.7).
        private func buildRowMenu(_ menu: NSMenu) {
            menu.removeAllItems()
            guard let row = targetRow else { return }
            func add(_ title: String, _ action: FlowRowAction, key: String = "", enabled: Bool = true) {
                let item = NSMenuItem(title: title, action: #selector(rowMenuChosen(_:)), keyEquivalent: key)
                item.keyEquivalentModifierMask = []
                item.target = self
                item.representedObject = action
                item.isEnabled = enabled && row.inScope
                menu.addItem(item)
            }
            let paused = row.state == .paused
            add(row.edited ? "Apply & Resume" : "Resume", .resume, enabled: paused)
            add("Edit Paused Request", .edit, key: "e", enabled: paused)
            add(paused || row.state == .pending ? "Kill" : "Delete", .delete, key: "d")
            menu.addItem(.separator())
            add("Replay", .replay, key: "r")
            add("Build PoC from Flow…", .buildPoC, key: "p")
            menu.addItem(.separator())
            let mark = NSMenuItem(title: "Mark", action: nil, keyEquivalent: "")
            mark.submenu = markMenu(for: row)
            menu.addItem(mark)
            add(row.comment == nil ? "Comment…" : "Edit Comment…", .comment, key: "c")
            menu.addItem(.separator())
            let pinned = parent.isPinned(row.authority)
            add(pinned ? "Unpin Host" : "Pin Host", .pinHost)
            add("Copy URL", .copyURL)
            if !row.inScope {
                menu.addItem(.separator())
                let note = NSMenuItem(title: "Out of scope — add \(row.authority) to scope to act", action: nil, keyEquivalent: "")
                note.isEnabled = false
                menu.addItem(note)
            }
        }

        @objc private func rowMenuChosen(_ sender: NSMenuItem) {
            guard let action = sender.representedObject as? FlowRowAction else { return }
            perform(action)
        }

        private func isVisible(_ column: FlowColumn) -> Bool {
            table?.tableColumn(withIdentifier: column.identifier)?.isHidden == false
        }

        @objc private func toggleColumn(_ sender: NSMenuItem) {
            guard let id = sender.representedObject as? String, let column = FlowColumn(rawValue: id), !column.alwaysVisible,
                  let tableColumn = table?.tableColumn(withIdentifier: column.identifier) else { return }
            tableColumn.isHidden.toggle()
            saveLayoutSoon()
        }

        @objc private func resetColumns() {
            guard let table else { return }
            for (index, column) in FlowColumn.allCases.enumerated() {
                guard let tableColumn = table.tableColumn(withIdentifier: column.identifier) else { continue }
                tableColumn.isHidden = false
                tableColumn.width = column.width
                let current = table.column(withIdentifier: column.identifier)
                if current != index, current >= 0 { table.moveColumn(current, toColumn: index) }
            }
            if let url = parent.layoutURL { try? FileManager.default.removeItem(at: url) }
        }

        func observeColumns(_ table: NSTableView) {
            let center = NotificationCenter.default
            center.addObserver(self, selector: #selector(columnsChanged), name: NSTableView.columnDidMoveNotification, object: table)
            center.addObserver(self, selector: #selector(columnsChanged), name: NSTableView.columnDidResizeNotification, object: table)
        }

        @objc private func columnsChanged(_ note: Notification) {
            saveLayoutSoon()
        }

        /// Resizes fire many times a second; one write a beat after the last change.
        private func saveLayoutSoon() {
            saveTask?.cancel()
            saveTask = Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(300))
                guard !Task.isCancelled else { return }
                self?.saveLayout()
            }
        }

        func currentLayout() -> ColumnLayout {
            guard let table else { return ColumnLayout() }
            var layout = ColumnLayout()
            for column in table.tableColumns {
                layout.order.append(column.identifier.rawValue)
                layout.widths[column.identifier.rawValue] = column.width
                if column.isHidden { layout.hidden.insert(column.identifier.rawValue) }
            }
            return layout
        }

        private func saveLayout() {
            guard let url = parent.layoutURL else { return }
            try? currentLayout().save(to: url)
        }

        deinit {
            NotificationCenter.default.removeObserver(self)
        }
    }
}

/// The columns, in default order (foundation §2.7 "Flow list").
enum FlowColumn: String, CaseIterable {
    case dot, seq, url, client, method, status, time, duration, request, response, ssl, edited, origin, comment, mark

    var identifier: NSUserInterfaceItemIdentifier { NSUserInterfaceItemIdentifier(rawValue) }

    var title: String {
        switch self {
        case .dot, .mark: ""
        case .seq: "#"
        case .url: "URL"
        case .client: "Client"
        case .method: "Method"
        case .status: "Status"
        case .time: "Time"
        case .duration: "Duration"
        case .request: "Request"
        case .response: "Response"
        case .ssl: "SSL"
        case .edited: "Edited"
        case .origin: "Origin"
        case .comment: "Comment"
        }
    }

    /// The header context menu's label (the two glyph-only columns need words).
    var menuTitle: String {
        switch self {
        case .dot: "Status Dot"
        case .mark: "Mark"
        default: title
        }
    }

    var width: CGFloat {
        switch self {
        case .dot: 24
        case .seq: 52
        case .url: 300
        case .client: 96
        case .method: 72
        case .status: 72
        case .time: 124
        case .duration: 88
        case .request: 80
        case .response: 80
        case .ssl: 40
        case .edited: 64
        case .origin: 72
        case .comment: 160
        case .mark: 20
        }
    }

    /// Comment starts hidden: the default set fits a 1440pt window.
    var defaultHidden: Bool { self == .comment }

    var minWidth: CGFloat { self == .url ? 200 : width }

    var numeric: Bool {
        switch self {
        case .seq, .duration, .request, .response: true
        default: false
        }
    }

    /// `#`, URL and Method cannot be hidden.
    var alwaysVisible: Bool {
        switch self {
        case .seq, .url, .method: true
        default: false
        }
    }

    var sortKey: FlowSort.Key? {
        switch self {
        case .dot, .comment: nil
        default: FlowSort.Key(rawValue: rawValue)
        }
    }
}

/// Row pitch and body size move together (foundation §2.4 "Density").
enum Density: String, CaseIterable, Identifiable {
    case dense, `default`, comfortable

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dense: "Dense"
        case .default: "Default"
        case .comfortable: "Comfortable"
        }
    }

    var rowHeight: CGFloat {
        switch self {
        case .dense: Tok.Size.Row.dense
        case .default: Tok.Size.Row.default
        case .comfortable: Tok.Size.Row.comfortable
        }
    }

    /// Body text in rows, header tables and code.
    var bodySize: CGFloat {
        switch self {
        case .dense, .default: Tok.Typography.Size.md
        case .comfortable: Tok.Typography.Size.base
        }
    }
}
