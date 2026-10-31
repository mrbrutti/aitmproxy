import AitmproxyKit
import AppKit
import Quartz
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
    /// Bumped by the session when the list should show Quick Look (`BodyQuickLook` holds the file).
    var quickLookTick = 0
    /// Whether a host is pinned (for the context menu's Pin/Unpin label).
    var isPinned: (String) -> Bool = { _ in false }
    /// A comment saved from the popover.
    var onComment: ((FlowID, String) -> Void)?
    /// The row the inspector should follow (the last clicked one).
    var onFocus: (FlowID?) -> Void
    /// A verb from the keyboard or the context menu, with the row it targets.
    var onAction: (FlowVerb, FlowID) -> Void = { _, _ in }
    /// Pending draft edits per flow: the row menu titles Resume vs Apply & Resume from the same
    /// predicate as the intercept bar and the Flow menu.
    @Environment(Session.self) private var session
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
            // URL is the flexible column: it takes whatever the pane leaves, so its width is
            // never restored from the saved layout (a width saved from a wider pane would be
            // replayed verbatim and push the table past its clip into a horizontal scroll).
            c.width = column == .url ? column.width : layout.width(for: column.rawValue, default: column.width)
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
        coordinator.observeClip(scroll)
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let coordinator = context.coordinator
        coordinator.parent = self
        coordinator.pendingEdits = { [session] id in session.pendingEditCount(id) }
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
        if coordinator.quickLookTick != quickLookTick {
            coordinator.quickLookTick = quickLookTick
            // The table controls the panel (FlowKeyTable); take focus so AppKit asks it.
            if let panel = QLPreviewPanel.shared() {
                table.window?.makeFirstResponder(table)
                panel.makeKeyAndOrderFront(nil)
                panel.reloadData()
            }
        }
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        var parent: FlowTableView
        var pendingEdits: (FlowID) -> Int = { _ in 0 }
        var rows: [FlowRow] = []
        var density: Density
        var appliedSort: FlowSort = .captureOrder
        var quickLookTick: Int
        weak var table: NSTableView?
        /// True while `updateNSView` pushes SwiftUI's selection or sort into the table.
        var syncing = false
        private var saveTask: Task<Void, Never>?

        init(_ parent: FlowTableView) {
            self.parent = parent
            self.density = parent.density
            self.quickLookTick = parent.quickLookTick
        }

        // MARK: Rows

        func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

        func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
            let id = NSUserInterfaceItemIdentifier("row")
            let view = tableView.makeView(withIdentifier: id, owner: nil) as? FlowRowView ?? FlowRowView()
            view.identifier = id
            view.leftEdge = rows[row].leftEdge?.nsColor
            // VoiceOver reads the row in the screen's words (S-069); cells add nothing.
            view.setAccessibilityLabel(rows[row].accessibilityDescription)
            // Stable identifier for CUA/accessibility: row index + the flow's seq.
            view.setAccessibilityIdentifier("flow-row-\(row)-seq\(rows[row].seq)")
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
        var targetRow: FlowRow? {
            guard let table else { return nil }
            if table.clickedRow >= 0, rows.indices.contains(table.clickedRow) { return rows[table.clickedRow] }
            if let last = table.selectedRowIndexes.last, rows.indices.contains(last) { return rows[last] }
            return nil
        }

        /// The verb table's view of `row` inside this list (its own selection, not the session's).
        func verbContext(for row: FlowRow) -> VerbContext {
            let selected = table.map { t in t.selectedRowIndexes.compactMap { rows.indices.contains($0) ? rows[$0] : nil } } ?? []
            return VerbContext(row: row,
                               pendingEdits: pendingEdits(row.id),
                               pinned: parent.isPinned(row.authority),
                               selectedCount: selected.count,
                               selectedPausedCount: selected.filter { $0.state == .paused }.count)
        }

        func perform(_ action: FlowVerb) {
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

        /// The row's context menu; built on open in `FlowTableView+Menus.swift`.
        var rowMenu: NSMenu?
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

        /// The URL column takes whatever width the other visible columns leave, so the table
        /// always fits its clip: no horizontal scroll bar after a side panel opens, a layout
        /// change, or a column toggle. AppKit's own column autoresizing only re-tiles on some
        /// frame changes and never when a saved layout is replayed, so the fit is explicit.
        func fitURLColumn() {
            guard let table, let clip = table.enclosingScrollView?.contentView,
                  let url = table.tableColumn(withIdentifier: FlowColumn.url.identifier), !url.isHidden else { return }
            let visible = table.tableColumns.filter { !$0.isHidden }
            let others = visible.filter { $0 !== url }.reduce(CGFloat(0)) { $0 + $1.width }
            let spacing = CGFloat(visible.count) * table.intercellSpacing.width
            let target = max(url.minWidth, clip.bounds.width - others - spacing)
            if abs(url.width - target) > 0.5 { url.width = target }
        }

        func observeClip(_ scroll: NSScrollView) {
            scroll.contentView.postsFrameChangedNotifications = true
            NotificationCenter.default.addObserver(self, selector: #selector(clipResized), name: NSView.frameDidChangeNotification,
                                                   object: scroll.contentView)
        }

        @objc private func clipResized(_ note: Notification) {
            fitURLColumn()
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
        func saveLayoutSoon() {
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
                // The flexible URL column's width is derived from the pane, never persisted.
                if column.identifier != FlowColumn.url.identifier { layout.widths[column.identifier.rawValue] = column.width }
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
