import AitmproxyKit
import AppKit
import SwiftUI

/// The flow list (foundation §2.10a): an `NSTableView`, because SwiftUI's
/// `Table` cannot hold 28px rows at 50 appends/s. Columns per §2.7; rows
/// append without animation; selection is the `active` tint.
struct FlowTableView: NSViewRepresentable {
    var rows: [FlowRow]
    @Binding var selection: Set<FlowID>
    /// The row the inspector should follow (the last clicked one).
    var onFocus: (FlowID?) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.rowHeight = Tok.Size.Row.dense
        table.intercellSpacing = .zero
        table.style = .plain
        table.usesAlternatingRowBackgroundColors = false
        table.gridStyleMask = []
        table.backgroundColor = Tok.Ground.surface.nsColor
        table.selectionHighlightStyle = .regular
        table.allowsMultipleSelection = true
        table.allowsColumnReordering = true
        table.allowsColumnResizing = true
        table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .uniformColumnAutoresizingStyle
        table.focusRingType = .none
        table.headerView = FlowHeaderView(frame: NSRect(x: 0, y: 0, width: 0, height: Tok.Size.columnHeader))
        for column in FlowColumn.allCases {
            let c = NSTableColumn(identifier: column.identifier)
            c.title = column.title
            c.width = column.width
            c.minWidth = column.minWidth
            c.resizingMask = column == .url ? .autoresizingMask : .userResizingMask
            c.headerCell = FlowHeaderCell(textCell: column.title)
            c.headerCell.alignment = column.numeric ? .right : .left
            table.addTableColumn(c)
        }
        table.dataSource = context.coordinator
        table.delegate = context.coordinator
        table.target = context.coordinator
        table.doubleAction = #selector(Coordinator.doubleClick)
        context.coordinator.table = table

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
        let wanted = IndexSet(rows.indices.filter { selection.contains(rows[$0].id) })
        if wanted != table.selectedRowIndexes {
            coordinator.syncing = true
            table.selectRowIndexes(wanted, byExtendingSelection: false)
            coordinator.syncing = false
        }
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: FlowTableView
        var rows: [FlowRow] = []
        weak var table: NSTableView?
        /// True while `updateNSView` pushes SwiftUI's selection into the table.
        var syncing = false

        init(_ parent: FlowTableView) { self.parent = parent }

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
            let flow = rows[row]
            let view = tableView.makeView(withIdentifier: tableColumn.identifier, owner: nil) as? FlowCellView
                ?? FlowCellView(column: column)
            view.identifier = tableColumn.identifier
            view.configure(flow)
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
    }
}

/// The columns, in default order (foundation §2.7 "Flow list").
enum FlowColumn: String, CaseIterable {
    case dot, seq, url, client, method, status, time, duration, request, response, ssl, edited, origin, mark

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
        }
    }

    var width: CGFloat {
        switch self {
        case .dot: 24
        case .seq: 52
        case .url: 320
        case .client: 96
        case .method: 72
        case .status: 72
        case .time: 124
        case .duration: 72
        case .request: 72
        case .response: 72
        case .ssl: 40
        case .edited: 52
        case .origin: 60
        case .mark: 20
        }
    }

    var minWidth: CGFloat { self == .url ? 200 : width }

    var numeric: Bool {
        switch self {
        case .seq, .duration, .request, .response: true
        default: false
        }
    }
}
