import AitmproxyKit
import AppKit

/// The flow list's two context menus: the row menu, read from `VerbTable` so its titles,
/// printed keys and enabled rules are the Flow menu's and the intercept bar's; and the
/// header's Columns menu (S-008). Both are rebuilt when they open.
extension FlowTableView.Coordinator {
    func makeRowMenu() -> NSMenu {
        let menu = NSMenu(title: "Flow")
        menu.delegate = self
        // The table decides what is enabled; AppKit's validation would turn everything on.
        menu.autoenablesItems = false
        rowMenu = menu
        return menu
    }

    func makeColumnsMenu() -> NSMenu {
        let menu = NSMenu(title: "Columns")
        menu.delegate = self
        return menu
    }

    /// Rebuilt on open, so check marks and titles follow the current state.
    func menuNeedsUpdate(_ menu: NSMenu) {
        if menu === rowMenu { return buildRowMenu(menu) }
        menu.removeAllItems()
        for column in FlowColumn.allCases {
            let item = NSMenuItem(title: column.menuTitle, action: #selector(toggleColumn(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = column.rawValue
            // The check mark is the user's choice; a column hidden to fit the pane shows mixed.
            item.state = userHidden.contains(column) ? .off : (autoHidden.contains(column) ? .mixed : .on)
            if autoHidden.contains(column) { item.toolTip = "Hidden to fit the pane" }
            item.isEnabled = !column.alwaysVisible
            menu.addItem(item)
        }
        menu.addItem(.separator())
        let reset = NSMenuItem(title: "Reset Columns", action: #selector(resetColumns), keyEquivalent: "")
        reset.target = self
        menu.addItem(reset)
    }

    // MARK: Row menu (foundation §2.7: every verb, with its key printed)

    private func buildRowMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        guard let row = targetRow else { return }
        let context = verbContext(for: row)
        var group: VerbGroup?
        for item in VerbTable.items(for: context) {
            // ⌘\ is the intercept bar's Kill; the row shows Kill/Delete (`d`) for the same flow.
            if item.verb == .kill { continue }
            // The bulk verbs appear only with several rows selected.
            if item.group == .selection, context.selectedCount <= 1 { continue }
            if let group, group != item.group { menu.addItem(.separator()) }
            group = item.group
            if case .mark = item.verb {
                let mark = NSMenuItem(title: item.title, action: nil, keyEquivalent: "")
                mark.submenu = markMenu(for: row)
                mark.isEnabled = item.enabled
                menu.addItem(mark)
                continue
            }
            let menuItem = NSMenuItem(title: item.title, action: #selector(rowMenuChosen(_:)), keyEquivalent: item.key ?? "")
            menuItem.keyEquivalentModifierMask = []
            menuItem.target = self
            menuItem.representedObject = item.verb
            menuItem.isEnabled = item.enabled
            menu.addItem(menuItem)
        }
        if !row.inScope {
            menu.addItem(.separator())
            let note = NSMenuItem(title: VerbTable.outOfScopeReason(row.authority), action: nil, keyEquivalent: "")
            note.isEnabled = false
            menu.addItem(note)
        }
    }

    func markMenu(for row: FlowRow) -> NSMenu {
        let menu = NSMenu(title: "Mark")
        menu.autoenablesItems = false
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

    @objc private func rowMenuChosen(_ sender: NSMenuItem) {
        guard let verb = sender.representedObject as? FlowVerb else { return }
        perform(verb)
    }

    // MARK: Columns menu

    @objc private func toggleColumn(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, let column = FlowColumn(rawValue: id), !column.alwaysVisible else { return }
        if userHidden.contains(column) { userHidden.remove(column) } else { userHidden.insert(column) }
        fitColumns()
        saveLayoutSoon()
    }

    @objc private func resetColumns() {
        guard let table else { return }
        userHidden = []
        for (index, column) in FlowColumn.allCases.enumerated() {
            guard let tableColumn = table.tableColumn(withIdentifier: column.identifier) else { continue }
            tableColumn.width = column.width
            let current = table.column(withIdentifier: column.identifier)
            if current != index, current >= 0 { table.moveColumn(current, toColumn: index) }
        }
        if let url = parent.layoutURL { try? FileManager.default.removeItem(at: url) }
        fitColumns()
    }
}
