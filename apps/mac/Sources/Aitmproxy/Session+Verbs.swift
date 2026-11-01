import AitmBusClient
import AitmproxyKit
import AppKit

/// Intents (foundation §4.5, §4.6): every action a row, the intercept bar, a menu or the palette can take.
extension Session {
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
    /// Runs an action; a failure lands in `lastError` instead of being lost.
    func perform(_ what: String, _ work: @escaping () async throws -> Void) {
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

    func kill(_ id: FlowID) {
        let mode = killMode
        perform("kill") { [self] in try await actions.kill(id, mode: mode) }
    }

    /// Saves the set; re-arms with the rules when intercept is on (the core takes them after F3).
    func setBreakpointRules(_ rules: BreakpointRules) {
        breakpointRules = rules
        try? rules.save(to: rulesURL)
        if interceptArmed {
            perform("set rules") { [self] in try await actions.setIntercept(true, rules: rules.enabled) }
        }
    }

    /// Resume or kill every paused row in the selection, in capture order; reports skips.
    func resumeSelected() { bulk("Resumed") { [self] id in resume(id) } }
    func killSelected() { bulk("Killed") { [self] id in kill(id) } }

    func bulk(_ verb: String, _ act: (FlowID) -> Void) {
        let chosen = focusedSelectedRows
        let paused = chosen.filter { $0.state == .paused }
        for row in paused { act(row.id) }
        let skipped = chosen.count - paused.count
        lastError = skipped > 0 ? "\(verb) \(paused.count) · skipped \(skipped) (not paused)" : nil
    }

    var selectedRows: [FlowRow] { rows.filter { selection.contains($0.id) } }

    /// The rows selected in the pane the inspector follows: the split view's second list has
    /// its own selection, and a verb on one of its rows must count that one.
    var focusedSelectedRows: [FlowRow] {
        let selected = focusedPane == 1 ? secondSelection : selection
        return rows.filter { selected.contains($0.id) }
    }

    func replay(_ id: FlowID) {
        perform("replay") { [self] in
            if let newID = try await actions.replay(id) { select(newID) }
        }
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
        perform(on ? "resume proxy" : "pause proxy") { [self] in try await actions.setCapturing(on) }
    }

    /// Clear asks first when flows are paused (they would be dropped mid-flight). Once the core
    /// has cleared, what was dropped stays in the app for one undo step — Edit ▸ Undo Clear (⌘Z)
    /// or the status bar's Undo — for `clearNoticeSeconds`; then the copy is released and the
    /// step withdrawn, so captured traffic never outlives what the operator was told (D2, rule 43).
    func clearSession(confirm: (Int) -> Bool = { _ in true }) {
        let pausedCount = paused.count
        if pausedCount > 0, !confirm(pausedCount) { return }
        let dropped = ClearedFlows(rows: rows, details: details, wsDetails: wsDetails, l4Details: l4Details,
                                   selection: selection, focused: focused)
        restoredFlows = []
        forgetClearedFlows()
        perform("clear") { [self] in
            try await actions.clear()
            if !dropped.rows.isEmpty { offerUndo(for: dropped) }
        }
    }

    /// How long Undo is offered; the self-test shortens it to prove the lapse.
    static var clearNoticeSeconds: Double = 8

    private func offerUndo(for dropped: ClearedFlows) {
        clearedFlows = dropped
        registerClearUndo()
        clearNotice = ClearNotice(count: dropped.count)
        clearNoticeTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.clearNoticeSeconds))
            guard !Task.isCancelled else { return }
            self?.forgetClearedFlows()
        }
    }

    /// Registers the one "Undo Clear" step on the flow list's undo manager. Any step still there
    /// (a second Clear racing the first's round trip) is withdrawn first: one step at a time.
    private func registerClearUndo() {
        flowUndoManager.removeAllActions()
        flowUndoManager.beginUndoGrouping()
        flowUndoManager.registerUndo(withTarget: self) { session in
            // AppKit runs undo handlers on the thread that called undo(): the responder chain
            // and the self-test both do so on the main thread.
            MainActor.assumeIsolated { session.undoClear() }
        }
        flowUndoManager.setActionName("Clear")
        flowUndoManager.endUndoGrouping()
    }

    /// Releases the dropped copy, withdraws the undo step and hides the notice.
    func forgetClearedFlows() {
        clearNoticeTask?.cancel()
        clearNoticeTask = nil
        clearedFlows = nil
        clearNotice = nil
        // The list's manager holds Clear's step alone; while an undo runs, the manager drops the
        // step itself and a removal mid-undo is refused.
        if !flowUndoManager.isUndoing { flowUndoManager.removeAllActions() }
    }

    /// Puts back what the last Clear dropped. The rows and their cached details are the app's
    /// copy: the core has already dropped the flows, so the list and the inspector show them
    /// again, while a verb that needs the core (replay, resume) reports the core's answer.
    func undoClear() {
        guard let dropped = clearedFlows else { return }
        forgetClearedFlows()
        restoredFlows = dropped.rows
        rows = ClearedFlows.merge(restored: dropped.rows, newer: rows)
        details.merge(dropped.details) { current, _ in current }
        wsDetails.merge(dropped.wsDetails) { current, _ in current }
        l4Details.merge(dropped.l4Details) { current, _ in current }
        selection = dropped.selection
        focused = dropped.focused
    }

    /// What the verb table needs to know about a row: its drafts, pin state and the selection
    /// of the list it sits in (the focused pane's; pane 1 is the split view's second list).
    func verbContext(for id: FlowID) -> VerbContext? {
        guard let row = rows.first(where: { $0.id == id }) else { return nil }
        let chosen = focusedSelectedRows
        return VerbContext(row: row,
                           pendingEdits: pendingEditCount(id),
                           pinned: isPinned(.host(row.authority)),
                           selectedCount: chosen.count,
                           selectedPausedCount: chosen.filter { $0.state == .paused }.count)
    }

    /// The verb table for a row (every surface's titles, keys and enabled rules).
    func verbItems(for id: FlowID?) -> [VerbItem] {
        VerbTable.items(for: id.flatMap(verbContext(for:)))
    }

    /// One verb item for a row; with no row the default, disabled item.
    func verbItem(_ verb: FlowVerb, for id: FlowID?) -> VerbItem {
        VerbTable.item(verb, for: id.flatMap(verbContext(for:)))
    }

    /// The only entry for a row verb, from the keyboard, the context menu, the Flow menu or the
    /// intercept bar (S-010). The table's enabled rule gates it: an off verb reports why.
    func perform(_ verb: FlowVerb, on id: FlowID) {
        guard let context = verbContext(for: id) else { return }
        let row = context.row
        let item = VerbTable.item(verb, for: context)
        guard item.enabled else {
            lastError = item.disabledReason
            return
        }
        switch verb {
        case .resume: context.pendingEdits > 0 ? applyAndResume(id) : resume(id)
        case .kill: kill(id)
        case .delete: deleteOrKill(id)
        case .replay: replay(id)
        case .editAndReplay: editAndReplay(id)
        case .resumeSelected: resumeSelected()
        case .killSelected: killSelected()
        case .edit: editPaused(id)
        case .mark(let color): mark(id, color)
        case .comment: select(id)
        case .buildPoC: buildPoCFlowID = id
        case .pinHost: context.pinned ? unpin(.host(row.authority)) : pin(.host(row.authority))
        case .copyURL:
            Pasteboard.copy(row.url, sensitive: true)
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
            restoredFlows.removeAll { $0.id == id }
            selection.remove(id)
            if focused == id { focused = nil }
        }
    }
}
