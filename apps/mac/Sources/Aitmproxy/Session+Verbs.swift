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
        case .resume: pendingEditCount(id) > 0 ? applyAndResume(id) : resume(id)
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
            selection.remove(id)
            if focused == id { focused = nil }
        }
    }
}
