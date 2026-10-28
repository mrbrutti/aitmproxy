import AitmBusClient
import AitmproxyKit
import AppKit

/// Compose (S-042–S-044) and editing a paused request (S-037, S-038).
extension Session {
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

    /// Header names the draft removed. `flow.mutate` has no removal form yet, so
    /// these are NOT applied — the UI surfaces them instead of silently dropping
    /// the action (an operator must never think a header was removed when it wasn't).
    func removedHeaders(_ id: FlowID) -> [String] {
        guard let draft = editDrafts[id], let detail = details[id] else { return [] }
        return RequestEdits.removedHeaderNames(from: detail.request, to: draft)
    }

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
}
