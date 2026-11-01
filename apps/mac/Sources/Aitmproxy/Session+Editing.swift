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

    /// Where a paused flow is parked (S-041): at the request, or at the response
    /// head once the detail carries a response. nil when the flow is not paused.
    func parkedPhase(_ id: FlowID) -> InterceptPhase? {
        guard let row = rows.first(where: { $0.id == id }) else { return nil }
        return InterceptPhase.parked(row, detail: details[id])
    }

    /// The message a paused flow's draft edits, as the proxy holds it: the request,
    /// or the response when the flow is parked there (nil until that response's
    /// detail has been fetched).
    func editTarget(_ id: FlowID) -> HTTPMessage? {
        guard let detail = details[id], let phase = parkedPhase(id) else { return nil }
        return detail.message(for: phase)
    }

    /// A row parked at the response head whose cached detail predates the park (it
    /// was selected while parked at the request, or before any detail arrived) has
    /// no response to edit yet: fetch the detail again.
    func refreshParkedResponse(_ id: FlowID) {
        guard parkedPhase(id) == .response, details[id]?.response == nil else { return }
        Task { await loadDetail(id) }
    }

    /// The draft that belongs to the flow's current park. A request draft left
    /// behind when a flow moved on to its response park (resumed by the agent, say)
    /// is not a response draft, and a flow that is no longer paused has no draft at
    /// all: both are ignored here and replaced by the next edit.
    func currentDraft(_ id: FlowID) -> HTTPMessage? {
        guard let phase = parkedPhase(id), let draft = editDrafts[id], draft.isResponse == (phase == .response) else { return nil }
        return draft
    }

    /// Edits the draft would send, against what the proxy currently holds.
    func pendingEdits(_ id: FlowID) -> RequestEdits {
        guard let draft = currentDraft(id), let target = editTarget(id) else { return RequestEdits() }
        return draft.isResponse ? RequestEdits.diff(fromResponse: target, to: draft) : RequestEdits.diff(from: target, to: draft)
    }

    func pendingEditCount(_ id: FlowID) -> Int { pendingEdits(id).changeCount }

    /// Header names the draft removed. `flow.mutate` has no removal form yet, so
    /// these are NOT applied — the UI surfaces them instead of silently dropping
    /// the action (an operator must never think a header was removed when it wasn't).
    func removedHeaders(_ id: FlowID) -> [String] {
        guard let draft = currentDraft(id), let target = editTarget(id) else { return [] }
        return RequestEdits.removedHeaderNames(from: target, to: draft)
    }

    /// Header names the draft changed to more than one value (two `set-cookie`
    /// lines, say). `flow.mutate` carries one value per name, so the diff leaves
    /// these out rather than collapse them; the UI says they keep their original values.
    func unencodableHeaders(_ id: FlowID) -> [String] {
        guard let draft = currentDraft(id), let target = editTarget(id) else { return [] }
        return RequestEdits.unencodableHeaderNames(from: target, to: draft)
    }

    /// `Apply & Resume`: mutate with the pending edits, then resume (§4.5). The
    /// detail is fetched again afterwards, so the inspector shows the message as
    /// the core forwarded it (the edited status, headers and body), not the copy
    /// cached when the flow was selected while parked.
    func applyAndResume(_ id: FlowID) {
        let edits = pendingEdits(id)
        perform("apply & resume") { [self] in
            if !edits.isEmpty { try await actions.mutate(id, edits: edits) }
            editDrafts[id] = nil
            try await actions.resume(id)
            if !edits.isEmpty { await loadDetail(id) }
        }
    }

    /// `e`: the paused row's Raw tab, editable — the Response pane's when the flow
    /// is parked at the response (S-041), else the Request pane's.
    func editPaused(_ id: FlowID) {
        select(id)
        if parkedPhase(id) == .response {
            responseTab = .raw
        } else {
            requestTab = .raw
        }
    }
}
