import AitmBusClient
import AitmproxyKit

/// Live full-detail fetch (F5 `flow.detail`). `flow.get` (the poll) is a summary
/// with no headers/body/cookies; when a flow is selected we fetch its full detail
/// so the inspector can show — and the operator can edit — the real request and
/// response. No-op on fixtures (detail is already loaded) or if the core lacks
/// `flow.detail`.
extension Session {
    func ensureDetail(for id: FlowID?) {
        guard let id, !Store.usesFixtures, commandRunner != nil,
              tools.contains(where: { $0.name == "flow.detail" }) else { return }
        Task { await loadDetail(id) }
    }

    /// Fetches and stores one flow's detail. Re-fetched on each selection so a
    /// response that arrived after the first look shows up. A WebSocket flow
    /// decodes into `wsDetails` (handshake + frames, S-045); HTTP into `details`.
    func loadDetail(_ id: FlowID) async {
        guard let value = try? await runCommand("flow.detail", ["id": .string(id.raw), "body": .string("inline")]) else { return }
        if let detail = FlowDetail(detailJSON: value) {
            details[id] = detail
        } else if let ws = WSDetail(detailJSON: value) {
            wsDetails[id] = ws
        }
    }
}
