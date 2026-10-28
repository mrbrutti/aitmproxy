import AitmproxyKit
import Foundation

/// What the shell's buttons do. Live, every call is a bus command (§4.5,
/// §4.6); on fixtures the session itself changes, so the UI stays
/// demonstrable and testable without a proxy.
protocol FlowActions: AnyObject {
    func setIntercept(_ enabled: Bool) async throws
    func resume(_ id: FlowID) async throws
    func kill(_ id: FlowID) async throws
    func mutate(_ id: FlowID, edits: RequestEdits) async throws
    func replay(_ id: FlowID) async throws -> FlowID?
    func send(_ request: RequestEdits) async throws -> FlowID?
    func addScope(_ host: String) async throws
}

/// Fixture behaviour: resume completes the flow with a 200 after a beat,
/// kill greys it out, replay appends a copy with `↻`.
final class FixtureActions: FlowActions {
    unowned let session: Session

    init(session: Session) { self.session = session }

    func setIntercept(_ enabled: Bool) async throws {
        session.interceptArmed = enabled
    }

    func resume(_ id: FlowID) async throws {
        guard let index = session.rows.firstIndex(where: { $0.id == id }) else { return }
        session.rows[index].state = .pending
        try? await Task.sleep(for: .milliseconds(400))
        guard let again = session.rows.firstIndex(where: { $0.id == id }) else { return }
        session.rows[again].state = .complete
        session.rows[again].status = 200
        session.rows[again].duration = .milliseconds(412)
        session.rows[again].responseBytes = 318
        if var detail = session.details[id] {
            detail.response = Fixtures.previousLoginResponse
            session.details[id] = detail
        }
    }

    func kill(_ id: FlowID) async throws {
        guard let index = session.rows.firstIndex(where: { $0.id == id }) else { return }
        session.rows[index].state = .killed
        session.rows[index].status = nil
    }

    func mutate(_ id: FlowID, edits: RequestEdits) async throws {
        guard var detail = session.details[id] else { return }
        if detail.originalRequest == nil { detail.originalRequest = detail.request }
        var request = detail.request
        for (name, value) in edits.headers ?? [:] {
            request.headers.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
            request.headers.append(.init(name, value))
        }
        if let body = edits.body { request.body = body }
        detail.request = request
        session.details[id] = detail
        if let index = session.rows.firstIndex(where: { $0.id == id }) { session.rows[index].edited = true }
    }

    func replay(_ id: FlowID) async throws -> FlowID? {
        guard let source = session.rows.first(where: { $0.id == id }) else { return nil }
        var copy = source
        copy.id = FlowID(UUID().uuidString.lowercased())
        copy.seq = (session.rows.map(\.seq).max() ?? 0) + 1
        copy.isReplay = true
        copy.origin = .human
        copy.client = Fixtures.aitm
        copy.startedAt = .now
        copy.state = source.status == nil ? .pending : .complete
        copy.edited = false
        session.rows.append(copy)
        session.details[copy.id] = session.details[id].map { FlowDetail(id: copy.id, request: $0.request, response: $0.response, connection: $0.connection) }
        return copy.id
    }

    func send(_ request: RequestEdits) async throws -> FlowID? {
        let id = FlowID(UUID().uuidString.lowercased())
        let (path, query) = FlowSummary.splitQuery(request.path ?? "/")
        let row = FlowRow(
            id: id, seq: (session.rows.map(\.seq).max() ?? 0) + 1, method: HTTPMethod(request.method ?? "GET"),
            scheme: request.scheme ?? "https", authority: request.authority ?? "", path: path, query: query,
            status: 200, state: .complete, origin: .human, client: Fixtures.aitm, startedAt: .now,
            duration: .milliseconds(120), requestBytes: Int64(request.body?.count ?? 0), responseBytes: 0,
            inScope: session.scopeHosts.contains { request.authority?.hasSuffix($0) ?? false })
        session.rows.append(row)
        session.details[id] = Fixtures.detail(for: row)
        return id
    }

    func addScope(_ host: String) async throws {
        if !session.scopeHosts.contains(host) { session.scopeHosts.append(host) }
        for index in session.rows.indices where session.rows[index].authority.hasSuffix(host) {
            session.rows[index].inScope = true
        }
    }
}
