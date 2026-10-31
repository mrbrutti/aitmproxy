import AitmBusClient
import AitmproxyKit
import Foundation

/// What the shell's buttons do. Live, every call is a bus command (§4.5,
/// §4.6); on fixtures the session itself changes, so the UI stays
/// demonstrable and testable without a proxy.
protocol FlowActions: AnyObject {
    func setIntercept(_ enabled: Bool, rules: [BreakpointRule]) async throws
    func resume(_ id: FlowID) async throws
    func kill(_ id: FlowID, mode: KillMode) async throws
    func mutate(_ id: FlowID, edits: RequestEdits) async throws
    func replay(_ id: FlowID) async throws -> FlowID?
    func send(_ request: RequestEdits) async throws -> FlowID?
    func addScope(_ host: String) async throws
    /// F12: `scope.remove {host}`.
    func removeScope(_ host: String) async throws
    /// F6: `flow.mark {id, marks}` / `flow.comment {id, text}`.
    func mark(_ id: FlowID, color: MarkColor?) async throws
    func comment(_ id: FlowID, text: String) async throws
    /// F7: `proxy.pause` / `proxy.resume` / `flow.clear`.
    func setCapturing(_ on: Bool) async throws
    func clear() async throws
}

/// Fixture behaviour: resume completes the flow with a 200 after a beat,
/// kill greys it out, replay appends a copy with `↻`.
final class FixtureActions: FlowActions {
    unowned let session: Session

    init(session: Session) { self.session = session }

    func setIntercept(_ enabled: Bool, rules: [BreakpointRule]) async throws {
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

    func kill(_ id: FlowID, mode: KillMode) async throws {
        guard let index = session.rows.firstIndex(where: { $0.id == id }) else { return }
        if let status = mode.syntheticStatus {
            session.rows[index].state = .complete
            session.rows[index].status = status
            session.rows[index].duration = .milliseconds(1)
            session.rows[index].responseBytes = 0
        } else {
            session.rows[index].state = .killed
            session.rows[index].status = nil
        }
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
        if edits.method != nil || edits.path != nil {
            let parts = request.startLine.split(separator: " ").map(String.init)
            let version = parts.count > 2 ? parts[2] : "HTTP/2"
            request.startLine = "\(edits.method ?? parts.first ?? "GET") \(edits.path ?? (parts.count > 1 ? parts[1] : "/")) \(version)"
        }
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
        copy.mark = nil
        copy.comment = nil
        session.details[copy.id] = session.details[id].map { FlowDetail(id: copy.id, request: $0.request, response: $0.response, connection: $0.connection) }
        session.rows.append(copy)
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
        session.details[id] = Fixtures.detail(for: row)
        session.rows.append(row)
        return id
    }

    func addScope(_ host: String) async throws {
        if !session.scopeHosts.contains(host) { session.scopeHosts.append(host) }
        for index in session.rows.indices where session.rows[index].authority.hasSuffix(host) {
            session.rows[index].inScope = true
        }
    }

    func removeScope(_ host: String) async throws {
        session.scopeHosts.removeAll { $0 == host }
        for index in session.rows.indices {
            session.rows[index].inScope = session.scopeHosts.isEmpty || Scope.contains(session.rows[index].authority, in: session.scopeHosts)
        }
    }

    func mark(_ id: FlowID, color: MarkColor?) async throws {
        guard let index = session.rows.firstIndex(where: { $0.id == id }) else { return }
        session.rows[index].mark = color
    }

    func comment(_ id: FlowID, text: String) async throws {
        guard let index = session.rows.firstIndex(where: { $0.id == id }) else { return }
        session.rows[index].comment = text.isEmpty ? nil : text
    }

    func setCapturing(_ on: Bool) async throws {
        session.capturing = on
    }

    /// The self-test flips this to walk the failed-clear path (Undo must not be offered).
    var clearFails = false

    func clear() async throws {
        if clearFails { throw BusError.tool(message: "flow.clear refused (fixture)") }
        session.rows = []
        session.details = [:]
        session.select(nil)
    }
}
