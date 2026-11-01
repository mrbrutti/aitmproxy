@testable import AitmproxyKit
import Foundation

/// Parameterised builders for the Kit unit tests (spec 2026-10-31-remove-fake-data-ui-modes,
/// D5 ruling of 2026-11-01). They shorten the Kit's long initialisers and nothing more: every
/// value a builder puts into a row, message or detail is a parameter; a default is a shape
/// (`https`, `HTTP/2`, a finished row), never a sample; no builder carries a host, a path, a
/// body or a list. Each test file declares the literal inputs its own assertions need, next
/// to the tests that read them.
enum Make {
    /// A flow row. `id` defaults to `flow-<seq>`; `state` defaults to `.complete` because most
    /// rows a test builds have finished — a parked, pending, killed or failed row says so.
    static func row(
        id: String? = nil, seq: Int, kind: FlowKind = .http, method: HTTPMethod = .get, scheme: String = "https",
        host: String, path: String, query: String? = nil, status: Int? = nil, state: FlowState = .complete,
        isReplay: Bool = false, origin: FlowOrigin = .client, client: ClientInfo? = nil, startedAt: Date? = nil,
        duration: Duration? = nil, requestBytes: Int64? = nil, responseBytes: Int64? = nil,
        tls: TLSState = .decrypted, edited: Bool = false, comment: String? = nil, mark: MarkColor? = nil,
        inScope: Bool = true, wsFrames: (sent: Int, received: Int)? = nil
    ) -> FlowRow {
        FlowRow(
            id: FlowID(id ?? "flow-\(seq)"), seq: seq, kind: kind, method: method, scheme: scheme, authority: host,
            path: path, query: query, status: status, state: state, isReplay: isReplay, origin: origin, client: client,
            startedAt: startedAt, duration: duration, requestBytes: requestBytes, responseBytes: responseBytes, tls: tls,
            edited: edited, comment: comment, mark: mark, inScope: inScope, wsFrames: wsFrames)
    }

    /// `HTTPMessage(startLine:headers:body:)` with `(name, value)` header pairs and a UTF-8 body.
    static func message(_ startLine: String, _ headers: [(String, String)] = [], body: String? = nil) -> HTTPMessage {
        HTTPMessage(startLine: startLine, headers: headers.map { HTTPMessage.Header($0.0, $0.1) },
                    body: body.map { Data($0.utf8) })
    }

    /// A response whose start line is `HTTP/2 <status> <reason>`, with `(name, value)` headers and a UTF-8 body.
    static func response(_ status: Int, _ headers: [(String, String)] = [], body: String? = nil) -> HTTPMessage {
        message("HTTP/2 \(status) \(StatusText.reason(status))".trimmingCharacters(in: .whitespaces), headers, body: body)
    }

    /// A flow detail. `connection` defaults to a bare HTTP/2 connection with no addresses.
    static func detail(
        id: String, request: HTTPMessage, response: HTTPMessage? = nil,
        connection: ConnectionInfo = ConnectionInfo(httpVersion: "HTTP/2"),
        originalRequest: HTTPMessage? = nil, timing: FlowTiming? = nil
    ) -> FlowDetail {
        FlowDetail(id: FlowID(id), request: request, response: response, connection: connection,
                   originalRequest: originalRequest, timing: timing)
    }
}

extension FlowRow {
    /// A copy with another id and sequence number.
    func withID(_ raw: String, seq: Int) -> FlowRow {
        var copy = self
        copy.id = FlowID(raw)
        copy.seq = seq
        return copy
    }
}
