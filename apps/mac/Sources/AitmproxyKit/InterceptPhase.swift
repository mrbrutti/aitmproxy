import Foundation

/// Where an intercepted flow is parked (F3): at the request, before it goes
/// upstream, or at the response head, before any response byte reaches the
/// client. `flow.get` labels both "intercepted"; a flow parked at the response
/// already carries one, so its summary has a status and its detail a response.
public enum InterceptPhase: String, Hashable, Sendable {
    case request, response

    /// The phase a paused row is parked at, or nil when it is not paused. The
    /// summary's status (polled every 500 ms while parked) says "response" before
    /// the detail is fetched; a paused row with neither is parked at the request.
    public static func parked(_ row: FlowRow, detail: FlowDetail?) -> InterceptPhase? {
        guard row.state == .paused else { return nil }
        return row.status != nil || detail?.response != nil ? .response : .request
    }

    /// The summary strip's pill: `Paused · request` / `Paused · response`.
    public var title: String { "Paused · \(rawValue)" }
}

extension FlowDetail {
    /// The message an editor at `phase` edits, as the proxy holds it: the request,
    /// or the response (nil until the parked response's detail has arrived).
    public func message(for phase: InterceptPhase) -> HTTPMessage? {
        phase == .response ? response : request
    }

    /// The copy Revert goes back to: the request as it arrived (the core's backup),
    /// or the parked response itself.
    public func original(for phase: InterceptPhase) -> HTTPMessage? {
        phase == .response ? response : originalRequest ?? request
    }
}

extension HTTPMessage {
    /// A response starts `HTTP/x <status>`; a request starts with its method.
    public var isResponse: Bool { startLine.hasPrefix("HTTP/") }

    /// The status code of a response start line (`HTTP/2 200 OK` → 200): three digits,
    /// 100–599 as the core accepts (`mutate.rs::as_status`); nil for a request or a bad line.
    public var statusCode: Int? {
        guard isResponse else { return nil }
        let parts = startLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, parts[1].count == 3, let code = Int(parts[1]), (100...599).contains(code) else { return nil }
        return code
    }
}
