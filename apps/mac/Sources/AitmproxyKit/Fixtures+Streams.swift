import Foundation

/// Fixtures for the inspector stories S-019, S-020, S-025 and S-026: a
/// streaming completion, a cookie exchange, a timed login and a pair of
/// flows to diff. Rows for the two new flows sit beside them so a preview
/// can select them; they are not in `Fixtures.rows`.
extension Fixtures {
    // MARK: S-025 SSE

    public static let sseRow = FlowRow(
        id: id(60), seq: 60, method: .post, scheme: "https", authority: "ai.shop-staging.test",
        path: "/v1/chat/completions", status: 200, state: .complete, client: python, startedAt: at(40.2),
        duration: ms(2_410), requestBytes: 612, responseBytes: 1_480)

    /// An OpenAI-style stream: one comment line, six content deltas, `[DONE]`.
    public static let sseDetail = FlowDetail(
        id: sseRow.id,
        request: HTTPMessage(
            startLine: "POST /v1/chat/completions HTTP/2",
            headers: [
                .init("host", "ai.shop-staging.test"),
                .init("content-type", "application/json"),
                .init("accept", "text/event-stream"),
                .init("authorization", "Bearer sk-test-…"),
                .init("user-agent", userAgent(python)),
            ],
            body: Data("""
            {
              "model": "shop-assistant",
              "stream": true,
              "messages": [{ "role": "user", "content": "Where is order 4471?" }]
            }
            """.utf8)),
        response: HTTPMessage(
            startLine: "HTTP/2 200 OK",
            headers: [
                .init("content-type", "text/event-stream; charset=utf-8"),
                .init("cache-control", "no-cache"),
                .init("server", "envoy"),
            ],
            body: Data(sseBody.utf8)),
        connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                   sni: "ai.shop-staging.test", clientAddress: "127.0.0.1:52060",
                                   serverAddress: "10.0.4.20:443"),
        timing: FlowTiming(dns: ms(3), connect: ms(14), tls: ms(27), wait: ms(506), download: ms(1_860)))

    public static let sseDeltas = ["Order", " 4471", " shipped", " on Monday", " and arrives", " Thursday."]

    static let sseBody: String = {
        var out = ": keep-alive\n\n"
        for (n, delta) in sseDeltas.enumerated() {
            let chunk = #"{"id":"chatcmpl-7Q","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"\#(delta)"},"finish_reason":null}]}"#
            out += "id: \(n + 1)\ndata: \(chunk)\n\n"
        }
        out += "data: [DONE]\n\n"
        return out
    }()

    // MARK: S-019 cookies

    public static let cookieRow = FlowRow(
        id: id(61), seq: 61, method: .get, scheme: "https", authority: "api.shop-staging.test",
        path: "/api/me", status: 200, state: .complete, client: obscura, startedAt: at(41.0),
        duration: ms(58), requestBytes: 498, responseBytes: 412)

    /// A request with three cookies (one quoted) and a response that sets two.
    public static let cookieDetail = FlowDetail(
        id: cookieRow.id,
        request: HTTPMessage(
            startLine: "GET /api/me HTTP/2",
            headers: [
                .init("host", "api.shop-staging.test"),
                .init("accept", "application/json"),
                .init("cookie", "session=9f1c2a7e; prefs=\"theme=dark; density=compact\"; ab_test=B"),
                .init("user-agent", userAgent(obscura)),
            ]),
        response: HTTPMessage(
            startLine: "HTTP/2 200 OK",
            headers: [
                .init("content-type", "application/json; charset=utf-8"),
                .init("set-cookie", "session=9f1c2a7e; Domain=.shop-staging.test; Path=/; "
                    + "Expires=Wed, 28 Oct 2026 11:04:58 GMT; HttpOnly; Secure; SameSite=Lax"),
                .init("set-cookie", "csrf=4d2e9c; Path=/api; Max-Age=3600; Secure; SameSite=Strict"),
                .init("cache-control", "no-store"),
                .init("server", "envoy"),
            ],
            body: Data("{\n  \"id\": 1042,\n  \"email\": \"ops@shop-staging.test\",\n  \"role\": \"admin\"\n}".utf8)),
        connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                   sni: "api.shop-staging.test", clientAddress: "127.0.0.1:52061",
                                   serverAddress: "10.0.4.12:443"),
        timing: FlowTiming(dns: .zero, connect: .zero, tls: .zero, wait: ms(41), download: ms(17)))

    // MARK: S-020 timing

    /// The paused login with every phase reported: 4 + 18 + 31 + 289 + 70 = 412 ms.
    public static let timedDetail: FlowDetail = {
        var detail = pausedLogin
        detail.timing = FlowTiming(dns: ms(4), connect: ms(18), tls: ms(31), wait: ms(289), download: ms(70))
        return detail
    }()

    // MARK: S-026 diff

    /// Two product listings that differ in one request header and one JSON field.
    public static let diffPair: (FlowDetail, FlowDetail) = {
        let left = detail(for: rows[0])
        var right = left
        right.id = id(62)
        right.request.headers = left.request.headers.map { header in
            header.name == "accept" ? .init("accept", "application/json; q=0.9, */*; q=0.1") : header
        }
        right.request.headers.append(.init("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.…"))
        if var response = right.response, let text = response.bodyText {
            response.body = Data(text.replacingOccurrences(of: "\"page\": 3", with: "\"page\": 4").utf8)
            right.response = response
        }
        return (left, right)
    }()
}
