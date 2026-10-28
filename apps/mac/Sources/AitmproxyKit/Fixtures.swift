import Foundation

/// Recorded-looking bus traffic for UI development and snapshots: the rows of
/// the reference mockup (docs/design/mockup/index.html), with request and
/// response messages for the inspector. The live bus replaces this once F4/F5 land.
public enum Fixtures {
    public static let obscura = ClientInfo(name: "obscura", monogram: "o", bundleID: "obscura")
    public static let curl = ClientInfo(name: "curl", monogram: "$")
    public static let safari = ClientInfo(name: "Safari", monogram: "S", bundleID: "com.apple.Safari")
    public static let python = ClientInfo(name: "python3", monogram: "P")
    public static let aitm = ClientInfo(name: "aitm", monogram: "a")

    public static let scope = ["api.shop-staging.test", "auth.shop-staging.test", "cdn.shop-staging.test"]

    /// 11:04:58 local on a fixed day, so snapshots never change.
    static let base: Date = {
        var c = DateComponents()
        c.year = 2026; c.month = 10; c.day = 27; c.hour = 11; c.minute = 4; c.second = 58
        c.nanosecond = 120_000_000
        return Calendar.current.date(from: c) ?? Date(timeIntervalSince1970: 0)
    }()

    static func at(_ seconds: Double) -> Date { base.addingTimeInterval(seconds) }
    static func ms(_ n: Int) -> Duration { .milliseconds(n) }
    static func id(_ n: Int) -> FlowID { FlowID(String(format: "0000%04d-0000-4000-8000-00000000%04d", n, n)) }

    public static let rows: [FlowRow] = [
        FlowRow(id: id(41), seq: 41, method: .get, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/products", query: "category=electronics&limit=20", status: 200, state: .complete,
                client: obscura, startedAt: at(0), duration: ms(89), requestBytes: 412, responseBytes: 18_200),
        FlowRow(id: id(42), seq: 42, method: .put, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/cart/items/42", status: 200, state: .complete, client: obscura, startedAt: at(1.181),
                duration: ms(67), requestBytes: 1_100, responseBytes: 640, mark: .cyan),
        FlowRow(id: id(43), seq: 43, method: .get, scheme: "https", authority: "cdn.shop-staging.test",
                path: "/assets/app.3f1c.js", status: 304, state: .complete, client: obscura, startedAt: at(1.894),
                duration: ms(21), requestBytes: 388, responseBytes: 0),
        FlowRow(id: id(44), seq: 44, method: .post, scheme: "https", authority: "telemetry.vendor-analytics.example",
                path: "/v2/batch", status: 204, state: .complete, client: safari, startedAt: at(3.652),
                duration: ms(143), requestBytes: 6_400, responseBytes: 0, tls: .tunnelled, inScope: false),
        FlowRow(id: id(45), seq: 45, method: .get, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/orders", query: "page=3", status: 502, state: .complete, client: curl, startedAt: at(5.77),
                duration: ms(1_210), requestBytes: 402, responseBytes: 1_900),
        FlowRow(id: id(46), seq: 46, method: .get, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/orders", query: "page=3", status: 200, state: .complete, isReplay: true, origin: .agent,
                client: aitm, startedAt: at(5.947), duration: ms(412), requestBytes: 402, responseBytes: 22_700),
        FlowRow(id: id(47), seq: 47, kind: .websocket, method: .ws, scheme: "wss", authority: "api.shop-staging.test",
                path: "/ws/notifications", status: 101, state: .complete, client: obscura, startedAt: at(6.846),
                wsFrames: (sent: 21, received: 17)),
        FlowRow(id: id(48), seq: 48, method: .get, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/search", query: "q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", status: 200,
                state: .complete, origin: .agent, client: aitm, startedAt: at(15.088), duration: ms(149),
                requestBytes: 511, responseBytes: 9_300, mark: .red),
        FlowRow(id: id(49), seq: 49, method: .delete, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/account/delete", state: .killed, client: curl, startedAt: at(21.282), requestBytes: 298),
        FlowRow(id: id(50), seq: 50, method: .post, scheme: "https", authority: "auth.shop-staging.test",
                path: "/api/auth/login", state: .paused, client: curl, startedAt: at(24.874), requestBytes: 186,
                edited: true),
        FlowRow(id: id(51), seq: 51, method: .get, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/me", state: .paused, client: obscura, startedAt: at(26.059), requestBytes: 344),
        FlowRow(id: id(52), seq: 52, method: .get, scheme: "https", authority: "cdn.shop-staging.test",
                path: "/assets/hero.webp", state: .pending, client: obscura, startedAt: at(36.389), requestBytes: 371),
        FlowRow(id: id(53), seq: 53, method: .patch, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/cart", status: 422, state: .complete, client: python, startedAt: at(36.694),
                duration: ms(121), requestBytes: 903, responseBytes: 212),
        FlowRow(id: id(54), seq: 54, method: .head, scheme: "https", authority: "api.shop-staging.test",
                path: "/api/health", status: 200, state: .complete, client: python, startedAt: at(37.483),
                duration: ms(25), requestBytes: 120, responseBytes: 0, tls: .pinnedOrFailed),
    ]

    /// The paused login (flow 50): one header edited while paused.
    public static let pausedLogin = FlowDetail(
        id: id(50),
        request: HTTPMessage(
            startLine: "POST /api/auth/login HTTP/2",
            headers: [
                .init("host", "auth.shop-staging.test"),
                .init("content-type", "application/json"),
                .init("accept", "*/*"),
                .init("user-agent", "curl/8.7.1"),
                .init("x-forwarded-for", "127.0.0.1"),
            ],
            body: Data("""
            {
              "email": "ops@shop-staging.test",
              "password": "correct-horse-battery",
              "remember": true
            }
            """.utf8)),
        response: nil,
        connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: "TLS 1.3", alpn: "h2",
                                   sni: "auth.shop-staging.test", clientAddress: "127.0.0.1:52114",
                                   serverAddress: "10.0.4.12:443"),
        originalRequest: HTTPMessage(
            startLine: "POST /api/auth/login HTTP/2",
            headers: [
                .init("host", "auth.shop-staging.test"),
                .init("content-type", "application/json"),
                .init("accept", "*/*"),
                .init("user-agent", "curl/8.7.1"),
            ],
            body: Data("""
            {
              "email": "ops@shop-staging.test",
              "password": "correct-horse-battery",
              "remember": true
            }
            """.utf8))
    )

    /// The last response to the login endpoint (flow 38), shown for reference while 50 is paused.
    public static let previousLoginResponse = HTTPMessage(
        startLine: "HTTP/2 200 OK",
        headers: [
            .init("content-type", "application/json; charset=utf-8"),
            .init("set-cookie", "session=9f1c…; HttpOnly; Secure; SameSite=Lax"),
            .init("cache-control", "no-store"),
            .init("content-length", "318"),
        ],
        body: Data("""
        {
          "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcHMiLCJyb2xlIjoiYWRtaW4ifQ.…",
          "expires_in": 3600,
          "user": {
            "id": 1042,
            "email": "ops@shop-staging.test",
            "role": "admin",
            "mfa_enrolled": false
          },
          "set_cookie": "session=…; HttpOnly; Secure; SameSite=Lax"
        }
        """.utf8))

    /// A plausible detail for any other fixture row, so every selection shows something.
    public static func detail(for row: FlowRow) -> FlowDetail {
        if row.id == pausedLogin.id { return pausedLogin }
        let pathAndQuery = row.query.map { "\(row.path)?\($0)" } ?? row.path
        let accept = row.path.hasSuffix(".js") ? "*/*" : "application/json"
        var reqHeaders: [HTTPMessage.Header] = [
            .init("host", row.authority),
            .init("accept", accept),
            .init("user-agent", userAgent(row.client)),
        ]
        var reqBody: Data?
        if [.post, .put, .patch].contains(row.method) {
            reqHeaders.append(.init("content-type", "application/json"))
            reqBody = Data("{\n  \"quantity\": 2,\n  \"note\": \"gift wrap\"\n}".utf8)
        }
        let request = HTTPMessage(startLine: "\(row.method.label) \(pathAndQuery) HTTP/2", headers: reqHeaders, body: reqBody)
        var response: HTTPMessage?
        if let status = row.status {
            let type: String
            var body: Data?
            if row.path.hasSuffix(".js") {
                type = "application/javascript"
            } else if row.path.hasSuffix(".webp") {
                type = "image/webp"
            } else if status == 204 || status == 304 || row.method == .head {
                type = "application/json"
            } else if status >= 500 {
                type = "text/html; charset=utf-8"
                body = Data("<html><body><h1>502 Bad Gateway</h1></body></html>".utf8)
            } else if status == 422 {
                type = "application/json"
                body = Data("{\n  \"error\": \"validation_failed\",\n  \"fields\": {\n    \"quantity\": \"must be ≥ 1\"\n  }\n}".utf8)
            } else {
                type = "application/json"
                body = Data("{\n  \"ok\": true,\n  \"items\": [\n    { \"id\": 7, \"name\": \"Headphones\", \"price\": 129.0 },\n    { \"id\": 9, \"name\": \"Charger\", \"price\": 24.5 }\n  ],\n  \"page\": 3,\n  \"total\": 42\n}".utf8)
            }
            var headers: [HTTPMessage.Header] = [.init("content-type", type), .init("server", "envoy")]
            if let n = row.responseBytes { headers.append(.init("content-length", String(n))) }
            response = HTTPMessage(startLine: "HTTP/2 \(status) \(StatusText.reason(status))", headers: headers, body: body)
        }
        return FlowDetail(
            id: row.id, request: request, response: response,
            connection: ConnectionInfo(httpVersion: "HTTP/2", tlsVersion: row.tls == .none ? nil : "TLS 1.3",
                                       alpn: row.tls == .none ? nil : "h2", sni: row.authority,
                                       clientAddress: "127.0.0.1:\(52_000 + row.seq)", serverAddress: "10.0.4.12:443"))
    }

    static func userAgent(_ client: ClientInfo?) -> String {
        switch client?.name {
        case "curl": "curl/8.7.1"
        case "python3": "python-requests/2.32.3"
        case "Safari": "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15"
        case "aitm": "aitmproxy/0.1.0"
        default: "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 obscura/1.0"
        }
    }
}
