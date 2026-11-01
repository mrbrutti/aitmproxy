import Testing
@testable import AitmproxyKit

/// Eight HTTP/WS rows and one raw-L4 session for `FlowQueryTests`: four hosts, one of them
/// out of scope; curl on three rows; one WebSocket; a JSON response on the first row only.
private enum FlowQueryInputs {
    static let obscura = ClientInfo(name: "obscura")
    static let curl = ClientInfo(name: "curl")
    static let safari = ClientInfo(name: "Safari")

    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", status: 200, client: obscura),
        Make.row(seq: 2, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 client: safari, tls: .tunnelled, inScope: false),
        Make.row(seq: 3, host: "cdn.shop-staging.test", path: "/assets/app.js", status: 304, client: obscura),
        Make.row(seq: 4, host: "api.shop-staging.test", path: "/api/orders", status: 502, client: curl),
        Make.row(seq: 5, kind: .websocket, method: .ws, scheme: "wss", host: "api.shop-staging.test",
                 path: "/ws/notifications", status: 101, client: obscura),
        Make.row(seq: 6, method: .delete, host: "api.shop-staging.test", path: "/api/account", state: .killed, client: curl),
        Make.row(seq: 7, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused, client: curl),
        Make.row(seq: 8, host: "cdn.shop-staging.test", path: "/assets/hero.webp", state: .pending, client: obscura),
    ]

    /// Details for the two rows with a body: a JSON listing and an HTML error page.
    static let details: [FlowID: FlowDetail] = [
        rows[0].id: Make.detail(
            id: rows[0].id.raw,
            request: Make.message("GET /api/products HTTP/2", [("host", "api.shop-staging.test")]),
            response: Make.response(200, [("content-type", "application/json")], body: "{\"ok\": true}")),
        rows[3].id: Make.detail(
            id: rows[3].id.raw,
            request: Make.message("GET /api/orders HTTP/2", [("host", "api.shop-staging.test")]),
            response: Make.response(502, [("content-type", "text/html")], body: "<h1>502 Bad Gateway</h1>")),
    ]

    /// One captured UDP session. An L4 row has no client and its authority is its bind, so no pin reaches it.
    static let l4Rows: [FlowRow] = [
        L4Flow(id: FlowID("l4-1"), sessionState: .capture, interface: "lo0", filter: "udp port 9", packetCount: 1,
               injectedCount: 0,
               packets: [L4Packet(index: 0, dir: .outbound, length: 42, injected: false, layers: ["IPv4", "UDP"])])
            .row(seq: 9, inScope: true),
    ]
}

/// `FlowQuery` over the rows above: scope, group, chip, filter, sort and pins.
@Suite struct FlowQueryTests {
    let rows = FlowQueryInputs.rows
    let details = FlowQueryInputs.details

    @Test func emptyQueryIsIdentity() {
        #expect(FlowQuery().apply(rows, details: details) == rows)
        #expect(!FlowQuery().isNarrowing)
    }

    @Test func scopeGroupAndChip() {
        #expect(FlowQuery(inScopeOnly: true).apply(rows, details: details).count == 7)
        #expect(FlowQuery(group: .client("curl")).apply(rows, details: details).count == 3)
        #expect(FlowQuery(group: .host("cdn.shop-staging.test")).apply(rows, details: details).map(\.seq) == [3, 8])
        #expect(FlowQuery(chip: .websocket).apply(rows, details: details).map(\.seq) == [5])
        #expect(FlowQuery(chip: .json).apply(rows, details: details).map(\.seq) == [1])
    }

    @Test func filterAndSortCompose() throws {
        let expr = try FilterExpression.parse("~m POST | ~c 502")
        let q = FlowQuery(filter: expr, sort: FlowSort(key: .status, ascending: false))
        // The 502 first, the 204 next, the parked POST (no status yet) last.
        #expect(q.apply(rows, details: details).map(\.seq) == [4, 2, 7])
        let compiled = q.compiled()
        #expect(compiled.apply(rows, details: details).count == 3)
        #expect(q.isNarrowing)
    }

    @Test func pinnedQueryNarrowsToPinnedHostsAndApps() {
        let pins = Pins(hosts: ["auth.shop-staging.test"], apps: ["curl"])
        let rows = FlowQuery(pins: pins).apply(FlowQueryInputs.rows + FlowQueryInputs.l4Rows, details: [:])
        // curl's three flows (4, 6, 7) plus the auth host (7, already in): capture order. The L4 row matches neither.
        #expect(rows.map(\.seq) == [4, 6, 7])
        #expect(FlowQuery(pins: Pins()).apply(FlowQueryInputs.rows, details: [:]).isEmpty)
    }
}
