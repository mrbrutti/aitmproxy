import Foundation
import Testing
@testable import AitmproxyKit

/// The rows `FilterMatchTests` filters, each with its detail. Thirteen rows because the suite
/// asserts over every field a filter can read: each row carries at least one value an
/// assertion needs that no other row has — a method, a status class, a state, the scope, an
/// origin, a mark, a client, a duration, a size, a query, a header or a body. Expected lists
/// name rows by `seq`.
private enum FilterInputs {
    static let obscura = ClientInfo(name: "obscura", monogram: "o")
    static let curl = ClientInfo(name: "curl", monogram: "$")
    static let safari = ClientInfo(name: "Safari", monogram: "S")
    static let python = ClientInfo(name: "python3", monogram: "P")
    static let aitm = ClientInfo(name: "aitm", monogram: "a")

    static let rows: [FlowRow] = [
        Make.row(seq: 1, host: "api.shop-staging.test", path: "/api/products", query: "category=electronics&limit=20",
                 status: 200, client: obscura, duration: .milliseconds(89), requestBytes: 412, responseBytes: 18_200),
        Make.row(seq: 2, method: .put, host: "api.shop-staging.test", path: "/api/cart/items/42", status: 200,
                 client: obscura, duration: .milliseconds(67), requestBytes: 1_100, responseBytes: 640, mark: .cyan),
        Make.row(seq: 3, host: "cdn.shop-staging.test", path: "/assets/app.3f1c.js", status: 304, client: obscura,
                 duration: .milliseconds(21), requestBytes: 388, responseBytes: 0),
        Make.row(seq: 4, method: .post, host: "telemetry.vendor-analytics.example", path: "/v2/batch", status: 204,
                 client: safari, duration: .milliseconds(143), requestBytes: 6_400, responseBytes: 0, tls: .tunnelled,
                 inScope: false),
        Make.row(seq: 5, host: "api.shop-staging.test", path: "/api/orders", query: "page=3", status: 502, client: curl,
                 duration: .milliseconds(1_210), requestBytes: 402, responseBytes: 1_900),
        Make.row(seq: 6, host: "api.shop-staging.test", path: "/api/orders", query: "page=3", status: 200, isReplay: true,
                 origin: .agent, client: aitm, duration: .milliseconds(412), requestBytes: 402, responseBytes: 22_700),
        Make.row(seq: 7, kind: .websocket, method: .ws, scheme: "wss", host: "api.shop-staging.test",
                 path: "/ws/notifications", status: 101, client: obscura, wsFrames: (sent: 3, received: 4)),
        Make.row(seq: 8, host: "api.shop-staging.test", path: "/api/search",
                 query: "q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", status: 200, origin: .agent, client: aitm,
                 duration: .milliseconds(149), requestBytes: 511, responseBytes: 9_300, mark: .red),
        Make.row(seq: 9, method: .delete, host: "api.shop-staging.test", path: "/api/account/delete", state: .killed,
                 client: curl, requestBytes: 298),
        Make.row(seq: 10, method: .post, host: "auth.shop-staging.test", path: "/api/auth/login", state: .paused,
                 client: curl, requestBytes: 186, edited: true),
        Make.row(seq: 11, host: "cdn.shop-staging.test", path: "/assets/hero.webp", state: .pending, client: obscura,
                 requestBytes: 371),
        Make.row(seq: 12, method: .patch, host: "api.shop-staging.test", path: "/api/cart", status: 422, client: python,
                 duration: .milliseconds(121), requestBytes: 903, responseBytes: 212),
        Make.row(seq: 13, method: .head, host: "api.shop-staging.test", path: "/api/health", status: 200, client: python,
                 duration: .milliseconds(25), requestBytes: 120, responseBytes: 0, tls: .pinnedOrFailed),
    ]

    static let obscuraUA = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 obscura/1.0"
    static let curlUA = "curl/8.7.1"
    static let safariUA = "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15"
    static let pythonUA = "python-requests/2.32.3"
    static let aitmUA = "aitmproxy/0.1.0"
    static let api = "api.shop-staging.test"
    static let json = "application/json"

    /// The product listing every 200 JSON response below carries.
    static let listing = """
    {
      "ok": true,
      "items": [
        { "id": 7, "name": "Headphones", "price": 129.0 },
        { "id": 9, "name": "Charger", "price": 24.5 }
      ],
      "page": 3,
      "total": 42
    }
    """
    /// The body of every cart edit (the PUT, the telemetry POST and the PATCH).
    static let cartEdit = "{\n  \"quantity\": 2,\n  \"note\": \"gift wrap\"\n}"
    static let login = "{\n  \"email\": \"ops@shop-staging.test\",\n  \"password\": \"correct-horse-battery\",\n  \"remember\": true\n}"
    static let badGateway = "<html><body><h1>502 Bad Gateway</h1></body></html>"
    static let unprocessable = "{\n  \"error\": \"validation_failed\",\n  \"fields\": {\n    \"quantity\": \"must be ≥ 1\"\n  }\n}"

    /// A request with `host`, `accept` and `user-agent`, plus a JSON `content-type` when it has a body.
    static func request(_ line: String, host: String, accept: String = "application/json", agent: String,
                        body: String? = nil, extra: [(String, String)] = []) -> HTTPMessage {
        var headers = [("host", host), ("accept", accept), ("user-agent", agent)]
        if body != nil { headers.append(("content-type", json)) }
        return Make.message(line, headers + extra, body: body)
    }

    /// A response from the envoy edge: `content-type`, `server` and, when sized, `content-length`.
    static func response(_ status: Int, _ type: String, length: Int64? = nil, body: String? = nil) -> HTTPMessage {
        var headers = [("content-type", type), ("server", "envoy")]
        if let length { headers.append(("content-length", String(length))) }
        return Make.response(status, headers, body: body)
    }

    /// One detail per row, keyed by the row's id.
    static let details: [FlowID: FlowDetail] = Dictionary(uniqueKeysWithValues: [
        Make.detail(id: "flow-1",
                    request: request("GET /api/products?category=electronics&limit=20 HTTP/2", host: api, agent: obscuraUA),
                    response: response(200, json, length: 18_200, body: listing)),
        Make.detail(id: "flow-2",
                    request: request("PUT /api/cart/items/42 HTTP/2", host: api, agent: obscuraUA, body: cartEdit),
                    response: response(200, json, length: 640, body: listing)),
        Make.detail(id: "flow-3",
                    request: request("GET /assets/app.3f1c.js HTTP/2", host: "cdn.shop-staging.test", accept: "*/*",
                                     agent: obscuraUA),
                    response: response(304, "application/javascript", length: 0)),
        Make.detail(id: "flow-4",
                    request: request("POST /v2/batch HTTP/2", host: "telemetry.vendor-analytics.example", agent: safariUA,
                                     body: cartEdit),
                    response: response(204, json, length: 0)),
        Make.detail(id: "flow-5",
                    request: request("GET /api/orders?page=3 HTTP/2", host: api, agent: curlUA),
                    response: response(502, "text/html; charset=utf-8", length: 1_900, body: badGateway)),
        Make.detail(id: "flow-6",
                    request: request("GET /api/orders?page=3 HTTP/2", host: api, agent: aitmUA),
                    response: response(200, json, length: 22_700, body: listing)),
        Make.detail(id: "flow-7",
                    request: request("WS /ws/notifications HTTP/2", host: api, agent: obscuraUA),
                    response: Make.response(101, [("server", "envoy")])),
        Make.detail(id: "flow-8",
                    request: request("GET /api/search?q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E HTTP/2", host: api,
                                     agent: aitmUA),
                    response: response(200, json, length: 9_300, body: listing)),
        Make.detail(id: "flow-9", request: request("DELETE /api/account/delete HTTP/2", host: api, agent: curlUA)),
        Make.detail(id: "flow-10",
                    request: request("POST /api/auth/login HTTP/2", host: "auth.shop-staging.test", accept: "*/*",
                                     agent: curlUA, body: login, extra: [("x-forwarded-for", "127.0.0.1")])),
        Make.detail(id: "flow-11",
                    request: request("GET /assets/hero.webp HTTP/2", host: "cdn.shop-staging.test", agent: obscuraUA)),
        Make.detail(id: "flow-12",
                    request: request("PATCH /api/cart HTTP/2", host: api, agent: pythonUA, body: cartEdit),
                    response: response(422, json, length: 212, body: unprocessable)),
        Make.detail(id: "flow-13",
                    request: request("HEAD /api/health HTTP/2", host: api, agent: pythonUA),
                    response: response(200, json, length: 0)),
    ].map { ($0.id, $0) })
}

/// The rows of `FilterInputs` that pass `text`, by seq, each with its detail.
private func seqs(_ text: String) throws -> [Int] {
    let filter = try CompiledFilter(parsing: text)
    return FilterInputs.rows
        .filter { filter.matches(FilterSubject(row: $0, detail: FilterInputs.details[$0.id])) }
        .map(\.seq)
}

/// The rows of `FilterInputs` that pass `text` with no detail loaded.
private func rowOnlySeqs(_ text: String) throws -> [Int] {
    let filter = try CompiledFilter(parsing: text)
    return FilterInputs.rows.filter { filter.matches(FilterSubject(row: $0)) }.map(\.seq)
}

private func parseError(_ text: String) -> FilterParseError? {
    do {
        _ = try FilterExpression.parse(text)
        return nil
    } catch {
        return error
    }
}

private let allSeqs = Array(1...13)
/// The rows with a status: everything but the killed, paused and pending rows.
private let withResponse = [1, 2, 3, 4, 5, 6, 7, 8, 12, 13]

@Suite struct FilterSyntaxTests {
    @Test(arguments: [
        "~u login",
        "~m POST & ~s",
        "~d cdn | ~c 304",
        "!~marked",
        "~hq \"user-agent: curl\"",
        "(~m GET | ~m HEAD) & ~d api",
        "~m GET & (~d cdn | ~m HEAD)",
        "~m GET & ~d cdn | ~m HEAD",
        "~q",
        "!~q",
        "~bs:json fields.quantity=2",
        "~duration:lt 30",
        "~u:glob *orders*",
        "~origin agent & !~replay",
        "~u \"a b\" & ~t json",
        "!(~m GET & ~s)",
        "~text \"bad gateway\"",
        "~size 10000",
        "~h cookie",
        "~b:contains token",
        "~client:eq curl",
        "~mark red",
        "~mark:contains e",
        "~u \"\\\"quoted\\\"\"",
        "~u \"\"",
        "~scope out",
        "~state paused",
        "~ws sent",
        "~path:eq /api/me & ~query page",
        "~comment todo",
        "~c:gt 400",
        "(~u a & ~u b) & ~u c",
    ])
    func roundTrips(_ text: String) throws {
        let parsed = try FilterExpression.parse(text)
        #expect(parsed.text == text)
        #expect(try FilterExpression.parse(parsed.text) == parsed)
    }

    @Test func canonicalises() throws {
        #expect(try FilterExpression.parse("login").text == "~u login")
        #expect(try FilterExpression.parse("\"two words\"").text == "~u \"two words\"")
        #expect(try FilterExpression.parse("~hq x ~m POST").text == "~hq x & ~m POST")
        #expect(try FilterExpression.parse("!~s").text == "~q")
        #expect(try FilterExpression.parse("~mark:contains \"\"").text == "~marked")
        #expect(try FilterExpression.parse("~c:contains \"\"").text == "~s")
        #expect(try FilterExpression.parse("  ~u   a   &~m  GET ").text == "~u a & ~m GET")
        #expect(try FilterExpression.parse("~u:re a").text == "~u a")
        #expect(try FilterExpression.parse("~m:equals GET").text == "~m GET")
        #expect(try FilterExpression.parse("~u \"~m\"") == .term(.field(.url, .regex, "~m")))
        #expect(try FilterExpression.parse("!!~s").text == "!~q")
        #expect(try FilterExpression.parse("") == .matchAll)
        #expect(try FilterExpression.parse("   ") == .matchAll)
        #expect(FilterExpression.matchAll.text == "")
    }

    @Test func precedence() throws {
        let a = FilterExpression.term(.field(.url, .regex, "a"))
        let b = FilterExpression.term(.field(.url, .regex, "b"))
        let c = FilterExpression.term(.field(.url, .regex, "c"))
        #expect(try FilterExpression.parse("a & b | c") == .or([.and([a, b]), c]))
        #expect(try FilterExpression.parse("a | b & c") == .or([a, .and([b, c])]))
        #expect(try FilterExpression.parse("!a & b") == .and([.not(a), b]))
        #expect(try FilterExpression.parse("!(a & b)") == .not(.and([a, b])))
        #expect(try FilterExpression.parse("a & b & c") == .and([a, b, c]))
        #expect(try FilterExpression.parse("(a & b) & c") == .and([.and([a, b]), c]))
        #expect(try FilterExpression.parse("a (b | c)") == .and([a, .or([b, c])]))
    }

    @Test func quoting() throws {
        #expect(try FilterExpression.parse("~u \"a \\\\ b\"") == .term(.field(.url, .regex, "a \\ b")))
        #expect(try FilterExpression.parse("~u \"(x|y)\"") == .term(.field(.url, .regex, "(x|y)")))
        #expect(FilterTerm.quote("plain") == "plain")
        #expect(FilterTerm.quote("has space") == "\"has space\"")
        #expect(FilterTerm.quote("") == "\"\"")
        #expect(FilterTerm.quote("!bang") == "\"!bang\"")
        #expect(FilterTerm.quote("a\"b") == "\"a\\\"b\"")
    }

    @Test func errorsCarryOffsets() {
        #expect(parseError("~u")?.kind == .missingValue)
        #expect(parseError("~u")?.offset == 2)
        #expect(parseError("~u &")?.offset == 3)
        #expect(parseError("~zz 1")?.kind == .unknownTerm)
        #expect(parseError("~zz 1")?.offset == 0)
        #expect(parseError("~m GET & ~")?.kind == .unknownTerm)
        #expect(parseError("~m GET & ~")?.offset == 9)
        #expect(parseError("~u:foo x")?.kind == .unknownOperator)
        #expect(parseError("~u:foo x")?.offset == 3)
        #expect(parseError("~u:text x")?.kind == .unknownOperator)
        #expect(parseError("~s:re")?.kind == .operatorNotAllowed)
        #expect(parseError("~s:re")?.offset == 3)
        #expect(parseError("~text:re x")?.kind == .operatorNotAllowed)
        #expect(parseError("(~u a")?.kind == .expectedClosingParenthesis)
        #expect(parseError("(~u a")?.offset == 5)
        #expect(parseError("~u a)")?.kind == .trailingInput)
        #expect(parseError("~u a)")?.offset == 4)
        #expect(parseError("~u \"abc")?.kind == .unterminatedQuote)
        #expect(parseError("~u \"abc")?.offset == 3)
        #expect(parseError("~u a & ")?.kind == .unexpectedEnd)
        #expect(parseError("~u a & ")?.offset == 7)
        #expect(parseError("& ~u a")?.kind == .unexpectedToken)
        #expect(parseError("& ~u a")?.offset == 0)
        #expect(parseError("~u a | )")?.kind == .unexpectedToken)
        #expect(parseError("~u a | )")?.offset == 7)
        #expect(parseError("~mark")?.kind == .missingValue)
        #expect(parseError("()")?.kind == .unexpectedToken)
        #expect(parseError("~u a") == nil)
        #expect(parseError("~marked login") == nil)
        #expect(parseError("~u a &")?.description == "Expected a filter (at 6)")
    }
}

@Suite struct FilterMatchTests {
    @Test func method() throws {
        #expect(try seqs("~m POST") == [4, 10])
        #expect(try seqs("~m post") == [4, 10])
        #expect(try seqs("~m:re ^P") == [2, 4, 10, 12])
        #expect(try seqs("~m ^P") == [])
    }

    @Test func status() throws {
        #expect(try seqs("~c 5") == [5])
        #expect(try seqs("~c 50") == [5])
        #expect(try seqs("~c 502") == [5])
        #expect(try seqs("~c 200") == [1, 2, 6, 8, 13])
        #expect(try seqs("~c 20") == [1, 2, 4, 6, 8, 13])
        #expect(try seqs("~c:contains 0") == [1, 2, 3, 4, 5, 6, 7, 8, 13])
        #expect(try seqs("~c:gt 400") == [5, 12])
        #expect(try seqs("~c:lt 300") == [1, 2, 4, 6, 7, 8, 13])
    }

    @Test func responsePresence() throws {
        #expect(try seqs("~s") == withResponse)
        #expect(try seqs("~q") == [9, 10, 11])
        #expect(try seqs("!~s") == [9, 10, 11])
        #expect(try seqs("!~q") == withResponse)
        #expect(try rowOnlySeqs("~s") == withResponse)
    }

    @Test func scopeOriginReplay() throws {
        #expect(try seqs("~scope out") == [4])
        #expect(try seqs("~scope in") == allSeqs.filter { $0 != 4 })
        #expect(try seqs("~origin agent") == [6, 8])
        #expect(try seqs("~origin client").count == 11)
        #expect(try seqs("~origin human") == [])
        #expect(try seqs("~replay") == [6])
        #expect(try seqs("~origin agent & !~replay") == [8])
    }

    @Test func state() throws {
        #expect(try seqs("~state paused") == [10])
        #expect(try seqs("~state killed") == [9])
        #expect(try seqs("~state pending") == [11])
        #expect(try seqs("~state failed") == [])
        #expect(try seqs("~state complete") == [1, 2, 3, 4, 5, 6, 7, 8, 12, 13])
        // The Errors tile's set: transport failures, killed flows, or 5xx.
        #expect(try seqs("~state failed | ~state killed | ~c 5") == [5, 9])
    }

    @Test func marks() throws {
        #expect(try seqs("~marked") == [2, 8])
        #expect(try seqs("!~marked").count == 11)
        #expect(try seqs("~mark red") == [8])
        #expect(try seqs("~mark:eq cyan") == [2])
        #expect(try seqs("~mark:contains e") == [8])
    }

    @Test func urlHostPathQuery() throws {
        #expect(try seqs("~u login") == [10])
        #expect(try seqs("login") == [10])
        #expect(try seqs("~u orders") == [5, 6])
        #expect(try seqs("~u ^https://cdn") == [3, 11])
        #expect(try seqs("~d cdn") == [3, 11])
        #expect(try seqs("~d ^api\\.") == [1, 2, 5, 6, 7, 8, 9, 12, 13])
        #expect(try seqs("~path:eq /api/orders") == [5, 6])
        #expect(try seqs("~path /api/orders") == [5, 6])
        #expect(try seqs("~query page") == [5, 6])
        #expect(try seqs("~query:contains limit=20") == [1])
        #expect(try seqs("~query:contains \"\"") == [1, 5, 6, 8])
    }

    @Test func client() throws {
        #expect(try seqs("~client curl") == [5, 9, 10])
        #expect(try seqs("~client:eq python3") == [12, 13])
        #expect(try seqs("~client ^s") == [4])
    }

    @Test func durationAndSize() throws {
        #expect(try seqs("~duration 400") == [5, 6])
        #expect(try seqs("~duration:gt 400") == [5, 6])
        #expect(try seqs("~duration:lt 30") == [3, 13])
        #expect(try seqs("~duration:eq 89") == [1])
        #expect(try seqs("~size 10000") == [1, 6])
        #expect(try seqs("~size:lt 300") == [9, 10, 13])
        #expect(try seqs("~size:gt abc") == [])
    }

    @Test func comment() throws {
        #expect(try seqs("~comment foo") == [])
        var row = FilterInputs.rows[0]
        row.comment = "Check this one"
        let filter = try CompiledFilter(parsing: "~comment check")
        #expect(filter.matches(FilterSubject(row: row)))
        #expect(!filter.matches(FilterSubject(row: FilterInputs.rows[0])))
    }

    @Test func webSocketDirectionIsNotAvailableYet() throws {
        #expect(try seqs("~ws sent") == [])
        #expect(try seqs("~ws received") == [])
        #expect(FilterRow(.wsDirection, .equals, "sent").validationError == nil)
    }

    @Test func requestHeaders() throws {
        #expect(try seqs("~hq x-forwarded-for") == [10])
        #expect(try seqs("~hq \"user-agent: curl\"") == [5, 9, 10])
        #expect(try seqs("~hq:eq user-agent").count == 13)
        #expect(try seqs("~hq:eq \"host: auth.shop-staging.test\"") == [10])
        #expect(try seqs("~hq:eq \"host: nowhere\"") == [])
        #expect(try seqs("~hq:contains \"accept: */*\"") == [3, 10])
        #expect(try seqs("~hq:glob \"content-type: *json\"") == [2, 4, 10, 12])
        #expect(try seqs("~hq:glob json") == [])
    }

    @Test func responseHeadersAndAnyHeader() throws {
        #expect(try seqs("~hs server") == withResponse)
        #expect(try seqs("~hs:eq \"server: envoy\"") == withResponse)
        #expect(try seqs("~h envoy") == withResponse)
        #expect(try seqs("~h x-forwarded-for") == [10])
        #expect(try seqs("~h:eq accept").count == 13)
    }

    @Test func bodies() throws {
        #expect(try seqs("~bs \"Bad Gateway\"") == [5])
        #expect(try seqs("~bs validation_failed") == [12])
        #expect(try seqs("~bs Headphones") == [1, 2, 6, 8])
        #expect(try seqs("~bq password") == [10])
        #expect(try seqs("~bq quantity") == [2, 4, 12])
        #expect(try seqs("~b quantity") == [2, 4, 12])
        #expect(try seqs("~b:contains TOKEN") == [])
        #expect(try seqs("~bs:glob *gateway*") == [5])
        #expect(try seqs("~bs:eq x") == [])
    }

    @Test func contentType() throws {
        #expect(try seqs("~t html") == [5])
        // A JSON response (1, 2, 4, 6, 8, 12, 13) or a JSON request (2, 4, 10, 12); the 304 is JavaScript, the 101 has no type.
        #expect(try seqs("~t json") == [1, 2, 4, 6, 8, 10, 12, 13])
        #expect(try seqs("~t:eq \"text/html; charset=utf-8\"") == [5])
        #expect(try seqs("~t ^image/") == [])
    }

    @Test func fullText() throws {
        #expect(try seqs("~text envoy") == withResponse)
        #expect(try seqs("~text correct-horse") == [10])
        #expect(try seqs("~text shop-staging") == allSeqs.filter { $0 != 4 })
        #expect(try rowOnlySeqs("~text orders") == [5, 6])
        #expect(try rowOnlySeqs("~text envoy") == [])
    }

    @Test func wildcards() throws {
        #expect(try seqs("~u:glob *orders*") == [5, 6])
        #expect(try seqs("~u:glob orders") == [])
        #expect(try seqs("~d:glob *.shop-staging.test").count == 12)
        #expect(try seqs("~path:glob /api/cart/items/??") == [2])
        #expect(try seqs("~path:glob /api/cart/items/?") == [])
        #expect(try seqs("~path:glob /API/*") == [1, 2, 5, 6, 8, 9, 10, 12, 13])
        #expect(CompiledTerm.wildcardPattern("a.b*c?") == "^a\\.b.*c.$")
    }

    @Test func invalidRegexMatchesNothing() throws {
        #expect(try seqs("~u [a-") == [])
        #expect(try seqs("~u \"(\"") == [])
        #expect(FilterRow(.url, .regex, "[a-").validationError?.hasPrefix("Invalid regular expression") == true)
        #expect(try FilterExpression.parse("~u [a- | ~m GET").validationErrors.count == 1)
        #expect(try seqs("~u [a- | ~m GET") == [1, 3, 5, 6, 8, 11])
        #expect(FilterRow(.url, .regex, "[a-z]+").validationError == nil)
    }

    @Test func jsonPath() throws {
        #expect(try seqs("~bs:json fields.quantity") == [12])
        #expect(try seqs("~bs:json \"fields.quantity=must be ≥ 1\"") == [12])
        #expect(try seqs("~bs:json \"fields.quantity = MUST BE ≥ 1\"") == [12])
        #expect(try seqs("~bs:json fields.quantity=2") == [])
        #expect(try seqs("~bs:json fields.nothing") == [])
        #expect(try seqs("~bs:json items[0].name=Headphones") == [1, 2, 6, 8])
        #expect(try seqs("~bs:json items[1].price=24.5") == [1, 2, 6, 8])
        #expect(try seqs("~bs:json $.items[0].price=129") == [1, 2, 6, 8])
        #expect(try seqs("~bs:json items[9].id") == [])
        #expect(try seqs("~bs:json page=3") == [1, 2, 6, 8])
        #expect(try seqs("~bs:json ok=true") == [1, 2, 6, 8])
        #expect(try seqs("~bs:json items=x") == [])
        #expect(try seqs("~bq:json remember=true") == [10])
        #expect(try seqs("~bq:json email=ops@shop-staging.test") == [10])
        #expect(try seqs("~b:json quantity=2") == [2, 4, 12])
        #expect(try seqs("~bs:json error") == [12])
    }

    @Test func jsonPathValidation() {
        #expect(FilterRow(.url, .jsonPath, "a").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "a..b").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "a[x]").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "").validationError != nil)
        #expect(FilterRow(.responseBody, .jsonPath, "items[0].id").validationError == nil)
        #expect(JSONPath("items[0].id")?.steps == [.key("items"), .index(0), .key("id")])
        #expect(JSONPath("$.a.b")?.steps == [.key("a"), .key("b")])
        #expect(JSONPath("[2]")?.steps == [.index(2)])
        #expect(JSONPath("a[0][1]")?.steps == [.key("a"), .index(0), .index(1)])
    }

    @Test func numericValidation() {
        #expect(FilterRow(.host, .greaterThan, "5").validationError != nil)
        #expect(FilterRow(.duration, .greaterThan, "abc").validationError != nil)
        #expect(FilterRow(.duration, .greaterThan, "500").validationError == nil)
        #expect(FilterRow(.size, .lessThan, " 1.5 ").validationError == nil)
        #expect(FilterRow(.status, .equals, "x").validationError == nil)
    }

    @Test func combinations() throws {
        #expect(try seqs("~m POST & ~scope out") == [4])
        #expect(try seqs("~m POST | ~m PATCH") == [4, 10, 12])
        #expect(try seqs("!(~m GET | ~m HEAD) & ~s") == [2, 4, 7, 12])
        #expect(try seqs("~m GET & ~d cdn | ~m HEAD") == [3, 11, 13])
        #expect(try seqs("~m GET & (~d cdn | ~m HEAD)") == [3, 11])
        #expect(try seqs("~d cdn ~c 304") == [3])
        #expect(try seqs("") == allSeqs)
    }

    @Test func missingDetailEvaluatesFalse() throws {
        #expect(try rowOnlySeqs("~hq host") == [])
        #expect(try rowOnlySeqs("!~hq host") == allSeqs)
        #expect(try rowOnlySeqs("~bs a") == [])
        #expect(try rowOnlySeqs("~b a") == [])
        #expect(try rowOnlySeqs("~h a") == [])
        #expect(try rowOnlySeqs("~t json") == [])
        #expect(try rowOnlySeqs("~bs:json a") == [])
        #expect(try rowOnlySeqs("~m POST") == [4, 10])
    }

    @Test func binaryAndOversizedBodies() throws {
        let row = FilterInputs.rows[0]
        var detail = try #require(FilterInputs.details[row.id])
        let needle = try CompiledFilter(parsing: "~bs needle")
        let needleText = try CompiledFilter(parsing: "~bs:contains needle")
        let anyA = try CompiledFilter(parsing: "~bs a")
        // "needle" starts exactly at the scan limit: not seen.
        detail.response?.body = Data(repeating: UInt8(ascii: "a"), count: CompiledFilter.bodyScanLimit) + Data("needle".utf8)
        let beyond = FilterSubject(row: row, detail: detail)
        #expect(!needle.matches(beyond))
        #expect(!needleText.matches(beyond))
        #expect(anyA.matches(beyond))
        // "needle" ends exactly at the scan limit: seen.
        detail.response?.body = Data(repeating: UInt8(ascii: "a"), count: CompiledFilter.bodyScanLimit - 6) + Data("needle".utf8)
        let within = FilterSubject(row: row, detail: detail)
        #expect(needle.matches(within))
        #expect(needleText.matches(within))
        detail.response?.body = Data([0xFF, 0xFE, 0x00, 0x41])
        let binary = FilterSubject(row: row, detail: detail)
        let letterA = try CompiledFilter(parsing: "~bs A")
        let json = try CompiledFilter(parsing: "~bs:json a")
        #expect(letterA.matches(binary))
        #expect(!json.matches(binary))
    }

    @Test func conveniencesAgreeWithCompiledFilter() throws {
        let expression = try FilterExpression.parse("~m POST")
        let stack = try #require(expression.stack)
        for row in FilterInputs.rows {
            let subject = FilterSubject(row: row)
            let expected = CompiledFilter(expression).matches(subject)
            #expect(expression.matches(subject) == expected)
            #expect(stack.matches(subject) == expected)
        }
    }
}

@Suite struct FilterHighlightTests {
    @Test func containsAndRegex() throws {
        let body = "<h1>502 Bad Gateway</h1>"
        let contains = try CompiledFilter(parsing: "~bs:contains gateway")
        #expect(contains.matchRanges(in: body, field: .responseBody).map { String(body[$0]) } == ["Gateway"])
        #expect(contains.matchRanges(in: body, field: .requestBody).isEmpty)
        let regex = try CompiledFilter(parsing: "~bs \\d+")
        #expect(regex.matchRanges(in: body, field: .responseBody).map { String(body[$0]) } == ["1", "502", "1"])
        #expect(regex.matchRanges(in: body, field: .url).isEmpty)
    }

    @Test func fullTextAndAnyHeaderSpanFields() throws {
        let text = "x-a: one\nx-b: One"
        let full = try CompiledFilter(parsing: "~text one")
        #expect(full.matchRanges(in: text, field: .requestHeader).count == 2)
        #expect(full.matchRanges(in: text, field: .path).count == 2)
        let header = try CompiledFilter(parsing: "~h:contains x-")
        #expect(header.matchRanges(in: text, field: .responseHeader).count == 2)
        #expect(header.matchRanges(in: text, field: .responseBody).isEmpty)
        let body = try CompiledFilter(parsing: "~b one")
        #expect(body.matchRanges(in: text, field: .requestBody).count == 2)
        #expect(body.matchRanges(in: text, field: .requestHeader).isEmpty)
    }

    @Test func negatedEqualsAndWildcardContributeNothing() throws {
        let text = "aaaa"
        #expect(try CompiledFilter(parsing: "!~bs:contains aa").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "!(~bs aa | ~m GET)").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs:eq aaaa").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs:glob a*").matchRanges(in: text, field: .responseBody).isEmpty)
        #expect(try CompiledFilter(parsing: "~bs [").matchRanges(in: text, field: .responseBody).isEmpty)
    }

    @Test func mergesOverlaps() throws {
        let text = "aaaa"
        let ranges = try CompiledFilter(parsing: "~bs:contains aa | ~bs:contains aaa")
            .matchRanges(in: text, field: .responseBody)
        #expect(ranges.count == 1)
        #expect(ranges.first.map { String(text[$0]) } == "aaaa")
        let separate = try CompiledFilter(parsing: "~bs:contains a").matchRanges(in: "a-a", field: .responseBody)
        #expect(separate.count == 2)
    }
}

@Suite struct FilterStackTests {
    @Test func stackPrints() {
        let stack = FilterStack(rows: [FilterRow(.method, .equals, "POST"), FilterRow(.scope, .equals, "out")])
        #expect(stack.text == "~m POST & ~scope out")
        #expect(FilterStack(rows: stack.rows, combinator: .or).text == "~m POST | ~scope out")
        #expect(FilterStack(rows: [FilterRow(.url, .contains, "login", negated: true)]).text == "!~u:contains login")
        #expect(FilterStack(rows: [FilterRow(.status, .contains, "")]).text == "~s")
        #expect(FilterStack(rows: [FilterRow(.status, .contains, "", negated: true)]).text == "~q")
        #expect(FilterStack(rows: [FilterRow(.mark, .contains, "")]).text == "~marked")
        #expect(FilterStack(rows: [FilterRow(.responseBody, .jsonPath, "user.role=admin")]).text
                == "~bs:json user.role=admin")
        #expect(FilterStack(rows: [FilterRow(.duration, .greaterThan, "500")]).text == "~duration 500")
        #expect(FilterStack(rows: [FilterRow(.size, .lessThan, "10")]).text == "~size:lt 10")
        #expect(FilterStack(rows: [FilterRow(.requestHeader, .contains, "cookie: a=b")]).text
                == "~hq:contains \"cookie: a=b\"")
        #expect(FilterStack(rows: [FilterRow(.url, .fullText, "x")]).text == "~text x")
        #expect(FilterStack(rows: [FilterRow(.path, .fullText, "x")]).text == "~text x")
        #expect(FilterStack().text == "")
        #expect(FilterStack().expression == .matchAll)
        #expect(FilterStack(rows: [], combinator: .or).expression == .matchAll)
    }

    @Test func flatExpressionsBecomeStacks() throws {
        let and = try #require(FilterStack(expression: FilterExpression.parse("~m POST & ~scope out & !~marked")))
        #expect(and.combinator == .and)
        #expect(and.rows == [
            FilterRow(.method, .equals, "POST"),
            FilterRow(.scope, .equals, "out"),
            FilterRow(.mark, .contains, "", negated: true),
        ])
        let or = try #require(FilterStack(expression: FilterExpression.parse("~m POST | ~m PATCH")))
        #expect(or.combinator == .or)
        #expect(or.rows.count == 2)
        let single = try #require(FilterStack(expression: FilterExpression.parse("~q")))
        #expect(single.rows == [FilterRow(.status, .contains, "", negated: true)])
        let bare = try #require(FilterStack(expression: FilterExpression.parse("login")))
        #expect(bare.rows == [FilterRow(.url, .regex, "login")])
        let empty = try #require(FilterStack(expression: FilterExpression.parse("")))
        #expect(empty.isEmpty)
    }

    @Test func nestedOrRowlessExpressionsHaveNoStack() throws {
        #expect(try FilterExpression.parse("~m GET & (~d cdn | ~m HEAD)").stack == nil)
        #expect(try FilterExpression.parse("!(~m GET | ~m HEAD)").stack == nil)
        #expect(try FilterExpression.parse("!!~s").stack == nil)
        #expect(try FilterExpression.parse("~h cookie").stack == nil)
        #expect(try FilterExpression.parse("~b token").stack == nil)
        #expect(try FilterExpression.parse("~replay").stack == nil)
        #expect(try FilterExpression.parse("~m GET & ~replay").stack == nil)
    }

    @Test func stackRoundTripsThroughText() throws {
        let stack = FilterStack(rows: [
            FilterRow(.url, .wildcard, "*orders*"),
            FilterRow(.requestHeader, .regex, "user-agent: curl", negated: true),
            FilterRow(.responseBody, .jsonPath, "items[0].id=7"),
            FilterRow(.duration, .lessThan, "500"),
            FilterRow(.origin, .equals, "agent"),
        ], combinator: .or)
        let back = try #require(FilterStack(expression: FilterExpression.parse(stack.text)))
        #expect(back == stack)
    }

    @Test func codable() throws {
        let stack = FilterStack(rows: [FilterRow(.host, .wildcard, "*.test"), FilterRow(.status, .greaterThan, "399", negated: true)],
                                combinator: .or)
        let data = try JSONEncoder().encode(stack)
        #expect(try JSONDecoder().decode(FilterStack.self, from: data) == stack)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains("\"wildcard\""))
        #expect(json.contains("\"greaterThan\""))
    }

    @Test func fieldAndOperatorCatalog() {
        #expect(FilterField.allCases.count == 20)
        #expect(FilterOperator.allCases.count == 8)
        #expect(FilterField.allCases.allSatisfy { !$0.title.isEmpty && !$0.operators.isEmpty })
        #expect(FilterOperator.allCases.allSatisfy { !$0.title.isEmpty })
        #expect(FilterField.status.operators.contains(.greaterThan))
        #expect(!FilterField.url.operators.contains(.jsonPath))
        #expect(FilterField.responseBody.operators.contains(.jsonPath))
        #expect(Set(FilterField.allCases.map(\.key)).count == FilterField.allCases.count)
    }
}

@Suite struct SavedFilterStoreTests {
    @Test func roundTripsThroughFile() throws {
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(filePath: $0) }
            ?? FileManager.default.temporaryDirectory
        let directory = tmp.appending(path: "aitmproxy-filter-tests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = SavedFilterStore(stateDirectory: directory)
        #expect(store.fileURL.lastPathComponent == "filters.json")
        #expect(try store.load() == [])

        let filters = [
            SavedFilter(name: "Agent traffic", expression: "~origin agent"),
            SavedFilter(name: "Errors", expression: "~c:gt 399 | ~q"),
        ]
        try store.save(filters)
        #expect(FileManager.default.fileExists(atPath: store.fileURL.path(percentEncoded: false)))
        #expect(try store.load() == filters)

        try store.save([])
        #expect(try store.load() == [])

        for saved in filters {
            _ = try FilterExpression.parse(saved.expression)
        }
    }
}
