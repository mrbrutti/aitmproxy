import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct FormatTests {
    @Test func bytes() {
        #expect(Format.bytes(Int64(0)) == "0 B")
        #expect(Format.bytes(Int64(412)) == "412 B")
        #expect(Format.bytes(Int64(1_100)) == "1.1 KB")
        #expect(Format.bytes(Int64(18_200)) == "18.2 KB")
        #expect(Format.bytes(Int64(196_000_000)) == "196 MB")
        #expect(Format.bytes(nil) == "—")
    }

    @Test func durations() {
        #expect(Format.duration(.milliseconds(89)) == "89 ms")
        #expect(Format.duration(.milliseconds(1_210)) == "1.21 s")
        #expect(Format.duration(.seconds(12.3)) == "12.3 s")
        #expect(Format.duration(.seconds(65)) == "1m 05s")
        #expect(Format.duration(nil) == "—")
    }

    @Test func time() {
        var c = DateComponents()
        c.year = 2026; c.month = 10; c.day = 27; c.hour = 11; c.minute = 4; c.second = 58; c.nanosecond = 120_000_000
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let date = cal.date(from: c)!
        #expect(Format.time(date, zone: TimeZone(identifier: "UTC")!) == "11:04:58.120")
    }
}

@Suite struct FlowSummaryTests {
    @Test func decodesHTTPSummary() throws {
        let json: JSONValue = [
            "id": "3f1c0d2e-0000-4000-8000-000000000001", "kind": "http", "intercept": "intercepted",
            "is_replay": false, "method": "POST", "scheme": "https", "authority": "auth.shop-staging.test",
            "path": "/api/auth/login?x=1", "status": .null, "request_bytes": 412,
        ]
        let summary = try #require(FlowSummary(json: json))
        #expect(summary.intercept == .intercepted)
        #expect(summary.status == nil)
        let row = summary.row(seq: 50)
        #expect(row.method == .post)
        #expect(row.path == "/api/auth/login")
        #expect(row.query == "x=1")
        #expect(row.state == .paused)
        #expect(row.tls == .decrypted)
        #expect(row.url == "https://auth.shop-staging.test/api/auth/login?x=1")
        // The sizes the core reports reach the row; a response not yet seen has none.
        #expect(row.requestBytes == 412)
        #expect(row.responseBytes == nil)
    }

    @Test func bodySizesAreOptionalOnTheWire() throws {
        // An older core (or a streaming body) sends no sizes: the row stays nil, not 0.
        let without: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                  "method": "GET", "scheme": "http", "authority": "h", "path": "/", "status": 200]
        let bare = try #require(FlowSummary(json: without)).row(seq: 1)
        #expect(bare.requestBytes == nil)
        #expect(bare.responseBytes == nil)
        let with: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                               "method": "GET", "scheme": "http", "authority": "h", "path": "/", "status": 200,
                               "request_bytes": 0, "response_bytes": 2_048]
        let sized = try #require(FlowSummary(json: with)).row(seq: 1)
        #expect(sized.requestBytes == 0)
        #expect(sized.responseBytes == 2_048)
        // A negative size is not a size: unknown (nil), never counted as 0 or shown.
        let negative: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                   "method": "GET", "scheme": "http", "authority": "h", "path": "/", "status": 200,
                                   "request_bytes": -1, "response_bytes": -9_000_000_000]
        let rejected = try #require(FlowSummary(json: negative)).row(seq: 1)
        #expect(rejected.requestBytes == nil)
        #expect(rejected.responseBytes == nil)
        // Nor is a size no real body can reach: it is a lie from the peer, read as unknown.
        let absurd: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                 "method": "GET", "scheme": "http", "authority": "h", "path": "/", "status": 200,
                                 "request_bytes": 9_000_000_000_000_000_000, "response_bytes": 1_099_511_627_776]
        let capped = try #require(FlowSummary(json: absurd)).row(seq: 1)
        #expect(capped.requestBytes == nil)
        #expect(capped.responseBytes == FlowSummary.maxBodyBytes)
    }

    @Test func decodesWebSocketSummary() throws {
        let json: JSONValue = [
            "id": "3f1c0d2e-0000-4000-8000-000000000002", "kind": "websocket", "intercept": "observed",
            "is_replay": false, "handshake": "3f1c0d2e-0000-4000-8000-000000000001", "messages": 21,
        ]
        let summary = try #require(FlowSummary(json: json))
        let row = summary.row(seq: 47)
        #expect(row.kind == .websocket)
        #expect(row.method == .ws)
        #expect(row.status == 101)
        #expect(row.wsFrames?.sent == 21)
        // A WebSocket flow carries no body sizes and never waits for one.
        #expect(row.requestBytes == nil)
        #expect(row.responseBytes == nil)
        #expect(!summary.reportsBodySizes)
        #expect(!summary.awaitsBodySize)
    }

    @Test func streamingResponseStillAwaitsItsSize() throws {
        // The core sets the status before it buffers the body, sending the size as
        // null meanwhile: such a flow is still in flight and must be fetched again.
        let streaming: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                    "method": "GET", "scheme": "https", "authority": "h", "path": "/big", "status": 200,
                                    "request_bytes": 0, "response_bytes": .null]
        let awaiting = try #require(FlowSummary(json: streaming))
        #expect(awaiting.reportsBodySizes)
        #expect(awaiting.responseBytes == nil)
        #expect(awaiting.awaitsBodySize)
        // Once the body is buffered the size lands and the flow is finished.
        let buffered: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                   "method": "GET", "scheme": "https", "authority": "h", "path": "/big", "status": 200,
                                   "request_bytes": 0, "response_bytes": 52_428_800]
        #expect(!(try #require(FlowSummary(json: buffered))).awaitsBodySize)
        // An older core sends no size keys at all: nil means unknown for good, not
        // streaming, so the poll must not re-fetch every finished flow forever.
        let older: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                "method": "GET", "scheme": "https", "authority": "h", "path": "/big", "status": 200]
        let legacy = try #require(FlowSummary(json: older))
        #expect(!legacy.reportsBodySizes)
        #expect(!legacy.awaitsBodySize)
        // No response head yet: in flight already by its missing status, not by size.
        let pending: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                  "method": "GET", "scheme": "https", "authority": "h", "path": "/big", "status": .null,
                                  "request_bytes": 10, "response_bytes": .null]
        #expect(!(try #require(FlowSummary(json: pending))).awaitsBodySize)
    }

    @Test func replayIsOperatorOrigin() throws {
        let json: JSONValue = ["id": "a", "kind": "http", "intercept": "resumed", "is_replay": true, "method": "GET",
                               "scheme": "http", "authority": "h", "path": "/", "status": 200]
        let row = try #require(FlowSummary(json: json)).row(seq: 1)
        #expect(row.isReplay)
        #expect(row.origin == .human)
        #expect(row.state == .complete)
        #expect(row.edited)
        #expect(row.tls == .none)
    }
}

/// Sizes reach every sum in the Kit from the bus, imports and fixtures: none may trap.
@Suite struct SizeSumSaturationTests {
    private func row(_ seq: Int, request: Int64?, response: Int64?) -> FlowRow {
        FlowRow(
            id: FlowID("row-\(seq)"), seq: seq, method: .get, scheme: "https", authority: "h", path: "/",
            status: 200, state: .complete, requestBytes: request, responseBytes: response)
    }

    @Test func rowEqualityNoticesARequestSizeLanding() {
        // The poll republishes rows only when `!=`: a request size that lands must count.
        #expect(row(1, request: 100, response: 10) != row(1, request: 200, response: 10))
        #expect(row(1, request: nil, response: 10) != row(1, request: 0, response: 10))
        #expect(row(1, request: 100, response: 10) == row(1, request: 100, response: 10))
    }

    @Test func overviewTotalsSaturate() {
        let stats = OverviewStats(rows: [row(1, request: Int64.max, response: Int64.max), row(2, request: 1, response: 1)])
        #expect(stats.requestBytes == Int64.max)
        #expect(stats.responseBytes == Int64.max)
    }

    @Test func selectionSummarySaturates() {
        let summary = SelectionSummary(rows: [row(1, request: Int64.max, response: 1), row(2, request: 7, response: 8)])
        #expect(summary.sized == 2)
        #expect(summary.totalBytes == Int64.max)
    }

    @Test func sizeFilterValueIsFiniteAndRenders() {
        let huge = MatchContext(subject: FilterSubject(row: row(1, request: Int64.max, response: Int64.max)))
        let twice = Double(Int64.max) + Double(Int64.max)
        #expect(huge.number(for: .size) == twice)
        #expect(huge.text(for: .size) == String(format: "%.0f", twice))
        let small = MatchContext(subject: FilterSubject(row: row(2, request: 400, response: 600)))
        #expect(small.text(for: .size) == "1000")
    }
}

@Suite struct SyntaxTests {
    @Test func jsonKeysAndValues() {
        let runs = Syntax.json(line: "  \"expires_in\": 3600,")
        #expect(runs.map(\.kind) == [.plain, .key, .punct, .plain, .number, .punct])
        #expect(runs[1].text == "\"expires_in\"")
    }

    @Test func jsonStringsAndLiterals() {
        let runs = Syntax.json(line: "\"a\": \"b\", \"c\": true")
        #expect(runs.filter { $0.kind == .string }.map(\.text) == ["\"b\""])
        #expect(runs.contains(SyntaxRun(.boolean, "true")))
    }

    @Test func headerLines() {
        #expect(Syntax.header(line: "content-type: application/json").map(\.kind) == [.key, .punct, .plain])
        #expect(Syntax.header(line: "POST /api/auth/login HTTP/2").map(\.kind)
                == [.method, .plain, .plain, .plain, .version])
        #expect(Syntax.header(line: "HTTP/2 200 OK").map(\.kind) == [.version, .plain, .number, .plain, .plain])
    }
}

@Suite struct ContentCategoryTests {
    @Test func classifies() {
        #expect(ContentCategory.classify(contentType: "application/json; charset=utf-8") == .json)
        #expect(ContentCategory.classify(contentType: "application/graphql-response+json") == .graphql)
        #expect(ContentCategory.classify(contentType: "text/html") == .document)
        #expect(ContentCategory.classify(contentType: "image/webp") == .media)
        #expect(ContentCategory.classify(contentType: nil) == .other)
    }

    /// ST-AC11: the transport chips keep raw-L4 rows by protocol; L4 is the "All" of packets.
    @Test func l4ChipsMatchByTransport() {
        func keeps(_ chip: ContentCategory, _ rows: [FlowRow]) -> [FlowRow] {
            rows.filter { chip.matches(row: $0, contentType: nil, httpVersion: nil) }
        }
        let l4 = Fixtures.l4Rows
        #expect(keeps(.tcp, l4).map { $0.l4?.proto } == [.tcp])
        let udp = keeps(.udp, l4)
        #expect(udp.count == 2)
        #expect(udp.allSatisfy { $0.l4?.proto == .udp })
        #expect(keeps(.l4, l4).count == l4.count)
        #expect(keeps(.l4, Fixtures.rows).isEmpty)
        #expect(keeps(.tcp, Fixtures.rows).isEmpty)
        #expect(ContentCategory.groups[2] == [.tcp, .udp, .l4])
        #expect(ContentCategory.shortcutChips.count == 9)
        #expect(ContentCategory.shortcutChips[4...6] == [.tcp, .udp, .l4])
        #expect(ContentCategory.allCases.allSatisfy { !$0.help.isEmpty })
    }

    @Test func fixturesMatchTheMockup() {
        #expect(Fixtures.rows.count == 14)
        #expect(Fixtures.rows.map(\.seq) == Array(41...54))
        #expect(Fixtures.rows.filter { $0.state == .paused }.count == 2)
        #expect(Fixtures.detail(for: Fixtures.rows[9]).request.header("x-forwarded-for") == "127.0.0.1")
    }
}
