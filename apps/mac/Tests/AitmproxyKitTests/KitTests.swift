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
            "started_at": 1_761_908_698_120, "duration_ms": .null,
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
        // It starts like any flow, but has no end marker yet, so the core sends a null duration.
        #expect(summary.startedAt == Date(timeIntervalSince1970: 1_761_908_698.120))
        #expect(summary.duration == nil)
    }

    @Test func decodesTiming() throws {
        // `started_at` is milliseconds since the Unix epoch; `duration_ms` whole milliseconds.
        let json: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                               "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                               "request_bytes": 0, "response_bytes": 2_048,
                               "started_at": 1_761_908_698_120, "duration_ms": 412]
        let summary = try #require(FlowSummary(json: json))
        #expect(summary.startedAt == Date(timeIntervalSince1970: 1_761_908_698.120))
        #expect(summary.duration == .milliseconds(412))
        // Both reach the row, whose Time and Duration columns already draw them.
        let row = summary.row(seq: 1)
        #expect(row.startedAt == summary.startedAt)
        #expect(row.duration == .milliseconds(412))
    }

    @Test func timingIsOptionalOnTheWire() throws {
        // An older core sends no timing keys: both stay nil and the columns draw dashes.
        let absent: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                 "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200]
        let bare = try #require(FlowSummary(json: absent))
        #expect(bare.startedAt == nil)
        #expect(bare.duration == nil)
        // A flow still in flight (or a clock before the epoch) is sent as null.
        let nulls: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                                "started_at": .null, "duration_ms": .null]
        let pending = try #require(FlowSummary(json: nulls))
        #expect(pending.startedAt == nil)
        #expect(pending.duration == nil)
        // A negative instant or duration is not one: unknown (nil), never a date before 1970.
        let negative: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                   "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                                   "started_at": -5, "duration_ms": -1]
        let rejected = try #require(FlowSummary(json: negative))
        #expect(rejected.startedAt == nil)
        #expect(rejected.duration == nil)
        // Nor is a fractional millisecond count an integer on this wire.
        let fractional: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                     "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                                     "started_at": 1.5]
        #expect(try #require(FlowSummary(json: fractional)).startedAt == nil)
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

    // MARK: source_app -> FlowRow.client (spec 2026-10-31-ne-source-app-on-the-wire, D5 / SA-AC3)

    @Test func sourceAppBecomesTheClient() throws {
        let json: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                               "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                               "source_app": "com.apple.Safari", "capture_interface": "macos-ne"]
        let summary = try #require(FlowSummary(json: json))
        #expect(summary.sourceApp == "com.apple.Safari")
        #expect(summary.captureInterface == "macos-ne")
        let row = summary.row(seq: 1)
        #expect(row.client == ClientInfo(name: "Safari", monogram: "S", bundleID: "com.apple.Safari"))
        #expect(row.client?.pid == nil)
    }

    @Test func sourceAppAbsentNullOrEmptyLeavesClientNil() throws {
        // A proxied flow (null), an older core (absent) and a provider that sent nothing
        // ("") all mean "no app": never an empty or placeholder app group.
        let absent: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                 "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200]
        let null: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                               "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                               "source_app": .null, "capture_interface": .null]
        let empty: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                                "source_app": "", "capture_interface": ""]
        for json in [absent, null, empty] {
            let summary = try #require(FlowSummary(json: json))
            #expect(summary.sourceApp == nil)
            #expect(summary.captureInterface == nil)
            #expect(summary.row(seq: 1).client == nil)
        }
    }

    @Test func displayNameStripsControlAndBidiCharactersButKeepsTheRawIdentifier() {
        // U+202E (RTL override) and C0/C1 controls never reach the shown name; `bundleID` stays raw.
        let spoof = "com.evil.\u{202E}irafaS\u{0007}"
        #expect(ClientInfo.displayName(forSourceApp: spoof) == "irafaS")
        let client = ClientInfo(sourceApp: spoof)
        #expect(client.bundleID == spoof)
        #expect(client.name == "irafaS")
        #expect(ClientInfo.displayName(forSourceApp: "\u{202E}\u{0001}") == "unknown app")
        #expect(ClientInfo.displayName(forSourceApp: "com.apple.Safari") == "Safari")
    }

    @Test func displayNameRule() {
        // Known map first, else the text after the last dot, casing kept; no dot or a
        // trailing dot keeps the whole identifier.
        #expect(ClientInfo.displayName(forSourceApp: "com.apple.Safari") == "Safari")
        #expect(ClientInfo.displayName(forSourceApp: "com.apple.curl") == "curl")
        #expect(ClientInfo.displayName(forSourceApp: "obscura") == "obscura")
        #expect(ClientInfo.displayName(forSourceApp: "com.google.Chrome") == "Chrome")
        #expect(ClientInfo.displayName(forSourceApp: "com.apple.WebKit.Networking") == "Safari")
        #expect(ClientInfo.displayName(forSourceApp: "org.mozilla.firefox") == "Firefox")
        #expect(ClientInfo.displayName(forSourceApp: "trailing.") == "trailing.")
        #expect(ClientInfo.knownSourceApps == ["com.apple.WebKit.Networking": "Safari", "org.mozilla.firefox": "Firefox"])
    }

    @Test func sameIdentifierGroupsAsOneClient() throws {
        // Session.clients counts rows by ClientInfo (Hashable): the same identifier on two
        // flows must be one key, so the Apps sidebar shows one group with a count of 2.
        let first: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                "method": "GET", "scheme": "https", "authority": "h", "path": "/one", "status": 200,
                                "source_app": "com.apple.curl", "capture_interface": "macos-ne"]
        let second: JSONValue = ["id": "b", "kind": "http", "intercept": "observed", "is_replay": false,
                                 "method": "POST", "scheme": "https", "authority": "h2", "path": "/two", "status": 404,
                                 "source_app": "com.apple.curl", "capture_interface": "macos-ne"]
        let rows = [try #require(FlowSummary(json: first)).row(seq: 1),
                    try #require(FlowSummary(json: second)).row(seq: 2)]
        #expect(rows[0].client == rows[1].client)
        var counts: [ClientInfo: Int] = [:]
        for row in rows { if let c = row.client { counts[c, default: 0] += 1 } }
        #expect(counts.count == 1)
        #expect(counts[ClientInfo(name: "curl", monogram: "c", bundleID: "com.apple.curl")] == 2)
    }

    @Test func webSocketSummaryCarriesClientToo() throws {
        let json: JSONValue = [
            "id": "3f1c0d2e-0000-4000-8000-000000000002", "kind": "websocket", "intercept": "observed",
            "is_replay": false, "handshake": "3f1c0d2e-0000-4000-8000-000000000001", "messages": 3,
            "source_app": "com.apple.Safari", "capture_interface": "macos-ne",
        ]
        let summary = try #require(FlowSummary(json: json))
        #expect(summary.captureInterface == "macos-ne")
        let row = summary.row(seq: 1)
        #expect(row.kind == .websocket)
        #expect(row.client?.bundleID == "com.apple.Safari")
        #expect(row.client?.name == "Safari")
    }

    // MARK: Tester additions (whole-branch stage 5): SA-AC3 edges

    @Test func sourceAppOfTheWrongTypeLeavesClientNil() throws {
        // A number, bool, array or object where an identifier belongs is not an
        // app: nil, never a stringified value shown as a fake group.
        let base: [String: JSONValue] = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                                         "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200]
        let wrong: [JSONValue] = [42, true, ["com.apple.Safari"], ["bundle": "com.apple.Safari"]]
        for value in wrong {
            var json = base
            json["source_app"] = value
            json["capture_interface"] = value
            let summary = try #require(FlowSummary(json: .object(json)))
            #expect(summary.sourceApp == nil, "\(value)")
            #expect(summary.captureInterface == nil, "\(value)")
            #expect(summary.row(seq: 1).client == nil, "\(value)")
        }
    }

    @Test func displayNameEdgesAndTheClientKeepsTheRawIdentifier() {
        // D5 rule 2 at its edges: a lone dot and a leading dot.
        #expect(ClientInfo.displayName(forSourceApp: ".") == ".")
        #expect(ClientInfo.displayName(forSourceApp: ".hidden") == "hidden")
        #expect(ClientInfo.displayName(forSourceApp: "a..b") == "b")
        // The known map wins, and the raw identifier is kept as bundleID either way.
        let safari = ClientInfo(sourceApp: "com.apple.WebKit.Networking")
        #expect(safari.name == "Safari")
        #expect(safari.monogram == "S")
        #expect(safari.bundleID == "com.apple.WebKit.Networking")
        #expect(safari.pid == nil)
        // Two identifiers with the same display name are two clients (bundleID is
        // part of Hashable), so two apps never merge into one group by name alone.
        #expect(ClientInfo(sourceApp: "com.apple.Safari") != safari)
    }

    @Test func anOversizedSourceAppStillDecodesAndGroups() throws {
        let long = "com.example." + String(repeating: "x", count: 64 * 1024)
        let json: JSONValue = ["id": "a", "kind": "http", "intercept": "observed", "is_replay": false,
                               "method": "GET", "scheme": "https", "authority": "h", "path": "/", "status": 200,
                               "source_app": .string(long), "capture_interface": "macos-ne"]
        let summary = try #require(FlowSummary(json: json))
        #expect(summary.sourceApp == long)
        let row = summary.row(seq: 1)
        #expect(row.client?.bundleID == long)
        #expect(row.client?.name == String(repeating: "x", count: 64 * 1024))
        #expect(row.client?.monogram == "x")
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

    @Test func fixturesMatchTheMockup() {
        #expect(Fixtures.rows.count == 14)
        #expect(Fixtures.rows.map(\.seq) == Array(41...54))
        #expect(Fixtures.rows.filter { $0.state == .paused }.count == 2)
        #expect(Fixtures.detail(for: Fixtures.rows[9]).request.header("x-forwarded-for") == "127.0.0.1")
    }
}
