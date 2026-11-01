import Foundation
import Testing
@testable import AitmproxyKit

/// A request with three cookies (one quoted) and a response that sets two, for
/// `CookieTests.cookiesInMessagePickTheRightHeader`.
private enum CookieInputs {
    static let request = Make.message("GET /api/me HTTP/2", [
        ("host", "api.shop-staging.test"),
        ("cookie", "session=9f1c2a7e; prefs=\"theme=dark; density=compact\"; ab_test=B"),
    ])
    static let response = Make.response(200, [
        ("content-type", "application/json; charset=utf-8"),
        ("set-cookie", "session=9f1c2a7e; Domain=.shop-staging.test; Path=/; "
            + "Expires=Wed, 28 Oct 2026 11:04:58 GMT; HttpOnly; Secure; SameSite=Lax"),
        ("set-cookie", "csrf=4d2e9c; Path=/api; Max-Age=3600; Secure; SameSite=Strict"),
    ])
}

/// An OpenAI-style stream — one comment line, six content deltas, `[DONE]` — for `SSETests.mergedDeltas`.
private enum SSEInputs {
    static let deltas = ["Order", " 4471", " shipped", " on Monday", " and arrives", " Thursday."]
    static let body: String = {
        var out = ": keep-alive\n\n"
        for (n, delta) in deltas.enumerated() {
            let chunk = #"{"id":"chatcmpl-7Q","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"\#(delta)"},"finish_reason":null}]}"#
            out += "id: \(n + 1)\ndata: \(chunk)\n\n"
        }
        return out + "data: [DONE]\n\n"
    }()
}

// MARK: - Cookies (S-019)

@Suite struct CookieTests {
    @Test func requestCookiesKeepQuotesOrderAndDuplicates() {
        let cookies = Cookie.parseCookieHeader("a=1; b=\"quoted; still\"; a=2;  c")
        #expect(cookies.map(\.name) == ["a", "b", "a", ""])
        #expect(cookies.map(\.value) == ["1", "quoted; still", "2", "c"])
        #expect(cookies.allSatisfy { $0.domain == nil && $0.expires == nil && !$0.secure && !$0.httpOnly })
    }

    @Test func emptyAndOddHeaders() {
        #expect(Cookie.parseCookieHeader("").isEmpty)
        #expect(Cookie.parseCookieHeader(" ; ; ").isEmpty)
        #expect(Cookie.parseCookieHeader("=bare") == [Cookie(name: "", value: "bare")])
        #expect(Cookie.parseCookieHeader("k=") == [Cookie(name: "k", value: "")])
        #expect(Cookie.parseCookieHeader("k=a=b").first?.value == "a=b")
        #expect(Cookie.parseSetCookie("") == nil)
        #expect(Cookie.parseSetCookie("; Secure") == nil)
    }

    @Test func setCookieAttributesAreCaseInsensitive() throws {
        let cookie = try #require(Cookie.parseSetCookie(
            "session=\"9f1c\"; domain=.shop-staging.test; PATH=/; expires=Wed, 28 Oct 2026 11:04:58 GMT; "
                + "httponly; SECURE; samesite=Lax; Partitioned"))
        #expect(cookie.name == "session")
        #expect(cookie.value == "9f1c")
        #expect(cookie.domain == ".shop-staging.test")
        #expect(cookie.path == "/")
        #expect(cookie.httpOnly)
        #expect(cookie.secure)
        #expect(cookie.sameSite == "Lax")
        #expect(cookie.maxAge == nil)
        #expect(cookie.flagsText == "HttpOnly · Secure · SameSite=Lax")
        let expires = try #require(cookie.expires)
        #expect(Int(expires.timeIntervalSince1970) == 1_793_185_498) // 2026-10-28T11:04:58Z
    }

    @Test func maxAgeAndMissingAttributes() throws {
        let cookie = try #require(Cookie.parseSetCookie("csrf=4d2e9c; Max-Age=3600"))
        #expect(cookie.maxAge == 3600)
        #expect(cookie.expires == nil)
        #expect(cookie.path == nil)
        #expect(cookie.flagsText == "")
        let bad = try #require(Cookie.parseSetCookie("x=1; Max-Age=soon; Expires=never"))
        #expect(bad.maxAge == nil)
        #expect(bad.expires == nil)
    }

    @Test func httpDateFormats() {
        let expected: TimeInterval = 784_111_777 // Sun, 06 Nov 1994 08:49:37 GMT
        #expect(Cookie.parseHTTPDate("Sun, 06 Nov 1994 08:49:37 GMT")?.timeIntervalSince1970 == expected)
        #expect(Cookie.parseHTTPDate("Sunday, 06-Nov-94 08:49:37 GMT")?.timeIntervalSince1970 == expected)
        #expect(Cookie.parseHTTPDate("Sun Nov  6 08:49:37 1994")?.timeIntervalSince1970 == expected)
        #expect(Cookie.parseHTTPDate("Thu, 01 Jan 1970 00:00:00 GMT")?.timeIntervalSince1970 == 0)
        #expect(Cookie.parseHTTPDate("Sun, 06 Nov 1994") == nil)
        #expect(Cookie.parseHTTPDate("08:49:37") == nil)
    }

    @Test func cookiesInMessagePickTheRightHeader() {
        let request = Cookie.cookies(in: CookieInputs.request)
        #expect(request.map(\.name) == ["session", "prefs", "ab_test"])
        #expect(request[1].value == "theme=dark; density=compact")
        let response = Cookie.cookies(in: CookieInputs.response)
        #expect(response.map(\.name) == ["session", "csrf"])
        #expect(response[0].expires != nil)
        #expect(response[1].maxAge == 3600)
        #expect(response[1].sameSite == "Strict")
        // A request never reads set-cookie, a response never reads cookie.
        let odd = HTTPMessage(startLine: "GET / HTTP/1.1", headers: [.init("set-cookie", "a=1")])
        #expect(Cookie.cookies(in: odd).isEmpty)
        let two = HTTPMessage(startLine: "GET / HTTP/1.1", headers: [.init("Cookie", "a=1"), .init("cookie", "b=2")])
        #expect(Cookie.cookies(in: two).map(\.name) == ["a", "b"])
    }
}

// MARK: - SSE (S-025)

@Suite struct SSETests {
    @Test func whatwgExamples() {
        // The spec's first example: a comment, two events, a trailing partial event that is dropped.
        let stream = ": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n"
        let events = SSE.parse(stream)
        #expect(events.count == 3)
        #expect(events[0].isComment && events[0].data == "test stream")
        #expect(events[1].data == "first event" && events[1].id == "1" && events[1].event == nil)
        #expect(events[2].data == "second event" && events[2].id == "")
        #expect(events.map(\.order) == [0, 1, 2])
    }

    @Test func dataLinesJoinAndBlankDataDispatches() {
        // Spec: "data\n\ndata\ndata\n\ndata:" → "", "\n", and the last is dropped (no blank line).
        let events = SSE.parse("data\n\ndata\ndata\n\ndata:")
        #expect(events.map(\.data) == ["", "\n"])
        let multi = SSE.parse("data: YHOO\ndata: +2\ndata: 10\n\n")
        #expect(multi.map(\.data) == ["YHOO\n+2\n10"])
        // A blank line with no data dispatches nothing but resets the type.
        let reset = SSE.parse("event: ping\n\ndata: x\n\n")
        #expect(reset.count == 1)
        #expect(reset[0].event == nil)
    }

    @Test func eventTypeRetryAndLastIDPersist() {
        let events = SSE.parse("event: add\nretry: 3000\nid: 7\ndata: {\"a\":1}\n\ndata: next\n\nid: bad\u{0}\ndata: z\n\n")
        #expect(events.map(\.event) == ["add", nil, nil])
        #expect(events[0].retry == 3000 && events[1].retry == nil)
        #expect(events.map(\.id) == ["7", "7", "7"])
        #expect(SSE.parse("retry: 3s\ndata: x\n\n")[0].retry == nil)
    }

    @Test func lineEndingsAndBOM() {
        let crlf = SSE.parse("data: a\r\n\r\ndata: b\r\n\r\n")
        let cr = SSE.parse("data: a\r\rdata: b\r\r")
        let lf = SSE.parse("\u{FEFF}data: a\n\ndata: b\n\n")
        #expect(crlf.map(\.data) == ["a", "b"])
        #expect(cr.map(\.data) == ["a", "b"])
        #expect(lf.map(\.data) == ["a", "b"])
        #expect(SSE.parse("").isEmpty)
    }

    @Test func mergedDeltas() {
        let events = SSE.parse(SSEInputs.body)
        #expect(events.count == 8)
        #expect(events[0].isComment)
        #expect(events.last?.data == "[DONE]")
        #expect(SSE.mergedDeltas(events) == "Order 4471 shipped on Monday and arrives Thursday.")
        // Role-only and null-content deltas count as the shape and add nothing.
        let roleOnly = SSE.parse("data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"
            + "data: {\"choices\":[{\"delta\":{\"content\":null}}]}\n\n")
        #expect(SSE.mergedDeltas(roleOnly) == "")
        // Nothing OpenAI-shaped → nil.
        #expect(SSE.mergedDeltas(SSE.parse("data: plain\n\ndata: {\"a\":1}\n\ndata: [DONE]\n\n")) == nil)
        #expect(SSE.mergedDeltas([]) == nil)
    }
}

// MARK: - Timing and diff (S-020, S-026)

@Suite struct TimingAndDiffTests {
    @Test func everyPhaseReportedSumsToTheTotal() {
        // 4 + 18 + 31 + 289 + 70 = 412 ms.
        let timing = FlowTiming(dns: .milliseconds(4), connect: .milliseconds(18), tls: .milliseconds(31),
                                wait: .milliseconds(289), download: .milliseconds(70))
        #expect(timing.total == .milliseconds(412))
        #expect(FlowTiming.Phase.allCases.allSatisfy { timing.duration(of: $0) != nil })
        // A reused connection reports a real zero for DNS, which prints as 0 ms, not a dash.
        #expect(Format.duration(FlowTiming(dns: .zero, wait: .milliseconds(41)).dns) == "0 ms")
    }

    @Test func twoListingsDifferInAHeaderAndAField() {
        let left = Make.detail(
            id: "left",
            request: Make.message("GET /api/products HTTP/2",
                                  [("host", "api.shop-staging.test"), ("accept", "application/json")]),
            response: Make.response(200, [("content-type", "application/json")], body: "{\n  \"ok\": true,\n  \"page\": 3\n}"))
        var right = left
        right.id = FlowID("right")
        right.request.headers = [
            .init("host", "api.shop-staging.test"), .init("accept", "application/json; q=0.9, */*; q=0.1"),
            .init("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.…"),
        ]
        right.response?.body = Data("{\n  \"ok\": true,\n  \"page\": 4\n}".utf8)
        let result = FlowDiff.compare(left, right)
        let changed = result.sections.filter { $0.diff.hasChanges }.map(\.part)
        #expect(changed == [.requestHead, .responseBody])
        #expect(result.unified().contains("+authorization: Bearer"))
        #expect(result.unified().contains("-  \"page\": 3"))
        #expect(result.unified().contains("+  \"page\": 4"))
        #expect(!result.truncated)
    }
}
