import Foundation
import Testing
@testable import AitmproxyKit

/// S-041: a flow parked at the response head is told apart by its detail, and its
/// draft diffs into the `flow.mutate` response fields (status, headers, body).
@Suite struct InterceptPhaseTests {
    private let response = HTTPMessage(
        startLine: "HTTP/2 200 OK",
        headers: [.init("content-type", "application/json"), .init("cache-control", "no-store")],
        body: Data("{\"ok\": true}".utf8))

    @Test func parkedPhaseComesFromTheDetail() {
        let paused = Fixtures.rows.first { $0.state == .paused && $0.id != Fixtures.pausedLogin.id }!
        let requestOnly = Fixtures.detail(for: paused)
        #expect(InterceptPhase.parked(paused, detail: nil) == .request)
        #expect(InterceptPhase.parked(paused, detail: requestOnly) == .request)
        var withResponse = requestOnly
        withResponse.response = response
        #expect(InterceptPhase.parked(paused, detail: withResponse) == .response)
        // The polled summary carries the parked response's status before any detail is fetched.
        var headKnown = paused
        headKnown.status = 200
        #expect(InterceptPhase.parked(headKnown, detail: nil) == .response)
        #expect(InterceptPhase.parked(headKnown, detail: requestOnly) == .response)
        let complete = Fixtures.rows.first { $0.state == .complete }!
        #expect(InterceptPhase.parked(complete, detail: Fixtures.detail(for: complete)) == nil)
        #expect(InterceptPhase.response.title == "Paused · response")
        #expect(InterceptPhase.request.title == "Paused · request")
    }

    @Test func statusCodeReadsAResponseLineOnly() {
        #expect(response.statusCode == 200)
        #expect(HTTPMessage(startLine: "HTTP/1.1 418 I'm a teapot", headers: []).statusCode == 418)
        #expect(HTTPMessage(startLine: "HTTP/2 418", headers: []).statusCode == 418)
        #expect(HTTPMessage(startLine: "GET /x HTTP/2", headers: []).statusCode == nil)
        #expect(Fixtures.pausedLogin.request.isResponse == false)
        #expect(response.isResponse)
    }

    @Test func responseDiffCarriesStatusHeadersAndBody() {
        var edited = response
        edited.startLine = "HTTP/2 418 I'm a teapot"
        edited.headers.append(.init("x-aitm-edited", "1"))
        edited.body = Data("{\"edited\": true}".utf8)
        let edits = RequestEdits.diff(fromResponse: response, to: edited)
        #expect(edits.status == 418)
        #expect(edits.headers == ["x-aitm-edited": "1"])
        #expect(edits.body == Data("{\"edited\": true}".utf8))
        #expect(edits.method == nil && edits.path == nil)
        #expect(edits.changeCount == 3)
        #expect(!edits.isEmpty)
        // The core's `status` field is an integer, not a string.
        #expect(edits.arguments["status"] == .number(418))
        #expect(edits.arguments["method"] == nil)
        #expect(RequestEdits.diff(fromResponse: response, to: response).isEmpty)
    }

    @Test func duplicateHeadersAreNeverCollapsedByAnEdit() {
        // A real response with two set-cookie lines: a status-only edit must not touch them.
        let cookies = HTTPMessage(
            startLine: "HTTP/1.1 200 OK",
            headers: [.init("set-cookie", "a=1"), .init("set-cookie", "b=2"), .init("vary", "Accept")])
        var statusOnly = cookies
        statusOnly.startLine = "HTTP/1.1 203 OK"
        let edits = RequestEdits.diff(fromResponse: cookies, to: statusOnly)
        #expect(edits.status == 203)
        #expect(edits.headers == nil)
        #expect(edits.changeCount == 1)
        #expect(RequestEdits.unencodableHeaderNames(from: cookies, to: statusOnly).isEmpty)
        // Changing one of the two values cannot cross as `{name: value}`: it is reported, not sent.
        var secondCookie = cookies
        secondCookie.headers[1].value = "b=3"
        let partial = RequestEdits.diff(fromResponse: cookies, to: secondCookie)
        #expect(partial.headers == nil && partial.isEmpty)
        #expect(RequestEdits.unencodableHeaderNames(from: cookies, to: secondCookie) == ["set-cookie"])
        // A single-valued header still edits; deleting one of two lines leaves one value, which the
        // core can carry (remove every set-cookie, set the one that remains).
        var vary = cookies
        vary.headers[2].value = "Accept, Origin"
        #expect(RequestEdits.diff(fromResponse: cookies, to: vary).headers == ["vary": "Accept, Origin"])
        var oneCookie = cookies
        oneCookie.headers.remove(at: 1)
        #expect(RequestEdits.diff(fromResponse: cookies, to: oneCookie).headers == ["set-cookie": "a=1"])
        #expect(RequestEdits.unencodableHeaderNames(from: cookies, to: oneCookie).isEmpty)
        // Header names compare case-insensitively, as the core treats them.
        var cased = cookies
        cased.headers[2] = .init("Vary", "Accept")
        #expect(RequestEdits.diff(fromResponse: cookies, to: cased).isEmpty)
    }

    @Test func aReasonPhraseAloneIsNotAStatusEdit() {
        var edited = response
        edited.startLine = "HTTP/2 200"
        #expect(RequestEdits.diff(fromResponse: response, to: edited).isEmpty)
    }

    @Test func rawResponseRoundTrips() throws {
        let text = RawHTTP.render(response)
        #expect(text.hasPrefix("HTTP/2 200 OK\ncontent-type: application/json\n"))
        let parsed = try RawHTTP.parse(text)
        #expect(parsed == response)
        let edited = try RawHTTP.parse("HTTP/1.1 418\r\nX-Edited: 1\r\n\r\nnope")
        #expect(edited.startLine == "HTTP/1.1 418")
        #expect(edited.statusCode == 418)
        #expect(edited.headers == [.init("x-edited", "1")])
        #expect(edited.bodyText == "nope")
        #expect((try? RawHTTP.parse("HTTP/2 teapot\n")) == nil)
        #expect((try? RawHTTP.parse("HTTP/2 99\n")) == nil)
        // The core accepts 100–599 only.
        #expect((try? RawHTTP.parse("HTTP/2 700\n")) == nil)
        #expect(HTTPMessage(startLine: "HTTP/2 700", headers: []).statusCode == nil)
    }

    @Test func theParserKnowsWhichKindOfMessageAnEditorExpects() {
        // A status line typed into the request editor is an error on line 1, not a silent drop.
        #expect(throws: RawHTTP.ParseError.self) { try RawHTTP.parse("HTTP/2 200 OK\n", expecting: .request) }
        #expect(throws: RawHTTP.ParseError.self) { try RawHTTP.parse("GET /x HTTP/2\n", expecting: .response) }
        #expect((try? RawHTTP.parse("HTTP/2 200 OK\n", expecting: .response))?.statusCode == 200)
        #expect((try? RawHTTP.parse("GET /x HTTP/2\n", expecting: .request))?.startLine == "GET /x HTTP/2")
    }

    @Test func headerNamesAndValuesAreValidatedWithTheLine() {
        // What the core would refuse (`HeaderMap::try_set`) is refused here, naming the line.
        for bad in ["HTTP/2 200\nx\"y: 1\n", "HTTP/2 200\nx(y): 1\n", "HTTP/2 200\nok: a\rb\n", "HTTP/2 200\nok: a\u{1}b\n"] {
            do {
                _ = try RawHTTP.parse(bad)
                Issue.record("expected a parse error for \(bad.debugDescription)")
            } catch {
                #expect(error.line == 2)
            }
        }
        let fine = try? RawHTTP.parse("HTTP/2 200\nx-aitm_edited.1: a\tb\n")
        #expect(fine?.headers == [.init("x-aitm_edited.1", "a\tb")])
    }
}
