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
    }
}
