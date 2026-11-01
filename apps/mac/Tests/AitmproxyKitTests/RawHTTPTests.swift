import Foundation
import Testing
@testable import AitmproxyKit

/// A parked login as the editor sees it: the request as it arrived (the core's backup) and
/// the same request with one header added while paused.
private enum RawHTTPInputs {
    static let original = Make.message(
        "POST /api/auth/login HTTP/2",
        [("host", "auth.shop-staging.test"), ("content-type", "application/json"), ("accept", "*/*"),
         ("user-agent", "curl/8.7.1")],
        body: "{\n  \"email\": \"ops@shop-staging.test\",\n  \"password\": \"correct-horse-battery\",\n  \"remember\": true\n}")

    static let edited: HTTPMessage = {
        var message = original
        message.headers.append(.init("x-forwarded-for", "127.0.0.1"))
        return message
    }()
}

@Suite struct RawHTTPTests {
    @Test func roundTripsAParkedRequest() throws {
        let request = RawHTTPInputs.edited
        let text = RawHTTP.render(request)
        #expect(text.hasPrefix("POST /api/auth/login HTTP/2\nhost: auth.shop-staging.test\n"))
        let parsed = try RawHTTP.parse(text)
        #expect(parsed.startLine == request.startLine)
        #expect(parsed.headers == request.headers)
        #expect(parsed.bodyText == request.bodyText)
    }

    @Test func parsesEditsAndReportsErrors() throws {
        let edited = try RawHTTP.parse("PUT /api/me?x=1\r\nHost: h\r\nX-Trace: 7\r\n\r\n{\"a\":1}")
        #expect(edited.startLine == "PUT /api/me?x=1 HTTP/2")
        #expect(edited.headers == [.init("host", "h"), .init("x-trace", "7")])
        #expect(edited.bodyText == "{\"a\":1}")
        #expect((try? RawHTTP.parse("")) == nil)
        #expect((try? RawHTTP.parse("get /x")) == nil)
        do {
            _ = try RawHTTP.parse("GET /x HTTP/2\nbad header\n")
            Issue.record("expected a parse error")
        } catch {
            #expect(error.line == 2)
        }
    }

    @Test func diffCountsChanges() {
        let original = RawHTTPInputs.original
        var edited = RawHTTPInputs.edited
        edited.body = Data("{}".utf8)
        let edits = RequestEdits.diff(from: original, to: edited)
        #expect(edits.headers?["x-forwarded-for"] == "127.0.0.1")
        #expect(edits.changeCount == 2)
        #expect(RequestEdits.diff(from: original, to: original).changeCount == 0)
    }

    @Test func detectsRemovedHeaders() {
        let original = HTTPMessage(startLine: "GET /x HTTP/2",
                                   headers: [.init("host", "a.test"), .init("x-debug", "1"), .init("accept", "*/*")])
        var edited = original
        edited.headers.removeAll { $0.name == "x-debug" }
        // flow.mutate can't remove headers yet, so diff encodes nothing for a pure removal…
        #expect(RequestEdits.diff(from: original, to: edited).changeCount == 0)
        // …but the removal is detectable so the UI can say it won't take effect.
        #expect(RequestEdits.removedHeaderNames(from: original, to: edited) == ["x-debug"])
        #expect(RequestEdits.removedHeaderNames(from: original, to: original).isEmpty)
        // A changed (not removed) header is not a removal.
        var changed = original
        changed.headers[1].value = "2"
        #expect(RequestEdits.removedHeaderNames(from: original, to: changed).isEmpty)
    }
}
