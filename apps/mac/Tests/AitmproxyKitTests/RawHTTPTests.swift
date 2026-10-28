import Foundation
import Testing
@testable import AitmproxyKit

@Suite struct RawHTTPTests {
    @Test func roundTripsTheFixtureRequest() throws {
        let text = RawHTTP.render(Fixtures.pausedLogin.request)
        #expect(text.hasPrefix("POST /api/auth/login HTTP/2\nhost: auth.shop-staging.test\n"))
        let parsed = try RawHTTP.parse(text)
        #expect(parsed.startLine == Fixtures.pausedLogin.request.startLine)
        #expect(parsed.headers == Fixtures.pausedLogin.request.headers)
        #expect(parsed.bodyText == Fixtures.pausedLogin.request.bodyText)
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
        let original = Fixtures.pausedLogin.originalRequest!
        var edited = Fixtures.pausedLogin.request
        edited.body = Data("{}".utf8)
        let edits = RequestEdits.diff(from: original, to: edited)
        #expect(edits.headers?["x-forwarded-for"] == "127.0.0.1")
        #expect(edits.changeCount == 2)
        #expect(RequestEdits.diff(from: original, to: original).changeCount == 0)
    }
}
