import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// TR-AC21 (spec 2026-10-31-mac-traffic-route-advice-design, D2): `proxy.status.decrypt` as the
/// v0.5.9+ core serialises it — the Scope host count, whether anything is decrypted, and the one
/// sentence every surface prints verbatim while nothing is. Nil from an older core.
@Suite struct DecryptStatusTests {
    static let advice = "Nothing is decrypted until a host is in Scope."

    @Test func decodesTheEmptyScopeObjectWithTheCoreSentence() throws {
        let json: JSONValue = ["scope_hosts": 0, "decrypting": false, "advice": "Nothing is decrypted until a host is in Scope."]
        let status = try #require(DecryptStatus(json: json))
        #expect(status.scopeHosts == 0)
        #expect(status.decrypting == false)
        #expect(status.advice == "Nothing is decrypted until a host is in Scope.")
        #expect(status == DecryptStatus(scopeHosts: 0, decrypting: false, advice: Self.advice))
    }

    @Test func decodesADecryptingScopeWithNullAdvice() throws {
        let status = try #require(DecryptStatus(json: ["scope_hosts": 2, "decrypting": true, "advice": nil]))
        #expect(status.scopeHosts == 2)
        #expect(status.decrypting == true)
        #expect(status.advice == nil)
    }

    @Test func anObjectWithoutScopeHostsIsNotADecryptObject() {
        #expect(DecryptStatus(json: .object([:])) == nil)
        #expect(DecryptStatus(json: ["decrypting": true, "advice": nil]) == nil)
        #expect(DecryptStatus(json: .null) == nil)
        #expect(DecryptStatus(json: "decrypt") == nil)
    }

    /// An older core's `proxy.status` has no `decrypt` key: the one `BusService` line yields nil.
    @Test func anOlderProxyStatusWithoutDecryptYieldsNil() {
        let status: JSONValue = ["listen": "127.0.0.1:8080", "flows": 3, "intercept": ["enabled": false]]
        #expect(status["decrypt"].flatMap(DecryptStatus.init) == nil)
        let newer: JSONValue = ["listen": "127.0.0.1:8080", "decrypt": ["scope_hosts": 1, "decrypting": true, "advice": nil]]
        #expect(newer["decrypt"].flatMap(DecryptStatus.init) == DecryptStatus(scopeHosts: 1, decrypting: true, advice: nil))
    }

    @Test func decryptingDefaultsToWhetherAnyHostIsInScope() throws {
        let one = try #require(DecryptStatus(json: ["scope_hosts": 1]))
        #expect(one.decrypting == true)
        #expect(one.advice == nil)
        let none = try #require(DecryptStatus(json: ["scope_hosts": 0]))
        #expect(none.decrypting == false)
    }

    /// An empty `advice` string is no sentence: it decodes as nil, the same as a null or missing key, so the
    /// Scope line falls back to the Kit's own words instead of printing an empty row and a blank banner.
    @Test func anEmptyAdviceStringDecodesAsNil() throws {
        let empty = try #require(DecryptStatus(json: ["scope_hosts": 0, "decrypting": false, "advice": ""]))
        #expect(empty.scopeHosts == 0)
        #expect(empty.decrypting == false)
        #expect(empty.advice == nil)
        #expect(empty == DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil))
    }

    /// Whitespace-only advice is empty too. A real sentence stays verbatim (D3), padding included: only an
    /// all-whitespace value reads as absent.
    @Test func aWhitespaceOnlyAdviceDecodesAsNil() throws {
        let blank = try #require(DecryptStatus(json: ["scope_hosts": 0, "decrypting": false, "advice": "  \n"]))
        #expect(blank.advice == nil)
        #expect(blank == DecryptStatus(scopeHosts: 0, decrypting: false, advice: nil))
        #expect(try #require(DecryptStatus(json: ["scope_hosts": 0, "advice": "\t"])).advice == nil)
        let padded = try #require(DecryptStatus(json: ["scope_hosts": 0, "advice": " Nothing is decrypted until a host is in Scope. "]))
        #expect(padded.advice == " Nothing is decrypted until a host is in Scope. ")
    }
}
