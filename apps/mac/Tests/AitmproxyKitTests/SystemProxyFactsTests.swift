import AitmBusClient
import Testing
@testable import AitmproxyKit

/// SP-AC23 (spec 2026-10-31-system-proxy-automation-design §D6, §D12, §D13): the verb facts of
/// `proxy.status.system_proxy` (and of the full `proxy.system.status` object) as the Kit reads
/// them, from literal JSON as the core serialises it.
@Suite struct SystemProxyFactsTests {
    private typealias Endpoint = SystemProxyState.Endpoint
    private let listen = "127.0.0.1:8080"

    /// HTTP and HTTPS both at `host:port`.
    private func both(_ host: String, _ port: Int) -> SystemProxyState {
        SystemProxyState(http: Endpoint(host: host, port: port), https: Endpoint(host: host, port: port))
    }

    /// §D6's compact sub-object for another proxy at 127.0.0.1:9090.
    @Test func parsesTheCompactVerbObject() throws {
        let compact: JSONValue = [
            "state": "other", "host": "127.0.0.1", "port": 9090, "managed_by_us": false, "setting": false,
            "supported": true, "detail": "x",
        ]
        let facts = try #require(SystemProxyFacts(compact: compact, listenAddress: listen))
        #expect(facts.word == .other)
        #expect(facts.state == both("127.0.0.1", 9090))
        #expect(facts.state?.route(to: listen) == .other(host: "127.0.0.1", port: 9090))
        #expect(facts.managedByUs == false)
        #expect(facts.setting == false)
        #expect(facts.supported == true)
        #expect(facts.detail == "x")
        #expect(facts.remedy == nil)
        #expect(facts.guidance == nil)
        // The same value through the memberwise init (remedy and guidance default to nil).
        #expect(facts == SystemProxyFacts(word: .other, state: both("127.0.0.1", 9090), managedByUs: false, setting: false,
                                          supported: true, detail: "x"))
        // The rest of §D6's words, from the compact shape the core sends while nothing is in flight.
        let managed = try #require(SystemProxyFacts(compact: [
            "state": "points_at_us", "host": nil, "port": nil, "managed_by_us": true, "setting": false,
            "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)",
        ], listenAddress: listen))
        #expect(managed.word == .pointsAtUs)
        #expect(managed.state == both("127.0.0.1", 8080))
        #expect(managed.managedByUs == true)
        #expect(managed.detail == "HTTP and HTTPS → 127.0.0.1:8080 (this core)")
        let off = try #require(SystemProxyFacts(compact: [
            "state": "off", "host": nil, "port": nil, "managed_by_us": false, "setting": true,
            "supported": true, "detail": "system proxy off",
        ], listenAddress: listen))
        #expect(off.word == .off)
        #expect(off.state == .off)
        #expect(off.setting == true)
        #expect(off.managedByUs == false)
    }

    /// The full `proxy.system.status` object: `guidance` is the env-var line when unsupported, `remedy` the
    /// privilege sentence when an administrator is needed (§D6); its other keys are ignored; a blank or
    /// null sentence is no sentence.
    @Test func theFullStatusObjectCarriesGuidanceAndRemedy() throws {
        let unsupported = try #require(SystemProxyFacts(compact: [
            "state": "unsupported", "host": nil, "port": nil, "detail": "no supported mechanism on this system",
            "ours": ["host": "127.0.0.1", "port": 8080], "mechanism": "none", "supported": false, "managed_by_us": false,
            "setting": false, "effective": nil, "services": [], "bypass_default": ["localhost", "127.0.0.1"],
            "guidance": "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080", "remedy": nil,
            "last_change_ms": nil, "watchdog_pid": nil, "state_file": "/Users/op/Library/Application Support/aitmproxy/system-proxy-state.json",
        ], listenAddress: listen))
        #expect(unsupported.word == .unsupported)
        #expect(unsupported.state == nil)
        #expect(unsupported.supported == false)
        #expect(unsupported.managedByUs == false)
        #expect(unsupported.guidance == "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080")
        #expect(unsupported.remedy == nil)
        #expect(unsupported.detail == "no supported mechanism on this system")

        let needsPrivilege = try #require(SystemProxyFacts(compact: [
            "state": "needs_privilege", "host": nil, "port": nil, "detail": "networksetup needs an administrator",
            "mechanism": "networksetup", "supported": true, "managed_by_us": false, "setting": false,
            "guidance": nil, "remedy": "macOS asks for an administrator to change network settings on this Mac.",
        ], listenAddress: listen))
        #expect(needsPrivilege.word == .needsPrivilege)
        #expect(needsPrivilege.state == nil)
        #expect(needsPrivilege.supported == true)
        #expect(needsPrivilege.remedy == "macOS asks for an administrator to change network settings on this Mac.")
        #expect(needsPrivilege.guidance == nil)

        let pointsAtUs = try #require(SystemProxyFacts(compact: [
            "state": "points_at_us", "host": nil, "port": nil, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)",
            "ours": ["host": "127.0.0.1", "port": 8080], "mechanism": "networksetup", "supported": true, "managed_by_us": true,
            "setting": false, "guidance": nil, "remedy": nil, "last_change_ms": 1_730_000_000_000, "watchdog_pid": 4242,
        ], listenAddress: listen))
        #expect(pointsAtUs.word == .pointsAtUs)
        #expect(pointsAtUs.state == both("127.0.0.1", 8080))
        #expect(pointsAtUs.managedByUs == true)
        #expect(pointsAtUs.remedy == nil)
        #expect(pointsAtUs.guidance == nil)

        // Blank sentences read as absent, so no surface prints an empty remedy clause.
        let blank = try #require(SystemProxyFacts(compact: [
            "state": "needs_privilege", "supported": true, "remedy": "   ", "guidance": "",
        ], listenAddress: listen))
        #expect(blank.remedy == nil)
        #expect(blank.guidance == nil)
    }

    @Test func aNonObjectOrMissingStateIsNil() {
        #expect(SystemProxyFacts(compact: .null, listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: "other", listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: 7, listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: true, listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: [], listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: [:], listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: ["host": "127.0.0.1", "port": 9090, "supported": true], listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: ["state": nil, "supported": true], listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: ["state": 3, "supported": true], listenAddress: listen) == nil)
        #expect(SystemProxyFacts(compact: ["state": ["off"]], listenAddress: listen) == nil)
    }

    /// A state word this build does not know is `unknown` (never off, never ours); the booleans the object
    /// lacks read as not managed (nil), not setting, and NOT supported (the core always sends `supported`;
    /// a missing one is not a yes).
    @Test func anUnknownStateWordParsesAsUnknown() throws {
        let future = try #require(SystemProxyFacts(compact: ["state": "banana", "supported": true, "detail": "?"], listenAddress: listen))
        #expect(future.word == .unknown)
        #expect(future.state == nil)
        #expect(future.supported == true)
        #expect(future.detail == "?")
        let bare = try #require(SystemProxyFacts(compact: ["state": "unknown"], listenAddress: listen))
        #expect(bare.word == .unknown)
        #expect(bare.state == nil)
        #expect(bare.managedByUs == nil)
        #expect(bare.setting == false)
        #expect(bare.supported == false)
        #expect(bare.detail == "")
        #expect(bare.remedy == nil)
        #expect(bare.guidance == nil)
        #expect(bare == SystemProxyFacts(word: .unknown, supported: false))
        // Booleans of the wrong type read as absent too.
        let typed = try #require(SystemProxyFacts(compact: [
            "state": "off", "managed_by_us": "false", "setting": 1, "supported": "yes", "detail": 5,
        ], listenAddress: listen))
        #expect(typed.managedByUs == nil)
        #expect(typed.setting == false)
        #expect(typed.supported == false)
        #expect(typed.detail == "")
        // The memberwise init's own defaults: supported is true there (a value a surface builds by hand is
        // a complete fact), the rest match the wire's absent values.
        let byHand = SystemProxyFacts(word: .off)
        #expect(byHand.state == nil && byHand.managedByUs == nil && byHand.setting == false && byHand.supported == true)
        #expect(byHand.detail == "" && byHand.remedy == nil && byHand.guidance == nil)
    }

    /// §D6's partial case: `other` is the core's verdict, and an `other` whose one endpoint is our own
    /// address cannot be expressed as two equal endpoints, so it carries no `state` (the word stands).
    @Test func otherAtOurOwnEndpointHasNoState() throws {
        let compact: JSONValue = [
            "state": "other", "host": "127.0.0.1", "port": 8080, "managed_by_us": false, "setting": false,
            "supported": true, "detail": "HTTP → 127.0.0.1:8080, HTTPS off",
        ]
        let partial = try #require(SystemProxyFacts(compact: compact, listenAddress: listen))
        #expect(partial.word == .other)
        #expect(partial.state == nil)
        #expect(partial.supported == true)
        #expect(partial.managedByUs == false)
        #expect(partial.detail == "HTTP → 127.0.0.1:8080, HTTPS off")
        #expect(SystemProxyFacts(compact: compact, listenAddress: "localhost:8080")?.state == nil)
        #expect(SystemProxyFacts(compact: compact, listenAddress: "0.0.0.0:8080")?.state == nil)
        // Against a core on another port the same object is an ordinary `other`.
        let elsewhere = try #require(SystemProxyFacts(compact: compact, listenAddress: "127.0.0.1:9090"))
        #expect(elsewhere.word == .other)
        #expect(elsewhere.state == both("127.0.0.1", 8080))
        // An `other` without a usable endpoint keeps the word and drops the state.
        #expect(SystemProxyFacts(compact: ["state": "other", "supported": true], listenAddress: listen)?.word == .other)
        #expect(SystemProxyFacts(compact: ["state": "other", "supported": true], listenAddress: listen)?.state == nil)
        #expect(SystemProxyFacts(compact: ["state": "other", "host": "10.0.0.5", "port": 0], listenAddress: listen)?.state == nil)
    }

    /// D13 "Facts in": the 500 ms compact poll keeps the last full read's guidance and remedy
    /// while the word is unchanged, and drops them when the word changes.
    @Test func aCompactPollKeepsTheFullReadsGuidanceAndRemedy() {
        let full = SystemProxyFacts(word: .unsupported, supported: false, detail: "no mechanism",
                                    guidance: "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080")
        let compact = SystemProxyFacts(word: .unsupported, supported: false, detail: "no mechanism")
        #expect(compact.keepingFullFields(from: full).guidance
                == "export http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080")
        #expect(compact.keepingFullFields(from: nil) == compact)
        let off = SystemProxyFacts(word: .off, detail: "HTTP and HTTPS off")
        #expect(off.keepingFullFields(from: full) == off, "a new word drops the old guidance")
        let fresh = SystemProxyFacts(word: .needsPrivilege, detail: "x", remedy: "new remedy")
        #expect(fresh.keepingFullFields(from: SystemProxyFacts(word: .needsPrivilege, detail: "x", remedy: "old")).remedy == "new remedy",
                "a value that carries its own fields keeps them")
    }
}
