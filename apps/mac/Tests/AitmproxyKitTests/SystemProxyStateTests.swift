import AitmBusClient
import Foundation
import Testing

@testable import AitmproxyKit

/// `SystemProxyState` is the macOS system HTTP/HTTPS proxy as a value: read from the
/// `CFNetworkCopySystemProxySettings` dictionary between polls, or from the core's compact
/// `proxy.status.system_proxy` object; `route(to:)` says whether it points at this core, at
/// another proxy, or is off.
struct SystemProxyStateTests {
    private typealias Endpoint = SystemProxyState.Endpoint

    private let us = Endpoint(host: "127.0.0.1", port: 8080)

    // MARK: Endpoint

    @Test func anEndpointRendersAsHostColonPort() {
        #expect(Endpoint(host: "127.0.0.1", port: 8080).address == "127.0.0.1:8080")
        #expect(Endpoint(host: "proxy.corp.example", port: 3128).address == "proxy.corp.example:3128")
        #expect(Endpoint(host: "[::1]", port: 8080).address == "[::1]:8080")
        // A bare IPv6 host is bracketed for display; an already-bracketed one is not bracketed twice.
        #expect(Endpoint(host: "::1", port: 8080).address == "[::1]:8080")
        #expect(Endpoint(host: "2001:db8::1", port: 8080).address == "[2001:db8::1]:8080")
    }

    /// `host:port` splits at the last colon; a host with a colon in it (IPv6) must be bracketed,
    /// so a bare literal is not an address rather than a host of `:` with port 1.
    @Test(arguments: [
        (address: "127.0.0.1:8080", expected: SystemProxyState.Endpoint(host: "127.0.0.1", port: 8080)),
        (address: "localhost:8181", expected: SystemProxyState.Endpoint(host: "localhost", port: 8181)),
        (address: "proxy.corp.example:3128", expected: SystemProxyState.Endpoint(host: "proxy.corp.example", port: 3128)),
        (address: "0.0.0.0:8080", expected: SystemProxyState.Endpoint(host: "0.0.0.0", port: 8080)),
        (address: "[::1]:8080", expected: SystemProxyState.Endpoint(host: "[::1]", port: 8080)),
        (address: "[::]:8080", expected: SystemProxyState.Endpoint(host: "[::]", port: 8080)),
        (address: "[2001:db8::1]:8080", expected: SystemProxyState.Endpoint(host: "[2001:db8::1]", port: 8080)),
        (address: "::1", expected: nil),
        (address: "fe80::1", expected: nil),
        (address: "::1:8080", expected: nil),
        (address: ":::8080", expected: nil),
        (address: "2001:db8::1:8080", expected: nil),
        (address: "", expected: nil),
        (address: "127.0.0.1", expected: nil),
        (address: ":8080", expected: nil),
        (address: "127.0.0.1:", expected: nil),
        (address: "127.0.0.1:port", expected: nil),
        (address: "127.0.0.1:0", expected: nil),
        (address: "127.0.0.1:70000", expected: nil),
    ] as [(address: String, expected: SystemProxyState.Endpoint?)])
    func anAddressParsesOnlyWithAHostAndAPortAndBracketsAroundIPv6(_ row: (address: String, expected: SystemProxyState.Endpoint?)) {
        #expect(Endpoint(address: row.address) == row.expected, "\(row.address)")
    }

    // MARK: init(settings:) — the CFNetwork dictionary

    @Test func settingsWithNumberFlagsAndIntPortsGiveBothEndpoints() {
        let settings: [String: Any] = [
            "HTTPEnable": NSNumber(value: 1), "HTTPProxy": "127.0.0.1", "HTTPPort": NSNumber(value: 8080),
            "HTTPSEnable": NSNumber(value: 1), "HTTPSProxy": "127.0.0.1", "HTTPSPort": NSNumber(value: 8080),
        ]
        let state = SystemProxyState(settings: settings)
        #expect(state.http == Endpoint(host: "127.0.0.1", port: 8080))
        #expect(state.https == Endpoint(host: "127.0.0.1", port: 8080))
        #expect(state == SystemProxyState(http: us, https: us))
    }

    /// The enable flag is any non-zero number; Swift `Int`, `Double` and `Bool` all bridge to
    /// `NSNumber` in a `[String: Any]`. A string is not a flag.
    @Test(arguments: [
        (name: "Int 1", flag: 1, enabled: true),
        (name: "Int 0", flag: 0, enabled: false),
        (name: "Double 1.0", flag: 1.0, enabled: true),
        (name: "Double 0.0", flag: 0.0, enabled: false),
        (name: "Bool true", flag: true, enabled: true),
        (name: "Bool false", flag: false, enabled: false),
        (name: "NSNumber 1", flag: NSNumber(value: 1), enabled: true),
        (name: "String \"1\"", flag: "1", enabled: false),
    ] as [(name: String, flag: any Sendable, enabled: Bool)])
    func settingsAcceptSwiftIntDoubleAndBoolAsTheEnableFlag(_ row: (name: String, flag: any Sendable, enabled: Bool)) {
        let state = SystemProxyState(settings: ["HTTPEnable": row.flag, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080])
        #expect(state.http == (row.enabled ? us : nil), "\(row.name)")
    }

    @Test func settingsAcceptThePortAsANumericString() {
        let state = SystemProxyState(settings: [
            "HTTPEnable": NSNumber(value: 1), "HTTPProxy": "127.0.0.1", "HTTPPort": "9090",
            "HTTPSEnable": NSNumber(value: 1), "HTTPSProxy": "127.0.0.1", "HTTPSPort": "9090",
        ])
        #expect(state.http == Endpoint(host: "127.0.0.1", port: 9090))
        #expect(state.https == Endpoint(host: "127.0.0.1", port: 9090))
    }

    @Test func aDisabledProtocolIsNilEvenWhenItsHostAndPortAreSet() {
        let state = SystemProxyState(settings: [
            "HTTPEnable": NSNumber(value: 0), "HTTPProxy": "127.0.0.1", "HTTPPort": NSNumber(value: 8080),
            "HTTPSEnable": NSNumber(value: 1), "HTTPSProxy": "127.0.0.1", "HTTPSPort": NSNumber(value: 8080),
        ])
        #expect(state.http == nil)
        #expect(state.https == Endpoint(host: "127.0.0.1", port: 8080))
    }

    @Test func anEnabledProtocolWithoutAHostOrAParsablePortIsNil() {
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPPort": 8080]).http == nil)
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "", "HTTPPort": 8080]).http == nil)
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1"]).http == nil)
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": "eighty"]).http == nil)
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 0]).http == nil)
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 70000]).http == nil)
        // A fractional port is rejected here as it is on the wire path, not truncated.
        #expect(SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080.7]).http == nil)
    }

    @Test func anEmptySettingsDictionaryIsOff() {
        #expect(SystemProxyState(settings: [:]) == .off)
        // Unrelated keys (SOCKS, auto-config) do not make an HTTP or HTTPS endpoint.
        #expect(SystemProxyState(settings: ["SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 1080]) == .off)
    }

    // MARK: off

    @Test func offHasNoEndpointsAndRoutesToOff() {
        #expect(SystemProxyState.off.http == nil)
        #expect(SystemProxyState.off.https == nil)
        #expect(SystemProxyState.off == SystemProxyState(http: nil, https: nil))
        #expect(SystemProxyState.off.route(to: "127.0.0.1:8080") == .off)
        #expect(SystemProxyState(http: nil, https: nil).route(to: "127.0.0.1:8080") == .off)
    }

    // MARK: route(to:)

    @Test func bothProtocolsAtOurAddressRouteToThisCore() {
        let state = SystemProxyState(http: us, https: us)
        #expect(state.route(to: "127.0.0.1:8080") == .thisCore(http: true, https: true))
    }

    @Test func localhostSpellingsMatchOurLoopbackAddress() {
        let localhost = Endpoint(host: "localhost", port: 8080)
        #expect(SystemProxyState(http: localhost, https: localhost).route(to: "127.0.0.1:8080") == .thisCore(http: true, https: true))
        let upper = Endpoint(host: "LOCALHOST", port: 8080)
        #expect(SystemProxyState(http: upper, https: upper).route(to: "127.0.0.1:8080") == .thisCore(http: true, https: true))
        let v6 = Endpoint(host: "::1", port: 8080)
        #expect(SystemProxyState(http: v6, https: v6).route(to: "127.0.0.1:8080") == .thisCore(http: true, https: true))
        let bracketed = Endpoint(host: "[::1]", port: 8080)
        #expect(SystemProxyState(http: bracketed, https: bracketed).route(to: "localhost:8080") == .thisCore(http: true, https: true))
        // A core listening on IPv6 loopback is the same machine as a proxy at 127.0.0.1.
        #expect(SystemProxyState(http: us, https: us).route(to: "[::1]:8080") == .thisCore(http: true, https: true))
    }

    @Test func aWildcardListenAddressMatchesALoopbackProxy() {
        let state = SystemProxyState(http: us, https: us)
        #expect(state.route(to: "0.0.0.0:8080") == .thisCore(http: true, https: true))
        #expect(state.route(to: "[::]:8080") == .thisCore(http: true, https: true))
        // A wildcard listen does not claim a proxy on another machine.
        let lan = Endpoint(host: "10.0.0.5", port: 8080)
        #expect(SystemProxyState(http: lan, https: lan).route(to: "0.0.0.0:8080") == .other(host: "10.0.0.5", port: 8080))
    }

    @Test func bracketsAroundAnIPv6HostDoNotMatter() {
        let bare = Endpoint(host: "2001:db8::1", port: 8080)
        #expect(SystemProxyState(http: bare, https: bare).route(to: "[2001:db8::1]:8080") == .thisCore(http: true, https: true))
        let bracketed = Endpoint(host: "[2001:db8::1]", port: 8080)
        #expect(SystemProxyState(http: bracketed, https: bracketed).route(to: "[2001:db8::1]:8080") == .thisCore(http: true, https: true))
        let upper = Endpoint(host: "2001:DB8::1", port: 8080)
        #expect(SystemProxyState(http: upper, https: upper).route(to: "[2001:db8::1]:8080") == .thisCore(http: true, https: true))
        // A different IPv6 address on the same port is another proxy.
        let elsewhere = Endpoint(host: "2001:db8::2", port: 8080)
        #expect(SystemProxyState(http: elsewhere, https: elsewhere).route(to: "[2001:db8::1]:8080") == .other(host: "2001:db8::2", port: 8080))
    }

    @Test func aDifferentPortIsAnotherProxy() {
        let proxyman = Endpoint(host: "127.0.0.1", port: 9090)
        let state = SystemProxyState(http: proxyman, https: proxyman)
        #expect(state.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func aDifferentHostOnOurPortIsAnotherProxy() {
        let lan = Endpoint(host: "10.0.0.5", port: 8080)
        #expect(SystemProxyState(http: lan, https: lan).route(to: "127.0.0.1:8080") == .other(host: "10.0.0.5", port: 8080))
    }

    @Test func hostnameCaseDoesNotMatter() {
        let corp = Endpoint(host: "Proxy.Corp.Example", port: 3128)
        #expect(SystemProxyState(http: corp, https: corp).route(to: "proxy.corp.example:3128") == .thisCore(http: true, https: true))
        #expect(SystemProxyState(http: corp, https: corp).route(to: "PROXY.CORP.EXAMPLE:3128") == .thisCore(http: true, https: true))
    }

    @Test func httpAtUsWithHttpsOffIsThisCoreForHttpOnly() {
        #expect(SystemProxyState(http: us, https: nil).route(to: "127.0.0.1:8080") == .thisCore(http: true, https: false))
        #expect(SystemProxyState(http: nil, https: us).route(to: "127.0.0.1:8080") == .thisCore(http: false, https: true))
    }

    @Test func oneProtocolAtUsAndTheOtherElsewhereIsStillThisCore() {
        let proxyman = Endpoint(host: "127.0.0.1", port: 9090)
        #expect(SystemProxyState(http: proxyman, https: us).route(to: "127.0.0.1:8080") == .thisCore(http: false, https: true))
        #expect(SystemProxyState(http: us, https: proxyman).route(to: "127.0.0.1:8080") == .thisCore(http: true, https: false))
    }

    @Test func otherTakesTheHttpEndpointElseTheHttpsOne() {
        let a = Endpoint(host: "127.0.0.1", port: 9090)
        let b = Endpoint(host: "10.0.0.5", port: 3128)
        #expect(SystemProxyState(http: a, https: b).route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
        #expect(SystemProxyState(http: nil, https: b).route(to: "127.0.0.1:8080") == .other(host: "10.0.0.5", port: 3128))
        #expect(SystemProxyState(http: b, https: nil).route(to: "127.0.0.1:8080") == .other(host: "10.0.0.5", port: 3128))
    }

    @Test func anUnparsableListenAddressNeverMatches() {
        let state = SystemProxyState(http: us, https: us)
        #expect(state.route(to: "") == .other(host: "127.0.0.1", port: 8080))
        #expect(state.route(to: "127.0.0.1") == .other(host: "127.0.0.1", port: 8080))
        #expect(state.route(to: "127.0.0.1:port") == .other(host: "127.0.0.1", port: 8080))
        // A bare IPv6 literal is not `host:port`, even when the proxy is on loopback.
        #expect(state.route(to: "::1") == .other(host: "127.0.0.1", port: 8080))
        #expect(state.route(to: "fe80::1") == .other(host: "127.0.0.1", port: 8080))
    }

    // MARK: init?(compact:listenAddress:) — the core's proxy.status.system_proxy object

    @Test func compactPointsAtUsIsBothProtocolsAtTheListenAddress() {
        let compact: JSONValue = [
            "state": "points_at_us", "host": nil, "port": nil, "managed_by_us": true, "setting": false,
            "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)",
        ]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == SystemProxyState(http: us, https: us))
        let localhost = Endpoint(host: "localhost", port: 8181)
        #expect(SystemProxyState(compact: compact, listenAddress: "localhost:8181") == SystemProxyState(http: localhost, https: localhost))
        let v6 = Endpoint(host: "[::1]", port: 8080)
        #expect(SystemProxyState(compact: compact, listenAddress: "[::1]:8080") == SystemProxyState(http: v6, https: v6))
    }

    @Test func compactPointsAtUsRewritesAWildcardListenHostToLoopback() {
        let compact: JSONValue = ["state": "points_at_us"]
        #expect(SystemProxyState(compact: compact, listenAddress: "0.0.0.0:8080") == SystemProxyState(http: us, https: us))
        #expect(SystemProxyState(compact: compact, listenAddress: "[::]:8080") == SystemProxyState(http: us, https: us))
        // The result must route back to the same core.
        #expect(SystemProxyState(compact: compact, listenAddress: "0.0.0.0:8080")?.route(to: "0.0.0.0:8080") == .thisCore(http: true, https: true))
        #expect(SystemProxyState(compact: compact, listenAddress: "[::]:8080")?.route(to: "[::]:8080") == .thisCore(http: true, https: true))
    }

    @Test func compactPointsAtUsWithAnUnparsableListenAddressIsNil() {
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "nonsense") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "127.0.0.1:0") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "::1") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: ":::8080") == nil)
    }

    @Test func compactOtherIsBothProtocolsAtTheGivenEndpoint() {
        let compact: JSONValue = [
            "state": "other", "host": "127.0.0.1", "port": 9090, "managed_by_us": false, "setting": false,
            "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
        ]
        let expected = SystemProxyState(http: Endpoint(host: "127.0.0.1", port: 9090), https: Endpoint(host: "127.0.0.1", port: 9090))
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == expected)
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080")?.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func compactOtherAcceptsThePortAsANumberOrANumericString() {
        let expected = SystemProxyState(http: Endpoint(host: "10.0.0.5", port: 3128), https: Endpoint(host: "10.0.0.5", port: 3128))
        let asNumber: JSONValue = ["state": "other", "host": "10.0.0.5", "port": 3128]
        #expect(SystemProxyState(compact: asNumber, listenAddress: "127.0.0.1:8080") == expected)
        let asString: JSONValue = ["state": "other", "host": "10.0.0.5", "port": "3128"]
        #expect(SystemProxyState(compact: asString, listenAddress: "127.0.0.1:8080") == expected)
    }

    /// §D6: `other` is the core's verdict, and covers the partial case where one protocol is at
    /// this core and the other is off or elsewhere. Two equal endpoints cannot say that and must
    /// never route back as `.thisCore`, so an `other` at our own address is nil (no fact to show).
    @Test func compactOtherAtOurOwnListenAddressIsNil() {
        let compact: JSONValue = ["state": "other", "host": "127.0.0.1", "port": 8080]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: compact, listenAddress: "localhost:8080") == nil)
        #expect(SystemProxyState(compact: compact, listenAddress: "0.0.0.0:8080") == nil)
        #expect(SystemProxyState(compact: compact, listenAddress: "[::]:8080") == nil)
        // The same object against a core on another port is an ordinary `other`.
        let state = SystemProxyState(compact: compact, listenAddress: "127.0.0.1:9090")
        #expect(state == SystemProxyState(http: us, https: us))
        #expect(state?.route(to: "127.0.0.1:9090") == .other(host: "127.0.0.1", port: 8080))
        // With no parsable listen address there is nothing to compare against; the endpoint stands.
        #expect(SystemProxyState(compact: compact, listenAddress: "nonsense") == SystemProxyState(http: us, https: us))
    }

    @Test func compactOffIsOff() {
        let compact: JSONValue = [
            "state": "off", "host": nil, "port": nil, "managed_by_us": false, "setting": false,
            "supported": true, "detail": "system proxy off",
        ]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == .off)
        #expect(SystemProxyState(compact: ["state": "off"], listenAddress: "nonsense") == .off)
    }

    @Test(arguments: [
        (state: "unsupported", supported: false),
        (state: "needs_privilege", supported: true),
        (state: "unknown", supported: true),
    ])
    func compactUnsupportedNeedsPrivilegeAndUnknownCarryNoState(_ row: (state: String, supported: Bool)) {
        let compact: JSONValue = ["state": .string(row.state), "supported": .bool(row.supported), "detail": "x"]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == nil, "\(row.state)")
    }

    @Test(arguments: [
        (name: "empty object", compact: [:]),
        (name: "not an object", compact: "off"),
        (name: "state is a number", compact: ["state": 42]),
        (name: "state is null", compact: ["state": nil]),
        (name: "unknown state", compact: ["state": "bogus"]),
        (name: "no state", compact: ["host": "127.0.0.1", "port": 9090]),
        (name: "other without host and port", compact: ["state": "other"]),
        (name: "other without port", compact: ["state": "other", "host": "127.0.0.1"]),
        (name: "other without host", compact: ["state": "other", "port": 9090]),
        (name: "other with an empty host", compact: ["state": "other", "host": "", "port": 9090]),
        (name: "other with a blank host", compact: ["state": "other", "host": "  ", "port": 9090]),
        (name: "other with a numeric host", compact: ["state": "other", "host": 127, "port": 9090]),
        (name: "other with a non-numeric port", compact: ["state": "other", "host": "127.0.0.1", "port": "abc"]),
        (name: "other with a null port", compact: ["state": "other", "host": "127.0.0.1", "port": nil]),
        (name: "other with a boolean port", compact: ["state": "other", "host": "127.0.0.1", "port": true]),
        (name: "other with a fractional port", compact: ["state": "other", "host": "127.0.0.1", "port": 9090.5]),
        (name: "other with port 0", compact: ["state": "other", "host": "127.0.0.1", "port": 0]),
        (name: "other with port 65536", compact: ["state": "other", "host": "127.0.0.1", "port": 65536]),
        (name: "other with a negative port", compact: ["state": "other", "host": "127.0.0.1", "port": -1]),
    ] as [(name: String, compact: JSONValue)])
    func aMalformedCompactObjectIsNil(_ row: (name: String, compact: JSONValue)) {
        #expect(SystemProxyState(compact: row.compact, listenAddress: "127.0.0.1:8080") == nil, "\(row.name)")
    }

    @Test func theFullStatusObjectOfTheSpecParsesLikeTheCompactOne() {
        // §D6's `proxy.system.status` example, with its extra fields present.
        let full: JSONValue = [
            "state": "other", "host": "127.0.0.1", "port": 9090,
            "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
            "ours": ["host": "127.0.0.1", "port": 8080],
            "mechanism": "networksetup", "supported": true, "managed_by_us": false, "setting": false,
            "effective": [
                "http": ["enabled": true, "host": "127.0.0.1", "port": 9090],
                "https": ["enabled": true, "host": "127.0.0.1", "port": 9090],
                "bypass": ["*.local", "169.254/16"],
            ],
            "services": [], "bypass_default": ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"],
            "guidance": nil, "remedy": nil, "last_change_ms": nil, "watchdog_pid": nil,
            "state_file": "/Users/matt/Library/Application Support/aitmproxy/system-proxy-state.json",
        ]
        let state = SystemProxyState(compact: full, listenAddress: "127.0.0.1:8080")
        #expect(state?.http == Endpoint(host: "127.0.0.1", port: 9090))
        #expect(state?.https == Endpoint(host: "127.0.0.1", port: 9090))
        #expect(state?.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func aParsedBusObjectIsAccepted() throws {
        // The shape the bus hands the Kit: parsed text, not a literal.
        let compact = try JSONValue.parse(#"{"state":"other","host":"10.0.0.5","port":3128,"supported":true,"detail":"x"}"#)
        let expected = SystemProxyState(http: Endpoint(host: "10.0.0.5", port: 3128), https: Endpoint(host: "10.0.0.5", port: 3128))
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == expected)
    }
}
