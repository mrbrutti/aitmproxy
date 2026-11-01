import Foundation
import Testing

@testable import AitmproxyKit

/// `SystemProxyState` is the macOS system HTTP/HTTPS proxy as a value: read from the
/// `CFNetworkCopySystemProxySettings` / `scutil --proxy` dictionary between polls, or from
/// the core's compact `proxy.status.system_proxy` object; `route(to:)` says whether it
/// points at this core, at another proxy, or is off.
struct SystemProxyStateTests {
    private typealias Endpoint = SystemProxyState.Endpoint

    private let us = Endpoint(host: "127.0.0.1", port: 8080)

    // MARK: Endpoint

    @Test func anEndpointRendersAsHostColonPort() {
        #expect(Endpoint(host: "127.0.0.1", port: 8080).address == "127.0.0.1:8080")
        #expect(Endpoint(host: "proxy.corp.example", port: 3128).address == "proxy.corp.example:3128")
    }

    // MARK: init(settings:) — the CFNetwork / scutil dictionary

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

    @Test func settingsAcceptSwiftIntDoubleAndBoolAsTheEnableFlag() {
        let asInt = SystemProxyState(settings: ["HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080])
        #expect(asInt.http == us)
        let asDouble = SystemProxyState(settings: ["HTTPEnable": 1.0, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080])
        #expect(asDouble.http == us)
        let asBool = SystemProxyState(settings: ["HTTPEnable": true, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080])
        #expect(asBool.http == us)
        let falseFlag = SystemProxyState(settings: ["HTTPEnable": false, "HTTPProxy": "127.0.0.1", "HTTPPort": 8080])
        #expect(falseFlag.http == nil)
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
    }

    @Test func aWildcardListenAddressMatchesALoopbackProxy() {
        let state = SystemProxyState(http: us, https: us)
        #expect(state.route(to: "0.0.0.0:8080") == .thisCore(http: true, https: true))
        #expect(state.route(to: ":::8080") == .thisCore(http: true, https: true))
        #expect(state.route(to: "[::]:8080") == .thisCore(http: true, https: true))
        // A wildcard listen does not claim a proxy on another machine.
        let lan = Endpoint(host: "10.0.0.5", port: 8080)
        #expect(SystemProxyState(http: lan, https: lan).route(to: "0.0.0.0:8080") == .other(host: "10.0.0.5", port: 8080))
    }

    @Test func aDifferentPortIsAnotherProxy() {
        let proxyman = Endpoint(host: "127.0.0.1", port: 9090)
        let state = SystemProxyState(http: proxyman, https: proxyman)
        #expect(state.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func aDifferentHostOnOurPortIsAnotherProxy() {
        let lan = Endpoint(host: "10.0.0.5", port: 8080)
        #expect(SystemProxyState(http: lan, https: lan).route(to: "127.0.0.1:8080") == .other(host: "10.0.0.5", port: 8080))
        // Same host spelled with a different case still matches.
        let corp = Endpoint(host: "Proxy.Corp.Example", port: 3128)
        #expect(SystemProxyState(http: corp, https: corp).route(to: "proxy.corp.example:3128") == .thisCore(http: true, https: true))
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
    }

    // MARK: init?(compact:listenAddress:) — the core's proxy.status.system_proxy object

    @Test func compactPointsAtUsIsBothProtocolsAtTheListenAddress() {
        let compact: [String: Any] = [
            "state": "points_at_us", "host": NSNull(), "port": NSNull(), "managed_by_us": true, "setting": false,
            "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:8080 (this core)",
        ]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == SystemProxyState(http: us, https: us))
        #expect(SystemProxyState(compact: compact, listenAddress: "localhost:8181") == SystemProxyState(http: Endpoint(host: "localhost", port: 8181), https: Endpoint(host: "localhost", port: 8181)))
    }

    @Test func compactPointsAtUsRewritesAWildcardListenHostToLoopback() {
        let compact: [String: Any] = ["state": "points_at_us"]
        #expect(SystemProxyState(compact: compact, listenAddress: "0.0.0.0:8080") == SystemProxyState(http: us, https: us))
        #expect(SystemProxyState(compact: compact, listenAddress: "[::]:8080") == SystemProxyState(http: us, https: us))
        #expect(SystemProxyState(compact: compact, listenAddress: ":::8080") == SystemProxyState(http: us, https: us))
        // The result must route back to the same core.
        #expect(SystemProxyState(compact: compact, listenAddress: "0.0.0.0:8080")?.route(to: "0.0.0.0:8080") == .thisCore(http: true, https: true))
    }

    @Test func compactPointsAtUsWithAnUnparsableListenAddressIsNil() {
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "nonsense") == nil)
        #expect(SystemProxyState(compact: ["state": "points_at_us"], listenAddress: "127.0.0.1:0") == nil)
    }

    @Test func compactOtherIsBothProtocolsAtTheGivenEndpoint() {
        let compact: [String: Any] = [
            "state": "other", "host": "127.0.0.1", "port": 9090, "managed_by_us": false, "setting": false,
            "supported": true, "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
        ]
        let expected = SystemProxyState(http: Endpoint(host: "127.0.0.1", port: 9090), https: Endpoint(host: "127.0.0.1", port: 9090))
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == expected)
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080")?.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func compactOtherAcceptsThePortAsANumericString() {
        let compact: [String: Any] = ["state": "other", "host": "10.0.0.5", "port": "3128"]
        let expected = SystemProxyState(http: Endpoint(host: "10.0.0.5", port: 3128), https: Endpoint(host: "10.0.0.5", port: 3128))
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == expected)
        let asNSNumber: [String: Any] = ["state": "other", "host": "10.0.0.5", "port": NSNumber(value: 3128)]
        #expect(SystemProxyState(compact: asNSNumber, listenAddress: "127.0.0.1:8080") == expected)
    }

    @Test func compactOffIsOff() {
        let compact: [String: Any] = [
            "state": "off", "host": NSNull(), "port": NSNull(), "managed_by_us": false, "setting": false,
            "supported": true, "detail": "system proxy off",
        ]
        #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == .off)
        #expect(SystemProxyState(compact: ["state": "off"], listenAddress: "nonsense") == .off)
    }

    @Test func compactUnsupportedNeedsPrivilegeAndUnknownCarryNoState() {
        for state in ["unsupported", "needs_privilege", "unknown"] {
            let compact: [String: Any] = ["state": state, "supported": state != "unsupported", "detail": "x"]
            #expect(SystemProxyState(compact: compact, listenAddress: "127.0.0.1:8080") == nil, "\(state)")
        }
    }

    @Test func aMalformedCompactObjectIsNil() {
        #expect(SystemProxyState(compact: [:], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": 42], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "bogus"], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["host": "127.0.0.1", "port": 9090], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other"], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "host": "127.0.0.1"], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "port": 9090], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "host": "", "port": 9090], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "host": "127.0.0.1", "port": "abc"], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "host": "127.0.0.1", "port": NSNull()], listenAddress: "127.0.0.1:8080") == nil)
        #expect(SystemProxyState(compact: ["state": "other", "host": "127.0.0.1", "port": 0], listenAddress: "127.0.0.1:8080") == nil)
    }

    @Test func theFullStatusObjectOfTheSpecParsesLikeTheCompactOne() {
        // §D6's `proxy.system.status` example, with its extra fields present.
        let full: [String: Any] = [
            "state": "other", "host": "127.0.0.1", "port": 9090,
            "detail": "HTTP and HTTPS → 127.0.0.1:9090 (not this core)",
            "ours": ["host": "127.0.0.1", "port": 8080] as [String: Any],
            "mechanism": "networksetup", "supported": true, "managed_by_us": false, "setting": false,
            "effective": [
                "http": ["enabled": true, "host": "127.0.0.1", "port": 9090] as [String: Any],
                "https": ["enabled": true, "host": "127.0.0.1", "port": 9090] as [String: Any],
                "bypass": ["*.local", "169.254/16"],
            ] as [String: Any],
            "services": [] as [Any], "bypass_default": ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16"],
            "guidance": NSNull(), "remedy": NSNull(), "last_change_ms": NSNull(), "watchdog_pid": NSNull(),
            "state_file": "/Users/matt/Library/Application Support/aitmproxy/system-proxy-state.json",
        ]
        let state = SystemProxyState(compact: full, listenAddress: "127.0.0.1:8080")
        #expect(state?.http == Endpoint(host: "127.0.0.1", port: 9090))
        #expect(state?.https == Endpoint(host: "127.0.0.1", port: 9090))
        #expect(state?.route(to: "127.0.0.1:8080") == .other(host: "127.0.0.1", port: 9090))
    }

    @Test func statesAndRoutesAreHashableByValue() {
        #expect(SystemProxyState(http: us, https: us) == SystemProxyState(http: us, https: us))
        #expect(SystemProxyState(http: us, https: nil) != SystemProxyState(http: nil, https: us))
        #expect(SystemProxyRoute.thisCore(http: true, https: false) != SystemProxyRoute.thisCore(http: true, https: true))
        #expect(SystemProxyRoute.other(host: "a", port: 1) != SystemProxyRoute.other(host: "a", port: 2))
        let set: Set<SystemProxyRoute> = [.off, .off, .thisCore(http: true, https: true), .other(host: "x", port: 1)]
        #expect(set.count == 3)
    }
}
