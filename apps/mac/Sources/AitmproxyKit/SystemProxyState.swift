import AitmBusClient
import Foundation

/// The macOS system HTTP and HTTPS proxy as a value (spec
/// 2026-10-31-system-proxy-automation-design, §D6, §D13). Two sources feed it: the
/// `CFNetworkCopySystemProxySettings` dictionary, which the app reads between bus polls, and
/// the core's compact `proxy.status.system_proxy` object (or the full `proxy.system.status`
/// result). `route(to:)` answers the one question the surfaces ask: does the system proxy
/// point at this core, at another proxy, or is it off.
///
/// Pure data, `Hashable` and `Sendable`, no SwiftUI. Reading the system setting and
/// calling the verbs live elsewhere (`Session`); this type never shells out.
public struct SystemProxyState: Hashable, Sendable {
    /// One protocol's proxy: where its traffic is sent.
    public struct Endpoint: Hashable, Sendable {
        public let host: String
        public let port: Int

        /// `host:port`, the spelling the word table and the listening pill use.
        public var address: String { "\(host):\(port)" }

        public init(host: String, port: Int) {
            self.host = host
            self.port = port
        }

        /// `host:port` split at the last colon. A host that itself contains a colon (an IPv6
        /// literal) must be bracketed, `[::1]:8080`, so a bare `::1` or `fe80::1` is not an
        /// address (nil) rather than host `:` with port 1. The host must be non-empty and the
        /// port in 1...65535.
        init?(address: String) {
            guard let colon = address.lastIndex(of: ":") else { return nil }
            let host = address[..<colon].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, !host.contains(":") || SystemProxyState.isBracketed(host) else { return nil }
            let portText = address[address.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let port = Int(portText).flatMap(SystemProxyState.validPort) else { return nil }
            self.init(host: host, port: port)
        }

        /// The host lower-cased with IPv6 brackets stripped, so `[::1]` and `::1` compare equal.
        var comparableHost: String { SystemProxyState.comparable(host) }

        /// Whether this proxy endpoint is the core listening at `listen`: equal ports and a
        /// host that is the same name (case-insensitively, brackets aside), another spelling
        /// of loopback, or any loopback when the core listens on a wildcard address.
        func matches(listen: Endpoint) -> Bool {
            guard port == listen.port else { return false }
            let mine = comparableHost
            let theirs = listen.comparableHost
            if mine == theirs { return true }
            let bothLoopback = SystemProxyState.loopbackHosts.contains(mine) && SystemProxyState.loopbackHosts.contains(theirs)
            let wildcardListen = SystemProxyState.wildcardHosts.contains(theirs) && SystemProxyState.loopbackHosts.contains(mine)
            return bothLoopback || wildcardListen
        }
    }

    /// The HTTP proxy; nil when the HTTP proxy is off.
    public let http: Endpoint?
    /// The HTTPS proxy; nil when the HTTPS proxy is off.
    public let https: Endpoint?

    public init(http: Endpoint?, https: Endpoint?) {
        self.http = http
        self.https = https
    }

    /// No proxy for either protocol.
    public static let off = SystemProxyState(http: nil, https: nil)

    // MARK: From the CFNetwork dictionary

    /// From `CFNetworkCopySystemProxySettings()`: the keys `HTTPEnable`, `HTTPProxy`,
    /// `HTTPPort`, `HTTPSEnable`, `HTTPSProxy`, `HTTPSPort`. "Enable" is any non-zero number
    /// (`Int`, `Double`, `Bool`, `NSNumber`); the port is a number or a numeric string. A
    /// protocol is an `Endpoint` only when it is enabled AND its host is non-empty AND its
    /// port parses; anything less is off for that protocol.
    public init(settings: [String: Any]) {
        self.init(
            http: SystemProxyState.endpoint(settings, enable: "HTTPEnable", host: "HTTPProxy", port: "HTTPPort"),
            https: SystemProxyState.endpoint(settings, enable: "HTTPSEnable", host: "HTTPSProxy", port: "HTTPSPort")
        )
    }

    // MARK: From the core's status object

    /// From the core's compact `proxy.status.system_proxy` object (or the full
    /// `proxy.system.status` result, which carries the same `state`/`host`/`port`) plus the
    /// core's own listen address. `points_at_us` → both protocols at `listenAddress` (a
    /// wildcard host `0.0.0.0`, `::` or `[::]` becomes `127.0.0.1`); `other` → both
    /// protocols at the object's `host`:`port` (the compact object carries one endpoint);
    /// `off` → `.off`.
    ///
    /// Nil when there is no endpoint fact to show: `unsupported`, `needs_privilege`,
    /// `unknown`, an unknown state, a missing `state`, an `other` without a usable host and
    /// port, a `points_at_us` with an unparsable listen address, or an `other` whose endpoint
    /// is this core's own listen address. That last one is §D6's partial case ("HTTP →
    /// 127.0.0.1:8080, HTTPS off"): `other` is the core's verdict, and two equal endpoints
    /// cannot express it, so they must never route back as `.thisCore`.
    public init?(compact: JSONValue, listenAddress: String) {
        guard let state = compact["state"]?.stringValue else { return nil }
        let listen = Endpoint(address: listenAddress)
        switch state {
        case "off":
            self.init(http: nil, https: nil)
        case "points_at_us":
            guard let listen else { return nil }
            let host = SystemProxyState.wildcardHosts.contains(listen.comparableHost) ? "127.0.0.1" : listen.host
            let ours = Endpoint(host: host, port: listen.port)
            self.init(http: ours, https: ours)
        case "other":
            guard let host = SystemProxyState.wireHost(compact["host"]), let port = SystemProxyState.wirePort(compact["port"]) else {
                return nil
            }
            let theirs = Endpoint(host: host, port: port)
            if let listen, theirs.matches(listen: listen) { return nil }
            self.init(http: theirs, https: theirs)
        default:
            return nil
        }
    }

    // MARK: Route

    /// Where the system proxy sends traffic relative to the core listening at
    /// `listenAddress` (`host:port`). `.thisCore` when at least one protocol matches, with a
    /// flag per protocol; `.off` when both protocols are off; `.other` otherwise, naming the
    /// HTTP endpoint, else the HTTPS one. An unparsable listen address matches nothing.
    public func route(to listenAddress: String) -> SystemProxyRoute {
        guard let first = http ?? https else { return .off }
        guard let listen = Endpoint(address: listenAddress) else { return .other(host: first.host, port: first.port) }
        let httpMatches = http?.matches(listen: listen) ?? false
        let httpsMatches = https?.matches(listen: listen) ?? false
        if httpMatches || httpsMatches { return .thisCore(http: httpMatches, https: httpsMatches) }
        return .other(host: first.host, port: first.port)
    }

    // MARK: Spellings

    /// Comparable (lower-cased, unbracketed) spellings of the loopback host that all mean this machine.
    private static let loopbackHosts: Set<String> = ["127.0.0.1", "localhost", "::1"]
    /// Comparable spellings of a wildcard listen host; a core bound to one is reachable on loopback.
    private static let wildcardHosts: Set<String> = ["0.0.0.0", "::"]

    private static func isBracketed(_ host: String) -> Bool {
        host.hasPrefix("[") && host.hasSuffix("]") && host.count > 2
    }

    /// Lower-cased, with surrounding IPv6 brackets removed.
    private static func comparable(_ host: String) -> String {
        let lowered = host.lowercased()
        return isBracketed(lowered) ? String(lowered.dropFirst().dropLast()) : lowered
    }

    /// `port` when it is in 1...65535, else nil.
    private static func validPort(_ port: Int) -> Int? {
        (1...65535).contains(port) ? port : nil
    }

    /// `text` trimmed, when that leaves something.
    private static func nonEmpty(_ text: String?) -> String? {
        guard let text = text?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
        return text
    }

    // MARK: Coercions — the CFNetwork dictionary

    private static func endpoint(_ settings: [String: Any], enable: String, host: String, port: String) -> Endpoint? {
        guard isEnabled(settings[enable]), let host = settingsHost(settings[host]), let port = settingsPort(settings[port]) else {
            return nil
        }
        return Endpoint(host: host, port: port)
    }

    /// Any non-zero number. `Int`, `Double` and `Bool` all bridge to `NSNumber`; a string or
    /// a missing value is not enabled.
    private static func isEnabled(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber else { return false }
        return number.doubleValue != 0
    }

    private static func settingsHost(_ value: Any?) -> String? {
        nonEmpty(value as? String)
    }

    /// A number or a numeric string in 1...65535.
    private static func settingsPort(_ value: Any?) -> Int? {
        let number: Int?
        if let text = value as? String {
            number = Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
        } else if let n = value as? NSNumber {
            number = n.intValue
        } else {
            number = nil
        }
        return number.flatMap(validPort)
    }

    // MARK: Coercions — the bus object

    private static func wireHost(_ value: JSONValue?) -> String? {
        nonEmpty(value?.stringValue)
    }

    /// An integral number (`intValue` rejects a fractional one) or a numeric string, in 1...65535.
    private static func wirePort(_ value: JSONValue?) -> Int? {
        let number = value?.intValue ?? value?.stringValue.flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        return number.flatMap(validPort)
    }
}

/// Where the system proxy sends traffic, relative to one core (`SystemProxyState.route(to:)`).
public enum SystemProxyRoute: Hashable, Sendable {
    /// Neither protocol has a proxy: proxy-aware apps bypass the core.
    case off
    /// At least one protocol points at this core; the flags say which.
    case thisCore(http: Bool, https: Bool)
    /// Both configured protocols point elsewhere; the HTTP endpoint, else the HTTPS one.
    case other(host: String, port: Int)
}
