import Foundation

/// The macOS system HTTP and HTTPS proxy as a value (spec
/// 2026-10-31-system-proxy-automation-design, §D6, §D13). Two sources feed it: the
/// `CFNetworkCopySystemProxySettings` / `scutil --proxy` dictionary, which the app reads
/// between bus polls, and the core's compact `proxy.status.system_proxy` object (or the
/// full `proxy.system.status` result). `route(to:)` answers the one question the surfaces
/// ask: does the system proxy point at this core, at another proxy, or is it off.
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

        /// `host:port` split at the last colon, so `[::1]:8080` and `:::8080` keep their
        /// host. The host must be non-empty and the port in 1...65535.
        init?(address: String) {
            guard let colon = address.lastIndex(of: ":") else { return nil }
            let host = address[..<colon].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = SystemProxyState.port(String(address[address.index(after: colon)...])) else {
                return nil
            }
            self.init(host: host, port: port)
        }

        /// Whether this proxy endpoint is the core listening at `listen`: equal ports and a
        /// host that is the same name (case-insensitively), another spelling of loopback, or
        /// any loopback when the core listens on a wildcard address.
        func matches(listen: Endpoint) -> Bool {
            guard port == listen.port else { return false }
            let mine = host.lowercased()
            let theirs = listen.host.lowercased()
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

    // MARK: From the CFNetwork / scutil dictionary

    /// From `CFNetworkCopySystemProxySettings()` or a parsed `scutil --proxy`: the keys
    /// `HTTPEnable`, `HTTPProxy`, `HTTPPort`, `HTTPSEnable`, `HTTPSProxy`, `HTTPSPort`.
    /// "Enable" is any non-zero number (`Int`, `Double`, `Bool`, `NSNumber`); the port is a
    /// number or a numeric string. A protocol is an `Endpoint` only when it is enabled AND
    /// its host is non-empty AND its port parses; anything less is off for that protocol.
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
    /// `off` → `.off`. `unsupported`, `needs_privilege`, `unknown`, an unknown state, a
    /// missing `state`, an `other` without a usable host and port, or a `points_at_us` with
    /// an unparsable listen address → nil: there is no endpoint fact to show.
    public init?(compact: [String: Any], listenAddress: String) {
        guard let state = compact["state"] as? String else { return nil }
        switch state {
        case "off":
            self = .off
        case "points_at_us":
            guard let listen = Endpoint(address: listenAddress) else { return nil }
            let host = SystemProxyState.wildcardHosts.contains(listen.host.lowercased()) ? "127.0.0.1" : listen.host
            let ours = Endpoint(host: host, port: listen.port)
            self.init(http: ours, https: ours)
        case "other":
            guard let host = SystemProxyState.host(compact["host"]), let port = SystemProxyState.port(compact["port"]) else {
                return nil
            }
            let theirs = Endpoint(host: host, port: port)
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

    // MARK: Spellings and coercions

    /// Lower-cased spellings of the loopback host that all mean this machine.
    static let loopbackHosts: Set<String> = ["127.0.0.1", "localhost", "::1", "[::1]"]
    /// Lower-cased spellings of a wildcard listen host; a core bound to one is reachable on loopback.
    static let wildcardHosts: Set<String> = ["0.0.0.0", "::", "[::]"]

    private static func endpoint(_ settings: [String: Any], enable: String, host: String, port: String) -> Endpoint? {
        guard isEnabled(settings[enable]), let host = self.host(settings[host]), let port = self.port(settings[port]) else {
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

    /// A non-empty string, trimmed.
    private static func host(_ value: Any?) -> String? {
        guard let text = (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
        return text
    }

    /// A number or a numeric string in 1...65535.
    private static func port(_ value: Any?) -> Int? {
        let number: Int?
        if let text = value as? String {
            number = Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
        } else if let n = value as? NSNumber {
            number = n.intValue
        } else {
            number = nil
        }
        guard let number, (1...65535).contains(number) else { return nil }
        return number
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
