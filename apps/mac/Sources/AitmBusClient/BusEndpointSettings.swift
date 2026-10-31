import Foundation

/// Settings ▸ Bus as values, read from one `UserDefaults` store so the endpoint
/// resolution is a pure function of (settings, config file) and testable without
/// the app. Which store the app reads is decided once, by `SettingsDomain` in the
/// Kit: the operator's real defaults in a normal launch, an isolated suite in
/// self-test / snapshot / fixture runs.
public struct BusEndpointSettings: Equatable, Sendable {
    /// Read host/port/token from aitmproxy's `config.yaml` (the default).
    public var fromConfig = true
    public var host = "127.0.0.1"
    public var port: UInt16 = 0
    public var tokenFile = ""
    /// A pasted operator token overrides the config/agent token; its class makes
    /// the server resolve the connection to operator (spec Decision E). Empty ⇒
    /// not configured, so the app stays an agent by default.
    public var operatorToken = ""

    public init(fromConfig: Bool = true, host: String = "127.0.0.1", port: UInt16 = 0, tokenFile: String = "", operatorToken: String = "") {
        self.fromConfig = fromConfig
        self.host = host
        self.port = port
        self.tokenFile = tokenFile
        self.operatorToken = operatorToken
    }

    /// The keys Settings ▸ Bus binds to.
    public enum Key {
        public static let fromConfig = "bus.fromConfig"
        public static let host = "bus.host"
        public static let port = "bus.port"
        public static let tokenFile = "bus.tokenFile"
        public static let operatorToken = "bus.operatorToken"
        public static let expectedRole = "bus.expectedRole"
    }

    public init(defaults: UserDefaults) {
        fromConfig = defaults.object(forKey: Key.fromConfig) as? Bool ?? true
        host = defaults.string(forKey: Key.host) ?? "127.0.0.1"
        port = UInt16(clamping: defaults.integer(forKey: Key.port))
        tokenFile = defaults.string(forKey: Key.tokenFile) ?? ""
        operatorToken = (defaults.string(forKey: Key.operatorToken) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Where the app connects: the config file's loopback transport (with the
    /// pasted operator token in place of the config token, when there is one),
    /// else the manual host / port / token file. `nil` when nothing is configured.
    public func endpoint(configURL: URL) -> BusEndpoint? {
        if fromConfig, var endpoint = try? BusEndpoint.fromConfigFile(configURL) {
            if !operatorToken.isEmpty { endpoint.token = operatorToken }
            return endpoint
        }
        var token = operatorToken
        if token.isEmpty, !tokenFile.isEmpty,
           let text = try? String(contentsOfFile: (tokenFile as NSString).expandingTildeInPath, encoding: .utf8) {
            token = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard port > 0, !token.isEmpty else { return nil }
        return BusEndpoint(host: host, port: port, token: token)
    }
}
