import AitmBusClient
import Foundation

/// Which `UserDefaults` the connection settings come from: Settings ▸ Bus
/// (`bus.*`), Settings ▸ Proxy (`proxy.*`) and the capture toggle
/// (`capture.enabled`). A normal launch reads the operator's real defaults. A
/// self-test, snapshot or fixture run reads an isolated suite instead, so stale
/// residue (a pasted operator token from an earlier session, an `external` core
/// choice) can neither steer the run nor be overwritten by it.
///
/// Decided once per process from the environment:
/// - `APP_DEFAULTS_SUITE=<name>` names the suite explicitly, kept as it is between
///   runs (pre-seed it to test a pasted token or a manual host/port).
/// - `APP_STORE`, `APP_LIVE=1`, `APP_SNAPSHOT` or `APP_FIXTURES=1` pick the harness
///   suite, wiped at startup so every run starts from the built-in defaults.
/// - Otherwise the standard defaults.
///
/// Under `APP_LIVE=1` the live self-test connects to the core at `AITM_CONFIG`, so
/// `bus.activeKind` is registered as `external` (a default, not a stored value):
/// the embedded core is never spawned and a stored choice still wins. The run
/// connects as operator when `APP_LIVE_OPERATOR_TOKEN` carries the core's
/// `mcp.operator_token` (an agent connection is refused `flow.intercept`, a
/// sensitive command, under the default `auto` policy); the token comes from the
/// environment, never from residue.
public enum SettingsDomain: Equatable, Sendable {
    case standard
    /// `wipe`: remove the suite's stored values before use.
    case suite(name: String, wipe: Bool)

    public static let suiteVariable = "APP_DEFAULTS_SUITE"
    public static let harnessSuite = "com.mrbrutti.aitmproxy.harness"

    /// The variables that mark a harness run (snapshots, fixtures, self-tests).
    static let harnessVariables = ["APP_STORE", "APP_LIVE", "APP_SNAPSHOT", "APP_FIXTURES"]

    public static func select(environment env: [String: String]) -> SettingsDomain {
        if let name = env[suiteVariable], !name.isEmpty {
            return .suite(name: name, wipe: false)
        }
        if harnessVariables.contains(where: { !(env[$0] ?? "").isEmpty }) {
            return .suite(name: harnessSuite, wipe: true)
        }
        return .standard
    }

    public static let liveOperatorTokenVariable = "APP_LIVE_OPERATOR_TOKEN"

    /// Default values registered for the run (overridable by stored values).
    public static func registration(environment env: [String: String]) -> [String: String] {
        guard env["APP_LIVE"] == "1" else { return [:] }
        var values = [UserDefaultsActiveKindPersistence.key: ActiveCoreKind.external.rawValue]
        if let token = env[liveOperatorTokenVariable], !token.isEmpty {
            values[BusEndpointSettings.Key.operatorToken] = token
        }
        return values
    }

    /// The store for this domain, wiped and seeded as the domain says. Returns the
    /// standard defaults when a suite cannot be opened (a name Foundation refuses).
    public func makeDefaults(registering registration: [String: String] = [:]) -> UserDefaults {
        let defaults: UserDefaults
        switch self {
        case .standard:
            defaults = .standard
        case .suite(let name, let wipe):
            guard let suite = UserDefaults(suiteName: name) else { return .standard }
            if wipe { suite.removePersistentDomain(forName: name) }
            defaults = suite
        }
        if !registration.isEmpty { defaults.register(defaults: registration) }
        return defaults
    }
}
