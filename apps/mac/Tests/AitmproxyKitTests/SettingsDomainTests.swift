import AitmBusClient
import Foundation
import Testing

@testable import AitmproxyKit

@Suite struct SettingsDomainTests {
    @Test func aNormalLaunchReadsTheStandardDefaults() {
        #expect(SettingsDomain.select(environment: ["HOME": "/Users/x"]) == .standard)
        #expect(SettingsDomain.select(environment: ["APP_STORE": ""]) == .standard)
    }

    @Test func harnessRunsReadAWipedIsolatedSuite() {
        #expect(SettingsDomain.harnessVariables == ["APP_STORE", "APP_LIVE"])
        for variable in ["APP_STORE", "APP_LIVE"] {
            #expect(SettingsDomain.select(environment: [variable: "1"]) == .suite(name: SettingsDomain.harnessSuite, wipe: true), "\(variable)")
        }
        // The fixture and snapshot modes are gone (2026-10-31): their variables no longer mark a harness run.
        #expect(SettingsDomain.select(environment: ["APP_SNAPSHOT": "/tmp/x"]) == .standard)
        #expect(SettingsDomain.select(environment: ["APP_FIXTURES": "1"]) == .standard)
    }

    @Test func anExplicitSuiteIsKeptAsIs() {
        let env = ["APP_DEFAULTS_SUITE": "com.example.mine", "APP_LIVE": "1"]
        #expect(SettingsDomain.select(environment: env) == .suite(name: "com.example.mine", wipe: false))
    }

    @Test func theLiveSelfTestDefaultsToTheExternalCore() {
        #expect(SettingsDomain.registration(environment: ["APP_LIVE": "1"]) == ["bus.activeKind": "external"])
        #expect(SettingsDomain.registration(environment: ["APP_STORE": "/tmp/x"]) == [:])
        #expect(SettingsDomain.registration(environment: ["APP_LIVE": "1", "APP_LIVE_OPERATOR_TOKEN": "op-1"])
            == ["bus.activeKind": "external", "bus.operatorToken": "op-1"])
        #expect(SettingsDomain.registration(environment: ["APP_STORE": "/tmp/x", "APP_LIVE_OPERATOR_TOKEN": "op-1"]) == [:])
    }

    /// The failure this guards against: Settings ▸ Bus residue in the operator's
    /// defaults (a pasted token from an earlier session) must not reach the live
    /// self-test, whose endpoint is the core at `AITM_CONFIG`.
    @Test func underAppLiveTheConfigTokenWinsOverStaleOperatorResidue() throws {
        let config = FileManager.default.temporaryDirectory.appending(path: "aitm-domain-\(UUID().uuidString).yaml")
        try "mcp:\n  transport:\n    loopback_tcp:\n      port: 7331\n      token: config-token\n".write(to: config, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: config) }

        // Stand-ins for the operator's real defaults and for the harness suite, so the
        // test never touches either real domain.
        let operatorName = "aitm-domain-operator-\(UUID().uuidString)"
        let harnessName = "aitm-domain-harness-\(UUID().uuidString)"
        let operatorDefaults = UserDefaults(suiteName: operatorName)!
        defer { operatorDefaults.removePersistentDomain(forName: operatorName) }
        operatorDefaults.set("dvwa-op-token", forKey: BusEndpointSettings.Key.operatorToken)
        operatorDefaults.set("embedded", forKey: UserDefaultsActiveKindPersistence.key)
        // Residue in the harness suite from an earlier run is wiped too.
        UserDefaults(suiteName: harnessName)!.set("old-run-token", forKey: BusEndpointSettings.Key.operatorToken)

        let env = ["APP_LIVE": "1", "AITM_CONFIG": config.path]
        let domain = SettingsDomain.select(environment: env)
        #expect(domain != .standard)
        let defaults = SettingsDomain.suite(name: harnessName, wipe: true).makeDefaults(registering: SettingsDomain.registration(environment: env))
        defer { defaults.removePersistentDomain(forName: harnessName) }

        #expect(BusEndpointSettings(defaults: defaults).endpoint(configURL: config) == BusEndpoint(port: 7331, token: "config-token"))
        #expect(UserDefaultsActiveKindPersistence(defaults: defaults).load() == .external)
        #expect(BusEndpointSettings(defaults: operatorDefaults).endpoint(configURL: config)?.token == "dvwa-op-token")
    }
}
