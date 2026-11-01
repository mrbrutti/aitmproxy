import Foundation
import Testing

@testable import AitmBusClient

@Suite struct BusSettingsTests {
    private func writeConfig(port: Int = 7331, token: String = "config-agent-token") throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "aitm-settings-\(UUID().uuidString).yaml")
        try "mcp:\n  transport:\n    loopback_tcp:\n      port: \(port)\n      token: \"\(token)\"\n".write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private func suite() -> (UserDefaults, String) {
        let name = "aitm-bus-settings-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return (defaults, name)
    }

    @Test func freshDefaultsReadTheConfigFile() throws {
        let config = try writeConfig()
        defer { try? FileManager.default.removeItem(at: config) }
        let (defaults, name) = suite()
        defer { defaults.removePersistentDomain(forName: name) }

        let settings = BusEndpointSettings(defaults: defaults)
        #expect(settings == BusEndpointSettings())
        #expect(settings.endpoint(configURL: config) == BusEndpoint(port: 7331, token: "config-agent-token"))
    }

    @Test func aPastedOperatorTokenReplacesTheConfigToken() throws {
        let config = try writeConfig()
        defer { try? FileManager.default.removeItem(at: config) }
        let (defaults, name) = suite()
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(" dvwa-op-token\n", forKey: BusEndpointSettings.Key.operatorToken)

        #expect(BusEndpointSettings(defaults: defaults).endpoint(configURL: config) == BusEndpoint(port: 7331, token: "dvwa-op-token"))
    }

    @Test func manualHostPortAndTokenFileWhenNotFromConfig() throws {
        let config = try writeConfig()
        defer { try? FileManager.default.removeItem(at: config) }
        let tokenFile = FileManager.default.temporaryDirectory.appending(path: "aitm-token-\(UUID().uuidString)")
        try "file-token\n".write(to: tokenFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tokenFile) }
        let (defaults, name) = suite()
        defer { defaults.removePersistentDomain(forName: name) }
        defaults.set(false, forKey: BusEndpointSettings.Key.fromConfig)
        defaults.set("10.0.0.5", forKey: BusEndpointSettings.Key.host)
        defaults.set(9090, forKey: BusEndpointSettings.Key.port)
        defaults.set(tokenFile.path, forKey: BusEndpointSettings.Key.tokenFile)

        #expect(BusEndpointSettings(defaults: defaults).endpoint(configURL: config) == BusEndpoint(host: "10.0.0.5", port: 9090, token: "file-token"))

        defaults.set(0, forKey: BusEndpointSettings.Key.port)
        #expect(BusEndpointSettings(defaults: defaults).endpoint(configURL: config) == nil)
    }

    @Test func nothingConfiguredIsNil() {
        let missing = FileManager.default.temporaryDirectory.appending(path: "no-such-\(UUID().uuidString).yaml")
        #expect(BusEndpointSettings().endpoint(configURL: missing) == nil)
    }
}
