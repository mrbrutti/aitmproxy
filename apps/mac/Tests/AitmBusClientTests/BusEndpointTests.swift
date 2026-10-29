import Foundation
import Testing

@testable import AitmBusClient

@Suite struct BusEndpointTests {
    private func write(_ yaml: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "aitm-bus-\(UUID().uuidString).yaml")
        try yaml.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    @Test func parsesBlockForm() throws {
        let url = try write(
            """
            # aitmproxy config
            listen: 127.0.0.1:8080
            scope:
              - host: example.com
            mcp:
              transport:
                loopback_tcp:
                  port: 7331   # chosen
                  token: "ab#cd-ef"
            browser:
              engine: obscura
            """)
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try BusEndpoint.fromConfigFile(url) == BusEndpoint(host: "127.0.0.1", port: 7331, token: "ab#cd-ef"))
    }

    @Test func parsesInlineMapForms() throws {
        let inline = try write("mcp:\n  transport: {loopback_tcp: {port: 9000, token: 'tok en'}}\n")
        defer { try? FileManager.default.removeItem(at: inline) }
        #expect(try BusEndpoint.fromConfigFile(inline) == BusEndpoint(port: 9000, token: "tok en"))

        let hybrid = try write("mcp:\n  transport:\n    loopback_tcp: { token: t1, port: 1 }\n")
        defer { try? FileManager.default.removeItem(at: hybrid) }
        #expect(try BusEndpoint.fromConfigFile(hybrid) == BusEndpoint(port: 1, token: "t1"))
    }

    @Test func otherTransportsAndMissingFilesAreNil() throws {
        let stdio = try write("mcp:\n  transport: {stdio: {}}\n")
        defer { try? FileManager.default.removeItem(at: stdio) }
        #expect(try BusEndpoint.fromConfigFile(stdio) == nil)
        let missing = FileManager.default.temporaryDirectory.appending(path: "no-such-\(UUID().uuidString).yaml")
        #expect(try BusEndpoint.fromConfigFile(missing) == nil)
    }

    @Test func badPortOrTokenThrows() throws {
        let badPort = try write("mcp:\n  transport:\n    loopback_tcp:\n      port: lots\n      token: x\n")
        defer { try? FileManager.default.removeItem(at: badPort) }
        #expect(throws: BusError.self) { try BusEndpoint.fromConfigFile(badPort) }
        let noToken = try write("mcp:\n  transport:\n    loopback_tcp:\n      port: 10\n")
        defer { try? FileManager.default.removeItem(at: noToken) }
        #expect(throws: BusError.self) { try BusEndpoint.fromConfigFile(noToken) }
    }

    @Test func parsesArguments() throws {
        #expect(try BusEndpoint.fromArguments(["--verbose"]) == nil)
        #expect(
            try BusEndpoint.fromArguments(["--bus", "127.0.0.1:4000", "--token", "abc"])
                == BusEndpoint(host: "127.0.0.1", port: 4000, token: "abc"))
        #expect(try BusEndpoint.fromArguments(["--bus=localhost:1", "--token=t"]) == BusEndpoint(host: "localhost", port: 1, token: "t"))
        let tokenFile = FileManager.default.temporaryDirectory.appending(path: "aitm-token-\(UUID().uuidString)")
        try "  filetoken\n".write(to: tokenFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tokenFile) }
        #expect(
            try BusEndpoint.fromArguments(["--bus", ":5", "--token-file", tokenFile.path])
                == BusEndpoint(host: "127.0.0.1", port: 5, token: "filetoken"))
        #expect(throws: BusError.self) { try BusEndpoint.fromArguments(["--bus", "nohost"]) }
        #expect(throws: BusError.self) { try BusEndpoint.fromArguments(["--bus", "h:1"]) }
    }

    @Test func defaultPathIsUnderApplicationSupport() {
        #expect(BusEndpoint.defaultConfigURL.path.hasSuffix("/Library/Application Support/aitmproxy/config.yaml"))
    }
}
