import AitmBusClient
import Foundation
import Testing
@testable import AitmproxyKit

/// The pure, testable helpers behind the embedded-core manager (Task 6): token
/// generation, the per-launch config file, the rendezvous-file parse, and the
/// free-port probe. The full spawn lifecycle is exercised by Task 9's live
/// self-test; here we pin the shapes the actor relies on.
@Suite struct EmbeddedCoreLaunchTests {
    // MARK: Token

    @Test func token_is_fresh_and_high_entropy() {
        let a = EmbeddedCoreLaunch.freshToken()
        let b = EmbeddedCoreLaunch.freshToken()

        // Two launches never share a token.
        #expect(a != b)
        // 32 CSPRNG bytes rendered as hex: 64 chars, all hex digits — ample entropy.
        #expect(a.count == 64)
        #expect(a.allSatisfy { $0.isHexDigit })
        #expect(a.lowercased() == a)
    }

    // MARK: Config file

    private func sampleConfig(endpointFile: URL) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/Apps/Aitmproxy.app/Contents/Resources/core/obscura"),
            proxyPort: 8080,
            browserProxyPort: 8083,
            token: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            operatorToken: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            endpointFile: endpointFile
        )
    }

    @Test func generated_config_is_0600_and_tokenless_in_world_readable_sense() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "embedded-core-test-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let endpointFile = dir.appending(path: "bus.endpoint")
        let configURL = dir.appending(path: "config.yaml")
        let config = sampleConfig(endpointFile: endpointFile)

        try EmbeddedCoreLaunch.writeConfig(config.yaml(), to: configURL)

        // The child needs the token, so it is in the file — but the file must not
        // be world- or group-readable: the token never lands anywhere readable.
        let perms = try FileManager.default.attributesOfItem(atPath: configURL.path)[.posixPermissions] as? NSNumber
        #expect(perms?.int16Value == 0o600)

        let text = try String(contentsOf: configURL, encoding: .utf8)
        #expect(text.contains(config.token))
        #expect(text.contains("port: 0"))                       // ephemeral bus port
        #expect(text.contains("listen: \"127.0.0.1:8080\""))    // the chosen proxy port
        #expect(text.contains("proxy_addr: \"127.0.0.1:8083\""))
        #expect(text.contains(endpointFile.path))               // rendezvous path
        #expect(text.contains(config.obscuraBinary.path))       // bundled obscura
    }

    @Test func generated_config_emits_the_operator_token_alongside_the_agent_token() throws {
        // The app connects as a present human (`Frontend::Operator`) so its Scope
        // panel can widen scope at runtime; the core still requires the agent token
        // on the loopback transport. So the generated YAML must carry BOTH a
        // `mcp.operator_token` and the agent `loopback_tcp.token`, and they must be
        // distinct (the operator route is only meaningful if the two differ).
        let config = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        let yaml = try config.yaml()

        #expect(config.token != config.operatorToken)
        #expect(yaml.contains("operator_token: \"\(config.operatorToken)\""))
        #expect(yaml.contains("token: \"\(config.token)\""))        // agent token still present
        // Startup stays deny-by-default: no `scope:` block is emitted, so the core
        // comes up with empty scope and only a present operator may widen it.
        #expect(!yaml.contains("scope:"))
        #expect(!yaml.contains("allow_agent_widen"))
    }

    @Test func config_pins_a_bounded_obscura_stop_timeout() throws {
        // The generated config asks the embedded core for a small obscura
        // teardown budget so the core's whole quit budget stays under the
        // Swift-side SIGKILL grace (S1 / AC7).
        let yaml = try sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint")).yaml()
        #expect(yaml.contains("stop_timeout: 2"))
    }

    private func config(sslInsecure: Bool) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: sslInsecure
        )
    }

    @Test func secure_default_emits_no_ssl_insecure_key() throws {
        // Verifying upstream TLS is the default, so the key is omitted entirely and
        // the core keeps `ssl_insecure: false` — the app never weakens TLS silently.
        let yaml = try config(sslInsecure: false).yaml()
        #expect(!yaml.contains("ssl_insecure"))
    }

    @Test func ssl_insecure_is_a_top_level_unindented_key() throws {
        // The core models `ssl_insecure` as a top-level key (sibling of `listen`),
        // and `deny_unknown_fields` rejects any wrapper — so a line like
        // `upstream:\n  ssl_insecure: true` would make the core refuse to start.
        // The opt-out must therefore be an unindented, top-level `ssl_insecure: true`.
        let yaml = try config(sslInsecure: true).yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.contains("ssl_insecure: true"))   // exact line: column 0, no indent
        #expect(!yaml.contains("upstream"))              // no wrapper object the core would reject
    }

    // MARK: Capture gate (TG-AC1 / TG-AC2)

    private func config(captureEnabled: Bool) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            captureEnabled: captureEnabled
        )
    }

    @Test func capture_gate_emitted_only_when_enabled() throws {
        // The Network Extension feeder is the core's deny-by-default on-switch:
        // the app writes the `macos_capture` section only when the operator has
        // turned capture on, and writes nothing at all when it is off so the core
        // parses its disabled default (TG-AC1).
        #expect(try config(captureEnabled: true).yaml().contains("macos_capture:\n  enabled: true"))
        #expect(!(try config(captureEnabled: false).yaml()).contains("macos_capture"))
    }

    @Test func capture_gate_defaults_off() throws {
        // A Config built without `captureEnabled:` — every pre-existing call site —
        // is off: the field is false and no `macos_capture` text reaches the file,
        // so shipping the field cannot silently arm capture (TG-AC2 default-off).
        let config = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        #expect(config.captureEnabled == false)
        #expect(!(try config.yaml()).contains("macos_capture"))
    }

    @Test func capture_gate_is_byte_identical_to_the_core_parse_input() throws {
        // The core's `config_file.rs` `macos_capture_enable_round_trips` test parses
        // exactly "macos_capture:\n  enabled: true\n" into an enabled feeder config.
        // The emitted block must be that text byte-for-byte — a top-level
        // `macos_capture:` at column 0 (sibling of `listen`/`mcp`/`browser`, since
        // `deny_unknown_fields` rejects any wrapper) with `enabled: true` indented
        // two spaces and newline-terminated — so what the app writes is what the
        // core is proven to accept (TG-AC2 core-compatible).
        let coreParseInput = "macos_capture:\n  enabled: true\n"
        let yaml = try config(captureEnabled: true).yaml()
        #expect(yaml.contains("macos_capture:\n  enabled: true"))
        #expect(yaml.contains(coreParseInput))
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.contains("macos_capture:"))          // exact line: column 0, no indent
        #expect(lines.contains("  enabled: true"))         // exact line: two-space indent
        let key = lines.firstIndex(of: "macos_capture:")
        let valueLine = key.flatMap { lines.indices.contains($0 + 1) ? lines[$0 + 1] : nil }
        #expect(valueLine == "  enabled: true")            // directly under the key, nothing between
    }

    @Test func swift_stop_grace_exceeds_the_embedded_core_obscura_budget() {
        // The SIGTERM→SIGKILL grace must outlast the core's whole obscura teardown
        // budget (stop_timeout + the core's 1 s reap margin) so a clean SIGTERM is
        // always enough and SIGKILL never orphans obscura mid-teardown (S1 / AC7).
        let coreBudget = EmbeddedCoreLaunch.obscuraStopTimeoutSeconds + 1
        #expect(EmbeddedCoreLaunch.childStopGraceSeconds > coreBudget)
    }

    // MARK: Config path escaping (S3)

    @Test func config_paths_are_escaped_for_a_double_quoted_scalar() throws {
        // A quote and a backslash in a path are backslash-escaped, not left to
        // break out of the double-quoted YAML scalar.
        #expect(try EmbeddedCoreLaunch.yamlDoubleQuoted(#"/a/"b"/c"#) == #"/a/\"b\"/c"#)
        #expect(try EmbeddedCoreLaunch.yamlDoubleQuoted(#"/a\b"#) == #"/a\\b"#)
        // A clean path is unchanged.
        #expect(try EmbeddedCoreLaunch.yamlDoubleQuoted("/Apps/obscura") == "/Apps/obscura")
    }

    @Test func config_rejects_a_path_with_a_newline() {
        // A newline can't live inside a one-line double-quoted scalar; rather than
        // emit broken/injectable YAML, rendering throws.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/a/b\nlisten: evil")) {
            try EmbeddedCoreLaunch.yamlDoubleQuoted("/a/b\nlisten: evil")
        }
        let bad = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11", endpointFile: URL(fileURLWithPath: "/tmp/with\nnewline")
        )
        #expect(throws: (any Error).self) { try bad.yaml() }
    }

    // MARK: Restart backoff (SP3 / AC8)

    @Test func restart_backoff_follows_base_times_two_to_the_n_capped() {
        let base: Duration = .milliseconds(500)
        let cap: Duration = .seconds(10)
        func decide(_ n: Int, max: Int = 5) -> EmbeddedCoreLaunch.RestartDecision {
            EmbeddedCoreLaunch.restartDecision(restarts: n, maxRestarts: max, base: base, cap: cap)
        }
        // base * 2^(n-1): 500ms, 1s, 2s, 4s, 8s.
        #expect(decide(1) == .retry(after: .milliseconds(500)))
        #expect(decide(2) == .retry(after: .seconds(1)))
        #expect(decide(3) == .retry(after: .seconds(2)))
        #expect(decide(4) == .retry(after: .seconds(4)))
        #expect(decide(5) == .retry(after: .seconds(8)))
        // The cap engages once base * 2^(n-1) would exceed it (here with a higher
        // maxRestarts so the attempt is still allowed): 500ms * 2^5 = 16s → 10s.
        #expect(decide(6, max: 10) == .retry(after: .seconds(10)))
    }

    @Test func restart_gives_up_once_restarts_exceed_the_cap() {
        let base: Duration = .milliseconds(500)
        let cap: Duration = .seconds(10)
        // At maxRestarts the attempt is still allowed; one past it gives up.
        #expect(EmbeddedCoreLaunch.restartDecision(restarts: 5, maxRestarts: 5, base: base, cap: cap)
            != .giveUp)
        #expect(EmbeddedCoreLaunch.restartDecision(restarts: 6, maxRestarts: 5, base: base, cap: cap)
            == .giveUp)
    }

    @Test func give_up_detail_carries_the_stderr_tail() {
        // Give-up surfaces the reason followed by the last `tailLines` captured
        // lines, so the degraded status shows why the core stopped (AC8).
        #expect(EmbeddedCoreLaunch.giveUpDetail(
            reason: "the core exited unexpectedly (status 1)",
            logTail: ["line1", "line2", "line3"], tailLines: 2
        ) == "the core exited unexpectedly (status 1)\nline2\nline3")
        // With no captured output, the reason stands alone (no trailing newline).
        #expect(EmbeddedCoreLaunch.giveUpDetail(reason: "boom", logTail: [], tailLines: 8) == "boom")
    }

    // MARK: Rendezvous-file parse

    @Test func endpoint_file_parses_to_bus_endpoint() {
        let token = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

        // Exactly what the core writes: SocketAddr Display + one trailing newline.
        let endpoint = EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "127.0.0.1:50512\n", token: token)
        #expect(endpoint == BusEndpoint(host: "127.0.0.1", port: 50512, token: token))

        // Whitespace-only / empty / malformed contents yield nothing (file not ready).
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "", token: token) == nil)
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "\n", token: token) == nil)
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "not-an-addr", token: token) == nil)
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "127.0.0.1:99999\n", token: token) == nil)
    }

    @Test func endpoint_file_rejects_a_non_loopback_host() {
        let token = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

        // A well-formed but non-loopback address means a tampered or stale file —
        // it must never be dialed (S4).
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "10.0.0.5:50512\n", token: token) == nil)
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "0.0.0.0:50512\n", token: token) == nil)
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "evil.example.com:50512\n", token: token) == nil)

        // The loopback aliases the core may print are accepted.
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "localhost:50512\n", token: token)
            == BusEndpoint(host: "localhost", port: 50512, token: token))
        #expect(EmbeddedCoreLaunch.parseEndpoint(fromFileContents: "[::1]:50512\n", token: token)
            == BusEndpoint(host: "[::1]", port: 50512, token: token))
    }

    // MARK: Free-port probe (binds a real socket — runs in the Terminal panel)

    @Test func free_port_probe_returns_an_unused_port() {
        // The preferred port, when free, is returned as-is.
        let picked = EmbeddedCoreLaunch.pickProxyPort(preferred: 0)
        #expect(picked != nil)
        if let picked { #expect(EmbeddedCoreLaunch.isPortFree(picked)) }

        // An ephemeral probe returns a port that is itself free.
        let ephemeral = EmbeddedCoreLaunch.anyFreePort()
        #expect(ephemeral != nil)
        if let ephemeral {
            #expect(ephemeral > 0)
            #expect(EmbeddedCoreLaunch.isPortFree(ephemeral))
        }
    }

    @Test func pick_falls_back_to_an_alternate_when_the_preferred_port_is_taken() {
        // Hold a port so `preferred` is demonstrably in use, then prove the probe
        // picks a different, free one (AC9: auto-pick an alternate proxy port).
        guard let held = EmbeddedCoreLaunch.anyFreePort() else {
            Issue.record("could not reserve a port to hold")
            return
        }
        let listener = TestPortHolder(port: held)
        guard listener.isListening else {
            Issue.record("could not bind the port to hold it")
            return
        }
        defer { listener.close() }

        #expect(!EmbeddedCoreLaunch.isPortFree(held))
        let picked = EmbeddedCoreLaunch.pickProxyPort(preferred: held)
        #expect(picked != nil)
        #expect(picked != held)
        if let picked { #expect(EmbeddedCoreLaunch.isPortFree(picked)) }
    }
}

/// A minimal real listener that holds a TCP port for the duration of a test, so
/// the probe sees it as taken. Binds with no address reuse, mirroring a live
/// proxy already on the port.
private final class TestPortHolder {
    private var fd: Int32 = -1
    let isListening: Bool

    init(port: UInt16) {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { isListening = false; return }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(s, 1) == 0 else {
            Darwin.close(s)
            isListening = false
            return
        }
        fd = s
        isListening = true
    }

    func close() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }
}
