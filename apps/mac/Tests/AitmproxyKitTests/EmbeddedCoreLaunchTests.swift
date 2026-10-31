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
        // Startup stays deny-by-default: no `scope:` block is emitted — none for the default,
        // empty scope (a persisted operator scope is the only thing that adds one) — and
        // `allow_agent_widen` is never emitted, so only a present operator may widen scope.
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

    @Test func capture_gate_composes_with_ssl_insecure_as_two_top_level_keys() throws {
        // Both operator opt-ins at once. Each block is appended after its own newline, so
        // neither fuses into the other's line, and each key appears once, at column 0.
        let both = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true
        )
        let yaml = try both.yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0 == "ssl_insecure: true" }.count == 1)
        #expect(lines.filter { $0 == "macos_capture:" }.count == 1)
        #expect(lines.filter { $0 == "  enabled: true" }.count == 1)
        #expect(yaml.hasSuffix("macos_capture:\n  enabled: true\n"))
        // Each flag controls only its own block.
        let sslOnly = try config(sslInsecure: true).yaml()
        #expect(sslOnly.contains("ssl_insecure: true"))
        #expect(!sslOnly.contains("macos_capture"))
        #expect(!(try config(captureEnabled: true).yaml()).contains("ssl_insecure"))
    }

    @Test func a_crafted_path_cannot_smuggle_the_capture_gate_into_a_capture_off_config() throws {
        // Deny-by-default holds against hostile input. A path that merely contains the gate's
        // text stays inside its double-quoted scalar; one that tries to start a new line is
        // refused outright. Either way a config built with capture OFF has no gate line.
        let sameLine = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/x/\"y\\macos_capture: enabled: true"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint")
        )
        let lines = try sameLine.yaml().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(!lines.contains("macos_capture:"))
        #expect(!lines.contains("  enabled: true"))

        let newlineInBinary = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/x\nmacos_capture:\n  enabled: true"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint")
        )
        #expect(throws: (any Error).self) { try newlineInBinary.yaml() }

        let newlineInEndpoint = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/e\nmacos_capture:\n  enabled: true")
        )
        #expect(throws: (any Error).self) { try newlineInEndpoint.yaml() }
    }

    @Test func rewriting_a_config_with_capture_off_leaves_no_gate_behind() throws {
        // OFF is applied by rewriting the config and restarting the core. The write truncates, so
        // a file that carried the gate cannot keep a stale tail of it: the OFF text is the shorter
        // of the two, which is exactly where a missing truncate would leave the old gate behind.
        // Honours $TMPDIR (as CaptureCapabilityTests does) so it also runs where the system
        // temp directory is not writable.
        let tmp = ProcessInfo.processInfo.environment["TMPDIR"].map { URL(filePath: $0) }
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = tmp.appending(path: "embedded-core-test-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let configURL = dir.appending(path: "config.yaml")

        try EmbeddedCoreLaunch.writeConfig(config(captureEnabled: true).yaml(), to: configURL)
        let on = try String(contentsOf: configURL, encoding: .utf8)
        #expect(on.contains("macos_capture:\n  enabled: true"))

        try EmbeddedCoreLaunch.writeConfig(config(captureEnabled: false).yaml(), to: configURL)
        let off = try String(contentsOf: configURL, encoding: .utf8)
        #expect(off.count < on.count)
        #expect(!off.contains("macos_capture"))
        #expect(!off.contains("enabled: true"))
        let perms = try FileManager.default.attributesOfItem(atPath: configURL.path)[.posixPermissions] as? NSNumber
        #expect(perms?.int16Value == 0o600)
    }

    @Test func capture_gate_text_is_what_the_core_round_trip_test_parses() throws {
        // `capture_gate_is_byte_identical_to_the_core_parse_input` compares against a literal
        // copied from the core's test. Pin the copy to its source: the Rust test must still spell
        // this exact text, and both tests the spec cites (TG-AC2) must still exist. This file
        // lives at apps/mac/Tests/AitmproxyKitTests/, so the repo root is five levels up.
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let source = root.appending(path: "crates/aitm/src/config_file.rs")
        try #require(
            FileManager.default.fileExists(atPath: source.path),
            "cannot find the core's config_file.rs at \(source.path)")
        let rust = try String(contentsOf: source, encoding: .utf8)

        let block = "macos_capture:\n  enabled: true\n"
        #expect(try config(captureEnabled: true).yaml().hasSuffix(block))
        // Rust spells the same text as a string literal with `\n` escapes.
        let rustLiteral = "\"" + block.replacingOccurrences(of: "\n", with: "\\n") + "\""
        let spelledInRust = rust.contains(rustLiteral)
        #expect(spelledInRust, "config_file.rs no longer contains the literal \(rustLiteral)")
        let roundTripTest = rust.contains("fn macos_capture_enable_round_trips")
        let defaultsOffTest = rust.contains("fn macos_capture_defaults_disabled")
        #expect(roundTripTest, "the core's macos_capture_enable_round_trips test is gone")
        #expect(defaultsOffTest, "the core's macos_capture_defaults_disabled test is gone")
    }

    @Test func swift_stop_grace_exceeds_the_embedded_core_obscura_budget() {
        // The SIGTERM→SIGKILL grace must outlast the core's whole obscura teardown
        // budget (stop_timeout + the core's 1 s reap margin) so a clean SIGTERM is
        // always enough and SIGKILL never orphans obscura mid-teardown (S1 / AC7).
        let coreBudget = EmbeddedCoreLaunch.obscuraStopTimeoutSeconds + 1
        #expect(EmbeddedCoreLaunch.childStopGraceSeconds > coreBudget)
    }

    // MARK: Scope block (SP-AC4 … SP-AC7, SP-AC16, SP-AC17)

    private func config(scopeHosts: [String]) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            scopeHosts: scopeHosts
        )
    }

    @Test func scope_block_is_byte_identical_to_the_core_parse_input() throws {
        // The core's `tests/config_file.rs` `scope_entries_block_round_trips` test parses exactly
        // this text into three scope entries. The emitted block must be that text byte-for-byte:
        // a top-level `scope:` at column 0 (sibling of `listen`/`mcp`/`browser`, since
        // `deny_unknown_fields` rejects any wrapper), `  entries:` directly under it, then one
        // double-quoted `- "<host>"` line per host indented four, in array order,
        // newline-terminated — so what the app writes is what the core is proven to accept (SP-AC4).
        let yaml = try config(scopeHosts: ["api.example.test", "*.shop.test", "localhost:8099"]).yaml()
        #expect(yaml.hasSuffix("scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n"))
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0 == "scope:" }.count == 1)
        let key = try #require(lines.firstIndex(of: "scope:"))
        #expect(Array(lines.dropFirst(key + 1).prefix(4)) == [
            "  entries:",
            "    - \"api.example.test\"",
            "    - \"*.shop.test\"",
            "    - \"localhost:8099\"",
        ])
    }

    @Test func scope_block_defaults_to_nothing() throws {
        // A Config built without `scopeHosts:` — every pre-existing call site — carries an empty
        // scope and emits no `scope` text of any kind, so the core keeps its deny-by-default
        // empty startup scope (SP-AC6).
        let config = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        #expect(config.scopeHosts == [])
        let yaml = try config.yaml()
        #expect(!yaml.contains("scope:"))
        #expect(!yaml.contains("entries"))
    }

    @Test func scope_block_never_emits_allow_agent_widen() throws {
        // Widening stays operator-only: restoring the operator's scope must never turn into
        // letting agents widen it, whether or not a scope is restored (SP-AC5).
        let defaultYAML = try sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint")).yaml()
        let scopedYAML = try config(scopeHosts: ["api.example.test", "*.shop.test", "localhost:8099"]).yaml()
        #expect(!defaultYAML.contains("allow_agent_widen"))
        #expect(!scopedYAML.contains("allow_agent_widen"))
    }

    @Test func scope_block_escapes_quotes_and_backslashes() throws {
        // A quote or a backslash in a host is backslash-escaped the way paths are, so it cannot
        // break out of its double-quoted scalar: one backslash before the quote, two for the
        // backslash (SP-AC17).
        let yaml = try config(scopeHosts: [#"a"b.test"#, #"c\d.test"#]).yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.contains(#"    - "a\"b.test""#))
        #expect(lines.contains(#"    - "c\\d.test""#))
    }

    @Test func scope_block_rejects_a_host_with_a_newline() {
        // A newline cannot live inside a one-line double-quoted scalar; rather than let a crafted
        // host inject YAML into the token-bearing config, rendering throws and names the host
        // (SP-AC16).
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\nlisten: 0.0.0.0:1")) {
            try config(scopeHosts: ["ok.test", "evil.test\nlisten: 0.0.0.0:1"]).yaml()
        }
        #expect(throws: (any Error).self) { try config(scopeHosts: ["evil.test\rx"]).yaml() }
    }

    @Test func scope_block_follows_the_ssl_and_capture_tails() throws {
        // All three tails at once: each top-level key appears exactly once, at column 0, and the
        // scope block comes last — so every byte-exact `hasSuffix` on a scope-less config still
        // holds (SP-AC4).
        let all = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true, scopeHosts: ["api.example.test"]
        )
        let lines = try all.yaml().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0 == "ssl_insecure: true" }.count == 1)
        #expect(lines.filter { $0 == "macos_capture:" }.count == 1)
        #expect(lines.filter { $0 == "scope:" }.count == 1)
        let ssl = try #require(lines.firstIndex(of: "ssl_insecure: true"))
        let capture = try #require(lines.firstIndex(of: "macos_capture:"))
        let scope = try #require(lines.firstIndex(of: "scope:"))
        #expect(ssl < capture)
        #expect(capture < scope)
        // Scope-less configs are unchanged.
        #expect(try config(captureEnabled: true).yaml().hasSuffix("macos_capture:\n  enabled: true\n"))
    }

    @Test func scope_block_text_is_what_the_core_round_trip_test_parses() throws {
        // `scope_block_is_byte_identical_to_the_core_parse_input` compares against a literal copied
        // from the core's test. Pin the copy to its source: the Rust test must still spell this
        // exact text and the round-trip test the spec cites (SP-AC7) must still exist. This file
        // lives at apps/mac/Tests/AitmproxyKitTests/, so the repo root is five levels up.
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let source = root.appending(path: "crates/aitm/tests/config_file.rs")
        try #require(
            FileManager.default.fileExists(atPath: source.path),
            "cannot find the core's tests/config_file.rs at \(source.path)")
        let rust = try String(contentsOf: source, encoding: .utf8)

        let block = "scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n"
        #expect(try config(scopeHosts: ["api.example.test", "*.shop.test", "localhost:8099"]).yaml().hasSuffix(block))
        // Rust spells the same text as one plain string literal with `\"` and `\n` escapes.
        let rustLiteral = "\"" + block
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
        #expect(rust.contains(rustLiteral), "tests/config_file.rs no longer contains the literal \(rustLiteral)")
        #expect(rust.contains("fn scope_entries_block_round_trips"),
                "the core's scope_entries_block_round_trips test is gone")
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
