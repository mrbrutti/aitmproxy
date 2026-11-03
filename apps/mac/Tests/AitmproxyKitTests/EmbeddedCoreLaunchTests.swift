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
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\rx")) {
            try config(scopeHosts: ["evil.test\rx"]).yaml()
        }
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

    // MARK: Tester — scope block edge cases (SP-AC4, SP-AC16, SP-AC17)

    @Test func scope_block_emits_unicode_and_yaml_specials_verbatim_inside_quotes() throws {
        // Hosts `EmbeddedScope.load` keeps (an IDN, mixed case, `#`, `'`) are spliced verbatim:
        // inside double quotes `#` is a literal, not a comment, and `'` needs no escaping. The
        // core's `tests/config_file.rs` `scope_entries_quoting_survives_the_parse` parses these
        // same lines back to the same hosts.
        let yaml = try config(scopeHosts: ["bücher.example", "API.Example.TEST", "a#b.test", "o'neil.test"]).yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let key = try #require(lines.firstIndex(of: "scope:"))
        #expect(Array(lines.dropFirst(key + 1).prefix(5)) == [
            "  entries:",
            "    - \"bücher.example\"",
            "    - \"API.Example.TEST\"",
            "    - \"a#b.test\"",
            "    - \"o'neil.test\"",
        ])
    }

    @Test func scope_block_keeps_a_huge_list_whole_and_in_order() throws {
        // Oversized input: every host becomes exactly one `    - "…"` line, in array order, the
        // key still appears once, nothing follows the list, and the block still ends in a newline.
        let hosts = (0..<2_000).map { "h\($0).example.test" }
        let yaml = try config(scopeHosts: hosts).yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0 == "scope:" }.count == 1)
        let key = try #require(lines.firstIndex(of: "scope:"))
        #expect(lines.dropFirst(key + 1).first == "  entries:")
        #expect(Array(lines.dropFirst(key + 2).prefix(hosts.count)) == hosts.map { "    - \"\($0)\"" })
        #expect(lines.count == key + 2 + hosts.count + 1)   // + the empty piece after the final newline
        #expect(yaml.hasSuffix("    - \"h1999.example.test\"\n"))
    }

    @Test func scope_block_rejects_a_newline_anywhere_in_the_list() {
        // The refusal is per host and total: a newline in the last of many hosts, or a bare
        // newline, throws the host variant (never the path one) and no config text is handed out
        // (SP-AC16).
        let many = (0..<50).map { "h\($0).example.test" } + ["last.test\n"]
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("last.test\n")) {
            try config(scopeHosts: many).yaml()
        }
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("\n")) {
            try config(scopeHosts: ["\n"]).yaml()
        }
    }

    @Test func scope_block_rejects_a_crlf_host() {
        // "\r\n" is one Swift `Character`: the guard must see the CR and LF scalars inside it, not
        // compare grapheme clusters. From the app's surface this host is unreachable
        // (`EmbeddedScope.load` drops it), so this pins `yaml()`'s own SP-AC16 contract.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\r\nlisten: 0.0.0.0:1")) {
            try config(scopeHosts: ["evil.test\r\nlisten: 0.0.0.0:1"]).yaml()
        }
    }

    @Test func scope_block_is_purely_additive_to_the_rest_of_the_config() throws {
        // Everything before the block — tokens, ports, paths, the ssl and capture tails — is
        // byte-identical with and without a persisted scope; the block only ever appends.
        let scopeless = try EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true
        ).yaml()
        let scoped = try EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true, scopeHosts: ["api.example.test"]
        ).yaml()
        #expect(scoped.hasPrefix(scopeless))
        #expect(scoped.hasSuffix("scope:\n  entries:\n    - \"api.example.test\"\n"))
        #expect(scoped.count > scopeless.count)
    }

    // MARK: System-proxy block (SP-AC25)

    private func config(systemProxyAuto: Bool = false, systemProxyBypass: [String] = []) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            systemProxyAuto: systemProxyAuto, systemProxyBypass: systemProxyBypass
        )
    }

    @Test func systemProxyBlockIsByteIdenticalToTheCoreParseInput() throws {
        // The core's `crates/aitm/src/config_file.rs` `system_proxy_block_the_mac_app_emits_parses`
        // test parses exactly this text: a top-level `system_proxy:` at column 0, `  auto: true`,
        // `  bypass:` and one double-quoted `- "<host>"` line per host indented four,
        // newline-terminated. What the app writes is what the core is proven to accept (SP-AC25).
        let block = "system_proxy:\n  auto: true\n  bypass:\n    - \"corp.test\"\n"
        #expect(try config(systemProxyAuto: true, systemProxyBypass: ["corp.test"]).yaml().hasSuffix(block))

        // Pin the literal to its source: the Rust test must still spell this exact text. This
        // file lives at apps/mac/Tests/AitmproxyKitTests/, so the repo root is five levels up.
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let source = root.appending(path: "crates/aitm/src/config_file.rs")
        try #require(
            FileManager.default.fileExists(atPath: source.path),
            "cannot find the core's src/config_file.rs at \(source.path)")
        let rust = try String(contentsOf: source, encoding: .utf8)
        let rustLiteral = "\"" + block
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
        #expect(rust.contains(rustLiteral), "src/config_file.rs no longer contains the literal \(rustLiteral)")
        #expect(rust.contains("fn system_proxy_block_the_mac_app_emits_parses()"))
    }

    @Test func systemProxyBlockIsAbsentWhenOffAndEmpty() throws {
        // A Config built without the two new parameters — every pre-existing call site — emits
        // no `system_proxy` block, so the core keeps its `auto: false`, empty-bypass default.
        let defaults = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        #expect(defaults.systemProxyAuto == false)
        #expect(defaults.systemProxyBypass == [])
        #expect(!(try defaults.yaml()).contains("system_proxy"))
        // Explicitly off with an empty list is the same as the default.
        #expect(!(try config(systemProxyAuto: false, systemProxyBypass: []).yaml()).contains("system_proxy"))
    }

    @Test func systemProxyBypassOnlyEmitsAutoFalse() throws {
        // A bypass list with the launch toggle off still needs the block (the list is honoured on
        // a live set), and `auto` is written out as `false` so the file says what the operator chose.
        let yaml = try config(systemProxyBypass: ["a.test"]).yaml()
        #expect(yaml.contains("system_proxy:\n  auto: false\n  bypass:\n    - \"a.test\"\n"))
        #expect(yaml.hasSuffix("system_proxy:\n  auto: false\n  bypass:\n    - \"a.test\"\n"))
    }

    @Test func systemProxyAutoOnlyEmitsNoBypassKey() throws {
        // The launch toggle alone emits `auto: true` and no `bypass:` key at all — the core's
        // default (empty) list is what an absent key parses to.
        let yaml = try config(systemProxyAuto: true).yaml()
        #expect(yaml.hasSuffix("\nsystem_proxy:\n  auto: true\n"))
        #expect(!yaml.contains("bypass"))
    }

    @Test func aBypassHostWithANewlineThrows() {
        // A bypass host with a newline could break out of its double-quoted scalar and inject
        // YAML into the token-bearing config; the same guard as scope hosts, the same error.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\nlisten: 0.0.0.0:1")) {
            try config(systemProxyAuto: true, systemProxyBypass: ["ok.test", "evil.test\nlisten: 0.0.0.0:1"]).yaml()
        }
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\r\nx")) {
            try config(systemProxyBypass: ["evil.test\r\nx"]).yaml()
        }
    }

    @Test func systemProxyBlockIsTheLastTailAfterScope() throws {
        // All four tails at once: each top-level key appears exactly once, at column 0, in the
        // order ssl_insecure, macos_capture, scope, system_proxy — so every byte-exact
        // `hasSuffix` on a system-proxy-less config still holds.
        let all = EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true, scopeHosts: ["api.example.test"],
            systemProxyAuto: true, systemProxyBypass: ["corp.test"]
        )
        let yaml = try all.yaml()
        let lines = yaml.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0 == "ssl_insecure: true" }.count == 1)
        #expect(lines.filter { $0 == "macos_capture:" }.count == 1)
        #expect(lines.filter { $0 == "scope:" }.count == 1)
        #expect(lines.filter { $0 == "system_proxy:" }.count == 1)
        let ssl = try #require(lines.firstIndex(of: "ssl_insecure: true"))
        let capture = try #require(lines.firstIndex(of: "macos_capture:"))
        let scope = try #require(lines.firstIndex(of: "scope:"))
        let systemProxy = try #require(lines.firstIndex(of: "system_proxy:"))
        #expect(ssl < capture)
        #expect(capture < scope)
        #expect(scope < systemProxy)
        #expect(yaml.hasSuffix("scope:\n  entries:\n    - \"api.example.test\"\n\nsystem_proxy:\n  auto: true\n  bypass:\n    - \"corp.test\"\n"))
        // The block only ever appends: everything before it is byte-identical without it.
        let without = try EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            sslInsecure: true, captureEnabled: true, scopeHosts: ["api.example.test"]
        ).yaml()
        #expect(yaml.hasPrefix(without))
        // Scope-less, system-proxy-less configs are unchanged.
        #expect(try config(scopeHosts: ["api.example.test"]).yaml().hasSuffix("scope:\n  entries:\n    - \"api.example.test\"\n"))
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

    // MARK: System-proxy block — edges (tester, stage 5, SP-AC25)

    @Test func systemProxyBypassHostsAreEscapedForTheDoubleQuotedScalar() throws {
        // A quote or a backslash in a host is backslash-escaped inside its scalar (the scope hosts' rule), so a
        // crafted host cannot close the scalar; everything else is written as typed.
        let yaml = try config(systemProxyAuto: true, systemProxyBypass: ["a\"b.test", "back\\slash.test", "*.local", "bücher.test"]).yaml()
        #expect(yaml.hasSuffix("system_proxy:\n  auto: true\n  bypass:\n    - \"a\\\"b.test\"\n    - \"back\\\\slash.test\"\n"
                               + "    - \"*.local\"\n    - \"bücher.test\"\n"))
    }

    @Test func systemProxyBypassKeepsOrderAndWritesEveryHost() throws {
        let yaml = try config(systemProxyBypass: ["z.test", "a.test", "m.test"]).yaml()
        #expect(yaml.hasSuffix("system_proxy:\n  auto: false\n  bypass:\n    - \"z.test\"\n    - \"a.test\"\n    - \"m.test\"\n"))
        // An oversized list is written whole: 500 hosts, one line each, four-space indented, nothing collapsed.
        let many = (1...500).map { "h\($0).test" }
        let big = try config(systemProxyAuto: true, systemProxyBypass: many).yaml()
        let lines = big.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        #expect(lines.filter { $0.hasPrefix("    - \"h") && $0.hasSuffix(".test\"") }.count == 500)
        #expect(lines.filter { $0 == "system_proxy:" }.count == 1)
        #expect(lines.filter { $0 == "  bypass:" }.count == 1)
        #expect(big.contains("system_proxy:\n  auto: true\n  bypass:\n    - \"h1.test\"\n    - \"h2.test\"\n"))
        #expect(big.hasSuffix("    - \"h499.test\"\n    - \"h500.test\"\n"))
    }

    @Test func aCarriageReturnAloneInABypassHostThrows() {
        // `\r` alone is a line break to a YAML parser that honours it; rejected like `\n`.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\rx")) {
            try config(systemProxyBypass: ["evil.test\rx"]).yaml()
        }
        // U+0085 (NEL) is a line break to libyaml too; the shared helper refuses it on a host as on a path (S-2).
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("evil.test\u{85}x")) {
            try config(systemProxyBypass: ["evil.test\u{85}x"]).yaml()
        }
        // The error names the offending host, not the first one, and a later good host does not rescue it.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("\n")) {
            try config(systemProxyAuto: true, systemProxyBypass: ["ok.test", "\n", "also-ok.test"]).yaml()
        }
        // A newline in a SCOPE host and in a BYPASS host throw the same case, so one catch covers both; the scope
        // host is checked first because its block is written first.
        #expect(throws: EmbeddedCoreLaunch.ConfigError.hostContainsNewline("scope\nhost")) {
            try EmbeddedCoreLaunch.Config(
                obscuraBinary: URL(fileURLWithPath: "/ok/obscura"), proxyPort: 8080, browserProxyPort: 8083,
                token: "00", operatorToken: "11", endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
                scopeHosts: ["scope\nhost"], systemProxyAuto: true, systemProxyBypass: ["bypass\nhost"]
            ).yaml()
        }
    }

    @Test func anEmptyBypassHostIsWrittenAsAnEmptyScalar() throws {
        // `Config` trusts its caller like `scopeHosts` does: the one filter is `SystemProxyPreferences.bypassHosts`,
        // which `EmbeddedCore.spawn()` and the live set always go through, so an empty host never reaches a real
        // config. Pinned so a change here is a deliberate one.
        let yaml = try config(systemProxyBypass: [""]).yaml()
        #expect(yaml.hasSuffix("system_proxy:\n  auto: false\n  bypass:\n    - \"\"\n"))
        #expect(SystemProxyPreferences.bypassHosts("") == [])
    }

    @Test func systemProxyBlockLinesAreAtTheRightColumns() throws {
        // The core's `deny_unknown_fields` parser needs `system_proxy:` at column 0, `auto:`/`bypass:` at two, the
        // items at four; one stray space would make it a child of the previous key or an unknown one.
        let yaml = try config(systemProxyAuto: true, systemProxyBypass: ["corp.test"]).yaml()
        let lines = yaml.split(separator: "\n").map(String.init)
        let start = try #require(lines.firstIndex(of: "system_proxy:"))
        #expect(Array(lines[start...]) == ["system_proxy:", "  auto: true", "  bypass:", "    - \"corp.test\""])
        // With no other tail the block follows the `browser` section directly (byte-exact, as the core parses it).
        #expect(yaml.hasSuffix("    stop_timeout: 2\nsystem_proxy:\n  auto: true\n  bypass:\n    - \"corp.test\"\n"))
    }

    // MARK: Harness audit log

    /// A config whose only non-default is the harness audit-log file: every other field matches
    /// the system-proxy helper's fixture, so `operatorToken` is `"11"` (the core's pin literal).
    private func config(auditLogFile: URL?, systemProxyAuto: Bool = false) -> EmbeddedCoreLaunch.Config {
        EmbeddedCoreLaunch.Config(
            obscuraBinary: URL(fileURLWithPath: "/ok/obscura"),
            proxyPort: 8080, browserProxyPort: 8083,
            token: "00", operatorToken: "11",
            endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"),
            systemProxyAuto: systemProxyAuto,
            auditLogFile: auditLogFile
        )
    }

    @Test func audit_log_is_absent_by_default() throws {
        // AC1: a Config built without the new parameter — every pre-existing call site, and the
        // installed app's normal launch — carries no audit-log file and writes no `audit_log` key,
        // so the core keeps its default and the generated config is byte-identical to before.
        let config = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        #expect(config.auditLogFile == nil)
        #expect(!(try config.yaml()).contains("audit_log"))
    }

    @Test func default_config_is_exactly_this_document() throws {
        // AC1: the installed app's config (no harness variable, every option at its default) is
        // pinned byte-for-byte. "No `audit_log` key" alone would still pass if an optional line
        // left a stray byte in the `mcp:` block (a blank line, a shifted indent after
        // `operator_token`), and the tail `hasSuffix` pins never look there. No trailing newline;
        // each optional tail starts with its own `\n`. Update this document deliberately, and
        // only when a key is meant to appear in every launch. (The text is what `yaml()` rendered
        // at 61a5ae05, before `auditLogFile` existed.)
        let config = sampleConfig(endpointFile: URL(fileURLWithPath: "/tmp/bus.endpoint"))
        let expected = """
        listen: "127.0.0.1:8080"
        mcp:
          transport:
            loopback_tcp:
              port: 0
              token: "\(config.token)"
              endpoint_file: "/tmp/bus.endpoint"
          operator_token: "\(config.operatorToken)"
        browser:
          proxy_addr: "127.0.0.1:8083"
          obscura:
            binary: "/Apps/Aitmproxy.app/Contents/Resources/core/obscura"
            stop_timeout: 2
        """
        #expect(try config.yaml() == expected)
    }

    @Test func audit_log_line_sits_inside_the_mcp_block_and_is_what_the_core_parses() throws {
        // AC2/AC5: the key belongs to `mcp` (`deny_unknown_fields`), so it is the line directly
        // after `operator_token` at two-space indent and before the top-level `browser:`.
        let fragment = "  operator_token: \"11\"\n  audit_log: \"/tmp/store/audit.jsonl\"\n"
        let yaml = try config(auditLogFile: URL(fileURLWithPath: "/tmp/store/audit.jsonl")).yaml()
        #expect(yaml.contains(fragment + "browser:\n"))

        // Pin the fragment to the core's round-trip test: the Rust test must still spell the same
        // two lines (under the minimal `mcp:` header that makes them a complete parse input) and
        // must still exist. The Rust literal is derived from the asserted fragment with the same
        // escaping as the system-proxy pin, so the two can never drift apart silently. This file
        // lives at apps/mac/Tests/AitmproxyKitTests/, so the repo root is five levels up.
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let source = root.appending(path: "crates/aitm/src/config_file.rs")
        try #require(
            FileManager.default.fileExists(atPath: source.path),
            "cannot find the core's src/config_file.rs at \(source.path)")
        let rust = try String(contentsOf: source, encoding: .utf8)
        let rustLiteral = "\"" + ("mcp:\n" + fragment)
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
        #expect(rust.contains(rustLiteral), "src/config_file.rs no longer contains the literal \(rustLiteral)")
        #expect(rust.contains("fn mcp_audit_log_path_the_mac_app_emits_parses()"))
    }

    @Test func audit_log_path_is_escaped_and_a_newline_is_refused() throws {
        // AC4: the path goes through the same double-quoted-scalar escape as the obscura and
        // endpoint paths — a quote or backslash cannot break out of the scalar — and a newline
        // (which would let a crafted `APP_STORE` inject YAML into the token-bearing file) throws.
        let escaped = try config(auditLogFile: URL(fileURLWithPath: #"/a/"b"\c/audit.jsonl"#)).yaml()
        #expect(escaped.contains(#"audit_log: "/a/\"b\"\\c/audit.jsonl""#))

        let bad = config(auditLogFile: URL(fileURLWithPath: "/tmp/x\nlisten: evil"))
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/tmp/x\nlisten: evil")) {
            try bad.yaml()
        }
        // A bare carriage return is a line break to YAML as much as `\n` is (AC4's `\r` half).
        let cr = config(auditLogFile: URL(fileURLWithPath: "/tmp/x\rlisten: evil"))
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/tmp/x\rlisten: evil")) {
            try cr.yaml()
        }
        // libyaml folds U+0085 (NEL), U+2028 and U+2029 inside a double-quoted scalar, so the
        // core would read a directory the app never named; they are refused like `\n` (S-2).
        let nel = config(auditLogFile: URL(fileURLWithPath: "/tmp/x\u{85}listen: evil"))
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/tmp/x\u{85}listen: evil")) {
            try nel.yaml()
        }
        let lineSeparator = config(auditLogFile: URL(fileURLWithPath: "/tmp/x\u{2028}listen: evil"))
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/tmp/x\u{2028}listen: evil")) {
            try lineSeparator.yaml()
        }
        let paragraphSeparator = config(auditLogFile: URL(fileURLWithPath: "/tmp/x\u{2029}listen: evil"))
        #expect(throws: EmbeddedCoreLaunch.ConfigError.pathContainsNewline("/tmp/x\u{2029}listen: evil")) {
            try paragraphSeparator.yaml()
        }
    }

    @Test func harness_audit_log_file_follows_the_harness_variables() {
        // AC1–AC3: no harness variable (absent or empty) means nil (the installed app); a
        // non-empty `APP_STORE` points into the store; a non-empty `APP_LIVE` alone points into
        // the per-run work dir; when both are set the store wins, as it does for `Store.url`.
        let workDir = URL(fileURLWithPath: "/tmp/wd", isDirectory: true)
        func file(_ env: [String: String]) -> URL? {
            EmbeddedCoreLaunch.harnessAuditLogFile(environment: env, workDir: workDir)
        }
        #expect(file([:]) == nil)
        #expect(file(["APP_STORE": ""]) == nil)
        #expect(file(["APP_LIVE": ""]) == nil)
        // Spec Design 2 (Amendment 1): `APP_LIVE` is matched as NON-EMPTY, the same predicate
        // `SettingsDomain.select` uses to pick the isolated defaults suite, so a run that isolates
        // its settings always isolates its audit too; "0" and "true" are harness runs here even
        // though `SelfTest.live` (does the self-test RUN) still wants exactly "1".
        #expect(file(["APP_LIVE": "0"])?.path == "/tmp/wd/audit.jsonl")
        #expect(file(["APP_LIVE": "true"])?.path == "/tmp/wd/audit.jsonl")
        #expect(file(["APP_STORE": "/tmp/Aitmproxy-dev-state-x"])?.path == "/tmp/Aitmproxy-dev-state-x/audit.jsonl")
        #expect(file(["APP_LIVE": "1"])?.path == "/tmp/wd/audit.jsonl")
        #expect(file(["APP_STORE": "/tmp/Aitmproxy-dev-state-x", "APP_LIVE": "1"])?.path == "/tmp/Aitmproxy-dev-state-x/audit.jsonl")
    }

    @Test func audit_log_does_not_disturb_the_tails() throws {
        // AC7: the line lives in the `mcp:` block, not as a tail, so the byte-exact `hasSuffix`
        // the system-proxy tests rely on still holds, and `audit_log` precedes `browser:`.
        let yaml = try config(auditLogFile: URL(fileURLWithPath: "/tmp/store/audit.jsonl"), systemProxyAuto: true).yaml()
        #expect(yaml.hasSuffix("\nsystem_proxy:\n  auto: true\n"))
        let audit = try #require(yaml.range(of: "  audit_log: \"/tmp/store/audit.jsonl\"\n"))
        let browser = try #require(yaml.range(of: "browser:\n"))
        #expect(audit.upperBound <= browser.lowerBound)
    }

    @Test func child_environment_drops_an_inherited_audit_log_override_only_in_a_harness_run() {
        // AC8 (Amendment 2, Design 5): the core's `env.rs` lets `AITM_AUDIT_LOG` in the child's
        // environment win over the file's `mcp.audit_log` (`on` means the DEFAULT file, the
        // operator's real `audit.jsonl`), and the child inherits the app's environment. In a
        // harness run (a non-nil file) the key is removed so the config stays authoritative and
        // the store isolation cannot be defeated from outside; every other key is untouched.
        // With no harness file the dictionary passes through unchanged, the key included (the
        // installed app keeps the core's own rule). #313's goal, by a different mechanism.
        let file = URL(fileURLWithPath: "/tmp/s/audit.jsonl")
        let base = ["PATH": "/usr/bin", "RUST_LOG": "info"]
        for value in ["on", "off", "/x/audit.jsonl"] {
            let inherited = base.merging(["AITM_AUDIT_LOG": value]) { $1 }
            #expect(EmbeddedCoreLaunch.childEnvironment(inherited, harnessAuditLogFile: file) == base,
                    "AITM_AUDIT_LOG=\(value) must be dropped from a harness child")
        }
        let kept = base.merging(["AITM_AUDIT_LOG": "on"]) { $1 }
        #expect(EmbeddedCoreLaunch.childEnvironment(kept, harnessAuditLogFile: nil) == kept)
        #expect(EmbeddedCoreLaunch.childEnvironment(base, harnessAuditLogFile: file) == base)
        #expect(EmbeddedCoreLaunch.auditLogEnvironmentKey == "AITM_AUDIT_LOG")
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

/// MS-R2: a harness launch (`APP_STORE`) makes its core publish under its own store so the installed
/// app's run dir stays the only one the CLI's one-shots see.
@Suite struct EmbeddedCoreRunDirTests {
    @Test func devBundlesGetTheirOwnRunDirAndTheInstalledAppDoesNot() {
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: [:]) == nil)
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: ["APP_STORE": ""]) == nil)
        #expect(EmbeddedCoreLaunch.isolatedRunDir(environment: ["APP_STORE": "/tmp/Aitmproxy-dev-state-x"])?.path
                == "/tmp/Aitmproxy-dev-state-x/run/cores")
        #expect(EmbeddedCoreLaunch.runDirEnvironmentKey == "AITM_RUN_DIR")
        #expect(SettingsDomain.overriddenStoreURL(environment: ["APP_STORE": "/tmp/s"])?.path == "/tmp/s")
        #expect(SettingsDomain.overriddenStoreURL(environment: ["APP_LIVE": "1"]) == nil)
    }
}
