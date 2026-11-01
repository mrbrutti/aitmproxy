//! Task 22 (M2-AC18, Review Focus #3): the YAML config file is a serde mirror
//! of `Config`. Every field is optional and defaults are applied field by
//! field, so a two-line file is valid; an unknown key is an error, not a silent
//! default; an absent file at the default path is `Config::default()`, while an
//! absent file at an explicit path is an error naming the path.

use std::path::{Path, PathBuf};
use std::sync::Once;

use aitm::config_file::{default_config_path, load, parse, parse_settings};
use aitm_core::{BrowserEngine, Config, McpTransport};

/// Point the per-user config dir at a temp dir, once, before any test reads
/// it. `dirs::config_dir()` follows `$HOME` on macOS and `$XDG_CONFIG_HOME` on
/// Linux, so both are set. Every test calls this first, so no thread computes
/// `Config::default()` against the real home and then against the redirect.
fn redirect_home() -> PathBuf {
    static ONCE: Once = Once::new();
    let dir = std::env::temp_dir().join(format!("aitm-config-file-{}", std::process::id()));
    ONCE.call_once(|| {
        std::fs::create_dir_all(&dir).expect("create temp home");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", &dir);
    });
    dir
}

/// Debug rendering of every `Config` field except the four M2 knobs
/// (`browser.engine`, `browser.obscura.binary`, `ca.allow_agent_install`,
/// `ca.audit_log`), so a test can pin "nothing else changed".
fn remaining_fields(c: &Config) -> String {
    let b = &c.browser;
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} | ca {:?} {:?} | browser {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        c.listen,
        c.scope,
        c.limits,
        c.mcp,
        c.poc,
        c.ssl_insecure,
        c.max_flows,
        c.max_flow_bytes,
        c.ca.dir,
        c.ca.key_mode,
        b.obscura.start_timeout,
        b.obscura.stop_timeout,
        b.proxy_addr,
        b.headless,
        b.ignore_cert_errors,
        b.nav_timeout,
        b.ssrf,
    )
}

/// M2-AC18: the four M2 knobs load from a file into their `Config` fields, and
/// every other field equals `Config::default()`'s.
#[test]
fn m2_knobs_load() {
    let home = redirect_home();
    let path = home.join("m2-knobs.yaml");
    std::fs::write(
        &path,
        "browser:\n  engine: chrome\n  obscura:\n    binary: /x/obscura\nca:\n  allow_agent_install: true\n  audit_log: /x/audit.jsonl\n",
    )
    .expect("write yaml");

    let cfg = load(Some(&path)).expect("four-knob file loads");

    assert_eq!(cfg.browser.engine, BrowserEngine::Chrome);
    assert_eq!(
        cfg.browser.obscura.binary,
        Some(PathBuf::from("/x/obscura"))
    );
    assert!(cfg.ca.allow_agent_install);
    assert_eq!(cfg.ca.audit_log, PathBuf::from("/x/audit.jsonl"));
    assert_eq!(remaining_fields(&cfg), remaining_fields(&Config::default()));
}

/// No file at the default path → exactly `Config::default()`, today's
/// behaviour. The default path is `config.yaml` beside the CA dir.
#[test]
fn absent_default_is_default() {
    let home = redirect_home();
    std::env::remove_var("AITM_CONFIG");

    let path = default_config_path();
    assert!(
        path.starts_with(&home),
        "default path {path:?} is not under the redirected home {home:?}"
    );
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("config.yaml")
    );
    assert_eq!(path.parent(), Config::default().ca.dir.parent());
    assert!(!path.exists(), "test precondition: {path:?} must not exist");

    let cfg = load(None).expect("absent default file is not an error");
    assert_eq!(format!("{cfg:?}"), format!("{:?}", Config::default()));
}

/// An explicit path that does not exist is an error that names the path.
#[test]
fn absent_explicit_is_error() {
    redirect_home();
    let err = load(Some(Path::new("/nonexistent/c.yaml"))).expect_err("absent explicit path");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("/nonexistent/c.yaml"),
        "error does not name the path: {msg}"
    );
}

/// Review Focus #3: a misspelled key is an error naming the key, not a silent
/// default.
#[test]
fn unknown_key_is_an_error() {
    redirect_home();
    let err = parse("browser:\n  enigne: chrome\n").expect_err("misspelled key");
    let msg = format!("{err:#}");
    assert!(msg.contains("enigne"), "error does not name the key: {msg}");
}

/// The documented `mcp.transport` forms are plain maps — `{loopback_tcp:
/// {port, token}}` and `{stdio: {}}` — not YAML `!tags`.
#[test]
fn transport_map_forms_load() {
    redirect_home();
    let cfg = parse("mcp:\n  transport:\n    loopback_tcp:\n      port: 7001\n      token: t0k\n")
        .expect("loopback_tcp map form");
    assert!(
        matches!(
            &cfg.mcp.transport,
            McpTransport::LoopbackTcp { port: 7001, token, .. } if token == "t0k"
        ),
        "{:?}",
        cfg.mcp.transport
    );

    let cfg = parse("mcp:\n  transport:\n    stdio: {}\n").expect("stdio map form");
    assert!(
        matches!(cfg.mcp.transport, McpTransport::Stdio),
        "{:?}",
        cfg.mcp.transport
    );
}

/// O5: the loopback transport takes an optional `endpoint_file` (the bus
/// rendezvous path); it defaults to `None` and parses when given.
#[test]
fn loopback_endpoint_file_parses() {
    redirect_home();
    let cfg = parse(
        "mcp:\n  transport:\n    loopback_tcp:\n      port: 0\n      token: t0k\n      endpoint_file: /tmp/aitm-bus.addr\n",
    )
    .expect("loopback_tcp with endpoint_file");
    assert!(
        matches!(
            &cfg.mcp.transport,
            McpTransport::LoopbackTcp { endpoint_file: Some(p), .. }
                if p == std::path::Path::new("/tmp/aitm-bus.addr")
        ),
        "{:?}",
        cfg.mcp.transport
    );

    let cfg = parse("mcp:\n  transport:\n    loopback_tcp:\n      port: 0\n      token: t0k\n")
        .expect("loopback_tcp without endpoint_file");
    assert!(
        matches!(
            &cfg.mcp.transport,
            McpTransport::LoopbackTcp {
                endpoint_file: None,
                ..
            }
        ),
        "{:?}",
        cfg.mcp.transport
    );
}

/// A `ca.key_mode` that lets group or other read the CA key is refused when
/// the file is parsed, so no config can widen the key's permissions; modes
/// confined to the owner load as given (octal or decimal spelling).
#[test]
fn key_mode_with_group_or_other_bits_is_refused() {
    redirect_home();
    for mode in ["0o644", "0o640", "0o604", "0o777", "420"] {
        let err = parse(&format!("ca:\n  key_mode: {mode}\n"))
            .expect_err(&format!("key_mode {mode} must be refused"));
        let msg = format!("{err:#}");
        assert!(msg.contains("key_mode"), "{mode}: {msg}");
        assert!(msg.contains("group"), "{mode}: {msg}");
        assert!(msg.contains("other"), "{mode}: {msg}");
    }
    for (mode, want) in [("0o600", 0o600), ("0o400", 0o400), ("384", 0o600)] {
        let cfg = parse(&format!("ca:\n  key_mode: {mode}\n"))
            .unwrap_or_else(|e| panic!("key_mode {mode} must load: {e:#}"));
        assert_eq!(cfg.ca.key_mode, want, "{mode}");
    }
}

/// A two-line file sets one field and leaves every other at its default.
#[test]
fn two_line_file_is_valid() {
    redirect_home();
    let mut cfg =
        parse("# lab with self-signed targets\nssl_insecure: true\n").expect("two-line file");
    assert!(cfg.ssl_insecure);
    cfg.ssl_insecure = false;
    assert_eq!(format!("{cfg:?}"), format!("{:?}", Config::default()));
}

/// The operator-command gate knobs parse from real config, so the `scope.add`
/// refusal's instruction is actionable and `poc.artifact` has an output dir.
#[test]
fn operator_gate_knobs_load() {
    redirect_home();
    let cfg = parse("scope:\n  allow_agent_widen: true\npoc:\n  out_dir: /var/poc-out\n")
        .expect("parse operator knobs");
    assert!(cfg.scope.allow_agent_widen);
    assert_eq!(cfg.poc.out_dir.as_deref(), Some(Path::new("/var/poc-out")),);
    // Defaults hold when the knobs are absent.
    let def = parse("ssl_insecure: false\n").expect("parse");
    assert!(!def.scope.allow_agent_widen);
    assert_eq!(def.poc.out_dir, None);
    // Unknown keys under these sections are still rejected (deny_unknown_fields).
    assert!(parse("scope:\n  bogus: 1\n").is_err());
    assert!(parse("poc:\n  bogus: 1\n").is_err());
}

/// SP-AC7 of the macOS Scope-persistence spec
/// (`docs/superpowers/specs/2026-10-31-macos-scope-persistence-design.md`): the
/// core parses the exact bytes the macOS app's `EmbeddedCoreLaunch.Config.yaml()`
/// emits for a persisted embedded scope. The literal below is the shared block the
/// Swift mirror test
/// `EmbeddedCoreLaunchTests.scope_block_is_byte_identical_to_the_core_parse_input`
/// asserts as the YAML suffix; its sibling tripwire
/// `scope_block_text_is_what_the_core_round_trip_test_parses` greps this file for
/// this exact spelling, so keep it one plain string literal (no concatenation, no
/// raw string). Also SP-AC5 `[rust]`: the block never turns on `allow_agent_widen`.
#[test]
fn scope_entries_block_round_trips() {
    redirect_home();
    let cfg = parse(
        "scope:\n  entries:\n    - \"api.example.test\"\n    - \"*.shop.test\"\n    - \"localhost:8099\"\n",
    )
    .expect("parse scope entries");
    let hosts: Vec<&str> = cfg.scope.entries.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(hosts, ["api.example.test", "*.shop.test", "localhost:8099"]);
    assert!(!cfg.scope.allow_agent_widen);
    // An explicit empty list is accepted and yields no entries.
    assert!(parse("scope:\n  entries: []\n")
        .expect("parse empty entries")
        .scope
        .entries
        .is_empty());
    // Composition with a sibling top-level key the app also emits.
    let both = parse("ssl_insecure: true\nscope:\n  entries:\n    - \"api.example.test\"\n")
        .expect("parse");
    assert!(both.ssl_insecure);
    let both_hosts: Vec<&str> = both.scope.entries.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(both_hosts, ["api.example.test"]);
}

/// Tester (SP-AC7, SP-AC17): the escaping `EmbeddedCoreLaunch.yamlDoubleQuoted` applies
/// (`\` → `\\`, `"` → `\"`) and the characters it leaves alone (an IDN, mixed case, `#`,
/// `'`) all come back out of the core's parse as the original host — so what the app
/// quotes is what the guard is seeded with. Swift mirrors:
/// `EmbeddedCoreLaunchTests.scope_block_escapes_quotes_and_backslashes` and
/// `scope_block_emits_unicode_and_yaml_specials_verbatim_inside_quotes`.
#[test]
fn scope_entries_quoting_survives_the_parse() {
    redirect_home();
    let cfg = parse(
        "scope:\n  entries:\n    - \"a\\\"b.test\"\n    - \"c\\\\d.test\"\n    - \"bücher.example\"\n    - \"API.Example.TEST\"\n    - \"a#b.test\"\n    - \"o'neil.test\"\n",
    )
    .expect("parse quoted entries");
    let hosts: Vec<&str> = cfg.scope.entries.iter().map(|e| e.host.as_str()).collect();
    assert_eq!(
        hosts,
        [
            "a\"b.test",
            "c\\d.test",
            "bücher.example",
            "API.Example.TEST",
            "a#b.test",
            "o'neil.test",
        ]
    );
}

/// Tester (SP-AC4, SP-AC13): the exact tail the app writes when every operator opt-in is
/// on — `ssl_insecure`, then `macos_capture`, then `scope`, each tail prefixed with its own
/// newline so a blank line separates the blocks — parses as all three at once, through
/// `parse_settings` (the entry point that also returns `macos_capture`). Mirrors
/// `EmbeddedCoreLaunchTests.scope_block_follows_the_ssl_and_capture_tails`.
#[test]
fn scope_entries_compose_with_every_other_tail_the_app_emits() {
    redirect_home();
    let settings = parse_settings(
        "listen: \"127.0.0.1:8080\"\nssl_insecure: true\n\nmacos_capture:\n  enabled: true\n\nscope:\n  entries:\n    - \"api.example.test\"\n    - \"localhost:8099\"\n",
    )
    .expect("parse every tail");
    assert!(settings.core.ssl_insecure);
    assert!(settings.macos_capture.enabled);
    let hosts: Vec<&str> = settings
        .core
        .scope
        .entries
        .iter()
        .map(|e| e.host.as_str())
        .collect();
    assert_eq!(hosts, ["api.example.test", "localhost:8099"]);
    assert!(!settings.core.scope.allow_agent_widen);
}

/// Tester (anti-goal "a corrupt or tampered file wedges the core"): shapes the app never
/// emits but a hand-edited config could carry are refused loudly, never read as an empty or
/// widened scope — a string where the list goes, a mapping item, an unknown key beside
/// `entries`, and a mis-indented `entries` that would otherwise land as a top-level key.
#[test]
fn scope_entries_malformed_shapes_are_errors_not_defaults() {
    redirect_home();
    assert!(parse("scope:\n  entries: \"api.example.test\"\n").is_err());
    assert!(parse("scope:\n  entries:\n    - host: api.example.test\n").is_err());
    assert!(parse("scope:\n  entries: []\n  entrees: []\n").is_err());
    assert!(parse("scope:\nentries:\n  - \"api.example.test\"\n").is_err());
}

/// Tester (oversized input): a long but valid list parses whole and in order — no silent
/// cap anywhere between the app's file and the guard.
#[test]
fn scope_entries_long_list_parses_whole_and_in_order() {
    redirect_home();
    let hosts: Vec<String> = (0..5_000).map(|i| format!("h{i}.example.test")).collect();
    let mut yaml = String::from("scope:\n  entries:\n");
    for host in &hosts {
        yaml.push_str("    - \"");
        yaml.push_str(host);
        yaml.push_str("\"\n");
    }
    let cfg = parse(&yaml).expect("parse long list");
    let parsed: Vec<&str> = cfg.scope.entries.iter().map(|e| e.host.as_str()).collect();
    let expected: Vec<&str> = hosts.iter().map(String::as_str).collect();
    assert_eq!(parsed, expected);
}

/// Panel finding #2: the additive `session_io.allow_agent_file_io` gate parses from
/// config (off by default), the way `Config.tls`/`Config.maps` do, and an unknown
/// key under it is rejected (deny_unknown_fields).
#[test]
fn session_io_gate_loads() {
    redirect_home();
    let cfg = parse("session_io:\n  allow_agent_file_io: true\n").expect("parse session_io");
    assert!(cfg.session_io.allow_agent_file_io);
    // Default is off when the section is absent.
    assert!(
        !parse("ssl_insecure: false\n")
            .expect("parse")
            .session_io
            .allow_agent_file_io
    );
    // Unknown keys under the section are rejected.
    assert!(parse("session_io:\n  bogus: 1\n").is_err());
}

/// M7 Task 5 (AC-H2.10): the additive `limits.max_concurrent_streams` knob parses
/// from config into its `LimitConfig` field; absent, it keeps the safe default
/// (128); an unknown sibling key under `limits` is still rejected
/// (`deny_unknown_fields`).
#[test]
fn config_parses_max_concurrent_streams() {
    redirect_home();
    let cfg = parse("limits:\n  max_concurrent_streams: 64\n").expect("parse limits knob");
    assert_eq!(cfg.limits.max_concurrent_streams, 64);
    // Absent → the safe default.
    assert_eq!(
        parse("ssl_insecure: false\n")
            .expect("parse")
            .limits
            .max_concurrent_streams,
        128
    );
    // An unknown sibling key under `limits` is still an error.
    assert!(parse("limits:\n  bogus: 1\n").is_err());
}
