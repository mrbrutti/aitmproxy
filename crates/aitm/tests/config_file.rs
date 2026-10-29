//! Task 22 (M2-AC18, Review Focus #3): the YAML config file is a serde mirror
//! of `Config`. Every field is optional and defaults are applied field by
//! field, so a two-line file is valid; an unknown key is an error, not a silent
//! default; an absent file at the default path is `Config::default()`, while an
//! absent file at an explicit path is an error naming the path.

use std::path::{Path, PathBuf};
use std::sync::Once;

use aitm::config_file::{default_config_path, load, parse};
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
            McpTransport::LoopbackTcp { port: 7001, token } if token == "t0k"
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
