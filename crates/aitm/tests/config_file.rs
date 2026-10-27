//! Task 22 (M2-AC18, Review Focus #3): the YAML config file is a serde mirror
//! of `Config`. Every field is optional and defaults are applied field by
//! field, so a two-line file is valid; an unknown key is an error, not a silent
//! default; an absent file at the default path is `Config::default()`, while an
//! absent file at an explicit path is an error naming the path.

use std::path::{Path, PathBuf};
use std::sync::Once;

use aitm::config_file::{default_config_path, load, parse};
use aitm_core::{BrowserEngine, Config};

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
