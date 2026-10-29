//! M4 Task 1 (AC-M4-3): every command in the fully wired registry declares the
//! D2 sensitivity tier the spec assigns it.
//!
//! The fail-closed `Sensitive` default (an unclassified command) is asserted at
//! the trait level in `crates/aitm-core/tests/sensitivity.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aitm::wire::build_proxy;
use aitm_core::{Config, Sensitivity};

/// A unique temp directory for a test's CA material.
fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-sens-{tag}-{nanos}-{n}"))
}

fn config_with_ca(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

#[test]
fn sensitivity_is_declared_for_every_command() {
    let cfg = config_with_ca("every");
    let proxy = build_proxy(&cfg).expect("build the wired proxy");
    let reg = proxy.registry();

    let tier = |name: &str| {
        reg.command(name)
            .unwrap_or_else(|| panic!("command {name} is not registered in the default wiring"))
            .sensitivity()
    };

    // D2 — Read (observation only; `mutates()` is false).
    for name in [
        "flow.list",
        "flow.get",
        "scope.list",
        "ca.status",
        "browser.get_dom",
        "browser.screenshot",
    ] {
        assert_eq!(tier(name), Sensitivity::Read, "{name} should be Read");
    }

    // D2 — Write (the routine testing verbs, bounded by scope/rate/SSRF).
    for name in [
        "flow.replay",
        "flow.mutate",
        "flow.resume",
        "flow.kill",
        "request.send",
        "poc.build",
        "poc.run",
        "browser.navigate",
        "browser.click",
        "browser.type",
        "browser.eval",
    ] {
        assert_eq!(tier(name), Sensitivity::Write, "{name} should be Write");
    }

    // D2 — Sensitive (trust / authorization / irreversible-beyond-scope).
    for name in ["ca.install", "ca.uninstall", "scope.add"] {
        assert_eq!(
            tier(name),
            Sensitivity::Sensitive,
            "{name} should be Sensitive"
        );
    }

    // `mutates()` is derived: false iff Read, across the whole registry.
    for cmd in reg.commands() {
        let expected = cmd.sensitivity() != Sensitivity::Read;
        assert_eq!(
            cmd.mutates(),
            expected,
            "{} mutates() must be sensitivity() != Read",
            cmd.name()
        );
    }
}
