//! M5 Task 13 (amended, AC17 / AC19): the binary registers the `l4.*` command
//! surface on the live core, gated on config + privilege, fail-closed.
//!
//! - `enabled = false` (default) ⇒ the module is not constructed; no `l4.*` in the
//!   registry.
//! - `enabled = true` + privilege ⇒ the full `l4.*` surface is registered.
//! - `enabled = true` + no privilege ⇒ STILL registered (honest, drivable), but the
//!   wire verbs fail closed (proven at the command layer in `aitm-proto-l4`); here we
//!   assert the proxy still builds and the surface is present.
//! - `aitm-core` is untouched by the whole milestone (AC19).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aitm::wire::{build_proxy_with, Features};
use aitm_core::Config;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;

/// A unique temp directory for a test's CA material.
fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-l4wire-{tag}-{nanos}-{n}"))
}

fn config_with_ca(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

fn l4_enabled() -> L4Config {
    L4Config {
        enabled: true,
        ..L4Config::default()
    }
}

/// AC17: `enabled = false` ⇒ the module is not constructed and no `l4.*` command is
/// registered.
#[test]
fn l4_disabled_not_registered() {
    let cfg = config_with_ca("disabled");
    let proxy = build_proxy_with(&cfg, &Features::default()).expect("build with l4 disabled");

    for name in [
        "l4.craft",
        "l4.inject",
        "l4.interfaces",
        "l4.intercept.start",
    ] {
        assert!(
            proxy.registry().command(name).is_none(),
            "{name} must be absent when l4 is disabled"
        );
    }
}

/// AC17: `enabled = true` with privilege present ⇒ the full `l4.*` surface is live;
/// `l4.craft` and `l4.inject` are both registered.
#[test]
fn l4_enabled_registers_commands() {
    let cfg = config_with_ca("enabled");
    let features = Features {
        l4: l4_enabled(),
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    let proxy = build_proxy_with(&cfg, &features).expect("build with l4 enabled");

    assert!(
        proxy.registry().command("l4.craft").is_some(),
        "l4.craft must be registered when l4 is enabled"
    );
    assert!(
        proxy.registry().command("l4.inject").is_some(),
        "l4.inject must be registered when l4 is enabled"
    );
}

/// AC17: `enabled = true` with privilege ABSENT ⇒ the proxy still builds (no panic),
/// and the module is still registered with its full surface — so the operator who
/// opted in sees an honest, drivable surface. (The wire verbs' fail-closed
/// `L4Unavailable` is asserted at the command layer in `aitm-proto-l4`.)
#[test]
fn l4_enabled_no_priv_builds() {
    let cfg = config_with_ca("noprivbuild");
    let unprivileged = L4Privilege {
        capture_inject: Some("missing CAP_NET_RAW".into()),
        intercept: Some("missing CAP_NET_ADMIN".into()),
    };
    let features = Features {
        l4: l4_enabled(),
        l4_privilege: Some(unprivileged),
        ..Features::default()
    };
    let proxy = build_proxy_with(&cfg, &features).expect("proxy still builds without privilege");

    // The read verb and a wire verb are both registered (honest surface).
    assert!(proxy.registry().command("l4.interfaces").is_some());
    assert!(proxy.registry().command("l4.inject").is_some());
}

/// AC19: the M5 milestone makes no `aitm-core` edits — `git diff` against the
/// merge-base with `main` shows nothing under `crates/aitm-core`. Skips cleanly when
/// git or the base ref is unavailable (e.g. a shallow checkout).
#[test]
fn aitm_core_untouched() {
    let toplevel = match git(&["rev-parse", "--show-toplevel"]) {
        Some(p) => p.trim().to_string(),
        None => return, // no git — nothing to assert here
    };
    let base = match git(&["-C", &toplevel, "merge-base", "HEAD", "main"]) {
        Some(b) if !b.trim().is_empty() => b.trim().to_string(),
        _ => return, // `main` not present (shallow CI clone) — skip
    };
    let changed = git(&[
        "-C",
        &toplevel,
        "diff",
        "--name-only",
        &base,
        "--",
        "crates/aitm-core",
    ])
    .expect("git diff runs once rev-parse/merge-base have");
    assert!(
        changed.trim().is_empty(),
        "M5 must not touch aitm-core, but these files changed:\n{changed}"
    );
}

/// Run a git command, returning its stdout on success, `None` if git is missing or
/// the command fails.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}
