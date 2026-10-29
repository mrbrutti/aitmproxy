//! M5 Task 13 (amended, AC17 / AC19): the binary registers the `l4.*` command
//! surface on the live core, gated on config + privilege, fail-closed.
//!
//! - `enabled = false` (default) ⇒ the module is not constructed; no `l4.*` in the
//!   registry.
//! - `enabled = true` + privilege ⇒ the full `l4.*` surface is registered.
//! - `enabled = true` + no privilege ⇒ STILL registered (honest, drivable), but the
//!   wire verbs fail closed (proven at the command layer in `aitm-proto-l4`); here we
//!   assert the proxy still builds and the surface is present.
//!
//! AC19 ("`aitm-core` is untouched by the whole M5 milestone") was guarded here by a
//! git-diff test; it has been retired (see the note below the `l4_*` tests) now that
//! later milestones legitimately edit `aitm-core`.

use std::path::PathBuf;
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

// AC19 ("the M5 milestone makes no `aitm-core` edits") was guarded here by an
// `aitm_core_untouched` test that diffed `crates/aitm-core` against the merge-base
// with `main`. That check is obsolete now that later, authorized milestones edit
// `aitm-core` (e.g. M7 Task 5 adds `LimitConfig.max_concurrent_streams`): the diff
// no longer isolates M5's commits, so it would fail on any legitimate post-M5
// `aitm-core` change. M5's no-`aitm-core`-edit property is settled in its merged
// history (PR #15); the guard has been removed rather than pinned to fragile SHAs.
