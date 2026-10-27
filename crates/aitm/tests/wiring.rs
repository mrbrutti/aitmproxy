//! Task 28 (AC-P3, AC-P4): the binary assembly wires everything from `Config`.
//!
//! AC-P3 — a plugin is removable by changing only the registration list, with no
//! `aitm-core` edit: dropping the mutate plugin removes `flow.mutate` while
//! capture's `flow.list` still works.
//! AC-P4 — a config option reaches observed behaviour end to end: the rate-limit
//! `per_host_rps` from `Config` moves the throttle threshold the guard enforces.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aitm::wire::{build_proxy_with, Features};
use aitm_core::{CommandHost, Config, GuardError, Params, ProxyClient, ScopeEntry, Value};

/// A unique temp directory for a test's CA material.
fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-wire-{tag}-{nanos}-{n}"))
}

fn config_with_ca(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

/// A `ProxyClient` that is never actually called by `flow.list`.
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(
        &self,
        _req: aitm_core::HttpRequest,
    ) -> futures::future::BoxFuture<'_, anyhow::Result<aitm_core::HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called in this test") })
    }
}

#[test]
fn drop_mutate_disables_mutation_no_core_edit() {
    let cfg = config_with_ca("acp3");

    let with_mutate =
        build_proxy_with(&cfg, &Features { mutate: true }).expect("build with mutate");
    let without_mutate =
        build_proxy_with(&cfg, &Features { mutate: false }).expect("build without mutate");

    // The only difference is the registration list — no aitm-core change.
    assert!(
        with_mutate.registry().command("flow.mutate").is_some(),
        "flow.mutate must be registered when the mutate plugin is included"
    );
    assert!(
        without_mutate.registry().command("flow.mutate").is_none(),
        "flow.mutate must be absent when the mutate plugin is dropped"
    );

    // Capture's flow.list works in both builds.
    for proxy in [&with_mutate, &without_mutate] {
        assert!(
            proxy.registry().command("flow.list").is_some(),
            "flow.list must be registered in both builds"
        );
        let store = proxy.store();
        let guard = proxy.guard();
        let client = UnusedClient;
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        let cmd = proxy.registry().command("flow.list").unwrap();
        let result = cmd
            .invoke(Params::new(BTreeMap::new()), &host)
            .expect("flow.list must succeed");
        // An empty store lists no flows.
        assert_eq!(result, Value::Array(Vec::new()));
    }
}

#[test]
fn option_from_config_moves_the_throttle_threshold() {
    let host = "ex.test:80";

    // A tight per-host budget: the third request in a burst is throttled.
    let mut tight = config_with_ca("acp4-tight");
    tight.scope.entries = vec![ScopeEntry {
        host: host.to_string(),
    }];
    tight.limits.per_host_rps = 2;
    let proxy = build_proxy_with(&tight, &Features::default()).expect("build tight");
    let guard = proxy.guard();

    let permits = vec![
        guard.check_active(host).expect("1st request permitted"),
        guard.check_active(host).expect("2nd request permitted"),
    ];
    let third = guard.check_active(host);
    assert!(
        matches!(third, Err(GuardError::RateLimited { .. })),
        "the 3rd request must be rate-limited at per_host_rps=2, but it was permitted: {}",
        third.is_ok()
    );
    drop(permits);

    // A generous budget from config lets the same burst through.
    let mut loose = config_with_ca("acp4-loose");
    loose.scope.entries = vec![ScopeEntry {
        host: host.to_string(),
    }];
    loose.limits.per_host_rps = 1000;
    let proxy2 = build_proxy_with(&loose, &Features::default()).expect("build loose");
    let guard2 = proxy2.guard();
    let _p1 = guard2.check_active(host).expect("1st permitted (loose)");
    let _p2 = guard2.check_active(host).expect("2nd permitted (loose)");
    let third2 = guard2.check_active(host);
    assert!(
        third2.is_ok(),
        "with per_host_rps=1000 the 3rd request must be permitted, but it was refused"
    );
}
