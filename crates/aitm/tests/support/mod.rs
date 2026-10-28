//! Shared helpers for the `aitm` integration tests that assemble a proxy from
//! a `Config` with a throwaway CA directory, and the service handles `main`
//! shares between the frontends (what `aitm tui` hands to `tui::build_servers`).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::tui::Services;
use aitm::wire::{assemble, Assembled, Http1Sender};
use aitm_core::{Config, PipelineClient, Proxy, ProxyClient, ScopeRateGuard};

/// A fresh, unique directory under the system temp dir for one test's CA.
pub fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-test-{tag}-{nanos}-{n}"))
}

/// The default config with its CA in [`temp_ca_dir`].
pub fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

/// `assemble`, then the service handles exactly as `main` builds them for the
/// frontends: the registry, store and guard from the proxy, the replay client
/// over `Http1Sender`; no browser, no log file.
pub fn assemble_services(cfg: &Config) -> (Proxy, Services) {
    let Assembled { proxy, ca: _ } = assemble(cfg).expect("assemble");
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard: Arc<dyn ScopeRateGuard> = proxy.guard();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new().with_insecure(cfg.ssl_insecure)),
    ));
    let services = Services {
        registry,
        store,
        client,
        guard,
        browser: None,
        log_path: None,
    };
    (proxy, services)
}
