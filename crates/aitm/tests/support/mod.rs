//! Shared helpers for the `aitm` integration tests that assemble a proxy from
//! a `Config` with a throwaway CA directory, and the service handles `main`
//! shares between the frontends (what `aitm tui` hands to `tui::build_servers`).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use aitm::tui::{self, Services, TuiLog};
use aitm::wire::{assemble, Assembled, Governance};
use aitm_core::{Config, Proxy};

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
/// frontends (`tui::services`): the registry, store and guard from the proxy,
/// the replay client over `Http1Sender`; no browser, no log file. It also
/// returns the core's `Governance` for `build_servers`.
pub fn assemble_services(cfg: &Config) -> (Proxy, Services, Governance) {
    let assembled = assemble(cfg).expect("assemble");
    let governance = assembled.governance();
    let Assembled { proxy, job_bus, .. } = assembled;
    let services = tui::services(&proxy, cfg, None, TuiLog::Off, job_bus);
    (proxy, services, governance)
}
