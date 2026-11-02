//! Shared helpers for the `aitm` integration tests that assemble a proxy from
//! a `Config` with a throwaway CA directory, and the service handles `main`
//! shares between the frontends (what `aitm tui` hands to `tui::build_servers`).
//!
//! Boundary (quality Q19): `support` is proxy assembly, CA directories and
//! service helpers; the textual source scans of the tree live in `common/mod.rs`.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::scripts::LateHandles;
use aitm::tui::{self, Services, TuiLog};
use aitm::wire::{assemble, assemble_with_scripts, Assembled, Features, Governance, ScriptWiring};
use aitm_core::{Config, Plugin, Proxy};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::wire::build_with_languages;
use aitm_plugin_rhai::{MemoryFindingSink, RhaiConfig, ScriptServices};
use aitm_poc::step_registry::PocStepRegistry;

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
    let Assembled { proxy, .. } = assembled;
    let services = tui::services(&proxy, cfg, None, TuiLog::Off);
    (proxy, services, governance)
}

/// `main.rs`'s script services: late-bound handles the proxy fills in once
/// built. Needs a tokio runtime context for the tier's `Handle`.
fn startup_services() -> ScriptServices {
    let handles = LateHandles::new();
    ScriptServices {
        store: handles.clone(),
        client: handles.clone(),
        browser: Some(handles.clone()),
        guard: handles.clone(),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// The command groups (first name segments) and every command name the
/// binary registers for `features` with a default config: an EMPTY Rhai tier
/// (`RhaiConfig::default()` declares no script and the bundled catalogue is
/// never applied, so no `check.*`/`l4.*` script commands) plus the
/// `FindingsPlugin`, through `assemble_with_scripts` exactly as `main` wires
/// it (bare `assemble` would miss `script.*` and `findings.*`). The CA is
/// minted in a throwaway [`temp_ca_dir`] that is removed before returning.
/// Builds its own current-thread runtime for the tier's `Handle`, so call it
/// from a plain `#[test]`, not from inside another runtime. Shared by
/// `tests/synopsis_groups.rs` and `tests/synopsis_groups_l4.rs` (quality Q19).
pub fn built_in_groups(features: &Features) -> (BTreeSet<String>, Vec<String>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the script tier");
    let dir = temp_ca_dir("built-in-groups");
    let mut cfg = Config::default();
    cfg.ca.dir = dir.clone();

    let result = rt.block_on(async {
        let tier = build_with_languages(RhaiConfig::default(), startup_services(), &[])
            .expect("the empty rhai tier builds");
        assert!(
            tier.errors.is_empty(),
            "empty tier errors: {:?}",
            tier.errors
        );
        let assembled = assemble_with_scripts(
            &cfg,
            features,
            ScriptWiring {
                plugins: vec![
                    Box::new(tier.host.with_max_body(cfg.limits.max_body_bytes)) as Box<dyn Plugin>
                ],
                executor: Some(tier.executor.clone()),
                poc_step_handlers: PocStepRegistry::new(),
                commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
            },
        )
        .expect("the proxy assembles in a temp CA dir");

        let registry = assembled.proxy.registry_arc();
        let names: Vec<String> = registry.commands().map(|c| c.name().to_string()).collect();
        let groups: BTreeSet<String> = names
            .iter()
            .filter_map(|name| name.split('.').next().map(str::to_string))
            .collect();
        drop(assembled);
        (groups, names)
    });
    let _ = std::fs::remove_dir_all(&dir);
    result
}
