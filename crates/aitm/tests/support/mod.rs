//! Shared helpers for the `aitm` integration tests that assemble a proxy from
//! a `Config` with a throwaway CA directory, and the service handles `main`
//! shares between the frontends (what `aitm tui` hands to `tui::build_servers`).
//!
//! Boundary (quality Q19): `support` is proxy assembly, CA directories and
//! service helpers; the textual source scans of the tree live in `common/mod.rs`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::describe;
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

/// Every command the binary registers for `features` with a default config and
/// the given Rhai config, through `assemble_with_scripts` exactly as `main`
/// wires it (the tier's host plugin, its executor, an empty PoC step registry,
/// its commands, then the `FindingsPlugin`), as `(name, describe::fingerprint)`
/// pairs in registration order. The live side of the `describe_registry` pins
/// (plan C28), generic over the Rhai config so the bundled catalogue can be
/// appended by the caller. The CA is minted in a
/// throwaway [`temp_ca_dir`] that is removed before returning; the function
/// builds its own current-thread runtime for the tier's `Handle`, so call it
/// from a plain `#[test]`, never from inside another runtime.
pub fn live_commands(features: &Features, rhai: RhaiConfig) -> Vec<(String, String)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime for the script tier");
    let dir = temp_ca_dir("live-commands");
    let mut cfg = Config::default();
    cfg.ca.dir = dir.clone();

    let result = rt.block_on(async {
        let tier =
            build_with_languages(rhai, startup_services(), &[]).expect("the rhai tier builds");
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
        let pairs: Vec<(String, String)> = registry
            .commands()
            .map(|cmd| (cmd.name().to_string(), describe::fingerprint(&cmd.schema())))
            .collect();
        drop(assembled);
        pairs
    });
    let _ = std::fs::remove_dir_all(&dir);
    result
}
