//! The static `aitm --help` synopsis names the built-in command groups (spec
//! D8, AC-W1-2; plan C19). The registry cannot be built without minting a CA,
//! so `--help` prints a constant; this pin keeps the constant honest against
//! the binary's own assembly: an EMPTY Rhai tier (no bundled catalogue, so no
//! `check.*`/`l4.*` script commands; `l4.enabled` off) plus the
//! `FindingsPlugin`, through `assemble_with_scripts` exactly as `main` wires
//! it. Bare `build_proxy_with` would miss `script.*` and `findings.*`.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::scripts::LateHandles;
use aitm::startup::GROUPS;
use aitm::wire::{assemble_with_scripts, Features, ScriptWiring};
use aitm_core::{Config, Plugin};
use aitm_findings::FindingsPlugin;
use aitm_plugin_rhai::wire::build_with_languages;
use aitm_plugin_rhai::{MemoryFindingSink, RhaiConfig, ScriptServices};
use aitm_poc::step_registry::PocStepRegistry;

/// A unique temp directory for the test's CA material.
fn temp_ca_dir() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-synopsis-groups-{nanos}-{n}"))
}

/// `main.rs`'s services: late-bound handles the proxy fills in once built.
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

#[tokio::test]
async fn synopsis_groups_match_the_built_in_registry() {
    let dir = temp_ca_dir();
    let mut cfg = Config::default();
    cfg.ca.dir = dir.clone();

    // The empty tier: `RhaiConfig::default()` declares no script and the bundled
    // catalogue is never applied, so only the tier's own `script.*` commands reach
    // the registry.
    let tier = build_with_languages(RhaiConfig::default(), startup_services(), &[])
        .expect("the empty rhai tier builds");
    assert!(
        tier.errors.is_empty(),
        "empty tier errors: {:?}",
        tier.errors
    );

    let assembled = assemble_with_scripts(
        &cfg,
        &Features::default(),
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
    let groups: BTreeSet<String> = registry
        .commands()
        .filter_map(|c| c.name().split('.').next().map(str::to_string))
        .collect();
    let names: Vec<String> = registry.commands().map(|c| c.name().to_string()).collect();
    drop(assembled);
    let _ = std::fs::remove_dir_all(&dir);

    let expected: BTreeSet<String> = GROUPS.iter().map(|g| g.to_string()).collect();
    assert_eq!(expected.len(), 17, "GROUPS must name 17 groups");
    assert_eq!(
        groups, expected,
        "the synopsis Groups block drifted from the built-in registry; registry names: {names:?}"
    );
    for absent in ["check", "l4", "demo", "egress"] {
        assert!(
            !groups.contains(absent),
            "`{absent}` is not a built-in group (catalogue or test-only); registry names: {names:?}"
        );
    }
}
