//! Tester (whole-branch pass): the static `Groups:` list leaves `l4` out on
//! purpose (plan C19): the `L4Module`'s verbs register only when
//! `l4.enabled`, so the binary's own assembly with L4 switched on is exactly
//! `GROUPS` plus `l4`. This proves the exclusion is deliberate and that the
//! `synopsis_groups` pin is sensitive to the feature set it assembles with
//! (`Features::default()` there; `l4.enabled` here). Same empty Rhai tier,
//! same `FindingsPlugin`, same `assemble_with_scripts` as `main` and as
//! `tests/synopsis_groups.rs`.

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
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::L4Privilege;

fn temp_ca_dir() -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-synopsis-groups-l4-{nanos}-{n}"))
}

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
async fn l4_enabled_adds_exactly_the_l4_group_to_the_built_in_registry() {
    let dir = temp_ca_dir();
    let mut cfg = Config::default();
    cfg.ca.dir = dir.clone();

    let tier = build_with_languages(RhaiConfig::default(), startup_services(), &[])
        .expect("the empty rhai tier builds");
    assert!(tier.errors.is_empty(), "{:?}", tier.errors);

    // `l4.enabled` with the privilege pre-answered, so no startup probe
    // touches the host (the module registers either way; its wire-touching
    // verbs fail closed without privilege).
    let features = Features {
        l4: L4Config {
            enabled: true,
            ..L4Config::default()
        },
        l4_privilege: Some(L4Privilege::available()),
        ..Features::default()
    };
    let assembled = assemble_with_scripts(
        &cfg,
        &features,
        ScriptWiring {
            plugins: vec![
                Box::new(tier.host.with_max_body(cfg.limits.max_body_bytes)) as Box<dyn Plugin>
            ],
            executor: Some(tier.executor.clone()),
            poc_step_handlers: PocStepRegistry::new(),
            commands: vec![Box::new(tier.commands), Box::new(FindingsPlugin::new())],
        },
    )
    .expect("the proxy assembles with l4 enabled in a temp CA dir");

    let registry = assembled.proxy.registry_arc();
    let groups: BTreeSet<String> = registry
        .commands()
        .filter_map(|c| c.name().split('.').next().map(str::to_string))
        .collect();
    let l4_verbs: Vec<String> = registry
        .commands()
        .map(|c| c.name().to_string())
        .filter(|n| n.starts_with("l4."))
        .collect();
    drop(assembled);
    let _ = std::fs::remove_dir_all(&dir);

    let mut expected: BTreeSet<String> = GROUPS.iter().map(|g| g.to_string()).collect();
    assert!(
        !expected.contains("l4"),
        "the static synopsis must not list the conditional `l4` group (plan C19)"
    );
    expected.insert("l4".to_string());
    assert_eq!(
        groups, expected,
        "with l4.enabled the registry is GROUPS plus `l4` and nothing else; l4 verbs: {l4_verbs:?}"
    );
    assert!(
        !l4_verbs.is_empty(),
        "l4.enabled registers at least one `l4.*` verb"
    );
}
