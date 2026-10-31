//! The bundled catalogue must load the way `aitm` loads it at startup: the real
//! discovery (`aitm::bundled::apply`), `main`'s late-bound `ScriptServices`, the
//! shared hardened engine built by `wire::build_with_languages`, and every
//! script's `load(reg)` run over a fresh `Registry`. Any compile error or any
//! `load` failure fails the test, in both shapes the binary ships: a plain
//! config (no `l4` namespace, the default) and an L4-enabled one.
//!
//! The catalogue's own test in `aitm-plugin-rhai` compiles the scripts and runs
//! the passive hooks; it never ran `load(reg)`, which is where a closure that
//! captures a top-level constant, or an absent optional namespace, fails.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm::bundled::{self, BUNDLED_DIR};
use aitm::scripts::LateHandles;
use aitm_core::{Plugin, Registry};
use aitm_plugin::language::ProtocolLanguage;
use aitm_plugin_rhai::wire::{build_with_languages, ScriptTier};
use aitm_plugin_rhai::{MemoryFindingSink, RhaiConfig, ScriptServices};
use aitm_proto_l4::backend::pcap::PcapBackend;
use aitm_proto_l4::config::L4Config;
use aitm_proto_l4::flow::InMemoryL4FlowStore;
use aitm_proto_l4::guard::L4Guard;
use aitm_proto_l4::L4Language;

/// Every command the `active/` and `l4/` scripts register in `load(reg)`. A
/// script whose `load` fails installs nothing, so a missing name here is the
/// operator-visible symptom.
const EXPECTED_COMMANDS: &[&str] = &[
    "check.cmdi",
    "check.cors",
    "check.crlf",
    "check.headers",
    "check.ldapi",
    "check.methods",
    "check.nosqli",
    "check.open_redirect",
    "check.path_traversal",
    "check.paths",
    "check.sqli",
    "check.ssrf",
    "check.ssti",
    "check.xss",
    "check.xxe",
    "l4.recon",
    "l4.tcp_probe",
    "l4.udp_probe",
];

fn catalogue_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
}

fn rhai_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("catalogue dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rhai_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rhai") {
            out.push(path);
        }
    }
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

/// `main.rs`'s config path, pointed at the repo catalogue through the same
/// environment override the binary honours.
fn startup_config() -> RhaiConfig {
    let dir = catalogue_dir();
    let mut cfg = RhaiConfig::default();
    bundled::apply(&mut cfg, |key| {
        (key == BUNDLED_DIR).then(|| dir.to_string_lossy().into_owned())
    });
    cfg
}

/// Build the tier as `main` does and run every script's `load(reg)` as
/// `Proxy::build` does. Returns the tier, the registry it filled, and each
/// script's recorded error.
fn load_like_startup(languages: &[&dyn ProtocolLanguage]) -> (ScriptTier, Registry, Vec<String>) {
    let mut tier =
        build_with_languages(startup_config(), startup_services(), languages).expect("tier builds");
    let mut registry = Registry::new();
    tier.host.load(&mut registry);
    let failures: Vec<String> = tier
        .host
        .set()
        .names()
        .into_iter()
        .filter_map(|name| {
            tier.error_sink
                .last_error(&name)
                .map(|err| format!("{name}: {err}"))
        })
        .collect();
    (tier, registry, failures)
}

fn assert_catalogue_loaded(tier: &ScriptTier, registry: &Registry, failures: &[String]) {
    let mut files = Vec::new();
    rhai_files(&catalogue_dir(), &mut files);
    assert!(
        tier.errors.is_empty(),
        "bundled scripts failed to compile:\n{}",
        tier.errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        tier.host.set().names().len(),
        files.len(),
        "every .rhai under scripts/bundled must be loaded"
    );
    assert!(
        failures.is_empty(),
        "bundled scripts failed at load(reg):\n{}",
        failures.join("\n")
    );
    let registered: BTreeSet<&str> = registry.commands().map(|c| c.name()).collect();
    let missing: Vec<&str> = EXPECTED_COMMANDS
        .iter()
        .copied()
        .filter(|name| !registered.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "commands the catalogue should register are missing: {missing:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bundled_script_loads_like_startup_l4_off() {
    let (tier, registry, failures) = load_like_startup(&[]);
    assert_catalogue_loaded(&tier, &registry, &failures);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bundled_script_loads_like_startup_l4_on() {
    let l4 = L4Config {
        enabled: true,
        ..L4Config::default()
    };
    let language = L4Language::new(
        Arc::new(L4Guard::new(&l4)),
        Arc::new(PcapBackend::new()),
        Arc::new(InMemoryL4FlowStore::new()),
    );
    let (tier, registry, failures) = load_like_startup(&[&language]);
    assert_catalogue_loaded(&tier, &registry, &failures);
}
