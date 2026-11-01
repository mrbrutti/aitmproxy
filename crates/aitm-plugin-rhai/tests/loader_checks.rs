//! Stage-6 fix (wave-2/3 spec review, Important): the production wiring from a
//! configured script file to the scanner's catalogue —
//! `RhaiLoader::load_all` → `LoadedScript::with_checks(loader.checks(),
//! check_origin(path))` → `ScriptHost::load` (the `Plugin::load` the registry
//! calls at startup) → `loader.checks()` — and plan call B17's `check_origin`.
//!
//! Every bridge test (`tests/check_bridge*.rs`) hands the bridge its own
//! `Arc<CheckRegistry>`; nothing exercised the loader's. These tests pass no
//! registry at all and read the one the loader owns, the way the scanner does.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, Plugin, ProxyClient, Registry, StdGuard};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_plugin_rhai::plugin::{ScriptHost, ScriptSet};
use aitm_plugin_rhai::wire;
use aitm_scan_model::vocab::CheckOrigin;

/// A client no script here reaches.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

fn config(scripts: Vec<ScriptEntry>) -> RhaiConfig {
    RhaiConfig {
        scripts,
        limits: RhaiLimits::default(),
        hook_timeout: Duration::from_secs(5),
        ..RhaiConfig::default()
    }
}

/// A throwaway scripts directory outside the repo, named after the test so
/// parallel tests never share one; removed on drop.
struct TempScripts(PathBuf);

impl TempScripts {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("aitm-loader-checks-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bundled")).expect("the temp scripts dir is created");
        Self(dir)
    }

    /// Write (or overwrite) `relative` under the directory and give its path.
    fn write(&self, relative: &str, src: &str) -> PathBuf {
        let path = self.0.join(relative);
        fs::write(&path, src).expect("the script is written");
        path
    }
}

impl Drop for TempScripts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A script named `name` whose `load(reg)` registers one check with id `id`,
/// the meta `tests/check_bridge.rs::meta_src` declares.
fn check_src(name: &str, id: &str) -> String {
    format!(
        r#"const NAME = "{name}";
fn load(reg) {{
    reg.add_check(#{{ id: "{id}", name: "Demo", class: "demo", lanes: ["http"],
                     kinds: ["query"], intensity: "light", cost: "light",
                     technique: "reflected", severity: "low", confidence_max: "certain",
                     description: "d" }}, |point| "nothing");
}}
"#
    )
}

/// The check ids in `loader`-style catalogue order (sorted by id).
fn ids(checks: &aitm_scan_model::registry::CheckRegistry) -> Vec<String> {
    checks
        .snapshot()
        .iter()
        .map(|c| c.meta().id.clone())
        .collect()
}

fn ends_with(path: &str, suffix: &str) -> bool {
    Path::new(path).ends_with(suffix)
}

/// `load_all` compiles each script with the loader's own catalogue and the
/// origin its path implies; registering the host (`Plugin::load`) runs every
/// `load(reg)`, and the checks land in `loader.checks()` tagged `bundled` for a
/// file under a `bundled/` directory and `custom` otherwise (B17). Loading one
/// script again — what a reload is — swaps exactly that script's entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_all_fills_the_loaders_catalogue_with_each_scripts_origin() {
    let dir = TempScripts::new("origin");
    let bundled = dir.write(
        "bundled/demo.rhai",
        &check_src("demo", "bundled-demo-check"),
    );
    let custom = dir.write(
        "custom-demo.rhai",
        &check_src("custom-demo", "custom-demo-check"),
    );
    let loader = RhaiLoader::new(
        config(vec![ScriptEntry::new(&bundled), ScriptEntry::new(&custom)]),
        services(),
    )
    .expect("the loader builds");

    let (scripts, errors) = loader.load_all();
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(scripts.len(), 2, "both scripts compile");
    assert!(
        loader.checks().is_empty(),
        "compiling registers nothing; `load(reg)` does"
    );

    let mut registry = Registry::new();
    let mut host = ScriptHost::new(ScriptSet::new(scripts));
    host.load(&mut registry);

    let catalogue = loader.checks();
    assert_eq!(catalogue.snapshot().len(), 2);
    assert_eq!(
        ids(&catalogue),
        vec![
            "bundled-demo-check".to_string(),
            "custom-demo-check".to_string()
        ]
    );
    let snapshot = catalogue.snapshot();
    match &snapshot[0].meta().origin {
        CheckOrigin::Bundled { path } => {
            assert_eq!(path, &bundled.display().to_string());
            assert!(ends_with(path, "bundled/demo.rhai"), "{path}");
        }
        other => panic!("a script under bundled/ must be Bundled, got {other:?}"),
    }
    match &snapshot[1].meta().origin {
        CheckOrigin::Custom { path } => {
            assert_eq!(path, &custom.display().to_string());
            assert!(ends_with(path, "custom-demo.rhai"), "{path}");
        }
        other => panic!("an operator's script must be Custom, got {other:?}"),
    }
    let bundled_check = Arc::clone(&snapshot[0]);

    // Reload: the file changes its check id; the loader compiles it again
    // against the same catalogue under the same origin, and its `load(reg)`
    // replaces only what this script registered before.
    dir.write(
        "custom-demo.rhai",
        &check_src("custom-demo", "custom-demo-check-v2"),
    );
    let reloaded = loader
        .load_one(&ScriptEntry::new(&custom))
        .expect("the rewritten script compiles");
    let mut registry = Registry::new();
    ScriptHost::new(ScriptSet::new(vec![reloaded])).load(&mut registry);

    assert_eq!(
        ids(&catalogue),
        vec![
            "bundled-demo-check".to_string(),
            "custom-demo-check-v2".to_string()
        ],
        "only the reloaded script's entry changed"
    );
    assert!(
        Arc::ptr_eq(&catalogue.snapshot()[0], &bundled_check),
        "the other script's check is the very same entry, untouched"
    );
    match &catalogue.snapshot()[1].meta().origin {
        CheckOrigin::Custom { path } => assert_eq!(path, &custom.display().to_string()),
        other => panic!("the reloaded script keeps its Custom origin, got {other:?}"),
    }
}

/// `wire::build` (what `main.rs` calls) hands the scanner `tier.checks`; it
/// must be the loader's catalogue, so the checks the tier's scripts register
/// when the host is added to the registry appear in it with no other wiring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wire_build_exposes_the_loaders_catalogue_as_tier_checks() {
    let dir = TempScripts::new("wire");
    let bundled = dir.write(
        "bundled/demo.rhai",
        &check_src("demo", "wired-bundled-check"),
    );
    let custom = dir.write(
        "custom-demo.rhai",
        &check_src("custom-demo", "wired-custom-check"),
    );
    let tier = wire::build(
        config(vec![ScriptEntry::new(&bundled), ScriptEntry::new(&custom)]),
        services(),
    )
    .expect("the scripting tier builds");
    assert!(tier.errors.is_empty(), "{:?}", tier.errors);
    let checks = Arc::clone(&tier.checks);
    assert!(checks.is_empty(), "nothing is registered before load");

    let mut registry = Registry::new();
    registry.add_plugin(Box::new(tier.host));

    assert_eq!(
        ids(&checks),
        vec![
            "wired-bundled-check".to_string(),
            "wired-custom-check".to_string()
        ],
        "the scripts' checks landed in the handle the tier hands the scanner"
    );
    let origins: Vec<bool> = checks
        .snapshot()
        .iter()
        .map(|c| matches!(c.meta().origin, CheckOrigin::Bundled { .. }))
        .collect();
    assert_eq!(origins, vec![true, false]);
}
