//! Stage-6 fix (T1b review log row 13, Important): `script.reload` must re-run
//! the reloaded script's `load(reg)` against the live check catalogue, so the
//! checks it declares with `reg.add_check` are swapped with its hooks — the
//! loader/plugin doc comments and plan call B9 ("a `script.reload` swaps
//! exactly that script's checks") promise it, and `tests/loader_checks.rs`
//! pins only the loader-driven swap, never the command.
//!
//! Every test here drives the real `script.reload` command through a
//! `Registry`, exactly as a frontend does, and reads the catalogue back the
//! way the scanner does: through `ScriptTier::checks`.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{
    CommandHost, FlowId, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value,
};
use aitm_plugin_rhai::config::{RhaiConfig, ScriptEntry};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::wire;
use aitm_scan_model::registry::CheckRegistry;

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A per-test temp dir of `.rhai` files, removed on drop.
struct TempScripts(PathBuf);

impl TempScripts {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aitm-rhai-reload-checks-{}-{}",
            std::process::id(),
            FlowId::new()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    /// Write (or overwrite) `<name>.rhai` and give its path.
    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(format!("{name}.rhai"));
        std::fs::write(&path, body).expect("write script");
        path
    }
}

impl Drop for TempScripts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The tier over `scripts`, its host and command plugin registered in a real
/// `Registry` (so every `load(reg)` ran), plus the catalogue the tier hands
/// the scanner.
struct Harness {
    store: Arc<MemFlowStore>,
    registry: Registry,
    checks: Arc<CheckRegistry>,
}

impl Harness {
    fn new(scripts: Vec<ScriptEntry>) -> Self {
        let store = Arc::new(MemFlowStore::new());
        let services = ScriptServices {
            store: store.clone(),
            client: Arc::new(StubClient),
            browser: None,
            guard: Arc::new(StdGuard::default()),
            findings: Arc::new(MemoryFindingSink::new()),
            rt: tokio::runtime::Handle::current(),
        };
        let cfg = RhaiConfig {
            scripts,
            ..RhaiConfig::default()
        };
        let tier = wire::build(cfg, services).expect("tier builds");
        assert!(tier.errors.is_empty(), "scripts compile: {:?}", tier.errors);
        let checks = Arc::clone(&tier.checks);
        let mut registry = Registry::new();
        registry.add_plugin(Box::new(tier.host));
        registry.add_plugin(Box::new(tier.commands));
        Self {
            store,
            registry,
            checks,
        }
    }

    /// `script.reload { name }` as the human CLI invokes it.
    fn reload(&self, name: &str) -> anyhow::Result<Value> {
        let cmd = self
            .registry
            .command("script.reload")
            .expect("script.reload is registered");
        let client = StubClient;
        let guard = StdGuard::default();
        let host = CommandHost::new(self.store.as_ref(), &client, &guard, None)
            .with_frontend(Frontend::Cli);
        let params = Params::new(BTreeMap::from([(
            "name".to_string(),
            Value::Str(name.to_string()),
        )]));
        cmd.invoke(params, &host)
    }

    /// The catalogue's check ids, in `snapshot()` (sorted) order.
    fn ids(&self) -> Vec<String> {
        self.checks
            .snapshot()
            .iter()
            .map(|c| c.meta().id.clone())
            .collect()
    }
}

/// A script named `script` whose `load(reg)` declares one check `id` named
/// `name`.
fn check_src(script: &str, id: &str, name: &str) -> String {
    format!(
        r#"const NAME = "{script}";
fn load(reg) {{
    reg.add_check(#{{ id: "{id}", name: "{name}", class: "demo", lanes: ["http"],
                     kinds: ["query"], intensity: "light", cost: "light",
                     technique: "reflected", severity: "low", confidence_max: "certain",
                     description: "d" }}, |point| "nothing");
}}
fn on_request(flow) {{ }}
"#
    )
}

/// `script.reload` re-runs the script's `load(reg)`: the catalogue holds
/// exactly the reloaded file's checks (`r2`, with its `scan.checks`-facing
/// meta), `r1` is gone, and another script's check is the very same entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_reload_swaps_exactly_that_scripts_checks() {
    let dir = TempScripts::new();
    let target = dir.write("target", &check_src("target", "r1", "Round one"));
    let other = dir.write("other", &check_src("other", "o1", "Other"));
    let h = Harness::new(vec![ScriptEntry::new(&target), ScriptEntry::new(&other)]);
    assert_eq!(h.ids(), vec!["o1".to_string(), "r1".to_string()]);
    let other_check = Arc::clone(&h.checks.snapshot()[0]);

    dir.write("target", &check_src("target", "r2", "Round two"));
    let out = h
        .reload("target")
        .expect("reload of a compiling script succeeds");
    match &out {
        Value::Object(fields) => assert_eq!(
            fields.get("name"),
            Some(&Value::Str("target".into())),
            "the reply names the reloaded script: {out:?}"
        ),
        other => panic!("the reply is an object, got {other:?}"),
    }

    assert_eq!(
        h.ids(),
        vec!["o1".to_string(), "r2".to_string()],
        "the reloaded script's checks are exactly the new file's"
    );
    let snapshot = h.checks.snapshot();
    let r2 = snapshot
        .iter()
        .find(|c| c.meta().id == "r2")
        .expect("r2 is in the catalogue the scanner reads");
    assert_eq!(r2.meta().name, "Round two");
    assert_eq!(r2.meta().class, "demo");
    assert!(
        Arc::ptr_eq(&snapshot[0], &other_check),
        "the other script's check is untouched"
    );
}

/// A reload whose new source does not compile is reported and changes
/// nothing: the previous checks stay registered beside the previous AST.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_reload_that_fails_to_compile_keeps_the_old_checks() {
    let dir = TempScripts::new();
    let target = dir.write("target", &check_src("target", "r1", "Round one"));
    let h = Harness::new(vec![ScriptEntry::new(&target)]);
    assert_eq!(h.ids(), vec!["r1".to_string()]);

    dir.write(
        "target",
        "const NAME = \"target\";\nfn load(reg) {\n  reg.add_check(#{ id: \"r2\" \n}\n",
    );
    let err = h
        .reload("target")
        .expect_err("a broken recompile is an error");
    assert!(
        err.to_string().contains("error: target:"),
        "the positioned compile error is reported: {err}"
    );
    assert_eq!(
        h.ids(),
        vec!["r1".to_string()],
        "the old checks stay in service with the old AST"
    );
}

/// A reload to a version with no `load(reg)` at all declares no checks, so the
/// catalogue drops what the script registered before — a check cannot outlive
/// the code that declared it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_reload_without_a_load_hook_drops_its_checks() {
    let dir = TempScripts::new();
    let target = dir.write("target", &check_src("target", "r1", "Round one"));
    let h = Harness::new(vec![ScriptEntry::new(&target)]);
    assert_eq!(h.ids(), vec!["r1".to_string()]);

    dir.write(
        "target",
        "const NAME = \"target\";\nfn on_request(flow) { }\n",
    );
    h.reload("target").expect("reload succeeds");
    assert_eq!(
        h.ids(),
        Vec::<String>::new(),
        "a script with no load(reg) provides no checks"
    );
}

/// A reload whose `load(reg)` throws swaps the hooks (they compiled) but
/// reports the load failure to the caller instead of answering as if the
/// checks were registered. The failed `load` installs nothing — the same
/// all-or-nothing effect model a throwing hook has — so the previous good
/// checks stay in service, exactly as the previous good AST does on a failed
/// recompile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_reload_whose_load_throws_reports_the_load_error() {
    let dir = TempScripts::new();
    let target = dir.write("target", &check_src("target", "r1", "Round one"));
    let h = Harness::new(vec![ScriptEntry::new(&target)]);
    assert_eq!(h.ids(), vec!["r1".to_string()]);

    dir.write(
        "target",
        "const NAME = \"target\";\nfn load(reg) { throw \"no checks today\"; }\n",
    );
    let err = h
        .reload("target")
        .expect_err("a reload whose load(reg) throws is an error");
    let text = err.to_string();
    assert!(text.contains("no checks today"), "{text}");
    assert!(
        text.contains("load"),
        "the error names the load hook: {text}"
    );
    assert_eq!(
        h.ids(),
        vec!["r1".to_string()],
        "a load that throws installs nothing; the previous checks stay"
    );
}
