//! Task 15 — the convergence seam inside the crate.
//!
//! Earlier tasks built the parts and left the joins: the loader did not
//! register the `reg` bridge (Task 10) or the PoC `vars` handle (Task 14),
//! and `ScriptPlugin::load` was a stub, so a script's `load(reg)` never ran
//! and its commands never reached the platform `Registry`. These tests pin
//! the joined surface:
//!
//! - a script's `load(reg)` runs when the plugin is registered, so its command
//!   and option are in the registry the frontends read (AC-M3-3, Registry level);
//! - `wire::load_scripts` keeps declaration order and reports what did not
//!   compile without losing the rest (AC-M3-9, ordering half of AC-M3-10);
//! - a PoC step run on the *loader's* engine reaches `vars` and the bundled
//!   prelude, which only holds if the loader registered both (AC-M3-8).

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, Plugin, ProxyClient, Registry,
    StdGuard, Value,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::wire;
use aitm_poc::{ScriptStep, ScriptStepCtx, ScriptStepExecutor, ScriptVerdict, VarBindings};

const TAGGER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tagger.rhai");
const BROKEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/broken.rhai");

/// A client no test here reaches: nothing sends.
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

/// AC-M3-3 at the `Registry` level: registering the plugin runs the script's
/// `load(reg)`, so `tagger.ping` is a real command and `tag` a real option.
#[tokio::test(flavor = "multi_thread")]
async fn script_load_registers_its_command_and_option() {
    let tier = wire::build(config(vec![ScriptEntry::new(TAGGER)]), services())
        .expect("the scripting tier builds");
    assert_eq!(tier.plugins.len(), 1, "one script, one plugin");
    let plugin = tier.plugins.into_iter().next().expect("the one plugin");

    let mut registry = Registry::new();
    registry.add_plugin(Box::new(plugin));

    let cmd = registry
        .command("tagger.ping")
        .expect("the script's command is in the registry");
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    assert_eq!(
        cmd.invoke(Params::default(), &host)
            .expect("tagger.ping invokes"),
        Value::Str("pong".into()),
    );
    assert_eq!(
        registry.option("tag"),
        Some(Value::Str("seen-by-aitm".into())),
        "the declared default is the registry's option value",
    );
}

/// The load keeps the order the operator declared and loses nothing to one
/// bad file (AC-M3-9; the order half of AC-M3-10).
#[tokio::test(flavor = "multi_thread")]
async fn load_scripts_keeps_declaration_order_and_collects_errors() {
    let cfg = config(vec![
        ScriptEntry::new(BROKEN),
        ScriptEntry::new(TAGGER),
        ScriptEntry::new(BROKEN),
    ]);
    let (plugins, errors) = wire::load_scripts(cfg, services());

    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert_eq!(names, ["tagger"], "the one that compiled, in its place");
    assert_eq!(errors.len(), 2, "both broken entries are reported");
    assert!(
        errors[0].to_string().contains("broken"),
        "the error names the script: {}",
        errors[0]
    );
}

/// AC-M3-8's precondition: a PoC step runs on the *loader's* shared engine, so
/// `vars` (Task 14's capability) and the bundled prelude (Task 11) must both
/// have been registered when that engine was built.
#[tokio::test(flavor = "multi_thread")]
async fn poc_step_reaches_vars_and_prelude_on_the_loader_engine() {
    let tier = wire::build(config(vec![]), services()).expect("the scripting tier builds");

    let mut vars = VarBindings::new();
    vars.insert("marker", Value::Str("AbC".into()));
    let mut step_results = BTreeMap::new();
    let mut artifacts: Vec<PathBuf> = Vec::new();
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    let mut ctx = ScriptStepCtx {
        vars: &mut vars,
        host: &host,
        step_results: &mut step_results,
        artifacts: &mut artifacts,
    };

    // `contains_ci` is prelude sugar; `vars.get`/`vars.set` are VarsCapability.
    let step = ScriptStep {
        name: Some("probe".into()),
        script: r#"
            if contains_ci(vars.get("marker"), "abc") {
                vars.set("seen", "yes");
                return pass;
            }
            return fail;
        "#
        .into(),
    };

    let verdict = tier
        .executor
        .run_step(&step, &mut ctx)
        .expect("the step runs on the shared engine");

    assert_eq!(verdict, ScriptVerdict::Pass);
    assert_eq!(
        vars.get("seen"),
        Some(&Value::Str("yes".into())),
        "vars.set wrote back through the shared bindings",
    );
}
