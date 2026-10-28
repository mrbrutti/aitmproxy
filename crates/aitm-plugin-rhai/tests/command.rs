//! Task 10 — script-registered commands and options: a script's `load(reg)`
//! installs a real `aitm_core::Command` (one `args` object param, `Any`
//! result) and records option defaults (AC-M3-3, Registry level).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, StdGuard,
    TypeDesc, Value,
};
use aitm_plugin_rhai::command::{register_reg_api, ScriptRegHandle};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use rhai::{Engine, AST};

/// A client that is never reached: a script command runs no network verb here.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A hardened engine with the `load(reg)` bridge registered.
fn engine_with_reg_api() -> Arc<Engine> {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_reg_api(&mut engine);
    Arc::new(engine)
}

/// Compile `src` as the script named `name` (what the loader does).
fn compile_named(engine: &Engine, name: &str, src: &str) -> Arc<AST> {
    let mut ast = engine.compile(src).expect("script compiles");
    ast.set_source(name);
    Arc::new(ast)
}

/// Run the script's `load(reg)` against `registry`; returns the options it
/// declared.
fn load_into(
    registry: &mut Registry,
    engine: &Arc<Engine>,
    ast: &Arc<AST>,
) -> aitm_plugin_rhai::host_core::Options {
    let mut handle = ScriptRegHandle::new(registry);
    handle
        .run_load(engine, ast)
        .expect("the script's load(reg) must run");
    handle.into_options()
}

#[tokio::test(flavor = "multi_thread")]
async fn script_command_registers_and_invokes() {
    let engine = engine_with_reg_api();
    let ast = compile_named(
        &engine,
        "demo",
        r#"fn load(reg) { reg.add_command("demo.ping", "", |args| "pong"); }"#,
    );
    let mut registry = Registry::new();
    load_into(&mut registry, &engine, &ast);

    let cmd = registry
        .command("demo.ping")
        .expect("demo.ping is registered as a native command");
    assert_eq!(cmd.name(), "demo.ping");

    // One `args` object param, `Any` result (spec §9).
    let schema = cmd.schema();
    assert_eq!(schema.params.len(), 1, "schema: {schema:?}");
    assert_eq!(schema.params[0].name, "args");
    assert!(
        !schema.params[0].required,
        "args is optional so a bare call works"
    );
    assert!(
        matches!(schema.params[0].ty, TypeDesc::Map(ref inner) if matches!(**inner, TypeDesc::Any)),
        "args is a free-form object: {:?}",
        schema.params[0].ty
    );
    assert!(
        matches!(schema.result, TypeDesc::Any),
        "{:?}",
        schema.result
    );

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    let out = cmd
        .invoke(Params::default(), &host)
        .expect("demo.ping invokes");
    assert_eq!(out, Value::Str("pong".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn script_command_receives_args_object() {
    let engine = engine_with_reg_api();
    let ast = compile_named(
        &engine,
        "demo",
        r#"fn load(reg) { reg.add_command("demo.echo", "echo who", |args| `hi ${args.who}`); }"#,
    );
    let mut registry = Registry::new();
    load_into(&mut registry, &engine, &ast);

    let cmd = registry.command("demo.echo").expect("demo.echo registered");
    assert_eq!(cmd.schema().description, "echo who");

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);

    // The frontends hand the object under `args`; the script sees it as a map.
    let params = Params::new(BTreeMap::from([(
        "args".to_string(),
        Value::Object(BTreeMap::from([(
            "who".to_string(),
            Value::Str("matt".into()),
        )])),
    )]));
    let out = cmd.invoke(params, &host).expect("demo.echo invokes");
    assert_eq!(out, Value::Str("hi matt".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn script_option_registered() {
    let engine = engine_with_reg_api();
    let ast = compile_named(
        &engine,
        "tagger",
        r#"fn load(reg) { reg.add_option("tag", "v", "value for the X-Aitm header"); }"#,
    );
    let mut registry = Registry::new();
    let options = load_into(&mut registry, &engine, &ast);

    assert_eq!(options.get("tag"), Some(&Value::Str("v".into())));
    assert_eq!(
        registry.option("tag"),
        Some(Value::Str("v".into())),
        "the default also reaches the platform option store"
    );
    assert!(registry.command("tag").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn script_without_load_registers_nothing() {
    let engine = engine_with_reg_api();
    let ast = compile_named(&engine, "quiet", r#"fn on_request(flow) { }"#);
    let mut registry = Registry::new();
    let options = load_into(&mut registry, &engine, &ast);

    assert_eq!(registry.commands().count(), 0);
    assert_eq!(options, aitm_plugin_rhai::host_core::Options::default());
}
