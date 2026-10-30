//! Task 10 — script-registered commands and options: a script's `load(reg)`
//! installs a real `aitm_core::Command` (one `args` object param, `Any`
//! result) and records option defaults (AC-M3-3, Registry level).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use std::sync::{Mutex, PoisonError};

use aitm_core::{
    CallerTrust, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, TypeDesc, Value,
};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, NamespaceCatalog, PocStepHandler,
    ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::command::{register_reg_api, ScriptRegHandle};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{build_engine, build_engine_with_languages};
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

/// Security + quality review (M3, Important): `load(reg)` runs on the thread
/// that is driving `main`'s future, inside the runtime. A guarded async verb
/// there used to panic ("Cannot start a runtime from within a runtime") and
/// take the proxy down at startup; `load` now crosses the same bridge every
/// other entry point does. This test body runs exactly where `Proxy::build`
/// does: on the runtime's `block_on` thread.
#[tokio::test(flavor = "multi_thread")]
async fn load_may_call_guarded_verbs() {
    use aitm_core::{FlowStore, ScopeEntry, ScopeRateGuard};
    use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
    use aitm_plugin_rhai::host_net::HttpCapability;

    let guard = Arc::new(StdGuard::default());
    guard.add_scope(ScopeEntry {
        host: "ok.test".to_string(),
    });
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let services = ScriptServices {
        store,
        client: Arc::new(PongClient),
        browser: None,
        guard,
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_reg_api(&mut engine);
    HttpCapability.register(&mut engine, &services);
    let engine = Arc::new(engine);

    let ast = compile_named(
        &engine,
        "warm",
        r#"
        fn load(reg) {
            let r = http.send(#{ url: "http://ok.test/health" });
            reg.add_command("warm.status", "status seen at load", |args| r.status);
        }
        "#,
    );
    let mut registry = Registry::new();
    load_into(&mut registry, &engine, &ast);

    let cmd = registry
        .command("warm.status")
        .expect("load ran to completion and registered its command");
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    assert_eq!(
        cmd.invoke(Params::default(), &host).expect("invokes"),
        Value::Int(200)
    );
}

/// A client that answers `200` with an empty body.
struct PongClient;

impl ProxyClient for PongClient {
    fn send(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        use aitm_core::{Body, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpResponse, HttpVersion};
        Box::pin(async move {
            Ok(HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    body: Body::Empty,
                    timestamp: std::time::SystemTime::now(),
                }),
                client_conn: ConnInfo {
                    peer: "127.0.0.1:0".parse().expect("addr"),
                    sni: None,
                    alpn: None,
                    tls: false,
                    established: std::time::SystemTime::now(),
                },
                server_conn: None,
                metadata: FlowMeta::default(),
                intercept: aitm_core::InterceptState::Observed,
            })
        })
    }
}

/// Quality review (M3, Minor): config-supplied options are readable inside
/// `load(reg)` too, not only in hooks and commands.
#[tokio::test(flavor = "multi_thread")]
async fn option_is_readable_inside_load() {
    use aitm_plugin_rhai::host_core::{LogCapability, Options, ScriptCapability, ScriptServices};

    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_reg_api(&mut engine);
    let services = ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(aitm_plugin_rhai::host_core::MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    LogCapability.register(&mut engine, &services);
    let engine = Arc::new(engine);
    let ast = compile_named(
        &engine,
        "named",
        r#"fn load(reg) { reg.add_command(option("command"), "", |args| "pong"); }"#,
    );

    let mut registry = Registry::new();
    let mut handle = ScriptRegHandle::new(&mut registry).with_options(Options::new(
        BTreeMap::from([("command".to_string(), Value::Str("named.ping".into()))]),
    ));
    handle.run_load(&engine, &ast).expect("load runs");
    assert!(
        registry.command("named.ping").is_some(),
        "load read the configured option"
    );
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

// ===========================================================================
// Task 3 — the script-command invocation boundary seeds the caller trust from
// the invoking `CommandHost` frontend before the script function (which can
// reach a seam host fn) evaluates (spec AC3 command boundary).
// ===========================================================================

/// A seam language whose `probe.note()` records the live `ctx.caller()`.
struct CapturingLanguage {
    seen: Arc<Mutex<Vec<CallerTrust>>>,
}

struct AdmitGuard;

impl GuardHandle for AdmitGuard {
    fn guard_name(&self) -> &str {
        "probe"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

impl ProtocolLanguage for CapturingLanguage {
    fn namespace(&self) -> &str {
        "probe"
    }
    fn api_version(&self) -> &str {
        "1"
    }
    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        let seen = Arc::clone(&self.seen);
        let note: HostFn = Box::new(move |ctx: &HostCallCtx, _args: &[Value]| {
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(ctx.caller());
            Ok(Value::Null)
        });
        reg.register("probe", "note", Guarded::new(Box::new(AdmitGuard), note))
    }
    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        None
    }
    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: "probe".to_string(),
            api_version: "1".to_string(),
            host_fns: vec![],
            poc_step: None,
            sources: vec![],
        }
    }
}

/// AC3 (command boundary): a script-registered command invoked by a given
/// frontend seeds that frontend's trust for the command's eval, so the seam fn
/// the command body calls observes `Agent` for an MCP agent and `Operator` for
/// the human CLI — never refused "no caller context", never a silent operator
/// default.
#[tokio::test(flavor = "multi_thread")]
async fn script_command_seeds_frontend_caller_trust() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let lang = CapturingLanguage {
        seen: Arc::clone(&seen),
    };
    let mut engine =
        build_engine_with_languages(&RhaiLimits::default(), Duration::from_secs(2), &[&lang])
            .expect("the capturing seam language installs");
    register_reg_api(&mut engine);
    let engine = Arc::new(engine);

    let ast = compile_named(
        &engine,
        "demo",
        r#"fn load(reg) { reg.add_command("demo.probe", "", |args| { probe.note(); "ok" }); }"#,
    );
    let mut registry = Registry::new();
    load_into(&mut registry, &engine, &ast);
    let cmd = registry
        .command("demo.probe")
        .expect("demo.probe is registered");

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();

    // An agent (MCP) frontend: the command eval is seeded Agent.
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Mcp);
    assert_eq!(
        cmd.invoke(Params::default(), &host).expect("invokes"),
        Value::Str("ok".into()),
        "the command ran (seeded), not refused for a missing caller context"
    );
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Agent]
    );

    // A human CLI frontend: the same command, now seeded Operator.
    seen.lock().unwrap_or_else(PoisonError::into_inner).clear();
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);
    cmd.invoke(Params::default(), &host).expect("invokes");
    assert_eq!(
        *seen.lock().unwrap_or_else(PoisonError::into_inner),
        vec![CallerTrust::Operator]
    );
}
