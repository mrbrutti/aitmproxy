//! Spec §3/§8 (panel fix, M3): the three operator-facing commands the tier
//! ships — `script.validate`, `script.reload` and `script.findings` — as real
//! `aitm_core::Command`s registered by `ScriptCommands`, so MCP and the CLI
//! pick them up like any other. Each test drives the command through the
//! `Registry` exactly as a frontend does.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{
    CallerTrust, Chain, CommandHost, Event, Flow, FlowId, FlowStore, Frontend, HttpFlow,
    HttpRequest, MemFlowStore, Params, ProxyClient, Registry, Sensitivity, StdGuard, Value,
    Verdict,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::host_core::{FindingSink, MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::{wire, ScriptHandle};

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A `.rhai` file in a per-test temp dir, removed on drop.
struct TempScript(PathBuf);

impl TempScript {
    fn new(name: &str, body: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aitm-rhai-commands-{}-{}",
            std::process::id(),
            FlowId::new()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{name}.rhai"));
        std::fs::write(&path, body).expect("write script");
        Self(path)
    }

    fn rewrite(&self, body: &str) {
        std::fs::write(&self.0, body).expect("rewrite script");
    }

    fn path(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// The tier built over `scripts`, its command plugin registered after the
/// script plugins in a real `Registry`, and a chain over that registry.
struct Harness {
    store: Arc<MemFlowStore>,
    findings: Arc<MemoryFindingSink>,
    registry: Arc<Registry>,
    chain: Arc<Chain>,
    /// The live handles of the loaded scripts, in chain order.
    handles: Vec<Arc<ScriptHandle>>,
    /// The tier's error sink; bind it to the chain to make a failed hook's
    /// `Event::Error` actually dispatch back through the chain.
    error_sink: Arc<aitm_plugin_rhai::ErrorSink>,
}

impl Harness {
    fn new(scripts: Vec<ScriptEntry>) -> Self {
        Self::with_config(RhaiConfig {
            scripts,
            ..RhaiConfig::default()
        })
    }

    fn with_config(config: RhaiConfig) -> Self {
        let store = Arc::new(MemFlowStore::new());
        let findings = Arc::new(MemoryFindingSink::new());
        let services = ScriptServices {
            store: store.clone(),
            client: Arc::new(StubClient),
            browser: None,
            guard: Arc::new(StdGuard::default()),
            findings: findings.clone(),
            rt: tokio::runtime::Handle::current(),
        };
        let tier = wire::build(config, services).expect("tier builds");
        assert!(tier.errors.is_empty(), "scripts compile: {:?}", tier.errors);

        let error_sink = Arc::clone(&tier.error_sink);
        // The live handles come off the host's shared set, in chain order.
        let handles: Vec<Arc<ScriptHandle>> = tier.host.set().handles();
        let mut registry = Registry::new();
        // One host plugin dispatches every script from a single chain position.
        registry.add_plugin(Box::new(tier.host));
        registry.add_plugin(Box::new(tier.commands));
        let registry = Arc::new(registry);
        let chain = Arc::new(Chain::new(registry.clone(), store.clone()));
        Self {
            store,
            findings,
            registry,
            chain,
            handles,
            error_sink,
        }
    }

    /// Bind the chain into the tier's error sink, as the real wiring does, so
    /// failed hooks emit `Event::Error` back through the chain.
    fn bind_error_sink(&self) {
        self.error_sink.bind(self.chain.clone());
    }

    /// Drive a command as the human CLI (unconfined), the way most tests want.
    fn invoke(&self, name: &str, params: Params) -> anyhow::Result<Value> {
        self.invoke_as(Frontend::Cli, None, name, params)
    }

    /// Drive a command declaring a frontend and the configured PoC/scripts
    /// confinement root, as a real frontend host does.
    fn invoke_as(
        &self,
        frontend: Frontend,
        poc_dir: Option<PathBuf>,
        name: &str,
        params: Params,
    ) -> anyhow::Result<Value> {
        let cmd = self
            .registry
            .command(name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        let client = StubClient;
        let guard = StdGuard::default();
        let host = CommandHost::new(self.store.as_ref(), &client, &guard, None)
            .with_frontend(frontend)
            .with_poc_dir(poc_dir);
        cmd.invoke(params, &host)
    }

    /// Dispatch a request carrying `header: value` through the chain.
    async fn dispatch_with_header(&self, header: &str, value: &str) {
        let mut flow = request();
        if let Flow::Http(f) = &mut flow {
            f.request.headers.set(header, value);
        }
        let id = self.store.insert(flow);
        self.chain.dispatch(Event::Request(id)).await;
    }

    /// Dispatch a request through the chain and return the `X-V` header the
    /// script under test sets.
    async fn x_v(&self) -> Option<String> {
        let id = self.store.insert(request());
        assert_eq!(
            self.chain.dispatch(Event::Request(id)).await,
            Verdict::Continue
        );
        match self.store.get(id).expect("flow") {
            Flow::Http(f) => f.request.headers.get("X-V").map(str::to_string),
            Flow::WebSocket(_) => None,
        }
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn request() -> Flow {
    use aitm_core::{Body, ConnInfo, FlowMeta, HeaderMap, HttpVersion, InterceptState};
    use std::time::SystemTime;
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: "127.0.0.1:0".parse().expect("addr"),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn field<'a>(obj: &'a Value, key: &str) -> &'a Value {
    match obj {
        Value::Object(fields) => fields
            .get(key)
            .unwrap_or_else(|| panic!("field {key} in {obj:?}")),
        other => panic!("expected an object, got {other:?}"),
    }
}

const V1: &str = r#"
const NAME = "versioned";
fn on_request(flow) { flow.request.headers.set("X-V", "1"); }
"#;

const V2: &str = r#"
const NAME = "versioned";
fn on_request(flow) { flow.request.headers.set("X-V", "2"); }
fn on_response(flow) { }
"#;

const BROKEN: &str = "const NAME = \"versioned\";\nfn on_request(flow) {\n  flow.request.headers.set(\"X-V\", \"3\"\n}\n";

/// Spec §8 *Validation*: `script.validate { path }` compiles without
/// registering and reports the script's declared metadata; a file that does
/// not compile is the positioned compile error in the pinned format.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_reports_meta_or_the_compile_error() {
    let h = Harness::new(Vec::new());
    assert!(
        h.registry.command("script.validate").is_some()
            && h.registry.command("script.reload").is_some()
            && h.registry.command("script.findings").is_some(),
        "all three commands are registered"
    );

    let good = TempScript::new("good", V2);
    let out = h
        .invoke(
            "script.validate",
            params(&[("path", Value::Str(good.path().display().to_string()))]),
        )
        .expect("a compiling script validates");
    assert_eq!(field(&out, "name"), &Value::Str("versioned".into()));
    assert_eq!(field(&out, "api"), &Value::Str("1".into()));
    assert_eq!(
        field(&out, "hooks"),
        &Value::Array(vec![
            Value::Str("on_request".into()),
            Value::Str("on_response".into())
        ])
    );
    assert!(
        h.registry.plugins().len() == 2,
        "validate registered nothing (only the script host and the command plugin are present)"
    );

    let broken = TempScript::new("broken", BROKEN);
    let err = h
        .invoke(
            "script.validate",
            params(&[("path", Value::Str(broken.path().display().to_string()))]),
        )
        .expect_err("a broken script does not validate");
    let text = err.to_string();
    assert!(
        text.starts_with("error: broken:4:") || text.contains("error: broken:4:"),
        "the compile error is positioned in the pinned format: {text}"
    );

    // Only `.rhai` files are read: the command is not a general file probe.
    let err = h
        .invoke(
            "script.validate",
            params(&[("path", Value::Str("/etc/hosts".into()))]),
        )
        .expect_err("a non-.rhai path is refused");
    assert!(err.to_string().contains(".rhai"), "{err}");
}

const REGISTERING: &str = r#"
const NAME = "reg-demo";
fn load(reg) {
    reg.add_option("tag", "x", "a tag");
    reg.add_command("demo.ping", "ping", |args| "pong");
}
fn on_request(flow) { }
"#;

fn names(list: &[&str]) -> Value {
    Value::Array(list.iter().map(|s| Value::Str((*s).into())).collect())
}

fn registers_value(commands: &[&str], options: &[&str]) -> Value {
    Value::Object(BTreeMap::from([
        ("commands".to_string(), names(commands)),
        ("options".to_string(), names(options)),
    ]))
}

/// AC2/AC3: `script.validate { source }` compiles a string with nothing on
/// disk and answers `{ name, api, hooks, registers }` (no `path`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_source_reports_meta_and_registers() {
    let h = Harness::new(Vec::new());
    let out = h
        .invoke(
            "script.validate",
            params(&[("source", Value::Str(REGISTERING.into()))]),
        )
        .expect("a compiling source validates");
    assert_eq!(field(&out, "name"), &Value::Str("reg-demo".into()));
    assert_eq!(field(&out, "api"), &Value::Str("1".into()));
    assert_eq!(field(&out, "hooks"), &names(&["load", "on_request"]));
    assert_eq!(
        field(&out, "registers"),
        &registers_value(&["demo.ping"], &["tag"])
    );
    match &out {
        Value::Object(fields) => assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["api", "hooks", "name", "registers"],
            "no `path`: there is no file"
        ),
        other => panic!("expected an object, got {other:?}"),
    }
    assert_eq!(
        h.registry.plugins().len(),
        2,
        "validate registered nothing (the script host and the command plugin are present)"
    );

    let hook_only = h
        .invoke(
            "script.validate",
            params(&[("source", Value::Str(V1.into()))]),
        )
        .expect("a hook-only source validates");
    assert_eq!(field(&hook_only, "registers"), &registers_value(&[], &[]));
}

/// AC2: a syntax error in `source` is the positioned compile error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_source_syntax_error_is_positioned() {
    let h = Harness::new(Vec::new());
    let err = h
        .invoke(
            "script.validate",
            params(&[("source", Value::Str(BROKEN.into()))]),
        )
        .expect_err("a broken source does not validate");
    assert!(
        err.to_string().contains("error: script:4:"),
        "the compile error is positioned in the pinned format: {err}"
    );
}

/// The `{ path }` arm keeps its fields and gains `registers`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_path_arm_includes_registers() {
    let h = Harness::new(Vec::new());
    let script = TempScript::new("regs", REGISTERING);
    let out = h
        .invoke(
            "script.validate",
            params(&[("path", Value::Str(script.path().display().to_string()))]),
        )
        .expect("the file validates");
    assert_eq!(field(&out, "name"), &Value::Str("reg-demo".into()));
    assert_eq!(
        field(&out, "path"),
        &Value::Str(script.path().display().to_string())
    );
    assert_eq!(field(&out, "hooks"), &names(&["load", "on_request"]));
    assert_eq!(
        field(&out, "registers"),
        &registers_value(&["demo.ping"], &["tag"])
    );
}

/// Exactly one of `path`/`source`: both and neither are argument errors, never
/// a silent pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_requires_exactly_one_of_path_and_source() {
    let h = Harness::new(Vec::new());
    let script = TempScript::new("both", V1);
    let err = h
        .invoke(
            "script.validate",
            params(&[
                ("path", Value::Str(script.path().display().to_string())),
                ("source", Value::Str(V1.into())),
            ]),
        )
        .expect_err("both is refused");
    assert!(
        err.to_string()
            .contains("exactly one of `path` or `source`")
            && err.to_string().contains("both"),
        "{err}"
    );
    let err = h
        .invoke("script.validate", params(&[]))
        .expect_err("neither is refused");
    assert!(
        err.to_string()
            .contains("exactly one of `path` or `source`")
            && err.to_string().contains("neither"),
        "{err}"
    );
}

/// A `source` longer than the sandbox `max_string_size` is a clean argument
/// error before anything compiles; one at the limit still validates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_source_is_bounded_by_max_string_size() {
    let h = Harness::with_config(RhaiConfig {
        limits: RhaiLimits {
            max_string_size: 4096,
            ..RhaiLimits::default()
        },
        ..RhaiConfig::default()
    });
    let padding = |len: usize| format!("//{}\n", "x".repeat(len - 3));
    let at_limit = padding(4096);
    assert_eq!(at_limit.len(), 4096);
    h.invoke(
        "script.validate",
        params(&[("source", Value::Str(at_limit))]),
    )
    .expect("a source at the limit validates");

    let err = h
        .invoke(
            "script.validate",
            params(&[("source", Value::Str(padding(4097)))]),
        )
        .expect_err("a source over the limit is refused");
    assert!(
        err.to_string().contains("4097") && err.to_string().contains("max_string_size (4096)"),
        "{err}"
    );
}

/// Minor(a): `script.validate` is not a file oracle for an agent frontend. The
/// human CLI may compile any `.rhai` path; an agent may reach only a file
/// inside the configured scripts/PoC directory, and a path outside it — present
/// or not — gets the one generic refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_validate_confines_an_agent_frontend() {
    let inside = TempScript::new("inside", V1);
    let outside = TempScript::new("outside", V1);
    let root = inside.path().parent().expect("temp dir").to_path_buf();
    let h = Harness::new(Vec::new());
    let p = |path: &std::path::Path| params(&[("path", Value::Str(path.display().to_string()))]);

    // Human CLI: any path validates, confined or not.
    h.invoke_as(Frontend::Cli, None, "script.validate", p(outside.path()))
        .expect("the CLI validates an arbitrary path");

    // Agent confined to `root`: a file inside validates.
    h.invoke_as(
        Frontend::Mcp,
        Some(root.clone()),
        "script.validate",
        p(inside.path()),
    )
    .expect("an agent validates a script inside the confined dir");

    // Agent reaching a real file outside the root is refused.
    let err = h
        .invoke_as(
            Frontend::Mcp,
            Some(root.clone()),
            "script.validate",
            p(outside.path()),
        )
        .expect_err("an agent cannot read outside the confined dir");
    assert!(err.to_string().contains("scripts/PoC directory"), "{err}");

    // Agent with no confinement configured: refused even for an in-temp file.
    let err = h
        .invoke_as(Frontend::Mcp, None, "script.validate", p(inside.path()))
        .expect_err("an unconfigured agent gets no raw-path access");
    assert!(err.to_string().contains("scripts/PoC directory"), "{err}");

    // No existence oracle: a missing .rhai outside the root returns the same
    // refusal as an existing one, so an agent cannot probe for files.
    let missing = root
        .parent()
        .expect("temp parent")
        .join("aitm-rhai-ghost-does-not-exist.rhai");
    let err = h
        .invoke_as(
            Frontend::Mcp,
            Some(root.clone()),
            "script.validate",
            p(&missing),
        )
        .expect_err("a missing path outside the root is refused, not reported absent");
    assert!(err.to_string().contains("scripts/PoC directory"), "{err}");
}

/// Spec §8 *Reload*: `script.reload { name }` recompiles the loaded script
/// from its file and swaps the hooks live; a recompile that fails keeps the
/// previous good AST and reports the error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_reload_swaps_hooks_and_keeps_the_old_ast_on_error() {
    let script = TempScript::new("versioned", V1);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    assert_eq!(h.x_v().await.as_deref(), Some("1"));

    script.rewrite(V2);
    let out = h
        .invoke(
            "script.reload",
            params(&[("name", Value::Str("versioned".into()))]),
        )
        .expect("reload of a compiling script succeeds");
    assert_eq!(
        field(&out, "hooks"),
        &Value::Array(vec![
            Value::Str("on_request".into()),
            Value::Str("on_response".into())
        ]),
        "the reply describes the script as recompiled"
    );
    assert_eq!(h.x_v().await.as_deref(), Some("2"), "the new hook is live");

    script.rewrite(BROKEN);
    let err = h
        .invoke(
            "script.reload",
            params(&[("name", Value::Str("versioned".into()))]),
        )
        .expect_err("a broken recompile is an error");
    assert!(err.to_string().contains("error: versioned:4:"), "{err}");
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("2"),
        "the previous good AST stays in service"
    );

    let err = h
        .invoke(
            "script.reload",
            params(&[("name", Value::Str("nope".into()))]),
        )
        .expect_err("an unknown script is an error");
    assert!(
        err.to_string().contains("versioned"),
        "the error lists the loaded scripts: {err}"
    );
}

/// Spec §3: what `finding(...)` records is read back through the command
/// surface — `script.findings` returns every finding as an object, newest last,
/// plus how many the bounded sink had to drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_findings_reads_back_what_scripts_recorded() {
    let script = TempScript::new(
        "observer",
        r#"
        fn on_request(flow) {
            finding(#{ name: "admin write", severity: "high", flow_id: flow.id,
                       detail: "unauthenticated", tags: ["auth", "admin"] });
            flow.request.headers.set("X-V", "seen");
        }
        "#,
    );
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    assert_eq!(h.x_v().await.as_deref(), Some("seen"));
    assert_eq!(h.x_v().await.as_deref(), Some("seen"));

    let out = h
        .invoke("script.findings", Params::default())
        .expect("script.findings runs");
    assert_eq!(field(&out, "dropped"), &Value::Int(0));
    let Value::Array(items) = field(&out, "findings") else {
        panic!("findings is an array: {out:?}");
    };
    assert_eq!(items.len(), 2);
    let first = &items[0];
    assert_eq!(field(first, "name"), &Value::Str("admin write".into()));
    assert_eq!(field(first, "severity"), &Value::Str("high".into()));
    assert_eq!(
        field(first, "detail"),
        &Value::Str("unauthenticated".into())
    );
    assert_eq!(
        field(first, "tags"),
        &Value::Array(vec![Value::Str("auth".into()), Value::Str("admin".into())])
    );
    assert_eq!(field(first, "source"), &Value::Str("observer".into()));
    assert!(
        matches!(field(first, "flow_id"), Value::Str(id) if !id.is_empty()),
        "{first:?}"
    );
    assert!(matches!(field(first, "at"), Value::Int(ms) if *ms > 0));

    // `limit` keeps the newest.
    let out = h
        .invoke("script.findings", params(&[("limit", Value::Int(1))]))
        .expect("script.findings with a limit");
    let Value::Array(items) = field(&out, "findings") else {
        panic!("findings is an array");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(h.findings.list().len(), 2, "the sink itself is untouched");
}

/// Security review (M3, Minor): the in-memory sink is a ring buffer — a hook
/// that records per request on a long engagement cannot grow it without
/// bound — and it counts what it dropped.
#[test]
fn memory_sink_is_bounded_and_counts_drops() {
    use aitm_plugin_rhai::host_core::Finding;
    use aitm_poc::Severity;
    use std::time::SystemTime;

    let sink = MemoryFindingSink::with_capacity(2);
    for n in 1..=3 {
        sink.record(Finding {
            name: format!("f{n}"),
            severity: Severity::Info,
            flow: None,
            detail: None,
            tags: Vec::new(),
            source: "t".into(),
            at: SystemTime::now(),
        });
    }
    let kept: Vec<String> = sink.list().into_iter().map(|f| f.name).collect();
    assert_eq!(kept, vec!["f2".to_string(), "f3".to_string()]);
    assert_eq!(sink.dropped(), 1);
    assert_eq!(
        MemoryFindingSink::new().dropped(),
        0,
        "the default sink is bounded too (it just has a large capacity)"
    );
}

/// The `script.list` rows as `(name, row)` pairs, in the order returned.
fn list_rows(h: &Harness) -> Vec<Value> {
    match h
        .invoke("script.list", Params::default())
        .expect("script.list runs")
    {
        Value::Array(rows) => rows,
        other => panic!("script.list is an array: {other:?}"),
    }
}

const FAILS_ON_HEADER: &str = r#"
const NAME = "flaky";
fn on_request(flow) {
    if flow.request.headers.has("X-Fail") { throw "boom from flaky"; }
}
"#;

/// Spec F8a / AC1: `script.list` returns one object per loaded script in chain
/// (declaration) order with its name, path, API, hooks, `enabled: true` and
/// `last_error: null`, and is a read-tier command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_reports_every_loaded_script_in_chain_order() {
    let first = TempScript::new("versioned", V2);
    let second = TempScript::new("observer", "fn on_response(flow) { }\n");
    let h = Harness::new(vec![
        ScriptEntry::new(first.path()),
        ScriptEntry::new(second.path()),
    ]);
    assert_eq!(
        h.registry
            .command("script.list")
            .expect("script.list is registered")
            .sensitivity(),
        aitm_core::Sensitivity::Read
    );

    let rows = list_rows(&h);
    assert_eq!(rows.len(), 2);
    assert_eq!(field(&rows[0], "name"), &Value::Str("versioned".into()));
    assert_eq!(
        field(&rows[0], "path"),
        &Value::Str(first.path().display().to_string())
    );
    assert_eq!(field(&rows[0], "api"), &Value::Str("1".into()));
    assert_eq!(
        field(&rows[0], "hooks"),
        &Value::Array(vec![
            Value::Str("on_request".into()),
            Value::Str("on_response".into())
        ])
    );
    assert_eq!(field(&rows[0], "enabled"), &Value::Bool(true));
    assert_eq!(field(&rows[0], "last_error"), &Value::Null);

    assert_eq!(field(&rows[1], "name"), &Value::Str("observer".into()));
    assert_eq!(
        field(&rows[1], "hooks"),
        &Value::Array(vec![Value::Str("on_response".into())])
    );
    assert_eq!(field(&rows[1], "enabled"), &Value::Bool(true));
    assert_eq!(field(&rows[1], "last_error"), &Value::Null);
}

/// A hook that throws surfaces its message in `last_error`; a later clean run
/// of the same hook clears it (no stale error).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_last_error_records_a_hook_failure_and_clears_on_success() {
    let script = TempScript::new("flaky", FAILS_ON_HEADER);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);

    h.dispatch_with_header("X-Fail", "1").await;
    let rows = list_rows(&h);
    assert!(
        matches!(field(&rows[0], "last_error"), Value::Str(m) if m.contains("boom from flaky")),
        "the failed hook's message is reported: {:?}",
        rows[0]
    );

    h.dispatch_with_header("X-Ok", "1").await;
    assert_eq!(
        field(&list_rows(&h)[0], "last_error"),
        &Value::Null,
        "a clean run clears the stale error"
    );
}

/// An errored script that is fixed and reloaded no longer reports the old
/// error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_last_error_clears_on_successful_reload() {
    let script = TempScript::new("flaky", FAILS_ON_HEADER);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);

    h.dispatch_with_header("X-Fail", "1").await;
    assert!(matches!(
        field(&list_rows(&h)[0], "last_error"),
        Value::Str(_)
    ));

    script.rewrite("const NAME = \"flaky\";\nfn on_request(flow) { }\n");
    h.invoke(
        "script.reload",
        params(&[("name", Value::Str("flaky".into()))]),
    )
    .expect("reload of the fixed script succeeds");
    assert_eq!(field(&list_rows(&h)[0], "last_error"), &Value::Null);
}

/// A script disabled through its handle lists `enabled: false`; the other
/// stays `true`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_shows_a_disabled_script_as_not_enabled() {
    let a = TempScript::new("alpha", "fn on_request(flow) { }\n");
    let b = TempScript::new("beta", "fn on_request(flow) { }\n");
    let h = Harness::new(vec![ScriptEntry::new(a.path()), ScriptEntry::new(b.path())]);
    h.handles[0].set_enabled(false);

    let rows = list_rows(&h);
    assert_eq!(field(&rows[0], "name"), &Value::Str("alpha".into()));
    assert_eq!(field(&rows[0], "enabled"), &Value::Bool(false));
    assert_eq!(field(&rows[1], "enabled"), &Value::Bool(true));
}

/// A script that throws in a normal hook and defines `on_error`: with the error
/// sink bound, the failure's `Event::Error` is dispatched back to the same
/// script, whose `on_error` returns cleanly. That clean `on_error` run must not
/// wipe the `last_error` the failure just recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_last_error_survives_the_scripts_own_on_error_dispatch() {
    let script = TempScript::new(
        "handler",
        r#"
        const NAME = "handler";
        fn on_request(flow) { throw "boom from handler"; }
        fn on_error(flow, err) { }
        "#,
    );
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    h.bind_error_sink();

    h.dispatch_with_header("X-Any", "1").await;
    // The error event is emitted on a spawned task; let it run to completion.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let rows = list_rows(&h);
    assert!(
        matches!(field(&rows[0], "last_error"), Value::Str(m) if m.contains("boom from handler")),
        "on_error's clean run must not clear the recorded failure: {:?}",
        rows[0]
    );
}

/// `{ name }` as the toggle commands take it.
fn name_arg(name: &str) -> Params {
    params(&[("name", Value::Str(name.into()))])
}

/// The `{ name, enabled }` object a toggle command answers with.
fn toggled(name: &str, enabled: bool) -> Value {
    Value::Object(BTreeMap::from([
        ("name".to_string(), Value::Str(name.into())),
        ("enabled".to_string(), Value::Bool(enabled)),
    ]))
}

/// F8c / AC7: `script.disable` stops the script's hook mutating flows,
/// `script.enable` restores it; both answer `{ name, enabled }`. Observed
/// through the real chain, not only the returned bool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_disable_and_enable_toggle_the_live_hook() {
    let script = TempScript::new("versioned", V1);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    assert_eq!(h.x_v().await.as_deref(), Some("1"));

    let out = h
        .invoke("script.disable", name_arg("versioned"))
        .expect("disable a loaded script");
    assert_eq!(out, toggled("versioned", false));
    assert_eq!(h.x_v().await, None, "a disabled script's hook is skipped");

    let out = h
        .invoke("script.enable", name_arg("versioned"))
        .expect("enable a loaded script");
    assert_eq!(out, toggled("versioned", true));
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("1"),
        "the hook is live again"
    );
}

/// F8c / AC7: an unknown name is the same error `script.reload` returns,
/// listing what is loaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_enable_and_disable_unknown_name_lists_loaded_scripts() {
    let script = TempScript::new("versioned", V1);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    for cmd in ["script.enable", "script.disable", "script.reload"] {
        let err = h
            .invoke(cmd, name_arg("nope"))
            .expect_err("an unknown script is an error");
        assert_eq!(
            err.to_string(),
            "no loaded script is named `nope`; loaded: versioned",
            "{cmd}"
        );
    }

    let empty = Harness::new(Vec::new());
    let err = empty
        .invoke("script.disable", name_arg("nope"))
        .expect_err("nothing is loaded");
    assert_eq!(
        err.to_string(),
        "no loaded script is named `nope`; loaded: (none)"
    );
}

/// Review Focus: toggling to the state a script is already in succeeds and
/// reports that state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_enable_and_disable_are_idempotent() {
    let script = TempScript::new("versioned", V1);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);

    // Already enabled: enable is a no-op that still answers.
    assert_eq!(
        h.invoke("script.enable", name_arg("versioned"))
            .expect("enable when enabled"),
        toggled("versioned", true)
    );
    for _ in 0..2 {
        assert_eq!(
            h.invoke("script.disable", name_arg("versioned"))
                .expect("disable, twice"),
            toggled("versioned", false)
        );
    }
    assert_eq!(h.x_v().await, None);
    for _ in 0..2 {
        assert_eq!(
            h.invoke("script.enable", name_arg("versioned"))
                .expect("enable, twice"),
            toggled("versioned", true)
        );
    }
    assert_eq!(h.x_v().await.as_deref(), Some("1"));
}

/// AC9: both toggle commands are `Sensitive`, so the agent policy gates them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_enable_and_disable_are_sensitive() {
    let h = Harness::new(Vec::new());
    for name in ["script.enable", "script.disable"] {
        let cmd = h.registry.command(name).expect("registered");
        assert_eq!(cmd.sensitivity(), Sensitivity::Sensitive, "{name}");
        assert!(cmd.mutates(), "{name}");
    }
}

// ---------------------------------------------------------------------------
// F8b-2: `script.save` — scripts_dir confinement, compile-before-write, and the
// overwrite-live / new-name-restart split (AC4, AC5, AC6).
// ---------------------------------------------------------------------------

/// A scratch directory tree, removed on drop. `root` holds `scripts/` (the
/// configured scripts dir) so a traversal that escaped it would land in `root`
/// where the tests can see it.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "aitm-rhai-save-{}-{}",
            std::process::id(),
            FlowId::new()
        ));
        std::fs::create_dir_all(root.join("scripts")).expect("sandbox dirs");
        Self { root }
    }

    fn scripts(&self) -> PathBuf {
        self.root.join("scripts")
    }

    /// Every entry under `root`, recursively, as paths relative to it: what the
    /// tests compare before and after a refused save.
    fn tree(&self) -> Vec<String> {
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                out.push(
                    path.strip_prefix(root)
                        .expect("under root")
                        .display()
                        .to_string(),
                );
                if path.is_dir() {
                    walk(&path, root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out);
        out.sort();
        out
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn save_args(name: &str, source: &str) -> Params {
    params(&[
        ("name", Value::Str(name.into())),
        ("source", Value::Str(source.into())),
    ])
}

fn save_harness(scripts: Vec<ScriptEntry>, scripts_dir: Option<PathBuf>) -> Harness {
    Harness::with_config(RhaiConfig {
        scripts,
        scripts_dir,
        ..RhaiConfig::default()
    })
}

const SAVED_V3: &str = r#"
const NAME = "versioned";
fn on_request(flow) { flow.request.headers.set("X-V", "3"); }
"#;

const SAVED_NEW: &str = r#"
const NAME = "fresh";
fn on_request(flow) { flow.request.headers.set("X-V", "new"); }
"#;

const SAVED_REGISTERING: &str = r#"
const NAME = "versioned";
fn load(reg) {
    reg.add_command("versioned.ping", "ping", |args| "pong");
}
fn on_request(flow) { flow.request.headers.set("X-V", "4"); }
"#;

const SAVED_NEW_REGISTERING: &str = r#"
const NAME = "brandnew";
fn load(reg) {
    reg.add_command("brandnew.ping", "ping", |args| "pong");
}
fn on_request(flow) { flow.request.headers.set("X-V", "live"); }
"#;

/// AC4 (overwrite branch): saving over an already-loaded script writes the file
/// AND swaps its hooks live, observed through the real chain with no restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_overwrite_swaps_the_loaded_hook_live() {
    let script = TempScript::new("versioned", V1);
    let dir = script.path().parent().expect("dir").to_path_buf();
    let h = save_harness(vec![ScriptEntry::new(script.path())], Some(dir.clone()));
    assert_eq!(h.x_v().await.as_deref(), Some("1"));

    let out = h
        .invoke("script.save", save_args("versioned", SAVED_V3))
        .expect("overwrite-save succeeds");

    assert_eq!(
        std::fs::read_to_string(dir.join("versioned.rhai")).expect("file"),
        SAVED_V3
    );
    assert_eq!(field(&out, "restart_required"), &Value::Bool(false));
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("3"),
        "the new on_request runs with no restart"
    );
    assert_eq!(h.handles.len(), 1, "no handle is added or duplicated");
}

/// Security (architect ruling): the least-privilege config default is a
/// fail-closed floor for UNKNOWN provenance only — it must not demote the
/// in-session path. A config-loaded script starts `Agent` (unknown authorship),
/// but an **operator**-frontend `script.save` carries positive evidence of
/// operator authorship and overrides the live script to `Operator`. "Operator
/// stays operator" in-session; the flip only downgrades genuinely-unknown
/// reloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_save_overrides_config_default_to_operator() {
    let script = TempScript::new("versioned", V1);
    let dir = script.path().parent().expect("dir").to_path_buf();
    let h = save_harness(vec![ScriptEntry::new(script.path())], Some(dir));

    // Config-loaded: unknown provenance → least-privilege Agent.
    assert_eq!(
        h.handles[0].authoring_trust(),
        CallerTrust::Agent,
        "a config-loaded script starts Agent (unknown provenance)"
    );

    // An operator (CLI) save over it is positive evidence of operator authorship;
    // the overwrite path reuses the same live handle and re-authors it.
    h.invoke("script.save", save_args("versioned", SAVED_V3))
        .expect("operator overwrite-save succeeds");
    assert_eq!(
        h.handles[0].authoring_trust(),
        CallerTrust::Operator,
        "an operator in-session save must re-author the live script as Operator"
    );
}

const SAVED_V3_WITH_RESPONSE: &str = r#"
const NAME = "versioned";
fn on_request(flow) { flow.request.headers.set("X-V", "3"); }
fn on_response(flow) { }
"#;

/// The `hooks` array `script.list` reports for the one loaded script.
fn listed_hooks(h: &Harness) -> Value {
    let out = h
        .invoke("script.list", Params::default())
        .expect("script.list succeeds");
    match out {
        Value::Array(items) => {
            assert_eq!(items.len(), 1, "exactly one loaded script: {items:?}");
            field(&items[0], "hooks").clone()
        }
        other => panic!("expected an array, got {other:?}"),
    }
}

fn hooks_value(names: &[&str]) -> Value {
    Value::Array(names.iter().map(|n| Value::Str((*n).into())).collect())
}

/// `script.list` reports the hooks the script defines NOW: a reload that adds a
/// hook shows it, not the set the script was first loaded with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_reports_fresh_hooks_after_reload() {
    let script = TempScript::new("versioned", V1);
    let h = Harness::new(vec![ScriptEntry::new(script.path())]);
    assert_eq!(listed_hooks(&h), hooks_value(&["on_request"]));

    script.rewrite(V2);
    h.invoke(
        "script.reload",
        params(&[("name", Value::Str("versioned".into()))]),
    )
    .expect("reload succeeds");

    assert_eq!(
        listed_hooks(&h),
        hooks_value(&["on_request", "on_response"]),
        "script.list must follow the reloaded script, not the load-time meta"
    );
}

/// The same freshness holds when an overwrite `script.save` swaps the script.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_list_reports_fresh_hooks_after_overwrite_save() {
    let script = TempScript::new("versioned", V1);
    let dir = script.path().parent().expect("dir").to_path_buf();
    let h = save_harness(vec![ScriptEntry::new(script.path())], Some(dir));
    assert_eq!(listed_hooks(&h), hooks_value(&["on_request"]));

    h.invoke(
        "script.save",
        save_args("versioned", SAVED_V3_WITH_RESPONSE),
    )
    .expect("overwrite-save succeeds");

    assert_eq!(
        listed_hooks(&h),
        hooks_value(&["on_request", "on_response"]),
        "script.list must follow the overwritten script, not the load-time meta"
    );
}

/// AC4 (new branch, F8 Option B): a never-loaded name is written, compiled, and
/// appended to the live set, so its `on_request` runs this session with no
/// restart. A hook-only new script needs no restart at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_new_name_goes_live_with_no_restart() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));

    let out = h
        .invoke("script.save", save_args("fresh", SAVED_NEW))
        .expect("save of a new script succeeds");

    let path = sandbox.scripts().join("fresh.rhai");
    assert_eq!(std::fs::read_to_string(&path).expect("file"), SAVED_NEW);
    assert_eq!(
        field(&out, "restart_required"),
        &Value::Bool(false),
        "a hook-only new script needs no restart"
    );
    assert_eq!(field(&out, "name"), &Value::Str("fresh".into()));
    assert_eq!(field(&out, "path"), &Value::Str(path.display().to_string()));
    assert_eq!(
        field(&out, "hooks"),
        &Value::Array(vec![Value::Str("on_request".into())]),
        "the result reports the compiled meta"
    );
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("new"),
        "the new script's on_request runs this session with no restart"
    );
    assert_eq!(
        sandbox.tree(),
        ["scripts", "scripts/fresh.rhai"],
        "exactly the one file, no temp leftovers"
    );
}

/// AC4: a source that does not compile is refused with the positioned error and
/// no file is written — not for a new name, and an existing file is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_refuses_a_non_compiling_source_and_writes_nothing() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));
    let before = sandbox.tree();

    let err = h
        .invoke("script.save", save_args("broken", BROKEN))
        .expect_err("a broken source is refused");
    assert!(err.to_string().contains("error: "), "{err}");
    assert!(!sandbox.scripts().join("broken.rhai").exists());
    assert_eq!(sandbox.tree(), before);

    // An existing file is not clobbered by a broken overwrite.
    std::fs::write(sandbox.scripts().join("keep.rhai"), V1).expect("seed");
    h.invoke("script.save", save_args("keep", BROKEN))
        .expect_err("a broken overwrite is refused");
    assert_eq!(
        std::fs::read_to_string(sandbox.scripts().join("keep.rhai")).expect("file"),
        V1
    );
}

/// AC5: a `name` that is not exactly one `[A-Za-z0-9_-]+` segment is rejected
/// before any write, and nothing appears anywhere under the sandbox root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_rejects_names_that_could_leave_the_scripts_dir() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));
    let before = sandbox.tree();

    let abs = sandbox.root.join("evil").display().to_string();
    let bad = [
        "../evil",
        "..",
        ".",
        "a/b",
        "/evil",
        "/etc/passwd",
        "..\\evil",
        "a\\b",
        "evil.rhai",
        ".hidden",
        "a b",
        "a\0b",
        "nul\u{0}",
        "é",
        "evil/..",
        "",
        abs.as_str(),
    ];
    for name in bad {
        let err = h
            .invoke("script.save", save_args(name, SAVED_NEW))
            .expect_err(&format!("name {name:?} must be rejected"));
        assert!(
            err.to_string().contains("[A-Za-z0-9_-]"),
            "{name:?} gets the name-rule error: {err}"
        );
        assert_eq!(sandbox.tree(), before, "{name:?} touched the disk");
    }
}

/// AC5: no `scripts_dir` configured → a clear refusal, nothing written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_without_a_scripts_dir_refuses_clearly() {
    let h = save_harness(Vec::new(), None);
    let err = h
        .invoke("script.save", save_args("fresh", SAVED_NEW))
        .expect_err("no scripts dir");
    assert_eq!(
        err.to_string(),
        "no scripts directory configured; set rhai.scripts_dir"
    );
}

/// AC6: a script whose `load` registers a command needs a restart even when it
/// overwrites a loaded script, and its hooks still go live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_of_a_registering_script_requires_a_restart_but_hooks_load() {
    let script = TempScript::new("versioned", V1);
    let dir = script.path().parent().expect("dir").to_path_buf();
    let h = save_harness(vec![ScriptEntry::new(script.path())], Some(dir));

    let out = h
        .invoke("script.save", save_args("versioned", SAVED_REGISTERING))
        .expect("save succeeds");
    assert_eq!(field(&out, "restart_required"), &Value::Bool(true));
    assert_eq!(
        field(&out, "registers"),
        &registers_value(&["versioned.ping"], &[])
    );
    assert_eq!(h.x_v().await.as_deref(), Some("4"), "hooks still load");
}

/// AC6 (new branch, F8 Option B): a brand-new save whose `load` registers a
/// command is appended live — its `on_request` runs this session — but still
/// reports `restart_required: true`, because the command/option Registry is
/// sealed and its `load` never ran, so `brandnew.ping` is not callable yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_new_name_registering_is_live_but_requires_a_restart() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));

    let out = h
        .invoke("script.save", save_args("brandnew", SAVED_NEW_REGISTERING))
        .expect("save of a new registering script succeeds");

    assert_eq!(
        field(&out, "restart_required"),
        &Value::Bool(true),
        "the registered command needs a restart (the Registry is sealed)"
    );
    assert_eq!(
        field(&out, "registers"),
        &registers_value(&["brandnew.ping"], &[])
    );
    assert!(
        h.registry.command("brandnew.ping").is_none(),
        "the command is not callable until a restart runs the script's load"
    );
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("live"),
        "its hooks still go live this session with no restart"
    );
}

/// `enable: false` on a brand-new name appends the script DISABLED: its
/// `on_request` does not fire until `script.enable` turns it on. (`enable` sets
/// the saved script's live flag on the new-name branch too, not just overwrite.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_new_name_enable_false_appends_disabled() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));

    let out = h
        .invoke(
            "script.save",
            params(&[
                ("name", Value::Str("fresh".into())),
                ("source", Value::Str(SAVED_NEW.into())),
                ("enable", Value::Bool(false)),
            ]),
        )
        .expect("save of a new disabled script succeeds");
    assert_eq!(field(&out, "restart_required"), &Value::Bool(false));

    assert_eq!(
        h.x_v().await,
        None,
        "a new script saved with enable:false must not fire until enabled"
    );

    h.invoke(
        "script.enable",
        params(&[("name", Value::Str("fresh".into()))]),
    )
    .expect("enable succeeds");
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("new"),
        "after script.enable the appended hook runs"
    );
}

/// The answer is exactly `{ name, path, api, hooks, registers, restart_required }`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_result_has_exactly_the_documented_shape() {
    let sandbox = Sandbox::new();
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));
    let out = h
        .invoke("script.save", save_args("fresh", SAVED_NEW))
        .expect("save");
    let Value::Object(fields) = &out else {
        panic!("expected an object, got {out:?}")
    };
    let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "api",
            "hooks",
            "name",
            "path",
            "registers",
            "restart_required"
        ]
    );
    assert_eq!(field(&out, "api"), &Value::Str("1".into()));
    assert_eq!(field(&out, "registers"), &registers_value(&[], &[]));
}

/// `enable: false` on an overwrite leaves the script loaded but disabled;
/// `enable: true` (and the default) ensures it is on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_enable_flag_controls_the_live_state_on_overwrite() {
    let script = TempScript::new("versioned", V1);
    let dir = script.path().parent().expect("dir").to_path_buf();
    let h = save_harness(vec![ScriptEntry::new(script.path())], Some(dir));

    let args = params(&[
        ("name", Value::Str("versioned".into())),
        ("source", Value::Str(SAVED_V3.into())),
        ("enable", Value::Bool(false)),
    ]);
    h.invoke("script.save", args).expect("save disabled");
    assert_eq!(h.x_v().await, None, "saved with enable: false is off");

    h.invoke("script.save", save_args("versioned", SAVED_V3))
        .expect("save with the default enable");
    assert_eq!(
        h.x_v().await.as_deref(),
        Some("3"),
        "enable defaults to true"
    );

    let bad = params(&[
        ("name", Value::Str("versioned".into())),
        ("source", Value::Str(SAVED_V3.into())),
        ("enable", Value::Str("yes".into())),
    ]);
    h.invoke("script.save", bad)
        .expect_err("enable must be a bool");
}

/// A source larger than the sandbox string cap is refused cleanly, nothing written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_source_is_bounded_by_max_string_size() {
    let sandbox = Sandbox::new();
    let h = Harness::with_config(RhaiConfig {
        scripts_dir: Some(sandbox.scripts()),
        limits: RhaiLimits {
            max_string_size: 64,
            ..RhaiLimits::default()
        },
        ..RhaiConfig::default()
    });
    let before = sandbox.tree();
    let big = format!("// {}\nfn on_request(flow) {{ }}\n", "x".repeat(200));
    let err = h
        .invoke("script.save", save_args("big", &big))
        .expect_err("over the cap");
    assert!(err.to_string().contains("max_string_size"), "{err}");
    assert_eq!(sandbox.tree(), before);
}

/// A pre-existing symlink at `<name>.rhai` is not followed out of the scripts
/// dir: the save is refused and the link's target is untouched.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_does_not_follow_a_symlinked_target_out_of_the_dir() {
    let sandbox = Sandbox::new();
    let outside = sandbox.root.join("outside.txt");
    std::fs::write(&outside, "precious").expect("seed");
    std::os::unix::fs::symlink(&outside, sandbox.scripts().join("link.rhai")).expect("symlink");
    let h = save_harness(Vec::new(), Some(sandbox.scripts()));

    h.invoke("script.save", save_args("link", SAVED_NEW))
        .expect_err("a symlinked target is refused");
    assert_eq!(std::fs::read_to_string(&outside).expect("file"), "precious");
}

/// AC9: `script.save` is `Sensitive` (and so mutating).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_save_is_sensitive() {
    let h = Harness::new(Vec::new());
    let cmd = h.registry.command("script.save").expect("registered");
    assert_eq!(cmd.sensitivity(), Sensitivity::Sensitive);
    assert!(cmd.mutates());
}

// ---------------------------------------------------------------------------
// F8 Task 6: the `allow_agent_authoring` flag gate and explicit sensitivities.
// This is the always-on per-command dimension; `AgentPolicy` (All/Auto/Ask/...)
// is the dispatcher's and is tested there.
// ---------------------------------------------------------------------------

/// The four authoring commands with arguments that would succeed against the
/// harness below (`versioned` loaded, `scripts_dir` set).
fn authoring_calls() -> Vec<(&'static str, Params)> {
    let name = params(&[("name", Value::Str("versioned".into()))]);
    vec![
        ("script.save", save_args("gated", SAVED_NEW)),
        ("script.reload", name.clone()),
        ("script.enable", name.clone()),
        ("script.disable", name),
    ]
}

/// A harness with one loaded script and a scripts dir, so every authoring
/// command can succeed once past the gate. Keeps the temp files alive.
fn gate_harness(allow_agent_authoring: bool) -> (Harness, TempScript, Sandbox) {
    let script = TempScript::new("versioned", V1);
    let sandbox = Sandbox::new();
    let h = Harness::with_config(RhaiConfig {
        scripts: vec![ScriptEntry::new(script.path())],
        scripts_dir: Some(sandbox.scripts()),
        allow_agent_authoring,
        ..RhaiConfig::default()
    });
    (h, script, sandbox)
}

/// AC8: an agent frontend with the flag off is refused on every authoring
/// command, and the refusal names the key an operator must set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_authoring_is_refused_when_the_flag_is_off() {
    let (h, _script, sandbox) = gate_harness(false);
    let before = sandbox.tree();
    for (cmd, args) in authoring_calls() {
        let err = h
            .invoke_as(Frontend::Mcp, None, cmd, args)
            .expect_err(&format!("{cmd} refused for an agent with the flag off"));
        assert!(
            err.to_string().contains("rhai.allow_agent_authoring"),
            "{cmd}: {err}"
        );
    }
    assert_eq!(sandbox.tree(), before, "a refused save writes nothing");
    assert!(
        h.handles[0].is_enabled(),
        "a refused disable changed nothing"
    );
}

/// AC8: with the flag on, an agent frontend passes the gate on each command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_authoring_passes_the_gate_when_the_flag_is_on() {
    let (h, _script, sandbox) = gate_harness(true);
    for (cmd, args) in authoring_calls() {
        h.invoke_as(Frontend::Mcp, None, cmd, args)
            .unwrap_or_else(|e| panic!("{cmd} allowed for an agent with the flag on: {e}"));
    }
    assert!(sandbox.scripts().join("gated.rhai").exists());
    assert!(!h.handles[0].is_enabled(), "the last call, disable, ran");
}

/// AC8: the human CLI authors freely, flag off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_authoring_is_allowed_regardless_of_the_flag() {
    let (h, _script, sandbox) = gate_harness(false);
    for (cmd, args) in authoring_calls() {
        h.invoke_as(Frontend::Cli, None, cmd, args)
            .unwrap_or_else(|e| panic!("{cmd} allowed for the CLI with the flag off: {e}"));
    }
    assert!(sandbox.scripts().join("gated.rhai").exists());
}

/// Spec-critical: a human operator (operator-token connection) authors
/// freely with the flag off — only an autonomous agent is gated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_authoring_is_allowed_regardless_of_the_flag() {
    let (h, _script, sandbox) = gate_harness(false);
    for (cmd, args) in authoring_calls() {
        h.invoke_as(Frontend::Operator, None, cmd, args)
            .unwrap_or_else(|e| panic!("{cmd} allowed for an operator with the flag off: {e}"));
    }
    assert!(sandbox.scripts().join("gated.rhai").exists());
}

/// AC8: the Read commands are never gated; an agent lists and validates with
/// the flag off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_read_commands_are_not_gated() {
    let (h, _script, _sandbox) = gate_harness(false);
    let listed = h
        .invoke_as(Frontend::Mcp, None, "script.list", params(&[]))
        .expect("script.list is not gated");
    assert!(
        matches!(listed, Value::Array(ref a) if a.len() == 1),
        "{listed:?}"
    );
    h.invoke_as(
        Frontend::Mcp,
        None,
        "script.validate",
        params(&[("source", Value::Str(SAVED_NEW.into()))]),
    )
    .expect("script.validate { source } is not gated");
}

/// AC9: `Sensitive` for the authoring commands, `Read` for the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_commands_declare_their_sensitivity() {
    let h = Harness::new(Vec::new());
    let sensitivity = |name: &str| h.registry.command(name).expect("registered").sensitivity();
    for name in [
        "script.save",
        "script.reload",
        "script.enable",
        "script.disable",
    ] {
        assert_eq!(sensitivity(name), Sensitivity::Sensitive, "{name}");
    }
    for name in ["script.list", "script.validate", "script.findings"] {
        assert_eq!(sensitivity(name), Sensitivity::Read, "{name}");
    }
}
