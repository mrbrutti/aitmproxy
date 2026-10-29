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
    Chain, CommandHost, Event, Flow, FlowId, FlowStore, Frontend, HttpFlow, HttpRequest,
    MemFlowStore, Params, ProxyClient, Registry, StdGuard, Value, Verdict,
};
use aitm_plugin_rhai::config::{RhaiConfig, ScriptEntry};
use aitm_plugin_rhai::host_core::{FindingSink, MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::wire;

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
    chain: Chain,
}

impl Harness {
    fn new(scripts: Vec<ScriptEntry>) -> Self {
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
        let tier = wire::build(
            RhaiConfig {
                scripts,
                ..RhaiConfig::default()
            },
            services,
        )
        .expect("tier builds");
        assert!(tier.errors.is_empty(), "scripts compile: {:?}", tier.errors);

        let mut registry = Registry::new();
        for plugin in tier.plugins {
            registry.add_plugin(Box::new(plugin));
        }
        registry.add_plugin(Box::new(tier.commands));
        let registry = Arc::new(registry);
        let chain = Chain::new(registry.clone(), store.clone());
        Self {
            store,
            findings,
            registry,
            chain,
        }
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
        h.registry.plugins().len() == 1,
        "validate registered nothing (only the command plugin is present)"
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
