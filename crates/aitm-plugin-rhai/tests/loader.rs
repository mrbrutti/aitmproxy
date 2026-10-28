//! Task 9 — `RhaiLoader`: one shared hardened engine with the whole host
//! surface registered, each `.rhai` file compiled once into a `ScriptPlugin`.
//! A script that does not compile is skipped with a positioned
//! `ScriptError::Compile` and the rest still load (AC-M3-9); under `strict`
//! the load fails fast instead. `validate` compiles without building a plugin.
//!
//! The loader builds `ScriptServices` with a runtime handle and the plugins
//! it yields run hooks under `block_in_place`, so every test runs on a
//! multi-thread runtime.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, MemFlowStore, Plugin, ProxyClient, StdGuard, Value, Verdict,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;

const TAGGER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tagger.rhai");
const BROKEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/broken.rhai");

/// A client that is never reached: no test sends.
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

fn config(scripts: Vec<ScriptEntry>, strict: bool) -> RhaiConfig {
    RhaiConfig {
        scripts,
        limits: RhaiLimits::default(),
        hook_timeout: Duration::from_secs(5),
        strict,
        ..RhaiConfig::default()
    }
}

fn loader(scripts: Vec<ScriptEntry>, strict: bool) -> RhaiLoader {
    RhaiLoader::new(config(scripts, strict), services()).expect("the loader builds")
}

/// A throwaway script outside the repo, named after the test so parallel
/// tests never share one; removed by [`TempScript::drop`].
struct TempScript(PathBuf);

impl TempScript {
    fn new(name: &str, src: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("aitm-loader-{}-{name}.rhai", std::process::id()));
        fs::write(&path, src).expect("the temp script is written");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// `POST http://ex.test/admin/users` with one header and a small body.
fn http_flow() -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "ex.test");
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/admin/users".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(b"name=x".to_vec()),
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

fn http(flow: &Flow) -> &HttpFlow {
    match flow {
        Flow::Http(f) => f,
        Flow::WebSocket(_) => panic!("expected an HTTP flow"),
    }
}

/// The `Compile` error's position and script, or a panic naming what came.
fn compile_parts(err: &ScriptError) -> (&str, &Path, usize, usize) {
    match err {
        ScriptError::Compile {
            script,
            path,
            line,
            column,
            ..
        } => (script, path, *line, *column),
        other => panic!("expected ScriptError::Compile, got {other:?}"),
    }
}

/// AC-M3-9: one broken script is skipped with a positioned `Compile` error;
/// the good one loads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_all_skips_broken() {
    let loader = loader(
        vec![ScriptEntry::new(TAGGER), ScriptEntry::new(BROKEN)],
        false,
    );

    let (plugins, errors) = loader.load_all();

    assert_eq!(plugins.len(), 1, "exactly the good script loaded");
    assert_eq!(plugins[0].meta().name, "tagger");
    assert_eq!(plugins[0].name(), "tagger");
    assert_eq!(errors.len(), 1, "exactly one error: {errors:?}");
    let (script, path, line, column) = compile_parts(&errors[0]);
    assert_eq!(script, "broken", "named after the file stem");
    assert_eq!(path, Path::new(BROKEN));
    assert_eq!(line, 5, "the unclosed call is on line 5");
    assert!(column > 0, "the column is set: {}", errors[0]);
    let text = errors[0].to_string();
    assert!(
        text.starts_with("error: broken:5:"),
        "pinned format, script:line:col: {text}"
    );
}

/// With `strict`, the same load fails fast: errors are surfaced and nothing
/// is handed to the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_surfaces_errors() {
    let loader = loader(
        vec![ScriptEntry::new(TAGGER), ScriptEntry::new(BROKEN)],
        true,
    );

    let (plugins, errors) = loader.load_all();

    assert!(!errors.is_empty(), "strict surfaces the compile error");
    let (script, _, line, _) = compile_parts(&errors[0]);
    assert_eq!(script, "broken");
    assert_eq!(line, 5);
    assert!(
        plugins.is_empty(),
        "strict loads nothing when any script fails: {:?}",
        plugins
            .iter()
            .map(|p| p.meta().name.clone())
            .collect::<Vec<_>>()
    );
}

/// `validate` compiles without building a plugin: metadata for a good file,
/// the positioned `Compile` error for a bad one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_good_and_bad() {
    let loader = loader(Vec::new(), false);

    let meta = loader
        .validate(Path::new(TAGGER))
        .expect("tagger validates");
    assert_eq!(meta.name, "tagger", "`const NAME` wins over the file stem");
    assert_eq!(meta.api, "1");
    assert_eq!(meta.path, PathBuf::from(TAGGER));
    assert!(
        meta.hooks.contains(&"on_request".to_string()),
        "hooks: {:?}",
        meta.hooks
    );
    assert_eq!(
        meta.hooks,
        vec!["load", "on_request", "on_response"],
        "every hook the script defines, in the spec's hook order"
    );

    let err = loader
        .validate(Path::new(BROKEN))
        .expect_err("broken does not validate");
    let (script, path, line, column) = compile_parts(&err);
    assert_eq!(script, "broken");
    assert_eq!(path, Path::new(BROKEN));
    assert_eq!(line, 5);
    assert!(column > 0);
}

/// `load_one` yields a working plugin over the shared engine: the config
/// entry's options reach `option(...)`, the flow API and prelude are
/// registered, and the hook's edit applies to a live flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn load_one_wires_options_and_hooks() {
    let loader = loader(Vec::new(), false);
    let mut entry = ScriptEntry::new(TAGGER);
    entry
        .options
        .insert("tag".to_string(), Value::Str("from-config".to_string()));

    let mut plugin = loader.load_one(&entry).expect("tagger loads");
    assert_eq!(plugin.meta().path, PathBuf::from(TAGGER));

    let mut flow = http_flow();
    let id = flow.id();
    let verdict = plugin.on_event(&Event::Request(id), &mut FlowCtx::new(&mut flow));

    assert_eq!(verdict, Verdict::Continue);
    assert_eq!(
        http(&flow).request.headers.get("X-Aitm"),
        Some("from-config"),
        "the hook ran with the entry's options"
    );
    assert_eq!(http(&flow).request.headers.get("Host"), Some("ex.test"));
}

/// Scripts without `NAME`/`API` are still complete plugins (spec §2 rule 1):
/// the name is the file stem, the API is the current one. The prelude is
/// callable, and declaration order is kept across the load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_script_defaults_and_declaration_order() {
    let bare = TempScript::new(
        "bare",
        r#"fn on_request(flow) { if contains_ci("AbC", "abc") { flow.request.headers.set("X-Bare", "1"); } }"#,
    );
    let loader = loader(
        vec![ScriptEntry::new(TAGGER), ScriptEntry::new(bare.path())],
        false,
    );

    let meta = loader
        .validate(bare.path())
        .expect("the bare script validates");
    let expected_name = bare
        .path()
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("stem")
        .to_string();
    assert_eq!(meta.name, expected_name, "NAME defaults to the file stem");
    assert_eq!(meta.api, "1", "a missing API is the current version");
    assert_eq!(meta.hooks, vec!["on_request"]);

    let (plugins, errors) = loader.load_all();
    assert!(errors.is_empty(), "{errors:?}");
    let names: Vec<_> = plugins.iter().map(|p| p.meta().name.as_str()).collect();
    assert_eq!(
        names,
        vec!["tagger", expected_name.as_str()],
        "declaration order is chain order"
    );

    let mut plugin = plugins.into_iter().nth(1).expect("the bare plugin");
    let mut flow = http_flow();
    let id = flow.id();
    plugin.on_event(&Event::Request(id), &mut FlowCtx::new(&mut flow));
    assert_eq!(
        http(&flow).request.headers.get("X-Bare"),
        Some("1"),
        "the prelude's contains_ci is callable from a loaded script"
    );
}

/// A disabled entry is neither loaded nor an error; a declared `API` this
/// build does not support is a logged warning, not a failed load.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_skipped_and_api_mismatch_warns() {
    let future = TempScript::new("future-api", r#"const API = "99"; fn on_request(flow) { }"#);
    let mut disabled = ScriptEntry::new(BROKEN);
    disabled.enabled = false;
    let loader = loader(vec![disabled, ScriptEntry::new(future.path())], false);

    let (plugins, errors) = loader.load_all();

    assert!(
        errors.is_empty(),
        "a disabled broken script is not compiled: {errors:?}"
    );
    assert_eq!(plugins.len(), 1);
    assert_eq!(
        plugins[0].meta().api,
        "99",
        "the declared API is kept in meta"
    );
}

/// A path that does not exist is a `Compile` error naming the path, with the
/// fix in its help line — never a panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_file_is_a_compile_error_naming_the_path() {
    let loader = loader(Vec::new(), false);
    let missing = Path::new("/nonexistent/aitm/addons/ghost.rhai");

    let err = loader
        .load_one(&ScriptEntry::new(missing))
        .err()
        .expect("a missing file cannot load");

    let (script, path, _, _) = compile_parts(&err);
    assert_eq!(script, "ghost");
    assert_eq!(path, missing);
    let text = err.to_string();
    assert!(text.contains("ghost.rhai"), "names the path: {text}");
    assert!(text.contains("\n  help: "), "carries the fix: {text}");
}

/// `new` fails cleanly, never panics, if the engine cannot be built — proven
/// by the one input it has: a config whose limits forbid the prelude itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_reports_an_unbuildable_engine() {
    let limits = RhaiLimits {
        // Too shallow for any function body: the bundled prelude cannot compile.
        max_expr_depth: 1,
        max_function_expr_depth: 1,
        ..RhaiLimits::default()
    };
    let cfg = RhaiConfig {
        limits,
        hook_timeout: Duration::from_secs(5),
        ..RhaiConfig::default()
    };

    let err = RhaiLoader::new(cfg, services())
        .err()
        .expect("the prelude cannot compile");

    let (script, _, _, _) = compile_parts(&err);
    assert_eq!(
        script, "prelude",
        "the error names the prelude, not a user script"
    );
}
