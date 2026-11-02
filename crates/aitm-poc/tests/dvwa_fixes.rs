//! DVWA tool-fixes runner chain: T1 (anchor to any captured flow), T2 (variables
//! defaults visible to a `script:` step), T7 (poc.run records a durable finding on
//! pass), and T3 (the `poc.allow_agent_run` agent gate on the `poc.run` command).
//!
//! No network and no port binding: an `OkSender` behind a `PipelineClient` answers
//! every request with an empty 200, a stub `ScriptStepExecutor` stands in for the
//! Rhai tier, and a stub `FindingRecorder` captures what `poc.run` would persist.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_core::ScopeRateGuard;
use aitm_core::{
    Body, Command, CommandHost, Config, ConnInfo, FindingDraft, FindingRecorder, Flow, FlowId,
    FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, LimitConfig, MemFlowStore, Params, PipelineClient, RequestSender, ScopeEntry,
    StdGuard, Value,
};
use aitm_poc::{
    Poc, PocRunCommand, PocRunner, ScriptStep, ScriptStepCtx, ScriptStepError, ScriptStepExecutor,
    ScriptVerdict, StdPocRunner, VarBindings,
};
use futures::future::BoxFuture;

/// Answers every request with an empty 200 without touching the network.
struct OkSender;
impl RequestSender for OkSender {
    fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Bytes(b"ok".to_vec()),
                timestamp: SystemTime::now(),
                peer: None,
            })
        })
    }
}

/// A stub executor: records the `marker` binding it saw (to prove T2), and returns
/// `Pass` so `step("s") == "pass"` holds.
struct StubExecutor {
    marker_seen: Mutex<Option<Value>>,
}
impl StubExecutor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            marker_seen: Mutex::new(None),
        })
    }
}
impl ScriptStepExecutor for StubExecutor {
    fn run_step(
        &self,
        _step: &ScriptStep,
        ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        *self.marker_seen.lock().unwrap() = ctx.vars.get("marker").cloned();
        Ok(ScriptVerdict::Pass)
    }
}

/// A stub recorder: captures the draft `poc.run` would persist and returns an id.
struct StubRecorder {
    seen: Mutex<Option<FindingDraft>>,
}
impl StubRecorder {
    fn new() -> Self {
        Self {
            seen: Mutex::new(None),
        }
    }
}
impl FindingRecorder for StubRecorder {
    fn record(&self, draft: &FindingDraft, _dir: &std::path::Path) -> anyhow::Result<String> {
        *self.seen.lock().unwrap() = Some(draft.clone());
        Ok("rec-xyz".to_string())
    }
}

fn scoped_guard() -> Arc<StdGuard> {
    let g = Arc::new(StdGuard::new(LimitConfig::default()));
    g.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    g
}

fn dummy_flow() -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".to_string(),
            scheme: "http".to_string(),
            authority: "poc.test".to_string(),
            path: "/".to_string(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: "127.0.0.1:0".parse().unwrap(),
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

const SCRIPT_ONLY: &str = r#"
id: t1-anchor
info:
  name: t1
  severity: low
steps:
  - script:
      name: s
      script: "x"
success:
  - dsl: 'step("s") == "pass"'
"#;

// ---------------------------------------------------------------------- T1

/// T1: a pure-`script:` PoC (no declarative `http:` step) anchors the finding to
/// the newest flow captured in the store during the run, not a hard error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_script_only_anchors_on_captured_flow() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    // A flow captured during the run (stands in for a script `http.send`).
    let seeded = store.insert(dummy_flow());
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let poc: Poc = serde_yaml::from_str(SCRIPT_ONLY).unwrap();
    let runner = StdPocRunner::with_output_dir(std::env::temp_dir())
        .with_script_executor(StubExecutor::new());
    let result = runner
        .run(&poc, VarBindings::new(), &host)
        .await
        .expect("script-only PoC anchors on the captured flow");
    assert_eq!(result.finding_capture, seeded);
}

/// T1: with nothing captured at all, the run still errors (the behaviour kept).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_no_flow_still_errors() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let poc: Poc = serde_yaml::from_str(SCRIPT_ONLY).unwrap();
    let runner = StdPocRunner::with_output_dir(std::env::temp_dir())
        .with_script_executor(StubExecutor::new());
    let err = runner
        .run(&poc, VarBindings::new(), &host)
        .await
        .expect_err("no captured flow must still error");
    assert!(
        err.to_string().contains("no HTTP flow was captured"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------- T2

const DEFAULTS_POC: &str = r#"
id: t2-defaults
info:
  name: t2
  severity: low
variables:
  - name: marker
    default: MARK
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - script:
      name: s
      script: "x"
success:
  - dsl: 'step("s") == "pass"'
"#;

/// T2: a `variables:` default is seeded into the live bindings so a `script:`
/// step's `vars.get("marker")` sees it (not only `{{template}}` rendering).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_defaults_visible_to_script() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let poc: Poc = serde_yaml::from_str(DEFAULTS_POC).unwrap();
    let exec = StubExecutor::new();
    let runner =
        StdPocRunner::with_output_dir(std::env::temp_dir()).with_script_executor(exec.clone());
    runner.run(&poc, VarBindings::new(), &host).await.unwrap();
    assert_eq!(
        *exec.marker_seen.lock().unwrap(),
        Some(Value::Str("MARK".to_string())),
        "the variables default must reach vars.get() in the script step"
    );
}

/// T2: a caller `--vars` value still wins over the default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_caller_vars_override_defaults() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let poc: Poc = serde_yaml::from_str(DEFAULTS_POC).unwrap();
    let exec = StubExecutor::new();
    let runner =
        StdPocRunner::with_output_dir(std::env::temp_dir()).with_script_executor(exec.clone());
    let bindings = VarBindings::new().with("marker", Value::Str("OVERRIDE".to_string()));
    runner.run(&poc, bindings, &host).await.unwrap();
    assert_eq!(
        *exec.marker_seen.lock().unwrap(),
        Some(Value::Str("OVERRIDE".to_string())),
    );
}

// ---------------------------------------------------------------------- T7

fn finding_poc(success_status: u16) -> String {
    format!(
        r#"
id: dvwa-01-sqli
info:
  name: SQLi finding
  severity: high
steps:
  - http:
      method: GET
      url: "http://poc.test/"
success:
  - dsl: 'status_code == {success_status}'
"#
    )
}

fn config_with_findings_dir(dir: &std::path::Path) -> Arc<Config> {
    let mut cfg = Config::default();
    cfg.findings.dir = Some(dir.to_path_buf());
    Arc::new(cfg)
}

/// T7: a passing `poc.run` records a durable finding through the recorder seam,
/// and the recorded id is carried on the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t7_records_finding_on_pass() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let rec = StubRecorder::new();
    let tmp = std::env::temp_dir();
    let cfg = config_with_findings_dir(&tmp);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_config(cfg)
        .with_finding_recorder(&rec);

    let poc: Poc = serde_yaml::from_str(&finding_poc(200)).unwrap();
    let runner = StdPocRunner::with_output_dir(tmp.clone());
    let bindings = VarBindings::new().with("target", Value::Str("http://poc.test".to_string()));
    let result = runner.run(&poc, bindings, &host).await.unwrap();

    assert!(result.passed, "the PoC should pass against the OkSender");
    assert_eq!(result.recorded_id.as_deref(), Some("rec-xyz"));
    let draft = rec
        .seen
        .lock()
        .unwrap()
        .clone()
        .expect("a finding was recorded");
    assert_eq!(draft.title, "SQLi finding");
    assert_eq!(draft.severity, "high");
    assert_eq!(draft.poc_ref, "dvwa-01-sqli");
    assert_eq!(draft.target, "http://poc.test");
    assert!(draft.passed);
    assert_eq!(draft.finding_capture, result.finding_capture);
}

/// T7: no recorder wired ⇒ nothing recorded, `recorded_id` is `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t7_no_recorder_records_nothing() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let poc: Poc = serde_yaml::from_str(&finding_poc(200)).unwrap();
    let runner = StdPocRunner::with_output_dir(std::env::temp_dir());
    let result = runner.run(&poc, VarBindings::new(), &host).await.unwrap();
    assert!(result.passed);
    assert_eq!(result.recorded_id, None);
}

/// T7: a failing run records nothing even with a recorder wired (record-on-pass).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t7_failed_run_records_nothing() {
    let store = Arc::new(MemFlowStore::new());
    let guard = scoped_guard();
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let rec = StubRecorder::new();
    let tmp = std::env::temp_dir();
    let cfg = config_with_findings_dir(&tmp);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_config(cfg)
        .with_finding_recorder(&rec);

    // success requires a 500, but OkSender returns 200 ⇒ the run fails.
    let poc: Poc = serde_yaml::from_str(&finding_poc(500)).unwrap();
    let runner = StdPocRunner::with_output_dir(tmp.clone());
    let result = runner.run(&poc, VarBindings::new(), &host).await.unwrap();
    assert!(!result.passed);
    assert_eq!(result.recorded_id, None);
    assert!(rec.seen.lock().unwrap().is_none());
}

// ---------------------------------------------------------------------- T3

fn poc_run_args() -> Params {
    let mut m = BTreeMap::new();
    m.insert(
        "poc_path".to_string(),
        Value::Str("/nonexistent-dvwa.yaml".to_string()),
    );
    Params::new(m)
}

fn host_for<'a>(
    store: &'a MemFlowStore,
    client: &'a PipelineClient,
    guard: &'a StdGuard,
    frontend: Frontend,
    cfg: Arc<Config>,
) -> CommandHost<'a> {
    CommandHost::new(store, client, guard, None)
        .with_frontend(frontend)
        .with_config(cfg)
}

/// T3: an agent frontend is refused `poc.run` unless `poc.allow_agent_run` is set.
#[test]
fn t3_agent_is_gated_by_default() {
    let store = MemFlowStore::new();
    let guard = StdGuard::new(LimitConfig::default());
    let client = PipelineClient::new(
        Arc::new(MemFlowStore::new()),
        Arc::new(StdGuard::new(LimitConfig::default())),
        Arc::new(OkSender),
    );
    let host = host_for(
        &store,
        &client,
        &guard,
        Frontend::Mcp,
        Arc::new(Config::default()),
    );
    let err = PocRunCommand
        .invoke(poc_run_args(), &host)
        .expect_err("agent poc.run must be refused by default");
    assert!(
        err.to_string().contains("agent frontend"),
        "unexpected error: {err}"
    );
}

/// T3: with the flag on, the agent passes the gate (then fails later on the
/// missing file — proving the gate did not block).
#[test]
fn t3_agent_allowed_when_flag_set() {
    let store = MemFlowStore::new();
    let guard = StdGuard::new(LimitConfig::default());
    let client = PipelineClient::new(
        Arc::new(MemFlowStore::new()),
        Arc::new(StdGuard::new(LimitConfig::default())),
        Arc::new(OkSender),
    );
    let mut cfg = Config::default();
    cfg.poc.allow_agent_run = true;
    let host = host_for(&store, &client, &guard, Frontend::Mcp, Arc::new(cfg));
    let err = PocRunCommand
        .invoke(poc_run_args(), &host)
        .expect_err("the missing file still errors");
    assert!(
        !err.to_string().contains("agent frontend"),
        "the gate must not block when allow_agent_run is set: {err}"
    );
}

/// T3: operator and CLI frontends are never gated (they fail only on the file).
#[test]
fn t3_operator_and_cli_never_gated() {
    let store = MemFlowStore::new();
    let guard = StdGuard::new(LimitConfig::default());
    let client = PipelineClient::new(
        Arc::new(MemFlowStore::new()),
        Arc::new(StdGuard::new(LimitConfig::default())),
        Arc::new(OkSender),
    );
    for fe in [Frontend::Operator, Frontend::Cli] {
        let host = host_for(&store, &client, &guard, fe, Arc::new(Config::default()));
        let err = PocRunCommand
            .invoke(poc_run_args(), &host)
            .expect_err("the missing file still errors");
        assert!(
            !err.to_string().contains("agent frontend"),
            "{fe:?} must never be gated: {err}"
        );
    }
}
