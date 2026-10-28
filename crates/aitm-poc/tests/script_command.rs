//! M3 Task 15: the `poc.run` *command* carries the script executor.
//!
//! Task 13 put `with_script_executor` on `StdPocRunner`, but `poc.run` — the
//! command MCP and the CLI actually invoke — built its own runner internally,
//! so a script step was unreachable through the frontends however the binary
//! was wired. These tests pin the registration that closes that gap:
//! `register_with_executor` yields a `poc.run` that dispatches script steps,
//! and the plain `register` keeps the M1 behaviour (a clear error, never a
//! silent skip — AC-M3-11).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, HeaderMap, HttpRequest, HttpResponse, HttpVersion, LimitConfig,
    MemFlowStore, Params, PipelineClient, Registry, RequestSender, ScopeEntry, ScopeRateGuard,
    StdGuard, Value,
};
use aitm_poc::{ScriptStep, ScriptStepCtx, ScriptStepError, ScriptVerdict};
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
                body: Body::Bytes(b"ok".to_vec()),
                timestamp: SystemTime::now(),
            })
        })
    }
}

/// Records what it ran and returns a fixed verdict.
struct FixedExecutor {
    verdict: ScriptVerdict,
    seen: Mutex<Vec<ScriptStep>>,
}

impl FixedExecutor {
    fn returning(verdict: ScriptVerdict) -> Arc<Self> {
        Arc::new(Self {
            verdict,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl aitm_poc::ScriptStepExecutor for FixedExecutor {
    fn run_step(
        &self,
        step: &ScriptStep,
        _ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        self.seen.lock().expect("seen lock").push(step.clone());
        Ok(self.verdict)
    }
}

/// A PoC with one anchoring http step and a named script step, on disk where
/// `poc.run` can read it.
fn poc_file(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "aitm-poc-cmd-{}-{tag}-{n}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        r#"
id: script-via-command
info:
  name: script step through poc.run
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - script:
      name: s
      script: "return pass;"
success:
  - dsl: 'step("s") == "pass"'
"#,
    )
    .expect("the PoC file is written");
    path
}

fn invoke_poc_run(registry: &Registry, path: &Path) -> anyhow::Result<Value> {
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    guard.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let args = Params::new(
        [(
            "poc_path".to_string(),
            Value::Str(path.display().to_string()),
        )]
        .into_iter()
        .collect(),
    );
    registry
        .command("poc.run")
        .expect("poc.run is registered")
        .invoke(args, &host)
}

/// The wired path: `poc.run` hands script steps to the executor, so the run
/// reaches `passed == true` through the same command a frontend calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_run_dispatches_script_steps_through_the_wired_executor() {
    let exec = FixedExecutor::returning(ScriptVerdict::Pass);
    let mut registry = Registry::new();
    aitm_poc::runner::register_with_executor(&mut registry, exec.clone());

    let path = poc_file("wired");
    let out = invoke_poc_run(&registry, &path).expect("poc.run succeeds");
    let _ = std::fs::remove_file(&path);

    let Value::Object(obj) = out else {
        panic!("poc.run returns an object");
    };
    assert_eq!(
        obj.get("passed"),
        Some(&Value::Bool(true)),
        "the script step's Pass must reach the success DSL",
    );
    assert_eq!(
        exec.seen.lock().expect("seen lock").len(),
        1,
        "the executor ran the one script step",
    );
}

/// The unwired path is unchanged (AC-M3-11): a clear error naming what is
/// missing, not a silent skip that would quietly report a wrong verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_run_without_an_executor_still_errors_clearly() {
    let mut registry = Registry::new();
    aitm_poc::runner::register(&mut registry);

    let path = poc_file("unwired");
    let err = invoke_poc_run(&registry, &path).expect_err("a script step needs the Rhai runtime");
    let _ = std::fs::remove_file(&path);

    assert!(
        err.to_string().contains("require the Rhai runtime"),
        "want the wiring hint, got: {err}",
    );
}
