//! M3 Task 13: the `ScriptStepExecutor` seam and the runner's `Step::Script`
//! dispatch (AC-M3-8 seam half, AC-M3-11 missing-executor error, Review Focus #5).
//!
//! No Rhai here — that is Task 14 in `aitm-plugin-rhai`. A stub executor returns a
//! fixed verdict (or an error) and the runner is judged on how `success`'s
//! `step("name")` resolves. Each PoC carries one http step ahead of the script
//! step, sent through a `PipelineClient` over a no-network sender, so the run has
//! a captured flow to anchor `finding_capture`; nothing listens on a port.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, HeaderMap, HttpRequest, HttpResponse, HttpVersion, LimitConfig,
    MemFlowStore, PipelineClient, RequestSender, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_poc::{
    Poc, PocRunResult, PocRunner, ScriptStep, ScriptStepCtx, ScriptStepError, ScriptStepExecutor,
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
                body: Body::Bytes(b"ok".to_vec()),
                timestamp: SystemTime::now(),
            })
        })
    }
}

/// The stub executor: hands back a fixed result for every step, records the
/// steps it was given, and binds `from_script = "yes"` to prove the context is
/// live (a later step and `success` must see that write).
struct FixedExecutor {
    result: Result<ScriptVerdict, String>,
    seen: Mutex<Vec<ScriptStep>>,
}

impl FixedExecutor {
    fn returning(result: Result<ScriptVerdict, String>) -> Arc<Self> {
        Arc::new(Self {
            result,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl ScriptStepExecutor for FixedExecutor {
    fn run_step(
        &self,
        step: &ScriptStep,
        ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError> {
        self.seen.lock().expect("seen lock").push(step.clone());
        ctx.vars
            .insert("from_script", Value::Str("yes".to_string()));
        self.result.clone().map_err(ScriptStepError)
    }
}

/// A PoC with one anchoring http step, then the named script step `s`, judged by
/// the given `success` DSL expression.
fn poc_yaml(success_dsl: &str) -> String {
    format!(
        r#"
id: script-seam
info:
  name: script step seam
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - script:
      name: s
      script: "return pass;"
success:
  - dsl: '{success_dsl}'
"#
    )
}

/// Run `yaml` through a `StdPocRunner`, with or without a script executor, over
/// an in-scope `poc.test` and a no-network client.
async fn run_poc(
    yaml: &str,
    executor: Option<Arc<dyn ScriptStepExecutor>>,
) -> anyhow::Result<PocRunResult> {
    let poc: Poc = serde_yaml::from_str(yaml).expect("PoC parses");
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    guard.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let mut runner = StdPocRunner::with_output_dir(std::env::temp_dir());
    if let Some(exec) = executor {
        runner = runner.with_script_executor(exec);
    }
    runner.run(&poc, VarBindings::new(), &host).await
}

/// AC-M3-8 (seam half): a `Pass` verdict recorded under the step's name satisfies
/// `success: step("s") == "pass"`, and the executor received the step as written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pass_verdict_satisfies_success() {
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Pass));
    let result = run_poc(&poc_yaml(r#"step("s") == "pass""#), Some(exec.clone()))
        .await
        .expect("run with a passing executor");

    assert!(
        result.passed,
        "a Pass verdict must satisfy success; outcomes: {:?}",
        result.evaluated
    );
    assert_eq!(result.evaluated.len(), 1);
    assert!(result.evaluated[0].matched);

    let seen = exec.seen.lock().expect("seen lock");
    assert_eq!(
        *seen,
        vec![ScriptStep {
            script: "return pass;".to_string(),
            name: Some("s".to_string()),
        }],
        "the executor must be handed the script step exactly once, as written"
    );
}

/// A `Fail` verdict does not satisfy `step("s") == "pass"` — the run completes
/// (no error) and reports `passed == false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_verdict() {
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Fail));
    let result = run_poc(&poc_yaml(r#"step("s") == "pass""#), Some(exec))
        .await
        .expect("run with a failing executor");
    assert!(
        !result.passed,
        "a Fail verdict must not satisfy `== \"pass\"`"
    );
    assert_eq!(result.evaluated.len(), 1);
    assert!(!result.evaluated[0].matched);

    // The verdict itself is still readable: `== "fail"` is true.
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Fail));
    let result = run_poc(&poc_yaml(r#"step("s") == "fail""#), Some(exec))
        .await
        .expect("run with a failing executor");
    assert!(result.passed, "step(\"s\") must resolve to \"fail\"");
}

/// Review Focus #5: a step that returns neither pass nor fail resolves to
/// `"neutral"`; an executor error resolves to `"error"` — deterministically and
/// without a panic — and is also reported as a failed assertion outcome that
/// carries the error text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_step_neutral_and_error_resolve() {
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Neutral));
    let result = run_poc(&poc_yaml(r#"step("s") == "neutral""#), Some(exec))
        .await
        .expect("run with a neutral executor");
    assert!(
        result.passed,
        "falling off the end must resolve to \"neutral\"; outcomes: {:?}",
        result.evaluated
    );

    let exec = FixedExecutor::returning(Err("boom: sandbox denied open_file".to_string()));
    let result = run_poc(&poc_yaml(r#"step("s") == "error""#), Some(exec))
        .await
        .expect("an executor error must not abort the run");
    assert!(
        result.passed,
        "an errored step must resolve to \"error\"; outcomes: {:?}",
        result.evaluated
    );
    // Spec §10 failure reporting: a failed AssertionOutcome surfacing the error text.
    let errored = result
        .evaluated
        .iter()
        .find(|o| !o.matched)
        .expect("an errored script step adds a failed assertion outcome");
    assert!(
        errored.assertion.contains("s") && errored.assertion.contains("boom"),
        "the failed outcome must name the step and carry the error text, got: {:?}",
        errored.assertion
    );
}

/// AC-M3-11: with no executor wired, a PoC containing a script step fails with a
/// clear message rather than silently skipping the step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_executor_errors() {
    let err = run_poc(&poc_yaml(r#"step("s") == "pass""#), None)
        .await
        .expect_err("a script step with no executor must error");
    assert!(
        err.to_string().contains("require the Rhai runtime"),
        "error must say the Rhai runtime is required, got: {err}"
    );
}

/// Spec §10 outputs (2): variables the script binds through `ctx.vars` are visible
/// to later steps and to `success`; and `step()` of a name nothing recorded is
/// `null`, not an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_vars_reach_success_and_unknown_step_is_null() {
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Pass));
    let result = run_poc(
        &poc_yaml(r#"from_script == "yes" && step("nope") == """#),
        Some(exec),
    )
    .await
    .expect("run");
    assert!(
        result.passed,
        "script-bound vars must reach success and an unknown step must be null; outcomes: {:?}",
        result.evaluated
    );
}

/// An unnamed script step is recorded under `step-<1-based position>`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unnamed_step_gets_positional_name() {
    let yaml = r#"
id: script-seam-unnamed
info:
  name: unnamed script step
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - script:
      script: "return pass;"
success:
  - dsl: 'step("step-2") == "pass"'
"#;
    let exec = FixedExecutor::returning(Ok(ScriptVerdict::Pass));
    let result = run_poc(yaml, Some(exec)).await.expect("run");
    assert!(
        result.passed,
        "the second step, unnamed, must be readable as step(\"step-2\"); outcomes: {:?}",
        result.evaluated
    );
}

/// The runner's manual `Debug` says whether an executor is wired (the executor
/// itself is an opaque trait object).
#[test]
fn runner_debug_reports_executor_presence() {
    let without = format!("{:?}", StdPocRunner::new());
    let with = format!(
        "{:?}",
        StdPocRunner::new().with_script_executor(FixedExecutor::returning(Ok(ScriptVerdict::Pass)))
    );
    assert!(without.contains("StdPocRunner") && without.contains("out_dir"));
    assert!(without.contains("script_executor: false"), "got: {without}");
    assert!(with.contains("script_executor: true"), "got: {with}");
}
