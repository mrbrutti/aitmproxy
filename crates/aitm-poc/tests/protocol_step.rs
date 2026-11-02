//! Task 3: the additive `Step::Protocol { ns, body, extract }` arm and the
//! runner's dispatch to a registered `PocStepHandler` (AC3, Review Focus:
//! unknown-namespace step).
//!
//! No protocol wire effects here — the `aitm-proto-test` `test:` handler is a
//! pure stand-in: `op: echo` produces a named `echo` source and an `echoed`
//! binding, enough to prove a `<ns>:` step round-trips, runs through the seam,
//! and feeds both a sibling `extract` (the normative `l4:` shape) and a
//! `success` dsl — with **no edit to the fixed http/browser/extract/script
//! steps**. One anchoring http step gives the run a captured flow, sent through
//! a `PipelineClient` over a no-network sender; nothing listens on a port.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CallerTrust, CommandHost, Frontend, HeaderMap, HttpRequest, HttpResponse, HttpVersion,
    LimitConfig, MemFlowStore, PipelineClient, RequestSender, ScopeEntry, ScopeRateGuard, StdGuard,
    Value,
};
use aitm_plugin::language::{HostError, PocStepHandler, PocStepInputs, PocStepOutcome};
use aitm_poc::model::ProtoExtract;
use aitm_poc::{Poc, PocRunResult, PocRunner, StdPocRunner, Step, VarBindings};
use aitm_proto_test::TestStepHandler;
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

/// Run `poc` through a `StdPocRunner`, optionally wiring the `test:` handler,
/// over an in-scope `poc.test` and a no-network client.
async fn run_poc(
    poc: &Poc,
    bindings: VarBindings,
    with_handler: bool,
) -> anyhow::Result<PocRunResult> {
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    guard.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let mut runner = StdPocRunner::with_output_dir(std::env::temp_dir());
    if with_handler {
        let handler: Arc<dyn PocStepHandler> = Arc::new(TestStepHandler);
        runner = runner.with_step_handler(handler);
    }
    runner.run(poc, bindings, &host).await
}

/// AC3: a `test:` protocol step parses into `Step::Protocol`, round-trips
/// (YAML ↔ model ↔ YAML), and the fixed `http` step beside it is untouched.
#[test]
fn protocol_step_round_trips() {
    let yaml = r#"
id: proto-roundtrip
info:
  name: protocol step round trip
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - test:
      op: echo
      value: hello
    extract:
      - name: pulled
        type: echo
        field: value
success:
  - dsl: 'echoed == "hello"'
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("PoC parses");

    // The fixed http step is unaffected; the `test:` step is a Protocol arm.
    assert!(matches!(&poc.steps[0], Step::Http(_)));
    match &poc.steps[1] {
        Step::Protocol { ns, body, extract } => {
            assert_eq!(ns, "test");
            assert_eq!(body.get("op").and_then(|v| v.as_str()), Some("echo"));
            assert_eq!(
                extract,
                &vec![ProtoExtract {
                    name: "pulled".to_string(),
                    source: "echo".to_string(),
                    field: "value".to_string(),
                }]
            );
        }
        other => panic!("expected a Protocol step, got {other:?}"),
    }

    // Serialize → parse → equal: the protocol step and its sibling extract
    // survive a YAML round-trip.
    let reserialized = serde_yaml::to_string(&poc).expect("serialize");
    let parsed: Poc = serde_yaml::from_str(&reserialized).expect("re-parse");
    assert_eq!(poc, parsed, "protocol step must round-trip");
}

/// AC3 end to end: the `test:` step runs via the injected handler; its direct
/// `echoed` binding and the `pulled` value its `echo` source feeds a sibling
/// `extract` both reach the `success` dsl, which passes. `{{greeting}}` in the
/// body proves the resolved variables reach the handler through `PocStepInputs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_step_runs_and_feeds_extract_and_success() {
    let yaml = r#"
id: proto-run
info:
  name: protocol step run
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - test:
      op: echo
      value: "{{greeting}}"
    extract:
      - name: pulled
        type: echo
        field: value
success:
  - dsl: 'echoed == "hello" && pulled == "hello"'
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("PoC parses");
    let bindings = VarBindings::new().with("greeting", Value::Str("hello".to_string()));

    let result = run_poc(&poc, bindings, true)
        .await
        .expect("run with the test handler wired");
    assert!(
        result.passed,
        "the `test:` step's binding + extracted source must satisfy success; outcomes: {:?}",
        result.evaluated
    );
}

/// A stand-in native (`l4:`-style) step handler that does NOT go through rhai and
/// so cannot read the thread-local seed: it echoes the caller trust the runner
/// threaded into [`PocStepInputs::caller`] back out as a binding, so a test can
/// assert the native PoC-step face carries the live frontend trust (spec AC5,
/// Ruling A).
struct CallerEchoHandler;

impl PocStepHandler for CallerEchoHandler {
    fn ns(&self) -> &str {
        "caller"
    }

    fn run(
        &self,
        _body: &serde_yaml::Value,
        inputs: &PocStepInputs,
    ) -> Result<PocStepOutcome, HostError> {
        let label = match inputs.caller {
            CallerTrust::Operator => "operator",
            CallerTrust::Agent => "agent",
        };
        let mut bindings = BTreeMap::new();
        bindings.insert("caller_seen".to_string(), Value::Str(label.to_string()));
        Ok(PocStepOutcome {
            sources: BTreeMap::new(),
            bindings,
        })
    }
}

/// Run a PoC with the `caller:` echo handler wired, under a chosen frontend, and
/// return whether `success` (which asserts the echoed trust) passed.
async fn run_caller_poc(success_dsl: &str, frontend: Frontend) -> bool {
    let yaml = format!(
        r#"
id: caller-trust
info:
  name: caller trust
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - caller:
      op: note
success:
  - dsl: '{success_dsl}'
"#
    );
    let poc: Poc = serde_yaml::from_str(&yaml).expect("PoC parses");

    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    guard.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let host =
        CommandHost::new(store.as_ref(), &client, guard.as_ref(), None).with_frontend(frontend);

    let handler: Arc<dyn PocStepHandler> = Arc::new(CallerEchoHandler);
    let runner = StdPocRunner::with_output_dir(std::env::temp_dir()).with_step_handler(handler);
    runner
        .run(&poc, VarBindings::new(), &host)
        .await
        .expect("run with the caller handler")
        .passed
}

/// AC5 (native face): an `l4:`-style protocol step run through the runner carries
/// the live `poc.run` frontend trust in `PocStepInputs.caller` — `Agent` for an
/// MCP agent frontend, `Operator` for the human CLI — asserted end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_step_carries_frontend_caller_trust() {
    // An agent-driven run: the native step sees `Agent`.
    assert!(
        run_caller_poc(r#"caller_seen == "agent""#, Frontend::Mcp).await,
        "an Mcp (agent) frontend must thread CallerTrust::Agent into PocStepInputs.caller"
    );
    assert!(
        !run_caller_poc(r#"caller_seen == "operator""#, Frontend::Mcp).await,
        "an agent run must NOT be seen as operator"
    );

    // A human CLI run: the native step sees `Operator`.
    assert!(
        run_caller_poc(r#"caller_seen == "operator""#, Frontend::Cli).await,
        "the human CLI frontend must thread CallerTrust::Operator into PocStepInputs.caller"
    );
    // An operator-token MCP connection is also operator trust.
    assert!(
        run_caller_poc(r#"caller_seen == "operator""#, Frontend::Operator).await,
        "an operator-token frontend must thread CallerTrust::Operator"
    );
}

/// Review Focus: a `<ns>:` step with no registered handler errors clearly at run
/// (naming the namespace), never a silent skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_protocol_step_errors_at_run() {
    let yaml = r#"
id: proto-unknown
info:
  name: unknown protocol step
  severity: low
steps:
  - http:
      method: GET
      url: "http://poc.test/"
  - bogus:
      op: whatever
success:
  - dsl: 'status_code == 200'
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("PoC parses");

    let err = run_poc(&poc, VarBindings::new(), false)
        .await
        .expect_err("an unregistered protocol step must error");
    assert!(
        err.to_string().contains("bogus"),
        "the error must name the unknown namespace, got: {err}"
    );
}
