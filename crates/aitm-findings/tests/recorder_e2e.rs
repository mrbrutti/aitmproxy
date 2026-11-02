//! T7 end-to-end: a passing `poc.run` through a `CommandHost` carrying the real
//! `DiskFindingRecorder` + a configured `findings.dir` persists a finding that the
//! `findings.list` command then returns. No network, no port binding (an
//! `OkSender` behind a `PipelineClient` answers every request with a 200).

use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, Config, HeaderMap, HttpRequest, HttpResponse, HttpVersion, LimitConfig,
    MemFlowStore, PipelineClient, RequestSender, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_findings::{DiskFindingRecorder, DiskFindingStore, FindingFilter, FindingStore};
use aitm_poc::{Poc, PocRunner, StdPocRunner, VarBindings};
use futures::future::BoxFuture;

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

const PASSING_POC: &str = r#"
id: dvwa-01-sqli
info:
  name: SQLi finding
  severity: high
steps:
  - http:
      method: GET
      url: "http://poc.test/"
success:
  - dsl: 'status_code == 200'
"#;

/// Run a passing PoC through a host with the real recorder + a temp `findings.dir`,
/// then assert `findings.list` returns exactly that finding.
#[test]
fn poc_run_persists_and_findings_list_returns_it() {
    let tmp = tempdir();
    let mut cfg = Config::default();
    cfg.findings.dir = Some(tmp.clone());
    let cfg = Arc::new(cfg);

    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    guard.add_scope(ScopeEntry {
        host: "poc.test".to_string(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(OkSender));
    let recorder = DiskFindingRecorder;

    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_config(cfg.clone())
        .with_finding_recorder(&recorder);

    let poc: Poc = serde_yaml::from_str(PASSING_POC).unwrap();
    let runner = StdPocRunner::with_output_dir(tmp.clone());
    let bindings = VarBindings::new().with("target", Value::Str("http://poc.test".to_string()));
    let result = futures::executor::block_on(runner.run(&poc, bindings, &host)).unwrap();
    assert!(result.passed);
    assert!(
        result.recorded_id.is_some(),
        "a passing run with a recorder + findings.dir must persist a finding"
    );

    // The persistent store `findings.list` serves now holds exactly this finding.
    let listed = DiskFindingStore::new(tmp.clone()).list(&FindingFilter::default());
    assert_eq!(listed.len(), 1, "exactly one finding should be persisted");
    assert_eq!(listed[0].poc_ref, "dvwa-01-sqli");
    assert_eq!(listed[0].title, "SQLi finding");
    assert!(listed[0].passed);
}

/// A unique temp dir for this test run.
fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aitm-recorder-e2e-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
