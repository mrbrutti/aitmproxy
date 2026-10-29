//! Task 24 (AC14/AC15/AC-L2/AC-L3): the `PocRunner` executes a `Poc` end to end
//! — HTTP steps through the scope guard + proxy client, browser steps through the
//! `BrowserDriver`, extract steps binding variables — evaluates `success`, and
//! emits the three artifacts (finding capture, YAML PoC file, screenshot PNG).
//!
//! The browser is a deterministic double here: `aitm-poc` has no way to stand up
//! Chromium + the proxy, so these tests exercise the runner's full logic with a
//! stub `BrowserDriver` and the real bundled vulnerable/patched target. The HTTP
//! `word` matcher carries the pass-vs-patch discrimination (the patched target
//! HTML-escapes the quote, so the marker word is absent); the genuine real-Chromium
//! full-stack run is Task 29. No test here needs Chromium.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, FlowStore, HeaderMap, HttpRequest, HttpResponse, HttpVersion, LimitConfig,
    MemFlowStore, NavOutcome, RequestSender, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_core::{BrowserDriver, ClickTarget};
use aitm_poc::{Poc, PocRunCommand, PocRunner, StdPocRunner, VarBindings};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::target::{spawn, TargetMode};

const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// A real `RequestSender`: issues the request over a raw HTTP/1.1 loopback
/// connection to the request's authority and returns the response. Wrapped in a
/// `PipelineClient` by each test, so scope/rate guarding and capture happen in
/// the single client chokepoint — not in the command.
struct TargetSender;

impl RequestSender for TargetSender {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        let authority = req.authority.clone();
        let method = req.method.clone();
        let path = req.path.clone();
        Box::pin(async move {
            let mut stream = tokio::net::TcpStream::connect(&authority).await?;
            let raw = format!(
                "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(raw.as_bytes()).await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            let text = String::from_utf8_lossy(&buf);
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
            let status = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or(0);
            Ok(HttpResponse {
                status,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Bytes(body.as_bytes().to_vec()),
                timestamp: SystemTime::now(),
            })
        })
    }
}

/// A `PipelineClient` over the real target sender and the given store + guard.
fn pipeline_client(store: &Arc<MemFlowStore>, guard: &Arc<StdGuard>) -> aitm_core::PipelineClient {
    aitm_core::PipelineClient::new(store.clone(), guard.clone(), Arc::new(TargetSender))
}

/// A deterministic `BrowserDriver` double: `eval` returns a fixed value, and
/// `screenshot` returns valid PNG bytes. No Chromium involved.
struct StubBrowser {
    eval_value: Value,
}

impl BrowserDriver for StubBrowser {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        let url = url.to_string();
        Box::pin(async move {
            Ok(NavOutcome {
                final_url: url,
                status: Some(200),
            })
        })
    }
    fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async {
            let mut png = PNG_MAGIC.to_vec();
            png.extend_from_slice(b"\x00\x00\x00\rIHDR stub pixels");
            Ok(png)
        })
    }
    fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        let value = self.eval_value.clone();
        Box::pin(async move { Ok(value) })
    }
    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        Box::pin(async { Ok(String::new()) })
    }
}

fn guard_scoping(addr: SocketAddr) -> StdGuard {
    let guard = StdGuard::new(LimitConfig::default());
    guard.add_scope(ScopeEntry {
        host: addr.to_string(),
    });
    guard
}

/// Example 1 (reflected XSS), with a fixed `marker` for deterministic assertions.
fn example1_yaml() -> &'static str {
    r#"
id: reflected-xss-search-q
info:
  name: Reflected XSS in search 'q' parameter
  severity: high
  cwe: CWE-79
  tags: [xss, reflected]
variables:
  - name: target
    required: true
  - name: param
    default: q
  - name: marker
    default: MARK1234
  - name: payload
    default: "<script>window.__aitm='{{marker}}'</script>"
steps:
  - http:
      method: GET
      url: "{{target}}/search?{{param}}={{url_encode(payload)}}"
  - browser:
      action: navigate
      url: "{{target}}/search?{{param}}={{url_encode(payload)}}"
  - browser:
      action: screenshot
      label: xss-triggered
success:
  all:
    - type: word
      word: "window.__aitm='{{marker}}'"
    - type: browser-eval
      expr: "window.__aitm"
      equals: "{{marker}}"
"#
}

fn example1_bindings(addr: SocketAddr) -> VarBindings {
    VarBindings::new().with("target", Value::Str(format!("http://{addr}")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pass_vs_patched() {
    let poc: Poc = serde_yaml::from_str(example1_yaml()).expect("parse example 1");

    // Vulnerable target: the marker word is reflected AND the browser marker is
    // observed → the PoC passes.
    let vuln = spawn(TargetMode::Vulnerable);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(guard_scoping(vuln));
    let client = pipeline_client(&store, &guard);
    let browser = StubBrowser {
        eval_value: Value::Str("MARK1234".to_string()),
    };
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser));
    let result = StdPocRunner::new()
        .run(&poc, example1_bindings(vuln), &host)
        .await
        .expect("run against vulnerable");
    assert!(
        result.passed,
        "PoC must pass against the vulnerable target; outcomes: {:?}",
        result.evaluated
    );

    // Patched target: the quote is HTML-escaped, so the marker word is absent →
    // the `all` success is false even though the stub browser still answers.
    let patched = spawn(TargetMode::Patched);
    let store2 = Arc::new(MemFlowStore::new());
    let guard2 = Arc::new(guard_scoping(patched));
    let client2 = pipeline_client(&store2, &guard2);
    let browser2 = StubBrowser {
        eval_value: Value::Str("MARK1234".to_string()),
    };
    let host2 = CommandHost::new(store2.as_ref(), &client2, guard2.as_ref(), Some(&browser2));
    let result2 = StdPocRunner::new()
        .run(&poc, example1_bindings(patched), &host2)
        .await
        .expect("run against patched");
    assert!(
        !result2.passed,
        "PoC must fail against the patched target; outcomes: {:?}",
        result2.evaluated
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_artifacts() {
    let poc: Poc = serde_yaml::from_str(example1_yaml()).expect("parse example 1");
    let vuln = spawn(TargetMode::Vulnerable);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(guard_scoping(vuln));
    let client = pipeline_client(&store, &guard);
    let browser = StubBrowser {
        eval_value: Value::Str("MARK1234".to_string()),
    };
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser));

    let result = StdPocRunner::new()
        .run(&poc, example1_bindings(vuln), &host)
        .await
        .expect("run");

    // (1) finding capture: a valid FlowId present in the store.
    assert!(
        store.get(result.finding_capture).is_some(),
        "finding_capture must be a flow in the store"
    );

    // (2) the PoC file re-parses as the same Poc.
    let written = std::fs::read_to_string(&result.poc_path).expect("read poc file");
    let reparsed: Poc = serde_yaml::from_str(&written).expect("re-parse poc file");
    assert_eq!(reparsed, poc, "written PoC must round-trip to the same Poc");

    // (3) the screenshot starts with the PNG magic.
    let png = std::fs::read(&result.screenshot_path).expect("read screenshot");
    assert!(
        png.starts_with(&PNG_MAGIC),
        "screenshot must be a PNG, got first bytes: {:?}",
        &png[..png.len().min(8)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_navigate_to_private_off_scope_is_refused() {
    // A browser-only PoC that navigates to a loopback target not in scope: the
    // SSRF pre-flight refuses it before the driver is touched.
    let yaml = r#"
id: ssrf-navigate
info:
  name: navigate SSRF guard
  severity: low
steps:
  - browser:
      action: navigate
      url: "http://127.0.0.1:9/"
success:
  type: status
  status: 200
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("parse");
    let store = Arc::new(MemFlowStore::new());
    // Empty scope: 127.0.0.1 is loopback and not explicitly in scope.
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    let client = pipeline_client(&store, &guard);
    let browser = StubBrowser {
        eval_value: Value::Null,
    };
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser));
    let err = StdPocRunner::new()
        .run(&poc, VarBindings::new(), &host)
        .await
        .expect_err("off-scope loopback navigation must be refused");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("scope") || msg.contains("private") || msg.contains("loopback"),
        "error must be an SSRF/scope refusal, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_step_out_of_scope_is_refused() {
    let poc: Poc = serde_yaml::from_str(example1_yaml()).expect("parse example 1");
    let vuln = spawn(TargetMode::Vulnerable);
    let store = Arc::new(MemFlowStore::new());
    // Guard with NO scope entry → the http step must be refused by the client.
    let guard = Arc::new(StdGuard::new(LimitConfig::default()));
    let client = pipeline_client(&store, &guard);
    let browser = StubBrowser {
        eval_value: Value::Null,
    };
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser));

    let err = StdPocRunner::new()
        .run(&poc, example1_bindings(vuln), &host)
        .await
        .expect_err("out-of-scope run must error");
    assert!(
        err.to_string().to_lowercase().contains("scope"),
        "error must mention scope, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extract_binds_variable_for_a_later_assertion() {
    // An http step whose body carries a token; an extract step binds it; the
    // top-level `success` is a DSL assertion that reads the bound variable.
    let yaml = r#"
id: extract-chain
info:
  name: Extractor binds a variable
  severity: low
steps:
  - http:
      method: GET
      url: "{{target}}/search?q=token-ABC123-end"
  - extract:
      name: token
      type: regex
      regex: "token-([A-Z0-9]+)-end"
      group: 1
success:
  type: dsl
  dsl: "token == \"ABC123\""
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("parse extract poc");
    let vuln = spawn(TargetMode::Vulnerable);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(guard_scoping(vuln));
    let client = pipeline_client(&store, &guard);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let result = StdPocRunner::new()
        .run(&poc, example1_bindings(vuln), &host)
        .await
        .expect("run extract chain");
    assert!(
        result.passed,
        "extracted token must satisfy the DSL success; outcomes: {:?}",
        result.evaluated
    );
}

/// poc.run opens the PoC file with `O_NOFOLLOW`, so a symlinked path is refused
/// (closing the stat/open TOCTOU). It bails before any network or browser work,
/// so this needs no target server.
#[cfg(unix)]
#[test]
fn poc_run_refuses_a_symlinked_poc_file() {
    use aitm_core::{Command, HttpFlow, Params};

    struct NoClient;
    impl aitm_core::ProxyClient for NoClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("unused") })
        }
    }

    let dir = std::env::temp_dir().join(format!("aitm-poc-toctou-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let real = dir.join("real.yaml");
    std::fs::write(
        &real,
        "id: demo\ninfo:\n  name: n\nsteps: []\nsuccess:\n  type: status\n  status: 200\n",
    )
    .expect("write real");
    let link = dir.join("link.yaml");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let store = MemFlowStore::new();
    let client = NoClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);

    let args = Params::new(
        [(
            "poc_path".to_string(),
            Value::Str(link.display().to_string()),
        )]
        .into_iter()
        .collect(),
    );
    let err = PocRunCommand
        .invoke(args, &host)
        .expect_err("a symlinked PoC path must be refused");
    assert!(
        err.to_string().contains("cannot open"),
        "want an open refusal, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Opt-in PoC-dir confinement: with a configured dir, a PoC file outside it is
/// refused (bails before any network). Unconfigured, loading is unconstrained.
#[cfg(unix)]
#[test]
fn poc_run_confines_to_configured_dir() {
    use aitm_core::{Command, HttpFlow, Params};

    struct NoClient;
    impl aitm_core::ProxyClient for NoClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("unused") })
        }
    }

    let base = std::env::temp_dir().join(format!("aitm-poc-confine-{}", std::process::id()));
    let inside = base.join("pocs");
    std::fs::create_dir_all(&inside).expect("mkdir inside");
    let outside = base.join("outside.yaml");
    std::fs::write(
        &outside,
        "id: demo\ninfo:\n  name: n\nsteps: []\nsuccess:\n  type: status\n  status: 200\n",
    )
    .expect("write outside");

    let store = MemFlowStore::new();
    let client = NoClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None).with_poc_dir(Some(inside.clone()));

    let args = Params::new(
        [(
            "poc_path".to_string(),
            Value::Str(outside.display().to_string()),
        )]
        .into_iter()
        .collect(),
    );
    let err = PocRunCommand
        .invoke(args, &host)
        .expect_err("a PoC outside the configured dir must be refused");
    assert!(
        err.to_string()
            .contains("outside the configured PoC directory"),
        "want a confinement refusal, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// poc.run's artifacts land under the configured output dir, and `poc.artifact`
/// reads a real one back (the F13 round-trip).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_honors_out_dir_and_artifact_reads_it_back() {
    use aitm_core::{Config, PocConfig};

    let poc: Poc = serde_yaml::from_str(example1_yaml()).expect("parse example 1");
    let vuln = spawn(TargetMode::Vulnerable);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(guard_scoping(vuln));
    let client = pipeline_client(&store, &guard);
    let browser = StubBrowser {
        eval_value: Value::Str("MARK1234".to_string()),
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let out_dir =
        std::env::temp_dir().join(format!("aitm-poc-outdir-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();

    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser));
    let result = StdPocRunner::with_output_dir(out_dir.clone())
        .run(&poc, example1_bindings(vuln), &host)
        .await
        .expect("run");

    // Artifacts are written under the configured out-dir.
    assert!(
        result.poc_path.starts_with(&out_dir),
        "poc artifact must be under out_dir: {}",
        result.poc_path.display()
    );
    assert!(
        result.screenshot_path.starts_with(&out_dir),
        "screenshot must be under out_dir: {}",
        result.screenshot_path.display()
    );

    // poc.artifact, confined to the same out-dir, reads the YAML copy back.
    let cfg = Config {
        poc: PocConfig {
            dir: None,
            out_dir: Some(out_dir.clone()),
        },
        ..Config::default()
    };
    let read_host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), Some(&browser))
        .with_config(Arc::new(cfg));
    let mut reg = aitm_core::Registry::new();
    aitm_poc::library::register(&mut reg);
    let mut args = std::collections::BTreeMap::new();
    args.insert(
        "path".to_string(),
        Value::Str(result.poc_path.display().to_string()),
    );
    let bytes = reg
        .command("poc.artifact")
        .unwrap()
        .invoke(aitm_core::Params::new(args), &read_host)
        .expect("poc.artifact reads the written YAML");
    match bytes {
        Value::Bytes(b) => assert!(!b.is_empty(), "artifact bytes must be non-empty"),
        other => panic!("poc.artifact must return bytes, got {other:?}"),
    }
}
