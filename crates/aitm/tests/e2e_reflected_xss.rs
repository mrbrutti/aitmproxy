//! Task 29 / AC18: the reflected-XSS reproduction driven **entirely over MCP**
//! against the bundled vulnerable/patched target, with a real headless Chrome.
//!
//! `#[ignore = "needs Chromium"]`: run explicitly (and single-threaded, so only
//! one Chrome launches at a time):
//!
//! ```text
//! cargo test -p aitm --test e2e_reflected_xss -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Flow: `scope.add` the target, then `poc.run` a parameterized Example-1 PoC
//! (its http step captures the finding; its browser step drives Chrome through
//! the proxy and evaluates the marker) → `passed == true` and the three artifacts
//! against the vulnerable target, `passed == false` against the patched one.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use aitm::wire::{build_proxy, Http1Sender};
use aitm_browser::ChromeDriver;
use aitm_core::{BrowserDriver, Config, McpTransport, PipelineClient, ProxyClient, ScopeEntry};
use aitm_mcp::McpServer;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value as JsonValue};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy)]
enum Mode {
    Vulnerable,
    Patched,
}

/// The bundled reflected-XSS target: `GET /search?q=…` reflects `q` raw
/// (vulnerable) or HTML-escaped (patched).
async fn spawn_target(mode: Mode) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| handle(req, mode)))
                    .await;
            });
        }
    });
    addr
}

async fn handle(req: Request<Incoming>, mode: Mode) -> Result<Response<Full<Bytes>>, Infallible> {
    let raw = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&').find_map(|p| {
                let (k, v) = p.split_once('=')?;
                (k == "q").then(|| percent_decode(v))
            })
        })
        .unwrap_or_default();
    let reflected = match mode {
        Mode::Vulnerable => raw,
        Mode::Patched => aitm_poc::dsl::html_escape(&raw),
    };
    let body = format!("<html><body><h1>Results for {reflected}</h1></body></html>");
    Ok(Response::new(Full::new(Bytes::from(body))))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The Example-1 reflected-XSS PoC, with a fixed marker for deterministic
/// assertions. `target` is supplied at run time.
fn example1_poc() -> &'static str {
    r#"
id: reflected-xss-search-q
info:
  name: Reflected XSS in search 'q' parameter
  severity: high
  cwe: CWE-79
variables:
  - name: target
    required: true
  - name: param
    default: q
  - name: marker
    default: E2EMARKER
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

fn rpc(server: &McpServer, id: u64, method: &str, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let resp = server.handle(&req.to_string()).expect("a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Chromium"]
async fn reflected_xss_over_mcp() {
    // Write the PoC to a temp file (poc.run loads it by path).
    let poc_path = std::env::temp_dir().join(format!("aitm-e2e-{}.poc.yaml", std::process::id()));
    std::fs::write(&poc_path, example1_poc()).expect("write poc");

    let vuln = run_case(Mode::Vulnerable, &poc_path).await;
    assert!(vuln, "the PoC must pass against the vulnerable target");

    let patched = run_case(Mode::Patched, &poc_path).await;
    assert!(!patched, "the PoC must fail against the patched target");
}

/// Stand up target + proxy + real browser + MCP server, drive the PoC entirely
/// over MCP, and return `passed`. Also asserts the three artifacts on a pass.
async fn run_case(mode: Mode, poc_path: &std::path::Path) -> bool {
    let target = spawn_target(mode).await;
    let target_authority = target.to_string();

    // A browser-facing proxy listener; the browser routes through it (SSRF-guarded).
    let browser_listen = free_addr();
    let mut cfg = Config::default();
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-e2e-ca-{}", std::process::id()));
    cfg.browser.proxy_addr = browser_listen;
    cfg.scope.entries = vec![ScopeEntry {
        host: target_authority.clone(),
    }];
    let proxy = build_proxy(&cfg).expect("build proxy");

    let store = proxy.store();
    let guard = proxy.guard();
    let registry = proxy.registry_arc();
    let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
        store.clone(),
        guard.clone(),
        Arc::new(Http1Sender::new()),
    ));

    // Run the browser-facing accept loop so Chrome can reach the target through it.
    tokio::spawn(async move {
        let _ = proxy.run_browser(browser_listen).await;
    });
    wait_listening(browser_listen).await;

    // A real headless Chrome routed through the proxy.
    let driver: Arc<dyn BrowserDriver> = Arc::new(
        ChromeDriver::launch(&cfg.browser)
            .await
            .expect("launch Chrome (Google Chrome must be installed)"),
    );

    let server = McpServer::new(registry, McpTransport::Stdio).with_services(
        store.clone(),
        client,
        guard,
        Some(driver),
    );
    let server = Arc::new(server);

    // scope.add over MCP.
    let added = rpc(
        &server,
        1,
        "tools/call",
        json!({"name": "scope.add", "arguments": {"host": target_authority}}),
    );
    assert_eq!(
        added["result"]["isError"],
        json!(false),
        "scope.add: {added}"
    );

    // poc.run over MCP. It drives a real browser (block_on inside), so run it off
    // the runtime thread via spawn_blocking; the multi-thread reactor polls the
    // browser futures.
    let server2 = server.clone();
    let path = poc_path.display().to_string();
    let target_url = format!("http://{target_authority}");
    let resp = tokio::task::spawn_blocking(move || {
        rpc(
            &server2,
            2,
            "tools/call",
            json!({"name": "poc.run", "arguments": {
                "poc_path": path,
                "target": target_url,
            }}),
        )
    })
    .await
    .expect("poc.run task");

    assert_eq!(
        resp["result"]["isError"],
        json!(false),
        "poc.run failed: {resp}"
    );
    let sc = &resp["result"]["structuredContent"];
    let passed = sc["passed"].as_bool().expect("passed field");

    if passed {
        // The three artifacts, for the vulnerable run.
        let finding = sc["finding_capture"].as_str().expect("finding id");
        let fid: aitm_core::FlowId = finding.parse().expect("valid flow id");
        assert!(
            store.get(fid).is_some(),
            "finding capture must be in the store"
        );

        let poc_path = sc["poc_path"].as_str().expect("poc_path");
        let written = std::fs::read_to_string(poc_path).expect("read poc artifact");
        let _: aitm_poc::Poc = serde_yaml::from_str(&written).expect("poc artifact re-parses");

        let shot = sc["screenshot_path"].as_str().expect("screenshot_path");
        let png = std::fs::read(shot).expect("read screenshot");
        assert!(
            png.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n']),
            "screenshot must be a PNG"
        );
    }

    passed
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "listener never came up"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
