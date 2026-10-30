//! Obscura-gated end-to-end tests for `scan.discover`.
//!
//! Each test serves the bundled multi-vuln `aitm-testtarget` (vulnerable seed),
//! scopes its loopback host and drives `scan.discover` through the embedded
//! obscura engine routed via the proxy:
//!
//! - `scan_discover_end_to_end`: the discovered endpoints cover the seeded
//!   paths, the `q` query parameter and the redirector's `next` parameter show
//!   up as injection points, and a re-scan returns the same points instead of
//!   accumulating them;
//! - `scan_discover_three_times_reuses_the_browser`: sequential scans in one
//!   session all crawl (the browser needs no reset between them);
//! - `scan_discover_over_the_web_bridge_returns`: the result reaches a `/bus`
//!   WebSocket client, as the web Scan panel drives it.
//!
//! Gated on a real browser the M4 way, through the shared rig's
//! [`obscura_enabled`](rig::obscura_enabled): with `AITM_OBSCURA` unset each test
//! returns early, so the default `cargo test` stays hermetic and fast. Run them
//! for real with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm --test discover_e2e -- --nocapture
//! ```
//!
//! It lives here, beside the rig, rather than in `aitm-plugin-scanner/tests/`:
//! it needs `aitm::wire::assemble`, and a dev-dependency on `aitm` from a crate
//! `aitm` itself depends on would close a crate-graph cycle.

// The rig's two sibling support modules, which `rig.rs` refers to by crate path.
#[path = "../../aitm-browser/tests/support/engines.rs"]
#[allow(dead_code)]
mod engines;
#[path = "support/rig.rs"]
#[allow(dead_code)]
mod rig;
#[path = "support/scripted_driver.rs"]
#[allow(dead_code)]
mod scripted_driver;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm::wire::{assemble, Assembled};
use aitm_browser::launch;
use aitm_core::{
    engine_may_reach_private, CommandHost, Config, HttpFlow, HttpRequest, McpTransport, Params,
    ProxyClient, ScopeEntry, Value,
};
use aitm_testtarget::{SeedMode, TestTarget};
use futures::future::BoxFuture;
use rig::obscura_enabled;
use tokio::net::TcpStream;

/// A `ProxyClient` the command never reaches: discovery crawls through the
/// browser, not the proxy client.
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("scan.discover must not send through the proxy client") })
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    )
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "listener never came up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Everything one end-to-end scan needs: the vulnerable target, the proxy's
/// store and guard, the launched engine, and the `scan.discover` the proxy's own
/// registry serves (the same instance every frontend reaches).
struct ScanRig {
    /// Held so the target keeps serving, and the CA directory existing, for the
    /// rig's lifetime. The directory is the rig's own: the tests in this binary
    /// run on parallel threads and `CertAuthority::load_or_generate` is not safe
    /// to race on one directory.
    _target: TestTarget,
    _ca_dir: rig::TempDir,
    target_url: String,
    store: Arc<dyn aitm_core::FlowStore>,
    guard: Arc<dyn aitm_core::ScopeRateGuard>,
    driver: Arc<dyn aitm_core::BrowserDriver>,
    cmd: Arc<dyn aitm_core::Command>,
    /// The bus the web bridge relays into, built from the same shared services
    /// (and the same engine) as `main` does for `aitm web`.
    mcp: Arc<aitm_mcp::McpServer>,
}

async fn scan_rig() -> ScanRig {
    // The deliberately-vulnerable target, on its own loopback origin.
    let target = TestTarget::start(SeedMode::Vulnerable).await;
    let target_url = target.base_url().to_string();
    let authority = target_url
        .strip_prefix("http://")
        .expect("loopback http target")
        .to_string();

    // A proxy that MITMs the target as an HTTPS origin; the engine routes through
    // its browser-facing listener.
    let ca_dir = rig::TempDir::new("scan-ca");
    let mut cfg = Config::default();
    cfg.ca.dir = ca_dir.path().to_path_buf();
    cfg.ssl_insecure = true;
    cfg.browser.proxy_addr = free_addr();
    cfg.scope.entries = vec![ScopeEntry {
        host: authority.clone(),
    }];
    cfg.browser.obscura.binary = std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from);
    // Derive obscura's private-network flag from policy ∪ scope (audit I15), as
    // `main` does: the scoped loopback target lifts it under the strict default.
    cfg.browser.obscura.allow_private =
        engine_may_reach_private(&cfg.browser.ssrf, &cfg.scope.entries);

    let Assembled { proxy, ca, .. } = assemble(&cfg).expect("assemble the proxy");
    let store = proxy.store();
    let guard = proxy.guard();
    let mut services = aitm::tui::services(&proxy, &cfg, None, aitm::tui::TuiLog::Off);
    let listen = cfg.browser.proxy_addr;
    tokio::spawn(async move {
        let _ = proxy.run_browser(listen).await;
    });
    wait_listening(listen).await;
    let driver = launch(&cfg.browser, ca.cert_path())
        .await
        .expect("launch obscura through the proxy");

    // The public command path: resolve the command from the proxy's registry,
    // exactly as a frontend would, so `cmd` and `mcp` share one instance.
    let cmd = services
        .registry
        .command("scan.discover")
        .expect("scan.discover registered")
        .clone();

    services.browser = Some(driver.clone());
    let mcp = Arc::new(aitm::tui::server(&cfg, McpTransport::Stdio, &services));

    ScanRig {
        _target: target,
        _ca_dir: ca_dir,
        target_url,
        store,
        guard,
        driver,
        cmd,
        mcp,
    }
}

/// Run `scan.discover` against the rig's target once and return its result
/// object. `invoke` is synchronous and blocks on the crawl internally, so it
/// runs off the reactor via spawn_blocking while the multi-thread runtime turns
/// the browser futures.
async fn discover(rig: &ScanRig) -> std::collections::BTreeMap<String, Value> {
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let result = tokio::task::spawn_blocking({
        let store = rig.store.clone();
        let guard = rig.guard.clone();
        let driver = rig.driver.clone();
        let cmd = rig.cmd.clone();
        let target_url = rig.target_url.clone();
        move || {
            let host = CommandHost::new(
                store.as_ref(),
                client.as_ref(),
                guard.as_ref(),
                Some(&*driver),
            );
            cmd.invoke(params(&[("target", Value::Str(target_url))]), &host)
        }
    })
    .await
    .expect("scan.discover task")
    .expect("scan.discover succeeds");
    let Value::Object(result) = result else {
        panic!("scan.discover must return an object, got {result:?}");
    };
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scan_discover_end_to_end() {
    if !obscura_enabled() {
        return;
    }
    let rig = scan_rig().await;
    let result = discover(&rig).await;
    let Some(Value::Array(endpoints)) = result.get("endpoints") else {
        panic!("result must carry an endpoints array: {result:?}");
    };
    let endpoints: Vec<&str> = endpoints
        .iter()
        .filter_map(|v| match v {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    for seeded in [
        "/search",
        "/comments",
        "/fetch",
        "/account/",
        "/admin",
        "/redirect",
    ] {
        assert!(
            endpoints.iter().any(|e| e.contains(seeded)),
            "endpoints must reach {seeded}: {endpoints:?}"
        );
    }

    let Some(Value::Array(points)) = result.get("injection_points") else {
        panic!("result must carry an injection_points array: {result:?}");
    };
    let has_query_q = points.iter().any(|p| {
        let Value::Object(p) = p else { return false };
        p.get("location") == Some(&Value::Str("query".into()))
            && p.get("name") == Some(&Value::Str("q".into()))
    });
    assert!(
        has_query_q,
        "a query injection point named `q` must be discovered: {points:?}"
    );

    // `/redirect?next=/` itself 302s to `/`; the redirecting URL must still be a
    // reached endpoint, or the `next` parameter on it is never enumerated.
    let has_query_next = points.iter().any(|p| {
        let Value::Object(p) = p else { return false };
        p.get("location") == Some(&Value::Str("query".into()))
            && p.get("name") == Some(&Value::Str("next".into()))
    });
    assert!(
        has_query_next,
        "the redirector's `next` parameter must be discovered: {points:?}"
    );

    // A re-scan of the same site must return the same points, not those plus
    // the previous scan's captures: the same `(location, name)` multiset, which
    // also pins the count.
    let rescan = discover(&rig).await;
    let Some(Value::Array(rescan_points)) = rescan.get("injection_points") else {
        panic!("re-scan must carry an injection_points array: {rescan:?}");
    };
    assert_eq!(
        point_keys(rescan_points),
        point_keys(points),
        "a re-scan of the same site must return the same injection points, not accumulate"
    );
}

/// The `(location, name)` of every injection point, sorted, so two scans'
/// outputs compare as multisets.
fn point_keys(points: &[Value]) -> Vec<(String, String)> {
    let mut keys: Vec<(String, String)> = points
        .iter()
        .map(|p| {
            let Value::Object(p) = p else {
                panic!("an injection point must be an object: {p:?}");
            };
            match (p.get("location"), p.get("name")) {
                (Some(Value::Str(location)), Some(Value::Str(name))) => {
                    (location.clone(), name.clone())
                }
                _ => panic!("an injection point must carry a location and a name: {p:?}"),
            }
        })
        .collect();
    keys.sort();
    keys
}

/// The browser survives a scan: a later `scan.discover` in the same session must
/// crawl as well as the first, not stop at `navigation_failed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scan_discover_three_times_reuses_the_browser() {
    if !obscura_enabled() {
        return;
    }
    let rig = scan_rig().await;
    for run in 1..=3 {
        let result = discover(&rig).await;
        assert_ne!(
            result.get("stopped_reason"),
            Some(&Value::Str("navigation_failed".into())),
            "run {run} could not navigate: {result:?}"
        );
        let Some(Value::Array(endpoints)) = result.get("endpoints") else {
            panic!("run {run}: no endpoints array: {result:?}");
        };
        assert!(
            endpoints.len() > 1,
            "run {run} crawled only {} endpoint(s): {result:?}",
            endpoints.len()
        );
    }
}

/// `scan.discover` returns to a web-bridge client: the Scan panel drives it over
/// the `/bus` WebSocket, so a long-running command's result must reach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scan_discover_over_the_web_bridge_returns() {
    use futures::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tokio_tungstenite::tungstenite::Message;

    if !obscura_enabled() {
        return;
    }
    let rig = scan_rig().await;
    let operator = "b".repeat(64);
    let state = Arc::new(aitm::web::WebState {
        mcp: rig.mcp.clone(),
        agent_token: "a".repeat(64),
        operator_token: Some(operator.clone()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(aitm::web::serve(listener, state));

    let req = format!("ws://{addr}/bus")
        .into_client_request()
        .expect("request");
    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .expect("connect");
    let frame = |v: serde_json::Value| Message::text(format!("{v}\n"));
    ws.send(Message::text(format!(
        "{}\n",
        serde_json::json!({ "token": operator })
    )))
    .await
    .expect("token");
    ws.send(frame(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"aitm-web","version":"0"}}})))
        .await
        .expect("initialize");
    let init = ws
        .next()
        .await
        .expect("initialize reply")
        .expect("frame")
        .into_text()
        .expect("text frame");
    let init: serde_json::Value = serde_json::from_str(init.as_str()).expect("json reply");
    assert_eq!(init["id"], 1, "reply to initialize: {init}");
    assert!(init["result"].is_object(), "initialize succeeded: {init}");

    for run in 1..=2 {
        ws.send(frame(
            serde_json::json!({"jsonrpc":"2.0","id":10 + run,"method":"tools/call",
            "params":{"name":"scan.discover","arguments":{"target": rig.target_url}}}),
        ))
        .await
        .expect("send scan");
        let reply = tokio::time::timeout(Duration::from_secs(120), ws.next())
            .await
            .unwrap_or_else(|_| panic!("run {run}: scan.discover never answered over the bridge"))
            .expect("frame")
            .expect("ws ok");
        let text = reply.into_text().expect("text frame").to_string();
        let v: serde_json::Value = serde_json::from_str(&text).expect("json reply");
        assert_eq!(v["id"], 10 + run, "reply to the scan request: {text}");
        let n = v["result"]["structuredContent"]["endpoints"]
            .as_array()
            .map_or(0, Vec::len);
        assert!(n > 1, "run {run} reached only {n} endpoint(s): {text}");
    }
    server.abort();
}
