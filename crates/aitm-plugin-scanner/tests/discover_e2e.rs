//! Obscura-gated end-to-end test for `scan.discover`.
//!
//! It serves the bundled multi-vuln `aitm-testtarget` (vulnerable seed), scopes
//! its loopback host, drives `scan.discover` through the embedded obscura engine
//! routed via the proxy, and asserts the discovered endpoints cover the seeded
//! paths and that the `q` query parameter shows up as an injection point.
//!
//! Gated on a real browser the M4 way (`crates/aitm/tests/support/rig.rs`):
//! with `AITM_OBSCURA` unset the test returns early, so the default `cargo test`
//! stays hermetic and fast. Run it for real with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm-plugin-scanner --test discover_e2e -- --nocapture
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm::wire::{assemble, Assembled};
use aitm_browser::launch;
use aitm_core::{
    engine_may_reach_private, CommandHost, Config, HttpFlow, HttpRequest, Params, ProxyClient,
    Registry, ScopeEntry, Value,
};
use aitm_plugin_scanner::{ScannerConfig, ScannerPlugin};
use aitm_testtarget::{SeedMode, TestTarget};
use futures::future::BoxFuture;
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

/// Whether the environment enables the real obscura engine (`AITM_OBSCURA=1`,
/// with `AITM_OBSCURA_BIN`). Prints the skip note when it does not — a local
/// copy of `rig.rs::obscura_enabled`, so this crate takes no test-support dep.
fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!("skipped; set AITM_OBSCURA=1 (with AITM_OBSCURA_BIN) to run the discovery e2e");
        return false;
    }
    true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scan_discover_end_to_end() {
    if !obscura_enabled() {
        return;
    }

    // The deliberately-vulnerable target, on its own loopback origin.
    let target = TestTarget::start(SeedMode::Vulnerable).await;
    let target_url = target.base_url().to_string();
    let authority = target_url
        .strip_prefix("http://")
        .expect("loopback http target")
        .to_string();

    // A proxy that MITMs the target as an HTTPS origin; the engine routes through
    // its browser-facing listener.
    let mut cfg = Config::default();
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-scan-ca-{}", std::process::id()));
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
    let listen = cfg.browser.proxy_addr;
    tokio::spawn(async move {
        let _ = proxy.run_browser(listen).await;
    });
    wait_listening(listen).await;

    let driver = launch(&cfg.browser, ca.cert_path())
        .await
        .expect("launch obscura through the proxy");

    // The public command path: register the scanner plugin and resolve the
    // command from the registry, exactly as a frontend would.
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ScannerPlugin::new(ScannerConfig::default())));
    let cmd = reg
        .command("scan.discover")
        .expect("scan.discover registered")
        .clone();

    // `invoke` is synchronous and blocks on the crawl internally, so run it off
    // the reactor via spawn_blocking while the multi-thread runtime turns the
    // browser futures.
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let guard = guard.clone();
        let driver = driver.clone();
        let target_url = target_url.clone();
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
}
