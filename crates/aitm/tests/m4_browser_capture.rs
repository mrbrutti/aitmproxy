//! M4 Task 14 — multi-browser custom-proxy capture e2e (AC-M4-12, Review Focus
//! #5, spec §D6).
//!
//! For each real engine the environment enables — obscura (`AITM_OBSCURA`, with
//! `AITM_OBSCURA_BIN`), Chrome (`AITM_CHROME`), Firefox (`AITM_FIREFOX`, which
//! also needs `certutil` on `PATH`; `AITM_FIREFOX_BIN` overrides the binary) —
//! this drives the hermetic [`aitm-testtarget`](aitm_testtarget) through
//! aitmproxy as a **custom** upstream proxy and asserts the target's requests
//! land in the flow store as captured flows. The negative leg points the browser
//! somewhere other than aitmproxy and asserts nothing is captured — proof the
//! positive capture happened because the browser was explicitly pointed at
//! aitmproxy's custom proxy, not because aitmproxy is the OS proxy.
//!
//! With none of the three variables set the engine list is empty and both tests
//! return early, so the default `cargo test` stays hermetic (no real browser, no
//! port binding, no network). Run them for real with, e.g.:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura AITM_CHROME=1 AITM_FIREFOX=1 \
//!   cargo test -p aitm --test m4_browser_capture -- --nocapture
//! ```
//!
//! Each engine routes through aitmproxy per spec §D6: obscura/Chrome by a
//! per-process `--proxy-server`, Firefox by the throwaway-profile proxy prefs.
//! The target is plain-HTTP loopback, so the browser-facing listener's SSRF
//! guard only forwards it because its `host:port` is in scope (same posture as
//! the obscura MITM e2e). One engine runs at a time ([`engine_lock`]): several
//! browsers racing would make the start timeouts a function of host load.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aitm::wire::{assemble, Assembled};
use aitm_browser::{launch_owned, LaunchedBrowser};
use aitm_core::{
    engine_may_reach_private, BrowserConfig, BrowserEngine, Config, FirefoxConfig, Flow, FlowStore,
    HttpFlow, ObscuraConfig, ScopeEntry,
};
use aitm_testtarget::{SeedMode, TestTarget};
use tokio::net::TcpStream;

/// The eight-byte PNG signature: a screenshot the engine produced starts with it.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// How long the positive leg waits for the navigated page's flow to appear
/// (spec §D11, matching the obscura MITM e2e).
const CAPTURE_WAIT: Duration = Duration::from_secs(10);

/// How long the negative leg lets a stray flow show up before asserting none
/// did. The browser cannot reach aitmproxy there, so this only bounds a mis-route;
/// a short settle keeps the test quick.
const NO_CAPTURE_SETTLE: Duration = Duration::from_secs(3);

// ---- gating -----------------------------------------------------------------

/// The engines this environment enables, each behind its own run-time gate, in a
/// fixed order. Empty (and a skip notice) when none is set, keeping the default
/// suite hermetic — the pattern of `AITM_OBSCURA`/`AITM_CHROME`/`AITM_FIREFOX`
/// across the other real-browser tests.
fn enabled_engines() -> Vec<BrowserEngine> {
    let mut engines = Vec::new();
    if std::env::var_os("AITM_OBSCURA").is_some() {
        engines.push(BrowserEngine::Obscura);
    }
    if std::env::var_os("AITM_CHROME").is_some() {
        engines.push(BrowserEngine::Chrome);
    }
    if std::env::var_os("AITM_FIREFOX").is_some() {
        engines.push(BrowserEngine::Firefox);
    }
    if engines.is_empty() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (with AITM_OBSCURA_BIN), AITM_CHROME=1, and/or \
             AITM_FIREFOX=1 (with certutil on PATH) to run the multi-browser capture e2e"
        );
    } else {
        // Visible under `--nocapture`: which engines this run exercised.
        eprintln!("engines enabled: {engines:?}");
    }
    engines
}

/// One real engine at a time across both tests: each launches a browser, and the
/// obscura/Firefox start timeouts are a function of host load if several race.
fn engine_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

// ---- config and temp CA -----------------------------------------------------

/// A `BrowserConfig` for `engine` routed through `proxy`, taking the obscura and
/// Firefox binaries from `AITM_OBSCURA_BIN` / `AITM_FIREFOX_BIN` (unset → the
/// obscura discovery order and the `firefox`-on-`PATH` default).
fn config_for(engine: BrowserEngine, proxy: SocketAddr) -> BrowserConfig {
    BrowserConfig {
        engine,
        obscura: ObscuraConfig {
            binary: std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from),
            ..ObscuraConfig::default()
        },
        firefox: FirefoxConfig {
            binary: std::env::var_os("AITM_FIREFOX_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("firefox")),
            ..FirefoxConfig::default()
        },
        proxy_addr: proxy,
        ..BrowserConfig::default()
    }
}

/// A fresh directory under the OS temp dir for the proxy CA, unique per call and
/// removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aitm-m4-capture-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp CA dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- the rig: aitmproxy's browser-facing listener + the engine --------------

/// A standing aitmproxy whose browser-facing listener is up, with `engine`
/// launched and routed at `browser_proxy`. `browser_proxy` is aitmproxy's own
/// listener in the positive leg and a dead port in the negative one — the only
/// difference between the two.
struct Rig {
    store: std::sync::Arc<dyn FlowStore>,
    browser: LaunchedBrowser,
    // Kept alive for the run: dropping it deletes the CA directory.
    _ca_dir: TempDir,
}

impl Rig {
    /// Assemble the proxy with `target_authority` in scope, run its browser-facing
    /// listener on `listen`, and launch `engine` pointed at `browser_proxy`
    /// (trusting the generated MITM CA). Both addresses are the caller's: the
    /// positive leg passes `listen == browser_proxy` so the engine's upstream is
    /// the live listener; the negative leg passes a live `listen` and a separate,
    /// dead `browser_proxy`.
    async fn start(
        tag: &str,
        engine: BrowserEngine,
        listen: SocketAddr,
        browser_proxy: SocketAddr,
        target_authority: &str,
    ) -> Rig {
        let ca_dir = TempDir::new(tag);

        let mut cfg = Config::default();
        cfg.ca.dir = ca_dir.path().to_path_buf();
        cfg.browser = config_for(engine, browser_proxy);
        cfg.scope.entries = vec![ScopeEntry {
            host: target_authority.to_string(),
        }];
        // The browser-facing listener's SSRF guard blocks loopback unless the
        // host is in scope; this e2e authorizes the loopback test target above.
        cfg.scope.allow_agent_widen = true;
        // Derive the engine's private-network flag from policy ∪ scope (audit
        // I15), exactly as `main` does: the scoped loopback target lifts it under
        // the strict default, so obscura can dial the proxy for it.
        cfg.browser.obscura.allow_private =
            engine_may_reach_private(&cfg.browser.ssrf, &cfg.scope.entries);

        let Assembled { proxy, ca, .. } = assemble(&cfg).expect("assemble the proxy");
        let store = proxy.store();
        tokio::spawn(async move {
            let _ = proxy.run_browser(listen).await;
        });
        wait_listening(listen).await;

        let browser = launch_owned(&cfg.browser, ca.cert_path())
            .await
            .unwrap_or_else(|err| panic!("[{engine:?}] launch through {browser_proxy}: {err:#}"));

        Rig {
            store,
            browser,
            _ca_dir: ca_dir,
        }
    }

    /// Poll the flow store until `done` holds or `deadline` passes; the final
    /// snapshot is returned either way so the caller's assertion can print it.
    async fn wait_for_flows(
        &self,
        timeout: Duration,
        done: impl Fn(&[HttpFlow]) -> bool,
    ) -> Vec<HttpFlow> {
        let deadline = Instant::now() + timeout;
        loop {
            let flows = http_flows(&*self.store);
            if done(&flows) || Instant::now() >= deadline {
                return flows;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn finish(self, engine: BrowserEngine) {
        self.browser
            .close()
            .await
            .unwrap_or_else(|err| panic!("[{engine:?}] close: {err:#}"));
    }
}

fn http_flows(store: &dyn FlowStore) -> Vec<HttpFlow> {
    store
        .list()
        .into_iter()
        .filter_map(|id| match store.get(id) {
            Some(Flow::Http(flow)) => Some(flow),
            _ => None,
        })
        .collect()
}

/// A captured 200 flow for `authority` + `path`, if one exists.
fn find_200<'a>(flows: &'a [HttpFlow], authority: &str, path: &str) -> Option<&'a HttpFlow> {
    flows.iter().find(|f| {
        f.request.authority == authority
            && f.request.path == path
            && f.response.as_ref().map(|r| r.status) == Some(200)
    })
}

/// Any captured flow addressed to `authority`, with or without a response. Used
/// by the negative leg: a bypassed request would show up here even if the proxy
/// never completed it.
fn any_flow_for(flows: &[HttpFlow], authority: &str) -> bool {
    flows.iter().any(|f| f.request.authority == authority)
}

/// One line per flow — `GET 127.0.0.1:1234/ -> 200` — for assertion messages.
fn describe(flows: &[HttpFlow]) -> String {
    if flows.is_empty() {
        return "  (no HTTP flows captured)".to_string();
    }
    flows
        .iter()
        .map(|f| {
            let status = f
                .response
                .as_ref()
                .map_or("(no response)".to_string(), |r| r.status.to_string());
            format!(
                "  {} {}{} -> {status}",
                f.request.method, f.request.authority, f.request.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

/// The `host:port` of an `http://host:port` base URL.
fn authority_of(base_url: &str) -> String {
    base_url
        .strip_prefix("http://")
        .unwrap_or(base_url)
        .to_string()
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "browser-facing listener {addr} never came up"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---- AC-M4-12 ---------------------------------------------------------------

/// For each enabled engine: the target, driven through aitmproxy as the custom
/// upstream proxy, lands in the flow store as a captured 200 flow, and the
/// engine produces a valid PNG screenshot. Because the store starts empty and
/// exactly one engine runs at a time, the captured flow was produced by that
/// browser (`HttpFlow` carries no per-browser tag; the single-engine rig is the
/// attribution). The Firefox leg's gate is capture + screenshot; `eval`/DOM are
/// best-effort and not asserted here (spec §D6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capture_through_custom_proxy_per_engine() {
    let engines = enabled_engines();
    if engines.is_empty() {
        return;
    }

    for engine in engines {
        let _serial = engine_lock().lock().await;
        let target = TestTarget::start(SeedMode::Vulnerable).await;
        let authority = authority_of(target.base_url());

        // The engine's upstream IS aitmproxy's browser-facing listener: bind the
        // listener and point the browser at the same address.
        let aitm_listen = free_addr();
        let rig = Rig::start("pos", engine, aitm_listen, aitm_listen, &authority).await;

        let url = format!("{}/", target.base_url());
        rig.browser
            .driver
            .navigate(&url)
            .await
            .unwrap_or_else(|err| panic!("[{engine:?}] navigate {url}: {err:#}"));

        let flows = rig
            .wait_for_flows(CAPTURE_WAIT, |flows| {
                find_200(flows, &authority, "/").is_some()
            })
            .await;
        assert!(
            find_200(&flows, &authority, "/").is_some(),
            "[{engine:?}] GET http://{authority}/ was not captured within {CAPTURE_WAIT:?}; \
             the target's requests did not go through aitmproxy's custom proxy. Captured:\n{}",
            describe(&flows)
        );

        let png = rig
            .browser
            .driver
            .screenshot()
            .await
            .unwrap_or_else(|err| panic!("[{engine:?}] screenshot: {err:#}"));
        assert!(
            png.starts_with(PNG_MAGIC),
            "[{engine:?}] screenshot is not a PNG ({} bytes)",
            png.len()
        );

        rig.finish(engine).await;
    }
}

// ---- Review Focus #5 (negative control) -------------------------------------

/// For each enabled engine: with aitmproxy standing and listening but the browser
/// pointed at a different, dead loopback port (no custom proxy at aitmproxy), the
/// target navigation reaches aitmproxy's store **not at all** — zero target
/// flows. This proves the positive capture occurs only because the browser was
/// explicitly pointed at aitmproxy's custom proxy, and that aitmproxy is not
/// silently the OS proxy catching traffic routed around it (spec §D6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_capture_without_custom_proxy() {
    let engines = enabled_engines();
    if engines.is_empty() {
        return;
    }

    for engine in engines {
        let _serial = engine_lock().lock().await;
        let target = TestTarget::start(SeedMode::Vulnerable).await;
        let authority = authority_of(target.base_url());

        // aitmproxy's browser-facing listener comes up on its own live port, but
        // the browser is pointed at a separate free loopback port with nothing
        // listening — i.e. the custom proxy is effectively unset.
        let aitm_listen = free_addr();
        let dead_proxy = free_addr();
        let rig = Rig::start("neg", engine, aitm_listen, dead_proxy, &authority).await;

        // The navigation cannot succeed (its proxy is dead); tolerate the error.
        // What matters is whether anything reached aitmproxy's store.
        let url = format!("{}/", target.base_url());
        let _ = rig.browser.driver.navigate(&url).await;

        let flows = rig
            .wait_for_flows(NO_CAPTURE_SETTLE, |flows| any_flow_for(flows, &authority))
            .await;
        assert!(
            !any_flow_for(&flows, &authority),
            "[{engine:?}] aitmproxy captured a flow for {authority} though the browser was not \
             pointed at its custom proxy — traffic reached aitmproxy by another route (OS proxy?). \
             Captured:\n{}",
            describe(&flows)
        );

        rig.finish(engine).await;
    }
}
