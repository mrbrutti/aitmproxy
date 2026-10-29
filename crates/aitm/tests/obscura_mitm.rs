//! M2 Task 24: the embedded obscura engine's HTTPS traffic is MITM'd and
//! captured through the SSRF-filtered browser listener — M2-AC10 (decrypted
//! navigation), M2-AC11 (sub-resources), M2-AC12 (no bypass path) and M2-AC15
//! (SSRF posture preserved).
//!
//! All four tests are `[obscura]`: part of the default suite but inert unless
//! `AITM_OBSCURA=1` is set, so `cargo test` stays hermetic. Run them for real
//! against the fork binary with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura cargo test -p aitm --test obscura_mitm
//! ```
//!
//! Each test assembles the real proxy (`assemble`), runs its browser-facing
//! listener, launches obscura with the proxy CA's certificate file, and drives
//! the `BrowserDriver` directly (M2-AC15 goes through the registered
//! `browser.navigate` command instead, since the guard it proves lives there).
//! Sub-resource flows may land after `navigate` returns, so the store is polled
//! for up to [`FLOW_WAIT`].

mod support {
    pub mod https_fixture;
}

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use aitm::wire::assemble;
use aitm_browser::{launch_owned, LaunchedBrowser};
use aitm_core::{
    Body, BrowserDriver, ClickTarget, Command, CommandHost, Config, Flow, FlowStore, GuardError,
    HttpFlow, HttpRequest, NavOutcome, Params, ProxyClient, Registry, ScopeEntry, ScopeRateGuard,
    Value,
};
use futures::future::BoxFuture;
use support::https_fixture::{HttpsFixture, PlainFixture, MARKER};
use tokio::net::TcpStream;
use tracing::{field::Field, span, Event, Level, Metadata};

/// How long a test waits for captured flows to appear (spec §D11).
const FLOW_WAIT: Duration = Duration::from_secs(10);

/// How long M2-AC12 gives the page to try the raw listener before asserting
/// that nothing reached it.
const BYPASS_WAIT: Duration = Duration::from_secs(5);

// ---- gating and process-wide fixtures ---------------------------------------

/// Run only when `AITM_OBSCURA=1` is set; otherwise skip inertly.
fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (and AITM_OBSCURA_BIN) to run the obscura MITM test"
        );
        return false;
    }
    true
}

/// One obscura engine at a time, as the lifecycle tests do: four engines
/// starting at once would make the 15 s start timeout a function of the host.
fn obscura_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// A fresh directory under the OS temp dir for the proxy CA; removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aitm-obscura-mitm-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
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

/// Every `tracing` event any thread emitted, as `(level, "field=value …")`.
/// The browser listener's refusals are logged from tokio worker tasks, which a
/// thread-local subscriber would miss, so one global capture is installed for
/// the whole test process and each test filters by its own ports.
static EVENTS: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());
static INSTALL_CAPTURE: Once = Once::new();

fn install_capture() {
    INSTALL_CAPTURE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Capture);
    });
}

fn captured_events() -> Vec<(Level, String)> {
    EVENTS.lock().expect("events").clone()
}

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        EVENTS
            .lock()
            .expect("events")
            .push((*event.metadata().level(), fields.0));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

// ---- the rig: proxy + browser listener + obscura + fixture ------------------

/// A `ProxyClient` no browser or scope command calls.
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

struct Rig {
    cfg: Config,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    registry: Arc<Registry>,
    browser: LaunchedBrowser,
    fixture: HttpsFixture,
    _ca_dir: TempDir,
}

impl Rig {
    /// Spec plan Task 24 setup: `ssl_insecure`, a free browser listener, the
    /// fixture authority in scope, the obscura binary from `AITM_OBSCURA_BIN`;
    /// then `assemble` → `run_browser` → `launch_owned` with the CA's cert file.
    async fn start(tag: &str, raw: Option<SocketAddr>) -> Self {
        install_capture();
        let fixture = HttpsFixture::spawn(raw).await;
        let ca_dir = TempDir::new(tag);

        let mut cfg = Config::default();
        cfg.ca.dir = ca_dir.path().to_path_buf();
        cfg.ssl_insecure = true;
        cfg.browser.proxy_addr = free_addr();
        cfg.scope.entries = vec![ScopeEntry {
            host: fixture.authority(),
        }];
        // These tests drive scope.add through the default (MCP) command host, so
        // they opt into agent scope-widening (F12 gate; off by default).
        cfg.scope.allow_agent_widen = true;
        cfg.browser.obscura.binary = std::env::var_os("AITM_OBSCURA_BIN").map(PathBuf::from);

        let assembled = assemble(&cfg).expect("assemble the proxy");
        let proxy = assembled.proxy;
        let store = proxy.store();
        let guard = proxy.guard();
        let registry = proxy.registry_arc();
        let listen = cfg.browser.proxy_addr;
        tokio::spawn(async move {
            let _ = proxy.run_browser(listen).await;
        });
        wait_listening(listen).await;

        let browser = launch_owned(&cfg.browser, assembled.ca.cert_path())
            .await
            .expect("launch obscura through the proxy");

        Self {
            cfg,
            store,
            guard,
            registry,
            browser,
            fixture,
            _ca_dir: ca_dir,
        }
    }

    fn driver(&self) -> Arc<dyn BrowserDriver> {
        self.browser.driver.clone()
    }

    /// Every captured HTTP flow, in insertion order.
    fn http_flows(&self) -> Vec<HttpFlow> {
        http_flows(&*self.store)
    }

    /// Poll the store every 100 ms until `done` holds for the snapshot or
    /// [`FLOW_WAIT`] passes; the final snapshot is returned either way so the
    /// caller's assertion can print it.
    async fn wait_for_flows(&self, done: impl Fn(&[HttpFlow]) -> bool) -> Vec<HttpFlow> {
        wait_for_flows(&*self.store, done).await
    }

    /// Graceful teardown: obscura closed (SIGTERM, then SIGKILL after
    /// `stop_timeout`) before the next test starts its own.
    async fn finish(self) {
        self.browser.close().await.expect("close obscura");
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

async fn wait_for_flows(
    store: &dyn FlowStore,
    done: impl Fn(&[HttpFlow]) -> bool,
) -> Vec<HttpFlow> {
    let deadline = Instant::now() + FLOW_WAIT;
    loop {
        let flows = http_flows(store);
        if done(&flows) || Instant::now() >= deadline {
            return flows;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// One line per flow — `GET https://localhost:1234/img.png -> 200` — for
/// assertion messages, so a failure says exactly what the proxy captured.
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
                "  {} {}://{}{} -> {status}",
                f.request.method, f.request.scheme, f.request.authority, f.request.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn status_of(flow: &HttpFlow) -> Option<u16> {
    flow.response.as_ref().map(|r| r.status)
}

fn body_text(body: &Body) -> String {
    match body {
        Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        Body::Empty | Body::Streamed(_) => String::new(),
    }
}

/// The captured flow for `authority` + `path` whose response status is 200.
fn find_200<'a>(flows: &'a [HttpFlow], authority: &str, path: &str) -> Option<&'a HttpFlow> {
    flows.iter().find(|f| {
        f.request.authority == authority && f.request.path == path && status_of(f) == Some(200)
    })
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "browser listener {addr} never came up"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---- M2-AC10 ----------------------------------------------------------------

/// Navigating obscura to the HTTPS fixture through the proxy stores a
/// **decrypted** flow — `https`, `GET /`, 200, the fixture's body — and
/// `navigate` reports the fixture URL as `final_url`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_navigation_is_decrypted() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start("ac10", None).await;
    let url = rig.fixture.url("/");

    let outcome: NavOutcome = rig
        .driver()
        .navigate(&url)
        .await
        .expect("navigate to the HTTPS fixture through the proxy");
    assert_eq!(outcome.final_url, url, "final_url is the fixture URL");

    let authority = rig.fixture.authority();
    let flows = rig
        .wait_for_flows(|flows| find_200(flows, &authority, "/").is_some())
        .await;
    let root = find_200(&flows, &authority, "/").unwrap_or_else(|| {
        panic!(
            "no decrypted 200 flow for GET https://{authority}/ within {FLOW_WAIT:?}; captured:\n{}",
            describe(&flows)
        )
    });
    assert_eq!(root.request.scheme, "https");
    assert_eq!(root.request.method, "GET");
    assert_eq!(root.request.path, "/");
    assert_eq!(status_of(root), Some(200));
    let body = root
        .response
        .as_ref()
        .map(|r| body_text(&r.body))
        .unwrap_or_default();
    assert!(
        body.contains(MARKER),
        "the decrypted response body must contain {MARKER:?}; got {body:?}"
    );

    rig.finish().await;
}

// ---- M2-AC11 ----------------------------------------------------------------

/// The `/` page's `<img>`, `fetch()` and XHR each produce a decrypted 200 flow
/// within 10 s of navigation. A missing `/img.png` means obscura's image loader
/// fetched outside the proxy (or not at all): that is the fork's Task 27, and
/// this test stays red until it lands — the criterion does not relax.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subresources_are_captured() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start("ac11", None).await;
    let authority = rig.fixture.authority();
    let mut expected = vec!["/"];
    expected.extend(HttpsFixture::subresource_paths());

    rig.driver()
        .navigate(&rig.fixture.url("/"))
        .await
        .expect("navigate to the HTTPS fixture through the proxy");

    let flows = rig
        .wait_for_flows(|flows| {
            expected
                .iter()
                .all(|path| find_200(flows, &authority, path).is_some())
        })
        .await;

    // What the page itself saw, for the report: which loaders ran at all.
    let page_state = rig
        .driver()
        .eval("JSON.stringify({img: window.__img, api: window.__api, xhr: window.__xhr})")
        .await
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|e| format!("(eval failed: {e:#})"));

    let (captured, missing): (Vec<&str>, Vec<&str>) = expected
        .iter()
        .partition(|path| find_200(&flows, &authority, path).is_some());
    // The evidence Task 27 hinges on, printed pass or fail (`--nocapture`).
    eprintln!(
        "[M2-AC11] captured {captured:?}; missing {missing:?}; page state {page_state}; flows:\n{}",
        describe(&flows)
    );
    assert!(
        missing.is_empty(),
        "sub-resources NOT captured as decrypted 200 flows within {FLOW_WAIT:?}: {missing:?} \
         (captured: {captured:?}; page state {page_state}); all flows:\n{}",
        describe(&flows)
    );

    rig.finish().await;
}

// ---- M2-AC12 ----------------------------------------------------------------

/// A page referencing a raw loopback listener (not the proxy, not in scope) via
/// `<img>` and `fetch()`: the raw listener accepts **zero** connections, every
/// flow for it is request-only, and the browser listener's
/// `PrivateAddressBlocked` refusal for its address was logged — i.e. the
/// requests went to the proxy and were refused there, not around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_bypass_path() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let raw = PlainFixture::spawn().await;
    let rig = Rig::start("ac12", Some(raw.addr)).await;
    let raw_authority = raw.addr.to_string();
    let raw_paths = ["/x.png", "/y"];

    rig.driver()
        .navigate(&rig.fixture.url("/"))
        .await
        .expect("navigate to the HTTPS fixture through the proxy");
    tokio::time::sleep(BYPASS_WAIT).await;

    assert_eq!(
        raw.accepted(),
        0,
        "the raw listener {raw_authority} accepted connections: a request bypassed the proxy"
    );

    let flows = rig.http_flows();
    let raw_flows: Vec<&HttpFlow> = flows
        .iter()
        .filter(|f| f.request.authority == raw_authority)
        .collect();
    for flow in &raw_flows {
        assert!(
            raw_paths.contains(&flow.request.path.as_str()),
            "unexpected raw-listener path {}; all flows:\n{}",
            flow.request.path,
            describe(&flows)
        );
        assert!(
            flow.response.is_none(),
            "flow for http://{raw_authority}{} has a response: the proxy let it through; all flows:\n{}",
            flow.request.path,
            describe(&flows)
        );
    }

    // The refusal is only in `tracing` (spec M2-AC12): the connection handler
    // reports the `GuardError::PrivateAddressBlocked` the browser connector
    // returned, whose text names the blocked host.
    let refusal = GuardError::PrivateAddressBlocked(raw.addr.ip().to_string()).to_string();
    let events = captured_events();
    let refusals: Vec<&(Level, String)> = events
        .iter()
        .filter(|(level, text)| *level == Level::WARN && text.contains(&refusal))
        .collect();
    assert!(
        !refusals.is_empty(),
        "no WARN event carried the refusal {refusal:?}; raw-listener flows: {:?}; all flows:\n{}",
        raw_flows
            .iter()
            .map(|f| f.request.path.as_str())
            .collect::<Vec<_>>(),
        describe(&flows)
    );

    rig.finish().await;
}

// ---- M2-AC15 ----------------------------------------------------------------

/// Counts `navigate` calls so a test can prove the guard refused **before** the
/// driver was touched; everything else is delegated to the real engine.
struct CountingDriver {
    inner: Arc<dyn BrowserDriver>,
    navigations: AtomicUsize,
}

impl CountingDriver {
    fn navigations(&self) -> usize {
        self.navigations.load(Ordering::SeqCst)
    }
}

impl BrowserDriver for CountingDriver {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        self.navigations.fetch_add(1, Ordering::SeqCst);
        self.inner.navigate(url)
    }
    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        self.inner.click(target)
    }
    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        self.inner.type_text(selector, text)
    }
    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        self.inner.screenshot()
    }
    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        self.inner.eval(expr)
    }
    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        self.inner.get_dom()
    }
}

fn params(pairs: &[(&str, &str)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::Str(v.to_string())))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Invoke a registered command the way a frontend does. `browser.navigate`
/// `block_on`s the driver, so this runs off the runtime thread.
async fn invoke(
    rig: &Rig,
    driver: Arc<CountingDriver>,
    name: &str,
    args: Params,
) -> anyhow::Result<Value> {
    let command: Arc<dyn Command> = rig
        .registry
        .command(name)
        .unwrap_or_else(|| panic!("{name} is not registered"))
        .clone();
    let store = rig.store.clone();
    let guard = rig.guard.clone();
    let ssrf = rig.cfg.browser.ssrf.clone();
    tokio::task::spawn_blocking(move || {
        let host =
            CommandHost::new(&*store, &UnusedClient, &*guard, Some(&*driver)).with_ssrf(ssrf);
        command.invoke(args, &host)
    })
    .await
    .expect("command task")
}

/// `browser.navigate` to an unscoped `http://127.0.0.1:<port>/` is refused by
/// aitmproxy with `PrivateAddressBlocked` before the driver is called; after
/// `scope.add` of that exact `host:port` the same navigation succeeds over
/// obscura and its flow is captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_posture_preserved() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start("ac15", None).await;
    let target = PlainFixture::spawn().await;
    let target_authority = target.addr.to_string();
    let url = target.url("/");
    let driver = Arc::new(CountingDriver {
        inner: rig.driver(),
        navigations: AtomicUsize::new(0),
    });

    let err = match invoke(
        &rig,
        driver.clone(),
        "browser.navigate",
        params(&[("url", &url)]),
    )
    .await
    {
        Ok(value) => panic!("unscoped loopback navigation succeeded: {value:?}"),
        Err(err) => err,
    };
    let text = format!("{err:#}");
    assert!(
        matches!(
            err.downcast_ref::<GuardError>(),
            Some(GuardError::PrivateAddressBlocked(host)) if host == "127.0.0.1"
        ),
        "expected GuardError::PrivateAddressBlocked(\"127.0.0.1\"), got: {text}"
    );
    assert!(
        text.contains("127.0.0.1"),
        "error does not name the host: {text}"
    );
    assert_eq!(
        driver.navigations(),
        0,
        "the driver was called for a navigation the SSRF guard must refuse"
    );
    assert_eq!(target.accepted(), 0, "the unscoped target was reached");

    invoke(
        &rig,
        driver.clone(),
        "scope.add",
        params(&[("host", &target_authority)]),
    )
    .await
    .expect("scope.add the exact host:port");

    let outcome = invoke(
        &rig,
        driver.clone(),
        "browser.navigate",
        params(&[("url", &url)]),
    )
    .await
    .expect("navigation permitted once the host:port is in scope");
    let Value::Object(fields) = outcome else {
        panic!("navigate returns an object, got {outcome:?}");
    };
    assert_eq!(
        fields.get("final_url"),
        Some(&Value::Str(url.clone())),
        "final_url is the scoped target"
    );
    assert_eq!(
        driver.navigations(),
        1,
        "the permitted navigation reached the driver"
    );

    let flows = rig
        .wait_for_flows(|flows| find_200(flows, &target_authority, "/").is_some())
        .await;
    let flow = find_200(&flows, &target_authority, "/").unwrap_or_else(|| {
        panic!(
            "no captured 200 flow for GET http://{target_authority}/ within {FLOW_WAIT:?}; captured:\n{}",
            describe(&flows)
        )
    });
    assert_eq!(flow.request.scheme, "http");
    assert!(
        target.accepted() >= 1,
        "the scoped target saw no connection: the navigation did not go through the proxy"
    );

    rig.finish().await;
}
