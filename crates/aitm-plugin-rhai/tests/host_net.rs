//! Task 7 — the guarded async host namespaces (`http`, `browser`, `store`,
//! `scope`): every active verb rides the same `ScopeRateGuard` / SSRF guard a
//! Rust plugin does, and a refusal surfaces as a **catchable** Rhai error
//! naming the host (option C forgives absence, never denial).
//!
//! The bridge under test is synchronous Rhai → async guarded future via
//! `block_in_place` + the stored runtime `Handle`, so every test runs on a
//! multi-thread runtime, the flavour the proxy uses.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aitm_browser::HostResolver;
use aitm_core::{
    Body, BrowserDriver, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome,
    ProxyClient, ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard, Value,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{begin_run, build_engine, AbortKind, Budget, RunKind};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::host_net::{
    BrowserCapability, HttpCapability, ScopeCapability, StoreCapability,
};
use rhai::{Array, Dynamic, Engine, EvalAltResult};

/// A client whose send never completes: an upstream that accepted the
/// connection and never answers.
struct StallingClient;

impl ProxyClient for StallingClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

/// A resolver with a fixed answer per name, so the SSRF decision on a DNS name
/// is testable without the network.
struct StubResolver(HashMap<&'static str, IpAddr>);

impl HostResolver for StubResolver {
    fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
        self.0
            .get(host)
            .map(|ip| vec![*ip])
            .ok_or_else(|| std::io::Error::other(format!("no such host: {host}")))
    }
}

/// A client that answers every request `200 pong` and records what it was
/// asked to send — so a test can prove a refused call never reached it.
#[derive(Default)]
struct StubClient {
    sent: Mutex<Vec<HttpRequest>>,
}

impl StubClient {
    fn sent(&self) -> Vec<HttpRequest> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ProxyClient for StubClient {
    fn send(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async move {
            self.sent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(req.clone());
            let mut headers = HeaderMap::new();
            headers.set("X-Stub", "1");
            Ok(HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers,
                    trailers: HeaderMap::new(),
                    body: Body::Bytes(b"pong".to_vec()),
                    timestamp: SystemTime::now(),
                    peer: None,
                }),
                client_conn: conn(),
                server_conn: None,
                metadata: FlowMeta {
                    is_replay: true,
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            })
        })
    }
}

/// Every browser call the driver was actually asked to perform.
#[derive(Default)]
struct StubBrowser {
    calls: Mutex<Vec<String>>,
}

impl StubBrowser {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(&self, call: impl Into<String>) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call.into());
    }
}

impl BrowserDriver for StubBrowser {
    fn navigate(
        &self,
        url: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<NavOutcome>> + Send + '_>> {
        let url = url.to_string();
        Box::pin(async move {
            self.record(format!("navigate {url}"));
            Ok(NavOutcome {
                final_url: url,
                status: Some(200),
            })
        })
    }

    fn click(
        &self,
        target: ClickTarget,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.record(match target {
                ClickTarget::Selector(s) => format!("click {s}"),
                ClickTarget::Point { x, y } => format!("click {x},{y}"),
            });
            Ok(())
        })
    }

    fn type_text(
        &self,
        selector: &str,
        text: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let (selector, text) = (selector.to_string(), text.to_string());
        Box::pin(async move {
            self.record(format!("type {selector}={text}"));
            Ok(())
        })
    }

    /// A realistic screenshot: 50 KiB of PNG-sized bytes.
    fn screenshot(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            self.record("screenshot");
            Ok(vec![0x89; SCREENSHOT_BYTES])
        })
    }

    fn eval(&self, expr: &str) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let expr = expr.to_string();
        Box::pin(async move {
            self.record(format!("eval {expr}"));
            Ok(Value::Str("marker".into()))
        })
    }

    /// A realistic page: 100 KiB of markup.
    fn get_dom(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move {
            self.record("get_dom");
            Ok(format!("<html>{}</html>", "x".repeat(DOM_BYTES - 13)))
        })
    }
}

/// Sizes the stub browser answers with: past the 64 KiB / 16 KiB the engine
/// limits used to allow, within the snapshot cap they now match.
const SCREENSHOT_BYTES: usize = 50 * 1024;
const DOM_BYTES: usize = 100 * 1024;

fn conn() -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("addr"),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// The services a script reaches: a real store and a real `StdGuard` (scoped to
/// `scope`), the stub client, and optionally the stub browser. The runtime
/// handle is the current test runtime — the bridge blocks on it.
struct Harness {
    services: ScriptServices,
    client: Arc<StubClient>,
    browser: Arc<StubBrowser>,
    guard: Arc<StdGuard>,
    store: Arc<MemFlowStore>,
}

impl Harness {
    fn new(scope: &[&str], with_browser: bool) -> Self {
        let guard = Arc::new(StdGuard::default());
        for host in scope {
            guard.add_scope(ScopeEntry {
                host: (*host).to_string(),
            });
        }
        let client = Arc::new(StubClient::default());
        let browser = Arc::new(StubBrowser::default());
        let store = Arc::new(MemFlowStore::new());
        let services = ScriptServices {
            store: store.clone(),
            client: client.clone(),
            browser: with_browser.then(|| browser.clone() as Arc<dyn BrowserDriver>),
            guard: guard.clone(),
            findings: Arc::new(MemoryFindingSink::new()),
            rt: tokio::runtime::Handle::current(),
        };
        Self {
            services,
            client,
            browser,
            guard,
            store,
        }
    }

    /// A hardened engine with all four Task 7 providers registered through the
    /// capability seam, in their default (deny-by-default) configuration —
    /// except that the test host `ok.test`, which has no DNS answer, resolves
    /// to a public address so `browser.navigate` can reach the SSRF decision.
    fn engine(&self) -> Engine {
        let resolver = StubResolver(HashMap::from([(
            "ok.test",
            "93.184.216.34".parse().unwrap(),
        )]));
        self.engine_with(vec![
            Box::new(HttpCapability),
            Box::new(BrowserCapability::default().with_resolver(Arc::new(resolver))),
            Box::new(StoreCapability),
            Box::new(ScopeCapability::default()),
        ])
    }

    /// A hardened engine with exactly these providers.
    fn engine_with(&self, providers: Vec<Box<dyn ScriptCapability>>) -> Engine {
        let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(5));
        for provider in providers {
            provider.register(&mut engine, &self.services);
        }
        engine
    }
}

/// Run a script the way a dispatcher does: inside `block_in_place`, so the
/// host verbs may block on the runtime handle, with a run of `kind` open so
/// they know who is calling and how long is left (`budget` is the hook
/// wall-clock; the browser budget is the shipped default).
fn run_as<T: Clone + Send + Sync + 'static>(
    kind: RunKind,
    budget: Duration,
    engine: &Engine,
    src: &str,
) -> Result<T, Box<EvalAltResult>> {
    tokio::task::block_in_place(|| {
        let _run = begin_run(
            kind,
            Budget {
                hook_timeout: budget,
                ..Budget::default()
            },
        );
        engine.eval::<T>(src)
    })
}

/// Run a script as a script command would: the run kind under which every
/// verb is available.
fn run<T: Clone + Send + Sync + 'static>(
    engine: &Engine,
    src: &str,
) -> Result<T, Box<EvalAltResult>> {
    run_as(RunKind::Command, Duration::from_secs(5), engine, src)
}

/// Decode the `on_progress`-style termination token of an aborted run.
fn abort_kind(err: &EvalAltResult) -> Option<AbortKind> {
    match err {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<AbortKind>(),
        _ => None,
    }
}

/// A captured flow for the store to hand back.
fn stored_flow(store: &MemFlowStore, authority: &str) -> FlowId {
    let mut headers = HeaderMap::new();
    headers.set("Host", authority);
    store.insert(Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: "/items".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 201,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Bytes(b"stored".to_vec()),
            timestamp: SystemTime::now(),
            peer: None,
        }),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }))
}

#[test]
fn seam_names_its_namespaces() {
    assert_eq!(HttpCapability.namespace(), "http");
    assert_eq!(BrowserCapability::default().namespace(), "browser");
    assert_eq!(StoreCapability.namespace(), "store");
    assert_eq!(ScopeCapability::default().namespace(), "scope");
    for provider in [
        HttpCapability.min_api(),
        BrowserCapability::default().min_api(),
        StoreCapability.min_api(),
        ScopeCapability::default().min_api(),
    ] {
        assert_eq!(provider, "1");
    }
}

/// RF#2/#3: a guard refusal is a catchable Rhai error naming the host — not a
/// host-side panic, and not a silent "absent" answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_scope_send_is_catchable() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let caught: String = run(
        &engine,
        r#"let r = "sent"; try { http.send(#{ method: "GET", url: "http://evil.test/" }); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable, not a hard failure");

    assert!(
        caught.starts_with("caught:"),
        "an out-of-scope send must throw: {caught}"
    );
    assert!(
        caught.contains("evil.test"),
        "the error must name the host: {caught}"
    );
    assert!(
        h.client.sent().is_empty(),
        "a refused send must never reach the client"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_scope_send_returns_map() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let status: i64 = run(
        &engine,
        r#"http.send(#{ method: "GET", url: "http://ok.test/" }).status"#,
    )
    .expect("an in-scope send must succeed");
    assert_eq!(status, 200);

    let sent = h.client.sent();
    assert_eq!(sent.len(), 1, "exactly one request reached the client");
    assert_eq!(sent[0].method, "GET");
    assert_eq!(sent[0].authority, "ok.test");
    assert_eq!(sent[0].path, "/");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_marshals_headers_and_body_both_ways() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let body: String = run(
        &engine,
        r#"
        let r = http.send(#{
            method: "POST",
            url: "http://ok.test/notes?x=1",
            headers: #{ "Content-Type": "text/plain" },
            body: "hello"
        });
        r.headers["X-Stub"] + ":" + r.body
        "#,
    )
    .expect("a POST with headers and a body must succeed");
    assert_eq!(body, "1:pong");

    let sent = h.client.sent();
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].path, "/notes?x=1");
    assert_eq!(sent[0].headers.get("Content-Type"), Some("text/plain"));
    assert!(matches!(&sent[0].body, Body::Bytes(b) if b == b"hello"));
}

/// A malformed request map is a mistake, not an absence: it says what is wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_without_url_is_an_error() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let caught: String = run(
        &engine,
        r#"let r = "sent"; try { http.send(#{ method: "GET" }); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the error must be catchable");
    assert!(
        caught.contains("url"),
        "the error must name the field: {caught}"
    );
    assert!(h.client.sent().is_empty());
}

/// Security review (M3, Important): `http.send` copies nothing unvalidated
/// into the request line. A method that is not an HTTP token, or a path with
/// a control character, is refused before anything is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_refuses_a_smuggled_request_line() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let smuggled_method = "GET / HTTP/1.1\r\nX-Smuggled: 1\r\nGET";
    let caught: String = run(
        &engine,
        &format!(
            r#"let r = "sent"; try {{ http.send(#{{ method: "{}", url: "http://ok.test/" }}); }} catch(e) {{ r = "caught:" + e; }} r"#,
            smuggled_method.escape_default()
        ),
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:") && caught.contains("method"),
        "a non-token method must be refused and named: {caught}"
    );

    let caught: String = run(
        &engine,
        r#"let r = "sent"; try { http.send(#{ url: "http://ok.test/a\r\nX-Smuggled: 1\r\n/b" }); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:") && caught.contains("path"),
        "a path with CR/LF must be refused and named: {caught}"
    );

    let caught: String = run(
        &engine,
        r#"let r = "sent"; try { http.send(#{ url: "http://ok.test/a b" }); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:"),
        "a path with a space: {caught}"
    );

    assert!(
        h.client.sent().is_empty(),
        "nothing with a bad request line reaches the client"
    );

    // Unusual but legal tokens still work.
    let status: i64 = run(
        &engine,
        r#"http.send(#{ method: "PURGE", url: "http://ok.test/x?y=1&z=%20" }).status"#,
    )
    .expect("a token method and an encoded query are fine");
    assert_eq!(status, 200);
}

/// Security review (M3, Important): a host call is bounded by the run's
/// wall-clock budget. An upstream that never answers cannot hold the hook —
/// and with it the chain — past the deadline; the abort is the same Timeout
/// termination `on_progress` produces, and a script cannot catch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_call_is_bounded_by_the_run_budget() {
    let mut h = Harness::new(&["ok.test"], false);
    h.services.client = Arc::new(StallingClient);
    let engine = h.engine();

    let started = Instant::now();
    let err = run_as::<Dynamic>(
        RunKind::Hook,
        Duration::from_millis(300),
        &engine,
        r#"try { http.send(#{ url: "http://ok.test/slow" }); } catch(e) { "caught" }"#,
    )
    .expect_err("a stalled send must abort the run, uncaught");
    let elapsed = started.elapsed();
    assert_eq!(
        abort_kind(&err),
        Some(AbortKind::Timeout),
        "the abort is the Timeout termination: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the hook must end at its budget, not when the upstream feels like it: {elapsed:?}"
    );
}

/// Security review (M3, Important): `browser.*` inside a flow hook would
/// navigate through this proxy and wait on the chain this hook is holding —
/// a deadlock broken only by the navigation timeout. It is refused with the
/// places the verbs are safe; from a command or PoC step it works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_verbs_are_refused_inside_a_hook() {
    let h = Harness::new(&["ok.test"], true);
    let engine = h.engine();

    for verb in [
        r#"browser.navigate("http://ok.test/")"#,
        r##"browser.click("#x")"##,
        r##"browser.type_text("#x", "y")"##,
        "browser.screenshot()",
        r#"browser.evaluate("1")"#,
        "browser.get_dom()",
    ] {
        let caught: String = run_as(
            RunKind::Hook,
            Duration::from_secs(5),
            &engine,
            &format!(r#"let r = "ran"; try {{ {verb}; }} catch(e) {{ r = "caught:" + e; }} r"#),
        )
        .expect("the refusal must be catchable");
        assert!(
            caught.starts_with("caught:") && caught.contains("hook"),
            "{verb} in a hook must be refused and say why: {caught}"
        );
        assert!(
            caught.contains("command") && caught.contains("PoC"),
            "{verb}: the error names where the verb is allowed: {caught}"
        );
    }
    assert!(
        h.browser.calls().is_empty(),
        "a refused verb never reaches the driver"
    );

    // The same verb from a PoC step runs.
    run_as::<()>(
        RunKind::PocStep,
        Duration::from_secs(5),
        &engine,
        r#"browser.navigate("http://ok.test/")"#,
    )
    .expect("browser verbs are available to PoC steps");
    assert_eq!(
        h.browser.calls(),
        vec!["navigate http://ok.test/".to_string()]
    );
}

/// Security review (M3, Important): `browser.navigate` on a DNS name runs the
/// same resolve-then-classify SSRF check as the Rust `browser.navigate`
/// command — a scoped *name* that resolves to a private address is refused,
/// one that resolves publicly is driven.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_resolves_names_through_the_ssrf_guard() {
    let h = Harness::new(&["*.example.com"], true);
    let resolver = StubResolver(HashMap::from([
        ("evil.example.com", "169.254.169.254".parse().unwrap()),
        ("ok.example.com", "93.184.216.34".parse().unwrap()),
    ]));
    let engine = h.engine_with(vec![Box::new(
        BrowserCapability::new(SsrfPolicy::default()).with_resolver(Arc::new(resolver)),
    )]);

    let caught: String = run(
        &engine,
        r#"let r = "went"; try { browser.navigate("http://evil.example.com/"); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:") && caught.contains("SSRF"),
        "a scoped name resolving to link-local must be refused by the SSRF guard: {caught}"
    );
    assert!(h.browser.calls().is_empty());

    run::<()>(&engine, r#"browser.navigate("http://ok.example.com/")"#)
        .expect("a scoped name resolving publicly is driven");
    assert_eq!(
        h.browser.calls(),
        vec!["navigate http://ok.example.com/".to_string()]
    );
}

/// The SSRF guard refuses a loopback target that is not in scope, and says so —
/// the refusal is the SSRF guard's, not merely "out of scope".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_ssrf_blocked() {
    let h = Harness::new(&[], true);
    let engine = h.engine();

    let caught: String = run(
        &engine,
        r#"let r = "went"; try { browser.navigate("http://127.0.0.1/"); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");

    assert!(
        caught.starts_with("caught:"),
        "a loopback navigation must be refused: {caught}"
    );
    assert!(
        caught.contains("127.0.0.1"),
        "the error must name the address: {caught}"
    );
    assert!(
        caught.contains("SSRF"),
        "the SSRF guard must be the refusal, not the scope check: {caught}"
    );
    assert!(
        h.browser.calls().is_empty(),
        "a refused navigation must never reach the driver"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_verbs_reach_the_driver_in_scope() {
    let h = Harness::new(&["ok.test"], true);
    let engine = h.engine();

    let dom: String = run(
        &engine,
        r##"
        browser.navigate("http://ok.test/notes");
        browser.click("#save");
        browser.type_text("#note", "hi");
        browser.screenshot();
        browser.evaluate("window.__aitm");
        browser.get_dom()
        "##,
    )
    .expect("in-scope browser verbs must run");
    assert!(dom.starts_with("<html>") && dom.len() == DOM_BYTES);

    assert_eq!(
        h.browser.calls(),
        vec![
            "navigate http://ok.test/notes".to_string(),
            "click #save".to_string(),
            "type #note=hi".to_string(),
            "screenshot".to_string(),
            "eval window.__aitm".to_string(),
            "get_dom".to_string(),
        ]
    );
}

/// Security review (M3, Important): a real screenshot (tens of KiB) and a real
/// DOM (hundreds of KiB) come back whole instead of tripping the engine's
/// data-size limits — and so does a large `http.send` response body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_host_results_fit_the_limits() {
    let h = Harness::new(&["ok.test"], true);
    let engine = h.engine();

    let sizes: Array = run(
        &engine,
        r#"[browser.screenshot().len(), browser.get_dom().len()]"#,
    )
    .expect("large browser results must not throw");
    assert_eq!(sizes[0].as_int().unwrap(), SCREENSHOT_BYTES as i64);
    assert_eq!(sizes[1].as_int().unwrap(), DOM_BYTES as i64);
}

/// A build with no browser wired has no browser to drive: an action that cannot
/// happen is an error a script can catch, not a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_without_a_browser_is_an_error() {
    let h = Harness::new(&["ok.test"], false);
    let engine = h.engine();

    let caught: String = run(
        &engine,
        r#"let r = "went"; try { browser.navigate("http://ok.test/"); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the error must be catchable");
    assert!(
        caught.contains("browser"),
        "the error must say no browser is configured: {caught}"
    );
}

/// Security review (M3, Important): `scope.add` widens the engagement scope
/// and lifts the SSRF block for the host it names, so it is off unless the
/// operator opts in (`rhai: allow_scope_add: true`), and never available to a
/// PoC `script` step — a PoC is a shared artifact that runs inside the scope
/// the operator set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_add_is_gated() {
    let h = Harness::new(&[], false);

    // Default: refused, naming the switch.
    let engine = h.engine();
    let caught: String = run(
        &engine,
        r#"let r = "added"; try { scope.add("169.254.169.254"); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:") && caught.contains("allow_scope_add"),
        "scope.add is off by default and the error names the switch: {caught}"
    );

    // Opted in, but from a PoC step: still refused.
    let engine = h.engine_with(vec![Box::new(ScopeCapability::new(true))]);
    let caught: String = run_as(
        RunKind::PocStep,
        Duration::from_secs(5),
        &engine,
        r#"let r = "added"; try { scope.add("169.254.169.254"); } catch(e) { r = "caught:" + e; } r"#,
    )
    .expect("the refusal must be catchable");
    assert!(
        caught.starts_with("caught:") && caught.contains("PoC"),
        "a PoC step cannot widen scope even when plugins may: {caught}"
    );

    assert!(
        h.guard.list_scope().is_empty(),
        "no refused call reached the guard"
    );
    // `scope.list` stays available everywhere.
    let listed: Array = run_as(
        RunKind::PocStep,
        Duration::from_secs(5),
        &engine,
        "scope.list()",
    )
    .expect("scope.list is read-only and allowed");
    assert!(listed.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_add_then_list() {
    let h = Harness::new(&[], false);
    let engine = h.engine_with(vec![Box::new(ScopeCapability::new(true))]);

    let listed: Array =
        run(&engine, r#"scope.add("ok.test"); scope.list()"#).expect("scope.add/list must run");

    let hosts: Vec<String> = listed
        .iter()
        .map(|entry| entry.clone().into_string().unwrap_or_default())
        .collect();
    assert!(
        hosts.contains(&"ok.test".to_string()),
        "scope.list() should hold the added host: {hosts:?}"
    );
    assert!(
        h.guard
            .list_scope()
            .iter()
            .any(|entry| entry.host == "ok.test"),
        "the host must be added to the real guard, not a script-side copy"
    );
}

/// Option C: an id the store does not hold reads as `()` — forgiveness covers
/// absence. (Denial stays an error: see `out_of_scope_send_is_catchable`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_get_missing_is_null() {
    let h = Harness::new(&[], false);
    let engine = h.engine();

    let missing: Dynamic = run(
        &engine,
        r#"store.get("00000000-0000-0000-0000-000000000000")"#,
    )
    .expect("a missing flow must not abort the hook");
    assert!(
        missing.is_unit(),
        "an unknown id should read as (), got {missing:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_get_and_query_read_flows() {
    let h = Harness::new(&[], false);
    let id = stored_flow(&h.store, "ok.test");
    let engine = h.engine();

    let status: i64 = run(&engine, &format!(r#"store.get("{id}").response.status"#))
        .expect("a stored flow must be readable");
    assert_eq!(status, 201);

    let method: String = run(
        &engine,
        r#"store.query(#{ host: "ok.test" })[0].request.method"#,
    )
    .expect("store.query must return the matching flows");
    assert_eq!(method, "GET");

    let empty: Array = run(&engine, r#"store.query(#{ host: "other.test" })"#)
        .expect("a query matching nothing is empty, not an error");
    assert!(empty.is_empty());
}
