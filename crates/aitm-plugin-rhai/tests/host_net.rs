//! Task 7 — the guarded async host namespaces (`http`, `browser`, `store`,
//! `scope`): every active verb rides the same `ScopeRateGuard` / SSRF guard a
//! Rust plugin does, and a refusal surfaces as a **catchable** Rhai error
//! naming the host (option C forgives absence, never denial).
//!
//! The bridge under test is synchronous Rhai → async guarded future via
//! `block_in_place` + the stored runtime `Handle`, so every test runs on a
//! multi-thread runtime, the flavour the proxy uses.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, BrowserDriver, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome,
    ProxyClient, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::host_net::{
    BrowserCapability, HttpCapability, ScopeCapability, StoreCapability,
};
use rhai::{Array, Dynamic, Engine, EvalAltResult};

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
                    body: Body::Bytes(b"pong".to_vec()),
                    timestamp: SystemTime::now(),
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

    fn screenshot(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            self.record("screenshot");
            Ok(vec![1, 2, 3])
        })
    }

    fn eval(&self, expr: &str) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let expr = expr.to_string();
        Box::pin(async move {
            self.record(format!("eval {expr}"));
            Ok(Value::Str("marker".into()))
        })
    }

    fn get_dom(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move {
            self.record("get_dom");
            Ok("<html>ok</html>".to_string())
        })
    }
}

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
    /// capability seam.
    fn engine(&self) -> Engine {
        let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(5));
        let providers: [&dyn ScriptCapability; 4] = [
            &HttpCapability,
            &BrowserCapability,
            &StoreCapability,
            &ScopeCapability,
        ];
        for provider in providers {
            provider.register(&mut engine, &self.services);
        }
        engine
    }
}

/// Run a script the way a hook does: inside `block_in_place`, so the host
/// verbs may block on the runtime handle.
fn run<T: Clone + Send + Sync + 'static>(
    engine: &Engine,
    src: &str,
) -> Result<T, Box<EvalAltResult>> {
    tokio::task::block_in_place(|| engine.eval::<T>(src))
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
            body: Body::Bytes(b"stored".to_vec()),
            timestamp: SystemTime::now(),
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
    assert_eq!(BrowserCapability.namespace(), "browser");
    assert_eq!(StoreCapability.namespace(), "store");
    assert_eq!(ScopeCapability.namespace(), "scope");
    for provider in [
        HttpCapability.min_api(),
        BrowserCapability.min_api(),
        StoreCapability.min_api(),
        ScopeCapability.min_api(),
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
    assert_eq!(dom, "<html>ok</html>");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_add_then_list() {
    let h = Harness::new(&[], false);
    let engine = h.engine();

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
