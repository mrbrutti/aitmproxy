//! T9 (DVWA tool fixes, Task 10 / AC12): a `browser.*` host call runs under
//! its own `browser_timeout`, not the hook wall-clock remainder. A browser
//! call that fetches can legitimately outlive a 2s hook budget; a stalled
//! upstream for `http.*` still may not.
//!
//! The non-browser verbs stay on `remaining_budget()`, and a browser call
//! that completes renews the run's deadline so the script's next operation
//! is not aborted just because the browser took its time.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, BrowserDriver, ClickTarget, ConnInfo, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome, ProxyClient, ScopeEntry,
    ScopeRateGuard, StdGuard, Value,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::{
    begin_run, browser_budget, build_engine, extend_deadline, remaining_budget, AbortKind, Budget,
    RunKind,
};
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptCapability, ScriptServices};
use aitm_plugin_rhai::host_net::{BrowserCapability, HttpCapability};
use rhai::{Dynamic, Engine, EvalAltResult, Position};

/// A browser whose every verb answers after `delay`; `eval` answers `7`.
struct SlowBrowser(Duration);

impl BrowserDriver for SlowBrowser {
    fn navigate(
        &self,
        url: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<NavOutcome>> + Send + '_>> {
        let url = url.to_string();
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(NavOutcome {
                final_url: url,
                status: Some(200),
            })
        })
    }

    fn click(
        &self,
        _target: ClickTarget,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(())
        })
    }

    fn type_text(
        &self,
        _selector: &str,
        _text: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(())
        })
    }

    fn screenshot(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(vec![0x89])
        })
    }

    fn eval(
        &self,
        _expr: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(Value::Int(7))
        })
    }

    fn get_dom(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok("<html></html>".to_string())
        })
    }
}

/// A client that answers `200` after `delay` — the same wait as the browser,
/// on the non-browser path.
struct SlowClient(Duration);

impl ProxyClient for SlowClient {
    fn send(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            Ok(HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    trailers: HeaderMap::new(),
                    body: Body::Bytes(b"pong".to_vec()),
                    timestamp: SystemTime::now(),
                    peer: None,
                }),
                client_conn: ConnInfo {
                    peer: "127.0.0.1:0".parse().expect("addr"),
                    sni: None,
                    alpn: None,
                    tls: false,
                    established: SystemTime::now(),
                },
                server_conn: None,
                metadata: FlowMeta::default(),
                intercept: InterceptState::Observed,
            })
        })
    }
}

/// The wait both stubs impose: past a 50ms hook budget, well inside a 5s
/// browser budget.
const DELAY: Duration = Duration::from_millis(200);

/// The plan's budget: a hook budget the wait exceeds, a browser budget it
/// does not.
fn budget() -> Budget {
    Budget {
        max_operations: 0,
        hook_timeout: Duration::from_millis(50),
        browser_timeout: Duration::from_secs(5),
    }
}

/// An engine with `http` and `browser` wired to the slow stubs, `ok.test` in
/// scope so the guards admit the calls and only the budgets decide.
fn engine(browser: Arc<dyn BrowserDriver>) -> Engine {
    let guard = Arc::new(StdGuard::default());
    guard.add_scope(ScopeEntry {
        host: "ok.test".to_string(),
    });
    let services = ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(SlowClient(DELAY)),
        browser: Some(browser),
        guard,
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    };
    let limits = RhaiLimits {
        max_operations: 0,
        ..RhaiLimits::default()
    };
    let mut engine = build_engine(&limits, Duration::from_secs(5));
    HttpCapability.register(&mut engine, &services);
    BrowserCapability::default().register(&mut engine, &services);
    engine
}

/// Run `src` as a script command does, under `budget`.
fn run<T: Clone + Send + Sync + 'static>(
    budget: Budget,
    engine: &Engine,
    src: &str,
) -> Result<T, Box<EvalAltResult>> {
    tokio::task::block_in_place(|| {
        let _run = begin_run(RunKind::Command, budget);
        engine.eval::<T>(src)
    })
}

fn abort_kind(err: &EvalAltResult) -> Option<AbortKind> {
    match err {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<AbortKind>(),
        _ => None,
    }
}

/// AC12: with `hook_timeout` 50ms and `browser_timeout` 5s, a browser call
/// that takes ~200ms succeeds with its literal value, while the same wait on
/// `http.send` aborts the run with the hook's `Timeout` token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_call_uses_browser_budget() {
    let engine = engine(Arc::new(SlowBrowser(DELAY)));

    let value = run::<i64>(budget(), &engine, r#"browser.evaluate("x")"#)
        .unwrap_or_else(|err| panic!("a browser call inside browser_timeout must succeed: {err}"));
    assert_eq!(value, 7);

    let started = Instant::now();
    let err = run::<i64>(
        budget(),
        &engine,
        r#"http.send(#{ url: "http://ok.test/slow" }).status"#,
    )
    .expect_err("a non-browser host call past the hook budget must abort");
    assert_eq!(
        abort_kind(&err),
        Some(AbortKind::Timeout),
        "the abort is the hook Timeout token: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the abort is prompt, at the hook budget"
    );
}

/// The post-call interaction: after a long legitimate browser call the run's
/// deadline has passed, and without renewal `on_progress` would abort the
/// very next operation. The script's follow-up work must run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_call_renews_the_run_deadline() {
    let engine = engine(Arc::new(SlowBrowser(DELAY)));

    let value = run::<i64>(
        budget(),
        &engine,
        r#"let v = browser.evaluate("x"); let n = 0; for i in 0..1000 { n += 1; } v + n"#,
    )
    .unwrap_or_else(|err| panic!("work after a browser call must not be aborted: {err}"));
    assert_eq!(value, 1007);

    // Two browser calls in a row: each one renews, so the second is admitted.
    let value = run::<i64>(
        budget(),
        &engine,
        r#"let a = browser.evaluate("x"); let b = browser.evaluate("y"); a + b"#,
    )
    .unwrap_or_else(|err| panic!("a second browser call must be admitted: {err}"));
    assert_eq!(value, 14);
}

/// The browser budget is a bound, not a licence: a browser that never answers
/// ends the run at `browser_timeout`, with a token that names that budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_call_is_bounded_by_browser_timeout() {
    let engine = engine(Arc::new(SlowBrowser(Duration::from_secs(3600))));
    let budget = Budget {
        max_operations: 0,
        hook_timeout: Duration::from_secs(5),
        browser_timeout: Duration::from_millis(100),
    };

    let started = Instant::now();
    let err = run::<i64>(budget, &engine, r#"browser.evaluate("x")"#)
        .expect_err("a stalled browser must abort the run");
    assert_eq!(
        abort_kind(&err),
        Some(AbortKind::BrowserTimeout),
        "the abort names the browser budget: {err}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the run ends at browser_timeout, not when the browser answers"
    );
}

/// The engine helpers the bridge is built on: the browser budget is readable
/// inside a run and absent outside one, and renewing the deadline gives the
/// run a fresh hook budget from now.
#[test]
fn run_exposes_browser_budget_and_renews_its_deadline() {
    assert_eq!(browser_budget(), None);
    let budget = Budget {
        max_operations: 0,
        hook_timeout: Duration::from_millis(50),
        browser_timeout: Duration::from_secs(7),
    };
    let _run = begin_run(RunKind::PocStep, budget);
    assert_eq!(browser_budget(), Some(Duration::from_secs(7)));

    std::thread::sleep(Duration::from_millis(70));
    assert_eq!(
        remaining_budget(),
        Some(Duration::ZERO),
        "the hook budget is spent"
    );

    extend_deadline();
    let left = remaining_budget().expect("a run is active");
    assert!(
        left > Duration::from_millis(30) && left <= Duration::from_millis(50),
        "renewal grants one hook budget from now: {left:?}"
    );
}

/// `error.rs` names the budget that fired: the browser figure for a browser
/// abort, the hook figure for a hook abort.
#[test]
fn timeout_error_names_the_budget_that_fired() {
    let budget = Budget {
        max_operations: 1000,
        hook_timeout: Duration::from_secs(2),
        browser_timeout: Duration::from_secs(30),
    };
    let token =
        |kind: AbortKind| EvalAltResult::ErrorTerminated(Dynamic::from(kind), Position::NONE);

    assert_eq!(
        ScriptError::from_eval("s.rhai", "run", &token(AbortKind::BrowserTimeout), &budget),
        ScriptError::Timeout {
            script: "s.rhai".to_string(),
            hook: "run".to_string(),
            elapsed: Duration::from_secs(30),
        }
    );
    assert_eq!(
        ScriptError::from_eval("s.rhai", "run", &token(AbortKind::Timeout), &budget),
        ScriptError::Timeout {
            script: "s.rhai".to_string(),
            hook: "run".to_string(),
            elapsed: Duration::from_secs(2),
        }
    );
}
