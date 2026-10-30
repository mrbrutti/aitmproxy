//! The chromiumoxide-backed CDP session and the Chrome launcher.
//!
//! [`CdpSession`] is one connected `Browser`, the one `Page` every primitive
//! drives, and the handler task that keeps the connection moving; the six
//! `BrowserDriver` primitives live on it and are shared by both engines.
//! `ChromeDriver::launch` starts headless Chromium with the proxy as its
//! upstream (`--proxy-server`) and trusts the proxy CA at runtime via CDP
//! `Security.setIgnoreCertificateErrors`; `ObscuraDriver` (`obscura.rs`)
//! attaches the same session to a managed obscura child.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use aitm_core::{BrowserConfig, BrowserDriver, ClickTarget, NavOutcome, Value};
use chromiumoxide::browser::{Browser, BrowserConfig as CdpConfig};
use chromiumoxide::cdp::browser_protocol::page::EventFrameStartedLoading;
use chromiumoxide::cdp::browser_protocol::security::SetIgnoreCertificateErrorsParams;
use chromiumoxide::cdp::js_protocol::runtime::{ExecutionContextId, RemoteObject};
use chromiumoxide::error::CdpError;
use chromiumoxide::handler::Handler;
use chromiumoxide::js::Evaluation;
use chromiumoxide::layout::Point;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::future::BoxFuture;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Bound on the CDP `Browser.close` round trip of a graceful close; an engine
/// that does not answer is then stopped by its launcher.
const CDP_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Which execution context one `eval` attempt names (T5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvalContext {
    /// The main-frame context chromiumoxide tracks, resolved afresh for this
    /// call rather than carried over from an earlier one.
    Tracked,
    /// No explicit context id: the engine evaluates in the page's live
    /// default context, so a tracked id the engine has since discarded (as
    /// happens with no `navigate` before the first `eval`) cannot be named.
    PageDefault,
}

/// The engine's answer to `Runtime.evaluate` naming a context it no longer
/// has. Both the JSON-RPC code and the message are matched, as the two
/// engines word it differently.
fn is_stale_context_error(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    text.contains("Cannot find context") || text.contains("-32601")
}

/// Run `attempt` against the tracked context; if the engine reports that
/// context stale, run it once more against the page's default context and
/// return that result. Any other error, and a second stale error, are the
/// caller's: there is no retry loop.
pub(crate) async fn eval_with_context_retry<F, Fut>(mut attempt: F) -> anyhow::Result<Value>
where
    F: FnMut(EvalContext) -> Fut,
    Fut: Future<Output = anyhow::Result<Value>>,
{
    match attempt(EvalContext::Tracked).await {
        Err(err) if is_stale_context_error(&err) => attempt(EvalContext::PageDefault).await,
        first => first,
    }
}

/// How long after a click the driver waits for a navigation to begin before
/// concluding the click navigated nothing (T6). `Page.frameStartedLoading`
/// fires as the browser commits to the navigation, before any network round
/// trip, so a form submit or link shows up well inside this bound; a click
/// that only runs page script costs at most this much.
const CLICK_NAV_GRACE: Duration = Duration::from_millis(500);

/// Settle a click (T6): if `started` reports a navigation within `grace`,
/// await `finished()` bounded by `nav_timeout` (an unfinished navigation is
/// the same error `navigate` gives); otherwise the click navigated nothing
/// and is simply `Ok`. `finished` is a constructor, not a future, because
/// `Page::wait_for_navigation` resolves immediately on a frame that is still
/// in its previous loaded state — it must only be created once the new load
/// has begun.
pub(crate) async fn settle_after_click<S, F, N>(
    started: S,
    finished: F,
    grace: Duration,
    nav_timeout: Duration,
) -> anyhow::Result<()>
where
    S: Future<Output = bool>,
    F: FnOnce() -> N,
    N: Future<Output = anyhow::Result<()>>,
{
    match tokio::time::timeout(grace, started).await {
        Ok(true) => tokio::time::timeout(nav_timeout, finished())
            .await
            .map_err(|_| anyhow::anyhow!("navigation triggered by click timed out"))?,
        // `Ok(false)`: the event stream ended (session closing) — nothing to
        // await. `Err(_)`: no navigation began within the grace bound.
        Ok(false) | Err(_) => Ok(()),
    }
}

/// One connected CDP session, shared by both engines.
pub(crate) struct CdpSession {
    /// Taken by [`CdpSession::close`], so a shared session closes exactly once.
    browser: Mutex<Option<Browser>>,
    page: Page,
    nav_timeout: Duration,
    handler: JoinHandle<()>,
}

impl CdpSession {
    /// Drive `events` on a task and open the one page the primitives use.
    pub(crate) async fn attach(
        browser: Browser,
        mut events: Handler,
        nav_timeout: Duration,
    ) -> anyhow::Result<Self> {
        // The handler must be polled for the CDP connection to make progress.
        let handler = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if event.is_err() {
                    break;
                }
            }
        });

        let page = match browser.new_page("about:blank").await {
            Ok(page) => page,
            Err(err) => {
                handler.abort();
                return Err(err.into());
            }
        };

        Ok(Self {
            browser: Mutex::new(Some(browser)),
            page,
            nav_timeout,
            handler,
        })
    }

    /// Close the browser over CDP (bounded) and stop the handler task. A
    /// second call is a no-op.
    pub(crate) async fn close(&self) -> anyhow::Result<()> {
        let browser = self
            .browser
            .lock()
            .map_err(|_| anyhow::anyhow!("CDP session lock poisoned"))?
            .take();
        let Some(mut browser) = browser else {
            return Ok(());
        };
        let closed = tokio::time::timeout(CDP_CLOSE_TIMEOUT, browser.close()).await;
        self.handler.abort();
        match closed {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(anyhow::anyhow!(
                "CDP Browser.close did not answer within {CDP_CLOSE_TIMEOUT:?}"
            )),
        }
    }

    pub(crate) async fn navigate(&self, url: &str) -> anyhow::Result<NavOutcome> {
        let nav = async {
            self.page.goto(url).await?;
            self.page.wait_for_navigation().await?;
            anyhow::Ok(())
        };
        tokio::time::timeout(self.nav_timeout, nav)
            .await
            .map_err(|_| anyhow::anyhow!("navigation to {url} timed out"))??;
        let final_url = self.page.url().await?.unwrap_or_else(|| url.to_string());
        // The HTTP status is not surfaced by CDP's Page.navigate; the proxy's
        // captured flow for this navigation carries it.
        Ok(NavOutcome {
            final_url,
            status: None,
        })
    }

    /// Click, then await the navigation it triggers, if any (T6): a following
    /// `get_dom` sees the post-submit page. The listener is registered before
    /// the click so a fast navigation cannot slip past it; only the main
    /// frame counts, so a subframe load does not hold the click.
    pub(crate) async fn click(&self, target: ClickTarget) -> anyhow::Result<()> {
        let mut loading = self
            .page
            .event_listener::<EventFrameStartedLoading>()
            .await?;
        let main_frame = self.page.mainframe().await?;
        match target {
            ClickTarget::Selector(selector) => {
                self.page.find_element(selector).await?.click().await?;
            }
            ClickTarget::Point { x, y } => {
                self.page.click(Point { x, y }).await?;
            }
        }
        let started = async move {
            while let Some(event) = loading.next().await {
                if main_frame
                    .as_ref()
                    .is_none_or(|frame| *frame == event.frame_id)
                {
                    return true;
                }
            }
            false
        };
        let finished = || async {
            self.page.wait_for_navigation().await?;
            anyhow::Ok(())
        };
        settle_after_click(started, finished, CLICK_NAV_GRACE, self.nav_timeout).await
    }

    pub(crate) async fn type_text(&self, selector: &str, text: &str) -> anyhow::Result<()> {
        self.page
            .find_element(selector)
            .await?
            .click()
            .await?
            .type_str(text)
            .await?;
        Ok(())
    }

    pub(crate) async fn screenshot(&self) -> anyhow::Result<Vec<u8>> {
        let png = self
            .page
            .screenshot(ScreenshotParams::builder().build())
            .await?;
        Ok(png)
    }

    /// Evaluate `expr` in the page (T5): the execution context is resolved
    /// per call, and a stale-context error earns one retry in the page's
    /// default context (see [`eval_with_context_retry`]).
    pub(crate) async fn eval(&self, expr: &str) -> anyhow::Result<Value> {
        eval_with_context_retry(|ctx| self.eval_in(expr, ctx)).await
    }

    /// One `eval` attempt in `ctx`. Mirrors chromiumoxide's `Page::evaluate`
    /// (function-vs-expression detection, awaited promises, by-value results,
    /// a JS exception as the error) but owns the context id: chromiumoxide
    /// substitutes its tracked id for a `None`, which is exactly what a
    /// [`EvalContext::PageDefault`] retry must not do.
    async fn eval_in(&self, expr: &str, ctx: EvalContext) -> anyhow::Result<Value> {
        let context_id: Option<ExecutionContextId> = match ctx {
            EvalContext::Tracked => self.page.execution_context().await?,
            EvalContext::PageDefault => None,
        };
        let object: RemoteObject = match Evaluation::from(expr) {
            Evaluation::Expression(mut params) => {
                params.context_id = context_id;
                params.await_promise = Some(true);
                params.return_by_value = Some(true);
                let returns = self.page.execute(params).await?.result;
                if let Some(exception) = returns.exception_details {
                    return Err(CdpError::JavascriptException(Box::new(exception)).into());
                }
                returns.result
            }
            Evaluation::Function(mut params) => {
                params.execution_context_id = context_id;
                params.await_promise = Some(true);
                params.return_by_value = Some(true);
                let returns = self.page.execute(params).await?.result;
                if let Some(exception) = returns.exception_details {
                    return Err(CdpError::JavascriptException(Box::new(exception)).into());
                }
                returns.result
            }
        };
        Ok(object
            .value
            .as_ref()
            .map(json_to_value)
            .unwrap_or(Value::Null))
    }

    pub(crate) async fn get_dom(&self) -> anyhow::Result<String> {
        Ok(self.page.content().await?)
    }
}

impl Drop for CdpSession {
    fn drop(&mut self) {
        self.handler.abort();
    }
}

/// Headless Chromium, routed through the proxy, driven over CDP.
pub struct ChromeDriver {
    session: CdpSession,
}

/// Chromium launch flags derived from the config: route everything — loopback
/// included, which Chromium otherwise bypasses — through the proxy.
pub(crate) fn launch_args(config: &BrowserConfig) -> Vec<String> {
    vec![
        format!("--proxy-server={}", config.proxy_addr),
        "--proxy-bypass-list=<-loopback>".to_string(),
    ]
}

/// Largest magnitude a float holds exactly (2^53): below it an integral
/// float is an integer, above it the cast would be lossy.
const MAX_EXACT_FLOAT: f64 = 9_007_199_254_740_992.0;

/// Convert a CDP evaluation result into a bus [`Value`]. JS has one number
/// type, and obscura serialises every number as a float, so an integral
/// float is the integer (`1+1` is `Int(2)` on both engines).
pub(crate) fn json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_EXACT_FLOAT {
                    Value::Int(f as i64)
                } else {
                    Value::Float(f)
                }
            }
        },
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        serde_json::Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

impl ChromeDriver {
    /// Launch Chromium with the proxy upstream and the CA-trust posture in `config`.
    pub async fn launch(config: &BrowserConfig) -> anyhow::Result<Self> {
        let mut builder = CdpConfig::builder().args(launch_args(config));
        if !config.headless {
            builder = builder.with_head();
        }
        let cdp_config = builder.build().map_err(anyhow::Error::msg)?;

        let (browser, events) = Browser::launch(cdp_config).await?;
        let session = CdpSession::attach(browser, events, config.nav_timeout).await?;
        // Audit minor a: `Security.setIgnoreCertificateErrors(true)` disables ALL
        // upstream certificate validation for this Chrome session — it is a
        // blanket bypass, not one scoped to the proxy CA, so a misissued or
        // attacker certificate on any upstream is also accepted. It should
        // default off and be opt-in. The default (`ignore_cert_errors: true`)
        // lives in `aitm-core::config::BrowserConfig::default` (crate outside
        // this fix's scope); flipping it to `false` belongs with that type.
        // Only the obscura engine, which trusts the proxy CA via `--ca-cert`
        // instead, avoids this bypass entirely.
        if config.ignore_cert_errors {
            session
                .page
                .execute(SetIgnoreCertificateErrorsParams::new(true))
                .await?;
        }

        Ok(Self { session })
    }

    /// Close the browser process.
    pub async fn close(self) -> anyhow::Result<()> {
        self.shutdown().await
    }

    /// The close path through a shared handle (`LaunchedBrowser`).
    pub(crate) async fn shutdown(&self) -> anyhow::Result<()> {
        self.session.close().await
    }
}

impl BrowserDriver for ChromeDriver {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        let url = url.to_string();
        Box::pin(async move { self.session.navigate(&url).await })
    }

    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(self.session.click(target))
    }

    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        let selector = selector.to_string();
        let text = text.to_string();
        Box::pin(async move { self.session.type_text(&selector, &text).await })
    }

    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(self.session.screenshot())
    }

    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        let expr = expr.to_string();
        Box::pin(async move { self.session.eval(&expr).await })
    }

    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        Box::pin(self.session.get_dom())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{BrowserConfig, Value};

    #[test]
    fn launch_args_route_through_the_proxy() {
        let config = BrowserConfig {
            proxy_addr: "127.0.0.1:18080".parse().expect("socket addr"),
            ..BrowserConfig::default()
        };
        let args = launch_args(&config);
        assert!(
            args.iter().any(|a| a == "--proxy-server=127.0.0.1:18080"),
            "no --proxy-server flag in {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--proxy-bypass-list=<-loopback>"),
            "loopback would bypass the proxy: {args:?}"
        );
    }

    #[test]
    fn json_to_value_maps_page_results() {
        assert_eq!(json_to_value(&serde_json::json!(2)), Value::Int(2));
        assert_eq!(json_to_value(&serde_json::json!(1.5)), Value::Float(1.5));
        assert_eq!(
            json_to_value(&serde_json::json!("hi")),
            Value::Str("hi".into())
        );
        assert_eq!(json_to_value(&serde_json::json!(true)), Value::Bool(true));
        assert_eq!(json_to_value(&serde_json::json!(null)), Value::Null);
        assert_eq!(
            json_to_value(&serde_json::json!([1, "a"])),
            Value::Array(vec![Value::Int(1), Value::Str("a".into())])
        );
        let Value::Object(obj) = json_to_value(&serde_json::json!({"k": 3})) else {
            panic!("expected an object");
        };
        assert_eq!(obj.get("k"), Some(&Value::Int(3)));
    }

    /// AC10 (T5): an eval whose first attempt fails because the engine no
    /// longer knows the execution context chromiumoxide handed us is retried
    /// exactly once, against the page's own default context, and the retry's
    /// value is what the caller gets.
    #[tokio::test]
    async fn eval_retries_on_stale_context() {
        let seen = std::sync::Mutex::new(Vec::new());
        let result = eval_with_context_retry(|ctx| {
            seen.lock().expect("seen lock").push(ctx);
            let attempt = seen.lock().expect("seen lock").len();
            async move {
                if attempt == 1 {
                    Err(anyhow::anyhow!(
                        "Error -32601: Cannot find context with specified id"
                    ))
                } else {
                    Ok(Value::Int(7))
                }
            }
        })
        .await
        .expect("the retry's value is returned");
        assert_eq!(result, Value::Int(7));
        assert_eq!(
            *seen.lock().expect("seen lock"),
            vec![EvalContext::Tracked, EvalContext::PageDefault],
            "exactly two attempts: the tracked context, then the page default"
        );
    }

    /// Only a stale-context error earns the retry: any other failure (a JS
    /// exception, a dead socket) is returned as-is after one attempt.
    #[tokio::test]
    async fn eval_does_not_retry_other_errors() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let err = eval_with_context_retry(|_ctx| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err::<Value, _>(anyhow::anyhow!("ReferenceError: nope is not defined")) }
        })
        .await
        .expect_err("a non-context error is not retried");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            err.to_string().contains("ReferenceError"),
            "original error preserved: {err:#}"
        );
    }

    /// A context that is gone on the retry too is the caller's error, after
    /// exactly two attempts (no unbounded retry loop).
    #[tokio::test]
    async fn eval_stale_twice_returns_second_error() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let err = eval_with_context_retry(|_ctx| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err::<Value, _>(anyhow::anyhow!("Cannot find context with specified id")) }
        })
        .await
        .expect_err("still stale after the retry");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(err.to_string().contains("Cannot find context"), "{err:#}");
    }

    /// AC11 (T6): a click that navigates nothing returns `Ok` once the short
    /// grace bound passes with no navigation started — well inside
    /// `nav_timeout`, and without ever awaiting the navigation path.
    #[tokio::test]
    async fn click_no_nav_returns_within_bound() {
        let grace = Duration::from_millis(50);
        let nav_timeout = Duration::from_secs(5);
        let awaited_nav = std::sync::atomic::AtomicBool::new(false);
        let started = std::time::Instant::now();
        settle_after_click(
            futures::future::pending::<bool>(),
            || {
                awaited_nav.store(true, std::sync::atomic::Ordering::SeqCst);
                async { anyhow::Ok(()) }
            },
            grace,
            nav_timeout,
        )
        .await
        .expect("a click that navigates nothing still succeeds");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= grace,
            "returned before the grace bound: {elapsed:?}"
        );
        assert!(
            elapsed < nav_timeout,
            "waited the whole nav_timeout: {elapsed:?}"
        );
        assert!(
            !awaited_nav.load(std::sync::atomic::Ordering::SeqCst),
            "no navigation started, so none must be awaited"
        );
    }

    /// AC11 (T6): once a navigation starts within the grace bound, the click
    /// awaits it to completion before returning.
    #[tokio::test]
    async fn click_nav_awaits_completion() {
        let finished = std::sync::atomic::AtomicBool::new(false);
        settle_after_click(
            futures::future::ready(true),
            || async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                finished.store(true, std::sync::atomic::Ordering::SeqCst);
                anyhow::Ok(())
            },
            Duration::from_millis(50),
            Duration::from_secs(5),
        )
        .await
        .expect("a completed navigation is Ok");
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "click returned before the navigation it triggered had finished"
        );
    }

    /// AC11 (T6): a navigation that starts but never finishes is bounded by
    /// `nav_timeout` and reported as such, like `navigate`'s own timeout.
    #[tokio::test]
    async fn click_nav_timeout_is_bounded() {
        let nav_timeout = Duration::from_millis(50);
        let started = std::time::Instant::now();
        let err = settle_after_click(
            futures::future::ready(true),
            futures::future::pending::<anyhow::Result<()>>,
            Duration::from_millis(10),
            nav_timeout,
        )
        .await
        .expect_err("an unfinished navigation times out");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            err.to_string().contains("timed out"),
            "timeout named in the error: {err:#}"
        );
    }

    /// M2-AC13: JS has one number type, and obscura serialises every number as
    /// a float, so an integral float is the integer (`1+1` is `Int(2)` on both
    /// engines); a true fraction, and a magnitude past the exactly-representable
    /// range, stay `Float`.
    #[test]
    fn json_to_value_folds_integral_floats() {
        assert_eq!(json_to_value(&serde_json::json!(2.0)), Value::Int(2));
        assert_eq!(json_to_value(&serde_json::json!(-3.0)), Value::Int(-3));
        assert_eq!(json_to_value(&serde_json::json!(0.0)), Value::Int(0));
        assert_eq!(json_to_value(&serde_json::json!(1.5)), Value::Float(1.5));
        assert_eq!(
            json_to_value(&serde_json::json!(1e300)),
            Value::Float(1e300)
        );
    }
}
