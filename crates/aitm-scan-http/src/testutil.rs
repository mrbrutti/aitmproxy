//! In-process test doubles for the HTTP lane's hermetic unit tests (task 9).
//!
//! The lane's inner loop must run under a plain `cargo test` with no port bound,
//! no browser launched and no traffic leaving the process, so this module stands
//! in for the three seams the lane reaches through: [`JobCtx`] ([`FakeJob`]),
//! [`ProxyClient`] ([`ScriptedClient`]) and [`BrowserDriver`] ([`FakeBrowser`]).
//!
//! **These doubles are an inner loop, never evidence.** A green test against a
//! double proves the lane's logic, not that the lane works: the acceptance
//! evidence for T2-1..T2-6 is the real end-to-end run against the seeded
//! loopback target (spec Verification). Nothing in this module is compiled into
//! a shipped binary — the whole module is `#[cfg(test)]`.
//!
//! **Redaction.** The doubles keep an in-process [`FakeBrowser::log`] so tests
//! can assert what the lane did. That log is assertion state in a test process:
//! it never reaches a `tracing` line, an error message or a stored artifact. It
//! still records a cookie *name* only, never a cookie value, so a test that
//! prints the log cannot leak one.

// A double may panic on a malformed input: that is a bug in the test that built
// it, and failing loudly is the point. The crate root denies both lints for the
// library paths that handle network and user input.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use futures::future::BoxFuture;

use aitm_core::{
    Body, BrowserDriver, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome,
    ProxyClient, RecordPolicy, ScopeEntry, ScopeRateGuard, SendOptions, StdGuard, Value,
};
use aitm_scan_model::{JobCtx, ScanProfile, SessionMaterial};

/// The job id every double reports, so a test can assert the `scan:<id>` mark
/// as a literal.
pub(crate) const JOB_ID: &str = "scan-1a2b3c4d";

/// The marker token every double reports (see `JobCtx::marker`).
pub(crate) const MARKER: &str = "aitm7f3a";

/// The authority the doubles' scope admits; the seeded target of the real run
/// uses the same shape.
pub(crate) const HOST: &str = "t:8080";

/// A loopback connection for a synthesised flow.
pub(crate) fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// A request built from an absolute `url`.
///
/// `body` is `(content-type, bytes)`; it sets both `content-type` and
/// `content-length`. Panics on a URL that is not absolute — a test that passes
/// one is wrong.
pub(crate) fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, &[u8])>,
) -> HttpRequest {
    let parsed = url::Url::parse(url).expect("the test passed an absolute URL");
    let host = parsed.host_str().expect("the test URL has a host");
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };

    let mut map = HeaderMap::new();
    map.set("host", &authority);
    for (name, value) in headers {
        map.set(name, value);
    }
    let body = match body {
        Some((content_type, bytes)) => {
            map.set("content-type", content_type);
            map.set("content-length", &bytes.len().to_string());
            Body::Bytes(bytes.to_vec())
        }
        None => Body::Empty,
    };

    HttpRequest {
        method: method.to_string(),
        scheme: parsed.scheme().to_string(),
        authority,
        path,
        version: HttpVersion::Http11,
        headers: map,
        body,
        timestamp: SystemTime::now(),
    }
}

/// A response with `content-length` set, for a script or a captured flow.
pub(crate) fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.set(name, value);
    }
    map.set("content-length", &body.len().to_string());
    HttpResponse {
        status,
        version: HttpVersion::Http11,
        headers: map,
        trailers: HeaderMap::new(),
        body: if body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(body.to_vec())
        },
        timestamp: SystemTime::now(),
    }
}

/// A flow as the proxy would have captured it: `is_replay` false, no marks.
pub(crate) fn captured_flow(
    req: HttpRequest,
    status: u16,
    resp_headers: &[(&str, &str)],
    resp_body: &[u8],
) -> HttpFlow {
    HttpFlow {
        id: FlowId::new(),
        request: req,
        response: Some(response(status, resp_headers, resp_body)),
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta {
            is_replay: false,
            ..Default::default()
        },
        intercept: InterceptState::Observed,
    }
}

/// What a [`ScriptedClient`] answers with, per request.
type Script = Box<dyn Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync>;

/// A [`ProxyClient`] that answers from a closure and records what it was asked.
///
/// It performs no I/O and consults no guard: scope is the real client's job, and
/// a lane test asserts on what the lane *sent*, which is what `sent` holds.
pub(crate) struct ScriptedClient {
    /// Every `(request, options)` pair the lane sent, in order.
    pub sent: Mutex<Vec<(HttpRequest, SendOptions)>>,
    /// Where a `RecordPolicy::Always` send is inserted, when a test wired one.
    store: Option<Arc<dyn FlowStore>>,
    /// The answer for one request.
    script: Script,
    /// An artificial per-send delay, for a test that exercises a deadline.
    pub delay: Option<Duration>,
}

impl ScriptedClient {
    /// A client answering every request from `script`, recording into no store.
    pub(crate) fn new<F>(script: F) -> Self
    where
        F: Fn(&HttpRequest) -> anyhow::Result<HttpResponse> + Send + Sync + 'static,
    {
        Self {
            sent: Mutex::new(Vec::new()),
            store: None,
            script: Box::new(script),
            delay: None,
        }
    }

    /// Insert `RecordPolicy::Always` sends into `store`, the way the real
    /// `PipelineClient` does.
    pub(crate) fn recording_into(mut self, store: Arc<dyn FlowStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Sleep `delay` inside every send, for a deadline or cancellation test.
    pub(crate) fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// The `path` (with query) of every request sent so far, in order.
    pub(crate) fn sent_paths(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(req, _)| req.path.clone())
            .collect()
    }

    /// The marks of every send so far, in order.
    pub(crate) fn sent_marks(&self) -> Vec<Vec<String>> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, opts)| opts.marks.clone())
            .collect()
    }
}

impl ProxyClient for ScriptedClient {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.send_opts(req, SendOptions::default())
    }

    fn send_opts(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push((req.clone(), opts.clone()));
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            let response = (self.script)(&req)?;
            let flow = HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(response),
                client_conn: conn(),
                server_conn: None,
                metadata: FlowMeta {
                    is_replay: true,
                    marks: opts.marks,
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            };
            if opts.record == RecordPolicy::Always {
                if let Some(store) = &self.store {
                    store.insert(Flow::Http(flow.clone()));
                }
            }
            Ok(flow)
        })
    }
}

/// One page a [`FakeBrowser`] serves, keyed in the browser by its exact URL.
pub(crate) struct PageScript {
    /// What `get_dom` returns for this page.
    pub html: String,
    /// The status `navigate` reports for this page.
    pub status: u16,
    /// Where a navigation to this page actually lands (a redirect); `None`
    /// means it lands on its own URL.
    pub final_url: Option<String>,
    /// `(selector, lands_on_url)` for every clickable on this page.
    pub clickables: Vec<(String, String)>,
    /// `(form index, lands_on_url)` for every submittable form on this page.
    ///
    /// **Deviation from the plan, noted for task 18.** The plan has the double
    /// resolve a form's action out of `html` with `crawl::extract` (task 4).
    /// That module was still a placeholder when this file was written, so the
    /// landing URL is declared explicitly here instead. The crawler's submit
    /// expression (`submit_form_js(1)`) picks the entry whose tagged index it
    /// names; an expression naming none is index 0.
    pub forms: Vec<(usize, String)>,
    /// Requests inserted into the store as captured flows when this page is
    /// reached, standing in for what the proxy would have captured.
    pub captures: Vec<HttpRequest>,
    /// The response body every capture of this page is stored with (empty by
    /// default; a test about held-body bounds makes it large).
    pub capture_body: Vec<u8>,
    /// What the *live* form at an index reports when the crawler tags it
    /// (S-I2). Without an entry the double derives the answer from `html`
    /// with the real extractor, so the live form is the declared form; a test
    /// that wants the two to diverge (a JS-mounted third-party form) sets one.
    pub live_forms: HashMap<usize, LiveFormScript>,
}

/// The attributes and control names the live form at one index reports back
/// to the crawler's tagging expression, and what has become of it by the time
/// the crawler submits it (R-I1).
#[derive(Clone, Debug, Default)]
pub(crate) struct LiveFormScript {
    pub action: Option<String>,
    pub method: Option<String>,
    pub enctype: Option<String>,
    pub names: Vec<String>,
    /// The tagged element is gone by submit time (a re-render replaced it):
    /// the submit expression finds no `form[data-aitm-form]` and answers
    /// `{ok:false}` without submitting anything.
    pub missing_at_submit: bool,
    /// The tagged element's `action` at submit time, when a script changed it
    /// after the tag eval; `None` means it still reads `action`.
    pub action_at_submit: Option<String>,
    /// The submit expression answers `{ok:true, action}` and submits whatever
    /// the live `action` is, without the in-eval origin and scheme check: a
    /// browser whose check was bypassed, so a test can prove the engine's own
    /// re-check of the returned `action` refuses it (F4-1).
    pub answers_ok_regardless: bool,
}

impl LiveFormScript {
    /// The same live form whose tagged element has vanished by submit time.
    pub(crate) fn gone_at_submit(mut self) -> Self {
        self.missing_at_submit = true;
        self
    }

    /// The same live form whose `action` reads `action` by submit time.
    pub(crate) fn with_action_at_submit(mut self, action: &str) -> Self {
        self.action_at_submit = Some(action.to_string());
        self
    }

    /// The same live form whose submit expression answers `{ok:true, action}`
    /// without checking the action's origin or scheme.
    pub(crate) fn answers_ok_regardless(mut self) -> Self {
        self.answers_ok_regardless = true;
        self
    }

    /// The `Value` the tagging expression answers with.
    fn to_value(&self) -> Value {
        let text = |value: &Option<String>| match value {
            Some(text) => Value::Str(text.clone()),
            None => Value::Null,
        };
        Value::Object(
            [
                ("action".to_string(), text(&self.action)),
                ("method".to_string(), text(&self.method)),
                ("enctype".to_string(), text(&self.enctype)),
                (
                    "names".to_string(),
                    Value::Array(self.names.iter().cloned().map(Value::Str).collect()),
                ),
            ]
            .into_iter()
            .collect(),
        )
    }
}

impl PageScript {
    /// A 200 page with `html`, no clickables, no forms and no captures.
    pub(crate) fn new(html: &str) -> Self {
        Self {
            html: html.to_string(),
            status: 200,
            final_url: None,
            clickables: Vec::new(),
            forms: Vec::new(),
            captures: Vec::new(),
            capture_body: Vec::new(),
            live_forms: HashMap::new(),
        }
    }

    /// The same page whose captures are stored with `body` as their response.
    pub(crate) fn with_capture_body(mut self, body: Vec<u8>) -> Self {
        self.capture_body = body;
        self
    }

    /// The same page whose live form `index` reports `live` instead of what
    /// `html` declares.
    pub(crate) fn with_live_form(mut self, index: usize, live: LiveFormScript) -> Self {
        self.live_forms.insert(index, live);
        self
    }

    /// The same page with `clickables` attached.
    pub(crate) fn with_clickables(mut self, clickables: &[(&str, &str)]) -> Self {
        self.clickables = clickables
            .iter()
            .map(|(selector, lands_on)| (selector.to_string(), lands_on.to_string()))
            .collect();
        self
    }

    /// The same page with its submittable forms' landing URLs attached.
    pub(crate) fn with_forms(mut self, forms: &[(usize, &str)]) -> Self {
        self.forms = forms
            .iter()
            .map(|(index, lands_on)| (*index, lands_on.to_string()))
            .collect();
        self
    }

    /// The same page with the requests the proxy would capture when it loads.
    pub(crate) fn with_captures(mut self, captures: Vec<HttpRequest>) -> Self {
        self.captures = captures;
        self
    }
}

/// A [`BrowserDriver`] over a fixed set of [`PageScript`]s.
///
/// It launches nothing and renders nothing: navigation, clicking and submitting
/// move a cursor between declared pages, and `eval` answers the handful of
/// expressions the crawler actually evaluates.
pub(crate) struct FakeBrowser {
    pages: HashMap<String, PageScript>,
    /// What the lane did, in order, for a test to assert against.
    pub log: Mutex<Vec<String>>,
    current: Mutex<String>,
    cookies: Mutex<String>,
    store: Option<Arc<dyn FlowStore>>,
}

/// The comment a crawler puts in the expression that asks for the page's
/// clickable elements.
pub(crate) const CLICKABLES_MARKER: &str = "/*aitm-clickables*/";

/// The comment a crawler puts in the expression that tags a form and reads
/// its live attributes back.
pub(crate) const TAG_FORM_MARKER: &str = "/*aitm-tag-form*/";

/// The comment a crawler puts in the expression that submits the tagged form
/// (R-I1).
pub(crate) const SUBMIT_FORM_MARKER: &str = "/*aitm-submit-form*/";

impl FakeBrowser {
    /// A browser serving `pages`, keyed by exact URL, starting on no page.
    pub(crate) fn new<K: Into<String>>(pages: Vec<(K, PageScript)>) -> Self {
        Self {
            pages: pages
                .into_iter()
                .map(|(url, page)| (url.into(), page))
                .collect(),
            log: Mutex::new(Vec::new()),
            current: Mutex::new(String::new()),
            cookies: Mutex::new(String::new()),
            store: None,
        }
    }

    /// Insert each reached page's `captures` into `store`, standing in for the
    /// proxy capturing the browser's own traffic.
    pub(crate) fn recording_into(mut self, store: Arc<dyn FlowStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Everything the browser was asked to do, in order.
    pub(crate) fn log_lines(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// The URL the browser is on.
    pub(crate) fn current_url(&self) -> String {
        self.current.lock().unwrap().clone()
    }

    /// The browser's cookie jar, in `document.cookie` form.
    pub(crate) fn cookie_header(&self) -> String {
        self.cookies.lock().unwrap().clone()
    }

    fn log_line(&self, line: String) {
        self.log.lock().unwrap().push(line);
    }

    /// Move to `url`, capturing that page's traffic. Returns its status, or 404
    /// when no page was declared for it.
    fn land_on(&self, url: &str) -> u16 {
        let Some(page) = self.pages.get(url) else {
            *self.current.lock().unwrap() = url.to_string();
            return 404;
        };
        let landed = page.final_url.clone().unwrap_or_else(|| url.to_string());
        *self.current.lock().unwrap() = landed;
        if let Some(store) = &self.store {
            for req in &page.captures {
                store.insert(Flow::Http(captured_flow(
                    req.clone(),
                    200,
                    &[],
                    &page.capture_body,
                )));
            }
        }
        page.status
    }

    /// Replace or append `pair` ("name=value") in the jar, keeping order.
    fn store_cookie(&self, pair: &str) {
        let Some((name, _)) = pair.split_once('=') else {
            return;
        };
        let mut jar = self.cookies.lock().unwrap();
        let mut kept: Vec<String> = jar
            .split(';')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .filter(|c| c.split_once('=').map(|(n, _)| n) != Some(name))
            .map(str::to_string)
            .collect();
        kept.push(pair.to_string());
        *jar = kept.join("; ");
    }
}

impl FakeBrowser {
    /// The live form at `index` on the current page: the test's override when
    /// it set one, otherwise what the page's markup declares, read with the
    /// real extractor; `None` when the page has no form there.
    fn live_form(&self, index: usize) -> Option<LiveFormScript> {
        let current = self.current_url();
        let page = self.pages.get(&current)?;
        if let Some(live) = page.live_forms.get(&index) {
            return Some(live.clone());
        }
        let declared = crate::crawl::extract::extract(&page.html)
            .forms
            .into_iter()
            .find(|form| form.index == index)?;
        Some(LiveFormScript {
            action: declared.action.clone(),
            method: Some(declared.method.clone()),
            enctype: declared.enctype.clone(),
            names: declared
                .fields
                .iter()
                .map(|field| field.name.clone())
                .collect(),
            ..LiveFormScript::default()
        })
    }

    /// What the crawler's tagged submit expression does on this page, as the
    /// real expression would: no tagged element answers `{ok:false}` and
    /// submits nothing; an element whose `action` now resolves off the page's
    /// origin answers `{ok:false, action}` and submits nothing; otherwise the
    /// form is submitted (logged `submit <index>`, landing where the page's
    /// `forms` entry says) and the answer is `{ok:true, action}` (R-I1).
    ///
    /// A [`LiveFormScript::answers_ok_regardless`] form skips the origin check
    /// and submits whatever the action is, standing in for a browser whose
    /// in-eval check was bypassed.
    fn submit_tagged(&self, index: usize) -> Value {
        let answer = |ok: bool, action: Option<&str>| {
            let mut fields: BTreeMap<String, Value> = BTreeMap::new();
            fields.insert("ok".to_string(), Value::Bool(ok));
            if let Some(action) = action {
                fields.insert("action".to_string(), Value::Str(action.to_string()));
            }
            Value::Object(fields)
        };
        let Some(live) = self.live_form(index) else {
            return answer(false, None);
        };
        if live.missing_at_submit {
            return answer(false, None);
        }
        let action = live.action_at_submit.as_deref().or(live.action.as_deref());
        let current = self.current_url();
        let here = crate::url_norm::parse_absolute(&current);
        let target = match (&here, action.map(str::trim)) {
            (Some(here), None | Some("")) => Some(here.clone()),
            (Some(here), Some(action)) => crate::url_norm::resolve(here, action),
            (None, _) => None,
        };
        let same_origin = match (&here, &target) {
            (Some(here), Some(target)) => crate::url_norm::same_origin(target, here),
            _ => false,
        };
        if !same_origin && !live.answers_ok_regardless {
            return answer(false, action);
        }
        self.log_line(format!("submit {index}"));
        let lands_on = self.pages.get(&current).and_then(|page| {
            page.forms
                .iter()
                .find(|(i, _)| *i == index)
                .map(|(_, lands_on)| lands_on.clone())
        });
        if let Some(lands_on) = lands_on {
            self.land_on(&lands_on);
        }
        answer(true, action)
    }
}

/// The text between the first quote pair in `expr`, if any.
fn quoted(expr: &str) -> Option<&str> {
    let start = expr.find(['"', '\''])?;
    let quote = expr.as_bytes()[start] as char;
    let rest = &expr[start + 1..];
    let end = rest.find(quote)?;
    Some(&rest[..end])
}

/// The form index an expression names: the `N` of `data-aitm-form="N"` (the
/// tagged selector the submit expression uses) or of `document.forms[N]` (the
/// tag expression), defaulting to 0 when it names none.
///
/// The submit expression carries the selector inside a JS string literal, so
/// its quotes arrive escaped (`data-aitm-form=\"N\"`); the backslashes are
/// dropped before matching so both spellings resolve to the same `N`.
fn form_index(expr: &str) -> usize {
    let expr = expr.replace('\\', "");
    let after = expr
        .find("data-aitm-form=\"")
        .map(|open| open + "data-aitm-form=\"".len())
        .or_else(|| expr.find("forms[").map(|open| open + "forms[".len()));
    let Some(after) = after else {
        return 0;
    };
    let digits: String = expr[after..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().unwrap_or(0)
}

impl BrowserDriver for FakeBrowser {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        let url = url.to_string();
        Box::pin(async move {
            self.log_line(format!("navigate {url}"));
            let status = self.land_on(&url);
            Ok(NavOutcome {
                final_url: self.current_url(),
                status: Some(status),
            })
        })
    }

    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            match target {
                ClickTarget::Selector(selector) => {
                    self.log_line(format!("click {selector}"));
                    let lands_on = {
                        let current = self.current_url();
                        self.pages.get(&current).and_then(|page| {
                            page.clickables
                                .iter()
                                .find(|(sel, _)| *sel == selector)
                                .map(|(_, lands_on)| lands_on.clone())
                        })
                    };
                    match lands_on {
                        Some(lands_on) => {
                            self.land_on(&lands_on);
                            Ok(())
                        }
                        None => Err(anyhow::anyhow!(
                            "the double has no clickable {selector} on the current page"
                        )),
                    }
                }
                ClickTarget::Point { x, y } => {
                    self.log_line(format!("click point {x},{y}"));
                    Ok(())
                }
            }
        })
    }

    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        let line = format!("type {selector} = {text}");
        Box::pin(async move {
            self.log_line(line);
            Ok(())
        })
    }

    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        let expr = expr.to_string();
        Box::pin(async move {
            // `document.cookie = "..."` writes; a bare `document.cookie` reads.
            if let Some(after) = expr.split_once("document.cookie").map(|(_, rest)| rest) {
                if after.trim_start().starts_with('=') {
                    if let Some(assigned) = quoted(after) {
                        let pair = assigned.split(';').next().unwrap_or("").trim();
                        if let Some((name, _)) = pair.split_once('=') {
                            // The name only: a cookie value never enters the log.
                            self.log_line(format!("cookie-set {name}"));
                            self.store_cookie(pair);
                        }
                    }
                    return Ok(Value::Null);
                }
                return Ok(Value::Str(self.cookie_header()));
            }
            if expr.contains(CLICKABLES_MARKER) {
                let current = self.current_url();
                let items = self
                    .pages
                    .get(&current)
                    .map(|page| {
                        page.clickables
                            .iter()
                            .map(|(selector, _)| {
                                // The double has no rendered text, so `text`
                                // repeats the selector.
                                Value::Object(
                                    [
                                        ("selector".to_string(), Value::Str(selector.clone())),
                                        ("text".to_string(), Value::Str(selector.clone())),
                                    ]
                                    .into_iter()
                                    .collect(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return Ok(Value::Array(items));
            }
            if expr.contains(TAG_FORM_MARKER) {
                let index = form_index(&expr);
                return Ok(self
                    .live_form(index)
                    .map_or(Value::Null, |live| live.to_value()));
            }
            // A `set_checked_js` expression: logged as `check <selector>` so a
            // test can see which group members the engine checked (Q7).
            if expr.contains(".checked=true") {
                let selector = expr
                    .split_once("querySelector(\"")
                    .and_then(|(_, rest)| rest.split_once("\");"))
                    .map(|(selector, _)| selector.to_string())
                    .unwrap_or_default();
                self.log_line(format!("check {selector}"));
                return Ok(Value::Null);
            }
            if expr.contains(SUBMIT_FORM_MARKER) {
                return Ok(self.submit_tagged(form_index(&expr)));
            }
            if expr.contains("location.href") {
                Ok(Value::Str(self.current_url()))
            } else if expr.contains("document.readyState") {
                Ok(Value::Str("complete".to_string()))
            } else {
                Ok(Value::Null)
            }
        })
    }

    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        Box::pin(async move {
            let current = self.current_url();
            Ok(self
                .pages
                .get(&current)
                .map(|page| page.html.clone())
                .unwrap_or_default())
        })
    }
}

/// A [`JobCtx`] over the doubles: a scripted client, an in-memory store, a real
/// [`StdGuard`] scoped to the test host, and a counted budget.
pub(crate) struct FakeJob {
    pub profile: ScanProfile,
    pub client: Arc<ScriptedClient>,
    pub store: Arc<MemFlowStore>,
    pub guard: Arc<StdGuard>,
    pub browser: Option<Arc<FakeBrowser>>,
    pub session: Option<Arc<SessionMaterial>>,
    pub budget: AtomicU32,
    /// How many charges were affordable (a refused charge is not counted).
    pub charges: AtomicU32,
    pub cancelled: AtomicBool,
    pub deadline: Instant,
}

impl FakeJob {
    /// A job with a budget of 1000, a deadline a minute out and the test host
    /// in scope.
    pub(crate) fn new(profile: ScanProfile, client: Arc<ScriptedClient>) -> Self {
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: HOST.to_string(),
        });
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        Self {
            profile,
            client,
            store: Arc::new(MemFlowStore::new()),
            guard,
            browser: None,
            session: None,
            budget: AtomicU32::new(1000),
            charges: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    /// The same job reading and writing `store`.
    pub(crate) fn with_store(mut self, store: Arc<MemFlowStore>) -> Self {
        self.store = store;
        self
    }

    /// The same job holding `browser`.
    pub(crate) fn with_browser(mut self, browser: Arc<FakeBrowser>) -> Self {
        self.browser = Some(browser);
        self
    }

    /// The same job holding `session`.
    pub(crate) fn with_session(mut self, session: SessionMaterial) -> Self {
        self.session = Some(Arc::new(session));
        self
    }

    /// The same job with `units` of budget.
    pub(crate) fn with_budget(self, units: u32) -> Self {
        self.budget.store(units, Ordering::SeqCst);
        self
    }

    /// The same job already cancelled.
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl JobCtx for FakeJob {
    fn job_id(&self) -> &str {
        JOB_ID
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn client(&self) -> Arc<dyn ProxyClient> {
        Arc::clone(&self.client) as Arc<dyn ProxyClient>
    }

    fn store(&self) -> Arc<dyn FlowStore> {
        Arc::clone(&self.store) as Arc<dyn FlowStore>
    }

    fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        Arc::clone(&self.guard) as Arc<dyn ScopeRateGuard>
    }

    fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
        self.browser
            .clone()
            .map(|browser| browser as Arc<dyn BrowserDriver>)
    }

    fn session(&self) -> Option<Arc<SessionMaterial>> {
        self.session.clone()
    }

    fn charge(&self, units: u32) -> bool {
        let charged = self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(units)
            })
            .is_ok();
        if charged {
            self.charges.fetch_add(1, Ordering::SeqCst);
        }
        charged
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::SeqCst)
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn marker(&self) -> String {
        MARKER.to_string()
    }
}

/// A tiny static site: `path` → `html`, answered 200 as `text/html`.
///
/// An unknown path answers 404 with an empty body. An entry whose html starts
/// with `302:` answers a redirect to the rest of that string instead. A request
/// path is matched whole (query included) first, then with its query stripped,
/// so a test can register either form.
pub(crate) fn site(pages: &[(&str, &str)]) -> ScriptedClient {
    let pages: HashMap<String, String> = pages
        .iter()
        .map(|(path, html)| ((*path).to_string(), (*html).to_string()))
        .collect();
    ScriptedClient::new(move |req: &HttpRequest| {
        let bare = req.path.split('?').next().unwrap_or(&req.path);
        let Some(html) = pages.get(&req.path).or_else(|| pages.get(bare)) else {
            return Ok(response(404, &[("content-type", "text/html")], b""));
        };
        match html.strip_prefix("302:") {
            Some(location) => Ok(response(302, &[("location", location)], b"")),
            None => Ok(response(
                200,
                &[("content-type", "text/html; charset=utf-8")],
                html.as_bytes(),
            )),
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The body bytes of a flow's response, for an assertion on a literal.
    fn body_of(flow: &HttpFlow) -> Vec<u8> {
        match &flow.response.as_ref().unwrap().body {
            Body::Bytes(bytes) => bytes.clone(),
            Body::Empty => Vec::new(),
            Body::Streamed(_) => panic!("the doubles never stream"),
        }
    }

    #[tokio::test]
    async fn scripted_client_records_only_on_always() {
        let store = Arc::new(MemFlowStore::new());
        let client = ScriptedClient::new(|_req| Ok(response(200, &[], b"hi")))
            .recording_into(store.clone() as Arc<dyn FlowStore>);

        let flow = client
            .send_opts(
                request("GET", "http://t:8080/a", &[], None),
                SendOptions {
                    record: RecordPolicy::Never,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(store.count(), 0);
        assert_eq!(client.sent.lock().unwrap().len(), 1);
        assert!(flow.metadata.is_replay);
        assert!(flow.metadata.marks.is_empty());

        let marks = vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()];
        let flow = client
            .send_opts(
                request("GET", "http://t:8080/b", &[], None),
                SendOptions {
                    record: RecordPolicy::Always,
                    marks: marks.clone(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(store.count(), 1);
        assert_eq!(flow.metadata.marks, marks);

        let stored = store.get(flow.id).unwrap();
        let Flow::Http(stored) = stored else {
            panic!("the double stores HTTP flows");
        };
        assert_eq!(stored.metadata.marks, marks);
        assert_eq!(stored.request.path, "/b");
        assert_eq!(
            client.sent_paths(),
            vec!["/a".to_string(), "/b".to_string()]
        );
        assert_eq!(client.sent_marks(), vec![Vec::<String>::new(), marks]);
    }

    #[tokio::test]
    async fn fake_browser_cookie_round_trip() {
        let browser = FakeBrowser::new(vec![("http://t:8080/", PageScript::new("<html></html>"))]);

        browser
            .eval("document.cookie = \"sid=S3; path=/\"")
            .await
            .unwrap();
        let got = browser.eval("document.cookie").await.unwrap();

        assert_eq!(got, Value::Str("sid=S3".to_string()));
        // The value never enters the log; the name does.
        assert_eq!(browser.log_lines(), vec!["cookie-set sid".to_string()]);
    }

    #[test]
    fn fake_job_charges() {
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        )
        .with_budget(2);

        assert!(job.charge(1));
        assert!(job.charge(1));
        assert!(!job.charge(1));
        assert_eq!(job.charges.load(Ordering::SeqCst), 2);
        assert_eq!(job.budget_left(), 0);
        assert_eq!(job.job_id(), "scan-1a2b3c4d");
        assert_eq!(job.marker(), "aitm7f3a");
        assert!(!job.cancelled());
        job.cancel();
        assert!(job.cancelled());
    }

    #[test]
    fn request_sets_authority_path_and_body_headers() {
        let req = request(
            "POST",
            "http://t:8080/login?next=/a",
            &[("x-test", "1")],
            Some(("application/x-www-form-urlencoded", b"u=a&p=b")),
        );

        assert_eq!(req.method, "POST");
        assert_eq!(req.scheme, "http");
        assert_eq!(req.authority, "t:8080");
        assert_eq!(req.path, "/login?next=/a");
        assert_eq!(req.headers.get("host"), Some("t:8080"));
        assert_eq!(req.headers.get("x-test"), Some("1"));
        assert_eq!(
            req.headers.get("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(req.headers.get("content-length"), Some("7"));
        assert!(matches!(req.body, Body::Bytes(ref b) if b == b"u=a&p=b"));
    }

    #[tokio::test]
    async fn site_serves_pages_a_redirect_and_a_404() {
        let client = site(&[
            ("/", "<a href=\"/a\">a</a>"),
            ("/a", "302:http://t:8080/b"),
            ("/b", "done"),
        ]);

        let home = client
            .send(request("GET", "http://t:8080/?q=1", &[], None))
            .await
            .unwrap();
        assert_eq!(home.response.as_ref().unwrap().status, 200);
        assert_eq!(
            home.response.as_ref().unwrap().headers.get("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(body_of(&home), b"<a href=\"/a\">a</a>".to_vec());

        let redirect = client
            .send(request("GET", "http://t:8080/a", &[], None))
            .await
            .unwrap();
        assert_eq!(redirect.response.as_ref().unwrap().status, 302);
        assert_eq!(
            redirect.response.as_ref().unwrap().headers.get("location"),
            Some("http://t:8080/b")
        );

        let missing = client
            .send(request("GET", "http://t:8080/nope", &[], None))
            .await
            .unwrap();
        assert_eq!(missing.response.as_ref().unwrap().status, 404);
    }

    /// The self-test's home page: one form at index 0, posting to `/posted`.
    const HOME_WITH_FORM: &str =
        "<html><form action=\"/posted\" method=\"post\"><input name=\"x\"></form>home</html>";

    #[tokio::test]
    async fn fake_browser_navigates_clicks_submits_and_captures() {
        let store = Arc::new(MemFlowStore::new());
        let browser = FakeBrowser::new(vec![
            (
                "http://t:8080/",
                PageScript::new(HOME_WITH_FORM)
                    .with_clickables(&[("#next", "http://t:8080/a")])
                    .with_forms(&[(0, "http://t:8080/posted")])
                    .with_captures(vec![request("GET", "http://t:8080/app.js", &[], None)]),
            ),
            ("http://t:8080/a", PageScript::new("<html>a</html>")),
            ("http://t:8080/posted", PageScript::new("<html>ok</html>")),
        ])
        .recording_into(store.clone() as Arc<dyn FlowStore>);

        let outcome = browser.navigate("http://t:8080/").await.unwrap();
        assert_eq!(outcome.final_url, "http://t:8080/");
        assert_eq!(outcome.status, Some(200));
        assert_eq!(store.count(), 1);
        assert_eq!(browser.get_dom().await.unwrap(), HOME_WITH_FORM);
        assert_eq!(
            browser.eval("location.href").await.unwrap(),
            Value::Str("http://t:8080/".to_string())
        );
        assert_eq!(
            browser.eval("document.readyState").await.unwrap(),
            Value::Str("complete".to_string())
        );
        assert_eq!(
            browser
                .eval(&format!("{CLICKABLES_MARKER} collect()"))
                .await
                .unwrap(),
            Value::Array(vec![Value::Object(
                [
                    ("selector".to_string(), Value::Str("#next".to_string())),
                    ("text".to_string(), Value::Str("#next".to_string())),
                ]
                .into_iter()
                .collect()
            )])
        );

        // The crawler's real submit expression: the double finds the form the
        // markup declares at index 0 and lands where `forms` says.
        let submitted = browser
            .eval(&crate::crawl::browser::submit_form_js(0))
            .await
            .unwrap();
        assert_eq!(
            submitted,
            Value::Object(
                [
                    ("ok".to_string(), Value::Bool(true)),
                    ("action".to_string(), Value::Str("/posted".to_string())),
                ]
                .into_iter()
                .collect()
            )
        );
        assert_eq!(browser.current_url(), "http://t:8080/posted");

        browser.navigate("http://t:8080/").await.unwrap();
        browser
            .click(ClickTarget::Selector("#next".to_string()))
            .await
            .unwrap();
        assert_eq!(browser.current_url(), "http://t:8080/a");

        browser.type_text("#u", "aitm").await.unwrap();
        assert_eq!(
            browser.log_lines(),
            vec![
                "navigate http://t:8080/".to_string(),
                "submit 0".to_string(),
                "navigate http://t:8080/".to_string(),
                "click #next".to_string(),
                "type #u = aitm".to_string(),
            ]
        );
        // The home page was reached twice, so its capture was inserted twice.
        assert_eq!(store.count(), 2);

        let unknown = browser.navigate("http://t:8080/gone").await.unwrap();
        assert_eq!(unknown.status, Some(404));
        assert_eq!(browser.get_dom().await.unwrap(), "");
        assert!(browser
            .click(ClickTarget::Selector("#nope".to_string()))
            .await
            .is_err());
    }

    /// The double reads the form index out of the real expressions it is
    /// handed: the tag expression names `document.forms[N]`, and the submit
    /// expression names the tagged selector inside a JS string, where the
    /// quotes are escaped (`form[data-aitm-form=\"N\"]`). A double that only
    /// matched the unescaped form would submit form 0 for every index and
    /// never prove the tagged index (F4-1).
    #[test]
    fn form_index_reads_the_tag_and_submit_expressions() {
        use crate::crawl::browser::{submit_form_js, tag_form_js};

        assert_eq!(form_index(&tag_form_js(0)), 0);
        assert_eq!(form_index(&tag_form_js(1)), 1);
        assert_eq!(form_index(&tag_form_js(12)), 12);
        assert_eq!(form_index(&submit_form_js(0)), 0);
        assert_eq!(form_index(&submit_form_js(1)), 1);
        assert_eq!(form_index(&submit_form_js(12)), 12);
        assert_eq!(form_index("document.cookie"), 0);
    }
}
