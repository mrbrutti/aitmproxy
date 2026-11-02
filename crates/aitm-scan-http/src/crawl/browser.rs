//! The browser crawl engine: navigation, clicks, form submissions and the
//! store diff that marks what they captured (task 18).
//!
//! This is the engine the lane prefers when the job has a browser (spec
//! **D8.1**): the target's own JavaScript runs, so routes that only a click
//! handler or a rendered form reaches are discovered, which no client-side HTML
//! walk can do. Three properties make that safe to run against a live
//! engagement:
//!
//! - **Everything is charged and bounded.** Every navigation, click and form
//!   submission calls `job.charge(1)` first and stops the crawl the moment the
//!   budget refuses (spec **D5**: the browser's own traffic is not sent through
//!   the job's client, so the lane is the only thing that can meter it). Every
//!   await on the browser is bounded by [`remaining`], every loop polls
//!   `job.cancelled()`, and one [`ScopeRateGuard`] permit is held across each
//!   page's navigation and DOM read.
//! - **The flows are real captures.** The browser is proxied, so a navigation
//!   lands in the flow store as an ordinary capture rather than as a replay.
//!   The lane therefore brackets every browser action with a [`StoreDiff`] and
//!   marks what appeared `scan:<job>` and `crawl` (spec **D5**, "crawl flows are
//!   different"; AC **T1-9**: every flow a job adds to the store carries its
//!   job mark). A flow that was already in the store is never touched.
//! - **It cannot wander off the engagement.** A navigation that lands on
//!   another origin, or on a host the scope guard does not admit, stops the
//!   crawl with `left_scope` instead of continuing: unlike a client `GET`, the
//!   browser *is* now on that page, and the next click would be a click on a
//!   third party.
//!
//! The page order is fixed — links, then forms, then clicks (plan call
//! **A3**) — so the charges one page costs are deterministic and a reviewer can
//! count them. A submission or a click usually navigates away; the engine
//! returns to the page only when another form or click is still waiting on it,
//! and that return is charged like any other navigation.
//!
//! Form submission goes through `requestSubmit()` on the form element tagged
//! with `data-aitm-form` (plan call **A4**) rather than through clicking a
//! submit control: it is deterministic across layouts and still fires the
//! page's own submit handlers. The submit expression addresses the tagged
//! element, never a `document.forms` index (that collection is live, so a
//! consent banner or a re-render between the tag eval and the submit eval
//! would put another form at the index), re-reads its `action` in the same
//! eval and refuses one that resolves off the page's origin before anything
//! is submitted (R-I1). Values come from [`crate::crawl::values`], which
//! generates inert ones.
//!
//! Nothing here logs a URL that has not been through [`safe_url`], and no DOM
//! text, field value or cookie value ever reaches a log line (spec D8.1
//! redaction rules, AC **T2-6**).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    BrowserDriver, ClickTarget, Flow, FlowId, FlowStore, HttpFlow, ScopeRateGuard, Value,
};
use aitm_scan_model::{JobCtx, SessionMaterial};
use futures::future::BoxFuture;
use url::Url;

use crate::crawl::extract::{extract, Extracted, FieldKind, FormSpec};
use crate::crawl::frontier::{
    crawl_error_token, fingerprint, held_copy, remaining, CrawlReport, Crawler, Frontier, Limits,
    StopReason,
};
use crate::crawl::values::{chosen_fields, form_action, value_for};
use crate::limits::{
    job_mark, MARK_CRAWL, MAX_CLICKABLES_LISTED, MAX_DOM_BYTES, MAX_STORED_FLOWS, SETTLE_MAX_MS,
    SETTLE_POLL_MS,
};
use crate::redact::{safe_url, scrub_error};
use crate::session::{browser_cookie_statements, browser_partial};
use crate::url_norm::{guard_authority, parse_absolute, request_url, resolve, same_origin};

/// The crawl engine that drives the embedded browser.
///
/// Stateless: one value serves every job, and everything a run needs lives in
/// the [`Run`] it builds per crawl.
pub(crate) struct BrowserCrawler;

impl Crawler for BrowserCrawler {
    fn crawl<'a>(
        &'a self,
        origin: &'a Url,
        seeds: Vec<Url>,
        job: &'a dyn JobCtx,
        limits: &'a Limits,
    ) -> BoxFuture<'a, anyhow::Result<CrawlReport>> {
        Box::pin(async move {
            let Some(browser) = job.browser() else {
                // The lane picks the engine, so this is a wiring mistake rather
                // than a target problem: it is an `Err`, not a stop reason.
                anyhow::bail!("scan: no browser for the browser crawl engine");
            };
            let mut run = Run::new(browser, origin, job, limits);
            for seed in seeds {
                run.frontier.push(seed, 0, limits);
            }
            let stopped = run.run_pages().await?;
            Ok(run.into_report(stopped))
        })
    }
}

/// What the store held before this page's browser actions, so the flows each
/// action produced can be told apart from everything else in it.
///
/// A browser navigation is a real capture through the proxy listener, so the
/// job's own client never sees it and cannot mark it. The lane takes one
/// snapshot per page and calls [`StoreDiff::mark_new`] after each action on
/// that page, which is the whole of spec **D5**'s "the lane diffs the store
/// around each navigation". The snapshot is the O(store) step; every id a
/// `mark_new` sees joins `seen`, so the later actions of a page diff against a
/// running set instead of re-listing the store each time (S-M6).
///
/// The `Default` diff has seen nothing, so it treats every flow in the store
/// as new; a run starts from it and takes its first real snapshot on the first
/// page.
#[derive(Default)]
pub(crate) struct StoreDiff {
    seen: HashSet<FlowId>,
}

impl StoreDiff {
    /// The ids the store holds right now.
    pub(crate) fn snapshot(store: &dyn FlowStore) -> Self {
        Self {
            seen: store.list().into_iter().collect(),
        }
    }

    /// Mark every HTTP flow added since the snapshot whose request addresses
    /// `origin`, and return those flows as the store now holds them, each as a
    /// [`held_copy`] without its response body (S-I3, R-M3).
    ///
    /// Every id this call sees joins the running set, so the next call on the
    /// same page reports only what arrived after it. Marks are a union: a
    /// flow that already carries one keeps one copy of each. A flow to another
    /// origin is left alone — the browser fetches fonts, analytics and CDN
    /// assets while it renders, and those are not this job's traffic.
    pub(crate) fn mark_new(
        &mut self,
        store: &dyn FlowStore,
        origin: &Url,
        marks: &[String],
    ) -> Vec<HttpFlow> {
        let mut produced = Vec::new();
        for id in store.list() {
            if !self.seen.insert(id) {
                continue;
            }
            let Some(Flow::Http(flow)) = store.get(id) else {
                continue;
            };
            let Some(url) = request_url(&flow.request) else {
                continue;
            };
            if !same_origin(&url, origin) {
                continue;
            }
            store.update(id, &mut |stored| {
                if let Flow::Http(http) = stored {
                    for mark in marks {
                        if !http.metadata.marks.iter().any(|held| held == mark) {
                            http.metadata.marks.push(mark.clone());
                        }
                    }
                }
            });
            if let Some(Flow::Http(marked)) = store.get(id) {
                produced.push(held_copy(marked));
            }
        }
        produced
    }
}

/// Put the job's session cookies into the browser profile and report which ones
/// did not take.
///
/// The browser is a separate HTTP client with its own jar, so a session the
/// scanner observed on the wire does not exist in it until the lane writes it
/// (spec **D7**). The only way in without a recorded login is
/// `document.cookie`, which an `HttpOnly` cookie is invisible to by design: the
/// assignment is accepted and silently dropped. The read-back is therefore not
/// a formality — it is how the lane learns the browser crawl is browsing
/// **unauthenticated**, and the returned names are what the caller warns with.
///
/// Returns the session cookie **names** the profile is missing; never a value,
/// and no value is logged here or by the caller (AC **T2-6**).
pub(crate) async fn prime_session(
    browser: &dyn BrowserDriver,
    origin: &Url,
    material: &SessionMaterial,
    job: &dyn JobCtx,
) -> anyhow::Result<Vec<String>> {
    if !job.charge(1) {
        anyhow::bail!("scan: the job budget is exhausted before the browser could be primed");
    }
    // A cookie can only be written for the document's own origin, so the
    // profile must be on the target before the assignments run.
    let root = origin_root(origin);
    bounded(job, browser.navigate(root.as_str())).await?;
    for statement in browser_cookie_statements(material) {
        bounded(job, browser.eval(&statement)).await?;
    }
    let read_back = match bounded(job, browser.eval("document.cookie")).await? {
        Value::Str(cookies) => cookies,
        _ => String::new(),
    };
    Ok(browser_partial(material, &read_back))
}

/// The one expression the engine evaluates to find what a pointer can click.
///
/// It is marked with `/*aitm-clickables*/` so a reader of a target's console
/// log, a CSP report or a test double can tell at a glance which expression the
/// scanner injected. It reads the DOM and nothing else: no `fetch`, no
/// mutation, no synthesised click. Each element is reported as a unique
/// `tag:nth-child(n)` chain from `<body>`, because that is stable between the
/// listing and the click even on a page that has no ids and repeats its
/// classes; an element outside `<body>` is skipped rather than given an
/// ambiguous selector. `text` is the trimmed, bounded label, for the operator's
/// log only.
///
/// The selector set is the "only a click reaches this" set: a `javascript:`
/// anchor, anything with an `onclick`, a non-submit `button` (a submit control
/// belongs to its form and is driven by [`submit_form_js`]), an ARIA
/// `role=button`, and the `data-href` idiom. The cap mirrors
/// [`MAX_CLICKABLES_LISTED`], which `js_helpers_pin` ties to this text.
pub(crate) const CLICKABLES_JS: &str = concat!(
    "/*aitm-clickables*/(function(){",
    "var out=[];",
    "var nodes=document.querySelectorAll(",
    "'a[href^=\"javascript:\"], [onclick], button:not([type=submit]), [role=button], [data-href]'",
    ");",
    "for(var i=0;i<nodes.length&&out.length<32;i++){",
    "var node=nodes[i];var parts=[];var at=node;var ok=true;",
    "while(at&&at!==document.body){",
    "var parent=at.parentNode;",
    "if(!parent||!parent.firstElementChild){ok=false;break;}",
    "var n=1;",
    "for(var sib=parent.firstElementChild;sib&&sib!==at;sib=sib.nextElementSibling){n++;}",
    "parts.unshift(at.tagName.toLowerCase()+':nth-child('+n+')');",
    "at=parent;}",
    "if(!ok||at!==document.body||parts.length===0){continue;}",
    "var label=(node.textContent||'').replace(/\\s+/g,' ').trim().slice(0,80);",
    "out.push({selector:'body > '+parts.join(' > '),text:label});}",
    "return out;})()"
);

/// Tag `document.forms[index]` with `data-aitm-form` so [`field_selector`] can
/// address its controls unambiguously, and read the **live** form back.
///
/// A page may hold several forms with the same field names (a header search and
/// a page search); without the tag, `[name="q"]` would type into whichever came
/// first in the document.
///
/// The expression answers an object — `action`, `method` and `enctype` as the
/// live element's attributes (`null` when absent) and `names`, the ordered
/// `name`s of its `input`/`select`/`textarea` controls minus the buttons — or
/// `null` when there is no form at that index. The engine submits only when
/// that answer agrees with the form the extractor read (S-I2): the page is
/// re-navigated between extraction and submission, and a JS-mounted
/// third-party form or a markup shape the extractor and the browser read
/// differently would otherwise put a different form at index `i`.
///
/// Everything is read through the prototype getters: a form's named controls
/// shadow its own properties, so `f.action` with an `<input name="action">`
/// in the form is the input, and `f.getAttribute`, `f.setAttribute` and
/// `f.elements` can be clobbered the same way. It reads the DOM and nothing
/// else, like [`CLICKABLES_JS`], and is marked `/*aitm-tag-form*/` for the
/// same reason.
pub(crate) fn tag_form_js(index: usize) -> String {
    format!(
        concat!(
            "/*aitm-tag-form*/(function(){{",
            "var f=document.forms[{index}];if(!f){{return null;}}",
            "var get=Element.prototype.getAttribute;",
            "Element.prototype.setAttribute.call(f,\"data-aitm-form\",\"{index}\");",
            "var els=Object.getOwnPropertyDescriptor(HTMLFormElement.prototype,\"elements\")",
            ".get.call(f);",
            "var names=[];",
            "for(var k=0;k<els.length;k++){{var e=els[k];var tag=e.tagName;",
            "if(tag!==\"INPUT\"&&tag!==\"SELECT\"&&tag!==\"TEXTAREA\"){{continue;}}",
            "var type=(get.call(e,\"type\")||\"\").trim().toLowerCase();",
            "if(tag===\"INPUT\"&&(type===\"submit\"||type===\"button\"||type===\"image\"",
            "||type===\"reset\")){{continue;}}",
            "var n=get.call(e,\"name\");if(n&&n.trim()){{names.push(n.trim());}}}}",
            "return {{action:get.call(f,\"action\"),method:get.call(f,\"method\"),",
            "enctype:get.call(f,\"enctype\"),names:names}};}})()"
        ),
        index = index
    )
}

/// What [`tag_form_js`] read from the live form.
struct LiveForm {
    action: Option<String>,
    method: Option<String>,
    enctype: Option<String>,
    names: Vec<String>,
}

impl LiveForm {
    /// The live form in `value`, or `None` when the page answered anything but
    /// the object [`tag_form_js`] builds (no form at that index, a driver that
    /// could not serialise it).
    fn from_value(value: &Value) -> Option<Self> {
        let Value::Object(fields) = value else {
            return None;
        };
        let text = |key: &str| match fields.get(key) {
            Some(Value::Str(text)) => Some(text.clone()),
            _ => None,
        };
        let Some(Value::Array(items)) = fields.get("names") else {
            return None;
        };
        let names = items
            .iter()
            .filter_map(|item| match item {
                Value::Str(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        Some(Self {
            action: text("action"),
            method: text("method"),
            enctype: text("enctype"),
            names,
        })
    }

    /// The live form in the extractor's shape, normalised by the extractor's
    /// own [`FormSpec::from_attrs`], so [`form_action`] judges it by exactly
    /// the rule that admitted the extracted form.
    fn as_spec(&self, index: usize) -> FormSpec {
        FormSpec::from_attrs(
            index,
            self.action.as_deref(),
            self.method.as_deref(),
            self.enctype.as_deref(),
        )
    }

    /// Whether this live form is the form the extractor read as `form`: its
    /// action resolves same-origin with a `GET`/`POST` method, and its
    /// controls are `form`'s controls (as a set of names).
    fn matches(&self, form: &FormSpec, page: &Url, origin: &Url, base: Option<&str>) -> bool {
        if form_action(&self.as_spec(form.index), page, origin, base).is_none() {
            return false;
        }
        let declared: HashSet<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        let live: HashSet<&str> = self.names.iter().map(String::as_str).collect();
        declared == live
    }
}

/// What [`submit_form_js`] answered: whether the tagged form was found,
/// admitted and submitted, and the `action` its live element carried at that
/// moment, for the lane to judge by [`form_action`] once more (R-I1).
struct Submitted {
    ok: bool,
    action: Option<String>,
}

impl Submitted {
    /// The answer in `value`, or `None` when the page answered anything but
    /// the object [`submit_form_js`] builds.
    fn from_value(value: &Value) -> Option<Self> {
        let Value::Object(fields) = value else {
            return None;
        };
        let Some(Value::Bool(ok)) = fields.get("ok") else {
            return None;
        };
        let action = match fields.get("action") {
            Some(Value::Str(action)) => Some(action.clone()),
            _ => None,
        };
        Some(Self { ok: *ok, action })
    }
}

/// Submit the form [`tag_form_js`] tagged `index` the way the page expects
/// (plan call **A4**), and answer `{ok, action}`.
///
/// The element is found by its tag, `form[data-aitm-form="index"]`, never by
/// `document.forms[index]`: that collection is live, so a form injected or
/// re-rendered between the tag eval and this one (a consent banner, a chat
/// widget, an SPA re-render) would be submitted in the tagged form's place,
/// possibly off-origin (R-I1). No tagged element answers `{ok:false}`.
///
/// The live `action` is read back through `Element.prototype.getAttribute`
/// and resolved against the document's base URL the way the browser will; one
/// that resolves off `location.origin` answers `{ok:false, action}` **before**
/// anything is submitted, so the check and the submit are one eval round and
/// a script cannot retarget the form between them. The comparison alone is
/// not enough: a sandboxed document's `location.origin` is the opaque
/// `"null"`, and so is the origin of a `javascript:`, `data:` or `about:`
/// target, so the two would compare equal; a target whose origin is `"null"`
/// or whose protocol is not `http:`/`https:` is refused outright (F4-3). The
/// lane judges the returned `action` by [`form_action`] once more, the rule
/// that admitted the extracted form.
///
/// `requestSubmit()` fires the page's `submit` handlers and its validation, so
/// a single-page app that intercepts the submit behaves as it does for a human;
/// `submit()` is the fallback for an engine that does not have it. Both are
/// called through `HTMLFormElement.prototype`, so a control named `submit` or
/// `requestSubmit` cannot shadow them. Marked `/*aitm-submit-form*/` for the
/// same reason as [`CLICKABLES_JS`].
pub(crate) fn submit_form_js(index: usize) -> String {
    format!(
        concat!(
            "/*aitm-submit-form*/(function(){{",
            "var f=document.querySelector(\"form[data-aitm-form=\\\"{index}\\\"]\");",
            "if(!f){{return {{ok:false}};}}",
            "var action=Element.prototype.getAttribute.call(f,\"action\");",
            "var base=Object.getOwnPropertyDescriptor(Node.prototype,\"baseURI\")",
            ".get.call(document);",
            "var target;",
            "try{{target=new URL(action===null?\"\":action,base);}}",
            "catch(e){{return {{ok:false,action:action}};}}",
            "if(target.origin===\"null\"",
            "||(target.protocol!==\"http:\"&&target.protocol!==\"https:\")",
            "||target.origin!==location.origin){{return {{ok:false,action:action}};}}",
            "if(HTMLFormElement.prototype.requestSubmit){{",
            "HTMLFormElement.prototype.requestSubmit.call(f);}}",
            "else{{HTMLFormElement.prototype.submit.call(f);}}",
            "return {{ok:true,action:action}};}})()"
        ),
        index = index
    )
}

/// The CSS selector for the control named `name` in the form tagged
/// `form_index`.
///
/// The name is escaped, so a control called `a"b` cannot close the selector's
/// quote and turn the rest of the name into selector syntax.
pub(crate) fn field_selector(form_index: usize, name: &str) -> String {
    format!(
        "form[data-aitm-form=\"{form_index}\"] [name=\"{}\"]",
        escape_quoted(name)
    )
}

/// `text` with the characters that would end a quoted selector or JavaScript
/// string literal escaped, and control characters dropped.
fn escape_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            ch if ch.is_control() => {}
            ch => out.push(ch),
        }
    }
    out
}

/// Set the `value` of the control `selector` addresses, for a control a human
/// picks rather than types into.
fn set_value_js(selector: &str, value: &str) -> String {
    format!(
        "(function(){{var e=document.querySelector(\"{}\");if(e){{e.value=\"{}\";}}}})()",
        escape_quoted(selector),
        escape_quoted(value)
    )
}

/// Check the control `selector` addresses.
fn set_checked_js(selector: &str) -> String {
    format!(
        "(function(){{var e=document.querySelector(\"{}\");if(e){{e.checked=true;}}}})()",
        escape_quoted(selector)
    )
}

/// `origin` reduced to its root document: the browser profile is primed there,
/// and a cookie is written for the whole origin anyway.
pub(crate) fn origin_root(origin: &Url) -> Url {
    let mut root = origin.clone();
    root.set_path("/");
    root.set_query(None);
    root.set_fragment(None);
    root
}

/// Await `future` under the job's deadline (spec D8.1: no await outlives
/// `min(deadline - now, MAX_AWAIT)`), so one hung browser call cannot outlive
/// the job, and with the driver's error text scrubbed, so nothing the driver
/// echoed reaches a log or an error (AC T2-6). Every browser call in this
/// module goes through here.
async fn bounded<T>(
    job: &dyn JobCtx,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    // Both time-bound failures keep a typed cause under their `scan:` context
    // (`crawl_error_token` reads the type, never this crate's own prose).
    let Some(limit) = remaining(job) else {
        return Err(
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut))
                .context("scan: the job deadline passed before the browser answered"),
        );
    };
    match tokio::time::timeout(limit, future).await {
        Ok(Ok(value)) => Ok(value),
        // The driver's error text is foreign (it may echo the URL it failed on
        // or the statement it rejected), so it is scrubbed here, once, before
        // any call site logs it or `prime_session` propagates it (AC T2-6).
        Ok(Err(err)) => Err(anyhow::anyhow!("{}", scrub_error(&err))),
        Err(elapsed) => Err(anyhow::Error::new(elapsed)
            .context(format!("scan: the browser timed out after {limit:?}"))),
    }
}

/// What the engine does after one step.
enum Step {
    /// Carry on with this page.
    Continue,
    /// Abandon this page, keep crawling.
    NextPage,
    /// Stop the crawl with this reason.
    Stop(StopReason),
}

/// One crawl run: the browser, the frontier and the report being filled.
struct Run<'a> {
    browser: Arc<dyn BrowserDriver>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    origin: &'a Url,
    job: &'a dyn JobCtx,
    limits: &'a Limits,
    frontier: Frontier,
    report: CrawlReport,
    /// The job mark and the crawl mark, put on every flow the run produces.
    marks: Vec<String>,
    /// Pages the scope guard refused after the first one.
    guard_refused: u32,
    /// The store diff of the page being worked: one snapshot per page, then a
    /// running set across its navigation, submissions, clicks and returns.
    page_diff: StoreDiff,
}

impl<'a> Run<'a> {
    fn new(
        browser: Arc<dyn BrowserDriver>,
        origin: &'a Url,
        job: &'a dyn JobCtx,
        limits: &'a Limits,
    ) -> Self {
        Self {
            browser,
            store: job.store(),
            guard: job.guard(),
            origin,
            job,
            limits,
            frontier: Frontier::new(),
            report: CrawlReport::default(),
            marks: vec![job_mark(job.job_id()), MARK_CRAWL.to_string()],
            guard_refused: 0,
            page_diff: StoreDiff::default(),
        }
    }

    /// Drain the frontier, one page at a time, until something says stop.
    async fn run_pages(&mut self) -> anyhow::Result<Option<StopReason>> {
        while let Some((page, depth)) = self.frontier.pop() {
            if self.job.cancelled() {
                return Ok(Some(StopReason::Cancelled));
            }
            if remaining(self.job).is_none() {
                return Ok(Some(StopReason::Time));
            }
            if self.report.attempts >= self.limits.max_pages {
                return Ok(Some(StopReason::MaxPages));
            }
            self.report.attempts = self.report.attempts.saturating_add(1);
            self.report.depth_reached = self.report.depth_reached.max(depth);

            match self.visit(&page, depth).await? {
                Step::Continue | Step::NextPage => {}
                Step::Stop(reason) => return Ok(Some(reason)),
            }
        }
        Ok(None)
    }

    /// Load one page and work it: links, then forms, then clicks (plan A3).
    async fn visit(&mut self, page: &Url, depth: u32) -> anyhow::Result<Step> {
        let authority = guard_authority(page);
        let permit = match self.guard.check_active(&authority) {
            Ok(permit) => permit,
            Err(err) => {
                // The first page is the one the lane asked for: refusing it is
                // the operator's answer to the whole crawl, not a page to skip.
                if self.report.attempts <= 1 {
                    anyhow::bail!(
                        "scan: the scope guard refused {}: {err}",
                        safe_url(page.as_str())
                    );
                }
                self.guard_refused = self.guard_refused.saturating_add(1);
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    "crawl: the scope guard refused this page"
                );
                return Ok(Step::NextPage);
            }
        };
        if !self.job.charge(1) {
            return Ok(Step::Stop(StopReason::Budget));
        }

        // The one O(store) step of this page (S-M6): every later action on
        // it diffs against the running set `collect` extends.
        self.page_diff = StoreDiff::snapshot(self.store.as_ref());
        let outcome = bounded(self.job, self.browser.navigate(page.as_str())).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => {
                self.guard.record_error(&authority);
                self.collect();
                // Amendment 39b: the job counts this page into `crawl.errors`
                // with a closed reason token; the driver's own text stays in
                // the (scrubbed) log line below.
                self.job
                    .report_crawl_error(self.origin.as_str(), crawl_error_token(&err));
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    error = %err,
                    "crawl: the browser could not load this page"
                );
                return Ok(Step::NextPage);
            }
        };

        let landed = parse_absolute(&outcome.final_url).filter(|url| self.in_scope(url));
        let Some(landed) = landed else {
            // The browser is on that page now; the next click would be a click
            // on a third party.
            self.collect();
            tracing::info!(
                target: "scan",
                job = self.job.job_id(),
                url = %safe_url(&outcome.final_url),
                "crawl: the browser landed outside the engagement; stopping"
            );
            return Ok(Step::Stop(StopReason::LeftScope));
        };

        self.report.pages = self.report.pages.saturating_add(1);
        self.frontier.mark_visited(&landed);
        let dom = match bounded(self.job, self.browser.get_dom()).await {
            Ok(dom) => dom,
            Err(err) => {
                self.collect();
                self.job
                    .report_crawl_error(self.origin.as_str(), crawl_error_token(&err));
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(landed.as_str()),
                    error = %err,
                    "crawl: the browser did not hand over the DOM"
                );
                return Ok(Step::NextPage);
            }
        };
        // The permit covered the navigation and the DOM read, which is the
        // authority this page needed from the scope guard. The submissions,
        // clicks and return navigations that follow take no permit of their
        // own: each is metered by `job.charge(1)` only (orchestrator ruling,
        // Q6).
        drop(permit);
        self.collect();

        // A page already seen under another URL is counted but not mined again.
        let dom = truncate(&dom, MAX_DOM_BYTES);
        if !self.frontier.note_fingerprint(fingerprint(dom)) {
            return Ok(Step::NextPage);
        }
        let extracted = extract(dom);
        self.push_links(&landed, &extracted, depth);

        match self.submit_forms(&landed, &extracted, depth).await? {
            Step::Continue => {}
            other => return Ok(other),
        }
        self.click_handlers(&landed, depth).await
    }

    /// Queue every link the page offers (and its sub-resources at `thorough`).
    fn push_links(&mut self, page: &Url, extracted: &Extracted, depth: u32) {
        let base = extracted
            .base
            .as_deref()
            .and_then(|href| resolve(page, href))
            .unwrap_or_else(|| page.clone());
        let resources: &[String] = if self.limits.follow_resources {
            &extracted.resources
        } else {
            &[]
        };
        for href in extracted.links.iter().chain(resources) {
            let Some(target) = resolve(&base, href) else {
                continue;
            };
            if !self.in_scope(&target) {
                continue;
            }
            self.frontier
                .push(target, depth.saturating_add(1), self.limits);
        }
    }

    /// Fill and submit the page's submittable forms, bounded by
    /// `limits.forms_per_page`.
    async fn submit_forms(
        &mut self,
        page: &Url,
        extracted: &Extracted,
        depth: u32,
    ) -> anyhow::Result<Step> {
        let forms: Vec<FormSpec> = if self.limits.submit_forms && self.limits.forms_per_page > 0 {
            extracted
                .forms
                .iter()
                .filter(|form| {
                    form_action(form, page, self.origin, extracted.base.as_deref()).is_some()
                })
                .take(self.limits.forms_per_page as usize)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        tracing::debug!(
            target: "scan",
            job = self.job.job_id(),
            url = %safe_url(page.as_str()),
            submit_forms = self.limits.submit_forms,
            forms_per_page = self.limits.forms_per_page,
            declared = extracted.forms.len(),
            admitted = forms.len(),
            "crawl: forms on this page"
        );
        if forms.is_empty() {
            return Ok(Step::Continue);
        }

        for form in forms {
            if self.job.cancelled() {
                return Ok(Step::Stop(StopReason::Cancelled));
            }
            match self.return_to(page).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
            // Tagging is best effort: a browser that cannot answer simply does
            // not get this form submitted. A browser that answers with a form
            // other than the one the extractor read (S-I2) is skipped and
            // counted: the submit would go wherever *that* form points.
            let live = match bounded(self.job, self.browser.eval(&tag_form_js(form.index))).await {
                Ok(value) => LiveForm::from_value(&value),
                Err(err) => {
                    self.report.forms_skipped = self.report.forms_skipped.saturating_add(1);
                    tracing::debug!(
                        target: "scan",
                        job = self.job.job_id(),
                        url = %safe_url(page.as_str()),
                        form = form.index,
                        error = %err,
                        "crawl: the browser could not tag the form; skipped"
                    );
                    continue;
                }
            };
            let agrees = live.as_ref().is_some_and(|live| {
                live.matches(&form, page, self.origin, extracted.base.as_deref())
            });
            if !agrees {
                self.report.forms_skipped = self.report.forms_skipped.saturating_add(1);
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    form = form.index,
                    "crawl: the live form is not the form the page declared; skipped"
                );
                continue;
            }
            self.fill_form(&form).await;

            if !self.job.charge(1) {
                return Ok(Step::Stop(StopReason::Budget));
            }
            let answer =
                match bounded(self.job, self.browser.eval(&submit_form_js(form.index))).await {
                    Ok(value) => Submitted::from_value(&value),
                    Err(err) => {
                        self.collect();
                        // Amendment 39b: a submission the browser fails counts
                        // into `crawl.errors` like a page it cannot load.
                        self.job
                            .report_crawl_error(self.origin.as_str(), crawl_error_token(&err));
                        tracing::debug!(
                            target: "scan",
                            job = self.job.job_id(),
                            url = %safe_url(page.as_str()),
                            error = %err,
                            "crawl: a form submission failed"
                        );
                        continue;
                    }
                };
            // The submit eval addressed the tagged element and re-read its
            // live action (R-I1): a form that vanished or was retargeted since
            // the tag eval is refused there, and the action it did carry is
            // judged here by the rule that admitted the extracted form, in the
            // shape `FormSpec::from_attrs` gives every form it judges (R-M6).
            // Either refusal is a skip: nothing to settle on, nothing to
            // collect.
            let admitted = answer.as_ref().is_some_and(|answer| {
                answer.ok
                    && form_action(
                        &FormSpec::from_attrs(
                            form.index,
                            answer.action.as_deref(),
                            Some(&form.method),
                            form.enctype.as_deref(),
                        ),
                        page,
                        self.origin,
                        extracted.base.as_deref(),
                    )
                    .is_some()
            });
            if !admitted {
                self.report.forms_skipped = self.report.forms_skipped.saturating_add(1);
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    form = form.index,
                    "crawl: the tagged form was gone or retargeted at submit time; skipped"
                );
                continue;
            }
            let landing = self.settle().await;
            self.report.forms_submitted = self.report.forms_submitted.saturating_add(1);
            self.collect();

            match self.landed_page(landing.as_deref(), page, depth).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
        }
        Ok(Step::Continue)
    }

    /// Put an inert value in every control of `form` the crawler can fill.
    ///
    /// Text-like controls are typed into, so the page's `input` handlers fire
    /// as they do for a human; a control a human picks rather than types
    /// (`select`, `checkbox`, `radio`) is set through an expression. Hidden
    /// controls keep what the page put there — that is where the CSRF token
    /// lives — and a file input is left empty, exactly as a browser submits it.
    /// Checkbox and radio groups come pre-reduced by [`chosen_fields`] to the
    /// one member a browser submits (Q7).
    async fn fill_form(&self, form: &FormSpec) {
        let origin = self.origin.as_str();
        let marker = self.job.marker();

        for field in chosen_fields(form) {
            if field.name.is_empty() {
                continue;
            }
            let selector = field_selector(form.index, &field.name);
            match field.kind {
                // The page's own value is already in the DOM.
                FieldKind::Hidden | FieldKind::File => continue,
                FieldKind::Checkbox | FieldKind::Radio => {
                    // The chosen member is the one the page checked, in which
                    // case the page's choice stands, or else the group's first
                    // member, which is the one the selector's first match is.
                    if field.checked {
                        continue;
                    }
                    let _ = bounded(self.job, self.browser.eval(&set_checked_js(&selector))).await;
                }
                FieldKind::Select => {
                    let Some(value) = value_for(field, &marker, origin) else {
                        continue;
                    };
                    let _ = bounded(
                        self.job,
                        self.browser.eval(&set_value_js(&selector, &value)),
                    )
                    .await;
                }
                _ => {
                    let Some(value) = value_for(field, &marker, origin) else {
                        continue;
                    };
                    let _ = bounded(self.job, self.browser.type_text(&selector, &value)).await;
                }
            }
        }
    }

    /// Click the page's click-only elements, bounded by
    /// `limits.clicks_per_page`.
    async fn click_handlers(&mut self, page: &Url, depth: u32) -> anyhow::Result<Step> {
        if !self.limits.click_handlers || self.limits.clicks_per_page == 0 {
            return Ok(Step::Continue);
        }
        // The listing must come from the page itself, so a submission that
        // navigated away is undone first (plan A3).
        match self.return_to(page).await? {
            Step::Continue => {}
            other => return Ok(other),
        }
        let targets = self.clickables().await;

        for selector in targets
            .into_iter()
            .take(self.limits.clicks_per_page as usize)
        {
            if self.job.cancelled() {
                return Ok(Step::Stop(StopReason::Cancelled));
            }
            match self.return_to(page).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
            if !self.job.charge(1) {
                return Ok(Step::Stop(StopReason::Budget));
            }
            let clicked = bounded(
                self.job,
                self.browser.click(ClickTarget::Selector(selector.clone())),
            )
            .await;
            if let Err(err) = clicked {
                self.collect();
                // Amendment 39b: a click the browser fails counts into
                // `crawl.errors` like a page it cannot load.
                self.job
                    .report_crawl_error(self.origin.as_str(), crawl_error_token(&err));
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    error = %err,
                    "crawl: a click failed"
                );
                continue;
            }
            let landing = self.settle().await;
            self.report.clicks = self.report.clicks.saturating_add(1);
            self.collect();

            match self.landed_page(landing.as_deref(), page, depth).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
        }
        Ok(Step::Continue)
    }

    /// What a submission or a click did: a new in-scope page is counted and
    /// mined, an off-origin landing stops the crawl, and a page that did not
    /// navigate is re-read only when its DOM actually changed.
    async fn landed_page(
        &mut self,
        landing: Option<&str>,
        page: &Url,
        depth: u32,
    ) -> anyhow::Result<Step> {
        let Some(landing) = landing else {
            return Ok(Step::Continue);
        };
        if landing == page.as_str() {
            // Still here: an in-page update is worth mining only if it changed
            // the page.
            let Ok(dom) = bounded(self.job, self.browser.get_dom()).await else {
                return Ok(Step::Continue);
            };
            let dom = truncate(&dom, MAX_DOM_BYTES);
            if self.frontier.note_fingerprint(fingerprint(dom)) {
                let extracted = extract(dom);
                self.push_links(page, &extracted, depth);
            }
            return Ok(Step::Continue);
        }

        let Some(landed) = parse_absolute(landing).filter(|url| self.in_scope(url)) else {
            tracing::info!(
                target: "scan",
                job = self.job.job_id(),
                url = %safe_url(landing),
                "crawl: an interaction left the engagement; stopping"
            );
            return Ok(Step::Stop(StopReason::LeftScope));
        };
        if self.frontier.mark_visited(&landed) {
            self.report.pages = self.report.pages.saturating_add(1);
        }
        let Ok(dom) = bounded(self.job, self.browser.get_dom()).await else {
            return Ok(Step::Continue);
        };
        let dom = truncate(&dom, MAX_DOM_BYTES);
        if self.frontier.note_fingerprint(fingerprint(dom)) {
            let extracted = extract(dom);
            self.push_links(&landed, &extracted, depth);
        }
        Ok(Step::Continue)
    }

    /// Go back to `page` when a submission or a click navigated away (plan A3).
    ///
    /// Charged like any other navigation, and its captures are marked like any
    /// other navigation's.
    async fn return_to(&mut self, page: &Url) -> anyhow::Result<Step> {
        if self.location().await.as_deref() == Some(page.as_str()) {
            return Ok(Step::Continue);
        }
        if !self.job.charge(1) {
            return Ok(Step::Stop(StopReason::Budget));
        }
        let outcome = bounded(self.job, self.browser.navigate(page.as_str())).await;
        self.collect();
        match outcome {
            Ok(_) => Ok(Step::Continue),
            Err(err) => {
                self.guard.record_error(&guard_authority(page));
                self.job
                    .report_crawl_error(self.origin.as_str(), crawl_error_token(&err));
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    error = %err,
                    "crawl: could not return to this page"
                );
                Ok(Step::NextPage)
            }
        }
    }

    /// The selectors [`CLICKABLES_JS`] reported, bounded by
    /// [`MAX_CLICKABLES_LISTED`] whatever the page answered.
    async fn clickables(&self) -> Vec<String> {
        let Ok(Value::Array(items)) = bounded(self.job, self.browser.eval(CLICKABLES_JS)).await
        else {
            return Vec::new();
        };
        items
            .into_iter()
            .take(MAX_CLICKABLES_LISTED)
            .filter_map(|item| match item {
                Value::Object(fields) => match fields.get("selector") {
                    Some(Value::Str(selector)) if !selector.is_empty() => Some(selector.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// Wait for the page to finish loading, polling `location.href` and
    /// `document.readyState` every [`SETTLE_POLL_MS`] for at most
    /// [`SETTLE_MAX_MS`]; the answer is where the browser ended up.
    async fn settle(&self) -> Option<String> {
        let started = Instant::now();
        loop {
            let here = self.location().await;
            let ready = matches!(
                bounded(self.job, self.browser.eval("document.readyState")).await,
                Ok(Value::Str(ref state)) if state == "complete"
            );
            if ready
                || started.elapsed() >= Duration::from_millis(SETTLE_MAX_MS)
                || remaining(self.job).is_none()
                || self.job.cancelled()
            {
                return here;
            }
            tokio::time::sleep(Duration::from_millis(SETTLE_POLL_MS)).await;
        }
    }

    /// Where the browser is, as the page reports it.
    async fn location(&self) -> Option<String> {
        match bounded(self.job, self.browser.eval("location.href")).await {
            Ok(Value::Str(href)) => Some(href),
            _ => None,
        }
    }

    /// Whether `url` is this crawl's origin and the scope guard still admits
    /// it.
    fn in_scope(&self, url: &Url) -> bool {
        same_origin(url, self.origin) && self.guard.in_scope(&guard_authority(url))
    }

    /// Mark what the last action on this page captured and keep those flows
    /// for the lane, at most [`MAX_STORED_FLOWS`] of them, oldest dropped
    /// (R-M3): every capture is marked in the store regardless, and the lane
    /// reads only the request of each held copy.
    fn collect(&mut self) {
        let produced = self
            .page_diff
            .mark_new(self.store.as_ref(), self.origin, &self.marks);
        self.report.flows.extend(produced);
        let excess = self.report.flows.len().saturating_sub(MAX_STORED_FLOWS);
        if excess > 0 {
            self.report.flows.drain(..excess);
            tracing::debug!(
                target: "scan",
                job = self.job.job_id(),
                dropped = excess,
                "crawl: the report holds its newest flows only; oldest dropped"
            );
        }
    }

    /// The finished report, with the stop reason the run arrived at.
    fn into_report(mut self, stopped: Option<StopReason>) -> CrawlReport {
        self.report.stopped_reason = match stopped {
            Some(reason) => Some(reason),
            // The frontier ran dry, but not because there was nothing left.
            None if self.frontier.depth_hit => Some(StopReason::MaxDepth),
            None if self.guard_refused > 0 => Some(StopReason::GuardRefused),
            None => None,
        };
        self.report
    }
}

/// `text` cut to at most `max` bytes on a char boundary.
fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or("")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    use aitm_core::{
        BrowserDriver, ClickTarget, Flow, FlowId, FlowStore, MemFlowStore, NavOutcome, Value,
    };
    use aitm_scan_model::{CrawlOptions, CrawlStrategy, ScanProfile, SessionMaterial};
    use futures::future::BoxFuture;
    use url::Url;

    use crate::crawl::frontier::{limits_for, Crawler};
    use crate::limits::{MAX_CLICKABLES_LISTED, MAX_STORED_FLOWS};
    use crate::testutil::{
        captured_flow, request, response, FakeBrowser, FakeJob, LiveFormScript, PageScript,
        ScriptedClient, CLICKABLES_MARKER, SUBMIT_FORM_MARKER, TAG_FORM_MARKER,
    };
    use crate::url_norm::parse_absolute;

    /// The origin every test crawls, matching the doubles' in-scope host.
    const ROOT: &str = "http://t:8080/";

    /// The plan's task 18 page: a link, a `GET` form to `/search` with one text
    /// field, and a button that only a click reaches.
    const HOME: &str = "<html><body><a href=\"/a\">a</a>\
<form action=\"/search\" method=\"get\"><input name=\"q\"></form>\
<button onclick=\"go()\">go</button></body></html>";

    /// Where submitting the home page's form lands: the inert value task 14
    /// generates for `q` under the doubles' marker.
    const SEARCH: &str = "http://t:8080/search?q=aitm-aitm7f3a";

    /// The selector `CLICKABLES_JS` yields for the home page's button.
    const BUTTON: &str = "body > button:nth-child(3)";

    fn url(s: &str) -> Url {
        parse_absolute(s).expect("the test URL parses")
    }

    fn marks() -> Vec<String> {
        vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()]
    }

    /// A captured flow to `url`, as the proxy would have stored it.
    fn capture(url: &str) -> aitm_core::HttpFlow {
        captured_flow(request("GET", url, &[], None), 200, &[], b"")
    }

    /// The site of the plan's test: every page carries one capture, so each
    /// navigation, submission and click adds exactly one flow to the store.
    fn pages() -> FakeBrowser {
        pages_with_home(home())
    }

    /// The home page of [`pages`], before any live-form override.
    fn home() -> PageScript {
        PageScript::new(HOME)
            .with_forms(&[(0, SEARCH)])
            .with_clickables(&[(BUTTON, "http://t:8080/clicked")])
            .with_captures(vec![request("GET", ROOT, &[], None)])
    }

    /// [`pages`] with `home` standing in for the root page.
    fn pages_with_home(home: PageScript) -> FakeBrowser {
        FakeBrowser::new(vec![
            (ROOT, home),
            (
                "http://t:8080/a",
                PageScript::new("<html><body>a</body></html>").with_captures(vec![request(
                    "GET",
                    "http://t:8080/a",
                    &[],
                    None,
                )]),
            ),
            (
                "http://t:8080/clicked",
                PageScript::new("<html><body>clicked</body></html>").with_captures(vec![request(
                    "GET",
                    "http://t:8080/clicked",
                    &[],
                    None,
                )]),
            ),
            (
                SEARCH,
                PageScript::new("<html><body>results</body></html>").with_captures(vec![request(
                    "GET",
                    SEARCH,
                    &[],
                    None,
                )]),
            ),
        ])
    }

    /// The browser log filtered to the three things the lane drives: the double
    /// writes `type <selector> = <text>` where the plan wrote `type_text`.
    fn driving(browser: &FakeBrowser) -> Vec<String> {
        browser
            .log_lines()
            .into_iter()
            .filter(|line| {
                line.starts_with("navigate ")
                    || line.starts_with("click ")
                    || line.starts_with("type ")
            })
            .collect()
    }

    fn job_with(browser: Arc<FakeBrowser>, store: Arc<MemFlowStore>) -> FakeJob {
        FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        )
        .with_store(store)
        .with_browser(browser)
    }

    #[tokio::test]
    async fn browser_crawl_pins() {
        let store = Arc::new(MemFlowStore::new());
        // A flow the proxy captured before the crawl: the crawl did not produce
        // it, so it must come out unmarked.
        let before = store.insert(Flow::Http(capture("http://t:8080/old")));

        let browser = Arc::new(pages().recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        // The second navigation to `/` is the return before the click: the
        // submit navigated away.
        assert_eq!(driving(&browser), pinned_driving());
        assert_eq!(job.charges.load(Ordering::SeqCst), 5);
        assert_eq!(report.pages, 4);
        assert_eq!(report.attempts, 2);
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.forms_skipped, 0);
        assert_eq!(report.clicks, 1);
        assert_eq!(report.stopped_reason, None);

        // Every flow the crawl produced carries both marks; the pre-existing one
        // carries none.
        assert_eq!(store.count(), 6);
        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                panic!("the double stores HTTP flows");
            };
            if id == before {
                assert!(
                    flow.metadata.marks.is_empty(),
                    "a flow captured before the crawl stays unmarked"
                );
            } else {
                assert_eq!(flow.metadata.marks, marks(), "flow {id:?}");
            }
        }
        assert_eq!(report.flows.len(), store.count() - 1);
        // Each produced flow is reported exactly once (S-M6: no double marking
        // across the actions of one page, no missed flow).
        let reported: HashSet<FlowId> = report.flows.iter().map(|flow| flow.id).collect();
        let expected: HashSet<FlowId> = store
            .list()
            .into_iter()
            .filter(|id| *id != before)
            .collect();
        assert_eq!(reported.len(), report.flows.len());
        assert_eq!(reported, expected);
    }

    /// The driving sequence `browser_crawl_pins` pins.
    fn pinned_driving() -> Vec<String> {
        vec![
            "navigate http://t:8080/".to_string(),
            "type form[data-aitm-form=\"0\"] [name=\"q\"] = aitm-aitm7f3a".to_string(),
            "navigate http://t:8080/".to_string(),
            "click body > button:nth-child(3)".to_string(),
            "navigate http://t:8080/a".to_string(),
        ]
    }

    // --- S-I2: the live form must be the form the extractor read -------------

    /// The extracted form posts to `/search`, but the form the live page holds
    /// at that index points at a third party: nothing is typed, nothing is
    /// submitted, no request leaves, and the report counts the skip.
    #[tokio::test]
    async fn live_form_off_origin_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(
            0,
            LiveFormScript {
                action: Some("https://evil.test/collect".to_string()),
                method: Some("post".to_string()),
                enctype: None,
                names: vec!["q".to_string()],
                ..LiveFormScript::default()
            },
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(
            driving(&browser),
            vec![
                "navigate http://t:8080/".to_string(),
                "click body > button:nth-child(3)".to_string(),
                "navigate http://t:8080/a".to_string(),
            ]
        );
        assert!(
            !browser
                .log_lines()
                .iter()
                .any(|line| line.starts_with("submit ")),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.clicks, 1);
        // Only the navigations' and the click's captures exist; nothing left
        // for `evil.test` and nothing reached `/search`.
        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                panic!("the double stores HTTP flows");
            };
            assert!(
                !flow.request.authority.contains("evil"),
                "{:?}",
                flow.request.path
            );
            assert!(
                !flow.request.path.starts_with("/search"),
                "{:?}",
                flow.request.path
            );
        }
    }

    /// The live form's controls are not the extracted form's controls (a
    /// re-rendered page swapped the form at this index): skipped and counted.
    #[tokio::test]
    async fn live_form_with_other_controls_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(
            0,
            LiveFormScript {
                action: Some("/search".to_string()),
                method: Some("get".to_string()),
                enctype: None,
                names: vec!["q".to_string(), "card_number".to_string()],
                ..LiveFormScript::default()
            },
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert!(
            !browser
                .log_lines()
                .iter()
                .any(|line| line.starts_with("submit ") || line.starts_with("type ")),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.forms_skipped, 1);
    }

    /// Live attributes that agree with the extracted form (same action, method
    /// in another case, the same control names) submit exactly as
    /// `browser_crawl_pins` pins.
    #[tokio::test]
    async fn live_form_that_matches_submits_as_pinned() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(
            0,
            LiveFormScript {
                action: Some("/search".to_string()),
                method: Some("GeT".to_string()),
                enctype: None,
                names: vec!["q".to_string()],
                ..LiveFormScript::default()
            },
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(driving(&browser), pinned_driving());
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.forms_skipped, 0);
        assert_eq!(job.charges.load(Ordering::SeqCst), 5);
    }

    // --- R-I1: the submit addresses the tagged element, not an index ---------

    /// The live form that matched at tag time; `rest` says what the page did to
    /// it before the submit eval.
    fn matching_live_form() -> LiveFormScript {
        LiveFormScript {
            action: Some("/search".to_string()),
            method: Some("get".to_string()),
            enctype: None,
            names: vec!["q".to_string()],
            ..LiveFormScript::default()
        }
    }

    /// No flow in `store` addresses `evil.test` or `/search`.
    fn assert_nothing_left_for_search_or_evil(store: &MemFlowStore) {
        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                panic!("the double stores HTTP flows");
            };
            assert!(
                !flow.request.authority.contains("evil"),
                "{:?}",
                flow.request.path
            );
            assert!(
                !flow.request.path.starts_with("/search"),
                "{:?}",
                flow.request.path
            );
        }
    }

    /// The form matched when it was tagged, but a re-render replaced it before
    /// the submit eval: the tagged element is gone, so nothing is submitted
    /// (whatever `document.forms[0]` is now), the skip is counted, and the
    /// crawl goes on from the same page without a return navigation.
    #[tokio::test]
    async fn live_form_gone_at_submit_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(0, matching_live_form().gone_at_submit());
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(
            driving(&browser),
            vec![
                "navigate http://t:8080/".to_string(),
                "type form[data-aitm-form=\"0\"] [name=\"q\"] = aitm-aitm7f3a".to_string(),
                "click body > button:nth-child(3)".to_string(),
                "navigate http://t:8080/a".to_string(),
            ]
        );
        assert!(
            !browser
                .log_lines()
                .iter()
                .any(|line| line.starts_with("submit ")),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.clicks, 1);
        assert_eq!(report.stopped_reason, None);
        // The submit attempt is still charged: the page, the submit, the click
        // and the `/a` navigation.
        assert_eq!(job.charges.load(Ordering::SeqCst), 4);
        assert_nothing_left_for_search_or_evil(&store);
    }

    /// The form matched when it was tagged, but a script pointed its `action`
    /// at a third party before the submit eval: the expression re-reads the
    /// live action and refuses, the lane counts the skip, and no request
    /// leaves for `evil.test` or `/search`.
    #[tokio::test]
    async fn live_form_retargeted_at_submit_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(
            0,
            matching_live_form().with_action_at_submit("https://evil.test/collect"),
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert!(
            !browser
                .log_lines()
                .iter()
                .any(|line| line.starts_with("submit ")),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.clicks, 1);
        assert_eq!(report.stopped_reason, None, "the browser never left");
        assert_nothing_left_for_search_or_evil(&store);
    }

    /// A page with two submittable forms: a `GET` search at index 0 and a
    /// `POST` login at index 1, each with one text field and no button.
    const TWO_FORMS: &str = "<html><body>\
<form action=\"/search\" method=\"get\"><input name=\"q\"></form>\
<form action=\"/login\" method=\"post\"><input name=\"u\"></form>\
</body></html>";

    /// Where submitting the login form lands.
    const LOGIN: &str = "http://t:8080/login";

    /// A site whose root is [`TWO_FORMS`], with the two landing pages.
    fn two_form_pages(home: PageScript) -> FakeBrowser {
        FakeBrowser::new(vec![
            (ROOT, home),
            (
                SEARCH,
                PageScript::new("<html><body>results</body></html>").with_captures(vec![request(
                    "GET",
                    SEARCH,
                    &[],
                    None,
                )]),
            ),
            (
                LOGIN,
                PageScript::new("<html><body>in</body></html>").with_captures(vec![request(
                    "POST",
                    LOGIN,
                    &[],
                    None,
                )]),
            ),
        ])
    }

    /// Two forms on one page; form 0 is retargeted off-origin by submit time
    /// and form 1 is untouched. The submit expression addresses each form by
    /// its own tag: form 1 is submitted (`submit 1`) and form 0 is refused,
    /// never submitted in form 1's place (F4-1, R-I1).
    #[tokio::test]
    async fn two_forms_submit_by_their_own_tag() {
        let store = Arc::new(MemFlowStore::new());
        let home = PageScript::new(TWO_FORMS)
            .with_forms(&[(0, SEARCH), (1, LOGIN)])
            .with_captures(vec![request("GET", ROOT, &[], None)])
            .with_live_form(
                0,
                matching_live_form().with_action_at_submit("https://evil.test/collect"),
            );
        let browser =
            Arc::new(two_form_pages(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        let submits: Vec<String> = browser
            .log_lines()
            .into_iter()
            .filter(|line| line.starts_with("submit "))
            .collect();
        assert_eq!(submits, vec!["submit 1".to_string()]);
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.stopped_reason, None);
        // The login landed and was collected; nothing left for `evil.test`
        // or `/search`.
        assert!(
            store.list().into_iter().any(|id| matches!(
                store.get(id),
                Some(Flow::Http(flow)) if flow.request.path == "/login"
            )),
            "the login submission was captured"
        );
        assert_nothing_left_for_search_or_evil(&store);
    }

    /// The form matched when it was tagged, but a script pointed its `action`
    /// at a `javascript:` URL before the submit eval: the target has no
    /// http(s) origin to compare, so it is refused like an off-origin one and
    /// nothing is submitted (F4-3).
    #[tokio::test]
    async fn live_form_retargeted_to_javascript_at_submit_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        let home = home().with_live_form(
            0,
            matching_live_form().with_action_at_submit("javascript:void(0)"),
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert!(
            !browser
                .log_lines()
                .iter()
                .any(|line| line.starts_with("submit ")),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.clicks, 1);
        assert_eq!(report.stopped_reason, None);
        assert_nothing_left_for_search_or_evil(&store);
    }

    /// The submit expression's in-eval check is bypassed (a browser that
    /// answers `{ok:true}` for an off-origin action): the engine judges the
    /// returned `action` by [`form_action`] itself and refuses it. The
    /// double's `submit 0` line is the browser having submitted; the lane
    /// counts it as a skip, not a submission, and collects nothing (F4-1).
    #[tokio::test]
    async fn engine_recheck_refuses_an_off_origin_action_the_browser_accepted() {
        let store = Arc::new(MemFlowStore::new());
        // No `forms` landing: the double stays on the page after its submit.
        let home = home().with_forms(&[]).with_live_form(
            0,
            matching_live_form()
                .with_action_at_submit("https://evil.test/collect")
                .answers_ok_regardless(),
        );
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        let submits: Vec<String> = browser
            .log_lines()
            .into_iter()
            .filter(|line| line.starts_with("submit "))
            .collect();
        assert_eq!(
            submits,
            vec!["submit 0".to_string()],
            "the browser did submit"
        );
        assert_eq!(report.forms_submitted, 0, "the engine did not count it");
        assert_eq!(report.forms_skipped, 1);
        assert_eq!(report.clicks, 1);
        assert_eq!(report.stopped_reason, None);
        assert_nothing_left_for_search_or_evil(&store);
    }

    /// The lane's reading of the submit expression's answer: `ok` and the live
    /// `action` when it is a string; anything but that object is no answer.
    #[test]
    fn submit_answer_pins() {
        let object = |pairs: &[(&str, Value)]| {
            Value::Object(
                pairs
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), value.clone()))
                    .collect(),
            )
        };
        let done = Submitted::from_value(&object(&[
            ("ok", Value::Bool(true)),
            ("action", Value::Str("/search".to_string())),
        ]))
        .expect("an object answer parses");
        assert!(done.ok);
        assert_eq!(done.action.as_deref(), Some("/search"));

        let gone = Submitted::from_value(&object(&[("ok", Value::Bool(false))]))
            .expect("an object answer parses");
        assert!(!gone.ok);
        assert_eq!(gone.action, None);

        let no_action = Submitted::from_value(&object(&[
            ("ok", Value::Bool(true)),
            ("action", Value::Null),
        ]))
        .expect("an object answer parses");
        assert!(no_action.ok);
        assert_eq!(no_action.action, None);

        // A missing `ok` is not a submission.
        assert!(
            Submitted::from_value(&object(&[("action", Value::Str("/x".to_string()))])).is_none()
        );
        assert!(Submitted::from_value(&Value::Null).is_none());
        assert!(Submitted::from_value(&Value::Bool(true)).is_none());
    }

    // --- Q7 (tester): the browser engine's half of the group rule -----------

    /// A form with two radio groups and two checkbox groups: a group the page
    /// left unchecked gets exactly its first member checked, a group the page
    /// checked is left alone, and nothing is typed into a radio or checkbox.
    /// The one text control is typed as pinned and the form still submits.
    #[tokio::test]
    async fn browser_fill_checks_one_member_per_unchecked_group() {
        const GROUPED: &str = "<html><body><form action=\"/search\" method=\"get\">\
<input name=\"q\">\
<input type=\"radio\" name=\"r\" value=\"x\"><input type=\"radio\" name=\"r\" value=\"y\">\
<input type=\"checkbox\" name=\"c\" value=\"1\" checked><input type=\"checkbox\" name=\"c\" value=\"2\">\
<input type=\"checkbox\" name=\"k\" value=\"a\"><input type=\"checkbox\" name=\"k\" value=\"b\">\
<input type=\"radio\" name=\"z\" value=\"p\"><input type=\"radio\" name=\"z\" value=\"q\" checked>\
</form></body></html>";
        let store = Arc::new(MemFlowStore::new());
        let home = PageScript::new(GROUPED)
            .with_forms(&[(0, SEARCH)])
            .with_captures(vec![request("GET", ROOT, &[], None)]);
        let browser =
            Arc::new(pages_with_home(home).recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        let fills: Vec<String> = browser
            .log_lines()
            .into_iter()
            .filter(|line| line.starts_with("check ") || line.starts_with("type "))
            .collect();
        assert_eq!(
            fills,
            vec![
                format!("type {} = aitm-aitm7f3a", field_selector(0, "q")),
                format!("check {}", escape_quoted(&field_selector(0, "r"))),
                format!("check {}", escape_quoted(&field_selector(0, "k"))),
            ]
        );
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.forms_skipped, 0);
    }

    // --- S-I3 / R-M3: the report holds request-only copies, the store the real flow

    /// A page whose capture carries a 200 KiB response: the report's copy
    /// drops the response body outright (nobody reads it: the lane enumerates
    /// `flow.request` only), while the flow in the store keeps every byte.
    #[tokio::test]
    async fn held_flows_drop_response_bodies() {
        let big = vec![b'x'; 200 * 1024];
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(
            FakeBrowser::new(vec![(
                ROOT,
                PageScript::new("<html><body>big</body></html>")
                    .with_captures(vec![request("GET", ROOT, &[], None)])
                    .with_capture_body(big.clone()),
            )])
            .recording_into(store.clone() as Arc<dyn FlowStore>),
        );
        let job = job_with(browser, store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(report.flows.len(), 1);
        let held = &report.flows[0];
        let response = held
            .response
            .as_ref()
            .expect("the held copy keeps its status");
        assert_eq!(response.status, 200);
        assert!(
            matches!(response.body, aitm_core::Body::Empty),
            "the held copy carries no response body"
        );
        assert_eq!(held.metadata.marks, marks());

        let Some(Flow::Http(stored)) = store.get(held.id) else {
            panic!("the store holds the flow");
        };
        let Some(aitm_core::Body::Bytes(stored_body)) = stored.response.as_ref().map(|r| &r.body)
        else {
            panic!("the stored flow keeps a bytes body");
        };
        assert_eq!(stored_body.len(), big.len());
        assert_eq!(stored.metadata.marks, marks());
    }

    /// A page whose load captures more flows than `MAX_STORED_FLOWS`: the
    /// report keeps the newest `MAX_STORED_FLOWS` and drops the oldest (R-M3),
    /// while every capture is still marked in the store.
    #[tokio::test]
    async fn browser_report_flows_are_capped_at_max_stored_flows() {
        let extra = 3;
        let captures: Vec<_> = (0..MAX_STORED_FLOWS + extra)
            .map(|i| request("GET", &format!("http://t:8080/c/{i}"), &[], None))
            .collect();
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(
            FakeBrowser::new(vec![(
                ROOT,
                PageScript::new("<html><body>many</body></html>").with_captures(captures),
            )])
            .recording_into(store.clone() as Arc<dyn FlowStore>),
        );
        let job = job_with(browser, store.clone());
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(report.flows.len(), MAX_STORED_FLOWS);
        assert_eq!(report.flows[0].request.path, format!("/c/{extra}"));
        assert_eq!(
            report.flows[MAX_STORED_FLOWS - 1].request.path,
            format!("/c/{}", MAX_STORED_FLOWS + extra - 1)
        );
        assert_eq!(store.count(), MAX_STORED_FLOWS + extra);
        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                panic!("the double stores HTTP flows");
            };
            assert_eq!(flow.metadata.marks, marks(), "flow {id:?}");
        }
    }

    #[tokio::test]
    async fn fast_limits_skip_forms_and_clicks() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(pages().recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser.clone(), store.clone());
        let limits = limits_for(&CrawlOptions {
            strategy: CrawlStrategy::Fast,
            ..CrawlOptions::default()
        });

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(
            driving(&browser),
            vec![
                "navigate http://t:8080/".to_string(),
                "navigate http://t:8080/a".to_string(),
            ]
        );
        assert_eq!(job.charges.load(Ordering::SeqCst), 2);
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.clicks, 0);
        assert_eq!(report.pages, 2);
    }

    /// A two-page site with nothing to submit or click.
    fn plain_pages() -> FakeBrowser {
        FakeBrowser::new(vec![
            (
                ROOT,
                PageScript::new("<html><body><a href=\"/a\">a</a></body></html>"),
            ),
            (
                "http://t:8080/a",
                PageScript::new("<html><body>a</body></html>"),
            ),
        ])
    }

    #[tokio::test]
    async fn budget_stops_crawl() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(plain_pages());
        let job = job_with(browser.clone(), store).with_budget(1);
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a budget stop is not an error");

        assert_eq!(job.charges.load(Ordering::SeqCst), 1);
        assert_eq!(report.stopped_reason, Some(StopReason::Budget));
        assert_eq!(report.attempts, 2);
        assert_eq!(report.pages, 1);
        assert_eq!(
            driving(&browser),
            vec!["navigate http://t:8080/".to_string()]
        );
    }

    #[tokio::test]
    async fn left_scope_stops() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(FakeBrowser::new(vec![
            (
                ROOT,
                PageScript::new(
                    "<html><body><a href=\"/a\">a</a><a href=\"/b\">b</a></body></html>",
                ),
            ),
            (
                "http://t:8080/a",
                PageScript {
                    final_url: Some("https://evil.test/".to_string()),
                    ..PageScript::new("<html><body>a</body></html>")
                },
            ),
            (
                "http://t:8080/b",
                PageScript::new("<html><body>b</body></html>"),
            ),
        ]));
        let job = job_with(browser.clone(), store);
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("leaving scope is a stop, not an error");

        assert_eq!(report.stopped_reason, Some(StopReason::LeftScope));
        assert_eq!(report.pages, 1);
        // `/b` was queued but never reached.
        assert_eq!(
            driving(&browser),
            vec![
                "navigate http://t:8080/".to_string(),
                "navigate http://t:8080/a".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn no_browser_errors() {
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );
        let limits = limits_for(&CrawlOptions::default());

        let err = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect_err("a browser crawl without a browser fails");

        assert!(err.to_string().contains("no browser"), "{err}");
    }

    /// A browser whose `document.cookie` read-back is scripted.
    ///
    /// [`FakeBrowser`] stores every assignment it is given, so it can only model
    /// a fully primed profile; an `HttpOnly` session cookie is exactly the one
    /// the browser never receives, which is what `browser_partial` reports. The
    /// recorded expressions are the contract under test (the statement the lane
    /// evaluates); the value in them is a test literal, never real material, and
    /// this double is `#[cfg(test)]` and reaches no log or artifact.
    struct ScriptedCookieBrowser {
        read_back: String,
        evals: Mutex<Vec<String>>,
        navigations: Mutex<Vec<String>>,
    }

    impl ScriptedCookieBrowser {
        fn new(read_back: &str) -> Self {
            Self {
                read_back: read_back.to_string(),
                evals: Mutex::new(Vec::new()),
                navigations: Mutex::new(Vec::new()),
            }
        }

        fn evals(&self) -> Vec<String> {
            self.evals.lock().unwrap().clone()
        }

        fn navigations(&self) -> Vec<String> {
            self.navigations.lock().unwrap().clone()
        }
    }

    impl BrowserDriver for ScriptedCookieBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.navigations.lock().unwrap().push(url.clone());
                Ok(NavOutcome {
                    final_url: url,
                    status: Some(200),
                })
            })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            let expr = expr.to_string();
            Box::pin(async move {
                self.evals.lock().unwrap().push(expr.clone());
                if expr.trim() == "document.cookie" {
                    return Ok(Value::Str(self.read_back.clone()));
                }
                Ok(Value::Null)
            })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(String::new()) })
        }
    }

    #[tokio::test]
    async fn prime_session_pins() {
        let material = SessionMaterial {
            cookies: vec![
                ("sid".to_string(), "S3".to_string()),
                ("hs".to_string(), "H".to_string()),
            ],
            headers: Vec::new(),
        };
        // The profile only ever receives `sid`: `hs` is `HttpOnly`.
        let browser = ScriptedCookieBrowser::new("sid=S3");
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );

        let partial = prime_session(&browser, &url(ROOT), &material, &job)
            .await
            .expect("priming succeeds");

        assert_eq!(partial, vec!["hs".to_string()]);
        assert_eq!(browser.navigations(), vec![ROOT.to_string()]);
        assert!(
            browser
                .evals()
                .contains(&"document.cookie = \"sid=S3; path=/\"".to_string()),
            "{:?}",
            browser.evals()
        );
        assert_eq!(
            browser.evals().last().map(String::as_str),
            Some("document.cookie")
        );
        assert_eq!(job.charges.load(Ordering::SeqCst), 1);

        // A profile that keeps every cookie reports no partial priming.
        let full = FakeBrowser::new(vec![(ROOT, PageScript::new("<html></html>"))]);
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );
        let partial = prime_session(&full, &url(ROOT), &material, &job)
            .await
            .expect("priming succeeds");
        assert!(partial.is_empty(), "{partial:?}");
        assert_eq!(
            full.log_lines(),
            vec![
                "navigate http://t:8080/".to_string(),
                "cookie-set sid".to_string(),
                "cookie-set hs".to_string(),
            ]
        );
    }

    /// An empty diff has seen nothing, so it marks every flow the store holds
    /// (R-M8): the state `Run::new` starts from before the first snapshot.
    #[test]
    fn store_diff_default_treats_everything_as_new() {
        let store = MemFlowStore::new();
        let id = store.insert(Flow::Http(capture("http://t:8080/already")));
        let produced = StoreDiff::default().mark_new(&store, &url(ROOT), &marks());
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].id, id);
        assert_eq!(produced[0].metadata.marks, marks());
    }

    #[test]
    fn store_diff_marks_only_new_origin_flows() {
        let store = Arc::new(MemFlowStore::new());
        let old = store.insert(Flow::Http(capture("http://t:8080/old")));

        let mut diff = StoreDiff::snapshot(store.as_ref());
        let fresh = store.insert(Flow::Http(capture("http://t:8080/new")));
        let foreign = store.insert(Flow::Http(capture("http://other:9/x")));

        let marked = diff.mark_new(store.as_ref(), &url(ROOT), &marks());

        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0].id, fresh);
        assert_eq!(marked[0].metadata.marks, marks());
        for untouched in [old, foreign] {
            let Some(Flow::Http(flow)) = store.get(untouched) else {
                panic!("the double stores HTTP flows");
            };
            assert!(flow.metadata.marks.is_empty(), "flow {untouched:?}");
        }

        // S-M6: one snapshot serves every action on a page. A second action's
        // flow is the only thing the second diff reports: `fresh` is neither
        // re-reported nor re-marked, and nothing is missed.
        let later = store.insert(Flow::Http(capture("http://t:8080/later")));
        let again = diff.mark_new(store.as_ref(), &url(ROOT), &marks());
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].id, later);
        assert_eq!(again[0].metadata.marks, marks());
        let Some(Flow::Http(first)) = store.get(fresh) else {
            panic!("the double stores HTTP flows");
        };
        assert_eq!(first.metadata.marks, marks());
        // A third diff with nothing new reports nothing.
        assert!(diff
            .mark_new(store.as_ref(), &url(ROOT), &marks())
            .is_empty());
    }

    #[test]
    fn js_helpers_pin() {
        // Tagging reads the LIVE form back through the prototype getters, so
        // an `<input name="action">` (or `name="getAttribute"`) in the form
        // cannot answer for the form itself; it reads the DOM and nothing else.
        let tag = tag_form_js(2);
        assert!(tag.starts_with(TAG_FORM_MARKER), "{tag}");
        assert!(tag.contains("document.forms[2]"), "{tag}");
        assert!(tag.contains("\"data-aitm-form\",\"2\""), "{tag}");
        for needed in [
            "Element.prototype.getAttribute",
            "Element.prototype.setAttribute",
            "HTMLFormElement.prototype,\"elements\"",
            "\"action\"",
            "\"method\"",
            "\"enctype\"",
            "names",
        ] {
            assert!(tag.contains(needed), "{needed}: {tag}");
        }
        for forbidden in [
            ".action",
            ".method",
            ".enctype",
            "fetch(",
            "XMLHttpRequest",
            "location",
            ".submit(",
            ".click(",
            "innerHTML",
        ] {
            assert!(!tag.contains(forbidden), "{forbidden}: {tag}");
        }
        // Submitting addresses the element the tag eval marked, never a live
        // `document.forms` index (R-I1), re-reads its `action` through the
        // prototype getter, refuses an action that resolves off the page's
        // origin — including the opaque `"null"` origin a sandboxed document
        // shares with a `javascript:`/`data:`/`about:` target, and any
        // non-http(s) scheme (F4-3) — and submits through the prototype
        // methods so a control named `submit` or `requestSubmit` cannot
        // clobber them.
        let submit = submit_form_js(1);
        assert!(submit.starts_with(SUBMIT_FORM_MARKER), "{submit}");
        for needed in [
            "document.querySelector(\"form[data-aitm-form=\\\"1\\\"]\")",
            "return {ok:false}",
            "Element.prototype.getAttribute.call(f,\"action\")",
            "Node.prototype,\"baseURI\"",
            "target.origin===\"null\"",
            "target.protocol!==\"http:\"&&target.protocol!==\"https:\"",
            "target.origin!==location.origin",
            "HTMLFormElement.prototype.requestSubmit.call(f)",
            "HTMLFormElement.prototype.submit.call(f)",
            "return {ok:true,action:action}",
        ] {
            assert!(submit.contains(needed), "{needed}: {submit}");
        }
        for forbidden in [
            "document.forms[",
            "f.requestSubmit(",
            "f.submit(",
            ".action",
            "fetch(",
            "XMLHttpRequest",
            "innerHTML",
        ] {
            assert!(!submit.contains(forbidden), "{forbidden}: {submit}");
        }
        assert_eq!(
            field_selector(0, "q"),
            "form[data-aitm-form=\"0\"] [name=\"q\"]"
        );
        // A name that would close the selector's quote is escaped.
        assert_eq!(
            field_selector(1, "a\"b"),
            "form[data-aitm-form=\"1\"] [name=\"a\\\"b\"]"
        );

        assert!(CLICKABLES_JS.starts_with(CLICKABLES_MARKER));
        for selector in [
            "a[href^=\"javascript:\"]",
            "[onclick]",
            "button:not([type=submit])",
            "[role=button]",
            "[data-href]",
        ] {
            assert!(CLICKABLES_JS.contains(selector), "{selector}");
        }
        // The listing cap is the named constant, not an inline literal.
        assert!(
            CLICKABLES_JS.contains(&format!("out.length<{MAX_CLICKABLES_LISTED}")),
            "{CLICKABLES_JS}"
        );
        assert!(CLICKABLES_JS.contains(":nth-child("));
        // The expression reads the page and nothing else: no network, no
        // mutation, no synthesised interaction.
        for forbidden in [
            "fetch(",
            "XMLHttpRequest",
            "document.write",
            "innerHTML",
            "setAttribute",
            ".click()",
            "location",
        ] {
            assert!(!CLICKABLES_JS.contains(forbidden), "{forbidden}");
        }
    }

    // --- stage-5 F1: foreign error texts are scrubbed -------------------------

    /// The text a misbehaving driver might put in its error: the URL it failed
    /// on, credential and all, and the cookie statement it rejected.
    const LEAKY_DRIVER_ERROR: &str =
        "navigation to http://t:8080/cb?token=abc failed; document.cookie = \"sid=S3\"";

    /// A driver whose every navigation fails with [`LEAKY_DRIVER_ERROR`].
    struct FailingNavBrowser;

    impl BrowserDriver for FailingNavBrowser {
        fn navigate(&self, _url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            Box::pin(async { Err(anyhow::anyhow!(LEAKY_DRIVER_ERROR)) })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { Ok(Value::Null) })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(String::new()) })
        }
    }

    /// A [`FakeJob`] whose browser is any driver, for a double `FakeJob` cannot
    /// hold.
    struct JobWithDriver {
        inner: FakeJob,
        driver: Arc<dyn BrowserDriver>,
    }

    impl JobCtx for JobWithDriver {
        fn job_id(&self) -> &str {
            self.inner.job_id()
        }
        fn profile(&self) -> &ScanProfile {
            self.inner.profile()
        }
        fn client(&self) -> Arc<dyn aitm_core::ProxyClient> {
            self.inner.client()
        }
        fn store(&self) -> Arc<dyn FlowStore> {
            self.inner.store()
        }
        fn guard(&self) -> Arc<dyn ScopeRateGuard> {
            self.inner.guard()
        }
        fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
            Some(Arc::clone(&self.driver))
        }
        fn session(&self) -> Option<Arc<SessionMaterial>> {
            self.inner.session()
        }
        fn charge(&self, units: u32) -> bool {
            self.inner.charge(units)
        }
        fn budget_left(&self) -> u32 {
            self.inner.budget_left()
        }
        fn deadline(&self) -> Instant {
            self.inner.deadline()
        }
        fn cancelled(&self) -> bool {
            self.inner.cancelled()
        }
        fn marker(&self) -> String {
            self.inner.marker()
        }
        fn report_crawl_error(&self, origin: &str, reason: &str) {
            self.inner.report_crawl_error(origin, reason);
        }
    }

    /// The crawler's "could not load this page" line carries the driver's error
    /// with every credential masked; the crawl itself goes on.
    #[tokio::test]
    async fn failed_navigation_is_logged_scrubbed() {
        let (_guard, lines) = crate::redact::capture::install();
        let job = JobWithDriver {
            inner: FakeJob::new(
                ScanProfile::default(),
                Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
            ),
            driver: Arc::new(FailingNavBrowser),
        };
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a page the browser cannot load is skipped, not fatal");
        assert_eq!(report.pages, 0);
        assert_eq!(report.attempts, 1);

        let logged = lines.containing("could not load this page");
        assert_eq!(logged.len(), 1, "{:?}", lines.all());
        assert!(logged[0].contains("error="), "{}", logged[0]);
        assert!(!logged[0].contains("abc"), "{}", logged[0]);
        assert!(!logged[0].contains("S3"), "{}", logged[0]);
        for line in lines.all() {
            assert!(!line.contains("abc") && !line.contains("S3"), "{line}");
        }
    }

    /// A driver whose every navigation fails with a TLS error.
    struct TlsFailBrowser;

    impl BrowserDriver for TlsFailBrowser {
        fn navigate(&self, _url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            Box::pin(async { Err(anyhow::anyhow!("tls handshake failed")) })
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { Ok(Value::Null) })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(String::new()) })
        }
    }

    /// Amendment 39b: a page the browser cannot load is reported to the job
    /// with the crawl origin and one closed reason token, so an all-failing
    /// browser crawl does not end with `crawl.errors 0`.
    #[tokio::test]
    async fn failed_navigation_is_reported_to_the_job() {
        let job = JobWithDriver {
            inner: FakeJob::new(
                ScanProfile::default(),
                Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
            ),
            driver: Arc::new(TlsFailBrowser),
        };
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a page the browser cannot load is skipped, not fatal");
        assert_eq!(report.pages, 0);

        assert_eq!(
            *job.inner.crawl_errors.lock().unwrap(),
            vec![(ROOT.to_string(), "tls".to_string())]
        );
    }

    /// A driver whose navigation never answers.
    struct HangingNavBrowser;

    impl BrowserDriver for HangingNavBrowser {
        fn navigate(&self, _url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            Box::pin(std::future::pending())
        }

        fn click(&self, _target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn type_text(&self, _selector: &str, _text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { Ok(Value::Null) })
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok(String::new()) })
        }
    }

    /// A page the browser never answers within the job's deadline is reported
    /// as `timeout`, read off the `tokio` timeout's own type (`bounded` keeps
    /// the `Elapsed` under its context), not off the prose around it.
    #[tokio::test]
    async fn a_browser_call_that_never_answers_reports_timeout() {
        let mut inner = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );
        inner.deadline = Instant::now() + Duration::from_millis(100);
        let job = JobWithDriver {
            inner,
            driver: Arc::new(HangingNavBrowser),
        };
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a page the browser never answered is skipped, not fatal");
        assert_eq!(report.pages, 0);

        assert_eq!(
            *job.inner.crawl_errors.lock().unwrap(),
            vec![(ROOT.to_string(), "timeout".to_string())]
        );
    }

    /// [`pages`] behind a driver whose tagged submit eval, or whose click,
    /// fails with a fixed error; everything else is the double's own.
    struct FailingInteractionBrowser {
        inner: FakeBrowser,
        submit_fails: Option<&'static str>,
        click_fails: Option<&'static str>,
    }

    impl BrowserDriver for FailingInteractionBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            self.inner.navigate(url)
        }

        fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
            match self.click_fails {
                Some(text) => Box::pin(async move { Err(anyhow::anyhow!(text)) }),
                None => self.inner.click(target),
            }
        }

        fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
            self.inner.type_text(selector, text)
        }

        fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
            self.inner.screenshot()
        }

        fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            if let Some(text) = self.submit_fails {
                if expr.contains(SUBMIT_FORM_MARKER) {
                    return Box::pin(async move { Err(anyhow::anyhow!(text)) });
                }
            }
            self.inner.eval(expr)
        }

        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            self.inner.get_dom()
        }
    }

    /// Amendment 39b: a form submission the browser fails is reported to the
    /// job with the crawl origin and one closed reason token, like a page it
    /// cannot load; the crawl goes on to the page's click.
    #[tokio::test]
    async fn failed_form_submission_is_reported_to_the_job() {
        let job = JobWithDriver {
            inner: FakeJob::new(
                ScanProfile::default(),
                Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
            ),
            driver: Arc::new(FailingInteractionBrowser {
                inner: pages(),
                submit_fails: Some("connection reset by peer"),
                click_fails: None,
            }),
        };
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a submission the browser fails is skipped, not fatal");
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.clicks, 1);

        assert_eq!(
            *job.inner.crawl_errors.lock().unwrap(),
            vec![(ROOT.to_string(), "transport".to_string())]
        );
    }

    /// Amendment 39b: a click the browser fails is reported to the job with
    /// the crawl origin and one closed reason token; the form before it was
    /// submitted and the crawl goes on.
    #[tokio::test]
    async fn failed_click_is_reported_to_the_job() {
        let job = JobWithDriver {
            inner: FakeJob::new(
                ScanProfile::default(),
                Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
            ),
            driver: Arc::new(FailingInteractionBrowser {
                inner: pages(),
                submit_fails: None,
                click_fails: Some("tls handshake failed"),
            }),
        };
        let limits = limits_for(&CrawlOptions::default());

        let report = BrowserCrawler
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("a click the browser fails is skipped, not fatal");
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.clicks, 0);

        assert_eq!(
            *job.inner.crawl_errors.lock().unwrap(),
            vec![(ROOT.to_string(), "tls".to_string())]
        );
    }

    /// `prime_session` propagates a failed navigation as an error whose text is
    /// scrubbed, so the lane's warning cannot leak what the driver echoed.
    #[tokio::test]
    async fn prime_session_propagates_a_scrubbed_error() {
        let material = SessionMaterial {
            cookies: vec![("sid".to_string(), "S3".to_string())],
            headers: Vec::new(),
        };
        let job = FakeJob::new(
            ScanProfile::default(),
            Arc::new(ScriptedClient::new(|_| Ok(response(200, &[], b"")))),
        );

        let err = prime_session(&FailingNavBrowser, &url(ROOT), &material, &job)
            .await
            .expect_err("the navigation failed");
        let text = format!("{err:#}");
        assert!(
            text.contains("navigation to http://t:8080/cb?token="),
            "{text}"
        );
        assert!(!text.contains("abc"), "{text}");
        assert!(!text.contains("S3"), "{text}");
    }

    #[tokio::test]
    async fn crawler_is_object_safe_and_reports_marked_flows() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(plain_pages().recording_into(store.clone() as Arc<dyn FlowStore>));
        let job = job_with(browser, store);
        let limits = limits_for(&CrawlOptions::default());
        let engine: Box<dyn Crawler> = Box::new(BrowserCrawler);

        let report = engine
            .crawl(&url(ROOT), vec![url(ROOT)], &job, &limits)
            .await
            .expect("the crawl succeeds");

        assert_eq!(report.pages, 2);
        let ids: Vec<FlowId> = report.flows.iter().map(|flow| flow.id).collect();
        assert!(
            ids.is_empty(),
            "the plain site declares no captures: {ids:?}"
        );
    }
}
