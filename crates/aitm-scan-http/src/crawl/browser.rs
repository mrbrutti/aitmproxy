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
//! Form submission goes through `document.forms[i].requestSubmit()` on a form
//! tagged with `data-aitm-form` (plan call **A4**) rather than through clicking
//! a submit control: it is deterministic across layouts and still fires the
//! page's own submit handlers. Values come from [`crate::crawl::values`], which
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

use crate::crawl::extract::{extract, Extracted, FieldKind, FieldSpec, FormSpec};
use crate::crawl::frontier::{fingerprint, remaining, CrawlReport, Crawler, Frontier, Limits};
use crate::crawl::values::{form_action, value_for};
use crate::limits::{
    job_mark, MARK_CRAWL, MAX_CLICKABLES_LISTED, MAX_DOM_BYTES, SETTLE_MAX_MS, SETTLE_POLL_MS,
};
use crate::redact::{safe_url, scrub_error};
use crate::session::{browser_cookie_statements, browser_partial};
use crate::url_norm::{guard_authority, parse_absolute, request_url, same_origin};

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

/// What the store held before a browser action, so the flows that action
/// produced can be told apart from everything else in it.
///
/// A browser navigation is a real capture through the proxy listener, so the
/// job's own client never sees it and cannot mark it. The lane brackets each
/// action with a snapshot and a [`StoreDiff::mark_new`], which is the whole of
/// spec **D5**'s "the lane diffs the store around each navigation".
pub(crate) struct StoreDiff {
    before: HashSet<FlowId>,
}

impl StoreDiff {
    /// The ids the store holds right now.
    pub(crate) fn snapshot(store: &dyn FlowStore) -> Self {
        Self {
            before: store.list().into_iter().collect(),
        }
    }

    /// Mark every HTTP flow added since the snapshot whose request addresses
    /// `origin`, and return those flows as the store now holds them.
    ///
    /// Marks are a union: a flow that somehow falls in two windows keeps one
    /// copy of each mark. A flow to another origin is left alone — the browser
    /// fetches fonts, analytics and CDN assets while it renders, and those are
    /// not this job's traffic.
    pub(crate) fn mark_new(
        &self,
        store: &dyn FlowStore,
        origin: &Url,
        marks: &[String],
    ) -> Vec<HttpFlow> {
        let mut produced = Vec::new();
        for id in store.list() {
            if self.before.contains(&id) {
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
                produced.push(marked);
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
/// address its controls unambiguously.
///
/// A page may hold several forms with the same field names (a header search and
/// a page search); without the tag, `[name="q"]` would type into whichever came
/// first in the document.
pub(crate) fn tag_form_js(index: usize) -> String {
    format!("document.forms[{index}].setAttribute(\"data-aitm-form\",\"{index}\")")
}

/// Submit `document.forms[index]` the way the page expects (plan call **A4**).
///
/// `requestSubmit()` fires the page's `submit` handlers and its validation, so
/// a single-page app that intercepts the submit behaves as it does for a human;
/// `submit()` is the fallback for an engine that does not have it.
pub(crate) fn submit_form_js(index: usize) -> String {
    format!(
        "document.forms[{index}].requestSubmit ? \
         document.forms[{index}].requestSubmit() : document.forms[{index}].submit()"
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
    let Some(limit) = remaining(job) else {
        anyhow::bail!("scan: the job deadline passed before the browser answered");
    };
    match tokio::time::timeout(limit, future).await {
        Ok(Ok(value)) => Ok(value),
        // The driver's error text is foreign (it may echo the URL it failed on
        // or the statement it rejected), so it is scrubbed here, once, before
        // any call site logs it or `prime_session` propagates it (AC T2-6).
        Ok(Err(err)) => Err(anyhow::anyhow!("{}", scrub_error(&err))),
        Err(_) => anyhow::bail!("scan: the browser did not answer within {limit:?}"),
    }
}

/// What the engine does after one step.
enum Step {
    /// Carry on with this page.
    Continue,
    /// Abandon this page, keep crawling.
    NextPage,
    /// Stop the crawl with this reason (one of the literals on
    /// [`CrawlReport::stopped_reason`]).
    Stop(&'static str),
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
        }
    }

    /// Drain the frontier, one page at a time, until something says stop.
    async fn run_pages(&mut self) -> anyhow::Result<Option<&'static str>> {
        while let Some((page, depth)) = self.frontier.pop() {
            if self.job.cancelled() {
                return Ok(Some("cancelled"));
            }
            if remaining(self.job).is_none() {
                return Ok(Some("time"));
            }
            if self.report.attempts >= self.limits.max_pages {
                return Ok(Some("max_pages"));
            }
            self.report.attempts += 1;
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
            return Ok(Step::Stop("budget"));
        }

        let diff = StoreDiff::snapshot(self.store.as_ref());
        let outcome = bounded(self.job, self.browser.navigate(page.as_str())).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => {
                self.guard.record_error(&authority);
                self.collect(&diff);
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

        let Some(landed) = self.in_scope(&outcome.final_url) else {
            // The browser is on that page now; the next click would be a click
            // on a third party.
            self.collect(&diff);
            tracing::info!(
                target: "scan",
                job = self.job.job_id(),
                url = %safe_url(&outcome.final_url),
                "crawl: the browser landed outside the engagement; stopping"
            );
            return Ok(Step::Stop("left_scope"));
        };

        self.report.pages += 1;
        self.frontier.mark_visited(&landed);
        let dom = match bounded(self.job, self.browser.get_dom()).await {
            Ok(dom) => dom,
            Err(err) => {
                self.collect(&diff);
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
        // The permit covered the navigation and the DOM read; the per-page work
        // that follows takes its own as it goes.
        drop(permit);
        self.collect(&diff);

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
            .and_then(|href| crate::url_norm::resolve(page, href))
            .unwrap_or_else(|| page.clone());
        let resources: &[String] = if self.limits.follow_resources {
            &extracted.resources
        } else {
            &[]
        };
        for href in extracted.links.iter().chain(resources) {
            let Some(target) = crate::url_norm::resolve(&base, href) else {
                continue;
            };
            if self.in_scope(target.as_str()).is_none() {
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
        if !self.limits.submit_forms || self.limits.forms_per_page == 0 {
            return Ok(Step::Continue);
        }
        let forms: Vec<FormSpec> = extracted
            .forms
            .iter()
            .filter(|form| {
                form_action(form, page, self.origin, extracted.base.as_deref()).is_some()
            })
            .take(self.limits.forms_per_page as usize)
            .cloned()
            .collect();

        for form in forms {
            if self.job.cancelled() {
                return Ok(Step::Stop("cancelled"));
            }
            match self.return_to(page).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
            // Tagging is best effort: a page that rewrote its forms between the
            // extraction and now simply does not get submitted.
            if bounded(self.job, self.browser.eval(&tag_form_js(form.index)))
                .await
                .is_err()
            {
                continue;
            }
            self.fill_form(&form).await;

            if !self.job.charge(1) {
                return Ok(Step::Stop("budget"));
            }
            let diff = StoreDiff::snapshot(self.store.as_ref());
            let submitted = bounded(self.job, self.browser.eval(&submit_form_js(form.index))).await;
            if let Err(err) = submitted {
                self.collect(&diff);
                tracing::debug!(
                    target: "scan",
                    job = self.job.job_id(),
                    url = %safe_url(page.as_str()),
                    error = %err,
                    "crawl: a form submission failed"
                );
                continue;
            }
            let landing = self.settle().await;
            self.report.forms_submitted = self.report.forms_submitted.saturating_add(1);
            self.collect(&diff);

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
    async fn fill_form(&self, form: &FormSpec) {
        let origin = self.origin.as_str();
        let marker = self.job.marker();
        let mut groups: HashSet<&str> = HashSet::new();

        for field in &form.fields {
            if field.name.is_empty() {
                continue;
            }
            let selector = field_selector(form.index, &field.name);
            match field.kind {
                // The page's own value is already in the DOM.
                FieldKind::Hidden | FieldKind::File => continue,
                FieldKind::Checkbox | FieldKind::Radio => {
                    if !groups.insert(field.name.as_str()) {
                        continue;
                    }
                    // A group the page already checked keeps the page's choice.
                    if group_checked(form, &field.name) {
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
                return Ok(Step::Stop("cancelled"));
            }
            match self.return_to(page).await? {
                Step::Continue => {}
                other => return Ok(other),
            }
            if !self.job.charge(1) {
                return Ok(Step::Stop("budget"));
            }
            let diff = StoreDiff::snapshot(self.store.as_ref());
            let clicked = bounded(
                self.job,
                self.browser.click(ClickTarget::Selector(selector.clone())),
            )
            .await;
            if let Err(err) = clicked {
                self.collect(&diff);
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
            self.collect(&diff);

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

        let Some(landed) = self.in_scope(landing) else {
            tracing::info!(
                target: "scan",
                job = self.job.job_id(),
                url = %safe_url(landing),
                "crawl: an interaction left the engagement; stopping"
            );
            return Ok(Step::Stop("left_scope"));
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
            return Ok(Step::Stop("budget"));
        }
        let diff = StoreDiff::snapshot(self.store.as_ref());
        let outcome = bounded(self.job, self.browser.navigate(page.as_str())).await;
        self.collect(&diff);
        match outcome {
            Ok(_) => Ok(Step::Continue),
            Err(err) => {
                self.guard.record_error(&guard_authority(page));
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

    /// `candidate` as a URL when it is this crawl's origin and the scope guard
    /// still admits it, `None` otherwise.
    fn in_scope(&self, candidate: &str) -> Option<Url> {
        let url = parse_absolute(candidate)?;
        if !same_origin(&url, self.origin) {
            return None;
        }
        if !self.guard.in_scope(&guard_authority(&url)) {
            return None;
        }
        Some(url)
    }

    /// Mark what the last action captured and keep those flows for the lane.
    fn collect(&mut self, diff: &StoreDiff) {
        let produced = diff.mark_new(self.store.as_ref(), self.origin, &self.marks);
        self.report.flows.extend(produced);
    }

    /// The finished report, with the stop reason the run arrived at.
    fn into_report(mut self, stopped: Option<&'static str>) -> CrawlReport {
        self.report.stopped_reason = match stopped {
            Some(reason) => Some(reason),
            // The frontier ran dry, but not because there was nothing left.
            None if self.frontier.depth_hit => Some("max_depth"),
            None if self.guard_refused > 0 => Some("guard_refused"),
            None => None,
        };
        self.report
    }
}

/// Whether the `name` group of `form` already has a member the page checked.
fn group_checked(form: &FormSpec, name: &str) -> bool {
    form.fields
        .iter()
        .any(|field: &FieldSpec| field.name == name && field.checked)
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
    use crate::limits::MAX_CLICKABLES_LISTED;
    use crate::testutil::{
        captured_flow, request, response, FakeBrowser, FakeJob, PageScript, ScriptedClient,
        CLICKABLES_MARKER,
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
        FakeBrowser::new(vec![
            (
                ROOT,
                PageScript::new(HOME)
                    .with_forms(&[(0, SEARCH)])
                    .with_clickables(&[(BUTTON, "http://t:8080/clicked")])
                    .with_captures(vec![request("GET", ROOT, &[], None)]),
            ),
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

        assert_eq!(
            driving(&browser),
            vec![
                "navigate http://t:8080/".to_string(),
                "type form[data-aitm-form=\"0\"] [name=\"q\"] = aitm-aitm7f3a".to_string(),
                // The return before the click: the submit navigated away.
                "navigate http://t:8080/".to_string(),
                "click body > button:nth-child(3)".to_string(),
                "navigate http://t:8080/a".to_string(),
            ]
        );
        assert_eq!(job.charges.load(Ordering::SeqCst), 5);
        assert_eq!(report.pages, 4);
        assert_eq!(report.attempts, 2);
        assert_eq!(report.forms_submitted, 1);
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
        assert_eq!(report.stopped_reason, Some("budget"));
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

        assert_eq!(report.stopped_reason, Some("left_scope"));
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

    #[test]
    fn store_diff_marks_only_new_origin_flows() {
        let store = Arc::new(MemFlowStore::new());
        let old = store.insert(Flow::Http(capture("http://t:8080/old")));

        let diff = StoreDiff::snapshot(store.as_ref());
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

        // Marks are a union, so marking the same flow twice does not duplicate.
        let again = diff.mark_new(store.as_ref(), &url(ROOT), &marks());
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].metadata.marks, marks());
    }

    #[test]
    fn js_helpers_pin() {
        assert_eq!(
            tag_form_js(2),
            "document.forms[2].setAttribute(\"data-aitm-form\",\"2\")"
        );
        assert_eq!(
            submit_form_js(1),
            "document.forms[1].requestSubmit ? document.forms[1].requestSubmit() : document.forms[1].submit()"
        );
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
