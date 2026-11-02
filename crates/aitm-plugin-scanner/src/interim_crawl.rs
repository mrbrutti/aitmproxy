//! The interim lane's **client crawl**: the HTML extractor and the
//! breadth-first driver the lane uses when no browser is bound.
//!
//! Spec D1 asks every T1 acceptance criterion to be provable on the interim
//! HTTP lane, and spec D5 says "client-crawler GETs go through `send_opts`
//! like probes, recorded under the same policy with the crawl mark". Without
//! this, a job against a target nobody has browsed discovers nothing: the lane
//! can only enumerate flows the proxy already captured.
//!
//! What the crawl does, and nothing more:
//!
//! - It fetches the origin root through the job's budgeted client with
//!   `record: Always` and the `scan:<job>` + `crawl` marks, so each page lands
//!   in the store as the D5 crawl capture the v1 enumerator then reads.
//! - It extracts same-origin navigations from each HTML page: `href` on
//!   anchors, `src` on the subresources a page fetches, and forms (a GET form
//!   becomes a query, a `x-www-form-urlencoded` POST form a body), every field
//!   carrying an inert value.
//! - It walks them breadth-first, bounded by `crawl.max_depth`,
//!   `crawl.max_pages` and the job's probe budget, and stops on cancellation
//!   or the first refusal from the client.
//!
//! It never leaves the origin, never follows a redirect off it, never submits
//! a multipart form, and skips anything that looks like a log-out. It is not a
//! browser: it runs no script and clicks nothing, so a script-only endpoint
//! still needs the browser crawl ([`crate::crawl`]).
//!
//! The extractor is a tag-aware scan in the shape of [`crate::crawl`]'s
//! `harvest_links` — comments and raw-text elements are not markup — but it
//! reads whole tags rather than one attribute, because a form's fields decide
//! what the navigation carries.

use std::collections::{HashSet, VecDeque};
use std::time::SystemTime;

use aitm_core::{Body, HeaderMap, HttpRequest, HttpVersion, RecordPolicy, SendOptions};
use aitm_scan_model::{CrawlErrorKind, JobCtx};
use url::Url;

use crate::client::ProbeRefused;
use crate::interim_lane::CRAWL_MARK;
use crate::util::origin_key;

/// Navigations one page may contribute to the frontier. A hostile page with a
/// million anchors cannot grow it further.
const MAX_LINKS_PER_PAGE: usize = 512;

/// Hard ceiling on the pending frontier, independent of `max_pages`.
const MAX_FRONTIER: usize = 4096;

/// Bytes of a page that are scanned for navigations. The rest is ignored.
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;

/// Fields one form contributes to its submission.
const MAX_FORM_FIELDS: usize = 32;

/// Tags parsed from one page, across the page walk and every form's field
/// scan together, before extraction stops. Together with the per-form bound
/// below it makes the work a page can demand linear in the page, whatever its
/// structure (security review, whole branch, 2026-11-01).
pub const MAX_TAGS_PER_PAGE: usize = 50_000;

/// Attributes read from one tag.
const MAX_ATTRS: usize = 64;

/// One navigation the crawl may make: a `GET` of a URL, or the
/// `application/x-www-form-urlencoded` `POST` a form describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Navigation {
    /// `GET` or `POST`.
    pub method: String,
    /// The absolute, same-origin, fragment-free URL.
    pub url: Url,
    /// The encoded form body of a `POST`, `None` for a `GET`.
    pub body: Option<String>,
}

impl Navigation {
    /// The key two navigations are the same under: method, URL and body.
    fn key(&self) -> String {
        format!(
            "{} {} {}",
            self.method,
            self.url,
            self.body.as_deref().unwrap_or("")
        )
    }

    /// A plain `GET` of `url`.
    fn get(url: Url) -> Self {
        Self {
            method: "GET".to_string(),
            url,
            body: None,
        }
    }
}

/// Why a client crawl stopped before the reachable graph was exhausted.
///
/// A typed reason rather than a loose string, like the job's own
/// [`aitm_scan_model::StoppedReason`]: it is only logged today, but a token a
/// log line carries is still a vocabulary (whole-branch quality finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlStop {
    /// `crawl.max_pages` pages were fetched.
    MaxPages,
    /// Every frontier link left was deeper than `crawl.max_depth`.
    MaxDepth,
    /// The job's probe budget could not pay for another page.
    Budget,
    /// The job was cancelled mid-crawl.
    Cancelled,
    /// The client refused a send (scope, ladder, deadline).
    Refused,
    /// The origin is not a URL with a host, so there was nothing to seed from.
    BadOrigin,
}

impl CrawlStop {
    /// The lowercase token the log line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxPages => "max_pages",
            Self::MaxDepth => "max_depth",
            Self::Budget => "budget",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
            Self::BadOrigin => "bad_origin",
        }
    }
}

impl std::fmt::Display for CrawlStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a client crawl reached and why it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCrawl {
    /// Pages fetched successfully.
    pub pages: u32,
    /// Requests that failed outright: a page the crawl asked for and could not
    /// fetch (a connect/transport failure or a per-probe timeout), not a
    /// refusal that ends the crawl (amendment 39).
    pub failed: u32,
    /// The kind of the most recent failed request, or `None` when none failed.
    pub last_error: Option<CrawlErrorKind>,
    /// Forms the crawl found and deliberately did not submit — logout-looking
    /// or destructive-looking ones (`CrawlCounters::forms_skipped`).
    pub forms_skipped: u32,
    /// Forms the crawl submitted and got an answer for
    /// (`CrawlCounters::forms_submitted`, amendment 53): the `POST`
    /// navigations a form became and the client sent. A form the crawl
    /// skipped is in `forms_skipped`, not here; a `POST` whose send failed is
    /// in `failed`. A `GET` form is a navigation like any link and is counted
    /// in `pages` only.
    pub forms_submitted: u32,
    /// Why it stopped, or `None` when the reachable graph was exhausted.
    pub stopped: Option<CrawlStop>,
}

/// Classify a failed client-crawl request into a closed [`CrawlErrorKind`]
/// token (amendment 39; `h2_not_negotiated` is amendment 21's counted probe
/// error). An exact-token check for `h2_not_negotiated` first, then the typed
/// probe timeout, then substring tests over the error chain: the TLS words,
/// then the connect refusal, with `transport` as the catch-all.
///
/// Amendment 68: TLS is tested **before** connect. A TLS failure names the
/// connection it was failing on ("error connecting to h:443: tls handshake
/// failed"), so reading the connect words first read every such chain as
/// `connect_refused`. For the same reason the connect arm names the refused
/// shapes only — "connection refused", "connect refused", "econnrefused" —
/// and not the bare word `connect`, which "connection reset by peer" and
/// "disconnected" also carry: those are `transport`.
pub(crate) fn classify(err: &anyhow::Error) -> CrawlErrorKind {
    let text = err
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
        .to_ascii_lowercase();
    if text.contains("h2_not_negotiated") {
        return CrawlErrorKind::H2NotNegotiated;
    }
    if matches!(
        err.downcast_ref::<ProbeRefused>(),
        Some(ProbeRefused::Timeout { .. })
    ) {
        return CrawlErrorKind::Timeout;
    }
    if text.contains("tls") || text.contains("certificate") || text.contains("handshake") {
        return CrawlErrorKind::Tls;
    }
    if text.contains("connection refused")
        || text.contains("connect refused")
        || text.contains("econnrefused")
    {
        return CrawlErrorKind::ConnectRefused;
    }
    CrawlErrorKind::Transport
}

/// Crawl `origin` breadth-first through the job's client.
///
/// Every fetch is one stimulus of the job's single budget: it goes through
/// [`JobCtx::client`], which is the engine's `JobClient` and charges the
/// budget, paces the host and refuses once the budget, deadline or
/// cancellation says so (spec D5, "one budget per job"). The crawl therefore
/// does **not** charge a second unit per page of its own; it asks for no more
/// pages than the budget has left and stops on the client's first refusal.
///
/// The caller is the interim lane, which runs this only when no browser can
/// crawl the origin and `crawl.max_pages > 0`.
pub(crate) async fn crawl_with_client(origin: &str, job: &dyn JobCtx) -> ClientCrawl {
    let profile = job.profile();
    let Some(seed) = Url::parse(origin).ok().filter(|u| u.has_host()) else {
        return ClientCrawl {
            pages: 0,
            failed: 0,
            last_error: None,
            forms_skipped: 0,
            forms_submitted: 0,
            stopped: Some(CrawlStop::BadOrigin),
        };
    };
    // Spec D5 "one budget per job": a page is a stimulus, so the crawl asks
    // for no more of them than the budget could pay for.
    let budget_bound = job.budget_left() < profile.crawl.max_pages;
    let max_pages = profile.crawl.max_pages.min(job.budget_left());
    let max_depth = profile.crawl.max_depth;
    let submit_forms = profile.crawl.submit_forms;

    let mut queue: VecDeque<(Navigation, u32)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let seed = Navigation::get(seed);
    visited.insert(seed.key());
    queue.push_back((seed, 0));

    let mut pages = 0u32;
    let mut failed = 0u32;
    let mut last_error: Option<CrawlErrorKind> = None;
    let mut forms_skipped = 0u32;
    let mut forms_submitted = 0u32;
    let mut attempts = 0u32;
    let mut depth_hit = false;
    let mut stopped: Option<CrawlStop> = None;

    while let Some((nav, depth)) = queue.pop_front() {
        if attempts >= max_pages {
            stopped = Some(if budget_bound {
                CrawlStop::Budget
            } else {
                CrawlStop::MaxPages
            });
            break;
        }
        if job.cancelled() {
            stopped = Some(CrawlStop::Cancelled);
            break;
        }
        if job.budget_left() == 0 {
            stopped = Some(CrawlStop::Budget);
            break;
        }

        attempts += 1;
        let flow = match job
            .client()
            .send_opts(request_for(&nav, job), options(job))
            .await
        {
            Ok(flow) => flow,
            Err(err) => {
                // A refusal is the job's own budget, deadline, cancellation or
                // error ladder speaking: the crawl is over. A per-probe timeout
                // (`ProbeRefused::Timeout`) is one unreachable page, not the end
                // of the crawl, as is any non-refusal error (amendment 39).
                if let Some(refused) = err.downcast_ref::<ProbeRefused>() {
                    if !matches!(refused, ProbeRefused::Timeout { .. }) {
                        stopped = Some(CrawlStop::Refused);
                        break;
                    }
                }
                // Reported here, where the failure happened, so each request
                // carries its own classified token; `failed`/`last_error` stay
                // the crawl's aggregate view for the status.
                let kind = classify(&err);
                job.report_crawl_error(origin, kind.as_str());
                failed += 1;
                last_error = Some(kind);
                continue;
            }
        };
        pages += 1;
        // Only a form becomes a `POST` navigation, so an answered `POST` is a
        // form the crawl submitted (amendment 53).
        if nav.method == "POST" {
            forms_submitted = forms_submitted.saturating_add(1);
        }

        let Some(response) = flow.response.as_ref() else {
            continue;
        };
        if depth + 1 > max_depth {
            depth_hit = true;
            continue;
        }

        let mut found: Vec<Navigation> = Vec::new();
        // A redirect is followed only when it stays on the origin, and as a
        // link rather than a redirect: the crawl is a map, not a client.
        if (300..400).contains(&response.status) {
            if let Some(location) = response.headers.get("location") {
                if let Some(url) = resolve(&nav.url, location) {
                    found.push(Navigation::get(url));
                }
            }
        }
        if is_html(response.headers.get("content-type").unwrap_or("")) {
            if let Some(bytes) = crate::discover::body_bytes(&response.body) {
                // Bounded before the decode, so a huge page costs the scan one
                // bounded copy rather than its own size.
                let head = bytes[..bytes.len().min(MAX_HTML_BYTES)].to_vec();
                let base = nav.url.clone();
                // The extractor is synchronous and bounded, but a 2 MiB page
                // is still real CPU: it runs on a blocking thread so it never
                // holds a runtime worker the other jobs need (security
                // review, whole branch, 2026-11-01). A parse that panicked
                // contributes nothing rather than ending the crawl.
                let parsed = tokio::task::spawn_blocking(move || {
                    let text = String::from_utf8_lossy(&head);
                    navigations_counted(&base, &text, submit_forms)
                })
                .await;
                if let Ok(extracted) = parsed {
                    forms_skipped = forms_skipped.saturating_add(extracted.forms_skipped);
                    found.extend(extracted.navigations);
                }
            }
        }

        for next in found {
            if queue.len() >= MAX_FRONTIER {
                break;
            }
            if visited.insert(next.key()) {
                queue.push_back((next, depth + 1));
            }
        }
    }

    ClientCrawl {
        pages,
        failed,
        last_error,
        forms_skipped,
        forms_submitted,
        stopped: stopped.or(depth_hit.then_some(CrawlStop::MaxDepth)),
    }
}

/// The request one navigation sends, carrying the job's session material the
/// way a probe does (spec D7).
fn request_for(nav: &Navigation, job: &dyn JobCtx) -> HttpRequest {
    let mut headers = HeaderMap::new();
    let body = match &nav.body {
        Some(encoded) => {
            headers.set("content-type", "application/x-www-form-urlencoded");
            Body::Bytes(encoded.as_bytes().to_vec())
        }
        None => Body::Empty,
    };
    let path = match nav.url.query() {
        Some(query) => format!("{}?{query}", nav.url.path()),
        None => nav.url.path().to_string(),
    };
    let mut req = HttpRequest {
        method: nav.method.clone(),
        scheme: nav.url.scheme().to_string(),
        authority: authority(&nav.url),
        path,
        version: HttpVersion::Http11,
        headers,
        body,
        timestamp: SystemTime::now(),
    };
    if let Some(material) = job.session() {
        crate::session::apply(&material, &mut req);
    }
    req
}

/// Spec D5: a crawl capture is recorded and marked, unlike a probe.
fn options(job: &dyn JobCtx) -> SendOptions {
    SendOptions {
        record: RecordPolicy::Always,
        marks: vec![format!("scan:{}", job.job_id()), CRAWL_MARK.to_string()],
        version: job.profile().http.version.into(),
    }
}

/// Whether a response body is worth scanning for navigations.
fn is_html(content_type: &str) -> bool {
    let ctype = content_type.to_ascii_lowercase();
    ctype.contains("text/html") || ctype.contains("application/xhtml")
}

/// The `host[:port]` of a URL, the port kept only when it is not the scheme's
/// default (`Url` elides a default port itself).
fn authority(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Every same-origin navigation `html` makes reachable from the page at
/// `base`, in document order, deduplicated, at most [`MAX_LINKS_PER_PAGE`].
///
/// The rules, all of them:
///
/// - `<a href>` and `<area href>` are navigations.
/// - `src` on the subresource elements a page fetches (`img`, `iframe`,
///   `frame`, `script`, `source`, `embed`, `track`, `audio`, `video`,
///   `input`) is a navigation: it is a request the page makes, and often the
///   only place a parameterized endpoint appears.
/// - A `<form>` is one navigation when `submit_forms` is set: a GET form
///   becomes the action with the fields as its query, a POST form the action
///   with an `application/x-www-form-urlencoded` body. Fields take their own
///   `value` when they have one (a hidden CSRF token stays itself) and an
///   inert `a` / `1` otherwise; submit, image, reset and file controls carry
///   nothing. A multipart or `text/plain` form is skipped — the crawl encodes
///   one way.
/// - A link is dropped unless it resolves to an `http(s)` URL, free of
///   userinfo, on the page's own origin. Fragments are stripped, so a link to
///   the page itself is not a navigation, and a log-out looking path is left
///   alone.
/// - A form whose action path or field names look like a log-out or a
///   destructive action ([`looks_destructive`]) is not submitted; the crawl
///   counts it instead ([`Extracted::forms_skipped`]).
/// - Comments are not markup, and the text of `<script>` / `<style>` is not
///   markup either (their `src` still is).
pub fn navigations(base: &Url, html: &str, submit_forms: bool) -> Vec<Navigation> {
    navigations_counted(base, html, submit_forms).navigations
}

/// What one page's markup yields: the navigations the crawl makes, and how
/// many forms it deliberately left alone.
#[derive(Debug, Default)]
pub struct Extracted {
    /// The navigations, in document order, deduplicated.
    pub navigations: Vec<Navigation>,
    /// Forms skipped as logout-looking or destructive-looking
    /// (`CrawlCounters::forms_skipped`). Counted only when `submit_forms` is
    /// on: with it off no form is read, so none is skipped.
    pub forms_skipped: u32,
}

/// [`navigations`], with the count of forms the crawl refused to submit.
pub fn navigations_counted(base: &Url, html: &str, submit_forms: bool) -> Extracted {
    let html = crate::util::truncate_on_char_boundary(html, MAX_HTML_BYTES);
    let mut out: Vec<Navigation> = Vec::new();
    let mut forms_skipped = 0u32;
    let mut seen: HashSet<String> = HashSet::new();
    let mut i = 0;
    // One budget of tag parses for the whole page, spent by this walk and by
    // every form's field scan, so the work a page can demand is bounded by
    // its length and not by its structure.
    let mut budget = MAX_TAGS_PER_PAGE;

    let mut push = |nav: Option<Navigation>, out: &mut Vec<Navigation>| {
        if let Some(nav) = nav {
            if !looks_like_logout(&nav.url) && seen.insert(nav.key()) {
                out.push(nav);
            }
        }
    };

    while out.len() < MAX_LINKS_PER_PAGE && budget > 0 {
        let Some(tag) = next_tag(html, i) else {
            break;
        };
        budget -= 1;
        i = tag.end;
        match tag.name.as_str() {
            "a" | "area" => push(link(base, tag.attr("href")), &mut out),
            "form" => {
                if submit_forms {
                    match form(base, &tag, html, &mut budget) {
                        FormOutcome::Submit(nav) => push(Some(nav), &mut out),
                        FormOutcome::Skipped => forms_skipped = forms_skipped.saturating_add(1),
                        FormOutcome::NotEncodable => {}
                    }
                }
            }
            // Raw text, not markup: skip the content, keep the `src`.
            "script" | "style" => {
                push(link(base, tag.attr("src")), &mut out);
                i = crate::util::find_close_tag(html, &tag.name, tag.end, html.len())
                    .unwrap_or(html.len());
            }
            "img" | "iframe" | "frame" | "source" | "embed" | "track" | "audio" | "video"
            | "input" => push(link(base, tag.attr("src")), &mut out),
            _ => {}
        }
    }
    Extracted {
        navigations: out,
        forms_skipped,
    }
}

/// A `GET` navigation for an `href`/`src` value, or `None` when it is not one.
fn link(base: &Url, href: Option<&str>) -> Option<Navigation> {
    let url = resolve(base, href?)?;
    // A link to the page itself (a bare fragment) is not a navigation.
    (url != *base).then(|| Navigation::get(url))
}

/// What the crawl does with one `<form>`.
enum FormOutcome {
    /// Submit it as this navigation.
    Submit(Navigation),
    /// Leave it alone, and say so: it looks like a log-out or a destructive
    /// action (`CrawlCounters::forms_skipped`).
    Skipped,
    /// Not a form the crawl can send: off-origin or unresolvable action, or an
    /// encoding the crawl does not produce.
    NotEncodable,
}

/// The navigation one `<form>` describes, or why the crawl will not submit
/// it. `budget` is the page's remaining tag budget, which the field scan
/// draws on.
fn form(base: &Url, tag: &Tag, html: &str, budget: &mut usize) -> FormOutcome {
    let enctype = tag.attr("enctype").unwrap_or("").to_ascii_lowercase();
    if !enctype.is_empty() && !enctype.contains("application/x-www-form-urlencoded") {
        return FormOutcome::NotEncodable;
    }
    // An empty action submits to the page the form is on, query and all.
    let mut url = match tag.attr("action").map(str::trim).unwrap_or("") {
        "" => base.clone(),
        action => match resolve(base, action) {
            Some(url) => url,
            None => return FormOutcome::NotEncodable,
        },
    };
    let fields = fields(html, tag.end, budget);
    let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
    if looks_like_logout(&url) || looks_destructive(url.path(), &names) {
        tracing::debug!(
            target: "aitm::scanner",
            path = url.path(),
            "crawl: skipped a form that looks like a log-out or a destructive action"
        );
        return FormOutcome::Skipped;
    }
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields)
        .finish();
    let post = tag
        .attr("method")
        .is_some_and(|method| method.trim().eq_ignore_ascii_case("post"));
    if post {
        return FormOutcome::Submit(Navigation {
            method: "POST".to_string(),
            url,
            body: Some(encoded),
        });
    }
    url.set_query((!encoded.is_empty()).then_some(encoded.as_str()));
    FormOutcome::Submit(Navigation::get(url))
}

/// The `(name, value)` pairs a form submits, read from the controls between
/// its opening tag and the end of the form.
///
/// Forms do not nest, so a form ends at its `</form>` **or** at the next
/// `<form`, whichever comes first: an unclosed form does not swallow the
/// controls of the one after it, and — because every form's scan is confined
/// to its own stretch of the page — a page of N unclosed forms costs N scans
/// of disjoint ranges, not N scans to the end of the document (security
/// review, whole branch, 2026-11-01). `budget` is the page's remaining tag
/// budget; each tag parsed here spends one unit of it.
fn fields(html: &str, from: usize, budget: &mut usize) -> Vec<(String, String)> {
    let next_form = find_open_tag(html, "form", from).unwrap_or(html.len());
    let end = crate::util::find_close_tag(html, "form", from, next_form).unwrap_or(next_form);
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut i = from;
    while fields.len() < MAX_FORM_FIELDS && *budget > 0 {
        let Some(tag) = next_tag(html, i) else {
            break;
        };
        if tag.end > end {
            break;
        }
        *budget -= 1;
        i = tag.end;
        if !matches!(tag.name.as_str(), "input" | "select" | "textarea") {
            continue;
        }
        let Some(name) = tag.attr("name").map(str::trim).filter(|n| !n.is_empty()) else {
            continue;
        };
        let kind = tag.attr("type").unwrap_or("").trim().to_ascii_lowercase();
        // A control that carries no value, or a file the crawl cannot encode.
        if matches!(
            kind.as_str(),
            "submit" | "button" | "image" | "reset" | "file"
        ) {
            continue;
        }
        let value = match tag.attr("value") {
            Some(value) if !value.is_empty() => value.to_string(),
            _ => inert_value(&kind),
        };
        fields.push((name.to_string(), value));
    }
    fields
}

/// The value the crawl submits for a field that has none: inert, and shaped
/// like what the control accepts so the submission is not refused outright.
fn inert_value(kind: &str) -> String {
    match kind {
        "number" | "range" => "1",
        "checkbox" | "radio" => "on",
        "email" => "a@test.invalid",
        "url" => "http://test.invalid/",
        _ => "a",
    }
    .to_string()
}

/// Resolve `href` against `base`, keeping only an `http(s)`, credential-free,
/// fragment-free URL on `base`'s own origin.
fn resolve(base: &Url, href: &str) -> Option<Url> {
    let href = href.trim();
    if href.is_empty() {
        return None;
    }
    let mut url = base.join(href).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if url.host_str().unwrap_or("").is_empty() {
        return None;
    }
    // A credentialed link is never followed: `http://target.test@evil.test/`
    // reads as the target and connects somewhere else.
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    url.set_fragment(None);
    (origin_of(&url) == origin_of(base)).then_some(url)
}

/// The origin a URL belongs to, in the engine's one normal form.
fn origin_of(url: &Url) -> String {
    origin_key(url.scheme(), &authority(url))
}

/// Whether a path reads as a log-out. The crawl has no session to throw away,
/// but an authenticated scan does (spec D7), and one anchor must not end it.
fn looks_like_logout(url: &Url) -> bool {
    let path = url.path().to_ascii_lowercase();
    [
        "logout", "log-out", "log_out", "signout", "sign-out", "sign_out",
    ]
    .iter()
    .any(|word| path.contains(word))
}

/// The words that make a form look like it changes something that matters.
/// Matched whole, against the words of the action path's segments and of the
/// field names (security review, delta ca852f71..e6bd03bc, 2026-11-01).
const DESTRUCTIVE_WORDS: [&str; 9] = [
    "delete",
    "remove",
    "destroy",
    "password",
    "transfer",
    "pay",
    "purchase",
    "unsubscribe",
    "confirm",
];

/// Whether a form reads as destructive: its action path or any field name
/// carries one of [`DESTRUCTIVE_WORDS`] as a whole word. A map crawl under
/// agent `auto` admission must not submit such a form; `scan.map` is admitted
/// without a human in the loop, and the crawl fills forms with inert values.
///
/// Words are matched whole, not as substrings — `payload` is not `pay`,
/// `deleted-items` is not `delete` — split on anything that is not a letter
/// or digit and at a camelCase boundary (`removeUser`, `confirmPassword`),
/// case-insensitively.
fn looks_destructive(action_path: &str, field_names: &[&str]) -> bool {
    action_path
        .split('/')
        .chain(field_names.iter().copied())
        .flat_map(words)
        .any(|word| DESTRUCTIVE_WORDS.contains(&word.as_str()))
}

/// The lowercase words of one path segment or field name: split on anything
/// that is not alphanumeric and at a lower-to-upper camelCase boundary.
fn words(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in text.chars() {
        if c.is_alphanumeric() {
            if c.is_uppercase() && previous_lower && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            current.extend(c.to_lowercase());
            previous_lower = c.is_lowercase();
        } else {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            previous_lower = false;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// One opening tag: its lowercase name, its attributes, and the index just
/// past its `>`.
struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
    end: usize,
}

impl Tag {
    /// The first value of `wanted`, matched whole and case-insensitively, so
    /// `data-href` is not `href`.
    fn attr(&self, wanted: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_str())
    }
}

/// The next opening tag at or after `from`, skipping comments and anything
/// that is not markup.
fn next_tag(html: &str, from: usize) -> Option<Tag> {
    let bytes = html.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // A comment is not markup: a commented-out anchor is not a link.
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map_or(bytes.len(), |off| i + off + 3);
            continue;
        }
        let name_start = i + 1;
        let mut j = name_start;
        while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if j == name_start {
            i += 1;
            continue;
        }
        let (attrs, end) = attributes(html, j);
        return Some(Tag {
            name: html[name_start..j].to_ascii_lowercase(),
            attrs,
            end,
        });
    }
    None
}

/// Walk the attributes of the tag whose name ends at `from`, returning them
/// and the index just past the tag's `>`.
fn attributes(html: &str, from: usize) -> (Vec<(String, String)>, usize) {
    let bytes = html.as_bytes();
    let mut attrs: Vec<(String, String)> = Vec::new();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            return (attrs, i + 1);
        }
        if bytes[i].is_ascii_whitespace() || bytes[i] == b'/' {
            i += 1;
            continue;
        }
        // An attribute name runs to whitespace, `=`, `/` or `>`.
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'>')
        {
            i += 1;
        }
        if i == name_start {
            // A stray `=` with no name: step over it rather than spin.
            i += 1;
            continue;
        }
        let name = html[name_start..i].to_ascii_lowercase();
        let mut k = i;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return (attrs, bytes.len());
        }
        if bytes[k] != b'=' {
            // A valueless attribute; `i` already points past its name.
            push_attr(&mut attrs, name, String::new());
            continue;
        }
        k += 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() {
            return (attrs, bytes.len());
        }
        let (value, next) = match bytes[k] {
            quote @ (b'"' | b'\'') => {
                let start = k + 1;
                match html[start..].find(quote as char) {
                    Some(len) => (&html[start..start + len], start + len + 1),
                    None => return (attrs, bytes.len()),
                }
            }
            b'>' => {
                i = k;
                continue;
            }
            _ => {
                let start = k;
                let len = html[start..]
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(html.len() - start);
                (&html[start..start + len], start + len)
            }
        };
        push_attr(&mut attrs, name, crate::util::decode_entities(value));
        i = next;
    }
    (attrs, bytes.len())
}

/// Keep the first value of each name, up to [`MAX_ATTRS`] per tag.
fn push_attr(attrs: &mut Vec<(String, String)>, name: String, value: String) {
    if attrs.len() >= MAX_ATTRS || attrs.iter().any(|(have, _)| *have == name) {
        return;
    }
    attrs.push((name, value));
}

/// The index of the `<` of the next `<tag` opening tag at or after `from`,
/// matched case-insensitively and whole (`<formal` is not `<form`).
fn find_open_tag(html: &str, tag: &str, from: usize) -> Option<usize> {
    let from = from.min(html.len());
    let hay = &html.as_bytes()[from..];
    let tag = tag.as_bytes();
    let needle_len = tag.len() + 1;
    if hay.len() < needle_len {
        return None;
    }
    (0..=hay.len() - needle_len)
        .find(|&i| {
            hay[i] == b'<'
                && hay[i + 1..i + needle_len].eq_ignore_ascii_case(tag)
                && !hay
                    .get(i + needle_len)
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        .map(|i| from + i)
}

#[cfg(test)]
mod tests {
    use super::*;

    use url::Url;

    fn base() -> Url {
        Url::parse("http://target.test/").expect("a base URL")
    }

    /// `(method, url, body)` for every navigation, in document order.
    fn shape(navs: &[Navigation]) -> Vec<(&str, &str, Option<&str>)> {
        navs.iter()
            .map(|n| (n.method.as_str(), n.url.as_str(), n.body.as_deref()))
            .collect()
    }

    const PAGE: &str = concat!(
        "<html><body>",
        "<a href=\"/search?q=x\">search</a>",
        "<a href=\"sub/page\">relative</a>",
        "<a href=\"#top\">fragment</a>",
        "<a href=\"http://elsewhere.test/evil\">off origin</a>",
        "<a href=\"/logout\">log out</a>",
        "<img src=\"/img/logo.png\">",
        "<form action=\"/find\" method=\"get\">",
        "<input name=\"term\"><input type=\"submit\" value=\"go\"></form>",
        "<form action=\"/comments\" method=\"post\">",
        "<input name=\"comment\"><input type=\"hidden\" name=\"csrf\" value=\"t0ken\">",
        "</form>",
        "<form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">",
        "<input name=\"file\" type=\"file\"></form>",
        "<script>var hidden = \"/not-a-link\";</script>",
        "</body></html>",
    );

    /// Spec D5: the client crawl reaches what the page links to — anchors,
    /// `src` fetches and forms — resolved against the page and never off the
    /// origin.
    #[test]
    fn links_src_and_forms_become_same_origin_navigations() {
        let navs = navigations(&base(), PAGE, true);

        assert_eq!(
            shape(&navs),
            vec![
                ("GET", "http://target.test/search?q=x", None),
                ("GET", "http://target.test/sub/page", None),
                ("GET", "http://target.test/img/logo.png", None),
                ("GET", "http://target.test/find?term=a", None),
                (
                    "POST",
                    "http://target.test/comments",
                    Some("comment=a&csrf=t0ken")
                ),
            ]
        );
    }

    /// Security review (delta ca852f71..e6bd03bc, 2026-11-01): a map crawl
    /// under agent `auto` admission must not submit a form that looks like
    /// it changes something that matters. A form whose action path or field
    /// name carries a destructive marker is skipped and counted; ordinary
    /// forms are submitted.
    #[test]
    fn destructive_looking_forms_are_skipped_and_counted() {
        let page = concat!(
            "<form action=\"/account/delete\" method=\"post\">",
            "<input name=\"id\" value=\"7\"></form>",
            "<form action=\"/comments\" method=\"post\">",
            "<input name=\"comment\"></form>",
            "<form action=\"/search\"><input name=\"q\"></form>",
            "<form action=\"/settings\" method=\"post\">",
            "<input name=\"old_password\"><input name=\"display\"></form>",
            "<form action=\"/logout\" method=\"post\"></form>",
        );

        let extracted = navigations_counted(&base(), page, true);
        assert_eq!(
            shape(&extracted.navigations),
            vec![
                ("POST", "http://target.test/comments", Some("comment=a")),
                ("GET", "http://target.test/search?q=a", None),
            ]
        );
        assert_eq!(
            extracted.forms_skipped, 3,
            "the delete form, the password form and the logout form"
        );

        // With `submit_forms: false` no form is read, so none is "skipped".
        let off = navigations_counted(&base(), page, false);
        assert!(off.navigations.is_empty());
        assert_eq!(off.forms_skipped, 0);
    }

    /// The destructive heuristic matches whole words (split on `/`, `-`, `_`,
    /// `.` and camelCase), case-insensitively, on the action path and the
    /// field names — not substrings, so `payload` is not `pay`.
    #[test]
    fn looks_destructive_matches_words_not_substrings() {
        assert!(looks_destructive("/account/delete", &[]));
        assert!(looks_destructive("/Account/DELETE", &[]));
        assert!(looks_destructive("/api/removeUser", &[]));
        assert!(looks_destructive("/cart/purchase.php", &[]));
        assert!(looks_destructive("/money/transfer-funds", &[]));
        assert!(looks_destructive("/pay", &[]));
        assert!(looks_destructive("/newsletter/unsubscribe", &[]));
        assert!(looks_destructive("/order/confirm", &[]));
        assert!(looks_destructive("/settings", &["old_password"]));
        assert!(looks_destructive(
            "/settings",
            &["display", "confirmPassword"]
        ));
        assert!(looks_destructive("/things", &["destroy"]));

        assert!(!looks_destructive("/comments", &["comment"]));
        assert!(!looks_destructive("/search", &["q"]));
        assert!(!looks_destructive("/upload", &["payload"]));
        assert!(
            !looks_destructive("/payments-history", &[]),
            "payments is not pay"
        );
        assert!(
            !looks_destructive("/deleted-items", &[]),
            "deleted is not delete"
        );
        assert!(!looks_destructive("/", &[]));
    }

    /// A relative link resolves against the page it was found on, not the
    /// origin root.
    #[test]
    fn a_relative_link_resolves_against_the_page() {
        let page = Url::parse("http://target.test/docs/intro").expect("a page URL");

        let navs = navigations(&page, "<a href=\"next\">next</a>", true);

        assert_eq!(
            shape(&navs),
            vec![("GET", "http://target.test/docs/next", None)]
        );
    }

    /// `submit_forms: false` leaves the links and drops the forms.
    #[test]
    fn forms_are_skipped_when_submit_forms_is_off() {
        let navs = navigations(&base(), PAGE, false);

        assert_eq!(
            shape(&navs),
            vec![
                ("GET", "http://target.test/search?q=x", None),
                ("GET", "http://target.test/sub/page", None),
                ("GET", "http://target.test/img/logo.png", None),
            ]
        );
    }

    /// A `<script src>` is a fetch the page makes; the script's *text* is not
    /// markup, so a URL inside it is not a navigation.
    #[test]
    fn a_script_src_is_a_navigation_but_its_text_is_not() {
        let navs = navigations(
            &base(),
            "<script src=\"/app.js\">var u = \"/from-script\";</script>\
             <a href=\"/after\">after</a>",
            true,
        );

        assert_eq!(
            shape(&navs),
            vec![
                ("GET", "http://target.test/app.js", None),
                ("GET", "http://target.test/after", None),
            ]
        );
    }

    /// A commented-out anchor is not a link, and the same target twice is one
    /// navigation.
    #[test]
    fn comments_are_not_markup_and_duplicates_collapse() {
        let navs = navigations(
            &base(),
            "<!-- <a href=\"/commented\">no</a> -->\
             <a href=\"/twice\">1</a><a href=\"/twice\">2</a>",
            true,
        );

        assert_eq!(
            shape(&navs),
            vec![("GET", "http://target.test/twice", None)]
        );
    }

    /// A form with no `action` posts back to the page it is on, and a `select`
    /// or `textarea` carries an inert value like an `input` does.
    #[test]
    fn a_form_without_an_action_submits_to_its_own_page() {
        let page = Url::parse("http://target.test/account?tab=overview").expect("a page URL");

        let navs = navigations(
            &page,
            "<form method=\"post\"><textarea name=\"bio\"></textarea>\
             <select name=\"lang\"><option value=\"en\">en</option></select>\
             <input name=\"age\" type=\"number\"></form>",
            true,
        );

        assert_eq!(
            shape(&navs),
            vec![(
                "POST",
                "http://target.test/account?tab=overview",
                Some("bio=a&lang=a&age=1")
            )]
        );
    }

    /// Nothing that is not an `http(s)` URL on the page's own origin is a
    /// navigation: another scheme, another origin, a credentialed URL, and the
    /// page itself behind a fragment are all dropped.
    #[test]
    fn only_same_origin_http_urls_survive() {
        let navs = navigations(
            &base(),
            "<a href=\"javascript:alert(1)\">js</a>\
             <a href=\"mailto:a@b.test\">mail</a>\
             <a href=\"https://target.test/tls\">other scheme</a>\
             <a href=\"http://user:pw@target.test/creds\">creds</a>\
             <a href=\"//elsewhere.test/proto-relative\">protocol relative</a>\
             <a href=\"/#top\">self</a>\
             <a href=\"/ok\">ok</a>",
            true,
        );

        assert_eq!(shape(&navs), vec![("GET", "http://target.test/ok", None)]);
    }

    /// A page that links a thousand times costs the crawl a bounded frontier.
    #[test]
    fn a_page_cannot_contribute_more_than_the_per_page_cap() {
        let html: String = (0..MAX_LINKS_PER_PAGE * 2)
            .map(|i| format!("<a href=\"/p{i}\">p</a>"))
            .collect();

        assert_eq!(navigations(&base(), &html, true).len(), MAX_LINKS_PER_PAGE);
    }

    /// Security review (whole branch, 2026-11-01): forms do not nest, so a
    /// form's fields end at the next `<form` as well as at `</form>`. An
    /// unclosed form must not swallow the next form's controls — and a hostile
    /// page must not make every form re-scan the rest of the document.
    #[test]
    fn nested_or_unclosed_forms_end_at_the_next_form_tag() {
        let navs = navigations(
            &base(),
            "<form action=\"/a\"><input name=\"x\">\
             <form action=\"/b\"><input name=\"y\"></form>\
             <form action=\"/c\"><input name=\"z\">",
            true,
        );

        assert_eq!(
            shape(&navs),
            vec![
                ("GET", "http://target.test/a?x=a", None),
                ("GET", "http://target.test/b?y=a", None),
                ("GET", "http://target.test/c?z=a", None),
            ]
        );
    }

    /// Security review (whole branch, 2026-11-01): a 2 MiB page made of
    /// nothing but unclosed forms used to cost O(N^2) tag parses — minutes of
    /// CPU on a pinned runtime worker. Extraction is linear in the page and
    /// bounded by [`MAX_TAGS_PER_PAGE`], so it finishes in well under a
    /// second, and the one navigation the forms describe is all that comes
    /// out.
    #[test]
    fn a_two_mebibyte_page_of_unclosed_forms_is_extracted_in_bounded_time() {
        let unit = "<form action=\"/x\"><input name=\"a\">";
        let html: String =
            std::iter::repeat_n(unit, MAX_HTML_BYTES / unit.len() + 1).collect::<String>();
        assert!(
            html.len() >= MAX_HTML_BYTES,
            "the page fills the scanned head"
        );

        // Parse on a helper thread so a regression fails in seconds rather
        // than pinning the test run for the half hour the old code took.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let navs = navigations(&base(), &html, true);
            let _ = tx.send((started.elapsed(), shape(&navs).len(), navs));
        });
        let (elapsed, count, navs) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("extraction finished within 10 s (a regression to quadratic time)");

        eprintln!("2 MiB page of unclosed forms extracted in {elapsed:?}");
        // The regression this guards is quadratic (~30 min on this page); the
        // linear pass takes ~0.1 s in debug on an idle machine and ~1.7 s at a
        // load average near 300 (2026-11-01 gate), so the bound leaves room for
        // a loaded shared machine while still catching the regression by orders
        // of magnitude.
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "a 2 MiB page of unclosed forms took {elapsed:?}"
        );
        assert_eq!(count, 1, "every form is the same navigation");
        assert_eq!(
            shape(&navs),
            vec![("GET", "http://target.test/x?a=a", None)]
        );
    }

    /// The per-page tag budget bounds the work a page can demand: once
    /// [`MAX_TAGS_PER_PAGE`] tags have been parsed, extraction stops, so an
    /// anchor past that point is not reached.
    #[test]
    fn extraction_stops_once_the_tag_budget_is_spent() {
        let mut html: String = "<a href=\"/first\">first</a>".to_string();
        html.extend(std::iter::repeat_n("<b>", MAX_TAGS_PER_PAGE));
        html.push_str("<a href=\"/last\">last</a>");

        assert_eq!(
            shape(&navigations(&base(), &html, true)),
            vec![("GET", "http://target.test/first", None)]
        );
    }

    // ---------------------------------------------- client-crawl failure tests

    mod failures {
        use super::super::*;

        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use aitm_core::{
            Body, BrowserDriver, FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
            HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeRateGuard, SendOptions,
            StdGuard,
        };
        use aitm_scan_model::{CrawlErrorKind, JobCtx, ScanProfile, SessionMaterial};
        use futures::future::BoxFuture;

        /// What the stub answers for one request path (before `?`).
        enum Answer {
            /// A 200 `text/html` page with this body.
            Html(&'static str),
            /// A 200 `text/plain` page.
            Ok,
            /// The send fails with this message.
            Err(&'static str),
        }

        /// A `ProxyClient` keyed on request path: an `Err` answer is a failed
        /// request, anything else a page.
        struct PathClient {
            answers: std::collections::HashMap<&'static str, Answer>,
            default: Answer,
            /// `METHOD path` for every request, in order.
            trail: std::sync::Mutex<Vec<String>>,
        }

        impl PathClient {
            fn new(default: Answer, answers: Vec<(&'static str, Answer)>) -> Arc<Self> {
                Arc::new(Self {
                    answers: answers.into_iter().collect(),
                    default,
                    trail: std::sync::Mutex::new(Vec::new()),
                })
            }

            fn trail(&self) -> Vec<String> {
                self.trail.lock().unwrap_or_else(|e| e.into_inner()).clone()
            }
        }

        fn conn() -> aitm_core::ConnInfo {
            aitm_core::ConnInfo {
                peer: "127.0.0.1:0".parse().expect("loopback"),
                sni: None,
                alpn: None,
                tls: false,
                established: std::time::SystemTime::now(),
            }
        }

        impl ProxyClient for PathClient {
            fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
                self.send_opts(req, SendOptions::default())
            }

            fn send_opts(
                &self,
                req: HttpRequest,
                _opts: SendOptions,
            ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
                Box::pin(async move {
                    let path = req.path.split('?').next().unwrap_or("/");
                    self.trail
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(format!("{} {path}", req.method));
                    let answer = self.answers.get(path).unwrap_or(&self.default);
                    let (status, ctype, body) = match answer {
                        Answer::Err(message) => return Err(anyhow::anyhow!(*message)),
                        Answer::Html(body) => (200u16, "text/html; charset=utf-8", *body),
                        Answer::Ok => (200u16, "text/plain", "ok"),
                    };
                    let mut headers = HeaderMap::new();
                    headers.set("content-type", ctype);
                    let response = HttpResponse {
                        status,
                        version: HttpVersion::Http11,
                        headers,
                        trailers: HeaderMap::new(),
                        body: Body::Bytes(body.as_bytes().to_vec()),
                        timestamp: std::time::SystemTime::now(),
                        peer: None,
                    };
                    Ok(HttpFlow {
                        id: aitm_core::FlowId::new(),
                        request: req,
                        response: Some(response),
                        client_conn: conn(),
                        server_conn: None,
                        metadata: aitm_core::FlowMeta::default(),
                        intercept: InterceptState::Observed,
                    })
                })
            }
        }

        /// A minimal `JobCtx` over the stub client: a generous budget, no
        /// session, no browser.
        struct Job {
            profile: ScanProfile,
            client: Arc<dyn ProxyClient>,
            store: Arc<dyn FlowStore>,
            guard: Arc<dyn ScopeRateGuard>,
        }

        impl Job {
            fn new(client: Arc<dyn ProxyClient>) -> Self {
                Self {
                    profile: ScanProfile::default(),
                    client,
                    store: Arc::new(MemFlowStore::new()),
                    guard: Arc::new(StdGuard::default()),
                }
            }
        }

        impl JobCtx for Job {
            fn job_id(&self) -> &str {
                "scan-1a2b3c4d"
            }
            fn profile(&self) -> &ScanProfile {
                &self.profile
            }
            fn client(&self) -> Arc<dyn ProxyClient> {
                Arc::clone(&self.client)
            }
            fn store(&self) -> Arc<dyn FlowStore> {
                Arc::clone(&self.store)
            }
            fn guard(&self) -> Arc<dyn ScopeRateGuard> {
                Arc::clone(&self.guard)
            }
            fn browser(&self) -> Option<Arc<dyn BrowserDriver>> {
                None
            }
            fn session(&self) -> Option<Arc<SessionMaterial>> {
                None
            }
            fn charge(&self, _units: u32) -> bool {
                true
            }
            fn budget_left(&self) -> u32 {
                1000
            }
            fn deadline(&self) -> Instant {
                Instant::now() + Duration::from_secs(60)
            }
            fn cancelled(&self) -> bool {
                false
            }
            fn marker(&self) -> String {
                "aitm7f3a0000".to_string()
            }
        }

        /// Amendment 39, call C4, amendment 68: the classifier maps a failure
        /// onto exactly one closed token, in the documented order — the
        /// forced-h2 marker first (it is amendment 21's counted probe error),
        /// then a typed per-probe timeout, then TLS, then connect, with
        /// `transport` as the catch-all. TLS is tested before connect because
        /// a TLS chain names the connection it was failing on ("error
        /// connecting: tls handshake failed"), and the connect arm names the
        /// refused shapes only, so "connection reset" is `transport`.
        /// Nothing here is a heuristic over a free-text reason: the token is
        /// what reaches `crawl.last_error`, so a wrong mapping is a wrong
        /// reason on the operator's status.
        #[test]
        fn classify_maps_each_failure_to_its_kind() {
            assert_eq!(
                classify(&anyhow::anyhow!("h2_not_negotiated: scan.test:80: alpn")),
                CrawlErrorKind::H2NotNegotiated
            );
            assert_eq!(
                classify(&anyhow::Error::new(ProbeRefused::Timeout {
                    host: "scan.test:80".to_string(),
                    after: Duration::from_secs(30),
                })),
                CrawlErrorKind::Timeout,
                "a typed per-probe timeout is `timeout`, not the text it prints"
            );
            for tls in [
                "TLS handshake failure",
                "the certificate is not trusted",
                "handshake eof",
            ] {
                assert_eq!(
                    classify(&anyhow::anyhow!(tls)),
                    CrawlErrorKind::Tls,
                    "{tls:?} is a TLS failure"
                );
            }
            assert_eq!(
                classify(&anyhow::anyhow!(
                    "error connecting to scan.test:443: tls handshake failed"
                )),
                CrawlErrorKind::Tls,
                "a TLS chain that names the connection it failed on is `tls`, \
                 not `connect_refused`"
            );
            assert_eq!(
                classify(&anyhow::anyhow!(
                    "tcp connect to scan.test:80: connection refused"
                )),
                CrawlErrorKind::ConnectRefused
            );
            assert_eq!(
                classify(&anyhow::anyhow!("connection reset by peer")),
                CrawlErrorKind::Transport,
                "a reset connection is `transport`: the connect arm is the \
                 refused shapes, not every word starting `connect`"
            );
            assert_eq!(
                classify(&anyhow::anyhow!("stream reset by peer")),
                CrawlErrorKind::Transport,
                "an unrecognised failure is `transport`, never `other`"
            );
            assert_eq!(
                classify(&anyhow::anyhow!("")),
                CrawlErrorKind::Transport,
                "an error with no message still classifies"
            );

            // The whole cause chain is read, not only the outermost error, and
            // the match is case-insensitive: a wrapped reason still classifies.
            let wrapped = anyhow::anyhow!("connection refused").context("fetching /a");
            assert_eq!(classify(&wrapped), CrawlErrorKind::ConnectRefused);
            assert_eq!(
                classify(&anyhow::anyhow!("H2_NOT_NEGOTIATED")),
                CrawlErrorKind::H2NotNegotiated
            );

            // Every token the classifier can produce is one the model parses
            // back, so the lane -> `report_crawl_error` -> worker round trip
            // never degrades a classified failure to `other`.
            for kind in [
                CrawlErrorKind::H2NotNegotiated,
                CrawlErrorKind::Timeout,
                CrawlErrorKind::ConnectRefused,
                CrawlErrorKind::Tls,
                CrawlErrorKind::Transport,
            ] {
                assert_eq!(CrawlErrorKind::parse(kind.as_str()), Some(kind));
            }
        }

        /// Amendment 39: every failed client-crawl request is counted in
        /// `failed` and classified, and `last_error` names the most recent
        /// cause. An all-failing crawl fetches no page; a crawl that lost one
        /// of three links keeps the two pages it reached.
        #[tokio::test]
        async fn every_failed_request_is_counted_and_classified() {
            // Every send fails: only the seed is attempted, nothing is found.
            let client = PathClient::new(
                Answer::Err("h2_not_negotiated: scan.test:80: alpn"),
                Vec::new(),
            );
            let job = Job::new(client);
            let crawled = crawl_with_client("http://scan.test", &job).await;
            assert_eq!(crawled.pages, 0);
            assert_eq!(crawled.failed, 1, "the seed is the one failed request");
            assert_eq!(crawled.last_error, Some(CrawlErrorKind::H2NotNegotiated));

            // The seed is a page with two links; one link's send fails.
            let seed = concat!(
                "<html><body>",
                "<a href=\"/a\">a</a>",
                "<a href=\"/b\">b</a>",
                "</body></html>",
            );
            let client = PathClient::new(
                Answer::Ok,
                vec![
                    ("/", Answer::Html(seed)),
                    ("/a", Answer::Err("connection refused")),
                    ("/b", Answer::Ok),
                ],
            );
            let job = Job::new(client);
            let crawled = crawl_with_client("http://scan.test", &job).await;
            assert_eq!(crawled.pages, 2, "the seed and the reachable link");
            assert_eq!(crawled.failed, 1, "exactly the refused link");
            assert_eq!(crawled.last_error, Some(CrawlErrorKind::ConnectRefused));
        }

        /// Amendment 53: `forms_submitted` is the number of forms the crawl
        /// actually sent — the POSTs on the wire — and nothing else: the
        /// logout-looking and destructive-looking forms it refused are
        /// `forms_skipped`, a link is a page, and a form whose send failed
        /// was not submitted.
        #[tokio::test]
        async fn submitted_forms_are_counted() {
            let seed = concat!(
                "<html><body>",
                "<a href=\"/about\">about</a>",
                "<form action=\"/comments\" method=\"post\"><input name=\"comment\"></form>",
                "<form action=\"/notes\" method=\"post\"><input name=\"note\"></form>",
                "<form action=\"/account/delete\" method=\"post\"><input name=\"id\"></form>",
                "<form action=\"/logout\" method=\"post\"></form>",
                "<form action=\"/broken\" method=\"post\"><input name=\"x\"></form>",
                "</body></html>",
            );
            let client = PathClient::new(
                Answer::Ok,
                vec![
                    ("/", Answer::Html(seed)),
                    ("/broken", Answer::Err("connection refused")),
                ],
            );
            let job = Job::new(Arc::clone(&client) as Arc<dyn ProxyClient>);
            let crawled = crawl_with_client("http://scan.test", &job).await;

            let posts_sent = client
                .trail()
                .iter()
                .filter(|line| line.starts_with("POST "))
                .count();
            assert_eq!(
                client.trail(),
                vec![
                    "GET /",
                    "GET /about",
                    "POST /comments",
                    "POST /notes",
                    "POST /broken",
                ],
                "the two skipped forms never reach the wire"
            );
            assert_eq!(posts_sent, 3, "three POSTs went out, one of them failed");
            assert_eq!(
                crawled.forms_submitted, 2,
                "the POSTs that were answered: {crawled:?}"
            );
            assert_eq!(crawled.forms_skipped, 2, "delete + logout");
            assert_eq!(crawled.failed, 1, "the broken form's send");
            assert_eq!(crawled.pages, 4, "seed, about, comments, notes");
        }
    }
}
