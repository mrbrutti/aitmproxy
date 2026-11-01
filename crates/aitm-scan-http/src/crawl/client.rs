//! `ClientCrawler`: the HTTP-client crawl engine (task 17).
//!
//! The engine the lane picks when `use_browser` is `never` (or no browser is
//! available): it walks the same [`Frontier`] under the same [`Limits`] as the
//! browser engine, but every page is one `GET` through the job's own client
//! instead of a navigation, so a crawl costs no browser and no process
//! (spec **D8.1**, client engine).
//!
//! Three rules a reviewer should be able to check at a glance:
//!
//! - **Scope.** A URL is fetched only when it is same-origin with the crawl
//!   origin *and* its `host:port` is in the job's scope. An off-origin link and
//!   an off-origin `3xx` `Location` are dropped, not followed (call **A13**:
//!   unlike the browser engine, the client crawl does not stop for one — it
//!   never went anywhere).
//! - **Budget.** Every send this engine makes — a page fetch and a form
//!   submission alike — counts one attempt and is refused once `max_pages`
//!   attempts are spent, so `max_pages` is a true ceiling on the traffic a
//!   crawl produces. Crawl sends are *not* charged with [`JobCtx::charge`]:
//!   the engine's own `JobClient` charges every `send_opts` (spec **D5**), and
//!   charging here would double-count.
//! - **Records and marks.** Every send goes out with
//!   [`RecordPolicy::Always`] and the marks `scan:<job>` and `crawl`
//!   (call **A2**), so the points found on a crawled page always have a stored
//!   source flow to re-probe and the UI can list a node's flows.
//!
//! Nothing here logs a header, a cookie or a body, and every URL that reaches
//! a line goes through [`redact::safe_url`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use futures::future::BoxFuture;
use url::Url;

use aitm_core::{
    Body, HeaderMap, HttpFlow, HttpRequest, HttpVersion, RecordPolicy, ScopeRateGuard, SendOptions,
};
use aitm_scan_model::JobCtx;

use crate::crawl::extract::{extract, FieldKind, FormSpec};
use crate::crawl::frontier::{fingerprint, remaining, CrawlReport, Crawler, Frontier, Limits};
use crate::crawl::values::{form_action, form_pairs_for};
use crate::limits::{MARK_CRAWL, MAX_DOM_BYTES, MAX_HELD_CRAWL_BODY, USER_AGENT};
use crate::url_norm::{guard_authority, origin_key, resolve, same_origin};
use crate::{multipart, params, redact, session};

/// What the crawler says it accepts; a target that content-negotiates answers
/// the HTML the crawler can actually read (call **A13**).
const ACCEPT: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

/// The crawl engine that fetches pages with the job's HTTP client.
pub(crate) struct ClientCrawler;

impl Crawler for ClientCrawler {
    fn crawl<'a>(
        &'a self,
        origin: &'a Url,
        seeds: Vec<Url>,
        job: &'a dyn JobCtx,
        limits: &'a Limits,
    ) -> BoxFuture<'a, Result<CrawlReport>> {
        Box::pin(async move {
            let mut run = Run::new(origin, job, limits);
            // The caller seeds the frontier, the origin root first (`lane.rs`
            // builds that list from the root plus `robots.txt`/`sitemap.xml`).
            for seed in seeds {
                run.frontier.push(seed, 0, limits);
            }
            run.walk().await;
            Ok(run.finish())
        })
    }
}

/// One form submission the crawler has built and not yet sent.
struct Submission {
    /// The request, session not yet applied.
    request: HttpRequest,
    /// Where it goes, for resolution and logging.
    url: Url,
    /// The depth its response is processed at.
    depth: u32,
}

/// The mutable state of one client crawl.
struct Run<'a> {
    origin: &'a Url,
    job: &'a dyn JobCtx,
    limits: &'a Limits,
    guard: Arc<dyn ScopeRateGuard>,
    /// `scheme://host[:port]`, the value inert form fields of `url` kind take.
    origin_text: String,
    /// The job's marker, woven into every value the crawler submits.
    marker: String,
    /// The options every send of this crawl goes out with (call **A2**).
    send: SendOptions,
    frontier: Frontier,
    /// Form submissions queued by a page already processed.
    pending: VecDeque<Submission>,
    /// Sends that produced no response, for the `navigation_failed` fallback.
    failures: u32,
    report: CrawlReport,
}

impl<'a> Run<'a> {
    fn new(origin: &'a Url, job: &'a dyn JobCtx, limits: &'a Limits) -> Self {
        Self {
            origin,
            job,
            limits,
            guard: job.guard(),
            origin_text: origin_key(origin),
            marker: job.marker(),
            send: SendOptions {
                record: RecordPolicy::Always,
                marks: vec![format!("scan:{}", job.job_id()), MARK_CRAWL.to_string()],
                version: job.profile().http.version.into(),
            },
            frontier: Frontier::new(),
            pending: VecDeque::new(),
            failures: 0,
            report: CrawlReport::default(),
        }
    }

    /// Fetch until a stop reason applies or there is nothing left to fetch.
    ///
    /// Queued form submissions are taken before the next page so a submission
    /// is sent while the page that produced it is still the newest thing the
    /// target saw.
    async fn walk(&mut self) {
        loop {
            if self.job.cancelled() {
                self.report.stopped_reason = Some("cancelled");
                return;
            }
            let Some(left) = remaining(self.job) else {
                self.report.stopped_reason = Some("time");
                return;
            };
            if self.frontier.attempts >= self.limits.max_pages {
                self.report.stopped_reason = Some("max_pages");
                return;
            }

            if let Some(submission) = self.pending.pop_front() {
                self.frontier.attempts = self.frontier.attempts.saturating_add(1);
                self.report.forms_submitted = self.report.forms_submitted.saturating_add(1);
                if let Some(flow) = self.send(submission.request, &submission.url, left).await {
                    self.absorb(flow, &submission.url, submission.depth);
                }
                continue;
            }

            let Some((url, depth)) = self.frontier.pop() else {
                return;
            };
            self.frontier.attempts = self.frontier.attempts.saturating_add(1);
            if !self.may_visit(&url) {
                tracing::debug!(
                    job = %self.job.job_id(),
                    page = %redact::safe_url(url.as_str()),
                    "scan: crawl: skipped a queued URL that is no longer in scope"
                );
                continue;
            }
            let Some(request) = get_request(&url) else {
                continue;
            };
            if let Some(flow) = self.send(request, &url, left).await {
                self.absorb(flow, &url, depth);
            }
        }
    }

    /// Send `request` with the session applied, bounded by `left`.
    ///
    /// A transport error and a timeout are the same thing here: one page the
    /// crawl did not get. The client's error text is never logged — it can
    /// carry the request it failed on.
    async fn send(
        &mut self,
        mut request: HttpRequest,
        url: &Url,
        left: Duration,
    ) -> Option<HttpFlow> {
        if let Some(material) = self.job.session() {
            session::apply_session(&mut request, &material);
        }
        let client = self.job.client();
        match tokio::time::timeout(left, client.send_opts(request, self.send.clone())).await {
            Ok(Ok(flow)) => Some(flow),
            Ok(Err(_)) | Err(_) => {
                self.failures = self.failures.saturating_add(1);
                tracing::debug!(
                    job = %self.job.job_id(),
                    page = %redact::safe_url(url.as_str()),
                    "scan: crawl: fetch failed"
                );
                None
            }
        }
    }

    /// Read everything the crawl wants out of one response and queue the work
    /// it implies: the flow itself, a same-origin redirect, the page's links
    /// and its forms.
    fn absorb(&mut self, flow: HttpFlow, page: &Url, depth: u32) {
        let digest = Digest::of(&flow);
        self.report.flows.push(held(flow));
        let Some(digest) = digest else {
            self.failures = self.failures.saturating_add(1);
            return;
        };

        if (200..400).contains(&digest.status) {
            self.report.pages = self.report.pages.saturating_add(1);
            self.report.depth_reached = self.report.depth_reached.max(depth);
        }

        if let Some(location) = &digest.location {
            match resolve(page, location) {
                Some(target) if self.may_visit(&target) => {
                    self.frontier
                        .push(target, depth.saturating_add(1), self.limits);
                }
                // A redirect off the origin is dropped and the crawl goes on:
                // nothing was fetched there (call A13).
                _ => tracing::debug!(
                    job = %self.job.job_id(),
                    page = %redact::safe_url(page.as_str()),
                    "scan: crawl: redirect target is out of scope or unusable"
                ),
            }
        }

        let Some(html) = digest.html else {
            return;
        };
        // A page whose normalised body was seen already is counted but not
        // mined again: two URLs rendering the same list, or one page whose
        // only difference is a timestamp, must not re-queue their links.
        if !self.frontier.note_fingerprint(fingerprint(&html)) {
            return;
        }

        let extracted = extract(&html);
        let base = extracted
            .base
            .as_deref()
            .and_then(|href| resolve(page, href))
            .unwrap_or_else(|| page.clone());

        let mut hrefs: Vec<&String> = extracted.links.iter().collect();
        if self.limits.follow_resources {
            hrefs.extend(extracted.resources.iter());
        }
        for href in hrefs {
            if let Some(target) = resolve(&base, href) {
                if self.may_visit(&target) {
                    self.frontier
                        .push(target, depth.saturating_add(1), self.limits);
                }
            }
        }

        if self.limits.submit_forms {
            self.queue_forms(&extracted.forms, page, extracted.base.as_deref(), depth);
        }
    }

    /// Queue up to `forms_per_page` submissions for the forms of one page.
    fn queue_forms(&mut self, forms: &[FormSpec], page: &Url, base: Option<&str>, depth: u32) {
        let mut queued = 0u32;
        for form in forms {
            if queued >= self.limits.forms_per_page {
                break;
            }
            // `form_action` already refuses a method other than GET/POST and
            // an action that leaves the origin; the guard check is the scope
            // half of the same question.
            let Some(action) = form_action(form, page, self.origin, base) else {
                continue;
            };
            if !self.may_visit(&action) {
                continue;
            }
            let pairs = form_pairs_for(form, &self.marker, &self.origin_text);
            let Some(submission) =
                submission_for(form, action, &pairs, &self.marker, depth.saturating_add(1))
            else {
                continue;
            };
            self.pending.push_back(submission);
            queued = queued.saturating_add(1);
        }
    }

    /// Whether the crawl may fetch `url`: same origin, and in the job's scope.
    fn may_visit(&self, url: &Url) -> bool {
        same_origin(url, self.origin) && self.guard.in_scope(&guard_authority(url))
    }

    /// The finished report, with the counters the frontier owns copied in and
    /// the stop reason a quiet end implies.
    fn finish(mut self) -> CrawlReport {
        self.report.attempts = self.frontier.attempts;
        if self.report.stopped_reason.is_none() {
            if self.frontier.depth_hit {
                self.report.stopped_reason = Some("max_depth");
            } else if self.report.pages == 0 && self.failures > 0 {
                self.report.stopped_reason = Some("navigation_failed");
            }
        }
        self.report
    }
}

/// The three things the crawl reads from a response: its status, a redirect
/// target, and the HTML small enough to mine.
struct Digest {
    status: u16,
    location: Option<String>,
    html: Option<String>,
}

impl Digest {
    /// `None` when the flow carries no response at all.
    fn of(flow: &HttpFlow) -> Option<Self> {
        let response = flow.response.as_ref()?;
        let location = if (300..400).contains(&response.status) {
            response.headers.get("location").map(str::to_string)
        } else {
            None
        };
        let html = if is_html(&response.headers) {
            params::body_bytes(&response.body)
                .filter(|bytes| bytes.len() <= MAX_DOM_BYTES)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        } else {
            None
        };
        Some(Self {
            status: response.status,
            location,
            html,
        })
    }
}

/// Whether a response declares itself HTML. Only the two document types the
/// extractor understands count; a `text/plain` body that happens to contain
/// `<a href>` is not a page.
fn is_html(headers: &HeaderMap) -> bool {
    headers.get("content-type").is_some_and(|value| {
        let mime = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        mime == "text/html" || mime == "application/xhtml+xml"
    })
}

/// The flow as the report keeps it: the response body cut to
/// [`MAX_HELD_CRAWL_BODY`] so a crawl of a few hundred large pages cannot grow
/// the job's memory without bound. The stored flow (recorded by the client) is
/// untouched; this copy only feeds the site-map builder.
fn held(mut flow: HttpFlow) -> HttpFlow {
    if let Some(response) = flow.response.as_mut() {
        if let Body::Bytes(bytes) = &mut response.body {
            bytes.truncate(MAX_HELD_CRAWL_BODY);
        }
    }
    flow
}

/// The request one form submission sends.
///
/// A `GET` form replaces the action's query with the serialised pairs, exactly
/// as a browser does. A `POST` form (which is all `form_action` leaves) sends
/// them as a body in the encoding the form asked for: `multipart/form-data`
/// when its `enctype` says so, `application/x-www-form-urlencoded` otherwise.
/// Honouring the `enctype` is what lets an upload endpoint answer the crawl at
/// all — one that validates its parts answers `400` to a urlencoded body and
/// the crawl learns nothing about it (AC T2-1, T2-2).
fn submission_for(
    form: &FormSpec,
    mut action: Url,
    pairs: &[(String, String)],
    marker: &str,
    depth: u32,
) -> Option<Submission> {
    if form.method.trim().eq_ignore_ascii_case("POST") {
        let request = if wants_multipart(form) {
            let (boundary, body) = multipart_body(form, pairs, marker);
            post_request(
                &action,
                &format!("multipart/form-data; boundary={boundary}"),
                &body,
            )?
        } else {
            post_request(
                &action,
                "application/x-www-form-urlencoded",
                params::serialize_form(pairs).as_bytes(),
            )?
        };
        return Some(Submission {
            request,
            url: action,
            depth,
        });
    }
    let encoded = params::serialize_form(pairs);
    action.set_query((!encoded.is_empty()).then_some(encoded.as_str()));
    let request = get_request(&action)?;
    Some(Submission {
        request,
        url: action,
        depth,
    })
}

/// Whether the form asked to be sent as `multipart/form-data`.
///
/// A prefix match, case-insensitively: the extractor already trims and
/// lower-cases the attribute, and a page may legally write the media type with
/// parameters after it.
fn wants_multipart(form: &FormSpec) -> bool {
    form.enctype.as_deref().is_some_and(|enctype| {
        enctype
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("multipart/form-data")
    })
}

/// The `multipart/form-data` body one submission sends, with its boundary.
///
/// One `form-data; name="…"` part per generated pair, in order, then one part
/// per file control: a browser sends a part for every `<input type="file">`,
/// and an endpoint that checks its upload rejects a body that has none, so the
/// crawler sends a small inert text file named after the job marker.
///
/// The boundary is derived from the job marker (`----aitm<marker>`), which is
/// unguessable from the page, so no value the page put in a hidden field can
/// forge a delimiter; a CRLF inside a part's value is ordinary content, not a
/// delimiter, so values are written as they are. Only the quoted `name=` and
/// `filename=` parameters are escaped, by the one escaper the parser's rules
/// are written against.
fn multipart_body(form: &FormSpec, pairs: &[(String, String)], marker: &str) -> (String, Vec<u8>) {
    let boundary = format!("----aitm{marker}");
    let mut body: Vec<u8> = Vec::new();

    for (name, value) in pairs {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                multipart::escape_filename(name)
            )
            .as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    for field in form
        .fields
        .iter()
        .filter(|field| matches!(field.kind, FieldKind::File))
    {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"; filename=\"aitm-{marker}.txt\"\r\n\
                 Content-Type: text/plain\r\n\r\n",
                multipart::escape_filename(&field.name)
            )
            .as_bytes(),
        );
        body.extend_from_slice(format!("aitm-{marker}").as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// A crawl `GET` for `url`: no body, the crawler's own `Accept` and
/// `User-Agent`, `Host` from the URL's own authority. `None` when the URL has
/// no host, which [`resolve`] already refuses.
fn get_request(url: &Url) -> Option<HttpRequest> {
    let (authority, path) = parts(url)?;
    let headers = base_headers(&authority);
    Some(HttpRequest {
        method: "GET".to_string(),
        scheme: url.scheme().to_string(),
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body: Body::Empty,
        timestamp: SystemTime::now(),
    })
}

/// A crawl form `POST` of `body` to `url`, framed by `content_type` and its
/// own length.
fn post_request(url: &Url, content_type: &str, body: &[u8]) -> Option<HttpRequest> {
    let (authority, path) = parts(url)?;
    let mut headers = base_headers(&authority);
    headers.set("content-type", content_type);
    headers.set("content-length", &body.len().to_string());
    Some(HttpRequest {
        method: "POST".to_string(),
        scheme: url.scheme().to_string(),
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body: Body::Bytes(body.to_vec()),
        timestamp: SystemTime::now(),
    })
}

/// A URL's `host[:port]` and its request target (`path` with the query).
fn parts(url: &Url) -> Option<(String, String)> {
    let host = url.host_str()?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    Some((authority, path))
}

/// The headers every crawl request carries.
fn base_headers(authority: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.set("host", authority);
    headers.set("accept", ACCEPT);
    headers.set("user-agent", USER_AGENT);
    headers
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use aitm_core::{FlowStore, MemFlowStore, RecordPolicy};
    use aitm_scan_model::{CrawlStrategy, ScanProfile, SessionMaterial, UseBrowser};

    use crate::crawl::frontier::limits_for;
    use crate::testutil::{site, FakeJob, JOB_ID};
    use crate::url_norm::parse_absolute;

    /// The origin every test crawls; `t:8080` is the host [`FakeJob`] scopes.
    const ORIGIN: &str = "http://t:8080/";

    /// The plan's fixture site: links on `/` and `/a`, one off-origin link, one
    /// `GET` form, one redirect, and plain leaves.
    fn fixture_pages() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "/",
                concat!(
                    r#"<a href="/a">a</a><a href="/b#top">b</a>"#,
                    r#"<a href="https://evil.test/x">ext</a>"#,
                    r#"<form action="/search" method="get"><input name="q">"#,
                    r#"<input type="submit"></form>"#,
                ),
            ),
            (
                "/a",
                concat!(
                    r#"<a href="/c?x=1">c</a><a href="/account/1">one</a>"#,
                    r#"<a href="/account/2">two</a>"#,
                ),
            ),
            ("/c", "302:/d"),
            ("/d", "<p>the d leaf</p>"),
            ("/b", "<p>the b leaf</p>"),
            ("/account/1", "<p>first account</p>"),
            ("/account/2", "<p>second account</p>"),
            ("/search", "<p>search results</p>"),
        ]
    }

    /// A profile with the client engine selected and `crawl` tuned by `tune`.
    fn profile(tune: impl FnOnce(&mut ScanProfile)) -> ScanProfile {
        let mut profile = ScanProfile::default();
        profile.crawl.use_browser = UseBrowser::Never;
        tune(&mut profile);
        profile
    }

    fn origin() -> Url {
        parse_absolute(ORIGIN).expect("the test origin is absolute")
    }

    /// Crawl `job` from the origin root and hand back the report.
    async fn crawl(job: &FakeJob) -> CrawlReport {
        let limits = limits_for(&job.profile.crawl);
        ClientCrawler
            .crawl(&origin(), vec![origin()], job, &limits)
            .await
            .expect("the client crawl answers a report")
    }

    #[tokio::test]
    async fn client_crawl_reaches_links_and_forms() {
        let store = Arc::new(MemFlowStore::new());
        let client = Arc::new(
            site(&fixture_pages()).recording_into(Arc::clone(&store) as Arc<dyn FlowStore>),
        );
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client)).with_store(Arc::clone(&store));

        let report = crawl(&job).await;

        let sent: BTreeSet<String> = client.sent_paths().into_iter().collect();
        assert_eq!(
            sent,
            [
                "/",
                "/a",
                "/b",
                "/c?x=1",
                "/d",
                "/account/1",
                "/account/2",
                "/search?q=aitm-aitm7f3a",
            ]
            .iter()
            .map(|path| (*path).to_string())
            .collect::<BTreeSet<String>>()
        );
        assert_eq!(report.pages, 8);
        assert_eq!(report.forms_submitted, 1);
        assert_eq!(report.flows.len(), 8);
        assert_eq!(store.count(), 8);
        assert_eq!(report.stopped_reason, None);

        for (_, opts) in client.sent.lock().unwrap().iter() {
            assert_eq!(opts.record, RecordPolicy::Always);
        }
        for marks in client.sent_marks() {
            assert_eq!(marks, vec![format!("scan:{JOB_ID}"), "crawl".to_string()]);
        }
    }

    #[tokio::test]
    async fn max_pages_is_attempts() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(profile(|p| p.crawl.max_pages = 2), Arc::clone(&client));

        let report = crawl(&job).await;

        assert_eq!(report.attempts, 2);
        assert_eq!(report.stopped_reason, Some("max_pages"));
    }

    #[tokio::test]
    async fn fast_limits_stop_at_depth_one() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| p.crawl.strategy = CrawlStrategy::Fast),
            Arc::clone(&client),
        );

        let report = crawl(&job).await;

        assert!(
            !client.sent_paths().iter().any(|path| path == "/c?x=1"),
            "depth 2 is past the fast limit: {:?}",
            client.sent_paths()
        );
        assert_eq!(report.forms_submitted, 0);
        assert_eq!(report.stopped_reason, Some("max_depth"));
    }

    #[tokio::test]
    async fn cancelled_stops() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));
        job.cancel();

        let report = crawl(&job).await;

        assert_eq!(client.sent.lock().unwrap().len(), 0);
        assert_eq!(report.stopped_reason, Some("cancelled"));
    }

    #[tokio::test]
    async fn session_on_every_request() {
        let client = Arc::new(site(&fixture_pages()));
        let job =
            FakeJob::new(profile(|_| {}), Arc::clone(&client)).with_session(SessionMaterial {
                cookies: vec![("sid".to_string(), "S3".to_string())],
                headers: Vec::new(),
            });

        crawl(&job).await;

        let sent = client.sent.lock().unwrap();
        assert_eq!(sent.len(), 8);
        for (req, _) in sent.iter() {
            assert!(
                req.headers
                    .get("cookie")
                    .is_some_and(|value| value.contains("sid=S3")),
                "a crawl request went out without the session cookie"
            );
        }
    }

    #[tokio::test]
    async fn volatile_pages_are_not_reextracted() {
        let client = Arc::new(site(&[
            ("/", r#"<a href="/p1">one</a><a href="/p2">two</a>"#),
            ("/p1", r#"<p>row 1</p><a href="/only-from-p1">more</a>"#),
            ("/p2", r#"<p>row 2</p><a href="/only-from-p2">more</a>"#),
            ("/only-from-p1", "<p>reached</p>"),
            ("/only-from-p2", "<p>reached</p>"),
        ]));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));

        crawl(&job).await;

        let sent = client.sent_paths();
        assert!(sent.iter().any(|path| path == "/only-from-p1"), "{sent:?}");
        assert!(
            !sent.iter().any(|path| path == "/only-from-p2"),
            "the second render of the same page was extracted again: {sent:?}"
        );
    }

    #[tokio::test]
    async fn redirect_off_origin_not_followed() {
        let client = Arc::new(site(&[
            ("/", r#"<a href="/c">c</a>"#),
            ("/c", "302:https://evil.test/"),
        ]));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));

        let report = crawl(&job).await;

        let sent = client.sent.lock().unwrap();
        assert!(
            !sent.iter().any(|(req, _)| req.authority.contains("evil")),
            "the crawl followed a redirect off the origin"
        );
        assert_eq!(sent.len(), 2);
        assert_eq!(report.stopped_reason, None);
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// A body not declared HTML, or one over `MAX_DOM_BYTES`, is counted as a
    /// page but never mined for links, and the report's held copies stay under
    /// `MAX_HELD_CRAWL_BODY`.
    #[tokio::test]
    async fn non_html_and_oversized_bodies_are_not_mined() {
        let huge = format!(
            "{}<a href=\"/from-huge\">x</a>",
            "<p>pad</p>".repeat(MAX_DOM_BYTES / 10 + 1)
        );
        let client = Arc::new(crate::testutil::ScriptedClient::new(
            move |req: &HttpRequest| {
                Ok(match req.path.as_str() {
                    "/" => crate::testutil::response(
                        200,
                        &[("content-type", "text/html")],
                        br#"<a href="/json">j</a><a href="/huge">h</a>"#,
                    ),
                    "/json" => crate::testutil::response(
                        200,
                        &[("content-type", "application/json")],
                        br#"{"html":"<a href=\"/from-json\">x</a>"}"#,
                    ),
                    "/huge" => crate::testutil::response(
                        200,
                        &[("content-type", "text/html")],
                        huge.as_bytes(),
                    ),
                    _ => crate::testutil::response(
                        200,
                        &[("content-type", "text/html")],
                        b"<p>leaf</p>",
                    ),
                })
            },
        ));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));

        let report = crawl(&job).await;

        let sent: BTreeSet<String> = client.sent_paths().into_iter().collect();
        assert_eq!(
            sent,
            ["/", "/json", "/huge"]
                .iter()
                .map(|path| (*path).to_string())
                .collect::<BTreeSet<String>>()
        );
        assert_eq!(report.pages, 3);
        assert_eq!(report.flows.len(), 3);
        for flow in &report.flows {
            if let Some(Body::Bytes(bytes)) = flow.response.as_ref().map(|r| &r.body) {
                assert!(
                    bytes.len() <= MAX_HELD_CRAWL_BODY,
                    "a held body of {} bytes",
                    bytes.len()
                );
            }
        }
    }

    /// A fetch that errors is one page the crawl did not get: the walk goes on
    /// and the report stays clean; only a crawl that loaded nothing at all
    /// reports `navigation_failed`.
    #[tokio::test]
    async fn fetch_errors_are_counted_not_fatal() {
        let client = Arc::new(crate::testutil::ScriptedClient::new(
            |req: &HttpRequest| match req.path.as_str() {
                "/" => Ok(crate::testutil::response(
                    200,
                    &[("content-type", "text/html")],
                    br#"<a href="/a">a</a><a href="/b">b</a>"#,
                )),
                "/a" => Err(anyhow::anyhow!("connection reset")),
                _ => Ok(crate::testutil::response(
                    200,
                    &[("content-type", "text/html")],
                    b"<p>b</p>",
                )),
            },
        ));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));

        let report = crawl(&job).await;

        assert_eq!(client.sent_paths(), vec!["/", "/a", "/b"]);
        assert_eq!(report.pages, 2);
        assert_eq!(report.attempts, 3);
        assert_eq!(report.flows.len(), 2);
        assert_eq!(report.stopped_reason, None);

        let dead = Arc::new(crate::testutil::ScriptedClient::new(|_: &HttpRequest| {
            Err(anyhow::anyhow!("refused"))
        }));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&dead));

        let report = crawl(&job).await;

        assert_eq!(report.pages, 0);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.stopped_reason, Some("navigation_failed"));
    }

    // --- N2: a `multipart/form-data` form is posted as multipart ------------

    /// The Task 4 form, `POST`ed as `multipart/form-data` with a file control
    /// added, beside a plain `POST` form that keeps the urlencoded pin.
    fn enctype_pages() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "/",
                concat!(
                    r#"<form action="/upload" method="post" enctype="multipart/form-data">"#,
                    r#"<input name="q">"#,
                    r#"<select name="s"><option value="a">A</option><option value="b">B</option></select>"#,
                    r#"<input type="hidden" name="h" value="1">"#,
                    r#"<input type="radio" name="r" value="x" checked>"#,
                    r#"<input type="radio" name="r" value="y">"#,
                    r#"<input type="file" name="doc">"#,
                    r#"<input type="submit"></form>"#,
                    r#"<form action="/save" method="post"><input name="q">"#,
                    r#"<input type="submit"></form>"#,
                ),
            ),
            ("/upload", "<p>uploaded</p>"),
            ("/save", "<p>saved</p>"),
        ]
    }

    /// The body bytes of a request the crawler sent.
    fn body_bytes(req: &HttpRequest) -> Vec<u8> {
        match &req.body {
            Body::Bytes(bytes) => bytes.clone(),
            Body::Empty => Vec::new(),
            Body::Streamed(_) => panic!("the crawler never streams a body"),
        }
    }

    /// The one request the crawl sent to `path`.
    fn sent_to(client: &crate::testutil::ScriptedClient, path: &str) -> HttpRequest {
        let sent = client.sent.lock().unwrap();
        let mut found = sent.iter().filter(|(req, _)| req.path == path);
        let (req, _) = found
            .next()
            .unwrap_or_else(|| panic!("nothing sent to {path}"));
        req.clone()
    }

    #[tokio::test]
    async fn multipart_form_is_posted_as_multipart() {
        let client = Arc::new(site(&enctype_pages()));
        let job = FakeJob::new(profile(|_| {}), Arc::clone(&client));

        crawl(&job).await;

        let upload = sent_to(&client, "/upload");
        assert_eq!(upload.method, "POST");
        let boundary = "----aitmaitm7f3a";
        assert_eq!(
            upload.headers.get("content-type"),
            Some(format!("multipart/form-data; boundary={boundary}").as_str())
        );
        let body = body_bytes(&upload);
        assert_eq!(
            upload.headers.get("content-length"),
            Some(body.len().to_string().as_str())
        );

        let parts = crate::multipart::parse(&body, boundary)
            .expect("the lane's own parser reads the body the lane built");
        // `name|filename|content-type|value` per part, `-` for an absent one.
        let shape: Vec<String> = parts
            .iter()
            .map(|part| {
                let dash =
                    |field: &Option<String>| field.clone().unwrap_or_else(|| "-".to_string());
                format!(
                    "{}|{}|{}|{}",
                    dash(&part.name),
                    dash(&part.filename),
                    dash(&part.content_type),
                    String::from_utf8_lossy(&body[part.value_span.clone()])
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                "q|-|-|aitm-aitm7f3a".to_string(),
                "s|-|-|a".to_string(),
                "h|-|-|1".to_string(),
                "r|-|-|x".to_string(),
                "doc|aitm-aitm7f3a.txt|text/plain|aitm-aitm7f3a".to_string(),
            ]
        );

        // A form that does not ask for multipart still posts urlencoded.
        let save = sent_to(&client, "/save");
        assert_eq!(
            save.headers.get("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(body_bytes(&save), b"q=aitm-aitm7f3a".to_vec());
    }
}
