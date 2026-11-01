//! `HttpLane`: the `Lane` implementation and discovery orchestration (task 20).
//!
//! This is the module the binary reaches through: `aitm_scan_http::lane()` hands
//! the engine an [`HttpLane`], and everything the HTTP half of the scanner does
//! for a job starts in one of its three methods (spec **D1**, **D8.1**).
//!
//! [`HttpLane::discover`] runs the same five steps for every origin the profile
//! names, in this order (orchestrator decision 6):
//!
//! 1. **Stored.** Already-captured, non-replay, same-origin HTTP flows become
//!    site-map nodes and insertion points without a single request going out —
//!    the passive pass a proxy can do that a crawler cannot.
//! 2. **Crawl.** When the profile allows one, the browser engine runs if the job
//!    has a browser and `use_browser` is not `never`, else the client engine; a
//!    profile demanding `always` without a browser is warned about and skipped.
//!    Seeds are the origin root, then `robots.txt`/`sitemap.xml`, then the
//!    captured `GET` URLs (call **A19**), so proxied traffic widens the crawl.
//! 3. **Enumerate.** Every stored and every crawled flow goes through
//!    [`enumerate_v2`] under the profile's kinds, ignore rules and cap.
//! 4. **Site map.** Each flow is added to one [`SiteMapBuilder`] shared by every
//!    origin, so the lane returns one merged [`Discovery`].
//! 5. **Totals.** The overflow, ignored and kind-filtered counts are logged once
//!    per origin with the job id (call **A15**); `Discovery` carries no skipped
//!    field, the engine owns `points.skipped.*`.
//!
//! Three rules hold throughout. Every loop polls [`JobCtx::cancelled`] and stops
//! early *with what it has*, because a cancelled job still reports its partial
//! discovery. A bad origin, a refused origin or a failed crawl is a warning and
//! a skip, never an error: `discover` errors only when it could do nothing at
//! all (an uncompilable ignore list). And every URL that reaches a log line or
//! an error goes through [`redact::safe_url`]; no header, cookie or body value
//! is ever named here.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::future::BoxFuture;
use url::Url;

use aitm_core::{Flow, FlowKind, FlowQuery, HttpFlow, RecordPolicy, SendOptions};
use aitm_scan_model::{
    Check, Discovery, InsertionPoint, JobCtx, Lane, LaneKind, ProbeHost, ProfileTarget,
    SessionMaterial, UseBrowser,
};

use crate::crawl::browser::{origin_root, prime_session, BrowserCrawler};
use crate::crawl::client::ClientCrawler;
use crate::crawl::frontier::{limits_for, Crawler};
use crate::crawl::seeds::fetch_seeds;
use crate::host::{HttpProbeHost, SessionMonitors};
use crate::limits::{MARK_CRAWL, MAX_SEED_URLS};
use crate::points::{enumerate_v2, CompiledIgnore, EnumerateOptions};
use crate::redact;
use crate::sitemap::{is_authenticated, SiteMapBuilder};
use crate::url_norm::{guard_authority, parse_absolute, request_url, same_origin};

/// The HTTP half of the scanner (spec **D8.1**).
///
/// Stateless apart from [`SessionMonitors`], the per-job canary registry every
/// probe host of a job shares so that a session loss seen by one probe stops all
/// of them (AC **T2-5**, call **A5**). One instance serves every job the engine
/// runs.
pub(crate) struct HttpLane {
    /// One canary monitor per job, bounded; built on the first
    /// [`Lane::probe_host_for`] of that job.
    monitors: SessionMonitors,
}

impl HttpLane {
    /// A lane with no job monitors yet.
    pub fn new() -> Self {
        Self {
            monitors: SessionMonitors::new(),
        }
    }
}

impl Default for HttpLane {
    fn default() -> Self {
        Self::new()
    }
}

impl Lane for HttpLane {
    fn lane(&self) -> LaneKind {
        LaneKind::Http
    }

    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, Result<Discovery>> {
        Box::pin(async move {
            let profile = job.profile();
            // The one thing that can fail the whole pass: an ignore rule the
            // operator wrote that does not compile.
            let ignore = CompiledIgnore::compile(&profile.audit.ignore)?;
            let session = job.session();
            let opts = EnumerateOptions::from_profile(profile, &ignore, session.as_deref());
            let mut builder = SiteMapBuilder::new();

            for text in &target.origins {
                if job.cancelled() {
                    break;
                }
                let Some(origin) = parse_absolute(text) else {
                    tracing::warn!(
                        job = job.job_id(),
                        origin = %redact::safe_url(text),
                        "scan: http lane: skipping a target origin that is not absolute http(s)"
                    );
                    continue;
                };
                // The engine refused an out-of-scope origin before the lane ran;
                // this is the belt to that braces.
                if !job.guard().in_scope(&guard_authority(&origin)) {
                    tracing::warn!(
                        job = job.job_id(),
                        origin = %redact::safe_url(origin.as_str()),
                        "scan: http lane: skipping a target origin the guard does not admit"
                    );
                    continue;
                }

                discover_origin(&origin, job, &opts, session.as_deref(), &mut builder).await;
            }

            Ok(builder.finish())
        })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> Result<Box<dyn ProbeHost>> {
        if point.lane != LaneKind::Http {
            return Err(anyhow!("scan: point {} is not an http point", point.id));
        }
        let parsed = point.url.as_deref().and_then(parse_absolute);
        let Some(origin) = parsed else {
            return Err(anyhow!(
                "scan: point {} does not name an absolute http(s) origin",
                point.id
            ));
        };

        // Call A5: the job's canary is picked against the origin of the first
        // point it asks for, and every later host of the job shares it.
        let monitor = self.monitors.for_job(job.as_ref(), &origin);
        Ok(Box::new(HttpProbeHost::new(point, job, monitor)?))
    }

    fn checks(&self) -> Vec<Arc<dyn Check>> {
        // The HTTP checks are track T3's; the lane ships none of its own.
        Vec::new()
    }
}

/// Steps (i) to (v) for one in-scope origin, merged into `builder`.
async fn discover_origin(
    origin: &Url,
    job: &dyn JobCtx,
    opts: &EnumerateOptions<'_>,
    session: Option<&SessionMaterial>,
    builder: &mut SiteMapBuilder,
) {
    let job_mark = format!("scan:{}", job.job_id());

    // (i) What the proxy already captured for this origin.
    let stored = stored_flows(job, origin, &job_mark);

    // (ii) What a crawl adds, if the profile allows one.
    let crawled = if job.cancelled() {
        Vec::new()
    } else {
        crawl_origin(origin, job, &stored, session, &job_mark).await
    };

    // (iii) to (v) Enumerate both sets into the shared site map.
    let mut overflow = 0_u32;
    let mut ignored = 0_u32;
    let mut kind_filtered = 0_u32;
    let mut flows = 0_usize;
    for flow in stored.iter().chain(crawled.iter()) {
        if job.cancelled() {
            break;
        }
        let enumerated = enumerate_v2(flow, opts);
        overflow = overflow.saturating_add(enumerated.overflow);
        ignored = ignored.saturating_add(enumerated.ignored);
        kind_filtered = kind_filtered.saturating_add(enumerated.kind_filtered);
        let auth = is_authenticated(&flow.request, session);
        builder.add(flow.id, &flow.request, enumerated, auth);
        flows += 1;
    }

    // Call A15: counts only, once per origin, with the job id.
    tracing::info!(
        job = job.job_id(),
        origin = %redact::safe_url(origin.as_str()),
        flows,
        stored = stored.len(),
        crawled = crawled.len(),
        points_overflow = overflow,
        points_ignored = ignored,
        points_kind_filtered = kind_filtered,
        "scan: http lane: origin discovered"
    );
}

/// Step (i): the captured, non-replay, same-origin HTTP flows this job may read.
///
/// A flow another job of this run crawled is left out: its points belong to that
/// job's discovery, and re-enumerating them here would double a shared store's
/// site map. This job's own crawl flows are kept — under call **A2** they are how
/// a crawled page's points reach a stored source request at all.
fn stored_flows(job: &dyn JobCtx, origin: &Url, job_mark: &str) -> Vec<HttpFlow> {
    let store = job.store();
    let query = FlowQuery {
        kind: Some(FlowKind::Http),
        is_replay: Some(false),
        ..FlowQuery::default()
    };

    let mut flows = Vec::new();
    for id in store.query(&query) {
        if job.cancelled() {
            break;
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
        if is_another_jobs_crawl(&flow, job_mark) {
            continue;
        }
        flows.push(flow);
    }
    flows
}

/// Whether `flow` carries the crawl mark of some *other* job of this run.
fn is_another_jobs_crawl(flow: &HttpFlow, job_mark: &str) -> bool {
    let marks = &flow.metadata.marks;
    marks.iter().any(|mark| mark == MARK_CRAWL) && !marks.iter().any(|mark| mark == job_mark)
}

/// Which crawl engine a job gets for an origin.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    /// A real browser: the job has one and `use_browser` is not `never`.
    Browser,
    /// The job's HTTP client.
    Client,
}

/// The engine for `job`, or `None` when the profile demands a browser the job
/// does not have (warned about once, then the crawl is skipped).
fn engine_for(job: &dyn JobCtx) -> Option<Engine> {
    let use_browser = job.profile().crawl.use_browser;
    if job.browser().is_some() && use_browser != UseBrowser::Never {
        return Some(Engine::Browser);
    }
    if use_browser != UseBrowser::Always {
        return Some(Engine::Client);
    }
    tracing::warn!(
        job = job.job_id(),
        "scan: http lane: use_browser: always but the job has no browser; skipping the crawl"
    );
    None
}

/// Step (ii): crawl `origin` and hand back the flows the crawl produced.
///
/// Empty when the profile disabled crawling, when no engine applies, when the
/// job was cancelled, or when the crawl failed — a failed crawl is a warning and
/// the discovery continues with the flows the store already held.
async fn crawl_origin(
    origin: &Url,
    job: &dyn JobCtx,
    stored: &[HttpFlow],
    session: Option<&SessionMaterial>,
    job_mark: &str,
) -> Vec<HttpFlow> {
    let crawl = &job.profile().crawl;
    if crawl.max_pages == 0 {
        return Vec::new();
    }
    let Some(engine) = engine_for(job) else {
        return Vec::new();
    };

    let send = SendOptions {
        record: RecordPolicy::Always,
        marks: vec![job_mark.to_string(), MARK_CRAWL.to_string()],
        ..SendOptions::default()
    };
    let client = job.client();
    let mut seeds = vec![origin_root(origin)];
    seeds.extend(
        fetch_seeds(
            client.as_ref(),
            origin,
            crawl,
            session,
            send,
            job.deadline(),
        )
        .await,
    );
    // `fetch_seeds` cannot poll cancellation itself, so the lane polls the moment
    // it returns.
    if job.cancelled() {
        return Vec::new();
    }
    seeds.extend(stored_seeds(stored));

    if engine == Engine::Browser {
        prime_browser(job, origin, session).await;
        if job.cancelled() {
            return Vec::new();
        }
    }

    let limits = limits_for(crawl);
    let crawler: &dyn Crawler = match engine {
        Engine::Browser => &BrowserCrawler,
        Engine::Client => &ClientCrawler,
    };
    match crawler.crawl(origin, seeds, job, &limits).await {
        Ok(report) => {
            if let Some(reason) = report.stopped_reason {
                tracing::info!(
                    job = job.job_id(),
                    reason,
                    "scan: http lane: the crawl stopped early"
                );
            }
            report.flows
        }
        Err(error) => {
            tracing::warn!(
                job = job.job_id(),
                error = %redact::scrub_error(&error),
                "scan: http lane: the crawl failed; continuing with the captured flows"
            );
            Vec::new()
        }
    }
}

/// Call **A19**: up to [`MAX_SEED_URLS`] captured `GET` URLs, so traffic the
/// operator already proxied widens the crawl instead of only the site map.
///
/// `stored` is already same-origin. A non-`GET` is never a seed: re-sending a
/// captured `POST` as a crawl page fetch would repeat whatever it did.
fn stored_seeds(stored: &[HttpFlow]) -> Vec<Url> {
    let mut seeds = Vec::new();
    for flow in stored {
        if seeds.len() >= MAX_SEED_URLS {
            break;
        }
        if !flow.request.method.eq_ignore_ascii_case("GET") {
            continue;
        }
        if let Some(url) = request_url(&flow.request) {
            seeds.push(url);
        }
    }
    seeds
}

/// Put the job's session into the browser profile before the browser engine
/// walks, and warn with the cookie **names** the profile did not take.
///
/// A missing cookie means the crawl is about to browse unauthenticated, which an
/// operator reading a thin site map needs to know (spec **D7**). Only names are
/// logged; a value never reaches a line.
async fn prime_browser(job: &dyn JobCtx, origin: &Url, session: Option<&SessionMaterial>) {
    let (Some(browser), Some(material)) = (job.browser(), session) else {
        return;
    };
    match prime_session(browser.as_ref(), origin, material, job).await {
        Ok(missing) if !missing.is_empty() => tracing::warn!(
            job = job.job_id(),
            cookies = missing.join(","),
            "scan: http lane: the browser profile did not take these session cookies (names only)"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            job = job.job_id(),
            error = %redact::scrub_error(&error),
            "scan: http lane: the browser could not be primed with the session"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use aitm_core::{Flow, FlowStore, MemFlowStore};
    use aitm_scan_model::{
        Discovery, FlowRef, IgnoreRule, InsertionKind, InsertionPoint, JobCtx, Lane, LaneKind,
        ParamRef, ProfileTarget, ScanProfile, SessionMaterial, SiteNode, UseBrowser,
    };

    use super::HttpLane;
    use crate::testutil::{
        captured_flow, request, site, FakeBrowser, FakeJob, PageScript, JOB_ID, MARKER,
    };

    /// The origin every test discovers; `t:8080` is the host [`FakeJob`] scopes.
    const ORIGIN: &str = "http://t:8080";

    /// A target over `origins` and no L4 endpoint.
    fn target(origins: &[&str]) -> ProfileTarget {
        ProfileTarget {
            origins: origins.iter().map(|origin| (*origin).to_string()).collect(),
            ..ProfileTarget::default()
        }
    }

    /// A profile with the seed files off (a test that wants them turns them on)
    /// and `tune` applied.
    fn profile(tune: impl FnOnce(&mut ScanProfile)) -> ScanProfile {
        let mut profile = ScanProfile::default();
        profile.crawl.robots = false;
        profile.crawl.sitemap = false;
        tune(&mut profile);
        profile
    }

    /// Run a discovery for `origins` against `job`.
    async fn discover(job: &FakeJob, origins: &[&str]) -> Discovery {
        HttpLane::new()
            .discover(&target(origins), job)
            .await
            .expect("discovery answers a Discovery")
    }

    /// The node with `template`, or a panic naming what was found instead.
    fn node<'a>(discovery: &'a Discovery, template: &str) -> &'a SiteNode {
        discovery
            .nodes
            .iter()
            .find(|node| node.path_template == template)
            .unwrap_or_else(|| {
                panic!(
                    "no node for {template}; found {:?}",
                    discovery
                        .nodes
                        .iter()
                        .map(|node| node.path_template.clone())
                        .collect::<Vec<String>>()
                )
            })
    }

    /// Task 17's fixture site: links on `/` and `/a`, one off-origin link, one
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

    /// The session every session test observes.
    fn material() -> SessionMaterial {
        SessionMaterial {
            cookies: vec![("sid".to_string(), "S3".to_string())],
            headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn discover_seeds_from_captured_flows_without_crawl() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/search?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        store.insert(Flow::Http(captured_flow(
            request(
                "GET",
                "http://t:8080/account/7",
                &[("cookie", "sid=S3")],
                None,
            ),
            200,
            &[],
            b"",
        )));
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://other:9/x", &[], None),
            200,
            &[],
            b"",
        )));
        let mut replay = captured_flow(
            request("GET", "http://t:8080/replayed", &[], None),
            200,
            &[],
            b"",
        );
        replay.metadata.is_replay = true;
        store.insert(Flow::Http(replay));

        let client = Arc::new(site(&[]));
        let job = FakeJob::new(profile(|p| p.crawl.max_pages = 0), Arc::clone(&client))
            .with_store(Arc::clone(&store));

        let discovery = discover(&job, &[ORIGIN]).await;

        assert_eq!(discovery.nodes.len(), 2);
        let templates: BTreeSet<String> = discovery
            .nodes
            .iter()
            .map(|node| node.path_template.clone())
            .collect();
        assert_eq!(
            templates,
            ["/account/{id}", "/search"]
                .iter()
                .map(|template| (*template).to_string())
                .collect::<BTreeSet<String>>()
        );
        assert!(node(&discovery, "/account/{id}").auth);
        assert!(!node(&discovery, "/search").auth);
        assert_eq!(client.sent.lock().unwrap().len(), 0);

        assert!(!discovery.points.is_empty());
        for point in &discovery.points {
            let flow = point.flow.expect("every point names its source flow");
            assert!(
                store.get(flow.0).is_some(),
                "point {} names a flow the store does not hold",
                point.id
            );
        }
    }

    #[tokio::test]
    async fn discover_client_crawl_builds_sitemap() {
        let store = Arc::new(MemFlowStore::new());
        let client = Arc::new(
            site(&fixture_pages()).recording_into(Arc::clone(&store) as Arc<dyn FlowStore>),
        );
        let job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Never),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store));

        let discovery = discover(&job, &[ORIGIN]).await;

        assert_eq!(node(&discovery, "/account/{id}").flows.len(), 2);
        assert!(node(&discovery, "/search").params.contains(&ParamRef {
            kind: InsertionKind::Query,
            name: "q".to_string(),
        }));
        for point in &discovery.points {
            assert!(
                point.site_node.is_some(),
                "point {} belongs to no node",
                point.id
            );
        }
        let q_points: Vec<&InsertionPoint> = discovery
            .points
            .iter()
            .filter(|point| point.kind == InsertionKind::Query && point.name == "q")
            .collect();
        assert!(!q_points.is_empty());
        for point in q_points {
            assert_eq!(point.frequency, 1);
        }
        assert_eq!(store.count(), 8);
    }

    #[tokio::test]
    async fn discover_prefers_browser_when_available() {
        let store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(
            FakeBrowser::new(vec![("http://t:8080/", PageScript::new("<p>root</p>"))])
                .recording_into(Arc::clone(&store) as Arc<dyn FlowStore>),
        );
        let client = Arc::new(site(&[]));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.use_browser = UseBrowser::Auto;
                p.crawl.robots = true;
                p.crawl.sitemap = true;
            }),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store))
        .with_browser(Arc::clone(&browser));

        let _ = discover(&job, &[ORIGIN]).await;

        assert!(
            browser
                .log_lines()
                .contains(&"navigate http://t:8080/".to_string()),
            "{:?}",
            browser.log_lines()
        );
        assert_eq!(
            client.sent_paths(),
            vec!["/robots.txt".to_string(), "/sitemap.xml".to_string()]
        );
    }

    #[tokio::test]
    async fn always_without_browser_skips_crawl() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/search?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.use_browser = UseBrowser::Always;
                p.crawl.robots = true;
                p.crawl.sitemap = true;
            }),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store));

        let discovery = discover(&job, &[ORIGIN]).await;

        assert_eq!(client.sent.lock().unwrap().len(), 0);
        assert_eq!(discovery.nodes.len(), 1);
        assert_eq!(discovery.nodes[0].path_template, "/search");
    }

    #[tokio::test]
    async fn kinds_and_ignore_apply() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request(
                "GET",
                "http://t:8080/search?q=1&page=2",
                &[("cookie", "sid=S3"), ("x-api", "k")],
                None,
            ),
            200,
            &[],
            b"",
        )));
        let client = Arc::new(site(&[]));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.max_pages = 0;
                p.audit.kinds = vec![InsertionKind::Query];
            }),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store));

        let discovery = discover(&job, &[ORIGIN]).await;

        assert!(!discovery.points.is_empty());
        for point in &discovery.points {
            assert_eq!(point.kind, InsertionKind::Query, "point {}", point.id);
        }
    }

    #[tokio::test]
    async fn session_reaches_crawl_and_browser() {
        let store = Arc::new(MemFlowStore::new());
        let client = Arc::new(
            site(&fixture_pages()).recording_into(Arc::clone(&store) as Arc<dyn FlowStore>),
        );
        let job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Never),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store))
        .with_session(material());

        let _ = discover(&job, &[ORIGIN]).await;

        // Copied out of the guard: the browser half below awaits, and a
        // `MutexGuard` may not be held across an await.
        let cookies: Vec<(String, String)> = client
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(req, _)| {
                (
                    req.path.clone(),
                    req.headers.get("cookie").unwrap_or_default().to_string(),
                )
            })
            .collect();
        assert!(!cookies.is_empty());
        for (path, cookie) in &cookies {
            assert!(
                cookie.contains("sid=S3"),
                "a crawl request went out without the session cookie: {path}"
            );
        }

        // The browser engine is primed with the same material before it walks:
        // the double logs the cookie **name** only, never its value.
        let browser_store = Arc::new(MemFlowStore::new());
        let browser = Arc::new(
            FakeBrowser::new(vec![("http://t:8080/", PageScript::new("<p>root</p>"))])
                .recording_into(Arc::clone(&browser_store) as Arc<dyn FlowStore>),
        );
        let browser_job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Auto),
            Arc::new(site(&[])),
        )
        .with_store(Arc::clone(&browser_store))
        .with_browser(Arc::clone(&browser))
        .with_session(material());

        let _ = discover(&browser_job, &[ORIGIN]).await;

        assert!(
            browser.log_lines().contains(&"cookie-set sid".to_string()),
            "{:?}",
            browser.log_lines()
        );
    }

    #[tokio::test]
    async fn invalid_origin_is_skipped_not_fatal() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/search?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        let client = Arc::new(site(&[]));
        let job = FakeJob::new(profile(|p| p.crawl.max_pages = 0), Arc::clone(&client))
            .with_store(Arc::clone(&store));

        let discovery = discover(&job, &["nope", ORIGIN]).await;

        assert_eq!(discovery.nodes.len(), 1);
        assert_eq!(discovery.nodes[0].path_template, "/search");
    }

    #[tokio::test]
    async fn cancelled_returns_early() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/search?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Never),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store));
        job.cancel();

        let discovery = discover(&job, &[ORIGIN]).await;

        assert!(discovery.nodes.is_empty());
        assert!(discovery.points.is_empty());
        assert_eq!(client.sent.lock().unwrap().len(), 0);
    }

    /// A point of `lane`, over the flow `flow`, for the probe-host tests.
    fn point(lane: LaneKind, flow: Option<FlowRef>) -> InsertionPoint {
        InsertionPoint {
            id: "p1".to_string(),
            lane,
            kind: InsertionKind::Query,
            name: "q".to_string(),
            path: None,
            example: None,
            flow,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: Some("GET".to_string()),
            url: Some("http://t:8080/search?q=1".to_string()),
        }
    }

    #[test]
    fn probe_host_for_rejects_foreign_lane() {
        let job: Arc<dyn JobCtx> =
            Arc::new(FakeJob::new(ScanProfile::default(), Arc::new(site(&[]))));

        let Err(err) = HttpLane::new().probe_host_for(&point(LaneKind::Ws, None), job) else {
            panic!("a WebSocket point is not this lane's and must be refused");
        };

        assert!(err.to_string().contains("not an http point"), "{err}");
    }

    #[test]
    fn probe_host_for_hosts_an_http_point() {
        let store = Arc::new(MemFlowStore::new());
        let id = store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/search?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        let job: Arc<dyn JobCtx> = Arc::new(
            FakeJob::new(ScanProfile::default(), Arc::new(site(&[])))
                .with_store(Arc::clone(&store)),
        );

        let lane = HttpLane::new();
        let Ok(host) = lane.probe_host_for(&point(LaneKind::Http, Some(FlowRef(id))), job) else {
            panic!("an http point with a stored flow is hosted");
        };

        assert_eq!(host.marker(), MARKER);
        // Call A5: the job's canary monitor is built once, against the origin
        // of the first point the job asks for.
        assert_eq!(lane.monitors.len(), 1);
    }

    #[test]
    fn the_lane_is_http_and_ships_no_checks() {
        let lane = HttpLane::new();

        assert_eq!(lane.lane(), LaneKind::Http);
        assert!(lane.checks().is_empty());
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// An ignore list that does not compile fails the pass before a single
    /// request goes out, and the error names the offending pattern.
    #[tokio::test]
    async fn invalid_ignore_rule_fails_discovery_before_any_request() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.use_browser = UseBrowser::Never;
                p.audit.ignore = vec![IgnoreRule {
                    kind: None,
                    name_regex: Some("(".to_string()),
                    point_trait: None,
                }];
            }),
            Arc::clone(&client),
        );

        let result = HttpLane::new().discover(&target(&[ORIGIN]), &job).await;

        let err = match result {
            Ok(discovery) => panic!("an uncompilable ignore list must fail: {discovery:?}"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains('('), "{err}");
        assert_eq!(client.sent.lock().unwrap().len(), 0);
    }

    /// An origin the scope guard does not admit is skipped whole: no crawl
    /// request, no node from the store, no error.
    #[tokio::test]
    async fn origin_outside_the_scope_guard_is_skipped() {
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://evil.test:9/x?q=1", &[], None),
            200,
            &[],
            b"",
        )));
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Never),
            Arc::clone(&client),
        )
        .with_store(Arc::clone(&store));

        let discovery = discover(&job, &["http://evil.test:9"]).await;

        assert!(discovery.nodes.is_empty());
        assert!(discovery.points.is_empty());
        assert_eq!(
            client.sent.lock().unwrap().len(),
            0,
            "an unadmitted origin is never crawled"
        );
    }

    /// A stored flow another job's crawl produced is that job's discovery, not
    /// this one's; this job's own crawl flows and plain captures (even ones
    /// marked by another job without the crawl mark) are enumerated.
    #[tokio::test]
    async fn another_jobs_crawl_flows_are_not_re_enumerated() {
        let store = Arc::new(MemFlowStore::new());
        let mut theirs = captured_flow(
            request("GET", "http://t:8080/theirs?q=1", &[], None),
            200,
            &[],
            b"",
        );
        theirs.metadata.marks = vec!["scan:scan-other001".to_string(), "crawl".to_string()];
        store.insert(Flow::Http(theirs));
        let mut ours = captured_flow(
            request("GET", "http://t:8080/ours?q=1", &[], None),
            200,
            &[],
            b"",
        );
        ours.metadata.marks = vec![format!("scan:{JOB_ID}"), "crawl".to_string()];
        store.insert(Flow::Http(ours));
        let mut marked_only = captured_flow(
            request("GET", "http://t:8080/marked?q=1", &[], None),
            200,
            &[],
            b"",
        );
        marked_only.metadata.marks = vec!["scan:scan-other001".to_string()];
        store.insert(Flow::Http(marked_only));
        let client = Arc::new(site(&[]));
        let job = FakeJob::new(profile(|p| p.crawl.max_pages = 0), Arc::clone(&client))
            .with_store(Arc::clone(&store));

        let discovery = discover(&job, &[ORIGIN]).await;

        let templates: BTreeSet<String> = discovery
            .nodes
            .iter()
            .map(|node| node.path_template.clone())
            .collect();
        assert_eq!(
            templates,
            ["/marked", "/ours"]
                .iter()
                .map(|template| (*template).to_string())
                .collect::<BTreeSet<String>>()
        );
        assert_eq!(client.sent.lock().unwrap().len(), 0);
    }
}
