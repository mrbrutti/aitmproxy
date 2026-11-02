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
//! all (an uncompilable ignore list), and after a failed crawl the store is
//! read again so the captures the crawl inserted before failing still become
//! nodes. And every URL that reaches a log line or an error goes through
//! [`redact::safe_url`], every foreign error text through
//! [`redact::scrub_error`]; no header, cookie or body value is ever named here.

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
use crate::crawl::frontier::{held_copy, limits_for, Crawler, StopReason};
use crate::crawl::seeds::fetch_seeds;
use crate::host::{HttpProbeHost, SessionMonitors};
use crate::limits::{is_crawl_mark, job_mark, MAX_SEED_URLS, MAX_STORED_FLOWS};
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
    /// The two crawl engines `discover` chooses between.
    crawlers: Crawlers,
}

/// The crawl engines a lane runs: one per [`Engine`].
///
/// Held by value on the lane so a test can stand in a failing engine; the
/// production pair is [`BrowserCrawler`] and [`ClientCrawler`].
#[derive(Clone, Copy)]
pub(crate) struct Crawlers {
    /// The engine for [`Engine::Browser`].
    pub(crate) browser: &'static dyn Crawler,
    /// The engine for [`Engine::Client`].
    pub(crate) client: &'static dyn Crawler,
}

impl Crawlers {
    /// The real engines.
    const REAL: Self = Self {
        browser: &BrowserCrawler,
        client: &ClientCrawler,
    };
}

impl HttpLane {
    /// A lane with no job monitors yet, running the real crawl engines.
    pub fn new() -> Self {
        Self::with_crawlers(Crawlers::REAL)
    }

    /// A lane running `crawlers` in place of the real engines.
    pub(crate) fn with_crawlers(crawlers: Crawlers) -> Self {
        Self {
            monitors: SessionMonitors::new(),
            crawlers,
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

                discover_origin(
                    &origin,
                    job,
                    &opts,
                    session.as_deref(),
                    &mut builder,
                    self.crawlers,
                )
                .await;
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
    crawlers: Crawlers,
) {
    let job_mark = job_mark(job.job_id());

    // (i) What the proxy already captured for this origin.
    let mut stored = stored_flows(job, origin, &job_mark);

    // (ii) What a crawl adds, if the profile allows one.
    let crawled = if job.cancelled() {
        Vec::new()
    } else {
        match crawl_origin(origin, job, &stored, session, &job_mark, crawlers).await {
            Ok(flows) => flows,
            Err(error) => {
                tracing::warn!(
                    job = job.job_id(),
                    error = %redact::scrub_error(&error),
                    "scan: http lane: the crawl failed; continuing with the captured flows"
                );
                // A browser crawl records through the proxy as it goes, so the
                // store may hold captures the failed crawl never reported. Read
                // it again rather than keep the pre-crawl snapshot; this job's
                // own crawl marks keep those flows in (R3).
                stored = stored_flows(job, origin, &job_mark);
                Vec::new()
            }
        }
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

/// Step (i): the captured, non-replay, same-origin HTTP flows this job may read,
/// newest first and at most [`MAX_STORED_FLOWS`] of them.
///
/// A flow another job of this run crawled is left out: its points belong to that
/// job's discovery, and re-enumerating them here would double a shared store's
/// site map. This job's own crawl flows are kept — under call **A2** they are how
/// a crawled page's points reach a stored source request at all.
///
/// The store is walked newest first (it lists in insertion order), so the cap
/// keeps the latest captures. Only the request of a stored flow is read — by
/// `enumerate_v2`, the site-map builder and `is_authenticated` — so the clone
/// held here drops its response body rather than duplicate up to two thousand
/// captured pages for the life of discovery (S-M7).
fn stored_flows(job: &dyn JobCtx, origin: &Url, job_mark: &str) -> Vec<HttpFlow> {
    let store = job.store();
    let query = FlowQuery {
        kind: Some(FlowKind::Http),
        is_replay: Some(false),
        ..FlowQuery::default()
    };

    let mut flows = Vec::new();
    for id in store.query(&query).into_iter().rev() {
        if job.cancelled() || flows.len() >= MAX_STORED_FLOWS {
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
        // Held the way a crawl holds its flows (R-M3): the stored pass reads
        // the request, so the response body is dropped here too.
        flows.push(held_copy(flow));
    }
    flows
}

/// Whether `flow` carries the crawl mark of some *other* job of this run.
fn is_another_jobs_crawl(flow: &HttpFlow, job_mark: &str) -> bool {
    let marks = &flow.metadata.marks;
    marks.iter().any(|mark| is_crawl_mark(mark)) && !marks.iter().any(|mark| mark == job_mark)
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
        reason = StopReason::NoBrowser.as_str(),
        "scan: http lane: use_browser: always but the job has no browser; skipping the crawl"
    );
    None
}

/// Step (ii): crawl `origin` and hand back the flows the crawl produced.
///
/// `Ok` and empty when the profile disabled crawling, when no engine applies or
/// when the job was cancelled; `Err` when the engine itself failed, which the
/// caller turns into a warning.
async fn crawl_origin(
    origin: &Url,
    job: &dyn JobCtx,
    stored: &[HttpFlow],
    session: Option<&SessionMaterial>,
    job_mark: &str,
    crawlers: Crawlers,
) -> Result<Vec<HttpFlow>> {
    let crawl = &job.profile().crawl;
    if crawl.max_pages == 0 {
        return Ok(Vec::new());
    }
    let Some(engine) = engine_for(job) else {
        return Ok(Vec::new());
    };

    // Recorded and on the profile's HTTP version like the client engine's
    // page fetches (Sp2), but marked with the job mark only: a `robots.txt`
    // or `sitemap.xml` probe is not a crawled page, and the engine counts
    // every `crawl`-marked flow as one (`scan.discover` reported four pages
    // for `max_pages: 2`; T1b contract cell, 2026-11-02).
    let send = SendOptions {
        record: RecordPolicy::Always,
        marks: vec![job_mark.to_string()],
        version: job.profile().http.version.into(),
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
        return Ok(Vec::new());
    }
    seeds.extend(stored_seeds(stored));

    if engine == Engine::Browser {
        prime_browser(job, origin, session).await;
        if job.cancelled() {
            return Ok(Vec::new());
        }
    }

    let limits = limits_for(crawl);
    let crawler = match engine {
        Engine::Browser => crawlers.browser,
        Engine::Client => crawlers.client,
    };
    let report = crawler.crawl(origin, seeds, job, &limits).await?;
    // Forms the crawl found but deliberately did not submit (a live form that
    // disagreed with the page, a tag the browser could not answer) are told to
    // the job, so `crawl.forms_skipped` says the map is not the whole form
    // surface (T1b's additive hook, 2026-11-01).
    if report.forms_skipped > 0 {
        job.report_forms_skipped(u64::from(report.forms_skipped));
    }
    // Forms it did submit are told the same way, so `crawl.forms_submitted`
    // is written at all: the counter existed but no hook fed it (amendment 53).
    if report.forms_submitted > 0 {
        job.report_forms_submitted(u64::from(report.forms_submitted));
    }
    if let Some(reason) = report.stopped_reason {
        tracing::info!(
            job = job.job_id(),
            reason = reason.as_str(),
            "scan: http lane: the crawl stopped early"
        );
    }
    Ok(report.flows)
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
/// walks, warn with the cookie **names** the profile did not take, and report
/// them to the job.
///
/// A missing cookie means the crawl is about to browse unauthenticated, which an
/// operator reading a thin site map needs to know (spec **D7**): the report sets
/// `JobStatus.session.browser_partial`. Only names are logged and only names are
/// reported; a value never reaches a line or a status.
async fn prime_browser(job: &dyn JobCtx, origin: &Url, session: Option<&SessionMaterial>) {
    let (Some(browser), Some(material)) = (job.browser(), session) else {
        return;
    };
    match prime_session(browser.as_ref(), origin, material, job).await {
        Ok(missing) if !missing.is_empty() => {
            tracing::warn!(
                job = job.job_id(),
                cookies = missing.join(","),
                "scan: http lane: the browser profile did not take these session cookies (names only)"
            );
            job.report_session_browser_partial(missing);
        }
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

    use super::{prime_browser, stored_flows, Crawlers, HttpLane};
    use crate::crawl::frontier::{CrawlReport, Crawler, Limits};
    use crate::limits::{job_mark, MARK_CRAWL, MAX_STORED_FLOWS};
    use crate::testutil::{
        captured_flow, request, site, FakeBrowser, FakeJob, PageScript, JOB_ID, MARKER,
    };
    use crate::url_norm::parse_absolute;

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

    /// Amendment 53: the one form the client crawl submits (`fixture_pages`'
    /// `GET /search`) reaches the job through `JobCtx::report_forms_submitted`,
    /// so the engine's `crawl.forms_submitted` is written at all; it had no
    /// hook before, and `test_t2_crawl` SKIPped on it.
    #[tokio::test]
    async fn client_crawl_reports_submitted_forms_to_the_job() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| p.crawl.use_browser = UseBrowser::Never),
            Arc::clone(&client),
        );

        discover(&job, &[ORIGIN]).await;

        assert!(
            client
                .sent_paths()
                .contains(&"/search?q=aitm-aitm7f3a".to_string()),
            "the crawl submitted the search form: {:?}",
            client.sent_paths()
        );
        assert_eq!(job.reported_forms_submitted(), 1);
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

        discover(&job, &[ORIGIN]).await;

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

        discover(&job, &[ORIGIN]).await;

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

        discover(&browser_job, &[ORIGIN]).await;

        assert!(
            browser.log_lines().contains(&"cookie-set sid".to_string()),
            "{:?}",
            browser.log_lines()
        );
    }

    /// Task 22: the session cookies the browser profile would not take are
    /// reported to the job by **name**, once, so the engine can set
    /// `JobStatus.session.browser_partial` (spec D7). A profile that keeps
    /// every cookie reports nothing at all.
    #[tokio::test]
    async fn a_partial_browser_priming_is_reported() {
        let material = SessionMaterial {
            cookies: vec![
                ("sid".to_string(), "S3".to_string()),
                ("hs".to_string(), "H".to_string()),
            ],
            headers: Vec::new(),
        };
        let origin = parse_absolute(ORIGIN).unwrap();
        let page = || vec![("http://t:8080/", PageScript::new("<p>root</p>"))];

        // `hs` is `HttpOnly`: `document.cookie` cannot set it.
        let partial = Arc::new(FakeBrowser::new(page()).refusing_cookies(&["hs"]));
        let job = FakeJob::new(profile(|_| {}), Arc::new(site(&[])))
            .with_browser(Arc::clone(&partial))
            .with_session(material.clone());

        prime_browser(&job, &origin, Some(&material)).await;

        assert_eq!(
            job.reported_browser_partials(),
            vec![vec!["hs".to_string()]],
            "the names the profile did not take, reported once"
        );

        let full = Arc::new(FakeBrowser::new(page()));
        let job = FakeJob::new(profile(|_| {}), Arc::new(site(&[])))
            .with_browser(Arc::clone(&full))
            .with_session(material.clone());

        prime_browser(&job, &origin, Some(&material)).await;

        assert!(
            job.reported_browser_partials().is_empty(),
            "a profile that took every cookie is not partial: {:?}",
            job.reported_browser_partials()
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

    // --- Sp2: every crawl send honours the profile's HTTP version ------------

    /// A seed probe is not a page: `robots.txt` and `sitemap.xml` go out with
    /// the job mark alone, while a crawl GET carries `crawl` too, so the
    /// engine's page count (every `crawl`-marked flow) stays within
    /// `max_pages` (T1b contract cell: `scan.discover { max_pages: 2 }` had
    /// reported four).
    #[tokio::test]
    async fn seed_sends_carry_the_job_mark_only() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.use_browser = UseBrowser::Never;
                p.crawl.robots = true;
                p.crawl.sitemap = true;
            }),
            Arc::clone(&client),
        );

        discover(&job, &[ORIGIN]).await;

        let sent = client.sent.lock().unwrap();
        let marks_of = |path: &str| -> Vec<String> {
            sent.iter()
                .find(|(req, _)| req.path == path)
                .map(|(_, opts)| opts.marks.clone())
                .unwrap_or_else(|| panic!("{path} was fetched"))
        };
        assert_eq!(marks_of("/robots.txt"), vec![job_mark(JOB_ID)]);
        assert_eq!(marks_of("/sitemap.xml"), vec![job_mark(JOB_ID)]);
        assert_eq!(
            marks_of("/a"),
            vec![job_mark(JOB_ID), MARK_CRAWL.to_string()],
            "a crawled page carries the crawl mark"
        );
    }

    /// `http.version: h1` reaches the seed fetches and the crawl GETs alike:
    /// the lane builds the seed `SendOptions` from the profile, not from
    /// `SendOptions::default()`.
    #[tokio::test]
    async fn seed_sends_honour_the_profile_http_version() {
        let client = Arc::new(site(&fixture_pages()));
        let job = FakeJob::new(
            profile(|p| {
                p.crawl.use_browser = UseBrowser::Never;
                p.crawl.robots = true;
                p.crawl.sitemap = true;
                p.http.version = aitm_scan_model::HttpVersionPolicy::H1;
            }),
            Arc::clone(&client),
        );

        discover(&job, &[ORIGIN]).await;

        let sent = client.sent.lock().unwrap();
        assert!(sent.iter().any(|(req, _)| req.path == "/robots.txt"));
        assert!(sent.iter().any(|(req, _)| req.path == "/sitemap.xml"));
        assert!(sent.iter().any(|(req, _)| req.path == "/a"));
        for (req, opts) in sent.iter() {
            assert_eq!(
                opts.version,
                aitm_core::VersionPolicy::H1,
                "{} went out with {:?}",
                req.path,
                opts.version
            );
        }
    }

    // --- S-M7: the stored pass is capped, newest first, request only ---------

    /// 2100 same-origin captures: the lane enumerates at most
    /// `MAX_STORED_FLOWS` of them, the newest kept, and the clones it holds
    /// carry no response body (only the request is read); the store's copies
    /// are untouched.
    #[test]
    fn stored_flows_are_capped_newest_first_without_bodies() {
        let store = Arc::new(MemFlowStore::new());
        let mut ids = Vec::new();
        for i in 0..2100 {
            ids.push(store.insert(Flow::Http(captured_flow(
                request("GET", &format!("http://t:8080/p{i}"), &[], None),
                200,
                &[("content-type", "text/html")],
                b"<p>kept in the store</p>",
            ))));
        }
        let job = FakeJob::new(profile(|_| {}), Arc::new(site(&[]))).with_store(Arc::clone(&store));
        let origin = parse_absolute(ORIGIN).expect("the test origin parses");

        let flows = stored_flows(&job, &origin, &job_mark(JOB_ID));

        assert_eq!(MAX_STORED_FLOWS, 2048);
        assert_eq!(flows.len(), MAX_STORED_FLOWS);
        assert_eq!(flows[0].request.path, "/p2099");
        assert_eq!(flows[MAX_STORED_FLOWS - 1].request.path, "/p52");
        assert!(!flows.iter().any(|flow| flow.request.path == "/p51"));
        for flow in &flows {
            let response = flow.response.as_ref().expect("the clone keeps its status");
            assert_eq!(response.status, 200);
            assert!(
                matches!(response.body, aitm_core::Body::Empty),
                "{} carries a body",
                flow.request.path
            );
        }
        let Some(Flow::Http(stored)) = store.get(ids[2099]) else {
            panic!("the store holds the flow");
        };
        assert!(matches!(
            stored.response.as_ref().map(|r| &r.body),
            Some(aitm_core::Body::Bytes(_))
        ));
    }

    // --- stage-5 R3: a failed crawl still yields the captures it inserted ---

    /// The path a [`FailingCrawler`] captures before it dies.
    const INSERTED_BY_CRAWL: &str = "/inserted-by-crawl";

    /// A crawl engine that records one origin flow into the store, as a browser
    /// navigation does through the proxy, and then fails with a driver error
    /// that echoes a credential.
    struct FailingCrawler;

    impl Crawler for FailingCrawler {
        fn crawl<'a>(
            &'a self,
            _origin: &'a url::Url,
            _seeds: Vec<url::Url>,
            job: &'a dyn JobCtx,
            _limits: &'a Limits,
        ) -> futures::future::BoxFuture<'a, anyhow::Result<CrawlReport>> {
            Box::pin(async move {
                let mut flow = captured_flow(
                    request("GET", &format!("{ORIGIN}{INSERTED_BY_CRAWL}"), &[], None),
                    200,
                    &[],
                    b"<p>captured mid-crawl</p>",
                );
                flow.metadata.marks = vec![format!("scan:{JOB_ID}"), MARK_CRAWL.to_string()];
                job.store().insert(Flow::Http(flow));
                Err(anyhow::anyhow!(
                    "the browser died on http://t:8080/cb?token=abc"
                ))
            })
        }
    }

    /// When the crawl fails, the lane re-reads the store, so a capture the crawl
    /// inserted before failing is enumerated into a node instead of being lost
    /// with the pre-crawl snapshot; the warning carries no credential.
    #[tokio::test]
    async fn failed_crawl_re_reads_the_store_for_its_captures() {
        let (_guard, lines) = crate::redact::capture::install();
        let store = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured_flow(
            request("GET", "http://t:8080/before", &[], None),
            200,
            &[],
            b"",
        )));
        let job = FakeJob::new(profile(|_| {}), Arc::new(site(&[]))).with_store(Arc::clone(&store));
        let lane = HttpLane::with_crawlers(Crawlers {
            browser: &FailingCrawler,
            client: &FailingCrawler,
        });

        let discovery = lane
            .discover(&target(&[ORIGIN]), &job)
            .await
            .expect("a failed crawl is a warning, not a failed discovery");

        node(&discovery, "/before");
        node(&discovery, INSERTED_BY_CRAWL);
        assert_eq!(store.query(&aitm_core::FlowQuery::default()).len(), 2);

        let warned = lines.containing("the crawl failed");
        assert_eq!(warned.len(), 1, "{:?}", lines.all());
        assert!(warned[0].contains("the browser died"), "{}", warned[0]);
        assert!(!warned[0].contains("abc"), "{}", warned[0]);
    }
}
