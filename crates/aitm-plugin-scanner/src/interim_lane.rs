//! The interim HTTP lane over the legacy crawl/discover/inject modules, so
//! every T1 acceptance criterion is provable before the T2 lane lands (plan
//! call B2). Task 12 of the T1b plan fills it.
//!
//! This is the v1 scanner wearing the v2 contract (spec D1, "Interim HTTP
//! lane"): the shipped browser crawl ([`crate::crawl`]), the v1 insertion
//! points ([`crate::discover`]), the two native payload classes
//! ([`crate::inject`] / [`crate::checks`]) and the three passive checks
//! ([`crate::passive`]), each adapted to [`Lane`], [`ProbeHost`] and [`Check`].
//! It adds no detection and no verb. T2 replaces it by flipping
//! `aitm-scan-http::lane()` to `Some`, after which the engine prefers the lane
//! crate and T2's integration task deletes this file with the legacy modules.
//!
//! Two rules from the spec are enforced here rather than by the engine:
//!
//! - **Record policy** (D5). Every probe, baseline and raw probe is sent with
//!   `record: Never` and the resulting flow is held in memory (at most
//!   [`MAX_HELD_FLOWS`] per point), so a probe reaches the store only through
//!   the engine's re-recording of an issue. Browser-crawl navigations are the
//!   exception: they are real proxied captures, so the lane marks exactly the
//!   flows a navigation added to the store — a bounded store diff — with
//!   `scan:<job>` and `crawl`, and never re-sends them.
//! - **Redaction** (D8.1). A point's `example` and every excerpt in
//!   `Evidence::matched` goes through [`crate::util::scrub`] and then
//!   [`Evidence::excerpt`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CommandHost, Flow, FlowId, HeaderMap, HttpFlow, HttpRequest, RecordPolicy, SendOptions,
};
#[cfg(test)]
use aitm_scan_model::PocHint;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, CheckScope, Confidence, Discovery, Evidence, FlowRef,
    InsertionKind, InsertionPoint, Intensity, JobCtx, Lane, LaneKind, NodeId, Outcome, ParamRef,
    Payload, PayloadMode, PointTrait, ProbeHost, ProbeResponse, ProfileTarget, RawProbe,
    ScanProfile, SiteNode, Technique, UseBrowser, Verdict, MAX_MATCH_BODY,
};
use futures::future::BoxFuture;
use tokio::sync::OnceCell;

#[cfg(test)]
use crate::checks::CheckDefinition;
#[cfg(test)]
use crate::client::ProbeRefused;
use crate::config::ScannerConfig;
use crate::discover::{is_secret_name, InjectionPoint, Location};
#[cfg(test)]
use crate::scheduler::payload_cap;
use crate::util::{default_port, normalize_origin, origin_key, scrub, split_authority, wire_token};

/// The mark every crawl capture carries beside `scan:<job>` (spec D5).
pub(crate) const CRAWL_MARK: &str = "crawl";

/// How many probe flows one [`InterimProbeHost`] keeps in memory (spec D5).
pub const MAX_HELD_FLOWS: usize = 16;

/// The reflected-XSS check's **id**, spec D8.2's literal name — distinct from
/// the issue **class** it emits (`crate::checks::CLASS_REFLECTED_XSS`), and so
/// the manual verb is `check.xss-reflected`.
#[cfg(test)]
const CHECK_XSS_REFLECTED: &str = "xss-reflected";

/// The two legacy active checks (`xss-reflected`, `open-redirect`) for this
/// crate's tests, which hand them to the plugin's native slot the way the
/// binary hands it the T3 natives that superseded them (T3 PR 2a). Not part of
/// [`Lane::checks`] any more; retired with the lane.
#[cfg(test)]
pub(crate) fn legacy_active_checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(LegacyActiveCheck {
            def: CheckDefinition::reflected_xss(),
            meta: reflected_xss_meta(),
        }),
        Arc::new(LegacyActiveCheck {
            def: CheckDefinition::open_redirect(),
            meta: open_redirect_meta(),
        }),
    ]
}

/// The interim HTTP [`Lane`]: the v1 scanner behind the v2 traits.
pub struct InterimHttpLane {
    cfg: ScannerConfig,
}

impl InterimHttpLane {
    /// The lane, ready for the engine's lane list.
    ///
    /// `cfg` supplies the crawl's non-profile knobs (the profile supplies
    /// `max_depth`, `max_pages` and the time budget per job).
    // The engine collects `Arc<dyn Lane>`, and the plan pins this signature;
    // handing back a bare `Self` would only make every caller wrap it.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(cfg: ScannerConfig) -> Arc<dyn Lane> {
        Arc::new(Self { cfg })
    }

    /// Crawl one origin with the job's browser, then mark the flows the
    /// navigation added to the store (spec D5, "Crawl flows are different").
    ///
    /// Degrades rather than failing: no browser, `use_browser: never`,
    /// `max_pages: 0`, a spent budget or a crawl refusal all leave the store
    /// untouched and the discovery pass continues over what the proxy already
    /// captured. A crawl the crawler *refused* (the seed out of scope, a
    /// malformed origin) is returned as its reason, so the caller can say why
    /// discovery ran on captures alone; every other case is `None`.
    ///
    /// Spec D5 "one budget per job": a navigation is a probe. The crawler's
    /// `max_pages` is capped by what the budget has left *before* it starts,
    /// so the crawl can never outrun the probes budget, and the pages it did
    /// navigate are charged afterwards. Should that charge be refused (another
    /// lane spent the budget meanwhile), whatever is left is drained: the
    /// navigations happened and the budget must say so.
    async fn crawl_origin(&self, origin: &str, job: &dyn JobCtx) -> BrowserCrawl {
        let profile = job.profile();
        if profile.crawl.max_pages == 0 || profile.crawl.use_browser == UseBrowser::Never {
            return BrowserCrawl::NotApplicable;
        }
        // No browser: nothing to crawl and nothing to report.
        let Some(browser) = job.browser() else {
            return BrowserCrawl::NotApplicable;
        };
        let max_pages = profile.crawl.max_pages.min(job.budget_left());
        if max_pages == 0 {
            return BrowserCrawl::NotApplicable;
        }

        let store = job.store();
        let client = job.client();
        let guard = job.guard();
        let before: HashSet<FlowId> = store.list().into_iter().collect();

        let cfg = ScannerConfig {
            max_depth: profile.crawl.max_depth as usize,
            max_pages: max_pages as usize,
            time_budget: Duration::from_secs(profile.budget.time_s),
            ..self.cfg.clone()
        };
        let outcome = {
            let host = CommandHost::new(&*store, &*client, &*guard, Some(&*browser));
            crate::crawl::crawl(&host, origin, &cfg).await
        };

        // The diff is bounded to the ids the navigation produced; a flow that
        // was in the store before the crawl is never touched.
        let job_mark = format!("scan:{}", job.job_id());
        for id in store.list() {
            if before.contains(&id) {
                continue;
            }
            store.update(id, &mut |flow| {
                let marks = &mut flow.metadata_mut().marks;
                for mark in [job_mark.as_str(), CRAWL_MARK] {
                    if !marks.iter().any(|have| have == mark) {
                        marks.push(mark.to_string());
                    }
                }
            });
        }

        match outcome {
            Ok(outcome) => {
                let pages = u32::try_from(outcome.pages_crawled).unwrap_or(u32::MAX);
                if pages > 0 && !job.charge(pages) {
                    job.charge(job.budget_left());
                }
                BrowserCrawl::Ran
            }
            Err(err) => BrowserCrawl::Failed(scrub(&format!("{err:#}"))),
        }
    }

    /// Crawl one origin with the job's HTTP client, for a job that has no
    /// browser to crawl with (spec D1 "every T1 AC must be provable on the
    /// interim lane", D5 "client-crawler GETs go through `send_opts` like
    /// probes, recorded under the same policy with the crawl mark").
    ///
    /// This is the fallback, not the default: a bound browser under
    /// `use_browser: auto` crawls instead, because it runs the script a client
    /// cannot. It runs when no browser is bound **or** `use_browser: never`,
    /// and `crawl.max_pages > 0` — that one setting turns every crawl off.
    ///
    /// Returns why the crawl stopped when the reason is worth saying, so the
    /// caller can log it beside the job; an exhausted graph says nothing.
    async fn client_crawl(
        &self,
        origin: &str,
        job: &dyn JobCtx,
        browser_crawled: bool,
    ) -> Option<crate::interim_crawl::CrawlStop> {
        let profile = job.profile();
        if profile.crawl.max_pages == 0 || browser_crawled {
            return None;
        }
        let crawled = crate::interim_crawl::crawl_with_client(origin, job).await;
        if crawled.forms_skipped > 0 {
            job.report_forms_skipped(u64::from(crawled.forms_skipped));
        }
        // Amendment 53: the forms the crawl posted feed `crawl.forms_submitted`.
        if crawled.forms_submitted > 0 {
            job.report_forms_submitted(u64::from(crawled.forms_submitted));
        }
        // Amendment 39: each failed request is one `crawl.errors` unit, named by
        // its classified token. `last_error` is the aggregate kind the crawl
        // retained; the reason is a token, so there is nothing to scrub.
        if let Some(kind) = crawled.last_error {
            for _ in 0..crawled.failed {
                job.report_crawl_error(origin, kind.as_str());
            }
        }
        crawled.stopped
    }

    /// Build the site map and the insertion points from every captured, in-scope
    /// flow in the store — the crawl's captures included, since they are now
    /// ordinary captures.
    fn map_flows(&self, origins: &[String], job: &dyn JobCtx) -> Discovery {
        let store = job.store();
        let job_mark = format!("scan:{}", job.job_id());
        let mut nodes: Vec<SiteNode> = Vec::new();
        let mut index: HashMap<NodeId, usize> = HashMap::new();
        let mut points: Vec<InsertionPoint> = Vec::new();

        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                continue;
            };
            // A replay is the scanner's own traffic (or an operator's); the
            // attack surface is what the target was actually asked for. This
            // job's own crawl captures are the exception: the client crawl
            // reissues each page through the proxy, which stamps a reissue a
            // replay, and those pages are exactly the surface (spec D5,
            // "crawl flows are different").
            if flow.metadata.is_replay && !is_crawl_capture(&flow, &job_mark) {
                continue;
            }
            let origin = origin_key(&flow.request.scheme, &flow.request.authority);
            if !origins.contains(&origin) {
                continue;
            }

            let node_id = node_id(&flow.request.method, &origin, &flow.request.path);
            let slot = *index.entry(node_id.clone()).or_insert_with(|| {
                nodes.push(new_node(&node_id, &flow, &origin));
                nodes.len() - 1
            });
            let node = &mut nodes[slot];
            node.flows.push(FlowRef(flow.id));
            node.auth |=
                flow.request.headers.has("cookie") || flow.request.headers.has("authorization");

            for legacy in crate::discover::enumerate(&flow) {
                let kind = kind_for(&legacy.location);
                let param = ParamRef {
                    kind,
                    name: legacy.name.clone(),
                };
                if !node.params.contains(&param) {
                    node.params.push(param);
                }
                node.points += 1;
                points.push(InsertionPoint {
                    id: point_id(flow.id, kind, &legacy.name),
                    lane: LaneKind::Http,
                    kind,
                    name: legacy.name.clone(),
                    path: None,
                    example: Some(scrub(&legacy.example)),
                    flow: Some(FlowRef(flow.id)),
                    site_node: Some(node_id.clone()),
                    traits: traits_for(&legacy),
                    // Filled in once every flow has been read.
                    frequency: 0,
                    method: Some(flow.request.method.clone()),
                    url: Some(format!(
                        "{}://{}{}",
                        flow.request.scheme, flow.request.authority, flow.request.path
                    )),
                });
            }
        }

        // `frequency` is how many *distinct nodes* carry the same (kind, name)
        // pair, so the scheduler can tell a per-page parameter from a
        // site-wide one.
        let mut carriers: HashMap<(InsertionKind, String), HashSet<NodeId>> = HashMap::new();
        for point in &points {
            carriers
                .entry((point.kind, point.name.clone()))
                .or_default()
                .extend(point.site_node.clone());
        }
        for point in &mut points {
            let seen = carriers
                .get(&(point.kind, point.name.clone()))
                .map_or(1, HashSet::len);
            point.frequency = u32::try_from(seen).unwrap_or(u32::MAX);
        }

        Discovery { points, nodes }
    }
}

/// What the browser crawl of one origin did, so the lane knows whether the
/// client crawl has to stand in for it.
#[derive(Debug, PartialEq, Eq)]
enum BrowserCrawl {
    /// No browser, `use_browser: never` or `max_pages: 0`: nothing to do.
    NotApplicable,
    /// The browser crawled; its navigations are in the store.
    Ran,
    /// The browser crawl failed (reason already scrubbed): counted as a crawl
    /// error, and the client crawl runs instead.
    Failed(String),
}

impl Lane for InterimHttpLane {
    fn lane(&self) -> LaneKind {
        LaneKind::Http
    }

    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
        Box::pin(async move {
            for origin in &target.origins {
                if job.cancelled() {
                    break;
                }
                // `Discovery` has no notes field (the model is frozen for this
                // task), so a refused crawl is logged with the job's context:
                // discovery still runs over what the proxy captured.
                // A browser crawl that fails (timed out, refused, wrong proxy
                // port) is counted in `crawl.errors` and the client crawl runs
                // in its place, so the job does not silently proceed on
                // captured flows alone (T7/T2 live runs, 2026-11-01).
                let browser_crawled = match self.crawl_origin(origin, job).await {
                    BrowserCrawl::Ran => true,
                    BrowserCrawl::NotApplicable => false,
                    BrowserCrawl::Failed(reason) => {
                        job.report_crawl_error(origin, &reason);
                        false
                    }
                };
                // The client crawl, for a job whose browser did not crawl.
                if let Some(stopped) = self.client_crawl(origin, job, browser_crawled).await {
                    tracing::debug!(
                        job = job.job_id(),
                        origin,
                        stopped = stopped.as_str(),
                        "interim lane: the client crawl stopped early"
                    );
                }
            }
            let origins: Vec<String> = target
                .origins
                .iter()
                .filter_map(|o| normalize_origin(o).ok())
                .collect();
            Ok(self.map_flows(&origins, job))
        })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        let Some(flow_ref) = point.flow else {
            // Amendment 38: an origin item stands for a whole origin, not for
            // anything a request carried, so it has no captured flow to host.
            // The lane serves it over a synthesized `GET <origin>/` instead;
            // any other flowless point is still an error.
            let flow = origin_request(point).ok_or_else(|| {
                anyhow::anyhow!("interim lane: point `{}` carries no flow", point.id)
            })?;
            return Ok(Box::new(InterimProbeHost {
                point: point.clone(),
                flow,
                legacy: None,
                synthetic: true,
                job,
                baseline: OnceCell::new(),
                baseline_peer: Mutex::new(None),
                held: Mutex::new(Vec::new()),
            }));
        };
        let Some(Flow::Http(flow)) = job.store().get(flow_ref.0) else {
            return Err(anyhow::anyhow!(
                "interim lane: the captured flow behind point `{}` is no longer in the store",
                point.id
            ));
        };
        // Re-enumerating is how the v2 point is matched back to the v1 point it
        // was built from: one mapping direction, so the two cannot drift.
        let legacy = crate::discover::enumerate(&flow)
            .into_iter()
            .find(|candidate| {
                point_id(flow.id, kind_for(&candidate.location), &candidate.name) == point.id
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "interim lane: point `{}` is no longer present in its captured request",
                    point.id
                )
            })?;

        Ok(Box::new(InterimProbeHost {
            point: point.clone(),
            flow,
            legacy: Some(legacy),
            synthetic: false,
            job,
            baseline: OnceCell::new(),
            baseline_peer: Mutex::new(None),
            held: Mutex::new(Vec::new()),
        }))
    }

    fn checks(&self) -> Vec<Arc<dyn Check>> {
        // The three passive checks only. The two active ones this lane used to
        // ship (`xss-reflected`, `open-redirect`) are owned by the T3 natives in
        // `aitm-scan-checks-http` since T3 PR 2a: the catalogue gives lanes
        // precedence over the native slot, so listing them here would refuse
        // the natives as id conflicts. `LegacyActiveCheck` stays as the test
        // vehicle for this lane's probe host until T2 retires the lane.
        vec![
            Arc::new(LegacyPassiveCheck {
                class: crate::passive::CLASS_REFLECTION,
                meta: passive_meta(
                    crate::passive::CLASS_REFLECTION,
                    "Reflected parameter value",
                    Confidence::Tentative,
                    "A request parameter value is echoed in the response body.",
                ),
            }),
            Arc::new(LegacyPassiveCheck {
                class: crate::passive::CLASS_SECURITY_HEADER,
                meta: passive_meta(
                    crate::passive::CLASS_SECURITY_HEADER,
                    "Missing security header",
                    Confidence::Firm,
                    "A response is missing a security header the browser relies on.",
                ),
            }),
            Arc::new(LegacyPassiveCheck {
                class: crate::passive::CLASS_COOKIE_FLAG,
                meta: passive_meta(
                    crate::passive::CLASS_COOKIE_FLAG,
                    "Cookie without Secure or HttpOnly",
                    Confidence::Firm,
                    "A `Set-Cookie` is missing the `Secure` and/or `HttpOnly` attribute.",
                ),
            }),
        ]
    }
}

/// The `GET <origin>/` flow an origin item is hosted over (amendment 38), or
/// `None` when the point is not an origin item or its URL is not an origin.
///
/// The request is the bare minimum: no headers and no body. The job client
/// applies the profile's version policy and the D7 session material to it on
/// the way out, exactly as it does for a captured point's baseline. The flow
/// has no response and no server connection: it describes a request that has
/// not been sent yet.
fn origin_request(point: &InsertionPoint) -> Option<HttpFlow> {
    if !point.id.starts_with("origin:") {
        return None;
    }
    let parsed = url::Url::parse(point.url.as_deref()?).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    let authority = match parsed.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Some(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".to_string(),
            scheme: parsed.scheme().to_string(),
            authority,
            path: "/".to_string(),
            version: aitm_core::HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: aitm_core::Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: aitm_core::ConnInfo {
            peer: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            ),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: aitm_core::FlowMeta::default(),
        intercept: aitm_core::InterceptState::Observed,
    })
}

/// The [`ProbeHost`] the interim lane builds for one insertion point.
///
/// It owns the job (so the check can outlive the lane's borrow), the captured
/// flow the point came from, and the v1 point that says how to mutate it.
pub struct InterimProbeHost {
    point: InsertionPoint,
    flow: HttpFlow,
    /// The v1 point [`ProbeHost::probe`] injects into, or `None` for an origin
    /// item (amendment 38), which has nothing to inject into.
    legacy: Option<InjectionPoint>,
    /// Whether [`InterimProbeHost::flow`] was synthesized for an origin item
    /// rather than captured from the wire, so [`ProbeHost::captured`] does not
    /// offer it as traffic that happened.
    synthetic: bool,
    job: Arc<dyn JobCtx>,
    baseline: OnceCell<ProbeResponse>,
    baseline_peer: Mutex<Option<SocketAddr>>,
    held: Mutex<Vec<Flow>>,
}

impl InterimProbeHost {
    /// Apply the job's session material and send through the job's budgeted
    /// client with `record: Never`, holding the flow for the engine.
    async fn send(&self, req: HttpRequest) -> anyhow::Result<ProbeResponse> {
        let flow = self.send_flow(req).await?;
        Ok(probe_response(&flow))
    }

    /// The send itself, handing the whole flow back for a caller that needs
    /// more of it than a [`ProbeResponse`] carries (the baseline's peer).
    async fn send_flow(&self, mut req: HttpRequest) -> anyhow::Result<HttpFlow> {
        if let Some(material) = self.job.session() {
            crate::session::apply(&material, &mut req);
        }
        let opts = SendOptions {
            // Spec D5: a probe flow reaches the store only through an issue's
            // re-recording, never through this send.
            record: RecordPolicy::Never,
            marks: Vec::new(),
            version: self.job.profile().http.version.into(),
        };
        let client = self.job.client();
        let flow = client.send_opts(req, opts).await?;
        self.hold(Flow::Http(flow.clone()));
        Ok(flow)
    }

    /// Keep the flow for the engine's re-recording, oldest dropped first.
    fn hold(&self, flow: Flow) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.push(flow);
        while held.len() > MAX_HELD_FLOWS {
            held.remove(0);
        }
    }

    /// This point's origin, for the same-origin rule on a raw probe.
    fn origin(&self) -> String {
        origin_key(&self.flow.request.scheme, &self.flow.request.authority)
    }
}

impl ProbeHost for InterimProbeHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.baseline
                .get_or_try_init(|| async {
                    let flow = self.send_flow(self.flow.request.clone()).await?;
                    // The address the baseline actually came from, so a raw
                    // probe dials it instead of re-resolving the name.
                    *self.baseline_peer.lock().unwrap_or_else(|e| e.into_inner()) =
                        flow.server_conn.as_ref().map(|conn| conn.peer);
                    Ok(probe_response(&flow))
                })
                .await
                .cloned()
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let Some(legacy) = self.legacy.as_ref() else {
                return Err(anyhow::anyhow!(
                    "interim lane: origin host `{}`: no insertion point to inject into",
                    self.point.id
                ));
            };
            let example = legacy.example.as_str();
            let value = match payload.mode {
                PayloadMode::Replace => payload.value.clone(),
                PayloadMode::Prefix => format!("{}{example}", payload.value),
                PayloadMode::Suffix => format!("{example}{}", payload.value),
            };
            let req = crate::inject::mutate_request(&self.flow.request, legacy, &value)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "interim lane: point `{}` cannot be mutated in its captured request",
                        self.point.id
                    )
                })?;
            self.send(req).await
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let parsed = url::Url::parse(&req.url).map_err(|_| {
                anyhow::anyhow!("interim lane: probe.raw needs an absolute http(s) URL")
            })?;
            let Some(host) = parsed.host_str() else {
                return Err(anyhow::anyhow!(
                    "interim lane: probe.raw needs an absolute http(s) URL"
                ));
            };
            let authority = match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            if origin_key(parsed.scheme(), &authority) != self.origin() {
                return Err(anyhow::anyhow!(
                    "interim lane: probe.raw is same-origin only"
                ));
            }

            let mut headers = HeaderMap::new();
            for (name, value) in &req.headers {
                headers.set(name, value);
            }
            let path = match parsed.query() {
                Some(query) => format!("{}?{query}", parsed.path()),
                None => parsed.path().to_string(),
            };
            self.send(HttpRequest {
                method: req.method.clone(),
                scheme: parsed.scheme().to_string(),
                authority,
                path,
                version: self.flow.request.version,
                headers,
                body: if req.body.is_empty() {
                    Body::Empty
                } else {
                    Body::Bytes(req.body.clone())
                },
                timestamp: SystemTime::now(),
            })
            .await
        })
    }

    /// Fresh on every call, straight from the job context (amendment 57): a
    /// canary value, never a key. `JobCtx::job_id` is the per-job key.
    fn marker(&self) -> String {
        self.job.marker()
    }

    fn budget_left(&self) -> u32 {
        self.job.budget_left()
    }

    fn deadline(&self) -> std::time::Instant {
        self.job.deadline()
    }

    fn profile(&self) -> &ScanProfile {
        self.job.profile()
    }

    fn cancelled(&self) -> bool {
        self.job.cancelled()
    }

    fn held_flows(&self) -> Vec<Flow> {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        Some(self.job.client())
    }

    fn captured(&self) -> Option<HttpFlow> {
        // A synthesized origin request is not traffic the scan observed, so a
        // passive check must not read it as a capture (amendment 38).
        if self.synthetic {
            return None;
        }
        Some(self.flow.clone())
    }

    fn charge(&self, units: u32) -> bool {
        // The one job budget the probes spend through the `JobClient`: a
        // stimulus that bypasses `probe` is charged against the same counter,
        // and nothing is charged when it cannot be covered.
        self.job.charge(units)
    }

    fn baseline_peer_addr(&self) -> Option<SocketAddr> {
        *self.baseline_peer.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One of the two shipped payload classes as a v2 [`Check`].
///
/// No longer in [`Lane::checks`]: the T3 natives own `xss-reflected` and
/// `open-redirect` (T3 PR 2a). Kept as the test vehicle for this lane's probe
/// host (recording policy, held flows, budget) and retired with the lane.
#[cfg(test)]
pub(crate) struct LegacyActiveCheck {
    def: CheckDefinition,
    meta: CheckMeta,
}

#[cfg(test)]
impl Check for LegacyActiveCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let cap = payload_cap(host.profile().speed, self.meta.technique) as usize;
            // `Clean` has to be earned: it needs at least one response that did
            // not confirm. A point whose every probe failed was never tested,
            // and saying "clean" about it is a false negative (orchestrator
            // ruling on Task 12).
            let mut answered = false;
            let mut last_error: Option<String> = None;
            for payload in self.def.payloads.iter().take(cap) {
                if host.cancelled() {
                    return inconclusive("the job was cancelled");
                }
                if host.budget_left() == 0 {
                    return inconclusive("the job's probe budget is spent");
                }
                let answer = match host
                    .probe(&Payload {
                        value: payload.value.clone(),
                        mode: PayloadMode::Replace,
                        bytes: None,
                    })
                    .await
                {
                    Ok(answer) => answer,
                    // The job is over: say so rather than calling the point
                    // clean on evidence that was never collected.
                    Err(err) if ends_the_run(&err) => return inconclusive(&err.to_string()),
                    // One probe failed; the next payload still deserves a try,
                    // but the failure is remembered so the verdict can say the
                    // point went untested if none of them land.
                    Err(err) => {
                        last_error = Some(err.to_string());
                        continue;
                    }
                };
                answered = true;
                let body = String::from_utf8_lossy(&answer.body);
                let Some(found) =
                    self.def
                        .confirm(answer.status.unwrap_or(0), &body, &answer.headers, payload)
                else {
                    continue;
                };
                return Verdict {
                    outcome: Outcome::Vulnerable,
                    confidence: self.meta.confidence_max,
                    evidence: Evidence {
                        payload: Some(payload.value.clone()),
                        matched: Some(Evidence::excerpt(&scrub(&found.matched))),
                        probe_flows: answer.flow.into_iter().collect(),
                        baseline_flow: None,
                        ..Evidence::default()
                    },
                    detail: format!(
                        "{} confirmed at {} `{}`",
                        self.meta.name,
                        wire_token(&point.kind),
                        point.name
                    ),
                    // AC T1-10: the engine reproduces the finding with exactly
                    // the assertion `confirm` judged it by.
                    poc_hint: Some(PocHint {
                        assertions: vec![self.def.success_assertion(payload)],
                        control: None,
                    }),
                    location: None,
                    more: Vec::new(),
                };
            }
            if !answered {
                if let Some(err) = last_error {
                    return inconclusive(&format!(
                        "every probe at {} `{}` failed: {err}",
                        wire_token(&point.kind),
                        point.name
                    ));
                }
            }
            Verdict {
                outcome: Outcome::Clean,
                confidence: Confidence::Tentative,
                evidence: Evidence::default(),
                detail: format!(
                    "no {} reaction at {} `{}`",
                    self.meta.class,
                    wire_token(&point.kind),
                    point.name
                ),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        })
    }
}

/// One of the three shipped passive checks as a v2 [`Check`]: it reads the
/// captured flow the point came from and sends nothing at all.
pub struct LegacyPassiveCheck {
    class: &'static str,
    meta: CheckMeta,
}

impl Check for LegacyPassiveCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        _point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(async move {
            let Some(flow) = host.captured() else {
                return inconclusive("the point carries no captured flow to read");
            };
            let Some(found) = crate::passive::passive_checks(&flow)
                .into_iter()
                .find(|finding| finding.class == self.class)
            else {
                return Verdict {
                    outcome: Outcome::Clean,
                    confidence: Confidence::Tentative,
                    evidence: Evidence::default(),
                    detail: format!("no {} finding on the captured response", self.class),
                    poc_hint: None,
                    location: None,
                    more: Vec::new(),
                };
            };
            Verdict {
                outcome: Outcome::Vulnerable,
                confidence: self.meta.confidence_max,
                evidence: Evidence {
                    payload: None,
                    matched: Some(Evidence::excerpt(&scrub(&flow.request.path))),
                    probe_flows: vec![FlowRef(flow.id)],
                    baseline_flow: None,
                    ..Evidence::default()
                },
                // `PassiveFinding::evidence` is a scanner constant, never
                // response text or a header value.
                detail: found.evidence,
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        })
    }
}

// ----------------------------------------------------------------- mapping

/// The v2 kind a v1 [`Location`] becomes. `Redirect` is not a kind in v2: it is
/// a query parameter carrying the `url` trait (spec D2).
/// Whether a flow is one of **this** job's crawl captures: both the job's
/// mark and [`CRAWL_MARK`], which only the two crawl paths put on a flow. A
/// probe stored under `record_probes: all` carries the job's mark alone and
/// stays what it is — the scanner's own traffic.
fn is_crawl_capture(flow: &HttpFlow, job_mark: &str) -> bool {
    let marks = &flow.metadata.marks;
    marks.iter().any(|mark| mark == job_mark) && marks.iter().any(|mark| mark == CRAWL_MARK)
}

fn kind_for(location: &Location) -> InsertionKind {
    match location {
        Location::Query | Location::Redirect => InsertionKind::Query,
        Location::BodyParam => InsertionKind::BodyParam,
        Location::Header => InsertionKind::Header,
        Location::Cookie => InsertionKind::Cookie,
        Location::PathSegment => InsertionKind::PathSegment,
    }
}

/// A point's stable id within a job: `<flow>:<kind>:<name>`, the kind in its
/// wire form so a point id can never disagree with what `scan.sitemap` prints.
fn point_id(flow: FlowId, kind: InsertionKind, name: &str) -> String {
    format!("{flow}:{}:{name}", wire_token(&kind))
}

/// What the observed value looks like (spec D2 `traits`).
///
/// `example` is the value `discover::enumerate` reported, which is already
/// `<redacted>` for every cookie and every secret-named point, so a redacted
/// value cannot be read as a number or an address.
fn traits_for(point: &InjectionPoint) -> Vec<PointTrait> {
    let mut traits = Vec::new();
    if point.location == Location::Redirect {
        traits.push(PointTrait::Url);
    }
    // A cookie's name is matched by the same vocabulary, so one clause covers
    // both halves of the plan's rule.
    if is_secret_name(&point.name) {
        traits.push(PointTrait::Session);
    }
    if point.example.parse::<i64>().is_ok() {
        traits.push(PointTrait::Number);
    }
    if point.example.contains('@') {
        traits.push(PointTrait::Email);
    }
    traits
}

/// A path with every purely numeric segment collapsed to `{id}` (spec D8.1).
fn path_template(path: &str) -> String {
    let raw = path.split('?').next().unwrap_or(path);
    let template = raw
        .split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    if template.is_empty() {
        "/".to_string()
    } else {
        template
    }
}

/// A site node's id: one node per `(method, scheme, host, port, path_template)`.
fn node_id(method: &str, origin: &str, path: &str) -> NodeId {
    format!("{method} {origin}{}", path_template(path))
}

/// An empty node for `flow`'s `(method, origin, path_template)`.
fn new_node(id: &NodeId, flow: &HttpFlow, origin: &str) -> SiteNode {
    let (scheme, authority) = origin.split_once("://").unwrap_or(("http", origin));
    let (host, port) = split_authority(authority);
    SiteNode {
        id: id.clone(),
        method: flow.request.method.clone(),
        scheme: scheme.to_string(),
        host: host.to_string(),
        // `origin` is in the normal form, so no port means the scheme's default.
        port: port.or_else(|| default_port(scheme)).unwrap_or(80),
        path_template: path_template(&flow.request.path),
        flows: Vec::new(),
        params: Vec::new(),
        auth: false,
        points: 0,
        audited: false,
    }
}

/// A probe's bounded, in-process view of the flow it produced.
fn probe_response(flow: &HttpFlow) -> ProbeResponse {
    let (status, headers, body) = match &flow.response {
        Some(response) => (
            Some(response.status),
            response
                .headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            bounded_body(&response.body),
        ),
        None => (None, Vec::new(), Vec::new()),
    };
    ProbeResponse {
        status,
        headers,
        body,
        elapsed_ms: flow
            .metadata
            .duration
            .map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
        flow: Some(FlowRef(flow.id)),
        ws_frames: None,
        l4: None,
    }
}

/// A response body cut to [`MAX_MATCH_BODY`], so matching is bounded work
/// whatever the target returns.
fn bounded_body(body: &Body) -> Vec<u8> {
    let bytes = crate::discover::body_bytes(body).unwrap_or_default();
    bytes[..bytes.len().min(MAX_MATCH_BODY)].to_vec()
}

/// Whether a probe error means this point is over — the job's budget, deadline
/// or cancellation, or the host's error ladder — rather than that one send
/// failed and the next payload still deserves a try.
///
/// Read from the typed [`ProbeRefused`] the job client raises, never from
/// words in the message: an upstream error that happens to say "canceled" is
/// one failed send, not the end of the run.
#[cfg(test)]
fn ends_the_run(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<ProbeRefused>(),
        Some(
            ProbeRefused::Budget
                | ProbeRefused::Deadline
                | ProbeRefused::Cancelled
                | ProbeRefused::HostLadder(_)
        )
    )
}

/// An inconclusive verdict carrying a scrubbed reason.
fn inconclusive(reason: &str) -> Verdict {
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: Evidence::excerpt(&scrub(reason)),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

// ------------------------------------------------------------------- metas

/// Every HTTP insertion kind the model knows, which is what a passive check
/// (reading a whole captured flow) applies to.
fn http_kinds() -> Vec<InsertionKind> {
    InsertionKind::ALL
        .into_iter()
        .filter(|kind| {
            !matches!(
                kind,
                InsertionKind::WsJsonValue
                    | InsertionKind::WsText
                    | InsertionKind::WsFormParam
                    | InsertionKind::WsBinary
                    | InsertionKind::WsHandshakeHeader
                    | InsertionKind::L4Field
            )
        })
        .collect()
}

/// The catalogue entry for the shipped reflected-XSS class.
///
/// The **id** is spec D8.2's literal check name (`xss-reflected`, so the
/// manual verb is `check.xss-reflected`); the **class** stays the issue class
/// the check emits (`reflected-xss`).
#[cfg(test)]
fn reflected_xss_meta() -> CheckMeta {
    CheckMeta {
        id: CHECK_XSS_REFLECTED.to_string(),
        name: "Reflected cross-site scripting".to_string(),
        class: crate::checks::CLASS_REFLECTED_XSS.to_string(),
        lanes: vec![LaneKind::Http],
        kinds: vec![InsertionKind::Query, InsertionKind::BodyParam],
        intensity: Intensity::Light,
        cost: CheckCost::Medium,
        technique: Technique::Reflected,
        severity: aitm_poc::Severity::Medium,
        confidence_max: Confidence::Certain,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        scope: CheckScope::Point,
        cwe: Some(79),
        description: "A benign marker sent in a parameter comes back unencoded in an HTML \
                      response, so an attacker-supplied value is rendered as markup."
            .to_string(),
        remediation: Some(
            "Contextually escape every value interpolated into a response and set a \
             Content-Security-Policy that forbids inline script."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    }
}

/// The catalogue entry for the shipped open-redirect class.
#[cfg(test)]
fn open_redirect_meta() -> CheckMeta {
    CheckMeta {
        id: crate::checks::CLASS_OPEN_REDIRECT.to_string(),
        name: "Open redirect".to_string(),
        class: crate::checks::CLASS_OPEN_REDIRECT.to_string(),
        lanes: vec![LaneKind::Http],
        kinds: vec![InsertionKind::Query],
        intensity: Intensity::Light,
        cost: CheckCost::Light,
        technique: Technique::Reflected,
        severity: aitm_poc::Severity::Low,
        confidence_max: Confidence::Certain,
        needs_baseline: false,
        wants_traits: Some(vec![PointTrait::Url]),
        targets_session: false,
        scope: CheckScope::Point,
        cwe: Some(601),
        description: "A redirect parameter sends the user agent to an off-origin host the \
                      scanner chose, so the target can be used to bounce a victim elsewhere."
            .to_string(),
        remediation: Some(
            "Redirect only to a path on the application's own origin, or to an entry of an \
             allow-list the request cannot extend."
                .to_string(),
        ),
        origin: CheckOrigin::Native,
    }
}

/// The catalogue entry for one of the three shipped passive checks.
fn passive_meta(
    class: &str,
    name: &str,
    confidence_max: Confidence,
    description: &str,
) -> CheckMeta {
    CheckMeta {
        id: class.to_string(),
        name: name.to_string(),
        class: class.to_string(),
        lanes: vec![LaneKind::Http],
        kinds: http_kinds(),
        intensity: Intensity::Passive,
        cost: CheckCost::Light,
        technique: Technique::Passive,
        severity: aitm_poc::Severity::Low,
        confidence_max,
        needs_baseline: false,
        wants_traits: None,
        targets_session: false,
        scope: CheckScope::Point,
        cwe: None,
        description: description.to_string(),
        remediation: None,
        origin: CheckOrigin::Native,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    use aitm_core::{
        Body, BrowserDriver, ClickTarget, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap,
        HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, NavOutcome,
        ProxyClient, RecordPolicy, ScopeEntry, ScopeRateGuard, SendOptions, StdGuard, Value,
    };
    use aitm_scan_model::{
        Discovery, InsertionKind, InsertionPoint, JobCtx, Lane, LaneKind, Outcome, Payload,
        PayloadMode, PointTrait, ProfileTarget, RawProbe, ScanProfile, SessionMaterial, UseBrowser,
    };
    use futures::future::BoxFuture;

    use crate::config::ScannerConfig;

    /// The job id every stub job answers, matching the plan's literal.
    const JOB: &str = "scan-1a2b3c4d";

    /// The origin every fixture flow belongs to.
    const ORIGIN: &str = "http://target.test";

    /// The upstream address the stub client answers from.
    const UPSTREAM: &str = "203.0.113.7:8080";

    // ---------------------------------------------------------------- fixtures

    fn request(scheme: &str, authority: &str, path: &str, headers: &[(&str, &str)]) -> HttpRequest {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpRequest {
            method: "GET".to_string(),
            scheme: scheme.to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            version: HttpVersion::Http11,
            headers: map,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpResponse {
            status,
            version: HttpVersion::Http11,
            headers: map,
            trailers: HeaderMap::new(),
            body: Body::Bytes(body.as_bytes().to_vec()),
            timestamp: SystemTime::now(),
        }
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: "127.0.0.1:0".parse().expect("loopback"),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    /// A captured (not replayed) HTTP flow with a plain 200 response.
    fn captured(scheme: &str, path: &str) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: request(scheme, "target.test", path, &[]),
            response: Some(response(200, &[("content-type", "text/plain")], "ok")),
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    // ------------------------------------------------------------ stub client

    /// What the stub answers with.
    #[derive(Clone, Copy)]
    enum Answer {
        /// 200 `text/html` echoing the named query parameter into the body.
        EchoHtml(&'static str),
        /// 302 whose `Location` is the named query parameter's value.
        RedirectTo(&'static str),
        /// A fixed status, content type and body.
        Fixed(u16, &'static str, &'static str),
        /// Every send fails with this message.
        Error(&'static str),
    }

    /// Read one decoded query parameter out of a request path.
    fn query_value(path: &str, name: &str) -> String {
        let Some((_, query)) = path.split_once('?') else {
            return String::new();
        };
        url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    }

    /// A `ProxyClient` that performs no I/O and records every request and the
    /// [`SendOptions`] it was handed.
    struct StubClient {
        answer: Answer,
        seen: Mutex<Vec<(HttpRequest, SendOptions)>>,
    }

    impl StubClient {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer,
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> std::sync::MutexGuard<'_, Vec<(HttpRequest, SendOptions)>> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn calls(&self) -> usize {
            self.seen().len()
        }

        fn options(&self) -> Vec<SendOptions> {
            self.seen().iter().map(|(_, o)| o.clone()).collect()
        }

        fn header_values(&self, name: &str) -> Vec<String> {
            self.seen()
                .iter()
                .filter_map(|(req, _)| req.headers.get(name).map(str::to_string))
                .collect()
        }
    }

    impl ProxyClient for StubClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            opts: SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async move {
                self.seen().push((req.clone(), opts));
                if let Answer::Error(message) = self.answer {
                    return Err(anyhow::anyhow!(message));
                }
                let response = match self.answer {
                    Answer::EchoHtml(name) => response(
                        200,
                        &[("content-type", "text/html; charset=utf-8")],
                        &format!("<html><body>{}</body></html>", query_value(&req.path, name)),
                    ),
                    Answer::RedirectTo(name) => response(
                        302,
                        &[("location", &query_value(&req.path, name))],
                        "redirecting",
                    ),
                    Answer::Fixed(status, ctype, body) => {
                        response(status, &[("content-type", ctype)], body)
                    }
                    // Returned above, before anything is built.
                    Answer::Error(_) => unreachable!("an erroring stub answers no response"),
                };
                let mut metadata = FlowMeta {
                    is_replay: true,
                    ..FlowMeta::default()
                };
                metadata.duration = Some(Duration::from_millis(12));
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(response),
                    client_conn: conn(),
                    server_conn: Some(ConnInfo {
                        peer: UPSTREAM.parse().expect("a socket address"),
                        ..conn()
                    }),
                    metadata,
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    /// A `ProxyClient` that answers from a queue — an error, or a plain-text
    /// 200 with the given status — and a plain 200 once the queue is empty.
    struct ScriptedClient {
        queue: Mutex<std::collections::VecDeque<anyhow::Result<u16>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedClient {
        fn new(script: Vec<anyhow::Result<u16>>) -> Arc<Self> {
            Arc::new(Self {
                queue: Mutex::new(script.into_iter().collect()),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ProxyClient for ScriptedClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            _opts: SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let next = self
                    .queue
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .pop_front();
                let status = match next {
                    Some(Err(err)) => return Err(err),
                    Some(Ok(status)) => status,
                    None => 200,
                };
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(response(status, &[("content-type", "text/plain")], "ok")),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta {
                        is_replay: true,
                        ..FlowMeta::default()
                    },
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    // -------------------------------------------------------- site stub client

    /// The landing page of the stub site: two anchors with query parameters,
    /// one GET form, and one link off the origin the crawl must never follow.
    const SITE_INDEX: &str = concat!(
        "<html><body>",
        "<a href=\"/search?q=x\">search</a>",
        "<a href=\"/redirect?to=http://away.test/\">redirect</a>",
        "<a href=\"http://elsewhere.test/evil\">off origin</a>",
        "<form action=\"/find\" method=\"get\"><input name=\"term\"></form>",
        "</body></html>",
    );

    /// A `ProxyClient` serving that tiny site, recording every request with the
    /// [`SendOptions`] it was handed and — like the real `PipelineClient` —
    /// inserting the flow into the store when the caller asked to record it.
    struct SiteClient {
        store: Arc<dyn FlowStore>,
        seen: Mutex<Vec<(HttpRequest, SendOptions)>>,
        /// Refuse every request after the root with a spent-budget refusal,
        /// the way the `JobClient` ends a crawl mid-page.
        refuse_after_root: bool,
    }

    impl SiteClient {
        fn new(store: &Arc<dyn FlowStore>) -> Arc<Self> {
            Arc::new(Self {
                store: Arc::clone(store),
                seen: Mutex::new(Vec::new()),
                refuse_after_root: false,
            })
        }

        fn refusing(store: &Arc<dyn FlowStore>) -> Arc<Self> {
            Arc::new(Self {
                store: Arc::clone(store),
                seen: Mutex::new(Vec::new()),
                refuse_after_root: true,
            })
        }

        fn seen(&self) -> std::sync::MutexGuard<'_, Vec<(HttpRequest, SendOptions)>> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner())
        }

        fn calls(&self) -> usize {
            self.seen().len()
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.seen().iter().map(|(req, _)| req.clone()).collect()
        }

        fn options(&self) -> Vec<SendOptions> {
            self.seen().iter().map(|(_, opts)| opts.clone()).collect()
        }

        /// `METHOD path` for every request the crawl made, in order.
        fn trail(&self) -> Vec<String> {
            self.requests()
                .iter()
                .map(|req| format!("{} {}", req.method, req.path))
                .collect()
        }
    }

    impl ProxyClient for SiteClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            self.send_opts(req, SendOptions::default())
        }

        fn send_opts(
            &self,
            req: HttpRequest,
            opts: SendOptions,
        ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async move {
                let path = req.path.split('?').next().unwrap_or("/").to_string();
                let marks = opts.marks.clone();
                let record = opts.record;
                self.seen().push((req.clone(), opts));
                if self.refuse_after_root && path != "/" {
                    return Err(anyhow::Error::new(ProbeRefused::Budget));
                }
                let response = match path.as_str() {
                    "/" => response(
                        200,
                        &[("content-type", "text/html; charset=utf-8")],
                        SITE_INDEX,
                    ),
                    "/search" | "/find" => response(
                        200,
                        &[("content-type", "text/html; charset=utf-8")],
                        "<html><body>ok</body></html>",
                    ),
                    "/redirect" => response(302, &[("location", "/")], ""),
                    _ => response(404, &[("content-type", "text/plain")], "not found"),
                };
                let flow = HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(response),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta {
                        // The pipeline client stamps a reissued send as a
                        // replay; a crawl capture is one, and the lane must
                        // still read it as attack surface.
                        is_replay: true,
                        marks,
                        ..FlowMeta::default()
                    },
                    intercept: InterceptState::Observed,
                };
                if record == RecordPolicy::Always {
                    self.store.insert(Flow::Http(flow.clone()));
                }
                Ok(flow)
            })
        }
    }

    // ----------------------------------------------------------- stub browser

    /// A browser whose every page links to fifty more on the origin, so an
    /// uncapped crawl would navigate fifty times. Each navigation lands one
    /// captured flow in the store and is counted.
    struct LinkyBrowser {
        store: Arc<dyn FlowStore>,
        navigations: std::sync::atomic::AtomicUsize,
    }

    impl BrowserDriver for LinkyBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.navigations.fetch_add(1, Ordering::SeqCst);
                let path = url::Url::parse(&url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_else(|_| "/".to_string());
                self.store.insert(Flow::Http(captured("http", &path)));
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
        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { Ok(Value::Null) })
        }
        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async {
                Ok((1..=50)
                    .map(|i| format!("<a href=\"/p{i}\">p{i}</a>"))
                    .collect::<String>())
            })
        }
    }

    /// A browser whose single navigation inserts one captured flow into the
    /// store, the way a real proxied navigation lands in it.
    struct StubBrowser {
        store: Arc<dyn FlowStore>,
        path: &'static str,
    }

    impl BrowserDriver for StubBrowser {
        fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
            let url = url.to_string();
            Box::pin(async move {
                self.store.insert(Flow::Http(captured("http", self.path)));
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
        fn eval(&self, _expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
            Box::pin(async { Ok(Value::Null) })
        }
        fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
            Box::pin(async { Ok("<html><body>no links</body></html>".to_string()) })
        }
    }

    // --------------------------------------------------------------- stub job

    struct TestJob {
        profile: ScanProfile,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
        browser: Option<Arc<dyn BrowserDriver>>,
        session: Option<Arc<SessionMaterial>>,
        budget: u32,
        charged: AtomicU32,
        /// Set by a test that wants the job to read as cancelled.
        cancelled: std::sync::atomic::AtomicBool,
        /// Every `(origin, reason)` the lane reported through
        /// [`JobCtx::report_crawl_error`].
        crawl_errors: Mutex<Vec<(String, String)>>,
        /// Forms the lane reported through [`JobCtx::report_forms_submitted`].
        forms_submitted: AtomicU64,
    }

    impl TestJob {
        fn new(store: Arc<dyn FlowStore>, client: Arc<dyn ProxyClient>) -> Self {
            let guard = StdGuard::default();
            guard.add_scope(ScopeEntry {
                host: "target.test".to_string(),
            });
            Self {
                profile: ScanProfile::default(),
                client,
                store,
                guard: Arc::new(guard),
                browser: None,
                session: None,
                budget: 1000,
                charged: AtomicU32::new(0),
                cancelled: std::sync::atomic::AtomicBool::new(false),
                crawl_errors: Mutex::new(Vec::new()),
                forms_submitted: AtomicU64::new(0),
            }
        }

        fn forms_submitted(&self) -> u64 {
            self.forms_submitted.load(Ordering::SeqCst)
        }

        fn charged(&self) -> u32 {
            self.charged.load(Ordering::SeqCst)
        }

        fn crawl_errors(&self) -> Vec<(String, String)> {
            self.crawl_errors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl JobCtx for TestJob {
        fn job_id(&self) -> &str {
            JOB
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
            self.browser.clone()
        }
        fn session(&self) -> Option<Arc<SessionMaterial>> {
            self.session.clone()
        }
        fn charge(&self, units: u32) -> bool {
            if self.budget_left() < units {
                return false;
            }
            self.charged.fetch_add(units, Ordering::SeqCst);
            true
        }
        fn budget_left(&self) -> u32 {
            self.budget.saturating_sub(self.charged())
        }
        fn deadline(&self) -> Instant {
            Instant::now() + Duration::from_secs(60)
        }
        fn cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn marker(&self) -> String {
            "aitm7f3a0000".to_string()
        }
        fn report_crawl_error(&self, origin: &str, reason: &str) {
            self.crawl_errors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((origin.to_string(), reason.to_string()));
        }
        fn report_forms_submitted(&self, count: u64) {
            self.forms_submitted.fetch_add(count, Ordering::SeqCst);
        }
    }

    // ----------------------------------------------------------------- helpers

    fn target(origins: &[&str]) -> ProfileTarget {
        ProfileTarget {
            origins: origins.iter().map(|o| (*o).to_string()).collect(),
            l4: Vec::new(),
        }
    }

    fn lane() -> Arc<dyn Lane> {
        InterimHttpLane::new(ScannerConfig::default())
    }

    /// The one origin item [`crate::scheduler::plan`] builds for `origins` and
    /// `points`, so these tests run against the real amendment-38 shape rather
    /// than a hand-written copy of it.
    fn origin_item(origins: &[&str], points: &[InsertionPoint]) -> InsertionPoint {
        let profile = ScanProfile {
            target: target(origins),
            ..ScanProfile::default()
        };
        let mut items = crate::scheduler::plan(points, &[], &[], &profile).origin_points;
        assert_eq!(items.len(), 1, "one origin in the set");
        items.remove(0)
    }

    /// A job whose crawl is off (`max_pages: 0`, spec D2), for the tests that
    /// are about the probes or the mapping of what the store already holds:
    /// discovery sends nothing, so the stub client's call count is the
    /// probes' alone.
    fn no_crawl_job(store: Arc<dyn FlowStore>, client: Arc<dyn ProxyClient>) -> TestJob {
        let mut job = TestJob::new(store, client);
        job.profile.crawl.max_pages = 0;
        job
    }

    async fn discover_origins(job: &TestJob, origins: &[&str]) -> Discovery {
        lane()
            .discover(&target(origins), job)
            .await
            .expect("the interim lane discovers")
    }

    async fn discover_with(job: &TestJob) -> Discovery {
        discover_origins(job, &[ORIGIN]).await
    }

    fn point_named<'a>(discovery: &'a Discovery, name: &str) -> &'a InsertionPoint {
        discovery
            .points
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("a point named {name} was discovered"))
    }

    fn check_named(id: &str) -> Arc<dyn aitm_scan_model::Check> {
        lane()
            .checks()
            .into_iter()
            .find(|c| c.meta().id == id)
            .unwrap_or_else(|| legacy_active(id))
    }

    /// The two legacy active checks, no longer in `checks()` since the T3
    /// natives own their ids (PR 2a); still the vehicle these tests drive the
    /// lane's probe host with.
    fn legacy_active(id: &str) -> Arc<dyn aitm_scan_model::Check> {
        legacy_active_checks()
            .into_iter()
            .find(|c| c.meta().id == id)
            .unwrap_or_else(|| panic!("the lane ships no {id} check"))
    }

    fn payload(value: &str) -> Payload {
        Payload {
            value: value.to_string(),
            mode: PayloadMode::Replace,
            bytes: None,
        }
    }

    // ------------------------------------------------------------------- tests

    /// Spec D1/D2: the v1 `Location` vocabulary becomes v2 `InsertionKind`s and
    /// traits, and the site map collapses numeric path segments.
    #[tokio::test]
    async fn discover_maps_v1_points_to_v2_kinds() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured(
            "http",
            "/search?q=1&next=http://elsewhere.test/",
        )));
        store.insert(Flow::Http(captured("http", "/account/42")));
        let job = no_crawl_job(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );

        let discovery = discover_with(&job).await;

        let q = point_named(&discovery, "q");
        assert_eq!(q.kind, InsertionKind::Query);
        assert_eq!(q.lane, LaneKind::Http);
        assert!(!q.traits.contains(&PointTrait::Url), "{:?}", q.traits);
        assert_eq!(q.frequency, 1);
        assert_eq!(q.method.as_deref(), Some("GET"));
        assert_eq!(
            q.url.as_deref(),
            Some("http://target.test/search?q=1&next=http://elsewhere.test/")
        );

        let next = point_named(&discovery, "next");
        assert_eq!(next.kind, InsertionKind::Query);
        assert!(next.traits.contains(&PointTrait::Url), "{:?}", next.traits);

        let segment = point_named(&discovery, "42");
        assert_eq!(segment.kind, InsertionKind::PathSegment);

        let templates: Vec<&str> = discovery
            .nodes
            .iter()
            .map(|n| n.path_template.as_str())
            .collect();
        assert!(templates.contains(&"/search"), "{templates:?}");
        assert!(templates.contains(&"/account/{id}"), "{templates:?}");
    }

    /// Spec D5 "Record policy": a browser-crawl navigation is a real capture,
    /// so the lane marks exactly the flows the store diff produced.
    #[tokio::test]
    async fn discover_marks_crawl_flows_and_charges() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let older = captured("http", "/already-here?a=1");
        let older_id = older.id;
        store.insert(Flow::Http(older));

        let mut job = TestJob::new(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled?b=2",
        }));

        let _ = discover_with(&job).await;

        let crawled: Vec<Flow> = store
            .list()
            .into_iter()
            .filter(|id| *id != older_id)
            .filter_map(|id| store.get(id))
            .collect();
        assert_eq!(crawled.len(), 1, "the navigation inserted one flow");
        assert_eq!(
            crawled[0].metadata().marks,
            vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()]
        );

        let older = store.get(older_id).expect("the older flow is still there");
        assert!(
            older.metadata().marks.is_empty(),
            "a pre-existing flow is not marked: {:?}",
            older.metadata().marks
        );
        assert!(job.charged() >= 1, "the crawl is charged to the job budget");
    }

    /// `max_pages: 0` is the one setting that turns *every* crawl off (spec
    /// D2): the lane maps what the proxy already captured, sends nothing and
    /// charges nothing.
    #[tokio::test]
    async fn discover_with_the_crawl_off_uses_captured_flows_only() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = SiteClient::new(&store);
        let job = no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _);

        let discovery = discover_with(&job).await;

        assert_eq!(point_named(&discovery, "q").kind, InsertionKind::Query);
        assert_eq!(client.calls(), 0, "max_pages: 0 fetches nothing");
        assert_eq!(store.list().len(), 1, "and records nothing");
        assert_eq!(job.charged(), 0, "no crawl, no charge");
    }

    /// AC T1-10: the native reflected-XSS check supplies a `PocHint`, so the
    /// engine can reproduce the finding, and its probe flows are held in memory
    /// rather than stored.
    #[tokio::test]
    async fn reflected_xss_supplies_a_poc_hint() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::EchoHtml("q"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("xss-reflected").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, aitm_scan_model::Confidence::Certain);
        assert!(verdict.poc_hint.is_some(), "AC T1-10 needs a hint");
        assert_eq!(verdict.evidence.probe_flows.len(), 1);
        assert!(!host.held_flows().is_empty(), "the probe flow is held");
        assert!(
            client
                .options()
                .iter()
                .all(|o| o.record == RecordPolicy::Never),
            "every probe is sent with record: Never"
        );
    }

    /// The open-redirect check is aimed by the `url` trait and confirms on the
    /// sentinel host in `Location`.
    #[tokio::test]
    async fn open_redirect_wants_url_and_confirms_on_location() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured(
            "http",
            "/go?next=http://elsewhere.test/",
        )));
        let client = StubClient::new(Answer::RedirectTo("next"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "next").clone();
        let check = check_named("open-redirect");
        assert_eq!(
            check.meta().wants_traits,
            Some(vec![PointTrait::Url]),
            "the check is aimed at url-valued points"
        );

        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");
        let verdict = check.run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert!(verdict.poc_hint.is_some());
    }

    /// Orchestrator ruling on Task 12: a point whose every probe failed was
    /// never actually tested, so it is inconclusive — `Clean` needs at least
    /// one response that did not confirm.
    #[tokio::test]
    async fn all_probes_failing_is_inconclusive_not_clean() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Error("upstream refused the connection"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("xss-reflected").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, aitm_scan_model::Confidence::Tentative);
        assert!(
            verdict.detail.contains("upstream refused the connection"),
            "the detail names the last error: {}",
            verdict.detail
        );
        assert!(verdict.poc_hint.is_none());
        assert!(verdict.evidence.probe_flows.is_empty());
        assert!(client.calls() > 0, "the probes were attempted");
        assert!(
            host.held_flows().is_empty(),
            "a failed probe records nothing"
        );
    }

    /// A target that reflects nothing is clean, not vulnerable.
    #[tokio::test]
    async fn clean_target_yields_clean() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "nothing to see"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("xss-reflected").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert!(verdict.poc_hint.is_none());
    }

    /// `probe.raw` is same-origin only (spec D4).
    #[tokio::test]
    async fn probe_raw_refuses_other_origin() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let err = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://elsewhere.test/".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("an off-origin raw probe is refused");

        assert!(
            err.to_string().contains("same-origin"),
            "the refusal names the rule: {err}"
        );
        assert_eq!(client.calls(), 0, "nothing was sent");
    }

    /// A `technique: passive` check reads the captured flow and sends nothing.
    #[tokio::test]
    async fn passive_check_reads_the_captured_flow_without_sending() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let mut flow = captured("https", "/account?page=about");
        flow.response = Some(response(
            200,
            &[("content-type", "text/plain")],
            "no headers here",
        ));
        store.insert(Flow::Http(flow));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_origins(&job, &["https://target.test"]).await;
        let point = point_named(&discovery, "page").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("security-header").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(client.calls(), 0, "a passive check never sends");
    }

    /// Spec D5: a host holds at most sixteen probe flows per point.
    #[tokio::test]
    async fn held_flows_are_bounded_to_16() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        for i in 0..20 {
            host.probe(&payload(&format!("v{i}")))
                .await
                .expect("the stub answers");
        }

        assert_eq!(host.held_flows().len(), 16);
        assert_eq!(client.calls(), 20);
    }

    /// Spec D7: session material is merged into every probe, and never appears
    /// in anything the host hands back.
    #[tokio::test]
    async fn session_material_is_applied_to_probes() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let mut job = no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _);
        job.session = Some(Arc::new(SessionMaterial {
            cookies: vec![("sid".to_string(), "abc".to_string())],
            headers: Vec::new(),
        }));
        let job = Arc::new(job);

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let answer = host.probe(&payload("x")).await.expect("the stub answers");

        let cookies = client.header_values("cookie");
        assert_eq!(cookies.len(), 1, "one probe, one cookie header");
        assert!(cookies[0].contains("sid=abc"), "{cookies:?}");
        assert!(
            !format!("{answer:?}").contains("abc"),
            "a session value must not reach a debug line"
        );
    }

    /// The coordinator's Task 8 contract: every send the host makes — probe,
    /// baseline and raw — carries `record: Never`, so a probe flow reaches the
    /// store only through an issue's re-recording.
    #[tokio::test]
    async fn every_send_the_host_makes_is_record_never() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        host.probe(&payload("x")).await.expect("the stub answers");
        host.baseline().await.expect("the stub answers");
        host.probe_raw(RawProbe {
            method: "GET".to_string(),
            url: "http://target.test/search?q=hello".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .expect("a same-origin raw probe is allowed");

        let options = client.options();
        assert_eq!(options.len(), 3, "probe, baseline and raw probe");
        assert!(
            options.iter().all(|o| o.record == RecordPolicy::Never),
            "{options:?}"
        );
    }

    /// The coordinator's T3 hand-off: `ProbeHost::charge` spends the job's one
    /// budget for real, so a stimulus that bypasses `probe` is still counted.
    #[tokio::test]
    async fn charge_spends_the_jobs_budget() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        assert!(host.charge(3), "the job can afford three units");
        assert_eq!(job.charged(), 3, "the job's own budget was spent");
        assert_eq!(client.calls(), 0, "a charge sends nothing");
    }

    /// A charge the budget cannot cover is refused and spends nothing.
    #[tokio::test]
    async fn charge_is_refused_when_the_budget_cannot_cover_it() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let mut job = no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _);
        job.budget = 2;
        let job = Arc::new(job);

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        assert!(!host.charge(3), "two units cannot cover three");
        assert_eq!(job.charged(), 0, "a refused charge spends nothing");
    }

    /// The coordinator's T3 hand-off: the host reports the address the baseline
    /// response actually came from, so a raw probe dials the validated address
    /// instead of re-resolving the name.
    #[tokio::test]
    async fn baseline_peer_addr_comes_from_the_baseline_flow() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        assert_eq!(
            host.baseline_peer_addr(),
            None,
            "nothing is known before the baseline is taken"
        );

        host.baseline().await.expect("the stub answers");

        assert_eq!(
            host.baseline_peer_addr(),
            Some(UPSTREAM.parse().expect("a socket address")),
            "the address the baseline came from"
        );
    }

    /// The baseline is sent once and reused.
    #[tokio::test]
    async fn baseline_is_cached() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(204, "text/plain", ""));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let first = host.baseline().await.expect("the stub answers");
        let second = host.baseline().await.expect("the cached baseline");

        assert_eq!(first.status, Some(204));
        assert_eq!(second.status, Some(204));
        assert_eq!(client.calls(), 1, "the baseline is sent once");
    }

    /// `use_browser: never` keeps the lane off the **browser** even when one
    /// is available (spec D2's `crawl.use_browser`) — the client crawl still
    /// runs, because D5 asks for the crawl captures either way and only
    /// `max_pages: 0` turns the crawl itself off.
    #[tokio::test]
    async fn use_browser_never_skips_the_browser_not_the_client_crawl() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));
        job.profile.crawl.use_browser = UseBrowser::Never;

        let discovery = discover_with(&job).await;

        let paths: Vec<String> = store
            .list()
            .into_iter()
            .filter_map(|id| match store.get(id) {
                Some(Flow::Http(flow)) => Some(flow.request.path),
                _ => None,
            })
            .collect();
        assert!(
            !paths.iter().any(|p| p.starts_with("/crawled")),
            "the browser was not driven: {paths:?}"
        );
        assert!(
            client.trail().contains(&"GET /".to_string()),
            "the client crawl ran instead: {:?}",
            client.trail()
        );
        assert_eq!(point_named(&discovery, "q").kind, InsertionKind::Query);
    }

    /// Amendment 53: the interim lane feeds `crawl.forms_submitted` too — the
    /// one form its client crawl posted reaches the job through
    /// `JobCtx::report_forms_submitted`, and the skipped one beside it does
    /// not count there (`max_depth: 1` parses the seed page only).
    #[tokio::test]
    async fn the_client_crawl_reports_the_forms_it_submitted() {
        const PAGE: &str = "<html><body>\
             <form action=\"/comments\" method=\"post\"><input name=\"comment\"></form>\
             <form action=\"/account/delete\" method=\"post\"><input name=\"id\"></form>\
             </body></html>";
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = StubClient::new(Answer::Fixed(200, "text/html; charset=utf-8", PAGE));
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.profile.crawl.max_depth = 1;

        let _ = discover_with(&job).await;

        let trail: Vec<String> = client
            .seen()
            .iter()
            .map(|(req, _)| format!("{} {}", req.method, req.path))
            .collect();
        assert_eq!(
            trail,
            vec!["GET /", "POST /comments"],
            "one form posted, the delete form left alone"
        );
        assert_eq!(job.forms_submitted(), 1);
    }

    // ---- wave-2/3 fix task ---------------------------------------------------

    /// Whether a probe error ends the run is read from the typed
    /// `ProbeRefused`, never from words in the message: an upstream error that
    /// happens to say "canceled" is one failed send and the next payload is
    /// still tried, while a typed `Deadline` ends the point with no further
    /// payload.
    #[tokio::test]
    async fn an_upstream_error_mentioning_cancel_does_not_end_the_point() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = ScriptedClient::new(vec![
            Err(anyhow::anyhow!("operation was canceled: connection closed")),
            Ok(200),
        ]);
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));
        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("xss-reflected").run(&point, &*host).await;

        assert!(
            client.calls() >= 2,
            "the second payload was not attempted after an upstream error: {} call(s), {:?} {}",
            client.calls(),
            verdict.outcome,
            verdict.detail
        );
        assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);

        let client = ScriptedClient::new(vec![Err(anyhow::Error::new(
            crate::client::ProbeRefused::Deadline,
        ))]);
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("xss-reflected").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
        assert!(verdict.detail.contains("deadline"), "{}", verdict.detail);
        assert_eq!(
            client.calls(),
            1,
            "a typed deadline refusal ends the point: no further payload"
        );
    }

    /// Spec D5 "one budget per job": the crawl's navigations are probes, so
    /// `crawl.max_pages` is capped by what the budget has left *before* the
    /// crawl, not charged after the fact. Budget 3, `max_pages: 50`, a browser
    /// that would yield fifty pages: at most three navigations, and the budget
    /// is spent.
    #[tokio::test]
    async fn the_crawl_cannot_outrun_the_probe_budget() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let browser = Arc::new(LinkyBrowser {
            store: Arc::clone(&store),
            navigations: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut job = TestJob::new(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );
        job.browser = Some(Arc::clone(&browser) as Arc<dyn BrowserDriver>);
        job.budget = 3;
        job.profile.crawl.max_pages = 50;

        let _ = discover_with(&job).await;

        let navigations = browser.navigations.load(Ordering::SeqCst);
        assert!(
            (1..=3).contains(&navigations),
            "{navigations} navigations against a budget of 3"
        );
        assert_eq!(
            job.budget_left(),
            0,
            "the crawl spent exactly what the budget had left (charged {})",
            job.charged()
        );
    }

    /// A crawl the crawler refused — here the seed is out of the job's scope —
    /// surfaces its reason instead of being swallowed, so the caller can say
    /// why discovery ran on captures alone; a crawl that ran, or was skipped
    /// by design, reports nothing.
    #[tokio::test]
    async fn a_refused_crawl_reports_its_reason() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let mut job = TestJob::new(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));
        let lane = InterimHttpLane {
            cfg: ScannerConfig::default(),
        };

        let BrowserCrawl::Failed(reason) = lane.crawl_origin("http://nobody.test", &job).await
        else {
            panic!("an out-of-scope seed is a failed crawl");
        };
        assert!(
            reason.contains("nobody.test") || reason.contains("scope"),
            "the reason names the refusal: {reason}"
        );
        assert_eq!(job.charged(), 0, "a refused crawl spends nothing");

        assert_eq!(
            lane.crawl_origin(ORIGIN, &job).await,
            BrowserCrawl::Ran,
            "a crawl that ran says so"
        );
        assert!(job.charged() >= 1);

        job.profile.crawl.use_browser = UseBrowser::Never;
        assert_eq!(
            lane.crawl_origin("http://nobody.test", &job).await,
            BrowserCrawl::NotApplicable,
            "a crawl skipped by design is not a failure"
        );
    }

    /// T7/T2 live runs (2026-11-01): a browser crawl that fails outright is
    /// reported through `JobCtx::report_crawl_error` — once, naming the
    /// origin — and the client crawl runs in its place, so the job does not
    /// proceed on captured flows alone.
    #[tokio::test]
    async fn a_failed_browser_crawl_is_reported_and_the_client_crawl_runs() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = StubClient::new(Answer::Fixed(
            200,
            "text/html",
            "<html><body><a href=\"/next?n=1\">next</a></body></html>",
        ));
        let mut job = TestJob::new(
            Arc::clone(&store),
            Arc::clone(&client) as Arc<dyn ProxyClient>,
        );
        // The out-of-scope seed makes the browser crawl fail (see
        // `a_refused_crawl_reports_its_reason`).
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));

        lane()
            .discover(&target(&["http://nobody.test"]), &job)
            .await
            .expect("discovery still completes after a failed crawl");

        let errors = job.crawl_errors();
        assert_eq!(errors.len(), 1, "one failed crawl, one report: {errors:?}");
        assert_eq!(errors[0].0, "http://nobody.test");
        assert!(
            errors[0].1.contains("nobody.test") || errors[0].1.contains("scope"),
            "the reason says why: {}",
            errors[0].1
        );

        // The client crawl ran instead: the seed GET, then the link it found.
        let trail: Vec<String> = client
            .seen()
            .iter()
            .map(|(req, _)| {
                format!(
                    "{} {}://{}{}",
                    req.method, req.scheme, req.authority, req.path
                )
            })
            .collect();
        assert_eq!(
            trail,
            vec![
                "GET http://nobody.test/".to_string(),
                "GET http://nobody.test/next?n=1".to_string(),
            ],
            "the client crawl's GETs"
        );
        assert_eq!(
            job.charged(),
            0,
            "a refused browser crawl spends nothing; the client crawl is metered by the client"
        );
    }

    // ---- tester additions ---------------------------------------------------

    /// The attack surface is what the target was asked for: a replay (the
    /// scanner's own traffic), a flow to another origin and a non-HTTP flow
    /// contribute no point and no node, while the origin's own captures do —
    /// whatever case or default port their authority was captured with.
    #[tokio::test]
    async fn replays_other_origins_and_non_http_flows_are_not_attack_surface() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let mut replay = captured("http", "/replayed?r=1");
        replay.metadata.is_replay = true;
        store.insert(Flow::Http(replay));
        let mut elsewhere = captured("http", "/other?o=1");
        elsewhere.request.authority = "elsewhere.test".to_string();
        store.insert(Flow::Http(elsewhere));
        let mut tls = captured("https", "/secure?s=1");
        tls.request.scheme = "https".to_string();
        store.insert(Flow::Http(tls));
        let mut odd_case = captured("http", "/mine?m=1");
        odd_case.request.authority = "TARGET.TEST:80".to_string();
        store.insert(Flow::Http(odd_case));
        let job = no_crawl_job(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );

        let discovery = discover_with(&job).await;

        let names: Vec<&str> = discovery.points.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["m"], "only the origin's own capture: {names:?}");
        assert_eq!(discovery.nodes.len(), 1, "{:?}", discovery.nodes);
        assert_eq!(discovery.nodes[0].host, "target.test");
        assert_eq!(discovery.nodes[0].port, 80);
        assert_eq!(discovery.nodes[0].path_template, "/mine");

        // An origin nobody captured maps to nothing, and an unparsable origin
        // is skipped rather than matched against everything.
        let empty = discover_origins(&job, &["http://nobody.test", "not-an-origin"]).await;
        assert!(empty.points.is_empty() && empty.nodes.is_empty());
    }

    /// `probe.raw` needs an absolute URL on the point's origin: a relative path,
    /// a scheme-less string and a userinfo-bearing URL to the same host are all
    /// refused before anything is sent.
    #[tokio::test]
    async fn probe_raw_refuses_relative_and_malformed_urls() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        for bad in [
            "/search?q=1",
            "target.test/search",
            "",
            "http://target.test:8080/",
            "https://target.test/",
            "http://user:pw@elsewhere.test/",
        ] {
            let err = host
                .probe_raw(RawProbe {
                    method: "GET".to_string(),
                    url: bad.to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                })
                .await
                .expect_err("a non-origin raw probe is refused");
            assert!(
                err.to_string().contains("probe.raw"),
                "`{bad}`: the refusal names the verb: {err}"
            );
        }
        assert_eq!(client.calls(), 0, "nothing was sent");

        // The same host with the default port spelled out is the same origin.
        host.probe_raw(RawProbe {
            method: "POST".to_string(),
            url: "http://TARGET.TEST:80/search?q=x".to_string(),
            headers: vec![("X-Probe".to_string(), "1".to_string())],
            body: b"a=b".to_vec(),
        })
        .await
        .expect("the default port is the same origin");
        let seen = client.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.method, "POST");
        assert_eq!(seen[0].0.path, "/search?q=x");
        assert_eq!(seen[0].0.headers.get("x-probe"), Some("1"));
        assert!(matches!(&seen[0].0.body, Body::Bytes(b) if b == b"a=b"));
    }

    /// Spec D5 "Cancellation": a cancelled job crawls nothing and an active
    /// check stops before its first probe with an inconclusive verdict; a spent
    /// budget does the same.
    #[tokio::test]
    async fn a_cancelled_or_exhausted_job_sends_nothing() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::EchoHtml("q"));
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));
        job.cancelled.store(true, Ordering::SeqCst);
        let job = Arc::new(job);

        let discovery = discover_with(&job).await;
        assert_eq!(store.list().len(), 1, "a cancelled job crawls nothing");
        assert_eq!(job.charged(), 0);

        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");
        let verdict = check_named("xss-reflected").run(&point, &*host).await;
        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert!(verdict.detail.contains("cancelled"), "{}", verdict.detail);
        assert_eq!(client.calls(), 0, "a cancelled check sends nothing");

        let client = StubClient::new(Answer::EchoHtml("q"));
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.budget = 0;
        let job = Arc::new(job);
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");
        let verdict = check_named("xss-reflected").run(&point, &*host).await;
        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert!(verdict.detail.contains("budget"), "{}", verdict.detail);
        assert_eq!(client.calls(), 0, "a spent budget sends nothing");
    }

    /// Spec D2 `PayloadMode`: `prefix` and `suffix` wrap the point's observed
    /// value; `replace` drops it.
    #[tokio::test]
    async fn payload_modes_wrap_the_observed_value() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello&other=1")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        for (mode, want) in [
            (PayloadMode::Replace, "X"),
            (PayloadMode::Prefix, "Xhello"),
            (PayloadMode::Suffix, "helloX"),
        ] {
            host.probe(&Payload {
                value: "X".to_string(),
                mode,
                bytes: None,
            })
            .await
            .expect("the stub answers");
            let (req, _) = client.seen().last().cloned().expect("a send");
            assert_eq!(query_value(&req.path, "q"), want, "{mode:?}: {}", req.path);
            assert_eq!(
                query_value(&req.path, "other"),
                "1",
                "{mode:?}: the other parameter is untouched"
            );
        }
    }

    /// A point whose captured flow left the store, or that never carried one,
    /// cannot be hosted: a plain error naming the point, no send.
    #[tokio::test]
    async fn a_point_without_its_flow_cannot_be_hosted() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let mut point = point_named(&discovery, "q").clone();

        let mut gone = point.clone();
        gone.flow = Some(FlowRef(FlowId::new()));
        let err = lane()
            .probe_host_for(&gone, Arc::clone(&job) as Arc<dyn JobCtx>)
            .err()
            .expect("a flow that is not in the store cannot be hosted");
        assert!(err.to_string().contains("no longer in the store"), "{err}");

        point.flow = None;
        let err = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .err()
            .expect("a point without a flow cannot be hosted");
        assert!(err.to_string().contains("carries no flow"), "{err}");

        let mut renamed = point_named(&discovery, "q").clone();
        renamed.id = format!("{}:query:zzz", renamed.flow.expect("a flow").0);
        let err = lane()
            .probe_host_for(&renamed, Arc::clone(&job) as Arc<dyn JobCtx>)
            .err()
            .expect("a point that is not in its request cannot be hosted");
        assert!(err.to_string().contains("no longer present"), "{err}");

        assert_eq!(client.calls(), 0);
    }

    /// Amendment 38: an origin item ([`crate::scheduler::SchedulePlan::origin_points`])
    /// carries no captured flow, so the lane hosts it over a synthesized
    /// `GET <origin>/`. That request is the baseline; there is no insertion
    /// point behind it, so `probe` is refused; and nothing was captured, so
    /// `captured` is empty.
    #[tokio::test]
    async fn an_origin_point_gets_a_host_whose_baseline_is_get_root() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let origin = origin_item(&[ORIGIN], &[]);
        assert_eq!(origin.id, "origin:http://target.test:80");

        let host = lane()
            .probe_host_for(&origin, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("an origin item is hosted");

        let baseline = host.baseline().await.expect("the stub answers");
        assert_eq!(baseline.status, Some(200));
        assert_eq!(client.calls(), 1, "the baseline is one request");
        let (req, opts) = client.seen().last().cloned().expect("a send");
        assert_eq!(req.method, "GET");
        assert_eq!(req.scheme, "http");
        assert_eq!(req.authority, "target.test:80");
        assert_eq!(req.path, "/");
        assert!(req.headers.get("cookie").is_none(), "no headers of its own");
        assert!(
            matches!(opts.record, RecordPolicy::Never),
            "{:?}",
            opts.record
        );

        let err = host
            .probe(&payload("anything"))
            .await
            .expect_err("an origin host has nothing to inject into");
        assert!(err.to_string().contains("no insertion point"), "{err}");
        assert_eq!(client.calls(), 1, "the refused probe sent nothing");

        assert!(
            host.captured().is_none(),
            "the flow was synthesized, not captured"
        );
    }

    /// The degenerate origin key: a point with neither a site node nor a
    /// parsable URL gives `point:<id>`, so the origin item's URL is not an
    /// origin at all. It takes the same error path as any other flowless
    /// point instead of being hosted over a nonsense request.
    #[tokio::test]
    async fn an_origin_item_whose_url_is_not_an_origin_cannot_be_hosted() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(no_crawl_job(Arc::clone(&store), Arc::clone(&client) as _));

        let nowhere = InsertionPoint {
            id: "p9".to_string(),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: "q".to_string(),
            path: None,
            example: None,
            flow: None,
            site_node: None,
            traits: Vec::new(),
            frequency: 1,
            method: Some("GET".to_string()),
            url: None,
        };
        let origin = origin_item(&[], &[nowhere]);
        assert_eq!(origin.id, "origin:point:p9");
        assert_eq!(origin.url.as_deref(), Some("point:p9/"));

        let err = lane()
            .probe_host_for(&origin, Arc::clone(&job) as Arc<dyn JobCtx>)
            .err()
            .expect("an origin item without an origin cannot be hosted");
        assert!(err.to_string().contains("carries no flow"), "{err}");
        assert_eq!(client.calls(), 0);
    }

    /// The lane ships its three passive checks (call B19), in the plan's order,
    /// with a native origin, covering every HTTP kind and no WebSocket or L4
    /// one. Its two legacy active checks left `checks()` with T3 PR 2a (the
    /// natives in `aitm-scan-checks-http` own `xss-reflected` and
    /// `open-redirect`) but still carry the metadata the plan pinned.
    ///
    /// Coordinator ruling 2026-11-01: an **id** is spec D8.2's literal name
    /// (`xss-reflected`), a **class** is the issue class the check emits
    /// (`reflected-xss`), so the two differ for the reflected-XSS check and
    /// coincide for the other four.
    #[test]
    fn the_three_interim_checks_carry_the_pinned_metadata() {
        let checks = lane().checks();
        let ids: Vec<&str> = checks.iter().map(|c| c.meta().id.as_str()).collect();
        assert_eq!(ids, ["reflection", "security-header", "cookie-flag"]);
        let classes: Vec<&str> = checks.iter().map(|c| c.meta().class.as_str()).collect();
        assert_eq!(classes, ["reflection", "security-header", "cookie-flag"]);
        let legacy = [
            legacy_active("xss-reflected"),
            legacy_active("open-redirect"),
        ];
        assert_eq!(legacy[0].meta().id, "xss-reflected");
        assert_eq!(legacy[0].meta().class, "reflected-xss");
        assert_eq!(legacy[1].meta().id, "open-redirect");
        assert_eq!(legacy[1].meta().class, "open-redirect");
        for check in checks.iter().chain(legacy.iter()) {
            let meta = check.meta();
            assert_eq!(meta.origin, CheckOrigin::Native, "{}", meta.id);
            assert_eq!(meta.lanes, vec![LaneKind::Http], "{}", meta.id);
            assert!(!meta.description.is_empty(), "{}", meta.id);
            assert_eq!(meta.scope, CheckScope::Point, "{}", meta.id);
        }

        let xss = legacy[0].meta();
        assert_eq!(
            xss.kinds,
            vec![InsertionKind::Query, InsertionKind::BodyParam]
        );
        assert_eq!(xss.intensity, Intensity::Light);
        assert_eq!(xss.cost, CheckCost::Medium);
        assert_eq!(xss.technique, Technique::Reflected);
        assert_eq!(xss.severity, aitm_poc::Severity::Medium);
        assert_eq!(xss.confidence_max, Confidence::Certain);
        assert_eq!(xss.cwe, Some(79));
        assert!(xss.remediation.is_some());

        let redirect = legacy[1].meta();
        assert_eq!(redirect.kinds, vec![InsertionKind::Query]);
        assert_eq!(redirect.cost, CheckCost::Light);
        assert_eq!(redirect.severity, aitm_poc::Severity::Low);
        assert_eq!(redirect.cwe, Some(601));
        assert_eq!(redirect.wants_traits, Some(vec![PointTrait::Url]));

        for (check, confidence) in
            checks
                .iter()
                .zip([Confidence::Tentative, Confidence::Firm, Confidence::Firm])
        {
            let meta = check.meta();
            assert_eq!(meta.technique, Technique::Passive, "{}", meta.id);
            assert_eq!(meta.intensity, Intensity::Passive, "{}", meta.id);
            assert_eq!(meta.cost, CheckCost::Light, "{}", meta.id);
            assert_eq!(meta.severity, aitm_poc::Severity::Low, "{}", meta.id);
            assert_eq!(meta.confidence_max, confidence, "{}", meta.id);
            assert!(meta.kinds.contains(&InsertionKind::Query), "{}", meta.id);
            assert!(meta.kinds.contains(&InsertionKind::Cookie), "{}", meta.id);
            assert!(
                !meta.kinds.iter().any(|k| matches!(
                    k,
                    InsertionKind::WsText | InsertionKind::WsBinary | InsertionKind::L4Field
                )),
                "{}: an HTTP passive check applies to HTTP kinds only",
                meta.id
            );
        }
    }
    // ---- stage-6 fix task: the client crawl ---------------------------------

    /// Spec D1 "every T1 AC must be provable on the interim lane" and D5
    /// "client-crawler GETs go through `send_opts` like probes": with no
    /// browser bound the lane crawls the origin through the job's client, so a
    /// job started against a target nobody has browsed still finds its
    /// parameters.
    #[tokio::test]
    async fn the_client_crawl_finds_points_when_no_browser_is_bound() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);

        let discovery = discover_with(&job).await;

        assert_eq!(
            client.trail(),
            vec![
                "GET /",
                "GET /search?q=x",
                "GET /redirect?to=http://away.test/",
                "GET /find?term=a",
            ],
            "the root, both anchors and the GET form, breadth-first"
        );

        let q = point_named(&discovery, "q");
        assert_eq!(q.kind, InsertionKind::Query);
        assert_eq!(q.url.as_deref(), Some("http://target.test/search?q=x"));
        let to = point_named(&discovery, "to");
        assert!(to.traits.contains(&PointTrait::Url), "{:?}", to.traits);
        assert_eq!(
            point_named(&discovery, "term").url.as_deref(),
            Some("http://target.test/find?term=a"),
            "the GET form became a query the v1 enumerator can see"
        );
    }

    /// Spec D5 "Record policy": a crawl capture is recorded, marked
    /// `scan:<job>` and `crawl`, and is read back as attack surface even
    /// though the client stamped it a replay.
    #[tokio::test]
    async fn client_crawl_captures_are_recorded_and_marked() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);

        let discovery = discover_with(&job).await;

        for opts in client.options() {
            assert_eq!(
                opts.record,
                RecordPolicy::Always,
                "a crawl page is recorded"
            );
            assert_eq!(
                opts.marks,
                vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()]
            );
        }
        let flows: Vec<Flow> = store
            .list()
            .into_iter()
            .filter_map(|id| store.get(id))
            .collect();
        assert_eq!(flows.len(), 4, "every page reached the store");
        for flow in &flows {
            assert_eq!(
                flow.metadata().marks,
                vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()]
            );
        }
        assert!(
            !discovery.points.is_empty(),
            "and the crawl captures are attack surface, replay stamp or not"
        );
    }

    /// The crawl never leaves the origin: the off-origin anchor on the landing
    /// page is not fetched, and nothing but the target's authority is dialled.
    #[tokio::test]
    async fn the_client_crawl_never_leaves_the_origin() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);

        let _ = discover_with(&job).await;

        let authorities: Vec<String> = client
            .requests()
            .iter()
            .map(|req| req.authority.clone())
            .collect();
        assert!(
            authorities.iter().all(|a| a == "target.test"),
            "{authorities:?}"
        );
    }

    /// `crawl.max_pages` bounds the client crawl the way it bounds the browser
    /// crawl.
    #[tokio::test]
    async fn the_client_crawl_is_bounded_by_max_pages() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.profile.crawl.max_pages = 2;

        let _ = discover_with(&job).await;

        assert_eq!(client.trail(), vec!["GET /", "GET /search?q=x"]);
    }

    /// `crawl.max_depth: 0` keeps the crawl on the seed: the links the landing
    /// page carries are one hop too deep.
    #[tokio::test]
    async fn the_client_crawl_is_bounded_by_max_depth() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.profile.crawl.max_depth = 0;

        let _ = discover_with(&job).await;

        assert_eq!(client.trail(), vec!["GET /"]);
    }

    /// Spec D5 "one budget per job": the crawl cannot ask for more pages than
    /// the budget has left — a navigation is a probe.
    #[tokio::test]
    async fn the_client_crawl_is_bounded_by_the_jobs_budget() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.budget = 1;

        let _ = discover_with(&job).await;

        assert_eq!(client.trail(), vec!["GET /"]);
    }

    /// And a send the budget refuses mid-crawl ends it on the spot, leaving
    /// discovery to run over what was captured before.
    #[tokio::test]
    async fn a_refused_send_ends_the_client_crawl() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::refusing(&store);
        let job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);

        let discovery = discover_with(&job).await;

        assert_eq!(
            client.trail(),
            vec!["GET /", "GET /search?q=x"],
            "the first refusal ends the crawl"
        );
        assert_eq!(store.list().len(), 1, "only the root was captured");
        assert!(discovery.points.is_empty() || !discovery.nodes.is_empty());
    }

    /// Spec D7: the crawl is the scan's own traffic, so it carries the job's
    /// session material exactly as a probe does.
    #[tokio::test]
    async fn the_client_crawl_carries_the_session() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.session = Some(Arc::new(SessionMaterial {
            cookies: vec![("sid".to_string(), "abc".to_string())],
            headers: Vec::new(),
        }));

        let _ = discover_with(&job).await;

        let cookies: Vec<String> = client
            .requests()
            .iter()
            .filter_map(|req| req.headers.get("cookie").map(str::to_string))
            .collect();
        assert_eq!(cookies.len(), client.calls(), "every page is authenticated");
        assert!(cookies.iter().all(|c| c.contains("sid=abc")), "{cookies:?}");
    }

    /// A browser crawl and a client crawl are alternatives, not both: with a
    /// browser bound under `use_browser: auto` the client sends nothing.
    #[tokio::test]
    async fn the_browser_crawl_leaves_no_work_for_the_client_crawl() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled?b=2",
        }));

        let _ = discover_with(&job).await;

        assert_eq!(client.calls(), 0, "{:?}", client.trail());
        assert_eq!(store.list().len(), 1, "the browser's capture, and only it");
    }
    /// A `ProxyClient` keyed on request path: a path mapped to `None` fails the
    /// send with the given message, any other path is a 200 page (HTML when a
    /// body is given), so a crawl can lose one link and keep the rest.
    struct FailingSite {
        pages: std::collections::HashMap<&'static str, &'static str>,
        failures: std::collections::HashMap<&'static str, &'static str>,
        default_failure: Option<&'static str>,
    }

    impl FailingSite {
        /// Every send fails with `message`.
        fn all_failing(message: &'static str) -> Arc<Self> {
            Arc::new(Self {
                pages: std::collections::HashMap::new(),
                failures: std::collections::HashMap::new(),
                default_failure: Some(message),
            })
        }

        /// Serve each `(path, html)` as a page; fail each `(path, message)`.
        fn new(
            pages: Vec<(&'static str, &'static str)>,
            failures: Vec<(&'static str, &'static str)>,
        ) -> Arc<Self> {
            Arc::new(Self {
                pages: pages.into_iter().collect(),
                failures: failures.into_iter().collect(),
                default_failure: None,
            })
        }
    }

    impl ProxyClient for FailingSite {
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
                if let Some(message) = self.failures.get(path).or(self.default_failure.as_ref()) {
                    return Err(anyhow::anyhow!(*message));
                }
                let (ctype, body) = match self.pages.get(path) {
                    Some(html) => ("text/html; charset=utf-8", *html),
                    None => ("text/plain", "ok"),
                };
                Ok(HttpFlow {
                    id: FlowId::new(),
                    request: req,
                    response: Some(response(200, &[("content-type", ctype)], body)),
                    client_conn: conn(),
                    server_conn: None,
                    metadata: FlowMeta::default(),
                    intercept: InterceptState::Observed,
                })
            })
        }
    }

    /// Amendment 39: the lane turns each failed client-crawl request into one
    /// `report_crawl_error` call naming the origin and the classified token —
    /// once per failure, not once per crawl.
    #[tokio::test]
    async fn a_failed_crawl_request_is_reported_once_each() {
        // Every send fails: the seed is the one failed request.
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let client = FailingSite::all_failing("h2_not_negotiated: scan.test:80: alpn");
        let job = TestJob::new(Arc::clone(&store), client as _);

        let _ = discover_origins(&job, &["http://scan.test"]).await;

        assert_eq!(
            job.crawl_errors(),
            vec![(
                "http://scan.test".to_string(),
                "h2_not_negotiated".to_string()
            )],
        );

        // A seed with two links, one of which the client refuses.
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        let seed = concat!(
            "<html><body>",
            "<a href=\"/a\">a</a>",
            "<a href=\"/b\">b</a>",
            "</body></html>",
        );
        let client = FailingSite::new(vec![("/", seed)], vec![("/a", "connection refused")]);
        let job = TestJob::new(Arc::clone(&store), client as _);

        let _ = discover_origins(&job, &["http://scan.test"]).await;

        assert_eq!(
            job.crawl_errors(),
            vec![(
                "http://scan.test".to_string(),
                "connect_refused".to_string()
            )],
            "exactly one entry, for the one refused link",
        );
    }

    /// Spec D3's `passive-only`: the built-in profile that asks for no crawl
    /// (`max_pages: 0`, `use_browser: never`) sends nothing at all, browser or
    /// no browser, and still maps what the proxy captured.
    #[tokio::test]
    async fn the_passive_only_profile_crawls_nothing() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = SiteClient::new(&store);
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));
        job.profile = aitm_scan_model::builtin_profiles()
            .into_iter()
            .find(|profile| profile.name == "passive-only")
            .expect("the built-in passive-only profile");

        let discovery = discover_with(&job).await;

        assert_eq!(client.calls(), 0, "{:?}", client.trail());
        assert_eq!(store.list().len(), 1, "the browser was not driven either");
        assert_eq!(job.charged(), 0);
        assert_eq!(point_named(&discovery, "q").kind, InsertionKind::Query);
    }
}
