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
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, CheckScope, Confidence, Discovery, Evidence, FlowRef,
    InsertionKind, InsertionPoint, Intensity, JobCtx, Lane, LaneKind, NodeId, Outcome, ParamRef,
    Payload, PayloadMode, PocHint, PointTrait, ProbeHost, ProbeResponse, ProfileTarget, RawProbe,
    ScanProfile, SiteNode, Technique, UseBrowser, Verdict, MAX_MATCH_BODY,
};
use futures::future::BoxFuture;
use tokio::sync::OnceCell;

use crate::checks::CheckDefinition;
use crate::config::ScannerConfig;
use crate::discover::{is_secret_name, InjectionPoint, Location};
use crate::scheduler::payload_cap;
use crate::util::scrub;

/// The mark every crawl capture carries beside `scan:<job>` (spec D5).
const CRAWL_MARK: &str = "crawl";

/// How many probe flows one [`InterimProbeHost`] keeps in memory (spec D5).
pub const MAX_HELD_FLOWS: usize = 16;

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
    /// `max_pages: 0` or a crawl refusal all leave the store untouched and the
    /// discovery pass continues over what the proxy already captured.
    async fn crawl_origin(&self, origin: &str, job: &dyn JobCtx) {
        let profile = job.profile();
        if profile.crawl.max_pages == 0 || profile.crawl.use_browser == UseBrowser::Never {
            return;
        }
        let Some(browser) = job.browser() else {
            return;
        };

        let store = job.store();
        let client = job.client();
        let guard = job.guard();
        let before: HashSet<FlowId> = store.list().into_iter().collect();

        let cfg = ScannerConfig {
            max_depth: profile.crawl.max_depth as usize,
            max_pages: profile.crawl.max_pages as usize,
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

        if let Ok(outcome) = outcome {
            let pages = u32::try_from(outcome.pages_crawled).unwrap_or(u32::MAX);
            if pages > 0 {
                job.charge(pages);
            }
        }
    }

    /// Build the site map and the insertion points from every captured, in-scope
    /// flow in the store — the crawl's captures included, since they are now
    /// ordinary captures.
    fn map_flows(&self, origins: &[String], job: &dyn JobCtx) -> Discovery {
        let store = job.store();
        let mut nodes: Vec<SiteNode> = Vec::new();
        let mut index: HashMap<NodeId, usize> = HashMap::new();
        let mut points: Vec<InsertionPoint> = Vec::new();

        for id in store.list() {
            let Some(Flow::Http(flow)) = store.get(id) else {
                continue;
            };
            // A replay is the scanner's own traffic (or an operator's); the
            // attack surface is what the target was actually asked for.
            if flow.metadata.is_replay {
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
                self.crawl_origin(origin, job).await;
            }
            let origins: Vec<String> = target.origins.iter().filter_map(|o| origin_of(o)).collect();
            Ok(self.map_flows(&origins, job))
        })
    }

    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>> {
        let flow_ref = point
            .flow
            .ok_or_else(|| anyhow::anyhow!("interim lane: point `{}` carries no flow", point.id))?;
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
            legacy,
            job,
            baseline: OnceCell::new(),
            baseline_peer: Mutex::new(None),
            held: Mutex::new(Vec::new()),
        }))
    }

    fn checks(&self) -> Vec<Arc<dyn Check>> {
        vec![
            Arc::new(LegacyActiveCheck {
                def: CheckDefinition::reflected_xss(),
                meta: reflected_xss_meta(),
            }),
            Arc::new(LegacyActiveCheck {
                def: CheckDefinition::open_redirect(),
                meta: open_redirect_meta(),
            }),
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

/// The [`ProbeHost`] the interim lane builds for one insertion point.
///
/// It owns the job (so the check can outlive the lane's borrow), the captured
/// flow the point came from, and the v1 point that says how to mutate it.
pub struct InterimProbeHost {
    point: InsertionPoint,
    flow: HttpFlow,
    legacy: InjectionPoint,
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
            let example = self.legacy.example.as_str();
            let value = match payload.mode {
                PayloadMode::Replace => payload.value.clone(),
                PayloadMode::Prefix => format!("{}{example}", payload.value),
                PayloadMode::Suffix => format!("{example}{}", payload.value),
            };
            let req = crate::inject::mutate_request(&self.flow.request, &self.legacy, &value)
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
pub struct LegacyActiveCheck {
    def: CheckDefinition,
    meta: CheckMeta,
}

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
                        kind_token(point.kind),
                        point.name
                    ),
                    // AC T1-10: the engine reproduces the finding with exactly
                    // the assertion `confirm` judged it by.
                    poc_hint: Some(PocHint {
                        assertions: vec![self.def.success_assertion(payload)],
                        control: None,
                    }),
                };
            }
            if !answered {
                if let Some(err) = last_error {
                    return inconclusive(&format!(
                        "every probe at {} `{}` failed: {err}",
                        kind_token(point.kind),
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
                    kind_token(point.kind),
                    point.name
                ),
                poc_hint: None,
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
            }
        })
    }
}

// ----------------------------------------------------------------- mapping

/// The v2 kind a v1 [`Location`] becomes. `Redirect` is not a kind in v2: it is
/// a query parameter carrying the `url` trait (spec D2).
fn kind_for(location: &Location) -> InsertionKind {
    match location {
        Location::Query | Location::Redirect => InsertionKind::Query,
        Location::BodyParam => InsertionKind::BodyParam,
        Location::Header => InsertionKind::Header,
        Location::Cookie => InsertionKind::Cookie,
        Location::PathSegment => InsertionKind::PathSegment,
    }
}

/// An insertion kind's wire token, taken from its serde form so a point id can
/// never disagree with what `scan.sitemap` prints.
fn kind_token(kind: InsertionKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// A point's stable id within a job: `<flow>:<kind>:<name>`.
fn point_id(flow: FlowId, kind: InsertionKind, name: &str) -> String {
    format!("{flow}:{}:{name}", kind_token(kind))
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

/// `scheme://host[:port]`, lowercased, with the scheme's default port elided,
/// so a flow's authority and a profile's origin compare in one normal form.
fn origin_key(scheme: &str, authority: &str) -> String {
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let (host, port) = split_authority(&authority);
    let default = if scheme == "https" { 443 } else { 80 };
    match port {
        Some(port) if port != default => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

/// The same normal form for a profile origin (`http(s)://host[:port][/...]`).
fn origin_of(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    Some(origin_key(scheme, authority))
}

/// Split `host[:port]`, keeping a bracketed IPv6 literal intact.
fn split_authority(authority: &str) -> (&str, Option<u16>) {
    let tail = match authority.rfind(']') {
        Some(bracket) => &authority[bracket + 1..],
        None => authority,
    };
    match tail.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let cut = authority.len() - port.len() - 1;
            (&authority[..cut], port.parse().ok())
        }
        _ => (authority, None),
    }
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
        port: port.unwrap_or(if scheme == "https" { 443 } else { 80 }),
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

/// Whether a probe error means the job is over (budget, deadline, cancel)
/// rather than that one send failed.
fn ends_the_run(err: &anyhow::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    ["budget", "deadline", "cancel"]
        .iter()
        .any(|needle| text.contains(needle))
}

/// An inconclusive verdict carrying a scrubbed reason.
fn inconclusive(reason: &str) -> Verdict {
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: Evidence::excerpt(&scrub(reason)),
        poc_hint: None,
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
fn reflected_xss_meta() -> CheckMeta {
    CheckMeta {
        id: crate::checks::CLASS_REFLECTED_XSS.to_string(),
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

    use std::sync::atomic::{AtomicU32, Ordering};
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

    // ----------------------------------------------------------- stub browser

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
            }
        }

        fn charged(&self) -> u32 {
            self.charged.load(Ordering::SeqCst)
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
            false
        }
        fn marker(&self) -> String {
            "aitm7f3a".to_string()
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
            .unwrap_or_else(|| panic!("the lane ships the {id} check"))
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
        let job = TestJob::new(
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

    /// Without a browser the lane still maps what the proxy already captured,
    /// and charges nothing.
    #[tokio::test]
    async fn discover_without_browser_uses_captured_flows_only() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let job = TestJob::new(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );

        let discovery = discover_with(&job).await;

        assert_eq!(point_named(&discovery, "q").kind, InsertionKind::Query);
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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("reflected-xss").run(&point, &*host).await;

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("reflected-xss").run(&point, &*host).await;

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

        let discovery = discover_with(&job).await;
        let point = point_named(&discovery, "q").clone();
        let host = lane()
            .probe_host_for(&point, Arc::clone(&job) as Arc<dyn JobCtx>)
            .expect("the lane hosts probes for its own point");

        let verdict = check_named("reflected-xss").run(&point, &*host).await;

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert!(verdict.poc_hint.is_none());
    }

    /// `probe.raw` is same-origin only (spec D4).
    #[tokio::test]
    async fn probe_raw_refuses_other_origin() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let client = StubClient::new(Answer::Fixed(200, "text/plain", "ok"));
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let mut job = TestJob::new(Arc::clone(&store), Arc::clone(&client) as _);
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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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
        let job = Arc::new(TestJob::new(Arc::clone(&store), Arc::clone(&client) as _));

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

    /// `use_browser: never` keeps the lane off the browser even when one is
    /// available (spec D2's `crawl.use_browser`).
    #[tokio::test]
    async fn use_browser_never_skips_the_crawl() {
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
        store.insert(Flow::Http(captured("http", "/search?q=hello")));
        let mut job = TestJob::new(
            Arc::clone(&store),
            StubClient::new(Answer::Fixed(200, "", "")),
        );
        job.browser = Some(Arc::new(StubBrowser {
            store: Arc::clone(&store),
            path: "/crawled",
        }));
        job.profile.crawl.use_browser = UseBrowser::Never;

        let _ = discover_with(&job).await;

        assert_eq!(store.list().len(), 1, "nothing was crawled");
        assert_eq!(job.charged(), 0);
    }
}
