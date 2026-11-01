//! The `Check`, `ProbeHost`, `Lane` and `JobCtx` traits (spec D2, D1). Task 7 of the T1a plan owns this file.
//!
//! These four traits are the whole seam between the scanner engine, the lanes
//! and the checks. A lane crate implements [`Lane`] and hands back `Arc<dyn Lane>`
//! from its `lane()` entry point, so a new lane needs no edit to a shared file
//! (spec D1, "Registration without shared files"). A check implements [`Check`]
//! and reaches the network only through the [`ProbeHost`] its lane built for one
//! insertion point; it never holds a client, a store or a guard of its own. A
//! lane reaches the job's budgeted client, store, guard, browser and session
//! through [`JobCtx`], which the engine owns (spec D5, "Where a probe goes").
//!
//! Every trait is object-safe and `Send + Sync`, and every async method returns
//! [`futures::future::BoxFuture`] rather than being `async fn`, so the engine can
//! hold `Arc<dyn Lane>` / `Box<dyn ProbeHost>` / `Arc<dyn Check>` and move them
//! across tasks.
//!
//! **Extension rule.** After track T1a lands, a later track (T1b and onwards) may
//! add methods to these traits **only with default bodies**. A lane or check track
//! in flight is compiling against this file; a method without a default body
//! breaks it, and this crate's version is the contract everyone pins.

use std::sync::Arc;
use std::time::Instant;

use futures::future::BoxFuture;

use crate::check::{CheckMeta, Verdict};
use crate::point::{InsertionPoint, Payload, ProbeResponse, RawProbe, SiteNode};
use crate::profile::{ProfileTarget, ScanProfile};
use crate::session::SessionMaterial;
use crate::vocab::LaneKind;

/// One detection, run against one insertion point (spec D2).
///
/// A check is pure logic: it decides what to send, reads what came back and
/// returns a [`Verdict`]. It owns no client and no budget — every stimulus goes
/// through the [`ProbeHost`] it is handed, which is already bound to the point,
/// the job's budget and the job's scope guard. The same trait serves a native
/// check and the Rhai bridge's adapter, so the catalogue and the scheduler treat
/// both identically.
pub trait Check: Send + Sync {
    /// The check's catalogue entry: identity, lanes, kinds, intensity, cost.
    ///
    /// Constant for the life of the check; the scheduler reads it to decide
    /// whether this check runs against a given point under a given profile.
    fn meta(&self) -> &CheckMeta;

    /// Run the check against `point`, sending everything through `host`.
    ///
    /// Returns a verdict in every case: a check that could not conclude returns
    /// [`crate::vocab::Outcome::Inconclusive`] or [`crate::vocab::Outcome::Error`]
    /// rather than an error, so one failing check never fails the job. The check
    /// must stop early when `host.cancelled()` is true, when `host.budget_left()`
    /// reaches zero or when `host.deadline()` has passed.
    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict>;
}

/// The lane-built, point-bound surface a [`Check`] sends through (spec D2).
///
/// One host serves one insertion point for the life of one check run. The lane
/// that built it knows how to place a payload at that point, which transport to
/// use, how to bound the response and how to charge the job's budget; the check
/// knows none of that. A host enforces scope and budget itself, so a check that
/// ignores [`ProbeHost::budget_left`] still cannot overspend.
pub trait ProbeHost: Send + Sync {
    /// The unmodified response for this point, for a check that diffs against it.
    ///
    /// Taken once and reused within a check run. Costs budget the first time.
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>>;

    /// Place `payload` at this point and send, returning the bounded response.
    ///
    /// Errors when the budget is exhausted, the deadline has passed, the job was
    /// cancelled or the guard refused the destination.
    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>>;

    /// Send a request the check built itself, for checks that cannot express
    /// their probe as a payload at a point (a malformed method, a second host).
    ///
    /// Subject to the same scope, budget and deadline rules as
    /// [`ProbeHost::probe`].
    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>>;

    /// The job's collision-resistant marker token, for a check that needs a
    /// value it can recognise again (a reflection canary, a callback label).
    fn marker(&self) -> String;

    /// Probes still affordable for this point. Zero means send nothing more.
    fn budget_left(&self) -> u32;

    /// When this check run must be finished. A check past its deadline returns
    /// what it has rather than sending again.
    fn deadline(&self) -> Instant;

    /// The job's profile, for a check that reads intensity, accuracy or speed.
    fn profile(&self) -> &ScanProfile;

    /// Whether the job was cancelled. A check polls this between probes.
    fn cancelled(&self) -> bool;

    /// The probe and baseline flows the host kept in memory for this point.
    ///
    /// Under `record_probes: issues_only` a probe's flow is not inserted into the
    /// store; the host holds at most sixteen of them per point so that, when a
    /// check does return a vulnerable verdict, the engine can re-record exactly
    /// the flows that proved it (spec D5). Empty when the host held none.
    fn held_flows(&self) -> Vec<aitm_core::Flow>;
}

/// The engine-owned, per-job surface a [`Lane`] consumes (spec D5).
///
/// Everything a lane needs that outlives one probe lives here: the job's
/// budgeted client, the flow store, the scope and rate guard, an optional
/// browser, the in-memory session material and the job's budget, deadline and
/// cancellation state. The engine implements it; a lane only reads it.
pub trait JobCtx: Send + Sync {
    /// The job's identifier, as it appears in results and push lines.
    fn job_id(&self) -> &str;

    /// The profile the job is running under.
    fn profile(&self) -> &ScanProfile;

    /// The job's budgeted client. Every request a lane sends goes through it, so
    /// scope, rate limits, marks and the record policy apply without the lane
    /// doing anything.
    fn client(&self) -> Arc<dyn aitm_core::ProxyClient>;

    /// The flow store, for a lane that reads already-captured flows (the passive
    /// pass) or re-records a probe flow that proved an issue.
    fn store(&self) -> Arc<dyn aitm_core::FlowStore>;

    /// The scope and rate guard, for a lane that must check a destination before
    /// it does something the client cannot express (an L4 connect).
    fn guard(&self) -> Arc<dyn aitm_core::ScopeRateGuard>;

    /// The browser, when the job has one. `None` when the profile said
    /// `use_browser: never` or no engine is available; a lane degrades rather
    /// than failing.
    fn browser(&self) -> Option<Arc<dyn aitm_core::BrowserDriver>>;

    /// The job's session cookie and header **values**, when the job observed a
    /// session. Held only in the worker's memory and never serialised (spec D7).
    fn session(&self) -> Option<Arc<SessionMaterial>>;

    /// Charge `units` of the one job budget for a non-HTTP stimulus (a WebSocket
    /// frame, an L4 case) and report whether the charge was affordable.
    ///
    /// Returns `false` when the budget is exhausted, in which case nothing was
    /// charged and the lane must stop sending.
    fn charge(&self, units: u32) -> bool;

    /// Stimuli still affordable across the whole job.
    fn budget_left(&self) -> u32;

    /// When the job must be finished.
    fn deadline(&self) -> Instant;

    /// Whether the job was cancelled. A lane polls this inside every loop.
    fn cancelled(&self) -> bool;

    /// The job's collision-resistant marker token (see [`ProbeHost::marker`]).
    fn marker(&self) -> String;
}

/// What one lane's discovery pass found (spec D2).
#[derive(Debug, Clone, Default)]
pub struct Discovery {
    /// The insertion points the lane can mutate.
    pub points: Vec<InsertionPoint>,
    /// The site-map nodes the points belong to.
    pub nodes: Vec<SiteNode>,
}

/// One protocol's half of the scanner: discovery, probe hosting and checks.
///
/// A lane crate exposes a `lane()` entry point returning `Option<Arc<dyn Lane>>`
/// and is registered by the binary alone, so adding a lane edits no shared file
/// (spec D1). The lane owns everything protocol-specific — how to find insertion
/// points, how to place a payload at one, which checks exist for it — and the
/// engine owns scheduling, budget and results.
pub trait Lane: Send + Sync {
    /// Which lane this is. A profile's `lanes` list selects by this value.
    fn lane(&self) -> LaneKind;

    /// Find the insertion points and site-map nodes in `target`.
    ///
    /// Reads already-captured flows, crawls, or both, depending on the profile.
    /// Returns an error only when the lane could do nothing at all; a partial
    /// discovery is a successful [`Discovery`] with what was found.
    fn discover<'a>(
        &'a self,
        target: &'a ProfileTarget,
        job: &'a dyn JobCtx,
    ) -> BoxFuture<'a, anyhow::Result<Discovery>>;

    /// Build the [`ProbeHost`] a check will send through for `point`.
    ///
    /// Errors when the point is not one this lane produced, or when the lane
    /// cannot host probes for it (a point whose flow is gone).
    fn probe_host_for(
        &self,
        point: &InsertionPoint,
        job: Arc<dyn JobCtx>,
    ) -> anyhow::Result<Box<dyn ProbeHost>>;

    /// The checks this lane ships. The engine filters them by profile; the lane
    /// returns all of them.
    fn checks(&self) -> Vec<Arc<dyn Check>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
        StdGuard,
    };
    use futures::executor::block_on;
    use futures::future::BoxFuture;

    use crate::check::{CheckMeta, Evidence, Verdict};
    use crate::point::{InsertionPoint, Payload, ProbeResponse, RawProbe};
    use crate::profile::{ProfileTarget, ScanProfile};
    use crate::session::SessionMaterial;
    use crate::vocab::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, Technique,
    };

    /// Compiles only for a type that can be a trait object.
    fn assert_object_safe<T: ?Sized>() {}

    /// A `ProxyClient` that performs no I/O; the job context needs one to exist.
    struct NullClient;

    impl ProxyClient for NullClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
        }
    }

    struct NullJob {
        profile: ScanProfile,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
    }

    impl NullJob {
        fn new() -> Self {
            Self {
                profile: ScanProfile::default(),
                client: Arc::new(NullClient),
                store: Arc::new(MemFlowStore::new()),
                guard: Arc::new(StdGuard::default()),
            }
        }
    }

    impl JobCtx for NullJob {
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
            7
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

    struct NullHost {
        profile: ScanProfile,
    }

    impl ProbeHost for NullHost {
        fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async { Err(anyhow::anyhow!("no baseline in the test context")) })
        }
        fn probe<'a>(
            &'a self,
            _payload: &'a Payload,
        ) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
            Box::pin(async { Err(anyhow::anyhow!("no probe in the test context")) })
        }
        fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async { Err(anyhow::anyhow!("no probe in the test context")) })
        }
        fn marker(&self) -> String {
            "aitm7f3a".to_string()
        }
        fn budget_left(&self) -> u32 {
            3
        }
        fn deadline(&self) -> Instant {
            Instant::now() + Duration::from_secs(60)
        }
        fn profile(&self) -> &ScanProfile {
            &self.profile
        }
        fn cancelled(&self) -> bool {
            false
        }
        fn held_flows(&self) -> Vec<aitm_core::Flow> {
            Vec::new()
        }
    }

    fn meta() -> CheckMeta {
        CheckMeta {
            id: "null-check".to_string(),
            name: "Null check".to_string(),
            class: "none".to_string(),
            lanes: vec![LaneKind::Http],
            kinds: vec![InsertionKind::Query],
            intensity: Intensity::Passive,
            cost: CheckCost::Light,
            technique: Technique::Observe,
            severity: aitm_poc::Severity::Info,
            confidence_max: Confidence::Tentative,
            needs_baseline: false,
            wants_traits: None,
            targets_session: false,
            cwe: None,
            description: "Concludes nothing.".to_string(),
            remediation: None,
            origin: CheckOrigin::Native,
        }
    }

    struct NullCheck {
        meta: CheckMeta,
    }

    impl Check for NullCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }
        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            _host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async {
                Verdict {
                    outcome: Outcome::Clean,
                    confidence: Confidence::Tentative,
                    evidence: Evidence::default(),
                    detail: "nothing to report".to_string(),
                    poc_hint: None,
                }
            })
        }
    }

    struct NullLane;

    impl Lane for NullLane {
        fn lane(&self) -> LaneKind {
            LaneKind::Http
        }
        fn discover<'a>(
            &'a self,
            _target: &'a ProfileTarget,
            _job: &'a dyn JobCtx,
        ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
            Box::pin(async { Ok(Discovery::default()) })
        }
        fn probe_host_for(
            &self,
            _point: &InsertionPoint,
            _job: Arc<dyn JobCtx>,
        ) -> anyhow::Result<Box<dyn ProbeHost>> {
            Err(anyhow::anyhow!("the null lane hosts no probes"))
        }
        fn checks(&self) -> Vec<Arc<dyn Check>> {
            Vec::new()
        }
    }

    fn point() -> InsertionPoint {
        InsertionPoint {
            id: "p1".to_string(),
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
            url: Some("http://127.0.0.1:8080/search".to_string()),
        }
    }

    fn accept_check(check: &dyn Check) -> String {
        check.meta().id.clone()
    }

    fn accept_probe_host(host: &dyn ProbeHost) -> u32 {
        host.budget_left()
    }

    fn accept_job_ctx(job: &dyn JobCtx) -> String {
        job.job_id().to_string()
    }

    fn accept_lane(lane: &dyn Lane) -> LaneKind {
        lane.lane()
    }

    #[test]
    fn traits_are_object_safe() {
        assert_object_safe::<dyn Check>();
        assert_object_safe::<dyn ProbeHost>();
        assert_object_safe::<dyn Lane>();
        assert_object_safe::<dyn JobCtx>();

        let check = NullCheck { meta: meta() };
        let host = NullHost {
            profile: ScanProfile::default(),
        };
        let job = NullJob::new();

        assert_eq!(accept_check(&check), "null-check");
        assert_eq!(accept_probe_host(&host), 3);
        assert_eq!(accept_job_ctx(&job), "scan-1a2b3c4d");
        assert_eq!(accept_lane(&NullLane), LaneKind::Http);

        let lanes: Vec<Arc<dyn Lane>> = vec![Arc::new(NullLane)];
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].lane(), LaneKind::Http);
        assert!(lanes[0].checks().is_empty());
    }

    #[test]
    fn dyn_check_runs_against_a_dyn_probe_host() {
        let check: Arc<dyn Check> = Arc::new(NullCheck { meta: meta() });
        let host = NullHost {
            profile: ScanProfile::default(),
        };
        let point = point();

        let verdict = block_on(check.run(&point, &host));

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert_eq!(verdict.detail, "nothing to report");
        assert_eq!(verdict.poc_hint, None);
    }

    #[test]
    fn dyn_lane_discovers_through_a_dyn_job_ctx() {
        let lane: Arc<dyn Lane> = Arc::new(NullLane);
        let job = NullJob::new();
        let target = ProfileTarget::default();

        let discovery = block_on(lane.discover(&target, &job)).expect("the null lane discovers");

        assert!(discovery.points.is_empty());
        assert!(discovery.nodes.is_empty());

        let job_arc: Arc<dyn JobCtx> = Arc::new(NullJob::new());
        assert!(lane.probe_host_for(&point(), job_arc).is_err());
    }

    #[test]
    fn discovery_default_is_empty() {
        let discovery = Discovery::default();

        assert!(discovery.points.is_empty());
        assert!(discovery.nodes.is_empty());
    }
}
