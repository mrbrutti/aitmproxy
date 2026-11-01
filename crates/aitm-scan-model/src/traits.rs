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
//!
//! T1b added [`ProbeHost::client`], [`ProbeHost::shared`], [`ProbeHost::captured`],
//! [`JobCtx::report_l4`], [`JobCtx::report_session_lost`] and [`Lane::validate`]
//! (all default-bodied) on 2026-10-31, then [`ProbeHost::baseline_peer_addr`],
//! [`JobCtx::report_session_canary`], [`JobCtx::report_session_browser_partial`]
//! and [`ProbeHost::charge`] (default-bodied too) on 2026-11-01.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use futures::future::BoxFuture;

use crate::check::{CheckMeta, Verdict};
use crate::job::L4Counters;
use crate::point::{InsertionPoint, Payload, ProbeResponse, RawProbe, SiteNode};
use crate::profile::{ProfileTarget, ScanProfile};
use crate::session::{Canary, SessionMaterial};
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
    ///
    /// **Error-prefix convention.** A host that detects the job's session is
    /// gone returns an error whose message starts with the literal
    /// `scan: session_lost: `; the engine reads that prefix, sets
    /// `JobStatus.session.lost` and, under `on_lost: stop`, ends the audit with
    /// `stopped_reason: session_lost`. Any other message is an ordinary probe
    /// error counted in `probes.errors`.
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

    /// The job's budgeted client, for a bridge that must route a send the host
    /// cannot express as a payload at a point — a Rhai check calling
    /// `http.send` runs through this client, so scope, rate, marks and the
    /// record policy still apply (spec D9.3).
    ///
    /// `None` by default: a host that cannot lend its client out makes the
    /// bridge fall back to refusing the send rather than sending unbudgeted.
    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        None
    }

    /// An owning handle to this host, for a bridge that must keep it alive past
    /// the borrow it was handed — the scripting tier parks it in a thread-local
    /// for the length of one check run (plan call B5, which is why no `unsafe`
    /// is needed there).
    ///
    /// `None` by default: a host that is not behind an `Arc` has none to give.
    fn shared(&self) -> Option<Arc<dyn ProbeHost>> {
        None
    }

    /// The captured flow this point came from, for a passive check that must
    /// read what was already observed and send nothing at all.
    ///
    /// `None` by default, and `None` for any point that was not built from a
    /// captured flow.
    fn captured(&self) -> Option<aitm_core::HttpFlow> {
        None
    }

    /// The peer address the baseline response actually came from, when the host
    /// knows it (an HTTP host fills it from the baseline flow's connection), so
    /// a raw probe (T3's raw-h2 observe check) can dial exactly the validated
    /// address instead of re-resolving the name; closes a DNS-rebinding window.
    /// Default `None` = unknown.
    fn baseline_peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Spend `units` of the job's probe budget for a stimulus that bypasses
    /// [`ProbeHost::probe`]/[`ProbeHost::probe_raw`] (T3's observe-only raw-h2
    /// connections, one unit per stream) so it is budgeted, paced and counted
    /// in `scan.status.probes`. Returns `false` when the budget cannot cover
    /// it; the caller must then not send.
    ///
    /// The default only checks [`ProbeHost::budget_left`] and charges nothing
    /// because the trait has no job handle; the engine's host overrides it to
    /// charge the job's `JobBudget` and pace through the guard.
    fn charge(&self, units: u32) -> bool {
        self.budget_left() >= units
    }
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

    /// Report the L4 lane's running counters — cases sent, crashes, failed
    /// liveness probes, retired elements. The engine folds them into
    /// `JobStatus.l4`, which is how a UI shows fuzzing progress (spec D5).
    ///
    /// A no-op by default: a context that tracks no L4 counters ignores the
    /// report, so an HTTP-only engine needs no change.
    fn report_l4(&self, _counters: L4Counters) {}

    /// Report that the job's session is gone, for a lane that detects auth loss
    /// itself rather than through a probe error.
    ///
    /// The engine sets `JobStatus.session.lost` and, under `on_lost: stop`, ends
    /// the audit with `stopped_reason: session_lost` (spec D7). A no-op by
    /// default.
    fn report_session_lost(&self) {}

    /// The lane reports the D7 canary it picked ([`Canary::None`] when
    /// auth-lost detection is off, or the GET/HEAD substitution) once, when the
    /// job's first [`ProbeHost`] is built; the engine mirrors it into
    /// `JobStatus.session.canary`.
    ///
    /// A no-op by default.
    fn report_session_canary(&self, canary: Canary) {
        let _ = canary;
    }

    /// The lane reports the HttpOnly session cookies `document.cookie` could
    /// not set; the engine sets `JobStatus.session.browser_partial: true`.
    /// Names only, never values.
    ///
    /// A no-op by default.
    fn report_session_browser_partial(&self, cookie_names: Vec<String>) {
        let _ = cookie_names;
    }

    /// A crawl of one origin failed outright (the browser crawl timed out or
    /// was refused). The engine counts it in `crawl.errors` so the status says
    /// the job ran on fewer points than it could have; the lane then falls back
    /// to whatever discovery it still has. The runtime scrubs `reason` before
    /// it is logged; lanes need not.
    ///
    /// A no-op by default.
    fn report_crawl_error(&self, origin: &str, reason: &str) {
        let _ = (origin, reason);
    }

    /// The crawl deliberately did not submit `count` forms it found —
    /// logout-looking or destructive-looking ones (see
    /// `CrawlCounters::forms_skipped`). The engine adds them to
    /// `crawl.forms_skipped` so a frontend can say the map is not the whole
    /// form surface.
    ///
    /// A no-op by default.
    fn report_forms_skipped(&self, count: u64) {
        let _ = count;
    }
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
    ///
    /// **Error-prefix convention.** An error whose message starts with the
    /// literal `invalid_profile: ` is a refusal of the profile, not a failure of
    /// the pass: the engine fails the job with
    /// `error: "scan: invalid_profile: <rest>"`. Prefer [`Lane::validate`],
    /// which refuses before the job is spawned; this prefix is for a refusal the
    /// lane can only reach once discovery has started.
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

    /// Refuse a profile this lane cannot run, before the job is spawned.
    ///
    /// The engine calls this for every lane a job would run and maps `Err(msg)`
    /// to `scan: invalid_profile: <msg>` synchronously, so a caller learns its
    /// profile is wrong from the `scan.start` call rather than from a job that
    /// fails later (AC T5-3). A packet plan naming a non-fuzzable field such as
    /// `ipv4.src` is the motivating case (spec D8.4).
    ///
    /// `Ok(())` by default: a lane with nothing to refuse needs no change.
    fn validate(&self, _target: &ProfileTarget, _profile: &ScanProfile) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use futures::executor::block_on;

    use crate::job::L4Counters;
    use crate::profile::{ProfileTarget, ScanProfile};
    use crate::session::Canary;
    use crate::testing::{null_meta, query_point, NullCheck, NullHost, NullJob, NullLane};
    use crate::vocab::{Confidence, LaneKind, Outcome};

    /// Compiles only for a type that can be a trait object.
    fn assert_object_safe<T: ?Sized>() {}

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

        let check = NullCheck::new(null_meta("null-check"));
        let host = NullHost::new();
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
        let check: Arc<dyn Check> = Arc::new(NullCheck::new(null_meta("null-check")));
        let host = NullHost::new();
        let point = query_point("http://127.0.0.1:8080/search", "q");

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
        assert!(lane
            .probe_host_for(&query_point("http://127.0.0.1:8080/search", "q"), job_arc)
            .is_err());
    }

    #[test]
    fn discovery_default_is_empty() {
        let discovery = Discovery::default();

        assert!(discovery.points.is_empty());
        assert!(discovery.nodes.is_empty());
    }

    /// T1b (spec D2, D9.3): the three `ProbeHost` additions are default-bodied,
    /// so a lane written against T1a still compiles and answers `None` — the
    /// engine's own hosts override them.
    #[test]
    fn probe_host_defaults_are_none() {
        let host = NullHost::new();

        assert!(host.client().is_none());
        assert!(host.shared().is_none());
        assert!(host.captured().is_none());

        // Through a trait object too: the bridge holds `&dyn ProbeHost`.
        let dynamic: &dyn ProbeHost = &host;
        assert!(dynamic.client().is_none());
        assert!(dynamic.shared().is_none());
        assert!(dynamic.captured().is_none());
    }

    /// Coordinator decision (2026-11-01): a raw probe that must dial the exact
    /// address the baseline came from asks the host for it. A host that does
    /// not know inherits `None`, so every lane written before this method
    /// still compiles and still answers "unknown".
    #[test]
    fn probe_host_baseline_peer_addr_defaults_to_none() {
        let host = NullHost::new();
        let dynamic: &dyn ProbeHost = &host;

        assert_eq!(dynamic.baseline_peer_addr(), None);
    }

    /// Coordinator decision 1: a lane may report L4 counters or a lost session;
    /// a `JobCtx` that does not care inherits a no-op body. That both calls
    /// compile against `dyn JobCtx` on a stub that implements neither is the
    /// proof the defaults exist; the one assertion is that they changed nothing.
    #[test]
    fn job_ctx_report_defaults_are_no_ops() {
        let job = NullJob::new();
        let dynamic: &dyn JobCtx = &job;

        dynamic.report_l4(L4Counters {
            cases: 1,
            ..Default::default()
        });
        dynamic.report_session_lost();

        // The no-op changed nothing the engine reads.
        assert_eq!(dynamic.budget_left(), 7);
    }

    /// T3 security panel (2026-11-01): a stimulus that bypasses `probe` must
    /// still be budgeted. The default body only *checks* — it has no job handle
    /// to charge — so a host written before this method refuses exactly what it
    /// cannot afford and its budget is unchanged either way.
    #[test]
    fn probe_host_charge_default_checks_the_budget_and_spends_nothing() {
        let host = NullHost::new();
        let dynamic: &dyn ProbeHost = &host;
        assert_eq!(dynamic.budget_left(), 3);

        assert!(dynamic.charge(3), "the whole budget is affordable");
        assert!(!dynamic.charge(4), "one unit more is not");
        assert_eq!(
            dynamic.budget_left(),
            3,
            "the default body charges nothing: it has no job handle"
        );
    }

    /// Coordinator decision (2026-11-01): a lane reports the D7 canary it picked
    /// and the HttpOnly cookies the browser could not set. A `JobCtx` that
    /// mirrors neither into its status inherits a no-op body, so a lane written
    /// before these methods still compiles.
    #[test]
    fn job_ctx_session_reports_default_to_no_ops() {
        let job = NullJob::new();
        let dynamic: &dyn JobCtx = &job;

        dynamic.report_session_canary(Canary::None);
        dynamic.report_session_browser_partial(vec!["sid".into()]);

        // The no-ops changed nothing the engine reads.
        assert_eq!(dynamic.budget_left(), 7);
    }

    /// AC T5-3 (spec D8.4): a lane refuses a profile it cannot run *before* the
    /// job is spawned. A lane with nothing to refuse inherits `Ok(())`.
    #[test]
    fn lane_validate_defaults_to_ok() {
        let lane: Arc<dyn Lane> = Arc::new(NullLane);

        assert_eq!(
            lane.validate(&ProfileTarget::default(), &ScanProfile::default()),
            Ok(())
        );
    }
}
