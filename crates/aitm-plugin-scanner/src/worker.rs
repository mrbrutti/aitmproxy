//! The job worker: phases, counters, progress push and the terminal
//! transition (spec D5, D3 "Progress push"). Task 14 of the T1b plan fills it.
//!
//! [`run_job`] is the whole life of a scan after `scan.start` returned. It
//! walks spec D5's phases — `crawling`, `passive`, `auditing`, `reporting`,
//! `done` — over the lanes `scan.start` resolved, and between every scheduled
//! item it re-asks the six questions that can end a job early: was it
//! cancelled, is its deadline past, is its budget spent, has the agent policy
//! turned, has a host's error ladder tripped, and is the session still alive.
//!
//! Three support types do the rest. [`JobRuntime`] is the `JobCtx` a lane
//! sees: the budgeted client, the store, the guard, the browser, the session
//! material, and the four report hooks a lane folds information back through.
//! [`ArcHost`] wraps a lane's `ProbeHost` so a script check can take an owning
//! handle to it (call B10, which is why the scripting bridge needs no
//! `unsafe`). [`Progress`] is the push side: it owns the `seq` counter and the
//! 250 ms window that coalesces `progress` lines to four a second while never
//! dropping `started`, `phase`, `issue` or a terminal line (call B13).
//!
//! Every counter on a [`JobStatus`] is monotonic, and [`bump`] is the only way
//! any of them changes: a phase that re-reads a meter raises the counter to the
//! new reading through [`raise`] and can never walk it back.

use std::any::Any;
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aitm_core::{
    BrowserDriver, CommandHost, Flow, FlowId, FlowStore, HttpFlow, ProxyClient, ScopeRateGuard,
};
use aitm_scan_model::{
    scan_error, Canary, CheckErrorSample, CheckMeta, Confidence, CrawlErrorKind, Discovery,
    Evidence, InsertionPoint, IssueLocation, IssueTarget, JobCtx, JobEvent, JobNotification,
    JobState, JobStatus, L4Counters, L4Location, L4Transport, Lane, LaneKind, OnLost, Outcome,
    Payload, ProbeHost, ProbeResponse, RawProbe, RecordProbes, ScanErrorCode, ScanProfile,
    SessionMaterial, SessionMode, SessionStatus, SiteNode, StoppedReason, Technique, UseBrowser,
    Verdict, JOB_KIND_SCAN, MAX_CHECK_ERROR_SAMPLES,
};
use futures::future::BoxFuture;
use futures::FutureExt;

use crate::client::{bounded_await, JobBudget, JobClient, LadderState, ProbeMeter};
use crate::issues::{IssueStore, NewIssue, Upsert};
use crate::jobs::{map_lane_error_text, Engine, JobStart, LaneErrorKind, PersistedJob};
use crate::scheduler::{self, ScheduleItem, SchedulePlan};
use crate::session::{self, CanaryOutcome, CanaryRunner, ObservedSession};
use crate::util;

/// The smallest gap between two published `progress` lines: four a second
/// (spec D3, call B13).
pub const MIN_PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// The most check ids `JobStatus.checks.running` carries (spec D5).
const MAX_RUNNING_IDS: usize = 8;

/// The most characters of a panic message that reach a status or a verdict.
const MAX_PANIC_TEXT: usize = 256;

/// Raise `counter` by `n`, saturating. The **only** way a job counter changes,
/// so no phase can make a `scan.status` figure go backwards (spec D5).
pub fn bump(counter: &mut u64, n: u64) {
    *counter = counter.saturating_add(n);
}

/// Raise `counter` to `reading` when the reading is higher, through [`bump`].
/// A meter that was re-read lower (a reset, a racing phase) changes nothing.
pub fn raise(counter: &mut u64, reading: u64) {
    bump(counter, reading.saturating_sub(*counter));
}

/// A `ProbeHost` behind an `Arc`, so a bridge can keep it past the borrow it
/// was handed (call B10).
///
/// The engine wraps every `Lane::probe_host_for` result in one of these, which
/// is what makes [`ProbeHost::shared`] answer `Some` for every host the
/// scripting tier ever sees — it parks the handle in a thread-local for the
/// length of one check run and needs no borrowed pointer, hence no `unsafe`.
pub struct ArcHost(pub Arc<dyn ProbeHost>);

impl ProbeHost for ArcHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        self.0.baseline()
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        self.0.probe(payload)
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        self.0.probe_raw(req)
    }

    fn marker(&self) -> String {
        self.0.marker()
    }

    fn budget_left(&self) -> u32 {
        self.0.budget_left()
    }

    fn deadline(&self) -> Instant {
        self.0.deadline()
    }

    fn profile(&self) -> &ScanProfile {
        self.0.profile()
    }

    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }

    fn held_flows(&self) -> Vec<Flow> {
        self.0.held_flows()
    }

    fn client(&self) -> Option<Arc<dyn ProxyClient>> {
        self.0.client()
    }

    /// The whole point of the wrapper.
    fn shared(&self) -> Option<Arc<dyn ProbeHost>> {
        Some(Arc::clone(&self.0))
    }

    fn captured(&self) -> Option<HttpFlow> {
        self.0.captured()
    }

    fn baseline_peer_addr(&self) -> Option<SocketAddr> {
        self.0.baseline_peer_addr()
    }

    fn charge(&self, units: u32) -> bool {
        self.0.charge(units)
    }
}

/// Where [`Progress`] reads the time from. The process clock in production;
/// a test clock a test steps by hand, so the coalescing rule can be checked
/// without sleeping through it (whole-branch quality finding).
type ProgressClock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The push side of one job (spec D3 "Progress push", call B13).
pub struct Progress {
    bus: Arc<aitm_core::JobBus>,
    job: String,
    seq: AtomicU64,
    last_progress: Mutex<Instant>,
    now: ProgressClock,
}

impl Progress {
    /// A publisher for `job`, on the process clock.
    pub fn new(bus: Arc<aitm_core::JobBus>, job: String) -> Self {
        Self::with_clock(bus, job, Arc::new(Instant::now))
    }

    /// A publisher reading `now` instead of the process clock.
    ///
    /// The first `progress` line is eligible at once: the window starts one
    /// interval in the past, so a short job still reports before it finishes.
    pub(crate) fn with_clock(bus: Arc<aitm_core::JobBus>, job: String, now: ProgressClock) -> Self {
        let start = (now)()
            .checked_sub(MIN_PROGRESS_INTERVAL)
            .unwrap_or_else(&*now);
        Self {
            bus,
            job,
            seq: AtomicU64::new(0),
            last_progress: Mutex::new(start),
            now,
        }
    }

    /// Publish one line, unless it is a `progress` inside the coalescing
    /// window. Returns whether it was published; `seq` counts published lines
    /// only, so a gap in `seq` never appears and a receiver can trust it.
    ///
    /// The payload is built from [`JobStatus::summary`] and an
    /// [`aitm_scan_model::IssueSummary`] alone: the bus fans out to every
    /// subscriber including an agent, so no `Evidence` body and no unscrubbed
    /// free text ever rides a push line (security review, 2026-11-01).
    pub fn emit(
        &self,
        event: JobEvent,
        status: &JobStatus,
        issue: Option<aitm_scan_model::IssueSummary>,
    ) -> bool {
        if event == JobEvent::Progress {
            let now = (self.now)();
            let mut last = self.last_progress.lock().unwrap_or_else(|e| e.into_inner());
            if now.saturating_duration_since(*last) < MIN_PROGRESS_INTERVAL {
                return false;
            }
            *last = now;
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let notification = JobNotification {
            job: self.job.clone(),
            kind: JOB_KIND_SCAN.to_string(),
            event,
            seq,
            ts_ms: util::now_ms(),
            status: status.summary(),
            issue,
        };
        let payload = serde_json::to_value(&notification)
            .map(util::json_to_value)
            .unwrap_or(aitm_core::Value::Null);
        self.bus.publish(aitm_core::JobEvent {
            job: self.job.clone(),
            kind: JOB_KIND_SCAN.to_string(),
            event: crate::util::wire_token(&event),
            seq,
            payload,
        });
        true
    }
}

/// The per-job surface a lane sees (spec D5 "Where a probe goes").
pub struct JobRuntime {
    job: String,
    profile: ScanProfile,
    client: Arc<dyn ProxyClient>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    browser: Option<Arc<dyn BrowserDriver>>,
    session: Option<Arc<SessionMaterial>>,
    budget: Arc<JobBudget>,
    status: Arc<RwLock<JobStatus>>,
    /// The per-call marker counter (amendment 57), as wide as
    /// [`crate::util::marker`]'s counter: it wraps rather than truncates.
    markers: AtomicU32,
    /// Per-job marker seed (amendment 55): minted once when the runtime is
    /// built, mixed into every marker so two jobs' first markers differ.
    marker_seed: u32,
    /// Set by [`JobCtx::report_session_lost`] or by the `scan: session_lost: `
    /// error prefix; the worker reads it between items.
    session_lost: AtomicBool,
    /// Budget units a lane charged outside an HTTP send (WebSocket frames, L4
    /// cases, browser navigations), in total. Added to the probe meter's
    /// reading for `probes.sent`, so a non-HTTP stimulus shows in
    /// `scan.status` exactly as an HTTP probe does (spec D5).
    lane_charges: AtomicU64,
    /// The same units, split by the lane that spent them, for
    /// `probes.by_lane`. A charge made while no lane is running is counted in
    /// `lane_charges` alone rather than attributed to a guess.
    charges_by_lane: Mutex<BTreeMap<LaneKind, u64>>,
    /// The lane the worker is running right now: whose discovery is in
    /// flight, or whose point the scheduled item belongs to. The worker runs
    /// lanes one at a time, so this is who a charge belongs to.
    current_lane: Mutex<Option<LaneKind>>,
    /// Set while the crawling phase is running, so a charge made then can be
    /// told from one made during the audit.
    in_crawl: AtomicBool,
    /// Charges the HTTP lane made during the crawling phase: one per browser
    /// navigation, which is the page count of a browser crawl (spec D5).
    crawl_charges: AtomicU64,
    /// Crawls of one origin that failed outright (`JobCtx::report_crawl_error`),
    /// folded into `crawl.errors` by `sync_counters`.
    crawl_errors: AtomicU64,
    /// The classified kind of the most recent crawl failure a lane reported
    /// (amendment 39). Surfaced on `crawl.last_error` only when the crawl made
    /// requests and every one failed (`crawl.errors > 0 && crawl.pages == 0`);
    /// a free-text browser reason that is not a token stores `Other`.
    last_crawl_error: Mutex<Option<CrawlErrorKind>>,
    /// Forms the crawl deliberately did not submit
    /// (`JobCtx::report_forms_skipped`), folded into `crawl.forms_skipped` by
    /// `sync_counters`.
    forms_skipped: AtomicU64,
    /// Forms the crawl submitted (`JobCtx::report_forms_submitted`), folded
    /// into `crawl.forms_submitted` by `sync_counters` (amendment 53).
    forms_submitted: AtomicU64,
    /// Check runs that ended in an `Outcome::Error` verdict, folded into
    /// `checks.errors` by `sync_counters` (amendment 58).
    check_errors: AtomicU64,
    /// The first [`MAX_CHECK_ERROR_SAMPLES`] distinct `(check, detail)` error
    /// pairs, each with the first point it was seen on, folded into
    /// `checks.error_samples` by `sync_counters` (amendment 58). The detail is
    /// stored scrubbed and bounded, so what is deduped is what is shown.
    check_error_samples: Mutex<Vec<CheckErrorSample>>,
}

/// The handles a [`JobRuntime`] works through: the job's metered client, the
/// flow store, the scope guard, and the optional browser and session material.
pub(crate) struct RuntimeServices {
    pub(crate) client: Arc<dyn ProxyClient>,
    pub(crate) store: Arc<dyn FlowStore>,
    pub(crate) guard: Arc<dyn ScopeRateGuard>,
    pub(crate) browser: Option<Arc<dyn BrowserDriver>>,
    pub(crate) session: Option<Arc<SessionMaterial>>,
}

impl JobRuntime {
    /// A runtime for `job` with every counter at zero, no lane running, no
    /// session lost, and a fresh marker seed (amendment 55). The inputs are
    /// the only things that vary between runtimes; everything else starts
    /// from the same empty state, so a new counter is added here once.
    pub(crate) fn new(
        job: String,
        profile: ScanProfile,
        services: RuntimeServices,
        budget: Arc<JobBudget>,
        status: Arc<RwLock<JobStatus>>,
    ) -> Self {
        Self {
            job,
            profile,
            client: services.client,
            store: services.store,
            guard: services.guard,
            browser: services.browser,
            session: services.session,
            budget,
            status,
            markers: AtomicU32::new(0),
            marker_seed: crate::util::marker_seed(),
            session_lost: AtomicBool::new(false),
            lane_charges: AtomicU64::new(0),
            charges_by_lane: Mutex::new(BTreeMap::new()),
            current_lane: Mutex::new(None),
            in_crawl: AtomicBool::new(false),
            crawl_charges: AtomicU64::new(0),
            crawl_errors: AtomicU64::new(0),
            last_crawl_error: Mutex::new(None),
            forms_skipped: AtomicU64::new(0),
            forms_submitted: AtomicU64::new(0),
            check_errors: AtomicU64::new(0),
            check_error_samples: Mutex::new(Vec::new()),
        }
    }

    /// Whether a lane has reported the session gone.
    fn session_is_lost(&self) -> bool {
        self.session_lost.load(Ordering::SeqCst)
    }

    /// Mark the session gone, from either route.
    fn mark_session_lost(&self) {
        self.session_lost.store(true, Ordering::SeqCst);
        self.with_session(|session| session.lost = true);
    }

    /// One check run ended in an `Outcome::Error` verdict (amendment 58): the
    /// error counter rises, and a `(check, detail)` pair not sampled yet is
    /// kept (up to [`MAX_CHECK_ERROR_SAMPLES`]) and logged **once** — never
    /// per probe, never per repeat. The detail is scrubbed first and cut like
    /// an evidence excerpt (spec amendment 16: scrub, then bound), so neither
    /// the sample nor the log line can carry a credential a runner echoed.
    /// Past the cap a new distinct pair is counted but neither kept nor
    /// logged.
    fn note_check_error(&self, check: &str, point: &str, detail: &str) {
        self.check_errors.fetch_add(1, Ordering::SeqCst);
        let detail = Evidence::excerpt(&util::scrub(detail));
        let mut samples = self
            .check_error_samples
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if samples.len() >= MAX_CHECK_ERROR_SAMPLES
            || samples
                .iter()
                .any(|s| s.check == check && s.detail == detail)
        {
            return;
        }
        tracing::warn!(
            target: "aitm::scanner",
            job = %self.job,
            check = %check,
            point = %point,
            "the check reported an error: {detail}",
        );
        samples.push(CheckErrorSample {
            check: check.to_string(),
            point: point.to_string(),
            detail,
        });
        if samples.len() == MAX_CHECK_ERROR_SAMPLES {
            // Said once, when the store fills: later distinct errors are
            // counted in `checks.errors` but neither sampled nor logged, so
            // a flood of near-identical details cannot flood the log either.
            tracing::warn!(
                target: "aitm::scanner",
                job = %self.job,
                "check error samples are full ({MAX_CHECK_ERROR_SAMPLES}); further distinct errors are counted only",
            );
        }
    }

    /// Budget units lanes charged outside an HTTP send.
    fn lane_charges(&self) -> u64 {
        self.lane_charges.load(Ordering::SeqCst)
    }

    /// Those units, by the lane that spent them.
    fn charges_by_lane(&self) -> BTreeMap<LaneKind, u64> {
        self.charges_by_lane
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Note which lane the worker is running, so its charges are attributed
    /// to it. Called before a lane's discovery and before each scheduled item.
    fn set_lane(&self, lane: LaneKind) {
        *self.current_lane.lock().unwrap_or_else(|e| e.into_inner()) = Some(lane);
    }

    /// The lane whose stimulus is in flight, if any.
    fn current_lane(&self) -> Option<LaneKind> {
        *self.current_lane.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Open and close the crawling phase, for [`JobRuntime::crawl_charges`].
    fn set_crawling(&self, crawling: bool) {
        self.in_crawl.store(crawling, Ordering::SeqCst);
    }

    /// Units the HTTP lane charged during the crawling phase.
    fn crawl_charges(&self) -> u64 {
        self.crawl_charges.load(Ordering::SeqCst)
    }

    /// The classified kind of the most recent crawl failure, if any.
    fn last_crawl_error(&self) -> Option<CrawlErrorKind> {
        *self
            .last_crawl_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Edit the session block of the status, creating it when the profile runs
    /// without one (a lane that reports anyway is still reported).
    fn with_session(&self, f: impl FnOnce(&mut SessionStatus)) {
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        f(status.session.get_or_insert_with(SessionStatus::default));
    }
}

impl JobCtx for JobRuntime {
    fn job_id(&self) -> &str {
        &self.job
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

    /// One budget for the whole job: a WebSocket frame, an L4 case or a
    /// browser navigation charged here spends exactly the unit an HTTP probe
    /// would (spec D5, coordinator item (d)).
    ///
    /// A charge that succeeds is a stimulus that went out, so it is counted
    /// in `probes.sent` and in `probes.by_lane` under the lane that is
    /// running — the half of `scan.status` a WebSocket job was missing (stage
    /// 6, live run 2). An HTTP send never comes through here: the `JobClient`
    /// charges the budget directly and the probe meter counts it, so no
    /// stimulus is counted twice.
    fn charge(&self, units: u32) -> bool {
        if !self.budget.charge(units) {
            return false;
        }
        if units == 0 {
            return true;
        }
        let units = u64::from(units);
        self.lane_charges.fetch_add(units, Ordering::SeqCst);
        let lane = self.current_lane();
        if let Some(lane) = lane {
            let mut by_lane = self
                .charges_by_lane
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            bump(by_lane.entry(lane).or_insert(0), units);
            if lane == LaneKind::Http && self.in_crawl.load(Ordering::SeqCst) {
                self.crawl_charges.fetch_add(units, Ordering::SeqCst);
            }
        }
        // Live, rather than at the next counter sync, so a long lane run is
        // honest about what it has already spent.
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut status.probes.sent, units);
        if let Some(lane) = lane {
            bump(status.probes.by_lane.entry(lane).or_insert(0), units);
        }
        true
    }

    fn budget_left(&self) -> u32 {
        self.budget.left()
    }

    fn deadline(&self) -> Instant {
        self.budget.deadline
    }

    fn cancelled(&self) -> bool {
        self.budget.cancel.is_cancelled()
    }

    /// A new token on every call (amendment 57): the per-job counter steps,
    /// so no two calls on one job agree. Not a key — `job_id()` is. The
    /// counter is mixed with this job's seed (amendment 55), so no two jobs
    /// share a first marker either.
    fn marker(&self) -> String {
        let counter = self.markers.fetch_add(1, Ordering::SeqCst);
        crate::util::marker(self.marker_seed, counter)
    }

    /// Fold the lane's counters in by **per-field maximum** (call B27), so a
    /// lane that restarts its own tally never walks `scan.status` backwards.
    fn report_l4(&self, counters: L4Counters) {
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        let current = status.l4.get_or_insert_with(L4Counters::default);
        current.cases = current.cases.max(counters.cases);
        current.crashes = current.crashes.max(counters.crashes);
        current.liveness_failures = current.liveness_failures.max(counters.liveness_failures);
        current.retired_elements = current.retired_elements.max(counters.retired_elements);
    }

    fn report_session_lost(&self) {
        self.mark_session_lost();
    }

    fn report_crawl_error(&self, origin: &str, reason: &str) {
        self.crawl_errors.fetch_add(1, Ordering::SeqCst);
        // A client-crawl reason is a `CrawlErrorKind` token; a browser-crawl
        // reason is free text, which stores `Other` and keeps the warn line.
        let parsed = CrawlErrorKind::parse(reason);
        *self
            .last_crawl_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(parsed.unwrap_or(CrawlErrorKind::Other));
        if parsed.is_some() {
            // A classified per-request failure is routine; the fold onto
            // `crawl.last_error` is the operator-visible signal.
            tracing::debug!(
                target: "aitm::scanner",
                origin,
                reason,
                "crawl request failed; discovery continues over what the lane still has"
            );
        } else {
            // Scrubbed at the sink: a free-text reason may quote a URL or an
            // error that carries a secret (security review, delta, 2026-11-01).
            tracing::warn!(
                target: "aitm::scanner",
                origin,
                reason = %util::scrub(reason),
                "crawl failed; discovery continues over what the lane still has"
            );
        }
    }

    fn report_forms_skipped(&self, count: u64) {
        self.forms_skipped.fetch_add(count, Ordering::SeqCst);
    }

    fn report_forms_submitted(&self, count: u64) {
        self.forms_submitted.fetch_add(count, Ordering::SeqCst);
    }

    fn report_session_canary(&self, canary: Canary) {
        self.with_session(|session| session.canary = canary);
    }

    /// Names only: the status records *that* the browser crawl was partial,
    /// never which cookie it could not set (spec D7).
    fn report_session_browser_partial(&self, cookie_names: Vec<String>) {
        if cookie_names.is_empty() {
            return;
        }
        self.with_session(|session| session.browser_partial = true);
    }
}

/// How one scheduled item ended.
enum ItemEnd {
    /// Keep going.
    Continue,
    /// End the job with this reason.
    Stop(StoppedReason),
}

/// Run one job to its terminal state (spec D5).
///
/// The supervisor around [`drive`]: the job body runs under `catch_unwind`,
/// so a lane or a check that panics still leaves the job terminal — `failed`,
/// with the panic named on `error` — with the terminal line pushed, the status
/// persisted and the registry handles released (the egress hold, the origin's
/// single-flight slot). Without it the task would die mid-flight and the job
/// stay `running` for good, which is the spec's anti-goal of a job that
/// outlives its budget, deadline or cancellation.
pub async fn run_job(engine: Arc<Engine>, ctx: JobStart) {
    let job = ctx.job.clone();
    let status = Arc::clone(&ctx.status);
    // The publisher lives out here so the `failed` line a panic produces
    // carries the job's own `seq`, after the lines the body already pushed.
    let bus = engine
        .late
        .get()
        .map(|s| Arc::clone(&s.jobs))
        .unwrap_or_default();
    let progress = Progress::new(bus, job.clone());

    let body = drive(Arc::clone(&engine), ctx, &progress);
    if let Err(payload) = AssertUnwindSafe(body).catch_unwind().await {
        let message = format!("the scan worker panicked: {}", panic_text(payload.as_ref()));
        tracing::error!(target: "aitm::scanner", job = %job, "{message}");
        let already_terminal = status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .state
            .is_terminal();
        if already_terminal {
            // The panic landed inside the terminal transition itself (a
            // persist that blew up): the status is final, so only the registry
            // hand-back may still be owed.
            engine.registry.finish(&job);
        } else {
            fail_job(&engine, &status, &progress, &job, &message);
        }
    }
}

/// The text of a panic payload, scrubbed and bounded, so what a buggy check
/// formatted into its panic never reaches a status or the bus unredacted.
fn panic_text(payload: &(dyn Any + Send)) -> String {
    let raw = if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "a non-string panic payload".to_string()
    };
    let scrubbed = util::scrub(&raw);
    match scrubbed.char_indices().nth(MAX_PANIC_TEXT) {
        Some((cut, _)) => format!("{}…", &scrubbed[..cut]),
        None => scrubbed,
    }
}

/// The body of one job: spec D5's phases, from `crawling` to the terminal
/// transition. Only ever called from [`run_job`], which supervises it.
async fn drive(engine: Arc<Engine>, ctx: JobStart, progress: &Progress) {
    let JobStart {
        job,
        profile,
        status,
        cancel,
        discovery,
        lanes,
        is_agent,
        started_by,
    } = ctx;

    // The services were bound before `start` admitted the job; if they went
    // away the job fails loudly rather than silently doing nothing.
    let (store, inner_client, guard, browser, agent_policy, config) = match engine.late.get() {
        Ok(s) => (
            Arc::clone(&s.store),
            Arc::clone(&s.client),
            Arc::clone(&s.guard),
            s.browser.clone(),
            Arc::clone(&s.agent_policy),
            Arc::clone(&s.config),
        ),
        Err(e) => {
            fail_job(&engine, &status, progress, &job, &e.to_string());
            return;
        }
    };

    let deadline = crate::jobs::deadline_in(profile.budget.time_s);
    let budget = Arc::new(JobBudget::new(
        u64::from(profile.budget.probes),
        deadline,
        cancel.clone(),
    ));
    let meter = Arc::new(ProbeMeter::default());
    let job_client: Arc<dyn ProxyClient> = Arc::new(JobClient::new(
        inner_client,
        &job,
        Arc::clone(&budget),
        Arc::clone(&meter),
        profile.http.record_probes,
        profile.http.version,
        profile.budget.per_host_errors.clone(),
    ));

    // Spec D7: the session's values live in the worker's memory and nowhere
    // else; only its names ever reach a status, a log or the bus.
    let observed = observe_session(store.as_ref(), &profile);
    let canary = observed
        .as_ref()
        .and_then(|s| s.canary_flow.as_ref())
        .and_then(CanaryRunner::new);
    if let Some(session) = &observed {
        let picked = session.profile.canary.clone();
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        let slot = guarded.session.get_or_insert_with(SessionStatus::default);
        slot.reused = true;
        slot.canary = picked;
    }

    let runtime = Arc::new(JobRuntime::new(
        job.clone(),
        profile.clone(),
        RuntimeServices {
            client: Arc::clone(&job_client),
            store: Arc::clone(&store),
            guard,
            browser,
            session: observed.as_ref().map(|s| Arc::new(s.material.clone())),
        },
        Arc::clone(&budget),
        Arc::clone(&status),
    ));
    let job_ctx: Arc<dyn JobCtx> = Arc::clone(&runtime) as Arc<dyn JobCtx>;

    set_phase(&status, JobState::Running, aitm_scan_model::Phase::Crawling);
    emit(progress, JobEvent::Started, &status, None);

    // --- crawling -----------------------------------------------------------
    let before: HashSet<FlowId> = store.list().into_iter().collect();
    runtime.set_crawling(true);
    let mut points: Vec<InsertionPoint> = Vec::new();
    let mut nodes: Vec<SiteNode> = Vec::new();
    for lane in &lanes {
        runtime.set_lane(lane.lane());
        // The whole crawl is one await: bound it by the job's deadline only
        // (`bounded_await`'s 30 s cap is for a single probe).
        match crate::client::await_until_deadline(
            deadline,
            &cancel,
            lane.discover(&profile.target, job_ctx.as_ref()),
        )
        .await
        {
            Ok(Ok(found)) => {
                points.extend(found.points);
                nodes.extend(found.nodes);
            }
            Ok(Err(e)) => {
                let text = e.to_string();
                let message = match map_lane_error_text(&text) {
                    LaneErrorKind::InvalidProfile(rest) => {
                        scan_error(ScanErrorCode::InvalidProfile, rest).to_string()
                    }
                    LaneErrorKind::SessionLost(_) => {
                        runtime.mark_session_lost();
                        continue;
                    }
                    LaneErrorKind::Other => text,
                };
                fail_job(&engine, &status, progress, &job, &message);
                return;
            }
            Err(end) => {
                // The job ran out of time, or was cancelled, mid-crawl.
                let reason = match end {
                    crate::client::AwaitEnd::Cancelled => StoppedReason::Cancelled,
                    _ => StoppedReason::Time,
                };
                runtime.set_crawling(false);
                sync_counters(&status, &meter, &runtime, &engine.issues, &job);
                finish_terminal(&engine, &status, progress, &job, Some(reason));
                return;
            }
        }
    }
    runtime.set_crawling(false);
    {
        let pages = crawl_pages(&runtime, store.as_ref(), &before, &job, &profile);
        let crawl_errors = runtime.crawl_errors.load(Ordering::SeqCst);
        let last_crawl_error = runtime.last_crawl_error();
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut guarded.crawl.pages, pages);
        // Amendment 39: fold the crawl's error tally in now, and when the crawl
        // made requests and every one failed (no page fetched) name why. A
        // partial failure (`pages > 0`) is visible in `crawl.errors` alone; the
        // job runs its passive checks over what it captured ("degrade, do not
        // fail"), so no `stopped_reason` or `error` is set here.
        raise(&mut guarded.crawl.errors, crawl_errors);
        fold_crawl_last_error(&mut guarded, last_crawl_error);
        bump(&mut guarded.points.found, points.len() as u64);
    }
    *discovery.write().unwrap_or_else(|e| e.into_inner()) = Discovery {
        points: points.clone(),
        nodes: nodes.clone(),
    };

    // --- planning -----------------------------------------------------------
    let catalogue = engine.catalogue();
    for conflict in catalogue.conflicts() {
        tracing::warn!(target: "aitm::scanner", job = %job, "{conflict}");
    }
    let selected = catalogue.selected(&profile.checks);
    let plan: SchedulePlan = scheduler::plan(&points, &nodes, &selected, &profile);
    {
        let scheduled = (plan.passive.len() + plan.active.len()) as u64;
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        guarded.points.skipped = plan.skipped;
        bump(&mut guarded.points.queued, scheduled);
        bump(&mut guarded.checks.scheduled, scheduled);
    }

    // How many items each point still owes, so `points.audited` rises once a
    // point's last check has run.
    let mut owed: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for item in plan.passive.iter().chain(plan.active.iter()) {
        *owed.entry(item.point).or_insert(0) += 1;
    }

    let run = RunCtx {
        engine: &engine,
        job: &job,
        plan: &plan,
        profile: &profile,
        status: &status,
        progress,
        runtime: &runtime,
        job_ctx: &job_ctx,
        lanes: &lanes,
        points: &points,
        nodes: &nodes,
        budget: &budget,
        meter: &meter,
        canary: canary.as_ref(),
        job_client: &job_client,
        config: &config,
        agent_policy: &agent_policy,
        is_agent,
        store: &store,
        started_by: &started_by,
    };

    let mut stopped: Option<StoppedReason> = None;
    for (phase, items) in [
        (aitm_scan_model::Phase::Passive, &plan.passive),
        (aitm_scan_model::Phase::Auditing, &plan.active),
    ] {
        if stopped.is_some() {
            break;
        }
        set_phase(&status, JobState::Running, phase);
        emit(progress, JobEvent::Phase, &status, None);
        for item in items.iter() {
            if let ItemEnd::Stop(reason) = run.gate(item).await {
                stopped = Some(reason);
                break;
            }
            run.run_item(item, &mut owed).await;
            run.sync();
            emit(progress, JobEvent::Progress, &status, None);
            if let Some(reason) = run.stop_now(None) {
                stopped = Some(reason);
                break;
            }
        }
    }

    // --- reporting ----------------------------------------------------------
    set_phase(
        &status,
        JobState::Running,
        aitm_scan_model::Phase::Reporting,
    );
    emit(progress, JobEvent::Phase, &status, None);
    sync_counters(&status, &meter, &runtime, &engine.issues, &job);

    let reason = match (stopped, cancel.is_cancelled()) {
        (Some(reason), _) => Some(reason),
        (None, true) => Some(StoppedReason::Cancelled),
        (None, false) => None,
    };
    finish_terminal(&engine, &status, progress, &job, reason);
}

/// Everything one phase loop needs, gathered so the per-item code reads as the
/// list of questions spec D5 asks before each item rather than as plumbing.
struct RunCtx<'a> {
    engine: &'a Arc<Engine>,
    job: &'a str,
    /// The plan the items came from, so an item's index resolves to a
    /// discovered point or to an origin item (amendment 38).
    plan: &'a SchedulePlan,
    profile: &'a ScanProfile,
    status: &'a Arc<RwLock<JobStatus>>,
    progress: &'a Progress,
    runtime: &'a Arc<JobRuntime>,
    job_ctx: &'a Arc<dyn JobCtx>,
    lanes: &'a [Arc<dyn Lane>],
    points: &'a [InsertionPoint],
    nodes: &'a [SiteNode],
    budget: &'a Arc<JobBudget>,
    meter: &'a Arc<ProbeMeter>,
    canary: Option<&'a CanaryRunner>,
    job_client: &'a Arc<dyn ProxyClient>,
    config: &'a Arc<aitm_core::Config>,
    agent_policy: &'a Arc<dyn Fn() -> aitm_core::AgentPolicy + Send + Sync>,
    is_agent: bool,
    store: &'a Arc<dyn FlowStore>,
    started_by: &'a aitm_scan_model::StartedBy,
}

impl RunCtx<'_> {
    /// The insertion point an item names: a discovered point, or the origin
    /// item an index past `points.len()` addresses (amendment 38).
    fn point_of(&self, item: &ScheduleItem) -> Option<&InsertionPoint> {
        self.plan.point_at(self.points, item.point)
    }

    /// Copy the live meters onto the status.
    fn sync(&self) {
        sync_counters(
            self.status,
            self.meter,
            self.runtime,
            &self.engine.issues,
            self.job,
        );
    }

    /// The questions spec D5 asks about the job itself: cancellation, the
    /// deadline, the budget, the agent policy, the session, the per-host error
    /// ladder and the issue ceiling.
    ///
    /// Pure, and asked **both** before and after each item: before, so nothing
    /// is started that the job can no longer afford; after, so a job whose last
    /// item spent the last probe reports *why* it stopped instead of looking
    /// like it finished its plan.
    fn stop_now(&self, item: Option<&ScheduleItem>) -> Option<StoppedReason> {
        if self.budget.cancel.is_cancelled() {
            return Some(StoppedReason::Cancelled);
        }
        if Instant::now() >= self.budget.deadline {
            return Some(StoppedReason::Time);
        }
        if self.budget.left() == 0 {
            return Some(StoppedReason::Budget);
        }
        if self.is_agent
            && matches!(
                (self.agent_policy)(),
                aitm_core::AgentPolicy::Paused | aitm_core::AgentPolicy::ReadOnly
            )
        {
            return Some(StoppedReason::Policy);
        }
        if self.runtime.session_is_lost() && self.profile.session.on_lost == OnLost::Stop {
            return Some(StoppedReason::SessionLost);
        }
        if let Some(point) = item.and_then(|item| self.point_of(item)) {
            let host = host_of_point(point);
            if !host.is_empty() && self.meter.ladder_state(&host) == LadderState::Tripped {
                return Some(StoppedReason::Errors);
            }
        }
        let total = self
            .status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .issues
            .total;
        if total >= u64::from(self.profile.budget.max_issues) {
            return Some(StoppedReason::Budget);
        }
        None
    }

    /// [`RunCtx::stop_now`] plus the D7 canary, which is asked once per item
    /// and therefore only before one.
    async fn gate(&self, item: &ScheduleItem) -> ItemEnd {
        if let Some(reason) = self.stop_now(Some(item)) {
            return ItemEnd::Stop(reason);
        }
        // Spec D7: every 25 probes the canary goes out; a status-class change
        // is a lost session, and under `on_lost: stop` it ends the audit.
        if let Some(canary) = self.canary {
            if canary.due() {
                if let Ok(CanaryOutcome::Lost { .. }) = canary.check(self.job_client.as_ref()).await
                {
                    self.runtime.mark_session_lost();
                    if self.profile.session.on_lost == OnLost::Stop {
                        return ItemEnd::Stop(StoppedReason::SessionLost);
                    }
                }
            }
        }
        ItemEnd::Continue
    }

    /// Run one `(point, check)` item and turn its verdict into issues.
    async fn run_item(
        &self,
        item: &ScheduleItem,
        owed: &mut std::collections::HashMap<usize, usize>,
    ) {
        let Some(point) = self.point_of(item) else {
            return;
        };
        let meta = item.check.meta().clone();
        let Some(lane) = self.lanes.iter().find(|l| l.lane() == point.lane) else {
            // Amendment 69, one branch earlier: a point whose lane is not on
            // this build cannot be hosted either; it is skipped with a sample,
            // never a silent `done`.
            let reason = format!(
                "lane {} is not on this build",
                serde_json::to_value(point.lane)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{:?}", point.lane))
            );
            self.item_skipped(item, &meta.id, &point.id, &reason, owed);
            return;
        };
        // Whatever this item charges belongs to this lane (spec D5,
        // `probes.by_lane`).
        self.runtime.set_lane(lane.lane());

        let hosted = match lane.probe_host_for(point, Arc::clone(self.job_ctx)) {
            // Amendment 38: an origin item carries no captured flow, and a lane
            // crate whose host is built from the captured flow refuses it
            // (`aitm-scan-http`: "has no source flow"). The engine then hosts
            // it itself, over the interim lane's synthesized `GET <origin>/`,
            // so origin-scoped checks run whatever crate holds the http slot.
            Err(lane_error)
                if point.flow.is_none()
                    && point.id.starts_with("origin:")
                    && point.lane == aitm_scan_model::LaneKind::Http =>
            {
                self.engine
                    .interim
                    .probe_host_for(point, Arc::clone(self.job_ctx))
                    .map_err(|engine_error| {
                        anyhow::anyhow!("{lane_error}; engine origin host: {engine_error}")
                    })
            }
            other => other,
        };
        let host = match hosted {
            Ok(host) => ArcHost(Arc::from(host)),
            // Amendment 69: the lane could not host this item — a flowless
            // origin item the engine's interim host did not rescue above, a
            // point whose flow left the store, a lost session. It is a skip
            // with a sample, never a silent `checks.done`.
            Err(e) => {
                let reason = e.to_string();
                self.note_lane_text(&reason);
                self.item_skipped(item, &meta.id, &point.id, &reason, owed);
                return;
            }
        };

        self.running_push(&meta.id);
        // Never past the job's own deadline: one check may not outlast it.
        let check_deadline =
            crate::jobs::deadline_in(self.profile.budget.check_timeout_s).min(self.budget.deadline);
        // A check that panics is one `error` verdict, not a dead job: the
        // item is still accounted for and the next one runs.
        let verdict = AssertUnwindSafe(bounded_await(
            check_deadline,
            &self.budget.cancel,
            item.check.run(point, &host),
        ))
        .catch_unwind()
        .await;
        self.running_pop(&meta.id);
        self.item_done(item.point, owed);

        let verdict = match verdict {
            Ok(Ok(verdict)) => verdict,
            // A check that did not finish is not a verdict: the job's own
            // counters already recorded its deadline or its cancellation.
            // Its *own* `check_timeout_s` is not recorded anywhere else
            // though — `probes.timeouts` counts probes, not checks — so it is
            // logged with the check id rather than vanishing (whole-branch
            // quality finding).
            Ok(Err(end)) => {
                if end == crate::client::AwaitEnd::Timeout {
                    tracing::debug!(
                        target: "aitm::scanner",
                        job = %self.job,
                        check = %meta.id,
                        timeout_s = self.profile.budget.check_timeout_s,
                        "the check hit its own timeout and reported no verdict",
                    );
                }
                return;
            }
            // The error path below counts, samples and logs it once per
            // distinct panic text (amendment 58).
            Err(payload) => {
                let detail = format!("the check panicked: {}", panic_text(payload.as_ref()));
                Verdict {
                    outcome: Outcome::Error,
                    confidence: Confidence::Tentative,
                    evidence: Evidence::default(),
                    detail,
                    poc_hint: None,
                    location: None,
                    more: Vec::new(),
                }
            }
        };
        if !matches!(verdict.outcome, Outcome::Vulnerable) {
            self.note_lane_text(&verdict.detail);
        }
        // Amendment 58: an `error` verdict is counted, sampled and logged;
        // `inconclusive` is a verdict like `clean` and leaves no trace here.
        if verdict.outcome == Outcome::Error {
            self.runtime
                .note_check_error(&meta.id, &point.id, &verdict.detail);
        }
        for (verdict, new) in issues_from_verdict(self.job, point, &meta, &verdict, self.nodes) {
            self.record_issue(new, &verdict, &meta, &host).await;
        }
    }

    /// Upsert one issue and, when it is new, re-record the flows that prove it
    /// and reproduce it through its PoC hint (spec D5/D6).
    async fn record_issue(
        &self,
        mut new: NewIssue,
        verdict: &Verdict,
        meta: &CheckMeta,
        host: &ArcHost,
    ) {
        let held = host.held_flows();
        // The store keys a flow by its own id, so re-recording preserves it:
        // the ids named here are exactly the ids the insert below lands under.
        if self.profile.http.record_probes == RecordProbes::IssuesOnly
            && new.evidence.probe_flows.is_empty()
        {
            new.evidence.probe_flows = held
                .iter()
                .map(|flow| aitm_scan_model::FlowRef(flow.id()))
                .collect();
        }

        let upsert = match self.engine.issues.upsert(new, util::now_ms()) {
            Ok(upsert) => upsert,
            Err(e) => {
                tracing::warn!(target: "aitm::scanner", job = %self.job, "the issue was not stored: {e}");
                return;
            }
        };
        let created = matches!(upsert, Upsert::Created(_));
        let issue = upsert.issue().clone();

        if created && self.profile.http.record_probes == RecordProbes::IssuesOnly {
            self.re_record(&held, &issue.id);
        }
        self.sync();
        self.progress.emit(
            JobEvent::Issue,
            &self.status.read().unwrap_or_else(|e| e.into_inner()),
            Some(issue.summary()),
        );

        if created {
            self.reproduce(&issue, verdict, meta, &held).await;
        }
    }

    /// Spec D5 "Record policy": the flows the host kept in memory become store
    /// flows marked `scan:<job>` and `issue:<id>`, flagged as replays.
    fn re_record(&self, held: &[Flow], issue_id: &str) {
        let job_mark = format!("scan:{}", self.job);
        let issue_mark = format!("issue:{issue_id}");
        for flow in held {
            let mut flow = flow.clone();
            // An existing flow (a second issue proved by the same probe) keeps
            // the marks it has and gains this issue's.
            let mut marks = self
                .store
                .get(flow.id())
                .map(|existing| existing.metadata().marks.clone())
                .unwrap_or_default();
            for mark in [&job_mark, &issue_mark] {
                if !marks.contains(mark) {
                    marks.push(mark.clone());
                }
            }
            let meta = flow.metadata_mut();
            meta.marks = marks;
            meta.is_replay = true;
            self.store.insert(flow);
        }
    }

    /// Spec D6: a `FindingRecord` is written only when the issue's PoC ran and
    /// passed. The hint is the contract; the engine holds no class list.
    async fn reproduce(
        &self,
        issue: &aitm_scan_model::Issue,
        verdict: &Verdict,
        meta: &CheckMeta,
        held: &[Flow],
    ) {
        let Some(hint) = verdict.poc_hint.as_ref() else {
            return;
        };
        if issue.confidence < Confidence::Firm || issue.lane != LaneKind::Http {
            return;
        }
        // No findings directory means no home for the PoC artifacts. Writing
        // them to the system temp dir would scatter attack payloads outside
        // the operator's evidence tree, so the issue simply stands alone.
        let Some(findings_dir) = self.config.findings.dir.clone() else {
            tracing::info!(
                target: "aitm::scanner",
                job = %self.job,
                issue = %issue.id,
                "no reproduction: `findings.dir` is not configured"
            );
            return;
        };
        let Some(Flow::Http(probe_flow)) = held.last().cloned() else {
            return;
        };
        let out_dir = util::scan_dir(&findings_dir, "pocs");
        // Blocking filesystem work on the async job path, deliberately: one
        // small PoC file per *issue*, not per probe, and the write is already
        // bounded by the issue ceiling. Accepted with this note rather than
        // moved to `spawn_blocking` (whole-branch quality finding).
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            tracing::warn!(target: "aitm::scanner", job = %self.job, "no reproduction: {e}");
            return;
        }

        // Deliberately **no** `FindingRecorder`: `reproduce_and_record` writes
        // the record itself, and a recorder here would make the PoC runner
        // write a second one for the same run.
        let host = CommandHost::new(
            self.store.as_ref(),
            self.job_client.as_ref(),
            self.runtime.guard.as_ref(),
            None,
        )
        .with_config(Arc::clone(self.config))
        .with_frontend(crate::util::frontend_of_token(&self.started_by.frontend))
        .with_poc_dir(Some(out_dir.clone()));
        let host = match self.started_by.client_label.as_deref() {
            Some(label) => host.with_client_label(label),
            None => host,
        };
        let host = match self.engine.late.get().ok().and_then(|s| s.egress.clone()) {
            Some(egress) => host.with_egress(egress),
            None => host,
        };

        let payload = verdict.evidence.payload.clone().unwrap_or_default();
        let input = crate::reproduce_link::ReproductionInput {
            issue,
            hint,
            probe_flow: &probe_flow,
            payload: &payload,
            meta,
            started_by: self.started_by,
        };
        match crate::reproduce_link::reproduce_and_record(input, &host, Some(&out_dir)).await {
            Ok(done) => {
                if let Some(note) = &done.note {
                    tracing::info!(
                        target: "aitm::scanner",
                        job = %self.job,
                        issue = %issue.id,
                        "{}",
                        util::scrub(note)
                    );
                }
                let poc_ref = (!done.poc_ref.is_empty()).then(|| done.poc_ref.clone());
                if poc_ref.is_some() || done.finding_id.is_some() {
                    if let Err(e) =
                        self.engine
                            .issues
                            .set_links(&issue.id, poc_ref, done.finding_id)
                    {
                        tracing::warn!(target: "aitm::scanner", job = %self.job, "the issue links were not saved: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!(
                target: "aitm::scanner",
                job = %self.job,
                issue = %issue.id,
                "the PoC could not be built: {}",
                util::scrub(&e.to_string())
            ),
        }
    }

    /// Read a lane or check error through the prefix convention.
    fn note_lane_text(&self, text: &str) {
        if let LaneErrorKind::SessionLost(_) = map_lane_error_text(text) {
            self.runtime.mark_session_lost();
        }
    }

    fn running_push(&self, id: &str) {
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        if status.checks.running.len() < MAX_RUNNING_IDS {
            status.checks.running.push(id.to_string());
        }
    }

    fn running_pop(&self, id: &str) {
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = status.checks.running.iter().position(|r| r == id) {
            status.checks.running.remove(at);
        }
    }

    /// One item is accounted for — it ran, or the engine could not run it:
    /// the point's owed counter falls, and the point is audited with the last
    /// item that named it.
    ///
    /// An origin item is an item like any other — it is in `points.queued` and
    /// `checks.scheduled` — but it is not a discovered insertion point, so it
    /// never bumps `points.audited` (amendment 38). A skipped item settles the
    /// owed count exactly as a finished one does (amendment 69, call C7), so
    /// `points.audited` reads the same whether a lane could host the point or
    /// not; only `checks.done` tells the two apart.
    fn settle_point(&self, point: usize, owed: &mut std::collections::HashMap<usize, usize>) {
        let last = match owed.get_mut(&point) {
            Some(left) => {
                *left = left.saturating_sub(1);
                *left == 0
            }
            None => false,
        };
        if last && point < self.points.len() {
            let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
            bump(&mut status.points.audited, 1);
        }
    }

    /// One item finished: the check counter rises, and the point settles.
    fn item_done(&self, point: usize, owed: &mut std::collections::HashMap<usize, usize>) {
        self.settle_point(point, owed);
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut status.checks.done, 1);
    }

    /// One item the engine could not run because no lane could host its point
    /// (amendment 69): it is counted on `checks.skipped`, never on
    /// `checks.done`, and the first distinct `(check, detail)` reason is kept
    /// on `checks.skipped_samples` (up to [`MAX_CHECK_ERROR_SAMPLES`]) and
    /// logged **once** — so a lane that hosts nothing says so instead of
    /// reporting a job of silent successes. The reason is scrubbed first and
    /// cut like an evidence excerpt (spec amendment 16: scrub, then bound).
    /// Kept apart from `checks.errors`/`error_samples` (call C6): a skip is
    /// not an `error` verdict. The point still settles (call C7).
    fn item_skipped(
        &self,
        item: &ScheduleItem,
        check: &str,
        point_id: &str,
        reason: &str,
        owed: &mut std::collections::HashMap<usize, usize>,
    ) {
        self.settle_point(item.point, owed);
        let detail = Evidence::excerpt(&util::scrub(reason));
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut status.checks.skipped, 1);
        let samples = &mut status.checks.skipped_samples;
        if samples.len() >= MAX_CHECK_ERROR_SAMPLES
            || samples
                .iter()
                .any(|s| s.check == check && s.detail == detail)
        {
            return;
        }
        tracing::debug!(
            target: "aitm::scanner",
            job = %self.job,
            check = %check,
            point = %point_id,
            "no lane could host the point; the item is skipped: {detail}",
        );
        samples.push(CheckErrorSample {
            check: check.to_string(),
            point: point_id.to_string(),
            detail,
        });
    }
}

/// Turn one check run into the issues it reports: the root verdict plus its
/// `more` siblings, flattened one level (coordinator item (g)).
///
/// A verdict may move the issue's location off the point it was found at — an
/// origin-scoped check that lists exposed paths reports one issue per path —
/// so `location.path`/`name` override the point's before the dedupe key is
/// computed and the issues separate instead of merging into one.
fn issues_from_verdict(
    job: &str,
    point: &InsertionPoint,
    meta: &CheckMeta,
    verdict: &Verdict,
    nodes: &[SiteNode],
) -> Vec<(Verdict, NewIssue)> {
    let node = point
        .site_node
        .as_ref()
        .and_then(|id| nodes.iter().find(|n| &n.id == id));
    let mut out = Vec::new();
    for one in std::iter::once(verdict).chain(verdict.more.iter()) {
        if one.outcome != Outcome::Vulnerable {
            continue;
        }
        out.push((one.clone(), new_issue(job, point, meta, one, node)));
    }
    out
}

/// The `location.l4` block of an L4 issue (T6 child spec S6.3; D6 dedupe):
/// `ip`/`port`/`proto` from the point's site node (`host`, `port`, `scheme`
/// via [`SiteNode::l4_transport`]), `grammar` = [`SiteNode::l4_grammar`],
/// `field_path` = the point's path inside the message, `mutation` = the first
/// mutator of the evidence chain truncated at its first `(` (the mutation
/// class). `None` when the node's scheme is not an L4 transport: the block is
/// absent rather than guessed `tcp`.
fn l4_location(point: &InsertionPoint, node: &SiteNode, verdict: &Verdict) -> Option<L4Location> {
    let proto: L4Transport = node.l4_transport()?;
    let mutation = verdict
        .evidence
        .l4
        .as_ref()
        .and_then(|l4| l4.mutation_chain.first())
        .map(|m| m.split('(').next().unwrap_or(m).to_string())
        .filter(|m| !m.is_empty());
    Some(L4Location {
        ip: node.host.clone(),
        port: node.port,
        proto,
        grammar: node.l4_grammar().map(str::to_string),
        field_path: point.path.clone(),
        mutation,
    })
}

/// The issue one vulnerable verdict reports. `node` is the point's site node
/// when discovery recorded one; an L4 point's target and `location.l4` come
/// from it (the point carries no URL).
fn new_issue(
    job: &str,
    point: &InsertionPoint,
    meta: &CheckMeta,
    verdict: &Verdict,
    node: Option<&SiteNode>,
) -> NewIssue {
    let is_l4 = matches!(point.lane, LaneKind::L4Stream | LaneKind::L4Packet);
    // An L4 point's site node is its target tuple (the point carries no URL).
    let l4_node = node.filter(|_| is_l4);
    let l4 = l4_node.and_then(|node| l4_location(point, node, verdict));
    let (scheme, host, port, path) = match l4_node {
        Some(node) => (
            node.scheme.clone(),
            node.host.clone(),
            node.port,
            node.path_template.clone(),
        ),
        None => parts_of(point),
    };
    let path = verdict
        .location
        .as_ref()
        .and_then(|l| l.path.clone())
        .unwrap_or(path);
    let name = verdict
        .location
        .as_ref()
        .and_then(|l| l.name.clone())
        .unwrap_or_else(|| point.name.clone());
    let mut evidence = verdict.evidence.clone();
    evidence.matched = evidence
        .matched
        .as_deref()
        .map(|text| Evidence::excerpt(&util::scrub(text)));
    evidence.payload = evidence.payload.as_deref().map(util::scrub);

    NewIssue {
        job: job.to_string(),
        check_id: meta.id.clone(),
        class: meta.class.clone(),
        name: meta.name.clone(),
        severity: meta.severity,
        confidence: verdict.confidence.min(meta.confidence_max),
        lane: point.lane,
        target: IssueTarget { scheme, host, port },
        location: IssueLocation {
            method: point.method.clone(),
            path: path.clone(),
            path_template: path,
            kind: point.kind,
            name,
            field_path: point.path.clone(),
            ws_path: None,
            l4,
        },
        evidence,
        description: meta.description.clone(),
        remediation: meta.remediation.clone(),
        passive: meta.technique == Technique::Passive,
    }
}

/// `(scheme, host, port, path)` of the request a point sits in.
fn parts_of(point: &InsertionPoint) -> (String, String, u16, String) {
    let fallback = ("http".to_string(), String::new(), 80u16, "/".to_string());
    let Some(url) = point.url.as_deref() else {
        return fallback;
    };
    let Ok(parsed) = url::Url::parse(url) else {
        return fallback;
    };
    let scheme = parsed.scheme().to_string();
    let default_port = crate::util::default_port(&scheme).unwrap_or(80);
    (
        scheme,
        parsed.host_str().unwrap_or_default().to_string(),
        parsed.port().unwrap_or(default_port),
        parsed.path().to_string(),
    )
}

/// The key a point's host is laddered under, or empty when the point carries
/// no usable URL.
///
/// It is [`crate::client::ladder_key`] and nothing else: the client writes the
/// ladder under that key on every probe, so reading it under any other
/// spelling is reading an empty ladder (whole-branch quality finding).
fn host_of_point(point: &InsertionPoint) -> String {
    let (scheme, host, port, _) = parts_of(point);
    if host.is_empty() {
        return String::new();
    }
    crate::client::ladder_key(&scheme, &format!("{host}:{port}"))
}

/// Pick the session to reuse, when the profile asked for one (spec D7).
fn observe_session(store: &dyn FlowStore, profile: &ScanProfile) -> Option<ObservedSession> {
    if profile.session.mode != SessionMode::Observed {
        return None;
    }
    let from_flow = profile.session.from_flow.map(|flow| flow.0);
    profile
        .target
        .origins
        .iter()
        .find_map(|origin| session::pick_observed(store, origin, from_flow))
}

/// How many pages the crawling phase fetched, counting each page **once**
/// (spec D5; stage 6 finding, Coder/client crawl).
///
/// The two crawl paths leave different traces, so they are read differently
/// and never added together:
///
/// * A **browser** crawl charges one unit per navigation and leaves every
///   capture the page made — its subresources included — in the store, so its
///   charges are the page count and its store growth is not.
/// * A **client** crawl charges nothing of its own (its GETs go through the
///   `JobClient`, which counts them as probes) and leaves exactly one
///   crawl-marked capture per page, so its store growth is the page count.
///
/// Growth is read by mark, not by size: only a flow added during this phase
/// carrying both this job's `scan:<job>` mark and the `crawl` mark is a page,
/// so a probe recorded under `record_probes: all` is never miscounted as one.
fn crawl_pages(
    runtime: &JobRuntime,
    store: &dyn FlowStore,
    before: &HashSet<FlowId>,
    job: &str,
    profile: &ScanProfile,
) -> u64 {
    let browser_crawls =
        runtime.browser.is_some() && profile.crawl.use_browser != UseBrowser::Never;
    if browser_crawls {
        return runtime.crawl_charges();
    }
    let job_mark = format!("scan:{job}");
    store
        .list()
        .into_iter()
        .filter(|id| !before.contains(id))
        .filter_map(|id| store.get(id))
        .filter(|flow| is_crawl_capture(flow, &job_mark))
        .count() as u64
}

/// Whether `flow` is one of this job's crawl captures: both this job's mark
/// and the `crawl` mark, which only the crawl paths put on a flow.
fn is_crawl_capture(flow: &Flow, job_mark: &str) -> bool {
    let marks = &flow.metadata().marks;
    marks.iter().any(|mark| mark == job_mark)
        && marks
            .iter()
            .any(|mark| mark == crate::interim_lane::CRAWL_MARK)
}

/// Amendment 39: a client crawl that made at least one request and had every
/// one fail (no page fetched) names why on `crawl.last_error`, so a frontend
/// can report the cause; a partial failure (`pages > 0`) is visible in
/// `crawl.errors` alone and leaves `last_error` as it was. Applied once, at the
/// end of the crawling phase, over the already-folded `crawl.errors`/`pages`.
/// `sync_counters` never touches `last_error`.
fn fold_crawl_last_error(status: &mut JobStatus, last_error: Option<CrawlErrorKind>) {
    if status.crawl.errors > 0 && status.crawl.pages == 0 {
        status.crawl.last_error = last_error;
    }
}

/// Copy the live meters onto the status, monotonically.
///
/// `probes.sent` is the probe meter's reading **plus** the units lanes
/// charged: an HTTP send is counted by the meter inside the `JobClient`, and
/// every other stimulus — a WebSocket frame, an L4 case, a browser navigation
/// — by [`JobCtx::charge`]. The two paths are disjoint (the client charges
/// the `JobBudget` directly and never calls `charge`), so no stimulus is
/// counted twice. `probes.by_lane` splits the same total: the meter's sends
/// are the HTTP lane's, each lane's charges are its own (spec D5).
fn sync_counters(
    status: &Arc<RwLock<JobStatus>>,
    meter: &ProbeMeter,
    runtime: &JobRuntime,
    issues: &IssueStore,
    job: &str,
) {
    let (issues_total, by_severity, by_confidence) = issues.tally_for_job(job);
    let charges = runtime.charges_by_lane();
    let sent = meter.sent.load(Ordering::SeqCst);
    let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
    raise(
        &mut guarded.probes.sent,
        sent.saturating_add(runtime.lane_charges()),
    );
    for (lane, units) in &charges {
        raise(guarded.probes.by_lane.entry(*lane).or_insert(0), *units);
    }
    if sent > 0 {
        let http = sent.saturating_add(charges.get(&LaneKind::Http).copied().unwrap_or(0));
        raise(
            guarded.probes.by_lane.entry(LaneKind::Http).or_insert(0),
            http,
        );
    }
    raise(
        &mut guarded.probes.errors,
        meter.errors.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.probes.timeouts,
        meter.timeouts.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.crawl.errors,
        runtime.crawl_errors.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.crawl.forms_skipped,
        runtime.forms_skipped.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.crawl.forms_submitted,
        runtime.forms_submitted.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.checks.errors,
        runtime.check_errors.load(Ordering::SeqCst),
    );
    // The sample list only ever grows (to its cap) on the runtime, so a
    // longer reading is the newer one and never walks the status backwards.
    // Compared under the lock and cloned only when it has grown: this runs
    // after every item, and the list is usually the same length as last time.
    let samples = runtime
        .check_error_samples
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if samples.len() > guarded.checks.error_samples.len() {
        guarded.checks.error_samples = samples.clone();
    }
    drop(samples);
    raise(
        &mut guarded.probes.rate_waits,
        meter.rate_waits.load(Ordering::SeqCst),
    );
    raise(&mut guarded.issues.total, issues_total);
    guarded.issues.by_severity = by_severity;
    guarded.issues.by_confidence = by_confidence;
    live_elapsed(&mut guarded);
}

/// `elapsed_ms` as of now for a job that is still running (spec D5 "monotonic
/// from `started_at`"); a terminal status keeps the value its transition
/// fixed. Every writer of a snapshot calls this, so a push line and
/// `scan.status` agree (panel, delta review, 2026-11-01).
fn live_elapsed(status: &mut JobStatus) {
    if status.finished_at.is_none() {
        status.elapsed_ms = util::now_ms().saturating_sub(status.started_at);
    }
}

/// Move the status to `state`/`phase`.
fn set_phase(status: &Arc<RwLock<JobStatus>>, state: JobState, phase: aitm_scan_model::Phase) {
    let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
    // A cancel that landed while a phase was running is not undone by it.
    if !guarded.state.is_terminal() && guarded.state != JobState::Cancelling {
        guarded.state = state;
    }
    guarded.phase = phase;
}

/// Publish one line for the status as it stands.
fn emit(
    progress: &Progress,
    event: JobEvent,
    status: &Arc<RwLock<JobStatus>>,
    issue: Option<aitm_scan_model::IssueSummary>,
) -> bool {
    let mut snapshot = status.read().unwrap_or_else(|e| e.into_inner()).clone();
    live_elapsed(&mut snapshot);
    progress.emit(event, &snapshot, issue)
}

/// End a job that could not run at all.
fn fail_job(
    engine: &Arc<Engine>,
    status: &Arc<RwLock<JobStatus>>,
    progress: &Progress,
    job: &str,
    message: &str,
) {
    {
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        guarded.error = Some(util::scrub(message));
    }
    terminal(
        engine,
        status,
        progress,
        job,
        JobState::Failed,
        Some(StoppedReason::Failed),
        JobEvent::Failed,
    );
}

/// End a job that ran, with `reason` when it stopped early.
fn finish_terminal(
    engine: &Arc<Engine>,
    status: &Arc<RwLock<JobStatus>>,
    progress: &Progress,
    job: &str,
    reason: Option<StoppedReason>,
) {
    // A job somebody (or a policy) stopped is `cancelled`; a job that ran out
    // of budget, time, patience with a host or session is `done` with the
    // reason, because it finished what it was still allowed to do (spec D5).
    let (state, event) = match reason {
        Some(StoppedReason::Cancelled | StoppedReason::Policy) => {
            (JobState::Cancelled, JobEvent::Cancelled)
        }
        _ => (JobState::Done, JobEvent::Finished),
    };
    terminal(engine, status, progress, job, state, reason, event);
}

/// The one terminal transition: stamp the status, push the line, persist, and
/// hand the live handles back to the registry.
fn terminal(
    engine: &Arc<Engine>,
    status: &Arc<RwLock<JobStatus>>,
    progress: &Progress,
    job: &str,
    state: JobState,
    reason: Option<StoppedReason>,
    event: JobEvent,
) {
    let snapshot = {
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        let now = util::now_ms();
        guarded.state = state;
        guarded.phase = aitm_scan_model::Phase::Done;
        guarded.finished_at = Some(now);
        guarded.elapsed_ms = now.saturating_sub(guarded.started_at);
        guarded.stopped_reason = reason;
        guarded.checks.running.clear();
        guarded.clone()
    };
    progress.emit(event, &snapshot, None);
    persist(engine, &snapshot, job);
    engine.registry.finish(job);
}

/// Write the terminal status and the job's issues under
/// `<findings.dir>/scan/jobs/<job>.json` (spec D5 "Persistence").
fn persist(engine: &Arc<Engine>, status: &JobStatus, job: &str) {
    let Some(dir) = engine.cfg.findings_dir.as_deref() else {
        return;
    };
    let jobs_dir = util::scan_dir(dir, "jobs");
    // Blocking filesystem work on the async job path, deliberately: one small
    // JSON file, written once per job on the terminal path, where nothing is
    // waiting on the task. Accepted with this note rather than moved to
    // `spawn_blocking` (whole-branch quality finding).
    if let Err(e) = std::fs::create_dir_all(&jobs_dir) {
        tracing::warn!(target: "aitm::scanner", job = %job, "the job was not persisted: {e}");
        return;
    }
    let record = PersistedJob {
        status: status.clone(),
        issues: engine.issues.for_job(job),
    };
    let path = jobs_dir.join(format!("{job}.json"));
    match serde_json::to_vec_pretty(&record) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!(target: "aitm::scanner", job = %job, "the job was not persisted: {e}");
            }
        }
        Err(e) => {
            tracing::warn!(target: "aitm::scanner", job = %job, "the job was not persisted: {e}")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jobs::test_support::*;

    use std::sync::Arc;
    use std::time::Duration;

    use aitm_core::{AgentPolicy, Flow, FlowStore};
    use aitm_scan_model::{
        CrawlErrorKind, JobEvent, JobNotification, JobState, JobStatus, L4Counters, LaneKind,
        OnLost, Phase, RecordProbes, StoppedReason,
    };

    /// Amendment 38 (spec D4/D8): an origin-scoped HTTP check runs once per
    /// target origin even when the crawl discovered no insertion point at all,
    /// and it is run against the origin item, not against a discovered point.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_origin_scoped_check_runs_on_an_origin_without_points() {
        let check = FakeCheck::with_scope(
            "fake.origin",
            "demo",
            aitm_scan_model::CheckScope::Origin,
            FakeRun::clean(),
        );
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(Vec::new())
                .with_check(Arc::clone(&check) as Arc<dyn aitm_scan_model::Check>),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.points.found, 0, "the lane discovered nothing");
        assert_eq!(status.points.audited, 0, "an origin is not a point");
        assert_eq!(status.points.queued, 1, "the origin item is queued");
        assert_eq!(status.checks.scheduled, 1);
        assert_eq!(status.checks.done, 1);
        assert_eq!(
            check.points_seen(),
            vec!["origin:http://scan.test:80".to_string()],
            "the check ran once, against the origin item"
        );
    }

    /// Amendment 38 on a lane crate whose host needs a captured flow
    /// (`aitm-scan-http` refuses "a point with no source flow"): the origin
    /// item is still run, hosted by the engine's own origin host (the interim
    /// lane's synthesized `GET <origin>/`), so the origin-scoped checks do not
    /// vanish from the product when a lane crate takes the http slot (found
    /// live: `test_t3_h2_observe.py` produced no issue on T2's lane).
    #[tokio::test(flavor = "multi_thread")]
    async fn an_origin_item_is_hosted_by_the_engine_when_the_lane_cannot() {
        // Like a real origin-scoped check (the h2 observe kinds), the fake
        // sends nothing through `probe()`: an origin host has no insertion
        // point to inject into and refuses it.
        let check = FakeCheck::with_scope(
            "fake.origin",
            "demo",
            aitm_scan_model::CheckScope::Origin,
            FakeRun::clean().with_probes(0),
        );
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(Vec::new())
                .refusing_flowless_points()
                .with_check(Arc::clone(&check) as Arc<dyn aitm_scan_model::Check>),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.checks.scheduled, 1);
        assert_eq!(status.checks.done, 1);
        assert_eq!(
            check.points_seen(),
            vec!["origin:http://scan.test:80".to_string()],
            "the origin check ran on the engine's origin host"
        );
        assert_eq!(
            status.checks.errors, 0,
            "a hosted origin item is not a check error"
        );
    }

    /// Amendment 38: an origin item is counted in `points.queued` and
    /// `checks.scheduled` like any other item, but never in `points.audited` —
    /// that counter is about discovered insertion points.
    #[tokio::test(flavor = "multi_thread")]
    async fn origin_items_do_not_count_as_audited_points() {
        let origin = FakeCheck::with_scope(
            "fake.origin",
            "demo",
            aitm_scan_model::CheckScope::Origin,
            FakeRun::clean(),
        );
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_check(FakeCheck::new("fake.point", "demo", FakeRun::clean()))
                .with_check(Arc::clone(&origin) as Arc<dyn aitm_scan_model::Check>),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.points.found, 2);
        assert_eq!(status.points.audited, 2, "the two discovered points");
        // Two points x (the lane's point check + the engine's three shipped
        // passive checks, spec amendment 24) plus the one origin item.
        assert_eq!(
            status.checks.scheduled, 9,
            "four point checks per point plus one origin item"
        );
        assert_eq!(
            status.points.queued, 9,
            "every scheduled item is queued work"
        );
        assert_eq!(status.checks.done, 9);
        assert_eq!(
            origin.points_seen(),
            vec!["origin:http://scan.test:80".to_string()]
        );
    }

    /// Amendment 69, one branch earlier: a point whose lane is not on this
    /// build (a WS point discovered on an http-only build) is skipped with a
    /// sample naming the lane, never a silent `done`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_item_whose_lane_is_not_on_this_build_is_skipped_with_a_sample() {
        let mut ws_point = fake_point("w1", "chan", "ws://scan.test/socket");
        ws_point.lane = LaneKind::Ws;
        let h = Harness::new().with_lane(FakeLane::http().with_points(vec![ws_point]).with_check(
            FakeCheck::on_lane("fake.ws", "demo", LaneKind::Ws, FakeRun::clean()),
        ));
        h.bind();
        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::Http, LaneKind::Ws];
        let started = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect("the http lane is available");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        let ws_samples: Vec<_> = status
            .checks
            .skipped_samples
            .iter()
            .filter(|s| s.check == "fake.ws")
            .collect();
        assert!(
            status.checks.skipped >= 1 && !ws_samples.is_empty(),
            "the ws item on an http-only build is skipped with a sample: {:?}",
            status.checks
        );
        assert!(
            ws_samples[0]
                .detail
                .contains("lane ws is not on this build"),
            "{:?}",
            ws_samples[0].detail
        );
        // Tester: the lane-absent branch keeps every amendment-69 promise the
        // cannot-host branch makes — nothing is a silent `done`, the skips
        // account for the schedule, a skip is not an error, and the one
        // sample names the point it was seen on.
        assert_eq!(
            status.checks.done, 0,
            "an item nobody could host never finished: {:?}",
            status.checks
        );
        assert_eq!(
            status.checks.done + status.checks.skipped,
            status.checks.scheduled,
            "every scheduled item is accounted for: {:?}",
            status.checks
        );
        assert_eq!(status.checks.errors, 0, "a skip is not a check error");
        assert!(status.checks.error_samples.is_empty());
        assert_eq!(ws_samples.len(), 1, "one sample per (check, detail)");
        assert_eq!(ws_samples[0].point, "w1");
        assert_eq!(status.stopped_reason, None);
    }

    /// Amendment 69: an item whose lane cannot host it — a point the lane
    /// refuses to build a host for (no captured flow, a lost session) — is
    /// `checks.skipped` with a sample naming the check, the first point and
    /// the scrubbed reason, never a silent `checks.done`. Call C7: the item
    /// still settles its point's owed count, so `points.audited` reads the
    /// same as it would have, and `done + skipped == scheduled`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_item_the_lane_cannot_host_is_skipped_with_a_sample_not_done() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_check(FakeCheck::new("fake.point", "demo", FakeRun::clean()))
                .with_host_error("the fake lane hosts nothing"),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, None);
        // Two points x (the lane's point check + the engine's three shipped
        // passive checks, spec amendment 24); the lane hosts none of them.
        assert_eq!(status.checks.scheduled, 8);
        assert_eq!(
            status.checks.done, 0,
            "an item that never ran is not a finished run"
        );
        assert_eq!(status.checks.skipped, 8);
        assert_eq!(
            status.checks.done + status.checks.skipped,
            status.checks.scheduled,
            "every scheduled item is accounted for"
        );
        assert_eq!(
            status.checks.errors, 0,
            "a skip is not a check error (call C6)"
        );
        assert!(
            status.checks.error_samples.is_empty(),
            "a skip is not sampled as an error: {:?}",
            status.checks.error_samples
        );
        assert_eq!(
            status.checks.skipped_samples.len(),
            4,
            "one sample per distinct (check, detail): the two points share \
             each of the four checks, and every skip has the same reason: {:?}",
            status.checks.skipped_samples
        );
        assert!(
            status
                .checks
                .skipped_samples
                .iter()
                .all(|s| s.detail == "the fake lane hosts nothing"),
            "{:?}",
            status.checks.skipped_samples
        );
        let sampled: std::collections::BTreeSet<&str> = status
            .checks
            .skipped_samples
            .iter()
            .map(|s| s.check.as_str())
            .collect();
        assert_eq!(
            sampled,
            std::collections::BTreeSet::from([
                "cookie-flag",
                "fake.point",
                "reflection",
                "security-header",
            ]),
            "every scheduled check is named once"
        );
        assert!(
            status
                .checks
                .skipped_samples
                .iter()
                .all(|s| s.point == "p1" || s.point == "p2"),
            "a sample names the first point the pair was seen on: {:?}",
            status.checks.skipped_samples
        );
        assert_eq!(
            status.points.audited, 2,
            "a skipped item still settles its point (call C7)"
        );
        assert_eq!(status.issues.total, 0, "a skip is not an issue");
    }

    /// Amendment 69 (call C6): a skip sample's detail goes through
    /// `util::scrub` before it is stored, and the list stops at
    /// [`MAX_CHECK_ERROR_SAMPLES`] distinct `(check, detail)` pairs while
    /// `checks.skipped` keeps counting.
    #[tokio::test(flavor = "multi_thread")]
    async fn skipped_samples_are_scrubbed_and_capped() {
        let mut lane =
            FakeLane::http().with_points(vec![fake_point("p1", "q", "http://scan.test/search")]);
        for i in 0..9 {
            lane = lane.with_check(FakeCheck::new(
                &format!("fake.point{i}"),
                "demo",
                FakeRun::clean(),
            ));
        }
        let h =
            Harness::new().with_lane(lane.with_host_error("no host: Authorization: Bearer abc"));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        // One point x (nine lane checks + the engine's three shipped passive
        // checks, spec amendment 24): twelve items, none of them hosted.
        assert_eq!(status.checks.scheduled, 12);
        assert_eq!(status.checks.skipped, 12);
        assert_eq!(status.checks.done, 0);
        assert_eq!(
            status.checks.skipped_samples.len(),
            aitm_scan_model::MAX_CHECK_ERROR_SAMPLES,
            "twelve distinct checks, eight kept: {:?}",
            status.checks.skipped_samples
        );
        assert!(
            status
                .checks
                .skipped_samples
                .iter()
                .all(|s| s.detail == "no host: Authorization: [redacted]"),
            "the bearer token never reaches scan.status: {:?}",
            status.checks.skipped_samples
        );
        let named: std::collections::BTreeSet<&str> = status
            .checks
            .skipped_samples
            .iter()
            .map(|s| s.check.as_str())
            .collect();
        assert_eq!(named.len(), 8, "every kept sample names a distinct check");
    }

    /// Tester (amendment 69, spec amendment 16): a skip reason is cut like an
    /// evidence excerpt after the scrub — a lane that refuses with a
    /// response-sized message leaves a bounded sample, never the whole text —
    /// and the cut never splits a character.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_skip_reason_is_bounded_like_an_evidence_excerpt() {
        let long_reason = format!("no host: {}", "é".repeat(300));
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_check(FakeCheck::new("fake.point", "demo", FakeRun::clean()))
                .with_host_error(&long_reason),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.checks.done, 0);
        assert_eq!(status.checks.skipped, status.checks.scheduled);
        assert!(
            !status.checks.skipped_samples.is_empty(),
            "{:?}",
            status.checks
        );
        for sample in &status.checks.skipped_samples {
            assert!(
                sample.detail.len() <= aitm_scan_model::MAX_EXCERPT_BYTES,
                "a sample detail is bounded: {} bytes",
                sample.detail.len()
            );
            assert!(
                sample.detail.starts_with("no host: "),
                "the cut keeps the head of the reason: {:?}",
                sample.detail
            );
            assert!(
                long_reason.starts_with(sample.detail.as_str()),
                "the cut lands on a character boundary and changes nothing before it"
            );
            assert!(
                sample.detail.len() > aitm_scan_model::MAX_EXCERPT_BYTES - 4,
                "the bound is the excerpt bound, not a shorter one: {} bytes",
                sample.detail.len()
            );
        }
    }

    /// Amendment 58 (T5's inert lane): a check that answers `Outcome::Error`
    /// is counted on `checks.errors` once per run, and its first distinct
    /// `(check, detail)` pair is kept on `checks.error_samples` naming the
    /// check and the first point it failed on — one sample for two points,
    /// not two. The run is still `done`, still counted, and reports no issue.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_erroring_check_is_counted_sampled_and_logged() {
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.error",
            "demo",
            FakeRun::error("runner missing"),
        )));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, None);
        // Two points x (the erroring check + the engine's three shipped
        // passive checks, spec amendment 24); only the erroring check errors.
        assert_eq!(status.checks.scheduled, 8);
        assert_eq!(
            status.checks.done, 8,
            "an erroring run is still a finished run"
        );
        assert_eq!(
            status.checks.errors, 2,
            "one error per point the check ran on"
        );
        assert_eq!(
            status.checks.error_samples,
            vec![aitm_scan_model::CheckErrorSample {
                check: "fake.error".to_string(),
                point: "p1".to_string(),
                detail: "runner missing".to_string(),
            }],
            "one sample per distinct (check, detail), naming the first point"
        );
        assert_eq!(status.issues.total, 0, "an error is not an issue");
    }

    /// Amendment 58: a sample's detail goes through `util::scrub` before it is
    /// stored (a credential a runner echoed never reaches `scan.status`), and
    /// the job keeps at most eight distinct samples — a ninth distinct detail
    /// is counted in `checks.errors` but not kept.
    #[tokio::test(flavor = "multi_thread")]
    async fn check_error_samples_are_scrubbed_and_capped_at_eight() {
        const DETAILS: [&str; 9] = [
            "runner missing: token=abc123",
            "detail two",
            "detail three",
            "detail four",
            "detail five",
            "detail six",
            "detail seven",
            "detail eight",
            "detail nine",
        ];
        let mut lane = FakeLane::http();
        for (i, detail) in DETAILS.iter().enumerate() {
            lane = lane.with_check(FakeCheck::new(
                &format!("fake.error{i}"),
                "demo",
                FakeRun::error(*detail),
            ));
        }
        let h = Harness::new().with_lane(lane);
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.checks.errors, 18, "nine checks over two points");
        assert_eq!(
            status.checks.error_samples.len(),
            aitm_scan_model::MAX_CHECK_ERROR_SAMPLES,
            "the ninth distinct detail is not kept: {:?}",
            status.checks.error_samples
        );
        let scrubbed = status
            .checks
            .error_samples
            .iter()
            .find(|s| s.check == "fake.error0")
            .expect("the first check's sample is kept");
        assert_eq!(scrubbed.point, "p1");
        assert_eq!(scrubbed.detail, "runner missing: token=[redacted]");
        assert!(!scrubbed.detail.contains("abc123"));
        let kept: std::collections::BTreeSet<&str> = status
            .checks
            .error_samples
            .iter()
            .map(|s| s.detail.as_str())
            .collect();
        assert_eq!(kept.len(), 8, "every kept sample is a distinct detail");
        let missing: Vec<&str> = DETAILS[1..]
            .iter()
            .copied()
            .filter(|d| !kept.contains(d))
            .collect();
        assert_eq!(
            missing.len(),
            1,
            "exactly one of the nine details is dropped"
        );
    }

    /// Amendment 58: a sample's detail is bounded like an evidence excerpt,
    /// and the bound is applied **after** the scrub (amendment 16's order), so
    /// a runner that dumps a whole response into its error cannot grow the
    /// status and cannot smuggle a credential past the redactor by sitting
    /// near the cut. Bounded first, the scrub would shrink the text below
    /// `MAX_EXCERPT_BYTES`; the length is what tells the two orders apart.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_check_error_detail_is_scrubbed_then_bounded() {
        let detail = format!("runner missing: token=abc123 {}", "b".repeat(300));
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.loud",
            "demo",
            FakeRun::error(detail),
        )));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        let sample = status
            .checks
            .error_samples
            .first()
            .expect("the error is sampled");
        assert!(
            !sample.detail.contains("abc123"),
            "the credential survived: {:?}",
            sample.detail
        );
        assert!(sample
            .detail
            .starts_with("runner missing: token=[redacted] b"));
        assert_eq!(
            sample.detail.len(),
            aitm_scan_model::check::MAX_EXCERPT_BYTES,
            "scrubbed first, then cut to the excerpt bound"
        );
    }

    /// AC T1-1 (spec D3/D5): `scan.start` returns while the job is still
    /// queued, and the worker takes it all the way to `done` on its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_returns_queued_within_the_call_and_the_job_reaches_done() {
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.clean",
            "demo",
            FakeRun::clean(),
        )));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        assert_eq!(started.status.state, JobState::Queued);
        assert_eq!(started.status.probes.budget, 2000);
        assert_eq!(started.job, started.status.job);

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.phase, Phase::Done);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.points.found, 2);
        assert_eq!(status.points.audited, 2);
        // Two points x (the lane's one check + the engine's three shipped
        // passive checks, which run on every http point whatever lane holds
        // the slot; spec amendment 24). The passives read the captured flow
        // and send nothing, so the probe count is the fake check's alone.
        assert_eq!(status.checks.scheduled, 8);
        assert_eq!(status.checks.done, 8);
        assert!(status.checks.running.is_empty());
        assert_eq!(status.probes.sent, 2, "one probe per point");
        assert!(status.finished_at.is_some());
    }

    /// Spec D5 "Cancellation": the token is observed between probes; the entry
    /// moves to `cancelled` with its issues intact and sends nothing more.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_moves_to_cancelled_and_keeps_issues() {
        let h = Harness::new()
            .with_lane(
                FakeLane::http()
                    // The catalogue is id-sorted, so `fake.hit` is scheduled
                    // before `fake.wait` and the issue exists before the block.
                    .with_check(FakeCheck::scripted(
                        "fake.hit",
                        "demo",
                        vec![FakeRun::vulnerable()],
                    ))
                    .with_check(FakeCheck::blocking("fake.wait")),
            )
            .with_egress();
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        // Wait until the vulnerable verdict has been recorded. The bound is the
        // tests' safety net (`TERMINAL_NET`), never a measured figure: the
        // blocking check holds the job open until the cancel below, so the
        // issue appears as soon as the scheduler reaches it.
        let net = std::time::Instant::now() + crate::jobs::test_support::TERMINAL_NET;
        while h.engine.issues.for_job(&started.job).is_empty() {
            assert!(std::time::Instant::now() < net, "no issue was raised");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // A running job holds the egress posture: race-free here because the
        // blocking check keeps the job open until the cancel below (the
        // panicking-lane test used to read this and raced its own finaliser).
        assert!(h.egress_confined(), "a running job holds the posture");

        let cancelling = h
            .engine
            .registry
            .cancel(&started.job)
            .expect("the job is in the registry");
        // `cancel` answers with the status as it stands: `Cancelling` while the
        // worker is still unwinding, or already `Cancelled` when the finaliser
        // beat this read on the multi-thread runtime (CI Rust gate on #229,
        // #287, #290, #292, 2026-11-02: "left: Cancelled, right: Cancelling";
        // coordinator's amendment 71b, test determinism). Either says the cancel
        // took; the terminal facts are asserted after the signal below.
        assert!(
            matches!(cancelling.state, JobState::Cancelling | JobState::Cancelled),
            "cancel answered {:?}",
            cancelling.state
        );

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Cancelled);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Cancelled));
        assert_eq!(h.engine.issues.for_job(&started.job).len(), 1);
        // Spec D5 "Cancellation": the confinement token drops with the entry;
        // `finish` clears it before flipping the terminal signal, so this read
        // is deterministic (PR 2a spec panel Minor).
        assert!(
            !h.egress_confined(),
            "the egress hold outlived the cancelled job"
        );

        let finished_at = status
            .finished_at
            .expect("a terminal job has a finish time");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            h.client.last_call_ms() <= finished_at,
            "the client was called after the job finished"
        );

        // Cancelling again is idempotent.
        let again = h.engine.registry.cancel(&started.job).expect("still held");
        assert_eq!(again.state, JobState::Cancelled);
    }

    /// Amendment 39, full run: a lane whose crawl failed on every request
    /// (three `h2_not_negotiated` reports, no page) ends `done` with
    /// `stopped_reason: null` and `error: null` (D5 "degrade, do not fail"),
    /// and the status says why: `crawl.errors == 3`,
    /// `crawl.last_error == h2_not_negotiated`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_all_failing_crawl_surfaces_its_reason_and_the_job_still_finishes() {
        let h = Harness::new().with_lane(FakeLane::http().with_crawl_errors(vec![
            ("http://scan.test", "h2_not_negotiated"),
            ("http://scan.test", "h2_not_negotiated"),
            ("http://scan.test", "h2_not_negotiated"),
        ]));
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.error, None);
        assert_eq!(status.crawl.errors, 3);
        assert_eq!(status.crawl.pages, 0);
        assert_eq!(
            status.crawl.last_error,
            Some(aitm_scan_model::CrawlErrorKind::H2NotNegotiated)
        );
    }

    /// Amendment 39, full run: one failed request beside a fetched page is a
    /// partial failure — counted in `crawl.errors`, no `last_error`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_partially_failing_crawl_sets_no_reason_in_a_full_run() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_crawl_flows(1)
                .with_crawl_errors(vec![("http://scan.test", "connect_refused")]),
        );
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.crawl.errors, 1);
        assert!(status.crawl.pages >= 1, "pages: {}", status.crawl.pages);
        assert_eq!(status.crawl.last_error, None);
    }

    /// Amendment 53, full run: a lane that reports three submitted forms
    /// through `JobCtx::report_forms_submitted` ends with
    /// `crawl.forms_submitted == 3` on the terminal status — the counter the
    /// model carried but nothing wrote until the hook existed.
    #[tokio::test(flavor = "multi_thread")]
    async fn reported_form_submissions_reach_the_status() {
        let h = Harness::new().with_lane(FakeLane::http().with_forms_submitted(3));
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.crawl.forms_submitted, 3, "{:?}", status.crawl);
        assert_eq!(status.crawl.forms_skipped, 0, "a submit is not a skip");
        assert_eq!(status.crawl.errors, 0);
    }

    /// Spec D5 / call B15: a host whose every request fails in transport
    /// (amendment 40: connect and transport failures climb the ladder, a
    /// status never does) trips the per-host error ladder, and the job ends
    /// `done` with `stopped_reason: errors`.
    ///
    /// Whole-branch quality finding: the ladder was keyed two ways — the
    /// client recorded under the raw request authority (`scan.test`) and
    /// `stop_now` read `host_of_point`'s `host:port` (`scan.test:80`) — so for
    /// a point whose URL carries **no explicit port** (every ordinary target;
    /// `FakeLane::http` points are `http://scan.test/search`) the two never
    /// met and the reason was never reported. Both sides now go through
    /// `client::ladder_key`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_all_erroring_host_stops_the_job_with_stopped_reason_errors() {
        let h = Harness::new()
            // Amendment 40: a 5xx is an answer; only a transport failure or a
            // timeout counts on the ladder, so the host fails at the transport.
            .failing("connect refused")
            .with_lane(FakeLane::http().with_check(FakeCheck::new(
                "fake.probe",
                "demo",
                FakeRun::clean().with_probes(1),
            )));
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        // One transport failure is enough; the ratio rule can never fire, so
        // the only thing under test is the consecutive ladder and its key.
        profile.budget.per_host_errors = aitm_scan_model::PerHostErrors {
            consecutive: 1,
            ratio: 1.0,
        };
        let started =
            crate::jobs::start(&h.engine, profile, operator(), false).expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(
            h.client.authorities().first().map(String::as_str),
            Some("scan.test"),
            "the premise: the probe's authority carries no explicit port"
        );
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Errors));
        assert!(
            status.checks.done < status.checks.scheduled,
            "the tripped ladder must leave an item unrun: {} of {}",
            status.checks.done,
            status.checks.scheduled
        );
    }

    /// Spec D5 "Budget and pacing": one budget across the job, and the job ends
    /// when it is spent.
    #[tokio::test(flavor = "multi_thread")]
    async fn budget_stops_the_job() {
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.spender",
            "demo",
            FakeRun::clean().with_probes(2),
        )));
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.budget.probes = 3;
        let started =
            crate::jobs::start(&h.engine, profile, operator(), false).expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Budget));
        assert!(
            status.probes.sent <= 3,
            "the budget was overspent: {}",
            status.probes.sent
        );
        assert!(h.client.calls() <= 3, "{} sends", h.client.calls());
    }

    /// Spec D3 "Progress push" and call B13: the line order, the monotonic
    /// `seq`, and the 4/s coalescing that applies to `progress` alone.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_lines_are_ordered_and_coalesced() {
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.hit",
            "demo",
            FakeRun::vulnerable(),
        )));
        h.bind();
        let mut rx = h.bus.subscribe();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;

        let mut lines: Vec<JobNotification> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            assert_eq!(event.kind, "scan");
            assert_eq!(event.job, started.job);
            lines.push(
                serde_json::from_value(crate::verbs::value_to_json(&event.payload))
                    .expect("the payload is a JobNotification"),
            );
        }

        assert!(lines.len() >= 3, "only {} lines", lines.len());
        assert_eq!(
            lines.first().expect("a first line").event,
            JobEvent::Started
        );
        assert_eq!(lines.last().expect("a last line").event, JobEvent::Finished);
        for pair in lines.windows(2) {
            assert!(
                pair[1].seq > pair[0].seq,
                "seq went {} -> {}",
                pair[0].seq,
                pair[1].seq
            );
        }
        assert!(
            lines.iter().any(|l| l.event == JobEvent::Issue),
            "a vulnerable verdict pushes an issue line"
        );
        assert!(
            lines.iter().any(|l| l.event == JobEvent::Phase),
            "phase changes are pushed"
        );
    }

    /// Call B13 in isolation, on a clock the test steps by hand: `progress` is
    /// dropped while the 250 ms window has not elapsed, a `phase` line in
    /// between is always published, and `seq` counts published lines only so
    /// it is dense.
    ///
    /// It used to sleep fifty times for 10 ms and assert `<= 4` lines, which
    /// held only while the whole loop ran inside a second — a flake under a
    /// loaded gate (whole-branch quality finding). With an injected clock the
    /// count is exact and nothing sleeps.
    #[tokio::test(flavor = "multi_thread")]
    async fn progress_is_coalesced_to_four_a_second_and_phase_never_is() {
        use crate::worker::{Progress, MIN_PROGRESS_INTERVAL};
        use std::sync::Mutex;

        // A clock that only moves when the test moves it.
        let clock = Arc::new(Mutex::new(std::time::Instant::now()));
        let read = Arc::clone(&clock);
        let advance = |by: Duration| {
            let mut at = clock.lock().expect("clock lock");
            *at = at.checked_add(by).expect("the test clock stays in range");
        };

        let bus = Arc::new(aitm_core::JobBus::default());
        let mut rx = bus.subscribe();
        let progress = Progress::with_clock(
            bus.clone(),
            "scan-1a2b3c4d".to_string(),
            Arc::new(move || *read.lock().expect("clock lock")),
        );
        let status = JobStatus::default();

        // Fifty ticks of 10 ms: the window opens at tick 0 (the first line is
        // always eligible) and again at 250 ms. 490 ms of ticks is two.
        let step = Duration::from_millis(10);
        let ticks = 50u32;
        let mut sent_progress = 0usize;
        let mut sent_phase = 0usize;
        for i in 0..ticks {
            if progress.emit(JobEvent::Progress, &status, None) {
                sent_progress += 1;
            }
            if i == 25 {
                assert!(
                    progress.emit(JobEvent::Phase, &status, None),
                    "a phase line is never coalesced"
                );
                sent_phase += 1;
            }
            advance(step);
        }

        let elapsed = step * (ticks - 1);
        let want = 1 + (elapsed.as_millis() / MIN_PROGRESS_INTERVAL.as_millis()) as usize;
        assert_eq!(
            sent_progress, want,
            "one line at the start and one per {MIN_PROGRESS_INTERVAL:?} of {elapsed:?}"
        );
        assert_eq!(sent_progress, 2, "the arithmetic above, spelled out");
        assert_eq!(sent_phase, 1);

        // One more window, and exactly one more line: the rule is per window,
        // not per call.
        advance(MIN_PROGRESS_INTERVAL);
        assert!(progress.emit(JobEvent::Progress, &status, None));
        assert!(
            !progress.emit(JobEvent::Progress, &status, None),
            "a second line inside the same window is coalesced"
        );
        sent_progress += 1;

        let mut seqs = Vec::new();
        while let Ok(event) = rx.try_recv() {
            seqs.push(event.seq);
        }
        assert_eq!(
            seqs.len(),
            sent_progress + sent_phase,
            "seq counts sent lines only"
        );
        assert_eq!(seqs.first(), Some(&1), "seq starts at one");
        assert!(
            seqs.windows(2).all(|p| p[1] == p[0] + 1),
            "seq is dense over sent lines: {seqs:?}"
        );
    }

    /// Spec D5 "Record policy": under `issues_only` a probe never reaches the
    /// store **except** through the issue re-recording, which marks the flows
    /// `scan:<job>` and `issue:<id>` and flags them as replays.
    #[tokio::test(flavor = "multi_thread")]
    async fn vulnerable_verdict_creates_an_issue_and_re_records_held_flows() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::new("fake.hit", "demo", FakeRun::vulnerable())),
        );
        h.bind();
        assert_eq!(h.store.count(), 0);

        let mut profile = h.profile(&["http://scan.test"]);
        assert_eq!(profile.http.record_probes, RecordProbes::IssuesOnly);
        profile.budget.probes = 10;
        let started =
            crate::jobs::start(&h.engine, profile, operator(), false).expect("the job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);

        let issues = h.engine.issues.for_job(&started.job);
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(issue.class, "demo");
        assert_eq!(issue.check_id, "fake.hit");

        assert_eq!(h.store.count(), 1, "exactly the flow that proved it");
        let stored = flows(h.store.as_ref());
        let Flow::Http(flow) = &stored[0] else {
            panic!("the re-recorded flow is HTTP");
        };
        assert_eq!(
            flow.metadata.marks,
            vec![
                format!("scan:{}", started.job),
                format!("issue:{}", issue.id)
            ]
        );
        assert!(flow.metadata.is_replay);
        assert_eq!(
            issue.evidence.probe_flows,
            vec![aitm_scan_model::FlowRef(flow.id)]
        );

        // A clean verdict adds nothing to either store.
        let h2 = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::new("fake.clean", "demo", FakeRun::clean())),
        );
        h2.bind();
        let started = crate::jobs::start(
            &h2.engine,
            h2.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h2.wait_terminal(&started.job).await;
        assert_eq!(h2.store.count(), 0);
        assert!(h2.engine.issues.for_job(&started.job).is_empty());
    }

    /// Spec D6: `check_id` is not in the dedupe key, so two checks of one class
    /// on one point are one issue counted twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_checks_one_class_one_issue() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::new("fake.one", "demo", FakeRun::vulnerable()))
                .with_check(FakeCheck::new("fake.two", "demo", FakeRun::vulnerable())),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;

        assert_eq!(status.issues.total, 1);
        let issues = h.engine.issues.for_job(&started.job);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].occurrences, 2);
    }

    /// Spec D5 "Policy re-check": an agent-started job reads the policy at
    /// every scheduling step; an operator-started job ignores it.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_job_stops_when_policy_pauses() {
        let h = Harness::new().with_agent_active().with_lane(
            FakeLane::http().with_check(FakeCheck::new("fake.clean", "demo", FakeRun::clean())),
        );
        h.bind();
        h.set_policy(AgentPolicy::All);
        h.flip_policy_after(1, AgentPolicy::Paused);

        let started =
            crate::jobs::start(&h.engine, h.profile(&["http://scan.test"]), agent(), false)
                .expect("the agent job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Cancelled);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Policy));

        // The same flip leaves an operator-started job alone.
        let h2 = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.clean",
            "demo",
            FakeRun::clean(),
        )));
        h2.bind();
        h2.flip_policy_after(1, AgentPolicy::Paused);
        let started = crate::jobs::start(
            &h2.engine,
            h2.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the operator job starts");
        let status = h2.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.stopped_reason, None);
    }

    /// Spec D5 "Persistence": the terminal status is written under
    /// `<findings.dir>/scan/jobs/<job>.json` and `scan.list` reads it back.
    #[tokio::test(flavor = "multi_thread")]
    async fn terminal_status_is_persisted_and_reloaded() {
        let h = Harness::new().with_findings_dir().with_lane(
            FakeLane::http().with_check(FakeCheck::new("fake.clean", "demo", FakeRun::clean())),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;

        let dir = h.findings_dir();
        let path = crate::util::scan_dir(&dir, "jobs").join(format!("{}.json", started.job));
        assert!(path.is_file(), "{} was not written", path.display());

        let fresh = crate::jobs::JobRegistry::new(50);
        assert_eq!(fresh.load_history(&dir).expect("history loads"), 1);
        let listed = fresh.list(false, 10);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].job, started.job);
        assert_eq!(listed[0].state, JobState::Done);
        assert!(
            fresh.list(true, 10).is_empty(),
            "a reloaded job is not active"
        );
    }

    /// Coordinator decision 1: a `discover` error carrying the
    /// `invalid_profile: ` prefix fails the job with the D3 code.
    #[tokio::test(flavor = "multi_thread")]
    async fn discover_invalid_profile_prefix_fails_the_job() {
        let h = Harness::new()
            .with_lane(FakeLane::http().with_discover_error("invalid_profile: bad seed"));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("start does not know yet");
        let status = h.wait_terminal(&started.job).await;

        assert_eq!(status.state, JobState::Failed);
        assert_eq!(
            status.error,
            Some("scan: invalid_profile: bad seed".to_string())
        );
        assert_eq!(status.stopped_reason, Some(StoppedReason::Failed));
    }

    /// Call B27: `report_l4` merges by per-field maximum, so a counter a lane
    /// resets never walks a `JobStatus` backwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn report_l4_folds_into_status_monotonically() {
        let h = Harness::new().with_lane(FakeLane::http().with_l4_reports(vec![
            L4Counters {
                cases: 10,
                crashes: 1,
                ..L4Counters::default()
            },
            L4Counters {
                cases: 5,
                crashes: 1,
                liveness_failures: 2,
                ..L4Counters::default()
            },
        ]));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;

        assert_eq!(
            status.l4,
            Some(L4Counters {
                cases: 10,
                crashes: 1,
                liveness_failures: 2,
                retired_elements: 0,
            })
        );
    }

    /// Spec D7: a lost session stops the audit under `on_lost: stop` and is
    /// only recorded under `continue`; the `scan: session_lost: ` probe-error
    /// prefix is the same signal by another route.
    #[tokio::test(flavor = "multi_thread")]
    async fn report_session_lost_stops_or_continues_per_on_lost() {
        for (payload, on_lost, reason, audited) in [
            (
                SESSION_LOST_PAYLOAD,
                OnLost::Stop,
                Some(StoppedReason::SessionLost),
                1,
            ),
            (SESSION_LOST_PAYLOAD, OnLost::Continue, None, 2),
            (
                SESSION_LOST_ERR_PAYLOAD,
                OnLost::Stop,
                Some(StoppedReason::SessionLost),
                1,
            ),
        ] {
            let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::scripted(
                "fake.session",
                "demo",
                vec![FakeRun::clean().with_payload(payload)],
            )));
            h.bind();

            let mut profile = h.profile(&["http://scan.test"]);
            profile.session.on_lost = on_lost;
            let started =
                crate::jobs::start(&h.engine, profile, operator(), false).expect("the job starts");
            let status = h.wait_terminal(&started.job).await;

            assert_eq!(status.state, JobState::Done, "{payload} / {on_lost:?}");
            assert_eq!(status.stopped_reason, reason, "{payload} / {on_lost:?}");
            assert!(
                status.session.as_ref().expect("observed mode").lost,
                "{payload} / {on_lost:?}"
            );
            assert_eq!(status.points.audited, audited, "{payload} / {on_lost:?}");
        }
    }

    /// A [`super::JobRuntime`] over the harness's services, with no job task
    /// behind it, so a test can drive the `JobCtx` hooks and `sync_counters`
    /// by hand (the jobs `Harness` binds no browser, and a browser crawl only
    /// fails outright on a guard refusal of its seed).
    fn bare_runtime(
        h: &Harness,
        job: &str,
        started_at: u64,
    ) -> (super::JobRuntime, Arc<std::sync::RwLock<JobStatus>>) {
        use std::sync::RwLock;
        use std::time::Instant;

        let status = Arc::new(RwLock::new(JobStatus {
            job: job.to_string(),
            started_at,
            ..JobStatus::default()
        }));
        let runtime = super::JobRuntime::new(
            job.to_string(),
            h.profile(&["http://scan.test"]),
            super::RuntimeServices {
                client: Arc::clone(&h.client) as Arc<dyn aitm_core::ProxyClient>,
                store: Arc::clone(&h.store) as Arc<dyn FlowStore>,
                guard: Arc::clone(&h.guard) as Arc<dyn aitm_core::ScopeRateGuard>,
                browser: None,
                session: None,
            },
            Arc::new(crate::client::JobBudget::new(
                100,
                Instant::now() + Duration::from_secs(60),
                tokio_util::sync::CancellationToken::new(),
            )),
            Arc::clone(&status),
        );
        (runtime, status)
    }

    /// Amendment 57 (T5/T6 keyed per-job state on `marker()` and missed every
    /// lookup): `JobCtx::marker` mints a fresh token on every call, while
    /// `JobCtx::job_id` is the stable per-job key and is the status's `job`.
    #[test]
    fn markers_are_fresh_per_call_and_job_id_is_stable() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee7", 1);

        let first = runtime.marker();
        let second = runtime.marker();
        assert_ne!(first, second, "every marker() call is a new token");
        assert_eq!(first.len(), second.len(), "same shape, different value");

        let id = runtime.job_id().to_string();
        assert_eq!(runtime.job_id(), id, "job_id() is stable across calls");
        assert_eq!(runtime.job_id(), "scan-0c0ffee7");
        assert_eq!(
            status.read().unwrap_or_else(|e| e.into_inner()).job,
            id,
            "job_id() is the status's job"
        );
    }

    /// Amendment 55 (T3's 2b panel, security Minor): every job mints its own
    /// marker seed, so two jobs' first markers differ — a target cannot forge
    /// a verdict by echoing `aitm00000000` before it has seen a probe — while
    /// one job's markers still step (the second differs from the first).
    #[test]
    fn two_jobs_first_markers_differ() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (job_a, _) = bare_runtime(&h, "scan-0000aaaa", 1);
        let (job_b, _) = bare_runtime(&h, "scan-0000bbbb", 1);

        let first_a = job_a.marker();
        let first_b = job_b.marker();
        assert_ne!(
            first_a, first_b,
            "two jobs on one engine never share a first marker"
        );
        assert_ne!(
            first_a, "aitm00000000",
            "a job's first marker is not the bare counter"
        );
        let second_a = job_a.marker();
        assert_ne!(first_a, second_a, "a job's markers keep stepping");
        for m in [&first_a, &first_b, &second_a] {
            assert_eq!(m.len(), 12, "{m:?} is not aitm+8 hex");
            assert!(m.starts_with("aitm"), "{m:?} is not aitm+8 hex");
            assert!(
                m[4..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{m:?} is not aitm+8 lowercase hex"
            );
        }
    }

    /// T7/T2 live runs (2026-11-01): a crawl error a lane reports through
    /// `JobCtx::report_crawl_error` is one unit of `crawl.errors` on the
    /// status once the counters are synced — once, not once per sync — and
    /// a skipped form reported through `report_forms_skipped` is one unit of
    /// `crawl.forms_skipped`.
    #[test]
    fn reported_crawl_errors_and_skipped_forms_reach_the_status() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee1", 1);
        let meter = crate::client::ProbeMeter::default();
        let issues = crate::issues::IssueStore::new(None);

        runtime.report_crawl_error("http://scan.test", "the browser refused the seed");
        runtime.report_forms_skipped(1);
        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee1");
        {
            let seen = status.read().expect("status");
            assert_eq!(seen.crawl.errors, 1);
            assert_eq!(seen.crawl.forms_skipped, 1);
        }

        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee1");
        let seen = status.read().expect("status");
        assert_eq!(seen.crawl.errors, 1, "a sync copies, it does not add");
        assert_eq!(seen.crawl.forms_skipped, 1);
    }

    /// Amendment 53: `report_forms_submitted` accumulates across calls and a
    /// sync copies the runtime's tally onto `crawl.forms_submitted` — it does
    /// not add it again — exactly as `forms_skipped` behaves.
    #[test]
    fn reported_form_submissions_are_copied_not_added_by_a_sync() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee2", 1);
        let meter = crate::client::ProbeMeter::default();
        let issues = crate::issues::IssueStore::new(None);

        runtime.report_forms_submitted(2);
        runtime.report_forms_submitted(1);
        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee2");
        assert_eq!(status.read().expect("status").crawl.forms_submitted, 3);

        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee2");
        let seen = status.read().expect("status");
        assert_eq!(
            seen.crawl.forms_submitted, 3,
            "a sync copies, it does not add"
        );
        assert_eq!(seen.crawl.forms_skipped, 0);
    }

    /// Replicate the end-of-crawling fold the worker does: fold `crawl.errors`
    /// from the runtime (via `sync_counters`) and then apply amendment 39's
    /// reason rule over the page count the crawl reached.
    fn fold_crawl_phase(
        status: &Arc<std::sync::RwLock<JobStatus>>,
        runtime: &super::JobRuntime,
        pages: u64,
    ) {
        let meter = crate::client::ProbeMeter::default();
        let issues = crate::issues::IssueStore::new(None);
        {
            let mut guarded = status.write().expect("status");
            guarded.crawl.pages = pages;
        }
        let job = {
            let guarded = status.read().expect("status");
            guarded.job.clone()
        };
        super::sync_counters(status, &meter, runtime, &issues, &job);
        let last = runtime.last_crawl_error();
        let mut guarded = status.write().expect("status");
        super::fold_crawl_last_error(&mut guarded, last);
    }

    /// Amendment 39 (spec D5 "degrade, do not fail"): a crawl that made requests
    /// and had every one fail (no page fetched) surfaces its classified reason
    /// on `crawl.last_error`, while the job sets no `stopped_reason` or `error`
    /// of its own from the crawl errors — it runs on over what it still has.
    #[test]
    fn an_all_failing_crawl_surfaces_its_reason() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee3", 1);

        // Three failed requests, all classified `h2_not_negotiated`; no page.
        for _ in 0..3 {
            runtime.report_crawl_error("http://scan.test", "h2_not_negotiated");
        }
        fold_crawl_phase(&status, &runtime, 0);

        let seen = status.read().expect("status");
        assert_eq!(seen.crawl.errors, 3);
        assert_eq!(seen.crawl.pages, 0);
        assert_eq!(seen.crawl.last_error, Some(CrawlErrorKind::H2NotNegotiated));
        assert_eq!(seen.stopped_reason, None, "the crawl errors do not stop it");
        assert_eq!(seen.error, None);
    }

    /// Amendment 39, call C4: a partial failure (`pages > 0`) shows in
    /// `crawl.errors` alone — no reason is named, so a frontend reads it as "the
    /// crawl lost some requests" rather than "the crawl failed".
    #[test]
    fn a_partially_failing_crawl_sets_no_reason() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee4", 1);

        runtime.report_crawl_error("http://scan.test", "connect_refused");
        fold_crawl_phase(&status, &runtime, 1);

        let seen = status.read().expect("status");
        assert_eq!(seen.crawl.errors, 1);
        assert!(seen.crawl.pages >= 1);
        assert_eq!(seen.crawl.last_error, None);
    }

    /// A free-text browser-crawl reason is not a token: it stores `Other` (and
    /// keeps the warn log), so the reason surface is still a closed vocabulary.
    #[test]
    fn a_free_text_crawl_reason_stores_other() {
        use aitm_scan_model::JobCtx;
        let h = Harness::bare();
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee5", 1);

        runtime.report_crawl_error("http://scan.test", "the browser refused the seed");
        assert_eq!(runtime.last_crawl_error(), Some(CrawlErrorKind::Other));

        fold_crawl_phase(&status, &runtime, 0);
        assert_eq!(
            status.read().expect("status").crawl.last_error,
            Some(CrawlErrorKind::Other)
        );
    }

    /// The fold rule in isolation: a reason is named only when the crawl made
    /// requests (`errors > 0`) and fetched no page (`pages == 0`).
    #[test]
    fn fold_crawl_last_error_follows_the_errors_and_pages_rule() {
        let mut all_failed = JobStatus::default();
        all_failed.crawl.errors = 2;
        all_failed.crawl.pages = 0;
        super::fold_crawl_last_error(&mut all_failed, Some(CrawlErrorKind::Timeout));
        assert_eq!(all_failed.crawl.last_error, Some(CrawlErrorKind::Timeout));

        let mut partial = JobStatus::default();
        partial.crawl.errors = 2;
        partial.crawl.pages = 1;
        super::fold_crawl_last_error(&mut partial, Some(CrawlErrorKind::Timeout));
        assert_eq!(partial.crawl.last_error, None, "a page was fetched");

        let mut clean = JobStatus::default();
        super::fold_crawl_last_error(&mut clean, Some(CrawlErrorKind::Timeout));
        assert_eq!(clean.crawl.last_error, None, "no request failed");
    }

    /// Spec D5 "monotonic from `started_at`" (T9 live run, panel delta
    /// review): every writer of a status snapshot — `sync_counters` and the
    /// push `emit` — carries a live `elapsed_ms` while the job runs, so a
    /// push line and `scan.status` agree; a terminal snapshot keeps the value
    /// the terminal transition fixed.
    #[tokio::test]
    async fn sync_counters_and_push_lines_carry_live_elapsed_ms() {
        let h = Harness::bare();
        let started_at = crate::util::now_ms().saturating_sub(5_000);
        let (runtime, status) = bare_runtime(&h, "scan-0c0ffee2", started_at);
        let meter = crate::client::ProbeMeter::default();
        let issues = crate::issues::IssueStore::new(None);

        assert_eq!(
            status.read().expect("status").elapsed_ms,
            0,
            "nothing ran yet"
        );
        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee2");
        let synced = status.read().expect("status").elapsed_ms;
        assert!(
            synced >= 5_000,
            "sync_counters writes the live elapsed: {synced}"
        );

        // The push line computes its own, not the stored value.
        status.write().expect("status").elapsed_ms = 0;
        let bus = Arc::new(aitm_core::JobBus::default());
        let mut rx = bus.subscribe();
        let progress = super::Progress::new(Arc::clone(&bus), "scan-0c0ffee2".to_string());
        assert!(super::emit(&progress, JobEvent::Phase, &status, None));
        let line: JobNotification = serde_json::from_value(crate::verbs::value_to_json(
            &rx.try_recv().expect("one line").payload,
        ))
        .expect("the payload is a JobNotification");
        assert!(
            line.status.elapsed_ms >= 5_000,
            "the push line's elapsed is live: {}",
            line.status.elapsed_ms
        );

        // Terminal: the fixed value stands, whatever the clock says now.
        {
            let mut guarded = status.write().expect("status");
            guarded.finished_at = Some(started_at + 42);
            guarded.elapsed_ms = 42;
        }
        super::sync_counters(&status, &meter, &runtime, &issues, "scan-0c0ffee2");
        assert_eq!(status.read().expect("status").elapsed_ms, 42);
        assert!(super::emit(&progress, JobEvent::Finished, &status, None));
        let line: JobNotification = serde_json::from_value(crate::verbs::value_to_json(
            &rx.try_recv().expect("one line").payload,
        ))
        .expect("the payload is a JobNotification");
        assert_eq!(
            line.status.elapsed_ms, 42,
            "a terminal line keeps the fixed elapsed"
        );
    }

    /// T6 child spec S6.3 / D6: an issue from an L4 point carries
    /// `location.l4 = { ip, port, proto, grammar, field_path, mutation }` built
    /// from the point's site node and the evidence's mutation chain, and its
    /// target is the node's tuple (an L4 point has no URL). An HTTP point keeps
    /// `l4: None`.
    #[test]
    fn l4_issue_location_comes_from_the_site_node_and_the_mutation_chain() {
        use super::issues_from_verdict;
        use aitm_scan_model::{
            Check, Confidence, Evidence, InsertionKind, InsertionPoint, LaneKind, Outcome,
            SiteNode, Verdict,
        };
        let node = SiteNode {
            id: "l4:127.0.0.1:6379/tcp".to_string(),
            method: "L4".to_string(),
            scheme: "tcp".to_string(),
            host: "127.0.0.1".to_string(),
            port: 6379,
            path_template: "/resp".to_string(),
            flows: Vec::new(),
            params: Vec::new(),
            auth: false,
            points: 1,
            audited: true,
        };
        let point = InsertionPoint {
            id: "l4-1".to_string(),
            lane: LaneKind::L4Stream,
            kind: InsertionKind::L4Field,
            name: "bulk.len".to_string(),
            path: Some("array[0].bulk.len".to_string()),
            example: None,
            flow: None,
            site_node: Some(node.id.clone()),
            traits: Vec::new(),
            frequency: 1,
            method: None,
            url: None,
        };
        let meta = crate::jobs::test_support::FakeCheck::on_lane(
            "l4-crash",
            "l4-crash",
            LaneKind::L4Stream,
            crate::jobs::test_support::FakeRun::vulnerable(),
        )
        .meta()
        .clone();
        let verdict = Verdict {
            outcome: Outcome::Vulnerable,
            confidence: Confidence::Firm,
            evidence: Evidence {
                l4: Some(aitm_scan_model::L4Evidence {
                    sent_hex: "2a31".into(),
                    seed_id: "127.0.0.1:6379/tcp#0".into(),
                    rng_seed: 7,
                    mutation_chain: vec!["len_desync(3)".into(), "bitflip".into()],
                    prior_messages: 0,
                    oracle: aitm_scan_model::L4Oracle::LivenessFailed,
                    liveness_before: true,
                    liveness_after: false,
                    reproduced: (2, 2),
                    scope_entry: "127.0.0.1/32".into(),
                }),
                ..Evidence::default()
            },
            detail: "crash".into(),
            poc_hint: None,
            location: None,
            more: Vec::new(),
        };

        let issues = issues_from_verdict(
            "scan-l4test1",
            &point,
            &meta,
            &verdict,
            std::slice::from_ref(&node),
        );
        assert_eq!(issues.len(), 1);
        let issue = &issues[0].1;
        let l4 = issue
            .location
            .l4
            .as_ref()
            .expect("an L4 point gets location.l4");
        assert_eq!(l4.ip, "127.0.0.1");
        assert_eq!(l4.port, 6379);
        assert_eq!(l4.proto, aitm_scan_model::L4Transport::Tcp);
        assert_eq!(l4.grammar.as_deref(), Some("resp"));
        assert_eq!(l4.field_path.as_deref(), Some("array[0].bulk.len"));
        assert_eq!(l4.mutation.as_deref(), Some("len_desync"));
        assert_eq!(issue.target.host, "127.0.0.1");
        assert_eq!(issue.target.port, 6379);
        assert_eq!(issue.target.scheme, "tcp");

        // Without a site node the block is absent rather than guessed.
        let orphan = issues_from_verdict("scan-l4test1", &point, &meta, &verdict, &[]);
        assert!(orphan[0].1.location.l4.is_none());

        // A node whose scheme is not `tcp`/`udp` is not an L4 tuple: the whole
        // block is `None`, never a `Tcp` guess (panel, delta review).
        let http_node = SiteNode {
            scheme: "http".to_string(),
            ..node.clone()
        };
        let guessed = issues_from_verdict(
            "scan-l4test1",
            &point,
            &meta,
            &verdict,
            std::slice::from_ref(&http_node),
        );
        assert_eq!(guessed.len(), 1);
        assert_eq!(guessed[0].1.location.l4, None, "no Tcp fallback");

        // An HTTP point keeps `l4: None`.
        let http = crate::jobs::test_support::fake_point("p1", "q", "http://scan.test/search");
        let http_meta = crate::jobs::test_support::FakeCheck::new(
            "fake.vuln",
            "demo",
            crate::jobs::test_support::FakeRun::vulnerable(),
        )
        .meta()
        .clone();
        let issues = issues_from_verdict("scan-l4test1", &http, &http_meta, &verdict, &[]);
        assert!(issues[0].1.location.l4.is_none());
    }

    /// Coordinator item (g): a verdict may move its issue off the point it was
    /// found at, and may report siblings. One issue per entry, each at its own
    /// path, because the dedupe key is computed after the override.
    #[tokio::test(flavor = "multi_thread")]
    async fn verdict_location_and_more_make_one_issue_each() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::multi(
                    "fake.exposed",
                    "exposed-path",
                    &["/.git/config", "/.env"],
                )),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);

        let mut paths: Vec<String> = h
            .engine
            .issues
            .for_job(&started.job)
            .into_iter()
            .map(|issue| issue.location.path)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["/.env".to_string(), "/.git/config".to_string()]);
        assert_eq!(status.issues.total, 2);
    }

    /// Security review (2026-11-01): PoC artifacts belong in the operator's
    /// evidence tree. With `findings.dir` set they go to `<dir>/scan/pocs`;
    /// without it nothing is reproduced at all, rather than scattering attack
    /// payloads through the system temp directory.
    #[tokio::test(flavor = "multi_thread")]
    async fn reproduction_only_runs_under_the_findings_dir() {
        let lane = || {
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::hinted("fake.hinted", "demo"))
        };

        // No findings dir: an issue, no PoC, no finding.
        let h = Harness::new().with_lane(lane());
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;
        let issues = h.engine.issues.for_job(&started.job);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].poc_ref, None);
        assert_eq!(issues[0].finding_id, None);

        // With one: the PoC output directory is the evidence tree's.
        let h = Harness::new().with_findings_dir().with_lane(lane());
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;
        let pocs = crate::util::scan_dir(&h.findings_dir(), "pocs");
        assert!(pocs.is_dir(), "{} was not created", pocs.display());
        assert!(
            std::env::temp_dir().read_dir().is_ok(),
            "the system temp dir is not where PoCs land"
        );
    }

    /// Security review (2026-11-01): the bus fans out to every subscriber,
    /// including an agent, so a push line carries the summary shapes alone —
    /// never an `Evidence` body and never an unscrubbed excerpt.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_lines_carry_no_evidence_body() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::new("fake.hit", "demo", FakeRun::vulnerable())),
        );
        h.bind();
        let mut rx = h.bus.subscribe();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;

        let mut saw_issue = false;
        while let Ok(event) = rx.try_recv() {
            let text = serde_json::to_string(&crate::verbs::value_to_json(&event.payload))
                .expect("the payload serializes");
            assert!(
                !text.contains("\"evidence\""),
                "a push line carried evidence: {text}"
            );
            assert!(
                !text.contains("\"description\""),
                "a push line carried a description: {text}"
            );
            saw_issue |= text.contains("\"issue\"");
        }
        assert!(saw_issue, "the vulnerable verdict pushed an issue line");
    }

    /// Spec D5 "Record policy" and the Tester's note: under `issues_only`
    /// every engine-side send leaves the store alone — a probe through
    /// `JobClient::send` and the D7 canary both carry `record: Never`, and the
    /// job's mark rides every one of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_engine_send_is_record_never_and_job_marked() {
        let h = Harness::new().with_lane(FakeLane::http().with_check(FakeCheck::new(
            "fake.clean",
            "demo",
            FakeRun::clean(),
        )));
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        h.wait_terminal(&started.job).await;

        let seen = h.client.seen();
        assert!(!seen.is_empty(), "the job probed");
        for opts in seen {
            assert_eq!(
                opts.record,
                aitm_core::RecordPolicy::Never,
                "a probe reached the store under issues_only"
            );
            assert_eq!(
                opts.marks.first().map(String::as_str),
                Some(format!("scan:{}", started.job).as_str())
            );
        }
    }

    /// Spec D5: every counter only ever rises, however a phase reports it.
    #[test]
    fn bump_is_saturating_and_monotonic() {
        use crate::worker::{bump, raise};

        let mut counter = 0u64;
        bump(&mut counter, 3);
        bump(&mut counter, 0);
        assert_eq!(counter, 3);
        bump(&mut counter, u64::MAX);
        assert_eq!(counter, u64::MAX, "the counter saturates, never wraps");

        let mut counter = 5u64;
        raise(&mut counter, 9);
        assert_eq!(counter, 9);
        raise(&mut counter, 2);
        assert_eq!(counter, 9, "a lower reading never lowers the counter");
    }

    /// Call B10: the engine wraps every lane host so a script check can take an
    /// owning handle to it.
    #[tokio::test(flavor = "multi_thread")]
    async fn arc_host_lends_an_owning_handle() {
        use aitm_scan_model::testing::NullHost;
        use aitm_scan_model::ProbeHost;

        let inner: Arc<dyn ProbeHost> = Arc::new(NullHost::new());
        let wrapped = crate::worker::ArcHost(inner.clone());

        assert_eq!(wrapped.budget_left(), inner.budget_left());
        assert!(
            wrapped.shared().is_some(),
            "the wrapper is what gives a bridge an owning handle"
        );
        let handle = wrapped.shared().expect("a handle");
        assert!(Arc::ptr_eq(&handle, &inner));
        assert_eq!(wrapped.marker(), inner.marker());
    }

    /// Spec D1 "Where a probe goes": nothing outside a started job reaches the
    /// client, and a job over an empty point list still finishes cleanly.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_job_with_no_point_finishes_without_probing() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(Vec::new())
                .with_check(FakeCheck::new("fake.clean", "demo", FakeRun::clean())),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        let status = h.wait_terminal(&started.job).await;

        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.points.found, 0);
        assert_eq!(status.checks.scheduled, 0);
        assert_eq!(h.client.calls(), 0);
        assert_eq!(status.probes.sent, 0);
    }

    /// The inverse of `util::json_to_value`, so a test can read the payload a
    /// push line carried back into the model type it was built from.
    /// Stage 6 finding (Task 16 review): a lane that panics must not leave
    /// the job `running` forever. The worker is supervised: the job ends
    /// `failed` naming the panic, the terminal line is pushed, the status is
    /// persisted, the egress hold is released and the origin is free again
    /// (spec anti-goal: a job that outlives its budget, deadline or
    /// cancellation; D5 terminal transitions).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_panicking_lane_ends_the_job_failed_and_frees_the_origin() {
        let h = Harness::new()
            .with_lane(FakeLane::http().with_discover_panic())
            .with_egress()
            .with_findings_dir();
        h.bind();
        let mut rx = h.bus.subscribe();
        assert!(!h.egress_confined(), "no job, no hold");

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        // No pre-terminal read of the hold here: on the multi-thread runtime
        // the lane's panic can end the job before this line runs, so "a
        // running job holds the posture" raced the supervisor (CI Rust gate on
        // #289, 2026-11-02; coordinator's amendment 71b). The cancel test above
        // pins that property race-free behind its blocking check.

        // The terminal signal decides when the job is over; `TERMINAL_NET` is
        // the only net (the old 2 s bound tripped on a loaded gate machine).
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Failed);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Failed));
        assert_eq!(status.phase, Phase::Done);
        assert!(
            status.finished_at.is_some(),
            "a terminal job has a finish time"
        );
        let error = status.error.as_deref().expect("the error names the panic");
        assert!(error.contains("panicked"), "{error}");
        assert!(error.contains(PANIC_TEXT), "{error}");
        assert!(status.checks.running.is_empty());

        // The hold is released with the job.
        assert!(!h.egress_confined(), "the egress hold outlived the job");

        // The terminal line reached the bus, after `started`, with a rising seq.
        let mut lines: Vec<JobNotification> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            lines.push(
                serde_json::from_value(crate::verbs::value_to_json(&event.payload))
                    .expect("the payload is a JobNotification"),
            );
        }
        assert_eq!(
            lines.first().expect("a first line").event,
            JobEvent::Started
        );
        let last = lines.last().expect("a last line");
        assert_eq!(last.event, JobEvent::Failed);
        assert!(last.seq > 1, "seq {}", last.seq);
        assert_eq!(last.status.state, JobState::Failed);

        // The status was persisted the way every other terminal state is.
        let path = h
            .findings_dir()
            .join("scan")
            .join("jobs")
            .join(format!("{}.json", started.job));
        let record: crate::jobs::PersistedJob =
            serde_json::from_slice(&std::fs::read(&path).expect("the job file exists"))
                .expect("the job file parses");
        assert_eq!(record.status.state, JobState::Failed);

        // The origin is not `busy`: a second job on it is admitted.
        let again = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the origin is free once the failed job is terminal");
        assert_ne!(again.job, started.job);
        h.wait_terminal(&again.job).await;

        // Cancelling the failed job is a no-op, not a hang.
        let cancelled = h
            .engine
            .registry
            .cancel(&started.job)
            .expect("the job is still in the registry");
        assert_eq!(cancelled.state, JobState::Failed);
    }

    /// Stage 6 finding (Task 16 review), the per-check half: one check that
    /// panics is one `error` verdict; the job goes on to its next item and
    /// finishes `done`, with the issue the next check found.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_panicking_check_is_an_error_verdict_not_a_dead_job() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                // The catalogue is id-sorted: `fake.boom` runs before
                // `fake.hit` on each point.
                .with_check(FakeCheck::panicking("fake.boom", "demo"))
                .with_check(FakeCheck::new("fake.hit", "other", FakeRun::vulnerable())),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done, "{:?}", status.error);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.error, None);
        // Two points x (two lane checks + the engine's three shipped passive
        // checks): every item, the panicking ones included, counts as done,
        // and the point count follows.
        assert_eq!(status.checks.scheduled, 10);
        assert_eq!(status.checks.done, 10);
        assert_eq!(status.points.audited, 2);
        assert!(status.checks.running.is_empty());
        // `fake.hit` still ran after `fake.boom` panicked on the same point.
        assert_eq!(h.engine.issues.for_job(&started.job).len(), 2);
        // The `fake.hit` runs sent one probe each; `fake.boom` sent none.
        assert_eq!(h.client.calls(), 2);
    }

    /// Stage 6 finding (live run 2, p13): a stimulus a lane charges through
    /// [`JobCtx::charge`] — a WebSocket frame, an L4 case, a browser
    /// navigation — is a probe of the one job budget, so it is counted in
    /// `probes.sent` and attributed to the lane that spent it (spec D5:
    /// "WS and L4 stimuli go through the lane's own transport ... metered by
    /// the same job budget"). Before the fix a 13-check WebSocket job
    /// reported `sent: 0`, `by_lane: {}` while raising issues.
    #[tokio::test(flavor = "multi_thread")]
    async fn charged_stimuli_count_in_probes_sent_and_by_lane() {
        let h = Harness::new().with_lane(FakeLane::ws().with_check(FakeCheck::on_lane(
            "fake.ws",
            "demo",
            LaneKind::Ws,
            FakeRun::clean().with_probes(0).with_charge(3),
        )));
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::Ws];
        let started =
            crate::jobs::start(&h.engine, profile, operator(), false).expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.checks.done, 1, "the ws check ran");
        assert_eq!(h.client.calls(), 0, "a ws frame is no HTTP send");
        assert_eq!(status.probes.sent, 3);
        assert_eq!(
            status.probes.by_lane,
            std::collections::BTreeMap::from([(LaneKind::Ws, 3)])
        );
    }

    /// The other half of the same rule: an HTTP send is counted by the probe
    /// meter inside the `JobClient` and by nothing else, so the two paths
    /// never count one stimulus twice (spec D5, "One `probes` budget per job
    /// across lanes; `JobClient` charges one unit per stimulus").
    #[tokio::test(flavor = "multi_thread")]
    async fn http_probes_and_charges_are_not_double_counted() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(vec![fake_point("p1", "q", "http://scan.test/search")])
                .with_check(FakeCheck::new(
                    "fake.http",
                    "demo",
                    FakeRun::clean().with_probes(2).with_charge(0),
                )),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(h.client.calls(), 2);
        assert_eq!(status.probes.sent, 2);
        assert_eq!(
            status.probes.by_lane,
            std::collections::BTreeMap::from([(LaneKind::Http, 2)])
        );
    }

    /// Stage 6 finding (Coder, client crawl): `crawl.pages` was store growth
    /// **plus** the lane's charges, so a crawl page that both charged and left
    /// a capture counted twice. A page counts once (spec D5).
    #[tokio::test(flavor = "multi_thread")]
    async fn crawl_pages_count_each_page_once() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                .with_points(Vec::new())
                .with_discover_charge(2)
                .with_crawl_flows(2),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.crawl.pages, 2, "two pages, counted once each");
    }
}
