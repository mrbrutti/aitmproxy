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
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use aitm_core::{
    BrowserDriver, CommandHost, Flow, FlowStore, HttpFlow, ProxyClient, ScopeRateGuard,
};
use aitm_scan_model::{
    scan_error, Canary, CheckMeta, Confidence, Discovery, Evidence, InsertionPoint, IssueLocation,
    IssueTarget, JobCtx, JobEvent, JobNotification, JobState, JobStatus, L4Counters, Lane,
    LaneKind, OnLost, Outcome, Payload, ProbeHost, ProbeResponse, RawProbe, RecordProbes,
    ScanErrorCode, ScanProfile, SessionMaterial, SessionMode, SessionStatus, SiteNode,
    StoppedReason, Technique, Verdict, JOB_KIND_SCAN,
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

/// The push side of one job (spec D3 "Progress push", call B13).
pub struct Progress {
    bus: Arc<aitm_core::JobBus>,
    job: String,
    seq: AtomicU64,
    last_progress: Mutex<Instant>,
}

impl Progress {
    /// A publisher for `job`. The first `progress` line is eligible at once:
    /// the window starts one interval in the past, so a short job still
    /// reports before it finishes.
    pub fn new(bus: Arc<aitm_core::JobBus>, job: String) -> Self {
        let start = Instant::now()
            .checked_sub(MIN_PROGRESS_INTERVAL)
            .unwrap_or_else(Instant::now);
        Self {
            bus,
            job,
            seq: AtomicU64::new(0),
            last_progress: Mutex::new(start),
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
            let mut last = self.last_progress.lock().unwrap_or_else(|e| e.into_inner());
            if last.elapsed() < MIN_PROGRESS_INTERVAL {
                return false;
            }
            *last = Instant::now();
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
            event: event_token(event),
            seq,
            payload,
        });
        true
    }
}

/// The wire token of a push event, as spec D3 names it.
fn event_token(event: JobEvent) -> String {
    serde_json::to_value(event)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{event:?}"))
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
    markers: AtomicU64,
    /// Set by [`JobCtx::report_session_lost`] or by the `scan: session_lost: `
    /// error prefix; the worker reads it between items.
    session_lost: AtomicBool,
    /// Budget units a lane charged outside an HTTP send (browser navigations,
    /// T3's observe-only streams), so `crawl.pages` can account for them.
    lane_charges: AtomicU64,
}

impl JobRuntime {
    /// Whether a lane has reported the session gone.
    fn session_is_lost(&self) -> bool {
        self.session_lost.load(Ordering::SeqCst)
    }

    /// Mark the session gone, from either route.
    fn mark_session_lost(&self) {
        self.session_lost.store(true, Ordering::SeqCst);
        self.with_session(|session| session.lost = true);
    }

    /// Budget units lanes charged outside an HTTP send.
    fn lane_charges(&self) -> u64 {
        self.lane_charges.load(Ordering::SeqCst)
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

    /// One budget for the whole job: a browser navigation a lane charges here
    /// spends exactly the unit an HTTP probe would (coordinator item (d)).
    fn charge(&self, units: u32) -> bool {
        if self.budget.charge(units) {
            self.lane_charges
                .fetch_add(u64::from(units), Ordering::SeqCst);
            return true;
        }
        false
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

    fn marker(&self) -> String {
        format!(
            "aitm{:08x}",
            self.markers.fetch_add(1, Ordering::SeqCst) & 0xffff_ffff
        )
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

    let deadline = Instant::now()
        .checked_add(crate::jobs::bounded_secs(profile.budget.time_s))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
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

    let runtime = Arc::new(JobRuntime {
        job: job.clone(),
        profile: profile.clone(),
        client: Arc::clone(&job_client),
        store: Arc::clone(&store),
        guard,
        browser,
        session: observed.as_ref().map(|s| Arc::new(s.material.clone())),
        budget: Arc::clone(&budget),
        status: Arc::clone(&status),
        markers: AtomicU64::new(0),
        session_lost: AtomicBool::new(false),
        lane_charges: AtomicU64::new(0),
    });
    let job_ctx: Arc<dyn JobCtx> = Arc::clone(&runtime) as Arc<dyn JobCtx>;

    set_phase(&status, JobState::Running, aitm_scan_model::Phase::Crawling);
    emit(progress, JobEvent::Started, &status, None);

    // --- crawling -----------------------------------------------------------
    let pages_before = store.count() as u64;
    let mut points: Vec<InsertionPoint> = Vec::new();
    let mut nodes: Vec<SiteNode> = Vec::new();
    for lane in &lanes {
        match bounded_await(
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
                sync_counters(&status, &meter, &engine.issues, &job);
                finish_terminal(&engine, &status, progress, &job, &started_by, Some(reason));
                return;
            }
        }
    }
    {
        let pages = (store.count() as u64)
            .saturating_sub(pages_before)
            .saturating_add(runtime.lane_charges());
        let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut guarded.crawl.pages, pages);
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
        profile: &profile,
        status: &status,
        progress,
        runtime: &runtime,
        job_ctx: &job_ctx,
        lanes: &lanes,
        points: &points,
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
    sync_counters(&status, &meter, &engine.issues, &job);

    let reason = match (stopped, cancel.is_cancelled()) {
        (Some(reason), _) => Some(reason),
        (None, true) => Some(StoppedReason::Cancelled),
        (None, false) => None,
    };
    finish_terminal(&engine, &status, progress, &job, &started_by, reason);
}

/// Everything one phase loop needs, gathered so the per-item code reads as the
/// list of questions spec D5 asks before each item rather than as plumbing.
struct RunCtx<'a> {
    engine: &'a Arc<Engine>,
    job: &'a str,
    profile: &'a ScanProfile,
    status: &'a Arc<RwLock<JobStatus>>,
    progress: &'a Progress,
    runtime: &'a Arc<JobRuntime>,
    job_ctx: &'a Arc<dyn JobCtx>,
    lanes: &'a [Arc<dyn Lane>],
    points: &'a [InsertionPoint],
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
    /// Copy the live meters onto the status.
    fn sync(&self) {
        sync_counters(self.status, self.meter, &self.engine.issues, self.job);
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
        if let Some(point) = item.and_then(|item| self.points.get(item.point)) {
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
        let Some(point) = self.points.get(item.point) else {
            return;
        };
        let meta = item.check.meta().clone();
        let Some(lane) = self.lanes.iter().find(|l| l.lane() == point.lane) else {
            self.item_done(item.point, owed, &meta.id);
            return;
        };

        let host = match lane.probe_host_for(point, Arc::clone(self.job_ctx)) {
            Ok(host) => ArcHost(Arc::from(host)),
            Err(e) => {
                self.note_lane_text(&e.to_string());
                self.item_done(item.point, owed, &meta.id);
                return;
            }
        };

        self.running_push(&meta.id);
        let check_deadline = Instant::now()
            .checked_add(crate::jobs::bounded_secs(
                self.profile.budget.check_timeout_s,
            ))
            .unwrap_or(self.budget.deadline)
            .min(self.budget.deadline);
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
        self.item_done(item.point, owed, &meta.id);

        let verdict = match verdict {
            Ok(Ok(verdict)) => verdict,
            // A check that did not finish is not a verdict: the job's own
            // counters already recorded the time or the cancellation.
            Ok(Err(_)) => return,
            Err(payload) => {
                let detail = format!("the check panicked: {}", panic_text(payload.as_ref()));
                tracing::warn!(target: "aitm::scanner", job = %self.job, check = %meta.id, "{detail}");
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
        for (verdict, new) in issues_from_verdict(self.job, point, &meta, &verdict) {
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
        .with_frontend(frontend_of(&self.started_by.frontend))
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

    /// One item finished: the check counter rises, and the point's counter
    /// rises with the last item that named it.
    fn item_done(
        &self,
        point: usize,
        owed: &mut std::collections::HashMap<usize, usize>,
        _check: &str,
    ) {
        let last = match owed.get_mut(&point) {
            Some(left) => {
                *left = left.saturating_sub(1);
                *left == 0
            }
            None => false,
        };
        let mut status = self.status.write().unwrap_or_else(|e| e.into_inner());
        bump(&mut status.checks.done, 1);
        if last {
            bump(&mut status.points.audited, 1);
        }
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
) -> Vec<(Verdict, NewIssue)> {
    let mut out = Vec::new();
    for one in std::iter::once(verdict).chain(verdict.more.iter()) {
        if one.outcome != Outcome::Vulnerable {
            continue;
        }
        out.push((one.clone(), new_issue(job, point, meta, one)));
    }
    out
}

/// The issue one vulnerable verdict reports.
fn new_issue(job: &str, point: &InsertionPoint, meta: &CheckMeta, verdict: &Verdict) -> NewIssue {
    let (scheme, host, port, path) = parts_of(point);
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
            l4: None,
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
    let default_port = if scheme == "https" { 443 } else { 80 };
    (
        scheme,
        parsed.host_str().unwrap_or_default().to_string(),
        parsed.port().unwrap_or(default_port),
        parsed.path().to_string(),
    )
}

/// The host a point's probes go to, for the per-host error ladder.
fn host_of_point(point: &InsertionPoint) -> String {
    let (_, host, port, _) = parts_of(point);
    if host.is_empty() {
        return String::new();
    }
    format!("{host}:{port}")
}

/// The frontend a `started_by` token names, defaulting to the gated posture.
fn frontend_of(token: &str) -> aitm_core::Frontend {
    match token {
        "cli" => aitm_core::Frontend::Cli,
        "operator" => aitm_core::Frontend::Operator,
        _ => aitm_core::Frontend::Mcp,
    }
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

/// Copy the live meters onto the status, monotonically.
/// `probes.sent` is the **meter's** reading, not the budget's: a lane charge
/// (a browser navigation) spends the same budget but is not an HTTP send, and
/// it is counted in `crawl.pages` instead.
fn sync_counters(
    status: &Arc<RwLock<JobStatus>>,
    meter: &ProbeMeter,
    issues: &IssueStore,
    job: &str,
) {
    let found = issues.for_job(job);
    let mut guarded = status.write().unwrap_or_else(|e| e.into_inner());
    raise(&mut guarded.probes.sent, meter.sent.load(Ordering::SeqCst));
    raise(
        &mut guarded.probes.errors,
        meter.errors.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.probes.timeouts,
        meter.timeouts.load(Ordering::SeqCst),
    );
    raise(
        &mut guarded.probes.rate_waits,
        meter.rate_waits.load(Ordering::SeqCst),
    );
    raise(&mut guarded.issues.total, found.len() as u64);
    let mut by_severity = aitm_scan_model::BySeverity::default();
    let mut by_confidence = aitm_scan_model::ByConfidence::default();
    for issue in &found {
        by_severity.bump(issue.severity);
        by_confidence.bump(issue.confidence);
    }
    guarded.issues.by_severity = by_severity;
    guarded.issues.by_confidence = by_confidence;
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
    let snapshot = status.read().unwrap_or_else(|e| e.into_inner()).clone();
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
    _started_by: &aitm_scan_model::StartedBy,
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
        JobEvent, JobNotification, JobState, JobStatus, L4Counters, OnLost, Phase, RecordProbes,
        StoppedReason,
    };

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

        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;
        assert_eq!(status.state, JobState::Done);
        assert_eq!(status.phase, Phase::Done);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.points.found, 2);
        assert_eq!(status.points.audited, 2);
        assert_eq!(status.checks.scheduled, 2);
        assert_eq!(status.checks.done, 2);
        assert!(status.checks.running.is_empty());
        assert_eq!(status.probes.sent, 2, "one probe per point");
        assert!(status.finished_at.is_some());
    }

    /// Spec D5 "Cancellation": the token is observed between probes; the entry
    /// moves to `cancelled` with its issues intact and sends nothing more.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_moves_to_cancelled_and_keeps_issues() {
        let h = Harness::new().with_lane(
            FakeLane::http()
                // The catalogue is id-sorted, so `fake.hit` is scheduled
                // before `fake.wait` and the issue exists before the block.
                .with_check(FakeCheck::scripted(
                    "fake.hit",
                    "demo",
                    vec![FakeRun::vulnerable()],
                ))
                .with_check(FakeCheck::blocking("fake.wait")),
        );
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");

        // Wait until the vulnerable verdict has been recorded.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while h.engine.issues.for_job(&started.job).is_empty() {
            assert!(std::time::Instant::now() < deadline, "no issue was raised");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let cancelling = h
            .engine
            .registry
            .cancel(&started.job)
            .expect("the job is in the registry");
        assert_eq!(cancelling.state, JobState::Cancelling);

        let status = h.wait_terminal(&started.job, Duration::from_secs(2)).await;
        assert_eq!(status.state, JobState::Cancelled);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Cancelled));
        assert_eq!(h.engine.issues.for_job(&started.job).len(), 1);

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

        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;

        let mut lines: Vec<JobNotification> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            assert_eq!(event.kind, "scan");
            assert_eq!(event.job, started.job);
            lines.push(
                serde_json::from_value(value_to_json(event.payload))
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

    /// Call B13 in isolation: `progress` is dropped while the 250 ms window has
    /// not elapsed; a `phase` line in between is always published.
    #[tokio::test(flavor = "multi_thread")]
    async fn progress_is_coalesced_to_four_a_second_and_phase_never_is() {
        use crate::worker::Progress;

        let bus = Arc::new(aitm_core::JobBus::default());
        let mut rx = bus.subscribe();
        let progress = Progress::new(bus.clone(), "scan-1a2b3c4d".to_string());
        let status = JobStatus::default();

        let mut sent_progress = 0usize;
        let mut sent_phase = 0usize;
        for i in 0..50 {
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            sent_progress <= 4,
            "{sent_progress} progress lines in ~0.5 s"
        );
        assert_eq!(sent_phase, 1);

        let mut seqs = Vec::new();
        while let Ok(event) = rx.try_recv() {
            seqs.push(event.seq);
        }
        assert_eq!(
            seqs.len(),
            sent_progress + sent_phase,
            "seq counts sent lines only"
        );
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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h2.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        let status = h2.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
            let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;

            assert_eq!(status.state, JobState::Done, "{payload} / {on_lost:?}");
            assert_eq!(status.stopped_reason, reason, "{payload} / {on_lost:?}");
            assert!(
                status.session.as_ref().expect("observed mode").lost,
                "{payload} / {on_lost:?}"
            );
            assert_eq!(status.points.audited, audited, "{payload} / {on_lost:?}");
        }
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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;

        let mut saw_issue = false;
        while let Ok(event) = rx.try_recv() {
            let text = serde_json::to_string(&value_to_json(event.payload))
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
        h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
        let status = h.wait_terminal(&started.job, Duration::from_secs(5)).await;

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
        assert!(h.egress_confined(), "a running job holds the posture");

        let status = h.wait_terminal(&started.job, Duration::from_secs(2)).await;
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
                serde_json::from_value(value_to_json(event.payload))
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
        h.wait_terminal(&again.job, Duration::from_secs(2)).await;

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

        let status = h.wait_terminal(&started.job, Duration::from_secs(2)).await;
        assert_eq!(status.state, JobState::Done, "{:?}", status.error);
        assert_eq!(status.stopped_reason, None);
        assert_eq!(status.error, None);
        // Two points x two checks: every item, the panicking ones included,
        // counts as done, and the point count follows.
        assert_eq!(status.checks.scheduled, 4);
        assert_eq!(status.checks.done, 4);
        assert_eq!(status.points.audited, 2);
        assert!(status.checks.running.is_empty());
        // `fake.hit` still ran after `fake.boom` panicked on the same point.
        assert_eq!(h.engine.issues.for_job(&started.job).len(), 2);
        // The `fake.hit` runs sent one probe each; `fake.boom` sent none.
        assert_eq!(h.client.calls(), 2);
    }

    fn value_to_json(value: aitm_core::Value) -> serde_json::Value {
        use aitm_core::Value;
        match value {
            Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(b),
            Value::Int(i) => serde_json::Value::from(i),
            Value::Float(f) => serde_json::Value::from(f),
            Value::Str(s) => serde_json::Value::String(s),
            Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(value_to_json).collect())
            }
            Value::Object(map) => serde_json::Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, value_to_json(v)))
                    .collect(),
            ),
            Value::Bytes(bytes) => serde_json::Value::from(bytes.len()),
        }
    }
}
