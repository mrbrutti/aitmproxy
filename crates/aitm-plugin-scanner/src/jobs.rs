//! The job registry, the late-bound services and `scan.start`'s gate order
//! (spec D5). Task 14 of the T1b plan fills it.
//!
//! Three things live here. [`ScanServices`] is the bundle of owned handles the
//! binary builds once the proxy exists and binds into [`ScanLate`] — the
//! `LateHandles` precedent of `crates/aitm/src/wire.rs`, so `wire::assemble`
//! alone leaves the engine unbound and a verb then fails with a plain wiring
//! error rather than a `scan:` code (call B3). [`JobRegistry`] is the live map
//! of jobs, shaped like the shipped `CaptureRegistry`: one [`JobEntry`] per
//! job, holding the status behind an `RwLock` every verb reads, the
//! cancellation token `scan.cancel` sets, and the confinement token that drops
//! with the job. [`start`] is `scan.start`'s whole gate ladder, in spec D3's
//! fixed order, ending in a spawned [`crate::worker::run_job`].
//!
//! The gate order is contract, not taste: a caller that is wrong in two ways
//! must always learn the same reason first, or a UI cannot explain itself.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use aitm_core::{
    AgentPolicy, BrowserDriver, ConfinementToken, EgressConfinement, FlowStore, Frontend,
    ProxyClient, ScopeRateGuard,
};
use aitm_scan_model::{
    scan_error, Check, CheckRegistry, Clamped, Discovery, Intensity, JobId, JobState, JobStatus,
    JobSummary, L4TargetSpec, L4Transport, Lane, LaneKind, LaneReport, Phase, ProbeCounters,
    ScanErrorCode, ScanProfile, SessionMode, SessionStatus, SkippedLane, StartResult, StartedBy,
};
use tokio_util::sync::CancellationToken;

use crate::catalogue::{assemble, Catalogue};
use crate::config::ScannerConfig;
use crate::issues::IssueStore;
use crate::profiles::{self, Profiles};
use crate::util;

/// How many times [`start`] re-mints a job id that is already taken before it
/// gives up. Eight hex digits are 32 bits of randomness (`util::job_id`), so a
/// clash is a one-in-tens-of-thousands event and two clashes in a row have
/// never been observed; the bound is there so the loop cannot spin.
const MAX_ID_ATTEMPTS: usize = 16;

/// The owned handles one scan job runs on (spec D5 "Owned handles").
///
/// Everything here is an `Arc` the binary already holds: the engine borrows
/// the proxy's store, client and guard rather than building its own, so a
/// probe is scoped, rated and recorded exactly like any other request. `config`
/// stands in for the spec's `findings: Option<Arc<FindingStore>>` (call B4):
/// the worker builds a `CommandHost` from these handles and the PoC runner and
/// `reproduce::record_finding` both read `host.config().findings.dir`.
pub struct ScanServices {
    /// The proxy's flow store.
    pub store: Arc<dyn FlowStore>,
    /// The proxy's client; the job wraps it in a [`crate::client::JobClient`].
    pub client: Arc<dyn ProxyClient>,
    /// The proxy's scope and rate guard.
    pub guard: Arc<dyn ScopeRateGuard>,
    /// The browser, when one was launched.
    pub browser: Option<Arc<dyn BrowserDriver>>,
    /// The egress posture a running job holds confined.
    pub egress: Option<Arc<EgressConfinement>>,
    /// The L4 guard, when the L4 layer is enabled.
    pub l4: Option<Arc<aitm_proto_l4::guard::L4Guard>>,
    /// The bus every job's progress line is published on (spec D9.2).
    pub jobs: Arc<aitm_core::JobBus>,
    /// Reads the live agent policy; an agent job re-checks it at every step.
    pub agent_policy: Arc<dyn Fn() -> AgentPolicy + Send + Sync>,
    /// The runtime the worker is spawned on.
    pub rt: tokio::runtime::Handle,
    /// The proxy configuration, for the `CommandHost` the worker builds.
    pub config: Arc<aitm_core::Config>,
}

impl std::fmt::Debug for ScanServices {
    /// Names the handles that are present; prints none of them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanServices")
            .field("browser", &self.browser.is_some())
            .field("egress", &self.egress.is_some())
            .field("l4", &self.l4.is_some())
            .finish_non_exhaustive()
    }
}

/// The write-once cell the binary binds [`ScanServices`] into after the proxy
/// is built (call B3, the `LateHandles` precedent).
#[derive(Debug, Default)]
pub struct ScanLate(OnceLock<ScanServices>);

impl ScanLate {
    /// An unbound cell, shared by the plugin and every `scan.*` command.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(OnceLock::new()))
    }

    /// Bind the services. Returns `false` if they were already bound, leaving
    /// the first binding in place: the handles a running job holds are never
    /// swapped under it.
    pub fn bind(&self, services: ScanServices) -> bool {
        self.0.set(services).is_ok()
    }

    /// The bound services, or a plain error.
    ///
    /// Deliberately **not** a `scan:` code: an unbound cell means the binary
    /// did not wire the engine, which is a bug in the build, not a condition a
    /// caller can do anything about or a frontend should match on.
    pub fn get(&self) -> anyhow::Result<&ScanServices> {
        self.0.get().ok_or_else(|| {
            anyhow::anyhow!(
                "scanner services are not bound; the binary binds them after the proxy is built"
            )
        })
    }

    /// Whether the services have been bound.
    pub fn is_bound(&self) -> bool {
        self.0.get().is_some()
    }
}

/// One job in the registry (spec D5 "Registry").
pub struct JobEntry {
    /// The live status every `scan.status`/`scan.list` call reads.
    pub status: Arc<RwLock<JobStatus>>,
    /// Set by `scan.cancel`; observed between probes and in every await.
    pub cancel: CancellationToken,
    /// The egress hold the job keeps for its lifetime.
    pub confine: Option<ConfinementToken>,
    /// Who started it.
    pub started_by: StartedBy,
    /// What discovery found, for `scan.sitemap`.
    pub discovery: Arc<RwLock<Discovery>>,
    /// The normalized origins the job is single-flight on.
    pub origins: Vec<String>,
    /// Whether an agent started it, so the worker knows to re-check policy.
    pub is_agent: bool,
    /// Flipped to `true` once, by [`JobRegistry::finish`], when the job is
    /// terminal. Readers that need "tell me when it is over" subscribe to it
    /// instead of polling `status` on a clock (a reloaded record starts `true`).
    pub terminal: tokio::sync::watch::Sender<bool>,
}

impl std::fmt::Debug for JobEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobEntry")
            .field("origins", &self.origins)
            .field("is_agent", &self.is_agent)
            .field(
                "state",
                &self.status.read().unwrap_or_else(|e| e.into_inner()).state,
            )
            .finish_non_exhaustive()
    }
}

/// Every job this process knows about: the live ones and the retained history
/// (spec D5).
#[derive(Debug)]
pub struct JobRegistry {
    inner: Mutex<HashMap<JobId, JobEntry>>,
    history: u32,
}

impl JobRegistry {
    /// A registry retaining `history` finished jobs.
    pub fn new(history: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            history,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<JobId, JobEntry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admit `entry` only if its id is free, keyed by the job id on its
    /// status. Returns `false` (and gives the entry back to the drop) when the
    /// id is taken.
    ///
    /// An id the registry already holds is **not** overwritten: a live job's
    /// handles are never dropped on the floor by a colliding mint. [`start`]
    /// mints through [`JobRegistry::admit`], which re-mints instead. The
    /// answer is `#[must_use]` so no caller can admit a job, lose it to a
    /// collision and carry on as if it were running.
    #[must_use]
    pub(crate) fn try_insert(&self, entry: JobEntry) -> bool {
        let id = entry
            .status
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .job
            .clone();
        let mut inner = self.lock();
        match inner.entry(id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(entry);
                true
            }
        }
    }

    /// Whether the registry already holds this id.
    fn holds(&self, id: &str) -> bool {
        self.lock().contains_key(id)
    }

    /// `scan.start`'s concurrency gate and admission as **one** critical
    /// section (spec D5 "Registry"/`busy`; security review, whole branch,
    /// 2026-11-01): the `max_jobs` ceiling and the per-origin single flight
    /// are checked, a free id is minted and the entry `build(id)` returns is
    /// inserted, all under the same lock, so two callers racing each other
    /// cannot both see a free slot and both take it.
    ///
    /// `build` runs under the lock: it must only assemble the entry (it is
    /// handed the minted id to stamp on the status) and never touch the
    /// registry.
    pub fn admit(
        &self,
        max_jobs: usize,
        origins: &[String],
        build: impl FnOnce(&JobId) -> JobEntry,
    ) -> Result<JobId, AdmitRefused> {
        let mut inner = self.lock();
        if active_count_in(&inner) >= max_jobs {
            return Err(AdmitRefused::MaxJobs);
        }
        let active = active_origins_in(&inner);
        if let Some(origin) = origins.iter().find(|o| active.contains(*o)) {
            return Err(AdmitRefused::Origin(origin.clone()));
        }
        let mut id = None;
        for _ in 0..MAX_ID_ATTEMPTS {
            let candidate = util::job_id();
            if !inner.contains_key(&candidate) {
                id = Some(candidate);
                break;
            }
        }
        let Some(id) = id else {
            return Err(AdmitRefused::NoFreeId);
        };
        inner.insert(id.clone(), build(&id));
        Ok(id)
    }

    /// A snapshot of one job's status. `elapsed_ms` is live while the job runs
    /// (spec D5: monotonic from `started_at`); the terminal transition fixes it.
    pub fn status(&self, id: &str) -> Option<JobStatus> {
        self.lock()
            .get(id)
            .map(|e| with_live_elapsed(e.status.read().unwrap_or_else(|p| p.into_inner()).clone()))
    }

    /// The newest job of all, for `scan.sitemap` with neither `job` nor `target`.
    pub fn newest(&self) -> Option<JobId> {
        self.newest_where(|_| true)
    }

    /// The newest job that ran against `origin`, for `scan.sitemap { target }`.
    pub fn newest_for_target(&self, origin: &str) -> Option<JobId> {
        self.newest_where(|e| e.origins.iter().any(|o| o == origin))
    }

    /// The job with the greatest `started_at` among those `keep` admits; the
    /// smaller id wins a same-millisecond tie, so the answer is deterministic.
    fn newest_where(&self, keep: impl Fn(&JobEntry) -> bool) -> Option<JobId> {
        let inner = self.lock();
        inner
            .values()
            .filter(|e| keep(e))
            .map(|e| {
                let status = e.status.read().unwrap_or_else(|p| p.into_inner());
                (status.started_at, Reverse(status.job.clone()))
            })
            .max()
            .map(|(_, Reverse(job))| job)
    }

    /// The three handles the worker needs to drive one job.
    pub fn entry_handles(&self, id: &str) -> Option<JobHandles> {
        self.lock().get(id).map(|e| JobHandles {
            status: Arc::clone(&e.status),
            cancel: e.cancel.clone(),
            discovery: Arc::clone(&e.discovery),
        })
    }

    /// Job summaries, newest `started_at` first, at most `limit`.
    pub fn list(&self, active_only: bool, limit: usize) -> Vec<JobSummary> {
        let inner = self.lock();
        let mut rows: Vec<JobStatus> = inner
            .values()
            .map(|e| with_live_elapsed(e.status.read().unwrap_or_else(|p| p.into_inner()).clone()))
            .filter(|s| !active_only || !s.state.is_terminal())
            .collect();
        // Newest first; the id breaks a tie so two jobs started in the same
        // millisecond still list deterministically.
        rows.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(a.job.cmp(&b.job)));
        rows.truncate(limit);
        rows.iter().map(JobStatus::summary).collect()
    }

    /// Request cancellation. Idempotent: a job already terminal is returned
    /// unchanged, and a second call on a cancelling job changes nothing.
    pub fn cancel(&self, id: &str) -> Option<JobStatus> {
        let inner = self.lock();
        let entry = inner.get(id)?;
        entry.cancel.cancel();
        let mut status = entry.status.write().unwrap_or_else(|p| p.into_inner());
        if !status.state.is_terminal() {
            status.state = JobState::Cancelling;
        }
        Some(with_live_elapsed(status.clone()))
    }

    /// How many jobs are not yet terminal.
    pub fn active_count(&self) -> usize {
        active_count_in(&self.lock())
    }

    /// The origins a non-terminal job is already running against.
    pub fn active_origins(&self) -> HashSet<String> {
        active_origins_in(&self.lock())
    }

    /// Release a finished job's live handles and prune the history.
    ///
    /// The confinement token drops here, so the egress hold ends with the job;
    /// the status stays so `scan.status` and `scan.list` can still answer.
    pub fn finish(&self, id: &str) {
        let mut inner = self.lock();
        if let Some(entry) = inner.get_mut(id) {
            entry.confine = None;
            // The status is already terminal when the worker calls this; the
            // signal is the last step, so a subscriber that wakes reads a
            // terminal status.
            entry.terminal.send_replace(true);
        }
        prune(&mut inner, self.history);
    }

    /// A receiver that reads `true` once the job is terminal (immediately for
    /// a job that already is), or `None` for an unknown job. This is how the
    /// test harnesses wait for the end without a wall-clock bound.
    pub fn terminal_signal(&self, id: &str) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.lock().get(id).map(|e| e.terminal.subscribe())
    }

    /// Read `<findings_dir>/scan/jobs/*.json` back into finished entries.
    ///
    /// Returns how many jobs were added. A job the registry already holds is
    /// left alone (the live one is the truth), and a file that does not parse
    /// is skipped rather than failing the load: one corrupt record must not
    /// hide the rest of an operator's history.
    ///
    /// A record is data, not truth (security review, whole branch,
    /// 2026-11-01). Its id must be a job id and must name the file it sits in,
    /// or the file is skipped with a warning. And nothing on disk can be
    /// running — no worker owns it — so a non-terminal `state` is forced to
    /// `failed` with `stopped_reason: failed`, `finished_at` set and an
    /// `error` saying why; left as written, such a record would hold a
    /// `max_jobs` slot and its origin's single flight forever, with a
    /// pre-cancelled token nothing could act on.
    pub fn load_history(&self, dir: &Path) -> anyhow::Result<usize> {
        let jobs_dir = util::scan_dir(dir, "jobs");
        if !jobs_dir.is_dir() {
            return Ok(0);
        }
        let mut added = 0usize;
        for entry in std::fs::read_dir(&jobs_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(mut record) = serde_json::from_str::<PersistedJob>(&text) else {
                continue;
            };
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if !is_job_id(&record.status.job) || record.status.job != stem {
                tracing::warn!(
                    target: "aitm::scanner",
                    file = %path.display(),
                    "skipped a job record whose id is not a job id naming its file"
                );
                continue;
            }
            if self.holds(&record.status.job) {
                continue;
            }
            if !record.status.state.is_terminal() {
                let now = util::now_ms();
                let status = &mut record.status;
                status.state = JobState::Failed;
                status.phase = Phase::Done;
                status.stopped_reason = Some(aitm_scan_model::StoppedReason::Failed);
                status.error = Some("reloaded a non-terminal job record".to_string());
                status.finished_at = Some(now);
                status.elapsed_ms = now.saturating_sub(status.started_at);
                status.checks.running.clear();
            }
            let started_by = record.status.started_by.clone();
            let origins = record.status.targets.clone();
            let is_agent = !util::frontend_of_token(&started_by.frontend).is_trusted_control();
            if self.try_insert(JobEntry {
                status: Arc::new(RwLock::new(record.status)),
                // A reloaded job is already over; the token is pre-cancelled so
                // nothing can mistake it for something still worth stopping.
                cancel: cancelled_token(),
                confine: None,
                started_by,
                discovery: Arc::new(RwLock::new(Discovery::default())),
                origins,
                is_agent,
                terminal: tokio::sync::watch::channel(true).0,
            }) {
                added += 1;
            }
        }
        let mut inner = self.lock();
        prune(&mut inner, self.history);
        Ok(added)
    }
}

/// `elapsed_ms` as a reader should see it: the wall time since `started_at`
/// while the job runs (spec D5 "monotonic from started_at"; T9 live run,
/// 2026-11-01), the fixed value once it is terminal. The worker writes the
/// field on every counter sync and push line, but not during the crawling
/// phase, so `status`, `list` and `cancel` compute it on the way out.
fn with_live_elapsed(mut status: JobStatus) -> JobStatus {
    if status.finished_at.is_none() {
        status.elapsed_ms = util::now_ms().saturating_sub(status.started_at);
    }
    status
}

/// What one job's live handles are, as [`JobRegistry::entry_handles`] hands
/// them out. Named fields rather than a 3-tuple, because every call site used
/// one of the three and had to spell two `_`s to say so.
pub struct JobHandles {
    /// The status every verb reads.
    pub status: Arc<RwLock<JobStatus>>,
    /// The token `scan.cancel` sets.
    pub cancel: CancellationToken,
    /// What discovery found, which `scan.sitemap` pages.
    pub discovery: Arc<RwLock<Discovery>>,
}

/// Why [`JobRegistry::admit`] did not admit a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitRefused {
    /// `max_jobs` jobs are already running.
    MaxJobs,
    /// A job is already running against this origin.
    Origin(String),
    /// Every id minted in [`MAX_ID_ATTEMPTS`] tries was taken. Not a verb
    /// refusal: no D3 code describes "the random source keeps repeating
    /// itself".
    NoFreeId,
}

/// Whether an entry's job is not yet terminal.
fn is_active(entry: &JobEntry) -> bool {
    !entry
        .status
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .state
        .is_terminal()
}

/// [`JobRegistry::active_count`] over an already-locked map.
fn active_count_in(inner: &HashMap<JobId, JobEntry>) -> usize {
    inner.values().filter(|e| is_active(e)).count()
}

/// [`JobRegistry::active_origins`] over an already-locked map.
fn active_origins_in(inner: &HashMap<JobId, JobEntry>) -> HashSet<String> {
    inner
        .values()
        .filter(|e| is_active(e))
        .flat_map(|e| e.origins.iter().cloned())
        .collect()
}

/// Whether `id` has the shape of a job id, `scan-<8 lowercase hex>`
/// (`util::job_id`). A record on disk is admitted to the registry only under
/// such an id, so a hand-edited or planted file cannot register a job under
/// an arbitrary key.
fn is_job_id(id: &str) -> bool {
    id.strip_prefix("scan-").is_some_and(|hex| {
        hex.len() == 8
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A token that is already cancelled, for a job reloaded from disk.
fn cancelled_token() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

/// Drop the oldest finished entries beyond `history` (spec D3 `scan.list`).
///
/// Only finished entries are prunable: a live job is never evicted by a burst
/// of completions, however small `history` is.
fn prune(inner: &mut HashMap<JobId, JobEntry>, history: u32) {
    let mut finished: Vec<(u64, JobId)> = inner
        .iter()
        .filter_map(|(id, entry)| {
            let status = entry.status.read().unwrap_or_else(|p| p.into_inner());
            status
                .state
                .is_terminal()
                .then(|| (status.finished_at.unwrap_or(status.started_at), id.clone()))
        })
        .collect();
    let keep = history as usize;
    let Some(overflow) = finished.len().checked_sub(keep).filter(|n| *n > 0) else {
        return;
    };
    // Oldest first, so the tail that survives is the newest `history` jobs.
    finished.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    for (_, id) in finished.into_iter().take(overflow) {
        inner.remove(&id);
    }
}

/// What is written to `<findings.dir>/scan/jobs/<job>.json` (spec D5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedJob {
    /// The job's terminal status.
    pub status: JobStatus,
    /// The issues the job raised.
    #[serde(default)]
    pub issues: Vec<aitm_scan_model::Issue>,
}

/// Who is calling a `scan.*` verb (spec D3, shared facts "Caller classes").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The frontend the call arrived on.
    pub frontend: Frontend,
    /// The bus client label, when one was given.
    pub client_label: Option<String>,
}

impl Caller {
    /// An agent is any caller that is not a trusted control surface. This asks
    /// the workspace's one predicate (`Frontend::is_trusted_control`, an
    /// allow-list of the CLI and an operator-token connection) rather than
    /// comparing against the agent role, so a `Frontend` variant this build
    /// does not know is gated, never trusted.
    pub fn is_agent(&self) -> bool {
        !self.frontend.is_trusted_control()
    }

    /// The caller as the `started_by` record `JobStatus` carries.
    pub fn started_by(&self) -> StartedBy {
        StartedBy {
            frontend: util::frontend_token(self.frontend).to_string(),
            client_label: self.client_label.clone(),
        }
    }
}

/// What a lane's error means to the engine (coordinator decision 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneErrorKind {
    /// The job's session is gone; the text is the lane's explanation.
    SessionLost(String),
    /// The lane refuses the profile; the text is the reason.
    InvalidProfile(String),
    /// An ordinary failure.
    Other,
}

/// Read a lane's error through the two prefix conventions a lane may use
/// instead of the `JobCtx` hooks (coordinator decision 1).
///
/// The prefixes are **literal** and anchored: a message that merely contains
/// one is an ordinary error, so a target that echoes the text back cannot make
/// the engine believe the session died.
pub fn map_lane_error(err: &anyhow::Error) -> LaneErrorKind {
    map_lane_error_text(&err.to_string())
}

/// [`map_lane_error`] over a message the engine already has as text (a check's
/// `detail`, which is where a check reports the probe error it could not send).
pub fn map_lane_error_text(text: &str) -> LaneErrorKind {
    if let Some(rest) = text.strip_prefix("scan: session_lost: ") {
        return LaneErrorKind::SessionLost(rest.to_string());
    }
    if let Some(rest) = text.strip_prefix("invalid_profile: ") {
        return LaneErrorKind::InvalidProfile(rest.to_string());
    }
    LaneErrorKind::Other
}

/// The scanner engine: the configuration, the late handles, the registered
/// lanes and checks, and the three stores a job writes to.
pub struct Engine {
    /// The `scanner:` configuration section.
    pub cfg: ScannerConfig,
    /// The late-bound proxy handles.
    pub late: Arc<ScanLate>,
    /// The lanes the lane crates handed the binary (spec D1).
    pub lanes: Vec<Arc<dyn Lane>>,
    /// The native checks `aitm_scan_checks_http::checks()` handed the binary.
    pub native_checks: Vec<Arc<dyn Check>>,
    /// The checks the scripting tier registered through `reg.add_check`.
    pub script_checks: Arc<CheckRegistry>,
    /// The interim HTTP lane, used only while no HTTP lane crate is built in.
    pub interim: Arc<dyn Lane>,
    /// The live jobs and the retained history.
    pub registry: JobRegistry,
    /// The issue store.
    pub issues: Arc<IssueStore>,
    /// The built-in, file-declared and saved profiles.
    pub profiles: Profiles,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field(
                "lanes",
                &self.lanes.iter().map(|l| l.lane()).collect::<Vec<_>>(),
            )
            .field("native_checks", &self.native_checks.len())
            .field("script_checks", &self.script_checks.len())
            .field("bound", &self.late.is_bound())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// The lanes a job actually runs on (call B2).
    ///
    /// Every lane a lane crate handed us, plus the interim HTTP lane **only**
    /// when no lane crate supplied one: the day `aitm_scan_http::lane()`
    /// returns `Some`, the interim lane stops being used with no code change
    /// here, and T2 then deletes it.
    pub fn lanes_for_run(&self) -> Vec<Arc<dyn Lane>> {
        let mut run = self.lanes.clone();
        if !run.iter().any(|lane| lane.lane() == LaneKind::Http) {
            run.push(Arc::clone(&self.interim));
        }
        run
    }

    /// [`lanes_for_run`](Self::lanes_for_run) as `scan.checks` reports it: each
    /// lane with its source, `interim` for the engine's own HTTP lane and
    /// `crate` for every lane a lane crate handed the binary.
    pub fn lane_entries(&self) -> Vec<aitm_scan_model::LaneEntry> {
        self.lanes_for_run()
            .iter()
            .map(|lane| aitm_scan_model::LaneEntry {
                lane: lane.lane(),
                source: if Arc::ptr_eq(lane, &self.interim) {
                    aitm_scan_model::LaneSource::Interim
                } else {
                    aitm_scan_model::LaneSource::Crate
                },
            })
            .collect()
    }

    /// The catalogue as this engine would run it, assembled fresh so a script
    /// added since the last call is in it (spec D4).
    pub fn catalogue(&self) -> Catalogue {
        assemble(
            &self.lanes_for_run(),
            &self.native_checks,
            &self.script_checks,
        )
    }

    /// Resolve `requested` against the lanes this build has, reporting the ones
    /// it does not (spec D1/D3/D5).
    pub fn resolve_lanes(&self, requested: &[LaneKind]) -> (Vec<Arc<dyn Lane>>, LaneReport) {
        let available = self.lanes_for_run();
        let mut run = Vec::new();
        let mut report = LaneReport {
            requested: requested.to_vec(),
            run: Vec::new(),
            skipped: Vec::new(),
        };
        for kind in requested {
            match available.iter().find(|lane| lane.lane() == *kind) {
                Some(lane) => {
                    run.push(Arc::clone(lane));
                    report.run.push(*kind);
                }
                None => report.skipped.push(SkippedLane {
                    lane: *kind,
                    reason: "lane not available on this build".to_string(),
                }),
            }
        }
        (run, report)
    }
}

/// The L4-layer and agent gates of spec D3, in one place (security review,
/// 2026-11-01).
///
/// `scan.start` calls it as steps (5) and (6) of its ladder, and the verb layer
/// calls it too, so an agent is refused with the same code and the same
/// sentence wherever the refusal is reached. It reads the configuration from
/// `engine.cfg` and the **live** agent policy from the bound services, because
/// an operator may have changed the policy since the process started.
///
/// `force_map` is the `scan.map` exemption (AC T1-4): a map job is a `Write`
/// verb that sends no probe, so an agent's map is admitted under `auto`, needs
/// no `allow_agent_active`, and the `intrusive` bar does not apply (`start`
/// forces the map shape to `passive`). Only `scan.start` is deferred to this
/// gate under `auto` (call B6). The worker's policy re-check still stops a
/// running map job when the operator pauses the agent. The L4 checks above
/// cannot apply to a map job either: `start` forces `lanes: [http]`.
pub fn agent_gate(
    engine: &Engine,
    caller: &Caller,
    profile: &ScanProfile,
    force_map: bool,
) -> anyhow::Result<()> {
    let services = engine.late.get()?;
    let l4_requested = profile
        .lanes
        .iter()
        .any(|lane| matches!(lane, LaneKind::L4Packet | LaneKind::L4Stream));

    if l4_requested {
        if services.l4.is_none() {
            return Err(scan_error(
                ScanErrorCode::RefusedL4,
                "the l4 layer is disabled",
            ));
        }
        if caller.is_agent()
            && !(engine.cfg.allow_agent_l4_fuzz && engine.cfg.l4_allow_agent_inject)
        {
            return Err(scan_error(
                ScanErrorCode::RefusedL4,
                "an agent needs both `scanner.allow_agent_l4_fuzz` and `l4.allow_agent_inject`",
            ));
        }
    }

    if !caller.is_agent() || force_map {
        return Ok(());
    }
    if (services.agent_policy)() == AgentPolicy::Auto {
        return Err(scan_error(
            ScanErrorCode::RefusedAgent,
            "the agent policy is `auto`; an operator can switch to `all` with agent.set",
        ));
    }
    if !engine.cfg.allow_agent_active {
        return Err(scan_error(
            ScanErrorCode::RefusedAgent,
            "an agent needs `scanner.allow_agent_active` to start an active scan",
        ));
    }
    if profile.intensity == Intensity::Intrusive {
        return Err(scan_error(
            ScanErrorCode::RefusedAgent,
            "`intensity: intrusive` is operator-only",
        ));
    }
    Ok(())
}

/// `scan.start` (and, with `force_map`, `scan.map`): validate, gate, admit and
/// spawn (spec D3, D5).
///
/// Every refusal is checked in one fixed order, so a caller that is wrong in
/// two ways always learns the same reason first. The order the body below
/// implements, which is spec D3's:
///
/// 1. the `scan.map` shape (`force_map`), then profile validation and clamping
///    (`invalid_profile`);
/// 2. the check selection (`unknown_check`);
/// 3. lane availability (`lane_unavailable`), then the l4-target rule and the
///    per-lane validation of the lanes that will actually run
///    (`invalid_profile`);
/// 4. scope, for every HTTP origin and L4 target (`out_of_scope`);
/// 5. and 6. the L4 layer gate and the agent gate, both in [`agent_gate`]
///    (`refused_l4`, then `refused_agent`);
/// 7. and 8. the concurrency gate and the admission (`busy`).
///
/// Nothing sends: by the time this returns, the job exists, is `queued`, and
/// the worker owns it. Step (6) is also why no verb takes the agent gate
/// itself — doing so would move `refused_agent` ahead of (3) and (4).
pub fn start(
    engine: &Arc<Engine>,
    mut profile: ScanProfile,
    caller: Caller,
    force_map: bool,
) -> anyhow::Result<StartResult> {
    let services = engine.late.get()?;

    // (1) `scan.map` is the passive, HTTP-only shape: it crawls and reads, and
    // sends no probe, so it is a `Write` verb rather than a `Sensitive` one.
    // Its crawl follows GET links only: a form POST is a write the target did
    // not see coming; a map job is admitted to an agent under `auto` on the
    // strength of sending no probe (security review, whole branch, 2026-11-01).
    if force_map {
        // Lanes and intensity only. `crawl.submit_forms` stays as the profile
        // says: spec D8.1 makes form filling with inert generated values a
        // crawl step (it reaches routes and finds points), not a probe, and
        // "map-only" means no checks, not no forms (coordinator decision,
        // 2026-11-01, reversing the earlier security-review Minor).
        profile.lanes = vec![LaneKind::Http];
        profile.intensity = Intensity::Passive;
    }
    profiles::validate(&profile).map_err(|e| scan_error(ScanErrorCode::InvalidProfile, e))?;
    let clamped: Vec<Clamped> = profiles::clamp(
        &mut profile,
        &engine.cfg.ceilings,
        engine.cfg.check_timeout_s,
    );

    // (2) An unknown selector is the caller's typo, not a missing lane.
    let catalogue = engine.catalogue();
    for conflict in catalogue.conflicts() {
        tracing::warn!(target: "aitm::scanner", "{conflict}");
    }
    catalogue.validate_selection(&profile.checks)?;

    // (3) Lane availability. A profile with one available lane runs. This is
    // resolved **before** any lane-specific validation, so a requested lane this
    // build does not have is skipped and reported, never a reason to refuse the
    // whole job (finding 1, spec D1/D3/D5).
    let (run, lanes) = engine.resolve_lanes(&profile.lanes);
    if run.is_empty() {
        let names = profile
            .lanes
            .iter()
            .map(util::wire_token)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(scan_error(
            ScanErrorCode::LaneUnavailable,
            format!("no requested lane is available on this build: {names}"),
        ));
    }
    // From here the job runs only the lanes that resolved; the skipped ones are
    // reported in `lanes.skipped` and must not drive any downstream gate (the l4
    // target rule below, the l4 layer gate, the l4 counters on the status).
    profile.lanes = lanes.run.clone();

    // The l4-lane/target rule, applied to the lanes that will run: an *available*
    // l4 lane with no `target.l4` is still `invalid_profile` (the rule moved here
    // from `profiles::validate` so an *unavailable* l4 lane is skipped instead).
    let l4_will_run = profile
        .lanes
        .iter()
        .any(|lane| matches!(lane, LaneKind::L4Packet | LaneKind::L4Stream));
    if l4_will_run && profile.target.l4.is_empty() {
        return Err(scan_error(
            ScanErrorCode::InvalidProfile,
            "an l4 lane needs at least one `target.l4` entry",
        ));
    }
    // A lane that cannot run this profile says so now, synchronously, rather
    // than failing a job the caller already believes started (AC T5-3).
    for lane in &run {
        if let Err(message) = lane.validate(&profile.target, &profile) {
            return Err(scan_error(ScanErrorCode::InvalidProfile, message));
        }
    }

    // (4) Scope: every HTTP origin and every L4 target, before anything spawns.
    let mut origins = Vec::new();
    for origin in &profile.target.origins {
        let normalized = profiles::normalize_origin(origin)
            .map_err(|e| scan_error(ScanErrorCode::InvalidProfile, e))?;
        // Ask the guard about the same `host:port` the request-time guard will
        // see (the explicit port, else the scheme default), through the one
        // parser the crawl seed and `inject` use. A ported scope entry such as
        // `127.0.0.1:54010` matches only on port equality, so a bare host
        // would never be admitted by it. An origin the parser cannot fold is
        // refused (deny-by-default) rather than checked on a guess.
        let admitted = crate::crawl::guard_authority_for(&normalized)
            .is_some_and(|authority| services.guard.in_scope(&authority));
        if !admitted {
            return Err(scan_error(
                ScanErrorCode::OutOfScope,
                format!("{normalized} is not in the HTTP scope"),
            ));
        }
        origins.push(normalized);
    }
    if let Some(guard) = &services.l4 {
        for target in &profile.target.l4 {
            check_l4_target(guard.as_ref(), target)?;
        }
    }

    // (5) and (6): the L4 layer gate and the agent gate, in one place so the
    // verb layer (Task 15) refuses with exactly the same words.
    agent_gate(engine, &caller, &profile, force_map)?;

    // (7) and (8): the concurrency gate — the job ceiling and the per-origin
    // single flight — and the admission, in one critical section of the
    // registry (`JobRegistry::admit`). The confinement token lives on the
    // entry and drops with it, so a job can never leave the egress posture
    // held.
    let confine = services.egress.as_ref().map(|e| e.confine());
    let started_by = caller.started_by();
    let mut targets = origins.clone();
    targets.extend(
        profile
            .target
            .l4
            .iter()
            .map(|t| format!("{}:{}", t.ip, t.port)),
    );

    let status = JobStatus {
        job: String::new(),
        state: JobState::Queued,
        phase: Phase::Queued,
        profile_name: profile.name.clone(),
        targets,
        started_by: started_by.clone(),
        started_at: util::now_ms(),
        probes: ProbeCounters {
            budget: u64::from(profile.budget.probes),
            ..ProbeCounters::default()
        },
        lanes: lanes.clone(),
        clamped: clamped.clone(),
        l4: l4_will_run.then(Default::default),
        session: (profile.session.mode == SessionMode::Observed).then(SessionStatus::default),
        ..JobStatus::default()
    };

    let cancel = CancellationToken::new();
    let discovery = Arc::new(RwLock::new(Discovery::default()));
    let status = Arc::new(RwLock::new(status));
    let job = engine
        .registry
        .admit(engine.cfg.max_jobs as usize, &origins, |id| {
            status.write().unwrap_or_else(|e| e.into_inner()).job = id.clone();
            JobEntry {
                status: Arc::clone(&status),
                cancel: cancel.clone(),
                confine,
                started_by: started_by.clone(),
                discovery: Arc::clone(&discovery),
                origins: origins.clone(),
                is_agent: caller.is_agent(),
                terminal: tokio::sync::watch::channel(false).0,
            }
        })
        .map_err(|refused| match refused {
            AdmitRefused::MaxJobs => scan_error(
                ScanErrorCode::Busy,
                format!("{} scan jobs are already running", engine.cfg.max_jobs),
            ),
            AdmitRefused::Origin(origin) => scan_error(
                ScanErrorCode::Busy,
                format!("a scan is already running against {origin}"),
            ),
            AdmitRefused::NoFreeId => {
                anyhow::anyhow!("job registry: no free job id after {MAX_ID_ATTEMPTS} attempts")
            }
        })?;

    let ctx = JobStart {
        job: job.clone(),
        profile: profile.clone(),
        status: Arc::clone(&status),
        cancel,
        discovery,
        lanes: run,
        is_agent: caller.is_agent(),
        started_by,
    };
    // The worker is detached on purpose: it owns its own cancellation token
    // (`scan.cancel`) and ends by moving the entry to a terminal state, so
    // there is nothing a retained `JoinHandle` could do that the token does
    // not do better (whole-branch quality finding).
    let engine_for_worker = Arc::clone(engine);
    services
        .rt
        .spawn(async move { crate::worker::run_job(engine_for_worker, ctx).await });

    let snapshot = status.read().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(StartResult {
        job,
        status: snapshot,
        clamped,
        lanes,
        dry_run: l4_will_run.then_some(profile.l4.dry_run),
    })
}

/// Everything the worker is handed at spawn time.
pub struct JobStart {
    /// The job's id.
    pub job: JobId,
    /// The resolved, clamped profile.
    pub profile: ScanProfile,
    /// The status every verb reads.
    pub status: Arc<RwLock<JobStatus>>,
    /// The job's cancellation token.
    pub cancel: CancellationToken,
    /// Where discovery's result is published for `scan.sitemap`.
    pub discovery: Arc<RwLock<Discovery>>,
    /// The lanes this job runs, already resolved.
    pub lanes: Vec<Arc<dyn Lane>>,
    /// Whether an agent started it (spec D5 "Policy re-check").
    pub is_agent: bool,
    /// Who started it.
    pub started_by: StartedBy,
}

/// Refuse an L4 target the guard does not grant `Inject` on (spec D3).
fn check_l4_target(
    guard: &aitm_proto_l4::guard::L4Guard,
    target: &L4TargetSpec,
) -> anyhow::Result<()> {
    let Ok(ip) = target.ip.parse::<std::net::IpAddr>() else {
        return Err(scan_error(
            ScanErrorCode::InvalidProfile,
            format!("`target.l4`: `{}` is not an IP address", target.ip),
        ));
    };
    let l4_target = aitm_proto_l4::types::L4Target {
        interface: "*".to_string(),
        direction: aitm_proto_l4::types::L4Direction::Outbound,
        dst: Some(ip),
        dst_port: Some(target.port),
        proto: match target.proto {
            L4Transport::Tcp => aitm_proto_l4::types::L4Proto::Tcp,
            L4Transport::Udp => aitm_proto_l4::types::L4Proto::Udp,
        },
    };
    guard
        .check(aitm_proto_l4::types::L4Action::Inject, &l4_target)
        .map_err(|e| {
            scan_error(
                ScanErrorCode::OutOfScope,
                format!(
                    "{}:{} is not in the l4 inject scope: {e}",
                    target.ip, target.port
                ),
            )
        })?;
    Ok(())
}

/// A duration that never overflows an `Instant`.
pub(crate) fn bounded_secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(60 * 60 * 24 * 7))
}

/// `now + bounded_secs(seconds)` — the one way a job, a manual check or a
/// per-check timeout turns a configured number of seconds into a deadline.
///
/// Three sites spelled this out with three different fallbacks for an
/// `Instant` that cannot represent the sum (whole-branch quality finding).
/// It is unreachable in practice — [`bounded_secs`] caps at a week — and the
/// one fallback here is a minute, then now, so a clock at the end of its
/// range ends the job rather than running it unbounded.
pub(crate) fn deadline_in(seconds: u64) -> Instant {
    let now = Instant::now();
    now.checked_add(bounded_secs(seconds))
        .or_else(|| now.checked_add(Duration::from_secs(60)))
        .unwrap_or(now)
}

/// The stubs Task 14's own tests share: a `ProxyClient` that answers from
/// memory, a scriptable `Lane`/`ProbeHost`/`Check`, and a `Harness` that
/// assembles an [`Engine`] over them. Never compiled into a release build.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime};

    use aitm_core::{
        AgentPolicy, Body, ConnInfo, EgressConfinement, Flow, FlowId, FlowMeta, FlowStore,
        Frontend, HeaderMap, HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState,
        JobBus, MemFlowStore, ProxyClient, ScopeEntry, ScopeRateGuard, SendOptions, StdGuard,
    };
    use aitm_scan_model::{
        Check, CheckCost, CheckMeta, CheckOrigin, CheckRegistry, CheckScope, Confidence, Discovery,
        Evidence, InsertionKind, InsertionPoint, Intensity, JobCtx, L4Counters, Lane, LaneKind,
        Outcome, Payload, PayloadMode, ProbeHost, ProbeResponse, ProfileTarget, RawProbe,
        ScanProfile, ScanRefusal, SiteNode, Technique, Verdict,
    };
    use futures::future::BoxFuture;

    use crate::config::ScannerConfig;
    use crate::issues::IssueStore;
    use crate::jobs::{Caller, Engine, ScanLate, ScanServices};
    use crate::profiles::Profiles;

    /// The payload a [`FakeCheck`] sends to make its host report the session
    /// lost through [`JobCtx::report_session_lost`].
    pub(crate) const SESSION_LOST_PAYLOAD: &str = "__report_session_lost__";

    /// The payload that makes the host fail the probe with the
    /// `scan: session_lost: ` error prefix instead (coordinator decision 1).
    pub(crate) const SESSION_LOST_ERR_PAYLOAD: &str = "__probe_err_session_lost__";

    /// The ordinary payload.
    pub(crate) const PROBE_PAYLOAD: &str = "probe";

    /// What a panicking fake lane or check panics with.
    pub(crate) const PANIC_TEXT: &str = "the fake blew up on purpose";

    /// A `ProxyClient` that answers every send with a canned `200` and counts
    /// what it was asked to do. No I/O, no network.
    pub(crate) struct StubClient {
        calls: AtomicU64,
        last_call_ms: AtomicU64,
        seen: Mutex<Vec<SendOptions>>,
        requests: Mutex<Vec<HttpRequest>>,
        /// An HTML page every send is answered with, when a test serves one;
        /// otherwise the canned `200 ok`.
        page: Option<String>,
        /// The status every send is answered with (`200` unless a test asks
        /// for another). A `5xx` is an answer like any other since amendment
        /// 40: the per-host error ladder counts transport errors and timeouts
        /// only, which [`StubClient::failing`] models.
        status: u16,
        /// When set, every send fails at the transport with this text instead
        /// of answering — what the per-host error ladder counts.
        failing: Option<&'static str>,
    }

    impl StubClient {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                last_call_ms: AtomicU64::new(0),
                seen: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                page: None,
                status: 200,
                failing: None,
            })
        }

        /// A client that answers every send with `html` as `text/html`, so the
        /// client crawl has something to extract.
        pub(crate) fn serving(html: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                last_call_ms: AtomicU64::new(0),
                seen: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                page: Some(html.to_string()),
                status: 200,
                failing: None,
            })
        }

        /// A client whose every send fails at the transport with `text` — the
        /// outcome the per-host error ladder counts (`client.rs`
        /// `ProbeMeter::record`). The call is still recorded.
        pub(crate) fn failing(text: &'static str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                last_call_ms: AtomicU64::new(0),
                seen: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                page: None,
                status: 200,
                failing: Some(text),
            })
        }

        /// The authority of every request the client was handed, in order.
        pub(crate) fn authorities(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("requests lock")
                .iter()
                .map(|req| req.authority.clone())
                .collect()
        }

        /// `METHOD path` for every request the client was handed, in order.
        pub(crate) fn trail(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("requests lock")
                .iter()
                .map(|req| format!("{} {}", req.method, req.path))
                .collect()
        }

        /// How many sends the client was handed.
        pub(crate) fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }

        /// When the last send arrived, in epoch milliseconds.
        pub(crate) fn last_call_ms(&self) -> u64 {
            self.last_call_ms.load(Ordering::SeqCst)
        }

        /// The options every send arrived under, in order.
        pub(crate) fn seen(&self) -> Vec<SendOptions> {
            self.seen.lock().expect("seen lock").clone()
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
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.seen.lock().expect("seen lock").push(opts);
                self.requests
                    .lock()
                    .expect("requests lock")
                    .push(req.clone());
                self.last_call_ms
                    .store(crate::util::now_ms(), Ordering::SeqCst);
                if let Some(text) = self.failing {
                    anyhow::bail!("{text}");
                }
                let mut flow = stub_flow(req);
                if let Some(response) = flow.response.as_mut() {
                    response.status = self.status;
                }
                if let (Some(page), Some(response)) = (&self.page, flow.response.as_mut()) {
                    response
                        .headers
                        .set("content-type", "text/html; charset=utf-8");
                    response.body = Body::Bytes(page.as_bytes().to_vec());
                }
                Ok(flow)
            })
        }
    }

    /// A captured-looking flow for `req`, answered `200 OK` with a tiny body.
    pub(crate) fn stub_flow(req: HttpRequest) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: req,
            response: Some(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Bytes(b"ok".to_vec()),
                timestamp: SystemTime::now(),
            }),
            client_conn: ConnInfo {
                peer: "127.0.0.1:0".parse().expect("loopback"),
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            },
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// What one [`FakeCheck`] run does.
    #[derive(Debug, Clone)]
    pub(crate) struct FakeRun {
        /// The outcome the run reports.
        pub(crate) outcome: Outcome,
        /// How many probes it sends first.
        pub(crate) probes: u32,
        /// The payload each of those probes carries.
        pub(crate) payload: &'static str,
        /// Budget units the run charges through [`ProbeHost::charge`] before
        /// it probes, as a non-HTTP stimulus does (a WebSocket frame, an L4
        /// case, a browser navigation).
        pub(crate) charge: u32,
        /// The verdict's `detail` text.
        pub(crate) detail: &'static str,
    }

    impl FakeRun {
        pub(crate) fn clean() -> Self {
            Self {
                outcome: Outcome::Clean,
                probes: 1,
                payload: PROBE_PAYLOAD,
                charge: 0,
                detail: "fake check",
            }
        }

        pub(crate) fn vulnerable() -> Self {
            Self {
                outcome: Outcome::Vulnerable,
                ..Self::clean()
            }
        }

        /// A run that sends nothing and answers `Outcome::Error` carrying
        /// `detail`, as a check whose runner is missing does (amendment 58).
        pub(crate) fn error(detail: &'static str) -> Self {
            Self {
                outcome: Outcome::Error,
                probes: 0,
                detail,
                ..Self::clean()
            }
        }

        pub(crate) fn with_probes(mut self, probes: u32) -> Self {
            self.probes = probes;
            self
        }

        pub(crate) fn with_payload(mut self, payload: &'static str) -> Self {
            self.payload = payload;
            self
        }

        /// Charge `units` through [`ProbeHost::charge`], the way a lane meters
        /// a stimulus that never goes through the job client.
        pub(crate) fn with_charge(mut self, units: u32) -> Self {
            self.charge = units;
            self
        }
    }

    /// A [`Check`] whose verdicts are scripted run by run.
    pub(crate) struct FakeCheck {
        meta: CheckMeta,
        script: Mutex<VecDeque<FakeRun>>,
        fallback: FakeRun,
        runs: AtomicU64,
        block_until_cancelled: bool,
        /// Panic inside `run` instead of returning a verdict.
        panics: bool,
        hint: Option<aitm_scan_model::PocHint>,
        /// Locations the verdict reports instead of the point's own: the first
        /// is the root verdict's, the rest ride in `more`.
        locations: Vec<String>,
    }

    impl FakeCheck {
        /// A check of class `class` that reports `fallback` on every run.
        pub(crate) fn new(id: &str, class: &str, fallback: FakeRun) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, class),
                script: Mutex::new(VecDeque::new()),
                fallback,
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: None,
                locations: Vec::new(),
            })
        }

        /// A check of class `class` that runs on `lane` rather than HTTP, so a
        /// non-HTTP lane's stimuli can be metered in a test.
        pub(crate) fn on_lane(
            id: &str,
            class: &str,
            lane: LaneKind,
            fallback: FakeRun,
        ) -> Arc<Self> {
            let mut meta = fake_meta(id, class);
            meta.lanes = vec![lane];
            Arc::new(Self {
                meta,
                script: Mutex::new(VecDeque::new()),
                fallback,
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: None,
                locations: Vec::new(),
            })
        }

        /// A check whose vulnerable verdict carries a PoC hint, so the engine
        /// reaches the reproduction path (spec D6).
        pub(crate) fn hinted(id: &str, class: &str) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, class),
                script: Mutex::new(VecDeque::new()),
                fallback: FakeRun::vulnerable(),
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: Some(aitm_scan_model::PocHint {
                    assertions: vec![aitm_poc::Assertion::Status(200)],
                    control: None,
                }),
                locations: Vec::new(),
            })
        }

        /// A check that reports one issue per entry in `locations`: the first
        /// as the root verdict, the rest as `more` (coordinator item (g)).
        pub(crate) fn multi(id: &str, class: &str, locations: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, class),
                script: Mutex::new(VecDeque::new()),
                fallback: FakeRun::vulnerable(),
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: None,
                locations: locations.iter().map(|p| (*p).to_string()).collect(),
            })
        }

        /// A check that reports `script` in order, then its fallback.
        pub(crate) fn scripted(id: &str, class: &str, script: Vec<FakeRun>) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, class),
                script: Mutex::new(script.into_iter().collect()),
                fallback: FakeRun::clean(),
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: None,
                locations: Vec::new(),
            })
        }

        /// A passive check (`intensity: passive`, `technique: passive`), the
        /// only kind a `scan.map` job schedules. Its fake run still goes
        /// through the job client, so the harness can count it.
        pub(crate) fn passive(id: &str, class: &str) -> Arc<Self> {
            let mut meta = fake_meta(id, class);
            meta.intensity = Intensity::Passive;
            meta.technique = Technique::Passive;
            Arc::new(Self {
                meta,
                script: Mutex::new(VecDeque::new()),
                fallback: FakeRun::clean(),
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: false,
                hint: None,
                locations: Vec::new(),
            })
        }

        /// A check that never finishes until the job is cancelled.
        pub(crate) fn blocking(id: &str) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, "demo"),
                script: Mutex::new(VecDeque::new()),
                fallback: FakeRun::clean(),
                runs: AtomicU64::new(0),
                block_until_cancelled: true,
                panics: false,
                hint: None,
                locations: Vec::new(),
            })
        }
    }

    impl FakeCheck {
        /// A check whose `run` panics, as a buggy lane crate's check would.
        pub(crate) fn panicking(id: &str, class: &str) -> Arc<Self> {
            Arc::new(Self {
                meta: fake_meta(id, class),
                script: Mutex::new(VecDeque::new()),
                fallback: FakeRun::clean(),
                runs: AtomicU64::new(0),
                block_until_cancelled: false,
                panics: true,
                hint: None,
                locations: Vec::new(),
            })
        }
    }

    impl Check for FakeCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }

        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async move {
                self.runs.fetch_add(1, Ordering::SeqCst);
                if self.panics {
                    panic!("{PANIC_TEXT}");
                }
                if self.block_until_cancelled {
                    while !host.cancelled() {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                    return verdict(Outcome::Inconclusive, "cancelled");
                }
                let run = self
                    .script
                    .lock()
                    .expect("script lock")
                    .pop_front()
                    .unwrap_or_else(|| self.fallback.clone());
                if run.charge > 0 && !host.charge(run.charge) {
                    return verdict(Outcome::Error, "the budget refused the stimulus");
                }
                for _ in 0..run.probes {
                    let payload = Payload {
                        value: run.payload.to_string(),
                        mode: PayloadMode::Replace,
                        bytes: None,
                    };
                    // A real check reports a probe it could not send as an
                    // `Error` verdict carrying the error text; the engine reads
                    // the `scan: session_lost: ` prefix out of it.
                    if let Err(e) = host.probe(&payload).await {
                        return verdict(Outcome::Error, &e.to_string());
                    }
                }
                let mut out = verdict(run.outcome, run.detail);
                out.poc_hint = self.hint.clone();
                let mut rest = self.locations.iter();
                if let Some(first) = rest.next() {
                    out.location = Some(aitm_scan_model::VerdictLocation {
                        path: Some(first.clone()),
                        name: None,
                    });
                    out.more = rest
                        .map(|path| {
                            let mut sibling = verdict(run.outcome, run.detail);
                            sibling.location = Some(aitm_scan_model::VerdictLocation {
                                path: Some(path.clone()),
                                name: None,
                            });
                            sibling
                        })
                        .collect();
                }
                out
            })
        }
    }

    fn verdict(outcome: Outcome, detail: &str) -> Verdict {
        Verdict {
            outcome,
            confidence: Confidence::Firm,
            evidence: Evidence {
                payload: Some(PROBE_PAYLOAD.to_string()),
                ..Evidence::default()
            },
            detail: detail.to_string(),
            poc_hint: None,
            location: None,
            more: Vec::new(),
        }
    }

    /// A catalogue entry for a [`FakeCheck`]: active, light, query points.
    pub(crate) fn fake_meta(id: &str, class: &str) -> CheckMeta {
        CheckMeta {
            id: id.to_string(),
            name: format!("fake {id}"),
            class: class.to_string(),
            lanes: vec![LaneKind::Http],
            kinds: vec![InsertionKind::Query],
            intensity: Intensity::Light,
            cost: CheckCost::Light,
            technique: Technique::Reflected,
            severity: aitm_poc::Severity::Medium,
            confidence_max: Confidence::Firm,
            needs_baseline: false,
            wants_traits: None,
            targets_session: false,
            scope: CheckScope::Point,
            cwe: Some(79),
            description: "A scripted check.".to_string(),
            remediation: Some("Nothing: it is a stub.".to_string()),
            origin: CheckOrigin::Native,
        }
    }

    /// The [`ProbeHost`] [`FakeLane`] builds: it probes through the job's own
    /// client, so budget, pacing and the meter all move for real.
    pub(crate) struct FakeHost {
        point: InsertionPoint,
        job: Arc<dyn JobCtx>,
        profile: ScanProfile,
        held: Mutex<Vec<Flow>>,
    }

    impl FakeHost {
        async fn send(&self, value: &str) -> anyhow::Result<ProbeResponse> {
            if value == SESSION_LOST_PAYLOAD {
                self.job.report_session_lost();
            }
            if value == SESSION_LOST_ERR_PAYLOAD {
                anyhow::bail!("scan: session_lost: canary 302");
            }
            let url = self
                .point
                .url
                .clone()
                .unwrap_or_else(|| "http://scan.test/".to_string());
            let parsed = url::Url::parse(&url).map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
            let req = HttpRequest {
                method: self
                    .point
                    .method
                    .clone()
                    .unwrap_or_else(|| "GET".to_string()),
                scheme: parsed.scheme().to_string(),
                authority: parsed.host_str().unwrap_or("scan.test").to_string(),
                path: format!("{}?{}={value}", parsed.path(), self.point.name),
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            };
            let flow = self.job.client().send(req).await?;
            let status = flow.response.as_ref().map(|r| r.status);
            self.held
                .lock()
                .expect("held lock")
                .push(Flow::Http(flow.clone()));
            Ok(ProbeResponse {
                status,
                headers: Vec::new(),
                body: b"ok".to_vec(),
                elapsed_ms: 1,
                flow: None,
                ws_frames: None,
                l4: None,
            })
        }
    }

    impl ProbeHost for FakeHost {
        fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(self.send("baseline"))
        }

        fn probe<'a>(
            &'a self,
            payload: &'a Payload,
        ) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
            Box::pin(async move { self.send(&payload.value).await })
        }

        fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async { Err(anyhow::anyhow!("the fake host sends no raw probe")) })
        }

        fn marker(&self) -> String {
            self.job.marker()
        }

        fn budget_left(&self) -> u32 {
            self.job.budget_left()
        }

        fn deadline(&self) -> Instant {
            self.job.deadline()
        }

        fn profile(&self) -> &ScanProfile {
            &self.profile
        }

        fn cancelled(&self) -> bool {
            self.job.cancelled()
        }

        fn held_flows(&self) -> Vec<Flow> {
            self.held.lock().expect("held lock").clone()
        }

        fn client(&self) -> Option<Arc<dyn ProxyClient>> {
            Some(self.job.client())
        }

        /// The engine's host charges the job budget, so the fake does too.
        fn charge(&self, units: u32) -> bool {
            self.job.charge(units)
        }
    }

    /// A [`Lane`] that discovers a scripted point list and ships scripted checks.
    pub(crate) struct FakeLane {
        kind: LaneKind,
        points: Vec<InsertionPoint>,
        nodes: Vec<SiteNode>,
        checks: Vec<Arc<dyn Check>>,
        discover_error: Option<String>,
        /// Panic inside `discover` instead of returning.
        discover_panic: bool,
        validate_error: Option<String>,
        l4_reports: Vec<L4Counters>,
        discoveries: AtomicU64,
        /// Budget units `discover` charges through [`JobCtx::charge`], as a
        /// browser crawl charges one unit per navigation.
        discover_charge: u32,
        /// Crawl captures `discover` leaves in the store, each carrying this
        /// job's `scan:<job>` mark and the `crawl` mark, as both crawl paths
        /// leave behind.
        crawl_flows: u32,
        /// `(origin, reason)` pairs `discover` reports through
        /// [`JobCtx::report_crawl_error`], one per failed crawl request, as the
        /// interim lane does (amendment 39).
        crawl_errors: Vec<(String, String)>,
        /// Forms `discover` reports as submitted through
        /// [`JobCtx::report_forms_submitted`], as a crawl that posted them
        /// does (amendment 53).
        forms_submitted: u64,
    }

    impl FakeLane {
        /// An HTTP lane over two query points on `http://scan.test/search`.
        pub(crate) fn http() -> Self {
            Self {
                kind: LaneKind::Http,
                points: vec![
                    fake_point("p1", "q", "http://scan.test/search"),
                    fake_point("p2", "r", "http://scan.test/search"),
                ],
                nodes: vec![fake_node()],
                checks: Vec::new(),
                discover_error: None,
                discover_panic: false,
                validate_error: None,
                l4_reports: Vec::new(),
                discoveries: AtomicU64::new(0),
                discover_charge: 0,
                crawl_flows: 0,
                crawl_errors: Vec::new(),
                forms_submitted: 0,
            }
        }

        /// An l4 lane crate, so a build that *has* the l4 lane can be exercised
        /// (the default harness has none, which is "l4 unavailable on this
        /// build"). Only its `lane()` kind matters to the start-path tests.
        /// A WebSocket lane over one point, so a non-HTTP lane's stimuli can
        /// be followed through `scan.status`.
        pub(crate) fn ws() -> Self {
            let mut point = fake_point("w1", "msg", "http://scan.test/socket");
            point.lane = LaneKind::Ws;
            Self {
                kind: LaneKind::Ws,
                points: vec![point],
                ..Self::http()
            }
        }

        pub(crate) fn l4_packet() -> Self {
            Self {
                kind: LaneKind::L4Packet,
                ..Self::http()
            }
        }

        pub(crate) fn with_points(mut self, points: Vec<InsertionPoint>) -> Self {
            self.points = points;
            self
        }

        pub(crate) fn with_check(mut self, check: Arc<dyn Check>) -> Self {
            self.checks.push(check);
            self
        }

        /// `discover` reports each `(origin, reason)` through
        /// `JobCtx::report_crawl_error`, like a client crawl whose requests
        /// failed; pair it with no crawl captures for an all-failing crawl.
        pub(crate) fn with_crawl_errors(mut self, errors: Vec<(&str, &str)>) -> Self {
            self.crawl_errors = errors
                .into_iter()
                .map(|(o, r)| (o.to_string(), r.to_string()))
                .collect();
            self
        }

        /// `discover` reports `count` submitted forms through
        /// `JobCtx::report_forms_submitted`, like a client crawl that posted
        /// `count` forms (amendment 53).
        pub(crate) fn with_forms_submitted(mut self, count: u64) -> Self {
            self.forms_submitted = count;
            self
        }

        pub(crate) fn with_discover_error(mut self, text: &str) -> Self {
            self.discover_error = Some(text.to_string());
            self
        }

        /// A lane whose `discover` panics with [`PANIC_TEXT`].
        pub(crate) fn with_discover_panic(mut self) -> Self {
            self.discover_panic = true;
            self
        }

        pub(crate) fn with_validate_error(mut self, text: &str) -> Self {
            self.validate_error = Some(text.to_string());
            self
        }

        pub(crate) fn with_l4_reports(mut self, reports: Vec<L4Counters>) -> Self {
            self.l4_reports = reports;
            self
        }

        /// Charge `units` from `discover`, as a browser crawl charges one unit
        /// per navigation.
        pub(crate) fn with_discover_charge(mut self, units: u32) -> Self {
            self.discover_charge = units;
            self
        }

        /// Leave `pages` crawl captures in the store from `discover`, marked
        /// the way both crawl paths mark a page they fetched.
        pub(crate) fn with_crawl_flows(mut self, pages: u32) -> Self {
            self.crawl_flows = pages;
            self
        }
    }

    impl Lane for FakeLane {
        fn lane(&self) -> LaneKind {
            self.kind
        }

        fn discover<'a>(
            &'a self,
            _target: &'a ProfileTarget,
            job: &'a dyn JobCtx,
        ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
            Box::pin(async move {
                self.discoveries.fetch_add(1, Ordering::SeqCst);
                for counters in &self.l4_reports {
                    job.report_l4(*counters);
                }
                if self.discover_charge > 0 {
                    job.charge(self.discover_charge);
                }
                for page in 0..self.crawl_flows {
                    job.store().insert(crawl_capture(job.job_id(), page));
                }
                for (origin, reason) in &self.crawl_errors {
                    job.report_crawl_error(origin, reason);
                }
                if self.forms_submitted > 0 {
                    job.report_forms_submitted(self.forms_submitted);
                }
                if self.discover_panic {
                    panic!("{PANIC_TEXT}");
                }
                if let Some(text) = &self.discover_error {
                    anyhow::bail!("{text}");
                }
                Ok(Discovery {
                    points: self.points.clone(),
                    nodes: self.nodes.clone(),
                })
            })
        }

        fn probe_host_for(
            &self,
            point: &InsertionPoint,
            job: Arc<dyn JobCtx>,
        ) -> anyhow::Result<Box<dyn ProbeHost>> {
            let profile = job.profile().clone();
            Ok(Box::new(FakeHost {
                point: point.clone(),
                job,
                profile,
                held: Mutex::new(Vec::new()),
            }))
        }

        fn checks(&self) -> Vec<Arc<dyn Check>> {
            self.checks.clone()
        }

        fn validate(&self, _target: &ProfileTarget, _profile: &ScanProfile) -> Result<(), String> {
            match &self.validate_error {
                Some(text) => Err(text.clone()),
                None => Ok(()),
            }
        }
    }

    /// One crawl capture of page `page`, marked the way both crawl paths mark
    /// a page they fetched: this job's `scan:<job>` mark and `crawl`.
    pub(crate) fn crawl_capture(job: &str, page: u32) -> Flow {
        let mut flow = stub_flow(HttpRequest {
            method: "GET".to_string(),
            scheme: "http".to_string(),
            authority: "scan.test".to_string(),
            path: format!("/page{page}"),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        });
        flow.metadata.marks = vec![format!("scan:{job}"), "crawl".to_string()];
        Flow::Http(flow)
    }

    /// A query insertion point named `name` on `url`.
    pub(crate) fn fake_point(id: &str, name: &str, url: &str) -> InsertionPoint {
        InsertionPoint {
            id: id.to_string(),
            lane: LaneKind::Http,
            kind: InsertionKind::Query,
            name: name.to_string(),
            path: None,
            example: Some("1".to_string()),
            flow: None,
            site_node: Some("n1".to_string()),
            traits: Vec::new(),
            frequency: 1,
            method: Some("GET".to_string()),
            url: Some(url.to_string()),
        }
    }

    fn fake_node() -> SiteNode {
        SiteNode {
            id: "n1".to_string(),
            method: "GET".to_string(),
            scheme: "http".to_string(),
            host: "scan.test".to_string(),
            port: 80,
            path_template: "/search".to_string(),
            flows: Vec::new(),
            params: Vec::new(),
            auth: false,
            points: 2,
            audited: false,
        }
    }

    /// A directory under `$TMPDIR` removed when the harness drops.
    pub(crate) struct ScratchDir(PathBuf);

    impl ScratchDir {
        pub(crate) fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("aitm-scanner-jobs-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// An [`Engine`] over in-memory services, with the knobs a test turns.
    pub(crate) struct Harness {
        pub(crate) engine: Arc<Engine>,
        pub(crate) client: Arc<StubClient>,
        pub(crate) store: Arc<MemFlowStore>,
        pub(crate) guard: Arc<StdGuard>,
        pub(crate) bus: Arc<JobBus>,
        pub(crate) policy: Arc<Mutex<AgentPolicy>>,
        pub(crate) scratch: Option<Arc<ScratchDir>>,
        /// The egress posture a job holds confined, when a test binds one.
        pub(crate) egress: Option<Arc<EgressConfinement>>,
        /// `(after n sends, policy)`: the live policy the engine reads flips
        /// once the stub client has served `n` probes, so a test can make the
        /// operator turn the policy *mid-job* without racing the worker.
        flip: Arc<Mutex<Option<(u64, AgentPolicy)>>>,
        cfg: ScannerConfig,
        lane: Option<Arc<FakeLane>>,
    }

    /// A fresh [`Engine`] over `cfg`, with `lane` as its only lane crate.
    fn build_engine(cfg: &ScannerConfig, lane: Option<&Arc<FakeLane>>) -> Arc<Engine> {
        let lanes: Vec<Arc<dyn Lane>> = match lane {
            Some(lane) => vec![lane.clone()],
            None => Vec::new(),
        };
        Arc::new(Engine {
            cfg: cfg.clone(),
            late: ScanLate::new(),
            lanes,
            native_checks: Vec::new(),
            script_checks: Arc::new(CheckRegistry::new()),
            interim: crate::interim_lane::InterimHttpLane::new(cfg.clone()),
            registry: crate::jobs::JobRegistry::new(cfg.history),
            issues: Arc::new(IssueStore::new(cfg.findings_dir.as_deref())),
            profiles: Profiles::new(cfg),
        })
    }

    impl Harness {
        /// An engine with one `FakeLane` carrying no check.
        pub(crate) fn new() -> Self {
            Self::make(Some(FakeLane::http()))
        }

        /// An engine with no lane crate at all, so the interim lane is what runs.
        pub(crate) fn bare() -> Self {
            Self::make(None)
        }

        fn make(lane: Option<FakeLane>) -> Self {
            let guard = Arc::new(StdGuard::default());
            for host in ["scan.test", "other.test"] {
                guard.add_scope(ScopeEntry { host: host.into() });
            }
            let cfg = ScannerConfig::default();
            let lane = lane.map(Arc::new);
            Self {
                engine: build_engine(&cfg, lane.as_ref()),
                client: StubClient::new(),
                store: Arc::new(MemFlowStore::new()),
                guard,
                bus: Arc::new(JobBus::default()),
                policy: Arc::new(Mutex::new(AgentPolicy::Ask)),
                scratch: None,
                egress: None,
                flip: Arc::new(Mutex::new(None)),
                cfg,
                lane,
            }
        }

        fn rebuilt(mut self) -> Self {
            self.engine = build_engine(&self.cfg, self.lane.as_ref());
            self
        }

        pub(crate) fn with_lane(mut self, lane: FakeLane) -> Self {
            self.lane = Some(Arc::new(lane));
            self.rebuilt()
        }

        /// Give the lane one check that blocks until the job is cancelled, so a
        /// started job stays active for the length of the test.
        pub(crate) fn with_blocking_check(self) -> Self {
            self.with_lane(FakeLane::http().with_check(FakeCheck::blocking("blocker")))
        }

        /// Serve `html` from every URL, so the interim lane's client crawl
        /// has a page to extract. Call before [`Harness::bind`].
        pub(crate) fn with_page(mut self, html: &str) -> Self {
            self.client = StubClient::serving(html);
            self
        }

        /// Fail every send at the transport with `text`, so a test can make a
        /// host trip the per-host error ladder. Call before [`Harness::bind`].
        pub(crate) fn failing(mut self, text: &'static str) -> Self {
            self.client = StubClient::failing(text);
            self
        }

        /// Bind an egress posture, so a test can watch a job's hold on it.
        pub(crate) fn with_egress(mut self) -> Self {
            self.egress = Some(Arc::new(EgressConfinement::new(false)));
            self
        }

        pub(crate) fn with_max_jobs(mut self, max_jobs: u32) -> Self {
            self.cfg.max_jobs = max_jobs;
            self.rebuilt()
        }

        pub(crate) fn with_agent_active(mut self) -> Self {
            self.cfg.allow_agent_active = true;
            self.rebuilt()
        }

        /// Persist job and issue state under a scratch `findings.dir`.
        pub(crate) fn with_findings_dir(mut self) -> Self {
            let scratch = Arc::new(ScratchDir::new());
            self.cfg.findings_dir = Some(scratch.path().to_path_buf());
            self.scratch = Some(scratch);
            self.rebuilt()
        }

        /// Bind the late services, as the binary does after the proxy is built.
        pub(crate) fn bind(&self) {
            let policy = self.policy.clone();
            let flip = self.flip.clone();
            let client = self.client.clone();
            assert!(self.engine.late.bind(ScanServices {
                store: self.store.clone(),
                client: self.client.clone(),
                guard: self.guard.clone(),
                browser: None,
                egress: self.egress.clone(),
                l4: None,
                jobs: self.bus.clone(),
                agent_policy: Arc::new(move || {
                    if let Some((after, flipped)) = *flip.lock().expect("flip lock") {
                        if client.calls() >= after {
                            return flipped;
                        }
                    }
                    *policy.lock().expect("policy lock")
                }),
                rt: tokio::runtime::Handle::current(),
                // The binary copies `config.findings.dir` onto `ScannerConfig`
                // (call B4), so the two always name the same tree; the harness
                // keeps that invariant.
                config: Arc::new(aitm_core::Config {
                    findings: aitm_core::FindingsConfig {
                        dir: self.cfg.findings_dir.clone(),
                    },
                    ..aitm_core::Config::default()
                }),
            }));
        }

        /// Whether the bound egress posture is confined right now.
        pub(crate) fn egress_confined(&self) -> bool {
            self.egress
                .as_ref()
                .expect("the harness has an egress posture")
                .confined()
        }

        /// The findings directory, when one was configured.
        pub(crate) fn findings_dir(&self) -> PathBuf {
            self.scratch
                .as_ref()
                .expect("the harness has a findings dir")
                .path()
                .to_path_buf()
        }

        /// Flip the live agent policy to `policy` once `after` probes have
        /// been sent (spec D5 "Policy re-check").
        pub(crate) fn flip_policy_after(&self, after: u64, policy: AgentPolicy) {
            *self.flip.lock().expect("flip lock") = Some((after, policy));
        }

        pub(crate) fn set_policy(&self, policy: AgentPolicy) {
            *self.policy.lock().expect("policy lock") = policy;
        }

        /// A named profile over `origins`, default in every other respect.
        pub(crate) fn profile(&self, origins: &[&str]) -> ScanProfile {
            ScanProfile {
                name: "harness".to_string(),
                target: ProfileTarget {
                    origins: origins.iter().map(|o| (*o).to_string()).collect(),
                    l4: Vec::new(),
                },
                ..ScanProfile::default()
            }
        }

        /// Cancel every job the registry holds, so a blocking check ends.
        pub(crate) fn cancel_all(&self) {
            for summary in self.engine.registry.list(true, 64) {
                self.engine.registry.cancel(&summary.job);
            }
        }

        /// Wait for `job` to be terminal via the registry's terminal signal
        /// (see [`wait_terminal`]); no clock, only the `TERMINAL_NET` safety net.
        pub(crate) async fn wait_terminal(&self, job: &str) -> aitm_scan_model::JobStatus {
            wait_terminal(&self.engine.registry, job).await
        }
    }

    /// The safety net around every terminal wait in the tests: never a measured
    /// bound (the job's own deadline and the terminal signal decide), only the
    /// point past which a hung job is reported instead of hanging the suite.
    pub(crate) const TERMINAL_NET: std::time::Duration = std::time::Duration::from_secs(60);

    /// The status once `job` is terminal, read after the registry's terminal
    /// signal fired (so it is terminal, not racing the worker's last write).
    fn terminal_status(
        registry: &crate::jobs::JobRegistry,
        job: &str,
    ) -> aitm_scan_model::JobStatus {
        let status = registry
            .status(job)
            .unwrap_or_else(|| panic!("job {job} is in the registry"));
        assert!(
            status.state.is_terminal(),
            "the terminal signal fired for job {job} but its state is {:?}/{:?}",
            status.state,
            status.phase
        );
        status
    }

    /// Wait for `job` to reach a terminal state by subscribing to the
    /// registry's terminal signal (no polling, no wall-clock bound): resolves
    /// at once for a job that is already over, otherwise when
    /// [`crate::jobs::JobRegistry::finish`] flips it. [`TERMINAL_NET`] only
    /// turns a hung job into a named panic.
    pub(crate) async fn wait_terminal(
        registry: &crate::jobs::JobRegistry,
        job: &str,
    ) -> aitm_scan_model::JobStatus {
        let mut rx = registry
            .terminal_signal(job)
            .unwrap_or_else(|| panic!("job {job} is in the registry"));
        let waited = tokio::time::timeout(TERMINAL_NET, async {
            while !*rx.borrow_and_update() {
                rx.changed()
                    .await
                    .expect("the registry entry outlives the wait");
            }
        })
        .await;
        if waited.is_err() {
            let status = registry.status(job);
            panic!(
                "job {job} is still {:?} after the {TERMINAL_NET:?} safety net",
                status.map(|s| (s.state, s.phase))
            );
        }
        terminal_status(registry, job)
    }

    /// [`wait_terminal`] for a harness waiting from **outside** a runtime: it
    /// blocks on the same signal through a short-lived current-thread runtime.
    /// Call it only from a thread that is not inside a tokio runtime
    /// (`Runtime::block_on` panics when nested); the `commands.rs` harness
    /// qualifies because its `#[test]` threads never enter its own runtime.
    pub(crate) fn wait_terminal_blocking(
        registry: &crate::jobs::JobRegistry,
        job: &str,
    ) -> aitm_scan_model::JobStatus {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime for the blocking wait");
        rt.block_on(wait_terminal(registry, job))
    }

    /// An operator caller (CLI).
    pub(crate) fn operator() -> Caller {
        Caller {
            frontend: Frontend::Cli,
            client_label: None,
        }
    }

    /// An agent caller (MCP).
    pub(crate) fn agent() -> Caller {
        Caller {
            frontend: Frontend::Mcp,
            client_label: Some("agent".to_string()),
        }
    }

    /// The `scan:` code a refusal carries.
    pub(crate) fn code(err: &anyhow::Error) -> aitm_scan_model::ScanErrorCode {
        err.downcast_ref::<ScanRefusal>()
            .unwrap_or_else(|| panic!("`{err}` is not a typed scan refusal"))
            .code
    }

    /// Every flow in `store`, oldest first.
    pub(crate) fn flows(store: &dyn FlowStore) -> Vec<Flow> {
        store
            .list()
            .into_iter()
            .filter_map(|id| store.get(id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;

    use std::sync::Arc;

    use aitm_core::{AgentPolicy, Frontend, ScopeRateGuard};
    use aitm_scan_model::{Intensity, LaneKind, ScanErrorCode, SessionMode, SkippedLane};

    /// Spec D5, call B3: the services are bound by the binary after the proxy
    /// is built. A verb that runs before that fails with a **plain** error —
    /// an unbound handle is a wiring bug, not a caller condition, so it carries
    /// no `scan:` code a frontend could match on.
    #[test]
    fn unbound_services_is_a_plain_error() {
        let late = crate::jobs::ScanLate::new();

        assert!(!late.is_bound());
        let err = late.get().expect_err("nothing is bound yet").to_string();
        assert!(err.contains("not bound"), "{err}");
        assert!(
            !err.starts_with("scan:"),
            "a wiring bug is not a verb refusal: {err}"
        );
    }

    /// Call B2: a lane crate's HTTP lane displaces the interim one without a
    /// code change; with no lane crate the interim lane is what runs.
    #[test]
    fn interim_lane_is_ignored_when_a_crate_lane_exists() {
        let h = Harness::new();
        let run = h.engine.lanes_for_run();
        assert_eq!(run.len(), 1);
        assert_eq!(run[0].lane(), LaneKind::Http);
        assert!(
            Arc::ptr_eq(&run[0], &h.engine.lanes[0]),
            "the lane-crate lane is preferred over the interim one"
        );

        let bare = Harness::bare();
        let run = bare.engine.lanes_for_run();
        assert_eq!(run.len(), 1);
        assert!(
            Arc::ptr_eq(&run[0], &bare.engine.interim),
            "with no lane crate the interim lane runs"
        );
    }

    /// `scan.checks` tells a client which lane is the interim one: with a lane
    /// crate present the `http` lane is `crate`, with none it is `interim`
    /// (a cell that needs T2's lane skips on this, instead of failing).
    #[test]
    fn lane_entries_name_the_interim_lane() {
        use aitm_scan_model::{LaneEntry, LaneSource};
        let bare = Harness::bare();
        assert_eq!(
            bare.engine.lane_entries(),
            vec![LaneEntry {
                lane: LaneKind::Http,
                source: LaneSource::Interim
            }]
        );
        let with_lane = Harness::new();
        let entries = with_lane.engine.lane_entries();
        let http = entries
            .iter()
            .find(|e| e.lane == LaneKind::Http)
            .expect("the harness lane is an http lane");
        assert_eq!(http.source, LaneSource::Crate);
        assert!(entries.iter().all(|e| e.source == LaneSource::Crate));
    }
    /// Coordinator decision 1: the two error-prefix conventions a lane may use
    /// instead of the `JobCtx` hooks.
    #[test]
    fn map_lane_error_reads_the_two_prefixes() {
        use crate::jobs::{map_lane_error, LaneErrorKind};

        assert_eq!(
            map_lane_error(&anyhow::anyhow!("scan: session_lost: canary 302")),
            LaneErrorKind::SessionLost("canary 302".into())
        );
        assert_eq!(
            map_lane_error(&anyhow::anyhow!("invalid_profile: bad seed")),
            LaneErrorKind::InvalidProfile("bad seed".into())
        );
        assert_eq!(
            map_lane_error(&anyhow::anyhow!("connection reset")),
            LaneErrorKind::Other
        );
        // The prefixes are literal: a code inside the text is not a prefix.
        assert_eq!(
            map_lane_error(&anyhow::anyhow!("the probe said scan: session_lost: x")),
            LaneErrorKind::Other
        );
    }

    /// A caller is an agent unless its frontend is a trusted control surface
    /// (`Frontend::is_trusted_control`, the allow-list every gate derives
    /// from): the CLI and an operator-token connection are human; MCP is the
    /// agent (shared facts).
    #[test]
    fn caller_is_agent_unless_its_frontend_is_trusted_control() {
        for (frontend, is_agent) in [
            (Frontend::Mcp, true),
            (Frontend::Cli, false),
            (Frontend::Operator, false),
        ] {
            let caller = crate::jobs::Caller {
                frontend,
                client_label: None,
            };
            assert_eq!(caller.is_agent(), is_agent, "{frontend:?}");
        }
    }

    /// Spec D1/D3: a profile with one available lane runs; the rest are skipped
    /// and reported. `lane_unavailable` fires only when nothing is left.
    #[tokio::test(flavor = "multi_thread")]
    async fn lane_unavailable_only_when_every_lane_is_missing() {
        let h = Harness::new();
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::Http, LaneKind::Ws];
        let started = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect("the http lane is available");
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        assert_eq!(
            started.lanes.skipped,
            vec![SkippedLane {
                lane: LaneKind::Ws,
                reason: "lane not available on this build".into(),
            }]
        );

        let mut profile = h.profile(&["http://other.test"]);
        profile.lanes = vec![LaneKind::Ws];
        let err = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect_err("no lane is available");
        assert!(
            err.to_string().starts_with("scan: lane_unavailable:"),
            "{err}"
        );
        assert_eq!(
            h.client.calls(),
            0,
            "the fake lane and a refused start send nothing"
        );
    }

    /// Finding 1 (T1b fix): lane availability is resolved **before** any l4
    /// target validation, so a profile naming an l4 lane this build does not
    /// have — with no `target.l4` — is not refused. The l4 lane is skipped and
    /// the http lane runs (spec D1/D3/D5). Before the fix this failed with
    /// `scan: invalid_profile: an l4 lane needs at least one target.l4 entry`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unavailable_l4_lane_is_skipped_not_validated() {
        // The default harness has one http lane and no l4 lane (l4 unavailable);
        // `bind` leaves the l4 layer unbound too.
        let h = Harness::new();
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::Http, LaneKind::L4Packet];
        assert!(profile.target.l4.is_empty(), "the profile has no l4 target");

        let started = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect("the unavailable l4 lane is skipped, not validated");
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        assert_eq!(
            started.lanes.skipped,
            vec![SkippedLane {
                lane: LaneKind::L4Packet,
                reason: "lane not available on this build".into(),
            }]
        );
        assert_eq!(
            started.lanes.requested,
            vec![LaneKind::Http, LaneKind::L4Packet]
        );
    }

    /// The flip side of finding 1: when the l4 lane **is** available on this
    /// build, a profile that names it with no `target.l4` is still
    /// `invalid_profile` — the rule only moved from `profiles::validate` to the
    /// lanes that will run, so the refusal is reached before the job spawns.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_available_l4_lane_without_a_target_is_invalid_profile() {
        let h = Harness::new().with_lane(FakeLane::l4_packet());
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::L4Packet];
        assert!(profile.target.l4.is_empty(), "the profile has no l4 target");

        let err = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect_err("an available l4 lane with no target is refused");
        assert_eq!(code(&err), ScanErrorCode::InvalidProfile);
        assert!(
            err.to_string().contains("l4"),
            "the message names the l4 target rule: {err}"
        );
        assert_eq!(
            h.engine.registry.active_count(),
            0,
            "nothing spawned on the refusal"
        );
    }

    /// Spec D3: `scan.start` checks its refusals in one fixed order, so a
    /// caller that is wrong in two ways always learns the same reason first.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_checks_in_d3_order() {
        let h = Harness::new();
        h.bind();

        // Out of scope *and* only an unavailable lane: the lane wins.
        let mut profile = h.profile(&["http://elsewhere.test"]);
        profile.lanes = vec![LaneKind::Ws];
        assert_eq!(
            code(&crate::jobs::start(&h.engine, profile, agent(), false).unwrap_err()),
            ScanErrorCode::LaneUnavailable
        );

        // Out of scope and an agent without the flag: scope wins.
        let profile = h.profile(&["http://elsewhere.test"]);
        assert_eq!(
            code(&crate::jobs::start(&h.engine, profile, agent(), false).unwrap_err()),
            ScanErrorCode::OutOfScope
        );

        // In scope, agent, policy `auto`: refused_agent (AC T1-4).
        h.set_policy(AgentPolicy::Auto);
        let profile = h.profile(&["http://scan.test"]);
        assert_eq!(
            code(&crate::jobs::start(&h.engine, profile, agent(), false).unwrap_err()),
            ScanErrorCode::RefusedAgent
        );

        // Policy `all` but the config flag is off: still refused.
        h.set_policy(AgentPolicy::All);
        let profile = h.profile(&["http://scan.test"]);
        assert_eq!(
            code(&crate::jobs::start(&h.engine, profile, agent(), false).unwrap_err()),
            ScanErrorCode::RefusedAgent
        );

        // Flag on, but `intrusive` is operator-only.
        let h = Harness::new().with_agent_active();
        h.bind();
        h.set_policy(AgentPolicy::All);
        let mut profile = h.profile(&["http://scan.test"]);
        profile.intensity = Intensity::Intrusive;
        assert_eq!(
            code(&crate::jobs::start(&h.engine, profile, agent(), false).unwrap_err()),
            ScanErrorCode::RefusedAgent
        );

        // Flag on, `medium`: accepted.
        let profile = h.profile(&["http://scan.test"]);
        assert!(crate::jobs::start(&h.engine, profile, agent(), false).is_ok());
    }

    /// Spec D5: `max_jobs` and per-origin single flight are both `busy`.
    #[tokio::test(flavor = "multi_thread")]
    async fn busy_on_max_jobs_and_same_origin() {
        let h = Harness::new().with_blocking_check().with_max_jobs(1);
        h.bind();
        crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the first job starts");
        let err = crate::jobs::start(
            &h.engine,
            h.profile(&["http://other.test"]),
            operator(),
            false,
        )
        .expect_err("the second job is over max_jobs");
        assert!(err.to_string().starts_with("scan: busy:"), "{err}");
        h.cancel_all();

        let h = Harness::new().with_blocking_check().with_max_jobs(2);
        h.bind();
        crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the first job starts");
        let err = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect_err("the same origin is single-flight");
        assert_eq!(code(&err), ScanErrorCode::Busy);
        h.cancel_all();
    }

    /// AC T5-3 (spec D8.4): a lane refuses a profile it cannot run **before**
    /// the job is spawned, so the caller learns it from `scan.start` itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn lane_validate_refuses_before_spawn() {
        let h = Harness::new().with_lane(
            FakeLane::http().with_validate_error("plan names a pinned field `ipv4.src`"),
        );
        h.bind();

        let err = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect_err("the lane refuses the profile");

        assert_eq!(
            err.to_string(),
            "scan: invalid_profile: plan names a pinned field `ipv4.src`"
        );
        assert_eq!(h.engine.registry.active_count(), 0);
        assert_eq!(h.client.calls(), 0);
    }

    /// Spec D5: `session` is present only in observed-session mode, and the
    /// probe budget on the status is the profile's.
    #[tokio::test(flavor = "multi_thread")]
    async fn status_carries_the_budget_and_the_session_slot() {
        let h = Harness::new();
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            false,
        )
        .expect("the job starts");
        assert_eq!(started.status.probes.budget, 2000);
        assert!(started.status.session.is_some());

        let mut profile = h.profile(&["http://other.test"]);
        profile.session.mode = SessionMode::None;
        let started = crate::jobs::start(&h.engine, profile, operator(), false)
            .expect("a second origin is free");
        assert!(started.status.session.is_none());
    }

    /// Security review (2026-11-01): the L4 and agent refusals live in one
    /// function so the verb layer refuses with exactly the same code and
    /// sentence `scan.start` would.
    #[tokio::test(flavor = "multi_thread")]
    async fn agent_gate_is_the_one_place_an_agent_is_refused() {
        use crate::jobs::agent_gate;

        let h = Harness::new();
        h.bind();
        let profile = h.profile(&["http://scan.test"]);

        // An operator is never gated.
        h.set_policy(AgentPolicy::Auto);
        assert!(agent_gate(&h.engine, &operator(), &profile, false).is_ok());

        // `auto` refuses an agent's `scan.start`; `scan.map` is a `Write` verb
        // that sends no probe, so it is exempt (AC T1-4, orchestrator ruling
        // 2026-11-01).
        let err = agent_gate(&h.engine, &agent(), &profile, false).unwrap_err();
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);
        assert!(err.to_string().contains("agent.set"), "{err}");
        assert!(
            agent_gate(&h.engine, &agent(), &profile, true).is_ok(),
            "an agent's map job is admitted under `auto`"
        );

        // Under `all` the flag decides, and a map job is exempt from it.
        h.set_policy(AgentPolicy::All);
        assert_eq!(
            code(&agent_gate(&h.engine, &agent(), &profile, false).unwrap_err()),
            ScanErrorCode::RefusedAgent
        );
        assert!(agent_gate(&h.engine, &agent(), &profile, true).is_ok());

        // Even an `intrusive` request from an agent maps: `scan.start` forces
        // the map shape to `passive`, so the bar cannot apply to it.
        let mut intrusive_map = h.profile(&["http://scan.test"]);
        intrusive_map.intensity = Intensity::Intrusive;
        assert!(agent_gate(&h.engine, &agent(), &intrusive_map, true).is_ok());

        // With the flag, `intrusive` is still operator-only.
        let h = Harness::new().with_agent_active();
        h.bind();
        h.set_policy(AgentPolicy::All);
        let mut intrusive = h.profile(&["http://scan.test"]);
        intrusive.intensity = Intensity::Intrusive;
        let err = agent_gate(&h.engine, &agent(), &intrusive, false).unwrap_err();
        assert_eq!(code(&err), ScanErrorCode::RefusedAgent);
        assert!(err.to_string().contains("operator-only"), "{err}");
        assert!(agent_gate(&h.engine, &operator(), &intrusive, false).is_ok());

        // An L4 lane with the layer disabled is `refused_l4`, for anyone.
        let mut l4 = h.profile(&["http://scan.test"]);
        l4.lanes = vec![LaneKind::L4Packet];
        for caller in [operator(), agent()] {
            let err = agent_gate(&h.engine, &caller, &l4, false).unwrap_err();
            assert_eq!(code(&err), ScanErrorCode::RefusedL4);
            assert!(err.to_string().contains("l4 layer is disabled"), "{err}");
        }
    }

    /// Orchestrator ruling (2026-11-01): a map job is exempt from the agent
    /// gate under `auto`, but it is still an agent's job. The worker's policy
    /// re-check (spec D5) applies to it unchanged: when the operator pauses
    /// the agent mid-map, the job stops with `stopped_reason: policy`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_map_job_started_under_auto_still_stops_when_the_operator_pauses() {
        let h = Harness::new()
            .with_lane(FakeLane::http().with_check(FakeCheck::passive("fake.passive", "demo")));
        h.bind();
        h.set_policy(AgentPolicy::Auto);
        h.flip_policy_after(1, AgentPolicy::Paused);

        let started =
            crate::jobs::start(&h.engine, h.profile(&["http://scan.test"]), agent(), true)
                .expect("an agent's map job is admitted under `auto`");
        let status = h.wait_terminal(&started.job).await;
        assert_eq!(status.state, aitm_scan_model::JobState::Cancelled);
        assert_eq!(
            status.stopped_reason,
            Some(aitm_scan_model::StoppedReason::Policy)
        );
        assert_eq!(status.started_by.frontend, "mcp");
    }

    /// Security review (2026-11-01): a `time_s` or `check_timeout_s` near
    /// `u64::MAX` reaches `Instant + Duration`, which panics on overflow. The
    /// worker builds every deadline through this bound instead.
    #[test]
    fn a_far_future_deadline_cannot_overflow_an_instant() {
        use crate::jobs::bounded_secs;

        assert_eq!(bounded_secs(60), std::time::Duration::from_secs(60));
        let capped = bounded_secs(u64::MAX);
        assert!(capped < std::time::Duration::from_secs(60 * 60 * 24 * 8));
        assert!(
            std::time::Instant::now().checked_add(capped).is_some(),
            "the bounded duration still lands on a representable Instant"
        );
    }

    /// The registry's terminal signal is what every "wait for the end" reads:
    /// `false` while a job runs, flipped exactly once by `finish` after the
    /// terminal status is written, `true` at once for a job that is already
    /// over (a reloaded record included), and a waiter parked on `changed()`
    /// wakes on the flip. No clock anywhere.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_signal_flips_once_on_finish_and_reads_true_for_finished_jobs() {
        let registry = crate::jobs::JobRegistry::new(10);
        let (tx, _) = tokio::sync::watch::channel(false);
        let status = Arc::new(std::sync::RwLock::new(aitm_scan_model::JobStatus {
            job: "scan-0000beef".to_string(),
            state: aitm_scan_model::JobState::Running,
            ..aitm_scan_model::JobStatus::default()
        }));
        assert!(registry.try_insert(crate::jobs::JobEntry {
            status: Arc::clone(&status),
            cancel: tokio_util::sync::CancellationToken::new(),
            confine: None,
            started_by: Default::default(),
            discovery: Arc::new(std::sync::RwLock::new(Default::default())),
            origins: Vec::new(),
            is_agent: false,
            terminal: tx,
        }));
        assert!(
            registry.terminal_signal("scan-nope").is_none(),
            "unknown job: no signal"
        );
        let mut rx = registry
            .terminal_signal("scan-0000beef")
            .expect("a known job has a signal");
        assert!(!*rx.borrow(), "a running job reads false");

        // A waiter parked on the signal wakes when `finish` flips it, and
        // reads a terminal status when it does.
        let (parked_tx, parked_rx) = tokio::sync::oneshot::channel::<()>();
        let waiter = {
            let registry_status = Arc::clone(&status);
            let mut rx = rx.clone();
            tokio::spawn(async move {
                let mut parked = Some(parked_tx);
                while !*rx.borrow_and_update() {
                    // Tell the test we are about to park, so `finish` below is
                    // guaranteed to be the wake-up and not a value read first.
                    if let Some(tx) = parked.take() {
                        let _ = tx.send(());
                    }
                    rx.changed().await.expect("sender alive");
                }
                registry_status.read().unwrap().state
            })
        };
        parked_rx.await.expect("the waiter reports before parking");
        {
            let mut guarded = status.write().unwrap();
            guarded.state = aitm_scan_model::JobState::Done;
            guarded.finished_at = Some(1);
        }
        registry.finish("scan-0000beef");
        assert_eq!(
            waiter.await.expect("waiter"),
            aitm_scan_model::JobState::Done
        );
        assert!(
            *rx.borrow_and_update(),
            "after finish the signal reads true"
        );

        // Flipping again is a no-op for readers: the value is already true.
        registry.finish("scan-0000beef");
        assert!(*rx.borrow(), "idempotent");

        // A job inserted already terminal starts true (what load_history does).
        let (tx2, _) = tokio::sync::watch::channel(true);
        assert!(registry.try_insert(crate::jobs::JobEntry {
            status: Arc::new(std::sync::RwLock::new(aitm_scan_model::JobStatus {
                job: "scan-0000dead".to_string(),
                state: aitm_scan_model::JobState::Failed,
                finished_at: Some(2),
                ..aitm_scan_model::JobStatus::default()
            })),
            cancel: tokio_util::sync::CancellationToken::new(),
            confine: None,
            started_by: Default::default(),
            discovery: Arc::new(std::sync::RwLock::new(Default::default())),
            origins: Vec::new(),
            is_agent: false,
            terminal: tx2,
        }));
        let done = crate::jobs::test_support::wait_terminal(&registry, "scan-0000dead").await;
        assert_eq!(
            done.state,
            aitm_scan_model::JobState::Failed,
            "resolves at once for a finished job"
        );
    }

    /// The registry surface `scan.sitemap`, `scan.cancel` and the worker read:
    /// the handles of one job, the newest job for an origin, and a history
    /// that never evicts a live job however small `history` is.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_registry_hands_out_handles_prunes_and_finds_by_target() {
        use crate::jobs::JobRegistry;
        use aitm_scan_model::{JobState, JobStatus};

        let registry = JobRegistry::new(1);
        let mut live = None;
        for (at, origin, state) in [
            (10u64, "http://a.test", JobState::Done),
            (20, "http://a.test", JobState::Done),
            (30, "http://b.test", JobState::Running),
        ] {
            let job = format!("scan-{at:08x}");
            assert!(registry.try_insert(crate::jobs::JobEntry {
                status: Arc::new(std::sync::RwLock::new(JobStatus {
                    job: job.clone(),
                    state,
                    started_at: at,
                    finished_at: state.is_terminal().then_some(at + 1),
                    targets: vec![origin.to_string()],
                    ..JobStatus::default()
                })),
                cancel: tokio_util::sync::CancellationToken::new(),
                confine: None,
                started_by: Default::default(),
                discovery: Arc::new(std::sync::RwLock::new(Default::default())),
                origins: vec![origin.to_string()],
                is_agent: false,
                terminal: tokio::sync::watch::channel(state.is_terminal()).0,
            }));
            if !state.is_terminal() {
                live = Some(job);
            }
        }

        // `history: 1` keeps the newest finished job and never the live one.
        registry.finish("scan-0000000a");
        let listed: Vec<String> = registry
            .list(false, 10)
            .into_iter()
            .map(|s| s.job)
            .collect();
        assert_eq!(
            listed,
            vec!["scan-0000001e".to_string(), "scan-00000014".to_string()],
            "newest first, the oldest finished job pruned"
        );
        let live = live.expect("a running job");
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.list(true, 10).len(), 1);
        assert!(registry.status(&live).is_some());

        // Both `a.test` jobs ran; the newest wins.
        assert_eq!(
            registry.newest_for_target("http://a.test"),
            Some("scan-00000014".to_string())
        );
        assert_eq!(registry.newest_for_target("http://nowhere.test"), None);
        // Of all three, the newest is the live `b.test` job.
        assert_eq!(registry.newest(), Some("scan-0000001e".to_string()));
        assert_eq!(crate::jobs::JobRegistry::new(1).newest(), None);

        // The handles are the entry's own, and cancelling through the registry
        // is what the worker observes.
        let handles = registry
            .entry_handles(&live)
            .expect("the live job has handles");
        let (status, cancel, discovery) = (handles.status, handles.cancel, handles.discovery);
        assert!(!cancel.is_cancelled());
        assert!(discovery.read().expect("discovery").points.is_empty());
        registry.cancel(&live);
        assert!(cancel.is_cancelled());
        assert_eq!(
            status.read().expect("status").state,
            JobState::Cancelling,
            "the handle sees the cancel the registry recorded"
        );

        // A colliding id never displaces the job already admitted.
        assert!(
            !registry.try_insert(crate::jobs::JobEntry {
                status: Arc::new(std::sync::RwLock::new(JobStatus {
                    job: live.clone(),
                    profile_name: "impostor".to_string(),
                    ..JobStatus::default()
                })),
                cancel: tokio_util::sync::CancellationToken::new(),
                confine: None,
                started_by: Default::default(),
                discovery: Arc::new(std::sync::RwLock::new(Default::default())),
                origins: Vec::new(),
                is_agent: false,
                terminal: tokio::sync::watch::channel(false).0,
            }),
            "a colliding id is refused, not silently dropped"
        );
        assert_ne!(
            registry.status(&live).expect("still held").profile_name,
            "impostor"
        );
    }

    /// `scan.map` forces the passive, HTTP-only shape (spec D3).
    #[tokio::test(flavor = "multi_thread")]
    async fn force_map_pins_http_and_passive() {
        let h = Harness::new();
        h.bind();

        let mut profile = h.profile(&["http://scan.test"]);
        profile.lanes = vec![LaneKind::Http, LaneKind::Ws];
        profile.intensity = Intensity::Intrusive;
        let started =
            crate::jobs::start(&h.engine, profile, operator(), true).expect("a map job starts");

        assert_eq!(started.lanes.requested, vec![LaneKind::Http]);
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        assert!(started.lanes.skipped.is_empty());
    }

    /// Panel fix (2026-11-01): the start-time scope check must ask the guard
    /// about the SAME `host:port` the request-time guard sees. A ported entry
    /// (`127.0.0.1:8080`, what every real e2e cell seeds) admits the origin on
    /// that port and refuses another port; stripping the port made the entry
    /// admit nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_ported_scope_entry_admits_the_matching_origin_and_refuses_another_port() {
        let h = Harness::new();
        h.bind();
        h.guard.add_scope(aitm_core::ScopeEntry {
            host: "127.0.0.1:8080".into(),
        });

        let err = crate::jobs::start(
            &h.engine,
            h.profile(&["http://127.0.0.1:8081"]),
            operator(),
            true,
        )
        .expect_err("another port is not the scoped one");
        assert_eq!(code(&err), ScanErrorCode::OutOfScope);
        assert!(err.to_string().starts_with("scan: out_of_scope: "), "{err}");

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://127.0.0.1:8080"]),
            operator(),
            true,
        )
        .expect("the ported entry admits the origin on that port");
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        h.cancel_all();
    }

    /// A portless entry still covers every port of its host (the
    /// `Authority::matches_scope_entry` rule), so the fix is not a tightening.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_portless_entry_still_admits_any_port() {
        let h = Harness::new();
        h.bind();

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test:9000"]),
            operator(),
            true,
        )
        .expect("`scan.test` covers every port");
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        h.cancel_all();
    }

    /// An origin that elides its port is checked on the scheme default, so an
    /// explicit `secure.test:443` entry admits `https://secure.test`.
    #[tokio::test(flavor = "multi_thread")]
    async fn https_default_port_matches_a_443_entry() {
        let h = Harness::new();
        h.bind();
        h.guard.add_scope(aitm_core::ScopeEntry {
            host: "secure.test:443".into(),
        });

        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["https://secure.test"]),
            operator(),
            true,
        )
        .expect("the 443 entry admits the default-port https origin");
        assert_eq!(started.lanes.run, vec![LaneKind::Http]);
        h.cancel_all();
    }

    /// Spec D5 "monotonic from `started_at`" (T9 live run, 2026-11-01): a job
    /// that is still running reports the wall time since `started_at` from
    /// every registry reader — `status`, `list` and the status `cancel`
    /// returns — while a finished job keeps the value its terminal transition
    /// fixed.
    #[test]
    fn a_running_job_reports_live_elapsed_ms() {
        use aitm_scan_model::{JobState, JobStatus};
        let registry = crate::jobs::JobRegistry::new(4);
        let now = crate::util::now_ms();
        let entry =
            |job: &str, state: JobState, started_at: u64, elapsed_ms: u64| crate::jobs::JobEntry {
                status: Arc::new(std::sync::RwLock::new(JobStatus {
                    job: job.to_string(),
                    state,
                    started_at,
                    finished_at: state.is_terminal().then_some(started_at + elapsed_ms),
                    elapsed_ms,
                    targets: vec!["http://a.test".to_string()],
                    ..JobStatus::default()
                })),
                cancel: tokio_util::sync::CancellationToken::new(),
                confine: None,
                started_by: Default::default(),
                discovery: Arc::new(std::sync::RwLock::new(Default::default())),
                origins: vec!["http://a.test".to_string()],
                is_agent: false,
                terminal: tokio::sync::watch::channel(state.is_terminal()).0,
            };
        assert!(registry.try_insert(entry(
            "scan-11111111",
            JobState::Running,
            now.saturating_sub(5_000),
            0
        )));
        assert!(registry.try_insert(entry(
            "scan-22222222",
            JobState::Done,
            now.saturating_sub(60_000),
            42
        )));

        let live = registry.status("scan-11111111").expect("the live job");
        assert_eq!(live.finished_at, None);
        assert!(
            live.elapsed_ms >= 5_000,
            "status is live: {}",
            live.elapsed_ms
        );

        let listed = registry.list(false, 10);
        let by_job = |job: &str| {
            listed
                .iter()
                .find(|s| s.job == job)
                .unwrap_or_else(|| panic!("{job} is listed"))
                .elapsed_ms
        };
        assert!(
            by_job("scan-11111111") >= 5_000,
            "list agrees: {}",
            by_job("scan-11111111")
        );
        assert_eq!(
            by_job("scan-22222222"),
            42,
            "a finished job keeps its fixed elapsed"
        );

        let cancelled = registry.cancel("scan-11111111").expect("the live job");
        assert_eq!(cancelled.state, JobState::Cancelling);
        assert!(
            cancelled.elapsed_ms >= 5_000,
            "cancel's returned status is live too: {}",
            cancelled.elapsed_ms
        );
        assert_eq!(
            registry
                .status("scan-22222222")
                .expect("the done job")
                .elapsed_ms,
            42
        );
    }

    /// Security review (delta ca852f71..e6bd03bc, 2026-11-01): a map crawl
    /// under agent `auto` admission does not submit a form that looks like it
    /// changes something that matters. The `/account/delete` form is skipped
    /// and counted in `crawl.forms_skipped`; the `/comments` form beside it is
    /// submitted as before. `max_depth: 1` parses the seed page only, so the
    /// count is one page's worth.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_destructive_looking_form_is_skipped_and_counted() {
        const PAGE: &str = "<html><body>\
             <form action=\"/account/delete\" method=\"post\"><input name=\"id\" value=\"7\"></form>\
             <form action=\"/comments\" method=\"post\"><input name=\"comment\"></form>\
             </body></html>";

        let h = Harness::bare().with_page(PAGE);
        h.bind();
        let mut profile = h.profile(&["http://scan.test"]);
        profile.crawl.max_depth = 1;
        let started =
            crate::jobs::start(&h.engine, profile, operator(), true).expect("a map job starts");
        let status = h.wait_terminal(&started.job).await;

        assert_eq!(
            h.client.trail(),
            vec!["GET /", "POST /comments"],
            "the delete form is never submitted; the comments form is"
        );
        assert_eq!(status.crawl.forms_skipped, 1, "{:?}", status.crawl);
        assert_eq!(status.crawl.errors, 0);
    }

    /// Coordinator decision (2026-11-01, spec D8.1): a `scan.map` crawl submits
    /// forms with inert generated values exactly like a scan's crawl does, because
    /// form filling is how the crawl reaches routes and finds points; "map-only"
    /// forces lanes and intensity, never `crawl.submit_forms`. The map job's
    /// restraint is the absence of probes (`force_map_pins_http_and_passive`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_map_job_submits_forms_like_any_crawl() {
        const PAGE: &str = "<html><body><a href=\"/about\">about</a>\
             <form action=\"/comments\" method=\"post\"><input name=\"comment\"></form>\
             </body></html>";

        let h = Harness::bare().with_page(PAGE);
        h.bind();
        let started = crate::jobs::start(
            &h.engine,
            h.profile(&["http://scan.test"]),
            operator(),
            true,
        )
        .expect("a map job starts");
        h.wait_terminal(&started.job).await;
        assert_eq!(
            h.client.trail(),
            vec!["GET /", "GET /about", "POST /comments"],
            "a scan.map crawl follows the links and submits the form, like a scan's crawl"
        );
    }

    /// One persisted record under `<dir>/scan/jobs/<job>.json`.
    fn write_record(dir: &std::path::Path, file_stem: &str, status: aitm_scan_model::JobStatus) {
        let jobs_dir = crate::util::scan_dir(dir, "jobs");
        std::fs::create_dir_all(&jobs_dir).expect("the jobs dir is creatable");
        let record = crate::jobs::PersistedJob {
            status,
            issues: Vec::new(),
        };
        std::fs::write(
            jobs_dir.join(format!("{file_stem}.json")),
            serde_json::to_vec(&record).expect("the record serializes"),
        )
        .expect("the record is written");
    }

    /// Security review (whole branch, 2026-11-01): a record on disk is data,
    /// not truth. Its id must be a job id (`scan-<8 hex>`) and must name the
    /// file it sits in; anything else is skipped and the rest of the history
    /// still loads.
    #[test]
    fn history_refuses_a_record_whose_id_disagrees_with_its_file() {
        use aitm_scan_model::{JobState, JobStatus};
        let scratch = ScratchDir::new();
        let done = |job: &str| JobStatus {
            job: job.to_string(),
            state: JobState::Done,
            started_at: 10,
            finished_at: Some(11),
            ..JobStatus::default()
        };
        write_record(scratch.path(), "scan-0000abcd", done("scan-deadbeef"));
        write_record(scratch.path(), "scan-ZZZZZZZZ", done("scan-ZZZZZZZZ"));
        write_record(scratch.path(), "scan-00000001", done("scan-00000001"));

        let registry = crate::jobs::JobRegistry::new(50);
        assert_eq!(
            registry
                .load_history(scratch.path())
                .expect("history loads"),
            1,
            "only the record whose id is a job id and names its own file"
        );
        assert!(registry.status("scan-deadbeef").is_none());
        assert!(registry.status("scan-0000abcd").is_none());
        assert!(registry.status("scan-ZZZZZZZZ").is_none());
        assert!(registry.status("scan-00000001").is_some());
    }

    /// Security review (whole branch, 2026-11-01): a reloaded record cannot
    /// be running — nothing is running it — so a non-terminal `state` on disk
    /// becomes `failed` on load. Otherwise it would hold a `max_jobs` slot and
    /// its origin's single flight forever, with no worker to ever release it
    /// and a pre-cancelled token nothing can act on (spec D5 anti-goal: a job
    /// that outlives its cancellation).
    #[test]
    fn a_reloaded_running_record_becomes_failed_and_frees_the_origin() {
        use aitm_scan_model::{JobState, JobStatus, Phase, StoppedReason};
        let scratch = ScratchDir::new();
        write_record(
            scratch.path(),
            "scan-00000002",
            JobStatus {
                job: "scan-00000002".to_string(),
                state: JobState::Running,
                phase: Phase::Auditing,
                targets: vec!["http://scan.test".to_string()],
                started_at: 10,
                ..JobStatus::default()
            },
        );

        let registry = crate::jobs::JobRegistry::new(50);
        assert_eq!(
            registry
                .load_history(scratch.path())
                .expect("history loads"),
            1
        );
        let status = registry
            .status("scan-00000002")
            .expect("the record was reloaded");
        assert_eq!(status.state, JobState::Failed);
        assert_eq!(status.phase, Phase::Done);
        assert_eq!(status.stopped_reason, Some(StoppedReason::Failed));
        assert_eq!(
            status.error.as_deref(),
            Some("reloaded a non-terminal job record")
        );
        assert!(status.finished_at.is_some(), "a terminal record has an end");
        // A reloaded record is already over: its terminal signal reads `true`
        // at once, so a waiter never parks on it.
        assert!(
            *registry
                .terminal_signal("scan-00000002")
                .expect("the reloaded job has a signal")
                .borrow(),
            "a reloaded record starts terminal"
        );
        assert_eq!(registry.active_count(), 0, "it holds no max_jobs slot");
        assert!(
            registry.active_origins().is_empty(),
            "and its origin is not busy"
        );
        assert!(registry.list(true, 10).is_empty());
    }

    /// Security review (whole branch, 2026-11-01): the `max_jobs` check and
    /// the insert are one critical section. Eight callers released together
    /// against eight distinct origins admit exactly `max_jobs` jobs; the rest
    /// are `busy`. With the check and the insert under separate locks, two
    /// callers could both see a free slot and both take it.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_starts_cannot_exceed_max_jobs() {
        const MAX_JOBS: u32 = 2;
        const STARTERS: usize = 8;
        const ROUNDS: usize = 10;

        let h = Harness::new().with_blocking_check().with_max_jobs(MAX_JOBS);
        for i in 0..STARTERS {
            h.guard.add_scope(aitm_core::ScopeEntry {
                host: format!("o{i}.test"),
            });
        }
        h.bind();

        for round in 0..ROUNDS {
            let barrier = std::sync::Barrier::new(STARTERS);
            let results: Vec<anyhow::Result<aitm_scan_model::StartResult>> =
                std::thread::scope(|scope| {
                    let starters: Vec<_> = (0..STARTERS)
                        .map(|i| {
                            let engine = &h.engine;
                            let barrier = &barrier;
                            let profile = h.profile(&[&format!("http://o{i}.test")]);
                            scope.spawn(move || {
                                barrier.wait();
                                crate::jobs::start(engine, profile, operator(), false)
                            })
                        })
                        .collect();
                    starters
                        .into_iter()
                        .map(|t| t.join().expect("a starter thread finishes"))
                        .collect()
                });

            let admitted: Vec<String> = results
                .iter()
                .filter_map(|r| r.as_ref().ok())
                .map(|started| started.job.clone())
                .collect();
            let busy = results
                .iter()
                .filter(|r| {
                    r.as_ref()
                        .err()
                        .is_some_and(|e| code(e) == ScanErrorCode::Busy)
                })
                .count();
            assert_eq!(
                admitted.len(),
                MAX_JOBS as usize,
                "round {round}: {} jobs admitted over max_jobs {MAX_JOBS}",
                admitted.len()
            );
            assert_eq!(busy, STARTERS - MAX_JOBS as usize, "round {round}");

            h.cancel_all();
            for job in &admitted {
                h.wait_terminal(job).await;
            }
        }
    }
}
