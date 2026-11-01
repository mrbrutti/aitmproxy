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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use aitm_core::{
    AgentPolicy, BrowserDriver, ConfinementToken, EgressConfinement, FlowStore, Frontend,
    ProxyClient, ScopeRateGuard,
};
use aitm_scan_model::{
    scan_error, Check, CheckRegistry, Clamped, Discovery, Intensity, JobId, JobState, JobStatus,
    JobSummary, L4TargetSpec, L4Transport, Lane, LaneKind, LaneReport, Phase, ProbeCounters,
    ScanErrorCode, ScanProfile, SessionMode, SessionStatus, SkippedLane, StartResult, StartedBy,
};
use tokio::task::JoinHandle;
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
    /// The worker, dropped when the job finishes.
    pub task: Option<JoinHandle<()>>,
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
}

impl std::fmt::Debug for JobEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobEntry")
            .field("origins", &self.origins)
            .field("is_agent", &self.is_agent)
            .field("running", &self.task.is_some())
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

    /// Admit `entry`, keyed by the job id on its status.
    ///
    /// An id the registry already holds is **not** overwritten: a live job's
    /// handles are never dropped on the floor by a colliding mint. [`start`]
    /// mints through [`JobRegistry::try_insert`] and re-mints instead.
    pub fn insert(&self, entry: JobEntry) {
        let _ = self.try_insert(entry);
    }

    /// Admit `entry` only if its id is free. Returns `false` (and gives the
    /// entry back to the drop) when the id is taken.
    fn try_insert(&self, entry: JobEntry) -> bool {
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

    /// A snapshot of one job's status.
    pub fn status(&self, id: &str) -> Option<JobStatus> {
        self.lock()
            .get(id)
            .map(|e| e.status.read().unwrap_or_else(|p| p.into_inner()).clone())
    }

    /// The three handles the worker needs to drive one job.
    pub fn entry_handles(&self, id: &str) -> Option<JobHandles> {
        self.lock().get(id).map(|e| {
            (
                Arc::clone(&e.status),
                e.cancel.clone(),
                Arc::clone(&e.discovery),
            )
        })
    }

    /// Job summaries, newest `started_at` first, at most `limit`.
    pub fn list(&self, active_only: bool, limit: usize) -> Vec<JobSummary> {
        let inner = self.lock();
        let mut rows: Vec<JobStatus> = inner
            .values()
            .map(|e| e.status.read().unwrap_or_else(|p| p.into_inner()).clone())
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
        Some(status.clone())
    }

    /// How many jobs are not yet terminal.
    pub fn active_count(&self) -> usize {
        self.lock()
            .values()
            .filter(|e| {
                !e.status
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .state
                    .is_terminal()
            })
            .count()
    }

    /// The origins a non-terminal job is already running against.
    pub fn active_origins(&self) -> HashSet<String> {
        self.lock()
            .values()
            .filter(|e| {
                !e.status
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .state
                    .is_terminal()
            })
            .flat_map(|e| e.origins.iter().cloned())
            .collect()
    }

    /// Release a finished job's live handles and prune the history.
    ///
    /// The confinement token drops here, so the egress hold ends with the job;
    /// the status stays so `scan.status` and `scan.list` can still answer.
    pub fn finish(&self, id: &str) {
        let mut inner = self.lock();
        if let Some(entry) = inner.get_mut(id) {
            entry.confine = None;
            entry.task = None;
        }
        prune(&mut inner, self.history);
    }

    /// Read `<findings_dir>/scan/jobs/*.json` back into finished entries.
    ///
    /// Returns how many jobs were added. A job the registry already holds is
    /// left alone (the live one is the truth), and a file that does not parse
    /// is skipped rather than failing the load: one corrupt record must not
    /// hide the rest of an operator's history.
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
            let Ok(record) = serde_json::from_str::<PersistedJob>(&text) else {
                continue;
            };
            if record.status.job.is_empty() || self.holds(&record.status.job) {
                continue;
            }
            let started_by = record.status.started_by.clone();
            let origins = record.status.targets.clone();
            let is_agent = !frontend_of_token(&started_by.frontend).is_trusted_control();
            if self.try_insert(JobEntry {
                status: Arc::new(RwLock::new(record.status)),
                // A reloaded job is already over; the token is pre-cancelled so
                // nothing can mistake it for something still worth stopping.
                cancel: cancelled_token(),
                task: None,
                confine: None,
                started_by,
                discovery: Arc::new(RwLock::new(Discovery::default())),
                origins,
                is_agent,
            }) {
                added += 1;
            }
        }
        let mut inner = self.lock();
        prune(&mut inner, self.history);
        Ok(added)
    }

    /// The newest job that ran against `origin`, for `scan.sitemap { target }`.
    pub fn newest_for_target(&self, origin: &str) -> Option<JobId> {
        let inner = self.lock();
        let mut rows: Vec<(u64, JobId)> = inner
            .values()
            .filter(|e| e.origins.iter().any(|o| o == origin))
            .map(|e| {
                let status = e.status.read().unwrap_or_else(|p| p.into_inner());
                (status.started_at, status.job.clone())
            })
            .collect();
        rows.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        rows.into_iter().next().map(|(_, job)| job)
    }
}

/// What one job's live handles are, as [`JobRegistry::entry_handles`] hands
/// them out: the status every verb reads, the token `scan.cancel` sets, and
/// the discovery `scan.sitemap` pages.
pub type JobHandles = (
    Arc<RwLock<JobStatus>>,
    CancellationToken,
    Arc<RwLock<Discovery>>,
);

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
            frontend: frontend_token(self.frontend).to_string(),
            client_label: self.client_label.clone(),
        }
    }
}

/// The lowercase wire name of a frontend (T1a Task 6).
fn frontend_token(frontend: Frontend) -> &'static str {
    match frontend {
        Frontend::Cli => "cli",
        Frontend::Mcp => "mcp",
        Frontend::Operator => "operator",
        // `Frontend` is `#[non_exhaustive]`: a frontend this build does not
        // know is treated as the gated posture, never as a trusted control.
        _ => "mcp",
    }
}

/// The frontend a `started_by` token names, for a job reloaded from disk.
/// An unknown token is the gated posture, so the agent-ness of a reloaded job
/// is still decided by `Frontend::is_trusted_control`, never by a string.
fn frontend_of_token(token: &str) -> Frontend {
    match token {
        "cli" => Frontend::Cli,
        "operator" => Frontend::Operator,
        _ => Frontend::Mcp,
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
/// Every refusal is checked in spec D3's order — lane availability, then the
/// check selection, then scope, then the L4 gate, then the agent gate, then
/// concurrency — so a caller that is wrong in two ways always learns the same
/// reason first. Nothing sends: by the time this returns, the job exists, is
/// `queued`, and the worker owns it.
pub fn start(
    engine: &Arc<Engine>,
    mut profile: ScanProfile,
    caller: Caller,
    force_map: bool,
) -> anyhow::Result<StartResult> {
    let services = engine.late.get()?;

    // (1) `scan.map` is the passive, HTTP-only shape: it crawls and reads, and
    // sends no probe, so it is a `Write` verb rather than a `Sensitive` one.
    if force_map {
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

    // (3) Lane availability. A profile with one available lane runs.
    let (run, lanes) = engine.resolve_lanes(&profile.lanes);
    if run.is_empty() {
        let names = profile
            .lanes
            .iter()
            .map(lane_token)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(scan_error(
            ScanErrorCode::LaneUnavailable,
            format!("no requested lane is available on this build: {names}"),
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
        let host = host_of(&normalized);
        if !services.guard.in_scope(&host) {
            return Err(scan_error(
                ScanErrorCode::OutOfScope,
                format!("{normalized} is not in the HTTP scope"),
            ));
        }
        origins.push(normalized);
    }
    let l4_requested = profile
        .lanes
        .iter()
        .any(|lane| matches!(lane, LaneKind::L4Packet | LaneKind::L4Stream));
    if let Some(guard) = &services.l4 {
        for target in &profile.target.l4 {
            check_l4_target(guard.as_ref(), target)?;
        }
    }

    // (5) and (6): the L4 layer gate and the agent gate, in one place so the
    // verb layer (Task 15) refuses with exactly the same words.
    agent_gate(engine, &caller, &profile, force_map)?;

    // (7) Concurrency: the job ceiling and per-origin single flight.
    if engine.registry.active_count() >= engine.cfg.max_jobs as usize {
        return Err(scan_error(
            ScanErrorCode::Busy,
            format!("{} scan jobs are already running", engine.cfg.max_jobs),
        ));
    }
    let active = engine.registry.active_origins();
    if let Some(origin) = origins.iter().find(|o| active.contains(*o)) {
        return Err(scan_error(
            ScanErrorCode::Busy,
            format!("a scan is already running against {origin}"),
        ));
    }

    // (8) Admit the job. The confinement token lives on the entry and drops
    // with it, so a job can never leave the egress posture held.
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
        l4: l4_requested.then(Default::default),
        session: (profile.session.mode == SessionMode::Observed).then(SessionStatus::default),
        ..JobStatus::default()
    };

    let cancel = CancellationToken::new();
    let discovery = Arc::new(RwLock::new(Discovery::default()));
    let status = Arc::new(RwLock::new(status));
    let mut confine = confine;
    let mut admitted = None;
    for _ in 0..MAX_ID_ATTEMPTS {
        let candidate = util::job_id();
        status.write().unwrap_or_else(|e| e.into_inner()).job = candidate.clone();
        if engine.registry.try_insert(JobEntry {
            status: Arc::clone(&status),
            cancel: cancel.clone(),
            task: None,
            confine: confine.take(),
            started_by: started_by.clone(),
            discovery: Arc::clone(&discovery),
            origins: origins.clone(),
            is_agent: caller.is_agent(),
        }) {
            admitted = Some(candidate);
            break;
        }
    }
    let Some(job) = admitted else {
        // Not a verb refusal: no D3 code describes "the random source keeps
        // repeating itself".
        anyhow::bail!("job registry: no free job id after {MAX_ID_ATTEMPTS} attempts");
    };

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
    let engine_for_worker = Arc::clone(engine);
    let handle = services
        .rt
        .spawn(async move { crate::worker::run_job(engine_for_worker, ctx).await });
    if let Some(entry) = engine.registry.lock().get_mut(&job) {
        entry.task = Some(handle);
    }

    let snapshot = status.read().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(StartResult {
        job,
        status: snapshot,
        clamped,
        lanes,
        dry_run: l4_requested.then_some(profile.l4.dry_run),
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

/// The host of a normalized `scheme://host[:port]` origin.
fn host_of(origin: &str) -> String {
    origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or_else(|| origin.split_once("://").map(|(_, r)| r).unwrap_or(origin))
        .to_string()
}

/// The wire token of a lane, for the `lane_unavailable` message.
fn lane_token(lane: &LaneKind) -> String {
    serde_json::to_value(lane)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{lane:?}"))
}

/// A duration that never overflows an `Instant`.
pub(crate) fn bounded_secs(seconds: u64) -> Duration {
    Duration::from_secs(seconds.min(60 * 60 * 24 * 7))
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
    }

    impl StubClient {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU64::new(0),
                last_call_ms: AtomicU64::new(0),
                seen: Mutex::new(Vec::new()),
            })
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
                self.last_call_ms
                    .store(crate::util::now_ms(), Ordering::SeqCst);
                Ok(stub_flow(req))
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
    }

    impl FakeRun {
        pub(crate) fn clean() -> Self {
            Self {
                outcome: Outcome::Clean,
                probes: 1,
                payload: PROBE_PAYLOAD,
            }
        }

        pub(crate) fn vulnerable() -> Self {
            Self {
                outcome: Outcome::Vulnerable,
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
                let mut out = verdict(run.outcome, "fake check");
                out.poc_hint = self.hint.clone();
                let mut rest = self.locations.iter();
                if let Some(first) = rest.next() {
                    out.location = Some(aitm_scan_model::VerdictLocation {
                        path: Some(first.clone()),
                        name: None,
                    });
                    out.more = rest
                        .map(|path| {
                            let mut sibling = verdict(run.outcome, "fake check");
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
        fn new() -> Self {
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

        /// Poll `registry.status(job)` until it is terminal, or give up.
        pub(crate) async fn wait_terminal(
            &self,
            job: &str,
            within: std::time::Duration,
        ) -> aitm_scan_model::JobStatus {
            let deadline = Instant::now() + within;
            loop {
                let status = self
                    .engine
                    .registry
                    .status(job)
                    .unwrap_or_else(|| panic!("job {job} is in the registry"));
                if status.state.is_terminal() {
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "job {job} is still {:?}/{:?} after {within:?}",
                    status.state,
                    status.phase
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
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

    use aitm_core::{AgentPolicy, Frontend};
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
        let status = h
            .wait_terminal(&started.job, std::time::Duration::from_secs(5))
            .await;
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
            registry.insert(crate::jobs::JobEntry {
                status: Arc::new(std::sync::RwLock::new(JobStatus {
                    job: job.clone(),
                    state,
                    started_at: at,
                    finished_at: state.is_terminal().then_some(at + 1),
                    targets: vec![origin.to_string()],
                    ..JobStatus::default()
                })),
                cancel: tokio_util::sync::CancellationToken::new(),
                task: None,
                confine: None,
                started_by: Default::default(),
                discovery: Arc::new(std::sync::RwLock::new(Default::default())),
                origins: vec![origin.to_string()],
                is_agent: false,
            });
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

        // The handles are the entry's own, and cancelling through the registry
        // is what the worker observes.
        let (status, cancel, discovery) = registry
            .entry_handles(&live)
            .expect("the live job has handles");
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
        registry.insert(crate::jobs::JobEntry {
            status: Arc::new(std::sync::RwLock::new(JobStatus {
                job: live.clone(),
                profile_name: "impostor".to_string(),
                ..JobStatus::default()
            })),
            cancel: tokio_util::sync::CancellationToken::new(),
            task: None,
            confine: None,
            started_by: Default::default(),
            discovery: Arc::new(std::sync::RwLock::new(Default::default())),
            origins: Vec::new(),
            is_agent: false,
        });
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
}
