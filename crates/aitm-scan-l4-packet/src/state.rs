//! Per-job lane state: plans, minted point ids, counters, ceilings, the
//! consecutive-timeout stop ladder, retirement and the point-run cache —
//! owned by scanner v2 track T5, plan task 8.
//!
//! This module is **pure bookkeeping**: it opens no handle, sends nothing and
//! never blocks on I/O. [`LaneState`] is the one place the lane counts what it
//! did for a job, so the counters it hands back are exactly spec D5's
//! `L4Counters { cases, crashes, liveness_failures, retired_elements }` and the
//! ceilings it enforces are spec D8.4's non-overridable ones ("cases per job
//! <= 5000").
//!
//! No engine hook tells a lane when a job ends, so the state remembers at most
//! [`MAX_JOBS_REMEMBERED`] jobs and evicts the oldest (plan call C2).
//!
//! Counters are monotonic and an unknown job id is inert: every reader answers
//! `None` and every writer is a no-op, so a forged or stale job id can neither
//! read another job's totals nor move them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use aitm_scan_model::check::L4Evidence;
use aitm_scan_model::job::L4Counters;
use aitm_scan_model::traits::JobCtx;

use crate::fields::FieldPath;
use crate::oracle::CaseClass;
use crate::plan::TargetPlan;

/// The hard ceiling on cases per job (spec D8.4 "cases per job <= 5000", D11).
/// A profile asking for more is clamped to this; nothing lifts it.
pub const CASES_CEILING: u32 = 5000;

/// How many jobs the lane's state remembers before evicting the oldest.
pub const MAX_JOBS_REMEMBERED: usize = 8;

/// Take a lock without panicking on a poisoned mutex: the state behind it is
/// plain counters, so a panic elsewhere must not take the lane down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why the lane stopped sending for a job.
///
/// Once set, the reason sticks: the first stop wins, so a later stop cannot
/// rewrite why the job's cases ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The stop ladder tripped: `n` silent cases in a row (spec D8.4, "the
    /// lane stops after `consecutive_timeouts` silent cases").
    ConsecutiveTimeouts(u32),
    /// The job's stimulus budget is spent.
    Budget,
    /// The job's deadline passed.
    Deadline,
    /// The operator cancelled the job.
    Cancelled,
    /// The `L4Guard` refused, with its message.
    GuardRefused(String),
    /// L4 is unavailable (no backend, no privilege), with its message.
    Unavailable(String),
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConsecutiveTimeouts(n) => {
                write!(f, "consecutive_timeouts: {n} silent cases in a row")
            }
            Self::Budget => write!(f, "budget exhausted"),
            Self::Deadline => write!(f, "job deadline passed"),
            Self::Cancelled => write!(f, "job cancelled"),
            Self::GuardRefused(m) => write!(f, "guard refused: {m}"),
            Self::Unavailable(m) => write!(f, "l4 unavailable: {m}"),
        }
    }
}

/// One fuzz case as the lane recorded it. `Debug` prints `sent_hex` as a byte
/// count, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CaseRecord {
    /// The case's index within its point's run, from `0`.
    pub index: u32,
    /// The seed the case was mutated from, carried into `L4Evidence.seed_id`.
    pub seed_id: String,
    /// The mutators applied, in order.
    pub chain: Vec<String>,
    /// The frame that was sent (or would have been, in a dry run), hex-encoded.
    pub sent_hex: String,
    /// How the oracle read the reaction, `None` for a case that never went out.
    pub class: Option<CaseClass>,
    /// Whether the case was actually sent.
    pub sent: bool,
    /// The round trip in milliseconds, `0` for an unsent case.
    pub elapsed_ms: u32,
    /// Whether the round trip was a latency outlier.
    pub latency_outlier: bool,
    /// The two liveness probes a crash candidate spent, `(immediate, retry)`.
    pub liveness: Option<(bool, bool)>,
}

impl fmt::Debug for CaseRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaseRecord")
            .field("index", &self.index)
            .field("seed_id", &self.seed_id)
            .field("chain", &self.chain)
            .field(
                "sent_hex",
                &format_args!("<{} bytes>", self.sent_hex.len() / 2),
            )
            .field("class", &self.class)
            .field("sent", &self.sent)
            .field("elapsed_ms", &self.elapsed_ms)
            .field("latency_outlier", &self.latency_outlier)
            .field("liveness", &self.liveness)
            .finish()
    }
}

/// The crash one point's run found: the case that did it and its evidence.
///
/// `recovered == false` means the target never answered a liveness probe again
/// within the recovery bound — a persistent outage, the strongest evidence
/// there is (task 9). `Debug` prints the evidence's hex as a byte count.
#[derive(Clone, PartialEq, Eq)]
pub struct CrashRecord {
    /// The index of the case that crashed the target.
    pub case_index: u32,
    /// Whether the target ever answered a liveness probe again.
    pub recovered: bool,
    /// The shared-vocabulary evidence the issue carries.
    pub evidence: L4Evidence,
}

impl fmt::Debug for CrashRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrashRecord")
            .field("case_index", &self.case_index)
            .field("recovered", &self.recovered)
            .field("seed_id", &self.evidence.seed_id)
            .field(
                "sent_hex",
                &format_args!("<{} bytes>", self.evidence.sent_hex.len() / 2),
            )
            .field("oracle", &self.evidence.oracle)
            .field("reproduced", &self.evidence.reproduced)
            .finish()
    }
}

/// One point's whole fuzz run: what was sent, how the target reacted, and why
/// the run ended. `Debug` summarises the cases as a count.
#[derive(Clone, PartialEq, Eq)]
pub struct PointRun {
    /// The insertion point this run belongs to.
    pub point_id: String,
    /// The target key, `"<ip>:<port>/<proto>"`.
    pub target: String,
    /// The field the run mutated.
    pub field: FieldPath,
    /// The seed the run's PRNG was derived from, so it replays exactly.
    pub rng_seed: u64,
    /// Whether the run only rendered cases instead of sending them.
    pub dry_run: bool,
    /// How long the run waits for a silent target to come back before it calls
    /// the outage persistent.
    pub recovery_wait: Duration,
    /// How the unmutated seed read, the yardstick every case is judged against.
    pub baseline: Option<CaseClass>,
    /// The cases, in order.
    pub cases: Vec<CaseRecord>,
    /// The crash this run found, if any.
    pub crash: Option<CrashRecord>,
    /// Why the run ended early, if it did.
    pub stopped: Option<StopReason>,
}

impl fmt::Debug for PointRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PointRun")
            .field("point_id", &self.point_id)
            .field("target", &self.target)
            .field("field", &self.field)
            .field("rng_seed", &self.rng_seed)
            .field("dry_run", &self.dry_run)
            .field("recovery_wait", &self.recovery_wait)
            .field("baseline", &self.baseline)
            .field("cases", &format_args!("<{} cases>", self.cases.len()))
            .field("crash", &self.crash)
            .field("stopped", &self.stopped)
            .finish()
    }
}

impl PointRun {
    /// The protocol reactions this run saw — the [`CaseClass::Icmp`] and
    /// [`CaseClass::Reset`] classes with their counts, in first-seen order.
    ///
    /// A reaction is not a crash: the target answered, so it is alive. Task 10
    /// turns each entry into one `info` issue.
    #[must_use]
    pub fn reactions(&self) -> Vec<(CaseClass, u32)> {
        let mut seen: Vec<(CaseClass, u32)> = Vec::new();
        for class in self.cases.iter().filter_map(|case| case.class) {
            if !matches!(class, CaseClass::Icmp { .. } | CaseClass::Reset) {
                continue;
            }
            if let Some(entry) = seen.iter_mut().find(|(seen, _)| *seen == class) {
                entry.1 += 1;
            } else {
                seen.push((class, 1));
            }
        }
        seen
    }

    /// How many of the run's cases actually went out on the wire.
    #[must_use]
    pub fn sent_count(&self) -> u32 {
        u32::try_from(self.cases.iter().filter(|case| case.sent).count()).unwrap_or(u32::MAX)
    }

    /// How many of the run's cases came back outside the latency window.
    #[must_use]
    pub fn outlier_count(&self) -> u32 {
        u32::try_from(
            self.cases
                .iter()
                .filter(|case| case.latency_outlier)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }
}

/// Everything the lane counted for one job: spec D5's `L4Counters` plus the
/// lane-local totals the status line and the stop ladder read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobStats {
    /// The counters that travel to `JobStatus.l4` (spec D5).
    pub l4: L4Counters,
    /// Cases that could not be sent (an undecodable crafted frame), which are
    /// never charged and never counted as cases.
    pub cases_unsendable: u64,
    /// How often the lane waited on the guard's injection rate limit.
    pub rate_waits: u64,
    /// How many sent cases were silent, in total.
    pub timeouts: u64,
    /// How many sent cases were silent in a row, right now.
    pub consecutive_timeouts: u32,
    /// How many insertion points the job minted.
    pub points: u32,
    /// The job's case ceiling, already clamped to [`CASES_CEILING`].
    pub cases_cap: u32,
    /// Why the lane stopped sending for this job, if it did.
    pub stopped: Option<StopReason>,
}

/// One job's state. Private: everything outside reaches it through
/// [`LaneState`], which keeps the locking in one place.
struct JobState {
    plans: Vec<TargetPlan>,
    point_ids: HashSet<String>,
    retired: HashSet<String>,
    runs: HashMap<String, Arc<PointRun>>,
    dry_run: bool,
    /// How many silent cases in a row trip the ladder. A configured `0` is
    /// read as `1` (stop on the first silent case) rather than as "never
    /// stop", so the ladder can never be configured away.
    threshold: u32,
    stats: JobStats,
}

impl JobState {
    fn new(
        plans: Vec<TargetPlan>,
        point_ids: Vec<String>,
        cases_requested: u32,
        consecutive_timeouts: u32,
        dry_run: bool,
    ) -> Self {
        let points = u32::try_from(point_ids.len()).unwrap_or(u32::MAX);
        Self {
            plans,
            point_ids: point_ids.into_iter().collect(),
            retired: HashSet::new(),
            runs: HashMap::new(),
            dry_run,
            threshold: consecutive_timeouts,
            stats: JobStats {
                points,
                cases_cap: cases_requested.min(CASES_CEILING),
                ..JobStats::default()
            },
        }
    }

    /// Set the stop reason unless one is already set (first stop wins).
    fn mark_stopped(&mut self, reason: StopReason) {
        if self.stats.stopped.is_none() {
            self.stats.stopped = Some(reason);
        }
    }
}

/// The lane's per-job bookkeeping, shared by every runner and check of every
/// job the lane is serving.
#[derive(Default)]
pub struct LaneState {
    inner: Mutex<Inner>,
}

/// The jobs and the order they were begun in, so the oldest evicts first.
#[derive(Default)]
struct Inner {
    jobs: HashMap<String, JobState>,
    order: VecDeque<String>,
}

impl fmt::Debug for LaneState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = lock(&self.inner);
        f.debug_struct("LaneState")
            .field("jobs", &inner.order)
            .finish()
    }
}

impl LaneState {
    /// Empty state, remembering no job yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read one job's state, or `None` when the job is unknown.
    fn with_job<R>(&self, job_id: &str, f: impl FnOnce(&JobState) -> R) -> Option<R> {
        lock(&self.inner).jobs.get(job_id).map(f)
    }

    /// Change one job's state. An unknown job is a no-op.
    fn with_job_mut<R>(&self, job_id: &str, f: impl FnOnce(&mut JobState) -> R) -> Option<R> {
        lock(&self.inner).jobs.get_mut(job_id).map(f)
    }

    /// Start (or restart) a job: its plans, its minted points, its clamped
    /// case ceiling and its stop-ladder threshold.
    ///
    /// `cases_cap` is `min(cases_requested, CASES_CEILING)`. Re-beginning a
    /// known job replaces its state; beginning a ninth job evicts the oldest.
    pub fn begin_job(
        &self,
        job_id: &str,
        plans: Vec<TargetPlan>,
        point_ids: Vec<String>,
        cases_requested: u32,
        consecutive_timeouts: u32,
        dry_run: bool,
    ) {
        let state = JobState::new(
            plans,
            point_ids,
            cases_requested,
            consecutive_timeouts,
            dry_run,
        );
        let mut inner = lock(&self.inner);
        if inner.jobs.insert(job_id.to_string(), state).is_none() {
            inner.order.push_back(job_id.to_string());
        }
        while inner.order.len() > MAX_JOBS_REMEMBERED {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.jobs.remove(&oldest);
        }
    }

    /// The job's target plans.
    #[must_use]
    pub fn plans(&self, job_id: &str) -> Option<Vec<TargetPlan>> {
        self.with_job(job_id, |job| job.plans.clone())
    }

    /// Whether the job minted this insertion point. A point it did not mint is
    /// not this lane's to fuzz.
    #[must_use]
    pub fn point_known(&self, job_id: &str, point_id: &str) -> bool {
        self.with_job(job_id, |job| job.point_ids.contains(point_id))
            .unwrap_or(false)
    }

    /// Whether the job renders cases instead of sending them.
    #[must_use]
    pub fn dry_run(&self, job_id: &str) -> Option<bool> {
        self.with_job(job_id, |job| job.dry_run)
    }

    /// How many cases the next point may send: the job's even share of the
    /// ceiling, never more than the ceiling has left.
    #[must_use]
    pub fn allocate_cases(&self, job_id: &str) -> Option<u32> {
        self.with_job(job_id, |job| {
            let share = job.stats.cases_cap.div_ceil(job.stats.points.max(1));
            let sent = u32::try_from(job.stats.l4.cases).unwrap_or(u32::MAX);
            share.min(job.stats.cases_cap.saturating_sub(sent))
        })
    }

    /// Record one case's outcome.
    ///
    /// A sent case counts as a case; a silent one also advances the stop
    /// ladder, any other class resets it. An unsendable case is counted apart
    /// and never touches the ladder.
    ///
    /// # Errors
    /// [`StopReason::ConsecutiveTimeouts`] once the ladder trips — the case is
    /// still counted, so the tripping case is never lost.
    pub fn record_case(
        &self,
        job_id: &str,
        class: CaseClass,
        sent: bool,
    ) -> Result<(), StopReason> {
        let tripped = self.with_job_mut(job_id, |job| {
            if !sent {
                job.stats.cases_unsendable += 1;
                return None;
            }
            job.stats.l4.cases += 1;
            if class == CaseClass::Silence {
                job.stats.timeouts += 1;
                job.stats.consecutive_timeouts += 1;
                if job.stats.consecutive_timeouts >= job.threshold.max(1) {
                    let reason = StopReason::ConsecutiveTimeouts(job.stats.consecutive_timeouts);
                    job.mark_stopped(reason.clone());
                    return Some(reason);
                }
            } else {
                job.stats.consecutive_timeouts = 0;
            }
            None
        });
        match tripped.flatten() {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Record one liveness probe's verdict.
    pub fn record_liveness(&self, job_id: &str, passed: bool) {
        if passed {
            return;
        }
        self.with_job_mut(job_id, |job| job.stats.l4.liveness_failures += 1);
    }

    /// Record one wait on the guard's injection rate limit.
    pub fn record_rate_wait(&self, job_id: &str) {
        self.with_job_mut(job_id, |job| job.stats.rate_waits += 1);
    }

    /// Record a crash on a point and retire it: no further case is sent
    /// against a target the lane already took down (spec D8.4).
    pub fn record_crash(&self, job_id: &str, point_id: &str) {
        self.with_job_mut(job_id, |job| {
            job.stats.l4.crashes += 1;
            job.stats.l4.retired_elements += 1;
            job.retired.insert(point_id.to_string());
        });
    }

    /// Whether this point is retired.
    #[must_use]
    pub fn is_retired(&self, job_id: &str, point_id: &str) -> bool {
        self.with_job(job_id, |job| job.retired.contains(point_id))
            .unwrap_or(false)
    }

    /// Stop the job's sending, with a reason. The first reason wins.
    pub fn mark_stopped(&self, job_id: &str, reason: StopReason) {
        self.with_job_mut(job_id, |job| job.mark_stopped(reason));
    }

    /// Why the job stopped sending, if it did.
    #[must_use]
    pub fn stopped(&self, job_id: &str) -> Option<StopReason> {
        self.with_job(job_id, |job| job.stats.stopped.clone())
            .flatten()
    }

    /// Cache one point's finished run, so both checks read the same one.
    pub fn set_run(&self, job_id: &str, point_id: &str, run: Arc<PointRun>) {
        self.with_job_mut(job_id, |job| {
            job.runs.insert(point_id.to_string(), run);
        });
    }

    /// The cached run for one point, if it has already been driven.
    #[must_use]
    pub fn run(&self, job_id: &str, point_id: &str) -> Option<Arc<PointRun>> {
        self.with_job(job_id, |job| job.runs.get(point_id).map(Arc::clone))
            .flatten()
    }

    /// The job's spec D5 counters.
    #[must_use]
    pub fn counters(&self, job_id: &str) -> Option<L4Counters> {
        self.with_job(job_id, |job| job.stats.l4)
    }

    /// Everything the lane counted for the job.
    #[must_use]
    pub fn stats(&self, job_id: &str) -> Option<JobStats> {
        self.with_job(job_id, |job| job.stats.clone())
    }
}

/// Hand the job's L4 counters back to the engine — the **only** place the lane
/// reports them (plan call C1b).
///
/// T1b adds a default-bodied `JobCtx::report_l4(&self, counters: L4Counters)`;
/// Task 13 flips this body to `job.report_l4(counters)` once `origin/main`
/// carries it. Until then the lane's counters still reach the operator through
/// `PacketLane::counters(job_id)`, which stays either way.
// Task 9 (`host.rs`) is the first caller: its runner reports after every point
// run and whenever it marks the job stopped.
#[allow(dead_code)]
pub(crate) fn report_counters(job: &dyn JobCtx, counters: L4Counters) {
    let _ = (job, counters);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use aitm_scan_model::job::L4Counters;
    use aitm_scan_model::profile::ScanProfile;
    use aitm_scan_model::vocab::L4Transport;

    use super::*;
    use crate::fields::FieldPath;
    use crate::oracle::CaseClass;
    use crate::plan::{LinkFraming, ResolvedTarget, SeedOrigin, SeedPayload, TargetPlan};
    use crate::testing::TestJob;

    /// One hand-built target plan: UDP `127.0.0.1:9` on loopback, the raw
    /// payload field, one default seed.
    fn plan_fixture() -> TargetPlan {
        TargetPlan {
            target: ResolvedTarget {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 9,
                proto: L4Transport::Udp,
                interface: "lo0".to_string(),
                framing: LinkFraming::Null,
                local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                scope_entry: "l4-loopback".to_string(),
            },
            fields: vec![FieldPath::Raw],
            seeds: vec![SeedPayload {
                id: "127.0.0.1:9/udp#0".to_string(),
                bytes: vec![0xde, 0xad, 0xbe, 0xef],
                origin: SeedOrigin::Default,
            }],
            src_port: 40000,
        }
    }

    /// `n` point ids, `p0..p{n-1}`.
    fn points(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("p{i}")).collect()
    }

    /// One recorded case with `class`, sent and in time.
    fn case(index: u32, class: CaseClass) -> CaseRecord {
        CaseRecord {
            index,
            seed_id: "127.0.0.1:9/udp#0".to_string(),
            chain: vec!["grow:8".to_string()],
            sent_hex: "deadbeef".to_string(),
            class: Some(class),
            sent: true,
            elapsed_ms: 1,
            latency_outlier: false,
            liveness: None,
        }
    }

    #[test]
    fn cases_cap_is_min_of_profile_and_ceiling() {
        let state = LaneState::new();

        state.begin_job("scan-big", vec![plan_fixture()], points(1), 9000, 20, false);
        assert_eq!(
            state.stats("scan-big").expect("the job is known").cases_cap,
            5000
        );

        state.begin_job(
            "scan-small",
            vec![plan_fixture()],
            points(1),
            500,
            20,
            false,
        );
        assert_eq!(
            state
                .stats("scan-small")
                .expect("the job is known")
                .cases_cap,
            500
        );
    }

    #[test]
    fn allocation_is_ceil_and_bounded() {
        let state = LaneState::new();
        state.begin_job("scan-a", vec![plan_fixture()], points(14), 100, 20, false);

        assert_eq!(state.allocate_cases("scan-a"), Some(8));

        for _ in 0..96 {
            assert_eq!(state.record_case("scan-a", CaseClass::Clean, true), Ok(()));
        }
        assert_eq!(state.allocate_cases("scan-a"), Some(4));

        for _ in 0..4 {
            assert_eq!(state.record_case("scan-a", CaseClass::Clean, true), Ok(()));
        }
        assert_eq!(state.allocate_cases("scan-a"), Some(0));
    }

    #[test]
    fn consecutive_timeouts_stop() {
        let state = LaneState::new();
        state.begin_job("scan-t", vec![plan_fixture()], points(1), 100, 3, false);

        assert_eq!(
            state.record_case("scan-t", CaseClass::Silence, true),
            Ok(())
        );
        assert_eq!(
            state.record_case("scan-t", CaseClass::Silence, true),
            Ok(())
        );
        assert_eq!(
            state.record_case("scan-t", CaseClass::Silence, true),
            Err(StopReason::ConsecutiveTimeouts(3))
        );

        let stopped = state.stopped("scan-t").expect("the job stopped");
        assert_eq!(stopped, StopReason::ConsecutiveTimeouts(3));
        assert!(
            stopped.to_string().contains("consecutive_timeouts"),
            "{stopped}"
        );
        assert_eq!(
            stopped.to_string(),
            "consecutive_timeouts: 3 silent cases in a row"
        );

        // A clean case after two silent ones resets the ladder.
        state.begin_job("scan-r", vec![plan_fixture()], points(1), 100, 3, false);
        assert_eq!(
            state.record_case("scan-r", CaseClass::Silence, true),
            Ok(())
        );
        assert_eq!(
            state.record_case("scan-r", CaseClass::Silence, true),
            Ok(())
        );
        assert_eq!(state.record_case("scan-r", CaseClass::Clean, true), Ok(()));
        let stats = state.stats("scan-r").expect("the job is known");
        assert_eq!(stats.consecutive_timeouts, 0);
        assert_eq!(stats.timeouts, 2);
        assert_eq!(stats.stopped, None);
    }

    #[test]
    fn unsendable_counts_separately() {
        let state = LaneState::new();
        state.begin_job("scan-u", vec![plan_fixture()], points(1), 100, 3, false);

        assert_eq!(
            state.record_case("scan-u", CaseClass::Silence, false),
            Ok(())
        );

        let stats = state.stats("scan-u").expect("the job is known");
        assert_eq!(stats.l4.cases, 0);
        assert_eq!(stats.cases_unsendable, 1);
        assert_eq!(stats.consecutive_timeouts, 0);
        assert_eq!(stats.timeouts, 0);
    }

    #[test]
    fn crash_retires_point() {
        let state = LaneState::new();
        state.begin_job("scan-c", vec![plan_fixture()], points(2), 100, 20, false);

        for _ in 0..5 {
            assert_eq!(state.record_case("scan-c", CaseClass::Clean, true), Ok(()));
        }
        state.record_liveness("scan-c", false);
        state.record_liveness("scan-c", false);
        state.record_liveness("scan-c", true);
        state.record_crash("scan-c", "p0");

        assert_eq!(
            state.counters("scan-c"),
            Some(L4Counters {
                cases: 5,
                crashes: 1,
                liveness_failures: 2,
                retired_elements: 1,
            })
        );
        assert!(state.is_retired("scan-c", "p0"));
        assert!(!state.is_retired("scan-c", "p1"));
    }

    #[test]
    fn unknown_job_is_none() {
        let state = LaneState::new();
        state.begin_job(
            "scan-known",
            vec![plan_fixture()],
            points(1),
            100,
            20,
            false,
        );

        assert_eq!(state.counters("scan-nope"), None);
        assert_eq!(state.allocate_cases("scan-nope"), None);
        assert_eq!(state.stats("scan-nope"), None);
        assert_eq!(state.plans("scan-nope"), None);
        assert_eq!(state.dry_run("scan-nope"), None);
        assert_eq!(state.stopped("scan-nope"), None);
        assert!(!state.point_known("scan-nope", "p0"));
        assert!(!state.is_retired("scan-nope", "p0"));

        assert_eq!(
            state.record_case("scan-nope", CaseClass::Silence, true),
            Ok(())
        );
        state.record_liveness("scan-nope", false);
        state.record_rate_wait("scan-nope");
        state.record_crash("scan-nope", "p0");
        state.mark_stopped("scan-nope", StopReason::Budget);

        assert_eq!(state.counters("scan-nope"), None);
        assert_eq!(
            state.counters("scan-known"),
            Some(L4Counters::default()),
            "the unknown job's records touched no other job"
        );
    }

    #[test]
    fn oldest_job_evicted_past_eight() {
        let state = LaneState::new();
        for i in 1..=9 {
            state.begin_job(
                &format!("j{i}"),
                vec![plan_fixture()],
                points(1),
                100,
                20,
                false,
            );
        }

        assert_eq!(state.counters("j1"), None);
        assert!(state.counters("j2").is_some());
        assert!(state.counters("j9").is_some());
    }

    #[test]
    fn point_run_reactions_in_first_seen_order() {
        let run = PointRun {
            point_id: "l4:127.0.0.1:9/udp/raw".to_string(),
            target: "127.0.0.1:9/udp".to_string(),
            field: FieldPath::Raw,
            rng_seed: 7,
            dry_run: false,
            recovery_wait: Duration::from_secs(10),
            baseline: Some(CaseClass::Clean),
            cases: vec![
                case(
                    0,
                    CaseClass::Icmp {
                        icmp_type: 3,
                        code: 3,
                    },
                ),
                case(1, CaseClass::Clean),
                case(
                    2,
                    CaseClass::Icmp {
                        icmp_type: 3,
                        code: 3,
                    },
                ),
                case(3, CaseClass::Reset),
            ],
            crash: None,
            stopped: None,
        };

        assert_eq!(
            run.reactions(),
            vec![
                (
                    CaseClass::Icmp {
                        icmp_type: 3,
                        code: 3
                    },
                    2
                ),
                (CaseClass::Reset, 1),
            ]
        );
        assert_eq!(run.sent_count(), 4);
        assert_eq!(run.outlier_count(), 0);
    }

    #[test]
    fn debug_hides_hex() {
        let printed = format!("{:?}", case(0, CaseClass::Clean));
        assert!(!printed.contains("deadbeef"), "{printed}");
        assert!(printed.contains("4 bytes"), "{printed}");
    }

    #[test]
    fn run_cache_round_trip() {
        let state = LaneState::new();
        state.begin_job("scan-run", vec![plan_fixture()], points(1), 100, 20, false);

        let run = Arc::new(PointRun {
            point_id: "p0".to_string(),
            target: "127.0.0.1:9/udp".to_string(),
            field: FieldPath::Raw,
            rng_seed: 1,
            dry_run: false,
            recovery_wait: Duration::from_secs(10),
            baseline: None,
            cases: Vec::new(),
            crash: None,
            stopped: None,
        });
        state.set_run("scan-run", "p0", Arc::clone(&run));

        let got = state.run("scan-run", "p0").expect("the run is cached");
        assert!(Arc::ptr_eq(&run, &got));
        assert!(state.run("scan-run", "p1").is_none());
        assert!(state.run("scan-nope", "p0").is_none());
    }

    #[test]
    fn report_counters_shim_is_a_no_op() {
        let job = TestJob::new(ScanProfile::default());
        report_counters(&*job, L4Counters::default());
        assert_eq!(job.charged(), 0);
    }
}
