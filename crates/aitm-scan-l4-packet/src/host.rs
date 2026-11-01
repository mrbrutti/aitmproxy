//! The shared lane context, the per-point runner and the `ProbeHost` the engine
//! hands to a check — owned by scanner v2 track T5, plan task 9.
//!
//! This is the only module of the lane that sends. Every stimulus is one
//! [`aitm_proto_l4::sendrecv::send_recv`] call, which mints an `Inject` and a
//! `Capture` permit and spends one rate token per packet at the wire choke
//! point: the lane never injects directly and never varies the pinned
//! destination (spec D8.4 "Transport"). `send_recv` blocks a thread, so every
//! call goes through [`tokio::task::spawn_blocking`].
//!
//! One [`PointRunner`] owns one point's whole fuzz run: baseline, cases,
//! liveness oracle and the bounded reproduce-then-retire crash triage. The run
//! is idempotent — both checks of spec D8.4 read the same cached
//! [`PointRun`] through the [`RunnerRegistry`], so whichever check reaches a
//! point first drives the cases and the other sends nothing.
//!
//! Budget and pacing (spec D5): the baseline, every case and every liveness
//! probe is charged one stimulus; a guard rate refusal is waited out and
//! retried without a second charge, because the refused case never reached the
//! wire. Cases are counted apart from probes ([`crate::state::LaneState`]), so
//! `L4Counters.cases` is exactly the mutated sends, replays included (call
//! C10).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aitm_proto_l4::backend::{CaptureInjectBackend, L4Error};
use aitm_proto_l4::craft::{Layer, PacketSpec};
use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::{L4Guard, L4GuardError};
use aitm_proto_l4::icmp::transport_payload;
use aitm_proto_l4::sendrecv::{send_recv, SendRecvOutcome};
use aitm_scan_model::{
    InsertionPoint, JobCtx, L4Evidence, L4Oracle, L4Reply, Payload, ProbeHost, ProbeResponse,
    RawProbe, ScanProfile, MAX_MATCH_BODY,
};
use futures::future::BoxFuture;

use crate::codec::hex_encode;
use crate::fields::FieldPath;
use crate::mutate::{boundary_cases, random_case, Mutation, DEFAULT_MAX_RAW_BYTES};
use crate::oracle::{classify, liveness_passes, CaseClass, LatencyWindow};
use crate::plan::{is_decodable, send_recv_spec, SeedSpec, TargetPlan};
use crate::rng::{derive_seed, Rng};
use crate::state::{report_counters, CaseRecord, CrashRecord, LaneState, PointRun, StopReason};

/// How long one case waits for its reply (spec D8.4's reply window).
pub const CASE_REPLY_WINDOW: Duration = Duration::from_millis(500);

/// How long a silent target is given to come back before the outage is called
/// persistent (plan call C27).
pub const RECOVERY_WAIT: Duration = Duration::from_secs(10);

/// Take a lock without panicking on a poisoned mutex: the state behind it is a
/// cached class and a runner table, so a panic elsewhere must not take the lane
/// down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Every wait and ceiling the fuzz loop obeys. Set by the lane (plan call C3),
/// never by a profile; tests shrink it so a run costs milliseconds.
///
/// The recovery bound is expressed as a poll count rather than a duration so a
/// test counts injects exactly: `recovery_polls * recovery_poll` is
/// [`RECOVERY_WAIT`] at the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long a case waits for its reply.
    pub reply_window: Duration,
    /// How long after a failed liveness probe the second one is sent.
    pub liveness_retry: Duration,
    /// How far apart two reproduction replays are spaced.
    pub replay_spacing: Duration,
    /// How long between two recovery polls of a silent target.
    pub recovery_poll: Duration,
    /// How many recovery polls a replay waits before calling the outage
    /// persistent.
    pub recovery_polls: u32,
    /// The ceiling on a mutated payload, in bytes.
    pub max_raw_bytes: usize,
    /// How many cases a dry run renders.
    pub dry_run_cases: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            reply_window: CASE_REPLY_WINDOW,
            liveness_retry: Duration::from_millis(500),
            replay_spacing: Duration::from_secs(1),
            recovery_poll: Duration::from_secs(1),
            recovery_polls: 10,
            max_raw_bytes: DEFAULT_MAX_RAW_BYTES,
            dry_run_cases: 50,
        }
    }
}

impl Timing {
    /// How long a silent target is given to come back, in total.
    #[must_use]
    pub fn recovery_wait(&self) -> Duration {
        self.recovery_poll.saturating_mul(self.recovery_polls)
    }
}

/// Everything every runner of the lane shares: the guard that admits a
/// stimulus, the backend that puts it on the wire, the lane-private case store
/// (call C8), the operator's store for seeds only, the timings and the per-job
/// bookkeeping.
pub struct Shared {
    /// The deny-by-default L4 guard; every send is checked against it.
    pub guard: Arc<L4Guard>,
    /// The capture/inject backend.
    pub backend: Arc<dyn CaptureInjectBackend>,
    /// The lane's own bounded store: 5000 cases never evict real captures.
    pub case_store: Arc<dyn L4FlowStore>,
    /// The operator's store, read for seeds and never written by the lane.
    pub seed_store: Option<Arc<dyn L4FlowStore>>,
    /// The lane's waits and ceilings.
    pub timing: Timing,
    /// Per-job plans, counters, stop ladder and run cache.
    pub state: Arc<LaneState>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("timing", &self.timing)
            .field("seed_store", &self.seed_store.is_some())
            .field("state", &self.state)
            .finish()
    }
}

/// Why a send did not happen, or did not finish the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The lane stopped sending for this job; the reason is the ladder's.
    Stopped(StopReason),
    /// The case could not be crafted or written to the wire.
    Craft(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped(reason) => write!(f, "{reason}"),
            Self::Craft(message) => write!(f, "cannot craft the case: {message}"),
        }
    }
}

// Deliberately not `std::error::Error`: anyhow's blanket `From<E: Error>` would
// collide with the conversion the `ProbeHost` impl needs.
impl From<HostError> for anyhow::Error {
    fn from(err: HostError) -> Self {
        Self::msg(err.to_string())
    }
}

/// One stimulus as it went out and came back. `Debug` prints the reply as a
/// byte count, never its contents.
pub struct Sent {
    /// The case record, ready to be logged on the point's run.
    pub record: CaseRecord,
    /// The reply's transport payload, or the whole frame when it carries none
    /// (an ICMP error); empty on silence.
    pub reply: Vec<u8>,
}

impl fmt::Debug for Sent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sent")
            .field("record", &self.record)
            .field("reply", &format_args!("<{} bytes>", self.reply.len()))
            .finish()
    }
}

/// Whether a stimulus counts as one of the job's cases. The baseline and every
/// liveness probe are charged to the budget but are not cases (call C10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Counted {
    /// A mutated case, including a reproduction replay.
    Case,
    /// The baseline or a liveness probe.
    Probe,
}

/// A delivered stimulus plus the stop the ladder raised *after* it was
/// recorded, so the tripping case is still logged by the caller.
struct Delivery {
    sent: Sent,
    stop: Option<StopReason>,
}

/// What the bounded reproduction attempt found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Triage {
    /// Whether the target ever answered a liveness probe again.
    recovered: bool,
    /// How many replays were attempted.
    attempts: u32,
    /// How many of them reproduced the silence.
    reproduced: u32,
    /// The stop that ended the triage early, if one did.
    stop: Option<StopReason>,
}

/// One point's fuzz run: the seed, the cases, the oracle and the triage.
///
/// Built by `Lane::probe_host_for` and registered in the [`RunnerRegistry`], so
/// the crash check and the reaction check share one run.
pub struct PointRunner {
    shared: Arc<Shared>,
    job: Arc<dyn JobCtx>,
    point: InsertionPoint,
    plan: TargetPlan,
    field: FieldPath,
    rng_seed: u64,
    baseline: Mutex<Option<CaseClass>>,
    run: tokio::sync::Mutex<Option<Arc<PointRun>>>,
}

impl fmt::Debug for PointRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PointRunner")
            .field("point_id", &self.point.id)
            .field("target", &self.plan.key())
            .field("field", &self.field)
            .field("rng_seed", &self.rng_seed)
            .field("baseline", &*lock(&self.baseline))
            .finish()
    }
}

impl PointRunner {
    /// A runner for one `(point, field)` of one job. The point's PRNG seed is
    /// derived from the job marker and the point id, so the run replays.
    #[must_use]
    pub fn new(
        shared: Arc<Shared>,
        job: Arc<dyn JobCtx>,
        point: InsertionPoint,
        plan: TargetPlan,
        field: FieldPath,
    ) -> Self {
        let rng_seed = derive_seed(&job.marker(), &point.id);
        Self {
            shared,
            job,
            point,
            plan,
            field,
            rng_seed,
            baseline: Mutex::new(None),
            run: tokio::sync::Mutex::new(None),
        }
    }

    /// The insertion point this runner fuzzes.
    #[must_use]
    pub fn point(&self) -> &InsertionPoint {
        &self.point
    }

    /// The job the runner sends for.
    #[must_use]
    pub fn job(&self) -> &Arc<dyn JobCtx> {
        &self.job
    }

    /// The point's PRNG seed, recorded in every piece of evidence.
    #[must_use]
    pub fn rng_seed(&self) -> u64 {
        self.rng_seed
    }

    /// The scope entry that authorised this point's target.
    ///
    /// Task 10's reaction check records it in `L4Evidence.scope_entry`; a
    /// crash carries its own copy in [`crate::state::CrashRecord`], but a
    /// reaction has no record of its own to read it from.
    #[must_use]
    pub fn scope_entry(&self) -> &str {
        &self.plan.target.scope_entry
    }

    /// Send one crafted packet as a case of this job.
    ///
    /// # Errors
    /// [`HostError::Stopped`] when the job is cancelled, out of budget, past
    /// its deadline, refused by the guard or already stopped — including when
    /// this very case tripped the stop ladder, which is recorded first.
    /// [`HostError::Craft`] when the spec does not build or the wire write
    /// fails.
    pub async fn send_spec(
        &self,
        spec: PacketSpec,
        seed_id: &str,
        chain: Vec<String>,
        index: u32,
    ) -> Result<Sent, HostError> {
        let delivered = self
            .deliver(spec, seed_id, chain, index, Counted::Case)
            .await?;
        match delivered.stop {
            Some(reason) => Err(HostError::Stopped(reason)),
            None => Ok(delivered.sent),
        }
    }

    /// Send the unmutated seed and compare its class with the baseline's: the
    /// target is alive exactly while it reacts as it did before any case.
    ///
    /// # Errors
    /// As [`PointRunner::send_spec`]; the probe is charged but is never a case.
    pub async fn liveness_probe(&self) -> Result<bool, HostError> {
        let seed = self
            .plan
            .seed_spec(0)
            .map_err(|err| HostError::Craft(err.to_string()))?;
        let delivered = self
            .deliver(
                seed.spec,
                &seed.id,
                vec!["liveness".to_string()],
                0,
                Counted::Probe,
            )
            .await?;
        let passed = match (*lock(&self.baseline), delivered.sent.record.class) {
            (Some(baseline), Some(class)) => liveness_passes(baseline, class),
            // No baseline yet, or a case that never went out: not a pass.
            _ => false,
        };
        self.shared.state.record_liveness(self.job.job_id(), passed);
        Ok(passed)
    }

    /// Drive this point's whole run once, and hand every later caller the same
    /// `Arc`: a second check over the same point sends nothing.
    pub async fn run_point(self: &Arc<Self>) -> Arc<PointRun> {
        let mut cached = self.run.lock().await;
        if let Some(run) = cached.as_ref() {
            return Arc::clone(run);
        }
        let job_id = self.job.job_id().to_string();
        if let Some(run) = self.shared.state.run(&job_id, &self.point.id) {
            *cached = Some(Arc::clone(&run));
            return run;
        }
        let run = Arc::new(self.drive(&job_id).await);
        self.shared
            .state
            .set_run(&job_id, &self.point.id, Arc::clone(&run));
        self.report(&job_id);
        *cached = Some(Arc::clone(&run));
        run
    }

    /// Render the first cases without sending any of them (spec D8.4's dry
    /// run): nothing is charged, nothing is counted, nothing reaches a wire.
    #[must_use]
    pub fn dry_run(&self) -> PointRun {
        let mut run = self.blank_run();
        run.dry_run = true;
        let timing = self.shared.timing;
        let allocated = self
            .shared
            .state
            .allocate_cases(self.job.job_id())
            .unwrap_or(0)
            .min(timing.dry_run_cases);
        let Some(boundary) = self.boundary_table() else {
            return run;
        };
        let mut rng = Rng::new(self.rng_seed);
        for index in 0..allocated {
            let Some((seed, mutation)) = self.case_at(index, &boundary, &mut rng) else {
                break;
            };
            let sent_hex = mutation
                .apply(&seed.spec, timing.max_raw_bytes)
                .ok()
                .and_then(|spec| spec.build().ok())
                .map(|bytes| hex_encode(&bytes))
                .unwrap_or_default();
            run.cases.push(CaseRecord {
                index,
                seed_id: seed.id,
                chain: vec![mutation.label()],
                sent_hex,
                class: None,
                sent: false,
                elapsed_ms: 0,
                latency_outlier: false,
                liveness: None,
            });
        }
        run
    }

    /// The run with nothing driven yet.
    fn blank_run(&self) -> PointRun {
        PointRun {
            point_id: self.point.id.clone(),
            target: self.plan.key(),
            field: self.field,
            rng_seed: self.rng_seed,
            dry_run: self
                .shared
                .state
                .dry_run(self.job.job_id())
                .unwrap_or(false),
            recovery_wait: self.shared.timing.recovery_wait(),
            baseline: None,
            cases: Vec::new(),
            crash: None,
            stopped: None,
        }
    }

    /// The deterministic boundary table, read off seed 0 so a point's case
    /// count does not depend on which seed a case cycles to.
    fn boundary_table(&self) -> Option<Vec<Mutation>> {
        let seed = self.plan.seed_spec(0).ok()?;
        Some(boundary_cases(
            self.field,
            &seed.spec,
            self.plan.target.framing.header_len(),
            self.shared.timing.max_raw_bytes,
        ))
    }

    /// The seed and the mutation for case `index`: the boundary table first,
    /// then draws from the point's seeded generator.
    fn case_at(
        &self,
        index: u32,
        boundary: &[Mutation],
        rng: &mut Rng,
    ) -> Option<(SeedSpec, Mutation)> {
        let nth = usize::try_from(index).unwrap_or(usize::MAX);
        let seed = self.plan.seed_spec(nth).ok()?;
        let mutation = match boundary.get(nth) {
            Some(mutation) => mutation.clone(),
            None => random_case(self.field, &seed.spec, rng),
        };
        Some((seed, mutation))
    }

    /// Stop the job's sending with `reason` (first stop wins) and report the
    /// counters, as call C1b requires of every stop this runner raises.
    fn stop(&self, reason: StopReason) {
        let job_id = self.job.job_id();
        self.shared.state.mark_stopped(job_id, reason);
        self.report(job_id);
    }

    /// Hand the job's counters to the engine through the integration shim.
    fn report(&self, job_id: &str) {
        if let Some(counters) = self.shared.state.counters(job_id) {
            report_counters(self.job.as_ref(), counters);
        }
    }

    /// One stimulus end to end: the stop checks, the craft, the charge, the
    /// guarded send with its rate wait, and the oracle's reading of the reply.
    async fn deliver(
        &self,
        spec: PacketSpec,
        seed_id: &str,
        chain: Vec<String>,
        index: u32,
        counted: Counted,
    ) -> Result<Delivery, HostError> {
        let job_id = self.job.job_id().to_string();

        // (a) Nothing goes out for a job that is cancelled, stopped or past
        // its deadline.
        if self.job.cancelled() {
            self.stop(StopReason::Cancelled);
            return Err(HostError::Stopped(StopReason::Cancelled));
        }
        if let Some(reason) = self.shared.state.stopped(&job_id) {
            return Err(HostError::Stopped(reason));
        }
        if Instant::now() >= self.job.deadline() {
            self.stop(StopReason::Deadline);
            return Err(HostError::Stopped(StopReason::Deadline));
        }

        // (b) Craft, and refuse to charge for a frame `send_recv`'s C3 check
        // would refuse anyway: an undecodable stimulus is rendered, counted
        // apart and never sent (call C9).
        let bytes = spec
            .build()
            .map_err(|err| HostError::Craft(err.to_string()))?;
        let mut record = CaseRecord {
            index,
            seed_id: seed_id.to_string(),
            chain,
            sent_hex: hex_encode(&bytes),
            class: None,
            sent: false,
            elapsed_ms: 0,
            latency_outlier: false,
            liveness: None,
        };
        if !is_decodable(&bytes) {
            if counted == Counted::Case {
                // `record_case` ignores the class of an unsent case; it counts
                // it as unsendable and leaves the stop ladder alone.
                let _ = self
                    .shared
                    .state
                    .record_case(&job_id, CaseClass::Silence, false);
            }
            return Ok(Delivery {
                sent: Sent {
                    record,
                    reply: Vec::new(),
                },
                stop: None,
            });
        }

        // (c) One stimulus, one budget unit — the case, not the attempt: a
        // rate wait below retries without charging again.
        if !self.job.charge(1) {
            self.stop(StopReason::Budget);
            return Err(HostError::Stopped(StopReason::Budget));
        }

        // (d) The guarded send, waiting out the guard's injection rate.
        let (outcome, elapsed) = loop {
            let now = Instant::now();
            let deadline = self.job.deadline();
            if now >= deadline {
                self.stop(StopReason::Deadline);
                return Err(HostError::Stopped(StopReason::Deadline));
            }
            let timeout = self
                .shared
                .timing
                .reply_window
                .min(deadline.saturating_duration_since(now));
            let started = Instant::now();
            match self.send_blocking(spec.clone(), timeout).await {
                Ok(outcome) => break (outcome, started.elapsed()),
                Err(L4Error::Guard(L4GuardError::InjectionRateExceeded { retry_after })) => {
                    self.shared.state.record_rate_wait(&job_id);
                    let now = Instant::now();
                    let deadline = self.job.deadline();
                    if now >= deadline {
                        self.stop(StopReason::Deadline);
                        return Err(HostError::Stopped(StopReason::Deadline));
                    }
                    tokio::time::sleep(retry_after.min(deadline.saturating_duration_since(now)))
                        .await;
                }
                Err(L4Error::Unavailable(message)) => {
                    let reason = StopReason::Unavailable(message);
                    self.stop(reason.clone());
                    return Err(HostError::Stopped(reason));
                }
                Err(L4Error::Guard(err)) => {
                    let reason = StopReason::GuardRefused(err.to_string());
                    self.stop(reason.clone());
                    return Err(HostError::Stopped(reason));
                }
                Err(L4Error::WireWrite(message)) => return Err(HostError::Craft(message)),
            }
        };

        // (e) The oracle reads the reply, and the ladder gets its say — after
        // the record exists, so the tripping case is never lost.
        let classified = classify(&outcome, elapsed);
        record.class = Some(classified.class);
        record.sent = true;
        record.elapsed_ms = classified.elapsed_ms;
        let stop = if counted == Counted::Case {
            self.shared
                .state
                .record_case(&job_id, classified.class, true)
                .err()
        } else {
            None
        };
        Ok(Delivery {
            sent: Sent {
                record,
                reply: reply_bytes(&outcome),
            },
            stop,
        })
    }

    /// `send_recv` on a blocking thread: it owns a pcap handle for the call.
    async fn send_blocking(
        &self,
        spec: PacketSpec,
        timeout: Duration,
    ) -> Result<SendRecvOutcome, L4Error> {
        let guard = Arc::clone(&self.shared.guard);
        let backend = Arc::clone(&self.shared.backend);
        let store = Arc::clone(&self.shared.case_store);
        let request = send_recv_spec(&self.plan.target, spec, self.field, timeout);
        match tokio::task::spawn_blocking(move || send_recv(&guard, backend, store, request)).await
        {
            Ok(result) => result.map(|(_flow, outcome)| outcome),
            Err(err) => Err(L4Error::Unavailable(format!(
                "the send_recv task did not finish: {err}"
            ))),
        }
    }

    /// The whole run: baseline, cases, oracle, triage.
    async fn drive(&self, job_id: &str) -> PointRun {
        let mut run = self.blank_run();
        if run.dry_run {
            return self.dry_run();
        }
        if let Some(reason) = self.shared.state.stopped(job_id) {
            run.stopped = Some(reason);
            return run;
        }
        if self.shared.state.is_retired(job_id, &self.point.id) {
            // Already taken down and already reported: no further case.
            return run;
        }

        // The baseline is the yardstick every case and every liveness probe is
        // read against. It is charged, but it is not a case.
        let Ok(seed) = self.plan.seed_spec(0) else {
            return run;
        };
        match self
            .deliver(
                seed.spec,
                &seed.id,
                vec!["baseline".to_string()],
                0,
                Counted::Probe,
            )
            .await
        {
            Ok(delivered) => {
                run.baseline = delivered.sent.record.class;
                *lock(&self.baseline) = run.baseline;
            }
            Err(HostError::Stopped(reason)) => {
                run.stopped = Some(reason);
                return run;
            }
            // The seed was built at discovery time, so this is unreachable
            // short of a guard ceiling change mid-job; the point sends nothing.
            Err(HostError::Craft(_)) => return run,
        }

        let timing = self.shared.timing;
        let options = &self.job.profile().l4;
        let (liveness_every, reproduce_count) = (options.liveness_every, options.reproduce_count);
        let allocated = self.shared.state.allocate_cases(job_id).unwrap_or(0);
        let Some(boundary) = self.boundary_table() else {
            return run;
        };
        let mut rng = Rng::new(self.rng_seed);
        let mut latency = LatencyWindow::new();
        let mut sent_cases: u32 = 0;
        // Every case starts from the most recent liveness verdict; the baseline
        // answering at all is the first one.
        let mut alive = true;

        for index in 0..allocated {
            let liveness_before = alive;
            let Some((seed, mutation)) = self.case_at(index, &boundary, &mut rng) else {
                break;
            };
            let chain = vec![mutation.label()];
            let Ok(spec) = mutation.apply(&seed.spec, timing.max_raw_bytes) else {
                // A case that cannot even be rendered is unsendable, exactly as
                // one the wire would refuse: counted apart, never charged.
                let _ = self
                    .shared
                    .state
                    .record_case(job_id, CaseClass::Silence, false);
                run.cases.push(CaseRecord {
                    index,
                    seed_id: seed.id,
                    chain,
                    sent_hex: String::new(),
                    class: None,
                    sent: false,
                    elapsed_ms: 0,
                    latency_outlier: false,
                    liveness: None,
                });
                continue;
            };

            let delivered = match self
                .deliver(spec.clone(), &seed.id, chain.clone(), index, Counted::Case)
                .await
            {
                Ok(delivered) => delivered,
                Err(HostError::Stopped(reason)) => {
                    run.stopped = Some(reason);
                    break;
                }
                Err(HostError::Craft(_)) => continue,
            };
            let mut record = delivered.sent.record;
            let stop = delivered.stop;
            if !record.sent {
                run.cases.push(record);
                continue;
            }
            sent_cases += 1;
            let class = record.class.unwrap_or(CaseClass::Silence);
            if class == CaseClass::Clean {
                latency.record(record.elapsed_ms);
                record.latency_outlier = latency.is_outlier(record.elapsed_ms);
            }

            if class.is_candidate() && stop.is_none() {
                let (first, second, probe_stop) = self.probe_pair(false).await;
                record.liveness = Some((first, second));
                alive = first || second;
                if let Some(reason) = probe_stop {
                    run.cases.push(record);
                    run.stopped = Some(reason);
                    break;
                }
                if !first && !second {
                    let triage = self
                        .triage(&spec, &seed.id, &chain, index, reproduce_count)
                        .await;
                    let crashed = !triage.recovered
                        || (triage.attempts == reproduce_count
                            && triage.reproduced == triage.attempts);
                    if crashed {
                        self.shared.state.record_crash(job_id, &self.point.id);
                        run.crash = Some(CrashRecord {
                            case_index: index,
                            recovered: triage.recovered,
                            evidence: L4Evidence {
                                sent_hex: record.sent_hex.clone(),
                                seed_id: seed.id.clone(),
                                rng_seed: self.rng_seed,
                                mutation_chain: chain.clone(),
                                prior_messages: 0,
                                oracle: L4Oracle::LivenessFailed,
                                liveness_before,
                                liveness_after: false,
                                reproduced: (triage.reproduced, triage.attempts),
                                scope_entry: self.plan.target.scope_entry.clone(),
                            },
                        });
                        run.cases.push(record);
                        run.stopped = triage.stop;
                        break;
                    }
                    if let Some(reason) = triage.stop {
                        run.cases.push(record);
                        run.stopped = Some(reason);
                        break;
                    }
                }
            }

            run.cases.push(record);
            if let Some(reason) = stop {
                run.stopped = Some(reason);
                break;
            }

            // The scheduled probe runs after every `liveness_every` sent cases
            // whatever the oracle said (spec D8.4).
            if liveness_every > 0 && sent_cases.is_multiple_of(liveness_every) {
                match self.liveness_probe().await {
                    Ok(passed) => alive = passed,
                    Err(HostError::Stopped(reason)) => {
                        run.stopped = Some(reason);
                        break;
                    }
                    Err(HostError::Craft(_)) => break,
                }
            }
        }

        run
    }

    /// The two liveness probes a candidate costs: the second only when the
    /// first failed, unless `always` (after a replay, where both verdicts are
    /// part of the reproduction criterion).
    async fn probe_pair(&self, always: bool) -> (bool, bool, Option<StopReason>) {
        let first = match self.liveness_probe().await {
            Ok(passed) => passed,
            Err(HostError::Stopped(reason)) => return (false, false, Some(reason)),
            Err(HostError::Craft(_)) => false,
        };
        if first && !always {
            return (true, true, None);
        }
        tokio::time::sleep(self.shared.timing.liveness_retry).await;
        match self.liveness_probe().await {
            Ok(second) => (first, second, None),
            Err(HostError::Stopped(reason)) => (first, false, Some(reason)),
            Err(HostError::Craft(_)) => (first, false, None),
        }
    }

    /// Reproduce a candidate crash a bounded number of times, waiting for the
    /// target to come back before each replay (call C27), so every replay
    /// starts from a passing liveness probe.
    async fn triage(
        &self,
        spec: &PacketSpec,
        seed_id: &str,
        chain: &[String],
        index: u32,
        reproduce_count: u32,
    ) -> Triage {
        let mut triage = Triage {
            recovered: false,
            attempts: 0,
            reproduced: 0,
            stop: None,
        };
        // The candidate left the target silent, so the first replay always
        // waits for it.
        let mut alive = false;
        for _ in 0..reproduce_count {
            if !alive {
                match self.await_recovery().await {
                    // The replay below sets `alive` from its own probes.
                    Ok(true) => {}
                    // A target that never answers again is the strongest
                    // evidence there is; stop replaying into it.
                    Ok(false) => {
                        triage.recovered = false;
                        return triage;
                    }
                    Err(HostError::Stopped(reason)) => {
                        triage.stop = Some(reason);
                        return triage;
                    }
                    Err(HostError::Craft(_)) => return triage,
                }
            }
            triage.recovered = true;
            triage.attempts += 1;
            let delivered = match self
                .deliver(spec.clone(), seed_id, chain.to_vec(), index, Counted::Case)
                .await
            {
                Ok(delivered) => delivered,
                Err(HostError::Stopped(reason)) => {
                    triage.stop = Some(reason);
                    return triage;
                }
                Err(HostError::Craft(_)) => return triage,
            };
            let candidate = delivered
                .sent
                .record
                .class
                .is_some_and(|class| class.is_candidate());
            let (first, second, probe_stop) = self.probe_pair(true).await;
            alive = first || second;
            if candidate && !first && !second {
                triage.reproduced += 1;
            }
            if let Some(reason) = probe_stop.or(delivered.stop) {
                triage.stop = Some(reason);
                return triage;
            }
        }
        triage
    }

    /// Poll liveness until the target answers again or the bound runs out.
    ///
    /// # Errors
    /// [`HostError::Stopped`] when the job stopped while waiting.
    async fn await_recovery(&self) -> Result<bool, HostError> {
        let timing = self.shared.timing;
        for attempt in 0..timing.recovery_polls {
            if Instant::now() >= self.job.deadline() {
                return Ok(false);
            }
            if self.liveness_probe().await? {
                return Ok(true);
            }
            if attempt + 1 < timing.recovery_polls {
                tokio::time::sleep(timing.recovery_poll).await;
            }
        }
        Ok(false)
    }
}

/// The reply bytes a check sees: the transport payload when the reply carries
/// one, else the whole frame (an ICMP error has no transport payload of its
/// own). Empty on silence.
fn reply_bytes(outcome: &SendRecvOutcome) -> Vec<u8> {
    let packet = match outcome {
        SendRecvOutcome::Response(packet) | SendRecvOutcome::Other(packet) => Some(packet),
        SendRecvOutcome::Responses(packets) => packets.first(),
        SendRecvOutcome::NoResponse { .. } => None,
    };
    packet.map_or_else(Vec::new, |packet| {
        transport_payload(packet).map_or_else(
            || packet.bytes.clone(),
            |transport| transport.payload.to_vec(),
        )
    })
}

/// The `ProbeResponse` shape the L4 lanes answer with: no status, no headers,
/// the reply bytes as the body, and `l4: Some` only for a classified reaction
/// (a clean reply has no `L4Oracle`, call C13).
fn response_for(sent: &Sent) -> ProbeResponse {
    let mut body = sent.reply.clone();
    body.truncate(MAX_MATCH_BODY);
    ProbeResponse {
        status: None,
        headers: Vec::new(),
        body,
        elapsed_ms: sent.record.elapsed_ms,
        flow: None,
        ws_frames: None,
        l4: sent
            .record
            .class
            .and_then(|class| class.oracle())
            .map(|oracle| L4Reply {
                bytes: sent.reply.clone(),
                oracle,
                elapsed_ms: sent.record.elapsed_ms,
            }),
    }
}

/// The `ProbeHost` the engine hands a check for one packet-lane point.
///
/// A check that only reads the point's fuzz run never touches this; it exists
/// so a check can send its own stimulus at the point, under exactly the same
/// guard, budget and deadline as a case.
pub struct PacketHost {
    runner: Arc<PointRunner>,
    baseline: tokio::sync::Mutex<Option<ProbeResponse>>,
}

impl fmt::Debug for PacketHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketHost")
            .field("runner", &self.runner)
            .finish()
    }
}

impl PacketHost {
    /// A host over one point's runner.
    #[must_use]
    pub fn new(runner: Arc<PointRunner>) -> Self {
        Self {
            runner,
            baseline: tokio::sync::Mutex::new(None),
        }
    }

    /// The runner this host sends through.
    #[must_use]
    pub fn runner(&self) -> &Arc<PointRunner> {
        &self.runner
    }
}

impl ProbeHost for PacketHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let mut cached = self.baseline.lock().await;
            if let Some(response) = cached.as_ref() {
                return Ok(response.clone());
            }
            let seed = self
                .runner
                .plan
                .seed_spec(0)
                .map_err(|err| anyhow::Error::msg(err.to_string()))?;
            let sent = self
                .runner
                .send_spec(seed.spec, &seed.id, vec!["baseline".to_string()], 0)
                .await?;
            let response = response_for(&sent);
            *cached = Some(response.clone());
            Ok(response)
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let Some(bytes) = payload.bytes.clone() else {
                return Err(anyhow::anyhow!("the packet lane replays frame bytes only"));
            };
            // The frame goes out as it is; `send_recv`'s C3 check still pins the
            // destination, so a replay cannot be aimed somewhere else.
            let spec = PacketSpec {
                layers: vec![Layer::Raw(bytes)],
            };
            let seed_id = self
                .runner
                .plan
                .seed_spec(0)
                .map(|seed| seed.id)
                .unwrap_or_default();
            let sent = self
                .runner
                .send_spec(spec, &seed_id, vec![payload.value.clone()], 0)
                .await?;
            Ok(response_for(&sent))
        })
    }

    fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("the packet lane hosts no raw HTTP probes")) })
    }

    fn marker(&self) -> String {
        self.runner.job.marker()
    }

    fn budget_left(&self) -> u32 {
        self.runner.job.budget_left()
    }

    fn deadline(&self) -> Instant {
        self.runner.job.deadline()
    }

    fn profile(&self) -> &ScanProfile {
        self.runner.job.profile()
    }

    fn cancelled(&self) -> bool {
        self.runner.job.cancelled()
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        // Every case is recorded in the lane-private L4 store, not as an HTTP
        // flow; there is nothing for the engine to re-record.
        Vec::new()
    }
}

/// The runners of every point the lane is driving, keyed by `(job marker,
/// point id)` so a check finds the one run of a point without downcasting the
/// `&dyn ProbeHost` it was handed (plan call C2).
#[derive(Default)]
pub struct RunnerRegistry {
    runners: Mutex<HashMap<(String, String), Arc<PointRunner>>>,
}

impl fmt::Debug for RunnerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerRegistry")
            .field("runners", &lock(&self.runners).len())
            .finish()
    }
}

impl RunnerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `runner` as the one runner for this marker and point.
    pub fn register(&self, marker: &str, point_id: &str, runner: Arc<PointRunner>) {
        lock(&self.runners).insert((marker.to_string(), point_id.to_string()), runner);
    }

    /// The runner for this marker and point, if one was registered.
    #[must_use]
    pub fn get(&self, marker: &str, point_id: &str) -> Option<Arc<PointRunner>> {
        lock(&self.runners)
            .get(&(marker.to_string(), point_id.to_string()))
            .map(Arc::clone)
    }

    /// Drop every runner of one job, once its marker is done with.
    pub fn forget_marker(&self, marker: &str) {
        lock(&self.runners).retain(|(known, _), _| known != marker);
    }

    /// How many runners are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.runners).len()
    }

    /// Whether no runner is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.runners).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime};

    use aitm_proto_l4::backend::CaptureInjectBackend;
    use aitm_proto_l4::craft::PacketSpec;
    use aitm_proto_l4::flow::{InMemoryL4FlowStore, L4FlowStore, L4Packet};
    use aitm_proto_l4::icmp::transport_payload;
    use aitm_proto_l4::types::L4Direction;
    use aitm_scan_model::{
        Discovery, InsertionPoint, JobCtx, L4Counters, Payload, PayloadMode, ProbeHost, ScanProfile,
    };

    use super::{PacketHost, PointRunner, RunnerRegistry, Shared, Timing};
    use crate::codec::hex_encode;
    use crate::discover::discover_all;
    use crate::fields::FieldPath;
    use crate::oracle::CaseClass;
    use crate::plan::{point_id, TargetPlan};
    use crate::state::{LaneState, StopReason};
    use crate::testing::{
        fields, l4_profile, loopback_guard, tcp_target, udp_target, with_hex_seed, MockBackend,
        MockReply, TestJob,
    };

    /// The lane context every test drives: the loopback guard, the mock backend,
    /// a lane-private case store, a separate seed store and a `LaneState` with
    /// the job already begun. Timings are shrunk so a test spends milliseconds
    /// where the lane spends seconds.
    fn setup(
        mock: Arc<MockBackend>,
        profile: ScanProfile,
        requested: &[String],
        pps: u32,
    ) -> (Arc<Shared>, Arc<TestJob>, Vec<TargetPlan>, Discovery) {
        let guard = loopback_guard("*", pps);
        let seed_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::default());
        let case_store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::with_limits(1024, 16));
        let backend: Arc<dyn CaptureInjectBackend> = mock;
        let job = TestJob::new(profile.clone());
        let (plans, discovery) = discover_all(
            guard.as_ref(),
            backend.as_ref(),
            Some(seed_store.as_ref()),
            &profile.target,
            &profile,
            requested,
            &job.marker(),
        )
        .expect("the loopback profile discovers");
        let state = Arc::new(LaneState::new());
        state.begin_job(
            job.job_id(),
            plans.clone(),
            discovery.points.iter().map(|p| p.id.clone()).collect(),
            profile.l4.cases,
            profile.l4.consecutive_timeouts,
            profile.l4.dry_run,
        );
        let shared = Arc::new(Shared {
            guard,
            backend,
            case_store,
            seed_store: Some(seed_store),
            timing: Timing {
                reply_window: Duration::from_millis(50),
                liveness_retry: Duration::from_millis(10),
                replay_spacing: Duration::from_millis(10),
                recovery_poll: Duration::from_millis(10),
                recovery_polls: 10,
                ..Timing::default()
            },
            state,
        });
        (shared, job, plans, discovery)
    }

    /// The runner for one field of the job's first target.
    fn runner_for(
        shared: &Arc<Shared>,
        job: &Arc<TestJob>,
        plans: &[TargetPlan],
        points: &[InsertionPoint],
        field: &str,
    ) -> Arc<PointRunner> {
        let path = FieldPath::from_str(field).expect("a known field path");
        let plan = plans.first().expect("one target plan").clone();
        let id = point_id(&plan.target, path);
        let point = points
            .iter()
            .find(|point| point.id == id)
            .expect("the field's point")
            .clone();
        Arc::new(PointRunner::new(
            Arc::clone(shared),
            Arc::clone(job) as Arc<dyn JobCtx>,
            point,
            plan,
            path,
        ))
    }

    /// Read an injected frame back as the packet views see it.
    fn as_packet(bytes: &[u8]) -> L4Packet {
        L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(bytes),
            bytes: bytes.to_vec(),
            injected: true,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hundred_clean_cases_exact_counts() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 100);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 100);
        assert!(
            run.cases
                .iter()
                .all(|case| case.class == Some(CaseClass::Clean)),
            "every case is clean: {:?}",
            run.cases.iter().map(|c| c.class).collect::<Vec<_>>()
        );
        assert_eq!(run.baseline, Some(CaseClass::Clean));
        assert!(run.crash.is_none());
        assert!(run.stopped.is_none());
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 100,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        // 1 baseline + 100 cases + 4 scheduled liveness probes (25/50/75/100).
        assert_eq!(mock.inject_count(), 105);
        assert_eq!(job.charged(), 105);
        for frame in mock.injected() {
            let packet = as_packet(&frame);
            let ends = transport_payload(&packet).expect("a decodable stimulus");
            assert_eq!(ends.dst.to_string(), "127.0.0.1");
            assert_eq!(ends.dst_port, 9);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn icmp_reactions_are_classified_not_crashes() {
        let mock = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        let icmp = CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        };
        assert_eq!(run.cases.len(), 10);
        assert!(run.cases.iter().all(|case| case.class == Some(icmp)));
        assert_eq!(run.baseline, Some(icmp));
        assert_eq!(run.reactions(), vec![(icmp, 10)]);
        let counters = shared.state.counters(job.job_id()).expect("counters");
        assert_eq!(counters.liveness_failures, 0);
        assert_eq!(counters.crashes, 0);
        assert_eq!(mock.inject_count(), 11);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_is_a_reaction_with_one_liveness_probe_each() {
        let mock = MockBackend::new(MockReply::Rst);
        let profile = l4_profile(vec![tcp_target(80)], 7);
        let (shared, job, plans, disc) =
            setup(Arc::clone(&mock), profile, &fields(&["tcp.flags"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "tcp.flags");

        let run = runner.run_point().await;

        assert_eq!(run.reactions(), vec![(CaseClass::Reset, 7)]);
        let counters = shared.state.counters(job.job_id()).expect("counters");
        assert_eq!(counters.liveness_failures, 0);
        // 1 baseline + 7 cases + one passing liveness probe per reset case.
        assert_eq!(mock.inject_count(), 1 + 7 + 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn crash_triage_reproduces_after_recovery_and_retires() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        let crash = run.crash.clone().expect("the grow:8 case crashes the mock");
        assert_eq!(crash.case_index, 1);
        assert!(crash.recovered);
        assert_eq!(crash.evidence.reproduced, (3, 3));
        assert!(crash.evidence.liveness_before);
        assert!(!crash.evidence.liveness_after);
        assert_eq!(
            crash.evidence.oracle,
            aitm_scan_model::L4Oracle::LivenessFailed
        );
        assert_eq!(crash.evidence.mutation_chain, vec!["grow:8".to_string()]);
        assert_eq!(crash.evidence.seed_id, "127.0.0.1:9/udp#0");
        assert_eq!(crash.evidence.prior_messages, 0);
        assert_eq!(
            crash.evidence.scope_entry, plans[0].target.scope_entry,
            "the evidence names the Inject entry that admitted the target"
        );
        let trigger = mock.injected().get(2).cloned().expect("the third inject");
        assert_eq!(crash.evidence.sent_hex, hex_encode(&trigger));
        let packet = as_packet(&trigger);
        let ends = transport_payload(&packet).expect("a decodable stimulus");
        assert_eq!(hex_encode(ends.payload), "deadbeef00000000");

        assert_eq!(run.cases.len(), 2);
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 5,
                crashes: 1,
                liveness_failures: 8,
                retired_elements: 1,
            })
        );
        assert_eq!(mock.inject_count(), 17);
        assert_eq!(job.charged(), 17);
        assert!(shared.state.is_retired(job.job_id(), &run.point_id));

        let again = runner.run_point().await;
        assert!(Arc::ptr_eq(&run, &again));
        assert_eq!(mock.inject_count(), 17);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_outage_is_a_crash_without_replays() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_after_injects(6);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        let crash = run.crash.clone().expect("a target that never comes back");
        assert_eq!(crash.case_index, 5);
        assert!(!crash.recovered);
        assert_eq!(crash.evidence.reproduced, (0, 0));
        assert!(!crash.evidence.liveness_after);
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 6,
                crashes: 1,
                liveness_failures: 12,
                retired_elements: 1,
            })
        );
        assert_eq!(mock.inject_count(), 19);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flaky_candidate_that_does_not_reproduce_is_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, false);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 10), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases[1].liveness, Some((false, false)));
        assert!(run.crash.is_none());
        assert_eq!(
            shared
                .state
                .counters(job.job_id())
                .expect("counters")
                .crashes,
            0
        );
        assert_eq!(run.cases.len(), 10);
        // 1 baseline + 10 cases + 2 failed probes + 1 recovery poll + 3 x (replay + 2 probes).
        assert_eq!(mock.inject_count(), 1 + 10 + 2 + 1 + 3 * 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn consecutive_timeouts_stop_the_job() {
        let mock = MockBackend::new(MockReply::Silence);
        let mut profile = l4_profile(vec![udp_target(9)], 50);
        profile.l4.consecutive_timeouts = 3;
        let (shared, job, plans, disc) = setup(
            Arc::clone(&mock),
            profile,
            &fields(&["raw", "udp.length"]),
            1000,
        );
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.baseline, Some(CaseClass::Silence));
        assert_eq!(run.cases.len(), 3);
        assert_eq!(run.stopped, Some(StopReason::ConsecutiveTimeouts(3)));
        assert!(shared.state.stopped(job.job_id()).is_some());

        let injected = mock.inject_count();
        let other = runner_for(&shared, &job, &plans, &disc.points, "udp.length");
        let second = other.run_point().await;
        assert!(second.cases.is_empty());
        assert!(second
            .stopped
            .as_ref()
            .expect("the job stop reason")
            .to_string()
            .contains("consecutive_timeouts"));
        assert_eq!(mock.inject_count(), injected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn budget_exhaustion_stops() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let job = job.with_budget(10);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.stopped, Some(StopReason::Budget));
        assert_eq!(run.cases.len(), 9);
        assert_eq!(job.charged(), 10);
        assert_eq!(mock.inject_count(), 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_sends_nothing() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        job.cancel();
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.stopped, Some(StopReason::Cancelled));
        assert_eq!(mock.inject_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn past_deadline_sends_nothing() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let job = job.with_deadline(Instant::now() - Duration::from_secs(1));
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.stopped, Some(StopReason::Deadline));
        assert_eq!(mock.inject_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limit_waits_and_retries() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 4);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 2);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 4);
        assert!(run
            .cases
            .iter()
            .all(|case| case.class == Some(CaseClass::Clean)));
        assert!(shared.state.stats(job.job_id()).expect("stats").rate_waits >= 1);
        assert_eq!(job.charged(), 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dry_run_renders_fifty_and_sends_nothing() {
        let mock = MockBackend::new(MockReply::Echo);
        let mut profile = l4_profile(vec![udp_target(9)], 100);
        profile.l4.dry_run = true;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert!(run.dry_run);
        assert_eq!(run.cases.len(), 50);
        for case in &run.cases {
            assert!(!case.sent);
            assert_eq!(case.class, None);
            assert!(!case.sent_hex.is_empty());
            assert_eq!(case.chain.len(), 1);
        }
        assert_eq!(mock.inject_count(), 0);
        assert_eq!(job.charged(), 0);
        assert_eq!(
            shared.state.counters(job.job_id()).expect("counters").cases,
            0
        );
    }

    // An `ipv4.ihl` case that cannot reach the wire is recorded unsent and charged to nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsendable_cases_are_not_charged() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 8);
        let (shared, job, plans, disc) =
            setup(Arc::clone(&mock), profile, &fields(&["ipv4.ihl"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "ipv4.ihl");

        let run = runner.run_point().await;

        for value in 0..=4 {
            let label = format!("ipv4.ihl={value}");
            let case = run
                .cases
                .iter()
                .find(|case| case.chain == vec![label.clone()])
                .unwrap_or_else(|| panic!("a record for {label}"));
            assert!(!case.sent, "{label} cannot be put on the wire");
        }
        let stats = shared.state.stats(job.job_id()).expect("stats");
        assert!(stats.cases_unsendable >= 5);
        assert_eq!(stats.cases_unsendable + stats.l4.cases, 8);
        assert_eq!(u64::from(job.charged()), 1 + stats.l4.cases);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_host_surface() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let host = PacketHost::new(Arc::clone(&runner));

        let raw = host
            .probe_raw(aitm_scan_model::RawProbe {
                method: "GET".to_string(),
                url: "http://127.0.0.1/".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await;
        assert!(raw
            .expect_err("the packet lane hosts no raw HTTP probes")
            .to_string()
            .contains("no raw HTTP probes"));
        assert!(host.held_flows().is_empty());
        assert_eq!(host.marker(), "aitm7f3a");

        let baseline = host.baseline().await.expect("the seed is sent once");
        assert!(baseline.l4.is_none(), "a clean reply carries no L4Reply");
        assert_eq!(baseline.body, plans[0].seeds[0].bytes);
        let after_first = mock.inject_count();
        let _again = host.baseline().await.expect("the cached baseline");
        assert_eq!(mock.inject_count(), after_first, "the baseline is cached");

        let frame = mock
            .injected()
            .first()
            .cloned()
            .expect("the baseline frame");
        let replayed = host
            .probe(&Payload {
                value: "replay".to_string(),
                mode: PayloadMode::Replace,
                bytes: Some(frame),
            })
            .await
            .expect("a replayed frame");
        assert!(
            replayed.status.is_none(),
            "the packet lane has no HTTP status"
        );
        assert_eq!(mock.inject_count(), after_first + 1);

        let refused = host
            .probe(&Payload {
                value: "no bytes".to_string(),
                mode: PayloadMode::Replace,
                bytes: None,
            })
            .await;
        assert!(refused
            .expect_err("the lane replays frame bytes only")
            .to_string()
            .contains("frame bytes only"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn case_flows_go_to_the_private_store() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 5);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 5);
        assert_eq!(shared.case_store.list().len(), 6);
        assert!(shared
            .seed_store
            .as_ref()
            .expect("a seed store")
            .list()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registry_keys_by_marker_and_point() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 5);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = RunnerRegistry::new();
        assert!(registry.is_empty());

        registry.register(
            &job.marker(),
            runner.point().id.as_str(),
            Arc::clone(&runner),
        );

        assert_eq!(registry.len(), 1);
        let found = registry
            .get(&job.marker(), runner.point().id.as_str())
            .expect("the registered runner");
        assert!(Arc::ptr_eq(&found, &runner));
        assert!(registry.get("other", runner.point().id.as_str()).is_none());
        registry.forget_marker(&job.marker());
        assert!(registry.is_empty());
    }

    /// Tester (stage 5): the budget runs out during the recovery wait. The
    /// candidate case had two failed probes but **no replay ran** and the
    /// target was never given the recovery bound, so spec D8.4 / call 14 ("two
    /// failed liveness probes, reproduced 3 times") and call C27 ("a target
    /// that never recovers within 10 s") both say this is a `Budget` stop, not
    /// an `l4-crash`.
    ///
    /// BLOCKED (tester finding F1, 2026-11-01): `triage` starts with
    /// `recovered: false` and returns it unchanged when `await_recovery`
    /// fails with `Stopped(Budget)`, so `drive` reads `!triage.recovered` as a
    /// persistent outage and records a crash with `reproduced: (0, 0)`. Red
    /// until the Coder's fix; the fix task un-ignores it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "BLOCKED: tester finding F1 — a Budget stop inside the recovery wait is recorded as a crash"]
    async fn budget_exhausted_mid_triage_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 baseline + 2 cases + the 2 failed probes = 5; the first recovery
        // poll is the charge that fails.
        let job = job.with_budget(5);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(mock.inject_count(), 5);
        assert_eq!(job.charged(), 5);
        assert_eq!(run.cases.len(), 2);
        assert_eq!(run.cases[1].liveness, Some((false, false)));
        assert_eq!(run.stopped, Some(StopReason::Budget));
        assert!(
            run.crash.is_none(),
            "a budget stop before any replay is not a reproduced crash: {:?}",
            run.crash
        );
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 2,
                crashes: 0,
                liveness_failures: 2,
                retired_elements: 0,
            })
        );
        assert!(!shared.state.is_retired(job.job_id(), &run.point_id));
    }

    /// Tester (stage 5): the job deadline passes while the runner is polling
    /// for recovery. The target was given neither the recovery bound nor a
    /// replay, so the run must end as a `Deadline` stop with no crash recorded
    /// (call C27's "did not recover within 10 s" needs the 10 s).
    ///
    /// BLOCKED (tester finding F1, 2026-11-01): `await_recovery` answers
    /// `Ok(false)` when the deadline passes, which `triage` cannot tell from
    /// "polled ten times, never came back", so the run records a crash and
    /// never marks the job `Deadline`. Red until the Coder's fix; the fix task
    /// un-ignores it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "BLOCKED: tester finding F1 — a Deadline during the recovery wait is recorded as a crash"]
    async fn deadline_during_recovery_wait_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        // Dead for far longer than the deadline allows, but the recovery bound
        // (10 polls x (20 ms window + 20 ms gap) = 400 ms) is never reached.
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 1000, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let shared = Arc::new(Shared {
            guard: Arc::clone(&shared.guard),
            backend: Arc::clone(&shared.backend),
            case_store: Arc::clone(&shared.case_store),
            seed_store: shared.seed_store.clone(),
            timing: Timing {
                reply_window: Duration::from_millis(20),
                liveness_retry: Duration::from_millis(5),
                replay_spacing: Duration::from_millis(5),
                recovery_poll: Duration::from_millis(20),
                recovery_polls: 10,
                ..Timing::default()
            },
            state: Arc::clone(&shared.state),
        });
        // Baseline + two cases + two failed probes take about 75 ms; the
        // deadline lands in the middle of the recovery polls.
        let job = job.with_deadline(Instant::now() + Duration::from_millis(200));
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(run.cases[1].liveness, Some((false, false)));
        assert_eq!(run.stopped, Some(StopReason::Deadline));
        assert_eq!(
            shared.state.stopped(job.job_id()),
            Some(StopReason::Deadline)
        );
        assert!(
            run.crash.is_none(),
            "a deadline stop during the recovery wait is not a crash: {:?}",
            run.crash
        );
        let counters = shared.state.counters(job.job_id()).expect("counters");
        assert_eq!(counters.crashes, 0);
        assert_eq!(counters.retired_elements, 0);
        assert_eq!(counters.cases, 2);
        // The ten recovery polls were never completed.
        assert!(
            mock.inject_count() < 15,
            "the deadline cut the recovery polls short: {} injects",
            mock.inject_count()
        );
    }
}
