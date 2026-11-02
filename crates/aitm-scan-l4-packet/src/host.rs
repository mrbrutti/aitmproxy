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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_proto_l4::backend::{CaptureInjectBackend, L4Error};
use aitm_proto_l4::craft::{Layer, PacketSpec};
use aitm_proto_l4::flow::L4FlowStore;
use aitm_proto_l4::guard::{L4Guard, L4GuardError};
use aitm_proto_l4::icmp::transport_payload;
use aitm_proto_l4::sendrecv::{send_recv, SendRecvOutcome};
use aitm_scan_model::{
    InsertionPoint, JobCtx, L4Evidence, L4Options, L4Oracle, L4Reply, Payload, ProbeHost,
    ProbeResponse, RawProbe, ScanProfile, MAX_MATCH_BODY,
};
use futures::future::BoxFuture;

use crate::codec::hex_encode;
use crate::fields::FieldPath;
use crate::mutate::{boundary_cases, random_case, Mutation, DEFAULT_MAX_RAW_BYTES};
use crate::oracle::{classify, liveness_passes, CaseClass, LatencyWindow};
use crate::plan::{is_decodable, send_recv_spec, PlanError, SeedSpec, TargetPlan};
use crate::rng::{derive_seed, Rng};
use crate::state::{
    report_counters, Candidate, CaseNote, CaseOutcome, CaseRecord, CrashRecord, LaneState,
    PointRun, StopReason,
};
use crate::sync::lock;

/// How long one case waits for its reply (spec D8.4's reply window).
pub const CASE_REPLY_WINDOW: Duration = Duration::from_millis(500);

/// How long a silent target is given to come back before the outage is called
/// persistent (plan call C27).
pub const RECOVERY_WAIT: Duration = Duration::from_secs(10);

/// The floor, in milliseconds, under which the lane refuses to pace an
/// ICMP-baseline point, whatever the profile asks for (spec amendment 46; D11's
/// `scanner.ceilings.l4_icmp_pace_ms_min`).
///
/// A remote target's kernel rate-limits the ICMP errors it generates — Linux
/// defaults to `net.ipv4.icmp_ratelimit = 1000` ms per destination; loopback is
/// exempt (write-up `2026-11-01-t5-live-proof.md`, section iii) — so a point
/// stimulated faster than this reads silence where the port is simply closed.
/// The engine clamps the profile value up to D11's ceiling and reports it in
/// `scan.start`'s `clamped`; until it passes its ceilings to the lane, the lane
/// applies this floor itself. The only way under it is [`Timing::icmp_pace`],
/// and that field is crate-private, so no lane caller can under-pace a closed
/// port.
pub const ICMP_PACE_FLOOR_MS: u32 = 1000;

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
    /// This crate's own ICMP pace, replacing both the profile's `icmp_pace_ms`
    /// and [`ICMP_PACE_FLOOR_MS`]. `None` — the production value — means the
    /// profile's, never below the floor (see [`Timing::icmp_pace_for`]).
    ///
    /// Crate-private: only the in-crate test harness (`fast_timing`) sets it,
    /// so a caller of [`crate::PacketLane::with_timing`] cannot under-pace a
    /// closed port (spec D11); the floor holds by construction.
    pub(crate) icmp_pace: Option<Duration>,
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
            icmp_pace: None,
        }
    }
}

impl Timing {
    /// How long a silent target is given to come back, in total.
    #[must_use]
    pub fn recovery_wait(&self) -> Duration {
        self.recovery_poll.saturating_mul(self.recovery_polls)
    }

    /// How far apart consecutive stimuli to an ICMP-baseline point are spaced
    /// (spec amendment 46): the profile's `l4.icmp_pace_ms`, raised to
    /// [`ICMP_PACE_FLOOR_MS`] when it is below it, unless the crate-private
    /// [`Timing::icmp_pace`] override is set.
    #[must_use]
    pub fn icmp_pace_for(&self, options: &L4Options) -> Duration {
        let floored =
            Duration::from_millis(u64::from(options.icmp_pace_ms.max(ICMP_PACE_FLOOR_MS)));
        self.icmp_pace.unwrap_or(floored)
    }
}

/// Everything every runner of the lane shares: the guard that admits a
/// stimulus, the backend that puts it on the wire, the lane-private case store
/// (call C8), the operator's store for seeds only, the timings and the per-job
/// bookkeeping.
///
/// `Clone` is a shallow clone of the shared `Arc`s and the `Copy` timing, so a
/// caller can re-time one field with struct update (review finding M5).
#[derive(Clone)]
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
    /// The case could not be crafted. A wire write that fails is a
    /// [`StopReason::WireWrite`] stop, not this (review finding Q1).
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

// `std::error::Error`, so anyhow's blanket `From<E: Error>` is the conversion a
// `ProbeHost` method's `?` uses and an engine caller can `downcast_ref`
// (review finding M1).
impl std::error::Error for HostError {}

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
    ///
    /// `false` is a *finding*, not a default: it is set only when the whole
    /// recovery bound ran and every one of its `recovery_polls` probes failed
    /// (tester finding F1). A triage cut short by a stop leaves it `true`,
    /// because nothing was learned about recovery.
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
    /// Seed 0's built spec, crafted once at construction and reused by every
    /// baseline, liveness probe and boundary table instead of rebuilt each time
    /// (review finding M8).
    seed0: SeedSpec,
    baseline: Mutex<Option<CaseClass>>,
    /// When this point last had a stimulus put on the wire, so an ICMP-paced
    /// point spaces the next one (spec amendment 46).
    last_stimulus_at: Mutex<Option<Instant>>,
    run: tokio::sync::OnceCell<Arc<PointRun>>,
}

impl fmt::Debug for PointRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PointRunner")
            .field("point_id", &self.point.id)
            .field("target", &self.plan.key())
            .field("field", &self.field)
            .field("rng_seed", &self.rng_seed)
            .field("baseline", &*lock(&self.baseline))
            .field("icmp_paced", &self.is_icmp_paced())
            .finish()
    }
}

impl PointRunner {
    /// A runner for one `(point, field)` of one job. The point's PRNG seed is
    /// derived from the job id and the point id, so the run replays — never
    /// from the engine's `JobCtx::marker`, which mints a fresh token on every
    /// call and so would seed the run differently each time (T5 live proof,
    /// 4b). Seed 0
    /// is built here, once, so a seed that does not craft is refused at
    /// `probe_host_for` rather than at send time (review finding M8).
    ///
    /// # Errors
    /// [`PlanError`] when the plan carries no seed or seed 0 does not build.
    pub fn new(
        shared: Arc<Shared>,
        job: Arc<dyn JobCtx>,
        point: InsertionPoint,
        plan: TargetPlan,
        field: FieldPath,
    ) -> Result<Self, PlanError> {
        let rng_seed = derive_seed(job.job_id(), &point.id);
        let seed0 = plan.seed_spec(0)?;
        Ok(Self {
            shared,
            job,
            point,
            plan,
            field,
            rng_seed,
            seed0,
            baseline: Mutex::new(None),
            last_stimulus_at: Mutex::new(None),
            run: tokio::sync::OnceCell::new(),
        })
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
    /// this very case tripped the stop ladder, which is recorded first —
    /// including a failed wire write ([`StopReason::WireWrite`]).
    /// [`HostError::Craft`] when the spec does not build.
    pub async fn send_spec(
        &self,
        spec: PacketSpec,
        seed_id: &str,
        chain: Vec<String>,
        index: u32,
    ) -> Result<Sent, HostError> {
        let delivered = self
            .deliver(spec, seed_id, chain, index, Counted::Case, self.field)
            .await?;
        match delivered.stop {
            Some(reason) => Err(HostError::Stopped(reason)),
            None => Ok(delivered.sent),
        }
    }

    /// Replay a verbatim frame at this point's target as a case.
    ///
    /// Unlike [`PointRunner::send_spec`], the reply correlation always pins
    /// `dst_port` to the target's port, whatever field this runner fuzzes, so a
    /// replay can never be correlated against — or aimed at — any other port
    /// `send_recv`'s C3 check would otherwise leave open (review finding SEC4).
    ///
    /// # Errors
    /// As [`PointRunner::send_spec`].
    pub async fn replay(
        &self,
        spec: PacketSpec,
        seed_id: &str,
        chain: Vec<String>,
        index: u32,
    ) -> Result<Sent, HostError> {
        let delivered = self
            .deliver(spec, seed_id, chain, index, Counted::Case, FieldPath::Raw)
            .await?;
        match delivered.stop {
            Some(reason) => Err(HostError::Stopped(reason)),
            None => Ok(delivered.sent),
        }
    }

    /// Send the unmutated seed and compare its class with the baseline's: the
    /// target is alive exactly while it reacts as it did before any case.
    ///
    /// The correlation pins `dst_port`, as [`PointRunner::replay`] does and
    /// whatever field this runner fuzzes: the probe sends seed 0, whose
    /// transport header is intact, so the strict pin is always possible — and
    /// it is the correct one. Only a *mutated* case may need the looser rule
    /// its field dictates (`send_recv_spec`). Passing `self.field` here would
    /// drop the pin on every point that does not preserve the transport
    /// (`udp.length`, `ipv4.proto`, the fragmentation fields), and on a shared
    /// interface an unrelated frame from another port of the same host could
    /// then be read as a passing probe (review finding SEC4).
    ///
    /// # Errors
    /// As [`PointRunner::send_spec`]; the probe is charged but is never a case.
    pub async fn liveness_probe(&self) -> Result<bool, HostError> {
        let seed = self.seed0.clone();
        let delivered = self
            .deliver(
                seed.spec,
                &seed.id,
                vec!["liveness".to_string()],
                0,
                Counted::Probe,
                FieldPath::Raw,
            )
            .await?;
        let baseline = *lock(&self.baseline);
        let class = delivered.sent.record.class();
        let passed = match (baseline, class) {
            (Some(baseline), Some(class)) => liveness_passes(baseline, class),
            // No baseline yet, or a case that never went out: not a pass.
            _ => false,
        };
        tracing::debug!(
            target: "aitm::scanner::l4_packet",
            job = %self.job.job_id(),
            point = %self.point.id,
            baseline = %class_label(baseline),
            class = %class_label(class),
            passed,
            "liveness probe"
        );
        self.shared.state.record_liveness(self.job.job_id(), passed);
        Ok(passed)
    }

    /// Drive this point's whole run once, and hand every later caller the same
    /// `Arc`: a second check over the same point sends nothing.
    pub async fn run_point(self: &Arc<Self>) -> Arc<PointRun> {
        Arc::clone(
            self.run
                .get_or_init(|| async {
                    let job_id = self.job.job_id().to_string();
                    if let Some(run) = self.shared.state.run(&job_id, &self.point.id) {
                        return run;
                    }
                    let run = Arc::new(self.drive(&job_id).await);
                    self.shared
                        .state
                        .set_run(&job_id, &self.point.id, Arc::clone(&run));
                    self.report(&job_id);
                    run
                })
                .await,
        )
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
        let boundary = self.boundary_table();
        let mut rng = Rng::new(self.rng_seed);
        for index in 0..allocated {
            let Some((seed, mutation)) = self.case_at(index, &boundary, &mut rng) else {
                // Exactly as the send loop does: a case whose seed does not
                // build is rendered unsendable and the rest of the
                // allocation is still rendered, instead of the dry run
                // ending early and under-reporting what the job would send
                // (review finding P3).
                run.cases.push(self.unbuildable_case(index));
                continue;
            };
            let sent_hex = mutation
                .apply(&seed.spec, timing.max_raw_bytes)
                .ok()
                .and_then(|spec| spec.build().ok())
                .map(|bytes| hex_encode(&bytes))
                .unwrap_or_default();
            run.cases.push(CaseRecord::unsent(
                index,
                seed.id,
                vec![mutation.label()],
                sent_hex,
            ));
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

    /// The deterministic boundary table, read off the cached seed 0 so a point's
    /// case count does not depend on which seed a case cycles to.
    fn boundary_table(&self) -> Vec<Mutation> {
        boundary_cases(
            self.field,
            &self.seed0.spec,
            self.plan.target.framing.header_len(),
            self.shared.timing.max_raw_bytes,
        )
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

    /// The id of the seed case `index` cycles to, for a case whose seed does
    /// not build and so has no [`SeedSpec`] to read it from. Empty for a plan
    /// with no seed at all, which `seed_payloads` never produces.
    fn seed_id_at(&self, index: u32) -> String {
        let nth = usize::try_from(index).unwrap_or(usize::MAX);
        self.plan
            .seed_at(nth)
            .map_or_else(String::new, |seed| seed.id.clone())
    }

    /// The record for a case whose seed the builder refuses: it never went
    /// out, so it carries the id of the seed it cycles to, no mutation chain
    /// and no bytes. Shared by the send loop and the dry run so the two
    /// render one refused case the one way (review finding P3).
    fn unbuildable_case(&self, index: u32) -> CaseRecord {
        CaseRecord::unsent(index, self.seed_id_at(index), Vec::new(), String::new())
    }

    /// Stop the job's sending with `reason` (first stop wins) and report the
    /// counters, as call C1b requires of every stop this runner raises.
    fn stop(&self, reason: StopReason) {
        let job_id = self.job.job_id();
        // The lane's one `info!` line (its triage trail is all `debug` under
        // the same target): a stop reason names a cap, a deadline, a budget, a
        // wire or craft failure or an unavailable backend, never a payload
        // byte, and it is the only trace a core operator has by default of why
        // a packet job sent fewer cases than its profile asked for (the engine
        // records a check's error verdict nowhere else; T5 live proof, 4b).
        tracing::info!(
            target: "aitm::scanner::l4_packet",
            job = %job_id,
            point = %self.point.id,
            "packet lane stopped this point's run: {reason:?}"
        );
        self.shared.state.mark_stopped(job_id, reason);
        self.report(job_id);
    }

    /// Stop the job because `what` no longer builds, and hand back the reason
    /// the caller records. See [`craft_stop`].
    fn stop_on_craft(&self, what: &str, message: &str) -> StopReason {
        let reason = craft_stop(what, message);
        self.stop(reason.clone());
        reason
    }

    /// Hand the job's counters to the engine through the integration shim.
    fn report(&self, job_id: &str) {
        if let Some(counters) = self.shared.state.counters(job_id) {
            report_counters(self.job.as_ref(), counters);
        }
    }

    /// Whether this point is **ICMP-paced**: its baseline reply class is an
    /// ICMP error, so the target host's kernel — not a service — is what
    /// answers it (spec D8.4, amendment 46).
    ///
    /// On such a point the lane spaces every stimulus by
    /// [`Timing::icmp_pace_for`], records a silent case as
    /// `no_reply (icmp_ratelimit)`, spends no liveness probe on that silence
    /// and never raises a crash candidate: a closed port can never yield
    /// `l4-crash`.
    fn is_icmp_paced(&self) -> bool {
        matches!(*lock(&self.baseline), Some(CaseClass::Icmp { .. }))
    }

    /// Wait until this point's pace has elapsed since its previous stimulus,
    /// for an ICMP-paced point (spec amendment 46).
    ///
    /// Bounded by the job's deadline: the wait never runs past it, and the
    /// caller's own deadline check raises the [`StopReason::Deadline`] stop, so
    /// the pace adds no new failure path. A point that has sent nothing yet,
    /// one whose baseline is not an ICMP error, and a zero pace all return at
    /// once.
    async fn pace_icmp_point(&self) {
        if !self.is_icmp_paced() {
            return;
        }
        let pace = self.shared.timing.icmp_pace_for(&self.job.profile().l4);
        if pace.is_zero() {
            return;
        }
        let Some(last) = *lock(&self.last_stimulus_at) else {
            return;
        };
        let now = Instant::now();
        let due = last + pace;
        if due <= now {
            return;
        }
        let left = self.job.deadline().saturating_duration_since(now);
        tokio::time::sleep((due - now).min(left)).await;
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
        request_field: FieldPath,
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
        let mut record = CaseRecord::unsent(index, seed_id.to_string(), chain, hex_encode(&bytes));
        if !is_decodable(&bytes) {
            if counted == Counted::Case {
                // An undecodable case is counted apart as unsendable and leaves
                // the stop ladder alone.
                self.shared.state.record_unsendable(&job_id);
            }
            return Ok(Delivery {
                sent: Sent {
                    record,
                    reply: Vec::new(),
                },
                stop: None,
            });
        }

        // (c) The job's case ceiling bounds every counted case, not only the
        // fuzz loop's and the triage's: a `Check` replaying frames through
        // `PacketHost::probe` spends the same ceiling (spec D8.4, "cases per
        // job <= 5000"; review finding G2).
        if counted == Counted::Case && self.shared.state.cases_remaining(&job_id) == Some(0) {
            let cap = self.shared.state.cases_cap(&job_id).unwrap_or(0);
            let reason = StopReason::CaseCap(cap);
            self.stop(reason.clone());
            return Err(HostError::Stopped(reason));
        }

        // (d) One stimulus, one budget unit — the case, not the attempt: a
        // rate wait below retries without charging again.
        if !self.job.charge(1) {
            self.stop(StopReason::Budget);
            return Err(HostError::Stopped(StopReason::Budget));
        }

        // (e) The pace of an ICMP-paced point (spec amendment 46), then the
        // guarded send, waiting out the guard's injection rate.
        self.pace_icmp_point().await;
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
            *lock(&self.last_stimulus_at) = Some(started);
            match self
                .send_blocking(spec.clone(), timeout, request_field)
                .await
            {
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
                // The stimulus was charged at (d) and never reached the wire:
                // the send path is broken, so the job stops on it rather than
                // running on and reporting a clean point (review finding Q1).
                Err(L4Error::WireWrite(message)) => {
                    let reason = StopReason::WireWrite(message);
                    self.stop(reason.clone());
                    return Err(HostError::Stopped(reason));
                }
            }
        };

        // (f) The oracle reads the reply, and the ladder gets its say — after
        // the record exists, so the tripping case is never lost.
        let classified = classify(&outcome, elapsed);
        record.outcome = CaseOutcome::Sent {
            class: classified.class,
            elapsed_ms: classified.elapsed_ms,
            latency_outlier: false,
        };
        // Silence on an ICMP-paced point is the target host's ICMP rate
        // limiter, not a service that stopped answering: it is recorded as
        // `no_reply (icmp_ratelimit)` and judged no further (amendment 46).
        if classified.class == CaseClass::Silence && self.is_icmp_paced() {
            record.note = Some(CaseNote::IcmpRatelimit);
        }
        let stop = if counted == Counted::Case {
            self.shared
                .state
                .record_case(&job_id, classified.class)
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
        request_field: FieldPath,
    ) -> Result<SendRecvOutcome, L4Error> {
        let guard = Arc::clone(&self.shared.guard);
        let backend = Arc::clone(&self.shared.backend);
        let store = Arc::clone(&self.shared.case_store);
        let request = send_recv_spec(&self.plan.target, spec, request_field, timeout);
        match tokio::task::spawn_blocking(move || send_recv(&guard, backend, store, request)).await
        {
            Ok(result) => result.map(|(_flow, outcome)| outcome),
            Err(err) => Err(L4Error::Unavailable(join_error_message(&err))),
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
        //
        // Its correlation pins `dst_port`, as the probes read against it do and
        // whatever field this point fuzzes: the baseline sends seed 0, whose
        // transport header is intact, so the strict pin is always possible and
        // correct. Only a mutated case may need the looser rule its field
        // dictates. With `self.field` a point that does not preserve the
        // transport would take its yardstick from a loose correlation, and an
        // unrelated frame from another port of the same host could become the
        // baseline class (review finding SEC4).
        let seed = self.seed0.clone();
        match self
            .deliver(
                seed.spec,
                &seed.id,
                vec!["baseline".to_string()],
                0,
                Counted::Probe,
                FieldPath::Raw,
            )
            .await
        {
            Ok(delivered) => {
                run.baseline = delivered.sent.record.class();
                *lock(&self.baseline) = run.baseline;
            }
            Err(HostError::Stopped(reason)) => {
                run.stopped = Some(reason);
                return run;
            }
            // Seed 0 was built once in `PointRunner::new` and the built
            // spec is cached, so this is unreachable: `build()` is pure and
            // never consults the guard. If it is ever reached the job stops
            // rather than reporting a point that sent nothing (finding N5).
            Err(HostError::Craft(message)) => {
                run.stopped = Some(self.stop_on_craft(SEED0, &message));
                return run;
            }
        }

        let timing = self.shared.timing;
        let options = &self.job.profile().l4;
        let (liveness_every, reproduce_count) = (options.liveness_every, options.reproduce_count);
        let allocated = self.shared.state.allocate_cases(job_id).unwrap_or(0);
        let boundary = self.boundary_table();
        let mut rng = Rng::new(self.rng_seed);
        let mut latency = LatencyWindow::new();
        let mut sent_cases: u32 = 0;
        // Every case starts from the most recent liveness verdict; the baseline
        // answering at all is the first one.
        let mut alive = true;

        for index in 0..allocated {
            // The ceiling is job-wide and this point's triage spends from it
            // too, so it is re-read every case: a replay shrinks the loop
            // instead of making the next case trip the cap job-wide (review
            // finding Q2). Running out here is the allocation ending, not a
            // stop (tester finding on the last loop case).
            if self.shared.state.cases_remaining(job_id) == Some(0) {
                break;
            }
            let liveness_before = alive;
            let Some((seed, mutation)) = self.case_at(index, &boundary, &mut rng) else {
                // Discovery builds every seed, so a case whose seed does not
                // build should not exist. If one does it is counted apart as
                // unsendable and recorded, exactly as a case the builder
                // refuses, instead of ending the run in silence (tester
                // finding T1).
                self.shared.state.record_unsendable(job_id);
                run.cases.push(self.unbuildable_case(index));
                continue;
            };
            let chain = vec![mutation.label()];
            let Ok(spec) = mutation.apply(&seed.spec, timing.max_raw_bytes) else {
                // A case that cannot even be rendered is unsendable, exactly as
                // one the wire would refuse: counted apart, never charged.
                self.shared.state.record_unsendable(job_id);
                run.cases
                    .push(CaseRecord::unsent(index, seed.id, chain, String::new()));
                continue;
            };

            let delivered = match self
                .deliver(
                    spec.clone(),
                    &seed.id,
                    chain.clone(),
                    index,
                    Counted::Case,
                    self.field,
                )
                .await
            {
                Ok(delivered) => delivered,
                Err(HostError::Stopped(reason)) => {
                    run.stopped = Some(reason);
                    break;
                }
                // A case the builder refused never went out: it is recorded as
                // an unsendable case, exactly as one `mutation.apply` could not
                // render, instead of vanishing from the run (review finding Q1).
                Err(HostError::Craft(_)) => {
                    self.shared.state.record_unsendable(job_id);
                    run.cases
                        .push(CaseRecord::unsent(index, seed.id, chain, String::new()));
                    continue;
                }
            };
            let mut record = delivered.sent.record;
            let stop = delivered.stop;
            // An unsent case (undecodable) carries no reaction; it is logged and
            // the loop moves on (review finding M2).
            let CaseOutcome::Sent {
                class, elapsed_ms, ..
            } = record.outcome
            else {
                run.cases.push(record);
                continue;
            };
            sent_cases += 1;
            if class == CaseClass::Clean {
                latency.record(elapsed_ms);
                record.outcome = CaseOutcome::Sent {
                    class,
                    elapsed_ms,
                    latency_outlier: latency.is_outlier(elapsed_ms),
                };
            }

            if class.is_candidate() {
                tracing::debug!(
                    target: "aitm::scanner::l4_packet",
                    job = %job_id,
                    point = %self.point.id,
                    index,
                    class = %class.label(),
                    liveness_before,
                    icmp_paced = self.is_icmp_paced(),
                    stopped = stop.is_some(),
                    "candidate case"
                );
            }

            // An ICMP-baseline point never spends a liveness probe on a
            // candidate class and never becomes a crash: the kernel's reaction
            // proves classification, never a crash (spec D8.4, amendment 46).
            if class.is_candidate() && stop.is_none() && !self.is_icmp_paced() {
                // A pair a stop cut short is read as the stop it is, before
                // any verdict is taken off it (review finding P1).
                let (first, second) = match self.probe_pair(false).await {
                    Ok(pair) => pair,
                    Err(reason) => {
                        record.candidate = Candidate::Interrupted {
                            stop: reason.clone(),
                        };
                        run.cases.push(record);
                        run.stopped = Some(reason);
                        break;
                    }
                };
                alive = first || second;
                // Both probes failed, so this case is a candidate.
                if !first && !second {
                    if reproduce_count == 0 {
                        // `reproduce_count: 0` asks for no replay at all, and
                        // spec call 14 confirms a crash only on a
                        // reproduction. So the triage never runs, the
                        // candidate is never confirmed — no crash, no
                        // retirement, no stop — and the loop goes on to the
                        // next case, leaving the unjudged candidate for
                        // `checks::CrashCheck` to report as inconclusive
                        // (review finding G1).
                        record.candidate = Candidate::Unjudged;
                    } else {
                        let triage = self
                            .triage(&spec, &seed.id, &chain, index, reproduce_count)
                            .await;
                        // A triage any stop cut short proves nothing: the
                        // point keeps its candidate case, the run ends on the
                        // stop and no crash is recorded or retired (tester
                        // finding F1). `checks::CrashCheck` surfaces the
                        // unconfirmed candidate as inconclusive.
                        if let Some(reason) = triage.stop {
                            tracing::debug!(
                                target: "aitm::scanner::l4_packet",
                                job = %job_id,
                                point = %self.point.id,
                                index,
                                attempts = triage.attempts,
                                reproduced = triage.reproduced,
                                stop = ?reason,
                                "crash decision: none, the triage was cut short"
                            );
                            record.candidate = Candidate::Interrupted {
                                stop: reason.clone(),
                            };
                            run.cases.push(record);
                            run.stopped = Some(reason);
                            break;
                        }
                        let crashed = !triage.recovered
                            || (triage.attempts == reproduce_count
                                && triage.reproduced == triage.attempts);
                        tracing::debug!(
                            target: "aitm::scanner::l4_packet",
                            job = %job_id,
                            point = %self.point.id,
                            index,
                            crashed,
                            recovered = triage.recovered,
                            attempts = triage.attempts,
                            reproduced = triage.reproduced,
                            reproduce_count,
                            "crash decision"
                        );
                        record.candidate = if crashed {
                            Candidate::Confirmed {
                                reproduced: triage.reproduced,
                                attempts: triage.attempts,
                            }
                        } else {
                            // The triage ran and the candidate did not come
                            // back: that is the lane's answer, and no later
                            // stop reopens it (review finding Q2).
                            Candidate::NotReproduced {
                                reproduced: triage.reproduced,
                                attempts: triage.attempts,
                            }
                        };
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
                            break;
                        }
                    }
                }
            }

            run.cases.push(record);
            if let Some(reason) = stop {
                // The consecutive-timeout ladder marks the job stopped inside
                // `record_case`, never through `PointRunner::stop`, so this
                // line is the only trace such a stop leaves (T5 live proof, 4b).
                tracing::debug!(
                    target: "aitm::scanner::l4_packet",
                    job = %job_id,
                    point = %self.point.id,
                    index,
                    sent_cases,
                    stop = ?reason,
                    "the case's own stop ended this point's run"
                );
                run.stopped = Some(reason);
                break;
            }

            // The scheduled probe runs after every `liveness_every` sent cases
            // whatever the oracle said (spec D8.4).
            if liveness_every > 0 && sent_cases.is_multiple_of(liveness_every) {
                match self.liveness_probe().await {
                    Ok(passed) => {
                        tracing::debug!(
                            target: "aitm::scanner::l4_packet",
                            job = %job_id,
                            point = %self.point.id,
                            index,
                            sent_cases,
                            liveness_every,
                            passed,
                            "scheduled liveness probe"
                        );
                        alive = passed;
                    }
                    Err(HostError::Stopped(reason)) => {
                        run.stopped = Some(reason);
                        break;
                    }
                    Err(HostError::Craft(message)) => {
                        run.stopped = Some(self.stop_on_craft(SEED0, &message));
                        break;
                    }
                }
            }
        }

        // The class histogram and the mean reply wait, so a rig log says what
        // the cases were answered with and how fast (labels and counts only).
        let mut classes: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut elapsed_total: u64 = 0;
        for case in &run.cases {
            let label = case
                .class()
                .map_or_else(|| "unsent".to_string(), |class| class.label());
            *classes.entry(label).or_insert(0) += 1;
            elapsed_total = elapsed_total.saturating_add(u64::from(case.elapsed_ms()));
        }
        let mean_elapsed_ms = elapsed_total
            .checked_div(run.cases.len() as u64)
            .unwrap_or(0);
        tracing::debug!(
            target: "aitm::scanner::l4_packet",
            job = %job_id,
            point = %self.point.id,
            sent_cases,
            allocated,
            cases = run.cases.len(),
            classes = ?classes,
            mean_elapsed_ms,
            stopped = run.stopped.is_some(),
            crash = run.crash.is_some(),
            "point run finished"
        );

        run
    }

    /// The two liveness probes a candidate costs: the second only when the
    /// first failed, unless `always` (after a replay, where both verdicts are
    /// part of the reproduction criterion).
    ///
    /// A probe the builder refused never went out, so it is a stop, not a
    /// verdict (review findings Q1 and P1): a pair any stop cut
    /// short carries no bools at all, so no caller can read one as a failed
    /// probe and start — or count — a reproduction on evidence that does not
    /// exist. A failed wire write is a stop and propagates as one.
    ///
    /// # Errors
    /// The [`StopReason`] that cut the pair short, whether the job stopped
    /// under it or the builder refused a probe.
    async fn probe_pair(&self, always: bool) -> Result<(bool, bool), StopReason> {
        let first = match self.liveness_probe().await {
            Ok(passed) => passed,
            Err(HostError::Stopped(reason)) => return Err(reason),
            Err(HostError::Craft(message)) => return Err(self.stop_on_craft(SEED0, &message)),
        };
        if first && !always {
            tracing::debug!(
                target: "aitm::scanner::l4_packet",
                job = %self.job.job_id(),
                point = %self.point.id,
                always,
                first,
                retried = false,
                "liveness pair: the first probe passed, so no retry"
            );
            return Ok((true, true));
        }
        tokio::time::sleep(self.shared.timing.liveness_retry).await;
        match self.liveness_probe().await {
            Ok(second) => {
                tracing::debug!(
                    target: "aitm::scanner::l4_packet",
                    job = %self.job.job_id(),
                    point = %self.point.id,
                    always,
                    first,
                    second,
                    retried = true,
                    "liveness pair"
                );
                Ok((first, second))
            }
            Err(HostError::Stopped(reason)) => Err(reason),
            Err(HostError::Craft(message)) => Err(self.stop_on_craft(SEED0, &message)),
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
            recovered: true,
            attempts: 0,
            reproduced: 0,
            stop: None,
        };
        // The candidate left the target silent, so the first replay always
        // waits for it.
        let mut alive = false;
        for round in 1..=reproduce_count {
            // A replay is a case (call C10), so the job's ceiling bounds it
            // exactly as it bounds the fuzz loop: with no room left there is
            // no reproduction to be had, and the triage stops before it even
            // waits for the target (tester finding F2). Per finding F1 an
            // interrupted triage is not a crash.
            let job_id = self.job.job_id();
            if self.shared.state.cases_remaining(job_id) == Some(0) {
                let cap = self.shared.state.cases_cap(job_id).unwrap_or(0);
                let reason = StopReason::CaseCap(cap);
                self.stop(reason.clone());
                tracing::debug!(
                    target: "aitm::scanner::l4_packet",
                    job = %job_id,
                    point = %self.point.id,
                    round,
                    attempts = triage.attempts,
                    reproduced = triage.reproduced,
                    "triage decision: stop, the case ceiling left no room for this replay"
                );
                triage.stop = Some(reason);
                return triage;
            }
            let waited_for_recovery = !alive;
            let wait_started = Instant::now();
            if !alive {
                match self.await_recovery().await {
                    // The replay below sets `alive` from its own probes.
                    Ok(true) => {}
                    // A target that never answers again — the whole recovery
                    // bound polled, every probe failed — is the strongest
                    // evidence there is; stop replaying into it.
                    Ok(false) => {
                        triage.recovered = false;
                        tracing::debug!(
                            target: "aitm::scanner::l4_packet",
                            job = %job_id,
                            point = %self.point.id,
                            round,
                            attempts = triage.attempts,
                            reproduced = triage.reproduced,
                            waited_ms = elapsed_ms(wait_started),
                            "triage decision: recovered=false, the outage is persistent"
                        );
                        return triage;
                    }
                    Err(HostError::Stopped(reason)) => {
                        tracing::debug!(
                            target: "aitm::scanner::l4_packet",
                            job = %job_id,
                            point = %self.point.id,
                            round,
                            attempts = triage.attempts,
                            reproduced = triage.reproduced,
                            stop = ?reason,
                            "triage decision: stop, the job stopped while waiting for recovery"
                        );
                        triage.stop = Some(reason);
                        return triage;
                    }
                    Err(HostError::Craft(message)) => {
                        triage.stop = Some(self.stop_on_craft(SEED0, &message));
                        return triage;
                    }
                }
            } else {
                // The previous replay did not reproduce the candidate, so its
                // probe pair passed and no recovery wait spaced this one. Space
                // it by `replay_spacing` instead (spec D8.4 "spaced 1 s"); the
                // reproducing path is spaced by the recovery poll (finding S1).
                let now = Instant::now();
                let deadline = self.job.deadline();
                let spacing = self
                    .shared
                    .timing
                    .replay_spacing
                    .min(deadline.saturating_duration_since(now));
                tokio::time::sleep(spacing).await;
            }
            // Named for what it measures: the recovery wait when
            // `waited_for_recovery`, the `replay_spacing` sleep otherwise
            // (quality panel Minor).
            let paused_ms = elapsed_ms(wait_started);
            triage.recovered = true;
            let delivered = match self
                .deliver(
                    spec.clone(),
                    seed_id,
                    chain.to_vec(),
                    index,
                    Counted::Case,
                    self.field,
                )
                .await
            {
                Ok(delivered) => delivered,
                Err(HostError::Stopped(reason)) => {
                    tracing::debug!(
                        target: "aitm::scanner::l4_packet",
                        job = %self.job.job_id(),
                        point = %self.point.id,
                        round,
                        attempts = triage.attempts,
                        reproduced = triage.reproduced,
                        stop = ?reason,
                        "triage decision: stop, the replay never went out"
                    );
                    triage.stop = Some(reason);
                    return triage;
                }
                // Not seed 0: the case's own spec, which `deliver` already
                // built once before this replay (finding N5).
                Err(HostError::Craft(message)) => {
                    triage.stop = Some(self.stop_on_craft("the replayed case", &message));
                    return triage;
                }
            };
            // Only a replay that actually went out is an attempt: a `deliver`
            // the charge or the wire refused never reached the target, so it is
            // counted (above, as a stop) but is not a reproduction attempt
            // (round-1 leftover).
            triage.attempts += 1;
            let class = delivered.sent.record.class();
            let candidate = class.is_some_and(|class| class.is_candidate());
            tracing::debug!(
                target: "aitm::scanner::l4_packet",
                job = %self.job.job_id(),
                point = %self.point.id,
                round,
                attempt = triage.attempts,
                waited_for_recovery,
                paused_ms,
                class = %class_label(class),
                candidate,
                "triage replay sent"
            );
            // A pair a stop cut short never finished, so it is read as the
            // stop it is and no reproduction is counted off it (review
            // finding P1).
            let (first, second) = match self.probe_pair(true).await {
                Ok(pair) => pair,
                Err(reason) => {
                    tracing::debug!(
                        target: "aitm::scanner::l4_packet",
                        job = %self.job.job_id(),
                        point = %self.point.id,
                        round,
                        attempts = triage.attempts,
                        reproduced = triage.reproduced,
                        stop = ?reason,
                        "triage decision: stop, the probe pair after the replay was cut short"
                    );
                    triage.stop = Some(reason);
                    return triage;
                }
            };
            alive = first || second;
            if candidate && !first && !second {
                triage.reproduced += 1;
            }
            tracing::debug!(
                target: "aitm::scanner::l4_packet",
                job = %self.job.job_id(),
                point = %self.point.id,
                round,
                first,
                second,
                candidate,
                attempts = triage.attempts,
                reproduced = triage.reproduced,
                "triage replay judged"
            );
            if let Some(reason) = delivered.stop {
                // The replay's own case tripped the ladder (a reproducing
                // replay is silent, and a probe is not a case, so nothing
                // resets it). The triage is cut short and is never a crash
                // however many replays reproduced (tester finding F1).
                tracing::debug!(
                    target: "aitm::scanner::l4_packet",
                    job = %self.job.job_id(),
                    point = %self.point.id,
                    round,
                    attempts = triage.attempts,
                    reproduced = triage.reproduced,
                    stop = ?reason,
                    "triage decision: stop, the replay's own case ended the job's sending"
                );
                triage.stop = Some(reason);
                return triage;
            }
        }
        tracing::debug!(
            target: "aitm::scanner::l4_packet",
            job = %self.job.job_id(),
            point = %self.point.id,
            attempts = triage.attempts,
            reproduced = triage.reproduced,
            recovered = triage.recovered,
            reproduce_count,
            "triage finished"
        );
        triage
    }

    /// Poll liveness until the target answers again or the bound runs out.
    ///
    /// `Ok(false)` is reserved for the persistent outage: all
    /// `recovery_polls` probes ran and all of them failed. A wait the job's
    /// deadline cuts short is a [`StopReason::Deadline`] stop, because the
    /// target was never given the recovery bound call C27 measures it against
    /// (tester finding F1).
    ///
    /// # Errors
    /// [`HostError::Stopped`] when the job stopped while waiting, including
    /// when this wait is what ran it past its deadline.
    async fn await_recovery(&self) -> Result<bool, HostError> {
        let timing = self.shared.timing;
        let started = Instant::now();
        for attempt in 0..timing.recovery_polls {
            if Instant::now() >= self.job.deadline() {
                self.stop(StopReason::Deadline);
                return Err(HostError::Stopped(StopReason::Deadline));
            }
            let passed = self.liveness_probe().await?;
            tracing::debug!(
                target: "aitm::scanner::l4_packet",
                job = %self.job.job_id(),
                point = %self.point.id,
                attempt = attempt + 1,
                polls = timing.recovery_polls,
                passed,
                elapsed_ms = elapsed_ms(started),
                "recovery poll"
            );
            if passed {
                return Ok(true);
            }
            if attempt + 1 < timing.recovery_polls {
                tokio::time::sleep(timing.recovery_poll).await;
            }
        }
        tracing::debug!(
            target: "aitm::scanner::l4_packet",
            job = %self.job.job_id(),
            point = %self.point.id,
            polls = timing.recovery_polls,
            elapsed_ms = elapsed_ms(started),
            "recovery bound ran out: the target answered none of its polls"
        );
        Ok(false)
    }
}

/// What [`craft_stop`] calls the lane's one cached seed.
const SEED0: &str = "seed 0";

/// A class's label for a debug line, or `none` for a stimulus that never went
/// out. The lane's tracing names a class, a count or a verdict — never a byte
/// of the stimulus or of the reply (T5 live proof, 4b).
fn class_label(class: Option<CaseClass>) -> String {
    class.map_or_else(|| "none".to_string(), |class| class.label())
}

/// Milliseconds since `since`, saturated, for a debug line's `*_ms` field.
fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The stop a craft failure raises: `what` no longer builds, so the stimulus
/// never reached the wire and the run cannot be read as a clean one (review
/// finding Q1). One mapping for every site, so none of them can answer a
/// craft failure differently from the others (review finding N5).
///
/// Nothing reachable produces one. Seed 0 is built once in
/// [`PointRunner::new`] and the built spec is cached; a case is built by its
/// first `deliver` before any replay reuses it; and `PacketSpec::build` is
/// pure — it never consults the `L4Guard`, so no mid-job ceiling change can
/// make it start failing. The arms exist because the error type admits the
/// case, and this says what the lane does with it.
fn craft_stop(what: &str, message: &str) -> StopReason {
    StopReason::Unavailable(format!("{what} no longer builds: {message}"))
}

/// The `L4Error::Unavailable` message for a `send_recv` task that did not
/// return a value: a panic is called out distinctly from a cancelled or aborted
/// task, so the stop ladder's `Unavailable` reason tells the two apart (review
/// finding M8).
fn join_error_message(err: &tokio::task::JoinError) -> String {
    if err.is_panic() {
        format!("send_recv panicked: {err}")
    } else {
        format!("the send_recv task did not finish: {err}")
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
        elapsed_ms: sent.record.elapsed_ms(),
        flow: None,
        ws_frames: None,
        l4: sent
            .record
            .class()
            .and_then(|class| class.oracle())
            .map(|oracle| L4Reply {
                bytes: sent.reply.clone(),
                oracle,
                elapsed_ms: sent.record.elapsed_ms(),
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
    baseline: tokio::sync::OnceCell<ProbeResponse>,
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
            baseline: tokio::sync::OnceCell::new(),
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
            let response = self
                .baseline
                .get_or_try_init(|| async {
                    let seed = self.runner.seed0.clone();
                    let sent = self
                        .runner
                        .send_spec(seed.spec, &seed.id, vec!["baseline".to_string()], 0)
                        .await?;
                    Ok::<_, anyhow::Error>(response_for(&sent))
                })
                .await?;
            Ok(response.clone())
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let Some(bytes) = payload.bytes.clone() else {
                return Err(anyhow::anyhow!("the packet lane replays frame bytes only"));
            };
            // A replay goes out verbatim, so before it does the frame's own
            // destination is read back and must be this point's target: the
            // packet lane never replays a frame aimed anywhere else, even at
            // another loopback port the Inject scope happens to cover (review
            // finding SEC4). `PointRunner::replay` then pins `dst_port` for the
            // reply correlation whatever field this point fuzzes.
            let target = &self.runner.plan.target;
            let ends = PacketSpec::endpoints(&bytes);
            if ends.dst != Some(target.ip) || ends.dst_port != Some(target.port) {
                return Err(anyhow::anyhow!(
                    "the packet lane replays frames to its own target only: got {}:{}",
                    ends.dst
                        .map_or_else(|| "none".to_string(), |ip| ip.to_string()),
                    ends.dst_port
                        .map_or_else(|| "none".to_string(), |port| port.to_string()),
                ));
            }
            let spec = PacketSpec {
                layers: vec![Layer::Raw(bytes)],
            };
            // The seed id is the one the runner already owns, not a packet
            // rebuilt from the plan (review findings M8/N4).
            let seed_id = self.runner.seed0.id.clone();
            let sent = self
                .runner
                .replay(spec, &seed_id, vec![payload.value.clone()], 0)
                .await?;
            Ok(response_for(&sent))
        })
    }

    fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async { Err(anyhow::anyhow!("the packet lane hosts no raw HTTP probes")) })
    }

    /// **This is not a marker.** It returns the engine's stable, unique **job
    /// id**, because that is the key `Lane::probe_host_for` registered this
    /// point's runner under in the [`RunnerRegistry`] and `resolve_run` has
    /// only this `&dyn ProbeHost` to find it by. [`JobCtx::marker`] itself is a
    /// reflection canary that mints a fresh token on every call (its trait doc
    /// and `aitm_plugin_scanner::worker`), so keying by it would have a check
    /// look the runner up under a different token than it was registered under
    /// and read `missing_runner`: zero cases, nothing on the wire (T5 live
    /// proof, 4b). A check that wants a canary from an L4 host therefore gets a
    /// job id instead; the lane's own two checks never ask for one.
    ///
    /// T1b follow-up 57: `JobCtx::marker` documented as fresh-per-call plus a
    /// stable `job_id()` key; once the lane keys on `job_id()` directly this
    /// method's registry role goes away and it can return the engine's marker
    /// again (quality panel Minor).
    fn marker(&self) -> String {
        self.runner.job.job_id().to_string()
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

    /// The job's budgeted client, lent for a bridge send (amendment 72b).
    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        Some(self.runner.job.client())
    }

    /// `None`: a packet point is crafted from a seed, never from a captured
    /// HTTP flow.
    fn captured(&self) -> Option<aitm_core::HttpFlow> {
        None
    }

    /// Debited against the one job budget, like every injected frame.
    fn charge(&self, units: u32) -> bool {
        self.runner.job.charge(units)
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        // Every case is recorded in the lane-private L4 store, not as an HTTP
        // flow; there is nothing for the engine to re-record.
        Vec::new()
    }
}

/// The runners of every point the lane is driving, keyed by `(job id, point
/// id)` so a check finds the one run of a point without downcasting the
/// `&dyn ProbeHost` it was handed (plan call C2). The job id is the engine's
/// stable, unique [`JobCtx::job_id`], never its per-call [`JobCtx::marker`]
/// canary — keying by the marker made every real-bus job send nothing
/// (T5 live proof, 4b).
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

    /// Remember `runner` as the one runner for this job and point, and hand
    /// back the runner this point now has. `job_id` is the engine's stable
    /// [`JobCtx::job_id`], never its per-call [`JobCtx::marker`] canary
    /// (T5 live proof, 4b).
    ///
    /// Idempotent: a point already registered keeps its runner and `runner` is
    /// dropped, so two hosts for one point share one `PointRunner` and
    /// therefore one idempotent [`PointRunner::run_point`] — never two runs of
    /// the same point against the same job (review finding Q3).
    pub fn register(
        &self,
        job_id: &str,
        point_id: &str,
        runner: Arc<PointRunner>,
    ) -> Arc<PointRunner> {
        Arc::clone(
            lock(&self.runners)
                .entry((job_id.to_string(), point_id.to_string()))
                .or_insert(runner),
        )
    }

    /// The runner for this job and point, if one was registered.
    #[must_use]
    pub fn get(&self, job_id: &str, point_id: &str) -> Option<Arc<PointRunner>> {
        lock(&self.runners)
            .get(&(job_id.to_string(), point_id.to_string()))
            .map(Arc::clone)
    }

    /// Drop every runner of one job, once its job id is done with.
    pub fn forget_job(&self, job_id: &str) {
        lock(&self.runners).retain(|(known, _), _| known != job_id);
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
    use std::collections::VecDeque;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime};

    use aitm_proto_l4::backend::{CaptureInjectBackend, CaptureSource, L4Error};
    use aitm_proto_l4::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use aitm_proto_l4::flow::L4Packet;
    use aitm_proto_l4::icmp::transport_payload;
    use aitm_proto_l4::types::L4Direction;
    use aitm_scan_model::{JobCtx, L4Counters, L4Options, Payload, PayloadMode, ProbeHost};

    use super::{
        craft_stop, join_error_message, HostError, PacketHost, PointRunner, RunnerRegistry, Shared,
        Timing,
    };
    use crate::codec::hex_encode;
    use crate::discover::max_payload_for;
    use crate::fields::{FieldPath, UdpField};
    use crate::oracle::CaseClass;
    use crate::plan::{send_recv_spec, SeedOrigin, SeedPayload};
    use crate::state::{Candidate, CaseNote, StopReason};
    use crate::sync::lock;
    use crate::testing::harness::{runner_for, setup};
    use crate::testing::{
        fields, l4_profile, tcp_target, udp_target, with_hex_seed, MockBackend, MockReply,
    };

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

    /// Amendment 72b: `client`, `charge` and `captured` are required, and the
    /// packet host answers them from its runner's job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_packet_host_lends_the_job_client_and_debits_its_budget() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let host = PacketHost::new(runner);

        let lent = host
            .client()
            .expect("the packet host lends the job's client");
        assert!(
            Arc::ptr_eq(&lent, &job.client()),
            "the host lends the job's own budgeted client, not a second one"
        );
        assert!(host.charge(2), "two units are affordable");
        assert_eq!(job.charged(), 2, "the charge reaches the job's budget");
        assert!(
            host.captured().is_none(),
            "a packet point came from no captured HTTP flow"
        );
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
                .all(|case| case.class() == Some(CaseClass::Clean)),
            "every case is clean: {:?}",
            run.cases.iter().map(|c| c.class()).collect::<Vec<_>>()
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
        assert!(run.cases.iter().all(|case| case.class() == Some(icmp)));
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

        let started = Instant::now();
        let run = runner.run_point().await;
        // Two of the three replays follow a passing probe pair, so each is
        // spaced by `replay_spacing` (10 ms here); the run cannot finish in
        // under two of them (review finding S1, a generous lower bound).
        assert!(
            started.elapsed() >= 2 * shared.timing.replay_spacing,
            "the spaced replays took {:?}",
            started.elapsed()
        );

        assert_eq!(
            run.cases[1].candidate,
            Candidate::NotReproduced {
                reproduced: 0,
                attempts: 3,
            }
        );
        assert!(run.crash.is_none());
        assert_eq!(
            shared
                .state
                .counters(job.job_id())
                .expect("counters")
                .crashes,
            0
        );
        // The three replays are cases of this job (call C10), so they come
        // out of the same ceiling of ten: the fuzz loop gets seven of them
        // and the triage the other three (spec D8.4; review finding G2 —
        // before it the triage spent its replays on top of the ceiling and
        // the job sent thirteen cases against a cap of ten). The loop re-reads
        // the ceiling every case, so the eighth is never asked for and the
        // point ends cleanly instead of stopping the whole job on the cap
        // (review finding Q2 — before it this run stopped on `CaseCap(10)`).
        assert_eq!(run.cases.len(), 7, "{:?}", run.cases);
        assert_eq!(run.stopped, None);
        assert_eq!(shared.state.stopped(job.job_id()), None);
        assert_eq!(
            shared.state.counters(job.job_id()).expect("counters").cases,
            10
        );
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(0));
        // 1 baseline + 7 cases + 2 failed probes + 1 recovery poll + 3 x (replay + 2 probes).
        assert_eq!(mock.inject_count(), 1 + 7 + 2 + 1 + 3 * 3);
    }

    /// Review finding G1: with `reproduce_count: 0` no replay can ever run,
    /// and the spec's call 14 confirms a crash only on a reproduction. The
    /// candidate is left unconfirmed — no crash, no retirement, no stop — and
    /// the fuzz loop goes on to the next case; `checks::CrashCheck` reports
    /// the candidate as inconclusive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reproduce_count_zero_never_confirms() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let mut profile = with_hex_seed(l4_profile(vec![udp_target(9)], 10), "deadbeef0000");
        profile.l4.reproduce_count = 0;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert!(
            run.crash.is_none(),
            "nothing was reproduced, so nothing is a crash: {:?}",
            run.crash
        );
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 10,
                crashes: 0,
                liveness_failures: 16,
                retired_elements: 0,
            })
        );
        // Eight of the ten cases carry the pattern that kills the target,
        // and every one of them was left unconfirmed: two failed probes each,
        // and the run carried on to the next case every time.
        assert_eq!(
            run.cases
                .iter()
                .filter(|case| matches!(case.candidate, Candidate::Unjudged))
                .map(|case| case.chain.join(";"))
                .collect::<Vec<_>>(),
            [
                "grow:8",
                "grow:12",
                "grow:16",
                "grow:64",
                "grow:256",
                "grow:1024",
                "grow:1472",
                "grow:8:repeat"
            ]
        );
        assert!(!shared.state.is_retired(job.job_id(), &run.point_id));
        assert_eq!(run.cases.len(), 10, "the loop ran on: {:?}", run.cases);
        let candidate = run
            .cases
            .iter()
            .find(|case| case.chain == vec!["grow:8".to_string()])
            .expect("the grow:8 case");
        assert_eq!(candidate.candidate, Candidate::Unjudged);
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
            .all(|case| case.class() == Some(CaseClass::Clean)));
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
            assert!(!case.sent());
            assert_eq!(case.class(), None);
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
            assert!(!case.sent(), "{label} cannot be put on the wire");
        }
        let stats = shared.state.stats(job.job_id()).expect("stats");
        // Every one of the eight `ipv4.ihl` cases garbles the header length, so
        // none decodes to an IP packet and none can be sent (review finding M8).
        assert_eq!(stats.cases_unsendable, 8);
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
        // The host's `marker()` is the registry key: the stable job id, never
        // the engine's per-call marker canary (T5 live proof, 4b).
        assert_eq!(host.marker(), "scan-1a2b3c4d");
        assert_eq!(host.marker(), job.job_id());

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

    /// Review finding M8: a `send_recv` task that panicked is reported with a
    /// message distinct from one that was cancelled or aborted, so the stop
    /// ladder's `Unavailable` reason tells the two apart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn join_error_message_calls_out_a_panic() {
        let panicked = tokio::spawn(async { panic!("send_recv blew up") })
            .await
            .expect_err("the task panicked");
        assert!(panicked.is_panic());
        assert!(
            join_error_message(&panicked).starts_with("send_recv panicked:"),
            "{}",
            join_error_message(&panicked)
        );

        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let cancelled = handle.await.expect_err("the task was aborted");
        assert!(!cancelled.is_panic());
        assert!(
            join_error_message(&cancelled).starts_with("the send_recv task did not finish:"),
            "{}",
            join_error_message(&cancelled)
        );
    }

    /// Review finding SEC4: a replay is pinned to the point's own target, so a
    /// frame addressed to any other port — even one the loopback Inject scope
    /// covers — is refused before it reaches the wire, and nothing is charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_refuses_a_frame_aimed_at_another_port() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let host = PacketHost::new(Arc::clone(&runner));

        // A well-formed frame to 127.0.0.1:10, a port the "*" loopback scope
        // covers but this point never targets (its target is :9).
        let mut wrong = plans[0].target.clone();
        wrong.port = 10;
        let elsewhere =
            crate::plan::seed_spec(&wrong, wrong.port + 1, b"x", "elsewhere".to_string())
                .expect("the frame builds")
                .spec
                .build()
                .expect("the frame crafts");

        let refused = host
            .probe(&Payload {
                value: "wrong port".to_string(),
                mode: PayloadMode::Replace,
                bytes: Some(elsewhere),
            })
            .await;
        let message = refused
            .expect_err("a frame to another port is refused")
            .to_string();
        assert!(
            message.contains("its own target only") && message.contains("127.0.0.1:10"),
            "{message}"
        );
        assert_eq!(mock.inject_count(), 0, "the refused replay never went out");
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters::default()),
            "a refused replay is not a case"
        );
    }

    /// Review finding G2: spec D8.4 caps a job at `cases_cap` cases and a
    /// check's own `probe()` send is a case like any other, so the cap bounds
    /// it exactly as it bounds the fuzz loop and the crash triage — a check
    /// replaying frames in a loop cannot push the job past its ceiling.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_host_respects_the_case_cap() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 2);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let host = PacketHost::new(Arc::clone(&runner));
        // `probe` sends no baseline of its own, so every inject below is a
        // case charged against the cap of two.
        let seed = runner.plan.seed_spec(0).expect("the seed spec");
        let frame = seed.spec.build().expect("the seed frame");
        let payload = Payload {
            value: "replay".to_string(),
            mode: PayloadMode::Replace,
            bytes: Some(frame),
        };

        host.probe(&payload).await.expect("the first case fits");
        host.probe(&payload).await.expect("the second case fits");
        let refused = host.probe(&payload).await;

        assert!(
            refused
                .expect_err("the third case is past the cap")
                .to_string()
                .contains("case cap reached"),
            "the cap is what refused it"
        );
        assert_eq!(mock.inject_count(), 2, "the third frame never went out");
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 2,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(0));
        assert_eq!(
            shared.state.stopped(job.job_id()),
            Some(StopReason::CaseCap(2)),
            "the cap is job-wide: no later point sends another case"
        );
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
    async fn registry_keys_by_job_id_and_point() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 5);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = RunnerRegistry::new();
        assert!(registry.is_empty());

        registry.register(
            job.job_id(),
            runner.point().id.as_str(),
            Arc::clone(&runner),
        );

        assert_eq!(registry.len(), 1);
        let found = registry
            .get(job.job_id(), runner.point().id.as_str())
            .expect("the registered runner");
        assert!(Arc::ptr_eq(&found, &runner));
        assert!(registry.get("other", runner.point().id.as_str()).is_none());
        registry.forget_job(job.job_id());
        assert!(registry.is_empty());
    }

    /// Tester (stage 5), T5 live proof 4b: the registry key is a **pair**, so
    /// two jobs auditing the same target hold their own runner for the same
    /// point id, and forgetting one job leaves the other's untouched. The
    /// point id is derived from the target alone (`l4:<ip>:<port>/<proto>/
    /// <field>`), so two concurrent jobs against one host collide on it by
    /// construction — this is the case a job-id-only or point-id-only key
    /// would get wrong, in opposite ways.
    ///
    /// Mutation: key the map by the point id alone and the second
    /// `register` hands back the first job's runner (`Arc::ptr_eq` fails);
    /// make `forget_job` clear the whole map and the surviving-job assertions
    /// fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_jobs_sharing_a_point_id_keep_their_own_runners() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 5);
        let (shared, job_a, plans, disc) =
            setup(Arc::clone(&mock), profile.clone(), &fields(&["raw"]), 1000);
        let job_b = crate::testing::TestJob::new(profile).with_job_id("scan-b0b0b0b0");
        assert_ne!(job_a.job_id(), job_b.job_id(), "two distinct jobs");

        let runner_a = runner_for(&shared, &job_a, &plans, &disc.points, "raw");
        let runner_b = runner_for(&shared, &job_b, &plans, &disc.points, "raw");
        let point_id = runner_a.point().id.clone();
        assert_eq!(point_id, runner_b.point().id, "the same point id");
        assert!(
            !Arc::ptr_eq(&runner_a, &runner_b),
            "two runners, one per job"
        );

        let registry = RunnerRegistry::new();
        let got_a = registry.register(job_a.job_id(), &point_id, Arc::clone(&runner_a));
        let got_b = registry.register(job_b.job_id(), &point_id, Arc::clone(&runner_b));
        assert!(Arc::ptr_eq(&got_a, &runner_a), "job A keeps its own runner");
        assert!(
            Arc::ptr_eq(&got_b, &runner_b),
            "job B is not handed job A's runner"
        );
        assert_eq!(registry.len(), 2, "one entry per (job, point) pair");

        // Forgetting a job the registry never saw changes nothing.
        registry.forget_job("scan-never-ran");
        assert_eq!(registry.len(), 2);

        registry.forget_job(job_a.job_id());
        assert!(
            registry.get(job_a.job_id(), &point_id).is_none(),
            "job A's runner is gone"
        );
        let survivor = registry
            .get(job_b.job_id(), &point_id)
            .expect("job B's runner survives its neighbour's end");
        assert!(Arc::ptr_eq(&survivor, &runner_b));
        assert_eq!(registry.len(), 1);

        registry.forget_job(job_b.job_id());
        assert!(registry.is_empty());
    }

    /// Tester (stage 5): the budget runs out during the recovery wait. The
    /// candidate case had two failed probes but **no replay ran** and the
    /// target was never given the recovery bound, so spec D8.4 / call 14 ("two
    /// failed liveness probes, reproduced 3 times") and call C27 ("a target
    /// that never recovers within 10 s") both say this is a `Budget` stop, not
    /// an `l4-crash`.
    ///
    /// Fixed by tester finding F1: `triage` now starts from `recovered: true`
    /// and `drive` reads any `triage.stop` as the end of the run, so a
    /// `Stopped(Budget)` inside the recovery wait never becomes a crash.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::Budget,
            }
        );
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

    /// Tester finding F2: spec D8.4 caps a job at `cases_cap` cases and a
    /// reproduction replay is a case (call C10), so a crash triage that has
    /// no room left is interrupted rather than allowed to overshoot. The
    /// interrupted triage is not a crash (finding F1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replays_never_exceed_the_case_cap() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        // Two cases is the whole job: the crashing case is the last one the
        // cap allows, so not one replay fits.
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 2), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.stopped, Some(StopReason::CaseCap(2)));
        assert!(
            run.crash.is_none(),
            "a triage with no room to replay proves nothing: {:?}",
            run.crash
        );
        assert_eq!(run.cases.len(), 2);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::CaseCap(2),
            }
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
        // 1 baseline + 2 cases + the 2 failed probes, and nothing after: no
        // replay, and no recovery poll spent waiting for one.
        assert_eq!(mock.inject_count(), 5);
        assert_eq!(job.charged(), 5);
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(0));
        assert_eq!(
            shared.state.stopped(job.job_id()),
            Some(StopReason::CaseCap(2)),
            "the cap is job-wide: no later point sends another case"
        );
    }

    /// Tester (stage 5): the job deadline passes while the runner is polling
    /// for recovery. The target was given neither the recovery bound nor a
    /// replay, so the run must end as a `Deadline` stop with no crash recorded
    /// (call C27's "did not recover within 10 s" needs the 10 s).
    ///
    /// Fixed by tester finding F1: `await_recovery` keeps `Ok(false)` for the
    /// exhausted recovery bound and raises `Stopped(Deadline)` — marking the
    /// job stopped — when the deadline is what cut the wait short.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deadline_during_recovery_wait_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        // Dead for far longer than the deadline allows, but the recovery bound
        // (10 polls x (20 ms window + 20 ms gap) = 400 ms) is never reached.
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 1000, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let shared = Arc::new(Shared {
            timing: Timing {
                reply_window: Duration::from_millis(20),
                liveness_retry: Duration::from_millis(5),
                replay_spacing: Duration::from_millis(5),
                recovery_poll: Duration::from_millis(20),
                recovery_polls: 10,
                ..Timing::default()
            },
            ..(*shared).clone()
        });
        // Baseline + two cases + two failed probes take about 75 ms; the
        // deadline lands in the middle of the recovery polls.
        let job = job.with_deadline(Instant::now() + Duration::from_millis(200));
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::Deadline,
            }
        );
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

    /// Tester (fix round): the operator cancels the job while the runner is
    /// polling for recovery. `Cancelled` is the one stop F1's fixes never
    /// exercised; it rides the same `await_recovery` path as `Budget`, so it
    /// must end the run as a `Cancelled` stop with no crash and no retirement.
    /// The cancel is keyed off the mock's inject count — once the second
    /// failed probe (inject 5) is out, the first recovery poll is the next
    /// send — so the test does not race a sleep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_during_recovery_wait_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        // Dead for longer than any recovery bound here, so only the cancel
        // can end the wait.
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 1000, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let canceller = {
            let (mock, job) = (Arc::clone(&mock), Arc::clone(&job));
            tokio::spawn(async move {
                // 1 baseline + 2 cases + 2 failed probes; the fifth inject's
                // capture waits out a 50 ms reply window before the runner
                // can send again.
                for _ in 0..20_000 {
                    if mock.inject_count() >= 5 {
                        job.cancel();
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };

        let run = runner.run_point().await;
        canceller.await.expect("the canceller task finishes");

        assert_eq!(
            mock.inject_count(),
            5,
            "the first recovery poll never went out"
        );
        assert_eq!(job.charged(), 5);
        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::Cancelled,
            }
        );
        assert_eq!(run.stopped, Some(StopReason::Cancelled));
        assert_eq!(
            shared.state.stopped(job.job_id()),
            Some(StopReason::Cancelled)
        );
        assert!(
            run.crash.is_none(),
            "a cancel during the recovery wait is not a crash: {:?}",
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

    /// Tester (fix round): the budget runs out at the replay itself — the
    /// target came back (one recovery poll passed) and the triage's first
    /// `deliver` is the charge that fails. This is the `Stopped` arm on the
    /// replay send, not on `await_recovery`; it must be a `Budget` stop with
    /// no crash, and the replay never reaches the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn budget_exhausted_at_the_replay_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 baseline + 2 cases + 2 failed probes + 1 passing recovery poll = 6;
        // the replay is the charge that fails.
        let job = job.with_budget(6);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(mock.inject_count(), 6, "the replay never went out");
        assert_eq!(job.charged(), 6);
        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::Budget,
            }
        );
        assert_eq!(run.stopped, Some(StopReason::Budget));
        assert_eq!(shared.state.stopped(job.job_id()), Some(StopReason::Budget));
        assert!(
            run.crash.is_none(),
            "a budget stop at the replay is not a reproduced crash: {:?}",
            run.crash
        );
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 2,
                crashes: 0,
                // The two failed probes; the recovery poll passed.
                liveness_failures: 2,
                retired_elements: 0,
            })
        );
        assert!(!shared.state.is_retired(job.job_id(), &run.point_id));
    }

    /// Tester (fix round): the budget runs out right after the first replay
    /// went out and left the target silent — the replay's own liveness pair
    /// is what the budget refuses. One replay of three is not a reproduction
    /// (spec call 14), so the run is a `Budget` stop with no crash; the replay
    /// is still a counted case (call C10).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn budget_exhausted_after_a_replay_is_a_stop_not_a_crash() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 baseline + 2 cases + 2 failed probes + 1 recovery poll + 1 replay
        // = 7; the replay's first probe is the charge that fails.
        let job = job.with_budget(7);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(mock.inject_count(), 7);
        assert_eq!(job.charged(), 7);
        // The replay is not a record of the run; the loop's two cases are.
        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::Budget,
            }
        );
        assert_eq!(run.stopped, Some(StopReason::Budget));
        assert!(
            run.crash.is_none(),
            "one unconfirmed replay is not a reproduced crash: {:?}",
            run.crash
        );
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                // Two loop cases and the one replay (call C10).
                cases: 3,
                crashes: 0,
                liveness_failures: 2,
                retired_elements: 0,
            })
        );
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(47));
        assert!(!shared.state.is_retired(job.job_id(), &run.point_id));
    }

    /// Tester (fix round): the case cap is job-wide. With two points sharing a
    /// cap of four, the first point's triage spends the shared ceiling on two
    /// replays (both reproduce) and the third replay is refused by the cap, so
    /// two reproductions of three is no crash — and the second point, which
    /// had two cases allocated, sends nothing at all: it reads the `CaseCap`
    /// stop before its baseline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cap_reached_inside_one_points_triage_stops_the_next_point() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 4), "deadbeef0000");
        let (shared, job, plans, disc) = setup(
            Arc::clone(&mock),
            profile,
            &fields(&["raw", "ipv4.ttl"]),
            1000,
        );
        assert_eq!(disc.points.len(), 2);
        assert_eq!(shared.state.allocate_cases(job.job_id()), Some(2));
        let first = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let second = runner_for(&shared, &job, &plans, &disc.points, "ipv4.ttl");

        let run = first.run_point().await;

        assert_eq!(run.cases.len(), 2, "{:?}", run.cases);
        assert_eq!(
            run.cases[1].candidate,
            Candidate::Interrupted {
                stop: StopReason::CaseCap(4),
            }
        );
        assert_eq!(run.stopped, Some(StopReason::CaseCap(4)));
        assert!(
            run.crash.is_none(),
            "two reproductions of three, then the cap: not a confirmed crash: {:?}",
            run.crash
        );
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                // Two loop cases and two replays: exactly the cap.
                cases: 4,
                crashes: 0,
                // The candidate's pair and each replay's pair.
                liveness_failures: 6,
                retired_elements: 0,
            })
        );
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(0));
        // 1 baseline + 2 cases + 2 probes + (1 poll + replay + 2 probes) x 2.
        assert_eq!(mock.inject_count(), 13);
        assert_eq!(job.charged(), 13);

        let starved = second.run_point().await;

        assert_eq!(starved.stopped, Some(StopReason::CaseCap(4)));
        assert_eq!(starved.baseline, None, "not even a baseline went out");
        assert!(starved.cases.is_empty(), "{:?}", starved.cases);
        assert!(starved.crash.is_none());
        assert_eq!(mock.inject_count(), 13, "the second point sent nothing");
        assert_eq!(job.charged(), 13);
        assert_eq!(
            shared.state.stopped(job.job_id()),
            Some(StopReason::CaseCap(4))
        );
    }

    /// Tester (fix round): the cap reached by the fuzz loop's own last case,
    /// with no triage, is a clean end — the loop's allocation already equals
    /// the ceiling, so the cap check in `deliver` never fires and the job is
    /// not marked stopped (spec D8.4 "cases per job <= 5000" is a bound, not
    /// a stop; plan C10).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cap_reached_on_the_last_loop_case_is_a_clean_end() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 4);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 4, "{:?}", run.cases);
        assert!(run.cases.iter().all(|case| case.sent()), "{:?}", run.cases);
        assert_eq!(run.stopped, None);
        assert_eq!(shared.state.stopped(job.job_id()), None);
        assert!(run.crash.is_none());
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 4,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        assert_eq!(shared.state.cases_remaining(job.job_id()), Some(0));
        // 1 baseline + 4 cases; `liveness_every` is 25, so no scheduled probe.
        assert_eq!(mock.inject_count(), 5);
        assert_eq!(job.charged(), 5);
    }

    /// Tester (fix rounds, review finding Q3): `register` is idempotent even
    /// while the registered runner's run is in flight. A second runner built
    /// for the same point mid-run is dropped in favour of the first, and the
    /// caller that waits on the returned runner gets the very `PointRun` the
    /// in-flight run produces — one baseline, one set of cases, no second run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_hands_back_the_in_flight_runner() {
        let mock = MockBackend::new(MockReply::Echo);
        // Every reply waits 10 ms, so the twenty-case run is long enough to be
        // caught mid-flight without a sleep race.
        mock.reply_delay(Duration::from_millis(10));
        let profile = l4_profile(vec![udp_target(9)], 20);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let first = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let registry = RunnerRegistry::new();
        let registered =
            registry.register(job.job_id(), first.point().id.as_str(), Arc::clone(&first));
        assert!(Arc::ptr_eq(&registered, &first));

        let in_flight = {
            let first = Arc::clone(&first);
            tokio::spawn(async move { first.run_point().await })
        };
        for _ in 0..20_000 {
            if mock.inject_count() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(mock.inject_count() >= 3, "the first run is mid-flight");
        assert!(mock.inject_count() < 21, "the first run has not finished");

        // A fresh runner for the same point, as a second `probe_host_for` would
        // build: the registry keeps the first and hands it back.
        let second = runner_for(&shared, &job, &plans, &disc.points, "raw");
        assert!(!Arc::ptr_eq(&second, &first));
        let second_id = second.point().id.clone();
        let shared_runner = registry.register(job.job_id(), &second_id, second);
        assert!(
            Arc::ptr_eq(&shared_runner, &first),
            "the in-flight runner stays the point's one runner"
        );
        assert_eq!(registry.len(), 1);

        let from_second = shared_runner.run_point().await;
        let from_first = in_flight.await.expect("the first run finishes");
        assert!(
            Arc::ptr_eq(&from_first, &from_second),
            "both callers hold the one run"
        );
        assert_eq!(from_first.cases.len(), 20);
        // 1 baseline + 20 cases; `liveness_every` is 25, so no scheduled probe,
        // and no second baseline from a second run.
        assert_eq!(mock.inject_count(), 21);
        assert_eq!(job.charged(), 21);
        assert_eq!(
            shared.state.counters(job.job_id()).expect("counters").cases,
            20
        );
    }

    /// Tester (fix rounds, review finding SEC4): the replay pin checks both
    /// halves of the destination. A frame to the right port on another loopback
    /// host, and a frame with no decodable IP at all, are refused by name and
    /// never charged; a frame to the right host and port is accepted even on a
    /// point whose own field does not preserve the transport header
    /// (`udp.length`), because the replay pins `dst_port` itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_refuses_another_host_or_no_ip_and_accepts_its_own_target() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 50);
        let (shared, job, plans, disc) = setup(
            Arc::clone(&mock),
            profile,
            &fields(&["raw", "udp.length"]),
            1000,
        );
        let runner = runner_for(&shared, &job, &plans, &disc.points, "udp.length");
        let host = PacketHost::new(Arc::clone(&runner));
        let replay = |bytes: Vec<u8>, label: &str| Payload {
            value: label.to_string(),
            mode: PayloadMode::Replace,
            bytes: Some(bytes),
        };

        // Right port, wrong host: 127.0.0.2:9 is inside the 127/8 Inject scope
        // but is not this point's target.
        let mut other_host = plans[0].target.clone();
        other_host.ip = "127.0.0.2".parse().expect("an address");
        let elsewhere = crate::plan::seed_spec(&other_host, 40_000, b"x", "elsewhere".to_string())
            .expect("the frame builds")
            .spec
            .build()
            .expect("the frame crafts");
        let message = host
            .probe(&replay(elsewhere, "wrong host"))
            .await
            .expect_err("a frame to another host is refused")
            .to_string();
        assert_eq!(
            message,
            "the packet lane replays frames to its own target only: got 127.0.0.2:9"
        );

        // No IP header at all: neither half of the destination can be read.
        let message = host
            .probe(&replay(vec![0xff; 7], "garbage"))
            .await
            .expect_err("an undecodable frame is refused")
            .to_string();
        assert_eq!(
            message,
            "the packet lane replays frames to its own target only: got none:none"
        );

        // Right host, wrong port, on this non-transport-preserving point.
        let mut other_port = plans[0].target.clone();
        other_port.port = 10;
        let wrong_port = crate::plan::seed_spec(&other_port, 40_000, b"x", "port".to_string())
            .expect("the frame builds")
            .spec
            .build()
            .expect("the frame crafts");
        let message = host
            .probe(&replay(wrong_port, "wrong port"))
            .await
            .expect_err("a frame to another port is refused")
            .to_string();
        assert_eq!(
            message,
            "the packet lane replays frames to its own target only: got 127.0.0.1:10"
        );

        assert_eq!(mock.inject_count(), 0, "no refused replay reached the wire");
        assert_eq!(job.charged(), 0, "no refused replay was charged");
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters::default())
        );

        // The point's own target, on a point whose field (`udp.length`) leaves
        // `dst_port` unpinned for its own cases: the replay still goes out and
        // is correlated, because `replay` pins the port itself.
        let own = plans[0]
            .seed_spec(0)
            .expect("the seed spec")
            .spec
            .build()
            .expect("the seed frame");
        let response = host
            .probe(&replay(own, "own target"))
            .await
            .expect("a frame to the point's own target is replayed");
        assert_eq!(response.body, plans[0].seeds[0].bytes, "the echo came back");
        // The reply's *class* is deliberately not pinned here: a verbatim
        // replay is a `Raw`-only `PacketSpec`, so `send_recv` correlates it
        // with `L4Proto::Raw` and reads the echo as `Other` (tester finding on
        // the fix rounds, reported for the Coder).
        assert_eq!(mock.inject_count(), 1);
        assert_eq!(job.charged(), 1);
        assert_eq!(
            shared.state.counters(job.job_id()).expect("counters").cases,
            1,
            "a replay is a case"
        );
    }

    /// Tester (fix rounds, review finding M8): `PointRunner::new` builds seed 0
    /// and is fallible, so a plan that cannot craft is refused at construction
    /// — no seed at all, a mixed-family target, or a seed the frame cannot
    /// carry — each with its `PlanError`. No production path reaches these
    /// (discovery built seed 0 of every plan already), so the constructor is
    /// the last line, pinned here directly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn point_runner_new_refuses_a_plan_that_does_not_build() {
        use crate::fields::FieldPath;
        use crate::plan::{PlanError, SeedOrigin, SeedPayload};

        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 10);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let point = disc.points[0].clone();
        let build = |plan: crate::plan::TargetPlan| {
            PointRunner::new(
                Arc::clone(&shared),
                Arc::clone(&job) as Arc<dyn JobCtx>,
                point.clone(),
                plan,
                FieldPath::Raw,
            )
            .map(|_| ())
        };

        let mut seedless = plans[0].clone();
        seedless.seeds.clear();
        assert_eq!(
            build(seedless),
            Err(PlanError::Craft(
                "the target plan carries no seed".to_string()
            ))
        );

        let mut mixed = plans[0].clone();
        mixed.target.local_ip = "::1".parse().expect("an address");
        assert_eq!(build(mixed), Err(PlanError::IpVersionMismatch));

        let mut oversize = plans[0].clone();
        oversize.seeds = vec![SeedPayload {
            id: "127.0.0.1:9/udp#0".to_string(),
            bytes: vec![0x41; 65_507],
            origin: SeedOrigin::Profile,
        }];
        let err = build(oversize).expect_err("the frame cannot carry 65507 payload bytes");
        assert!(
            matches!(&err, PlanError::Craft(message) if message.contains("exceeds 65535 bytes")),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "cannot craft the seed packet: crafted packet exceeds 65535 bytes"
        );

        assert!(
            build(plans[0].clone()).is_ok(),
            "the discovered plan builds"
        );
        assert_eq!(mock.inject_count(), 0, "construction sends nothing");
    }

    /// Tester (fix rounds, review finding M1): `HostError` is a
    /// `std::error::Error`, so the `anyhow::Error` a `ProbeHost` method returns
    /// downcasts back to the exact stop reason, and each variant renders as
    /// its literal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_error_downcasts_through_anyhow_with_its_reason() {
        assert_eq!(
            HostError::Stopped(StopReason::Budget).to_string(),
            "budget exhausted"
        );
        assert_eq!(
            HostError::Craft("no such layer".to_string()).to_string(),
            "cannot craft the case: no such layer"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(HostError::Stopped(StopReason::Deadline));
        assert_eq!(boxed.to_string(), "job deadline passed");

        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 1);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        let host = PacketHost::new(Arc::clone(&runner));
        let frame = plans[0]
            .seed_spec(0)
            .expect("the seed spec")
            .spec
            .build()
            .expect("the seed frame");
        let payload = Payload {
            value: "replay".to_string(),
            mode: PayloadMode::Replace,
            bytes: Some(frame),
        };
        host.probe(&payload).await.expect("the one case fits");
        let err = host
            .probe(&payload)
            .await
            .expect_err("the cap of one is spent");
        assert_eq!(
            err.downcast_ref::<HostError>(),
            Some(&HostError::Stopped(StopReason::CaseCap(1))),
            "{err}"
        );
        assert_eq!(err.to_string(), "case cap reached: 1 cases sent");
        assert_eq!(mock.inject_count(), 1);
    }

    /// Tester (fix rounds, review finding S1): a replay that follows a passing
    /// probe pair is spaced by `replay_spacing`, and the bound is proven with a
    /// spacing the rest of the run cannot reach on its own. At 300 ms, the two
    /// spaced replays alone cost 600 ms, while everything else in this run —
    /// the two 50 ms silent probes, the 10 ms retries, a dozen echoed sends —
    /// is well under 300 ms; without the sleep the run finishes long before
    /// the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replays_after_a_passing_pair_are_spaced_by_replay_spacing() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, false);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 10), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let spacing = Duration::from_millis(300);
        let shared = Arc::new(Shared {
            timing: Timing {
                replay_spacing: spacing,
                ..shared.timing
            },
            ..(*shared).clone()
        });
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let started = Instant::now();
        let run = runner.run_point().await;
        let elapsed = started.elapsed();

        // The first replay follows the recovery poll (no spacing); the second
        // and third follow passing pairs, so exactly two spacings are slept.
        assert_eq!(
            run.cases[1].candidate,
            Candidate::NotReproduced {
                reproduced: 0,
                attempts: 3,
            }
        );
        assert!(
            elapsed >= 2 * spacing,
            "two spaced replays need at least {:?}, the run took {elapsed:?}",
            2 * spacing
        );
        assert_eq!(mock.inject_count(), 1 + 7 + 2 + 1 + 3 * 3);
    }

    /// Review finding N5: every craft failure the runner can meet maps to one
    /// stop shape, so the sites that must handle one cannot diverge into four
    /// different answers.
    ///
    /// No reachable path produces one: seed 0 is built once in
    /// [`PointRunner::new`] and the built spec is cached, a case is built in
    /// its first `deliver` before any replay reuses it, and
    /// `PacketSpec::build` is pure — it never consults the guard, so no
    /// mid-job ceiling change can make it start failing. The mapping is
    /// therefore pinned here on its own.
    #[test]
    fn a_craft_failure_maps_to_one_unavailable_stop() {
        assert_eq!(
            craft_stop("seed 0", "the packet is 65536 bytes, max 65535"),
            StopReason::Unavailable(
                "seed 0 no longer builds: the packet is 65536 bytes, max 65535".to_string()
            )
        );
        assert_eq!(
            craft_stop("the replayed case", "no such layer").to_string(),
            "l4 unavailable: the replayed case no longer builds: no such layer"
        );
    }

    /// Tester finding T1, belt and braces: discovery builds every seed, so
    /// the fuzz loop should never meet one the builder refuses. If it ever
    /// does, the case is counted apart as unsendable and recorded, instead of
    /// the loop breaking in silence — no stop, no unsendable, a run that
    /// reads as a clean point that simply ran out of cases.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_seed_the_builder_refuses_is_an_unsendable_case() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 2);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // Discovery refuses this corpus, so the plan is bent by hand: seed 0
        // builds, seed 1 is one byte more than the frame can carry.
        let mut plan = plans[0].clone();
        plan.seeds.push(SeedPayload {
            id: "127.0.0.1:9/udp#1".to_string(),
            bytes: vec![0x41; max_payload_for(&plan.target) + 1],
            origin: SeedOrigin::Profile,
        });
        let point = disc.points.first().expect("one point").clone();
        let runner = Arc::new(
            PointRunner::new(
                Arc::clone(&shared),
                Arc::clone(&job) as Arc<dyn JobCtx>,
                point,
                plan,
                FieldPath::Raw,
            )
            .expect("seed 0 builds"),
        );

        let run = runner.run_point().await;

        assert_eq!(run.cases.len(), 2);
        assert!(run.cases[0].sent(), "case 0 cycles to seed 0 and goes out");
        let refused = &run.cases[1];
        assert!(!refused.sent());
        assert_eq!(refused.class(), None);
        assert_eq!(refused.index, 1);
        assert_eq!(refused.seed_id, "127.0.0.1:9/udp#1");
        assert_eq!(refused.sent_hex, "");
        assert_eq!(refused.chain, Vec::<String>::new());
        assert_eq!(
            shared
                .state
                .stats(job.job_id())
                .expect("the job's stats")
                .cases_unsendable,
            1
        );
        // 1 baseline + the one case that built; the refused seed never went
        // out and never charged.
        assert_eq!(mock.inject_count(), 2);
    }

    /// Tester (round 3), finding T1's send-time half for a seed in the
    /// *middle* of the corpus: with three seeds of which seed 1 does not
    /// build, case 1 is recorded unsendable under seed 1's id and the loop
    /// runs on, so cases 0 and 2 go out, the run has no stop and no crash,
    /// exactly one case is counted unsendable, exactly two are counted sent,
    /// and the wire saw the baseline plus those two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_middle_seed_leaves_its_neighbours_sent() {
        let mock = MockBackend::new(MockReply::Echo);
        let profile = l4_profile(vec![udp_target(9)], 3);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // Discovery refuses this corpus, so the plan is bent by hand: seed 0
        // is the default seed, seed 1 is one byte more than the frame can
        // carry, seed 2 builds.
        let mut plan = plans[0].clone();
        assert_eq!(plan.seeds.len(), 1);
        assert_eq!(plan.seeds[0].id, "127.0.0.1:9/udp#0");
        plan.seeds.push(SeedPayload {
            id: "127.0.0.1:9/udp#1".to_string(),
            bytes: vec![0x41; max_payload_for(&plan.target) + 1],
            origin: SeedOrigin::Profile,
        });
        plan.seeds.push(SeedPayload {
            id: "127.0.0.1:9/udp#2".to_string(),
            bytes: vec![0x42; 16],
            origin: SeedOrigin::Profile,
        });
        let point = disc.points.first().expect("one point").clone();
        let runner = Arc::new(
            PointRunner::new(
                Arc::clone(&shared),
                Arc::clone(&job) as Arc<dyn JobCtx>,
                point,
                plan,
                FieldPath::Raw,
            )
            .expect("seed 0 builds"),
        );

        let run = runner.run_point().await;

        assert_eq!(run.stopped, None, "a refused seed is not a stop");
        assert!(run.crash.is_none());
        assert_eq!(
            run.cases
                .iter()
                .map(|case| (case.index, case.seed_id.as_str(), case.sent()))
                .collect::<Vec<_>>(),
            vec![
                (0, "127.0.0.1:9/udp#0", true),
                (1, "127.0.0.1:9/udp#1", false),
                (2, "127.0.0.1:9/udp#2", true),
            ],
            "the loop runs on past the refused seed"
        );
        let refused = &run.cases[1];
        assert_eq!(refused.class(), None);
        assert_eq!(refused.sent_hex, "");
        assert_eq!(refused.chain, Vec::<String>::new());
        assert_eq!(refused.candidate, Candidate::No);
        assert!(run.cases[0].class().is_some());
        assert!(run.cases[2].class().is_some());

        let stats = shared.state.stats(job.job_id()).expect("the job's stats");
        assert_eq!(stats.cases_unsendable, 1);
        assert_eq!(stats.l4.cases, 2);
        assert_eq!(stats.l4.crashes, 0);
        // 1 baseline + cases 0 and 2; the refused seed never went out and
        // never charged.
        assert_eq!(mock.inject_count(), 3);
        assert_eq!(job.charged(), 3);
    }

    /// Quality (panel 3) finding P1: a probe pair a stop cut short never went
    /// out in full, so it is a stop, not a verdict. The budget runs out at the
    /// pair's first probe after a replay that did silence the target, which is
    /// exactly the shape that must not be read as a reproduction — the triage
    /// stops on the stop and counts nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_probe_pair_cut_short_by_a_stop_is_not_a_reproduction() {
        let mock = MockBackend::new(MockReply::Echo);
        mock.dies_on_pattern(vec![0xde, 0xad, 0xbe, 0xef], 8, 2, true);
        let profile = with_hex_seed(l4_profile(vec![udp_target(9)], 50), "deadbeef0000");
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // 1 recovery poll (the 6-byte seed is too short to trigger, so it is
        // answered) + 1 replay = 2; the pair's first probe is the charge that
        // fails.
        let job = job.with_budget(2);
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");
        // The triage is driven on its own here, so the baseline the liveness
        // probes are read against is set by hand: without it every probe
        // fails and the recovery poll, not the pair, spends the budget.
        *crate::sync::lock(&runner.baseline) = Some(CaseClass::Clean);
        // An eight-byte frame carrying the trigger: this replay silences the
        // mock, so the replay itself is a candidate.
        let silencer = crate::plan::seed_spec(
            &runner.plan.target,
            runner.plan.src_port,
            &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00],
            runner.plan.seeds[0].id.clone(),
        )
        .expect("the trigger frame builds");

        let triage = runner
            .triage(&silencer.spec, &silencer.id, &["grow:8".to_string()], 1, 1)
            .await;

        assert_eq!(triage.stop, Some(StopReason::Budget));
        assert_eq!(triage.attempts, 1, "the replay itself went out");
        assert_eq!(
            triage.reproduced, 0,
            "a pair the budget cut short proves nothing"
        );
        assert!(
            triage.recovered,
            "a triage a stop cut short learned nothing about recovery"
        );
        assert_eq!(mock.inject_count(), 2, "the pair's probe never went out");
    }

    /// Quality (panel 3) finding P3: a dry run over a seed the builder refuses
    /// renders the rest of the allocation instead of breaking, exactly as the
    /// send loop does — the refused case is rendered unsendable and the run
    /// still shows every case the job allocated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dry_run_renders_past_a_seed_the_builder_refuses() {
        let mock = MockBackend::new(MockReply::Echo);
        let mut profile = l4_profile(vec![udp_target(9)], 2);
        profile.l4.dry_run = true;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // Discovery refuses this corpus, so the plan is bent by hand: seed 0
        // builds, seed 1 is one byte more than the frame can carry.
        let mut plan = plans[0].clone();
        plan.seeds.push(SeedPayload {
            id: "127.0.0.1:9/udp#1".to_string(),
            bytes: vec![0x41; max_payload_for(&plan.target) + 1],
            origin: SeedOrigin::Profile,
        });
        let point = disc.points.first().expect("one point").clone();
        let runner = Arc::new(
            PointRunner::new(
                Arc::clone(&shared),
                Arc::clone(&job) as Arc<dyn JobCtx>,
                point,
                plan,
                FieldPath::Raw,
            )
            .expect("seed 0 builds"),
        );

        let run = runner.run_point().await;

        assert!(run.dry_run);
        assert_eq!(run.cases.len(), 2, "both allocated cases are rendered");
        assert!(!run.cases[0].sent_hex.is_empty(), "case 0 renders a frame");
        assert_eq!(run.cases[0].seed_id, "127.0.0.1:9/udp#0");
        let refused = &run.cases[1];
        assert!(!refused.sent());
        assert_eq!(refused.class(), None);
        assert_eq!(refused.index, 1);
        assert_eq!(refused.seed_id, "127.0.0.1:9/udp#1");
        assert_eq!(refused.sent_hex, "");
        assert_eq!(refused.chain, Vec::<String>::new());
        assert_eq!(mock.inject_count(), 0, "a dry run sends nothing");
        assert_eq!(job.charged(), 0);
    }

    /// Amendment 46: the pace a point obeys is the profile's, never below the
    /// lane's defensive floor, and the crate-private override replaces both
    /// (so a unit test costs milliseconds instead of twenty seconds; see
    /// `pace_override_is_crate_private_and_floor_holds_otherwise`).
    #[test]
    fn profile_pace_below_the_floor_is_raised() {
        assert_eq!(super::ICMP_PACE_FLOOR_MS, 1000);
        let mut options = L4Options::default();

        assert_eq!(
            Timing::default().icmp_pace_for(&options),
            Duration::from_millis(1100),
            "the profile default is above the floor, so it is used as written"
        );

        options.icmp_pace_ms = 500;
        assert_eq!(
            Timing::default().icmp_pace_for(&options),
            Duration::from_millis(1000),
            "a profile value below the floor is raised to it"
        );

        options.icmp_pace_ms = 0;
        assert_eq!(
            Timing::default().icmp_pace_for(&options),
            Duration::from_millis(1000),
            "zero is below the floor too"
        );

        options.icmp_pace_ms = 2000;
        assert_eq!(
            Timing::default().icmp_pace_for(&options),
            Duration::from_millis(2000)
        );

        let timing = Timing {
            icmp_pace: Some(Duration::from_millis(30)),
            ..Timing::default()
        };
        assert_eq!(
            timing.icmp_pace_for(&options),
            Duration::from_millis(30),
            "the test override replaces the profile value and the floor"
        );
    }

    /// Tester F2 (spec D11: "the packet lane applies the same floor itself so
    /// no lane caller can under-pace a closed port") and the quality panel:
    /// `Timing::icmp_pace` is `pub(crate)`, so no caller of
    /// `PacketLane::with_timing` outside this crate can set it and the floor
    /// holds by construction for every lane caller. In-crate, the override
    /// replaces the floored profile value — how `fast_timing` keeps a unit
    /// test at milliseconds — and without one the floored value stands.
    #[test]
    fn pace_override_is_crate_private_and_floor_holds_otherwise() {
        let options = L4Options {
            icmp_pace_ms: 0,
            ..L4Options::default()
        };

        let overridden = Timing {
            icmp_pace: Some(Duration::ZERO),
            ..Timing::default()
        };
        assert_eq!(
            overridden.icmp_pace_for(&options),
            Duration::ZERO,
            "an in-crate override is honoured as written"
        );

        let production = Timing {
            icmp_pace: None,
            ..Timing::default()
        };
        assert_eq!(
            production.icmp_pace_for(&options),
            Duration::from_millis(1000),
            "without an override the profile value is raised to the floor"
        );
    }

    /// The case classes of a run, as the oracle labels them, for an assertion
    /// message that says what actually happened.
    fn labels(run: &crate::state::PointRun) -> Vec<String> {
        run.cases
            .iter()
            .map(|case| {
                case.class()
                    .map_or_else(|| "unsent".to_string(), |class| class.label())
            })
            .collect()
    }

    /// Amendment 46, the differential half. A target host whose kernel
    /// rate-limits ICMP errors (Linux: `net.ipv4.icmp_ratelimit = 1000` ms per
    /// destination) answers at most one stimulus per window, so an **unpaced**
    /// run against a closed port reads mostly silence — the shape a
    /// rate-limiting remote host shows (the rig's loopback is exempt; write-up
    /// `2026-11-01-t5-live-proof.md`, section iii). Every such silence is recorded as
    /// `no_reply (icmp_ratelimit)`, spends no liveness probe and is no crash
    /// candidate: a closed port can never yield `l4-crash` (spec D8.4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpaced_closed_port_on_a_ratelimiting_host_reads_silence() {
        let mock = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        mock.icmp_ratelimit(Duration::from_millis(300));
        let mut profile = l4_profile(vec![udp_target(9)], 20);
        profile.l4.icmp_pace_ms = 0;
        // The timeout ladder is not what this test is about: twenty silent
        // cases in a row would stop the job on its own threshold.
        profile.l4.consecutive_timeouts = 50;
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        // `fast_timing` overrides the pace with zero, which is how the lane ran
        // before amendment 46.
        assert_eq!(shared.timing.icmp_pace, Some(Duration::ZERO));
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let run = runner.run_point().await;

        let icmp = CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        };
        let silent: Vec<_> = run
            .cases
            .iter()
            .filter(|case| case.class() == Some(CaseClass::Silence))
            .collect();
        assert_eq!(run.cases.len(), 20);
        assert_eq!(run.baseline, Some(icmp));
        assert!(
            silent.len() >= 10,
            "an unpaced run against a rate-limiting host reads mostly silence; classes {:?}",
            labels(&run)
        );
        for case in &silent {
            assert_eq!(
                case.note,
                Some(CaseNote::IcmpRatelimit),
                "case {} is silence on an ICMP-paced point",
                case.index
            );
            assert_eq!(case.candidate, Candidate::No);
        }
        assert_eq!(
            run.no_reply_count(),
            u32::try_from(silent.len()).expect("a case count fits a u32")
        );
        assert!(run.crash.is_none());
        assert!(run.stopped.is_none(), "{:?}", run.stopped);
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 20,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        // 1 baseline + 20 cases: not one liveness probe was spent on the
        // silence of a closed port.
        assert_eq!(mock.inject_count(), 21);
    }

    /// Amendment 46, the paced half: with the stimuli spaced at least the pace
    /// apart, the same rate-limiting host answers every one of them, so every
    /// case classifies `icmp(3,3)` and the run takes at least `19 x pace`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn paced_closed_port_classifies_every_case() {
        let mock = MockBackend::new(MockReply::Icmp {
            icmp_type: 3,
            code: 3,
        });
        mock.icmp_ratelimit(Duration::from_millis(20));
        let profile = l4_profile(vec![udp_target(9)], 20);
        let (shared, job, plans, disc) = setup(Arc::clone(&mock), profile, &fields(&["raw"]), 1000);
        let pace = Duration::from_millis(30);
        let shared = Arc::new(Shared {
            timing: Timing {
                icmp_pace: Some(pace),
                ..shared.timing
            },
            ..(*shared).clone()
        });
        let runner = runner_for(&shared, &job, &plans, &disc.points, "raw");

        let started = Instant::now();
        let run = runner.run_point().await;
        let elapsed = started.elapsed();

        let icmp = CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        };
        assert_eq!(run.cases.len(), 20);
        assert!(
            run.cases.iter().all(|case| case.class() == Some(icmp)),
            "every paced case draws the port-unreachable; classes {:?}",
            labels(&run)
        );
        assert!(run.cases.iter().all(|case| case.note.is_none()));
        assert!(run.cases.iter().all(|case| case.candidate == Candidate::No));
        assert_eq!(run.no_reply_count(), 0);
        assert_eq!(run.reactions(), vec![(icmp, 20)]);
        assert!(run.crash.is_none());
        assert!(run.stopped.is_none(), "{:?}", run.stopped);
        assert_eq!(
            shared.state.counters(job.job_id()),
            Some(L4Counters {
                cases: 20,
                crashes: 0,
                liveness_failures: 0,
                retired_elements: 0,
            })
        );
        assert!(
            elapsed >= 19 * pace,
            "twenty cases spaced by {pace:?} cost at least {:?}; the run took {elapsed:?}",
            19 * pace
        );
        assert_eq!(mock.inject_count(), 21);
    }

    /// Tester (T5 stage 5, amendment 46's blast radius): the pace applies to an
    /// **ICMP baseline only**. A point whose baseline is `Reset` (a closed TCP
    /// port) or `Clean` (a live service) runs at full speed even with a minute
    /// of configured pace, and the lane keeps its crash rule on such a point.
    ///
    /// The profile pace is a minute and the job's deadline ten seconds, so a
    /// pace wrongly applied here would sleep into the deadline and the run
    /// would come back `StopReason::Deadline` with cases missing — the
    /// assertions below are what fails, not a hang.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_point_whose_baseline_is_not_icmp_is_never_paced() {
        for (reply, target, field, expected, probes_per_case) in [
            (
                MockReply::Rst,
                tcp_target(80),
                "tcp.flags",
                CaseClass::Reset,
                1,
            ),
            (MockReply::Echo, udp_target(9), "raw", CaseClass::Clean, 0),
        ] {
            let mock = MockBackend::new(reply);
            let mut profile = l4_profile(vec![target], 6);
            // A minute of pace: only an ICMP baseline may act on it.
            profile.l4.icmp_pace_ms = 60_000;
            let (shared, job, plans, disc) =
                setup(Arc::clone(&mock), profile, &fields(&[field]), 1000);
            // `icmp_pace: None` is production behaviour: the profile's value,
            // raised to the floor. `fast_timing` would have zeroed it.
            let shared = Arc::new(Shared {
                timing: Timing {
                    icmp_pace: None,
                    ..shared.timing
                },
                ..(*shared).clone()
            });
            assert_eq!(
                shared.timing.icmp_pace_for(&job.profile().l4),
                Duration::from_secs(60),
                "{expected:?}: the pace that must not be applied"
            );
            let job = Arc::clone(&job).with_deadline(Instant::now() + Duration::from_secs(10));
            let runner = runner_for(&shared, &job, &plans, &disc.points, field);

            let started = Instant::now();
            let run = runner.run_point().await;
            let elapsed = started.elapsed();

            assert_eq!(run.baseline, Some(expected));
            assert!(
                run.stopped.is_none(),
                "{expected:?}: an unpaced point never runs into the deadline: {:?}",
                run.stopped
            );
            assert_eq!(run.cases.len(), 6, "{expected:?}: every case was sent");
            assert!(
                run.cases.iter().all(|case| case.class() == Some(expected)),
                "{expected:?}: classes {:?}",
                labels(&run)
            );
            assert!(
                run.cases.iter().all(|case| case.note.is_none()),
                "{expected:?}: no `no_reply (icmp_ratelimit)` note off an ICMP baseline"
            );
            assert_eq!(
                mock.inject_count(),
                1 + 6 + 6 * probes_per_case,
                "{expected:?}: baseline + cases + the liveness probes the class earns"
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "{expected:?}: six cases cost milliseconds unpaced; the run took {elapsed:?}"
            );
        }
    }

    /// The stray same-host frame a shared interface carries: a UDP frame from
    /// the target host but one port off the target's, addressed back at the
    /// stimulus's source port. Pinned to the five-tuple it is not this
    /// stimulus's reply and the oracle reads it as `ProtocolError`; correlated
    /// on the host alone it is taken for the target's own answer (`Clean`).
    fn stray_port_frame(stimulus: &[u8]) -> Option<Vec<u8>> {
        let packet = as_packet(stimulus);
        let ends = transport_payload(&packet)?;
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (ends.dst, ends.src) else {
            return None;
        };
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some(src),
                    dst: Some(dst),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(ends.dst_port.wrapping_add(1)),
                    dst_port: Some(ends.src_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"stray".to_vec()),
            ],
        }
        .build()
        .ok()
    }

    /// A host that answers every stimulus with a [`stray_port_frame`] and never
    /// echoes the stimulus back, so the stray frame is the only thing a send
    /// can read.
    #[derive(Debug, Default)]
    struct StrayPortHost {
        queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    #[derive(Debug)]
    struct StrayPortCapture {
        queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl CaptureSource for StrayPortCapture {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            if let Some(frame) = lock(&self.queue).pop_front() {
                return Ok(Some(frame));
            }
            std::thread::sleep(Duration::from_millis(2));
            Ok(None)
        }
    }

    impl CaptureInjectBackend for StrayPortHost {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            Ok(Box::new(StrayPortCapture {
                queue: Arc::clone(&self.queue),
            }))
        }

        fn inject(&self, _iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
            if let Some(frame) = stray_port_frame(bytes) {
                lock(&self.queue).push_back(frame);
            }
            Ok(())
        }
    }

    /// A runner on one field of `127.0.0.1:9`, talking to a [`StrayPortHost`].
    /// One lane context per point, so one point's stop ladder never reaches
    /// another's; discovery runs against a silent mock, since discovery is not
    /// what this test drives.
    fn stray_point(field: &str) -> Arc<PointRunner> {
        let (shared, job, plans, disc) = setup(
            MockBackend::new(MockReply::Silence),
            l4_profile(vec![udp_target(9)], 2),
            &fields(&[field]),
            1000,
        );
        let shared = Arc::new(Shared {
            backend: Arc::new(StrayPortHost::default()),
            ..(*shared).clone()
        });
        runner_for(&shared, &job, &plans, &disc.points, field)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn baseline_and_liveness_probes_correlate_on_the_pinned_tuple_whatever_the_field() {
        let length_point = stray_point("udp.length");

        // The rule a *mutated* case follows: a case that garbles `udp.length`
        // cannot present the port `send_recv`'s C3 check compares, so its reply
        // is correlated on the host alone. The seed a baseline and a liveness
        // probe send is unmutated, so the pin is always possible for it — and
        // the looser rule must not leak onto it from the point's field.
        let target = &length_point.plan.target;
        let seed = length_point.seed0.spec.clone();
        let window = Duration::from_millis(50);
        assert_eq!(
            send_recv_spec(target, seed.clone(), FieldPath::Raw, window).dst_port,
            Some(9),
            "an intact transport header pins the target's port"
        );
        assert_eq!(
            send_recv_spec(target, seed, FieldPath::Udp(UdpField::Length), window).dst_port,
            None,
            "a garbled length cannot present a port to pin"
        );

        // The baseline: a frame from another port of the target host is not the
        // seed's reply, on a `udp.length` point exactly as on a `raw` one.
        // Which class a *rejected* frame earns is `send_recv`'s correlator to
        // say and is pinned by its own tests; what this point fuzzes must not
        // change it, and it is never `Clean` — `Clean` is the stray frame
        // mistaken for the target's own answer.
        let length_run = length_point.run_point().await;
        let raw_point = stray_point("raw");
        let raw_run = raw_point.run_point().await;
        assert_ne!(
            raw_run.baseline,
            Some(CaseClass::Clean),
            "the pinned correlation rejects the stray frame"
        );
        assert_eq!(
            length_run.baseline, raw_run.baseline,
            "the baseline is correlated the same way whatever this point fuzzes"
        );

        // Every liveness probe, too. Read against the baseline a pinned send
        // measures, a probe correlating loosely reads the stray frame as
        // `Clean` and so calls the target changed.
        let probe_point = stray_point("udp.length");
        *lock(&probe_point.baseline) = raw_run.baseline;
        assert!(
            probe_point.liveness_probe().await.expect("the probe sends"),
            "the probe reads the stray frame as the baseline did"
        );
    }
}
