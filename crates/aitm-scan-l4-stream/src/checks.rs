//! The three `Check` implementations over one shared `Campaign` (spec S6).
//!
//! A campaign is the whole fuzzing of one insertion point: the deterministic
//! schedule (S6.4), the oracle reading of every case, the bounded reproduction
//! of an interesting one and the retirement that follows a crash. The three
//! checks — `l4-crash`, `l4-parser-fault` and `l4-latency-outlier` — share one
//! campaign per point (spec S6.2): the first of them to reach a point runs it
//! and the other two read the stored result, so the traffic is sent once and
//! the three issue classes still carry their own severities.
//!
//! Everything leaves through `&dyn ProbeHost`. The campaign has no client, no
//! guard and no socket of its own; even the liveness probe is asked for through
//! the reserved payload of plan call P5 ([`crate::host::LIVENESS_PAYLOAD`]).
//! The host enforces the denylist, the message bound, the budget, the deadline
//! and the scope, and reports them back as [`HostError`]s this module maps to a
//! [`StopReason`].
//!
//! Nothing here logs or prints a message byte: `Debug` on [`Campaign`] and
//! [`Finding`] prints lengths and counts, and the only hex that reaches an
//! operator is the bounded evidence payload and the dry-run render (S7, S9).

use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use aitm_core::redact::scrub_text;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, CheckScope, Confidence, Evidence, InsertionKind,
    InsertionPoint, Intensity, L4Evidence, L4Oracle, LaneKind, Outcome, Payload, PayloadMode,
    ProbeHost, ProbeResponse, Technique, Verdict,
};
use futures::future::BoxFuture;

use crate::codec::{encode_hex, fnv1a64};
use crate::denylist;
use crate::grammar::{self, Grammar};
use crate::host::{HostError, LIVENESS_PAYLOAD};
use crate::mutate::schedule::Schedule;
use crate::mutate::structure::{affects_framing, Case};
use crate::oracle;
use crate::spec::GrammarKind;
use crate::state::{
    lock, not_this_lanes_point, proto_name, seed_does_not_parse, DiscoveredPoint, JobState,
    LaneState, MAX_CASES_PER_JOB, MAX_PRELUDE, RECOVERY_POLL, RECOVERY_WINDOW, REPRODUCE_SPACING,
};
use crate::tree::{FieldPath, Node};

/// The verdict `detail` bound outside a dry run (spec S6.5).
const MAX_DETAIL: usize = 2048;

/// The dry-run report's bound (spec S7).
const MAX_DRY_RUN_DETAIL: usize = 16384;

/// How many rendered cases the dry-run report lists (spec S7).
const DRY_RUN_FIRST: usize = 50;

/// How many bytes of a rendered case the dry-run report shows (spec S7).
const DRY_RUN_HEX: usize = 64;

/// The bound on `Evidence::payload`, in hex characters (spec S6.3).
const MAX_PAYLOAD_HEX: usize = 256;

/// The bound on the reply excerpt kept for `Evidence::matched` (spec S6.3).
const MAX_REPLY_EXCERPT: usize = 256;

/// The bound on the `seed_notes=[...]` clause of the S6.5 detail line.
const MAX_SEED_NOTES: usize = 2048;

/// The A2 miss: a check whose host belongs to no known job sends nothing.
const NO_JOB_STATE: &str = "l4_stream: no job state for this host";

// ---------------------------------------------------------------------------
// What a campaign found and why it stopped
// ---------------------------------------------------------------------------

/// One interesting case, reproduced and recorded (spec S6.2).
///
/// `Debug` prints the oracle, the reproduction count and lengths; the case's
/// own `Debug` prints its bytes as a length, and the reply excerpt is never
/// printed (S9, C11).
#[derive(Clone)]
pub struct Finding {
    /// The case that produced the reaction.
    pub case: Case,
    /// Everything needed to re-run it.
    pub evidence: L4Evidence,
    /// A bounded excerpt of what came back, scrubbed at verdict time.
    pub reply_excerpt: String,
    /// `(elapsed_ms, median_ms)` for a latency finding: the S6.5 clause needs
    /// both numbers and `L4Evidence` has no field for either.
    pub timing: Option<(u32, u32)>,
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("case", &self.case)
            .field("oracle", &self.evidence.oracle)
            .field("reproduced", &self.evidence.reproduced)
            .field(
                "reply_excerpt",
                &format_args!("<{len} bytes>", len = self.reply_excerpt.len()),
            )
            .field("timing", &self.timing)
            .finish()
    }
}

/// Why a campaign stopped sending (spec S6.2, S6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Every planned case was sent, or the schedule ran out of distinct ones.
    Completed,
    /// The job's budget refused a charge.
    Budget,
    /// The job's deadline passed.
    Deadline,
    /// The job was cancelled.
    Cancelled,
    /// This many silent cases in a row.
    ConsecutiveTimeouts(u32),
    /// The target did not answer a liveness probe within the recovery window.
    TargetDown,
    /// The point's node was marked down by an earlier campaign of this job,
    /// so this one sent nothing (spec S6.2, F10).
    ///
    /// The same `stop=target_down` token as [`StopReason::TargetDown`] — it
    /// is the same answer about the same endpoint — with its own clause, so
    /// the detail does not claim this campaign waited a recovery window it
    /// never entered.
    NodeDown,
    /// The L4 guard refused; the message is already in the D3 form.
    Guard(String),
    /// The job reached [`MAX_CASES_PER_JOB`].
    LaneCap,
    /// The profile is a dry run: every case was rendered, none was sent.
    DryRun,
    /// The point was retired after a confirmed crash.
    Retired,
}

impl StopReason {
    /// The `stop=` token of the S6.5 detail line.
    fn token(&self) -> String {
        match self {
            StopReason::Completed => "completed".to_string(),
            StopReason::Budget => "budget".to_string(),
            StopReason::Deadline => "deadline".to_string(),
            StopReason::Cancelled => "cancelled".to_string(),
            StopReason::ConsecutiveTimeouts(n) => format!("consecutive_timeouts({n})"),
            StopReason::TargetDown | StopReason::NodeDown => "target_down".to_string(),
            StopReason::Guard(_) => "guard".to_string(),
            StopReason::LaneCap => "lane_cap".to_string(),
            StopReason::DryRun => "dry_run".to_string(),
            StopReason::Retired => "retired".to_string(),
        }
    }

    /// The S6.5 stop clause, when the stop is worth a sentence of its own.
    fn clause(&self) -> Option<String> {
        match self {
            StopReason::Completed | StopReason::Retired => None,
            StopReason::Budget => Some("budget exhausted".to_string()),
            StopReason::Deadline => Some("deadline".to_string()),
            StopReason::Cancelled => Some("cancelled".to_string()),
            StopReason::ConsecutiveTimeouts(n) => Some(format!("consecutive timeouts {n}")),
            StopReason::TargetDown => Some(format!(
                "target did not recover within {secs} s",
                secs = RECOVERY_WINDOW.as_secs()
            )),
            StopReason::NodeDown => Some("node marked down earlier in this job".to_string()),
            StopReason::Guard(message) => Some(format!("guard refused: {message}")),
            StopReason::LaneCap => Some(format!("lane cap {MAX_CASES_PER_JOB} reached")),
            StopReason::DryRun => Some("dry run".to_string()),
        }
    }
}

/// What a dry run would have sent (spec S7).
///
/// `first` holds the rendered lines, each with the first 64 bytes of a case in
/// hex: the one place in the lane where a message's bytes are shown, and only
/// because nothing was sent.
#[derive(Clone)]
pub struct DryRunReport {
    /// Cases the schedule produced.
    pub total: u32,
    /// How many of them the denylist would have refused.
    pub denylisted: u32,
    /// The first [`DRY_RUN_FIRST`] rendered lines.
    pub first: Vec<String>,
}

impl fmt::Debug for DryRunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DryRunReport")
            .field("total", &self.total)
            .field("denylisted", &self.denylisted)
            .field("first", &self.first.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The campaign
// ---------------------------------------------------------------------------

/// The whole fuzzing of one point (spec S6.2).
///
/// Built once per point per job and read by all three checks. `Debug` prints
/// counters and the findings' shapes, never a byte of a case or a reply.
#[derive(Clone)]
pub struct Campaign {
    /// The point the campaign ran against.
    pub point_id: String,
    /// The seed the schedule was built from, so the run is reproducible.
    pub rng_seed: u64,
    /// This point's share of the job's cases.
    pub cases_planned: u32,
    /// Cases from the schedule that reached the host.
    pub cases_sent: u32,
    /// Cases the denylist refused.
    pub skipped_denylisted: u32,
    /// Cases over the 64 KiB message bound.
    pub skipped_too_large: u32,
    /// How often the guard's injection rate made the host wait.
    pub rate_waits: u32,
    /// How often a refused connect made the campaign wait the target back
    /// before sending a case (spec S6.2, F9).
    pub connect_waits: u32,
    /// Latency evaluations the F4 guard skipped: cases that leave the frame
    /// incomplete, whose delay is the peer's framing timeout.
    pub latency_skipped_framing: u32,
    /// The confirmed crash, if any.
    pub crash: Option<Finding>,
    /// The confirmed parser fault, if any.
    pub parser_fault: Option<Finding>,
    /// The confirmed latency outlier, if any.
    pub latency: Option<Finding>,
    /// Why the campaign stopped.
    pub stopped: StopReason,
    /// What a dry run would have sent (spec S7).
    pub dry_run: Option<DryRunReport>,
}

impl fmt::Debug for Campaign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Campaign")
            .field("point_id", &self.point_id)
            .field("rng_seed", &self.rng_seed)
            .field("cases_planned", &self.cases_planned)
            .field("cases_sent", &self.cases_sent)
            .field("skipped_denylisted", &self.skipped_denylisted)
            .field("skipped_too_large", &self.skipped_too_large)
            .field("rate_waits", &self.rate_waits)
            .field("connect_waits", &self.connect_waits)
            .field("latency_skipped_framing", &self.latency_skipped_framing)
            .field("crash", &self.crash)
            .field("parser_fault", &self.parser_fault)
            .field("latency", &self.latency)
            .field("stopped", &self.stopped)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

impl Campaign {
    /// An empty campaign for `point_id`, before the first case.
    fn new(point_id: String, rng_seed: u64, cases_planned: u32) -> Campaign {
        Campaign {
            point_id,
            rng_seed,
            cases_planned,
            cases_sent: 0,
            skipped_denylisted: 0,
            skipped_too_large: 0,
            rate_waits: 0,
            connect_waits: 0,
            latency_skipped_framing: 0,
            crash: None,
            parser_fault: None,
            latency: None,
            stopped: StopReason::Completed,
            dry_run: None,
        }
    }

    /// Run this point's campaign, or read the one another check already ran
    /// (spec S6.2, amendment A2).
    ///
    /// The job is found by the host's marker, which is the only handle a check
    /// has; a miss means no `probe_host_for` ran for this job, or the state was
    /// evicted, and the campaign sends nothing.
    ///
    /// # Errors
    ///
    /// The [`Verdict`] the calling check must return as-is: `Outcome::Error`
    /// when there is no job state for the host, when the point is not this
    /// job's, or when the point's seed no longer parses under its grammar.
    pub async fn run_or_read(
        point: &InsertionPoint,
        host: &dyn ProbeHost,
        state: &LaneState,
    ) -> Result<Arc<Campaign>, Verdict> {
        let Some(job) = state.job_by_marker(&host.marker()) else {
            return Err(error_verdict(NO_JOB_STATE.to_string()));
        };
        let slot = {
            let mut campaigns = lock(&job.campaigns);
            Arc::clone(
                campaigns
                    .entry(point.id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
            )
        };
        let mut held = slot.lock().await;
        if let Some(existing) = held.as_ref() {
            return Ok(Arc::new(existing.clone()));
        }
        let campaign = run(point, host, &job).await?;
        *held = Some(campaign.clone());
        Ok(Arc::new(campaign))
    }
}

/// The grammar the point's endpoint speaks: the inferred one when discovery
/// stored a handle for the node (TLV and raw are per-endpoint), else the
/// registry's grammar for the named kind.
fn grammar_for(job: &JobState, dp: &DiscoveredPoint) -> Arc<dyn Grammar> {
    if let Some(inferred) = lock(&job.grammars).get(&dp.node_id) {
        return Arc::clone(inferred);
    }
    grammar::by_kind(dp.grammar)
}

/// This point's share of the job's cases (spec S6.2). Reachable for
/// `tests/campaign.rs`, which rebuilds the deterministic schedule from this
/// one rule rather than a copy; not part of the public API.
#[doc(hidden)]
pub fn cases_planned(profile_cases: u32, points_total: u32, budget_left: u32) -> u32 {
    let capped = profile_cases.min(MAX_CASES_PER_JOB);
    let share = (capped / points_total.max(1)).max(1);
    share.min(budget_left)
}

/// The other seeds of the same endpoint, which `Crossover*` and `Splice` draw
/// from (spec S6.4). Reachable for `tests/campaign.rs` for the same reason as
/// [`cases_planned`] — a schedule built without the campaign's own donors
/// diverges from it after stage one — and not part of the public API.
#[doc(hidden)]
pub fn donors_for(job: &JobState, dp: &DiscoveredPoint) -> Vec<Vec<u8>> {
    let mut donors: Vec<Vec<u8>> = Vec::new();
    for other in lock(&job.points).values() {
        if other.node_id != dp.node_id || other.seed_id == dp.seed_id {
            continue;
        }
        if !donors.contains(&other.seed_bytes) {
            donors.push(other.seed_bytes.clone());
        }
    }
    donors.sort();
    donors
}

/// The seed of one point's schedule: the host's marker and the point's id,
/// so a run is reproducible and two points never share a schedule.
fn rng_seed_for(host: &dyn ProbeHost, point: &InsertionPoint) -> u64 {
    fnv1a64(
        format!(
            "{marker}|{id}",
            marker = host.marker(),
            id = point.id.as_str()
        )
        .as_bytes(),
    )
}

/// Build and run one campaign.
async fn run(
    point: &InsertionPoint,
    host: &dyn ProbeHost,
    job: &Arc<JobState>,
) -> Result<Campaign, Verdict> {
    let Some(dp) = lock(&job.points).get(&point.id).cloned() else {
        return Err(error_verdict(not_this_lanes_point(&point.id, &job.job_id)));
    };
    // A crash on this field, from any seed, already retired the path (spec
    // S6.2, F8). Every case this point could send would re-crash the same
    // field for an issue the engine dedupes into the first one, so the
    // campaign is empty and the three checks read it without sending: no
    // recovery window, no replays, no second verdict of the same crash.
    if job.is_path_retired(&dp.node_id, dp.field_path()) {
        let mut campaign = Campaign::new(point.id.clone(), rng_seed_for(host, point), 0);
        campaign.stopped = StopReason::Retired;
        tracing::debug!(
            point = %point.id,
            node = %dp.node_id,
            stop = "retired",
            "l4 stream campaign skipped: the field path is retired"
        );
        return Ok(campaign);
    }

    // The endpoint stopped answering an earlier campaign of this job and
    // never came back (spec S6.2, F10). Every point on the node would pay a
    // recovery window of its own to learn the same thing, and a node carries
    // a point per `(seed, field path)` pair, so the campaign is empty and the
    // three checks read it: no parse, no baseline, no socket.
    if job.is_node_down(&dp.node_id) {
        let mut campaign = Campaign::new(point.id.clone(), rng_seed_for(host, point), 0);
        campaign.stopped = StopReason::NodeDown;
        tracing::debug!(
            point = %point.id,
            node = %dp.node_id,
            stop = "target_down",
            "l4 stream campaign skipped: the node was marked down"
        );
        return Ok(campaign);
    }

    let grammar = grammar_for(job, &dp);
    let Some(tree) = grammar.parse(&dp.seed_bytes) else {
        return Err(error_verdict(seed_does_not_parse(
            &dp.seed_id,
            &point.id,
            grammar.name(),
        )));
    };

    let path = FieldPath::new(point.path.as_deref().unwrap_or_default());
    let rng_seed = rng_seed_for(host, point);
    let profile = host.profile();
    let planned = cases_planned(
        profile.l4.cases,
        job.points_total.load(Ordering::SeqCst),
        host.budget_left(),
    );
    // The point's own node, kept for the latency path's framing guard (F4);
    // the schedule takes the tree.
    let node = tree.get(&path).cloned();
    let schedule = Schedule::new(
        tree,
        grammar.spec(),
        path.clone(),
        dp.grammar,
        rng_seed,
        planned,
        donors_for(job, &dp),
    );
    let mut campaign = Campaign::new(point.id.clone(), rng_seed, planned);

    if profile.l4.dry_run {
        campaign.dry_run = Some(dry_run_report(schedule, dp.grammar));
        campaign.stopped = StopReason::DryRun;
        tracing::debug!(
            point = %point.id,
            cases_planned = planned,
            stop = "dry_run",
            "l4 stream campaign rendered"
        );
        return Ok(campaign);
    }

    let waits_before = job.rate_waits.load(Ordering::SeqCst);
    let mut runner = Runner {
        host,
        job,
        dp: &dp,
        grammar: &grammar,
        node,
        rng_seed,
        reproduce: profile.l4.reproduce_count.max(1),
        alive: true,
    };
    runner.drive(schedule, &mut campaign).await;
    campaign.rate_waits = job
        .rate_waits
        .load(Ordering::SeqCst)
        .saturating_sub(waits_before);
    tracing::debug!(
        point = %point.id,
        cases_planned = planned,
        cases_sent = campaign.cases_sent,
        stop = %campaign.stopped.token(),
        "l4 stream campaign finished"
    );
    if campaign.stopped == StopReason::TargetDown {
        // The endpoint never came back, so the rest of the job's points on
        // it stop at once rather than each paying a recovery window (F10).
        job.mark_node_down(&dp.node_id);
        // The one stop an operator must see without turning on debug
        // logging: the target stopped answering and did not come back
        // (spec S9, SPEC-I3). Ids and counts only, never a byte. The marking
        // above is part of this same stop and is not logged again.
        tracing::warn!(
            point = %point.id,
            node = %dp.node_id,
            job = %job.job_id,
            cases_sent = campaign.cases_sent,
            recovery_window_s = RECOVERY_WINDOW.as_secs(),
            down_nodes = lock(&job.down_nodes).len(),
            "l4 stream target did not recover; the node is down for this job"
        );
    }
    Ok(campaign)
}

/// What one probe error means for the loop.
enum Step {
    /// Count the skip and go on to the next case.
    SkipDenylisted,
    /// Count the skip and go on to the next case.
    SkipTooLarge,
    /// The transport could not reach the peer, so nothing went out: wait the
    /// target back and send the same case once more (spec S6.2, F9).
    ConnectFailed,
    /// Stop the campaign.
    Stop(StopReason),
}

/// Read a probe's error back as a loop decision (spec S6.2).
///
/// A host error that cannot happen on this path (`NotBytes`, `Unsupported`)
/// and any error the host did not raise itself are reported as a refusal, so
/// the check's verdict is `Error` rather than a silent `Clean`. No branch
/// renders bytes: `HostError` carries none, and a foreign error is replaced by
/// a fixed string rather than printed.
fn step_for(error: &anyhow::Error) -> Step {
    let Some(host_error) = error.downcast_ref::<HostError>() else {
        return Step::Stop(StopReason::Guard(
            "l4_stream: the probe failed with an error the lane did not raise".to_string(),
        ));
    };
    match host_error {
        HostError::Denylisted(_) => Step::SkipDenylisted,
        HostError::TooLarge => Step::SkipTooLarge,
        HostError::Budget => Step::Stop(StopReason::Budget),
        HostError::Deadline => Step::Stop(StopReason::Deadline),
        HostError::Cancelled => Step::Stop(StopReason::Cancelled),
        HostError::ConsecutiveTimeouts(n) => Step::Stop(StopReason::ConsecutiveTimeouts(*n)),
        HostError::Retired => Step::Stop(StopReason::Retired),
        // The endpoint was marked down earlier in this job (F10); the host
        // refuses before the socket, so nothing went out.
        HostError::TargetDown => Step::Stop(StopReason::NodeDown),
        HostError::Guard(message) => Step::Stop(StopReason::Guard(message.clone())),
        HostError::DryRun => Step::Stop(StopReason::DryRun),
        // The transport could not reach the peer at all. Nothing went out,
        // so this is a pre-existing down state and not a reading about the
        // case: the caller waits the target back and retries it once, and
        // only a second refusal is the target being down (F9).
        HostError::Connect(_) => Step::ConnectFailed,
        HostError::NotBytes | HostError::Unsupported(_) => Step::Stop(StopReason::Guard(format!(
            "l4_stream: the host refused the probe: {host_error}"
        ))),
    }
}

/// The stop a loop decision means where there is no next case to go on to:
/// the opening baseline and its retry (F9).
fn stop_of(step: Step) -> StopReason {
    match step {
        Step::Stop(reason) => reason,
        Step::ConnectFailed => StopReason::TargetDown,
        // The baseline is the grammar's own fixed exchange: neither filter
        // applies to it, and neither ends the campaign.
        Step::SkipDenylisted | Step::SkipTooLarge => StopReason::Completed,
    }
}

/// The case loop and the three reaction paths of spec S6.2.
struct Runner<'a> {
    host: &'a dyn ProbeHost,
    job: &'a Arc<JobState>,
    dp: &'a DiscoveredPoint,
    grammar: &'a Arc<dyn Grammar>,
    /// The node the point names, when the seed's tree has one. Only the
    /// latency path reads it, for the F4 framing guard.
    node: Option<Node>,
    rng_seed: u64,
    reproduce: u32,
    /// The last known liveness of the target, which becomes a finding's
    /// `liveness_before`.
    alive: bool,
}

impl Runner<'_> {
    /// Send one case and read its reaction.
    async fn probe(&self, bytes: &[u8]) -> Result<ProbeResponse, Step> {
        let payload = Payload {
            value: String::new(),
            mode: PayloadMode::Replace,
            bytes: Some(bytes.to_vec()),
        };
        self.host.probe(&payload).await.map_err(|e| step_for(&e))
    }

    /// One liveness reading through the reserved payload (plan call P5).
    async fn liveness(&self) -> Result<bool, StopReason> {
        let payload = Payload {
            value: LIVENESS_PAYLOAD.to_string(),
            mode: PayloadMode::Replace,
            bytes: None,
        };
        match self.host.probe(&payload).await {
            // `l4: None` is the host's "the target answered"; an `L4Reply`
            // here carries `LivenessFailed`.
            Ok(response) => Ok(!failed_liveness(&response)),
            Err(e) => match step_for(&e) {
                Step::Stop(reason) => Err(reason),
                // A probe that cannot reach the peer is the reading itself.
                Step::ConnectFailed => Ok(false),
                // A liveness probe is never denylisted or too large.
                Step::SkipDenylisted | Step::SkipTooLarge => Ok(false),
            },
        }
    }

    /// Poll liveness every second for up to [`RECOVERY_WINDOW`] (spec S6.2).
    async fn wait_recovery(&mut self) -> Result<bool, StopReason> {
        let started = Instant::now();
        loop {
            if self.liveness().await? {
                self.alive = true;
                return Ok(true);
            }
            self.alive = false;
            if started.elapsed() >= RECOVERY_WINDOW {
                return Ok(false);
            }
            tokio::time::sleep(RECOVERY_POLL).await;
        }
    }

    /// Replay one case `n` times, counting the attempts whose oracle reads
    /// `want` again (spec S6.2).
    ///
    /// `recover` is the crash path's extra step: wait for the target to come
    /// back before each attempt after the first.
    async fn reproduce(
        &mut self,
        case: &Case,
        want: L4Oracle,
        recover: bool,
    ) -> (u32, Option<StopReason>) {
        let n = self.reproduce;
        let mut confirmed = 0;
        for attempt in 0..n {
            if recover && attempt > 0 {
                match self.wait_recovery().await {
                    Ok(true) => {}
                    Ok(false) => return (confirmed, Some(StopReason::TargetDown)),
                    Err(reason) => return (confirmed, Some(reason)),
                }
            }
            tokio::time::sleep(REPRODUCE_SPACING).await;
            match self.probe(&case.bytes).await {
                Ok(response) => {
                    let oracle = response.l4.as_ref().map(|reply| reply.oracle);
                    if oracle == Some(want) {
                        confirmed += 1;
                    }
                    self.alive = oracle != Some(L4Oracle::LivenessFailed);
                }
                Err(Step::SkipDenylisted | Step::SkipTooLarge) => {
                    // The identical case passed the same filters already.
                    return (confirmed, None);
                }
                // A replay runs behind its own recovery wait, so a peer that
                // still cannot be reached is the target being down.
                Err(Step::ConnectFailed) => return (confirmed, Some(StopReason::TargetDown)),
                Err(Step::Stop(reason)) => return (confirmed, Some(reason)),
            }
        }
        (confirmed, None)
    }

    /// The evidence record for one case and its reading (spec S6.2).
    fn evidence(
        &self,
        case: &Case,
        oracle: L4Oracle,
        liveness_before: bool,
        liveness_after: bool,
        reproduced: (u32, u32),
    ) -> L4Evidence {
        let prelude = self.grammar.prelude_for(&case.bytes).len().min(MAX_PRELUDE);
        L4Evidence {
            sent_hex: encode_hex(&case.bytes),
            seed_id: self.dp.seed_id.clone(),
            rng_seed: self.rng_seed,
            mutation_chain: case.chain.clone(),
            prior_messages: u32::try_from(prelude).unwrap_or(u32::MAX),
            oracle,
            liveness_before,
            liveness_after,
            reproduced,
            scope_entry: self.dp.scope_entry.clone(),
        }
    }

    /// One opening baseline exchange.
    async fn baseline_once(&mut self) -> Result<(), Step> {
        match self.host.baseline().await {
            Ok(response) => {
                self.alive = !failed_liveness(&response);
                Ok(())
            }
            Err(e) => Err(step_for(&e)),
        }
    }

    /// Wait the target back after a refused connect, counting the wait
    /// (spec S6.2, F9).
    ///
    /// `true` when the caller may try the same exchange once more; `false`
    /// when the campaign must stop, with the reason already recorded.
    async fn wait_after_refused_connect(&mut self, campaign: &mut Campaign) -> bool {
        campaign.connect_waits += 1;
        self.alive = false;
        match self.wait_recovery().await {
            Ok(true) => true,
            Ok(false) => {
                campaign.stopped = StopReason::TargetDown;
                false
            }
            Err(reason) => {
                campaign.stopped = reason;
                false
            }
        }
    }

    /// The opening baseline, behind one recovery wait when the connect
    /// itself was refused (F9). `true` when the campaign may go on.
    async fn baseline_with_retry(&mut self, campaign: &mut Campaign) -> bool {
        let Err(step) = self.baseline_once().await else {
            return true;
        };
        if !matches!(step, Step::ConnectFailed) {
            campaign.stopped = stop_of(step);
            return false;
        }
        // The campaign may have started inside another point's crash window:
        // a peer that cannot be reached before anything was sent is a
        // pre-existing down state, not a reading of this point.
        if !self.wait_after_refused_connect(campaign).await {
            return false;
        }
        match self.baseline_once().await {
            Ok(()) => true,
            Err(step) => {
                campaign.stopped = stop_of(step);
                false
            }
        }
    }

    /// The whole case loop.
    async fn drive(&mut self, schedule: Schedule, campaign: &mut Campaign) {
        if !self.baseline_with_retry(campaign).await {
            return;
        }

        for case in schedule {
            if self.host.cancelled() {
                campaign.stopped = StopReason::Cancelled;
                return;
            }
            if self.job.cases_sent.load(Ordering::SeqCst) >= MAX_CASES_PER_JOB {
                campaign.stopped = StopReason::LaneCap;
                return;
            }

            let response = match self.probe(&case.bytes).await {
                Ok(response) => response,
                Err(Step::SkipDenylisted) => {
                    campaign.skipped_denylisted += 1;
                    continue;
                }
                Err(Step::SkipTooLarge) => {
                    campaign.skipped_too_large += 1;
                    continue;
                }
                // Nothing went out, so this is not a reading of the case:
                // wait the target back and send the same case once more
                // (F9). The refused attempt is not a sent case.
                Err(Step::ConnectFailed) => {
                    if !self.wait_after_refused_connect(campaign).await {
                        return;
                    }
                    match self.probe(&case.bytes).await {
                        Ok(response) => response,
                        Err(Step::SkipDenylisted) => {
                            campaign.skipped_denylisted += 1;
                            continue;
                        }
                        Err(Step::SkipTooLarge) => {
                            campaign.skipped_too_large += 1;
                            continue;
                        }
                        // It answered the recovery poll and still refuses
                        // the case's connection: the target is down.
                        Err(Step::ConnectFailed) => {
                            campaign.stopped = StopReason::TargetDown;
                            return;
                        }
                        Err(Step::Stop(reason)) => {
                            campaign.stopped = reason;
                            return;
                        }
                    }
                }
                Err(Step::Stop(reason)) => {
                    campaign.stopped = reason;
                    return;
                }
            };
            campaign.cases_sent += 1;

            match response.l4.as_ref().map(|reply| reply.oracle) {
                Some(L4Oracle::LivenessFailed) => {
                    if self.crash(&case, &response, campaign).await {
                        return;
                    }
                }
                // A `Reset` reaching the campaign means the liveness probe
                // that followed the case passed — a failed one would be
                // `LivenessFailed` — which is exactly the oracle's own
                // parser-fault predicate (A7).
                Some(oracle) if oracle::is_parser_fault_candidate(oracle, true) => {
                    if self.parser_fault(&case, &response, campaign).await {
                        return;
                    }
                }
                // `ProtocolError` is a clean refusal (A7); `Silence` and
                // `Icmp` with liveness still passing are noise the
                // consecutive-timeout ceiling handles.
                Some(_) => self.alive = true,
                None => {
                    self.alive = true;
                    if self.latency(&case, &response, campaign).await {
                        return;
                    }
                }
            }
        }
        campaign.stopped = StopReason::Completed;
    }

    /// The crash path (spec S6.2). `true` when the campaign must stop.
    async fn crash(
        &mut self,
        case: &Case,
        response: &ProbeResponse,
        campaign: &mut Campaign,
    ) -> bool {
        let liveness_before = self.alive;
        self.alive = false;
        let excerpt = reply_excerpt(response);

        match self.wait_recovery().await {
            Err(reason) => {
                campaign.stopped = reason;
                return true;
            }
            Ok(false) => {
                // A target that stays down after one case is the strongest
                // signal there is, and the one that cannot be reproduced.
                let evidence = self.evidence(
                    case,
                    L4Oracle::LivenessFailed,
                    liveness_before,
                    false,
                    (1, 1),
                );
                self.record_crash(case, evidence, excerpt, campaign);
                campaign.stopped = StopReason::TargetDown;
                return true;
            }
            Ok(true) => {}
        }

        let (confirmed, stop) = self.reproduce(case, L4Oracle::LivenessFailed, true).await;
        if confirmed == 0 {
            tracing::debug!(
                point = %campaign.point_id,
                case = case.index,
                "one-off liveness failure, not reproduced"
            );
            if let Some(reason) = stop {
                campaign.stopped = reason;
                return true;
            }
            return false;
        }
        let evidence = self.evidence(
            case,
            L4Oracle::LivenessFailed,
            liveness_before,
            false,
            (confirmed, self.reproduce),
        );
        self.record_crash(case, evidence, excerpt, campaign);
        campaign.stopped = stop.unwrap_or(StopReason::Retired);
        true
    }

    /// Record a crash, and retire both the point and the field path it sits
    /// on (spec S6.2 step 5, F8).
    ///
    /// The path is retired for the same reason the engine dedupes on it: one
    /// endpoint yields a point per `(seed, field path)` pair, so a field that
    /// crashes the target crashes it once per seed, for one issue and a
    /// recovery window plus three replays each time.
    fn record_crash(
        &self,
        case: &Case,
        evidence: L4Evidence,
        reply_excerpt: String,
        campaign: &mut Campaign,
    ) {
        tracing::info!(
            class = "l4-crash",
            point = %campaign.point_id,
            reproduced = ?evidence.reproduced,
            chain = ?evidence.mutation_chain,
            "l4 stream finding"
        );
        campaign.crash = Some(Finding {
            case: case.clone(),
            evidence,
            reply_excerpt,
            timing: None,
        });
        self.job.crashes.fetch_add(1, Ordering::SeqCst);
        self.job.retire(&campaign.point_id);
        self.job.retire_path(&self.dp.node_id, self.dp.field_path());
    }

    /// The parser-fault path (spec S6.2, amendment A7). `true` when the
    /// campaign must stop.
    async fn parser_fault(
        &mut self,
        case: &Case,
        response: &ProbeResponse,
        campaign: &mut Campaign,
    ) -> bool {
        // A `Reset` reading reaches the campaign only when the liveness probe
        // that followed the case passed: a failed one is `LivenessFailed`.
        self.alive = true;
        if campaign.parser_fault.is_some() {
            return false;
        }
        let excerpt = reply_excerpt(response);
        let (confirmed, stop) = self.reproduce(case, L4Oracle::Reset, false).await;
        if confirmed > 0 {
            let evidence = self.evidence(
                case,
                L4Oracle::Reset,
                true,
                true,
                (confirmed, self.reproduce),
            );
            tracing::info!(
                class = "l4-parser-fault",
                point = %campaign.point_id,
                reproduced = ?evidence.reproduced,
                chain = ?evidence.mutation_chain,
                "l4 stream finding"
            );
            campaign.parser_fault = Some(Finding {
                case: case.clone(),
                evidence,
                reply_excerpt: excerpt,
                timing: None,
            });
            self.job.parser_faults.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(reason) = stop {
            campaign.stopped = reason;
            return true;
        }
        false
    }

    /// The latency path (spec S6.1, S6.2). `true` when the campaign must stop.
    async fn latency(
        &mut self,
        case: &Case,
        response: &ProbeResponse,
        campaign: &mut Campaign,
    ) -> bool {
        if campaign.latency.is_some() {
            return false;
        }
        // F4: a case that leaves the frame incomplete is answered when the
        // peer's framing timeout expires, so its latency says nothing about
        // the peer's processing. The whole rule is skipped, the confirming
        // repeat included. A point with no node in the tree has no cases at
        // all, so the `None` arm is never the one that matters.
        if self
            .node
            .as_ref()
            .is_some_and(|node| affects_framing(node, &case.chain))
        {
            campaign.latency_skipped_framing = campaign.latency_skipped_framing.saturating_add(1);
            return false;
        }
        let Some(median) = self.job.latency_median() else {
            return false;
        };
        if !oracle::latency_outlier(response.elapsed_ms, Some(median)) {
            return false;
        }
        let repeat = match self.probe(&case.bytes).await {
            Ok(repeat) => repeat,
            Err(Step::SkipDenylisted | Step::SkipTooLarge) => return false,
            // The confirming repeat follows a case the target answered, so a
            // peer that cannot now be reached has gone away: today's meaning,
            // unchanged by F9, which only covers a connect refused before a
            // case went out.
            Err(Step::ConnectFailed) => {
                campaign.stopped = StopReason::TargetDown;
                return true;
            }
            Err(Step::Stop(reason)) => {
                campaign.stopped = reason;
                return true;
            }
        };
        if repeat.l4.is_some() || !oracle::latency_confirms(repeat.elapsed_ms, median) {
            return false;
        }
        let evidence = self.evidence(case, L4Oracle::LatencyOutlier, true, true, (1, 2));
        tracing::info!(
            class = "l4-latency-outlier",
            point = %campaign.point_id,
            elapsed_ms = response.elapsed_ms,
            median_ms = median,
            "l4 stream finding"
        );
        campaign.latency = Some(Finding {
            case: case.clone(),
            evidence,
            reply_excerpt: reply_excerpt(response),
            timing: Some((response.elapsed_ms, median)),
        });
        false
    }
}

/// Whether a response is the host's "the target did not answer" reading.
fn failed_liveness(response: &ProbeResponse) -> bool {
    response
        .l4
        .as_ref()
        .is_some_and(|reply| reply.oracle == L4Oracle::LivenessFailed)
}

/// A bounded excerpt of whatever came back, before scrubbing.
fn reply_excerpt(response: &ProbeResponse) -> String {
    let bytes = match response.l4.as_ref() {
        Some(reply) => reply.bytes.as_slice(),
        None => response.body.as_slice(),
    };
    let shown = bytes.get(..MAX_REPLY_EXCERPT).unwrap_or(bytes);
    String::from_utf8_lossy(shown).into_owned()
}

/// Render every case without sending one (spec S7).
fn dry_run_report(schedule: Schedule, kind: GrammarKind) -> DryRunReport {
    let mut report = DryRunReport {
        total: 0,
        denylisted: 0,
        first: Vec::new(),
    };
    for case in schedule {
        report.total = report.total.saturating_add(1);
        let refused = denylist::refuses(kind, &case.bytes).is_some();
        if refused {
            report.denylisted = report.denylisted.saturating_add(1);
        }
        if report.first.len() >= DRY_RUN_FIRST {
            continue;
        }
        let tail = if refused {
            "<denylisted>".to_string()
        } else {
            let shown = case.bytes.get(..DRY_RUN_HEX).unwrap_or(&case.bytes);
            let mut hex = encode_hex(shown);
            if shown.len() < case.bytes.len() {
                hex.push_str("...");
            }
            hex
        };
        report.first.push(format!(
            "#{index} {len}B {chain} {tail}",
            index = case.index,
            len = case.bytes.len(),
            chain = case.chain.join(","),
        ));
    }
    report
}

// ---------------------------------------------------------------------------
// The three checks (spec S6.3)
// ---------------------------------------------------------------------------

/// Which class of finding a check reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Crash,
    ParserFault,
    Latency,
}

impl Class {
    /// This class's finding in a campaign.
    fn finding(self, campaign: &Campaign) -> Option<&Finding> {
        match self {
            Class::Crash => campaign.crash.as_ref(),
            Class::ParserFault => campaign.parser_fault.as_ref(),
            Class::Latency => campaign.latency.as_ref(),
        }
    }

    /// The S6.5 clause for a finding of this class.
    fn clause(self, finding: &Finding) -> String {
        let (confirmed, attempts) = finding.evidence.reproduced;
        match self {
            Class::Crash | Class::ParserFault => format!(
                "{what} reproduced {confirmed}/{attempts} after case #{index} chain=[{chain}]",
                what = if self == Class::Crash {
                    "crash"
                } else {
                    "parser fault"
                },
                index = finding.case.index,
                chain = finding.evidence.mutation_chain.join(","),
            ),
            Class::Latency => {
                let (elapsed, median) = finding.timing.unwrap_or((0, 0));
                format!("latency outlier {elapsed} ms vs median {median} ms")
            }
        }
    }

    /// How sure a finding of this class is (spec S6.2, S6.3).
    fn confidence(self, campaign: &Campaign, finding: &Finding) -> Confidence {
        let (confirmed, attempts) = finding.evidence.reproduced;
        match self {
            // A target that never came back could not be reproduced.
            Class::Crash if campaign.stopped == StopReason::TargetDown => Confidence::Tentative,
            Class::Crash | Class::ParserFault if confirmed >= attempts => Confidence::Firm,
            Class::Crash | Class::ParserFault | Class::Latency => Confidence::Tentative,
        }
    }
}

/// The `l4-crash` check (spec S6.3).
pub struct L4Crash {
    meta: CheckMeta,
    state: Arc<LaneState>,
}

/// The `l4-parser-fault` check (spec S6.3).
pub struct L4ParserFault {
    meta: CheckMeta,
    state: Arc<LaneState>,
}

/// The `l4-latency-outlier` check (spec S6.3).
pub struct L4LatencyOutlier {
    meta: CheckMeta,
    state: Arc<LaneState>,
}

impl Check for L4Crash {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(run_class(Class::Crash, &self.state, point, host))
    }
}

impl Check for L4ParserFault {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(run_class(Class::ParserFault, &self.state, point, host))
    }
}

impl Check for L4LatencyOutlier {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> BoxFuture<'a, Verdict> {
        Box::pin(run_class(Class::Latency, &self.state, point, host))
    }
}

/// The lane's three checks, all sharing one [`LaneState`] (spec S6.3).
#[must_use]
pub fn checks(state: Arc<LaneState>) -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(L4Crash {
            meta: crash_meta(),
            state: Arc::clone(&state),
        }),
        Arc::new(L4ParserFault {
            meta: parser_fault_meta(),
            state: Arc::clone(&state),
        }),
        Arc::new(L4LatencyOutlier {
            meta: latency_meta(),
            state,
        }),
    ]
}

/// Run or read the campaign, then map it into this class's verdict (S6.3).
async fn run_class(
    class: Class,
    state: &LaneState,
    point: &InsertionPoint,
    host: &dyn ProbeHost,
) -> Verdict {
    let campaign = match Campaign::run_or_read(point, host, state).await {
        Ok(campaign) => campaign,
        Err(verdict) => return verdict,
    };
    let Some(job) = state.job_by_marker(&host.marker()) else {
        return error_verdict(NO_JOB_STATE.to_string());
    };
    let point_data = lock(&job.points).get(&campaign.point_id).cloned();
    verdict_for(class, &campaign, &job, point_data.as_ref())
}

/// The S6.3 mapping from a campaign to one class's verdict.
fn verdict_for(
    class: Class,
    campaign: &Campaign,
    job: &JobState,
    dp: Option<&DiscoveredPoint>,
) -> Verdict {
    if let Some(report) = campaign.dry_run.as_ref() {
        return dry_run_verdict(class, campaign, report, dp);
    }

    let base = detail_base(campaign, job, dp);
    match class.finding(campaign) {
        Some(finding) => {
            let mut detail = format!("{base} {clause}", clause = class.clause(finding));
            if let Some(stop) = campaign.stopped.clause() {
                detail = format!("{detail}; {stop}");
            }
            Verdict {
                outcome: Outcome::Vulnerable,
                confidence: class.confidence(campaign, finding),
                evidence: finding_evidence(finding),
                detail: truncate(detail, MAX_DETAIL),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        }
        None => {
            let (outcome, clause) = match campaign.stopped.clause() {
                // A guard refusal is the lane's own error, not a result.
                Some(clause) if matches!(campaign.stopped, StopReason::Guard(_)) => {
                    (Outcome::Error, clause)
                }
                Some(clause) => (Outcome::Inconclusive, clause),
                None => (Outcome::Clean, "clean".to_string()),
            };
            // A point retired by this campaign's own crash is not an
            // inconclusive result for the other two classes: every case that
            // could be sent was sent (spec S6.2 step 5).
            let outcome = if campaign.stopped == StopReason::Retired && campaign.crash.is_none() {
                Outcome::Inconclusive
            } else {
                outcome
            };
            Verdict {
                outcome,
                confidence: Confidence::Tentative,
                evidence: Evidence::default(),
                detail: truncate(format!("{base} {clause}"), MAX_DETAIL),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }
        }
    }
}

/// The S7 verdicts: the report on `l4-crash`, a pointer on the other two.
fn dry_run_verdict(
    class: Class,
    campaign: &Campaign,
    report: &DryRunReport,
    dp: Option<&DiscoveredPoint>,
) -> Verdict {
    let detail = if class == Class::Crash {
        let path = dp
            .and_then(|dp| dp.point.path.clone())
            .unwrap_or_else(|| campaign.point_id.clone());
        let head = format!(
            "dry run: {total} cases for {path} ({denylisted} denylisted would be skipped); first \
             {first}:",
            total = report.total,
            denylisted = report.denylisted,
            first = DRY_RUN_FIRST,
        );
        let body = report.first.join("\n");
        truncate(format!("{head}\n{body}"), MAX_DRY_RUN_DETAIL)
    } else {
        "dry run: see l4-crash for the rendered cases".to_string()
    };
    Verdict {
        outcome: Outcome::Inconclusive,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail,
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

/// The bounded, scrubbed evidence of one finding (spec S6.3).
fn finding_evidence(finding: &Finding) -> Evidence {
    let hex = encode_hex(&finding.case.field_bytes);
    let payload = truncate(hex, MAX_PAYLOAD_HEX);
    let matched = if finding.reply_excerpt.is_empty() {
        oracle_token(finding.evidence.oracle).to_string()
    } else {
        Evidence::excerpt(&scrub_text(&finding.reply_excerpt))
    };
    Evidence {
        payload: Some(payload),
        matched: Some(matched),
        l4: Some(finding.evidence.clone()),
        ..Evidence::default()
    }
}

/// The S6.5 detail line, up to the class clause.
fn detail_base(campaign: &Campaign, job: &JobState, dp: Option<&DiscoveredPoint>) -> String {
    let (grammar, endpoint, path, selection) = match dp {
        Some(dp) => (
            dp.grammar.name().to_string(),
            format!(
                "{ip}:{port}/{proto}",
                ip = dp.endpoint.ip,
                port = dp.endpoint.port,
                proto = proto_name(dp.endpoint.proto),
            ),
            dp.point.path.clone().unwrap_or_default(),
            dp.selection.clone(),
        ),
        None => (
            "unknown".to_string(),
            "unknown".to_string(),
            campaign.point_id.clone(),
            "unknown".to_string(),
        ),
    };
    let line = format!(
        "l4_stream {grammar} {endpoint} point={path} cases={sent}/{planned} \
         skipped_denylisted={denylisted} skipped_too_large={too_large} \
         liveness_probes={probes} liveness_failures={failures} rate_waits={waits} \
         connect_waits={connect_waits} latency_skipped_framing={skipped_framing} stop={stop} \
         selection={selection}",
        sent = campaign.cases_sent,
        planned = campaign.cases_planned,
        denylisted = campaign.skipped_denylisted,
        too_large = campaign.skipped_too_large,
        probes = job.liveness_probes.load(Ordering::SeqCst),
        failures = job.liveness_failures.load(Ordering::SeqCst),
        waits = campaign.rate_waits,
        connect_waits = campaign.connect_waits,
        skipped_framing = campaign.latency_skipped_framing,
        stop = campaign.stopped.token(),
    );
    match seed_notes(job, dp) {
        Some(notes) => format!("{line} seed_notes=[{notes}]"),
        None => line,
    }
}

/// The endpoint's skipped-seed notes, bounded (spec S5.2, SPEC-I2).
///
/// A profile seed this lane cannot use — a `flow:` reference, an empty or
/// over-long one — is skipped at discovery with a note saying why. The note
/// is the operator's only sign that the seed they wrote yielded nothing, so
/// it rides the verdict as well as the discovery line. Reasons and indices
/// only: `corpus::seeds_from_profile` never puts a seed byte in one.
fn seed_notes(job: &JobState, dp: Option<&DiscoveredPoint>) -> Option<String> {
    let node_id = &dp?.node_id;
    let notes = lock(&job.seed_notes).get(node_id)?.join("; ");
    if notes.is_empty() {
        return None;
    }
    Some(truncate(notes, MAX_SEED_NOTES))
}

/// The oracle's name, for a finding whose reply was empty.
fn oracle_token(oracle: L4Oracle) -> &'static str {
    match oracle {
        L4Oracle::ProtocolError => "protocol_error",
        L4Oracle::Reset => "reset",
        L4Oracle::Icmp { .. } => "icmp",
        L4Oracle::Silence => "silence",
        L4Oracle::LivenessFailed => "liveness_failed",
        L4Oracle::LatencyOutlier => "latency_outlier",
    }
}

/// `text` cut to `max` bytes, never splitting a character.
fn truncate(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default().to_string()
}

/// The verdict a check returns when it could not even locate its campaign.
fn error_verdict(detail: String) -> Verdict {
    Verdict {
        outcome: Outcome::Error,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: truncate(detail, MAX_DETAIL),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

/// The `l4-crash` catalogue entry (spec S6.3).
fn crash_meta() -> CheckMeta {
    CheckMeta {
        id: "l4-crash".to_string(),
        name: "L4 service crash on malformed message".to_string(),
        class: "l4-crash".to_string(),
        lanes: vec![LaneKind::L4Stream],
        kinds: vec![InsertionKind::L4Field],
        intensity: Intensity::Medium,
        cost: CheckCost::Heavy,
        technique: Technique::Malformed,
        severity: aitm_poc::Severity::Critical,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(400),
        description: "A mutated message stopped the service answering, confirmed by failed \
                      liveness probes and reproduced."
            .to_string(),
        remediation: Some(REMEDIATION.to_string()),
        origin: CheckOrigin::Native,
        scope: CheckScope::Point,
    }
}

/// The `l4-parser-fault` catalogue entry (spec S6.3).
fn parser_fault_meta() -> CheckMeta {
    CheckMeta {
        id: "l4-parser-fault".to_string(),
        name: "L4 parser fault: connection dropped on malformed message".to_string(),
        class: "l4-parser-fault".to_string(),
        lanes: vec![LaneKind::L4Stream],
        kinds: vec![InsertionKind::L4Field],
        intensity: Intensity::Medium,
        cost: CheckCost::Heavy,
        technique: Technique::Malformed,
        severity: aitm_poc::Severity::Medium,
        confidence_max: Confidence::Firm,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(20),
        description: "The service closes the connection on a malformed message instead of \
                      answering with its protocol error, reproducibly."
            .to_string(),
        remediation: Some(REMEDIATION.to_string()),
        origin: CheckOrigin::Native,
        scope: CheckScope::Point,
    }
}

/// The `l4-latency-outlier` catalogue entry (spec S6.3).
fn latency_meta() -> CheckMeta {
    CheckMeta {
        id: "l4-latency-outlier".to_string(),
        name: "L4 latency outlier on malformed message".to_string(),
        class: "l4-latency-outlier".to_string(),
        lanes: vec![LaneKind::L4Stream],
        kinds: vec![InsertionKind::L4Field],
        intensity: Intensity::Medium,
        cost: CheckCost::Heavy,
        technique: Technique::Malformed,
        severity: aitm_poc::Severity::Info,
        confidence_max: Confidence::Tentative,
        needs_baseline: true,
        wants_traits: None,
        targets_session: false,
        cwe: Some(400),
        description: "One mutated message took more than five times the median reply time, twice. \
                      Cases that leave the frame incomplete — a mutated length or count, a \
                      removed delimiter, an over-long varint — are excluded, because the delay \
                      such a case measures is the peer's framing timeout."
            .to_string(),
        remediation: None,
        origin: CheckOrigin::Native,
        scope: CheckScope::Point,
    }
}

/// What to do about a crash or a parser fault (spec S6.3).
const REMEDIATION: &str =
    "Validate declared lengths and counts against the bytes received before allocating or \
     indexing.";

#[cfg(test)]
mod tests {
    //! The campaign's logic, driven by a scripted `ProbeHost` double.
    //!
    //! No socket and no fixture target: these are the inner loop (plan, "No
    //! fake-data evidence"), pinning the case loop, the oracle reading, the
    //! bounded reproduction and the verdict mapping. Only Task 23's real run
    //! against T10's speakers is acceptance evidence.

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use aitm_core::{
        BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
        StdGuard,
    };
    use aitm_scan_model::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, InsertionPoint, Intensity, JobCtx,
        L4Oracle, L4Reply, L4Transport, LaneKind, Outcome, Payload, ProbeHost, ProbeResponse,
        RawProbe, ScanProfile, SessionMaterial, Technique,
    };
    use futures::future::BoxFuture;

    use super::{checks, Campaign, StopReason};
    use crate::grammars::tlv;
    use crate::host::{HostError, LIVENESS_PAYLOAD};
    use crate::spec::{GrammarKind, Transport};
    use crate::state::{lock, DiscoveredPoint, EndpointAddr, JobState, LaneState};

    /// The two seeds every test infers its TLV grammar from: a length-first
    /// `u16` relation over `abc`, and a one-byte body.
    fn seeds() -> Vec<Vec<u8>> {
        vec![vec![0x00, 0x03, b'a', b'b', b'c'], vec![0x00, 0x01, 0xff]]
    }

    /// What the fake host was asked for, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Baseline,
        Liveness,
        Case(Vec<u8>),
    }

    /// A `ProxyClient` that performs no I/O; a job context needs one to exist.
    struct NullClient;

    impl ProxyClient for NullClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
        }
    }

    /// A `JobCtx` with a fixed marker and an affordable budget.
    struct NullJob {
        profile: ScanProfile,
        marker: String,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
    }

    impl NullJob {
        fn new(marker: &str, cases: u32) -> NullJob {
            let mut profile = ScanProfile::default();
            profile.l4.cases = cases;
            profile.l4.reproduce_count = 3;
            NullJob {
                profile,
                marker: marker.to_string(),
                client: Arc::new(NullClient),
                store: Arc::new(MemFlowStore::new()),
                guard: Arc::new(StdGuard::default()),
            }
        }

        fn dry_run(mut self) -> NullJob {
            self.profile.l4.dry_run = true;
            self
        }
    }

    impl JobCtx for NullJob {
        fn job_id(&self) -> &str {
            "scan-19"
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
            1000
        }
        fn deadline(&self) -> Instant {
            Instant::now() + Duration::from_secs(600)
        }
        fn cancelled(&self) -> bool {
            false
        }
        fn marker(&self) -> String {
            self.marker.clone()
        }
    }

    /// A `ProbeHost` that sends nothing and answers from a script.
    ///
    /// It takes the same bookkeeping step `StreamHost::send_case` takes on
    /// the job state — [`JobState::record_case`] — so the campaign reads the
    /// same medians and counts it would read live.
    struct FakeHost {
        profile: ScanProfile,
        marker: String,
        state: Option<Arc<JobState>>,
        script: Mutex<VecDeque<Result<ProbeResponse, HostError>>>,
        calls: Mutex<Vec<Call>>,
    }

    impl FakeHost {
        fn new(marker: &str, profile: ScanProfile, state: Option<Arc<JobState>>) -> FakeHost {
            FakeHost {
                profile,
                marker: marker.to_string(),
                state,
                script: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn script(self, items: Vec<Result<ProbeResponse, HostError>>) -> FakeHost {
            *lock(&self.script) = items.into();
            self
        }

        fn calls(&self) -> Vec<Call> {
            lock(&self.calls).clone()
        }

        fn case_calls(&self) -> Vec<Vec<u8>> {
            lock(&self.calls)
                .iter()
                .filter_map(|call| match call {
                    Call::Case(bytes) => Some(bytes.clone()),
                    _ => None,
                })
                .collect()
        }

        fn next(&self) -> anyhow::Result<ProbeResponse> {
            let item = lock(&self.script)
                .pop_front()
                .unwrap_or_else(|| panic!("the fake host's script ran out"));
            match item {
                Ok(response) => Ok(response),
                Err(e) => Err(anyhow::Error::new(e)),
            }
        }

        /// The bookkeeping `StreamHost::send_case` does after an exchange,
        /// through the host's own helper, so the campaign reads the same
        /// medians and counts it would read live.
        fn record_case(&self, response: &anyhow::Result<ProbeResponse>) {
            let (Some(state), Ok(response)) = (self.state.as_ref(), response) else {
                return;
            };
            state.record_case(response.elapsed_ms);
        }
    }

    impl ProbeHost for FakeHost {
        fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async move {
                lock(&self.calls).push(Call::Baseline);
                let response = self.next();
                self.record_case(&response);
                response
            })
        }

        fn probe<'a>(
            &'a self,
            payload: &'a Payload,
        ) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
            Box::pin(async move {
                match payload.bytes.as_deref() {
                    None if payload.value == LIVENESS_PAYLOAD => {
                        lock(&self.calls).push(Call::Liveness);
                        self.next()
                    }
                    None => Err(anyhow::Error::new(HostError::NotBytes)),
                    Some(bytes) => {
                        lock(&self.calls).push(Call::Case(bytes.to_vec()));
                        let response = self.next();
                        self.record_case(&response);
                        response
                    }
                }
            })
        }

        fn probe_raw(&self, _req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async {
                Err(anyhow::Error::new(HostError::Unsupported(
                    "probe_raw is not available on the L4 stream lane",
                )))
            })
        }

        fn marker(&self) -> String {
            self.marker.clone()
        }

        fn budget_left(&self) -> u32 {
            1000
        }

        fn deadline(&self) -> Instant {
            Instant::now() + Duration::from_secs(600)
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

    /// A clean reply that took `elapsed_ms`.
    fn clean(elapsed_ms: u32) -> Result<ProbeResponse, HostError> {
        Ok(ProbeResponse {
            status: None,
            headers: Vec::new(),
            body: b"+OK".to_vec(),
            elapsed_ms,
            flow: None,
            ws_frames: None,
            l4: None,
        })
    }

    /// An oracle reading with an empty reply.
    fn reading(oracle: L4Oracle) -> Result<ProbeResponse, HostError> {
        reading_with(oracle, Vec::new())
    }

    fn reading_with(oracle: L4Oracle, bytes: Vec<u8>) -> Result<ProbeResponse, HostError> {
        Ok(ProbeResponse {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            elapsed_ms: 10,
            flow: None,
            ws_frames: None,
            l4: Some(L4Reply {
                bytes,
                oracle,
                elapsed_ms: 10,
            }),
        })
    }

    /// The liveness probe's two answers (plan call P5).
    fn alive() -> Result<ProbeResponse, HostError> {
        Ok(ProbeResponse {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            elapsed_ms: 1,
            flow: None,
            ws_frames: None,
            l4: None,
        })
    }

    fn endpoint() -> EndpointAddr {
        EndpointAddr {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9000,
            proto: L4Transport::Tcp,
        }
    }

    /// One point on the inferred TLV grammar, at `path`.
    fn discovered(path: &str) -> DiscoveredPoint {
        DiscoveredPoint {
            point: InsertionPoint {
                id: format!("l4s-point-{path}"),
                lane: LaneKind::L4Stream,
                kind: InsertionKind::L4Field,
                name: path.to_string(),
                path: Some(path.to_string()),
                example: None,
                flow: None,
                site_node: Some("l4s-tcp-127.0.0.1-9000".to_string()),
                traits: Vec::new(),
                frequency: 1,
                method: Some("L4".to_string()),
                url: Some("tcp://127.0.0.1:9000/tlv".to_string()),
            },
            node_id: "l4s-tcp-127.0.0.1-9000".to_string(),
            endpoint: endpoint(),
            grammar: GrammarKind::Tlv,
            seed_id: "hex:0".to_string(),
            seed_bytes: vec![0x00, 0x03, b'a', b'b', b'c'],
            scope_entry: "127.0.0.0/8:0-65535 * outbound".to_string(),
            selection: "inferred(u16 be at 0, counts body)".to_string(),
        }
    }

    /// The same point as [`discovered`], from another seed: the shape
    /// discovery produces when one endpoint has several seeds, which gives
    /// every field path one point per seed (F8).
    fn discovered_from(path: &str, seed_id: &str, seed_bytes: Vec<u8>) -> DiscoveredPoint {
        let mut dp = discovered(path);
        dp.point.id = format!("l4s-point-{path}-{seed_id}");
        dp.seed_id = seed_id.to_string();
        dp.seed_bytes = seed_bytes;
        dp
    }

    /// A lane state holding one job (marker `m1`) with one point at `path`
    /// and the inferred TLV grammar for its node.
    fn lane_state_with(job: &NullJob, path: &str) -> (Arc<LaneState>, DiscoveredPoint) {
        let state = Arc::new(LaneState::new());
        let job_state = state.job_for(job);
        let point = discovered(path);
        let (grammar, _descriptor) = tlv::from_seeds_on(&seeds(), Transport::Tcp)
            .expect("the two seeds carry a length relation");
        lock(&job_state.points).insert(point.point.id.clone(), point.clone());
        lock(&job_state.grammars).insert(point.node_id.clone(), grammar);
        job_state.points_total.store(1, Ordering::SeqCst);
        (state, point)
    }

    /// A lane state holding one job (marker `m1`) with two points at the same
    /// `path` on the same node, one per seed, and the inferred TLV grammar.
    fn lane_state_with_two_seeds(
        job: &NullJob,
        path: &str,
    ) -> (Arc<LaneState>, DiscoveredPoint, DiscoveredPoint) {
        let state = Arc::new(LaneState::new());
        let job_state = state.job_for(job);
        let first = discovered_from(path, "hex:0", vec![0x00, 0x03, b'a', b'b', b'c']);
        let second = discovered_from(path, "hex:1", vec![0x00, 0x01, 0xff]);
        let (grammar, _descriptor) = tlv::from_seeds_on(&seeds(), Transport::Tcp)
            .expect("the two seeds carry a length relation");
        {
            let mut points = lock(&job_state.points);
            points.insert(first.point.id.clone(), first.clone());
            points.insert(second.point.id.clone(), second.clone());
        }
        lock(&job_state.grammars).insert(first.node_id.clone(), grammar);
        job_state.points_total.store(2, Ordering::SeqCst);
        (state, first, second)
    }

    #[tokio::test]
    async fn no_job_state_is_error_verdict() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "payload");
        let host = FakeHost::new("zz", job.profile.clone(), None);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Error);
        assert_eq!(verdict.detail, "l4_stream: no job state for this host");
        assert_eq!(host.calls(), Vec::new());
    }

    #[tokio::test]
    async fn campaign_runs_once_for_three_checks() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "payload");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state))
            .script((0..21).map(|_| clean(10)).collect());

        let all = checks(Arc::clone(&state));
        let mut outcomes = Vec::new();
        for check in &all {
            outcomes.push(check.run(&point.point, &host).await.outcome);
        }

        assert_eq!(
            outcomes,
            vec![Outcome::Clean, Outcome::Clean, Outcome::Clean]
        );
        assert_eq!(host.calls().len(), 21, "baseline plus twenty cases");
        assert_eq!(host.case_calls().len(), 20);

        // The S6.5 line, in full.
        let verdict = all[1].run(&point.point, &host).await;
        assert_eq!(
            verdict.detail,
            "l4_stream tlv 127.0.0.1:9000/tcp point=payload cases=20/20 skipped_denylisted=0 \
             skipped_too_large=0 liveness_probes=0 liveness_failures=0 rate_waits=0 \
             connect_waits=0 latency_skipped_framing=0 stop=completed \
             selection=inferred(u16 be at 0, counts body) clean"
        );
        assert_eq!(
            host.calls().len(),
            21,
            "a read of the campaign sends nothing"
        );
    }

    #[tokio::test]
    async fn crash_path_reproduces_and_retires() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                clean(10),
                clean(10),
                clean(10),
                clean(10),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
            ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Firm);
        let evidence = verdict.evidence.l4.as_ref().expect("l4 evidence");
        assert_eq!(evidence.reproduced, (3, 3));
        assert_eq!(evidence.oracle, L4Oracle::LivenessFailed);
        assert!(evidence.liveness_before);
        assert!(!evidence.liveness_after);
        assert!(
            evidence.mutation_chain[0].starts_with("len_desync("),
            "{chain:?}",
            chain = evidence.mutation_chain
        );
        assert_eq!(evidence.seed_id, "hex:0");
        assert_eq!(evidence.scope_entry, "127.0.0.0/8:0-65535 * outbound");
        assert!(job_state.is_retired(&point.point.id));
        assert!(
            verdict.detail.contains("crash reproduced 3/3"),
            "{detail}",
            detail = verdict.detail
        );
        assert!(verdict.poc_hint.is_none());

        // The three replays are the identical case, each preceded by a
        // liveness probe that found the target back up.
        let cases = host.case_calls();
        assert_eq!(cases.len(), 7, "four cases and three identical replays");
        assert_eq!(cases[3], cases[4]);
        assert_eq!(cases[4], cases[5]);
        assert_eq!(cases[5], cases[6]);
        assert_eq!(
            host.calls()[5],
            Call::Liveness,
            "the recovery poll runs before the first replay"
        );
    }

    #[tokio::test]
    async fn a_crash_retires_the_field_path_for_every_seed() {
        let job = NullJob::new("m1", 20);
        let (state, first, second) = lane_state_with_two_seeds(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                clean(10),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
                alive(),
                reading(L4Oracle::LivenessFailed),
            ]);

        // The first seed's point crashes the target and is confirmed 3/3.
        let crash = checks(Arc::clone(&state))[0].run(&first.point, &host).await;
        assert_eq!(crash.outcome, Outcome::Vulnerable, "{}", crash.detail);
        let evidence = crash.evidence.l4.as_ref().expect("l4 evidence");
        assert_eq!(evidence.reproduced, (3, 3));
        assert!(job_state.is_retired(&first.point.id));
        assert!(job_state.is_path_retired(&first.node_id, "length"));

        // The second seed's point sits on the same node and the same field
        // path. Its own id was never retired, but every case it could send
        // would crash the same field again, for one more issue the engine
        // dedupes away and ~40 s of recovery window and replays.
        assert!(!job_state.is_retired(&second.point.id));
        let calls_before = host.calls().len();
        let mut verdicts = Vec::new();
        for check in &checks(Arc::clone(&state)) {
            verdicts.push(check.run(&second.point, &host).await);
        }

        assert_eq!(
            host.calls().len(),
            calls_before,
            "the three checks of a point on a retired path send nothing"
        );
        assert_eq!(
            verdicts.iter().map(|v| v.outcome).collect::<Vec<_>>(),
            vec![
                Outcome::Inconclusive,
                Outcome::Inconclusive,
                Outcome::Inconclusive
            ],
        );
        for verdict in &verdicts {
            assert_ne!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
            assert!(
                verdict.detail.contains("stop=retired"),
                "the detail names the retirement: {detail}",
                detail = verdict.detail
            );
            assert!(
                verdict.detail.contains("cases=0/0"),
                "no case was planned or sent: {detail}",
                detail = verdict.detail
            );
            assert!(verdict.evidence.l4.is_none());
        }

        // One crash, one retired element: the per-seed repeats of one field
        // are a single issue under the umbrella's L4 dedupe key.
        assert_eq!(job_state.counters().crashes, 1);
        assert_eq!(job_state.counters().retired_elements, 1);
    }

    /// The transport could not reach the peer at all, before any case went
    /// out.
    fn refused_connect() -> Result<ProbeResponse, HostError> {
        Err(HostError::Connect("connection refused".to_string()))
    }

    #[tokio::test]
    async fn a_refused_connect_waits_for_recovery_and_retries_the_same_case() {
        let job = NullJob::new("m1", 3);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                clean(10),         // the baseline
                refused_connect(), // case 0: nothing was sent
                alive(),           // the recovery poll: the target is back
                clean(10),         // case 0 again
                clean(10),         // case 1
                clean(10),         // case 2
            ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        // A connect refused before a case went out says nothing about that
        // case: the campaign waits the target back and sends it.
        assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("cases=3/3"),
            "every planned case was sent: {detail}",
            detail = verdict.detail
        );
        assert!(
            verdict.detail.contains("connect_waits=1"),
            "the wait is counted: {detail}",
            detail = verdict.detail
        );
        assert!(
            verdict.detail.contains("stop=completed"),
            "{detail}",
            detail = verdict.detail
        );
        assert!(
            !verdict.detail.contains("target_down"),
            "a target that came back is not down: {detail}",
            detail = verdict.detail
        );

        // The refused attempt sent nothing and is not counted as a case; the
        // retry is the identical case, after one recovery poll.
        let cases = host.case_calls();
        assert_eq!(cases.len(), 4, "one refused attempt, then three cases");
        assert_eq!(cases[0], cases[1], "the retry is the same case");
        assert_eq!(
            host.calls()[2],
            Call::Liveness,
            "the recovery poll runs before the retry"
        );
    }

    #[tokio::test]
    async fn a_baseline_connect_refusal_also_waits_for_recovery() {
        let job = NullJob::new("m1", 2);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                refused_connect(), // the baseline
                alive(),           // the recovery poll
                clean(10),         // the baseline again
                clean(10),         // case 0
                clean(10),         // case 1
            ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("cases=2/2"),
            "{detail}",
            detail = verdict.detail
        );
        assert!(
            verdict.detail.contains("connect_waits=1"),
            "{detail}",
            detail = verdict.detail
        );
        assert_eq!(host.calls()[1], Call::Liveness);
    }

    #[tokio::test]
    async fn a_connect_refused_again_after_recovery_is_target_down() {
        let job = NullJob::new("m1", 3);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                clean(10),         // the baseline
                refused_connect(), // case 0: nothing was sent
                alive(),           // the recovery poll says it is back
                refused_connect(), // but the retry cannot reach it either
            ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("stop=target_down"),
            "{detail}",
            detail = verdict.detail
        );
        assert!(
            verdict.detail.contains("cases=0/3"),
            "no case ever went out: {detail}",
            detail = verdict.detail
        );
        assert!(
            verdict.detail.contains("connect_waits=1"),
            "{detail}",
            detail = verdict.detail
        );
    }

    /// The same point as [`discovered`], on a second endpoint: the shape
    /// discovery produces when a job holds more than one L4 node (F10).
    fn discovered_on(path: &str, node_id: &str, port: u16) -> DiscoveredPoint {
        let mut dp = discovered(path);
        dp.point.id = format!("l4s-point-{node_id}-{path}");
        dp.point.site_node = Some(node_id.to_string());
        dp.node_id = node_id.to_string();
        dp.endpoint.port = port;
        dp
    }

    #[tokio::test]
    async fn a_down_node_skips_every_later_campaign_without_sockets() {
        let job = NullJob::new("m1", 3);
        let state = Arc::new(LaneState::new());
        let job_state = state.job_for(&job);
        let (grammar, _descriptor) = tlv::from_seeds_on(&seeds(), Transport::Tcp)
            .expect("the two seeds carry a length relation");

        // Two points on one node, and a third on another node.
        let first = discovered("length");
        let second = discovered("payload");
        let elsewhere = discovered_on("length", "l4s-tcp-127.0.0.1-9001", 9001);
        {
            let mut points = lock(&job_state.points);
            for dp in [&first, &second, &elsewhere] {
                points.insert(dp.point.id.clone(), dp.clone());
            }
        }
        {
            let mut grammars = lock(&job_state.grammars);
            grammars.insert(first.node_id.clone(), Arc::clone(&grammar));
            grammars.insert(elsewhere.node_id.clone(), grammar);
        }
        job_state.points_total.store(3, Ordering::SeqCst);

        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                // The first point: the connect is refused, the recovery poll
                // says the target is back, and the retry is refused again.
                clean(10),
                refused_connect(),
                alive(),
                refused_connect(),
                // The third point, on another node, runs normally.
                clean(10),
                clean(10),
            ]);

        let all = checks(Arc::clone(&state));
        let down = all[0].run(&first.point, &host).await;
        assert_eq!(down.outcome, Outcome::Inconclusive, "{}", down.detail);
        assert!(
            down.detail.contains("stop=target_down"),
            "{detail}",
            detail = down.detail
        );
        assert!(
            job_state.is_node_down(&first.node_id),
            "the node that never came back is marked down for the job"
        );

        // Every later point on that node stops at once: no grammar parse, no
        // baseline, no recovery window, and no socket.
        let after_first = host.calls().len();
        for check in &all {
            let verdict = check.run(&second.point, &host).await;
            assert_eq!(
                verdict.outcome,
                Outcome::Inconclusive,
                "{detail}",
                detail = verdict.detail
            );
            assert!(
                verdict.detail.contains("stop=target_down"),
                "{detail}",
                detail = verdict.detail
            );
            assert!(
                verdict
                    .detail
                    .contains("node marked down earlier in this job"),
                "{detail}",
                detail = verdict.detail
            );
            assert!(
                verdict.detail.contains("cases=0/0"),
                "nothing was planned or sent: {detail}",
                detail = verdict.detail
            );
        }
        assert_eq!(
            host.calls().len(),
            after_first,
            "a point on a down node costs no host call"
        );

        // The flag is this node's, not the job's: another endpoint still runs.
        let other = all[0].run(&elsewhere.point, &host).await;
        assert_eq!(other.outcome, Outcome::Clean, "{}", other.detail);
        assert!(
            other.detail.contains("cases=1/1"),
            "{detail}",
            detail = other.detail
        );
        assert!(!job_state.is_node_down(&elsewhere.node_id));
    }

    #[tokio::test]
    async fn partial_reproduction_is_tentative() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(vec![
            clean(10),
            reading(L4Oracle::LivenessFailed),
            alive(),
            reading(L4Oracle::LivenessFailed),
            alive(),
            reading(L4Oracle::LivenessFailed),
            alive(),
            clean(10),
        ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        let evidence = verdict.evidence.l4.as_ref().expect("l4 evidence");
        assert_eq!(evidence.reproduced, (2, 3));
        assert!(verdict.detail.contains("crash reproduced 2/3"));
    }

    #[tokio::test]
    async fn parser_fault_path() {
        let job = NullJob::new("m1", 5);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host =
            FakeHost::new("m1", job.profile.clone(), Some(Arc::clone(&job_state))).script(vec![
                clean(10),
                reading_with(L4Oracle::Reset, Vec::new()),
                reading(L4Oracle::Reset),
                reading(L4Oracle::Reset),
                reading(L4Oracle::Reset),
                clean(10),
                clean(10),
                clean(10),
                clean(10),
            ]);

        let all = checks(Arc::clone(&state));
        let crash = all[0].run(&point.point, &host).await;
        let fault = all[1].run(&point.point, &host).await;

        assert_eq!(crash.outcome, Outcome::Clean);
        assert_eq!(fault.outcome, Outcome::Vulnerable);
        assert_eq!(fault.confidence, Confidence::Firm);
        let evidence = fault.evidence.l4.as_ref().expect("l4 evidence");
        assert_eq!(evidence.oracle, L4Oracle::Reset);
        assert_eq!(evidence.reproduced, (3, 3));
        assert!(evidence.liveness_after);
        assert!(!job_state.is_retired(&point.point.id));
        assert!(
            fault.detail.contains("parser fault reproduced 3/3"),
            "{detail}",
            detail = fault.detail
        );
        assert!(
            fault.detail.contains("stop=completed"),
            "{detail}",
            detail = fault.detail
        );
    }

    #[tokio::test]
    async fn protocol_error_then_close_is_clean() {
        let job = NullJob::new("m1", 5);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(
            std::iter::once(clean(10))
                .chain((0..5).map(|_| {
                    reading_with(L4Oracle::ProtocolError, b"-ERR Protocol error".to_vec())
                }))
                .collect(),
        );

        let all = checks(Arc::clone(&state));
        for check in &all {
            let verdict = check.run(&point.point, &host).await;
            assert_eq!(
                verdict.outcome,
                Outcome::Clean,
                "{id}",
                id = check.meta().id
            );
            assert!(verdict.evidence.l4.is_none());
        }
        assert_eq!(host.case_calls().len(), 5);
    }

    #[tokio::test]
    async fn latency_outlier_confirmed() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "payload");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let mut script: Vec<Result<ProbeResponse, HostError>> =
            (0..13).map(|_| clean(10)).collect();
        script.push(clean(80));
        script.push(clean(40));
        script.extend((0..7).map(|_| clean(10)));
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(script);

        let verdict = checks(Arc::clone(&state))[2].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Vulnerable);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        let evidence = verdict.evidence.l4.as_ref().expect("l4 evidence");
        assert_eq!(evidence.oracle, L4Oracle::LatencyOutlier);
        assert_eq!(evidence.reproduced, (1, 2));
        assert!(
            verdict
                .detail
                .contains("latency outlier 80 ms vs median 10 ms"),
            "{detail}",
            detail = verdict.detail
        );
    }

    /// F4: a case whose declared length no longer matches the bytes sent is
    /// an incomplete frame by construction, so the peer answers only when its
    /// own framing timeout expires. That delay is not a processing anomaly:
    /// on a framing node the latency oracle is skipped — no confirming repeat
    /// is sent — and the skips are counted on the detail line.
    #[tokio::test]
    async fn latency_rule_skips_framing_cases() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let mut script: Vec<Result<ProbeResponse, HostError>> =
            (0..13).map(|_| clean(10)).collect();
        script.push(clean(300));
        script.extend((0..7).map(|_| clean(10)));
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(script);

        let verdict = checks(Arc::clone(&state))[2].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert!(verdict.evidence.l4.is_none());
        assert!(
            verdict.detail.contains("latency_skipped_framing=20"),
            "{detail}",
            detail = verdict.detail
        );
        assert_eq!(
            host.case_calls().len(),
            20,
            "the twenty planned cases and no confirming repeat"
        );
    }

    #[tokio::test]
    async fn latency_repeat_within_three_times_is_clean() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "payload");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let mut script: Vec<Result<ProbeResponse, HostError>> =
            (0..13).map(|_| clean(10)).collect();
        script.push(clean(80));
        script.push(clean(20));
        script.extend((0..7).map(|_| clean(10)));
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(script);

        let verdict = checks(Arc::clone(&state))[2].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Clean);
        assert!(verdict.evidence.l4.is_none());
    }

    #[tokio::test]
    async fn dry_run_report() {
        let job = NullJob::new("m1", 20).dry_run();
        let (state, point) = lane_state_with(&job, "payload");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state));

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert!(
            verdict.detail.starts_with("dry run: 20 cases"),
            "{detail}",
            detail = verdict.detail
        );
        let rendered = verdict
            .detail
            .lines()
            .filter(|line| line.starts_with('#'))
            .count();
        assert_eq!(rendered, 20);
        assert_eq!(host.calls(), Vec::new(), "a dry run opens nothing");

        let others = checks(Arc::clone(&state));
        let latency = others[2].run(&point.point, &host).await;
        assert_eq!(latency.outcome, Outcome::Inconclusive);
        assert_eq!(
            latency.detail,
            "dry run: see l4-crash for the rendered cases"
        );
    }

    #[tokio::test]
    async fn stop_reasons_map_to_inconclusive() {
        let job = NullJob::new("m1", 20);
        let (state, point) = lane_state_with(&job, "payload");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(vec![
            clean(10),
            clean(10),
            Err(HostError::Budget),
        ]);

        let verdict = checks(Arc::clone(&state))[0].run(&point.point, &host).await;

        assert_eq!(verdict.outcome, Outcome::Inconclusive);
        assert_eq!(verdict.confidence, Confidence::Tentative);
        assert!(
            verdict.detail.contains("budget exhausted"),
            "{detail}",
            detail = verdict.detail
        );

        let job2 = NullJob::new("m2", 20);
        let (state2, point2) = lane_state_with(&job2, "payload");
        let job_state2 = state2.job_by_marker("m2").expect("the job was recorded");
        let host2 = FakeHost::new("m2", job2.profile.clone(), Some(job_state2)).script(vec![
            clean(10),
            Err(HostError::Guard("scan: out_of_scope: x".to_string())),
        ]);

        let guard = checks(Arc::clone(&state2))[0]
            .run(&point2.point, &host2)
            .await;

        assert_eq!(guard.outcome, Outcome::Error);
        assert!(
            guard
                .detail
                .contains("guard refused: scan: out_of_scope: x"),
            "{detail}",
            detail = guard.detail
        );
    }

    #[test]
    fn meta_matches_spec() {
        let state = Arc::new(LaneState::new());
        let all = checks(state);
        let ids: Vec<&str> = all.iter().map(|check| check.meta().id.as_str()).collect();
        assert_eq!(ids, ["l4-crash", "l4-parser-fault", "l4-latency-outlier"]);

        for check in &all {
            let meta = check.meta();
            assert_eq!(meta.id, meta.class);
            assert_eq!(meta.lanes, vec![LaneKind::L4Stream]);
            assert_eq!(meta.kinds, vec![InsertionKind::L4Field]);
            assert_eq!(meta.intensity, Intensity::Medium);
            assert_eq!(meta.cost, CheckCost::Heavy);
            assert_eq!(meta.technique, Technique::Malformed);
            assert_eq!(meta.origin, CheckOrigin::Native);
            assert!(meta.needs_baseline);
            assert!(meta.wants_traits.is_none());
            assert!(!meta.targets_session);
        }

        let crash = all[0].meta();
        assert_eq!(crash.name, "L4 service crash on malformed message");
        assert_eq!(crash.severity, aitm_poc::Severity::Critical);
        assert_eq!(crash.confidence_max, Confidence::Firm);
        assert_eq!(crash.cwe, Some(400));
        assert!(crash.remediation.is_some());

        let fault = all[1].meta();
        assert_eq!(
            fault.name,
            "L4 parser fault: connection dropped on malformed message"
        );
        assert_eq!(fault.severity, aitm_poc::Severity::Medium);
        assert_eq!(fault.confidence_max, Confidence::Firm);
        assert_eq!(fault.cwe, Some(20));
        assert!(fault.remediation.is_some());

        let latency = all[2].meta();
        assert_eq!(latency.name, "L4 latency outlier on malformed message");
        assert_eq!(latency.severity, aitm_poc::Severity::Info);
        assert_eq!(latency.confidence_max, Confidence::Tentative);
        assert_eq!(latency.cwe, Some(400));
        assert_eq!(latency.remediation, None);
    }

    #[tokio::test]
    async fn debug_prints_no_bytes() {
        let job = NullJob::new("m1", 5);
        let (state, point) = lane_state_with(&job, "length");
        let job_state = state.job_by_marker("m1").expect("the job was recorded");
        let host = FakeHost::new("m1", job.profile.clone(), Some(job_state)).script(vec![
            clean(10),
            reading_with(L4Oracle::Reset, b"S3CR3TBYTES".to_vec()),
            reading(L4Oracle::Reset),
            reading(L4Oracle::Reset),
            reading(L4Oracle::Reset),
            clean(10),
            clean(10),
            clean(10),
            clean(10),
        ]);

        let campaign: Arc<Campaign> = Campaign::run_or_read(&point.point, &host, &state)
            .await
            .expect("the job state is present");

        assert!(matches!(campaign.stopped, StopReason::Completed));
        let rendered = format!("{campaign:?}");
        assert!(!rendered.contains("S3CR3TBYTES"), "{rendered}");
        assert!(!rendered.contains("6162"), "{rendered}");
    }
}
