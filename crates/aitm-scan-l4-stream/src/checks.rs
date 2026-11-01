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
use std::time::{Duration, Instant};

use aitm_core::redact::scrub_text;
use aitm_scan_model::{
    Check, CheckCost, CheckMeta, CheckOrigin, Confidence, Evidence, InsertionKind, InsertionPoint,
    Intensity, L4Evidence, L4Oracle, L4Transport, LaneKind, Outcome, Payload, PayloadMode,
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
    lock, DiscoveredPoint, JobState, LaneState, MAX_CASES_PER_JOB, MAX_PRELUDE, RECOVERY_WINDOW,
    REPRODUCE_SPACING,
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

/// How often the recovery wait re-probes a target that went away (S6.2).
const RECOVERY_POLL: Duration = Duration::from_secs(1);

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
            StopReason::TargetDown => "target_down".to_string(),
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

/// This point's share of the job's cases (spec S6.2).
fn cases_planned(profile_cases: u32, points_total: u32, budget_left: u32) -> u32 {
    let capped = profile_cases.min(MAX_CASES_PER_JOB);
    let share = (capped / points_total.max(1)).max(1);
    share.min(budget_left)
}

/// The other seeds of the same endpoint, which `Crossover*` and `Splice` draw
/// from (spec S6.4).
fn donors_for(job: &JobState, dp: &DiscoveredPoint) -> Vec<Vec<u8>> {
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

/// Build and run one campaign.
async fn run(
    point: &InsertionPoint,
    host: &dyn ProbeHost,
    job: &Arc<JobState>,
) -> Result<Campaign, Verdict> {
    let Some(dp) = lock(&job.points).get(&point.id).cloned() else {
        return Err(error_verdict(format!(
            "l4_stream: point {id} was not produced by this lane for job {job_id}",
            id = point.id,
            job_id = job.job_id
        )));
    };
    let grammar = grammar_for(job, &dp);
    let Some(tree) = grammar.parse(&dp.seed_bytes) else {
        return Err(error_verdict(format!(
            "l4_stream: the seed {seed} of point {id} does not parse under {grammar}",
            seed = dp.seed_id,
            id = point.id,
            grammar = grammar.name()
        )));
    };

    let path = FieldPath::new(point.path.as_deref().unwrap_or_default());
    let rng_seed = fnv1a64(
        format!(
            "{marker}|{id}",
            marker = host.marker(),
            id = point.id.as_str()
        )
        .as_bytes(),
    );
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
    Ok(campaign)
}

/// What one probe error means for the loop.
enum Step {
    /// Count the skip and go on to the next case.
    SkipDenylisted,
    /// Count the skip and go on to the next case.
    SkipTooLarge,
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
        HostError::Guard(message) => Step::Stop(StopReason::Guard(message.clone())),
        HostError::DryRun => Step::Stop(StopReason::DryRun),
        // The transport could not reach the peer at all: from the campaign's
        // side that is the target being down.
        HostError::Connect(_) => Step::Stop(StopReason::TargetDown),
        HostError::NotBytes | HostError::Unsupported(_) => Step::Stop(StopReason::Guard(format!(
            "l4_stream: the host refused the probe: {host_error}"
        ))),
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

    /// The whole case loop.
    async fn drive(&mut self, schedule: Schedule, campaign: &mut Campaign) {
        match self.host.baseline().await {
            Ok(response) => self.alive = !failed_liveness(&response),
            Err(e) => {
                campaign.stopped = match step_for(&e) {
                    Step::Stop(reason) => reason,
                    Step::SkipDenylisted | Step::SkipTooLarge => StopReason::Completed,
                };
                return;
            }
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
                Some(L4Oracle::Reset) => {
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

    /// Record a crash and retire the point (spec S6.2 step 5).
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
            Class::Crash => format!(
                "crash reproduced {confirmed}/{attempts} after case #{index} chain=[{chain}]",
                index = finding.case.index,
                chain = finding.evidence.mutation_chain.join(","),
            ),
            Class::ParserFault => format!(
                "parser fault reproduced {confirmed}/{attempts} after case #{index} chain=[{chain}]",
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
    format!(
        "l4_stream {grammar} {endpoint} point={path} cases={sent}/{planned} \
         skipped_denylisted={denylisted} skipped_too_large={too_large} \
         liveness_probes={probes} liveness_failures={failures} rate_waits={waits} \
         latency_skipped_framing={skipped_framing} stop={stop} selection={selection}",
        sent = campaign.cases_sent,
        planned = campaign.cases_planned,
        denylisted = campaign.skipped_denylisted,
        too_large = campaign.skipped_too_large,
        probes = job.liveness_probes.load(Ordering::SeqCst),
        failures = job.liveness_failures.load(Ordering::SeqCst),
        waits = campaign.rate_waits,
        skipped_framing = campaign.latency_skipped_framing,
        stop = campaign.stopped.token(),
    )
}

/// `tcp` or `udp`.
fn proto_name(proto: L4Transport) -> &'static str {
    match proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    }
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
    /// It mirrors the two bookkeeping steps `StreamHost::send_case` performs
    /// on the job state — the latency window and the case counter — so the
    /// campaign reads the same medians it would read live.
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

        fn record_latency(&self, response: &anyhow::Result<ProbeResponse>) {
            let (Some(state), Ok(response)) = (self.state.as_ref(), response) else {
                return;
            };
            state.push_latency(response.elapsed_ms);
            state.cases_sent.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ProbeHost for FakeHost {
        fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
            Box::pin(async move {
                lock(&self.calls).push(Call::Baseline);
                let response = self.next();
                self.record_latency(&response);
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
                        self.record_latency(&response);
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
             latency_skipped_framing=0 stop=completed selection=inferred(u16 be at 0, counts \
             body) clean"
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
