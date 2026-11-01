//! `StreamHost`: the `ProbeHost` the checks send through, and the probe
//! sequence behind it (spec S5.4, S5.5, S5.6, S5.7).
//!
//! One host serves one insertion point for the life of one check run. It owns
//! nothing a check could reach around: the L4 guard permit is minted per
//! connection, the byte pacer and the connection semaphore are the job's, the
//! budget is charged per message, and the destructive-command denylist is
//! consulted before anything is charged or opened. The order of those refusals
//! is spec S5.6 steps 1-11 and is what [`StreamHost::send_case`] implements.
//!
//! Three refusals here never send a byte and are not liftable by a profile:
//! the denylist (S3), the 64 KiB message bound (S5.7) and the amendment A1
//! re-check that a loopback destination is not one of the core's own listener
//! ports — the set changes at runtime, so discovery's check is re-run before
//! every connect.
//!
//! Nothing in this module logs a message, a reply or their hex, and the
//! hand-written `Debug` impls print byte fields as `<n bytes>` (spec S9, C11).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_proto_l4::guard::{L4Guard, L4GuardError, L4Permit, ANY_INTERFACE};
use aitm_proto_l4::types::{L4Action, L4Direction, L4Proto, L4Target};
use aitm_scan_model::{
    JobCtx, L4Oracle, L4Reply, L4Transport, Payload, ProbeHost, ProbeResponse, RawProbe,
    ScanProfile,
};
use futures::future::BoxFuture;
use tokio::sync::{OnceCell, OwnedSemaphorePermit};

use crate::client::{ClientError, Ended, ExchangeStep, StreamClient};
use crate::denylist::{self, DenyContext};
use crate::grammar::{Grammar, ReplyClass};
use crate::grammars::smtp;
use crate::oracle::{self, Reading};
use crate::spec::GrammarKind;
use crate::state::{
    lock, DiscoveredPoint, JobState, CONNECT_TIMEOUT, LIVENESS_RETRY, MAX_AWAIT, MAX_MESSAGE,
    MAX_PRELUDE, RECOVERY_WINDOW, REPLY_TIMEOUT,
};
use crate::tree::Tree;

/// The `Payload::value` a check sends, with no `bytes`, to ask for a liveness
/// probe rather than a case (plan call P5).
///
/// The `ProbeHost` trait has no liveness method and may not grow one without a
/// default body (the T1a extension rule), so the campaign asks for a probe
/// through the one channel it has.
pub const LIVENESS_PAYLOAD: &str = "liveness";

/// How many times one exchange is retried after the guard's injection-rate
/// refusal before it becomes an error (spec S5.4).
const MAX_RATE_WAITS: u32 = 10;

/// The longest one rate-refusal retry sleeps (spec S5.4).
const MAX_RATE_SLEEP: Duration = Duration::from_secs(1);

/// How often [`StreamHost::wait_recovery`] re-probes a target that went away
/// (spec S6.2).
#[allow(dead_code, reason = "Task 19's campaign is the only caller")]
const RECOVERY_POLL: Duration = Duration::from_secs(1);

/// Why a probe sent nothing, or could not finish (spec S5.6).
///
/// Wrapped in an `anyhow::Error` by the `ProbeHost` methods so a check can
/// `downcast_ref::<HostError>()` and tell a refusal it caused (a denylisted
/// case) from one the job imposed (budget, deadline, cancellation). No variant
/// carries a message byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The destructive-command denylist refused the case or one of its prelude
    /// messages; the verb is named, the bytes are not.
    Denylisted(&'static str),
    /// The rendered case is over [`MAX_MESSAGE`]; it is skipped, never
    /// truncated.
    TooLarge,
    /// The payload carried no bytes, and was not the reserved liveness value.
    NotBytes,
    /// The point was retired after a confirmed crash.
    Retired,
    /// The job's budget refused the charge for this message.
    Budget,
    /// The job's deadline has passed, or waiting for a connection would cross
    /// it.
    Deadline,
    /// The job was cancelled.
    Cancelled,
    /// This many silent cases in a row: the lane gives up on the target.
    ConsecutiveTimeouts(u32),
    /// The L4 guard refused, or L4 is disabled. The message is already in the
    /// D3 `scan: <code>: <message>` form.
    Guard(String),
    /// The profile is a dry run: the backstop that keeps a socket shut even if
    /// a check calls `probe` (spec S7).
    DryRun,
    /// The `ProbeHost` method does not exist on this lane.
    Unsupported(&'static str),
    /// The transport could not reach the peer at all.
    Connect(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::Denylisted(verb) => {
                write!(
                    f,
                    "l4_stream: the denylist refuses {verb}; nothing was sent"
                )
            }
            HostError::TooLarge => write!(
                f,
                "l4_stream: the rendered case is over the {MAX_MESSAGE}-byte message bound"
            ),
            HostError::NotBytes => {
                f.write_str("l4_stream: an L4 payload must carry bytes, not text")
            }
            HostError::Retired => {
                f.write_str("l4_stream: the point was retired after a confirmed crash")
            }
            HostError::Budget => f.write_str("l4_stream: the job's budget is exhausted"),
            HostError::Deadline => f.write_str("l4_stream: the job's deadline has passed"),
            HostError::Cancelled => f.write_str("l4_stream: the job was cancelled"),
            HostError::ConsecutiveTimeouts(n) => {
                write!(f, "l4_stream: consecutive timeouts {n}")
            }
            HostError::Guard(message) => f.write_str(message),
            HostError::DryRun => f.write_str("l4_stream: dry run: nothing was sent"),
            HostError::Unsupported(what) => write!(f, "l4_stream: {what}"),
            HostError::Connect(why) => write!(f, "l4_stream: {why}"),
        }
    }
}

impl std::error::Error for HostError {}

/// What one case did (spec S5.6).
///
/// The campaign (Task 19) reads this; `probe` folds it into a
/// [`ProbeResponse`]. `Debug` prints `reply` as a length (S9).
#[derive(Clone, PartialEq, Eq)]
pub struct CaseOutcome {
    /// The reply, bounded by the client at 64 KiB and empty on silence.
    pub reply: Vec<u8>,
    /// The oracle's reading, or `None` when the target behaved.
    pub oracle: Option<L4Oracle>,
    /// Wall-clock milliseconds the case's own exchange step took.
    pub elapsed_ms: u32,
    /// Whether the target was known alive before the case.
    pub liveness_before: bool,
    /// Whether it was alive after it; `true` when no liveness probe ran.
    pub liveness_after: bool,
    /// Prelude messages written on the same connection before the case.
    pub prior_messages: u32,
}

impl fmt::Debug for CaseOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaseOutcome")
            .field("reply", &format_args!("<{} bytes>", self.reply.len()))
            .field("oracle", &self.oracle)
            .field("elapsed_ms", &self.elapsed_ms)
            .field("liveness_before", &self.liveness_before)
            .field("liveness_after", &self.liveness_after)
            .field("prior_messages", &self.prior_messages)
            .finish()
    }
}

/// The lane's `ProbeHost`: one insertion point, one job, one transport
/// (spec S5.5).
///
/// Built synchronously and with no I/O; the first `baseline` or `probe` opens
/// the first connection. `Debug` names the point and the grammar and prints no
/// byte of a seed, a case or a reply (S9).
pub struct StreamHost {
    /// The point, its endpoint, its seed and its provenance.
    pub(crate) point: DiscoveredPoint,
    /// The grammar selected for the endpoint.
    pub(crate) grammar: Arc<dyn Grammar>,
    /// The seed's parse tree, which the campaign mutates.
    #[allow(dead_code, reason = "Task 19's campaign is the only reader")]
    pub(crate) tree: Tree,
    /// The job: budget, deadline, cancellation, profile, marker.
    pub(crate) job: Arc<dyn JobCtx>,
    /// The job's lane state: counters, pacer, semaphore, latency window.
    pub(crate) state: Arc<JobState>,
    /// The L4 guard, or `None` when L4 is disabled (call A18).
    pub(crate) guard: Option<Arc<L4Guard>>,
    /// The transport, a trait so a test double can prove nothing was sent.
    pub(crate) client: Arc<dyn StreamClient>,
    /// The unmutated seed's response, taken once per host.
    baseline: OnceCell<ProbeResponse>,
    /// The last known liveness of the target (spec S5.6 step 10).
    liveness_before: AtomicBool,
    /// The hostname an SMTP target announced in its banner, which relaxes
    /// exactly one denylist rule (S3, `RCPT`).
    banner_host: Mutex<Option<String>>,
}

impl fmt::Debug for StreamHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamHost")
            .field("point", &self.point.point.id)
            .field("endpoint", &self.point.endpoint)
            .field("grammar", &self.grammar.name())
            .field("job", &self.state.job_id)
            .field("guard", &self.guard.is_some())
            .field("baseline", &self.baseline.initialized())
            .field(
                "liveness_before",
                &self.liveness_before.load(Ordering::Relaxed),
            )
            .field("banner_host", &lock(&self.banner_host).is_some())
            .finish()
    }
}

impl StreamHost {
    /// Build the host for one point. Performs no I/O (spec S5.5).
    #[must_use]
    pub fn new(
        point: DiscoveredPoint,
        grammar: Arc<dyn Grammar>,
        tree: Tree,
        job: Arc<dyn JobCtx>,
        state: Arc<JobState>,
        guard: Option<Arc<L4Guard>>,
        client: Arc<dyn StreamClient>,
    ) -> Self {
        Self {
            point,
            grammar,
            tree,
            job,
            state,
            guard,
            client,
            baseline: OnceCell::new(),
            liveness_before: AtomicBool::new(true),
            banner_host: Mutex::new(None),
        }
    }

    /// The point this host sends for.
    #[allow(dead_code, reason = "Task 19's campaign is the only caller")]
    pub(crate) fn point(&self) -> &DiscoveredPoint {
        &self.point
    }

    /// The seed's parse tree, which the campaign mutates.
    #[allow(dead_code, reason = "Task 19's campaign is the only caller")]
    pub(crate) fn tree(&self) -> &Tree {
        &self.tree
    }

    /// The job behind this host.
    #[allow(dead_code, reason = "Task 19's campaign is the only caller")]
    pub(crate) fn job(&self) -> &Arc<dyn JobCtx> {
        &self.job
    }

    /// The job's lane state.
    #[allow(dead_code, reason = "Task 19's campaign is the only caller")]
    pub(crate) fn state(&self) -> &Arc<JobState> {
        &self.state
    }

    // -----------------------------------------------------------------
    // Authorisation (spec S5.4, amendment A1)
    // -----------------------------------------------------------------

    /// Mint the permit for one connection, after the A1 self-port re-check.
    ///
    /// The core's listener set changes while a job runs (a new web or bus
    /// listener binds), so discovery's check is not enough: it is re-run here,
    /// **before** `guard.check`, and nothing is opened when it bites (C18).
    fn mint_permit(&self) -> Result<L4Permit, HostError> {
        let ep = self.point.endpoint;
        let Some(guard) = self.guard.as_ref() else {
            return Err(HostError::Guard(
                "scan: refused_l4: L4 is disabled (l4.enabled: false); the stream lane sends \
                 nothing"
                    .to_string(),
            ));
        };
        if ep.ip.is_loopback() && guard.self_ports().contains(&ep.port) {
            return Err(HostError::Guard(format!(
                "scan: out_of_scope: {}:{} is one of the core's own listener ports",
                ep.ip, ep.port
            )));
        }
        guard
            .check(
                L4Action::Inject,
                &L4Target {
                    interface: ANY_INTERFACE.to_string(),
                    direction: L4Direction::Outbound,
                    dst: Some(ep.ip),
                    dst_port: Some(ep.port),
                    proto: match ep.proto {
                        L4Transport::Tcp => L4Proto::Tcp,
                        L4Transport::Udp => L4Proto::Udp,
                    },
                },
            )
            .map_err(|e| HostError::Guard(guard_message(&e)))
    }

    /// Take one of the job's [`crate::state::MAX_CONNECTIONS`] connection
    /// permits, waiting at most `min(remaining to deadline, MAX_AWAIT)`.
    async fn acquire_connection(&self) -> Result<OwnedSemaphorePermit, HostError> {
        let remaining = self
            .job
            .deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HostError::Deadline);
        }
        let waiting = Arc::clone(&self.state.connections).acquire_owned();
        match tokio::time::timeout(remaining.min(MAX_AWAIT), waiting).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(HostError::Connect(
                "the job's connection semaphore was closed".to_string(),
            )),
            Err(_elapsed) => Err(HostError::Deadline),
        }
    }

    /// One exchange on one fresh connection, with the S5.4 retry rules.
    ///
    /// A rate refusal sleeps `min(retry_after, 1 s)` and retries, at most
    /// [`MAX_RATE_WAITS`] times; a spent permit (`CountExceeded`) is re-minted
    /// once. Any other guard refusal is final.
    async fn run_exchange(
        &self,
        messages: &[Vec<u8>],
        expects_banner: bool,
    ) -> Result<Vec<ExchangeStep>, HostError> {
        let grammar = Arc::clone(&self.grammar);
        let complete = move |buf: &[u8]| grammar.reply_complete(buf);
        let ep = self.point.endpoint;
        let mut rate_waits: u32 = 0;
        let mut reminted = false;
        loop {
            let mut permit = self.mint_permit()?;
            let connection = self.acquire_connection().await?;
            let result = self
                .client
                .exchange(
                    &ep,
                    &mut permit,
                    &self.state.pacer,
                    messages,
                    &complete,
                    expects_banner,
                    REPLY_TIMEOUT,
                    CONNECT_TIMEOUT,
                )
                .await;
            match result {
                Ok(steps) => return Ok(steps),
                Err(ClientError::Guard(L4GuardError::InjectionRateExceeded { retry_after })) => {
                    rate_waits += 1;
                    if rate_waits > MAX_RATE_WAITS {
                        return Err(HostError::Guard(guard_message(
                            &L4GuardError::InjectionRateExceeded { retry_after },
                        )));
                    }
                    // Hold no connection permit while waiting out the rate cap.
                    drop(connection);
                    tokio::time::sleep(retry_after.min(MAX_RATE_SLEEP)).await;
                }
                // The permit is spent: mint a new one for the same connection,
                // once (spec S5.4).
                Err(ClientError::Guard(L4GuardError::CountExceeded { .. })) if !reminted => {
                    reminted = true;
                }
                Err(ClientError::Guard(e)) => return Err(HostError::Guard(guard_message(&e))),
                Err(ClientError::DryRun) => return Err(HostError::DryRun),
                Err(e) => return Err(HostError::Connect(e.to_string())),
            }
        }
    }

    // -----------------------------------------------------------------
    // The probe sequence (spec S5.6)
    // -----------------------------------------------------------------

    /// Send one case: steps 1-11 of spec S5.6.
    pub(crate) async fn send_case(&self, case: &[u8]) -> Result<CaseOutcome, HostError> {
        // 1. The job's own stop conditions, and this point's retirement.
        if self.job.cancelled() {
            return Err(HostError::Cancelled);
        }
        if Instant::now() >= self.job.deadline() {
            return Err(HostError::Deadline);
        }
        if self.state.is_retired(&self.point.point.id) {
            return Err(HostError::Retired);
        }

        // 2. Too many silent cases in a row: the target is not answering.
        let ceiling = self.job.profile().l4.consecutive_timeouts;
        if ceiling > 0 && self.state.consecutive_timeouts.load(Ordering::SeqCst) >= ceiling {
            return Err(HostError::ConsecutiveTimeouts(ceiling));
        }

        // 3. The dry-run backstop: the campaign never calls `probe` in a dry
        //    run, and if it did, no socket opens (spec S7).
        if self.job.profile().l4.dry_run {
            return Err(HostError::DryRun);
        }

        // 4. The denylist, over the case and every prelude message, before any
        //    charge and before the guard is asked for anything.
        let mut prelude = self.grammar.prelude_for(case);
        prelude.truncate(MAX_PRELUDE);
        if let Some(verb) = self
            .refused(case)
            .or_else(|| prelude.iter().find_map(|message| self.refused(message)))
        {
            self.state
                .cases_skipped_denylisted
                .fetch_add(1, Ordering::SeqCst);
            return Err(HostError::Denylisted(verb));
        }

        // The 64 KiB message bound: skipped and counted, never truncated
        // (spec S5.7).
        if case.len() > MAX_MESSAGE || prelude.iter().any(|m| m.len() > MAX_MESSAGE) {
            self.state
                .cases_skipped_too_large
                .fetch_add(1, Ordering::SeqCst);
            return Err(HostError::TooLarge);
        }

        // 5. One unit of the job's budget per case.
        if !self.job.charge(1) {
            return Err(HostError::Budget);
        }

        // 10. The cadence probe runs before the case it reports on.
        let liveness_before = self.liveness_cadence().await?;

        // 6, 7. The permit, the connection, the prelude and the case.
        let prior_messages = u32::try_from(prelude.len()).unwrap_or(u32::MAX);
        let mut messages = prelude;
        messages.push(case.to_vec());
        let steps = self
            .run_exchange(&messages, self.grammar.expects_banner())
            .await?;
        self.state.cases_sent.fetch_add(1, Ordering::SeqCst);
        self.record_banner(&steps);

        // 8. The oracle reads the case's own step: the last one.
        let (reply, ended, elapsed_ms) = match steps.last() {
            Some(step) => (step.reply.clone(), step.ended, step.elapsed_ms),
            // A client that returns no step sent nothing it could read.
            None => (Vec::new(), Ended::Silence, 0),
        };
        let class = self.grammar.classify_reply(&reply);
        let reading = oracle::read(
            ended,
            class,
            reply.is_empty(),
            self.grammar.close_on_malformed_is_expected(),
        );
        self.state.push_latency(elapsed_ms);
        match ended {
            Ended::Silence => {
                self.state
                    .consecutive_timeouts
                    .fetch_add(1, Ordering::SeqCst);
            }
            Ended::Eof | Ended::Reset => self.state.consecutive_timeouts.store(0, Ordering::SeqCst),
            _ if !reply.is_empty() => self.state.consecutive_timeouts.store(0, Ordering::SeqCst),
            _ => {}
        }

        // 9. Liveness, when the reading calls for it. A grammar that closes on
        //    a malformed message by design (MQTT) still gets a probe when it
        //    closed without answering its error token.
        let mut oracle_read = match reading {
            Reading::Clean => None,
            Reading::Oracle(o) => Some(o),
        };
        let triggers = oracle_read.is_some_and(oracle::triggers_liveness)
            || (ended == Ended::Eof
                && self.grammar.close_on_malformed_is_expected()
                && class != ReplyClass::ProtocolError);
        let mut liveness_after = true;
        if triggers {
            liveness_after = self.liveness_twice().await?;
            if !liveness_after {
                oracle_read = Some(L4Oracle::LivenessFailed);
                self.state.liveness_failures.fetch_add(1, Ordering::SeqCst);
            }
            self.liveness_before.store(liveness_after, Ordering::SeqCst);
        }

        self.report();

        // 11.
        Ok(CaseOutcome {
            reply,
            oracle: oracle_read,
            elapsed_ms,
            liveness_before,
            liveness_after,
            prior_messages,
        })
    }

    /// Step 10: every `liveness_every` cases, probe before the case; otherwise
    /// report the last known state.
    async fn liveness_cadence(&self) -> Result<bool, HostError> {
        let every = self.job.profile().l4.liveness_every;
        let sent = self.state.cases_sent.load(Ordering::SeqCst);
        if every > 0 && sent > 0 && sent.is_multiple_of(every) {
            let alive = self.liveness().await?;
            self.liveness_before.store(alive, Ordering::SeqCst);
            return Ok(alive);
        }
        Ok(self.liveness_before.load(Ordering::SeqCst))
    }

    /// One liveness probe on a fresh connection (spec S5.6 step 9).
    ///
    /// A target that cannot be reached at all is not an error here: that is
    /// the probe's answer, `false`.
    pub(crate) async fn liveness(&self) -> Result<bool, HostError> {
        let probe = self.grammar.liveness_probe();
        if probe.send.is_empty() {
            // A grammar with no liveness message (the corpus-less `raw` case)
            // cannot judge the target; it is never called dead for that.
            return Ok(true);
        }
        if !self.job.charge(1) {
            return Err(HostError::Budget);
        }
        self.state.liveness_probes.fetch_add(1, Ordering::SeqCst);

        let mut messages = vec![probe.send.clone()];
        if let Some(after) = probe.after.clone() {
            messages.push(after);
        }
        let expects_banner = self.grammar.expects_banner();
        let steps = match self.run_exchange(&messages, expects_banner).await {
            Ok(steps) => steps,
            Err(HostError::Connect(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.record_banner(&steps);
        // The probe's own step: step 0, or step 1 behind a banner. The `after`
        // message's reply is never judged.
        let Some(step) = steps.get(usize::from(expects_banner)) else {
            return Ok(false);
        };
        Ok(probe.matches(&step.reply, step.ended))
    }

    /// The liveness reading of spec S5.6 step 9: immediately, then once more
    /// after [`LIVENESS_RETRY`].
    pub(crate) async fn liveness_twice(&self) -> Result<bool, HostError> {
        if self.liveness().await? {
            return Ok(true);
        }
        tokio::time::sleep(LIVENESS_RETRY).await;
        self.liveness().await
    }

    /// Poll liveness every second for up to [`RECOVERY_WINDOW`] (spec S6.2).
    #[allow(dead_code, reason = "Task 19's campaign is the only caller")]
    pub(crate) async fn wait_recovery(&self) -> Result<bool, HostError> {
        let started = Instant::now();
        loop {
            if self.liveness().await? {
                return Ok(true);
            }
            if started.elapsed() >= RECOVERY_WINDOW {
                return Ok(false);
            }
            tokio::time::sleep(RECOVERY_POLL).await;
        }
    }

    /// Report the job's L4 counters to the engine.
    fn report(&self) {
        // A5: wired by the integration task — `JobCtx` has no `report_l4` yet,
        // and this crate may not add one to the T1a contract (Task 24 does).
    }

    /// The denylist verdict for one message.
    ///
    /// SMTP is the one grammar whose verdict depends on what the target said:
    /// once a `220` banner has been read, `RCPT` to that hostname is the
    /// target's own mail, not a relay. Without a banner the plain rule applies
    /// and every `RCPT` is refused.
    fn refused(&self, message: &[u8]) -> Option<&'static str> {
        let kind = self.point.grammar;
        if kind == GrammarKind::Smtp {
            if let Some(banner_host) = lock(&self.banner_host).as_deref() {
                return denylist::refuses_with_context(
                    kind,
                    message,
                    &DenyContext {
                        target_ip: self.point.endpoint.ip,
                        banner_host: Some(banner_host),
                    },
                );
            }
        }
        denylist::refuses(kind, message)
    }

    /// Remember an SMTP target's banner hostname, for [`StreamHost::refused`].
    fn record_banner(&self, steps: &[ExchangeStep]) {
        if self.point.grammar != GrammarKind::Smtp || !self.grammar.expects_banner() {
            return;
        }
        let Some(step) = steps.first() else {
            return;
        };
        if step.sent_len != 0 {
            return;
        }
        if let Some(host) = smtp::banner_host(&step.reply) {
            *lock(&self.banner_host) = Some(host);
        }
    }
}

/// The D3 rendering of a guard refusal (spec S5.4, S5.6).
///
/// A refusal about *where* the case would go is `out_of_scope`; a refusal
/// about what the subsystem will do at all is `refused_l4`.
fn guard_message(e: &L4GuardError) -> String {
    match e {
        L4GuardError::OutOfL4Scope(_)
        | L4GuardError::CapabilityNotGranted(_)
        | L4GuardError::DangerousDestinationBlocked(_) => format!("scan: out_of_scope: {e}"),
        _ => format!("scan: refused_l4: {e}"),
    }
}

/// Milliseconds since `started`, saturating.
fn millis_since(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// Fold a case outcome into the model's response (plan call P4).
///
/// `L4Reply::oracle` is not optional in the T1a contract, so a clean case —
/// one the oracle had nothing to say about — is reported as `l4: None` with
/// the reply in `body`, and only a reading carries an `L4Reply`.
fn response_for(outcome: &CaseOutcome) -> ProbeResponse {
    match outcome.oracle {
        None => ProbeResponse {
            status: None,
            headers: Vec::new(),
            body: outcome.reply.clone(),
            elapsed_ms: outcome.elapsed_ms,
            flow: None,
            ws_frames: None,
            l4: None,
        },
        Some(oracle) => ProbeResponse {
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            elapsed_ms: outcome.elapsed_ms,
            flow: None,
            ws_frames: None,
            l4: Some(L4Reply {
                bytes: outcome.reply.clone(),
                oracle,
                elapsed_ms: outcome.elapsed_ms,
            }),
        },
    }
}

impl ProbeHost for StreamHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            let response = self
                .baseline
                .get_or_try_init(|| async {
                    let seed = self.point.seed_bytes.clone();
                    let outcome = self.send_case(&seed).await.map_err(anyhow::Error::new)?;
                    if !outcome.reply.is_empty() {
                        self.liveness_before.store(true, Ordering::SeqCst);
                    }
                    Ok::<ProbeResponse, anyhow::Error>(response_for(&outcome))
                })
                .await?;
            Ok(response.clone())
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            // The reserved liveness payload (plan call P5): no bytes, and the
            // one value the lane reads.
            if payload.bytes.is_none() && payload.value == LIVENESS_PAYLOAD {
                let started = Instant::now();
                let alive = self.liveness_twice().await.map_err(anyhow::Error::new)?;
                let elapsed_ms = millis_since(started);
                return Ok(ProbeResponse {
                    status: None,
                    headers: Vec::new(),
                    body: Vec::new(),
                    elapsed_ms,
                    flow: None,
                    ws_frames: None,
                    l4: if alive {
                        None
                    } else {
                        Some(L4Reply {
                            bytes: Vec::new(),
                            oracle: L4Oracle::LivenessFailed,
                            elapsed_ms,
                        })
                    },
                });
            }
            let Some(case) = payload.bytes.as_deref() else {
                return Err(anyhow::Error::new(HostError::NotBytes));
            };
            let outcome = self.send_case(case).await.map_err(anyhow::Error::new)?;
            Ok(response_for(&outcome))
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        let _ = req;
        Box::pin(async {
            Err(anyhow::Error::new(HostError::Unsupported(
                "probe_raw is not available on the L4 stream lane",
            )))
        })
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
        self.job.profile()
    }

    fn cancelled(&self) -> bool {
        self.job.cancelled()
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        // The lane holds no HTTP flow; `L4Evidence.sent_hex` is its record.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    //! Loopback probes against in-test listeners.
    //!
    //! These are the inner loop, not acceptance evidence (plan, "No fake-data
    //! evidence"): they pin the probe sequence's order and its refusals. Every
    //! test that needs a socket binds an ephemeral port on 127.0.0.1; a sandbox
    //! that refuses local binding makes it print `SKIP: sandbox refuses local
    //! binding` and return, and the Tester runs the same tests in a real shell.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
        StdGuard,
    };
    use aitm_proto_l4::config::L4Config;
    use aitm_proto_l4::guard::{L4Guard, ANY_INTERFACE};
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use aitm_scan_model::{
        InsertionKind, InsertionPoint, JobCtx, L4Oracle, L4Transport, LaneKind, Payload,
        PayloadMode, ProbeHost, RawProbe, ScanProfile, SessionMaterial,
    };
    use futures::future::BoxFuture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use std::sync::Mutex;

    use aitm_proto_l4::guard::L4Permit;

    use super::{HostError, StreamHost};
    use crate::client::testing::CountingClient;
    use crate::client::{ClientError, Ended, Endpoint, ExchangeStep, StreamClient};
    use crate::grammar;
    use crate::spec::GrammarKind;
    use crate::state::{lock, BytePacer, DiscoveredPoint, JobState};

    /// A `ProxyClient` that performs no I/O; a job context needs one to exist.
    struct NullClient;

    impl ProxyClient for NullClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
        }
    }

    /// A `JobCtx` that counts charges and can refuse them.
    struct TestJob {
        profile: ScanProfile,
        charges: AtomicU32,
        affordable: bool,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
    }

    impl TestJob {
        fn new() -> Self {
            let mut profile = ScanProfile::default();
            profile.l4.liveness_every = 25;
            profile.l4.consecutive_timeouts = 20;
            Self {
                profile,
                charges: AtomicU32::new(0),
                affordable: true,
                client: Arc::new(NullClient),
                store: Arc::new(MemFlowStore::new()),
                guard: Arc::new(StdGuard::default()),
            }
        }

        fn broke(mut self) -> Self {
            self.affordable = false;
            self
        }

        fn dry_run(mut self) -> Self {
            self.profile.l4.dry_run = true;
            self
        }

        fn consecutive_timeouts(mut self, n: u32) -> Self {
            self.profile.l4.consecutive_timeouts = n;
            self
        }

        fn charges(&self) -> u32 {
            self.charges.load(Ordering::SeqCst)
        }
    }

    impl JobCtx for TestJob {
        fn job_id(&self) -> &str {
            "scan-18"
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
        fn charge(&self, units: u32) -> bool {
            if !self.affordable {
                return false;
            }
            self.charges.fetch_add(units, Ordering::SeqCst);
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
            "aitm18".to_string()
        }
    }

    /// A guard whose config-declared scope authorises outbound injection to
    /// `127.0.0.0/8`, which is what an operator writes to let the lane reach a
    /// local speaker (loopback is otherwise a dangerous destination).
    fn loopback_guard() -> Arc<L4Guard> {
        Arc::new(L4Guard::new(&L4Config {
            enabled: true,
            scope: vec![L4ScopeEntry {
                id: L4ScopeId::new(),
                cidr: IpCidr {
                    addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                    prefix: 8,
                },
                ports: PortRange { lo: 0, hi: 65535 },
                interface: ANY_INTERFACE.to_string(),
                direction: L4Direction::Outbound,
                capability: L4Capability::Inject,
                inject_rate: RateCap {
                    pps: 1000,
                    burst: 1000,
                },
                source: L4ScopeSource::Config,
            }],
            ..Default::default()
        }))
    }

    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            proto: L4Transport::Tcp,
        }
    }

    /// The RESP point every test sends through: one seed, one mutable leaf.
    fn discovered(ep: Endpoint) -> DiscoveredPoint {
        DiscoveredPoint {
            point: InsertionPoint {
                id: "l4s-0123456789abcdef".to_string(),
                lane: LaneKind::L4Stream,
                kind: InsertionKind::L4Field,
                name: "data".to_string(),
                path: Some("inline.data".to_string()),
                example: Some("50494e47".to_string()),
                flow: None,
                site_node: None,
                traits: Vec::new(),
                frequency: 1,
                method: Some("L4".to_string()),
                url: Some(format!("tcp://{}:{}/resp", ep.ip, ep.port)),
            },
            node_id: format!("l4s-tcp-{}-{}", ep.ip, ep.port),
            endpoint: ep,
            grammar: GrammarKind::Resp,
            seed_id: "gen:0".to_string(),
            seed_bytes: b"PING\r\n".to_vec(),
            scope_entry: "127.0.0.0/8:0-65535 * outbound".to_string(),
            selection: "default_port(6379)".to_string(),
        }
    }

    fn test_host(
        ep: Endpoint,
        guard: Option<Arc<L4Guard>>,
        job: &Arc<TestJob>,
        client: &Arc<CountingClient>,
    ) -> StreamHost {
        host_with(ep, guard, job, Arc::clone(client) as Arc<dyn StreamClient>)
    }

    fn host_with(
        ep: Endpoint,
        guard: Option<Arc<L4Guard>>,
        job: &Arc<TestJob>,
        client: Arc<dyn StreamClient>,
    ) -> StreamHost {
        let grammar = grammar::by_kind(GrammarKind::Resp);
        let tree = grammar
            .parse(b"PING\r\n")
            .expect("the RESP grammar parses its own liveness message");
        let state = JobState::new("scan-18", "aitm18", job.profile.l4.max_bytes_per_s);
        StreamHost::new(
            discovered(ep),
            grammar,
            tree,
            Arc::clone(job) as Arc<dyn JobCtx>,
            state,
            guard,
            client,
        )
    }

    /// A `StreamClient` that answers from a script and opens no socket.
    ///
    /// The plan's named tests drive the real transport against a loopback
    /// listener; a sandbox that refuses binding skips those, so this double
    /// keeps the probe sequence under test everywhere, and records the exact
    /// messages each exchange was given.
    struct ScriptedClient {
        reply: Vec<u8>,
        ended: Ended,
        seen: Mutex<Vec<Vec<Vec<u8>>>>,
    }

    impl ScriptedClient {
        fn new(reply: &[u8], ended: Ended) -> Self {
            Self {
                reply: reply.to_vec(),
                ended,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn exchanges(&self) -> Vec<Vec<Vec<u8>>> {
            lock(&self.seen).clone()
        }
    }

    impl StreamClient for ScriptedClient {
        #[allow(clippy::too_many_arguments)]
        fn exchange<'a>(
            &'a self,
            _ep: &'a Endpoint,
            _permit: &'a mut L4Permit,
            _pacer: &'a Mutex<BytePacer>,
            messages: &'a [Vec<u8>],
            _complete: &'a (dyn Fn(&[u8]) -> bool + Sync),
            _expects_banner: bool,
            _reply_timeout: Duration,
            _connect_timeout: Duration,
        ) -> BoxFuture<'a, Result<Vec<ExchangeStep>, ClientError>> {
            lock(&self.seen).push(messages.to_vec());
            let steps: Vec<ExchangeStep> = messages
                .iter()
                .map(|message| ExchangeStep {
                    sent_len: message.len(),
                    reply: self.reply.clone(),
                    ended: self.ended,
                    elapsed_ms: 7,
                })
                .collect();
            Box::pin(async move { Ok(steps) })
        }
    }

    fn payload(bytes: &[u8]) -> Payload {
        Payload {
            value: String::new(),
            mode: PayloadMode::Replace,
            bytes: Some(bytes.to_vec()),
        }
    }

    /// `EPERM`/`EACCES` on bind: the sandbox, not the code under test.
    fn bind_refused(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(1 | 13))
    }

    async fn loopback_listener() -> Option<TcpListener> {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(listener) => Some(listener),
            Err(e) if bind_refused(&e) => {
                println!("SKIP: sandbox refuses local binding");
                None
            }
            Err(e) => panic!("loopback TCP bind failed: {e}"),
        }
    }

    /// A listener that answers every message with `+PONG\r\n`.
    fn spawn_pong(listener: TcpListener) -> SocketAddr {
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(b"+PONG\r\n").await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A listener that accepts, reads and never answers, holding the
    /// connection open so every exchange ends in silence.
    fn spawn_silent(listener: TcpListener) -> SocketAddr {
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    let _ = sock.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });
        addr
    }

    fn host_error(e: &anyhow::Error) -> &HostError {
        e.downcast_ref::<HostError>()
            .unwrap_or_else(|| panic!("not a HostError: {e}"))
    }

    #[tokio::test]
    async fn probe_sends_once_and_charges_once() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = spawn_pong(listener);

        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(addr.port()), Some(loopback_guard()), &job, &client);

        let response = host.probe(&payload(b"PING\r\n")).await.expect("probe");

        assert!(response.l4.is_none(), "{:?}", response.l4);
        assert_eq!(response.body, b"+PONG\r\n".to_vec());
        assert_eq!(client.count(), 1);
        assert_eq!(job.charges(), 1);
        assert_eq!(host.state().cases_sent.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn denylisted_is_skipped_not_sent() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe(&payload(b"FLUSHALL\r\n"))
            .await
            .expect_err("the denylist refuses FLUSHALL");

        assert!(
            matches!(host_error(&error), HostError::Denylisted("FLUSHALL")),
            "{error}"
        );
        assert_eq!(client.count(), 0);
        assert_eq!(job.charges(), 0);
        assert_eq!(
            host.state().cases_skipped_denylisted.load(Ordering::SeqCst),
            1
        );
        assert_eq!(host.state().cases_sent.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn too_large_is_skipped() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe(&payload(&vec![b'A'; 70_000]))
            .await
            .expect_err("70 000 bytes is over the 64 KiB message bound");

        assert!(matches!(host_error(&error), HostError::TooLarge), "{error}");
        assert_eq!(client.count(), 0);
        assert_eq!(job.charges(), 0);
        assert_eq!(
            host.state().cases_skipped_too_large.load(Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn budget_exhausted() {
        let job = Arc::new(TestJob::new().broke());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("a refused charge stops the probe");

        assert!(matches!(host_error(&error), HostError::Budget), "{error}");
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn retired_refuses() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);
        assert!(host.state().retire("l4s-0123456789abcdef"));

        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("a retired point sends nothing");

        assert!(matches!(host_error(&error), HostError::Retired), "{error}");
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn silence_triggers_liveness_and_counts_timeouts() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = spawn_silent(listener);

        let job = Arc::new(TestJob::new().consecutive_timeouts(2));
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(addr.port()), Some(loopback_guard()), &job, &client);

        // The case times out, both liveness probes time out too: three
        // exchanges and a LivenessFailed reading.
        let response = host.probe(&payload(b"PING\r\n")).await.expect("probe");
        let reply = response.l4.expect("an oracle reading, not a clean reply");
        assert_eq!(reply.oracle, L4Oracle::LivenessFailed);
        assert_eq!(reply.bytes, Vec::<u8>::new());
        assert_eq!(client.count(), 3);
        assert_eq!(host.state().liveness_probes.load(Ordering::SeqCst), 2);
        assert_eq!(host.state().liveness_failures.load(Ordering::SeqCst), 1);
        assert_eq!(host.state().consecutive_timeouts.load(Ordering::SeqCst), 1);

        // The same reading through `send_case`, which carries the liveness
        // flags the campaign reads.
        let outcome = host.send_case(b"PING\r\n").await.expect("send_case");
        assert_eq!(outcome.oracle, Some(L4Oracle::LivenessFailed));
        assert!(!outcome.liveness_after);
        assert_eq!(outcome.prior_messages, 0);
        assert_eq!(client.count(), 6);
        assert_eq!(host.state().consecutive_timeouts.load(Ordering::SeqCst), 2);

        // Two silent cases in a row is the profile's ceiling: the next probe
        // never reaches the socket.
        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("the consecutive-timeout ceiling stops the point");
        assert!(
            matches!(host_error(&error), HostError::ConsecutiveTimeouts(2)),
            "{error}"
        );
        assert_eq!(client.count(), 6);
    }

    #[tokio::test]
    async fn self_port_recheck() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let guard = loopback_guard();
        let host = test_host(endpoint(9797), Some(Arc::clone(&guard)), &job, &client);

        // The core binds a listener on that port after the host was built.
        guard.add_self_ports([9797]);

        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("the lane never probes the core's own listener");

        match host_error(&error) {
            HostError::Guard(message) => {
                assert!(
                    message.contains("is one of the core's own listener ports"),
                    "{message}"
                );
                assert!(message.contains("127.0.0.1:9797"), "{message}");
                assert!(message.starts_with("scan: out_of_scope: "), "{message}");
            }
            other => panic!("expected a guard refusal, got {other:?}"),
        }
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn guard_none_refuses() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), None, &job, &client);

        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("no guard, no traffic");

        match host_error(&error) {
            HostError::Guard(message) => {
                assert!(message.starts_with("scan: refused_l4: "), "{message}");
                assert!(message.contains("l4.enabled: false"), "{message}");
            }
            other => panic!("expected a guard refusal, got {other:?}"),
        }
        assert_eq!(client.count(), 0);

        // The recovery poll of S6.2 mints a permit too, so it refuses at once
        // rather than waiting out the fifteen-second window.
        let error = host
            .wait_recovery()
            .await
            .expect_err("no guard, no recovery probe");
        assert!(matches!(error, HostError::Guard(_)), "{error}");
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn accessors_name_the_point_the_tree_and_the_job() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        assert_eq!(host.point().point.id, "l4s-0123456789abcdef");
        assert_eq!(host.point().seed_id, "gen:0");
        assert_eq!(host.tree().grammar, "resp");
        assert_eq!(host.job().marker(), "aitm18");
        assert_eq!(host.marker(), "aitm18");
        assert_eq!(host.budget_left(), 1000);
        assert!(!host.cancelled());
        assert_eq!(host.profile().l4.liveness_every, 25);
        assert!(host.held_flows().is_empty());
        // `Debug` names the point and the grammar and no byte of either.
        let rendered = format!("{host:?}");
        assert!(rendered.contains("l4s-0123456789abcdef"), "{rendered}");
        assert!(rendered.contains("\"resp\""), "{rendered}");
        assert!(!rendered.contains("PING"), "{rendered}");
    }

    #[tokio::test]
    async fn dry_run_backstop() {
        let job = Arc::new(TestJob::new().dry_run());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe(&payload(b"PING\r\n"))
            .await
            .expect_err("a dry run opens no socket");

        assert!(matches!(host_error(&error), HostError::DryRun), "{error}");
        assert_eq!(client.count(), 0);
        assert!(host.baseline().await.is_err());
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn probe_raw_unsupported() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe_raw(RawProbe {
                method: "GET".to_string(),
                url: "http://127.0.0.1/".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await
            .expect_err("the stream lane has no raw HTTP probe");

        assert!(
            matches!(
                host_error(&error),
                HostError::Unsupported("probe_raw is not available on the L4 stream lane")
            ),
            "{error}"
        );
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn liveness_payload_runs_the_probe_and_sends_no_case() {
        let Some(listener) = loopback_listener().await else {
            return;
        };
        let addr = spawn_pong(listener);

        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(addr.port()), Some(loopback_guard()), &job, &client);

        // The reserved payload of plan call P5: no bytes, value "liveness".
        let response = host
            .probe(&Payload {
                value: "liveness".to_string(),
                mode: PayloadMode::Replace,
                bytes: None,
            })
            .await
            .expect("the liveness payload is not an error");

        assert!(response.l4.is_none(), "{:?}", response.l4);
        assert_eq!(client.count(), 1);
        assert_eq!(host.state().cases_sent.load(Ordering::SeqCst), 0);
        assert_eq!(host.state().liveness_probes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_payload_without_bytes_is_not_a_case() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(CountingClient::live());
        let host = test_host(endpoint(6379), Some(loopback_guard()), &job, &client);

        let error = host
            .probe(&Payload {
                value: "'; DROP TABLE".to_string(),
                mode: PayloadMode::Replace,
                bytes: None,
            })
            .await
            .expect_err("a text payload has no rendered message");

        assert!(matches!(host_error(&error), HostError::NotBytes), "{error}");
        assert_eq!(client.count(), 0);
    }

    #[tokio::test]
    async fn a_clean_reply_is_a_body_with_no_oracle() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(ScriptedClient::new(b"+PONG\r\n", Ended::Replied));
        let host = host_with(
            endpoint(6379),
            Some(loopback_guard()),
            &job,
            Arc::clone(&client) as Arc<dyn StreamClient>,
        );

        let response = host.probe(&payload(b"PING\r\n")).await.expect("probe");

        assert!(response.l4.is_none(), "{:?}", response.l4);
        assert_eq!(response.body, b"+PONG\r\n".to_vec());
        assert_eq!(response.elapsed_ms, 7);
        // One exchange, carrying the case alone: RESP has no prelude.
        assert_eq!(client.exchanges(), vec![vec![b"PING\r\n".to_vec()]]);
        assert_eq!(job.charges(), 1);
        assert_eq!(host.state().cases_sent.load(Ordering::SeqCst), 1);
        assert_eq!(host.state().consecutive_timeouts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn scripted_silence_reads_liveness_failed() {
        let job = Arc::new(TestJob::new());
        let client = Arc::new(ScriptedClient::new(b"", Ended::Silence));
        let host = host_with(
            endpoint(6379),
            Some(loopback_guard()),
            &job,
            Arc::clone(&client) as Arc<dyn StreamClient>,
        );

        let outcome = host.send_case(b"PING\r\n").await.expect("send_case");

        assert_eq!(outcome.oracle, Some(L4Oracle::LivenessFailed));
        assert!(!outcome.liveness_after);
        assert!(outcome.liveness_before);
        assert_eq!(outcome.prior_messages, 0);
        // The case, then the two liveness probes of S5.6 step 9.
        assert_eq!(
            client.exchanges(),
            vec![
                vec![b"PING\r\n".to_vec()],
                vec![b"PING\r\n".to_vec()],
                vec![b"PING\r\n".to_vec()],
            ]
        );
        assert_eq!(host.state().liveness_probes.load(Ordering::SeqCst), 2);
        assert_eq!(host.state().liveness_failures.load(Ordering::SeqCst), 1);
        assert_eq!(host.state().consecutive_timeouts.load(Ordering::SeqCst), 1);
        // The case plus two liveness probes, one budget unit each.
        assert_eq!(job.charges(), 3);
    }
}
