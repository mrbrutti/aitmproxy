//! `JobClient`: the budgeted, paced, error-laddered client every lane sends
//! through (spec D5). Task 8 of the T1b plan fills it.
//!
//! Spec D1 "Where a probe goes": the engine never calls a sender directly.
//! Every HTTP stimulus of a job goes through this wrapper around the binary's
//! `ProxyClient` (the `PipelineClient`: guard, sender, store), which adds the
//! five things a scan needs and a bare client has no business knowing about:
//!
//! * **one budget per job** — one unit per stimulus across every lane, so a
//!   job can never become a flood-shaped primitive (spec D5, anti-goals);
//! * **pacing** — a [`GuardError::RateLimited`] is a wait, not an abort, and
//!   each wait is counted in `rate_waits`;
//! * **a per-host error ladder** — a host that answers with 5xx or transport
//!   failures past the profile's `consecutive`/`ratio` rule is dropped for the
//!   rest of the job (call B15);
//! * **timing and marks** — every probe flow carries `scan:<job>` and the
//!   elapsed time the sender does not measure;
//! * **the record policy** — under `issues_only` a probe is sent with
//!   `record: Never`, so probes never evict real captures (spec D5, call B14);
//!   only a lane's crawl captures opt in with an explicit `Always` and the
//!   `crawl` mark, and an issue's re-recording is a store insert by the engine.
//!
//! Every await is bounded by `min(remaining deadline, 30 s)` and ends early on
//! the job's [`CancellationToken`] (spec D5 "Cancellation").

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{
    GuardError, HttpFlow, HttpRequest, ProxyClient, RecordPolicy, SendOptions, VersionPolicy,
};
use aitm_scan_model::profile::PerHostErrors;
use aitm_scan_model::vocab::{HttpVersionPolicy, RecordProbes};
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

/// The ceiling on any single await inside a job (spec D5: every await is
/// bounded by `min(remaining, 30 s)`). A probe that has not answered in half a
/// minute is not worth the job's remaining time.
pub const MAX_AWAIT: Duration = Duration::from_secs(30);

/// How many times one probe is re-sent after a rate-limit refusal before the
/// refusal is handed back to the caller.
pub const MAX_RATE_RETRIES: u32 = 8;

/// How many probe outcomes the per-host ladder keeps per host (call B15).
const LADDER_WINDOW: usize = 50;

/// How many outcomes a host's window needs before the *ratio* half of call
/// B15 can trip it. Without a floor the ratio rule fires on a single failed
/// probe (1 of 1 is over any ratio below 1.0) and the `consecutive` half could
/// never be reached; ten is the smallest floor under which both of the plan's
/// ladder cases hold (three 5xx trip on `consecutive: 3`, and ten alternating
/// outcomes at exactly `ratio: 0.5` do not trip while the eleventh does).
const LADDER_MIN_SAMPLE: usize = 10;

/// Why a bounded await ended without a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwaitEnd {
    /// The 30 s per-await ceiling elapsed while the job still had time.
    Timeout,
    /// The job's deadline passed.
    Deadline,
    /// The job was cancelled.
    Cancelled,
}

/// Await `fut` under the job's deadline and cancellation token.
///
/// The bound is `min(deadline - now, MAX_AWAIT)`: whichever of the two ends
/// first names the [`AwaitEnd`], so a caller can tell "this probe hung" from
/// "the job ran out of time". A deadline that has already passed returns
/// [`AwaitEnd::Deadline`] without polling `fut`.
pub async fn bounded_await<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Result<T, AwaitEnd> {
    bounded_await_with(deadline, cancel, Some(MAX_AWAIT), fut).await
}

/// [`bounded_await`] without the per-await cap: the future runs until it ends,
/// the job's deadline passes or the job is cancelled. For the **discovery**
/// phase, whose one await is a whole crawl: capping it at [`MAX_AWAIT`] cut
/// every crawl longer than 30 s and reported the job as out of `time` while
/// `budget.time_s` still had minutes left (T2 live run, 2026-11-01).
pub async fn await_until_deadline<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Result<T, AwaitEnd> {
    bounded_await_with(deadline, cancel, None, fut).await
}

/// The one implementation behind [`bounded_await`] (`cap = Some(MAX_AWAIT)`)
/// and [`await_until_deadline`] (`cap = None`).
pub async fn bounded_await_with<T>(
    deadline: Instant,
    cancel: &CancellationToken,
    cap: Option<Duration>,
    fut: impl Future<Output = T>,
) -> Result<T, AwaitEnd> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AwaitEnd::Deadline);
    }
    // Whichever bound is tighter is the one whose name the caller gets.
    let (bound, end) = match cap {
        Some(cap) if remaining > cap => (cap, AwaitEnd::Timeout),
        _ => (remaining, AwaitEnd::Deadline),
    };
    tokio::select! {
        // Biased: a send that has already answered is never thrown away for a
        // timer that fired in the same poll.
        biased;
        value = fut => Ok(value),
        () = cancel.cancelled() => Err(AwaitEnd::Cancelled),
        () = tokio::time::sleep(bound) => Err(end),
    }
}

/// One job's probe budget, deadline and cancellation token — the three things
/// that bound a scan in time and volume (spec D5 "Budget and pacing").
///
/// Shared by every lane of the job behind an `Arc`, so the budget is one
/// figure across lanes rather than one per lane.
#[derive(Debug)]
pub struct JobBudget {
    /// The job's `budget.probes`: the total number of stimuli it may spend.
    pub budget: u64,
    charged: AtomicU64,
    /// `started_at + budget.time_s`.
    pub deadline: Instant,
    /// Set by `scan.cancel`; observed between probes and inside every await.
    pub cancel: CancellationToken,
}

impl JobBudget {
    /// A budget of `budget` probes that ends at `deadline` or when `cancel`
    /// fires. A `budget` of zero is a valid, parseable configuration and means
    /// exhausted: the first [`JobBudget::charge`] refuses.
    pub fn new(budget: u64, deadline: Instant, cancel: CancellationToken) -> Self {
        Self {
            budget,
            charged: AtomicU64::new(0),
            deadline,
            cancel,
        }
    }

    /// Spend `units` of the budget, atomically. Returns `false` and leaves the
    /// counter untouched when the charge would overdraw, so concurrent lanes
    /// can never spend past `budget` between them.
    pub fn charge(&self, units: u32) -> bool {
        let units = u64::from(units);
        let mut current = self.charged.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_add(units);
            if next > self.budget {
                return false;
            }
            match self.charged.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Probes still affordable, saturating at `u32::MAX` for the wire field.
    pub fn left(&self) -> u32 {
        let left = self
            .budget
            .saturating_sub(self.charged.load(Ordering::SeqCst));
        u32::try_from(left).unwrap_or(u32::MAX)
    }

    /// Probes charged so far — the `probes.sent` side of a job's progress.
    pub fn spent(&self) -> u64 {
        self.charged.load(Ordering::SeqCst)
    }
}

/// Whether a host is still worth probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderState {
    /// Keep probing.
    Ok,
    /// The error ladder tripped: this host takes no more probes this job.
    Tripped,
}

/// One host's error ladder: its current run of failures and the last
/// [`LADDER_WINDOW`] outcomes (`true` = usable answer).
///
/// `tripped` is sticky. A trip is a decision about the host for the rest of
/// the job (call B15: "a trip ends the job with `stopped_reason: errors`"), and
/// it is what lets [`ProbeMeter::ladder_state`] answer without being handed the
/// profile's rules again.
#[derive(Debug, Default)]
struct Ladder {
    consecutive: u32,
    window: VecDeque<bool>,
    tripped: bool,
}

impl Ladder {
    fn trips(&self, rules: &PerHostErrors) -> bool {
        if rules.consecutive > 0 && self.consecutive >= rules.consecutive {
            return true;
        }
        let total = self.window.len();
        if total < LADDER_MIN_SAMPLE {
            // Too few outcomes to call a ratio — and never a division by zero.
            return false;
        }
        let failures = self.window.iter().filter(|ok| !**ok).count();
        (failures as f32 / total as f32) > rules.ratio
    }
}

/// What a job's probes did: the counters a `scan.status` line reports and the
/// per-host ladders that stop a lane (spec D5).
#[derive(Debug, Default)]
pub struct ProbeMeter {
    /// Probes that got an answer.
    pub sent: AtomicU64,
    /// Probes that failed (transport, guard refusal other than a rate limit,
    /// or the 30 s ceiling).
    pub errors: AtomicU64,
    /// Probes that hit the 30 s per-await ceiling (also counted in `errors`).
    pub timeouts: AtomicU64,
    /// Rate-limit waits served instead of aborting.
    pub rate_waits: AtomicU64,
    ladders: Mutex<HashMap<String, Ladder>>,
}

impl ProbeMeter {
    /// Record one outcome for `host` and return the host's state afterwards.
    pub fn record(&self, host: &str, ok: bool, rules: &PerHostErrors) -> LadderState {
        let mut ladders = self.ladders.lock().unwrap_or_else(|e| e.into_inner());
        let ladder = ladders.entry(host.to_string()).or_default();
        if ok {
            ladder.consecutive = 0;
        } else {
            ladder.consecutive = ladder.consecutive.saturating_add(1);
        }
        if ladder.window.len() >= LADDER_WINDOW {
            ladder.window.pop_front();
        }
        ladder.window.push_back(ok);
        ladder.tripped = ladder.tripped || ladder.trips(rules);
        if ladder.tripped {
            LadderState::Tripped
        } else {
            LadderState::Ok
        }
    }

    /// The host's state without recording anything. A host never probed is
    /// [`LadderState::Ok`].
    pub fn ladder_state(&self, host: &str) -> LadderState {
        let ladders = self.ladders.lock().unwrap_or_else(|e| e.into_inner());
        match ladders.get(host) {
            Some(ladder) if ladder.tripped => LadderState::Tripped,
            _ => LadderState::Ok,
        }
    }
}

/// Why the engine refused to send, or to finish, a probe. Each variant's text
/// names the reason, because it is what a `scan.status` `stopped_reason` and a
/// check's error surface quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRefused {
    /// The job's probe budget is spent.
    Budget,
    /// The job's deadline passed.
    Deadline,
    /// The job was cancelled.
    Cancelled,
    /// The host's error ladder tripped.
    HostLadder(String),
    /// The proxy's own guard refused (out of scope, SSRF, concurrency).
    Guard(GuardError),
    /// The probe to `host` did not answer within the per-await ceiling
    /// (`after`, i.e. [`MAX_AWAIT`]) while the job still had time.
    Timeout { host: String, after: Duration },
}

impl fmt::Display for ProbeRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeRefused::Budget => write!(f, "probe refused: the job's probe budget is spent"),
            ProbeRefused::Deadline => write!(f, "probe refused: the job's deadline passed"),
            ProbeRefused::Cancelled => write!(f, "probe refused: the job was cancelled"),
            ProbeRefused::HostLadder(host) => {
                write!(f, "probe refused: the error ladder tripped for {host}")
            }
            ProbeRefused::Guard(err) => write!(f, "probe refused by the guard: {err}"),
            ProbeRefused::Timeout { host, after } => {
                write!(f, "probe to {host} timed out after {after:?}")
            }
        }
    }
}

impl std::error::Error for ProbeRefused {}

/// The client every lane of one job sends through (spec D1 "Where a probe
/// goes"). It owns no transport: `inner` is the binary's `PipelineClient`, so a
/// probe still passes the proxy's scope and rate guard before it leaves.
pub struct JobClient {
    inner: Arc<dyn ProxyClient>,
    job_id: String,
    budget: Arc<JobBudget>,
    meter: Arc<ProbeMeter>,
    record: RecordPolicy,
    version: VersionPolicy,
    per_host: PerHostErrors,
}

impl JobClient {
    /// Wrap `inner` for the job `job_id`, sharing `budget` and `meter` with
    /// every other lane of that job.
    pub fn new(
        inner: Arc<dyn ProxyClient>,
        job_id: &str,
        budget: Arc<JobBudget>,
        meter: Arc<ProbeMeter>,
        record: RecordProbes,
        version: HttpVersionPolicy,
        per_host: PerHostErrors,
    ) -> Self {
        Self {
            inner,
            job_id: job_id.to_string(),
            budget,
            meter,
            record: match record {
                RecordProbes::All => RecordPolicy::Always,
                RecordProbes::IssuesOnly => RecordPolicy::Never,
            },
            version: version.into(),
            per_host,
        }
    }

    /// The job's shared budget (the worker reads `left`/`spent` for progress).
    pub fn budget(&self) -> &Arc<JobBudget> {
        &self.budget
    }

    /// The job's shared probe counters and per-host ladders.
    pub fn meter(&self) -> &Arc<ProbeMeter> {
        &self.meter
    }

    /// The options the inner client actually gets: the job's mark first, the
    /// caller's marks after it (deduped), the record policy below, and the
    /// caller's version unless it left the choice to the job.
    ///
    /// Record policy (spec D5, call B14, orchestrator ruling on Task 8):
    /// `Always` iff the job's policy is `all` **or** the caller explicitly
    /// asked for `Always`; otherwise `Never`. Probes use [`JobClient::send`]
    /// (or an explicit `Never`) and so never reach the store under
    /// `issues_only`. The one caller that passes `Always` is a lane recording
    /// its client-crawl captures with the `crawl` mark (D5 "crawl flows are
    /// different"); an issue's re-recording is a store insert of the flows the
    /// `ProbeHost` held in memory, done by the engine, never a send through
    /// this client.
    fn job_opts(&self, opts: SendOptions) -> SendOptions {
        let mut marks = vec![format!("scan:{}", self.job_id)];
        for mark in opts.marks {
            if !marks.contains(&mark) {
                marks.push(mark);
            }
        }
        let record = if self.record == RecordPolicy::Always || opts.record == RecordPolicy::Always {
            RecordPolicy::Always
        } else {
            RecordPolicy::Never
        };
        let version = if opts.version == VersionPolicy::Auto {
            self.version
        } else {
            opts.version
        };
        SendOptions {
            record,
            marks,
            version,
        }
    }

    /// Map a bounded await that ended early onto the refusal it is. A probe's
    /// own 30 s ceiling is counted (`timeouts`, `errors`) and marks the host's
    /// ladder; the deadline and cancellation are the job's, not the host's.
    fn await_end_error(&self, end: AwaitEnd, host: &str) -> anyhow::Error {
        match end {
            AwaitEnd::Timeout => {
                self.meter.timeouts.fetch_add(1, Ordering::SeqCst);
                self.meter.errors.fetch_add(1, Ordering::SeqCst);
                self.meter.record(host, false, &self.per_host);
                anyhow::Error::new(ProbeRefused::Timeout {
                    host: host.to_string(),
                    after: MAX_AWAIT,
                })
            }
            AwaitEnd::Deadline => anyhow::Error::new(ProbeRefused::Deadline),
            AwaitEnd::Cancelled => anyhow::Error::new(ProbeRefused::Cancelled),
        }
    }
}

/// The key one host's error ladder lives under: [`util::guard_authority`]'s
/// `host:port`, always with an explicit port.
///
/// Every probe records its outcome under this key and the worker reads the
/// same key before every scheduled item ([`crate::worker`]'s `host_of_point`).
/// They were once two spellings — the raw request authority here and
/// `host:port` there — so a target on a default port tripped the ladder,
/// refused the rest of its probes, and still ended with no `stopped_reason`
/// (whole-branch quality finding).
pub(crate) fn ladder_key(scheme: &str, authority: &str) -> String {
    crate::util::guard_authority(scheme, authority)
}

impl ProxyClient for JobClient {
    /// A bare `send` is a **probe**: it goes out with `record: Never` (not
    /// `SendOptions::default()`, whose `Always` would put every probe in the
    /// store), so under `issues_only` it never reaches the store. Only a
    /// lane's crawl captures pass `Always` through [`ProxyClient::send_opts`],
    /// with the `crawl` mark; issue re-recording is a store insert by the
    /// engine, not a send.
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.send_opts(
            req,
            SendOptions {
                record: RecordPolicy::Never,
                ..SendOptions::default()
            },
        )
    }

    /// Send under the caller's options, budgeted, paced and laddered. The
    /// inner client records iff the job's policy is `all` or `opts.record` is
    /// an explicit `Always` (a lane's crawl captures, marked `crawl`); probes
    /// use [`ProxyClient::send`] or pass `Never`.
    fn send_opts(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async move {
            let host = ladder_key(&req.scheme, &req.authority);
            // A tripped host costs the job nothing more: refused before the
            // budget is charged and before the guard is touched.
            if self.meter.ladder_state(&host) == LadderState::Tripped {
                return Err(anyhow::Error::new(ProbeRefused::HostLadder(host)));
            }
            // A job that is already over spends nothing either: the deadline
            // and the cancellation are read before a unit is charged, so a
            // `Deadline`/`Cancelled` refusal never costs a probe.
            if self.budget.cancel.is_cancelled() {
                return Err(anyhow::Error::new(ProbeRefused::Cancelled));
            }
            if Instant::now() >= self.budget.deadline {
                return Err(anyhow::Error::new(ProbeRefused::Deadline));
            }
            if !self.budget.charge(1) {
                return Err(anyhow::Error::new(ProbeRefused::Budget));
            }
            let opts = self.job_opts(opts);

            // One charge, up to MAX_RATE_RETRIES attempts: a rate-limit wait is
            // pacing of the same probe, not a new one. The loop returns on
            // every path, including the attempt ceiling, so it never spins.
            let mut attempt: u32 = 0;
            loop {
                attempt += 1;
                let started = Instant::now();
                let sent = bounded_await(
                    self.budget.deadline,
                    &self.budget.cancel,
                    self.inner.send_opts(req.clone(), opts.clone()),
                )
                .await;
                let outcome = match sent {
                    Ok(outcome) => outcome,
                    Err(end) => return Err(self.await_end_error(end, &host)),
                };
                let err = match outcome {
                    Ok(mut flow) => {
                        self.meter.sent.fetch_add(1, Ordering::SeqCst);
                        // The sender leaves `duration` `None`; this is the only
                        // place a probe's elapsed time is measured.
                        flow.metadata.duration = Some(started.elapsed());
                        let usable = flow.response.as_ref().is_some_and(|r| r.status < 500);
                        self.meter.record(&host, usable, &self.per_host);
                        return Ok(flow);
                    }
                    Err(err) => err,
                };

                match err.downcast_ref::<GuardError>() {
                    Some(GuardError::RateLimited { retry_after }) => {
                        if attempt >= MAX_RATE_RETRIES {
                            // Paced as long as the job can afford to: hand the
                            // guard's refusal back, typed like every other
                            // guard refusal, rather than keep the lane spinning
                            // on one point.
                            self.meter.errors.fetch_add(1, Ordering::SeqCst);
                            return Err(anyhow::Error::new(ProbeRefused::Guard(
                                GuardError::RateLimited {
                                    retry_after: *retry_after,
                                },
                            )));
                        }
                        self.meter.rate_waits.fetch_add(1, Ordering::SeqCst);
                        let wait = (*retry_after).min(MAX_AWAIT);
                        if let Err(end) = bounded_await(
                            self.budget.deadline,
                            &self.budget.cancel,
                            tokio::time::sleep(wait),
                        )
                        .await
                        {
                            match end {
                                // The 30 s ceiling cut the wait short; the
                                // retry itself is still worth one attempt.
                                AwaitEnd::Timeout => {}
                                AwaitEnd::Deadline => {
                                    return Err(anyhow::Error::new(ProbeRefused::Deadline))
                                }
                                AwaitEnd::Cancelled => {
                                    return Err(anyhow::Error::new(ProbeRefused::Cancelled))
                                }
                            }
                        }
                    }
                    Some(GuardError::HostDisabled) => {
                        // The proxy's own per-host breaker already fired: the
                        // job's ladder agrees and stops probing this host. It
                        // is still a probe that got no answer, so it counts in
                        // `errors` like every other refusal.
                        self.meter.errors.fetch_add(1, Ordering::SeqCst);
                        self.meter.record(&host, false, &self.per_host);
                        return Err(anyhow::Error::new(ProbeRefused::HostLadder(host)));
                    }
                    Some(guard) => {
                        self.meter.errors.fetch_add(1, Ordering::SeqCst);
                        self.meter.record(&host, false, &self.per_host);
                        return Err(anyhow::Error::new(ProbeRefused::Guard(guard.clone())));
                    }
                    None => {
                        self.meter.errors.fetch_add(1, Ordering::SeqCst);
                        self.meter.record(&host, false, &self.per_host);
                        return Err(err);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::time::SystemTime;

    use aitm_core::{
        Body, GuardError, HeaderMap, HttpFlow, HttpResponse, HttpVersion, InterceptState,
        RecordPolicy, SendOptions, VersionPolicy,
    };
    use aitm_core::{ConnInfo, FlowId, FlowMeta};
    use aitm_scan_model::profile::PerHostErrors;
    use aitm_scan_model::vocab::{HttpVersionPolicy, RecordProbes};

    /// One programmed answer from the stub. A `Sleep` is not an answer by
    /// itself: the stub sleeps and reads the next entry, so `[Sleep(15ms),
    /// Ok(200)]` is one slow 200.
    #[derive(Debug, Clone)]
    enum Outcome {
        Ok(u16),
        Guard(GuardError),
        Other(&'static str),
        Sleep(Duration),
    }

    /// A `ProxyClient` that answers from a queue and records every
    /// [`SendOptions`] it was handed. No I/O, no network.
    struct StubClient {
        queue: Mutex<VecDeque<Outcome>>,
        calls: AtomicUsize,
        seen: Mutex<Vec<SendOptions>>,
    }

    impl StubClient {
        fn new(outcomes: Vec<Outcome>) -> Arc<Self> {
            Arc::new(Self {
                queue: Mutex::new(outcomes.into_iter().collect()),
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn seen(&self) -> Vec<SendOptions> {
            self.seen.lock().expect("stub lock").clone()
        }

        fn pop(&self) -> Option<Outcome> {
            self.queue.lock().expect("stub lock").pop_front()
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
                self.seen.lock().expect("stub lock").push(opts);
                loop {
                    match self.pop() {
                        Some(Outcome::Sleep(d)) => tokio::time::sleep(d).await,
                        Some(Outcome::Ok(status)) => return Ok(stub_flow(req, status)),
                        Some(Outcome::Guard(g)) => return Err(anyhow::Error::new(g)),
                        Some(Outcome::Other(msg)) => return Err(anyhow::anyhow!(msg)),
                        None => return Ok(stub_flow(req, 200)),
                    }
                }
            })
        }
    }

    fn stub_flow(req: HttpRequest, status: u16) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: req,
            response: Some(HttpResponse {
                status,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Empty,
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
            // The sender leaves `duration` `None`; the `JobClient` fills it.
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// The ladder key [`req_to`]'s request is recorded under: the probe is
    /// `https`, so the key the client writes and the worker reads is
    /// `host:443` ([`ladder_key`]), never the bare host.
    fn key(host: &str) -> String {
        ladder_key("https", host)
    }

    fn req_to(host: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: host.into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    /// A budget that is not the thing under test: 1000 probes, a minute of
    /// deadline, uncancelled.
    fn loose_budget(probes: u64) -> Arc<JobBudget> {
        Arc::new(JobBudget::new(
            probes,
            Instant::now() + Duration::from_secs(60),
            CancellationToken::new(),
        ))
    }

    fn lenient_hosts() -> PerHostErrors {
        PerHostErrors {
            consecutive: 1000,
            ratio: 1.0,
        }
    }

    /// Spec D5 "Budget and pacing": one `probes` budget per job, one unit per
    /// stimulus, and the probe that would overdraw it is refused before it
    /// reaches the sender.
    #[tokio::test]
    async fn charges_one_unit_per_send_and_stops_at_budget() {
        let stub = StubClient::new(vec![Outcome::Ok(200), Outcome::Ok(200), Outcome::Ok(200)]);
        let budget = loose_budget(2);
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            budget.clone(),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        assert!(client.send(req_to("ex.test")).await.is_ok());
        assert!(client.send(req_to("ex.test")).await.is_ok());
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the third probe is over budget");
        assert!(
            err.to_string().contains("budget"),
            "refusal does not name the budget: {err}"
        );

        assert_eq!(stub.calls(), 2, "the refused probe reached the sender");
        assert_eq!(budget.left(), 0);
        assert_eq!(budget.spent(), 2);
    }

    /// A zero probe budget is a real, parseable configuration (`budget.probes:
    /// 0`, wave-1 security review): it means "exhausted", so the first probe is
    /// refused and nothing reaches the sender. No division, no spin.
    #[tokio::test]
    async fn a_zero_budget_refuses_the_first_probe() {
        let stub = StubClient::new(vec![Outcome::Ok(200)]);
        let budget = loose_budget(0);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            budget.clone(),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("a zero budget has nothing to spend");
        assert!(
            err.to_string().contains("budget"),
            "refusal does not name the budget: {err}"
        );
        assert_eq!(stub.calls(), 0);
        assert_eq!(meter.sent.load(Ordering::SeqCst), 0);
        assert_eq!(budget.left(), 0);
        assert_eq!(budget.spent(), 0);
    }

    /// Spec D5 "Record policy", call B14 (orchestrator ruling on Task 8):
    /// a bare `send` is a probe and never records under `issues_only`; a lane
    /// recording its crawl captures passes an explicit `Always` with the
    /// `crawl` mark and is honoured; under `all` even a bare `send` records.
    /// Every flow carries `scan:<job>` exactly once, the caller's marks after.
    #[tokio::test]
    async fn marks_and_record_policy_reach_the_inner_client() {
        let stub = StubClient::new(vec![Outcome::Ok(200), Outcome::Ok(200)]);
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        client.send(req_to("ex.test")).await.expect("probe");
        assert_eq!(stub.seen()[0].marks, vec!["scan:scan-1a2b3c4d".to_string()]);
        assert_eq!(
            stub.seen()[0].record,
            RecordPolicy::Never,
            "a bare send is a probe and must not record under issues_only"
        );

        client
            .send_opts(
                req_to("ex.test"),
                SendOptions {
                    record: RecordPolicy::Always,
                    marks: vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()],
                    version: VersionPolicy::Auto,
                },
            )
            .await
            .expect("crawl capture");
        assert_eq!(
            stub.seen()[1].marks,
            vec!["scan:scan-1a2b3c4d".to_string(), "crawl".to_string()],
            "the job mark is not duplicated and the crawl mark passes through"
        );
        assert_eq!(
            stub.seen()[1].record,
            RecordPolicy::Always,
            "a lane's explicit Always (crawl captures) is honoured"
        );

        let all_stub = StubClient::new(vec![Outcome::Ok(200)]);
        let all = JobClient::new(
            all_stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            Arc::new(ProbeMeter::default()),
            RecordProbes::All,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );
        all.send(req_to("ex.test")).await.expect("probe");
        assert_eq!(all_stub.seen()[0].record, RecordPolicy::Always);
        assert_eq!(
            all_stub.seen()[0].marks,
            vec!["scan:scan-1a2b3c4d".to_string()]
        );
    }

    /// Spec D5: an upstream failure that is not a guard refusal is the
    /// caller's to see — the engine only counts it and marks the host's
    /// ladder, it never swallows or rewrites the error.
    #[tokio::test]
    async fn a_transport_error_counts_and_passes_through() {
        let stub = StubClient::new(vec![Outcome::Other("upstream connection reset")]);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the upstream failed");
        assert_eq!(err.to_string(), "upstream connection reset");
        assert_eq!(meter.errors.load(Ordering::SeqCst), 1);
        assert_eq!(meter.sent.load(Ordering::SeqCst), 0);
        assert_eq!(meter.timeouts.load(Ordering::SeqCst), 0);
        assert_eq!(stub.calls(), 1, "a non-rate error is not retried");
    }

    /// Spec D5: a rate-limit refusal is a wait, not an abort, and the wait is
    /// counted in `rate_waits`.
    #[tokio::test]
    async fn rate_limited_waits_then_retries() {
        let stub = StubClient::new(vec![
            Outcome::Guard(GuardError::RateLimited {
                retry_after: Duration::from_millis(10),
            }),
            Outcome::Ok(200),
        ]);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let flow = client.send(req_to("ex.test")).await.expect("the retry");
        assert_eq!(flow.response.expect("response").status, 200);
        assert_eq!(meter.rate_waits.load(Ordering::SeqCst), 1);
        assert_eq!(stub.calls(), 2);
        assert_eq!(meter.sent.load(Ordering::SeqCst), 1);
        assert_eq!(meter.errors.load(Ordering::SeqCst), 0);
    }

    /// Spec D5 and call B15: consecutive 5xx trip the host's ladder and the
    /// next probe to that host never leaves the engine.
    #[tokio::test]
    async fn host_ladder_trips_on_consecutive_5xx() {
        let stub = StubClient::new(vec![
            Outcome::Ok(500),
            Outcome::Ok(500),
            Outcome::Ok(500),
            Outcome::Ok(200),
        ]);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            PerHostErrors {
                consecutive: 3,
                ratio: 0.5,
            },
        );

        for _ in 0..3 {
            client.send(req_to("ex.test")).await.expect("a 5xx is sent");
        }
        assert_eq!(meter.ladder_state(&key("ex.test")), LadderState::Tripped);

        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the host is tripped");
        assert!(
            err.to_string().contains("ladder"),
            "refusal does not name the ladder: {err}"
        );
        assert_eq!(stub.calls(), 3, "a tripped host was probed again");
    }

    /// Call B15's second rule: the 50-entry window's failure ratio trips the
    /// ladder even when no run of failures ever reaches `consecutive`.
    #[tokio::test]
    async fn ratio_rule_trips_too() {
        let mut outcomes = Vec::new();
        for i in 0..10 {
            outcomes.push(Outcome::Ok(if i % 2 == 0 { 200 } else { 500 }));
        }
        outcomes.push(Outcome::Ok(500));
        let stub = StubClient::new(outcomes);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(20),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            PerHostErrors {
                consecutive: 100,
                ratio: 0.5,
            },
        );

        for _ in 0..10 {
            client.send(req_to("ex.test")).await.expect("probe");
        }
        assert_eq!(
            meter.ladder_state(&key("ex.test")),
            LadderState::Ok,
            "five failures in ten is not over the 0.5 ratio"
        );

        client.send(req_to("ex.test")).await.expect("probe");
        assert_eq!(meter.ladder_state(&key("ex.test")), LadderState::Tripped);
    }

    /// `await_until_deadline` has no per-await cap: a future longer than the
    /// cap still completes while the deadline holds, and only the deadline
    /// (never `Timeout`) ends it; `bounded_await_with(Some(cap))` keeps the
    /// cap and names it `Timeout`.
    #[tokio::test]
    async fn await_until_deadline_has_no_per_await_cap() {
        let cancel = CancellationToken::new();
        let cap = Duration::from_millis(20);
        let deadline = Instant::now() + Duration::from_millis(400);
        let slow = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            7
        };
        let capped = bounded_await_with(deadline, &cancel, Some(cap), slow).await;
        assert!(
            matches!(capped, Err(AwaitEnd::Timeout)),
            "the cap ends a slow future as Timeout: {capped:?}"
        );

        let slow = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            7
        };
        assert_eq!(
            await_until_deadline(deadline, &cancel, slow).await.ok(),
            Some(7),
            "without a cap the same future completes inside the deadline"
        );

        let soon = Instant::now() + Duration::from_millis(30);
        let never = std::future::pending::<u8>();
        assert!(
            matches!(
                await_until_deadline(soon, &cancel, never).await,
                Err(AwaitEnd::Deadline)
            ),
            "only the deadline ends an uncapped await"
        );
    }

    /// Spec D5 "Cancellation": `scan.cancel` ends a probe that is still in
    /// flight, inside the bounded await.
    #[tokio::test]
    async fn cancel_ends_a_pending_send_within_the_bound() {
        let stub = StubClient::new(vec![Outcome::Sleep(Duration::from_secs(10))]);
        let cancel = CancellationToken::new();
        let budget = Arc::new(JobBudget::new(
            10,
            Instant::now() + Duration::from_secs(60),
            cancel.clone(),
        ));
        let client = JobClient::new(
            stub,
            "scan-1a2b3c4d",
            budget,
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });

        let started = Instant::now();
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("a cancelled job does not finish its probe");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Cancelled),
            "not the typed cancellation refusal: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the cancelled probe took {:?}",
            started.elapsed()
        );
    }

    /// Spec D5: the deadline is `started_at + time_s` and every await is
    /// bounded by `min(remaining, 30 s)` — a hung send ends at the deadline,
    /// and that is not a probe timeout.
    #[tokio::test]
    async fn deadline_bounds_the_await() {
        let stub = StubClient::new(vec![Outcome::Sleep(Duration::from_secs(10))]);
        let budget = Arc::new(JobBudget::new(
            10,
            Instant::now() + Duration::from_millis(100),
            CancellationToken::new(),
        ));
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub,
            "scan-1a2b3c4d",
            budget,
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let started = Instant::now();
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the deadline passed");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Deadline),
            "not the typed deadline refusal: {err}"
        );
        assert!(
            err.to_string().contains("deadline"),
            "refusal does not name the deadline: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the probe outlived the deadline bound by {:?}",
            started.elapsed()
        );
        assert_eq!(meter.timeouts.load(Ordering::SeqCst), 0);
    }

    /// Spec D5: a probe that outlives the 30 s per-await ceiling while the job
    /// still has time is a typed [`ProbeRefused::Timeout`] naming the host: it
    /// is counted in `timeouts` and `errors` and marks the host's ladder. The
    /// ceiling itself is not waited for here; the mapping is exercised directly.
    #[tokio::test]
    async fn a_probe_timeout_is_a_typed_refusal() {
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            StubClient::new(vec![]),
            "scan-1a2b3c4d",
            loose_budget(10),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            PerHostErrors {
                consecutive: 1,
                ratio: 1.0,
            },
        );

        // `send_opts` hands the ladder key down, so the refusal names the same
        // `host:port` the ladder is written under.
        let err = client.await_end_error(AwaitEnd::Timeout, &key("ex.test"));
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Timeout {
                host: key("ex.test"),
                after: MAX_AWAIT,
            })
        );
        assert!(
            err.to_string().contains("timed out") && err.to_string().contains("ex.test"),
            "refusal does not name the timeout and host: {err}"
        );
        assert_eq!(meter.timeouts.load(Ordering::SeqCst), 1);
        assert_eq!(meter.errors.load(Ordering::SeqCst), 1);
        assert_eq!(meter.ladder_state(&key("ex.test")), LadderState::Tripped);

        let cancelled = client.await_end_error(AwaitEnd::Cancelled, "ex.test");
        assert_eq!(
            cancelled.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Cancelled)
        );
        assert_eq!(
            meter.timeouts.load(Ordering::SeqCst),
            1,
            "only a timeout counts"
        );
    }

    /// AC T1-9's timing half: the sender leaves `FlowMeta.duration` `None`, so
    /// the `JobClient` is what makes a probe's elapsed time observable.
    #[tokio::test]
    async fn elapsed_is_recorded_on_the_flow() {
        let stub = StubClient::new(vec![
            Outcome::Sleep(Duration::from_millis(15)),
            Outcome::Ok(200),
        ]);
        let client = JobClient::new(
            stub,
            "scan-1a2b3c4d",
            loose_budget(10),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let flow = client.send(req_to("ex.test")).await.expect("probe");
        assert!(
            flow.metadata.duration.expect("an elapsed time") >= Duration::from_millis(15),
            "elapsed {:?} is under the stub's own sleep",
            flow.metadata.duration
        );
    }

    /// Spec D9.1: the job's `http.version` is the default, and a caller that
    /// names a version (the h2-specific checks) overrides it.
    #[tokio::test]
    async fn version_override_wins_over_the_job_policy() {
        let stub = StubClient::new(vec![Outcome::Ok(200), Outcome::Ok(200)]);
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::H1,
            lenient_hosts(),
        );

        client
            .send_opts(
                req_to("ex.test"),
                SendOptions {
                    version: VersionPolicy::H2,
                    ..SendOptions::default()
                },
            )
            .await
            .expect("probe");
        assert_eq!(stub.seen()[0].version, VersionPolicy::H2);

        client
            .send_opts(req_to("ex.test"), SendOptions::default())
            .await
            .expect("probe");
        assert_eq!(stub.seen()[1].version, VersionPolicy::H1);
    }

    // ---- tester additions ---------------------------------------------------

    /// Pacing is bounded (wave-1 security review: "never spin in the pacer"):
    /// after `MAX_RATE_RETRIES` attempts the guard's own refusal is handed
    /// back, the probe cost one budget unit, and it counts as one error.
    #[tokio::test]
    async fn rate_limit_retries_are_bounded() {
        let outcomes: Vec<Outcome> = (0..MAX_RATE_RETRIES + 2)
            .map(|_| {
                Outcome::Guard(GuardError::RateLimited {
                    retry_after: Duration::from_millis(1),
                })
            })
            .collect();
        let stub = StubClient::new(outcomes);
        let budget = loose_budget(10);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            budget.clone(),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let started = Instant::now();
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("a host that never stops rate limiting is given up on");
        // Wave-2/3 quality fix: the exhausted pacer hands back the typed
        // `ProbeRefused::Guard`, like every other guard refusal, and the text
        // still names the rate limit.
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Guard(GuardError::RateLimited {
                retry_after: Duration::from_millis(1),
            })),
            "not the typed guard refusal: {err}"
        );
        assert!(
            err.to_string().contains("rate limited"),
            "the refusal names the rate limit: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            stub.calls() as u32,
            MAX_RATE_RETRIES,
            "exactly the attempt ceiling"
        );
        assert_eq!(
            meter.rate_waits.load(Ordering::SeqCst) as u32,
            MAX_RATE_RETRIES - 1
        );
        assert_eq!(meter.errors.load(Ordering::SeqCst), 1);
        assert_eq!(meter.sent.load(Ordering::SeqCst), 0);
        assert_eq!(
            budget.spent(),
            1,
            "one probe, one unit, however many retries"
        );
        assert_eq!(
            meter.ladder_state(&key("ex.test")),
            LadderState::Ok,
            "being rate limited is not a host failure"
        );
    }

    /// The Task 8 amendment's `LADDER_MIN_SAMPLE = 10`: the ratio rule is
    /// silent until a host has ten outcomes in its window (nine failures of
    /// nine is not a ratio), and speaks at exactly the tenth.
    #[tokio::test]
    async fn ratio_rule_needs_ten_outcomes() {
        let stub = StubClient::new((0..10).map(|_| Outcome::Ok(500)).collect());
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(20),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            PerHostErrors {
                consecutive: 100,
                ratio: 0.5,
            },
        );

        for i in 0..9 {
            client
                .send(req_to("ex.test"))
                .await
                .expect("a 5xx is an answer");
            assert_eq!(
                meter.ladder_state(&key("ex.test")),
                LadderState::Ok,
                "{} failures of {} is below the sample floor",
                i + 1,
                i + 1
            );
        }
        client
            .send(req_to("ex.test"))
            .await
            .expect("the tenth answer");
        assert_eq!(
            meter.ladder_state(&key("ex.test")),
            LadderState::Tripped,
            "ten of ten over 0.5 trips at the floor"
        );
        assert_eq!(stub.calls(), 10);

        // The ratio is per host: another host starts clean.
        assert_eq!(meter.ladder_state(&key("other.test")), LadderState::Ok);
    }

    /// A guard refusal other than a rate limit is a typed `ProbeRefused::Guard`
    /// counted once; the proxy's own `HostDisabled` breaker is answered as a
    /// `HostLadder` refusal, marks the host's ladder and (wave-2/3 quality
    /// fix) counts in `errors` like every other probe that got no answer.
    #[tokio::test]
    async fn guard_refusals_are_typed_and_host_disabled_is_a_ladder_refusal() {
        let stub = StubClient::new(vec![
            Outcome::Guard(GuardError::OutOfScope("ex.test".into())),
            Outcome::Guard(GuardError::HostDisabled),
            Outcome::Ok(200),
        ]);
        let meter = Arc::new(ProbeMeter::default());
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            loose_budget(10),
            meter.clone(),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );

        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("out of scope is refused");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Guard(GuardError::OutOfScope(
                "ex.test".into()
            ))),
            "{err}"
        );
        assert!(err.to_string().contains("out of scope"), "{err}");
        assert_eq!(meter.errors.load(Ordering::SeqCst), 1);
        assert_eq!(
            meter.ladder_state(&key("ex.test")),
            LadderState::Ok,
            "one failure under lenient rules is not a trip"
        );

        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("a disabled host is refused");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::HostLadder(key("ex.test"))),
            "{err}"
        );
        assert_eq!(stub.calls(), 2);
        assert_eq!(
            meter.errors.load(Ordering::SeqCst),
            2,
            "a `HostDisabled` refusal is a probe without an answer: counted"
        );

        // Not tripped by the lenient rules, so the next probe still reaches the
        // sender: `HostDisabled` agrees with the ladder but does not force it.
        // What *is* pinned: the job never overrides the proxy's breaker.
        let third = client.send(req_to("ex.test")).await;
        assert!(third.is_ok(), "{third:?}");
        assert_eq!(stub.calls(), 3);
        assert_eq!(
            meter.sent.load(Ordering::SeqCst),
            1,
            "only the answered probe counts as sent"
        );
    }

    /// Spec D5 "one budget per job": twenty lanes racing for a budget of five
    /// get exactly five sends between them, and the sender sees exactly five.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sends_never_overdraw_the_budget() {
        let stub = StubClient::new((0..20).map(|_| Outcome::Ok(200)).collect());
        let budget = loose_budget(5);
        let client = Arc::new(JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            budget.clone(),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        ));

        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let client = Arc::clone(&client);
                tokio::spawn(async move { client.send(req_to("ex.test")).await.is_ok() })
            })
            .collect();
        let mut ok = 0;
        for task in tasks {
            if task.await.expect("the task ran") {
                ok += 1;
            }
        }

        assert_eq!(ok, 5, "exactly the budget's worth of probes succeeded");
        assert_eq!(stub.calls(), 5, "the sender never saw an over-budget probe");
        assert_eq!(budget.spent(), 5);
        assert_eq!(budget.left(), 0);
    }

    /// A deadline that has already passed, or a token already cancelled,
    /// refuses without polling the sender at all — and (wave-2/3 fix) without
    /// spending a budget unit: the probe was never going to be sent.
    #[tokio::test]
    async fn an_expired_deadline_or_cancelled_job_refuses_without_sending() {
        let stub = StubClient::new(vec![Outcome::Ok(200)]);
        let expired = Arc::new(JobBudget::new(
            10,
            Instant::now() - Duration::from_secs(1),
            CancellationToken::new(),
        ));
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            Arc::clone(&expired),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the deadline has passed");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Deadline)
        );
        assert_eq!(stub.calls(), 0, "nothing is sent after the deadline");
        assert_eq!(expired.spent(), 0, "a deadline refusal spends no budget");

        let cancel = CancellationToken::new();
        cancel.cancel();
        let stub = StubClient::new(vec![Outcome::Sleep(Duration::from_secs(5))]);
        let cancelled_budget = Arc::new(JobBudget::new(
            10,
            Instant::now() + Duration::from_secs(60),
            cancel,
        ));
        let client = JobClient::new(
            stub.clone(),
            "scan-1a2b3c4d",
            Arc::clone(&cancelled_budget),
            Arc::new(ProbeMeter::default()),
            RecordProbes::IssuesOnly,
            HttpVersionPolicy::Auto,
            lenient_hosts(),
        );
        let started = Instant::now();
        let err = client
            .send(req_to("ex.test"))
            .await
            .expect_err("the job is cancelled");
        assert_eq!(
            err.downcast_ref::<ProbeRefused>(),
            Some(&ProbeRefused::Cancelled)
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a pre-cancelled job must not wait on the sender: {:?}",
            started.elapsed()
        );
        assert_eq!(stub.calls(), 0, "nothing is sent after a cancel");
        assert_eq!(
            cancelled_budget.spent(),
            0,
            "a cancel refusal spends no budget"
        );
    }

    /// `bounded_await` names the tighter of the two bounds, and `JobBudget`
    /// arithmetic saturates: a `u32::MAX` charge against a small budget is a
    /// clean refusal, not an overflow.
    #[tokio::test]
    async fn bounded_await_and_budget_edges() {
        let cancel = CancellationToken::new();
        let soon = Instant::now() + Duration::from_millis(20);
        let end = bounded_await(soon, &cancel, tokio::time::sleep(Duration::from_secs(5)))
            .await
            .expect_err("the deadline is the tighter bound");
        assert_eq!(end, AwaitEnd::Deadline);

        let value = bounded_await(Instant::now() + Duration::from_secs(60), &cancel, async {
            7
        })
        .await
        .expect("a ready future completes");
        assert_eq!(value, 7);

        let budget = JobBudget::new(3, Instant::now() + Duration::from_secs(60), cancel);
        assert!(!budget.charge(u32::MAX), "an overdraw is refused");
        assert_eq!(budget.spent(), 0, "a refused charge spends nothing");
        assert!(budget.charge(0), "a zero charge is free");
        assert!(budget.charge(3));
        assert_eq!(budget.left(), 0);
        assert!(!budget.charge(1));

        let huge = JobBudget::new(
            u64::MAX,
            Instant::now() + Duration::from_secs(60),
            CancellationToken::new(),
        );
        assert_eq!(huge.left(), u32::MAX, "`left` saturates for the wire field");
    }
}
