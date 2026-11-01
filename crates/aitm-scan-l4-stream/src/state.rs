//! Per-process `LaneState` and per-job `JobState`: pacer, semaphore, liveness
//! (spec S5.1, S5.7, S6.2).
//!
//! Everything the lane remembers between calls lives here and is bounded: at
//! most [`MAX_JOBS`] job states, each holding its counters, its retired points,
//! its byte pacer, its connection semaphore, its latency window and its
//! per-point campaign slots. A job that never reaches `probe_host_for` leaves
//! nothing behind, and a job that is cancelled, passes its deadline, or simply
//! ages out is dropped from both maps together (spec S5.1, amendment A2).
//!
//! Nothing here opens a socket or parses a byte off the wire: it is per-job
//! bookkeeping. `Debug` on [`JobState`] and [`DiscoveredPoint`] prints byte
//! fields as `<n bytes>` and never their contents (spec S9, C11).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aitm_proto_l4::types::L4Proto;
use aitm_scan_model::{InsertionPoint, JobCtx, L4Counters, L4Transport};
use tokio::sync::Semaphore;

use crate::checks::Campaign;
use crate::grammar::Grammar;
use crate::spec::GrammarKind;

// ---------------------------------------------------------------------------
// S5.7: the ceilings the lane enforces itself
// ---------------------------------------------------------------------------
// The engine clamps a profile to the umbrella D11 ceilings; the lane re-caps
// against these so a misconfigured engine cannot make it overshoot. Each one is
// named in the verdict `detail` when it binds.

/// Cases one job may send, however large `l4.cases` is.
pub const MAX_CASES_PER_JOB: u32 = 5000;
/// The send-rate ceiling, in bytes per second: 1 MiB/s.
pub const MAX_BYTES_PER_S: u32 = 1 << 20;
/// Connections the lane holds open at once, across every point of a job.
pub const MAX_CONNECTIONS: usize = 4;
/// The most reply bytes read from one exchange: 64 KiB.
pub const MAX_REPLY: usize = 65536;
/// The largest message the lane sends: 64 KiB. A larger rendered case is
/// skipped and counted before the guard sees it.
pub const MAX_MESSAGE: usize = 65536;
/// The longest the lane waits on one exchange, before the deadline bounds it.
pub const MAX_AWAIT: Duration = Duration::from_secs(30);
/// How long one reply may take before the exchange counts as silence.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a connect may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// The gap between the two liveness probes of one reading.
pub const LIVENESS_RETRY: Duration = Duration::from_millis(500);
/// How long the campaign waits for a target to come back (spec S6.2).
pub const RECOVERY_WINDOW: Duration = Duration::from_secs(15);
/// How often the recovery wait re-probes a target that went away (spec S6.2).
pub const RECOVERY_POLL: Duration = Duration::from_secs(1);
/// The gap between two reproduction attempts.
pub const REPRODUCE_SPACING: Duration = Duration::from_secs(1);
/// The most prelude messages a grammar may send before a case.
pub const MAX_PRELUDE: usize = 8;
/// Job states held at once; the oldest is evicted beyond this.
pub const MAX_JOBS: usize = 16;
/// Seeds kept per endpoint.
pub const MAX_SEEDS_PER_ENDPOINT: usize = 64;
/// Insertion points emitted per endpoint.
pub const MAX_POINTS_PER_ENDPOINT: usize = 256;
/// The highest `repeat` index that yields points; `[4..]` yield none.
pub const MAX_REPEAT_INDEX: usize = 3;
/// Reply times kept for the latency rule (spec S6.1).
pub const LATENCY_WINDOW: usize = 20;
/// Samples the latency window needs before a median is meaningful (S6.1,
/// "with at least 10 samples in the window").
pub const MIN_LATENCY_SAMPLES: usize = 10;

/// The lane's refusal when a point is not one of this job's (spec S5.5).
///
/// Both the host factory and the campaign check it, and an operator reading
/// a verdict should not have to tell two spellings of one fact apart.
pub(crate) fn not_this_lanes_point(point_id: &str, job_id: &str) -> String {
    format!("l4_stream: point {point_id} was not produced by this lane for job {job_id}")
}

/// The lane's refusal when a point's seed no longer parses (spec S5.5).
pub(crate) fn seed_does_not_parse(seed_id: &str, point_id: &str, grammar: &str) -> String {
    format!("l4_stream: the seed {seed_id} of point {point_id} does not parse under {grammar}")
}

/// The guard's protocol selector for a scan profile's transport.
pub(crate) fn proto_of(proto: L4Transport) -> L4Proto {
    match proto {
        L4Transport::Tcp => L4Proto::Tcp,
        L4Transport::Udp => L4Proto::Udp,
    }
}

/// `tcp` or `udp`: the wire spelling of a transport, in an id, a URL or a
/// verdict line.
pub(crate) fn proto_name(proto: L4Transport) -> &'static str {
    match proto {
        L4Transport::Tcp => "tcp",
        L4Transport::Udp => "udp",
    }
}

/// Lock a state mutex, taking the data back if a thread panicked while holding
/// it.
///
/// None of this module's data has an invariant that a panic could break: the
/// maps, the counters and the latency window are each consistent after any
/// single operation. Recovering beats poisoning the whole lane for the rest of
/// the process, and keeps these paths free of `unwrap` (spec Constraints).
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// The pacer
// ---------------------------------------------------------------------------

/// A sliding one-second window over bytes sent (spec S5.7).
///
/// The bound the umbrella measures (T6-4) is stated over the target's log:
/// *for every one-second window, the bytes the lane wrote in it are at most
/// `max_bytes_per_s`*. So that is what the pacer keeps. It remembers each
/// write of the last second and, asked for `len` more, either records the
/// write and returns zero or returns exactly how long the caller must sleep
/// for enough of those writes to age out of the window.
///
/// A token bucket does not hold that bound: one that starts full lets a
/// wall-clock second carry its initial second of tokens *and* the second of
/// refill behind them, which is how a 8192 bytes/s profile was observed
/// writing 9937 bytes in a second against T10's SMTP speaker.
///
/// Every write the lane makes — prelude, case, liveness probe, reproduction —
/// passes through [`BytePacer::wait_for`]. The pacer only computes the wait
/// and records the write; the caller sleeps, so no lock is ever held across
/// an await, and the caller may sleep once and write (it need not ask again).
pub struct BytePacer {
    /// The bytes one window may carry.
    rate: u32,
    /// Each write of the last second: when it goes out, and how many bytes.
    /// Ascending in time, oldest at the front.
    window: VecDeque<(Instant, usize)>,
    /// The bytes [`BytePacer::window`] holds, kept in step with it.
    in_window: usize,
}

/// The width of the window the pacer bounds.
const PACER_WINDOW: Duration = Duration::from_secs(1);

/// Writes remembered at once. Beyond this the two oldest are merged, which
/// holds their bytes in the window until the later of the two ages out: the
/// pacer stays conservative and its memory stays bounded however small the
/// lane's messages are.
const MAX_PACER_WRITES: usize = 4096;

impl BytePacer {
    /// A pacer at `bytes_per_s`, clamped to `1..=`[`MAX_BYTES_PER_S`].
    ///
    /// The lower clamp keeps the rate out of a division by zero; a profile
    /// asking for zero bytes per second would otherwise mean "never send".
    #[must_use]
    pub fn new(bytes_per_s: u32) -> Self {
        Self {
            rate: bytes_per_s.clamp(1, MAX_BYTES_PER_S),
            window: VecDeque::new(),
            in_window: 0,
        }
    }

    /// The effective rate in bytes per second, after the clamp.
    #[must_use]
    pub fn rate(&self) -> u32 {
        self.rate
    }

    /// How long the caller must sleep before writing `len` bytes.
    ///
    /// The write is recorded as happening after that sleep, so the caller
    /// sleeps once and writes.
    pub fn wait_for(&mut self, len: usize) -> Duration {
        self.wait_for_at(len, Instant::now())
    }

    /// [`BytePacer::wait_for`] with the clock injected, so the rule is testable
    /// without sleeping.
    ///
    /// `now` going backwards — which [`Instant`] does not do in the lane, but
    /// a caller may inject — only makes the pacer slower: the write is still
    /// recorded after every write already held, so the window never loses one.
    pub fn wait_for_at(&mut self, len: usize, now: Instant) -> Duration {
        self.expire(now);
        let rate = self.rate as usize;

        let wait = if self.in_window + len <= rate {
            // It fits in the window as it stands.
            Duration::ZERO
        } else {
            // Wait for the oldest writes to age out, until what is left makes
            // room for `len`. A write at `t` leaves the window at `t` + one
            // second. A `len` over the whole rate frees nothing it needs, so
            // the loop runs to the end and it waits for the window to drain
            // entirely: alone in an empty window it is allowed, since no
            // sleep could ever make it fit.
            let needed = (self.in_window + len).saturating_sub(rate);
            let mut freed = 0usize;
            let mut until = None;
            for (at, bytes) in &self.window {
                freed += bytes;
                until = Some(*at + PACER_WINDOW);
                if freed >= needed && len <= rate {
                    break;
                }
            }
            until.map_or(Duration::ZERO, |t| t.saturating_duration_since(now))
        };

        self.record(now + wait, len);
        wait
    }

    /// Drop the writes that are no longer inside the window ending at `now`.
    ///
    /// The window is half-open — a write at `t` counts until `t` + one second
    /// exactly — which is what makes the per-write check imply the bound over
    /// every window: the last write of any window sees every other write in
    /// it.
    fn expire(&mut self, now: Instant) {
        while let Some(&(at, bytes)) = self.window.front() {
            if now.saturating_duration_since(at) < PACER_WINDOW {
                break;
            }
            self.window.pop_front();
            self.in_window -= bytes;
        }
    }

    /// Remember a write of `len` bytes going out at `at`.
    fn record(&mut self, at: Instant, len: usize) {
        // Never before the write already held, so the window stays ordered.
        let at = match self.window.back() {
            Some(&(last, _)) if last > at => last,
            _ => at,
        };
        self.window.push_back((at, len));
        self.in_window += len;
        while self.window.len() > MAX_PACER_WRITES {
            let (_, older) = self.window.pop_front().unwrap_or((at, 0));
            if let Some(front) = self.window.front_mut() {
                front.1 += older;
            } else {
                self.in_window -= older;
            }
        }
    }
}

impl fmt::Debug for BytePacer {
    /// Sizes and counts only, like every other `Debug` in the lane (S9, C11).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BytePacer")
            .field("rate", &self.rate)
            .field("writes", &self.window.len())
            .field("in_window", &self.in_window)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// What discovery found
// ---------------------------------------------------------------------------

/// Where an endpoint is and what it speaks.
///
/// A small address of our own rather than a borrowed profile type: discovery
/// resolves and validates the profile's `ip` string once, and everything
/// downstream works from the parsed address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointAddr {
    /// The destination address.
    pub ip: IpAddr,
    /// The destination port.
    pub port: u16,
    /// The transport the endpoint speaks.
    pub proto: L4Transport,
}

/// One insertion point with everything `probe_host_for` needs to send it
/// (spec S5.1, the discovery cache).
///
/// `Debug` prints `seed_bytes` as a length, never its contents (S9, C11).
#[derive(Clone)]
pub struct DiscoveredPoint {
    /// The point as the engine sees it.
    pub point: InsertionPoint,
    /// The site node (endpoint) the point belongs to.
    pub node_id: String,
    /// The endpoint the case is sent to.
    pub endpoint: EndpointAddr,
    /// The grammar selected for the endpoint.
    pub grammar: GrammarKind,
    /// Where the seed came from: `flow:<id>#<n>`, `hex:<i>`, `gen:<i>`.
    pub seed_id: String,
    /// The seed the case is mutated from.
    pub seed_bytes: Vec<u8>,
    /// The scope entry that authorises the endpoint, for the evidence.
    pub scope_entry: String,
    /// Why this grammar was selected, rendered for the evidence and the
    /// discovery log line.
    pub selection: String,
}

impl fmt::Debug for DiscoveredPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveredPoint")
            .field("point", &self.point.id)
            .field("node_id", &self.node_id)
            .field("endpoint", &self.endpoint)
            .field("grammar", &self.grammar)
            .field("seed_id", &self.seed_id)
            .field(
                "seed_bytes",
                &format_args!("<{} bytes>", self.seed_bytes.len()),
            )
            .field("scope_entry", &self.scope_entry)
            .field("selection", &self.selection)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-job state
// ---------------------------------------------------------------------------

/// Everything one scan job's L4 work remembers (spec S5.1).
///
/// Shared as an `Arc` between the job's `StreamHost`s and the three checks,
/// which reach it through [`LaneState::job_by_marker`]. `Debug` prints sizes
/// and counters only (S9, C11).
pub struct JobState {
    /// The job's identifier, the key of [`LaneState`]'s first map.
    pub job_id: String,
    /// The first marker seen for this job: what `JobCtx::marker()` returned
    /// when this state was created (A2).
    ///
    /// Informational only — it is one of possibly several keys in
    /// [`LaneState`]'s marker map, because a `JobCtx` may mint a fresh marker
    /// on every call (F7). A check reaches a job through the marker its host
    /// carries, never through this field.
    pub marker: String,
    /// Every message written that is a case (not a prelude, not a liveness
    /// probe).
    pub cases_sent: AtomicU32,
    /// Cases the denylist refused before anything was sent.
    pub cases_skipped_denylisted: AtomicU32,
    /// Cases over [`MAX_MESSAGE`], skipped before the guard saw them.
    pub cases_skipped_too_large: AtomicU32,
    /// Liveness probes attempted.
    pub liveness_probes: AtomicU32,
    /// Liveness probes that failed.
    pub liveness_failures: AtomicU32,
    /// Confirmed crashes.
    pub crashes: AtomicU32,
    /// Confirmed parser faults.
    pub parser_faults: AtomicU32,
    /// Point ids retired after a crash; a probe on one of these is refused.
    pub retired: Mutex<HashSet<String>>,
    /// Silent cases in a row, against the profile's `consecutive_timeouts`.
    pub consecutive_timeouts: AtomicU32,
    /// How often the guard's injection-rate cap made an exchange wait and
    /// retry (spec S5.4); reported in the S6.5 detail line.
    pub rate_waits: AtomicU32,
    /// The job's [`MAX_CONNECTIONS`] connection permits.
    pub connections: Arc<Semaphore>,
    /// The byte pacer every write passes through.
    pub pacer: Mutex<BytePacer>,
    /// The last [`LATENCY_WINDOW`] reply times, in milliseconds.
    pub latency: Mutex<VecDeque<u32>>,
    /// One campaign slot per point id; the first check to reach a point runs
    /// the campaign, the other two read it (spec S6.2).
    pub campaigns: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<Campaign>>>>>,
    /// Points discovered across every endpoint: the divisor of each point's
    /// share of the case budget.
    pub points_total: AtomicU32,
    /// Why each node's grammar was selected, keyed by node id.
    pub selection: Mutex<HashMap<String, String>>,
    /// Why a profile seed yielded nothing, keyed by node id: one note per
    /// seed `corpus::seeds_from_profile` skipped. The profile's seeds are the
    /// same for every endpoint, so the note list is decoded once and shared
    /// behind an [`Arc`] rather than held per node. Counts and reasons only —
    /// a note never carries a seed byte (spec S9, C11).
    pub seed_notes: Mutex<HashMap<String, Arc<Vec<String>>>>,
    /// The discovery cache `probe_host_for` reads, keyed by point id.
    pub points: Mutex<HashMap<String, DiscoveredPoint>>,
    /// The grammar each node speaks, keyed by node id. Only the per-endpoint
    /// grammars need an entry — TLV, whose spec is inferred from that
    /// endpoint's seeds, and `raw` — because every other kind is the
    /// registry's (`grammar::by_kind`).
    pub grammars: Mutex<HashMap<String, Arc<dyn Grammar>>>,
    /// Insertion order, for eviction ("oldest" is the smallest).
    pub created_seq: u64,
    /// The job's deadline, refreshed by [`LaneState::job_for`]; a state whose
    /// deadline has passed is evicted before any live one.
    pub deadline: Mutex<Instant>,
    /// Whether the job was cancelled, refreshed by [`LaneState::job_for`]; a
    /// cancelled state is evicted before any live one.
    pub cancelled: AtomicBool,
}

impl JobState {
    /// A fresh state for `job_id`, paced at `max_bytes_per_s` (clamped by
    /// [`BytePacer::new`]).
    ///
    /// `created_seq` is zero and `deadline` is now; [`LaneState::job_for`],
    /// which owns the insertion counter and holds the `JobCtx`, sets both
    /// before the state is reachable by anyone else.
    #[must_use]
    pub fn new(job_id: &str, marker: &str, max_bytes_per_s: u32) -> Arc<Self> {
        Self::new_at(job_id, marker, max_bytes_per_s, 0)
    }

    /// [`JobState::new`] with the insertion counter supplied.
    pub(crate) fn new_at(
        job_id: &str,
        marker: &str,
        max_bytes_per_s: u32,
        created_seq: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            job_id: job_id.to_string(),
            marker: marker.to_string(),
            cases_sent: AtomicU32::new(0),
            cases_skipped_denylisted: AtomicU32::new(0),
            cases_skipped_too_large: AtomicU32::new(0),
            liveness_probes: AtomicU32::new(0),
            liveness_failures: AtomicU32::new(0),
            crashes: AtomicU32::new(0),
            parser_faults: AtomicU32::new(0),
            retired: Mutex::new(HashSet::new()),
            consecutive_timeouts: AtomicU32::new(0),
            rate_waits: AtomicU32::new(0),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            pacer: Mutex::new(BytePacer::new(max_bytes_per_s)),
            latency: Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW)),
            campaigns: Mutex::new(HashMap::new()),
            points_total: AtomicU32::new(0),
            selection: Mutex::new(HashMap::new()),
            seed_notes: Mutex::new(HashMap::new()),
            points: Mutex::new(HashMap::new()),
            grammars: Mutex::new(HashMap::new()),
            created_seq,
            deadline: Mutex::new(Instant::now()),
            cancelled: AtomicBool::new(false),
        })
    }

    /// The counters the engine reports (spec S6.2, A5).
    #[must_use]
    pub fn counters(&self) -> L4Counters {
        L4Counters {
            cases: u64::from(self.cases_sent.load(Ordering::Relaxed)),
            crashes: u64::from(self.crashes.load(Ordering::Relaxed)),
            liveness_failures: u64::from(self.liveness_failures.load(Ordering::Relaxed)),
            retired_elements: lock(&self.retired).len() as u64,
        }
    }

    /// Record one sent case: its reply time and the case itself.
    ///
    /// The two steps `StreamHost::send_case` takes after an exchange, in one
    /// place so a test double can take them too and read back the medians a
    /// live run would.
    pub fn record_case(&self, elapsed_ms: u32) {
        self.push_latency(elapsed_ms);
        self.cases_sent.fetch_add(1, Ordering::SeqCst);
    }

    /// Record one reply time, keeping the last [`LATENCY_WINDOW`].
    pub fn push_latency(&self, ms: u32) {
        let mut window = lock(&self.latency);
        window.push_back(ms);
        while window.len() > LATENCY_WINDOW {
            window.pop_front();
        }
    }

    /// The median reply time of the window, or `None` under
    /// [`MIN_LATENCY_SAMPLES`] samples.
    ///
    /// With an even number of samples this is the upper of the two middle
    /// values; the rule it feeds is a 5x multiple, which one sample either way
    /// does not turn.
    #[must_use]
    pub fn latency_median(&self) -> Option<u32> {
        let window = lock(&self.latency);
        if window.len() < MIN_LATENCY_SAMPLES {
            return None;
        }
        let mut sorted: Vec<u32> = window.iter().copied().collect();
        sorted.sort_unstable();
        sorted.get(sorted.len() / 2).copied()
    }

    /// Retire a point. `true` the first time, `false` afterwards.
    pub fn retire(&self, point_id: &str) -> bool {
        lock(&self.retired).insert(point_id.to_string())
    }

    /// Whether the point was retired.
    #[must_use]
    pub fn is_retired(&self, point_id: &str) -> bool {
        lock(&self.retired).contains(point_id)
    }

    /// Take the job's current deadline and cancellation, for eviction.
    fn refresh_from(&self, job: &dyn JobCtx) {
        *lock(&self.deadline) = job.deadline();
        self.cancelled.store(job.cancelled(), Ordering::Relaxed);
    }

    /// Whether this state may be dropped before any live one.
    fn is_spent(&self, now: Instant) -> bool {
        self.cancelled.load(Ordering::Relaxed) || *lock(&self.deadline) <= now
    }
}

impl fmt::Debug for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobState")
            .field("job_id", &self.job_id)
            .field("marker", &self.marker)
            .field("created_seq", &self.created_seq)
            .field("cases_sent", &self.cases_sent.load(Ordering::Relaxed))
            .field(
                "cases_skipped_denylisted",
                &self.cases_skipped_denylisted.load(Ordering::Relaxed),
            )
            .field(
                "cases_skipped_too_large",
                &self.cases_skipped_too_large.load(Ordering::Relaxed),
            )
            .field(
                "liveness_probes",
                &self.liveness_probes.load(Ordering::Relaxed),
            )
            .field(
                "liveness_failures",
                &self.liveness_failures.load(Ordering::Relaxed),
            )
            .field("crashes", &self.crashes.load(Ordering::Relaxed))
            .field("parser_faults", &self.parser_faults.load(Ordering::Relaxed))
            .field("retired", &lock(&self.retired).len())
            .field(
                "consecutive_timeouts",
                &self.consecutive_timeouts.load(Ordering::Relaxed),
            )
            .field("rate_waits", &self.rate_waits.load(Ordering::Relaxed))
            .field("permits", &self.connections.available_permits())
            .field("pacer", &*lock(&self.pacer))
            .field("latency", &lock(&self.latency).len())
            .field("campaigns", &lock(&self.campaigns).len())
            .field("points_total", &self.points_total.load(Ordering::Relaxed))
            .field("seed_notes", &lock(&self.seed_notes).len())
            .field("points", &lock(&self.points).len())
            .field("grammars", &lock(&self.grammars).len())
            .field("cancelled", &self.cancelled.load(Ordering::Relaxed))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-process state
// ---------------------------------------------------------------------------

/// The lane's per-process state: a bounded map of job states, reachable by job
/// id and by marker (spec S5.1, amendment A2).
///
/// One `Arc<dyn Lane>` serves every job in the process, so this map is the only
/// thing that grows with jobs, and it is bounded at [`MAX_JOBS`]. Both maps are
/// updated under one lock order — `jobs`, then `by_marker` — so they never
/// disagree about which jobs are held.
///
/// `by_marker` is many-to-one: a `JobCtx` is free to mint a fresh marker on
/// every `marker()` call, so one job holds one marker per host built for it
/// (F7). Every one of them resolves to the same `Arc<JobState>`, and
/// [`LaneState::drop_job`] removes all of a job's markers together, so an
/// evicted job leaves nothing behind in either map.
#[derive(Debug)]
pub struct LaneState {
    jobs: Mutex<HashMap<String, Arc<JobState>>>,
    by_marker: Mutex<HashMap<String, String>>,
    seq: AtomicU64,
}

impl Default for LaneState {
    fn default() -> Self {
        Self::new()
    }
}

impl LaneState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            by_marker: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
        }
    }

    /// The state for `job`, creating it on first use.
    ///
    /// Evicts to stay within [`MAX_JOBS`]: states whose job is cancelled or
    /// past its deadline go first, then the oldest by insertion. The job's
    /// deadline and cancellation are refreshed on every call, so a job
    /// cancelled mid-run is the next one evicted.
    pub fn job_for(&self, job: &dyn JobCtx) -> Arc<JobState> {
        let marker = job.marker();
        let job_id = job.job_id().to_string();
        let mut jobs = lock(&self.jobs);
        let mut markers = lock(&self.by_marker);

        if let Some(held) = jobs.get(&job_id) {
            held.refresh_from(job);
            markers.insert(marker, job_id);
            return Arc::clone(held);
        }

        if jobs.len() >= MAX_JOBS {
            let now = Instant::now();
            let spent: Vec<String> = jobs
                .values()
                .filter(|state| state.is_spent(now))
                .map(|state| state.job_id.clone())
                .collect();
            for id in spent {
                Self::drop_job(&mut jobs, &mut markers, &id);
            }
        }
        while jobs.len() >= MAX_JOBS {
            let oldest = jobs
                .values()
                .min_by_key(|state| state.created_seq)
                .map(|state| state.job_id.clone());
            match oldest {
                Some(id) => Self::drop_job(&mut jobs, &mut markers, &id),
                None => break,
            }
        }

        let state = JobState::new_at(
            &job_id,
            &marker,
            job.profile().l4.max_bytes_per_s,
            self.seq.fetch_add(1, Ordering::Relaxed),
        );
        state.refresh_from(job);
        jobs.insert(job_id.clone(), Arc::clone(&state));
        markers.insert(marker, job_id);
        state
    }

    /// Record one more marker for a job already held, so a check reaching
    /// this state from a host's marker finds it (A2, F7).
    ///
    /// `JobCtx::marker()` is a generator in the engine — each call mints a
    /// token a check can recognise again — so the marker a host carries is
    /// not the one [`LaneState::job_for`] happened to capture. Every host
    /// registers the marker it was built with here. A marker for a job this
    /// state does not hold is dropped rather than recorded, so the map never
    /// grows an entry no job will ever evict.
    pub fn register_marker(&self, marker: &str, job_id: &str) {
        let jobs = lock(&self.jobs);
        if !jobs.contains_key(job_id) {
            return;
        }
        let mut markers = lock(&self.by_marker);
        markers.insert(marker.to_string(), job_id.to_string());
    }

    /// The state a check reaches from its `ProbeHost`'s marker (A2).
    #[must_use]
    pub fn job_by_marker(&self, marker: &str) -> Option<Arc<JobState>> {
        let jobs = lock(&self.jobs);
        let markers = lock(&self.by_marker);
        let job_id = markers.get(marker)?;
        jobs.get(job_id).map(Arc::clone)
    }

    /// The state for a job id, if it is still held.
    #[must_use]
    pub fn get(&self, job_id: &str) -> Option<Arc<JobState>> {
        lock(&self.jobs).get(job_id).map(Arc::clone)
    }

    /// How many job states are held.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.jobs).len()
    }

    /// Whether no job state is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.jobs).is_empty()
    }

    /// Drop a job from both maps, including every marker pointing at it.
    fn drop_job(
        jobs: &mut HashMap<String, Arc<JobState>>,
        markers: &mut HashMap<String, String>,
        job_id: &str,
    ) {
        jobs.remove(job_id);
        markers.retain(|_, held| held != job_id);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use aitm_core::{
        BrowserDriver, FlowStore, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, ScopeRateGuard,
        StdGuard,
    };
    use aitm_scan_model::{
        InsertionKind, InsertionPoint, JobCtx, L4Counters, L4Transport, LaneKind, ScanProfile,
        SessionMaterial,
    };
    use futures::future::BoxFuture;

    use super::{lock, BytePacer, DiscoveredPoint, EndpointAddr, JobState, LaneState};
    use crate::spec::GrammarKind;

    /// A `ProxyClient` that performs no I/O; a job context needs one to exist.
    struct NullClient;

    impl ProxyClient for NullClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { Err(anyhow::anyhow!("no client in the test context")) })
        }
    }

    /// A `JobCtx` with a distinct id and marker, and a settable `cancelled`.
    struct TestJob {
        job_id: String,
        marker: String,
        cancelled: bool,
        profile: ScanProfile,
        client: Arc<dyn ProxyClient>,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
    }

    impl TestJob {
        fn new(n: u32) -> Self {
            Self {
                job_id: format!("scan-{n:02}"),
                marker: format!("aitm{n:02}"),
                cancelled: false,
                profile: ScanProfile::default(),
                client: Arc::new(NullClient),
                store: Arc::new(MemFlowStore::new()),
                guard: Arc::new(StdGuard::default()),
            }
        }

        fn cancelled(mut self) -> Self {
            self.cancelled = true;
            self
        }
    }

    impl JobCtx for TestJob {
        fn job_id(&self) -> &str {
            &self.job_id
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
            self.cancelled
        }
        fn marker(&self) -> String {
            self.marker.clone()
        }
    }

    #[test]
    fn pacer_rate_is_capped() {
        assert_eq!(BytePacer::new(1_000_000_000).rate(), 1_048_576);
        assert_eq!(BytePacer::new(65_536).rate(), 65_536);
    }

    #[test]
    fn pacer_bounds_every_one_second_window() {
        let mut pacer = BytePacer::new(1000);
        let t0 = Instant::now();
        // An empty window takes a whole second's worth at once.
        assert_eq!(pacer.wait_for_at(1000, t0), Duration::ZERO);
        // The window is full until those 1000 bytes age out of it, so the next
        // 500 bytes wait the whole second — not the half second a bucket that
        // starts full allowed, which let a wall-clock second carry 1500.
        assert_eq!(pacer.wait_for_at(500, t0), Duration::from_secs(1));
        // Two seconds on, both recorded sends have left the window.
        assert_eq!(
            pacer.wait_for_at(1, t0 + Duration::from_secs(2)),
            Duration::ZERO
        );
    }

    /// T6-4, the umbrella's bound, as the independent observer measures it:
    /// over a long paced run, no one-second window of the write log may carry
    /// more than the rate (spec S5.7).
    #[test]
    fn pacer_sliding_window_property() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0xB17E_9ACE);
        let mut pacer = BytePacer::new(1000);
        let t0 = Instant::now();
        let mut now = t0;
        // Every write the caller actually makes: the instant it goes out and
        // how many bytes it is. Ascending in time, because the next call is
        // never earlier than the write before it.
        let mut written: Vec<(Instant, usize)> = Vec::with_capacity(10_000);
        let mut paced = 0u32;

        for _ in 0..10_000 {
            let len = rng.random_range(1..=200usize);
            let wait = pacer.wait_for_at(len, now);
            if !wait.is_zero() {
                paced += 1;
            }
            // The caller sleeps the wait the pacer returned, then writes.
            let at = now + wait;
            written.push((at, len));

            // The window that closes on this write holds at most the rate.
            let opened = at - Duration::from_secs(1);
            let in_window: usize = written
                .iter()
                .rev()
                .take_while(|(t, _)| *t > opened)
                .map(|(_, n)| *n)
                .sum();
            assert!(
                in_window <= 1000,
                "the second ending {:?} after the start carried {in_window} bytes, over 1000",
                at.duration_since(t0)
            );

            now = at + Duration::from_millis(rng.random_range(0..=50));
        }

        // The run was paced, not merely spread thin: the writes wanted about
        // 4000 bytes/s and the pacer held them near 1000 without starving them.
        assert!(paced > 4_000, "only {paced} of 10000 writes were paced");
        let total: usize = written.iter().map(|(_, n)| *n).sum();
        let elapsed = written
            .last()
            .map(|(t, _)| t.duration_since(t0))
            .unwrap_or_default();
        let achieved = (total as f64 / elapsed.as_secs_f64()) as u64;
        assert!(
            (800..=1000).contains(&achieved),
            "{total} bytes over {elapsed:?} is {achieved} bytes/s, not a rate of 1000"
        );
    }

    #[test]
    fn counters_shape() {
        let state = JobState::new("scan-01", "aitm01", 65_536);
        state.cases_sent.fetch_add(3, Ordering::Relaxed);
        state.crashes.fetch_add(1, Ordering::Relaxed);
        assert!(state.retire("p"));
        assert_eq!(
            state.counters(),
            L4Counters {
                cases: 3,
                crashes: 1,
                liveness_failures: 0,
                retired_elements: 1,
            }
        );
    }

    #[test]
    fn latency_median() {
        let state = JobState::new("scan-01", "aitm01", 65_536);
        for _ in 0..9 {
            state.push_latency(10);
        }
        assert_eq!(state.latency_median(), None);
        state.push_latency(10);
        assert_eq!(state.latency_median(), Some(10));

        let state = JobState::new("scan-02", "aitm02", 65_536);
        for ms in 1..=25 {
            state.push_latency(ms);
        }
        {
            let window = lock(&state.latency);
            assert_eq!(window.len(), 20);
            assert_eq!(window.front().copied(), Some(6));
            assert_eq!(window.back().copied(), Some(25));
        }
        // The kept window is 6..=25; its median is 16, not the 13 of 1..=25.
        assert_eq!(state.latency_median(), Some(16));
    }

    #[test]
    fn retire_is_idempotent() {
        let state = JobState::new("scan-01", "aitm01", 65_536);
        assert!(!state.is_retired("p"));
        assert!(state.retire("p"));
        assert!(!state.retire("p"));
        assert!(state.is_retired("p"));
        assert_eq!(state.counters().retired_elements, 1);
    }

    #[test]
    fn lane_state_bounded_and_consistent() {
        let state = LaneState::new();
        let jobs: Vec<TestJob> = (0..17).map(TestJob::new).collect();
        for job in &jobs {
            state.job_for(job);
        }
        assert_eq!(state.len(), 16);

        // The oldest by insertion is gone from both maps.
        assert!(state.get("scan-00").is_none());
        assert!(state.job_by_marker("aitm00").is_none());

        // Every other job resolves by id and by marker, to the same state.
        for job in &jobs[1..] {
            let by_id = state
                .get(job.job_id())
                .expect("a job inserted after the evicted one is still held");
            assert_eq!(by_id.marker, job.marker());
            let by_marker = state
                .job_by_marker(&job.marker())
                .expect("the marker map agrees with the id map");
            assert!(Arc::ptr_eq(&by_id, &by_marker));
        }

        // Asking again for a held job returns the same state, not a new one.
        let again = state.job_for(&jobs[1]);
        assert!(Arc::ptr_eq(
            &again,
            &state.get("scan-01").expect("still held")
        ));
        assert_eq!(state.len(), 16);

        // A cancelled job is inserted (evicting the oldest, scan-01) ...
        let cancelled = TestJob::new(17).cancelled();
        state.job_for(&cancelled);
        assert_eq!(state.len(), 16);
        assert!(state.get("scan-01").is_none());

        // ... and is itself evicted first on the next insert, before the oldest.
        state.job_for(&TestJob::new(18));
        assert_eq!(state.len(), 16);
        assert!(state.get("scan-17").is_none());
        assert!(state.job_by_marker("aitm17").is_none());
        assert!(state.get("scan-02").is_some());
        assert!(state.get("scan-18").is_some());
    }

    #[test]
    fn many_markers_resolve_to_one_job_and_die_with_it() {
        // A `JobCtx` may mint a fresh marker on every call (F7), so one job
        // can have one marker per host it built. All of them resolve, and
        // eviction takes every one of them.
        let state = LaneState::new();
        let job = TestJob::new(1);
        let held = state.job_for(&job);

        state.register_marker("mint-a", job.job_id());
        state.register_marker("mint-b", job.job_id());

        for marker in ["aitm01", "mint-a", "mint-b"] {
            let found = state
                .job_by_marker(marker)
                .unwrap_or_else(|| panic!("`{marker}` resolves to the job"));
            assert!(Arc::ptr_eq(&found, &held), "`{marker}` is the same state");
        }

        // A marker for a job this state never held is not recorded.
        state.register_marker("mint-c", "scan-99");
        assert!(state.job_by_marker("mint-c").is_none());

        // Evicting the job takes every marker pointing at it.
        for n in 2..18 {
            state.job_for(&TestJob::new(n));
        }
        assert!(state.get("scan-01").is_none(), "the oldest job was evicted");
        for marker in ["aitm01", "mint-a", "mint-b"] {
            assert!(
                state.job_by_marker(marker).is_none(),
                "`{marker}` outlived its job"
            );
        }
    }

    #[test]
    fn debug_hides_message_bytes() {
        let point = DiscoveredPoint {
            point: InsertionPoint {
                id: "l4s-0123456789abcdef".into(),
                lane: LaneKind::L4Stream,
                kind: InsertionKind::L4Field,
                name: "body".into(),
                path: Some("body".into()),
                example: None,
                flow: None,
                site_node: Some("l4s-tcp-127.0.0.1-9000".into()),
                traits: Vec::new(),
                frequency: 1,
                method: Some("L4".into()),
                url: Some("tcp://127.0.0.1:9000/tlv".into()),
            },
            node_id: "l4s-tcp-127.0.0.1-9000".into(),
            endpoint: EndpointAddr {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 9000,
                proto: L4Transport::Tcp,
            },
            grammar: GrammarKind::Tlv,
            seed_id: "hex:0".into(),
            seed_bytes: b"S3CR3TBYTES".to_vec(),
            scope_entry: "127.0.0.0/8:0-65535".into(),
            selection: "named in the profile".into(),
        };
        let rendered = format!("{point:?}");
        assert!(rendered.contains("<11 bytes>"), "{rendered}");
        assert!(!rendered.contains("S3CR3TBYTES"), "{rendered}");
        assert!(!rendered.contains("5333435233544259544553"), "{rendered}");

        let state = JobState::new("scan-01", "aitm01", 65_536);
        lock(&state.points).insert(point.point.id.clone(), point);
        let rendered = format!("{state:?}");
        assert!(rendered.contains("points: 1"), "{rendered}");
        assert!(!rendered.contains("S3CR3TBYTES"), "{rendered}");
        assert!(!rendered.contains("5333435233544259544553"), "{rendered}");
    }
}
