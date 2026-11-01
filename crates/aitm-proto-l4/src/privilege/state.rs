//! `PrivilegeState`: the one shared source of truth for packet-capture
//! privilege (spec §2.1). It owns the platform prober, the clock, the cached
//! [`PrivilegeReport`], the progress of the last `l4.privilege.request` and the
//! platform [`Requester`] that `request()` dispatches to (spec §2.3).
//!
//! `report()` re-probes when the cached capture is not `Available` and is at
//! least [`REPROBE_MS`] old (**Architect's call** for the TTL), so a core
//! started before approval sees the flip without a restart (AC7). An
//! `Available` result is held for the process lifetime: nothing here takes a
//! privilege away once granted (a backend failure reporting one is P1b.8's
//! job). Each capture-state change logs exactly one `tracing::info!` line
//! (AC24) naming the two states; never a token, never a payload.
//!
//! The Linux request (plan P1b.14) lives half here: the pure decisions are in
//! [`crate::privilege::linux`]; this file owns the [`Shared`] half a watcher
//! thread writes to (progress, the helper backend slot, the live session, the
//! guard), the thread itself ([`run_watcher`]), and the lazy direct start of a
//! file-capability helper on first use.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::backend::helper::HelperBackend;
use crate::backend::routed::RoutedBackend;
use crate::backend::CaptureInjectBackend;
pub use crate::config::{L4PrivilegeConfig, RequestMode};
use crate::guard::L4Guard;
use crate::helper::client::{
    ensure_socket_dir, socket_path, HelperListener, HelperSession, SessionError,
};
use crate::privilege::derive::{derive, text, LinuxInputs, ProbeInputs, SessionFailure};
use crate::privilege::linux::{
    direct_helper_argv, gather_linux, msg, request_linux, watch_step, Child, ExitClass, HoldCount,
    HoldToken, Spawned, Spawner, StdSpawner, WatchOutcome,
};
use crate::privilege::macos::gather_mac;
use crate::privilege::report::{
    bounded_text, Capability, Platform, PrivilegeReport, RequestProgress, RequestState, TEXT_BOUND,
};

/// How old a not-available cached report may be before `report()` re-probes.
pub const REPROBE_MS: u64 = 1000;

/// The message a request carries once capture became available under it.
pub const APPROVED_MESSAGE: &str = "packet capture approved";

/// The message of an `already_available` outcome.
pub const ALREADY_AVAILABLE_MESSAGE: &str = "packet capture is already available on this core";

/// The message the default requester answers on a platform with no handoff.
pub const NO_HANDOFF_MESSAGE: &str = "no platform handoff is wired on this build yet";

/// The core version the handshake announces to the helper.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One `accept` slice of the watcher loop; also its pacing.
const ACCEPT_SLICE: Duration = Duration::from_millis(100);
/// How long the helper has to answer `Hello` once connected.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a live session is checked for its end.
const LIVE_POLL: Duration = Duration::from_millis(250);
/// How long the watcher waits for a killed or ended child to be reaped.
const REAP_WAIT: Duration = Duration::from_secs(10);
/// How long a first use waits for a directly started helper to attach.
const LAZY_START_WAIT: Duration = Duration::from_secs(5);
/// How long `request()` waits for another caller's first probe to land.
const SETTLE_WAIT: Duration = Duration::from_secs(10);
/// Consecutive `accept` errors (not timeouts, not foreign peers) after which
/// the watch ends `failed`: the listener is broken, waiting is pointless.
pub(crate) const ACCEPT_ERRORS_MAX: usize = 10;

/// What `l4.privilege.request` answers (spec §2.3): the outcome, a message for
/// the operator, and the report as it stands right after the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOutcome {
    pub outcome: Outcome,
    pub message: String,
    pub privilege: PrivilegeReport,
}

/// The wire `outcome` of `l4.privilege.request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Capture already works; nothing was asked.
    AlreadyAvailable,
    /// A prompt is up (or a request was already in flight); poll `l4.privilege`.
    Pending,
    /// The request went to the Aitmproxy app (macOS); macOS asks the operator.
    HandedToApp,
    /// Nothing could be shown; `message` says why.
    CannotPrompt,
}

impl Outcome {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::AlreadyAvailable => "already_available",
            Outcome::Pending => "pending",
            Outcome::HandedToApp => "handed_to_app",
            Outcome::CannotPrompt => "cannot_prompt",
        }
    }
}

/// The platform half of `l4.privilege.request` (spec §2.3): start the OS
/// permission flow for the report's `needs_approval` capture and say what
/// happened. It must return at once (never block on the OS); the state turns
/// its answer into [`RequestProgress`]. `report` is the current report, with
/// capture not `Available` and no request in flight; `cfg` carries
/// `l4.privilege.*` and the process lifetime. The macOS handoff (plan P1b.11)
/// and the Linux `pkexec` spawn (plan P1b.14) implement it behind
/// [`PlatformRequester`]; a fixed-input module or a test installs its own
/// through [`PrivilegeState::with_requester`] (a seam, like `with_prober`).
pub(crate) trait Requester: Send + Sync {
    fn request(&self, cfg: &PrivilegeConfig, report: &PrivilegeReport) -> (Outcome, String);

    /// Called by the state right after the answer of `request` was recorded
    /// as this core's progress (same `request()` call, same lock). A
    /// requester that spawned something starts watching it here, so the
    /// watcher's first progress write can never be overwritten by the
    /// `pending` row. The default does nothing.
    fn after_recorded(&self) {}

    /// The spawner the direct (launcher-less) start of a file-capability
    /// helper goes through, so a scripted requester's spawner sees that
    /// spawn too. The default is the real one.
    fn spawner(&self) -> Arc<dyn Spawner> {
        Arc::new(StdSpawner)
    }
}

/// What the helper slot holds: a capture/inject backend that also knows
/// whether its session is still open. One slot serves both readers: the
/// routed backend (as a [`CaptureInjectBackend`]) and the prober's
/// `session_connected` (through `is_live`).
pub(crate) trait LiveBackend: CaptureInjectBackend {
    /// The helper session behind this backend is open right now.
    fn is_live(&self) -> bool;
}

/// What the state needs from the core's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeConfig {
    /// `l4.enabled`.
    pub enabled: bool,
    /// The `l4.privilege` block.
    pub l4: L4PrivilegeConfig,
    /// Whether this process serves (TUI, web, bus) or exits after one verb.
    pub lifetime: ProcessLifetime,
}

/// How long this process lives; a one-shot CLI verb cannot host a helper
/// session (spec §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLifetime {
    /// A long-lived core: `aitm`, `aitm web`, `aitm tui`.
    Serving,
    /// `aitm <verb>` as a one-shot command.
    OneShot,
}

/// Gathers the inputs `derive` decides from. The platform prober does the
/// read-only I/O; tests script one.
pub trait Prober: Send + Sync {
    /// Gather the current inputs. `request` is this core's last request, for
    /// the rows that depend on it; the state stamps `now_ms` and `request` on
    /// the result itself, so a prober may leave them as it likes.
    fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs;
}

/// A monotonic-enough clock in epoch milliseconds; injected so tests drive the TTL.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The shared privilege state. Callers wrap it in an `Arc`.
pub struct PrivilegeState {
    cfg: PrivilegeConfig,
    prober: Box<dyn Prober>,
    /// The platform half of `request()`.
    requester: Box<dyn Requester>,
    /// Serialises `request()`: one request at a time (spec §2.3), so two
    /// operators asking together cannot both reach the platform.
    requesting: Mutex<()>,
    /// Serialises the lazy direct start of a file-capability helper.
    lazy_start: Mutex<()>,
    /// The half a watcher thread, the prober and the requester share.
    shared: Arc<Shared>,
}

/// What the state shares with its watcher threads, its platform prober and
/// its platform requester: the clock, the cache, the helper backend slot the
/// routed backend reads, the live helper session, the guard a helper backend
/// is built over, and the last Linux inputs.
pub(crate) struct Shared {
    clock: Clock,
    cache: Mutex<Cache>,
    /// The one helper slot: the connected session's backend (plan P1b.8
    /// seam). [`RoutedBackend`] takes it for `Available { via: Helper }`; the
    /// prober reads its `is_live()` as `session_connected` (plan P1b.13).
    live: Mutex<Option<Arc<dyn LiveBackend>>>,
    /// The guard a [`HelperBackend`] is built over; set by the wiring through
    /// [`PrivilegeState::set_guard`]. Without it a connecting helper cannot be
    /// attached.
    guard: Mutex<Option<Arc<L4Guard>>>,
    /// The Linux inputs of the last platform probe, for the requester and the
    /// lazy direct start.
    last_linux: Mutex<Option<LinuxInputs>>,
    /// How the last helper session failed its handshake (spec §5.2), for the
    /// `version_mismatch` row; cleared when a session attaches.
    session_failure: Mutex<Option<SessionFailure>>,
    /// The SIGINT hold (spec §5.5): raised around a launcher child, read by
    /// the binary's shutdown future through a clone.
    hold: Mutex<HoldCount>,
    /// The launcher child while its prompt is up (spec §5.5, panel 2): what
    /// [`PrivilegeState::cancel_prompt`] sends SIGINT to. Set by the watcher
    /// when a request's child is watched, cleared with the hold.
    prompt_child: Mutex<Option<SharedChild>>,
    /// The id of the running watcher thread (a request in flight or a helper
    /// serving), 0 for none. Each watch owns one id (panel 3, D1) and clears
    /// only its own, so a watch that has ended but is still in its bounded
    /// reap cannot clear the flag of the watch that followed it.
    watching: AtomicU64,
    /// Watch ids handed out so far; the next is one more, never 0.
    watch_ids: AtomicU64,
}

/// A watched child, shared between the watcher thread (which steps it) and
/// `cancel_prompt` (which signals it).
type SharedChild = Arc<Mutex<Box<dyn Child>>>;

/// What `report()` keeps between probes.
#[derive(Default)]
pub(crate) struct Cache {
    /// The last derived report, `None` until the first probe.
    report: Option<PrivilegeReport>,
    /// When `report` was derived, on the state's clock.
    probed_at: u64,
    /// The last `l4.privilege.request` on this core.
    request: Option<RequestProgress>,
    /// Set by `set_request`: the next `report()` probes regardless of the TTL.
    dirty: bool,
    /// Capture-state changes seen so far; one `info!` line each.
    changes: u64,
    /// A probe is running outside this lock (single flight): another caller
    /// answers from `report` as it stands instead of waiting.
    probing: bool,
    /// The inputs `report` was derived from, for a re-derive under a new
    /// request without another gather.
    inputs: Option<ProbeInputs>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What `claim_probe` decided for one `report()` caller.
enum Claim {
    /// This caller probes, with the request as it stood at the claim.
    Probe(Option<RequestProgress>),
    /// The cache answers (fresh, or another caller's probe is in flight).
    Fresh,
    /// Another caller's **first** probe is in flight: there is no report yet.
    InFlightNoReport,
}

/// Releases the single-flight claim if the prober unwinds.
struct ProbeClaim<'a> {
    shared: &'a Shared,
    armed: bool,
}

impl Drop for ProbeClaim<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.shared.lock_cache().probing = false;
        }
    }
}

impl Shared {
    fn new(clock: Clock) -> Arc<Self> {
        Arc::new(Shared {
            clock,
            cache: Mutex::new(Cache::default()),
            live: Mutex::new(None),
            guard: Mutex::new(None),
            last_linux: Mutex::new(None),
            session_failure: Mutex::new(None),
            hold: Mutex::new(HoldCount::default()),
            prompt_child: Mutex::new(None),
            watching: AtomicU64::new(0),
            watch_ids: AtomicU64::new(0),
        })
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// A poisoned lock means another `report()` panicked mid-update; the cache
    /// is re-derivable, so take it as it is rather than propagate the panic.
    pub(crate) fn lock_cache(&self) -> MutexGuard<'_, Cache> {
        lock(&self.cache)
    }

    /// Record this core's request progress; the next `report()` probes.
    fn set_progress(&self, state: RequestState, message: &str) {
        let mut cache = self.lock_cache();
        self.write_progress(&mut cache, state, message);
    }

    /// The one writer of a progress row: `state` and `message` at `now`, and
    /// the cache is dirty so the next `report()` probes.
    fn write_progress(&self, cache: &mut Cache, state: RequestState, message: &str) {
        cache.request = Some(RequestProgress {
            state,
            at: self.now(),
            message: message.to_string(),
        });
        cache.dirty = true;
    }

    /// The next `report()` probes regardless of the TTL or an `Available` hold.
    fn mark_dirty(&self) {
        self.lock_cache().dirty = true;
    }

    /// The slot's backend as the router takes it.
    fn helper(&self) -> Option<Arc<dyn CaptureInjectBackend>> {
        lock(&self.live)
            .clone()
            .map(|backend| backend as Arc<dyn CaptureInjectBackend>)
    }

    fn set_live(&self, backend: Option<Arc<dyn LiveBackend>>) {
        *lock(&self.live) = backend;
    }

    /// A helper session is connected and open right now.
    pub(crate) fn live_is_up(&self) -> bool {
        lock(&self.live)
            .as_ref()
            .is_some_and(|backend| backend.is_live())
    }

    fn guard(&self) -> Option<Arc<L4Guard>> {
        lock(&self.guard).clone()
    }

    fn last_linux(&self) -> Option<LinuxInputs> {
        lock(&self.last_linux).clone()
    }

    /// How the last helper session failed its handshake, if it did.
    pub(crate) fn session_failure(&self) -> Option<SessionFailure> {
        lock(&self.session_failure).clone()
    }

    fn set_session_failure(&self, failure: Option<SessionFailure>) {
        *lock(&self.session_failure) = failure;
    }

    /// The SIGINT hold; clones share the count.
    fn sigint_hold(&self) -> HoldCount {
        lock(&self.hold).clone()
    }

    /// The launcher child whose prompt is up, if one is.
    pub(crate) fn prompt_child(&self) -> Option<SharedChild> {
        lock(&self.prompt_child).clone()
    }

    fn register_prompt_child(&self, child: &SharedChild) {
        *lock(&self.prompt_child) = Some(Arc::clone(child));
    }

    /// Clear the prompt slot if `child` is the child in it (panel 3, D1): a
    /// later watch's child, registered while this one reaped, stays.
    fn unregister_prompt_child(&self, child: &SharedChild) {
        let mut slot = lock(&self.prompt_child);
        if slot
            .as_ref()
            .is_some_and(|registered| Arc::ptr_eq(registered, child))
        {
            *slot = None;
        }
    }

    /// Move a still-`pending` request to `failed` with `message`; any other
    /// progress (or none) is left as it is.
    fn fail_if_pending(&self, message: &str) {
        let mut cache = self.lock_cache();
        if cache
            .request
            .as_ref()
            .is_some_and(|req| req.state == RequestState::Pending)
        {
            self.write_progress(&mut cache, RequestState::Failed, message);
        }
    }

    /// Mark a watch as running under a fresh id (never 0) and return the id.
    fn start_watching(&self) -> u64 {
        let id = self.watch_ids.fetch_add(1, Ordering::SeqCst) + 1;
        self.watching.store(id, Ordering::SeqCst);
        id
    }

    /// Clear `watching` only if it still names `id` (panel 3, D1): the id of
    /// a watch that started meanwhile stays.
    fn stop_watching(&self, id: u64) {
        let _ = self
            .watching
            .compare_exchange(id, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn watching(&self) -> bool {
        self.watching.load(Ordering::SeqCst) != 0
    }
}

impl std::fmt::Debug for PrivilegeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegeState")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl PrivilegeState {
    /// The production state: this OS's gatherer, the system clock, and this
    /// OS's requester (the Linux arm spawns through [`StdSpawner`]).
    #[must_use]
    pub fn new(cfg: &PrivilegeConfig) -> Self {
        let shared = Shared::new(Arc::new(epoch_ms_now));
        let prober = PlatformProber {
            enabled: cfg.enabled,
            l4: cfg.l4.clone(),
            shared: Arc::clone(&shared),
        };
        Self::assemble(cfg, Box::new(prober), shared)
    }

    /// A state over any prober and clock; for tests and fixed-input modules.
    #[must_use]
    pub fn with_prober(cfg: &PrivilegeConfig, prober: Box<dyn Prober>, clock: Clock) -> Self {
        let shared = Shared::new(clock);
        Self::assemble(cfg, prober, shared)
    }

    fn assemble(cfg: &PrivilegeConfig, prober: Box<dyn Prober>, shared: Arc<Shared>) -> Self {
        let requester = PlatformRequester::new(Arc::clone(&shared));
        Self {
            cfg: cfg.clone(),
            prober,
            requester: Box::new(requester),
            requesting: Mutex::new(()),
            lazy_start: Mutex::new(()),
            shared,
        }
    }

    /// Replace the platform requester (the spawner and request seams); the
    /// crate's tests script one. A test seam: production always runs the
    /// [`PlatformRequester`] `assemble` installs.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_requester(mut self, requester: Box<dyn Requester>) -> Self {
        self.requester = requester;
        self
    }

    /// Share the SIGINT hold with the binary (spec §5.5): the Linux request
    /// raises it for the launcher child's lifetime and the binary's shutdown
    /// future keeps serving on a Ctrl-C while it is held. Without this call
    /// the state counts holds nobody reads.
    #[must_use]
    pub fn with_sigint_hold(self, hold: HoldCount) -> Self {
        *lock(&self.shared.hold) = hold;
        self
    }

    /// The SIGINT hold this state raises around a launcher child (a clone
    /// sharing the count).
    #[must_use]
    pub fn sigint_hold(&self) -> HoldCount {
        self.shared.sigint_hold()
    }

    /// Cancel the prompt a held Ctrl-C was meant for (spec §5.5, panel 2):
    /// when the core alone received the Ctrl-C (no shared foreground process
    /// group), send the live launcher child SIGINT itself, so the prompt ends
    /// now instead of at the 300 s timeout and the watcher records
    /// `dismissed` through the §5.5 table. With no launcher alive (no request
    /// in flight, or a directly started file-caps helper) this does nothing.
    ///
    /// It never blocks on the watcher's child lock (panel 3, D4): the watcher
    /// holds it only across one `try_wait` or `kill`, and a lock found held
    /// means the child is being stepped as it ends, so the cancel is skipped.
    pub fn cancel_prompt(&self) {
        let Some(child) = self.shared.prompt_child() else {
            return;
        };
        match child.try_lock() {
            Ok(mut child) => child.interrupt(),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().interrupt(),
            Err(TryLockError::WouldBlock) => {
                tracing::debug!("the prompt's child is mid-step with its watcher; cancel skipped");
            }
        };
    }

    /// The one capture/inject backend every production caller holds (spec §2.1,
    /// plan P1b.8): a [`RoutedBackend`] that reads this state on every call and
    /// delegates to libpcap in process, to the helper session, or refuses
    /// fail-closed with the gated text.
    #[must_use]
    pub fn backend(self: &Arc<Self>) -> Arc<dyn CaptureInjectBackend> {
        Arc::new(RoutedBackend::new(Arc::clone(self)))
    }

    /// Attach the guard a Linux helper session's backend is built over
    /// ([`HelperBackend::new`] needs it). The binary's wiring (or
    /// `L4Module::with_shared_state`) calls this once with the shared guard;
    /// until it does, a helper that connects cannot be attached: the watcher
    /// logs one `warn` and the request `failed` with [`msg::NO_GUARD`].
    pub fn set_guard(&self, guard: Arc<L4Guard>) {
        *lock(&self.shared.guard) = Some(guard);
    }

    /// A guard is attached (see [`set_guard`](PrivilegeState::set_guard)), so
    /// a connecting helper session can be built over it.
    #[must_use]
    pub fn has_guard(&self) -> bool {
        self.shared.guard().is_some()
    }

    /// Set (or clear) the helper session's backend: the one slot the routed
    /// backend takes for `Available { via: Helper }` from the next call on and
    /// the prober reads `session_connected` from. A test seam: in production
    /// only the watcher thread fills and clears the slot.
    #[cfg(test)]
    pub(crate) fn set_helper_backend(&self, backend: Option<Arc<dyn LiveBackend>>) {
        self.shared.set_live(backend);
    }

    /// The helper session's backend, if one is connected. On the Linux
    /// file-capability row (capture `Available { via: Helper }` with no
    /// session yet) the first call starts the helper directly, without a
    /// launcher, and waits a bounded moment for it to attach (plan P1b.14).
    pub(crate) fn helper_backend(&self) -> Option<Arc<dyn CaptureInjectBackend>> {
        if let Some(backend) = self.shared.helper() {
            return Some(backend);
        }
        self.lazy_start_helper();
        self.shared.helper()
    }

    /// The configuration this state was built from.
    #[must_use]
    pub fn config(&self) -> &PrivilegeConfig {
        &self.cfg
    }

    /// The current report. Probes on the first call, whenever a request was
    /// just recorded, and whenever the cached capture is not `Available` and
    /// at least [`REPROBE_MS`] old; otherwise answers from the cache. The
    /// `request` field is always the current one.
    ///
    /// The probe runs **outside** the cache lock (the platform gatherers spawn
    /// subprocesses) and in single flight: while one caller probes, another
    /// answers from the report in hand instead of waiting, and the progress
    /// writers never block behind a gather.
    #[must_use]
    pub fn report(&self) -> PrivilegeReport {
        let now = self.shared.now();
        if let Claim::Probe(request) = self.claim_probe(now) {
            self.probe(request, now);
        }
        self.report_in_hand(now)
    }

    /// `report()` for a caller that must not act on an empty first report: if
    /// another thread's first probe is in flight, wait (bounded) for it.
    fn report_settled(&self) -> PrivilegeReport {
        let deadline = Instant::now() + SETTLE_WAIT;
        loop {
            let now = self.shared.now();
            match self.claim_probe(now) {
                Claim::Probe(request) => self.probe(request, now),
                Claim::InFlightNoReport if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Claim::InFlightNoReport | Claim::Fresh => {}
            }
            return self.report_in_hand(now);
        }
    }

    /// Under the cache: decide whether this caller probes. Claiming the probe
    /// also consumes the dirty mark; a `set_request` during the gather sets it
    /// again, so the next `report()` re-probes under the new request.
    fn claim_probe(&self, now: u64) -> Claim {
        let mut cache = self.shared.lock_cache();
        if cache.probing {
            return if cache.report.is_some() {
                Claim::Fresh
            } else {
                Claim::InFlightNoReport
            };
        }
        let stale = match &cache.report {
            None => true,
            Some(cached) => {
                !matches!(cached.capture, Capability::Available { .. })
                    && now.saturating_sub(cache.probed_at) >= REPROBE_MS
            }
        };
        if !(stale || cache.dirty) {
            return Claim::Fresh;
        }
        cache.probing = true;
        cache.dirty = false;
        Claim::Probe(cache.request.clone())
    }

    /// The cached report (or, before the first probe landed, the empty one)
    /// under the current request.
    fn report_in_hand(&self, now: u64) -> PrivilegeReport {
        let cache = self.shared.lock_cache();
        let mut report = cache
            .report
            .clone()
            .unwrap_or_else(|| derive(&self.empty_inputs(now)));
        report.request = cache.request.clone();
        report
    }

    /// `l4.privilege.request` (spec §2.3). Non-blocking. In order: L4 off in
    /// this core's config is `CannotPrompt` (**Architect's call**, plan
    /// P1b.10); capture already `Available` is `AlreadyAvailable`; a request
    /// still in flight (`pending` or `handed_to_app`) is `Pending` with the
    /// same progress; otherwise the platform [`Requester`] is asked once and
    /// its answer is recorded as this core's request progress
    /// (`HandedToApp` / `Pending` as themselves, `CannotPrompt` as `failed`),
    /// then the requester's `after_recorded` runs. The returned report is the
    /// one in hand re-derived under the recorded progress, so it carries the
    /// request-dependent rows without a second gather (one probe per
    /// request at most).
    #[must_use]
    pub fn request(&self) -> RequestOutcome {
        let _one_at_a_time = lock(&self.requesting);

        let report = self.report_settled();
        if !self.cfg.enabled {
            return RequestOutcome {
                outcome: Outcome::CannotPrompt,
                message: text::L4_OFF.to_string(),
                privilege: report,
            };
        }
        if matches!(report.capture, Capability::Available { .. }) {
            return RequestOutcome {
                outcome: Outcome::AlreadyAvailable,
                message: ALREADY_AVAILABLE_MESSAGE.to_string(),
                privilege: report,
            };
        }
        if let Some(in_flight) = report
            .request
            .as_ref()
            .filter(|req| matches!(req.state, RequestState::Pending | RequestState::HandedToApp))
        {
            let message = in_flight.message.clone();
            return RequestOutcome {
                outcome: Outcome::Pending,
                message,
                privilege: report,
            };
        }

        let (outcome, message) = self.requester.request(&self.cfg, &report);
        let state = match outcome {
            Outcome::HandedToApp => Some(RequestState::HandedToApp),
            Outcome::Pending => Some(RequestState::Pending),
            Outcome::CannotPrompt => Some(RequestState::Failed),
            Outcome::AlreadyAvailable => None,
        };
        if let Some(state) = state {
            self.set_request(Some(RequestProgress {
                state,
                at: self.shared.now(),
                message: message.clone(),
            }));
            self.requester.after_recorded();
        }
        RequestOutcome {
            outcome,
            message,
            privilege: self.rederived_report(),
        }
    }

    /// Record (or clear) the progress of this core's `l4.privilege.request`.
    /// The next `report()` probes at once so the request-dependent rows apply.
    pub(crate) fn set_request(&self, request: Option<RequestProgress>) {
        let mut cache = self.shared.lock_cache();
        cache.request = request;
        cache.dirty = true;
    }

    /// Gather and derive outside the cache lock, then merge under it. A
    /// prober that panics still releases the single-flight claim.
    fn probe(&self, request: Option<RequestProgress>, now: u64) {
        let mut claim = ProbeClaim {
            shared: &self.shared,
            armed: true,
        };
        let mut inputs = self.prober.gather(request.as_ref());
        inputs.now_ms = now;
        inputs.request = request;
        let fresh = derive(&inputs);

        let mut cache = self.shared.lock_cache();
        Self::merge(&mut cache, inputs, fresh, now);
        cache.probing = false;
        claim.armed = false;
    }

    /// Under the lock: move a waiting request to `approved` when capture
    /// became available, log a capture-state change, and store the result.
    fn merge(cache: &mut Cache, inputs: ProbeInputs, mut fresh: PrivilegeReport, now: u64) {
        if matches!(fresh.capture, Capability::Available { .. }) {
            let waiting = cache.request.as_ref().is_some_and(|req| {
                matches!(req.state, RequestState::Pending | RequestState::HandedToApp)
            });
            if waiting {
                let approved = RequestProgress {
                    state: RequestState::Approved,
                    at: now,
                    message: APPROVED_MESSAGE.to_string(),
                };
                cache.request = Some(approved.clone());
                fresh.request = Some(approved);
            }
        }

        if let Some(previous) = &cache.report {
            if previous.capture != fresh.capture {
                cache.changes += 1;
                tracing::info!(
                    from = previous.capture.state_str(),
                    to = fresh.capture.state_str(),
                    reason = fresh.capture.reason().unwrap_or(""),
                    "L4 packet capture state changed"
                );
            }
        }

        cache.inputs = Some(inputs);
        cache.report = Some(fresh);
        cache.probed_at = now;
    }

    /// The report in hand re-derived under the current request (the
    /// request-dependent rows), without another gather. The dirty mark the
    /// request left stands, so the next `report()` re-gathers.
    fn rederived_report(&self) -> PrivilegeReport {
        let cache = self.shared.lock_cache();
        let Some(inputs) = &cache.inputs else {
            drop(cache);
            return self.report_in_hand(self.shared.now());
        };
        let mut inputs = inputs.clone();
        inputs.request.clone_from(&cache.request);
        derive(&inputs)
    }

    /// Inputs for a platform with nothing gathered; only reached if a probe
    /// left no report, which `probe` never does. Keeps `report` total.
    fn empty_inputs(&self, now: u64) -> ProbeInputs {
        ProbeInputs {
            enabled: self.cfg.enabled,
            platform: current_platform(),
            mac: None,
            linux: None,
            request: None,
            now_ms: now,
        }
    }

    /// The Linux file-capability row (spec §5.6, plan P1b.14): capture is
    /// `Available { via: Helper }` because discovery found a helper whose
    /// `probe` reports `CAP_NET_RAW`, but no session exists yet. Start it
    /// directly (`<helper> serve --connect <socket>`, no launcher, no prompt)
    /// and wait up to [`LAZY_START_WAIT`] for the attach. Serving processes
    /// only: a one-shot cannot host the session (spec §2.4). Anything that
    /// goes wrong is one `warn`; the caller then reads an empty slot and the
    /// routed backend refuses fail-closed.
    fn lazy_start_helper(&self) {
        let Some(inputs) = self.shared.last_linux() else {
            return;
        };
        let Some(helper) = direct_start_target(self.cfg.lifetime, &inputs) else {
            return;
        };

        let _one_at_a_time = lock(&self.lazy_start);
        if self.shared.helper().is_some() {
            return;
        }
        if !self.shared.watching() {
            match spawn_direct(&self.shared, &helper, self.requester.spawner()) {
                Ok(()) => tracing::info!(
                    "starting the packet-capture helper directly (file capabilities)"
                ),
                Err(err) => {
                    tracing::warn!(error = %err, "the packet-capture helper could not be started");
                    return;
                }
            }
        }
        let deadline = Instant::now() + LAZY_START_WAIT;
        while self.shared.helper().is_none() && self.shared.watching() && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The direct start's one decision, pure (spec §5.6; S2 of the p1b panel):
/// `Some(helper path)` when this process serves, holds no `CAP_NET_RAW` of
/// its own, and discovery found a helper whose `probe` reports `CAP_NET_RAW`
/// **and** whose path chain only root could have written. File capabilities
/// on a user-writable path are never trusted, let alone executed.
#[must_use]
pub(crate) fn direct_start_target(
    lifetime: ProcessLifetime,
    inputs: &LinuxInputs,
) -> Option<PathBuf> {
    if lifetime != ProcessLifetime::Serving || inputs.cap_net_raw {
        return None;
    }
    inputs
        .helper
        .as_ref()
        .filter(|helper| helper.trusted_file_caps())
        .map(|helper| helper.path.clone())
}

/// The start-up line (spec §2.4, AC24): `Some` only when L4 is enabled and
/// packet capture needs approval; it carries the remedy's label, never a
/// command.
#[must_use]
pub fn startup_line(report: &PrivilegeReport) -> Option<String> {
    if !report.enabled {
        return None;
    }
    match &report.capture {
        Capability::NeedsApproval { how, .. } => Some(format!(
            "L4 enabled; packet capture needs approval: {}",
            how.label
        )),
        _ => None,
    }
}

/// This OS's gatherer behind the [`Prober`] seam.
struct PlatformProber {
    enabled: bool,
    l4: L4PrivilegeConfig,
    shared: Arc<Shared>,
}

impl Prober for PlatformProber {
    fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
        let platform = current_platform();
        let mac = (platform == Platform::Macos).then(|| gather_mac(&self.l4.macos_app_path));
        // `session_connected` is whether the helper session the watcher
        // attached is still open (plan P1b.13 hand-over).
        let linux = (platform == Platform::Linux).then(|| {
            let mut inputs = gather_linux(self.l4.helper_path.as_deref(), self.shared.live_is_up());
            inputs.last_session_error = self.shared.session_failure();
            *lock(&self.shared.last_linux) = Some(inputs.clone());
            inputs
        });
        ProbeInputs {
            enabled: self.enabled,
            platform,
            mac,
            linux,
            request: request.cloned(),
            now_ms: epoch_ms_now(),
        }
    }
}

/// This build's platform half of `request()`. It decides on the report's
/// `platform` (the one the decision table ran for) and never blocks.
///
/// - macOS: until P1b.11 lands the handoff, `CannotPrompt` with the remedy the
///   report already offers (`how.label`), so an operator reads the same one
///   action everywhere.
/// - Linux (plan P1b.14): [`request_linux`] over the last probe's inputs,
///   under the state's SIGINT hold ([`PrivilegeState::with_sigint_hold`]),
///   spawning through the real [`StdSpawner`] once the listener is bound in
///   the socket directory; the child and listener wait in `pending` until
///   [`Requester::after_recorded`] starts the watcher thread.
/// - Anything else: `CannotPrompt`, [`NO_HANDOFF_MESSAGE`].
struct PlatformRequester {
    shared: Arc<Shared>,
    spawner: Arc<dyn Spawner>,
    pending: Mutex<Option<PendingWatch>>,
}

/// A spawned child and its listener, between `request` and `after_recorded`.
struct PendingWatch {
    spawned: Spawned,
    listener: HelperListener,
    started_ms: u64,
}

impl PlatformRequester {
    fn new(shared: Arc<Shared>) -> Self {
        PlatformRequester {
            shared,
            spawner: Arc::new(StdSpawner),
            pending: Mutex::new(None),
        }
    }

    fn linux_request(&self, cfg: &PrivilegeConfig) -> (Outcome, String) {
        let inputs = self.shared.last_linux().unwrap_or_else(|| {
            gather_linux(cfg.l4.helper_path.as_deref(), self.shared.live_is_up())
        });
        let binder = BindingSpawner::new(Arc::clone(&self.spawner));
        // No socket location: refuse before `request_linux`, so no argv is
        // ever built with an empty path.
        let Some(socket) = binder.socket() else {
            return (Outcome::CannotPrompt, no_socket_location());
        };
        // The hold is the state's (shared with the binary's shutdown future).
        let hold = self.shared.sigint_hold();
        let request = request_linux(cfg, &inputs, &binder, &hold, &socket, display_set());
        if let Some(spawned) = request.spawned {
            match binder.take_listener() {
                Some(listener) => {
                    *lock(&self.pending) = Some(PendingWatch {
                        spawned,
                        listener,
                        started_ms: self.shared.now(),
                    });
                }
                None => {
                    // `spawn` binds before it spawns, so this cannot happen;
                    // fail closed rather than leave a child unwatched.
                    let mut spawned = spawned;
                    spawned.child.kill();
                    return (
                        Outcome::CannotPrompt,
                        format!("{} (no listener)", msg::SPAWN_FAILED),
                    );
                }
            }
        }
        (request.outcome, request.message)
    }
}

impl Requester for PlatformRequester {
    fn request(&self, cfg: &PrivilegeConfig, report: &PrivilegeReport) -> (Outcome, String) {
        let remedy = || {
            report
                .capture
                .how()
                .map(|how| how.label.clone())
                .or_else(|| report.capture.reason().map(str::to_string))
                .unwrap_or_else(|| NO_HANDOFF_MESSAGE.to_string())
        };
        match report.platform {
            // P1b.11 replaces this arm (macOS handoff to the app).
            Platform::Macos => (Outcome::CannotPrompt, remedy()),
            Platform::Linux => self.linux_request(cfg),
            Platform::Other => (Outcome::CannotPrompt, NO_HANDOFF_MESSAGE.to_string()),
        }
    }

    /// The direct start goes through this requester's own spawner, so a
    /// scripted one sees that spawn too.
    fn spawner(&self) -> Arc<dyn Spawner> {
        Arc::clone(&self.spawner)
    }

    fn after_recorded(&self) {
        let Some(pending) = lock(&self.pending).take() else {
            return;
        };
        if let Err(err) = start_watch(Arc::clone(&self.shared), pending) {
            tracing::warn!(error = %err, "the packet-capture request could not be watched");
            self.shared.set_progress(
                RequestState::Failed,
                &format!("{} ({err})", msg::SPAWN_FAILED),
            );
        }
    }
}

/// `DISPLAY` or `WAYLAND_DISPLAY` is set and non-empty (the `pending` text).
fn display_set() -> bool {
    let set = |key: &str| std::env::var(key).is_ok_and(|value| !value.is_empty());
    set("DISPLAY") || set("WAYLAND_DISPLAY")
}

/// Where the helper socket goes: the directory from
/// [`crate::helper::client::socket_dir`] (`$XDG_RUNTIME_DIR/aitm`, else
/// `/tmp/aitm-<uid>`) and this process's real uid.
#[cfg(target_os = "linux")]
fn socket_location() -> Option<(PathBuf, u32)> {
    let uid = nix::unistd::getuid().as_raw();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    Some((
        crate::helper::client::socket_dir(runtime.as_deref(), uid),
        uid,
    ))
}

/// Off Linux there is no helper session to bind for.
#[cfg(not(target_os = "linux"))]
fn socket_location() -> Option<(PathBuf, u32)> {
    None
}

/// The refusal when there is no socket location: nothing is spawned, no argv
/// ever carries an empty path.
fn no_socket_location() -> String {
    format!(
        "{} (no socket directory on this platform)",
        msg::SPAWN_FAILED
    )
}

/// A [`Spawner`] that binds the listener first, then spawns: the helper's
/// `connect` must find the socket, so the bind precedes the spawn and
/// happens only when [`request_linux`]'s pre-checks passed (nothing is
/// created on a refusal). The bound listener is taken by the caller.
struct BindingSpawner {
    inner: Arc<dyn Spawner>,
    location: Option<(PathBuf, u32)>,
    listener: Mutex<Option<HelperListener>>,
}

impl BindingSpawner {
    fn new(inner: Arc<dyn Spawner>) -> Self {
        BindingSpawner {
            inner,
            location: socket_location(),
            listener: Mutex::new(None),
        }
    }

    /// The socket path the listener will bind (the argv needs it first);
    /// `None` where no helper session can be bound for (off Linux).
    fn socket(&self) -> Option<PathBuf> {
        self.location
            .as_ref()
            .map(|(dir, _)| socket_path(dir, std::process::id()))
    }

    fn take_listener(&self) -> Option<HelperListener> {
        lock(&self.listener).take()
    }
}

impl Spawner for BindingSpawner {
    fn spawn(&self, argv: &[std::ffi::OsString]) -> io::Result<Box<dyn Child>> {
        let (dir, uid) = self
            .location
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, no_socket_location()))?;
        ensure_socket_dir(dir, *uid)?;
        let listener = HelperListener::bind(dir)?;
        *lock(&self.listener) = Some(listener);
        self.inner.spawn(argv)
    }
}

/// Start a file-capability helper directly (no launcher, no SIGINT hold)
/// through `spawner` (the requester's seam) and watch it like a request,
/// without touching the request progress.
fn spawn_direct(
    shared: &Arc<Shared>,
    helper: &std::path::Path,
    spawner: Arc<dyn Spawner>,
) -> io::Result<()> {
    let binder = BindingSpawner::new(spawner);
    let socket = binder
        .socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, no_socket_location()))?;
    let child = binder.spawn(&direct_helper_argv(helper, &socket))?;
    let listener = binder
        .take_listener()
        .ok_or_else(|| io::Error::other("the helper listener was not bound"))?;
    start_watch_with(
        Arc::clone(shared),
        PendingWatch {
            spawned: Spawned { child, hold: None },
            listener,
            started_ms: shared.now(),
        },
        false,
    )
}

/// Start the watcher thread for a request's child.
fn start_watch(shared: Arc<Shared>, pending: PendingWatch) -> io::Result<()> {
    start_watch_with(shared, pending, true)
}

fn start_watch_with(shared: Arc<Shared>, pending: PendingWatch, progress: bool) -> io::Result<()> {
    let PendingWatch {
        spawned: Spawned { child, hold },
        listener,
        started_ms,
    } = pending;
    // `watching` reads true from the spawn on. The thread's `Watch` takes an
    // id of its own as it starts and clears that one when it ends, however
    // it ends (a panic included); this id only covers the gap.
    let id = shared.start_watching();
    let thread_shared = Arc::clone(&shared);
    let built = std::thread::Builder::new()
        .name("l4-privilege-watch".to_string())
        .spawn(move || {
            run_watcher(
                thread_shared,
                child,
                Box::new(listener),
                hold,
                started_ms,
                progress,
            );
        });
    if let Err(err) = built {
        // The child handle went with the closure; its connect will find no
        // listener and the helper exits on its own.
        shared.stop_watching(id);
        return Err(err);
    }
    Ok(())
}

/// The listener as the watcher sees it: one checked accept per slice.
pub(crate) trait Acceptor: Send {
    fn accept(&self, expected_pid: u32, timeout: Duration) -> Result<HelperSession, SessionError>;
}

impl Acceptor for HelperListener {
    fn accept(&self, expected_pid: u32, timeout: Duration) -> Result<HelperSession, SessionError> {
        self.accept_checked(expected_pid, timeout)
    }
}

/// The watcher of one spawned child (spec §2.3, §5.5; plan P1b.14), run on
/// its own thread. Each turn: one checked accept slice on the listener, then
/// one [`watch_step`] on the injected clock.
///
/// - The helper connects and passes the peer check: the SIGINT hold is
///   released, the session is handshaken and its reader started, a
///   [`HelperBackend`] is built over the state's guard and set as the helper
///   backend, the progress is `approved`; the thread then stays until the
///   session closes, clears the slot and marks the cache dirty so the next
///   report re-probes.
/// - The child ends first: the hold is released and
///   [`crate::privilege::linux::classify_exit_full`] names the row
///   ([`ExitClass`]) and the progress; the no-agent row also logs one `warn`
///   (the predicate and the launcher disagreed).
/// - [`crate::privilege::linux::APPROVAL_TIMEOUT_MS`] pass: the child is
///   killed and the progress is `failed` with the timeout text.
/// - The listener fails `accept` [`ACCEPT_ERRORS_MAX`] times in a row: one
///   `warn` at the first, then the child is killed and the progress is
///   `failed` with the socket error.
///
/// Every terminal arm ends through one epilogue, [`Watch::end_request`]: the
/// hold is released, the listener is dropped (its socket path unlinked)
/// **before** the terminal progress row is written and before any reap, so a
/// re-request that binds the same path never has it unlinked by this one.
/// The [`Watch`] is also the thread's unwind guard (spec §5.5, panel 2): a
/// panic releases the hold and the listener, moves a still-`pending` request
/// to `failed` and clears `watching`.
///
/// `progress` is false for a direct file-capability start, which nobody
/// requested: it logs instead of writing request progress, and its child is
/// not a prompt, so it is never registered for `cancel_prompt`.
pub(crate) fn run_watcher(
    shared: Arc<Shared>,
    child: Box<dyn Child>,
    acceptor: Box<dyn Acceptor>,
    hold: Option<HoldToken>,
    started_ms: u64,
    progress: bool,
) {
    let mut watch = Watch::new(shared, child, acceptor, hold, started_ms, progress);
    let mut accept_errors = 0usize;
    loop {
        match watch.accept() {
            Ok(session) => {
                watch.release_prompt();
                match attach_session(&watch.shared, session) {
                    Ok(backend) => {
                        watch
                            .shared
                            .set_live(Some(Arc::clone(&backend) as Arc<dyn LiveBackend>));
                        watch.record(RequestState::Approved, msg::APPROVED);
                        watch.shared.mark_dirty();
                        tracing::info!("L4 packet-capture helper connected");
                        drop(watch.acceptor.take());
                        while backend.is_live() {
                            std::thread::sleep(LIVE_POLL);
                        }
                        watch.shared.set_live(None);
                        watch.shared.mark_dirty();
                        tracing::info!("L4 packet-capture helper session ended");
                        watch.reap();
                    }
                    Err(message) => {
                        tracing::warn!(
                            reason = %message,
                            "the packet-capture helper connected but could not be attached"
                        );
                        watch.end_request(RequestState::Failed, &message, true);
                    }
                }
                return;
            }
            Err(SessionError::Timeout) => accept_errors = 0,
            Err(SessionError::PeerUid(_) | SessionError::PeerPid(_)) => {
                accept_errors = 0;
                tracing::warn!(
                    "a process other than the spawned helper connected to the \
                     packet-capture socket; dropped"
                );
            }
            Err(err) => {
                // A broken listener: say so once, and give up after a bound
                // rather than spin for the whole approval window.
                accept_errors += 1;
                if accept_errors == 1 {
                    tracing::warn!(error = %err, "the packet-capture socket failed to accept");
                }
                if accept_errors >= ACCEPT_ERRORS_MAX {
                    let message = format!(
                        "{} ({})",
                        msg::SOCKET_FAILED,
                        bounded_text(&err.to_string(), TEXT_BOUND)
                    );
                    watch.end_request(RequestState::Failed, &message, true);
                    return;
                }
                std::thread::sleep(ACCEPT_SLICE);
            }
        }

        match watch.step() {
            WatchOutcome::Waiting => {}
            WatchOutcome::Ended {
                reason,
                state,
                message,
            } => {
                if reason == ExitClass::NoAgent {
                    tracing::warn!(
                        "a prompt was judged possible but the launcher found no \
                         authentication agent"
                    );
                }
                // A timed-out child was killed by `watch_step`; any other
                // ending was the child's own. Either way the epilogue reaps.
                watch.end_request(state, &message, false);
                return;
            }
        }
    }
}

/// One watch, owned by the watcher thread: the child (shared with
/// `cancel_prompt` while it is a prompt), the listener, the SIGINT hold, and
/// the thread's unwind guard. Its `Drop` is the panic path: whatever the
/// watcher was doing, the hold and the listener go, the child is killed
/// (best effort, no reap), a still-`pending` request reads `failed`, and
/// `watching` is cleared. It releases only what it registered (panel 3,
/// D1): its own child from the prompt slot, its own id from `watching`.
struct Watch {
    shared: Arc<Shared>,
    child: SharedChild,
    acceptor: Option<Box<dyn Acceptor>>,
    /// The SIGINT hold while the child is a prompt; `None` for a direct start.
    hold: Option<HoldToken>,
    started_ms: u64,
    progress: bool,
    /// The child was spawned under a hold, so it is a prompt: registered for
    /// `cancel_prompt` until the prompt is over.
    prompt: bool,
    /// This watch's id in `Shared::watching`.
    id: u64,
}

impl Watch {
    fn new(
        shared: Arc<Shared>,
        child: Box<dyn Child>,
        acceptor: Box<dyn Acceptor>,
        hold: Option<HoldToken>,
        started_ms: u64,
        progress: bool,
    ) -> Self {
        let id = shared.start_watching();
        let child: SharedChild = Arc::new(Mutex::new(child));
        // A child spawned under the SIGINT hold is a launcher at a prompt: a
        // held Ctrl-C may cancel it. A direct start has no hold and no prompt.
        let prompt = hold.is_some();
        if prompt {
            shared.register_prompt_child(&child);
        }
        Watch {
            shared,
            child,
            acceptor: Some(acceptor),
            hold,
            started_ms,
            progress,
            prompt,
            id,
        }
    }

    /// One checked accept slice on the listener.
    fn accept(&self) -> Result<HelperSession, SessionError> {
        let Some(acceptor) = &self.acceptor else {
            return Err(SessionError::Timeout);
        };
        let pid = lock(&self.child).id();
        acceptor.accept(pid, ACCEPT_SLICE)
    }

    /// One [`watch_step`] on the injected clock.
    fn step(&self) -> WatchOutcome {
        watch_step(
            lock(&self.child).as_mut(),
            self.started_ms,
            self.shared.now(),
        )
    }

    /// Write request progress; a direct start writes none.
    fn record(&self, state: RequestState, message: &str) {
        if self.progress {
            self.shared.set_progress(state, message);
        }
    }

    /// The prompt is over (the helper connected, or the child ended): release
    /// the SIGINT hold and unregister the child from `cancel_prompt`.
    fn release_prompt(&mut self) {
        drop(self.hold.take());
        if self.prompt {
            self.shared.unregister_prompt_child(&self.child);
        }
    }

    /// The one epilogue of every terminal arm (S1 ordering): the prompt is
    /// over, the listener (and its socket path) goes **before** the terminal
    /// row, the child is killed when `kill` says so, one `info` line names
    /// the end, the row is recorded, and the child is reaped (bounded).
    fn end_request(&mut self, state: RequestState, message: &str, kill: bool) {
        self.release_prompt();
        drop(self.acceptor.take());
        if kill {
            lock(&self.child).kill();
        }
        tracing::info!(
            state = state.as_str(),
            reason = %message,
            "L4 packet-capture request ended"
        );
        self.record(state, message);
        self.reap();
    }

    /// Wait, bounded, for an ended or killed child to be reaped; a launcher
    /// that refused the kill (another user) is left to the OS. The child's
    /// lock is taken per poll, never across the wait.
    fn reap(&self) {
        let deadline = Instant::now() + REAP_WAIT;
        loop {
            match lock(&self.child).try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => return,
                Ok(None) => {}
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // The normal arms have already released everything; this is the
        // unwind path, and the idempotent tail of the normal one.
        let panicking = std::thread::panicking();
        self.release_prompt();
        drop(self.acceptor.take());
        if panicking {
            // Nothing will step this child again: kill it, best effort, and
            // skip the bounded reap (panel 3, D2).
            lock(&self.child).kill();
            if self.progress {
                tracing::warn!("the packet-capture watcher ended unexpectedly");
                self.shared.fail_if_pending(msg::ENDED_UNEXPECTEDLY);
            }
        }
        self.shared.stop_watching(self.id);
    }
}

/// Handshake, start the reader, and build the backend over the state's guard.
fn attach_session(
    shared: &Shared,
    mut session: HelperSession,
) -> Result<Arc<HelperBackend>, String> {
    if let Err(err) = session.handshake(CORE_VERSION, HANDSHAKE_TIMEOUT) {
        // Spec §5.2: the next report says `version_mismatch`, naming the
        // protocols or the defect, until a session attaches.
        shared.set_session_failure(Some(match &err {
            SessionError::VersionMismatch(theirs) => SessionFailure::VersionMismatch(*theirs),
            other => SessionFailure::Protocol(bounded_text(&other.to_string(), TEXT_BOUND)),
        }));
        return Err(format!(
            "the packet-capture helper did not complete its handshake ({err})"
        ));
    }
    shared.set_session_failure(None);
    session
        .start_reader()
        .map_err(|err| format!("the packet-capture helper session could not start ({err})"))?;
    let guard = shared.guard().ok_or_else(|| msg::NO_GUARD.to_string())?;
    HelperBackend::new(Arc::new(session), guard)
        .map(Arc::new)
        .map_err(|err| err.to_string())
}

/// The platform this build runs on, in the report's vocabulary.
#[must_use]
pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Other
    }
}

/// The system clock in epoch milliseconds; a clock before 1970 reads as 0.
fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::privilege::derive::{HelperCandidate, LinuxInputs, MacInputs, ProbeInputs};

    impl PrivilegeState {
        /// How many capture-state changes `report()` has logged.
        fn changes(&self) -> u64 {
            self.shared.lock_cache().changes
        }
    }
    use crate::privilege::report::{
        Capability, HelperStatus, Platform, PrivilegeReport, RequestProgress, RequestState, Via,
    };

    /// A prober that answers from a queue of macOS inputs, repeating the last.
    struct Scripted {
        enabled: bool,
        rows: Mutex<Vec<MacInputs>>,
        calls: Arc<AtomicU64>,
    }

    impl Scripted {
        fn new(rows: Vec<MacInputs>) -> Box<Self> {
            Self::with_enabled(true, rows)
        }

        /// The same prober plus a handle on its `gather` count.
        fn counted(rows: Vec<MacInputs>) -> (Box<Self>, Arc<AtomicU64>) {
            let prober = Self::new(rows);
            let calls = Arc::clone(&prober.calls);
            (prober, calls)
        }

        /// The same prober reporting `l4.enabled` as `enabled` (the production
        /// prober copies it from the config).
        fn with_enabled(enabled: bool, rows: Vec<MacInputs>) -> Box<Self> {
            Box::new(Self {
                enabled,
                rows: Mutex::new(rows),
                calls: Arc::new(AtomicU64::new(0)),
            })
        }
    }

    impl Prober for Scripted {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            let mac = if rows.len() > 1 {
                rows.remove(0)
            } else {
                rows[0].clone()
            };
            ProbeInputs {
                enabled: self.enabled,
                platform: Platform::Macos,
                mac: Some(mac),
                linux: None,
                request: request.cloned(),
                // The state stamps the probe with its own clock, whatever the
                // prober wrote here.
                now_ms: 7,
            }
        }
    }

    /// Row 6 of the macOS table: nothing opens, no receipt, no handoff app.
    fn row6() -> MacInputs {
        MacInputs {
            bpf_rw_opens: false,
            receipt: None,
            handoff_app_embeds_helper: false,
        }
    }

    /// Row 2: a `/dev/bpf*` opens read+write.
    fn row2() -> MacInputs {
        MacInputs {
            bpf_rw_opens: true,
            receipt: None,
            handoff_app_embeds_helper: false,
        }
    }

    /// Row 5: the handoff app embeds the helper plist.
    fn row5() -> MacInputs {
        MacInputs {
            bpf_rw_opens: false,
            receipt: None,
            handoff_app_embeds_helper: true,
        }
    }

    fn cfg() -> PrivilegeConfig {
        PrivilegeConfig {
            enabled: true,
            l4: L4PrivilegeConfig::default(),
            lifetime: ProcessLifetime::Serving,
        }
    }

    fn state_over(rows: Vec<MacInputs>) -> (PrivilegeState, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(0));
        let clock_now = Arc::clone(&now);
        let state = PrivilegeState::with_prober(
            &cfg(),
            Scripted::new(rows),
            Arc::new(move || clock_now.load(Ordering::SeqCst)),
        );
        (state, now)
    }

    #[test]
    fn flip_is_seen_without_rebuild() {
        let (state, now) = state_over(vec![row6(), row2()]);

        // t = 0: the first probe sees row 6.
        let first = state.report();
        assert_eq!(first.capture.state_str(), "needs_approval");
        assert_eq!(first.inject.state_str(), "needs_approval");
        assert_eq!(first.checked_at, 0, "checked_at is the state's clock");
        assert!(first.enabled);

        // t = 500 ms: the OS has flipped (row 2 is next) but the cache is
        // younger than the TTL, so the answer is still the cached one.
        now.store(500, Ordering::SeqCst);
        let cached = state.report();
        assert_eq!(cached.capture.state_str(), "needs_approval");
        assert_eq!(cached.checked_at, 0, "no re-probe inside the TTL");

        // t = 1100 ms: older than 1000 ms and not available, so it re-probes
        // and sees the flip. No rebuild of the state.
        now.store(1100, Ordering::SeqCst);
        let flipped = state.report();
        assert_eq!(flipped.capture, Capability::Available { via: Via::Process });
        assert_eq!(flipped.inject, Capability::Available { via: Via::Process });
        assert_eq!(flipped.checked_at, 1100);

        // Once available, the result is held: a later report inside the TTL
        // is the same object, and one past it is not re-probed either.
        now.store(5000, Ordering::SeqCst);
        let held = state.report();
        assert_eq!(held.capture, Capability::Available { via: Via::Process });
        assert_eq!(
            held.checked_at, 1100,
            "an available result is not re-probed"
        );
    }

    #[test]
    fn info_logged_once_per_change() {
        let (state, now) = state_over(vec![row6(), row2()]);
        assert_eq!(state.changes(), 0);

        // The first probe establishes the state; it is not a change.
        let _ = state.report();
        assert_eq!(state.changes(), 0, "the first probe is not a change");

        // Inside the TTL nothing is probed, so nothing can change.
        now.store(500, Ordering::SeqCst);
        let _ = state.report();
        assert_eq!(state.changes(), 0);

        // The flip is one change.
        now.store(1100, Ordering::SeqCst);
        let _ = state.report();
        assert_eq!(state.changes(), 1);

        // Repeats, inside or past the TTL, add nothing.
        now.store(1500, Ordering::SeqCst);
        let _ = state.report();
        now.store(9000, Ordering::SeqCst);
        let _ = state.report();
        assert_eq!(state.changes(), 1, "exactly one change for row 6 -> row 2");
    }

    #[test]
    fn pending_request_becomes_approved_when_capture_flips() {
        let (state, now) = state_over(vec![row6(), row2()]);
        let _ = state.report();

        state.set_request(Some(RequestProgress {
            state: RequestState::HandedToApp,
            at: 100,
            message: "handed to the Aitmproxy app".to_string(),
        }));
        // A new request invalidates the cache: the next report re-probes at
        // once (row 2) and the request moves to approved.
        now.store(200, Ordering::SeqCst);
        let report = state.report();
        assert_eq!(report.capture, Capability::Available { via: Via::Process });
        let request = report.request.expect("the request is carried");
        assert_eq!(request.state, RequestState::Approved);
        assert_eq!(request.at, 200);
        assert_eq!(request.message, "packet capture approved");

        // Clearing the request is visible without waiting for the TTL.
        state.set_request(None);
        assert_eq!(state.report().request, None);
    }

    #[test]
    fn startup_line_literal() {
        let (state, _now) = state_over(vec![row5()]);
        let report = state.report();
        assert_eq!(
            startup_line(&report),
            Some(
                "L4 enabled; packet capture needs approval: Allow packet capture in the Aitmproxy app"
                    .to_string()
            )
        );

        // Available: no line.
        let (state, _now) = state_over(vec![row2()]);
        assert_eq!(startup_line(&state.report()), None);

        // Disabled: no line, whatever the probe says.
        let off = PrivilegeReport {
            enabled: false,
            ..report
        };
        assert_eq!(startup_line(&off), None);
    }

    /// Plan P1b.10 (Architect's call): with `l4.enabled: false` the request is
    /// `cannot_prompt` with the L4-off literal; no progress is recorded and the
    /// report still says `enabled: false`.
    #[test]
    fn request_with_l4_off_is_cannot_prompt() {
        let now = Arc::new(AtomicU64::new(0));
        let clock_now = Arc::clone(&now);
        let state = PrivilegeState::with_prober(
            &PrivilegeConfig {
                enabled: false,
                ..cfg()
            },
            Scripted::with_enabled(false, vec![row6()]),
            Arc::new(move || clock_now.load(Ordering::SeqCst)),
        );

        let outcome = state.request();
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(outcome.outcome.as_str(), "cannot_prompt");
        assert_eq!(
            outcome.message,
            "L4 is off in this core's config (l4.enabled)"
        );
        assert!(!outcome.privilege.enabled);
        assert_eq!(outcome.privilege.request, None, "nothing was attempted");
        assert_eq!(state.report().request, None);
    }

    /// The default requester, before P1b.11/P1b.14: `cannot_prompt` carrying
    /// the row's own remedy label, recorded as a `failed` request. Row 2 is
    /// `already_available` without touching it.
    #[test]
    fn platform_requester_answers_cannot_prompt_with_the_label() {
        let (state, now) = state_over(vec![row6()]);
        now.store(300, Ordering::SeqCst);
        let outcome = state.request();
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(
            outcome.message,
            "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for \
             packet-capture permission"
        );
        assert_eq!(
            outcome.privilege.request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 300,
                message: "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for \
                          packet-capture permission"
                    .to_string(),
            })
        );

        let (state, _now) = state_over(vec![row2()]);
        let outcome = state.request();
        assert_eq!(outcome.outcome, Outcome::AlreadyAvailable);
        assert_eq!(outcome.outcome.as_str(), "already_available");
        assert_eq!(outcome.privilege.request, None);
    }

    #[test]
    fn platform_prober_matches_this_os() {
        // `new` uses the platform prober and the real clock; whatever this host
        // allows, the report names this OS and `enabled` follows the config.
        let state = PrivilegeState::new(&PrivilegeConfig {
            enabled: false,
            ..cfg()
        });
        let report = state.report();
        let expected = if cfg!(target_os = "macos") {
            Platform::Macos
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        };
        assert_eq!(report.platform, expected);
        assert!(!report.enabled);
        assert_eq!(report.capture.state_str(), "unsupported");
        assert!(report.checked_at > 1_700_000_000_000, "epoch milliseconds");
    }

    // ---- Task P1b.14: the watcher, the guard seam, the recorded hook ----

    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crate::config::L4Config;
    use crate::guard::L4Guard;
    use crate::helper::client::{HelperSession, SessionError};
    use crate::helper::proto::{encode, read_msg, Msg, PROTO};
    use crate::privilege::linux::fakes::{FakeChild, FakeSpawner};
    use crate::privilege::linux::{ChildExit, HoldCount};

    /// Generous: the machine running these may be under heavy load.
    const WAIT: Duration = Duration::from_secs(30);

    /// An acceptor that never sees a peer.
    struct NoPeer;

    impl Acceptor for NoPeer {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            Err(SessionError::Timeout)
        }
    }

    /// An acceptor that hands out one prepared session, then times out.
    struct OnePeer(Mutex<Option<HelperSession>>);

    impl Acceptor for OnePeer {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            self.0.lock().unwrap().take().ok_or(SessionError::Timeout)
        }
    }

    fn until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The helper's end of a session: acks the hello, reads the first scope
    /// set, then holds the socket open until told to close.
    fn helper_peer(mut peer: UnixStream, expect_scope: bool) -> mpsc::Sender<()> {
        let (close_tx, close_rx) = mpsc::channel::<()>();
        peer.set_read_timeout(Some(WAIT)).expect("peer timeout");
        std::thread::spawn(move || {
            let hello = read_msg(&mut peer).expect("hello");
            assert!(matches!(hello, Msg::Hello { proto: PROTO, .. }));
            peer.write_all(&encode(&Msg::HelloAck {
                proto: PROTO,
                helper_version: "0.9.9-helper".to_string(),
                caps: vec!["cap_net_raw".to_string()],
            }))
            .expect("ack");
            if expect_scope {
                let scope = read_msg(&mut peer).expect("scope set");
                assert!(matches!(scope, Msg::ScopeSet(_)));
            }
            let _ = close_rx.recv_timeout(WAIT);
            drop(peer);
        });
        close_tx
    }

    #[test]
    fn watcher_releases_hold_and_records_dismissal() {
        let (state, now) = state_over(vec![row6()]);
        now.store(1_000, Ordering::SeqCst);
        let holds = HoldCount::default();
        let hold = holds.hold();
        assert_eq!(holds.count(), 1);

        let child = FakeChild {
            ticks_left: 2,
            exit: Some(ChildExit::Exited(126)),
            stderr: "Error executing command as another user: Request dismissed\n".to_string(),
            ..FakeChild::alive(4242)
        };
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(NoPeer),
            Some(hold),
            1_000,
            true,
        );

        assert_eq!(holds.count(), 0, "the hold is released with the child");
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Dismissed,
                at: 1_000,
                message: "Approval was cancelled".to_string(),
            })
        );
        assert!(state.helper_backend().is_none());
    }

    #[test]
    fn watcher_attaches_helper_on_connect_and_detaches_on_close() {
        let (state, now) = state_over(vec![row6()]);
        let state = Arc::new(state);
        now.store(5_000, Ordering::SeqCst);
        state.set_guard(Arc::new(L4Guard::new(&L4Config::default())));
        let holds = HoldCount::default();
        let hold = holds.hold();

        let (core, peer) = UnixStream::pair().expect("socketpair");
        let close = helper_peer(peer, true);
        let session = HelperSession::from_stream(core).expect("session");
        let acceptor = OnePeer(Mutex::new(Some(session)));
        let child = FakeChild {
            exit: Some(ChildExit::Exited(0)),
            ..FakeChild::alive(4242)
        };

        let shared = Arc::clone(&state.shared);
        let watcher = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(acceptor),
                Some(hold),
                5_000,
                true,
            );
        });

        // Approved: the backend is attached, the progress says so, the hold is
        // gone, and the prober now sees a live session.
        until("the helper backend", || state.helper_backend().is_some());
        until("the approved progress", || {
            state.report().request.as_ref().map(|r| r.state) == Some(RequestState::Approved)
        });
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Approved,
                at: 5_000,
                message: "Packet capture is available through the helper".to_string(),
            })
        );
        assert_eq!(holds.count(), 0, "the hold is released on connect");
        assert!(state.shared.live_is_up());

        // The helper goes away: the slot clears, the session is no longer
        // live and the next report re-probes.
        close.send(()).expect("close");
        watcher.join().expect("watcher thread");
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.live_is_up());
        assert!(
            state.shared.lock_cache().dirty,
            "the session end forces a re-probe"
        );
    }

    #[test]
    fn watcher_without_guard_fails_the_attach() {
        let (state, now) = state_over(vec![row6()]);
        now.store(9_000, Ordering::SeqCst);
        let holds = HoldCount::default();
        let hold = holds.hold();

        let (core, peer) = UnixStream::pair().expect("socketpair");
        let _close = helper_peer(peer, false);
        let session = HelperSession::from_stream(core).expect("session");
        let child = FakeChild {
            exit: Some(ChildExit::Exited(0)),
            ..FakeChild::alive(4242)
        };
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(OnePeer(Mutex::new(Some(session)))),
            Some(hold),
            9_000,
            true,
        );

        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 9_000,
                message: "no L4 guard attached to the privilege state".to_string(),
            })
        );
        assert!(state.helper_backend().is_none());
        assert_eq!(holds.count(), 0);
    }

    /// The binding spawner binds the listener before it spawns; where no
    /// listener can be bound (off Linux here) nothing is spawned at all.
    #[test]
    fn binding_spawner_never_spawns_without_a_listener() {
        use crate::privilege::linux::{pkexec_argv, Spawner};

        let holds = HoldCount::default();
        let inner = Arc::new(FakeSpawner::new(&holds));
        let binder = BindingSpawner::new(Arc::clone(&inner) as Arc<dyn Spawner>);
        let on_linux = cfg!(target_os = "linux");
        let socket = binder.socket();
        assert_eq!(
            socket.is_some(),
            on_linux,
            "a socket location exists on Linux only"
        );
        let result = binder.spawn(&pkexec_argv(&socket.unwrap_or_default()));
        match result {
            Ok(_child) => {
                // Linux: a real bind in the runtime directory, then the spawn.
                assert!(on_linux, "a bind succeeded off Linux");
                assert_eq!(inner.argvs().len(), 1);
                assert!(binder.take_listener().is_some());
            }
            Err(err) => {
                // Off Linux there is no listener, so there is no spawn.
                assert!(!on_linux, "{err}");
                assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
                assert!(
                    inner.argvs().is_empty(),
                    "nothing is spawned without a listener"
                );
                assert!(binder.take_listener().is_none());
            }
        }
    }

    /// `after_recorded` runs after the `pending` progress is in the cache, so
    /// a watcher started there can never be overwritten by the request's own
    /// bookkeeping.
    #[test]
    fn after_recorded_runs_once_pending_is_recorded() {
        struct Pending {
            shared: Mutex<Option<Arc<Shared>>>,
            saw_pending: Arc<AtomicBool>,
        }
        impl Requester for Pending {
            fn request(
                &self,
                _cfg: &PrivilegeConfig,
                _report: &PrivilegeReport,
            ) -> (Outcome, String) {
                (Outcome::Pending, "Waiting for approval".to_string())
            }
            fn after_recorded(&self) {
                let shared = self.shared.lock().unwrap().clone().expect("shared");
                let recorded = shared.lock_cache().request.clone();
                assert_eq!(
                    recorded.map(|r| (r.state, r.message)),
                    Some((RequestState::Pending, "Waiting for approval".to_string()))
                );
                self.saw_pending.store(true, Ordering::SeqCst);
            }
        }

        let saw_pending = Arc::new(AtomicBool::new(false));
        let requester = Pending {
            shared: Mutex::new(None),
            saw_pending: Arc::clone(&saw_pending),
        };
        let (state, _now) = state_over(vec![row6()]);
        // The requester needs the state's shared half to look at the cache.
        let shared = Arc::clone(&state.shared);
        *requester.shared.lock().unwrap() = Some(shared);
        let state = state.with_requester(Box::new(requester));

        let outcome = state.request();
        assert_eq!(outcome.outcome, Outcome::Pending);
        assert!(saw_pending.load(Ordering::SeqCst), "after_recorded ran");
        assert_eq!(
            outcome.privilege.request.map(|r| r.state),
            Some(RequestState::Pending)
        );

        // The default hook is a no-op, so a requester without one still works.
        struct Plain;
        impl Requester for Plain {
            fn request(
                &self,
                _cfg: &PrivilegeConfig,
                _report: &PrivilegeReport,
            ) -> (Outcome, String) {
                (Outcome::CannotPrompt, "no".to_string())
            }
        }
        let (state, _now) = state_over(vec![row6()]);
        let state = state.with_requester(Box::new(Plain));
        assert_eq!(state.request().outcome, Outcome::CannotPrompt);
    }
    // ---- tester (privilege unit p1b): a helper that misbehaves at Hello, a
    // foreign peer at the socket -----------------------------------------------

    /// A peer that answers `Hello` with `reply` bytes verbatim, then holds the
    /// socket until the core shuts its end.
    fn garbage_peer(mut peer: UnixStream, reply: Vec<u8>) -> std::thread::JoinHandle<()> {
        peer.set_read_timeout(Some(WAIT)).expect("peer timeout");
        std::thread::spawn(move || {
            let _hello = read_msg(&mut peer).expect("hello");
            peer.write_all(&reply).expect("reply");
            let _ = read_msg(&mut peer);
        })
    }

    /// Tester: a helper that connects with the right credentials but answers
    /// garbage (an HTTP line, an unknown frame type) or another protocol
    /// version to `Hello` never becomes a backend: the request is `failed`
    /// naming the handshake and the defect, the launcher is killed, the SIGINT
    /// hold is released, the routed backend stays unwired and the prober sees
    /// no live session.
    #[test]
    fn watcher_fails_the_request_when_the_helper_answers_garbage_to_hello() {
        let version_2 = encode(&Msg::HelloAck {
            proto: 2,
            helper_version: "9.9.9".to_string(),
            caps: vec![],
        });
        let cases: [(Vec<u8>, &str); 3] = [
            (
                b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                "the packet-capture helper did not complete its handshake (frame length \
                 1213486160 exceeds",
            ),
            (
                vec![0, 0, 0, 5, 0xff, 1, 2, 3, 4],
                "the packet-capture helper did not complete its handshake (unknown message \
                 type 0xff)",
            ),
            (
                version_2,
                "the packet-capture helper did not complete its handshake (helper speaks \
                 protocol 2, this core speaks 1)",
            ),
        ];
        for (reply, want_prefix) in cases {
            let (state, now) = state_over(vec![row6()]);
            now.store(11_000, Ordering::SeqCst);
            state.set_guard(Arc::new(L4Guard::new(&L4Config::default())));
            let holds = HoldCount::default();
            let hold = holds.hold();

            let (core, peer) = UnixStream::pair().expect("socketpair");
            let peer_thread = garbage_peer(peer, reply);
            let session = HelperSession::from_stream(core).expect("session");
            let child = FakeChild {
                exit: Some(ChildExit::Exited(0)),
                ..FakeChild::alive(4242)
            };
            let killed = Arc::clone(&child.killed);

            run_watcher(
                Arc::clone(&state.shared),
                Box::new(child),
                Box::new(OnePeer(Mutex::new(Some(session)))),
                Some(hold),
                11_000,
                true,
            );

            let request = state.report().request.expect("progress recorded");
            assert_eq!(request.state, RequestState::Failed, "{want_prefix}");
            assert!(
                request.message.starts_with(want_prefix),
                "got {:?}, want prefix {want_prefix:?}",
                request.message
            );
            assert_eq!(request.at, 11_000);
            assert_eq!(killed.load(Ordering::SeqCst), 1, "the launcher is killed");
            assert_eq!(holds.count(), 0, "the hold is released");
            assert!(state.helper_backend().is_none());
            assert!(!state.shared.live_is_up());
            for word in ["sudo", "pkexec", "chmod", "setcap", "chown"] {
                assert!(!request.message.contains(word), "{}", request.message);
            }
            peer_thread.join().expect("peer");
        }
    }

    // ---- fix task C 2026-11-01 (p1b panel 2): C4 cancel on a held Ctrl-C,
    // C5 the watcher's unwind guard ----------------------------------------

    /// Plan P1b.14 `held_ctrl_c_alone_cancels_the_prompt` (panel 2; spec §5.5
    /// as amended): a Ctrl-C that reaches the core alone must still end the
    /// prompt. With a launcher child alive and the hold at 1,
    /// `cancel_prompt()` sends that child SIGINT (not SIGKILL, so the §5.5
    /// table records `dismissed`); the watcher then records `dismissed`,
    /// "Approval was cancelled", and the hold is 0. With no child it changes
    /// nothing, before the request and after it. A directly started
    /// file-caps helper is not a prompt and is never signalled.
    #[test]
    fn held_ctrl_c_alone_cancels_the_prompt() {
        let (state, now) = state_over(vec![row6()]);
        now.store(6_000, Ordering::SeqCst);
        let holds = HoldCount::default();

        // No child yet: a no-op.
        state.cancel_prompt();
        assert_eq!(state.report().request, None);

        let child = FakeChild::alive(4242);
        let signals = Arc::clone(&child.signals);
        let killed = Arc::clone(&child.killed);
        let hold = holds.hold();
        let shared = Arc::clone(&state.shared);
        let watcher = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(NoPeer),
                Some(hold),
                6_000,
                true,
            );
        });
        until("the launcher to be registered as the prompt", || {
            state.shared.prompt_child().is_some()
        });
        assert_eq!(holds.count(), 1, "the prompt is up");

        cancel_until_signalled(&state, &signals);
        watcher.join().expect("the watcher ended the request");
        assert_eq!(
            *signals.lock().unwrap(),
            vec![crate::privilege::linux::SIGINT],
            "the child got exactly one SIGINT"
        );
        assert_eq!(
            killed.load(Ordering::SeqCst),
            0,
            "never SIGKILL for a cancel"
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Dismissed,
                at: 6_000,
                message: "Approval was cancelled".to_string(),
            })
        );
        assert_eq!(holds.count(), 0, "the hold is released with the child");
        assert!(
            state.shared.prompt_child().is_none(),
            "no prompt left to cancel"
        );

        // After the request: a no-op again.
        state.cancel_prompt();
        assert_eq!(
            state.report().request.map(|r| r.state),
            Some(RequestState::Dismissed)
        );

        // A direct (launcher-less) start is not a prompt: never registered,
        // never signalled, no progress written.
        let (state, _now) = state_over(vec![row6()]);
        let child = FakeChild {
            ticks_left: 3,
            exit: Some(ChildExit::Exited(0)),
            ..FakeChild::alive(4243)
        };
        let signals = Arc::clone(&child.signals);
        let registered = Arc::new(AtomicBool::new(false));
        struct SeesPrompt(Arc<Shared>, Arc<AtomicBool>);
        impl Acceptor for SeesPrompt {
            fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
                if self.0.prompt_child().is_some() {
                    self.1.store(true, Ordering::SeqCst);
                }
                Err(SessionError::Timeout)
            }
        }
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(SeesPrompt(
                Arc::clone(&state.shared),
                Arc::clone(&registered),
            )),
            None,
            0,
            false,
        );
        assert!(
            !registered.load(Ordering::SeqCst),
            "a direct start is no prompt"
        );
        state.cancel_prompt();
        assert!(signals.lock().unwrap().is_empty());
        assert_eq!(state.report().request, None);
    }

    /// A child whose `try_wait` panics (a broken `waitpid` wrapper, a bug).
    /// `kill` only counts.
    #[derive(Default)]
    struct PanicsOnWait {
        killed: Arc<AtomicUsize>,
    }

    impl Child for PanicsOnWait {
        fn id(&self) -> u32 {
            4244
        }
        fn try_wait(&mut self) -> std::io::Result<Option<ChildExit>> {
            panic!("try_wait blew up");
        }
        fn kill(&mut self) {
            self.killed.fetch_add(1, Ordering::SeqCst);
        }
        fn interrupt(&mut self) {}
        fn stderr_tail(&mut self) -> String {
            String::new()
        }
    }

    /// Plan P1b.14 `watcher_panic_releases_hold_and_ends_pending` (panel 2;
    /// spec §5.5 as amended): the watcher thread carries an unwind guard. A
    /// panic mid-watch leaves the request `failed` ("The packet-capture
    /// request ended unexpectedly"), never `pending`; the hold is 0, the
    /// prompt slot and the `watching` flag are clear, and the next
    /// `request()` is accepted (not answered `pending`). A request that was
    /// not pending is left as it was. Panel 3 (D2): the unwinding watcher
    /// also kills its child, best effort, so no launcher outlives the watch
    /// that was its only keeper.
    #[test]
    fn watcher_panic_releases_hold_and_ends_pending() {
        let (state, now) = state_over(vec![row6()]);
        now.store(7_000, Ordering::SeqCst);
        state.set_request(Some(RequestProgress {
            state: RequestState::Pending,
            at: 6_900,
            message: msg::PENDING_DIALOG.to_string(),
        }));
        let holds = HoldCount::default();
        let hold = holds.hold();
        let shared = Arc::clone(&state.shared);
        let child = PanicsOnWait::default();
        let killed = Arc::clone(&child.killed);
        let crashed = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(NoPeer),
                Some(hold),
                7_000,
                true,
            );
        })
        .join();
        assert!(crashed.is_err(), "the watcher panicked");
        assert_eq!(
            killed.load(Ordering::SeqCst),
            1,
            "the unwinding watcher kills its child once"
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 7_000,
                message: "The packet-capture request ended unexpectedly".to_string(),
            })
        );
        assert_eq!(holds.count(), 0, "the hold is released");
        assert!(!state.shared.watching(), "no watcher is running");
        assert!(state.shared.prompt_child().is_none());
        let outcome = state.request();
        assert_ne!(
            outcome.outcome,
            Outcome::Pending,
            "a new request is accepted"
        );

        // Not pending (already dismissed): untouched by the guard.
        let (state, now) = state_over(vec![row6()]);
        now.store(8_000, Ordering::SeqCst);
        let dismissed = RequestProgress {
            state: RequestState::Dismissed,
            at: 7_900,
            message: msg::CANCELLED.to_string(),
        };
        state.set_request(Some(dismissed.clone()));
        let shared = Arc::clone(&state.shared);
        let hold = holds.hold();
        let crashed = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(PanicsOnWait::default()),
                Box::new(NoPeer),
                Some(hold),
                8_000,
                true,
            );
        })
        .join();
        assert!(crashed.is_err());
        assert_eq!(state.report().request, Some(dismissed));
        assert_eq!(holds.count(), 0);
    }

    // ---- tester, fix-C range (p1b panel 2): the S1 ordering on the accept-errors
    // arm, the unwind guard's ordering, a serving helper is never a cancel target --

    /// What the state looks like at one instant: the request progress, the
    /// hold count, whether a prompt child is registered, and `watching`.
    type Snapshot = (Option<RequestState>, usize, bool, bool);

    /// An acceptor that fails every `accept` and, when dropped, records a
    /// [`Snapshot`] of the state at that instant.
    struct BrokenDropWatch {
        shared: Arc<Shared>,
        holds: HoldCount,
        at_drop: Arc<Mutex<Option<Snapshot>>>,
    }

    impl Acceptor for BrokenDropWatch {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            Err(SessionError::Io("accept: EBADF".to_string()))
        }
    }

    impl Drop for BrokenDropWatch {
        fn drop(&mut self) {
            let progress = self.shared.lock_cache().request.as_ref().map(|r| r.state);
            *self.at_drop.lock().unwrap() = Some((
                progress,
                self.holds.count(),
                self.shared.prompt_child().is_some(),
                self.shared.watching(),
            ));
        }
    }

    /// Tester (C5/C11): the one `end_request` epilogue keeps the S1 ordering
    /// on the accept-errors arm too, which no earlier test pinned: when the
    /// listener has failed `ACCEPT_ERRORS_MAX` times the acceptor (and its
    /// socket path) is dropped **before** the `failed` row is written, and by
    /// then the hold is released and the child is no longer a cancel target.
    /// The child is killed exactly once (SIGKILL, never SIGINT: this is not a
    /// cancel).
    #[test]
    fn accept_errors_arm_drops_the_acceptor_before_the_failed_row() {
        let (state, now) = state_over(vec![row6()]);
        now.store(13_000, Ordering::SeqCst);
        // As `start_watch_with` does before the thread starts.
        state.shared.start_watching();
        let holds = HoldCount::default();
        let at_drop = Arc::new(Mutex::new(None));
        let child = FakeChild::alive(4242);
        let signals = Arc::clone(&child.signals);
        let (done_tx, done_rx) = mpsc::channel();
        let shared = Arc::clone(&state.shared);
        let acceptor = BrokenDropWatch {
            shared: Arc::clone(&state.shared),
            holds: holds.clone(),
            at_drop: Arc::clone(&at_drop),
        };
        let hold = holds.hold();
        std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(acceptor),
                Some(hold),
                13_000,
                true,
            );
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(WAIT)
            .expect("the watcher ended after the accept errors");
        assert_eq!(
            *at_drop.lock().unwrap(),
            Some((None, 0, false, true)),
            "at the acceptor's drop: no terminal row yet, hold released, prompt \
             unregistered, the watcher still marked running"
        );
        assert_eq!(
            *signals.lock().unwrap(),
            vec![9],
            "killed once, never interrupted"
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 13_000,
                message: "The packet-capture helper socket failed (helper socket error: accept: \
                          EBADF)"
                    .to_string(),
            })
        );
        assert!(!state.shared.watching());
        assert!(state.shared.prompt_child().is_none());
        state.cancel_prompt();
        assert_eq!(
            *signals.lock().unwrap(),
            vec![9],
            "a cancel after the end reaches no child"
        );
    }

    /// Tester (C5): the unwind guard keeps the S1 ordering on the panic path
    /// as well: the acceptor is dropped while the request still reads
    /// `pending` (the `failed` row comes after), with the hold already
    /// released and the prompt child already unregistered; `watching` is the
    /// last thing cleared. A direct (launcher-less) start that panics writes
    /// no request progress at all and still clears `watching`.
    #[test]
    fn watcher_panic_drops_the_acceptor_before_the_failed_row() {
        let (state, now) = state_over(vec![row6()]);
        now.store(14_000, Ordering::SeqCst);
        state.set_request(Some(RequestProgress {
            state: RequestState::Pending,
            at: 13_900,
            message: msg::PENDING_DIALOG.to_string(),
        }));
        state.shared.start_watching();
        let holds = HoldCount::default();
        let at_drop = Arc::new(Mutex::new(None));
        let acceptor = BrokenDropWatch {
            shared: Arc::clone(&state.shared),
            holds: holds.clone(),
            at_drop: Arc::clone(&at_drop),
        };
        let hold = holds.hold();
        let shared = Arc::clone(&state.shared);
        let crashed = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(PanicsOnWait::default()),
                Box::new(acceptor),
                Some(hold),
                14_000,
                true,
            );
        })
        .join();
        assert!(crashed.is_err(), "the watcher panicked");
        assert_eq!(
            *at_drop.lock().unwrap(),
            Some((Some(RequestState::Pending), 0, false, true)),
            "at the acceptor's drop: still pending, hold released, prompt \
             unregistered, watching not yet cleared"
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 14_000,
                message: msg::ENDED_UNEXPECTEDLY.to_string(),
            })
        );
        assert_eq!(
            msg::ENDED_UNEXPECTEDLY,
            "The packet-capture request ended unexpectedly"
        );
        assert!(!state.shared.watching());

        // A direct start (no hold, no progress) that panics: nothing is
        // written as request progress, the slot stays empty, the flag clears.
        let (state, _now) = state_over(vec![row6()]);
        state.shared.start_watching();
        let at_drop = Arc::new(Mutex::new(None));
        let acceptor = BrokenDropWatch {
            shared: Arc::clone(&state.shared),
            holds: HoldCount::default(),
            at_drop: Arc::clone(&at_drop),
        };
        let shared = Arc::clone(&state.shared);
        let crashed = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(PanicsOnWait::default()),
                Box::new(acceptor),
                None,
                0,
                false,
            );
        })
        .join();
        assert!(crashed.is_err());
        assert_eq!(*at_drop.lock().unwrap(), Some((None, 0, false, true)));
        assert_eq!(state.report().request, None, "a direct start writes no row");
        assert!(!state.shared.watching());
        assert!(state.shared.prompt_child().is_none());
    }

    /// Tester (C4): once the helper has connected the child is no longer a
    /// prompt. `cancel_prompt()` during the serving session signals nothing
    /// (the live helper must never get the Ctrl-C meant for a prompt), the
    /// backend stays live, and the session's own end still reaps the child
    /// without a kill.
    #[test]
    fn cancel_prompt_never_signals_a_serving_helper() {
        let (state, now) = state_over(vec![row6()]);
        let state = Arc::new(state);
        now.store(15_000, Ordering::SeqCst);
        state.set_guard(Arc::new(L4Guard::new(&L4Config::default())));
        let holds = HoldCount::default();
        let hold = holds.hold();

        let (core, peer) = UnixStream::pair().expect("socketpair");
        let close = helper_peer(peer, true);
        let session = HelperSession::from_stream(core).expect("session");
        let child = FakeChild {
            exit: Some(ChildExit::Exited(0)),
            ..FakeChild::alive(4242)
        };
        let signals = Arc::clone(&child.signals);
        let shared = Arc::clone(&state.shared);
        let watcher = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(OnePeer(Mutex::new(Some(session)))),
                Some(hold),
                15_000,
                true,
            );
        });
        until("the helper backend", || state.helper_backend().is_some());
        assert_eq!(holds.count(), 0, "the hold went with the connect");
        assert!(
            state.shared.prompt_child().is_none(),
            "a connected helper is not a prompt"
        );
        state.cancel_prompt();
        state.cancel_prompt();
        assert!(
            signals.lock().unwrap().is_empty(),
            "no signal reaches a serving helper"
        );
        assert!(state.shared.live_is_up(), "the session is untouched");

        close.send(()).expect("close");
        watcher.join().expect("watcher thread");
        assert!(signals.lock().unwrap().is_empty(), "reaped, never killed");
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.watching());
    }

    /// Tester: a connection from a process other than the spawned launcher
    /// (the peer uid or pid check fails) is dropped and the watcher keeps
    /// waiting; the request's end is still decided by the launcher's exit.
    /// Here the launcher is dismissed after the foreign peers came and went.
    #[test]
    fn watcher_drops_a_foreign_peer_and_keeps_watching() {
        struct ForeignThenNobody(Arc<AtomicUsize>);
        impl Acceptor for ForeignThenNobody {
            fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
                match self.0.fetch_add(1, Ordering::SeqCst) {
                    0 => Err(SessionError::PeerPid(999)),
                    1 => Err(SessionError::PeerUid(0)),
                    _ => Err(SessionError::Timeout),
                }
            }
        }

        let (state, now) = state_over(vec![row6()]);
        now.store(2_000, Ordering::SeqCst);
        let holds = HoldCount::default();
        let hold = holds.hold();
        let accepts = Arc::new(AtomicUsize::new(0));
        let child = FakeChild {
            ticks_left: 3,
            exit: Some(ChildExit::Exited(126)),
            stderr: "Error executing command as another user: Request dismissed\n".to_string(),
            ..FakeChild::alive(4242)
        };
        let killed = Arc::clone(&child.killed);

        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(ForeignThenNobody(Arc::clone(&accepts))),
            Some(hold),
            2_000,
            true,
        );

        assert!(
            accepts.load(Ordering::SeqCst) >= 4,
            "the foreign peers did not end the watch: {} accept slices",
            accepts.load(Ordering::SeqCst)
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Dismissed,
                at: 2_000,
                message: "Approval was cancelled".to_string(),
            })
        );
        assert_eq!(
            killed.load(Ordering::SeqCst),
            0,
            "the child ended on its own"
        );
        assert_eq!(holds.count(), 0);
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.live_is_up());
    }

    // ---- fix task 2026-11-01: I1 (single-flight probe), I3 (version_mismatch) ----

    /// A prober that blocks in `gather` until its gate opens, and says when it
    /// entered; once opened it answers at once from then on.
    struct Blocking {
        entered: mpsc::Sender<()>,
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
        calls: Arc<AtomicU64>,
    }

    impl Prober for Blocking {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered.send(());
            let (open, changed) = &*self.gate;
            let mut open = open.lock().unwrap();
            while !*open {
                let (next, _) = changed.wait_timeout(open, WAIT).unwrap();
                open = next;
            }
            ProbeInputs {
                enabled: true,
                platform: Platform::Macos,
                mac: Some(row6()),
                linux: None,
                request: request.cloned(),
                now_ms: 0,
            }
        }
    }

    /// I1: `report()` must not hold the cache while the platform prober runs
    /// (it spawns subprocesses). While one caller's probe is blocked, a second
    /// `report()` returns the report in hand, the progress writers do not wait,
    /// and the second caller starts no probe of its own (single flight).
    #[test]
    fn report_does_not_hold_the_cache_while_the_prober_runs() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let calls = Arc::new(AtomicU64::new(0));
        let state = Arc::new(PrivilegeState::with_prober(
            &cfg(),
            Box::new(Blocking {
                entered: entered_tx,
                gate: Arc::clone(&gate),
                calls: Arc::clone(&calls),
            }),
            Arc::new(|| 0),
        ));

        let first = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || state.report())
        };
        entered_rx
            .recv_timeout(WAIT)
            .expect("the first probe started");

        // A second report while the first probe is blocked.
        let (done_tx, done_rx) = mpsc::channel();
        {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let _ = done_tx.send(state.report());
            });
        }
        let second = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a second report() returned while the first probe was still blocked");
        assert_eq!(second.request, None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second caller started no probe of its own"
        );

        // The progress writers do not block behind the probe either.
        let (wrote_tx, wrote_rx) = mpsc::channel();
        {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                state.set_request(Some(RequestProgress {
                    state: RequestState::Pending,
                    at: 1,
                    message: "Waiting".to_string(),
                }));
                state.shared.mark_dirty();
                let _ = wrote_tx.send(());
            });
        }
        wrote_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("set_request/mark_dirty returned while the probe was blocked");

        // Release: the first report lands with the probe's result and the
        // request recorded meanwhile; the probe ran once for all of this.
        {
            let (open, changed) = &*gate;
            *open.lock().unwrap() = true;
            changed.notify_all();
        }
        let first = first.join().expect("first report");
        assert_eq!(first.capture.state_str(), "needs_approval");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The request written during the probe is on the next report, and the
        // dirty mark it left makes that report probe again (now unblocked).
        let next = state.report();
        assert_eq!(
            next.request.as_ref().map(|r| r.state),
            Some(RequestState::Pending)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// I1: one `request()` gathers at most once: the report in hand serves the
    /// pre-checks and the reply is derived under the recorded progress.
    #[test]
    fn request_probes_at_most_once() {
        let (prober, calls) = Scripted::counted(vec![row6()]);
        let state = PrivilegeState::with_prober(&cfg(), prober, Arc::new(|| 300));
        let outcome = state.request();
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh state's request() probes exactly once"
        );
        // The reply still carries the progress the request recorded: row 6's
        // remedy label, as `failed`.
        assert_eq!(
            outcome.privilege.request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 300,
                message: "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for \
                          packet-capture permission"
                    .to_string(),
            })
        );
        assert_eq!(outcome.privilege.helper.status, HelperStatus::NotInstalled);
    }

    /// A Linux prober over the state's own shared half: `session_connected`
    /// and the last session failure come from the watcher, as in production.
    struct LinuxOverShared(Arc<Mutex<Option<Arc<Shared>>>>);

    impl Prober for LinuxOverShared {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            let shared = self.0.lock().unwrap().clone().expect("shared");
            ProbeInputs {
                enabled: true,
                platform: Platform::Linux,
                mac: None,
                linux: Some(LinuxInputs {
                    cap_net_raw: false,
                    cap_net_admin: false,
                    session_connected: shared.live_is_up(),
                    helper: Some(HelperCandidate {
                        path: PathBuf::from(crate::privilege::contract::LINUX_HELPER_PATH),
                        at_policy_path: true,
                        root_owned_chain: true,
                        file_caps_net_raw: false,
                    }),
                    policy_file_present: true,
                    pkexec_present: true,
                    prompt_possible: true,
                    last_session_error: shared.session_failure(),
                }),
                request: request.cloned(),
                now_ms: 0,
            }
        }
    }

    fn linux_state_over_shared() -> Arc<PrivilegeState> {
        let slot = Arc::new(Mutex::new(None));
        let prober = LinuxOverShared(Arc::clone(&slot));
        let state = Arc::new(PrivilegeState::with_prober(
            &cfg(),
            Box::new(prober),
            Arc::new(|| 11_000),
        ));
        // The prober reads the state's own shared half.
        *slot.lock().unwrap() = Some(Arc::clone(&state.shared));
        state.set_guard(Arc::new(L4Guard::new(&L4Config::default())));
        state
    }

    /// I3 (spec §5.2): a helper that answers `Hello` with another protocol
    /// version fails the request **and** the next report says
    /// `helper.status: version_mismatch` naming both protocol numbers; a
    /// malformed handshake reads `unknown` with the defect; a session that then
    /// attaches clears it (`running`), and after it ends the row is `installed`.
    #[test]
    fn watcher_reports_version_mismatch_until_a_session_attaches() {
        let state = linux_state_over_shared();
        let holds = HoldCount::default();

        // Protocol 2.
        let (core, peer) = UnixStream::pair().expect("socketpair");
        let peer_thread = garbage_peer(
            peer,
            encode(&Msg::HelloAck {
                proto: 2,
                helper_version: "9.9.9".to_string(),
                caps: vec![],
            }),
        );
        let session = HelperSession::from_stream(core).expect("session");
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(FakeChild {
                exit: Some(ChildExit::Exited(0)),
                ..FakeChild::alive(4242)
            }),
            Box::new(OnePeer(Mutex::new(Some(session)))),
            Some(holds.hold()),
            11_000,
            true,
        );
        peer_thread.join().expect("peer");
        let report = state.report();
        assert_eq!(report.helper.status, HelperStatus::VersionMismatch);
        assert_eq!(report.helper.status.as_str(), "version_mismatch");
        assert_eq!(
            report.helper.detail.as_deref(),
            Some("helper speaks protocol 2, this core speaks 1")
        );
        assert_eq!(
            report.request.as_ref().map(|r| r.state),
            Some(RequestState::Failed)
        );
        assert!(!holds.is_held());

        // Garbage: the defect is carried and the status is `unknown` (spec
        // §5.2 as amended: only a named protocol is a version mismatch).
        let (core, peer) = UnixStream::pair().expect("socketpair");
        let peer_thread = garbage_peer(peer, vec![0, 0, 0, 5, 0xff, 1, 2, 3, 4]);
        let session = HelperSession::from_stream(core).expect("session");
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(FakeChild {
                exit: Some(ChildExit::Exited(0)),
                ..FakeChild::alive(4242)
            }),
            Box::new(OnePeer(Mutex::new(Some(session)))),
            Some(holds.hold()),
            11_000,
            true,
        );
        peer_thread.join().expect("peer");
        let report = state.report();
        assert_eq!(report.helper.status, HelperStatus::Unknown);
        assert_eq!(report.helper.status.as_str(), "unknown");
        assert_eq!(
            report.helper.detail.as_deref(),
            Some("helper did not speak protocol 1 (unknown message type 0xff)")
        );

        // A good session attaches: the failure is cleared and the row is
        // `running`; once it ends, `installed` (nothing remembered).
        let (core, peer) = UnixStream::pair().expect("socketpair");
        let close = helper_peer(peer, true);
        let session = HelperSession::from_stream(core).expect("session");
        let shared = Arc::clone(&state.shared);
        let hold = holds.hold();
        let watcher = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(FakeChild {
                    exit: Some(ChildExit::Exited(0)),
                    ..FakeChild::alive(4242)
                }),
                Box::new(OnePeer(Mutex::new(Some(session)))),
                Some(hold),
                11_000,
                true,
            );
        });
        until("the attached session", || state.shared.live_is_up());
        let report = state.report();
        assert_eq!(report.helper.status, HelperStatus::Running);
        assert_eq!(report.helper.detail, None);
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });
        close.send(()).expect("close");
        watcher.join().expect("watcher");
        let report = state.report();
        assert_eq!(report.helper.status, HelperStatus::Installed);
        assert_eq!(report.helper.detail, None);
    }

    // ---- fix task 2026-11-01: S1 (listener gone before the terminal row), S2 ----

    /// An acceptor that never sees a peer and, when dropped, records the
    /// request progress as it stands and raises a flag.
    struct DropWatch {
        shared: Arc<Shared>,
        dropped: Arc<AtomicBool>,
        progress_at_drop: Arc<Mutex<Option<Option<RequestState>>>>,
    }

    impl Acceptor for DropWatch {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            Err(SessionError::Timeout)
        }
    }

    impl Drop for DropWatch {
        fn drop(&mut self) {
            let state = self.shared.lock_cache().request.as_ref().map(|r| r.state);
            *self.progress_at_drop.lock().unwrap() = Some(state);
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    /// S1: in the `Ended` arm the listener (which unlinks the socket path on
    /// drop) is gone **before** the terminal progress row is written and
    /// before the child is reaped, so a re-request that binds the same path
    /// can never have it unlinked under its feet by the old listener.
    #[test]
    fn watcher_drops_the_acceptor_before_the_terminal_row_and_the_reap() {
        // Dismissed by exit: the acceptor is dropped while the progress is
        // still the one before the end (none here).
        let (state, now) = state_over(vec![row6()]);
        now.store(3_000, Ordering::SeqCst);
        let dropped = Arc::new(AtomicBool::new(false));
        let progress_at_drop = Arc::new(Mutex::new(None));
        let acceptor = DropWatch {
            shared: Arc::clone(&state.shared),
            dropped: Arc::clone(&dropped),
            progress_at_drop: Arc::clone(&progress_at_drop),
        };
        let child = FakeChild {
            ticks_left: 1,
            exit: Some(ChildExit::Exited(126)),
            stderr: "Request dismissed".to_string(),
            ..FakeChild::alive(4242)
        };
        let holds = HoldCount::default();
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(acceptor),
            Some(holds.hold()),
            3_000,
            true,
        );
        assert_eq!(
            *progress_at_drop.lock().unwrap(),
            Some(None),
            "the acceptor was dropped before the dismissed row was recorded"
        );
        assert_eq!(
            state.report().request.map(|r| r.state),
            Some(RequestState::Dismissed)
        );

        // Timed out: the acceptor is dropped before the reap's `try_wait`.
        struct Reapable {
            killed: bool,
            dropped: Arc<AtomicBool>,
            dropped_at_reap: Arc<AtomicBool>,
        }
        impl Child for Reapable {
            fn id(&self) -> u32 {
                7
            }
            fn try_wait(&mut self) -> std::io::Result<Option<ChildExit>> {
                if self.killed {
                    self.dropped_at_reap
                        .store(self.dropped.load(Ordering::SeqCst), Ordering::SeqCst);
                    return Ok(Some(ChildExit::Signaled(9)));
                }
                Ok(None)
            }
            fn kill(&mut self) {
                self.killed = true;
            }
            fn interrupt(&mut self) {}
            fn stderr_tail(&mut self) -> String {
                String::new()
            }
        }
        let (state, now) = state_over(vec![row6()]);
        now.store(1_000_000, Ordering::SeqCst);
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_at_reap = Arc::new(AtomicBool::new(false));
        let acceptor = DropWatch {
            shared: Arc::clone(&state.shared),
            dropped: Arc::clone(&dropped),
            progress_at_drop: Arc::new(Mutex::new(None)),
        };
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(Reapable {
                killed: false,
                dropped: Arc::clone(&dropped),
                dropped_at_reap: Arc::clone(&dropped_at_reap),
            }),
            Box::new(acceptor),
            Some(holds.hold()),
            0,
            true,
        );
        assert!(
            dropped_at_reap.load(Ordering::SeqCst),
            "the acceptor was dropped before the killed child was reaped"
        );
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 1_000_000,
                message: "No approval within 5 minutes".to_string(),
            })
        );
        assert!(!holds.is_held());
    }

    /// S2: the direct (launcher-less) start is decided by one pure function:
    /// a serving process, no process capability, and a helper whose `probe`
    /// reports `CAP_NET_RAW` **and** whose path chain only root could have
    /// written. A user-writable helper with file caps is never started.
    #[test]
    fn direct_start_requires_a_root_owned_file_caps_helper() {
        let trusted = LinuxInputs {
            helper: Some(HelperCandidate {
                path: PathBuf::from("/opt/aitm/aitm-l4-helper"),
                at_policy_path: false,
                root_owned_chain: true,
                file_caps_net_raw: true,
            }),
            ..linux_nothing()
        };
        assert_eq!(
            direct_start_target(ProcessLifetime::Serving, &trusted),
            Some(PathBuf::from("/opt/aitm/aitm-l4-helper"))
        );
        assert_eq!(
            direct_start_target(ProcessLifetime::OneShot, &trusted),
            None
        );

        let user_writable = LinuxInputs {
            helper: Some(HelperCandidate {
                root_owned_chain: false,
                ..trusted.helper.clone().unwrap()
            }),
            ..linux_nothing()
        };
        assert_eq!(
            direct_start_target(ProcessLifetime::Serving, &user_writable),
            None,
            "file caps on a path root does not own are not trusted"
        );

        let no_caps = LinuxInputs {
            helper: Some(HelperCandidate {
                file_caps_net_raw: false,
                ..trusted.helper.clone().unwrap()
            }),
            ..linux_nothing()
        };
        assert_eq!(
            direct_start_target(ProcessLifetime::Serving, &no_caps),
            None
        );

        let in_process = LinuxInputs {
            cap_net_raw: true,
            ..trusted.clone()
        };
        assert_eq!(
            direct_start_target(ProcessLifetime::Serving, &in_process),
            None,
            "a core with CAP_NET_RAW needs no helper"
        );
        assert_eq!(
            direct_start_target(ProcessLifetime::Serving, &linux_nothing()),
            None
        );
    }

    fn linux_nothing() -> LinuxInputs {
        LinuxInputs {
            cap_net_raw: false,
            cap_net_admin: false,
            session_connected: false,
            helper: None,
            policy_file_present: false,
            pkexec_present: false,
            prompt_possible: false,
            last_session_error: None,
        }
    }

    // ---- fix task 2026-11-01: Q4 (one slot), Q6 (seams), Q7 (no socket), Q10 ----

    /// A helper-slot backend whose liveness the test flips.
    struct Flippable {
        live: AtomicBool,
    }

    impl CaptureInjectBackend for Flippable {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn crate::backend::CaptureSource>, crate::backend::L4Error> {
            Err(crate::backend::L4Error::Unavailable("test".to_string()))
        }
        fn inject(&self, _iface: &str, _bytes: &[u8]) -> Result<(), crate::backend::L4Error> {
            Ok(())
        }
    }

    impl LiveBackend for Flippable {
        fn is_live(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
    }

    /// Q4: the helper backend lives in **one** slot: what `helper_backend()`
    /// hands the router is the same object whose liveness the prober reads.
    #[test]
    fn helper_backend_has_one_slot_read_by_router_and_prober() {
        let (state, _now) = state_over(vec![row6()]);
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.live_is_up());

        let backend = Arc::new(Flippable {
            live: AtomicBool::new(true),
        });
        state.set_helper_backend(Some(Arc::clone(&backend) as Arc<dyn LiveBackend>));
        assert!(state.helper_backend().is_some());
        assert!(state.shared.live_is_up());

        // Same object: flipping its liveness is what the prober sees, and the
        // slot still holds it until the watcher clears it.
        backend.live.store(false, Ordering::SeqCst);
        assert!(!state.shared.live_is_up());
        assert!(state.helper_backend().is_some());

        state.set_helper_backend(None);
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.live_is_up());
    }

    /// A requester that answers nothing but lends its spawner to the direct
    /// start (Q6: the seam is reachable in a production build).
    struct SpawnerOnly(Arc<FakeSpawner>);

    impl Requester for SpawnerOnly {
        fn request(&self, _cfg: &PrivilegeConfig, _report: &PrivilegeReport) -> (Outcome, String) {
            (Outcome::CannotPrompt, "no".to_string())
        }
        fn spawner(&self) -> Arc<dyn Spawner> {
            Arc::clone(&self.0) as Arc<dyn Spawner>
        }
    }

    /// Q6 / S2 (the Tester's lazy-start unit test): on the file-caps row the
    /// first `helper_backend()` starts the helper directly through the
    /// requester's spawner with exactly `direct_helper_argv`; a user-writable
    /// file-caps helper is never spawned; a one-shot process never spawns.
    #[test]
    fn lazy_start_spawns_only_a_root_owned_file_caps_helper_through_the_seam() {
        let trusted = HelperCandidate {
            path: PathBuf::from("/opt/aitm/aitm-l4-helper"),
            at_policy_path: false,
            root_owned_chain: true,
            file_caps_net_raw: true,
        };
        let run = |lifetime: ProcessLifetime, helper: HelperCandidate| {
            let holds = HoldCount::default();
            let spawner = Arc::new(FakeSpawner::new(&holds));
            let (state, _now) = state_over(vec![row6()]);
            let state = PrivilegeState {
                cfg: PrivilegeConfig { lifetime, ..cfg() },
                ..state
            }
            .with_requester(Box::new(SpawnerOnly(Arc::clone(&spawner))));
            *lock(&state.shared.last_linux) = Some(LinuxInputs {
                helper: Some(helper),
                ..linux_nothing()
            });
            let backend = state.helper_backend();
            (backend.is_some(), spawner.argvs(), holds.count())
        };

        // Untrusted: nothing is spawned, on every OS.
        let (attached, argvs, holds) = run(
            ProcessLifetime::Serving,
            HelperCandidate {
                root_owned_chain: false,
                ..trusted.clone()
            },
        );
        assert!(!attached);
        assert!(argvs.is_empty(), "a user-writable helper is never started");
        assert_eq!(holds, 0);

        // One-shot: nothing is spawned.
        let (attached, argvs, _) = run(ProcessLifetime::OneShot, trusted.clone());
        assert!(!attached);
        assert!(argvs.is_empty());

        // Trusted, serving: the direct argv through the seam (Linux binds a
        // real listener first; off Linux there is no socket location, so the
        // refusal comes before any spawn).
        let (attached, argvs, holds) = run(ProcessLifetime::Serving, trusted);
        assert!(!attached, "the fake child never connects");
        assert_eq!(holds, 0, "a direct start takes no SIGINT hold");
        if cfg!(target_os = "linux") {
            assert_eq!(argvs.len(), 1, "{argvs:?}");
            let argv = &argvs[0];
            assert_eq!(
                argv[0],
                std::ffi::OsString::from("/opt/aitm/aitm-l4-helper")
            );
            assert_eq!(argv[1], std::ffi::OsString::from("serve"));
            assert_eq!(argv[2], std::ffi::OsString::from("--connect"));
            assert_eq!(
                argv,
                &direct_helper_argv(
                    std::path::Path::new("/opt/aitm/aitm-l4-helper"),
                    std::path::Path::new(&argv[3])
                )
            );
        } else {
            assert!(argvs.is_empty(), "no socket location, no spawn: {argvs:?}");
        }
    }

    /// Q7: with no socket location (off Linux) the Linux request refuses
    /// before `request_linux`, so no argv ever carries an empty socket path
    /// and nothing is spawned.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_request_refuses_without_a_socket_location() {
        let holds = HoldCount::default();
        let spawner = Arc::new(FakeSpawner::new(&holds));
        let requester = PlatformRequester {
            shared: Shared::new(Arc::new(|| 0)),
            spawner: Arc::clone(&spawner) as Arc<dyn Spawner>,
            pending: Mutex::new(None),
        };
        let (outcome, message) = requester.linux_request(&cfg());
        assert_eq!(outcome, Outcome::CannotPrompt);
        assert_eq!(
            message,
            "The packet-capture helper could not be started (no socket directory on this \
             platform)"
        );
        assert!(spawner.argvs().is_empty());
        assert_eq!(holds.count(), 0);
        assert!(
            BindingSpawner::new(Arc::clone(&spawner) as Arc<dyn Spawner>)
                .socket()
                .is_none()
        );
    }

    /// Q10: a listener that keeps failing `accept` (not a timeout, not a
    /// foreign peer) does not spin forever: after `ACCEPT_ERRORS_MAX`
    /// consecutive errors the watch ends `failed`, the child is killed once,
    /// the hold is released. A timeout in between resets the count.
    #[test]
    fn watcher_ends_the_request_after_consecutive_accept_errors() {
        struct Broken(Arc<AtomicUsize>);
        impl Acceptor for Broken {
            fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(SessionError::Io("accept: EBADF".to_string()))
            }
        }
        let (state, now) = state_over(vec![row6()]);
        now.store(4_000, Ordering::SeqCst);
        let accepts = Arc::new(AtomicUsize::new(0));
        let child = FakeChild::alive(4242);
        let killed = Arc::clone(&child.killed);
        let holds = HoldCount::default();
        let hold = holds.hold();
        let shared = Arc::clone(&state.shared);
        let accepts_in = Arc::clone(&accepts);
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(child),
                Box::new(Broken(accepts_in)),
                Some(hold),
                4_000,
                true,
            );
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(WAIT)
            .expect("the watcher ended instead of spinning on accept errors");
        assert_eq!(accepts.load(Ordering::SeqCst), ACCEPT_ERRORS_MAX);
        assert_eq!(killed.load(Ordering::SeqCst), 1, "the child is killed once");
        assert!(!holds.is_held());
        assert_eq!(
            state.report().request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 4_000,
                message: "The packet-capture helper socket failed (helper socket error: accept: \
                          EBADF)"
                    .to_string(),
            })
        );

        // Errors interleaved with timeouts never reach the bound.
        struct Flaky(Arc<AtomicUsize>);
        impl Acceptor for Flaky {
            fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                if n.is_multiple_of(2) {
                    Err(SessionError::Io("accept: EBADF".to_string()))
                } else {
                    Err(SessionError::Timeout)
                }
            }
        }
        let (state, now) = state_over(vec![row6()]);
        now.store(5_000, Ordering::SeqCst);
        let child = FakeChild {
            ticks_left: 2 * ACCEPT_ERRORS_MAX as u32 + 2,
            exit: Some(ChildExit::Exited(126)),
            stderr: "Request dismissed".to_string(),
            ..FakeChild::alive(4242)
        };
        let killed = Arc::clone(&child.killed);
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(Flaky(Arc::new(AtomicUsize::new(0)))),
            Some(holds.hold()),
            5_000,
            true,
        );
        assert_eq!(killed.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.report().request.map(|r| r.state),
            Some(RequestState::Dismissed)
        );
    }

    // ---- tester, fix range (p1b panel I1, S1): the single flight under
    // contention, the claim after a panic, the settle bound, the attach arm ----

    /// A requester that answers `CannotPrompt` and keeps every report it was
    /// handed, so a test can see which report the request acted on.
    struct Recording(Arc<Mutex<Vec<PrivilegeReport>>>);

    impl Requester for Recording {
        fn request(&self, _cfg: &PrivilegeConfig, report: &PrivilegeReport) -> (Outcome, String) {
            self.0.lock().unwrap().push(report.clone());
            (Outcome::CannotPrompt, "no".to_string())
        }
    }

    fn open_gate(gate: &(Mutex<bool>, std::sync::Condvar)) {
        let (open, changed) = gate;
        *open.lock().unwrap() = true;
        changed.notify_all();
    }

    /// A state over a [`Blocking`] prober and a [`Recording`] requester, with
    /// the handles a test drives them through.
    struct BlockingRig {
        state: Arc<PrivilegeState>,
        /// One message per `gather` the prober entered.
        entered_rx: mpsc::Receiver<()>,
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
        /// How many times the prober gathered.
        calls: Arc<AtomicU64>,
        /// Every report the requester was handed.
        seen: Arc<Mutex<Vec<PrivilegeReport>>>,
    }

    /// A [`BlockingRig`] with the gate as given and the clock pinned at `now`.
    fn blocking_state(gate_open: bool, now: u64) -> BlockingRig {
        let (entered_tx, entered_rx) = mpsc::channel();
        let gate = Arc::new((Mutex::new(gate_open), std::sync::Condvar::new()));
        let calls = Arc::new(AtomicU64::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(
            PrivilegeState::with_prober(
                &cfg(),
                Box::new(Blocking {
                    entered: entered_tx,
                    gate: Arc::clone(&gate),
                    calls: Arc::clone(&calls),
                }),
                Arc::new(move || now),
            )
            .with_requester(Box::new(Recording(Arc::clone(&seen)))),
        );
        BlockingRig {
            state,
            entered_rx,
            gate,
            calls,
            seen,
        }
    }

    /// I1: a `request()` that arrives while another caller's **first** probe
    /// is in flight waits for that probe instead of acting on the empty
    /// report, starts no probe of its own, and completes as soon as the probe
    /// lands: one gather serves the report and the request together.
    #[test]
    fn request_waits_for_an_in_flight_first_probe_and_gathers_once() {
        let BlockingRig {
            state,
            entered_rx,
            gate,
            calls,
            seen,
        } = blocking_state(false, 500);

        let first = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || state.report())
        };
        entered_rx
            .recv_timeout(WAIT)
            .expect("the first probe started");

        let (done_tx, done_rx) = mpsc::channel();
        {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                let _ = done_tx.send(state.request());
            });
        }
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_err(),
            "request() must not act on the empty report while the first probe is in flight"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the waiting request starts no probe of its own"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "the requester is never asked over the empty report"
        );

        open_gate(&gate);
        let opened = Instant::now();
        let outcome = done_rx
            .recv_timeout(WAIT)
            .expect("request() returned once the probe landed");
        assert!(
            opened.elapsed() < Duration::from_secs(5),
            "it returned on the probe landing, not at the settle bound ({:?})",
            opened.elapsed()
        );
        let first = first.join().expect("first report");
        assert_eq!(first.capture.state_str(), "needs_approval");
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].capture.state_str(),
            "needs_approval",
            "the requester saw the probe's report, not the empty one"
        );
        assert_eq!(outcome.privilege.capture.state_str(), "needs_approval");
        assert_eq!(
            outcome.privilege.request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 500,
                message: "no".to_string(),
            })
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one gather for the report and the request together"
        );
    }

    /// I1: with a report in hand, a `request()` that arrives while a re-probe
    /// is blocked in the prober answers at once from that report and starts
    /// no gather of its own; the blocked report lands with the progress the
    /// request recorded meanwhile, and the dirty mark it left makes the next
    /// `report()` gather again.
    #[test]
    fn request_with_a_report_in_hand_does_not_wait_for_a_running_probe() {
        let BlockingRig {
            state,
            entered_rx,
            gate,
            calls,
            ..
        } = blocking_state(true, 600);
        assert_eq!(state.report().capture.state_str(), "needs_approval");
        entered_rx.recv_timeout(WAIT).expect("the first probe");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Close the gate; the next probe blocks in the prober.
        *gate.0.lock().unwrap() = false;
        state.shared.mark_dirty();
        let blocked = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || state.report())
        };
        entered_rx
            .recv_timeout(WAIT)
            .expect("the re-probe started and is blocked");

        let started = Instant::now();
        let outcome = state.request();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "request() did not wait behind the running probe ({:?})",
            started.elapsed()
        );
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(outcome.privilege.capture.state_str(), "needs_approval");
        assert_eq!(
            outcome.privilege.request.as_ref().map(|r| r.state),
            Some(RequestState::Failed)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the request started no probe of its own"
        );

        open_gate(&gate);
        let landed = blocked.join().expect("the blocked report");
        assert_eq!(
            landed.request.map(|r| r.state),
            Some(RequestState::Failed),
            "the blocked report carries the progress recorded meanwhile"
        );
        let next = state.report();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the dirty mark the request left makes the next report() gather again"
        );
        assert_eq!(next.request.map(|r| r.state), Some(RequestState::Failed));
    }

    /// A prober whose first `gather` panics; every later one answers row 6.
    struct PanicsOnce(Arc<AtomicU64>);

    impl Prober for PanicsOnce {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("the gatherer blew up");
            }
            ProbeInputs {
                enabled: true,
                platform: Platform::Macos,
                mac: Some(row6()),
                linux: None,
                request: request.cloned(),
                now_ms: 0,
            }
        }
    }

    /// I1: a prober that panics releases the single-flight claim, so the next
    /// `report()` gathers again instead of reading "in flight" forever, and a
    /// `request()` after it needs no settle wait.
    #[test]
    fn a_panicking_prober_releases_the_single_flight_claim() {
        let calls = Arc::new(AtomicU64::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(
            PrivilegeState::with_prober(
                &cfg(),
                Box::new(PanicsOnce(Arc::clone(&calls))),
                Arc::new(|| 700),
            )
            .with_requester(Box::new(Recording(Arc::clone(&seen)))),
        );
        let crashed = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || state.report()).join()
        };
        assert!(crashed.is_err(), "the first probe panicked");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let started = Instant::now();
        let report = state.report();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the claim was released: this report() gathered again"
        );
        assert_eq!(report.capture.state_str(), "needs_approval");
        let outcome = state.request();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no settle wait after the panic ({:?})",
            started.elapsed()
        );
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// I1: a `request()` waiting on a first probe that never lands gives up
    /// at [`SETTLE_WAIT`] (bounded, never a deadlock), acts on the report in
    /// hand, starts no probe of its own, and records its answer; the probe
    /// that lands late carries that progress.
    #[test]
    fn request_stops_waiting_for_a_first_probe_at_the_settle_bound() {
        let BlockingRig {
            state,
            entered_rx,
            gate,
            calls,
            seen,
        } = blocking_state(false, 800);
        let stuck = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || state.report())
        };
        entered_rx
            .recv_timeout(WAIT)
            .expect("the first probe started");

        let started = Instant::now();
        let outcome = state.request();
        let waited = started.elapsed();
        assert!(waited >= SETTLE_WAIT, "returned early: {waited:?}");
        assert!(
            waited < SETTLE_WAIT + Duration::from_secs(20),
            "not bounded: {waited:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the request started no probe of its own"
        );
        assert_eq!(outcome.outcome, Outcome::CannotPrompt);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(
            outcome.privilege.request,
            Some(RequestProgress {
                state: RequestState::Failed,
                at: 800,
                message: "no".to_string(),
            })
        );

        open_gate(&gate);
        let first = stuck.join().expect("the stuck report");
        assert_eq!(first.capture.state_str(), "needs_approval");
        assert_eq!(
            first.request.map(|r| r.state),
            Some(RequestState::Failed),
            "the probe that landed late carries the progress recorded meanwhile"
        );
    }

    /// One prepared session, then timeouts; on drop, the progress as it stands.
    struct OnePeerDropWatch {
        session: Mutex<Option<HelperSession>>,
        shared: Arc<Shared>,
        progress_at_drop: Arc<Mutex<Option<Option<RequestState>>>>,
    }

    impl Acceptor for OnePeerDropWatch {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            self.session
                .lock()
                .unwrap()
                .take()
                .ok_or(SessionError::Timeout)
        }
    }

    impl Drop for OnePeerDropWatch {
        fn drop(&mut self) {
            let state = self.shared.lock_cache().request.as_ref().map(|r| r.state);
            *self.progress_at_drop.lock().unwrap() = Some(state);
        }
    }

    /// S1 in the third terminal arm: when the helper connects but fails its
    /// handshake, the listener is dropped **before** the `failed` row is
    /// recorded (and before the kill and reap), the hold is released, the
    /// launcher is killed once, and the failure is remembered for the
    /// `version_mismatch` row.
    #[test]
    fn watcher_drops_the_acceptor_before_the_failed_row_on_a_handshake_failure() {
        let (state, now) = state_over(vec![row6()]);
        now.store(12_000, Ordering::SeqCst);
        state.set_guard(Arc::new(L4Guard::new(&L4Config::default())));
        let holds = HoldCount::default();

        let (core, peer) = UnixStream::pair().expect("socketpair");
        let peer_thread = garbage_peer(
            peer,
            encode(&Msg::HelloAck {
                proto: 2,
                helper_version: "9.9.9".to_string(),
                caps: vec![],
            }),
        );
        let session = HelperSession::from_stream(core).expect("session");
        let child = FakeChild {
            exit: Some(ChildExit::Exited(0)),
            ..FakeChild::alive(4242)
        };
        let killed = Arc::clone(&child.killed);
        let progress_at_drop = Arc::new(Mutex::new(None));
        run_watcher(
            Arc::clone(&state.shared),
            Box::new(child),
            Box::new(OnePeerDropWatch {
                session: Mutex::new(Some(session)),
                shared: Arc::clone(&state.shared),
                progress_at_drop: Arc::clone(&progress_at_drop),
            }),
            Some(holds.hold()),
            12_000,
            true,
        );
        assert_eq!(
            *progress_at_drop.lock().unwrap(),
            Some(None),
            "the acceptor (and its socket path) went before the failed row was recorded"
        );
        let request = state.report().request.expect("progress recorded");
        assert_eq!(request.state, RequestState::Failed);
        assert_eq!(request.at, 12_000);
        assert_eq!(
            killed.load(Ordering::SeqCst),
            1,
            "the launcher is killed once"
        );
        assert!(!holds.is_held(), "the hold is released");
        assert_eq!(
            state.shared.session_failure(),
            Some(SessionFailure::VersionMismatch(2))
        );
        assert!(state.helper_backend().is_none());
        peer_thread.join().expect("peer");
    }

    // ---- fix task, round-3 minors (p1b panel 3): D1 a watch releases only
    // what it registered, D4 `cancel_prompt` never blocks on the child ------

    /// `cancel_prompt()` until its SIGINT lands. The cancel skips a contended
    /// child lock rather than block (D4); an acceptor that times out at once
    /// keeps the watcher hot on that lock, so one call may land on nothing.
    /// Exactly one SIGINT is sent: no call is made once one has landed.
    fn cancel_until_signalled(state: &PrivilegeState, signals: &Mutex<Vec<i32>>) {
        until("the cancel to land", || {
            if signals.lock().unwrap().is_empty() {
                state.cancel_prompt();
            }
            !signals.lock().unwrap().is_empty()
        });
    }

    /// A child that outlives `kill` until the test lets it go: `try_wait`
    /// reads `None` until `released`, then `Exited(0)`. `kill` only counts.
    struct LingeringChild {
        pid: u32,
        released: Arc<AtomicBool>,
        killed: Arc<AtomicUsize>,
    }

    impl Child for LingeringChild {
        fn id(&self) -> u32 {
            self.pid
        }
        fn try_wait(&mut self) -> std::io::Result<Option<ChildExit>> {
            Ok(self
                .released
                .load(Ordering::SeqCst)
                .then_some(ChildExit::Exited(0)))
        }
        fn kill(&mut self) {
            self.killed.fetch_add(1, Ordering::SeqCst);
        }
        fn interrupt(&mut self) {}
        fn stderr_tail(&mut self) -> String {
            String::new()
        }
    }

    /// An acceptor whose listener is broken: every `accept` is an I/O error.
    struct BrokenListener;

    impl Acceptor for BrokenListener {
        fn accept(&self, _pid: u32, _timeout: Duration) -> Result<HelperSession, SessionError> {
            Err(SessionError::Io("accept: EBADF".to_string()))
        }
    }

    /// Panel 3 (D1): a watch releases only what it registered. Watch A ends
    /// through the accept-errors arm into the bounded reap of a child that
    /// refuses to die; inside that window a re-request starts watch B, whose
    /// child becomes the prompt. When A's child finally goes and A's `Drop`
    /// runs, B's prompt slot and the `watching` flag survive: a held Ctrl-C
    /// still reaches B's child, and `lazy_start_helper` still sees a watcher.
    #[test]
    fn ended_watch_in_its_reap_does_not_release_the_next_watch() {
        let (state, now) = state_over(vec![row6()]);
        now.store(16_000, Ordering::SeqCst);
        let holds = HoldCount::default();

        // Watch A: after ACCEPT_ERRORS_MAX the request fails, the child is
        // killed and the reap starts; the child ignores the kill.
        let released = Arc::new(AtomicBool::new(false));
        let a_killed = Arc::new(AtomicUsize::new(0));
        let a_child = LingeringChild {
            pid: 4242,
            released: Arc::clone(&released),
            killed: Arc::clone(&a_killed),
        };
        let shared = Arc::clone(&state.shared);
        let hold = holds.hold();
        let watch_a = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(a_child),
                Box::new(BrokenListener),
                Some(hold),
                16_000,
                true,
            );
        });
        until("watch A to reach its reap", || {
            a_killed.load(Ordering::SeqCst) == 1
        });
        assert_eq!(
            state.report().request.map(|r| r.state),
            Some(RequestState::Failed)
        );
        assert!(state.shared.prompt_child().is_none(), "A's prompt is over");
        assert_eq!(holds.count(), 0, "A's hold is released");
        assert!(state.shared.watching(), "A is still reaping");

        // Watch B starts inside A's reap window; its child is the prompt.
        let b_child = FakeChild::alive(4243);
        let b_signals = Arc::clone(&b_child.signals);
        let shared = Arc::clone(&state.shared);
        let hold = holds.hold();
        let watch_b = std::thread::spawn(move || {
            run_watcher(
                shared,
                Box::new(b_child),
                Box::new(NoPeer),
                Some(hold),
                16_000,
                true,
            );
        });
        let prompt_pid = || state.shared.prompt_child().map(|child| lock(&child).id());
        until("B's child to be the prompt", || prompt_pid() == Some(4243));

        // A's child goes: A's reap returns and its `Drop` runs.
        released.store(true, Ordering::SeqCst);
        watch_a.join().expect("watch A");
        assert_eq!(a_killed.load(Ordering::SeqCst), 1);

        assert_eq!(
            prompt_pid(),
            Some(4243),
            "A's end left B's child registered as the prompt"
        );
        assert!(
            state.shared.watching(),
            "A's end left the watching flag to B"
        );
        assert_eq!(holds.count(), 1, "B's hold is up");

        // And a held Ctrl-C still reaches B's child.
        cancel_until_signalled(&state, &b_signals);
        watch_b.join().expect("watch B");
        assert_eq!(
            *b_signals.lock().unwrap(),
            vec![crate::privilege::linux::SIGINT]
        );
        assert_eq!(
            state.report().request.map(|r| r.state),
            Some(RequestState::Dismissed)
        );
        assert_eq!(holds.count(), 0);
        assert!(state.shared.prompt_child().is_none());
        assert!(!state.shared.watching(), "B's end cleared its own flag");
    }
}
