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

use std::any::Any;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::backend::helper::HelperBackend;
use crate::backend::routed::RoutedBackend;
use crate::backend::CaptureInjectBackend;
pub use crate::config::{L4PrivilegeConfig, RequestMode};
use crate::guard::L4Guard;
use crate::helper::client::{
    ensure_socket_dir, socket_path, HelperListener, HelperSession, SessionError,
};
use crate::privilege::derive::{derive, text, LinuxInputs, ProbeInputs};
use crate::privilege::linux::{
    direct_helper_argv, gather_linux, msg, request_linux, watch_step, Child, NoopSignalGuard,
    SignalGuard, Spawned, Spawner, StdSpawner, WatchOutcome,
};
use crate::privilege::macos::gather_mac;
use crate::privilege::report::{
    Capability, Platform, PrivilegeReport, RequestProgress, RequestState,
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
/// [`PlatformRequester`].
pub(crate) trait Requester: Send + Sync {
    fn request(&self, cfg: &PrivilegeConfig, report: &PrivilegeReport) -> (Outcome, String);

    /// Called by the state right after the answer of `request` was recorded
    /// as this core's progress (same `request()` call, same lock). A
    /// requester that spawned something starts watching it here, so the
    /// watcher's first progress write can never be overwritten by the
    /// `pending` row. The default does nothing.
    fn after_recorded(&self) {}
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
    /// The helper session's capture/inject backend while one is connected
    /// (plan P1b.8 seam). [`RoutedBackend`] takes it for
    /// `Available { via: Helper }`.
    helper: Mutex<Option<Arc<dyn CaptureInjectBackend>>>,
    /// The connected helper backend, for `is_live()`: the prober's
    /// `session_connected` input (plan P1b.13 hand-over).
    live: Mutex<Option<Arc<HelperBackend>>>,
    /// The guard a [`HelperBackend`] is built over; set by the wiring through
    /// [`PrivilegeState::set_guard`]. Without it a connecting helper cannot be
    /// attached.
    guard: Mutex<Option<Arc<L4Guard>>>,
    /// The Linux inputs of the last platform probe, for the requester and the
    /// lazy direct start.
    last_linux: Mutex<Option<LinuxInputs>>,
    /// A watcher thread is running (a request in flight or a helper serving).
    watching: AtomicBool,
}

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
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn new(clock: Clock) -> Arc<Self> {
        Arc::new(Shared {
            clock,
            cache: Mutex::new(Cache::default()),
            helper: Mutex::new(None),
            live: Mutex::new(None),
            guard: Mutex::new(None),
            last_linux: Mutex::new(None),
            watching: AtomicBool::new(false),
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

    fn helper(&self) -> Option<Arc<dyn CaptureInjectBackend>> {
        lock(&self.helper).clone()
    }

    fn set_helper(&self, backend: Option<Arc<dyn CaptureInjectBackend>>) {
        *lock(&self.helper) = backend;
    }

    fn set_live(&self, backend: Option<Arc<HelperBackend>>) {
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

    fn watching(&self) -> bool {
        self.watching.load(Ordering::SeqCst)
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

    /// Replace the platform requester; tests script one.
    #[cfg(test)]
    pub(crate) fn with_requester(mut self, requester: Box<dyn Requester>) -> Self {
        self.requester = requester;
        self
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

    /// Set (or clear) the helper session's backend. The routed backend takes it
    /// for `Available { via: Helper }` from the next call on.
    pub(crate) fn set_helper_backend(&self, backend: Option<Arc<dyn CaptureInjectBackend>>) {
        self.shared.set_helper(backend);
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
    #[must_use]
    pub fn report(&self) -> PrivilegeReport {
        let now = self.shared.now();
        let mut cache = self.shared.lock_cache();

        let stale = match &cache.report {
            None => true,
            Some(cached) => {
                !matches!(cached.capture, Capability::Available { .. })
                    && now.saturating_sub(cache.probed_at) >= REPROBE_MS
            }
        };
        if stale || cache.dirty {
            self.probe(&mut cache, now);
        }

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
    /// then the requester's `after_recorded` runs. The returned report is
    /// taken after that, so it carries the progress and the request-dependent
    /// rows.
    #[must_use]
    pub fn request(&self) -> RequestOutcome {
        let _one_at_a_time = lock(&self.requesting);

        let report = self.report();
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
            privilege: self.report(),
        }
    }

    /// Record (or clear) the progress of this core's `l4.privilege.request`.
    /// The next `report()` probes at once so the request-dependent rows apply.
    pub(crate) fn set_request(&self, request: Option<RequestProgress>) {
        let mut cache = self.shared.lock_cache();
        cache.request = request;
        cache.dirty = true;
    }

    /// How many capture-state changes `report()` has logged.
    #[cfg(test)]
    pub(crate) fn changes(&self) -> u64 {
        self.shared.lock_cache().changes
    }

    /// Run the prober, derive, move a waiting request to `approved` when
    /// capture became available, and log a capture-state change.
    fn probe(&self, cache: &mut Cache, now: u64) {
        let mut inputs = self.prober.gather(cache.request.as_ref());
        inputs.now_ms = now;
        inputs.request.clone_from(&cache.request);
        let mut fresh = derive(&inputs);

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

        cache.report = Some(fresh);
        cache.probed_at = now;
        cache.dirty = false;
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
        if self.cfg.lifetime != ProcessLifetime::Serving {
            return;
        }
        let Some(inputs) = self.shared.last_linux() else {
            return;
        };
        if inputs.cap_net_raw {
            return;
        }
        let Some(helper) = inputs.helper.filter(|helper| helper.file_caps_net_raw) else {
            return;
        };

        let _one_at_a_time = lock(&self.lazy_start);
        if self.shared.helper().is_some() {
            return;
        }
        if !self.shared.watching() {
            match spawn_direct(&self.shared, &helper.path) {
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
            let inputs = gather_linux(self.l4.helper_path.as_deref(), self.shared.live_is_up());
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
///   spawning through the real [`StdSpawner`] once the listener is bound in
///   the socket directory; the child and listener wait in `pending` until
///   [`Requester::after_recorded`] starts the watcher thread.
/// - Anything else: `CannotPrompt`, [`NO_HANDOFF_MESSAGE`].
struct PlatformRequester {
    shared: Arc<Shared>,
    spawner: Arc<dyn Spawner>,
    signal: Arc<dyn SignalGuard>,
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
            signal: Arc::new(NoopSignalGuard),
            pending: Mutex::new(None),
        }
    }

    fn linux_request(&self, cfg: &PrivilegeConfig) -> (Outcome, String) {
        let inputs = self.shared.last_linux().unwrap_or_else(|| {
            gather_linux(cfg.l4.helper_path.as_deref(), self.shared.live_is_up())
        });
        let binder = BindingSpawner::new(Arc::clone(&self.spawner));
        let socket = binder.socket();
        let request = request_linux(cfg, &inputs, &binder, &*self.signal, &socket, display_set());
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
fn socket_location() -> io::Result<(PathBuf, u32)> {
    let uid = nix::unistd::getuid().as_raw();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    Ok((
        crate::helper::client::socket_dir(runtime.as_deref(), uid),
        uid,
    ))
}

/// Off Linux there is no helper session to bind for.
#[cfg(not(target_os = "linux"))]
fn socket_location() -> io::Result<(PathBuf, u32)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "helper sessions are Linux only",
    ))
}

/// A [`Spawner`] that binds the listener first, then spawns: the helper's
/// `connect` must find the socket, so the bind precedes the spawn and
/// happens only when [`request_linux`]'s pre-checks passed (nothing is
/// created on a refusal). The bound listener is taken by the caller.
struct BindingSpawner {
    inner: Arc<dyn Spawner>,
    location: Result<(PathBuf, u32), String>,
    listener: Mutex<Option<HelperListener>>,
}

impl BindingSpawner {
    fn new(inner: Arc<dyn Spawner>) -> Self {
        BindingSpawner {
            inner,
            location: socket_location().map_err(|err| err.to_string()),
            listener: Mutex::new(None),
        }
    }

    /// The socket path the listener will bind (the argv needs it first).
    fn socket(&self) -> PathBuf {
        self.location
            .as_ref()
            .map(|(dir, _)| socket_path(dir, std::process::id()))
            .unwrap_or_default()
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
            .map_err(|err| io::Error::new(io::ErrorKind::Unsupported, err.clone()))?;
        ensure_socket_dir(dir, *uid)?;
        let listener = HelperListener::bind(dir)?;
        *lock(&self.listener) = Some(listener);
        self.inner.spawn(argv)
    }
}

/// Start a file-capability helper directly (no launcher, no SIGINT hold) and
/// watch it like a request, without touching the request progress.
fn spawn_direct(shared: &Arc<Shared>, helper: &std::path::Path) -> io::Result<()> {
    let binder = BindingSpawner::new(Arc::new(StdSpawner));
    let socket = binder.socket();
    let child = binder.spawn(&direct_helper_argv(helper, &socket))?;
    let listener = binder
        .take_listener()
        .ok_or_else(|| io::Error::other("the helper listener was not bound"))?;
    start_watch_with(
        Arc::clone(shared),
        PendingWatch {
            spawned: Spawned {
                child,
                hold: Box::new(()),
            },
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
    shared.watching.store(true, Ordering::SeqCst);
    let thread_shared = Arc::clone(&shared);
    let built = std::thread::Builder::new()
        .name("l4-privilege-watch".to_string())
        .spawn(move || {
            let watched = Arc::clone(&thread_shared);
            run_watcher(
                watched,
                child,
                Box::new(listener),
                hold,
                started_ms,
                progress,
            );
            thread_shared.watching.store(false, Ordering::SeqCst);
        });
    if let Err(err) = built {
        // The child handle went with the closure; its connect will find no
        // listener and the helper exits on its own.
        shared.watching.store(false, Ordering::SeqCst);
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
///   [`crate::privilege::linux::classify_exit`] names the progress; the
///   no-agent row also logs one `warn` (the predicate and the launcher
///   disagreed).
/// - [`crate::privilege::linux::APPROVAL_TIMEOUT_MS`] pass: the child is
///   killed and the progress is `failed` with the timeout text.
///
/// `progress` is false for a direct file-capability start, which nobody
/// requested: it logs instead of writing request progress.
pub(crate) fn run_watcher(
    shared: Arc<Shared>,
    mut child: Box<dyn Child>,
    acceptor: Box<dyn Acceptor>,
    hold: Box<dyn Any + Send>,
    started_ms: u64,
    progress: bool,
) {
    let mut hold = Some(hold);
    let record = |state: RequestState, message: &str| {
        if progress {
            shared.set_progress(state, message);
        }
    };
    loop {
        match acceptor.accept(child.id(), ACCEPT_SLICE) {
            Ok(session) => {
                drop(hold.take());
                match attach_session(&shared, session) {
                    Ok(backend) => {
                        shared.set_helper(Some(
                            Arc::clone(&backend) as Arc<dyn CaptureInjectBackend>
                        ));
                        record(RequestState::Approved, msg::APPROVED);
                        shared.set_live(Some(Arc::clone(&backend)));
                        shared.mark_dirty();
                        tracing::info!("L4 packet-capture helper connected");
                        drop(acceptor);
                        while backend.is_live() {
                            std::thread::sleep(LIVE_POLL);
                        }
                        shared.set_helper(None);
                        shared.set_live(None);
                        shared.mark_dirty();
                        tracing::info!("L4 packet-capture helper session ended");
                        reap(child.as_mut());
                    }
                    Err(message) => {
                        tracing::warn!(
                            reason = %message,
                            "the packet-capture helper connected but could not be attached"
                        );
                        record(RequestState::Failed, &message);
                        child.kill();
                        reap(child.as_mut());
                    }
                }
                return;
            }
            Err(SessionError::Timeout) => {}
            Err(SessionError::PeerUid(_) | SessionError::PeerPid(_)) => {
                tracing::warn!(
                    "a process other than the spawned helper connected to the \
                     packet-capture socket; dropped"
                );
            }
            Err(_) => std::thread::sleep(ACCEPT_SLICE),
        }

        match watch_step(child.as_mut(), false, started_ms, shared.now()) {
            WatchOutcome::Waiting | WatchOutcome::Connected => {}
            WatchOutcome::Ended { state, message } => {
                if message == msg::NO_PROMPT_SHOWN {
                    tracing::warn!(
                        "a prompt was judged possible but the launcher found no \
                         authentication agent"
                    );
                }
                drop(hold.take());
                tracing::info!(
                    state = state.as_str(),
                    reason = %message,
                    "L4 packet-capture request ended"
                );
                record(state, &message);
                if message == msg::TIMED_OUT {
                    reap(child.as_mut());
                }
                return;
            }
        }
    }
}

/// Handshake, start the reader, and build the backend over the state's guard.
fn attach_session(
    shared: &Shared,
    mut session: HelperSession,
) -> Result<Arc<HelperBackend>, String> {
    session
        .handshake(CORE_VERSION, HANDSHAKE_TIMEOUT)
        .map_err(|err| {
            format!("the packet-capture helper did not complete its handshake ({err})")
        })?;
    session
        .start_reader()
        .map_err(|err| format!("the packet-capture helper session could not start ({err})"))?;
    let guard = shared.guard().ok_or_else(|| msg::NO_GUARD.to_string())?;
    HelperBackend::new(Arc::new(session), guard)
        .map(Arc::new)
        .map_err(|err| err.to_string())
}

/// Wait, bounded, for an ended or killed child to be reaped; a launcher that
/// refused the kill (another user) is left to the OS.
fn reap(child: &mut dyn Child) {
    let deadline = Instant::now() + REAP_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
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
    use crate::privilege::derive::{MacInputs, ProbeInputs};
    use crate::privilege::report::{
        Capability, Platform, PrivilegeReport, RequestProgress, RequestState, Via,
    };

    /// A prober that answers from a queue of macOS inputs, repeating the last.
    struct Scripted {
        enabled: bool,
        rows: Mutex<Vec<MacInputs>>,
        calls: AtomicU64,
    }

    impl Scripted {
        fn new(rows: Vec<MacInputs>) -> Box<Self> {
            Self::with_enabled(true, rows)
        }

        /// The same prober reporting `l4.enabled` as `enabled` (the production
        /// prober copies it from the config).
        fn with_enabled(enabled: bool, rows: Vec<MacInputs>) -> Box<Self> {
            Box::new(Self {
                enabled,
                rows: Mutex::new(rows),
                calls: AtomicU64::new(0),
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
                message: outcome.message.clone(),
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

    use std::any::Any;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crate::config::L4Config;
    use crate::guard::L4Guard;
    use crate::helper::client::{HelperSession, SessionError};
    use crate::helper::proto::{encode, read_msg, Msg, PROTO};
    use crate::privilege::linux::fakes::{CountingGuard, FakeChild};
    use crate::privilege::linux::{ChildExit, SignalGuard};

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
        let holds = Arc::new(AtomicUsize::new(0));
        let hold = CountingGuard(Arc::clone(&holds)).hold();
        assert_eq!(holds.load(Ordering::SeqCst), 1);

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
            hold,
            1_000,
            true,
        );

        assert_eq!(
            holds.load(Ordering::SeqCst),
            0,
            "the hold is released with the child"
        );
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
        let holds = Arc::new(AtomicUsize::new(0));
        let hold = CountingGuard(Arc::clone(&holds)).hold();

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
                hold,
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
        assert_eq!(
            holds.load(Ordering::SeqCst),
            0,
            "the hold is released on connect"
        );
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
        let holds = Arc::new(AtomicUsize::new(0));
        let hold = CountingGuard(Arc::clone(&holds)).hold();

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
            hold,
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
        assert_eq!(holds.load(Ordering::SeqCst), 0);
    }

    /// The binding spawner binds the listener before it spawns; where no
    /// listener can be bound (off Linux here) nothing is spawned at all.
    #[test]
    fn binding_spawner_never_spawns_without_a_listener() {
        use crate::privilege::linux::fakes::FakeSpawner;
        use crate::privilege::linux::{pkexec_argv, Spawner};

        let holds = Arc::new(AtomicUsize::new(0));
        let inner = Arc::new(FakeSpawner::new(&holds));
        let binder = BindingSpawner::new(Arc::clone(&inner) as Arc<dyn Spawner>);
        let socket = binder.socket();
        let result = binder.spawn(&pkexec_argv(&socket));
        let on_linux = cfg!(target_os = "linux");
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
        let _: Box<dyn Any + Send> = Box::new(());
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
            let holds = Arc::new(AtomicUsize::new(0));
            let hold = CountingGuard(Arc::clone(&holds)).hold();

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
                hold,
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
            assert_eq!(holds.load(Ordering::SeqCst), 0, "the hold is released");
            assert!(state.helper_backend().is_none());
            assert!(!state.shared.live_is_up());
            for word in ["sudo", "pkexec", "chmod", "setcap", "chown"] {
                assert!(!request.message.contains(word), "{}", request.message);
            }
            peer_thread.join().expect("peer");
        }
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
        let holds = Arc::new(AtomicUsize::new(0));
        let hold = CountingGuard(Arc::clone(&holds)).hold();
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
            hold,
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
        assert_eq!(holds.load(Ordering::SeqCst), 0);
        assert!(state.helper_backend().is_none());
        assert!(!state.shared.live_is_up());
    }
}
