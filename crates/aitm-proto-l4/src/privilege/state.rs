//! `PrivilegeState`: the one shared source of truth for packet-capture
//! privilege (spec §2.1). It owns the platform prober, the clock, the cached
//! [`PrivilegeReport`] and the progress of the last `l4.privilege.request`.
//!
//! `report()` re-probes when the cached capture is not `Available` and is at
//! least [`REPROBE_MS`] old (**Architect's call** for the TTL), so a core
//! started before approval sees the flip without a restart (AC7). An
//! `Available` result is held for the process lifetime: nothing here takes a
//! privilege away once granted (a backend failure reporting one is P1b.8's
//! job). Each capture-state change logs exactly one `tracing::info!` line
//! (AC24) naming the two states; never a token, never a payload.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::routed::RoutedBackend;
use crate::backend::CaptureInjectBackend;
pub use crate::config::{L4PrivilegeConfig, RequestMode};
use crate::privilege::derive::{derive, ProbeInputs};
use crate::privilege::linux::gather_linux;
use crate::privilege::macos::gather_mac;
use crate::privilege::report::{
    Capability, Platform, PrivilegeReport, RequestProgress, RequestState,
};

/// How old a not-available cached report may be before `report()` re-probes.
pub const REPROBE_MS: u64 = 1000;

/// The message a request carries once capture became available under it.
pub const APPROVED_MESSAGE: &str = "packet capture approved";

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
    clock: Clock,
    cache: Mutex<Cache>,
    /// The helper session's capture/inject backend while one is connected
    /// (plan P1b.8 seam; P1b.13 sets and clears it). [`RoutedBackend`] takes
    /// it for `Available { via: Helper }`.
    helper: Mutex<Option<Arc<dyn CaptureInjectBackend>>>,
}

/// What `report()` keeps between probes.
#[derive(Default)]
struct Cache {
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

impl std::fmt::Debug for PrivilegeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegeState")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl PrivilegeState {
    /// The production state: this OS's gatherer and the system clock.
    #[must_use]
    pub fn new(cfg: &PrivilegeConfig) -> Self {
        let prober = PlatformProber {
            enabled: cfg.enabled,
            l4: cfg.l4.clone(),
        };
        Self::with_prober(cfg, Box::new(prober), Arc::new(epoch_ms_now))
    }

    /// A state over any prober and clock; for tests and fixed-input modules.
    #[must_use]
    pub fn with_prober(cfg: &PrivilegeConfig, prober: Box<dyn Prober>, clock: Clock) -> Self {
        Self {
            cfg: cfg.clone(),
            prober,
            clock,
            cache: Mutex::new(Cache::default()),
            helper: Mutex::new(None),
        }
    }

    /// The one capture/inject backend every production caller holds (spec §2.1,
    /// plan P1b.8): a [`RoutedBackend`] that reads this state on every call and
    /// delegates to libpcap in process, to the helper session, or refuses
    /// fail-closed with the gated text.
    #[must_use]
    pub fn backend(self: &Arc<Self>) -> Arc<dyn CaptureInjectBackend> {
        Arc::new(RoutedBackend::new(Arc::clone(self)))
    }

    /// Set (or clear) the helper session's backend. The routed backend takes it
    /// for `Available { via: Helper }` from the next call on.
    #[allow(dead_code)] // wired by P1b.13 (the Linux helper session)
    pub(crate) fn set_helper_backend(&self, backend: Option<Arc<dyn CaptureInjectBackend>>) {
        *self.helper.lock().unwrap_or_else(PoisonError::into_inner) = backend;
    }

    /// The helper session's backend, if one is connected.
    pub(crate) fn helper_backend(&self) -> Option<Arc<dyn CaptureInjectBackend>> {
        self.helper
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
        let now = (self.clock)();
        let mut cache = self.lock();

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

    /// Record (or clear) the progress of this core's `l4.privilege.request`.
    /// The next `report()` probes at once so the request-dependent rows apply.
    #[allow(dead_code)] // wired by P1b.10 (`l4.privilege.request`)
    pub(crate) fn set_request(&self, request: Option<RequestProgress>) {
        let mut cache = self.lock();
        cache.request = request;
        cache.dirty = true;
    }

    /// How many capture-state changes `report()` has logged.
    #[cfg(test)]
    pub(crate) fn changes(&self) -> u64 {
        self.lock().changes
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

    /// A poisoned lock means another `report()` panicked mid-update; the cache
    /// is re-derivable, so take it as it is rather than propagate the panic.
    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
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
}

impl Prober for PlatformProber {
    fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
        let platform = current_platform();
        let mac = (platform == Platform::Macos).then(|| gather_mac(&self.l4.macos_app_path));
        // `session_connected` is what the helper-session owner knows; until
        // P1b.13 wires it, no session is ever connected.
        let linux = (platform == Platform::Linux)
            .then(|| gather_linux(self.l4.helper_path.as_deref(), false));
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
        rows: Mutex<Vec<MacInputs>>,
        calls: AtomicU64,
    }

    impl Scripted {
        fn new(rows: Vec<MacInputs>) -> Box<Self> {
            Box::new(Self {
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
                enabled: true,
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
}
