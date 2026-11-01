//! The L4 plugin module (M5 Task 9).
//!
//! `aitm-proto-l4` is **command-driven**, not acceptor-driven: it has no listening
//! socket to take over, so it rides the core [`Plugin`] + [`Command`] seams rather
//! than the `ProtocolModule` acceptor seam. [`L4Module`] is the one [`Plugin`]; its
//! [`load`](L4Module::load) registers every `l4.*` command into the [`Registry`],
//! so MCP, the CLI, and the Rhai tier reach them through the single command bus.
//!
//! The module owns the two pieces of L4 state the core [`CommandHost`] does not
//! carry — the deny-by-default [`L4Guard`] and the l4-owned [`L4FlowStore`] — and
//! hands each command an `Arc` to them. (The core [`CommandHost`] stays
//! HTTP-shaped; L4 state living here is how M5 lands with zero `aitm-core` edits.)
//! The binary (M5 Task 13) constructs the module only when `enabled` and privilege
//! are present.
//!
//! This task registers the **no-wire** commands only. The wire commands
//! (`l4.capture.*`, `l4.inject`, `l4.send_recv`, `l4.intercept.*`) are added in
//! M5 Tasks 10 and 12, where they compose [`L4Guard::check`] with the core
//! [`ScopeRateGuard::check_active`] at this same layer.
//!
//! [`Plugin`]: aitm_core::Plugin
//! [`Command`]: aitm_core::Command
//! [`Registry`]: aitm_core::Registry
//! [`CommandHost`]: aitm_core::CommandHost
//! [`L4Guard`]: crate::guard::L4Guard
//! [`L4FlowStore`]: crate::flow::L4FlowStore
//! [`L4Guard::check`]: crate::guard::L4Guard::check
//! [`ScopeRateGuard::check_active`]: aitm_core::ScopeRateGuard::check_active

use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamSchema, Params, Plugin, Registry, Value};

use crate::backend::pcap::PcapBackend;
use crate::backend::{CaptureInjectBackend, L4Error};
use crate::commands::intercept::InterceptSessions;
use crate::commands::PrivilegeReportSource;
use crate::config::{InterceptConfig, L4Config};
use crate::flow::{InMemoryL4FlowStore, L4FlowStore};
use crate::guard::L4Guard;
use crate::privilege::availability::{capture_availability, intercept_availability};
use crate::privilege::state::{PrivilegeConfig, ProcessLifetime};
use crate::privilege::PrivilegeState;

/// The result of the cheap startup capability probe. `Some(reason)` means that
/// class of capability is **unavailable**.
///
/// Since the privilege plan (P1b.7) the production module gates its wire verbs on
/// the live [`PrivilegeState`] instead; this type stays as the low-level probe
/// ([`L4Privilege::probe`]) and as the **fixed** privilege the test constructors
/// ([`L4Module::with_privilege`], [`L4Module::with_shared`]) take, whose reason
/// strings the gate and the status verbs then carry verbatim.
///
/// The two classes mirror the spec's privilege model:
/// - `capture_inject` — raw capture/inject (`l4.capture.*`, `l4.inject`,
///   `l4.send_recv`): Linux `CAP_NET_RAW`, macOS `/dev/bpf*` read+write.
/// - `intercept` — in-path NFQUEUE (`l4.intercept.*`): Linux `CAP_NET_ADMIN`;
///   unsupported on macOS and other platforms.
#[derive(Debug, Clone)]
pub struct L4Privilege {
    /// `Some(reason)` ⇒ raw capture/inject is unavailable (names the missing cap).
    pub capture_inject: Option<String>,
    /// `Some(reason)` ⇒ in-path interception is unavailable (names the missing cap).
    pub intercept: Option<String>,
}

impl L4Privilege {
    /// Both capability classes present (for wiring/tests that know they are).
    #[must_use]
    pub fn available() -> Self {
        Self {
            capture_inject: None,
            intercept: None,
        }
    }

    /// Both classes unavailable for one reason (unsupported platform / no process
    /// capability info). Only the Linux and fallback probes use it; macOS always
    /// splits capture/inject from the (unsupported) in-path class.
    #[cfg(not(target_os = "macos"))]
    fn unavailable_both(reason: &str) -> Self {
        Self {
            capture_inject: Some(reason.to_string()),
            intercept: Some(reason.to_string()),
        }
    }

    /// Run the cheap startup capability probe for this platform. Never opens a raw
    /// socket against a target; fails **closed** (reports unavailable) on any doubt.
    #[must_use]
    pub fn probe() -> Self {
        probe()
    }
}

/// Why a capability class is **not** usable on this core, as the status verbs report
/// it in `code` (spec §1, L4PAR-AC3/AC4). A closed vocabulary so a UI can attach
/// behaviour (D0's "Allow packet capture") without matching on `reason` text. The
/// `available` case is [`L4Availability::Available`], so an "available with a
/// reason" or "unavailable with no reason" state cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableCode {
    /// The platform supports the class; this process lacks the privilege.
    NeedsPrivilege,
    /// No backend for the class on this platform (e.g. in-path on macOS).
    UnsupportedPlatform,
    /// Supported and privileged, but not configured (`l4.intercept` absent).
    NotConfigured,
}

impl UnavailableCode {
    /// The wire string, in vocabulary order.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeedsPrivilege => "needs_privilege",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotConfigured => "not_configured",
        }
    }
}

/// One capability class's availability: either usable now, or unusable for a
/// closed-vocabulary [`UnavailableCode`] with the exact `reason` text the gated
/// verbs return in `L4 unavailable: <reason>`. Derived from the cached
/// [`L4Privilege`] through an [`AvailabilitySource`], so the status verbs and the
/// gated verbs can never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Availability {
    /// The class works on this core now.
    Available,
    /// The class does not work on this core now; `reason` is the gated verbs' text.
    Unavailable {
        /// The closed-vocabulary classification.
        code: UnavailableCode,
        /// The gated verbs' exact refusal text.
        reason: String,
    },
}

impl L4Availability {
    /// The wire `code`: `"available"`, or the [`UnavailableCode`]'s string.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable { code, .. } => code.as_str(),
        }
    }

    /// The gated verbs' exact refusal text; `None` when available.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason, .. } => Some(reason.as_str()),
        }
    }

    /// Whether the class is usable now.
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Where a status verb reads one capability class's availability **at invoke time**
/// (spec §1, L4PAR-AC38). [`L4Module::load`] builds one per class over the module's
/// `PrivilegeSource`: the live [`PrivilegeState`] in production (privilege spec
/// §2.1, §2.4), read afresh on every call, so the status verbs and the gated verbs
/// can never disagree.
pub type AvailabilitySource = Arc<dyn Fn() -> L4Availability + Send + Sync>;

impl L4Privilege {
    /// The capture/inject class's availability. A `Some` reason is `NeedsPrivilege`
    /// where the platform has a backend (macOS `/dev/bpf*`, Linux `CAP_NET_RAW`) and
    /// `UnsupportedPlatform` elsewhere.
    #[must_use]
    pub fn capture_availability(&self) -> L4Availability {
        match &self.capture_inject {
            None => L4Availability::Available,
            Some(reason) => L4Availability::Unavailable {
                code: if cfg!(any(target_os = "macos", target_os = "linux")) {
                    UnavailableCode::NeedsPrivilege
                } else {
                    UnavailableCode::UnsupportedPlatform
                },
                reason: reason.clone(),
            },
        }
    }

    /// The in-path class's availability. A `Some` reason is `NeedsPrivilege` on Linux
    /// (the only NFQUEUE platform) and `UnsupportedPlatform` elsewhere, macOS
    /// included. Privilege outranks configuration: only a privileged class with no
    /// `l4.intercept` config (`configured == false`) reads `NotConfigured`, carrying
    /// the same text `l4.intercept.start` refuses with.
    #[must_use]
    pub fn intercept_availability(&self, configured: bool) -> L4Availability {
        match &self.intercept {
            Some(reason) => L4Availability::Unavailable {
                code: if cfg!(target_os = "linux") {
                    UnavailableCode::NeedsPrivilege
                } else {
                    UnavailableCode::UnsupportedPlatform
                },
                reason: reason.clone(),
            },
            None if !configured => L4Availability::Unavailable {
                code: UnavailableCode::NotConfigured,
                reason: crate::commands::intercept::INTERCEPT_NOT_CONFIGURED.to_string(),
            },
            None => L4Availability::Available,
        }
    }
}

/// Linux: read the effective capability set from `/proc/self/status` and check the
/// `CAP_NET_RAW` / `CAP_NET_ADMIN` bits. Unreadable / unparsable ⇒ fail-closed.
#[cfg(target_os = "linux")]
fn probe() -> L4Privilege {
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;

    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            return L4Privilege::unavailable_both(&format!(
                "could not read process capabilities (/proc/self/status: {e})"
            ))
        }
    };
    let Some(bits) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    else {
        return L4Privilege::unavailable_both(
            "could not read effective capabilities from /proc/self/status",
        );
    };
    let has = |cap: u32| bits & (1u64 << cap) != 0;
    L4Privilege {
        capture_inject: (!has(CAP_NET_RAW)).then(|| {
            "missing CAP_NET_RAW (raw capture and inject need the packet-capture helper or a \
             privileged process)"
                .to_string()
        }),
        intercept: (!has(CAP_NET_ADMIN)).then(|| {
            "missing CAP_NET_ADMIN (in-path interception needs the core itself to hold \
             CAP_NET_ADMIN)"
                .to_string()
        }),
    }
}

/// macOS: capture/inject goes through `/dev/bpf*` (read=capture, write=inject), so
/// the first device node that opens read+write proves the capability. In-path
/// interception is unsupported (no NFQUEUE), matching the fail-closed spec.
#[cfg(target_os = "macos")]
fn probe() -> L4Privilege {
    use std::io::ErrorKind;

    let mut capture_inject = Some("no read+write access to any /dev/bpf* device".to_string());
    for n in 0..256u32 {
        let path = format!("/dev/bpf{n}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            // Opened read+write ⇒ capture+inject available; the handle drops at once.
            Ok(_f) => {
                capture_inject = None;
                break;
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => break, // past the last device node
                _ => continue,                // denied / busy: try the next node
            },
        }
    }
    L4Privilege {
        capture_inject,
        intercept: Some(
            "in-path interception is unsupported on macOS (Linux CAP_NET_ADMIN / NFQUEUE only)"
                .to_string(),
        ),
    }
}

/// Other platforms have no supported capture/inject or in-path backend: fail-closed.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe() -> L4Privilege {
    L4Privilege::unavailable_both("no supported L4 capture/inject backend on this platform")
}

/// The capability class a gated verb needs (privilege plan P1b.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateClass {
    /// Raw capture/inject: `l4.capture.*`, `l4.inject`, `l4.send_recv`.
    CaptureInject,
    /// In-path interception: `l4.intercept.*`. `configured` is whether the
    /// `l4.intercept` block is present; privilege outranks configuration.
    Intercept { configured: bool },
}

/// Where the gate and the status verbs read a class's availability.
///
/// A production module reads the live [`PrivilegeState`] on **every** call
/// (privilege spec §2.1, AC7): a core started before approval serves capture
/// after it, with no rebuild. The test constructors that take an
/// [`L4Privilege`] ([`L4Module::with_privilege`], [`L4Module::with_shared`])
/// hold that fixed result instead, carrying its reason strings verbatim, which
/// is what the parity tests' literals pin.
enum PrivilegeSource {
    Live(Arc<PrivilegeState>),
    Fixed(L4Privilege),
}

impl PrivilegeSource {
    /// The capture/inject backend the wire verbs hold (privilege spec §2.1, plan
    /// P1b.8): the live state's [`RoutedBackend`](crate::backend::routed::RoutedBackend),
    /// which routes every call on the current report; or, for a fixed test
    /// privilege, the plain in-process libpcap backend (the fixed gate already
    /// refuses an unavailable class before any call reaches it).
    fn backend(&self) -> Arc<dyn CaptureInjectBackend> {
        match self {
            Self::Live(state) => state.backend(),
            Self::Fixed(_) => Arc::new(PcapBackend::new()),
        }
    }

    /// The [`PrivilegeReport`](crate::privilege::report::PrivilegeReport) source
    /// the two status verbs carry under `privilege` (privilege spec §2.4, plan
    /// P1b.9): the live state's `report()` on every call; `None` for a fixed test
    /// privilege, which has no report to show.
    fn report_source(&self) -> PrivilegeReportSource {
        match self {
            Self::Live(state) => {
                let state = state.clone();
                Arc::new(move || Some(state.report()))
            }
            Self::Fixed(_) => Arc::new(|| None),
        }
    }

    /// One class's availability now (spec §2.4 mapping, plan P1b.4).
    fn availability(&self, class: GateClass) -> L4Availability {
        match (self, class) {
            (Self::Live(state), GateClass::CaptureInject) => capture_availability(&state.report()),
            (Self::Live(state), GateClass::Intercept { configured }) => {
                intercept_availability(&state.report(), configured)
            }
            (Self::Fixed(privilege), GateClass::CaptureInject) => privilege.capture_availability(),
            (Self::Fixed(privilege), GateClass::Intercept { configured }) => {
                privilege.intercept_availability(configured)
            }
        }
    }
}

/// A wire-touching `l4.*` command wrapped so that every invocation first reads its
/// class's availability from the shared [`PrivilegeSource`]: available ⇒ the inner
/// command runs; otherwise a typed [`L4Error::Unavailable`] carrying the exact
/// `reason` the status verb reports (privilege spec §2.4: for `needs_approval`,
/// `packet capture is not allowed yet (<how.label>)`). Nothing touches the wire
/// while gated. `name`, `schema`, `sensitivity` and `confirm_prompt` delegate to the
/// inner command, so the command appears honestly in `tools/list` and keeps its
/// `confirmable` reading before and after the privilege flips (AC27).
struct L4Gated {
    inner: Arc<dyn Command>,
    privilege: Arc<PrivilegeSource>,
    class: GateClass,
}

impl Command for L4Gated {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn schema(&self) -> ParamSchema {
        self.inner.schema()
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        // Classify honestly even while unavailable, so `tools/list` and the policy
        // gate see the real tier (all gated verbs are Sensitive, but delegate rather
        // than assume).
        self.inner.sensitivity()
    }

    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        // The operator handshake is the inner command's to offer; the gate neither
        // hides nor invents it (spec §2.4, AC27).
        self.inner.confirm_prompt(args)
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        match self.privilege.availability(self.class) {
            L4Availability::Available => self.inner.invoke(args, host),
            L4Availability::Unavailable { reason, .. } => {
                Err(anyhow::Error::new(L4Error::Unavailable(reason)))
            }
        }
    }
}

/// Wrap every command in `cmds` as [`L4Gated`] over `privilege` for `class`. Always
/// wraps: availability is decided per call, never at registration, so a flip after
/// start-up is seen (AC7). The two status verbs never reach this function:
/// `wire_commands` / `intercept_commands` return them separately and
/// [`L4Module::load`] registers them beside the gated list, so they always answer
/// with the availability object (spec §1, L4PAR-AC9).
fn gate(
    cmds: Vec<Arc<dyn Command>>,
    privilege: &Arc<PrivilegeSource>,
    class: GateClass,
) -> Vec<Arc<dyn Command>> {
    cmds.into_iter()
        .map(|inner| {
            Arc::new(L4Gated {
                inner,
                privilege: privilege.clone(),
                class,
            }) as Arc<dyn Command>
        })
        .collect()
}

/// The L4 protocol feature as a core [`Plugin`]. Holds the shared guard + flow
/// store and registers the `l4.*` command surface.
pub struct L4Module {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    /// In-path interception config; `None` ⇒ `l4.intercept.*` is `L4Unavailable`.
    intercept_cfg: Option<InterceptConfig>,
    /// Live `l4.intercept` sessions, shared with the intercept commands so a
    /// session started by one call outlives it.
    sessions: Arc<InterceptSessions>,
    /// Where the wire verbs' gate and the status verbs read privilege: the live
    /// state in production, a fixed result in tests. Fail-closed either way.
    privilege: Arc<PrivilegeSource>,
}

impl L4Module {
    /// Build a module from config over a fresh live [`PrivilegeState`] for this OS
    /// (`l4.enabled`, the `l4.privilege` block, a serving process). The wire verbs
    /// are gated on it per call, fail-closed, and see a later approval without a
    /// restart (privilege spec AC7). Tests that want a known privilege state use
    /// [`with_privilege`](L4Module::with_privilege) or
    /// [`with_state`](L4Module::with_state).
    #[must_use]
    pub fn new(cfg: &L4Config) -> Self {
        let state = PrivilegeState::new(&PrivilegeConfig {
            enabled: cfg.enabled,
            l4: cfg.privilege.clone(),
            lifetime: ProcessLifetime::Serving,
        });
        Self::with_state(cfg, Arc::new(state))
    }

    /// Build a module from config over a shared live [`PrivilegeState`] (the one
    /// the `l4.privilege` verb and the status replies read too). Every gated verb
    /// reads `state.report()` when invoked.
    #[must_use]
    pub fn with_state(cfg: &L4Config, state: Arc<PrivilegeState>) -> Self {
        Self::from_config(cfg, Arc::new(PrivilegeSource::Live(state)))
    }

    /// Build a module from config over a **fixed** capability probe result, whose
    /// reason strings the gate and the status verbs carry verbatim. A test
    /// constructor, for tests that force a known privilege state; the binary
    /// builds over the live state with [`with_state`](L4Module::with_state) /
    /// [`with_shared_state`](L4Module::with_shared_state).
    #[must_use]
    pub fn with_privilege(cfg: &L4Config, privilege: L4Privilege) -> Self {
        Self::from_config(cfg, Arc::new(PrivilegeSource::Fixed(privilege)))
    }

    fn from_config(cfg: &L4Config, privilege: Arc<PrivilegeSource>) -> Self {
        Self::from_parts(
            Arc::new(L4Guard::new(cfg)),
            Arc::new(InMemoryL4FlowStore::new()),
            cfg.intercept.clone(),
            privilege,
        )
    }

    /// Build a module over an already-shared guard + store (for wiring that owns
    /// the guard elsewhere, and for tests). `intercept_cfg` carries the in-path
    /// settings; `None` disables `l4.intercept.*`. Assumes privilege is present
    /// (the caller owns the guard and the capability decision).
    #[must_use]
    pub fn with_parts(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
    ) -> Self {
        Self::from_parts(
            guard,
            store,
            intercept_cfg,
            Arc::new(PrivilegeSource::Fixed(L4Privilege::available())),
        )
    }

    /// Build a module over an **already-shared** guard + store and a **fixed**
    /// privilege result, keeping the fail-closed gate. A test constructor: the
    /// binary, which pre-builds the L4 state for the scripting engine's
    /// [`L4Language`](crate::language::L4Language), uses
    /// [`with_shared_state`](L4Module::with_shared_state) over the live state.
    #[must_use]
    pub fn with_shared(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
        privilege: L4Privilege,
    ) -> Self {
        Self::from_parts(
            guard,
            store,
            intercept_cfg,
            Arc::new(PrivilegeSource::Fixed(privilege)),
        )
    }

    /// Build a module over an **already-shared** guard + store and the shared live
    /// [`PrivilegeState`]: the production path when the binary owns the guard/store
    /// so the scripting engine's [`L4Language`](crate::language::L4Language) and
    /// this command module act over the **same** L4 engagement state, and every
    /// gated verb sees a privilege flip without a restart (AC7).
    #[must_use]
    pub fn with_shared_state(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
        state: Arc<PrivilegeState>,
    ) -> Self {
        Self::from_parts(
            guard,
            store,
            intercept_cfg,
            Arc::new(PrivilegeSource::Live(state)),
        )
    }

    fn from_parts(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        intercept_cfg: Option<InterceptConfig>,
        privilege: Arc<PrivilegeSource>,
    ) -> Self {
        // Over a live state, attach the guard a Linux helper session's backend is
        // built over (plan P1b.14 hand-over): every live constructor (`new`,
        // `with_state`, `with_shared_state`) passes here, so the binary's wiring
        // cannot forget it. A fixed source has no state to attach to.
        if let PrivilegeSource::Live(state) = &*privilege {
            state.set_guard(Arc::clone(&guard));
        }
        Self {
            guard,
            store,
            intercept_cfg,
            sessions: Arc::new(InterceptSessions::new()),
            privilege,
        }
    }

    /// Hand the module the core's **own** listener ports (proxy, embedded-browser
    /// proxy, loopback bus, web UI, MCP streamable HTTP). They are set on the
    /// module's guard, so no capture — bus, CLI or Rhai, all of which record
    /// through this guard — ever records a loopback frame to or from one of them
    /// (L4PAR-AC34, spec §2.1). Replaces any set already there.
    #[must_use]
    pub fn with_self_ports(self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.guard.set_self_ports(ports);
        self
    }

    /// The shared deny-by-default guard (an `Arc` clone).
    #[must_use]
    pub fn guard(&self) -> Arc<L4Guard> {
        self.guard.clone()
    }

    /// The shared l4-owned flow store (an `Arc` clone).
    #[must_use]
    pub fn store(&self) -> Arc<dyn L4FlowStore> {
        self.store.clone()
    }
}

impl Plugin for L4Module {
    fn name(&self) -> &str {
        "l4"
    }

    fn load(&mut self, reg: &mut Registry) {
        // The single shared agent-gate object the guard owns: the Mcp-only wrapper and
        // the `l4.agent.*` commands read/flip the same gates the guard's
        // `add_runtime_scope` enforces, so an operator toggle is one live source of truth.
        let gates = self.guard.agent_gates();
        // The pure/read verbs (`l4.interfaces`, `l4.scope.*`, `l4.flow.*`, `l4.craft`)
        // work regardless of privilege — never privilege-gated, so these are
        // unwrapped. `l4.scope.add` needs no wrapper either: its widen gate lives in
        // the guard (`add_runtime_scope`), applies to untrusted and script/PoC
        // callers, and is skipped by a confirmed operator or CLI call
        // (`add_operator_scope`); both paths force `source = Runtime` via
        // `push_runtime`.
        for cmd in crate::commands::active_commands(self.guard(), self.store()) {
            reg.add_command(cmd);
        }
        // M5 Task 10 — the wire-touching commands (`l4.capture.*`, `l4.inject`,
        // `l4.send_recv`). Two layers wrap each Sensitive verb: the Mcp-only
        // per-capability agent gate (`agent_gate`, inner), then the fail-closed
        // privilege gate (`gate`, outer) so an unprivileged core returns a typed
        // `L4Unavailable` before the flag is even consulted. The operator who opted in
        // still sees an honest, drivable surface (amended M5 Task 13).
        // Both availability sources close over the one `PrivilegeSource` the gate
        // below reads (the live `PrivilegeState` in production), and the status
        // verbs query them at invoke time (spec §1, L4PAR-AC38): `l4.capture.status`
        // / `l4.intercept.status` and the gated verbs' `L4Unavailable` reason cannot
        // disagree, and a privilege flip after start-up is seen by both (privilege
        // spec AC7). Each status verb comes back separately from its gated list and
        // registers ungated beside it, so it always answers (L4PAR-AC9).
        let intercept_class = GateClass::Intercept {
            configured: self.intercept_cfg.is_some(),
        };
        let capture_source: AvailabilitySource = {
            let privilege = self.privilege.clone();
            Arc::new(move || privilege.availability(GateClass::CaptureInject))
        };
        let intercept_source: AvailabilitySource = {
            let privilege = self.privilege.clone();
            Arc::new(move || privilege.availability(intercept_class))
        };
        // Both status verbs also carry the live `PrivilegeReport` under their
        // optional `privilege` key (privilege spec §2.4, L4PRIV-AC4, plan P1b.9);
        // a fixed test privilege has no report, so the reply stays the parity four.
        let report_source = self.privilege.report_source();
        // The wire verbs share one backend: in production the state's routed
        // backend, so a helper session or a later approval is seen per call
        // (privilege spec §2.1, plan P1b.8).
        let (wire, capture_status) = crate::commands::wire_commands(
            self.guard(),
            self.store(),
            capture_source,
            self.privilege.backend(),
            report_source.clone(),
        );
        for cmd in gate(
            crate::commands::agent_gate(wire, &gates),
            &self.privilege,
            GateClass::CaptureInject,
        ) {
            reg.add_command(cmd);
        }
        reg.add_command(capture_status);
        // The in-path interception commands (M5 Task 12) register additively over
        // the shared session registry, so a `start` outlives the call and the later
        // verdict commands reach it. Agent-gated (`intercept` capability) then
        // privilege-gated on in-path (`CAP_NET_ADMIN`) the same way.
        let (intercept, intercept_status) = crate::commands::intercept::intercept_commands(
            self.guard(),
            self.store(),
            self.sessions.clone(),
            self.intercept_cfg.clone(),
            intercept_source,
            report_source,
        );
        for cmd in gate(
            crate::commands::agent_gate(intercept, &gates),
            &self.privilege,
            intercept_class,
        ) {
            reg.add_command(cmd);
        }
        reg.add_command(intercept_status);
        // The operator-only live toggle: `l4.agent.status` (read the four gates) and
        // `l4.agent.set` (flip one). Never privilege- or agent-gated here — the set
        // command self-gates to operator/CLI, and status is read-only.
        for cmd in crate::commands::agent_commands(gates.clone()) {
            reg.add_command(cmd);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aitm_core::{
        CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, StdGuard,
        Value,
    };
    use futures::future::BoxFuture;

    use super::*;

    /// The l4 commands never reissue HTTP; the core host still requires a client.
    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// A core `CommandHost` the l4 commands can be invoked against. The l4 commands
    /// read their own guard/store (the module's), so the host's store/guard are
    /// only there to satisfy the signature.
    fn host<'a>(
        store: &'a MemFlowStore,
        client: &'a StubClient,
        guard: &'a StdGuard,
    ) -> CommandHost<'a> {
        CommandHost::new(store, client, guard, None)
    }

    /// A prober scripted to one fixed macOS `needs_approval` row; these tests
    /// never run the real platform probe.
    struct OneRowProber;

    impl crate::privilege::state::Prober for OneRowProber {
        fn gather(
            &self,
            _request: Option<&crate::privilege::report::RequestProgress>,
        ) -> crate::privilege::derive::ProbeInputs {
            use crate::privilege::derive::{MacInputs, ProbeInputs};
            use crate::privilege::report::Platform;
            ProbeInputs {
                enabled: true,
                platform: Platform::Macos,
                mac: Some(MacInputs {
                    bpf_rw_opens: false,
                    receipt: None,
                    handoff_app_embeds_helper: false,
                }),
                linux: None,
                request: None,
                now_ms: 1_762_000_000_000,
            }
        }
    }

    /// A live `PrivilegeState` over the scripted prober, the way the binary
    /// holds one (shared with the `l4.privilege` verb and the scripting engine).
    fn live_state() -> Arc<PrivilegeState> {
        Arc::new(PrivilegeState::with_prober(
            &PrivilegeConfig {
                enabled: true,
                l4: crate::config::L4PrivilegeConfig::default(),
                lifetime: ProcessLifetime::Serving,
            },
            Box::new(OneRowProber),
            Arc::new(|| 1_762_000_000_000),
        ))
    }

    /// Plan P1b.14 hand-over: a module built over a **live** state attaches its
    /// guard to that state, so a Linux helper session that connects can build its
    /// `HelperBackend` over the module's guard instead of failing the attach with
    /// "no L4 guard attached to the privilege state". Both live constructors the
    /// binary's `assemble_with` uses (`with_state`, `with_shared_state`) do it.
    #[test]
    fn live_constructors_attach_the_guard_to_the_privilege_state() {
        let cfg = L4Config {
            enabled: true,
            ..L4Config::default()
        };

        let state = live_state();
        assert!(!state.has_guard(), "a fresh state has no guard attached");
        let _module = L4Module::with_state(&cfg, Arc::clone(&state));
        assert!(
            state.has_guard(),
            "with_state must attach the module's guard"
        );

        let state = live_state();
        let guard = Arc::new(L4Guard::new(&cfg));
        let _module = L4Module::with_shared_state(
            Arc::clone(&guard),
            Arc::new(InMemoryL4FlowStore::new()),
            None,
            Arc::clone(&state),
        );
        assert!(
            state.has_guard(),
            "with_shared_state must attach the shared guard"
        );
    }

    fn registered(cfg: &L4Config) -> (Registry, Arc<L4Guard>, Arc<dyn L4FlowStore>) {
        // Known privilege state: these tests exercise the command surface, not the
        // real platform probe (which they must not depend on).
        let module = L4Module::with_privilege(cfg, L4Privilege::available());
        let guard = module.guard();
        let store = module.store();
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));
        (reg, guard, store)
    }

    fn scope_add_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("cidr".to_string(), Value::Str("127.0.0.1/32".into()));
        m.insert("interface".to_string(), Value::Str("lo0".into()));
        m.insert("direction".to_string(), Value::Str("outbound".into()));
        m.insert("capability".to_string(), Value::Str("inject".into()));
        m.insert("ports".to_string(), Value::Str("1-1024".into()));
        m.insert("inject_rate_pps".to_string(), Value::Int(5));
        Params::new(m)
    }

    /// An IPv4/UDP/Raw craft spec in the `Value` shape `l4.craft` accepts
    /// (`Layer` is externally tagged with snake_case variant names).
    fn craft_spec() -> Value {
        let ipv4 = {
            let mut m = BTreeMap::new();
            m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
            let mut l = BTreeMap::new();
            l.insert("ipv4".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let udp = {
            let mut m = BTreeMap::new();
            m.insert("dst_port".to_string(), Value::Int(9));
            let mut l = BTreeMap::new();
            l.insert("udp".to_string(), Value::Object(m));
            Value::Object(l)
        };
        let raw = {
            let mut l = BTreeMap::new();
            l.insert(
                "raw".to_string(),
                Value::Array(b"probe".iter().map(|b| Value::Int(i64::from(*b))).collect()),
            );
            Value::Object(l)
        };
        let mut spec = BTreeMap::new();
        spec.insert("layers".to_string(), Value::Array(vec![ipv4, udp, raw]));
        Value::Object(spec)
    }

    fn craft_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), craft_spec());
        Params::new(m)
    }

    /// Pinned (plan Task 9): `load` registers the command surface; `l4.craft` and
    /// `l4.scope.add` are present; invoking `l4.craft` with an IPv4/UDP/`"probe"`
    /// spec returns the built length (33 = 20 IPv4 + 8 UDP + 5 payload) + a summary.
    #[test]
    fn commands_registered() {
        let (reg, _g, _s) = registered(&L4Config::default());

        for name in [
            "l4.interfaces",
            "l4.scope.add",
            "l4.scope.remove",
            "l4.scope.list",
            "l4.flow.list",
            "l4.flow.get",
            "l4.craft",
        ] {
            assert!(reg.command(name).is_some(), "{name} must be registered");
        }

        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let h = host(&store, &client, &guard);

        let result = reg
            .command("l4.craft")
            .expect("l4.craft registered")
            .invoke(craft_params(), &h)
            .expect("l4.craft ok");
        let Value::Object(obj) = result else {
            panic!("l4.craft must return an object");
        };
        assert_eq!(obj.get("length"), Some(&Value::Int(33)));
        let Some(Value::Bytes(bytes)) = obj.get("bytes") else {
            panic!("l4.craft must return bytes");
        };
        assert_eq!(bytes.len(), 33);
        let Some(Value::Object(summary)) = obj.get("summary") else {
            panic!("l4.craft must return a summary");
        };
        assert_eq!(
            summary.get("layers"),
            Some(&Value::Array(vec![
                Value::Str("IPv4".into()),
                Value::Str("UDP".into()),
            ]))
        );
        assert_eq!(summary.get("length"), Some(&Value::Int(33)));
    }

    /// Pinned (plan Task 9): `l4.scope.add` then `l4.scope.list` round-trips an
    /// entry — the listed entry carries exactly the fields that were added, and the
    /// add result is its id.
    #[test]
    fn scope_add_then_list() {
        // This test exercises the runtime add→list round-trip, so it opts into
        // scope widening; the gate itself is covered by
        // `scope_add_refused_when_widen_disabled`.
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        // Deny-by-default: empty to start.
        assert!(guard.list_scope().is_empty());

        let added = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect("l4.scope.add ok");
        let Value::Str(id) = added else {
            panic!("l4.scope.add must return the entry id");
        };
        assert!(!id.is_empty());

        // The guard now holds exactly that entry.
        let scope = guard.list_scope();
        assert_eq!(scope.len(), 1);

        let listed = reg
            .command("l4.scope.list")
            .expect("l4.scope.list registered")
            .invoke(Params::default(), &h)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array");
        };
        assert_eq!(entries.len(), 1);
        let Value::Object(entry) = &entries[0] else {
            panic!("a scope entry must be an object");
        };
        assert_eq!(entry.get("id"), Some(&Value::Str(id)));
        assert_eq!(entry.get("cidr"), Some(&Value::Str("127.0.0.1/32".into())));
        assert_eq!(entry.get("ports"), Some(&Value::Str("1-1024".into())));
        assert_eq!(entry.get("interface"), Some(&Value::Str("lo0".into())));
        assert_eq!(entry.get("direction"), Some(&Value::Str("outbound".into())));
        assert_eq!(entry.get("capability"), Some(&Value::Str("inject".into())));
        let Some(Value::Object(rate)) = entry.get("inject_rate") else {
            panic!("a scope entry must carry inject_rate");
        };
        assert_eq!(rate.get("pps"), Some(&Value::Int(5)));
        assert_eq!(rate.get("burst"), Some(&Value::Int(5)));
    }

    /// `l4.scope.remove` by id reverts to deny-by-default; an unknown id ⇒ `false`.
    #[test]
    fn scope_remove_by_id() {
        // Needs a runtime add to then remove ⇒ opt into widening.
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        let Value::Str(id) = reg
            .command("l4.scope.add")
            .unwrap()
            .invoke(scope_add_params(), &h)
            .unwrap()
        else {
            panic!("id");
        };
        assert_eq!(guard.list_scope().len(), 1);

        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id));
        let removed = reg
            .command("l4.scope.remove")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("remove ok");
        assert_eq!(removed, Value::Bool(true));
        assert!(guard.list_scope().is_empty());

        // A second remove of the same id (now gone) is `false`, not an error.
        let mut m = BTreeMap::new();
        m.insert(
            "id".to_string(),
            Value::Str(crate::commands::scope_id_to_string(
                crate::types::L4ScopeId::new(),
            )),
        );
        let removed = reg
            .command("l4.scope.remove")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("remove ok");
        assert_eq!(removed, Value::Bool(false));
    }

    /// A single operator-declared scope entry (on `eth0`, `10.0.0.0/8`), carrying
    /// `source: Config`, so tests can prove it survives a refused runtime add.
    fn config_declared_entry() -> crate::types::L4ScopeEntry {
        use crate::types::{IpCidr, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange, RateCap};
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "eth0".to_string(),
            direction: crate::types::L4Direction::Outbound,
            capability: crate::types::L4Capability::Inject,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: L4ScopeSource::Config,
        }
    }

    /// SEC-2 — with `allow_agent_widen` false (the default), a runtime `l4.scope.add`
    /// over the bus is refused with a typed [`L4GuardError::ScopeWideningDisabled`]
    /// and adds nothing; the operator's config-declared scope still loads and
    /// remains the only entry.
    #[test]
    fn scope_add_refused_when_widen_disabled() {
        use crate::guard::L4GuardError;

        // Default config ⇒ allow_agent_widen is false; one operator-declared entry.
        let cfg = L4Config {
            scope: vec![config_declared_entry()],
            ..L4Config::default()
        };
        assert!(!cfg.allow_agent_widen, "the default must be deny (false)");

        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        // The config-declared entry loaded regardless of the flag.
        assert_eq!(guard.list_scope().len(), 1, "config scope must load");

        // A runtime add is refused with the typed refusal, and adds nothing.
        let err = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect_err("runtime scope widening must be refused when disabled");
        let typed = err
            .downcast_ref::<L4GuardError>()
            .unwrap_or_else(|| panic!("want a typed L4GuardError, got {err:?}"));
        assert_eq!(*typed, L4GuardError::ScopeWideningDisabled);

        // No entry was added: only the operator's config entry remains, usable.
        let scope = guard.list_scope();
        assert_eq!(scope.len(), 1, "a refused add must not widen the scope");
        assert_eq!(scope[0].cidr.prefix, 8, "the config entry still stands");
    }

    /// With `allow_agent_widen` true (operator opt-in), a runtime `l4.scope.add`
    /// behaves as before: it succeeds and the entry is listed.
    #[test]
    fn scope_add_allowed_when_widen_enabled() {
        let cfg = L4Config {
            allow_agent_widen: true,
            ..L4Config::default()
        };
        let (reg, guard, _s) = registered(&cfg);
        let store = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&store, &client, &core_guard);

        assert!(guard.list_scope().is_empty(), "deny-by-default to start");

        let added = reg
            .command("l4.scope.add")
            .expect("l4.scope.add registered")
            .invoke(scope_add_params(), &h)
            .expect("l4.scope.add must succeed when widening is enabled");
        let Value::Str(id) = added else {
            panic!("l4.scope.add must return the entry id");
        };
        assert!(!id.is_empty());

        let listed = reg
            .command("l4.scope.list")
            .unwrap()
            .invoke(Params::default(), &h)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array");
        };
        assert_eq!(entries.len(), 1, "the added entry must be listed");
    }

    /// `l4.flow.get` round-trips a flow inserted into the module's own store:
    /// `l4.flow.list` shows its id and `l4.flow.get` summarizes it, including the
    /// injected packet. Proves the commands read the l4-owned store (no core edit).
    #[test]
    fn flow_list_and_get() {
        use crate::craft::PacketSummary;
        use crate::flow::{L4Bind, L4Flow, L4FlowId, L4FlowKind, L4Meta, L4Packet};
        use crate::types::L4Direction;

        let (reg, _g, store) = registered(&L4Config::default());
        let mem = MemFlowStore::new();
        let client = StubClient;
        let core_guard = StdGuard::default();
        let h = host(&mem, &client, &core_guard);

        let id = store.insert(L4Flow {
            id: L4FlowId::new(),
            kind: L4FlowKind::Craft,
            bind: L4Bind {
                interface: "lo0".into(),
                filter: None,
                queue: None,
            },
            packets: std::collections::VecDeque::from(vec![L4Packet {
                dir: L4Direction::Outbound,
                timestamp: std::time::SystemTime::now(),
                bytes: vec![0u8; 33],
                decoded: PacketSummary {
                    layers: vec!["IPv4".into(), "UDP".into()],
                    length: 33,
                },
                injected: true,
            }]),
            metadata: L4Meta::default(),
        });

        let listed = reg
            .command("l4.flow.list")
            .unwrap()
            .invoke(Params::default(), &h)
            .expect("flow.list ok");
        let id_str = crate::commands::flow_id_to_string(id);
        assert_eq!(listed, Value::Array(vec![Value::Str(id_str.clone())]));

        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(id_str.clone()));
        let got = reg
            .command("l4.flow.get")
            .unwrap()
            .invoke(Params::new(m), &h)
            .expect("flow.get ok");
        let Value::Object(obj) = got else {
            panic!("flow.get returns an object");
        };
        assert_eq!(obj.get("id"), Some(&Value::Str(id_str)));
        assert_eq!(obj.get("kind"), Some(&Value::Str("craft".into())));
        assert_eq!(obj.get("interface"), Some(&Value::Str("lo0".into())));
        assert_eq!(obj.get("packet_count"), Some(&Value::Int(1)));
        assert_eq!(obj.get("injected_count"), Some(&Value::Int(1)));
    }

    /// An `l4.inject` params object (spec + dst + interface). The gate short-circuits
    /// before these are parsed, so a representative-but-minimal set suffices.
    fn inject_params() -> Params {
        let mut m = BTreeMap::new();
        m.insert("spec".to_string(), craft_spec());
        m.insert("dst".to_string(), Value::Str("127.0.0.1".into()));
        m.insert("interface".to_string(), Value::Str("lo0".into()));
        Params::new(m)
    }

    /// Amended M5 Task 13 (AC17): with the module enabled but the startup capability
    /// probe reporting no privilege, the module STILL registers its full surface; the
    /// pure/read verbs still work (`l4.interfaces`), but the wire-touching verbs
    /// (`l4.inject`) return a typed `L4Unavailable` naming the missing capability —
    /// without a panic and without re-probing.
    #[test]
    fn enabled_no_priv_wire_unavailable() {
        use crate::backend::L4Error;

        let cfg = L4Config {
            enabled: true,
            ..L4Config::default()
        };
        let privilege = L4Privilege {
            capture_inject: Some("missing CAP_NET_RAW / /dev/bpf access".into()),
            intercept: Some("missing CAP_NET_ADMIN".into()),
        };
        let module = L4Module::with_privilege(&cfg, privilege);
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));

        // The full surface is registered (an honest, drivable surface for the operator
        // who opted in), wire verbs included.
        assert!(reg.command("l4.inject").is_some(), "l4.inject registered");
        assert!(
            reg.command("l4.interfaces").is_some(),
            "l4.interfaces registered"
        );
        assert!(reg.command("l4.craft").is_some(), "l4.craft registered");

        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let h = host(&store, &client, &guard);

        // A pure/read verb works regardless of privilege.
        reg.command("l4.interfaces")
            .expect("l4.interfaces registered")
            .invoke(Params::default(), &h)
            .expect("l4.interfaces works without privilege");

        // A wire verb fails closed with the specific capability reason.
        let err = reg
            .command("l4.inject")
            .expect("l4.inject registered")
            .invoke(inject_params(), &h)
            .unwrap_err();
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        match l4 {
            L4Error::Unavailable(why) => assert!(
                why.contains("CAP_NET_RAW") || why.contains("/dev/bpf"),
                "the reason must name the missing capability, got {why:?}"
            ),
            other => panic!("want L4Error::Unavailable, got {other:?}"),
        }
    }

    /// Invoke a registered `l4.*` verb with no params against a stub host.
    fn invoke_no_params(reg: &Registry, name: &str) -> anyhow::Result<Value> {
        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let h = host(&store, &client, &guard);
        reg.command(name)
            .unwrap_or_else(|| panic!("{name} registered"))
            .invoke(Params::default(), &h)
    }

    /// The expected availability object: `{available, code, reason, <payload_key>: []}`.
    fn availability_value(
        available: bool,
        code: &str,
        reason: Option<&str>,
        payload_key: &str,
    ) -> Value {
        let mut m = BTreeMap::new();
        m.insert("available".to_string(), Value::Bool(available));
        m.insert("code".to_string(), Value::Str(code.into()));
        m.insert(
            "reason".to_string(),
            reason.map_or(Value::Null, |r| Value::Str(r.into())),
        );
        m.insert(payload_key.to_string(), Value::Array(vec![]));
        Value::Object(m)
    }

    /// L4PAR-AC3 / AC4 (plan A4): on a privileged module with in-path configured,
    /// both status verbs answer the availability object with `available: true`,
    /// `code: "available"`, `reason: null` and an empty payload.
    #[test]
    fn status_verbs_answer_when_privileged() {
        let cfg = L4Config {
            enabled: true,
            intercept: Some(InterceptConfig::default()),
            ..L4Config::default()
        };
        let module = L4Module::with_privilege(&cfg, L4Privilege::available());
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));

        assert_eq!(
            invoke_no_params(&reg, "l4.capture.status").expect("capture.status answers"),
            availability_value(true, "available", None, "captures")
        );
        assert_eq!(
            invoke_no_params(&reg, "l4.intercept.status").expect("intercept.status answers"),
            availability_value(true, "available", None, "sessions")
        );
    }

    /// L4PAR-AC34 (plan A10): `with_self_ports` sets the core's own listener
    /// ports on the module's guard, the one every `l4.capture.*` verb records
    /// through.
    #[test]
    fn with_self_ports_sets_the_guard() {
        let cfg = L4Config {
            enabled: true,
            ..L4Config::default()
        };
        let module = L4Module::with_privilege(&cfg, L4Privilege::available())
            .with_self_ports([28182, 27431]);
        assert_eq!(module.guard().self_ports(), vec![27431, 28182]);
    }

    /// L4PAR-AC4 (plan A4): privilege present but no `intercept` config ⇒
    /// `l4.intercept.status` reads `not_configured` with the exact text
    /// `l4.intercept.start` refuses with.
    #[test]
    fn intercept_status_not_configured() {
        let cfg = L4Config {
            enabled: true,
            intercept: None,
            ..L4Config::default()
        };
        let module = L4Module::with_privilege(&cfg, L4Privilege::available());
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(module));

        assert_eq!(
            invoke_no_params(&reg, "l4.intercept.status").expect("intercept.status answers"),
            availability_value(
                false,
                "not_configured",
                Some("in-path interception is disabled (no `intercept` config)"),
                "sessions"
            )
        );
    }

    /// L4PAR-AC4 (plan A4): the real macOS probe classifies in-path as
    /// `unsupported_platform` with a non-empty reason, and privilege outranks
    /// configuration (`configured = false` does not turn it into
    /// `not_configured`). The literal reason text is the e2e cell's to pin.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_probe_intercept_is_unsupported_platform() {
        let av = L4Privilege::probe().intercept_availability(false);
        assert_eq!(av.code_str(), "unsupported_platform");
        assert!(
            av.reason().is_some_and(|r| !r.is_empty()),
            "a non-empty reason, got {av:?}"
        );
        assert!(!av.is_available());
    }

    /// L4PAR-AC4 (plan A14): on Linux, the only NFQUEUE platform, a probe that found
    /// `CAP_NET_ADMIN` missing classifies in-path as `needs_privilege` even when the
    /// `l4.intercept` block is configured (privilege outranks configuration).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_intercept_without_cap_net_admin_needs_privilege() {
        let av = L4Privilege {
            capture_inject: None,
            intercept: Some("missing CAP_NET_ADMIN".into()),
        }
        .intercept_availability(true);
        assert_eq!(av.code_str(), "needs_privilege");
        assert_eq!(av.reason(), Some("missing CAP_NET_ADMIN"));
        assert!(!av.is_available());
    }

    /// The real startup probe is defensive: it never panics, whatever the platform
    /// or privilege. (Behaviour is platform-dependent; this only pins "no panic".)
    #[test]
    fn probe_does_not_panic() {
        let _ = L4Privilege::probe();
    }
}
