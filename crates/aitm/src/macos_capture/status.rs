//! The `capture.status` handle and verb: what the core knows about the macOS NE
//! capture path, recorded by the feeder (`feeder.rs`) and read by the bus verb
//! [`CaptureStatusPlugin`] registers (spec D1, D6).
//!
//! The handle is split into a [`CaptureStatusWriter`] (the feeder's side; its
//! mutators are `pub(super)`, so only `macos_capture` can record a transition)
//! and a [`CaptureStatusReader`] (the verb's side; one method,
//! [`CaptureStatusReader::snapshot`]), so "read-only from the bus" is a
//! type-level fact rather than a review convention (spec D1, CS-AC16; precedent:
//! the sealed `Governance` in `wire.rs`).
//!
//! Storage is one mutex over the small, rarely-changing facts (feeder state,
//! provider state, scope tokens) plus atomics for the per-flow counters and the
//! last-handoff time, so the hot path — one flow handed off — is two relaxed
//! atomic operations and takes no lock (spec Anti-goals). `snapshot()` takes the
//! mutex and then reads the atomics: a consistent view at that granularity, not a
//! transaction (spec D2).
//!
//! Timestamps are Unix-epoch milliseconds (spec D9). `0` is the internal "none"
//! sentinel and is emitted as `null`; a real epoch-millisecond value is never 0,
//! so a pre-1970 clock reads as none.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Plugin, Registry, Sensitivity, TypeDesc,
    Value,
};

use super::capability::CaptureCapability;
use super::listener::{FlowKind, ScopeSpec};

/// Why the feeder is off: the closed vocabulary `feeder.reason` carries when
/// `feeder.state == "off"` (spec D7, CS-AC4). Exactly four values; clients may
/// match on [`as_str`](Self::as_str).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffReason {
    /// `macos_capture.enabled` is false in the config file.
    Disabled,
    /// Enabled, but this is not a macOS build.
    NotMacos,
    /// macOS and enabled, but the feeder has not bound yet — the window before
    /// `run`, or the one-shot CLI mode where it never runs.
    NotStarted,
    /// The feeder ran and returned.
    Stopped,
}

impl OffReason {
    /// The wire string, in vocabulary order.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "macos_capture.enabled is false",
            Self::NotMacos => "not a macOS build",
            Self::NotStarted => "not started",
            Self::Stopped => "stopped",
        }
    }
}

/// Where the feeder is (spec D2 `feeder`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeederState {
    /// Not running, for the carried reason.
    Off(OffReason),
    /// The sockets are bound and the rendezvous is published.
    Listening,
    /// The sockets could not be bound or the rendezvous could not be published;
    /// terminal for the session. The reason is `io::ErrorKind` text, never a path.
    BindFailed(String),
}

/// Whether a verified provider is attached (spec D2 `provider`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderState {
    /// No provider holds the scope.
    Detached,
    /// A provider passed the code-signature check and received its initial scope.
    Attached {
        /// When the initial scope was sent, Unix-epoch milliseconds (`0` = unknown).
        attached_at_ms: u64,
        /// The team the verifier's requirement pins ([`PeerVerifier::team_id`]),
        /// not a value read from the peer.
        ///
        /// [`PeerVerifier::team_id`]: super::peer_auth::PeerVerifier::team_id
        team_id: Option<String>,
    },
}

/// One consistent read of the handle (spec D1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatusSnapshot {
    /// `macos_capture.enabled`, fixed for the process.
    pub enabled: bool,
    /// Feeder state.
    pub feeder: FeederState,
    /// Provider state.
    pub provider: ProviderState,
    /// The tokens of the scope spec most recently sent to the attached provider;
    /// empty when detached.
    pub scope_tokens: Vec<String>,
    /// TCP flows handed off during the current attachment.
    pub tcp_handed_off: u64,
    /// UDP flows handed off during the current attachment.
    pub udp_handed_off: u64,
    /// When the last flow was handed off, Unix-epoch milliseconds; `None` when no
    /// flow has been handed off in this attachment.
    pub last_handoff_at_ms: Option<u64>,
}

impl CaptureStatusSnapshot {
    /// The derived capability (spec D5), in precedence order: a bind failure is
    /// `Degraded`; an attached provider is `Capturing` once a flow has been handed
    /// off in this attachment and `ApprovedAttached` before; a listening feeder
    /// with no provider is `AwaitingProvider`; an off feeder is `FeederOff` with the
    /// off reason. The verb never produces the two app-side variants.
    pub fn capability(&self) -> CaptureCapability {
        match (&self.feeder, &self.provider) {
            (FeederState::BindFailed(reason), _) => CaptureCapability::Degraded(reason.clone()),
            (_, ProviderState::Attached { .. }) => {
                if self.tcp_handed_off.saturating_add(self.udp_handed_off) > 0 {
                    CaptureCapability::Capturing
                } else {
                    CaptureCapability::ApprovedAttached
                }
            }
            (FeederState::Listening, ProviderState::Detached) => {
                CaptureCapability::AwaitingProvider
            }
            (FeederState::Off(reason), ProviderState::Detached) => {
                CaptureCapability::FeederOff(reason.as_str().to_string())
            }
        }
    }

    /// The exact wire shape (spec D7): nine top-level keys, nested `feeder`,
    /// `provider` and `flows_handed_off` objects, nullable fields as `Null`.
    pub fn to_value(&self) -> Value {
        let capability = self.capability();
        let capability_reason = match &capability {
            CaptureCapability::Degraded(reason) | CaptureCapability::FeederOff(reason) => {
                Value::Str(reason.clone())
            }
            _ => Value::Null,
        };
        let (feeder_state, feeder_reason) = match &self.feeder {
            FeederState::Off(reason) => ("off", Value::Str(reason.as_str().to_string())),
            FeederState::Listening => ("listening", Value::Null),
            FeederState::BindFailed(reason) => ("bind_failed", Value::Str(reason.clone())),
        };
        let (provider_state, attached_at, team_id) = match &self.provider {
            ProviderState::Detached => ("detached", Value::Null, Value::Null),
            ProviderState::Attached {
                attached_at_ms,
                team_id,
            } => (
                "attached",
                millis_value(*attached_at_ms),
                team_id.clone().map_or(Value::Null, Value::Str),
            ),
        };
        object([
            ("capability", Value::Str(capability.wire_name().to_string())),
            ("capability_reason", capability_reason),
            ("enabled", Value::Bool(self.enabled)),
            (
                "feeder",
                object([
                    ("reason", feeder_reason),
                    ("state", Value::Str(feeder_state.to_string())),
                ]),
            ),
            (
                "flows_handed_off",
                object([
                    ("tcp", count_value(self.tcp_handed_off)),
                    ("udp", count_value(self.udp_handed_off)),
                ]),
            ),
            (
                "last_handoff_at",
                self.last_handoff_at_ms.map_or(Value::Null, millis_value),
            ),
            (
                "provider",
                object([
                    ("attached_at", attached_at),
                    ("state", Value::Str(provider_state.to_string())),
                    ("team_id", team_id),
                ]),
            ),
            (
                "scope_entries",
                Value::Int(i64::try_from(self.scope_tokens.len()).unwrap_or(i64::MAX)),
            ),
            (
                "scope_tokens",
                Value::Array(
                    self.scope_tokens
                        .iter()
                        .map(|token| Value::Str(token.clone()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// A `Value::Object` from `(key, value)` pairs.
pub(crate) fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// An epoch-millisecond stamp as the wire emits it: `Null` for the `0` sentinel
/// (or a value that does not fit `i64`), else `Int`.
fn millis_value(ms: u64) -> Value {
    if ms == 0 {
        return Value::Null;
    }
    i64::try_from(ms).map_or(Value::Null, Value::Int)
}

/// A counter as the wire emits it; saturates at `i64::MAX`.
fn count_value(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// Now, as Unix-epoch milliseconds; `0` (the none sentinel) for a pre-1970 clock
/// or a count that does not fit.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| u64::try_from(since_epoch.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// Lock `m`, recovering from a poisoned lock: the state is plain data and no
/// critical section here can leave it inconsistent.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The facts behind the mutex: rarely written, never on the per-flow path.
struct Inner {
    feeder: FeederState,
    provider: ProviderState,
    tokens: Vec<String>,
    /// Bumped by every [`CaptureStatusWriter::attached`]; an [`Attachment`] clears
    /// on drop only while this still equals the value it was issued with.
    generation: u64,
}

/// The state both halves of the handle share.
struct Shared {
    enabled: bool,
    inner: Mutex<Inner>,
    tcp_handed_off: AtomicU64,
    udp_handed_off: AtomicU64,
    /// `0` = no handoff in this attachment.
    last_handoff_at_ms: AtomicU64,
}

impl Shared {
    /// Zero the per-attachment counters and the last-handoff time.
    fn reset_counters(&self) {
        self.tcp_handed_off.store(0, Ordering::Relaxed);
        self.udp_handed_off.store(0, Ordering::Relaxed);
        self.last_handoff_at_ms.store(0, Ordering::Relaxed);
    }

    /// Record a detach: provider `Detached`, tokens cleared, counters zeroed. The
    /// caller holds the lock; idempotent.
    fn clear_attachment(&self, inner: &mut Inner) {
        inner.provider = ProviderState::Detached;
        inner.tokens.clear();
        self.reset_counters();
    }
}

/// The shared capture-status state; built only through [`CaptureStatus::channel`],
/// which hands out the two halves.
pub struct CaptureStatus;

impl CaptureStatus {
    /// A writer/reader pair over fresh state. The initial feeder state is `Off`
    /// with the reason the constructor can derive from its inputs: `Disabled` when
    /// `!enabled`, `NotMacos` off a macOS build, else `NotStarted` (spec D1). Reads
    /// `cfg!(target_os = "macos")` itself; see [`channel_on`](Self::channel_on).
    pub fn channel(enabled: bool) -> (CaptureStatusWriter, CaptureStatusReader) {
        Self::channel_on(enabled, cfg!(target_os = "macos"))
    }

    /// [`channel`](Self::channel) with the build target passed in, so a test on any
    /// platform can exercise both branches.
    pub(crate) fn channel_on(
        enabled: bool,
        macos: bool,
    ) -> (CaptureStatusWriter, CaptureStatusReader) {
        let reason = if !enabled {
            OffReason::Disabled
        } else if !macos {
            OffReason::NotMacos
        } else {
            OffReason::NotStarted
        };
        let shared = Arc::new(Shared {
            enabled,
            inner: Mutex::new(Inner {
                feeder: FeederState::Off(reason),
                provider: ProviderState::Detached,
                tokens: Vec::new(),
                generation: 0,
            }),
            tcp_handed_off: AtomicU64::new(0),
            udp_handed_off: AtomicU64::new(0),
            last_handoff_at_ms: AtomicU64::new(0),
        });
        (
            CaptureStatusWriter(Arc::clone(&shared)),
            CaptureStatusReader(shared),
        )
    }
}

/// The feeder's half: records transitions. Every mutator is `pub(super)`, so only
/// `macos_capture` can call one; `wire.rs`, `main.rs`, other crates and the
/// integration tests can only move the writer into the feeder.
#[derive(Clone)]
pub struct CaptureStatusWriter(Arc<Shared>);

impl CaptureStatusWriter {
    /// The sockets are bound and the rendezvous is published.
    pub(super) fn listening(&self) {
        lock(&self.0.inner).feeder = FeederState::Listening;
    }

    /// The session could not start; `reason` must carry no path (spec D3).
    pub(super) fn bind_failed(&self, reason: String) {
        lock(&self.0.inner).feeder = FeederState::BindFailed(reason);
    }

    /// The session returned: feeder `Off(Stopped)` and the provider forced
    /// `Detached` with tokens and counters cleared. A later [`Attachment`] drop
    /// re-clears the same fields and changes nothing else.
    pub(super) fn stopped(&self) {
        let mut inner = lock(&self.0.inner);
        inner.feeder = FeederState::Off(OffReason::Stopped);
        self.0.clear_attachment(&mut inner);
    }

    /// A verified provider received its initial scope: stamp the attach time and
    /// the verifier's team, replace the tokens, and start the per-attachment
    /// counters from zero. Hold the returned guard for the life of the
    /// attachment; dropping it records the detach.
    ///
    /// A newer attachment supersedes an older guard: each call bumps the handle's
    /// attachment generation, and a guard whose generation is no longer current
    /// changes nothing when it drops, so a stale guard can never clear the
    /// attachment that replaced it.
    #[must_use]
    pub(super) fn attached(&self, team_id: Option<String>, tokens: Vec<String>) -> Attachment {
        let generation = {
            let mut inner = lock(&self.0.inner);
            inner.provider = ProviderState::Attached {
                attached_at_ms: now_ms(),
                team_id,
            };
            inner.tokens = tokens;
            inner.generation = inner.generation.wrapping_add(1);
            self.0.reset_counters();
            inner.generation
        };
        Attachment {
            shared: Arc::clone(&self.0),
            generation,
        }
    }

    /// A re-pushed scope reached the provider: replace the tokens.
    pub(super) fn scope_pushed(&self, tokens: Vec<String>) {
        lock(&self.0.inner).tokens = tokens;
    }

    /// One flow of `kind` was handed to a pump. Two relaxed atomic operations; no
    /// lock (spec Anti-goals).
    pub(super) fn handed_off(&self, kind: FlowKind) {
        let counter = match kind {
            FlowKind::Tcp => &self.0.tcp_handed_off,
            FlowKind::Udp => &self.0.udp_handed_off,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.0.last_handoff_at_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// RAII proof that a provider is attached. Dropping it records the detach
/// (provider `Detached`, tokens cleared, counters and last-handoff time zeroed),
/// so an attachment task that is cancelled at shutdown detaches too (spec D3).
/// Only the current guard clears: one superseded by a later
/// [`CaptureStatusWriter::attached`] drops silently.
pub struct Attachment {
    shared: Arc<Shared>,
    /// The handle's attachment generation when this guard was issued.
    generation: u64,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        let mut inner = lock(&self.shared.inner);
        if inner.generation == self.generation {
            self.shared.clear_attachment(&mut inner);
        }
    }
}

/// The bus verb's half: reads only. Its one public method is
/// [`snapshot`](Self::snapshot); the writer's mutators are not reachable through
/// it. A writer call on the reader does not compile:
///
/// ```compile_fail
/// use aitm::macos_capture::status::CaptureStatus;
/// let (_w, reader) = CaptureStatus::channel(true);
/// reader.listening();
/// ```
///
/// The same lines with a read compile and run:
///
/// ```
/// use aitm::macos_capture::status::CaptureStatus;
/// let (_w, reader) = CaptureStatus::channel(true);
/// let _ = reader.snapshot();
/// ```
#[derive(Clone)]
pub struct CaptureStatusReader(Arc<Shared>);

impl CaptureStatusReader {
    /// One consistent read: takes the mutex, then reads the atomics. No I/O.
    pub fn snapshot(&self) -> CaptureStatusSnapshot {
        let inner = lock(&self.0.inner);
        let last_handoff_at_ms = self.0.last_handoff_at_ms.load(Ordering::Relaxed);
        CaptureStatusSnapshot {
            enabled: self.0.enabled,
            feeder: inner.feeder.clone(),
            provider: inner.provider.clone(),
            scope_tokens: inner.tokens.clone(),
            tcp_handed_off: self.0.tcp_handed_off.load(Ordering::Relaxed),
            udp_handed_off: self.0.udp_handed_off.load(Ordering::Relaxed),
            last_handoff_at_ms: (last_handoff_at_ms != 0).then_some(last_handoff_at_ms),
        }
    }
}

/// The tokens of a provider scope spec, exactly as the emitter joined them.
/// `provider_scope_spec` never emits a token containing whitespace, so this
/// round-trips: `scope_tokens(&spec).join(" ") == spec.spec` (spec D2).
pub(crate) fn scope_tokens(spec: &ScopeSpec) -> Vec<String> {
    spec.spec
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The `capture.status` plugin (spec D6): a command-only provider that holds the
/// handle's read half and registers the verb. It observes no events. `wire.rs`
/// registers it on every platform and for every `Features`, so a client can
/// always ask and the answer is honest about why nothing is captured.
pub struct CaptureStatusPlugin {
    reader: CaptureStatusReader,
}

impl CaptureStatusPlugin {
    /// A plugin over the read half of a [`CaptureStatus::channel`] (CS-AC16: a
    /// reader, never a writer).
    pub fn new(reader: CaptureStatusReader) -> Self {
        Self { reader }
    }
}

impl Plugin for CaptureStatusPlugin {
    fn name(&self) -> &str {
        "capture_status"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(CaptureStatusCommand {
            reader: self.reader.clone(),
        }));
    }
}

/// `capture.status`: one snapshot of the handle as the D7 wire shape. Read-only
/// (`Sensitivity::Read`, so callable under the agent's `ReadOnly` policy),
/// parameterless, and infallible: `invoke` reads nothing from its arguments or
/// the host and never errors.
struct CaptureStatusCommand {
    reader: CaptureStatusReader,
}

impl Command for CaptureStatusCommand {
    fn name(&self) -> &str {
        "capture.status"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "What the core knows about the macOS Network/System Extension \
                          capture path: whether `macos_capture.enabled` is set, whether \
                          the capture feeder is listening, whether a code-signature-verified \
                          extension provider is attached, the scope it holds, and the flows \
                          it has handed off during the current attachment. Read-only and \
                          parameterless. Times are Unix epoch milliseconds. When \
                          `feeder.state` is `off`, `feeder.reason` is exactly one of \
                          `macos_capture.enabled is false`, `not a macOS build`, \
                          `not started`, `stopped`. This is not the record toggle: \
                          `proxy.status.capturing` reports whether the proxy records flows."
                .into(),
            params: vec![],
            result: TypeDesc::Object(result_fields()),
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(self.reader.snapshot().to_value())
    }
}

/// The fields `capture.status` emits (spec D6/D7), every one described. The five
/// nullable fields are `required: false` and emitted as `Null` when absent
/// (precedent: `summary_fields()` in `aitm-plugins/src/capture.rs`).
fn result_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field(
            "enabled",
            TypeDesc::Bool,
            true,
            "Whether `macos_capture.enabled` is true in the config file; fixed for the process.",
        ),
        field(
            "feeder",
            TypeDesc::Object(vec![
                field(
                    "state",
                    TypeDesc::Str,
                    true,
                    "`off`, `listening`, or `bind_failed`.",
                ),
                field(
                    "reason",
                    TypeDesc::Str,
                    false,
                    "Why the feeder is off or could not start. When `state` is `off`, \
                     exactly one of `macos_capture.enabled is false`, `not a macOS build`, \
                     `not started`, `stopped`; when `bind_failed`, the step that failed and \
                     the I/O error kind, never a path. Null when `listening`.",
                ),
            ]),
            true,
            "The core-side capture feeder: whether its Unix sockets are bound and its \
             rendezvous is published.",
        ),
        field(
            "provider",
            TypeDesc::Object(vec![
                field("state", TypeDesc::Str, true, "`detached` or `attached`."),
                field(
                    "attached_at",
                    TypeDesc::Int,
                    false,
                    "When the attached provider received its initial scope, Unix epoch \
                     milliseconds. Null when detached.",
                ),
                field(
                    "team_id",
                    TypeDesc::Str,
                    false,
                    "The Apple team identifier the provider's code signature was verified \
                     against (the requirement's pinned OU); not read from the peer's signing \
                     information. Null when detached or when the verifier pins no team.",
                ),
            ]),
            true,
            "The Network/System Extension provider: whether one has passed the \
             code-signature check and holds a scope.",
        ),
        field(
            "scope_entries",
            TypeDesc::Int,
            true,
            "The number of scope tokens the attached provider holds (`scope_tokens.len()`); \
             0 when detached.",
        ),
        field(
            "scope_tokens",
            TypeDesc::Array(Box::new(TypeDesc::Str)),
            true,
            "The tokens of the scope spec most recently sent to the attached provider (host \
             names, wildcard hosts, L4 capture addresses), in the order sent; empty when \
             detached.",
        ),
        field(
            "flows_handed_off",
            TypeDesc::Object(vec![
                field(
                    "tcp",
                    TypeDesc::Int,
                    true,
                    "TCP flows the provider handed to the core during the current attachment.",
                ),
                field(
                    "udp",
                    TypeDesc::Int,
                    true,
                    "UDP flows the provider handed to the core during the current attachment.",
                ),
            ]),
            true,
            "Flows handed to the core during the current attachment, by kind. Zeroed when a \
             provider attaches and when it detaches, so a detached provider shows zeros.",
        ),
        field(
            "last_handoff_at",
            TypeDesc::Int,
            false,
            "When the last flow was handed off, Unix epoch milliseconds. Null when no flow \
             has been handed off in the current attachment.",
        ),
        field(
            "capability",
            TypeDesc::Str,
            true,
            "The derived capture capability: `feeder_off`, `degraded`, `awaiting_provider`, \
             `approved_attached`, or `capturing`. Combine with `scope_entries == 0` for an \
             \"on, nothing in scope\" reading.",
        ),
        field(
            "capability_reason",
            TypeDesc::Str,
            false,
            "Why the capability is `feeder_off` (the off reason) or `degraded` (the bind \
             failure); null for every other capability.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use aitm_core::{
        Command, CommandHost, HttpFlow, HttpRequest, MemFlowStore, ParamDef, Params, Plugin,
        ProxyClient, Registry, ScopeEntry, Sensitivity, StdGuard, TypeDesc, Value,
    };
    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };
    use futures::future::BoxFuture;

    use super::super::adapter::CAPTURE_INTERFACE;
    use super::super::capability::CaptureCapability;
    use super::super::feeder::DEFAULT_SOCKET_DIR;
    use super::super::listener::{FlowKind, ScopeSpec};
    use super::super::scope_spec::provider_scope_spec;
    use super::super::test_support::{
        at, bind_failed_literal, capturing_literal, disabled_literal, listening_literal, matrix,
        now_ms, s,
    };
    use super::{
        object, scope_tokens, CaptureStatus, CaptureStatusCommand, CaptureStatusPlugin,
        CaptureStatusSnapshot, FeederState, OffReason, ProviderState,
    };

    // ---- helpers ------------------------------------------------------------------

    fn attached_at(snapshot: &CaptureStatusSnapshot) -> u64 {
        match &snapshot.provider {
            ProviderState::Attached { attached_at_ms, .. } => *attached_at_ms,
            ProviderState::Detached => panic!("expected an attached provider: {snapshot:?}"),
        }
    }

    // ---- tests --------------------------------------------------------------------

    /// **CS-AC4.** The constructor's three `off` reasons, from its two inputs; the
    /// disabled one is the D7 literal byte for byte.
    #[test]
    fn channel_reports_the_three_initial_off_reasons() {
        let (_w, r) = CaptureStatus::channel(false);
        let snap = r.snapshot();
        assert_eq!(snap.feeder, FeederState::Off(OffReason::Disabled));
        assert!(!snap.enabled);
        assert_eq!(snap.to_value(), disabled_literal());

        let (_w, r) = CaptureStatus::channel_on(true, false);
        let snap = r.snapshot();
        assert_eq!(snap.feeder, FeederState::Off(OffReason::NotMacos));
        let v = snap.to_value();
        assert_eq!(at(at(&v, "feeder"), "reason"), &s("not a macOS build"));
        assert_eq!(at(&v, "capability_reason"), &s("not a macOS build"));
        assert_eq!(at(&v, "enabled"), &Value::Bool(true));

        let (_w, r) = CaptureStatus::channel_on(true, true);
        let snap = r.snapshot();
        assert_eq!(snap.feeder, FeederState::Off(OffReason::NotStarted));
        assert_eq!(
            at(at(&snap.to_value(), "feeder"), "reason"),
            &s("not started")
        );

        // `channel` reads the build target itself.
        let (_w, r) = CaptureStatus::channel(true);
        let expected = if cfg!(target_os = "macos") {
            OffReason::NotStarted
        } else {
            OffReason::NotMacos
        };
        assert_eq!(r.snapshot().feeder, FeederState::Off(expected));
    }

    /// **CS-AC4.** The closed vocabulary clients may match on.
    #[test]
    fn off_reason_vocabulary_is_exactly_four() {
        assert_eq!(
            [
                OffReason::Disabled,
                OffReason::NotMacos,
                OffReason::NotStarted,
                OffReason::Stopped,
            ]
            .map(OffReason::as_str),
            [
                "macos_capture.enabled is false",
                "not a macOS build",
                "not started",
                "stopped",
            ]
        );
    }

    /// **CS-AC4, CS-AC6 (writer level).** `listening()` is the D7 listening
    /// literal; `stopped()` is `off`/`stopped`.
    #[test]
    fn listening_then_stopped() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let snap = r.snapshot();
        assert_eq!(snap.to_value(), listening_literal());
        assert_eq!(snap.capability(), CaptureCapability::AwaitingProvider);

        w.stopped();
        let snap = r.snapshot();
        assert_eq!(snap.feeder, FeederState::Off(OffReason::Stopped));
        assert_eq!(
            snap.capability(),
            CaptureCapability::FeederOff("stopped".into())
        );
        assert_eq!(
            at(&snap.to_value(), "feeder"),
            &object([("reason", s("stopped")), ("state", s("off"))])
        );
    }

    /// **CS-AC5 (writer level).** A bind failure is `degraded` with the reason in
    /// both places. (The feeder never calls `stopped()` on this path; the feeder
    /// tests prove that.)
    #[test]
    fn bind_failed_is_degraded_and_terminal() {
        let reason = "cannot bind the capture sockets (not a directory)";
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.bind_failed(reason.into());
        let snap = r.snapshot();
        assert_eq!(snap.to_value(), bind_failed_literal());
        assert_eq!(snap.feeder, FeederState::BindFailed(reason.into()));
        assert_eq!(
            snap.capability(),
            CaptureCapability::Degraded(reason.into())
        );
    }

    /// **CS-AC7/8/9/10 (writer level), CS-AC19.** Attach stamps the time and team
    /// and replaces the tokens; handoffs count by kind and stamp the time; a scope
    /// push replaces the tokens; dropping the guard resets everything to
    /// `awaiting_provider`.
    #[test]
    fn attach_records_facts_and_detach_resets() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();

        let before = now_ms();
        let a = w.attached(Some("995PCLM9KH".into()), vec!["example.com".into()]);
        let after = now_ms();
        let snap = r.snapshot();
        let t = attached_at(&snap);
        assert_eq!(
            snap.provider,
            ProviderState::Attached {
                attached_at_ms: t,
                team_id: Some("995PCLM9KH".into()),
            }
        );
        assert!(before <= t && t <= after, "{before} <= {t} <= {after}");
        assert_eq!(snap.scope_tokens, vec!["example.com".to_string()]);
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));
        assert_eq!(snap.last_handoff_at_ms, None);
        assert_eq!(snap.capability(), CaptureCapability::ApprovedAttached);
        let v = snap.to_value();
        assert_eq!(at(&v, "scope_entries"), &Value::Int(1));
        assert_eq!(at(&v, "last_handoff_at"), &Value::Null);
        assert_eq!(
            at(at(&v, "provider"), "attached_at"),
            &Value::Int(i64::try_from(t).unwrap())
        );
        assert_eq!(at(at(&v, "provider"), "state"), &s("attached"));
        assert_eq!(at(at(&v, "provider"), "team_id"), &s("995PCLM9KH"));
        assert_eq!(at(&v, "capability"), &s("approved_attached"));

        let before = now_ms();
        for _ in 0..12 {
            w.handed_off(FlowKind::Tcp);
        }
        for _ in 0..3 {
            w.handed_off(FlowKind::Udp);
        }
        let after = now_ms();
        let snap = r.snapshot();
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (12, 3));
        let last = snap.last_handoff_at_ms.expect("a handoff time");
        assert!(
            before <= last && last <= after,
            "{before} <= {last} <= {after}"
        );
        assert_eq!(snap.capability(), CaptureCapability::Capturing);
        let v = snap.to_value();
        assert_eq!(
            at(&v, "flows_handed_off"),
            &object([("tcp", Value::Int(12)), ("udp", Value::Int(3))])
        );
        assert_eq!(
            at(&v, "last_handoff_at"),
            &Value::Int(i64::try_from(last).unwrap())
        );
        assert_eq!(at(&v, "capability"), &s("capturing"));

        w.scope_pushed(vec!["example.com".into(), "api.test".into()]);
        assert_eq!(
            r.snapshot().scope_tokens,
            vec!["example.com".to_string(), "api.test".to_string()]
        );

        drop(a);
        let snap = r.snapshot();
        assert_eq!(snap.provider, ProviderState::Detached);
        assert_eq!(snap.scope_tokens, Vec::<String>::new());
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));
        assert_eq!(snap.last_handoff_at_ms, None);
        assert_eq!(snap.feeder, FeederState::Listening);
        assert_eq!(snap.capability(), CaptureCapability::AwaitingProvider);
        assert_eq!(
            at(&snap.to_value(), "provider"),
            &object([
                ("attached_at", Value::Null),
                ("state", s("detached")),
                ("team_id", Value::Null),
            ])
        );
    }

    /// **CS-AC4/11 (writer level).** `stopped()` forces the detach even while the
    /// guard is alive, and the guard's later drop changes nothing.
    #[test]
    fn stopped_forces_detached_while_attached() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let guard = w.attached(Some("995PCLM9KH".into()), vec!["example.com".into()]);
        w.handed_off(FlowKind::Tcp);
        w.handed_off(FlowKind::Udp);

        w.stopped();
        let snap = r.snapshot();
        assert_eq!(snap.provider, ProviderState::Detached);
        assert_eq!(snap.scope_tokens, Vec::<String>::new());
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));
        assert_eq!(snap.last_handoff_at_ms, None);
        assert_eq!(snap.feeder, FeederState::Off(OffReason::Stopped));
        assert_eq!(
            snap.capability(),
            CaptureCapability::FeederOff("stopped".into())
        );

        drop(guard);
        assert_eq!(r.snapshot(), snap);
    }

    /// **CS-AC9 (integrity).** A newer attachment supersedes an older guard: when
    /// the stale guard drops, the newer attachment's provider, tokens and counters
    /// survive untouched; only the current guard's drop records the detach.
    #[test]
    fn stale_guard_does_not_clear_a_newer_attachment() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let a = w.attached(None, vec!["a.test".into()]);
        let b = w.attached(Some("995PCLM9KH".into()), vec!["b.test".into()]);

        drop(a);
        let snap = r.snapshot();
        assert!(
            matches!(
                &snap.provider,
                ProviderState::Attached { team_id: Some(team), .. } if team == "995PCLM9KH"
            ),
            "the stale guard cleared the newer attachment: {snap:?}"
        );
        assert_eq!(snap.scope_tokens, vec!["b.test".to_string()]);
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));

        w.handed_off(FlowKind::Tcp);
        let snap = r.snapshot();
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (1, 0));
        assert_eq!(snap.capability(), CaptureCapability::Capturing);

        drop(b);
        let snap = r.snapshot();
        assert_eq!(snap.provider, ProviderState::Detached);
        assert_eq!(snap.scope_tokens, Vec::<String>::new());
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));
        assert_eq!(snap.last_handoff_at_ms, None);
    }

    /// **CS-AC19.** The D7 capturing literal, then the same attachment with no
    /// handoffs (`approved_attached`, `null` never `0`), then the incident state
    /// (attached, empty scope).
    #[test]
    fn to_value_matches_the_capturing_literal() {
        let capturing = CaptureStatusSnapshot {
            enabled: true,
            feeder: FeederState::Listening,
            provider: ProviderState::Attached {
                attached_at_ms: 1_761_907_200_000,
                team_id: Some("995PCLM9KH".into()),
            },
            scope_tokens: vec![
                "example.com".into(),
                "*.example.com".into(),
                "198.51.100.7".into(),
            ],
            tcp_handed_off: 12,
            udp_handed_off: 3,
            last_handoff_at_ms: Some(1_761_907_305_123),
        };
        assert_eq!(capturing.to_value(), capturing_literal());

        let idle = CaptureStatusSnapshot {
            tcp_handed_off: 0,
            udp_handed_off: 0,
            last_handoff_at_ms: None,
            ..capturing.clone()
        };
        let v = idle.to_value();
        assert_eq!(at(&v, "capability"), &s("approved_attached"));
        assert_eq!(at(&v, "capability_reason"), &Value::Null);
        assert_eq!(at(&v, "last_handoff_at"), &Value::Null);
        assert_eq!(
            at(&v, "flows_handed_off"),
            &object([("tcp", Value::Int(0)), ("udp", Value::Int(0))])
        );

        let incident = CaptureStatusSnapshot {
            scope_tokens: Vec::new(),
            ..idle
        };
        let v = incident.to_value();
        assert_eq!(at(&v, "scope_entries"), &Value::Int(0));
        assert_eq!(at(&v, "scope_tokens"), &Value::Array(vec![]));
        assert_eq!(at(&v, "capability"), &s("approved_attached"));
        assert_eq!(at(at(&v, "provider"), "state"), &s("attached"));
    }

    /// **CS-AC12.** The D5 precedence over the whole matrix, checked against a
    /// literal table (one row per feeder state; one column each for detached,
    /// attached with no handoff, attached with a handoff), with the three
    /// spelled-out rows the plan names, and never an app-side variant.
    #[test]
    fn capability_derivation_table() {
        let bind_failed = "cannot bind the capture sockets (not a directory)";
        let table: [(FeederState, &str, &str, &str); 6] = [
            (
                FeederState::Off(OffReason::Disabled),
                "feeder_off",
                "approved_attached",
                "capturing",
            ),
            (
                FeederState::Off(OffReason::NotMacos),
                "feeder_off",
                "approved_attached",
                "capturing",
            ),
            (
                FeederState::Off(OffReason::NotStarted),
                "feeder_off",
                "approved_attached",
                "capturing",
            ),
            (
                FeederState::Off(OffReason::Stopped),
                "feeder_off",
                "approved_attached",
                "capturing",
            ),
            (
                FeederState::Listening,
                "awaiting_provider",
                "approved_attached",
                "capturing",
            ),
            (
                FeederState::BindFailed(bind_failed.into()),
                "degraded",
                "degraded",
                "degraded",
            ),
        ];
        let rows = matrix();
        assert_eq!(rows.len(), 36);
        for (feeder, ..) in &table {
            assert!(
                rows.iter().any(|snap| snap.feeder == *feeder),
                "the matrix never visits {feeder:?}"
            );
        }
        for snap in &rows {
            let (_, detached, attached_idle, attached_capturing) = table
                .iter()
                .find(|(feeder, ..)| *feeder == snap.feeder)
                .unwrap_or_else(|| panic!("no table row for {:?}", snap.feeder));
            let wire = match &snap.provider {
                ProviderState::Detached => detached,
                ProviderState::Attached { .. }
                    if snap.tcp_handed_off + snap.udp_handed_off == 0 =>
                {
                    attached_idle
                }
                ProviderState::Attached { .. } => attached_capturing,
            };
            let got = snap.capability();
            assert_eq!(got.wire_name(), *wire, "{snap:?}");
            assert_eq!(at(&snap.to_value(), "capability"), &s(wire), "{snap:?}");
            assert!(
                !matches!(
                    got,
                    CaptureCapability::ExtensionNotInstalled | CaptureCapability::PendingApproval
                ),
                "the verb never claims app-side knowledge: {snap:?}"
            );
        }

        // The plan's spelled-out rows.
        let attached = ProviderState::Attached {
            attached_at_ms: 1_761_907_200_000,
            team_id: Some("995PCLM9KH".into()),
        };
        let row = |feeder: FeederState, provider: ProviderState, tcp: u64, udp: u64| {
            CaptureStatusSnapshot {
                enabled: true,
                feeder,
                provider,
                scope_tokens: Vec::new(),
                tcp_handed_off: tcp,
                udp_handed_off: udp,
                last_handoff_at_ms: None,
            }
        };
        let degraded = row(
            FeederState::BindFailed(bind_failed.into()),
            attached.clone(),
            1,
            0,
        );
        assert_eq!(
            degraded.capability(),
            CaptureCapability::Degraded(bind_failed.into())
        );
        assert_eq!(degraded.capability().wire_name(), "degraded");
        let stopped_but_attached = row(FeederState::Off(OffReason::Stopped), attached, 0, 1);
        assert_eq!(
            stopped_but_attached.capability(),
            CaptureCapability::Capturing
        );
        for (tcp, udp) in [(0, 0), (1, 0), (0, 1)] {
            assert_eq!(
                row(FeederState::Listening, ProviderState::Detached, tcp, udp).capability(),
                CaptureCapability::AwaitingProvider
            );
        }
    }

    /// **CS-AC15.** No socket directory, socket name, rendezvous name, or path
    /// separator in any result.
    #[test]
    fn result_never_leaks_paths_or_sockets() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.bind_failed("cannot bind the capture sockets (not a directory)".into());
        let mut snapshots = matrix();
        snapshots.push(r.snapshot());
        assert_eq!(snapshots.len(), 37);
        for snap in &snapshots {
            let rendered = format!("{:?}", snap.to_value());
            for needle in [
                DEFAULT_SOCKET_DIR,
                "control.sock",
                "data.sock",
                ".rendezvous",
            ] {
                assert!(!rendered.contains(needle), "{needle:?} leaked: {rendered}");
            }
            assert!(
                !rendered.contains('/'),
                "a path separator leaked: {rendered}"
            );
        }
    }

    /// **CS-AC8.** `scope_tokens` inverts the emitter's join over the pinned fixture
    /// (L7 `example.com`, `*.example.com`; L4 `198.51.100.7/32` any port).
    #[test]
    fn scope_tokens_round_trips_the_emitter() {
        let l7 = [
            ScopeEntry {
                host: "example.com".into(),
            },
            ScopeEntry {
                host: "*.example.com".into(),
            },
        ];
        let l4 = [L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "198.51.100.7".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: CAPTURE_INTERFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 0, burst: 0 },
            source: L4ScopeSource::Config,
        }];
        let spec = provider_scope_spec(&l7, &l4);
        assert_eq!(
            scope_tokens(&spec),
            vec![
                "example.com".to_string(),
                "*.example.com".to_string(),
                "198.51.100.7".to_string(),
            ]
        );
        assert_eq!(scope_tokens(&spec).join(" "), spec.spec);
        assert_eq!(
            scope_tokens(&ScopeSpec {
                spec: String::new()
            }),
            Vec::<String>::new()
        );
    }

    // ---- the verb -------------------------------------------------------------------

    /// A `ProxyClient` the verb must never reach (precedent:
    /// `aitm-plugins/tests/control.rs`).
    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// **CS-AC2.** Read-only, parameterless, inert: `Read` sensitivity, no params,
    /// the same literal with and without junk arguments, and the handle untouched.
    #[test]
    fn command_is_read_only_and_parameterless() -> anyhow::Result<()> {
        let (w, r) = CaptureStatus::channel(true);
        w.listening();
        let before = r.snapshot();
        let command = CaptureStatusCommand { reader: r.clone() };
        assert_eq!(command.name(), "capture.status");
        assert_eq!(command.sensitivity(), Sensitivity::Read);
        assert!(!command.mutates());
        assert!(command.schema().params.is_empty());

        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &StubClient, &guard, None);
        let a = command.invoke(Params::default(), &host)?;
        let junk = Params::new(BTreeMap::from([
            ("enabled".to_string(), Value::Bool(true)),
            ("feeder".to_string(), s("listening")),
            ("provider".to_string(), s("attached")),
        ]));
        let b = command.invoke(junk, &host)?;
        assert_eq!(a, listening_literal());
        assert_eq!(b, listening_literal());
        assert_eq!(r.snapshot(), before, "invoking changed the handle");
        Ok(())
    }

    /// **CS-AC3.** Through a `Registry`, as a frontend reaches it: the plugin
    /// registers `capture.status`, and over a disabled handle it returns the D7
    /// disabled literal.
    #[test]
    fn registry_invocation_returns_the_disabled_literal() -> anyhow::Result<()> {
        let (_w, r) = CaptureStatus::channel(false);
        let plugin = CaptureStatusPlugin::new(r);
        assert_eq!(plugin.name(), "capture_status");
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(plugin));
        let command = reg
            .command("capture.status")
            .expect("the plugin registers capture.status");
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &StubClient, &guard, None);
        assert_eq!(
            command.invoke(Params::default(), &host)?,
            disabled_literal()
        );
        Ok(())
    }

    /// Walk a schema object against an emitted object: the same key set at this
    /// level and every description non-empty; collects the optional names and the
    /// names emitted as `Null`, recursing into nested objects.
    fn walk_schema(
        fields: &[ParamDef],
        value: &Value,
        optional: &mut BTreeSet<String>,
        nullable: &mut BTreeSet<String>,
    ) {
        let Value::Object(map) = value else {
            panic!("the schema describes an object but the verb emitted {value:?}");
        };
        let described: BTreeSet<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        let emitted: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        assert_eq!(described, emitted, "schema fields vs emitted keys");
        for field in fields {
            assert!(
                !field.description.trim().is_empty(),
                "{} has an empty description",
                field.name
            );
            if !field.required {
                optional.insert(field.name.clone());
            }
            let emitted = at(value, &field.name);
            if *emitted == Value::Null {
                nullable.insert(field.name.clone());
            }
            if let TypeDesc::Object(inner) = &field.ty {
                walk_schema(inner, emitted, optional, nullable);
            }
        }
    }

    /// The field at `path` (nested through `TypeDesc::Object`s).
    fn field_at<'a>(mut fields: &'a [ParamDef], path: &[&str]) -> &'a ParamDef {
        let (last, parents) = path.split_last().expect("a non-empty path");
        let find = |fields: &'a [ParamDef], name: &str| -> &'a ParamDef {
            fields
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("no field {name:?} in {path:?}"))
        };
        for name in parents {
            match &find(fields, name).ty {
                TypeDesc::Object(inner) => fields = inner,
                other => panic!("{name:?} is not an object: {other:?}"),
            }
        }
        find(fields, last)
    }

    /// **CS-AC14.** The schema describes every emitted key at every level with a
    /// non-empty description; exactly the five nullable fields are optional; the
    /// declared types match the wire (D6) and `team_id` carries D4's fixed text.
    #[test]
    fn schema_describes_every_emitted_key() {
        let (_w, r) = CaptureStatus::channel(true);
        let schema = CaptureStatusCommand { reader: r }.schema();
        for must_name in [
            "Unix epoch milliseconds",
            "macos_capture.enabled is false",
            "not a macOS build",
            "not started",
            "stopped",
            "proxy.status.capturing",
        ] {
            assert!(
                schema.description.contains(must_name),
                "schema description lacks {must_name:?}: {}",
                schema.description
            );
        }
        let TypeDesc::Object(fields) = &schema.result else {
            panic!("the result is an object: {:?}", schema.result);
        };

        let mut optional = BTreeSet::new();
        let mut nullable = BTreeSet::new();
        for snapshot in matrix() {
            walk_schema(fields, &snapshot.to_value(), &mut optional, &mut nullable);
        }
        let expected: BTreeSet<String> = [
            "reason",
            "attached_at",
            "team_id",
            "last_handoff_at",
            "capability_reason",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(optional, expected, "the optional (nullable) fields");
        assert!(
            nullable.is_subset(&optional),
            "emitted null for a required field: {:?}",
            nullable.difference(&optional).collect::<Vec<_>>()
        );
        assert_eq!(
            nullable, expected,
            "the matrix exercises every nullable field"
        );

        assert!(matches!(
            &field_at(fields, &["scope_tokens"]).ty,
            TypeDesc::Array(inner) if matches!(**inner, TypeDesc::Str)
        ));
        assert!(matches!(field_at(fields, &["enabled"]).ty, TypeDesc::Bool));
        for path in [
            &["scope_entries"][..],
            &["last_handoff_at"],
            &["flows_handed_off", "tcp"],
            &["flows_handed_off", "udp"],
            &["provider", "attached_at"],
        ] {
            assert!(
                matches!(field_at(fields, path).ty, TypeDesc::Int),
                "{path:?} is Int"
            );
        }
        for path in [
            &["capability"][..],
            &["capability_reason"],
            &["feeder", "state"],
            &["feeder", "reason"],
            &["provider", "state"],
            &["provider", "team_id"],
        ] {
            assert!(
                matches!(field_at(fields, path).ty, TypeDesc::Str),
                "{path:?} is Str"
            );
        }
        assert_eq!(
            field_at(fields, &["provider", "team_id"]).description,
            "The Apple team identifier the provider's code signature was verified against \
             (the requirement's pinned OU); not read from the peer's signing information. \
             Null when detached or when the verifier pins no team."
        );
    }

    /// The `impl <header>` block of this file's source, up to its column-0 close.
    fn impl_block<'a>(source: &'a str, header: &str) -> &'a str {
        let start = source
            .find(header)
            .unwrap_or_else(|| panic!("{header:?} not found in status.rs"));
        let body = &source[start..];
        let end = body.find("\n}").expect("an impl block closes at column 0");
        &body[..end]
    }

    /// **CS-AC16 (structural).** The reader's only `pub fn` is `snapshot`; the
    /// writer has no `pub fn` at all (its mutators are `pub(super)`).
    #[test]
    fn reader_has_exactly_one_pub_method() {
        let source = include_str!("status.rs");
        let reader = impl_block(source, "impl CaptureStatusReader {");
        assert_eq!(reader.matches("pub fn ").count(), 1, "{reader}");
        assert!(reader.contains("pub fn snapshot("), "{reader}");
        let writer = impl_block(source, "impl CaptureStatusWriter {");
        assert_eq!(writer.matches("pub fn ").count(), 0, "{writer}");
        assert!(writer.contains("pub(super) fn listening("), "{writer}");
    }

    /// **CS-AC17 (structural).** This module adds no way to build or run a session.
    #[test]
    fn status_module_names_no_session_builder() {
        let source = include_str!("status.rs");
        assert!(!source.contains(concat!("build_capture_", "session(")));
        assert!(!source.contains(concat!("CaptureSession", "::")));
    }

    // ---- edge cases the handle must survive -------------------------------------------

    /// **CS-AC10 (under contention).** `handed_off` is lock-free and must
    /// not lose a count: eight threads each record 1 000 handoffs (three TCP to one
    /// UDP) while a reader snapshots continuously; every one is counted and every
    /// intermediate read is a well-formed, attached D7 object.
    #[test]
    fn concurrent_handoffs_are_all_counted_while_snapshots_read() {
        const THREADS: u64 = 8;
        const PER_THREAD: u64 = 1_000;
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let _attachment = w.attached(Some("995PCLM9KH".into()), vec!["example.com".into()]);

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let w = w.clone();
                scope.spawn(move || {
                    for i in 0..PER_THREAD {
                        w.handed_off(if i % 4 == 0 {
                            FlowKind::Udp
                        } else {
                            FlowKind::Tcp
                        });
                    }
                });
            }
            let r = r.clone();
            scope.spawn(move || {
                for _ in 0..200 {
                    let v = r.snapshot().to_value();
                    assert_eq!(at(at(&v, "provider"), "state"), &s("attached"));
                    assert_eq!(at(&v, "enabled"), &Value::Bool(true));
                }
            });
        });

        let snap = r.snapshot();
        assert_eq!(snap.tcp_handed_off, THREADS * PER_THREAD * 3 / 4);
        assert_eq!(snap.udp_handed_off, THREADS * PER_THREAD / 4);
        assert!(snap.last_handoff_at_ms.is_some());
        assert_eq!(snap.capability(), CaptureCapability::Capturing);
    }

    /// A thread that panics while holding the handle's lock poisons it;
    /// both halves recover (`PoisonError::into_inner`, as the module promises), so
    /// one bad critical section can neither wedge the verb nor silence the
    /// feeder's later transitions.
    #[test]
    fn both_halves_recover_from_a_poisoned_lock() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();

        let shared = std::sync::Arc::clone(&w.0);
        let poisoner = std::thread::spawn(move || {
            let _guard = shared.inner.lock().expect("not yet poisoned");
            panic!("poisoning the capture-status lock on purpose");
        });
        assert!(poisoner.join().is_err(), "the poisoning thread panicked");
        assert!(w.0.inner.is_poisoned());

        assert_eq!(
            r.snapshot().feeder,
            FeederState::Listening,
            "the reader recovers"
        );
        let attachment = w.attached(None, vec!["example.com".into()]);
        assert!(
            matches!(r.snapshot().provider, ProviderState::Attached { .. }),
            "the writer recovers"
        );
        w.scope_pushed(vec!["api.test".into()]);
        assert_eq!(r.snapshot().scope_tokens, vec!["api.test".to_string()]);
        drop(attachment);
        assert_eq!(r.snapshot().provider, ProviderState::Detached);
        w.stopped();
        assert_eq!(r.snapshot().feeder, FeederState::Off(OffReason::Stopped));
    }

    /// **CS-AC9.** The RAII guard holds its own reference to the shared
    /// state, not a borrow of the writer: with every writer gone the attachment
    /// still reads as attached, its drop still records the detach, and the reader
    /// still answers.
    #[test]
    fn attachment_guard_outlives_its_writer_and_still_records_the_detach() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let attachment = w.attached(Some("995PCLM9KH".into()), vec!["example.com".into()]);
        w.handed_off(FlowKind::Tcp);
        drop(w);

        let snap = r.snapshot();
        assert!(
            matches!(snap.provider, ProviderState::Attached { .. }),
            "{snap:?}"
        );
        assert_eq!(snap.capability(), CaptureCapability::Capturing);

        drop(attachment);
        let snap = r.snapshot();
        assert_eq!(snap.provider, ProviderState::Detached);
        assert_eq!(snap.scope_tokens, Vec::<String>::new());
        assert_eq!((snap.tcp_handed_off, snap.udp_handed_off), (0, 0));
        assert_eq!(snap.last_handoff_at_ms, None);
        assert_eq!(snap.capability(), CaptureCapability::AwaitingProvider);
    }

    /// **CS-AC19.** The emitter's saturation branches: a count past
    /// `i64::MAX` saturates instead of wrapping negative, a stamp that does not fit
    /// `i64` reads as `null` rather than a negative time, and the capability sum
    /// does not overflow. A client never sees a negative integer.
    #[test]
    fn to_value_saturates_counts_and_nulls_unrepresentable_stamps() {
        fn assert_no_negative(v: &Value) {
            match v {
                Value::Int(n) => assert!(*n >= 0, "negative integer on the wire: {n}"),
                Value::Object(m) => m.values().for_each(assert_no_negative),
                Value::Array(a) => a.iter().for_each(assert_no_negative),
                _ => {}
            }
        }
        let snap = CaptureStatusSnapshot {
            enabled: true,
            feeder: FeederState::Listening,
            provider: ProviderState::Attached {
                attached_at_ms: u64::MAX,
                team_id: None,
            },
            scope_tokens: Vec::new(),
            tcp_handed_off: u64::MAX,
            udp_handed_off: 1,
            last_handoff_at_ms: Some(u64::MAX),
        };
        assert_eq!(snap.capability(), CaptureCapability::Capturing);
        let v = snap.to_value();
        assert_eq!(at(at(&v, "flows_handed_off"), "tcp"), &Value::Int(i64::MAX));
        assert_eq!(at(at(&v, "flows_handed_off"), "udp"), &Value::Int(1));
        assert_eq!(at(at(&v, "provider"), "attached_at"), &Value::Null);
        assert_eq!(at(&v, "last_handoff_at"), &Value::Null);
        assert_eq!(at(&v, "capability"), &s("capturing"));
        assert_no_negative(&v);
    }

    /// **CS-AC8.** `scope_tokens` over blank and ragged specs: empty,
    /// whitespace-only, tabs, runs of spaces and a trailing newline tokenize to
    /// exactly the non-empty words, never an empty token, and `scope_entries`
    /// follows the tokens, not the raw spec.
    #[test]
    fn scope_tokens_over_blank_and_ragged_specs() {
        for blank in ["", " ", "   ", "\t", "\n", " \t\n "] {
            assert_eq!(
                scope_tokens(&ScopeSpec { spec: blank.into() }),
                Vec::<String>::new(),
                "{blank:?}"
            );
        }
        let ragged = ScopeSpec {
            spec: "  example.com\t*.example.com   198.51.100.7\n".into(),
        };
        let tokens = scope_tokens(&ragged);
        assert_eq!(tokens, ["example.com", "*.example.com", "198.51.100.7"]);
        assert!(tokens.iter().all(|t| !t.is_empty()));

        let snap = CaptureStatusSnapshot {
            enabled: true,
            feeder: FeederState::Listening,
            provider: ProviderState::Attached {
                attached_at_ms: 1,
                team_id: None,
            },
            scope_tokens: tokens,
            tcp_handed_off: 0,
            udp_handed_off: 0,
            last_handoff_at_ms: None,
        };
        assert_eq!(at(&snap.to_value(), "scope_entries"), &Value::Int(3));
    }

    // ---- tester re-check of the panel-minors fix ---------------------------------------

    /// **CS-AC12, CS-AC5 (spec D5, last column).** `capability_derivation_table`
    /// pins the wire name of every matrix row; this pins the reason beside it. Over
    /// the 36-row matrix plus the three constructor snapshots: under `degraded` and
    /// `feeder_off` the `capability_reason` is a non-empty string equal, byte for
    /// byte, to `feeder.reason`; under the three reasonless variants it is `null`.
    /// Then each of the four `off` reasons is pinned as its `FeederOff` variant by
    /// literal text, so `not started` is no longer checked only through
    /// `feeder.reason`.
    #[test]
    fn capability_reason_is_the_feeder_reason_wherever_it_is_set() {
        let mut rows = matrix();
        rows.push(CaptureStatus::channel(false).1.snapshot());
        rows.push(CaptureStatus::channel_on(true, false).1.snapshot());
        rows.push(CaptureStatus::channel_on(true, true).1.snapshot());
        assert_eq!(rows.len(), 39);
        let mut with_reason = 0;
        for snap in &rows {
            let v = snap.to_value();
            let wire = at(&v, "capability");
            let reason = at(&v, "capability_reason");
            let feeder_reason = at(at(&v, "feeder"), "reason");
            if wire == &s("degraded") || wire == &s("feeder_off") {
                with_reason += 1;
                assert!(
                    matches!(reason, Value::Str(r) if !r.is_empty()),
                    "a reason-carrying capability without a reason: {snap:?}"
                );
                assert_eq!(reason, feeder_reason, "{snap:?}");
            } else {
                assert_eq!(reason, &Value::Null, "{snap:?}");
                assert!(
                    matches!(
                        snap.capability(),
                        CaptureCapability::Capturing
                            | CaptureCapability::ApprovedAttached
                            | CaptureCapability::AwaitingProvider
                    ),
                    "{snap:?}"
                );
            }
        }
        // Six `bind_failed` rows, twelve `off`+`detached` rows, three constructors.
        assert_eq!(with_reason, 6 + 12 + 3);

        let off = |reason: OffReason| CaptureStatusSnapshot {
            enabled: true,
            feeder: FeederState::Off(reason),
            provider: ProviderState::Detached,
            scope_tokens: Vec::new(),
            tcp_handed_off: 0,
            udp_handed_off: 0,
            last_handoff_at_ms: None,
        };
        assert_eq!(
            off(OffReason::Disabled).capability(),
            CaptureCapability::FeederOff("macos_capture.enabled is false".into())
        );
        assert_eq!(
            off(OffReason::NotMacos).capability(),
            CaptureCapability::FeederOff("not a macOS build".into())
        );
        assert_eq!(
            off(OffReason::NotStarted).capability(),
            CaptureCapability::FeederOff("not started".into())
        );
        assert_eq!(
            off(OffReason::Stopped).capability(),
            CaptureCapability::FeederOff("stopped".into())
        );
    }

    /// **CS-AC9, CS-AC10 (integrity).** The handoffs the newer attachment has
    /// already counted survive the stale guard's drop: a superseded guard must not
    /// zero the counters or the last-handoff stamp of the attachment that replaced
    /// it, nor knock `capturing` back to `approved_attached`. With no write between
    /// the two reads, "the snapshot is identical" is the exact "changed nothing"
    /// oracle. The current guard's drop then resets everything to the listening
    /// literal.
    #[test]
    fn stale_guard_drop_preserves_the_newer_attachments_handoffs() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let stale = w.attached(None, vec!["a.test".into()]);
        let current = w.attached(Some("995PCLM9KH".into()), vec!["b.test".into()]);
        let before = now_ms();
        w.handed_off(FlowKind::Tcp);
        w.handed_off(FlowKind::Udp);
        let after = now_ms();
        let live = r.snapshot();
        assert_eq!((live.tcp_handed_off, live.udp_handed_off), (1, 1));
        let stamp = live.last_handoff_at_ms.expect("a handoff was stamped");
        assert!((before..=after).contains(&stamp), "{live:?}");
        assert_eq!(live.capability(), CaptureCapability::Capturing);

        drop(stale);
        assert_eq!(
            r.snapshot(),
            live,
            "the stale guard's drop changed the newer attachment"
        );

        drop(current);
        let snap = r.snapshot();
        assert_eq!(snap.capability(), CaptureCapability::AwaitingProvider);
        assert_eq!(snap.to_value(), listening_literal());
    }

    /// **CS-AC9 (integrity).** A superseded guard that outlives the current one
    /// drops silently: the current guard's drop already recorded the detach, and the
    /// late stale drop leaves the handle exactly as it found it.
    #[test]
    fn superseded_guard_dropping_last_changes_nothing() {
        let (w, r) = CaptureStatus::channel_on(true, true);
        w.listening();
        let stale = w.attached(None, vec!["a.test".into()]);
        let current = w.attached(Some("995PCLM9KH".into()), vec!["b.test".into()]);
        w.handed_off(FlowKind::Udp);

        drop(current);
        let detached = r.snapshot();
        assert_eq!(detached.to_value(), listening_literal());

        drop(stale);
        assert_eq!(r.snapshot(), detached);
    }

    /// **CS-AC4/11 (writer level).** `stopped()` with two live guards — a stale one
    /// and the current one — is `off`/`stopped` + `detached` at once, and stays
    /// exactly that through both drops whichever guard goes first: neither drop
    /// moves the feeder off `stopped`, re-attaches, or resurrects a count.
    #[test]
    fn stopped_with_two_live_guards_converges_in_either_drop_order() {
        for stale_first in [true, false] {
            let (w, r) = CaptureStatus::channel_on(true, true);
            w.listening();
            let stale = w.attached(None, vec!["a.test".into()]);
            let current = w.attached(Some("995PCLM9KH".into()), vec!["b.test".into()]);
            w.handed_off(FlowKind::Tcp);

            w.stopped();
            let stopped = r.snapshot();
            assert_eq!(stopped.feeder, FeederState::Off(OffReason::Stopped));
            assert_eq!(stopped.provider, ProviderState::Detached);
            assert_eq!(stopped.scope_tokens, Vec::<String>::new());
            assert_eq!((stopped.tcp_handed_off, stopped.udp_handed_off), (0, 0));
            assert_eq!(stopped.last_handoff_at_ms, None);
            assert_eq!(
                stopped.capability(),
                CaptureCapability::FeederOff("stopped".into())
            );

            let (first, second) = if stale_first {
                (stale, current)
            } else {
                (current, stale)
            };
            drop(first);
            assert_eq!(
                r.snapshot(),
                stopped,
                "stale_first={stale_first}: the first drop changed the handle"
            );
            drop(second);
            assert_eq!(
                r.snapshot(),
                stopped,
                "stale_first={stale_first}: the second drop changed the handle"
            );
            assert_eq!(
                at(&r.snapshot().to_value(), "feeder"),
                &object([("reason", s("stopped")), ("state", s("off"))])
            );
        }
    }
}
