//! `l4.intercept.*` — in-path packet interception commands (M5 Task 12).
//!
//! These are the command-bus face of the NFQUEUE interception session built in
//! M5 Task 11 ([`crate::intercept`]). They mirror the HTTP `flow.intercept` /
//! `flow.mutate` / `flow.resume` / `flow.kill` surface at the packet level:
//!
//! - `l4.intercept.start` — guarded (`Intercept`); binds the `nft` queue on a
//!   dedicated reader thread and records the session. `L4Unavailable` when in-path
//!   is disabled (`intercept: None`) or on a non-Linux OS / without `CAP_NET_ADMIN`.
//! - `l4.intercept.stop` — end a session (fail-open forwards anything still parked).
//! - `l4.intercept.status` — in-path availability (`available` / `code` / `reason`)
//!   and the live sessions with their parked counts (read-only, never privilege-gated).
//! - `l4.intercept.list` — the parked packets awaiting a verdict (read-only).
//! - `l4.intercept.mutate` / `.revert` — edit (or revert) a parked packet via a
//!   [`PacketSpec`] or raw bytes; the original is kept as a backup.
//! - `l4.intercept.forward` / `.drop` — the verdict: forward (mangled iff mutated)
//!   or drop.
//!
//! **The guarded verdict path.** A session is authorized once, at `start`: the
//! [`InterceptHandle`] holds the `Intercept` [`L4Permit`](crate::guard::L4Permit)
//! for its whole life, and the reader thread parks **only** in-scope packets
//! (out-of-scope ones auto-forward untouched, never surfacing here). So a command
//! can only ever forward/mutate a packet the guard already admitted — a mangling
//! verdict never escapes the guarded path. The commands mint no new permit.
//!
//! [`PacketSpec`]: crate::craft::PacketSpec
//! [`InterceptHandle`]: crate::intercept::InterceptHandle

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use super::{epoch_ms, field, PrivilegeReportSource};
use crate::backend::L4Error;
use crate::config::{InterceptConfig, Verdict};
use crate::craft::PacketSpec;
use crate::flow::{L4FlowId, L4FlowStore};
use crate::guard::{L4Guard, L4GuardError};
use crate::intercept::{
    start_intercept, InterceptBackend, InterceptHandle, InterceptParams, NfqueueBackend, ParkedId,
    ParkedPacket,
};
use crate::module::AvailabilitySource;
use crate::types::{L4Action, L4Direction};

/// How the `start` command obtains the in-path backend for a queue number. The
/// production factory builds a Linux [`NfqueueBackend`]; tests substitute a mock so
/// the whole command surface is provable without NFQUEUE or privilege.
type BackendFactory = Arc<dyn Fn(u16) -> Arc<dyn InterceptBackend> + Send + Sync>;

/// The default (production) backend factory: a Linux NFQUEUE backend for `queue`,
/// a fail-closed `L4Unavailable` stub on every other OS.
fn nfqueue_factory() -> BackendFactory {
    Arc::new(|queue| Arc::new(NfqueueBackend::new(queue)) as Arc<dyn InterceptBackend>)
}

/// A command-side edit of a parked packet: the original bytes (for revert) and the
/// current mutated bytes (reinjected on forward). The reader thread's parked table
/// is the source of truth for *what is still parked*; this holds only the pending
/// edit the operator has staged but not yet forwarded.
#[derive(Debug, Clone)]
struct PendingEdit {
    /// The packet's original on-wire bytes, restored by `revert`.
    backup: Vec<u8>,
    /// The current mutated bytes, reinjected when the packet is forwarded.
    mutated: Vec<u8>,
}

/// One live interception session: the owning [`InterceptHandle`] plus the staged
/// edits keyed by parked id.
struct Session {
    handle: InterceptHandle,
    interface: String,
    /// The direction the session bound with — needed to re-resolve and re-check a
    /// mutated packet's target before a mangling `forward`.
    direction: L4Direction,
    queue: u16,
    edits: HashMap<ParkedId, PendingEdit>,
}

/// The registry of live `l4.intercept` sessions, shared by every intercept command
/// and owned by [`L4Module`](crate::module::L4Module) so a session started by one
/// call outlives it and the later verdict commands can reach it.
#[derive(Default)]
pub(crate) struct InterceptSessions {
    inner: Mutex<HashMap<L4FlowId, Session>>,
}

impl InterceptSessions {
    /// An empty registry.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<L4FlowId, Session>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The `L4Unavailable` text `l4.intercept.start` refuses with when in-path is
/// disabled (no `intercept` config); also the `reason` `l4.intercept.status` carries
/// under `code: not_configured`, so the two can never disagree (spec §1).
pub(crate) const INTERCEPT_NOT_CONFIGURED: &str =
    "in-path interception is disabled (no `intercept` config)";

// ---- l4.intercept.start -------------------------------------------------------

/// `l4.intercept.start {interface, direction?, queue_num?}` — bind the NFQUEUE and
/// open a guarded interception session.
pub(crate) struct InterceptStart {
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    sessions: Arc<InterceptSessions>,
    config: Option<InterceptConfig>,
    make_backend: BackendFactory,
}

impl InterceptStart {
    /// A start command over the shared guard/store/session registry, using the
    /// production NFQUEUE backend factory.
    pub(crate) fn new(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        sessions: Arc<InterceptSessions>,
        config: Option<InterceptConfig>,
    ) -> Self {
        Self::with_backend(guard, store, sessions, config, nfqueue_factory())
    }

    /// A start command with an explicit backend factory (tests inject a mock).
    fn with_backend(
        guard: Arc<L4Guard>,
        store: Arc<dyn L4FlowStore>,
        sessions: Arc<InterceptSessions>,
        config: Option<InterceptConfig>,
        make_backend: BackendFactory,
    ) -> Self {
        Self {
            guard,
            store,
            sessions,
            config,
            make_backend,
        }
    }
}

impl Command for InterceptStart {
    fn name(&self) -> &str {
        "l4.intercept.start"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Binds the NFQUEUE and can hold live traffic.
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Bind the in-path NFQUEUE and open a guarded interception session \
                          (Linux). Requires an `Intercept` scope entry on the interface + \
                          direction; returns the session's flow id. `L4Unavailable` when in-path \
                          is disabled or unsupported."
                .into(),
            params: vec![
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description:
                        "The interface the `nft` rule steers into the queue (e.g. `eth0`).".into(),
                },
                ParamDef {
                    name: "direction".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description:
                        "`inbound` or `outbound` (default `outbound`) — the direction the \
                                  authorizing scope entries declare."
                            .into(),
                },
                ParamDef {
                    name: "queue_num".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "The `nft` queue number to bind; defaults to the configured \
                                  intercept queue."
                        .into(),
                },
            ],
            result: TypeDesc::Object(session_fields()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        // In-path disabled (no `intercept` config) ⇒ fail-closed, before the guard
        // or any backend. Fail-closed is also what a non-Linux backend returns on
        // open, so `l4.intercept.*` is honest about platform support either way.
        let mut config = self.config.clone().ok_or_else(|| {
            anyhow::Error::new(L4Error::Unavailable(INTERCEPT_NOT_CONFIGURED.into()))
        })?;

        let interface = args.get_str("interface")?.to_string();
        let direction = parse_direction_arg(&args)?;
        if let Some(queue) = optional_queue(&args)? {
            config.queue_num = queue;
        }
        let queue = config.queue_num;

        // Authorization + bind both live in `start_intercept`: it mints the
        // `Intercept` permit (held by the handle for the session's life) before
        // opening the backend, so an unauthorized or unavailable start spawns no
        // live session. The backend factory is the only test seam.
        let backend = (self.make_backend)(queue);
        let params = InterceptParams::new(interface.clone(), direction, config);
        let handle = start_intercept(self.guard.clone(), self.store.clone(), backend, params)
            .map_err(anyhow::Error::new)?;

        let flow_id = handle.flow_id();
        let parked = handle.parked().len();
        self.sessions.lock().insert(
            flow_id,
            Session {
                handle,
                interface: interface.clone(),
                direction,
                queue,
                edits: HashMap::new(),
            },
        );
        Ok(session_value(
            &super::flow_id_to_string(flow_id),
            &interface,
            queue,
            parked,
        ))
    }
}

// ---- l4.intercept.stop --------------------------------------------------------

/// `l4.intercept.stop {flow}` — end a session (fail-open forwards anything parked).
pub(crate) struct InterceptStop {
    sessions: Arc<InterceptSessions>,
}

impl InterceptStop {
    /// A stop command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptStop {
    fn name(&self) -> &str {
        "l4.intercept.stop"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Ends a session the operator started (fail-open); no new wire write.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "End an interception session by flow id; fail-open forwards anything \
                          still parked. `false` if no such session."
                .into(),
            params: vec![ParamDef {
                name: "flow".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The interception session's flow id (from `l4.intercept.start`)."
                    .into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let flow = super::flow_id_from_str(args.get_str("flow")?)?;
        let removed = self.sessions.lock().remove(&flow);
        match removed {
            // `stop` consumes the handle; its `Drop`/`stop` fail-open forwards
            // anything still parked (never black-holed).
            Some(session) => {
                session.handle.stop();
                Ok(Value::Bool(true))
            }
            None => Ok(Value::Bool(false)),
        }
    }
}

// ---- l4.intercept.status ------------------------------------------------------

/// `l4.intercept.status` — whether in-path interception is available on this core
/// (`available`, `code`, `reason`) and the live interception sessions (read-only),
/// plus, when the core reads a live privilege state, the `PrivilegeReport` under
/// `privilege` (privilege spec §2.4, L4PRIV-AC4). Never privilege-gated (spec §1):
/// it always answers.
pub(crate) struct InterceptStatus {
    sessions: Arc<InterceptSessions>,
    source: AvailabilitySource,
    privilege: PrivilegeReportSource,
}

impl InterceptStatus {
    /// A status command over the shared session registry, the in-path class's
    /// [`AvailabilitySource`] and the [`PrivilegeReportSource`], both read on every
    /// invoke (L4PAR-AC38).
    pub(crate) fn new(
        sessions: Arc<InterceptSessions>,
        source: AvailabilitySource,
        privilege: PrivilegeReportSource,
    ) -> Self {
        Self {
            sessions,
            source,
            privilege,
        }
    }
}

impl Command for InterceptStatus {
    fn name(&self) -> &str {
        "l4.intercept.status"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Report whether in-path interception is available on this core \
                          (`available`, `code`, `reason`), the live interception sessions \
                          with their parked-packet counts and, when known, the `privilege` \
                          report. Always answers, never `L4 unavailable`."
                .into(),
            params: vec![],
            result: TypeDesc::Object({
                let mut fields = super::availability_fields(
                    "sessions",
                    TypeDesc::Array(Box::new(TypeDesc::Object(session_fields()))),
                    "The live interception sessions; `[]` when unavailable.",
                );
                fields.push(super::privilege_field());
                fields
            }),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let map = self.sessions.lock();
        let mut out: Vec<(String, Value)> = map
            .iter()
            .map(|(id, s)| {
                let flow = super::flow_id_to_string(*id);
                let value = session_value(&flow, &s.interface, s.queue, s.handle.parked().len());
                (flow, value)
            })
            .collect();
        // Stable, caller-friendly order (the registry is a HashMap).
        out.sort_by(|a, b| a.0.cmp(&b.0));
        let reply = super::availability_object(
            &(self.source)(),
            "sessions",
            out.into_iter().map(|(_, v)| v).collect(),
        );
        Ok(super::with_privilege(reply, (self.privilege)()))
    }
}

// ---- l4.intercept.list --------------------------------------------------------

/// `l4.intercept.list {flow?}` — the parked packets awaiting a verdict (read-only).
pub(crate) struct InterceptList {
    sessions: Arc<InterceptSessions>,
}

impl InterceptList {
    /// A list command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptList {
    fn name(&self) -> &str {
        "l4.intercept.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the packets currently parked awaiting a verdict, across sessions \
                          or for one `flow` (read-only), in arrival order, oldest first."
                .into(),
            params: vec![ParamDef {
                name: "flow".into(),
                ty: TypeDesc::Str,
                required: false,
                description: "Restrict to one interception session's flow id.".into(),
            }],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(parked_fields()))),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let filter = optional_flow(&args)?;
        let map = self.sessions.lock();
        // Arrival order, oldest first (spec §4 / AC37): the process-wide
        // sequence stamped when the packet was parked (one counter for every
        // session, so sessions interleave in true arrival order), never the
        // random uuid string; the id string is the deterministic tie-break.
        let mut out: Vec<((u64, String), Value)> = Vec::new();
        for (fid, session) in map.iter() {
            if let Some(want) = filter {
                if *fid != want {
                    continue;
                }
            }
            for parked in session.handle.parked() {
                let edit = session.edits.get(&parked.id);
                let state = if edit.is_some() { "mutated" } else { "parked" };
                let bytes = edit.map_or(parked.packet.bytes.as_slice(), |e| e.mutated.as_slice());
                let value = parked_value(
                    parked.id,
                    *fid,
                    state,
                    bytes,
                    parked.packet.dir,
                    parked.parked_at,
                );
                let key = (parked.parked_seq, parked_id_to_string(parked.id));
                out.push((key, value));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Value::Array(out.into_iter().map(|(_, v)| v).collect()))
    }
}

// ---- l4.intercept.mutate ------------------------------------------------------

/// `l4.intercept.mutate {id, spec|bytes}` — edit a parked packet, recording a backup.
pub(crate) struct InterceptMutate {
    sessions: Arc<InterceptSessions>,
}

impl InterceptMutate {
    /// A mutate command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptMutate {
    fn name(&self) -> &str {
        "l4.intercept.mutate"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Alters a parked live packet's bytes (reinjected on a later forward).
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Edit a parked packet via a PacketSpec (`spec`) or raw `bytes`, keeping \
                          the original as a backup for `l4.intercept.revert`. The edit is \
                          reinjected only when the packet is forwarded."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The parked packet id (from `l4.intercept.list`).".into(),
                },
                ParamDef {
                    name: "spec".into(),
                    ty: TypeDesc::Any,
                    required: false,
                    description: "A PacketSpec to build the mutated bytes from (mutually \
                                  exclusive with `bytes`)."
                        .into(),
                },
                ParamDef {
                    name: "bytes".into(),
                    ty: TypeDesc::Bytes,
                    required: false,
                    description: "Raw replacement bytes (mutually exclusive with `spec`).".into(),
                },
            ],
            result: TypeDesc::Object(parked_fields()),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id_str = args.get_str("id")?;
        let id = parked_id_from_str(id_str)?;
        let new_bytes = mutated_bytes(&args)?;

        let mut map = self.sessions.lock();
        let (flow, parked) =
            locate(&map, id).ok_or_else(|| anyhow::anyhow!("no parked packet with id {id_str}"))?;
        let session = map.get_mut(&flow).expect("located session is present");
        // Preserve the first backup across repeated mutations: the original packet,
        // not an earlier edit, is what `revert` restores.
        let backup = session
            .edits
            .get(&id)
            .map_or_else(|| parked.packet.bytes.clone(), |e| e.backup.clone());
        session.edits.insert(
            id,
            PendingEdit {
                backup,
                mutated: new_bytes.clone(),
            },
        );
        Ok(parked_value(
            id,
            flow,
            "mutated",
            &new_bytes,
            parked.packet.dir,
            parked.parked_at,
        ))
    }
}

// ---- l4.intercept.revert ------------------------------------------------------

/// `l4.intercept.revert {id}` — discard a staged edit, restoring the original.
pub(crate) struct InterceptRevert {
    sessions: Arc<InterceptSessions>,
}

impl InterceptRevert {
    /// A revert command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptRevert {
    fn name(&self) -> &str {
        "l4.intercept.revert"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Restores a parked packet's backup; no new wire write.
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Discard a staged mutation on a parked packet, restoring its original \
                          bytes. `false` if nothing was staged."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The parked packet id.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = parked_id_from_str(args.get_str("id")?)?;
        let mut map = self.sessions.lock();
        for session in map.values_mut() {
            if session.edits.remove(&id).is_some() {
                return Ok(Value::Bool(true));
            }
        }
        Ok(Value::Bool(false))
    }
}

// ---- l4.intercept.forward -----------------------------------------------------

/// `l4.intercept.forward {id}` — forward a parked packet (mangled iff mutated).
pub(crate) struct InterceptForward {
    guard: Arc<L4Guard>,
    sessions: Arc<InterceptSessions>,
}

impl InterceptForward {
    /// A forward command over the shared guard + session registry. The guard
    /// re-checks any staged mutation before it is reinjected.
    pub(crate) fn new(guard: Arc<L4Guard>, sessions: Arc<InterceptSessions>) -> Self {
        Self { guard, sessions }
    }
}

impl Command for InterceptForward {
    fn name(&self) -> &str {
        "l4.intercept.forward"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Releases a (possibly mangled) packet to the wire.
        Sensitivity::Sensitive
    }

    /// The operator confirm-over-the-wire prompt (spec §2.4): what will be released
    /// to the wire — the staged mutation if one exists, else the kernel's original.
    /// `None` when the id is not parked (the call is a no-op `false` with no token).
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        verdict_confirm_summary(&self.sessions, args, "l4.intercept.forward", true)
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Forward a parked packet through the guarded verdict path — mangled if it \
                          was mutated, otherwise the kernel's original. `false` if the id is not \
                          parked."
                    .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The parked packet id.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = parked_id_from_str(args.get_str("id")?)?;
        let mut map = self.sessions.lock();
        let Some((flow, _)) = locate(&map, id) else {
            return Ok(Value::Bool(false));
        };
        let session = map.get_mut(&flow).expect("located session is present");
        // A staged edit ⇒ reinject mangled; otherwise forward the kernel's original.
        //
        // The session's permit was minted at `start` with `dst: None`, so a mutation
        // that changes the destination (or inflates the size) was never scope-checked
        // against *that* target. Before issuing a mangling verdict, re-resolve the
        // mutated packet's target and run it back through the guard + the size cap, so
        // a reinjected mutation can never leave scope, hit the dangerous-destination
        // denylist, or exceed `max_packet_bytes`. Refuse with a typed error (the edit
        // stays staged; the operator can `revert`) — the packet is NOT delivered
        // mangled. An unmutated forward reinjects the kernel's already-scoped original.
        let mutated = match session.edits.get(&id) {
            Some(edit) => {
                recheck_mutation(
                    &self.guard,
                    &session.interface,
                    session.direction,
                    &edit.mutated,
                )
                .map_err(anyhow::Error::new)?;
                session.edits.remove(&id).map(|e| e.mutated)
            }
            None => None,
        };
        let ok = session.handle.submit_verdict(id, Verdict::Forward, mutated);
        Ok(Value::Bool(ok))
    }
}

/// Re-check a staged mutation before it is reinjected on `forward`: resolve the
/// mutated bytes to their target and run it through the guard (scope + capability +
/// dangerous-destination denylist) and the per-packet size cap. Returns the typed
/// [`L4Error`] the refusal carries, so a mutation that leaves scope, hits the
/// denylist, or exceeds `max_packet_bytes` can never be delivered mangled.
///
/// A mutation that no longer decodes to an IP destination cannot be proven in
/// scope, so it is refused deny-by-default (treated as out of scope).
fn recheck_mutation(
    guard: &L4Guard,
    interface: &str,
    direction: L4Direction,
    bytes: &[u8],
) -> Result<(), L4Error> {
    let target = crate::intercept::ip_target(bytes, interface, direction).ok_or_else(|| {
        L4Error::Guard(L4GuardError::OutOfL4Scope(
            "mutated packet has no decodable IP destination; cannot re-verify scope".into(),
        ))
    })?;
    // Scope + capability + denylist for the mutation's (possibly new) destination.
    // `Intercept` mints no injection rate, so this re-check spends no rate budget.
    let mut permit = guard.check(L4Action::Intercept, &target)?;
    // The per-packet size ceiling, enforced via the permit exactly as the wire choke
    // point does (`PacketTooLarge` when the mutation inflates past `max_packet_bytes`).
    permit.authorize_packet(bytes.len())?;
    Ok(())
}

// ---- l4.intercept.drop --------------------------------------------------------

/// `l4.intercept.drop {id}` — drop a parked packet.
pub(crate) struct InterceptDrop {
    sessions: Arc<InterceptSessions>,
}

impl InterceptDrop {
    /// A drop command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptDrop {
    fn name(&self) -> &str {
        "l4.intercept.drop"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Drops live traffic.
        Sensitivity::Sensitive
    }

    /// The operator confirm-over-the-wire prompt (spec §2.4): which parked packet is
    /// being dropped. `None` when the id is not parked (the call is a no-op `false`).
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        verdict_confirm_summary(&self.sessions, args, "l4.intercept.drop", false)
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Drop a parked packet (verdict Drop). `false` if the id is not parked."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The parked packet id.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = parked_id_from_str(args.get_str("id")?)?;
        let mut map = self.sessions.lock();
        let Some((flow, _)) = locate(&map, id) else {
            return Ok(Value::Bool(false));
        };
        let session = map.get_mut(&flow).expect("located session is present");
        session.edits.remove(&id);
        let ok = session.handle.submit_verdict(id, Verdict::Drop, None);
        Ok(Value::Bool(ok))
    }
}

// ---- registration -------------------------------------------------------------

/// Build the `l4.intercept.*` commands over the shared guard, store, and session
/// registry, using the production NFQUEUE backend: the seven privilege-gated
/// verbs, and **separately** the `l4.intercept.status` verb over the same
/// registry, which [`crate::module::L4Module::load`] registers ungated beside
/// them so it always answers (spec §1, L4PAR-AC9). Kept additive and separate
/// from [`super::active_commands`] so the command groups register independently.
/// `privilege` is the [`PrivilegeReportSource`] the status verb carries under its
/// optional `privilege` key (plan P1b.9).
pub(crate) fn intercept_commands(
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    sessions: Arc<InterceptSessions>,
    config: Option<InterceptConfig>,
    availability: AvailabilitySource,
    privilege: PrivilegeReportSource,
) -> (Vec<Arc<dyn Command>>, Arc<dyn Command>) {
    let start = InterceptStart::new(guard.clone(), store, sessions.clone(), config);
    commands_over(start, guard, sessions, availability, privilege)
}

/// The seven gated intercept commands over one start command + session registry,
/// plus the status verb. The guard is threaded to `forward` so a staged mutation
/// is re-checked before reinject; `availability` (the in-path class's source,
/// read at invoke time) and `privilege` (the report source) to `status`.
fn commands_over(
    start: InterceptStart,
    guard: Arc<L4Guard>,
    sessions: Arc<InterceptSessions>,
    availability: AvailabilitySource,
    privilege: PrivilegeReportSource,
) -> (Vec<Arc<dyn Command>>, Arc<dyn Command>) {
    let gated: Vec<Arc<dyn Command>> = vec![
        Arc::new(start),
        Arc::new(InterceptStop::new(sessions.clone())),
        Arc::new(InterceptList::new(sessions.clone())),
        Arc::new(InterceptMutate::new(sessions.clone())),
        Arc::new(InterceptRevert::new(sessions.clone())),
        Arc::new(InterceptForward::new(guard, sessions.clone())),
        Arc::new(InterceptDrop::new(sessions.clone())),
    ];
    (
        gated,
        Arc::new(InterceptStatus::new(sessions, availability, privilege)),
    )
}

// ---- shared helpers -----------------------------------------------------------

/// The fields a session reports (`start` result, `status` elements).
fn session_fields() -> Vec<ParamDef> {
    vec![
        field(
            "flow",
            TypeDesc::Str,
            true,
            "The interception session's flow id.",
        ),
        field("interface", TypeDesc::Str, true, "The bound interface."),
        field("queue", TypeDesc::Int, true, "The bound NFQUEUE number."),
        field("parked", TypeDesc::Int, true, "Packets currently parked."),
    ]
}

/// The fields a parked packet reports (`list` elements, `mutate` result).
fn parked_fields() -> Vec<ParamDef> {
    vec![
        field("id", TypeDesc::Str, true, "The parked packet id."),
        field(
            "flow",
            TypeDesc::Str,
            true,
            "The session flow id it belongs to.",
        ),
        field("state", TypeDesc::Str, true, "`parked` or `mutated`."),
        field("dir", TypeDesc::Str, true, "`inbound` or `outbound`."),
        field(
            "length",
            TypeDesc::Int,
            true,
            "The (current) packet byte length.",
        ),
        field(
            "layers",
            TypeDesc::Array(Box::new(TypeDesc::Str)),
            true,
            "Decoded layer names of the (current) packet.",
        ),
        field(
            "parked_at",
            TypeDesc::Int,
            true,
            "When the packet was parked, epoch milliseconds. `list` is ordered by \
             arrival, oldest first.",
        ),
    ]
}

/// A parked id as the string it carries on the bus (its serde-derived uuid string).
fn parked_id_to_string(id: ParkedId) -> String {
    match serde_json::to_value(id) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Parse a bus string into a parked id.
fn parked_id_from_str(s: &str) -> anyhow::Result<ParkedId> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("not a valid parked packet id `{s}`: {e}"))
}

/// `inbound` / `outbound` for a direction.
fn direction_str(dir: L4Direction) -> &'static str {
    match dir {
        L4Direction::Inbound => "inbound",
        L4Direction::Outbound => "outbound",
    }
}

/// The optional `direction` argument, defaulting to `outbound` (the common in-path
/// output-hook case). A non-string, non-null value is an error.
fn parse_direction_arg(args: &Params) -> anyhow::Result<L4Direction> {
    match args.get("direction") {
        None | Some(Value::Null) => Ok(L4Direction::Outbound),
        Some(Value::Str(s)) => super::parse_direction(s),
        Some(other) => anyhow::bail!("param `direction` must be a string, got {other:?}"),
    }
}

/// The optional `queue_num` argument, bounded to a `u16`.
fn optional_queue(args: &Params) -> anyhow::Result<Option<u16>> {
    match args.get("queue_num") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Int(i)) => u16::try_from(*i)
            .map(Some)
            .map_err(|_| anyhow::anyhow!("queue_num {i} is out of range 0..=65535")),
        Some(other) => anyhow::bail!("param `queue_num` must be an integer, got {other:?}"),
    }
}

/// The optional `flow` filter argument as an [`L4FlowId`].
fn optional_flow(args: &Params) -> anyhow::Result<Option<L4FlowId>> {
    match args.get("flow") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => super::flow_id_from_str(s).map(Some),
        Some(other) => anyhow::bail!("param `flow` must be a string, got {other:?}"),
    }
}

/// Build the replacement bytes for `l4.intercept.mutate` from exactly one of a
/// `spec` (a [`PacketSpec`] to compile) or raw `bytes`. A `Null` value counts as
/// absent, mirroring the rest of the command surface.
fn mutated_bytes(args: &Params) -> anyhow::Result<Vec<u8>> {
    let present = |v: &&Value| !matches!(v, Value::Null);
    let spec = args.get("spec").filter(present);
    let bytes = args.get("bytes").filter(present);
    match (spec, bytes) {
        (Some(_), Some(_)) => anyhow::bail!("give either `spec` or `bytes`, not both"),
        (Some(spec), None) => {
            let json = super::value_to_json(spec);
            let ps: PacketSpec = serde_json::from_value(json)
                .map_err(|e| anyhow::anyhow!("invalid PacketSpec: {e}"))?;
            ps.build().map_err(|e| anyhow::anyhow!("craft failed: {e}"))
        }
        (None, Some(bytes)) => bytes_of(bytes),
        (None, None) => anyhow::bail!("give one of `spec` or `bytes`"),
    }
}

/// A byte buffer from a `Bytes` value or an array of 0..=255 integers (matching the
/// craft layer's raw-payload convention).
fn bytes_of(v: &Value) -> anyhow::Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        Value::Array(items) => items
            .iter()
            .map(|it| match it {
                Value::Int(i) => u8::try_from(*i)
                    .map_err(|_| anyhow::anyhow!("byte {i} is out of range 0..=255")),
                other => anyhow::bail!("a bytes array element must be an integer, got {other:?}"),
            })
            .collect(),
        other => anyhow::bail!("`bytes` must be a byte buffer or array of integers, got {other:?}"),
    }
}

/// Find the session holding the parked packet `id`, returning its flow id and a
/// clone of the parked packet. `None` if no live session still holds it.
fn locate(map: &HashMap<L4FlowId, Session>, id: ParkedId) -> Option<(L4FlowId, ParkedPacket)> {
    map.iter().find_map(|(fid, session)| {
        session
            .handle
            .parked()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| (*fid, p))
    })
}

/// Build the operator confirm-over-the-wire summary for a parked-packet verdict
/// (`forward` / `drop`): the packet that will be acted on — its direction, decoded
/// layers, length, and (decoded) destination — plus whether it carries a staged
/// mutation. `use_mutation` picks the mutated bytes when a `forward` would reinject
/// them, so the operator sees exactly what hits the wire. `None` when the id is not
/// parked, so the server offers no confirmation (and mints no token) for a no-op.
fn verdict_confirm_summary(
    sessions: &InterceptSessions,
    args: &Params,
    verb: &str,
    use_mutation: bool,
) -> Option<String> {
    let id = parked_id_from_str(args.get_str("id").ok()?).ok()?;
    let map = sessions.lock();
    let (_flow, session) = map
        .iter()
        .find(|(_, s)| s.handle.parked().iter().any(|p| p.id == id))?;
    let parked = session.handle.parked().into_iter().find(|p| p.id == id)?;
    let edit = session.edits.get(&id);
    let (bytes, state) = match (use_mutation, edit) {
        (true, Some(e)) => (e.mutated.clone(), "mutated"),
        _ => (parked.packet.bytes.clone(), "original"),
    };
    let summary = PacketSpec::summarize(&bytes);
    let dst = crate::intercept::ip_target(&bytes, &session.interface, session.direction)
        .and_then(|t| t.dst)
        .map_or_else(|| "?".to_string(), |ip| ip.to_string());
    Some(format!(
        "Confirm {verb}: {state} {} packet [{}] ({} bytes) → {dst} on {} (queue {}). \
         Re-issue with `_confirm` to proceed.",
        direction_str(parked.packet.dir),
        summary.layers.join("/"),
        bytes.len(),
        session.interface,
        session.queue,
    ))
}

/// A session as a transport-neutral object (`start` result, `status` elements).
fn session_value(flow: &str, interface: &str, queue: u16, parked: usize) -> Value {
    let mut o = BTreeMap::new();
    o.insert("flow".to_string(), Value::Str(flow.to_string()));
    o.insert("interface".to_string(), Value::Str(interface.to_string()));
    o.insert("queue".to_string(), Value::Int(i64::from(queue)));
    o.insert("parked".to_string(), Value::Int(parked as i64));
    Value::Object(o)
}

/// A parked packet as a transport-neutral object (`list` elements, `mutate` result),
/// summarizing the current (possibly mutated) bytes, stamped with `parked_at`.
fn parked_value(
    id: ParkedId,
    flow: L4FlowId,
    state: &str,
    bytes: &[u8],
    dir: L4Direction,
    parked_at: SystemTime,
) -> Value {
    let summary = PacketSpec::summarize(bytes);
    let mut o = BTreeMap::new();
    o.insert("id".to_string(), Value::Str(parked_id_to_string(id)));
    o.insert("parked_at".to_string(), Value::Int(epoch_ms(parked_at)));
    o.insert(
        "flow".to_string(),
        Value::Str(super::flow_id_to_string(flow)),
    );
    o.insert("state".to_string(), Value::Str(state.to_string()));
    o.insert(
        "dir".to_string(),
        Value::Str(direction_str(dir).to_string()),
    );
    o.insert("length".to_string(), Value::Int(bytes.len() as i64));
    o.insert(
        "layers".to_string(),
        Value::Array(summary.layers.into_iter().map(Value::Str).collect()),
    );
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant, SystemTime};

    use aitm_core::{CommandHost, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
    use futures::future::BoxFuture;

    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::{InMemoryL4FlowStore, L4Packet};
    use crate::guard::{L4Guard, L4GuardError};
    use crate::intercept::{InterceptQueue, QueuedPacket, WireVerdict};
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, PortRange, RateCap,
    };

    const IFACE: &str = "lo";

    // ---- shared test scaffolding ----------------------------------------------

    /// The l4 commands never reissue HTTP; the core host still requires a client.
    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// Owns the core-host backing objects (the l4 commands read their own
    /// guard/store, so these only satisfy the `CommandHost` signature).
    struct HostParts {
        store: MemFlowStore,
        client: StubClient,
        guard: StdGuard,
    }

    impl HostParts {
        fn new() -> Self {
            Self {
                store: MemFlowStore::new(),
                client: StubClient,
                guard: StdGuard::default(),
            }
        }

        fn host(&self) -> CommandHost<'_> {
            CommandHost::new(&self.store, &self.client, &self.guard, None)
        }
    }

    fn scope_entry(cidr: (&str, u8), cap: L4Capability) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: cidr.0.parse().unwrap(),
                prefix: cidr.1,
            },
            ports: PortRange {
                lo: 0,
                hi: u16::MAX,
            },
            interface: IFACE.to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap {
                pps: 100,
                burst: 100,
            },
            source: crate::types::L4ScopeSource::Config,
        }
    }

    fn guard_with(entries: Vec<L4ScopeEntry>) -> Arc<L4Guard> {
        let g = L4Guard::new(&crate::config::L4Config::default());
        for e in entries {
            g.add_scope(e).unwrap();
        }
        Arc::new(g)
    }

    fn cfg(queue_num: u16) -> InterceptConfig {
        InterceptConfig {
            queue_num,
            verdict_timeout: Duration::from_secs(30),
            on_timeout: Verdict::Forward,
            max_parked: 16,
            on_overflow: Verdict::Forward,
        }
    }

    fn start_params(queue_num: u16) -> Params {
        let mut m = BTreeMap::new();
        m.insert("interface".to_string(), Value::Str(IFACE.into()));
        m.insert("direction".to_string(), Value::Str("outbound".into()));
        m.insert("queue_num".to_string(), Value::Int(i64::from(queue_num)));
        Params::new(m)
    }

    /// An IPv4/UDP packet (starting at L3, exactly as NFQUEUE delivers) to `dst:9`
    /// carrying `payload`.
    fn ip_udp(dst: &str, payload: &[u8]) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    dst: Some(dst.parse().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    dst_port: Some(9),
                    ..UdpSpec::default()
                }),
                Layer::Raw(payload.to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    fn one_param(name: &str, v: Value) -> Params {
        let mut m = BTreeMap::new();
        m.insert(name.to_string(), v);
        Params::new(m)
    }

    fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The parked-packet ids `l4.intercept.list` reports.
    fn list_ids(list: &InterceptList, host: &CommandHost) -> Vec<String> {
        let Value::Array(items) = list.invoke(Params::default(), host).expect("list ok") else {
            panic!("list returns an array");
        };
        items
            .into_iter()
            .map(|v| {
                let Value::Object(o) = v else {
                    panic!("a parked entry is an object");
                };
                match o.get("id") {
                    Some(Value::Str(s)) => s.clone(),
                    other => panic!("parked entry id must be a string, got {other:?}"),
                }
            })
            .collect()
    }

    // ---- a mock in-path backend (no NFQUEUE, no privilege) --------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum VKind {
        Forward,
        ForwardMangled(Vec<u8>),
        Drop,
    }

    type VerdictLog = Arc<Mutex<Vec<(u32, VKind)>>>;

    /// Replays a fixed script of packets into one session and records every verdict.
    struct MockBackend {
        script: Mutex<Option<Vec<Vec<u8>>>>,
        verdicts: VerdictLog,
    }

    impl MockBackend {
        fn with(frames: Vec<Vec<u8>>) -> (Arc<Self>, VerdictLog) {
            let verdicts: VerdictLog = Arc::new(Mutex::new(Vec::new()));
            let backend = Arc::new(Self {
                script: Mutex::new(Some(frames)),
                verdicts: verdicts.clone(),
            });
            (backend, verdicts)
        }
    }

    impl InterceptBackend for MockBackend {
        fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error> {
            let frames = self.script.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(MockQueue {
                frames: frames.into_iter().collect(),
                next_handle: AtomicU32::new(0),
                verdicts: self.verdicts.clone(),
            }))
        }
    }

    struct MockQueue {
        frames: VecDeque<Vec<u8>>,
        next_handle: AtomicU32,
        verdicts: VerdictLog,
    }

    impl InterceptQueue for MockQueue {
        fn next_packet(&mut self, _t: Duration) -> Result<Option<QueuedPacket>, L4Error> {
            match self.frames.pop_front() {
                Some(bytes) => {
                    let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(QueuedPacket { handle, bytes }))
                }
                None => {
                    std::thread::sleep(Duration::from_millis(2));
                    Ok(None)
                }
            }
        }

        fn verdict(&mut self, handle: u32, verdict: WireVerdict) -> Result<(), L4Error> {
            let kind = match verdict {
                WireVerdict::Forward(None) => VKind::Forward,
                WireVerdict::Forward(Some(b)) => VKind::ForwardMangled(b),
                WireVerdict::Drop => VKind::Drop,
            };
            self.verdicts.lock().unwrap().push((handle, kind));
            Ok(())
        }
    }

    fn mock_factory(backend: Arc<MockBackend>) -> BackendFactory {
        Arc::new(move |_q| backend.clone() as Arc<dyn InterceptBackend>)
    }

    /// A backend that must never be *opened* — its construction is harmless, but a
    /// bind (`open`) means authorization was skipped. Proves the guard gates the
    /// bind, not merely the backend object's existence.
    struct UnopenableBackend;
    impl InterceptBackend for UnopenableBackend {
        fn open(&self) -> Result<Box<dyn InterceptQueue>, L4Error> {
            panic!("backend opened despite an authorization refusal");
        }
    }

    fn unopenable_factory() -> BackendFactory {
        Arc::new(|_q| Arc::new(UnopenableBackend) as Arc<dyn InterceptBackend>)
    }

    // ---- tests ----------------------------------------------------------------

    /// Privilege spec §2.4 / L4PRIV-AC4 (plan P1b.9): `l4.intercept.status` gains
    /// the optional `privilege` key beside the parity four, whose values are
    /// byte-identical with and without the report source. `code` comes from
    /// `intercept_availability` over the same report, never a literal: a macOS
    /// report maps to `unsupported_platform`; a Linux report without
    /// `CAP_NET_ADMIN` (and without `CAP_NET_RAW`) maps to `needs_privilege`.
    #[test]
    fn status_carries_privilege_additively() {
        use crate::privilege::availability::intercept_availability;
        use crate::privilege::derive::{derive, LinuxInputs, MacInputs, ProbeInputs};
        use crate::privilege::report::{Platform, PrivilegeReport};

        const NOW: u64 = 1_762_000_000_123;
        let macos = derive(&ProbeInputs {
            enabled: true,
            platform: Platform::Macos,
            mac: Some(MacInputs {
                bpf_rw_opens: false,
                receipt: None,
                handoff_app_embeds_helper: false,
            }),
            linux: None,
            request: None,
            now_ms: NOW,
        });
        let linux_no_admin = derive(&ProbeInputs {
            enabled: true,
            platform: Platform::Linux,
            mac: None,
            linux: Some(LinuxInputs {
                cap_net_raw: false,
                cap_net_admin: false,
                session_connected: false,
                helper: None,
                policy_file_present: false,
                pkexec_present: false,
                prompt_possible: false,
                last_session_error: None,
            }),
            request: None,
            now_ms: NOW,
        });

        let parts = HostParts::new();
        let keys = |v: &Value| -> Vec<String> {
            let Value::Object(obj) = v else {
                panic!("status returns an object, got {v:?}");
            };
            obj.keys().cloned().collect()
        };

        for (report, want_code) in [
            (macos, "unsupported_platform"),
            (linux_no_admin, "needs_privilege"),
        ] {
            let availability: AvailabilitySource = {
                let report = report.clone();
                Arc::new(move || intercept_availability(&report, true))
            };
            let with_report: PrivilegeReportSource = {
                let report: PrivilegeReport = report.clone();
                Arc::new(move || Some(report.clone()))
            };
            let sessions = Arc::new(InterceptSessions::new());

            let full = InterceptStatus::new(sessions.clone(), availability.clone(), with_report)
                .invoke(Params::default(), &parts.host())
                .expect("status answers with a privilege report");
            assert_eq!(
                keys(&full),
                ["available", "code", "privilege", "reason", "sessions"],
                "{want_code}"
            );
            let Value::Object(full_obj) = &full else {
                unreachable!()
            };
            assert_eq!(full_obj.get("available"), Some(&Value::Bool(false)));
            assert_eq!(
                full_obj.get("code"),
                Some(&Value::Str(want_code.into())),
                "{want_code}"
            );
            assert_eq!(full_obj.get("sessions"), Some(&Value::Array(vec![])));
            assert_eq!(full_obj.get("privilege"), Some(&report.to_value()));

            let parity = InterceptStatus::new(sessions, availability, Arc::new(|| None))
                .invoke(Params::default(), &parts.host())
                .expect("status answers without a privilege report");
            assert_eq!(
                keys(&parity),
                ["available", "code", "reason", "sessions"],
                "{want_code}"
            );
            let mut full_minus_privilege = full_obj.clone();
            full_minus_privilege.remove("privilege");
            assert_eq!(parity, Value::Object(full_minus_privilege), "{want_code}");
        }
    }

    /// `intercept_commands` mints the whole `l4.intercept.*` surface over the shared
    /// session registry.
    #[test]
    fn commands_registered() {
        let guard = guard_with(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (gated, status) = intercept_commands(
            guard,
            store,
            sessions,
            Some(cfg(0)),
            Arc::new(|| crate::module::L4Availability::Available),
            Arc::new(|| None),
        );
        let names: Vec<&str> = gated.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            vec![
                "l4.intercept.start",
                "l4.intercept.stop",
                "l4.intercept.list",
                "l4.intercept.mutate",
                "l4.intercept.revert",
                "l4.intercept.forward",
                "l4.intercept.drop",
            ],
            "the gated list never carries the status verb"
        );
        assert_eq!(status.name(), "l4.intercept.status");
    }

    /// Plan Task 12 / AC3: a `Capture`-only scope refuses `l4.intercept.start` with
    /// `CapabilityNotGranted(Intercept)` — before any backend is opened, and with no
    /// session recorded. Hermetic (the guard refuses first), so it runs on any host.
    #[test]
    fn intercept_requires_capability() {
        let guard = guard_with(vec![scope_entry(("127.0.0.1", 32), L4Capability::Capture)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let start = InterceptStart::with_backend(
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            unopenable_factory(),
        );

        let parts = HostParts::new();
        let err = start.invoke(start_params(0), &parts.host()).unwrap_err();
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want an L4Error, got {err:?}"));
        assert_eq!(
            *l4,
            L4Error::Guard(L4GuardError::CapabilityNotGranted(L4Capability::Intercept)),
            "a Capture-only scope must refuse intercept with CapabilityNotGranted"
        );
        assert!(
            sessions.lock().is_empty(),
            "a refused start records no session"
        );
    }

    /// `l4.intercept.start` is `L4Unavailable` when in-path is disabled (`intercept:
    /// None`), before touching the guard or a backend.
    #[test]
    fn start_unavailable_when_disabled() {
        let guard = guard_with(vec![scope_entry(
            ("127.0.0.1", 32),
            L4Capability::Intercept,
        )]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let factory: BackendFactory =
            Arc::new(|_q| -> Arc<dyn InterceptBackend> { panic!("backend opened while disabled") });
        let start = InterceptStart::with_backend(guard, store, sessions, None, factory);

        let parts = HostParts::new();
        let err = start.invoke(start_params(0), &parts.host()).unwrap_err();
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want an L4Error, got {err:?}"));
        assert!(matches!(l4, L4Error::Unavailable(_)), "got {l4:?}");
    }

    /// Hermetic (mock backend): start → park an in-scope packet → mutate it via raw
    /// bytes → forward delivers the *mangled* bytes through the guarded verdict path.
    /// This is the command-layer wiring behind AC12, provable without NFQUEUE.
    #[test]
    fn mutate_then_forward_delivers_mangled_verdict() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, verdicts) = MockBackend::with(vec![ip_udp("10.0.0.5", b"ORIG")]);
        let start = InterceptStart::with_backend(
            guard.clone(),
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let forward = InterceptForward::new(guard.clone(), sessions.clone());

        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start ok");

        wait_until(|| list_ids(&list, &host).len() == 1, "one parked packet");
        let id = list_ids(&list, &host).remove(0);

        let mangled = ip_udp("10.0.0.5", b"MANGLED-PAYLOAD");
        mutate
            .invoke(
                {
                    let mut m = BTreeMap::new();
                    m.insert("id".to_string(), Value::Str(id.clone()));
                    m.insert("bytes".to_string(), Value::Bytes(mangled.clone()));
                    Params::new(m)
                },
                &host,
            )
            .expect("mutate ok");

        let forwarded = forward
            .invoke(one_param("id", Value::Str(id)), &host)
            .expect("forward ok");
        assert_eq!(forwarded, Value::Bool(true));

        wait_until(
            || !verdicts.lock().unwrap().is_empty(),
            "the forward verdict",
        );
        assert_eq!(
            verdicts.lock().unwrap().as_slice(),
            &[(0, VKind::ForwardMangled(mangled))],
            "a mutated-then-forwarded packet is reinjected mangled"
        );
    }

    /// Panel finding (Important): the park-time `Intercept` permit was minted with
    /// `dst: None`, so a mutation that re-aims the packet at a destination the
    /// operator never scoped must be re-checked before it is reinjected. A mutation
    /// onto the dangerous-destination denylist (cloud metadata) or out of the scoped
    /// CIDR is refused with a typed error and is **never delivered mangled**; an
    /// in-scope mutation still forwards. Hermetic via the mock queue.
    #[test]
    fn mutate_out_of_scope_forward_refused() {
        // An interception session scoped to `scope_cidr`, with one in-scope packet
        // (10.0.0.5) parked, used to test a mutation that re-aims it at `bad_dst`.
        let run_case =
            |scope_cidr: (&str, u8), bad_dst: &str| -> (anyhow::Result<Value>, Vec<(u32, VKind)>) {
                let guard = guard_with(vec![scope_entry(scope_cidr, L4Capability::Intercept)]);
                let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
                let sessions = Arc::new(InterceptSessions::new());
                let (backend, verdicts) = MockBackend::with(vec![ip_udp("10.0.0.5", b"ORIG")]);
                let start = InterceptStart::with_backend(
                    guard.clone(),
                    store,
                    sessions.clone(),
                    Some(cfg(0)),
                    mock_factory(backend),
                );
                let list = InterceptList::new(sessions.clone());
                let mutate = InterceptMutate::new(sessions.clone());
                let forward = InterceptForward::new(guard.clone(), sessions.clone());

                let parts = HostParts::new();
                let host = parts.host();
                start.invoke(start_params(0), &host).expect("start ok");
                wait_until(|| list_ids(&list, &host).len() == 1, "one parked packet");
                let id = list_ids(&list, &host).remove(0);

                // Re-aim the parked packet at an out-of-scope / dangerous destination.
                mutate
                    .invoke(
                        {
                            let mut m = BTreeMap::new();
                            m.insert("id".to_string(), Value::Str(id.clone()));
                            m.insert(
                                "bytes".to_string(),
                                Value::Bytes(ip_udp(bad_dst, b"RE-AIMED")),
                            );
                            Params::new(m)
                        },
                        &host,
                    )
                    .expect("mutate stages the edit");

                let result = forward.invoke(one_param("id", Value::Str(id)), &host);
                // Give any (erroneously) submitted verdict a chance to land before we read.
                std::thread::sleep(Duration::from_millis(20));
                let log = verdicts.lock().unwrap().clone();
                (result, log)
            };

        // (A) Cloud-metadata — covered by a broad scope, so it is the denylist (not a
        // plain scope miss) that must block the re-aimed mutation.
        let (res, log) = run_case(("0.0.0.0", 0), "169.254.169.254");
        let err = res.expect_err("a mutation onto the denylist must be refused");
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        assert!(
            matches!(
                l4,
                L4Error::Guard(L4GuardError::DangerousDestinationBlocked(_))
            ),
            "want DangerousDestinationBlocked, got {l4:?}"
        );
        assert!(
            log.is_empty(),
            "a refused mutation is NEVER delivered mangled; got {log:?}"
        );

        // (B) A mutation that leaves the scoped CIDR entirely.
        let (res, log) = run_case(("10.0.0.5", 32), "8.8.8.8");
        let err = res.expect_err("a mutation leaving scope must be refused");
        let l4 = err
            .downcast_ref::<L4Error>()
            .unwrap_or_else(|| panic!("want a typed L4Error, got {err:?}"));
        assert!(
            matches!(l4, L4Error::Guard(L4GuardError::OutOfL4Scope(_))),
            "want OutOfL4Scope, got {l4:?}"
        );
        assert!(
            log.is_empty(),
            "a refused mutation is NEVER delivered mangled; got {log:?}"
        );
    }

    /// Hermetic (mock backend): a parked packet given `l4.intercept.drop` yields a
    /// Drop verdict. The command-layer wiring behind AC13.
    #[test]
    fn drop_records_drop_verdict() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, verdicts) = MockBackend::with(vec![ip_udp("10.0.0.5", b"ORIG")]);
        let start = InterceptStart::with_backend(
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let drop_cmd = InterceptDrop::new(sessions.clone());

        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start ok");

        wait_until(|| list_ids(&list, &host).len() == 1, "one parked packet");
        let id = list_ids(&list, &host).remove(0);

        let dropped = drop_cmd
            .invoke(one_param("id", Value::Str(id)), &host)
            .expect("drop ok");
        assert_eq!(dropped, Value::Bool(true));

        wait_until(|| !verdicts.lock().unwrap().is_empty(), "the drop verdict");
        assert_eq!(verdicts.lock().unwrap().as_slice(), &[(0, VKind::Drop)]);
    }

    /// Hermetic: `revert` discards a staged edit so a later `forward` reinjects the
    /// kernel's original (untouched) packet, not the mutation.
    #[test]
    fn revert_then_forward_is_untouched() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, verdicts) = MockBackend::with(vec![ip_udp("10.0.0.5", b"ORIG")]);
        let start = InterceptStart::with_backend(
            guard.clone(),
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let revert = InterceptRevert::new(sessions.clone());
        let forward = InterceptForward::new(guard.clone(), sessions.clone());

        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start ok");
        wait_until(|| list_ids(&list, &host).len() == 1, "one parked packet");
        let id = list_ids(&list, &host).remove(0);

        mutate
            .invoke(
                {
                    let mut m = BTreeMap::new();
                    m.insert("id".to_string(), Value::Str(id.clone()));
                    m.insert(
                        "bytes".to_string(),
                        Value::Bytes(ip_udp("10.0.0.5", b"MANGLED")),
                    );
                    Params::new(m)
                },
                &host,
            )
            .expect("mutate ok");
        assert_eq!(
            revert
                .invoke(one_param("id", Value::Str(id.clone())), &host)
                .unwrap(),
            Value::Bool(true)
        );

        forward
            .invoke(one_param("id", Value::Str(id)), &host)
            .expect("forward ok");
        wait_until(
            || !verdicts.lock().unwrap().is_empty(),
            "the forward verdict",
        );
        assert_eq!(
            verdicts.lock().unwrap().as_slice(),
            &[(0, VKind::Forward)],
            "a reverted packet forwards untouched"
        );
    }

    /// The `mutated_bytes` helper: a `spec` builds bytes, raw `bytes` pass through,
    /// and the two are mutually exclusive / required.
    #[test]
    fn mutated_bytes_sources() {
        // Raw bytes array.
        let got = mutated_bytes(&one_param(
            "bytes",
            Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(255)]),
        ))
        .expect("bytes ok");
        assert_eq!(got, vec![1u8, 2, 255]);

        // A PacketSpec spec builds the same bytes as a direct craft.
        let spec = {
            let mut l = BTreeMap::new();
            let mut raw = BTreeMap::new();
            raw.insert(
                "raw".to_string(),
                Value::Array(b"hi".iter().map(|b| Value::Int(i64::from(*b))).collect()),
            );
            l.insert("layers".to_string(), Value::Array(vec![Value::Object(raw)]));
            Value::Object(l)
        };
        let got = mutated_bytes(&one_param("spec", spec)).expect("spec ok");
        assert_eq!(got, b"hi".to_vec());

        // Neither ⇒ error; both ⇒ error; out-of-range byte ⇒ error.
        assert!(mutated_bytes(&Params::default()).is_err());
        let mut both = BTreeMap::new();
        both.insert("bytes".to_string(), Value::Bytes(vec![0]));
        both.insert("spec".to_string(), Value::Null);
        // Null spec counts as absent, so this is the bytes path, not "both".
        assert!(mutated_bytes(&Params::new(both)).is_ok());
        assert!(mutated_bytes(&one_param("bytes", Value::Array(vec![Value::Int(256)]))).is_err());
    }

    /// AC37 (plan A13): `l4.intercept.list` is in **arrival order**, oldest first,
    /// and every entry carries `parked_at` (epoch ms). The order comes from the
    /// per-session arrival sequence assigned when a packet is parked, never from the
    /// random uuid string: `P2` (uuid `…0002`) is parked first and `P1` (uuid `…0001`,
    /// which sorts *lower* as a string) second, so the list must be `[P2, P1]`.
    #[test]
    fn intercept_list_is_arrival_ordered() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, _verdicts) = MockBackend::with(vec![]);
        let start = InterceptStart::with_backend(
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start ok");

        let p2 = ParkedId::from_u128(2);
        let p1 = ParkedId::from_u128(1);
        let packet = |payload: &[u8]| {
            let bytes = ip_udp("10.0.0.5", payload);
            L4Packet {
                dir: L4Direction::Outbound,
                timestamp: SystemTime::now(),
                decoded: PacketSpec::summarize(&bytes),
                bytes,
                injected: false,
            }
        };
        {
            let map = sessions.lock();
            let session = map.values().next().expect("one live session");
            let deadline = SystemTime::now() + Duration::from_secs(30);
            session
                .handle
                .park_for_test(p2, packet(b"arrives first"), deadline);
            session
                .handle
                .park_for_test(p1, packet(b"arrives second"), deadline);
        }

        let Value::Array(items) = list.invoke(Params::default(), &host).expect("list ok") else {
            panic!("list returns an array");
        };
        let field = |v: &Value, name: &str| -> Value {
            let Value::Object(o) = v else {
                panic!("a parked entry is an object");
            };
            o.get(name)
                .unwrap_or_else(|| panic!("entry lacks `{name}`"))
                .clone()
        };
        let ids: Vec<Value> = items.iter().map(|v| field(v, "id")).collect();
        assert_eq!(
            ids,
            vec![
                Value::Str("00000000-0000-0000-0000-000000000002".into()),
                Value::Str("00000000-0000-0000-0000-000000000001".into()),
            ],
            "arrival order, not uuid string order"
        );
        let parked_at: Vec<i64> = items
            .iter()
            .map(|v| match field(v, "parked_at") {
                Value::Int(ms) => ms,
                other => panic!("`parked_at` must be an Int (epoch ms), got {other:?}"),
            })
            .collect();
        assert!(
            parked_at[0] <= parked_at[1],
            "the first-listed (oldest) entry's parked_at {} must be <= the next {}",
            parked_at[0],
            parked_at[1]
        );
        // Epoch milliseconds, not seconds or nanoseconds: after 2020-01-01T00:00:00Z
        // and before 3000-01-01T00:00:00Z.
        assert!(
            parked_at[0] > 1_577_836_800_000 && parked_at[0] < 32_503_680_000_000,
            "parked_at {} is not an epoch-ms timestamp",
            parked_at[0]
        );

        // The schema advertises the new field as an Int.
        let TypeDesc::Array(elem) = list.schema().result else {
            panic!("list result is an array");
        };
        let TypeDesc::Object(fields) = *elem else {
            panic!("list elements are objects");
        };
        let parked_at_field = fields
            .iter()
            .find(|f| f.name == "parked_at")
            .expect("schema lists `parked_at`");
        assert!(
            matches!(parked_at_field.ty, TypeDesc::Int),
            "`parked_at` is an Int in the schema, got {:?}",
            parked_at_field.ty
        );
        assert!(parked_at_field.required);
    }

    // ---- Tester (stage 5): L4PAR-AC37 edge cases -----------------------------

    /// The `(id, parked_at, state)` of every entry `l4.intercept.list` returns for
    /// `params`, in reply order.
    fn list_entries(
        list: &InterceptList,
        host: &CommandHost,
        params: Params,
    ) -> Vec<(String, i64, String)> {
        let Value::Array(items) = list.invoke(params, host).expect("list ok") else {
            panic!("list returns an array");
        };
        items
            .into_iter()
            .map(|v| {
                let Value::Object(o) = v else {
                    panic!("a parked entry is an object");
                };
                let id = match o.get("id") {
                    Some(Value::Str(s)) => s.clone(),
                    other => panic!("id must be a string, got {other:?}"),
                };
                let at = match o.get("parked_at") {
                    Some(Value::Int(ms)) => *ms,
                    other => panic!("parked_at must be an Int, got {other:?}"),
                };
                let state = match o.get("state") {
                    Some(Value::Str(s)) => s.clone(),
                    other => panic!("state must be a string, got {other:?}"),
                };
                (id, at, state)
            })
            .collect()
    }

    /// A parked UDP packet to `10.0.0.5:9` carrying `payload`.
    fn parked_packet(payload: &[u8]) -> L4Packet {
        let bytes = ip_udp("10.0.0.5", payload);
        L4Packet {
            dir: L4Direction::Outbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        }
    }

    /// AC37 (tester): mutating the oldest parked packet does not move it. The
    /// order is the arrival sequence, not "last touched", so the intercept bar's
    /// default (the first listed) stays on the same packet after a Mutate, and the
    /// `flow` filter keeps that order.
    #[test]
    fn intercept_list_order_survives_mutate_and_flow_filter() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, _verdicts) = MockBackend::with(vec![]);
        let start = InterceptStart::with_backend(
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start ok");

        let deadline = SystemTime::now() + Duration::from_secs(30);
        let ids = [3_u128, 1, 2].map(ParkedId::from_u128);
        let flow = {
            let map = sessions.lock();
            let (fid, session) = map.iter().next().expect("one live session");
            for (i, id) in ids.iter().enumerate() {
                session
                    .handle
                    .park_for_test(*id, parked_packet(&[b'a' + i as u8]), deadline);
            }
            *fid
        };
        let want: Vec<String> = ids.iter().map(|id| parked_id_to_string(*id)).collect();
        assert_eq!(
            want,
            vec![
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            ]
        );

        // Mutate the oldest (uuid ...0003) with new raw bytes.
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), Value::Str(want[0].clone()));
        m.insert(
            "bytes".to_string(),
            Value::Bytes(ip_udp("10.0.0.5", b"mutated")),
        );
        mutate.invoke(Params::new(m), &host).expect("mutate ok");

        let got = list_entries(&list, &host, Params::default());
        let got_ids: Vec<&str> = got.iter().map(|(id, _, _)| id.as_str()).collect();
        assert_eq!(got_ids, want, "a mutate must not reorder the list");
        assert_eq!(got[0].2, "mutated");
        assert_eq!(got[1].2, "parked");
        assert_eq!(got[2].2, "parked");
        assert!(
            got[0].1 <= got[1].1 && got[1].1 <= got[2].1,
            "parked_at is non-decreasing in arrival order: {got:?}"
        );

        // The same order through the `flow` filter the UIs use.
        let filtered = list_entries(
            &list,
            &host,
            one_param("flow", Value::Str(super::super::flow_id_to_string(flow))),
        );
        let filtered_ids: Vec<&str> = filtered.iter().map(|(id, _, _)| id.as_str()).collect();
        assert_eq!(filtered_ids, want);

        // A well-formed flow id with no session lists nothing.
        let other = list_entries(
            &list,
            &host,
            one_param(
                "flow",
                Value::Str(super::super::flow_id_to_string(crate::flow::L4FlowId::new())),
            ),
        );
        assert!(other.is_empty(), "an unknown flow lists nothing: {other:?}");
    }

    /// AC37 (tester): a malformed `flow` filter is an error, not an unfiltered list.
    #[test]
    fn intercept_list_rejects_malformed_flow_filter() {
        let sessions = Arc::new(InterceptSessions::new());
        let list = InterceptList::new(sessions);
        let parts = HostParts::new();
        let host = parts.host();
        assert!(list
            .invoke(one_param("flow", Value::Str("not-a-uuid".into())), &host)
            .is_err());
        assert!(list
            .invoke(one_param("flow", Value::Int(7)), &host)
            .is_err());
        // `null` counts as absent: the (empty) unfiltered list.
        assert_eq!(
            list.invoke(one_param("flow", Value::Null), &host)
                .expect("null flow is no filter"),
            Value::Array(vec![])
        );
    }

    /// AC37 (tester, fixed): across two live sessions the unfiltered
    /// `l4.intercept.list` is in true arrival order. The arrival sequence is
    /// process-wide (one counter for every session), and the sort key is
    /// `(parked_seq, id)`, so session A's second packet lists before session B's
    /// first packet when it arrived first. Spec §4: "in arrival order, oldest
    /// first".
    #[test]
    fn intercept_list_is_arrival_ordered_across_sessions() {
        let guard = guard_with(vec![scope_entry(("10.0.0.5", 32), L4Capability::Intercept)]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let (backend, _verdicts) = MockBackend::with(vec![]);
        let start = InterceptStart::with_backend(
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let parts = HostParts::new();
        let host = parts.host();
        start.invoke(start_params(0), &host).expect("start A");
        start.invoke(start_params(1), &host).expect("start B");

        let deadline = SystemTime::now() + Duration::from_secs(30);
        let park = |session_index: usize, id: u128| {
            let map = sessions.lock();
            let mut flows: Vec<_> = map.keys().copied().collect();
            flows.sort_by_key(|f| super::super::flow_id_to_string(*f));
            let session = map.get(&flows[session_index]).expect("session");
            session
                .handle
                .park_for_test(ParkedId::from_u128(id), parked_packet(b"x"), deadline);
        };
        // Arrival: A1 (A seq 0), A2 (A seq 1), then B1 (B seq 0), with a gap so
        // `parked_at` differs by at least one millisecond each time.
        park(0, 0xA1);
        std::thread::sleep(Duration::from_millis(5));
        park(0, 0xA2);
        std::thread::sleep(Duration::from_millis(5));
        park(1, 0xB1);

        let got = list_entries(&list, &host, Params::default());
        let got_ids: Vec<String> = got.into_iter().map(|(id, _, _)| id).collect();
        assert_eq!(
            got_ids,
            vec![
                parked_id_to_string(ParkedId::from_u128(0xA1)),
                parked_id_to_string(ParkedId::from_u128(0xA2)),
                parked_id_to_string(ParkedId::from_u128(0xB1)),
            ],
            "oldest first across sessions"
        );
    }

    // ---- Linux-gated functional tests (real NFQUEUE on a loopback nft queue) ---

    /// Whether the privileged, Linux-only in-path functional suite should run.
    fn inpath_enabled() -> bool {
        cfg!(target_os = "linux") && std::env::var("AITM_L4_INPATH").ok().as_deref() == Some("1")
    }

    /// Install / tear down a loopback `nft` output-hook rule that steers UDP to
    /// `dport` into queue `queue`. Returns whether the command succeeded.
    fn nft(args: &[&str]) -> bool {
        std::process::Command::new("nft")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Plan Task 12 / AC12 (`AITM_L4_INPATH`, Linux): against a scoped loopback
    /// `nft` queue, a parked packet mutated then forwarded is delivered **mangled**.
    #[test]
    #[ignore = "privileged + Linux NFQUEUE; run as root with AITM_L4_INPATH=1 and -- --ignored"]
    fn mutate_forward_delivers_mangled() {
        if !inpath_enabled() {
            return;
        }
        use std::net::UdpSocket;

        const QUEUE: u16 = 2112;
        let table = "aitm_t12_fwd";

        // A receiver on loopback; its port is what the nft rule queues.
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let dport = receiver.local_addr().unwrap().port();

        // Scoped nft output-hook rule: UDP to the receiver's port → queue QUEUE.
        let _ = nft(&["delete", "table", "inet", table]);
        assert!(nft(&["add", "table", "inet", table]), "nft add table");
        assert!(
            nft(&[
                "add", "chain", "inet", table, "out", "{", "type", "filter", "hook", "output",
                "priority", "0", ";", "}",
            ]),
            "nft add chain"
        );
        assert!(
            nft(&[
                "add",
                "rule",
                "inet",
                table,
                "out",
                "ip",
                "daddr",
                "127.0.0.1",
                "udp",
                "dport",
                &dport.to_string(),
                "queue",
                "num",
                &QUEUE.to_string(),
            ]),
            "nft add rule"
        );

        let guard = guard_with(vec![scope_entry(
            ("127.0.0.1", 32),
            L4Capability::Intercept,
        )]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let start = InterceptStart::new(guard.clone(), store, sessions.clone(), Some(cfg(QUEUE)));
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let forward = InterceptForward::new(guard.clone(), sessions.clone());
        let parts = HostParts::new();
        let host = parts.host();

        start
            .invoke(start_params(QUEUE), &host)
            .expect("start binds");

        // Send the original datagram; it is parked at the output hook.
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender
            .send_to(b"ORIGINAL", ("127.0.0.1", dport))
            .expect("send original");

        wait_until(|| !list_ids(&list, &host).is_empty(), "the packet to park");
        let id = list_ids(&list, &host).remove(0);

        // Rebuild a valid IPv4/UDP datagram to the same dst with a new payload.
        let mangled = PacketSpec {
            layers: vec![
                Layer::Ipv4(Ipv4Spec {
                    src: Some("127.0.0.1".parse().unwrap()),
                    dst: Some("127.0.0.1".parse().unwrap()),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(sender.local_addr().unwrap().port()),
                    dst_port: Some(dport),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"MANGLED!".to_vec()),
            ],
        }
        .build()
        .expect("craft mangled");

        let mut mp = BTreeMap::new();
        mp.insert("id".to_string(), Value::Str(id.clone()));
        mp.insert("bytes".to_string(), Value::Bytes(mangled));
        mutate.invoke(Params::new(mp), &host).expect("mutate ok");
        forward
            .invoke(one_param("id", Value::Str(id)), &host)
            .expect("forward ok");

        let mut buf = [0u8; 64];
        let n = receiver
            .recv(&mut buf)
            .expect("receiver gets the forwarded packet");
        assert_eq!(
            &buf[..n],
            b"MANGLED!",
            "the delivered packet is the mutation"
        );

        let _ = nft(&["delete", "table", "inet", table]);
    }

    /// Plan Task 12 / AC13 (`AITM_L4_INPATH`, Linux): a parked packet given
    /// `l4.intercept.drop` is **not delivered** — the receiver times out.
    #[test]
    #[ignore = "privileged + Linux NFQUEUE; run as root with AITM_L4_INPATH=1 and -- --ignored"]
    fn drop_not_delivered() {
        if !inpath_enabled() {
            return;
        }
        use std::net::UdpSocket;

        const QUEUE: u16 = 2113;
        let table = "aitm_t12_drop";

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let dport = receiver.local_addr().unwrap().port();

        let _ = nft(&["delete", "table", "inet", table]);
        assert!(nft(&["add", "table", "inet", table]), "nft add table");
        assert!(
            nft(&[
                "add", "chain", "inet", table, "out", "{", "type", "filter", "hook", "output",
                "priority", "0", ";", "}",
            ]),
            "nft add chain"
        );
        assert!(
            nft(&[
                "add",
                "rule",
                "inet",
                table,
                "out",
                "ip",
                "daddr",
                "127.0.0.1",
                "udp",
                "dport",
                &dport.to_string(),
                "queue",
                "num",
                &QUEUE.to_string(),
            ]),
            "nft add rule"
        );

        let guard = guard_with(vec![scope_entry(
            ("127.0.0.1", 32),
            L4Capability::Intercept,
        )]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let start = InterceptStart::new(guard, store, sessions.clone(), Some(cfg(QUEUE)));
        let list = InterceptList::new(sessions.clone());
        let drop_cmd = InterceptDrop::new(sessions.clone());
        let parts = HostParts::new();
        let host = parts.host();

        start
            .invoke(start_params(QUEUE), &host)
            .expect("start binds");

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender
            .send_to(b"ORIGINAL", ("127.0.0.1", dport))
            .expect("send original");

        wait_until(|| !list_ids(&list, &host).is_empty(), "the packet to park");
        let id = list_ids(&list, &host).remove(0);

        drop_cmd
            .invoke(one_param("id", Value::Str(id)), &host)
            .expect("drop ok");

        let mut buf = [0u8; 64];
        assert!(
            receiver.recv(&mut buf).is_err(),
            "a dropped packet is never delivered"
        );

        let _ = nft(&["delete", "table", "inet", table]);
    }
}
