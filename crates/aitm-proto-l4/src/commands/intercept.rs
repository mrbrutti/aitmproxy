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
//! - `l4.intercept.status` — the live sessions and their parked counts (read-only).
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

use aitm_core::{Command, CommandHost, ParamDef, ParamSchema, Params, TypeDesc, Value};

use crate::backend::L4Error;
use crate::config::{InterceptConfig, Verdict};
use crate::craft::PacketSpec;
use crate::flow::{L4FlowId, L4FlowStore};
use crate::guard::L4Guard;
use crate::intercept::{
    start_intercept, InterceptBackend, InterceptHandle, InterceptParams, NfqueueBackend, ParkedId,
    ParkedPacket,
};
use crate::types::L4Direction;

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
            anyhow::Error::new(L4Error::Unavailable(
                "in-path interception is disabled (no `intercept` config)".into(),
            ))
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

/// `l4.intercept.status` — the live interception sessions (read-only).
pub(crate) struct InterceptStatus {
    sessions: Arc<InterceptSessions>,
}

impl InterceptStatus {
    /// A status command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptStatus {
    fn name(&self) -> &str {
        "l4.intercept.status"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the live interception sessions and their parked-packet counts \
                          (read-only)."
                .into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(session_fields()))),
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
        Ok(Value::Array(out.into_iter().map(|(_, v)| v).collect()))
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

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the packets currently parked awaiting a verdict, across sessions \
                          or for one `flow` (read-only)."
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
        let mut out: Vec<(String, Value)> = Vec::new();
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
                let value = parked_value(parked.id, *fid, state, bytes, parked.packet.dir);
                out.push((parked_id_to_string(parked.id), value));
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
    sessions: Arc<InterceptSessions>,
}

impl InterceptForward {
    /// A forward command over the shared session registry.
    pub(crate) fn new(sessions: Arc<InterceptSessions>) -> Self {
        Self { sessions }
    }
}

impl Command for InterceptForward {
    fn name(&self) -> &str {
        "l4.intercept.forward"
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
        let mutated = session.edits.remove(&id).map(|e| e.mutated);
        let ok = session.handle.submit_verdict(id, Verdict::Forward, mutated);
        Ok(Value::Bool(ok))
    }
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
/// registry, using the production NFQUEUE backend. Kept additive and separate from
/// [`super::active_commands`] so the two command groups register independently.
pub(crate) fn intercept_commands(
    guard: Arc<L4Guard>,
    store: Arc<dyn L4FlowStore>,
    sessions: Arc<InterceptSessions>,
    config: Option<InterceptConfig>,
) -> Vec<Arc<dyn Command>> {
    let start = InterceptStart::new(guard, store, sessions.clone(), config);
    commands_over(start, sessions)
}

/// The eight intercept commands over one start command + session registry.
fn commands_over(start: InterceptStart, sessions: Arc<InterceptSessions>) -> Vec<Arc<dyn Command>> {
    vec![
        Arc::new(start),
        Arc::new(InterceptStop::new(sessions.clone())),
        Arc::new(InterceptStatus::new(sessions.clone())),
        Arc::new(InterceptList::new(sessions.clone())),
        Arc::new(InterceptMutate::new(sessions.clone())),
        Arc::new(InterceptRevert::new(sessions.clone())),
        Arc::new(InterceptForward::new(sessions.clone())),
        Arc::new(InterceptDrop::new(sessions)),
    ]
}

// ---- shared helpers -----------------------------------------------------------

/// The fields a session reports (`start` result, `status` elements).
fn session_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
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
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
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
/// summarizing the current (possibly mutated) bytes.
fn parked_value(
    id: ParkedId,
    flow: L4FlowId,
    state: &str,
    bytes: &[u8],
    dir: L4Direction,
) -> Value {
    let summary = PacketSpec::summarize(bytes);
    let mut o = BTreeMap::new();
    o.insert("id".to_string(), Value::Str(parked_id_to_string(id)));
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
    use std::time::{Duration, Instant};

    use aitm_core::{CommandHost, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
    use futures::future::BoxFuture;

    use crate::craft::{Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::flow::InMemoryL4FlowStore;
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

    /// `intercept_commands` mints the whole `l4.intercept.*` surface over the shared
    /// session registry.
    #[test]
    fn commands_registered() {
        let guard = guard_with(vec![]);
        let store: Arc<dyn L4FlowStore> = Arc::new(InMemoryL4FlowStore::new());
        let sessions = Arc::new(InterceptSessions::new());
        let cmds = intercept_commands(guard, store, sessions, Some(cfg(0)));
        let names: Vec<&str> = cmds.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            vec![
                "l4.intercept.start",
                "l4.intercept.stop",
                "l4.intercept.status",
                "l4.intercept.list",
                "l4.intercept.mutate",
                "l4.intercept.revert",
                "l4.intercept.forward",
                "l4.intercept.drop",
            ]
        );
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
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let forward = InterceptForward::new(sessions.clone());

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
            guard,
            store,
            sessions.clone(),
            Some(cfg(0)),
            mock_factory(backend),
        );
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let revert = InterceptRevert::new(sessions.clone());
        let forward = InterceptForward::new(sessions.clone());

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
        let start = InterceptStart::new(guard, store, sessions.clone(), Some(cfg(QUEUE)));
        let list = InterceptList::new(sessions.clone());
        let mutate = InterceptMutate::new(sessions.clone());
        let forward = InterceptForward::new(sessions.clone());
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
