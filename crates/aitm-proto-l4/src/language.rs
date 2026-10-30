//! The L4 consumer of the `ProtocolLanguage` seam (plan
//! `2026-10-28-aitmproxy-protocol-extensible-languages`, Task 6).
//!
//! [`L4Language`] makes L4 first-class in **both** scripting faces through the one
//! seam, with **no edit** to `aitm-plugin-rhai` or `aitm-poc`:
//!
//! - **Rhai:** `register_host_fns` installs the `l4.*` host namespace
//!   (`l4.interfaces`, `l4.craft`, `l4.scope.*`, `l4.flow.*`, `l4.inject`,
//!   `l4.send_recv`) so a script calls `l4.send_recv(spec, dst, iface, port)`.
//! - **PoC:** `poc_step` returns the native `L4StepHandler` for the `l4:` step,
//!   whose human-friendly, scapy-style body produces a `packet` matcher/extractor
//!   source a PoC asserts on (`extract { type: packet, field: tcp.flags }`).
//! - **Catalog:** `catalog` describes both faces as the data that assembles into
//!   `rhai.api.json` / `poc-yaml.schema.json`.
//!
//! ## Gating (the L4 interlock, frozen)
//!
//! Every `l4.*` host fn and every `l4:` verb routes through the **same** gating the
//! `l4.*` command path applies, over the **same** shared objects — the
//! [`L4Guard`] and its [`L4AgentGates`](crate::gates::L4AgentGates):
//!
//! 1. The **agent gate** (`l4.allow_agent_*`) is enforced here, in
//!    [`agent_gate_check`], exactly as the command path's
//!    [`L4AgentGate`](crate::commands) enforces it — but only when the engine is
//!    **agent-sourced** (`Frontend::Mcp`), never for operator-authored scripts.
//!    The verb→gate map is the command path's `gate_for`: `inject` / `send_recv`
//!    → [`AgentGate::Inject`]; `scope.add`'s **widen** gate is enforced inside
//!    [`L4Guard::add_runtime_scope`] for every runtime caller (so it is not an
//!    agent-only gate and is not duplicated here).
//! 2. The **scope / denylist / rate / capability** check is the `L4Guard` itself,
//!    run inside each verb's logic (`l4.send_recv` → [`send_recv`], `l4.inject` →
//!    [`send_on_wire`] over an `L4Guard::check` permit). Deny-by-default: an empty
//!    or non-matching scope refuses before anything reaches the wire.
//!
//! This is the architect's **sanctioned fallback** (not by-construction via a
//! `Command::invoke`): the host-fn model (`Fn(&[Value])`) carries no
//! `CommandHost`, so the l4 language captures the shared `Arc<L4Guard>` +
//! `agent_gates()` and applies the identical checks over the identical objects.
//! The only command-path layer not mirrored is the HTTP-shaped core
//! `ScopeRateGuard::check_active` defense-in-depth, which needs a `CommandHost`
//! this seam does not thread; the L4 guard (the real L4 authorization) is applied
//! in full.
//!
//! ## Surface scope
//!
//! The namespace exposes the **one-shot** l4 verbs — the ones that fit a
//! stateless host-fn call / single PoC assertion step. The **session-oriented**
//! verbs (`l4.capture.*`, which runs a background capture, and `l4.intercept.*`,
//! the Linux-only in-path NFQUEUE session) stay on the command bus / operator UI;
//! they do not map onto a one-shot host fn or PoC step. The operator-only
//! `l4.agent.set` / `l4.agent.status` are deliberately **not** scripting verbs
//! (an agent must never read-then-flip its own gates).
//!
//! [`L4Guard`]: crate::guard::L4Guard
//! [`send_recv`]: crate::sendrecv::send_recv
//! [`send_on_wire`]: crate::wire::send_on_wire

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::Value;
use aitm_plugin::language::{
    GuardHandle, Guarded, HostError, HostFn, HostFnSig, NamespaceCatalog, ParamSig, PocStepHandler,
    PocStepInputs, PocStepOutcome, PocStepSchema, ProtocolLanguage, RegisterError,
    ScriptHostRegistry,
};

use crate::backend::pcap::PcapBackend;
use crate::backend::CaptureInjectBackend;
use crate::config::L4Config;
use crate::craft::{IcmpSpec, Ipv4Spec, Ipv6Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
use crate::flow::{
    InMemoryL4FlowStore, L4Bind, L4Flow, L4FlowId, L4FlowKind, L4FlowStore, L4Meta, L4Packet,
};
use crate::gates::{AgentGate, L4AgentGates};
use crate::guard::{L4Guard, L4GuardError};
use crate::sendrecv::{send_recv, ReplyMatch, SendRecvOutcome, SendRecvSpec};
use crate::types::{L4Action, L4Direction};
use crate::wire::send_on_wire;

/// The namespace this crate contributes: `l4.*` host fns, the `l4:` PoC step.
pub const NAMESPACE: &str = "l4";

/// The l4 namespace's API version (a per-namespace semver-ish token, like the
/// script tier's `const API`).
pub const API_VERSION: &str = "0.1.0";

/// The matcher/extractor source the `l4:` step contributes: the received packet,
/// as a dotted-walkable object (`tcp.flags`, `ipv4.src`, …).
pub const PACKET_SOURCE: &str = "packet";

/// Default `send_recv` await when a `l4:` step omits `timeout_ms`.
const DEFAULT_TIMEOUT_MS: u64 = 1000;

/// The default interface a `l4:` step injects on / captures from when its body
/// omits `interface` (the normative spec example does).
const DEFAULT_INTERFACE: &str = "lo";

/// Every l4 scripting verb, in catalog order — the one vocabulary shared by the
/// Rhai `l4.*` host fns, the `l4:` step `op`, and the `l4.*` command names. The
/// optional [`AgentGate`] is the command path's `gate_for` for that verb (`None`
/// ⇒ not agent-gated at this layer).
const VERBS: &[(&str, Option<AgentGate>)] = &[
    ("interfaces", None),
    ("craft", None),
    ("scope.add", None), // widen gate lives in L4Guard::add_runtime_scope
    ("scope.remove", None),
    ("scope.list", None),
    ("flow.list", None),
    ("flow.get", None),
    ("inject", Some(AgentGate::Inject)),
    ("send_recv", Some(AgentGate::Inject)),
];

/// The **wire** subset of [`VERBS`] — the verbs a one-shot `l4:` PoC step actually
/// runs (`craft`, `inject`, `send_recv`), in catalog order. The full [`VERBS`] set
/// stays the one shared Rhai host-fn / `l4.*` command vocabulary; the `l4:` step's
/// `op` enum is this *consistent subset* of it (AC8): every step `op` is a real
/// host-fn verb, but the query / session verbs have no one-shot assertion step, so
/// they are driven from a `script:` step instead. The other six `VERBS` would
/// `BadArgs` at runtime as a `l4:` `op`, so they are kept out of the step enum.
const WIRE_VERBS: &[&str] = &["craft", "inject", "send_recv"];

/// The agent gate that governs `verb`, if any (the command path's `gate_for`).
fn gate_for(verb: &str) -> Option<AgentGate> {
    VERBS.iter().find(|(v, _)| *v == verb).and_then(|(_, g)| *g)
}

/// The live L4 state the scripting verbs act over — the **same** guard, backend,
/// and flow store the `l4.*` command surface uses when shared through
/// [`L4Module`](crate::module::L4Module).
#[derive(Clone)]
struct L4Live {
    guard: Arc<L4Guard>,
    backend: Arc<dyn CaptureInjectBackend>,
    store: Arc<dyn L4FlowStore>,
}

/// L4's contribution to both language faces and the shared completion catalog.
///
/// Construct with [`L4Language::new`] for a live engine (its `register_host_fns`
/// and `l4:` handler act over the shared guard/backend/store), or
/// [`L4Language::for_catalog`] for the static catalog assembly
/// (`production_languages()`), which needs only `catalog()` / `namespace()` /
/// `api_version()`.
pub struct L4Language {
    live: L4Live,
    /// Whether the engine this language is installed on is **agent-sourced**
    /// (`Frontend::Mcp`). Only then do the `l4.allow_agent_*` gates apply (an
    /// operator-authored script is the control, exactly like the command path).
    agent_sourced: bool,
}

impl L4Language {
    /// A live L4 language over the shared guard, wire backend, and flow store.
    /// `agent_sourced` marks the engine as agent-driven (`Frontend::Mcp`), the
    /// only case where the per-capability agent gates apply.
    #[must_use]
    pub fn new(
        guard: Arc<L4Guard>,
        backend: Arc<dyn CaptureInjectBackend>,
        store: Arc<dyn L4FlowStore>,
        agent_sourced: bool,
    ) -> Self {
        Self {
            live: L4Live {
                guard,
                backend,
                store,
            },
            agent_sourced,
        }
    }

    /// A language for the **static catalog** only (`production_languages()` →
    /// `rhai.api.json`). It carries a default deny-by-default guard, the pure
    /// (no-privilege) wire backend, and an in-memory store, because
    /// `catalog()` / `namespace()` / `api_version()` read only static data — no
    /// live engagement state is needed to describe the surface.
    #[must_use]
    pub fn for_catalog() -> Self {
        let cfg = L4Config::default();
        Self::new(
            Arc::new(L4Guard::new(&cfg)),
            Arc::new(PcapBackend::new()),
            Arc::new(InMemoryL4FlowStore::new()),
            false,
        )
    }
}

impl ProtocolLanguage for L4Language {
    fn namespace(&self) -> &str {
        NAMESPACE
    }

    fn api_version(&self) -> &str {
        API_VERSION
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        for (verb, gate) in VERBS {
            let live = self.live.clone();
            let verb_name = (*verb).to_string();
            let f: HostFn = Box::new(move |args: &[Value]| host_fn(&live, &verb_name, args));
            let guard = L4SeamGuard {
                agent_sourced: self.agent_sourced,
                gates: self.live.guard.agent_gates(),
                gate: *gate,
            };
            reg.register(NAMESPACE, verb, Guarded::new(Box::new(guard), f))?;
        }
        Ok(())
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        Some(Box::new(L4StepHandler {
            live: self.live.clone(),
            agent_sourced: self.agent_sourced,
        }))
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: NAMESPACE.to_string(),
            api_version: API_VERSION.to_string(),
            host_fns: catalog_host_fns(),
            poc_step: Some(catalog_poc_step()),
            sources: vec![PACKET_SOURCE.to_string()],
        }
    }
}

/// The l4 guard the seam installs around each `l4.*` host fn. Its
/// [`permit`](GuardHandle::permit) enforces the **agent gate** (the first command
/// path dimension) before the host fn runs; the host fn's body then runs the
/// `L4Guard` scope/denylist/rate check (the second), so the two dimensions match
/// the command path over the same shared objects.
struct L4SeamGuard {
    agent_sourced: bool,
    gates: Arc<L4AgentGates>,
    gate: Option<AgentGate>,
}

impl GuardHandle for L4SeamGuard {
    fn guard_name(&self) -> &str {
        NAMESPACE
    }

    fn permit(&self, fn_name: &str) -> Result<(), HostError> {
        agent_gate_check(self.agent_sourced, &self.gates, fn_name, self.gate)
    }
}

/// Enforce the per-capability agent gate for `verb`, exactly as the command
/// path's [`L4AgentGate`](crate::commands) does: a `Frontend::Mcp` (agent) caller
/// is refused a Sensitive verb whose `l4.allow_agent_*` gate is closed; an
/// operator-authored engine (`agent_sourced == false`) bypasses it, as the
/// operator/CLI roles do on the command path. A verb with no agent gate (`None`)
/// is always admitted here (its own guard, e.g. `scope.add`'s widen, runs in the
/// verb body).
fn agent_gate_check(
    agent_sourced: bool,
    gates: &L4AgentGates,
    verb: &str,
    gate: Option<AgentGate>,
) -> Result<(), HostError> {
    if !agent_sourced {
        return Ok(());
    }
    if let Some(gate) = gate {
        if !gates.allowed(gate) {
            return Err(HostError::GuardRefused {
                namespace: NAMESPACE.to_string(),
                reason: format!(
                    "agent access to the L4 `{}` capability is disabled; `l4.{verb}` refused. An \
                     operator can enable it (`l4.agent.set {{capability: \"{}\", allowed: true}}` \
                     or the `l4.allow_agent_{}` config flag).",
                    gate.label(),
                    gate.label(),
                    gate.label(),
                ),
            });
        }
    }
    Ok(())
}

// ===========================================================================
// Rhai host-fn dispatch
// ===========================================================================

/// Dispatch a `l4.<verb>(...)` Rhai call (arguments already marshalled to
/// [`Value`]) to the shared verb logic. The agent gate already ran in
/// [`L4SeamGuard::permit`]; the `L4Guard` scope check runs inside the verb.
fn host_fn(live: &L4Live, verb: &str, args: &[Value]) -> Result<Value, HostError> {
    match verb {
        "interfaces" => Ok(do_interfaces()),
        "craft" => {
            let spec = parse_spec_arg(args.first())?;
            Ok(do_craft(&spec)?)
        }
        "scope.add" => {
            let obj = object_arg(args.first())?;
            do_scope_add(live, obj)
        }
        "scope.remove" => {
            let id = str_arg(args.first(), "id")?;
            do_scope_remove(live, &id)
        }
        "scope.list" => Ok(do_scope_list(live)),
        "flow.list" => Ok(do_flow_list(live)),
        "flow.get" => {
            let id = str_arg(args.first(), "id")?;
            do_flow_get(live, &id)
        }
        "inject" => {
            let spec = parse_spec_arg(args.first())?;
            let dst = ip_arg(args.get(1), "dst")?;
            let interface = str_arg(args.get(2), "interface")?;
            let count = args.get(3).and_then(value_as_u32).unwrap_or(1);
            do_inject(live, &spec, dst, &interface, count)
        }
        "send_recv" => {
            let spec = parse_spec_arg(args.first())?;
            let dst = ip_arg(args.get(1), "dst")?;
            let interface = str_arg(args.get(2), "interface")?;
            let dst_port = args.get(3).and_then(value_as_u16);
            let timeout_ms = args
                .get(4)
                .and_then(value_as_u64)
                .unwrap_or(DEFAULT_TIMEOUT_MS);
            let (flow_id, outcome) = do_send_recv(
                live,
                SendRecvSpec {
                    packet: spec,
                    dst,
                    dst_port,
                    interface,
                    timeout: Duration::from_millis(timeout_ms),
                    expect: ReplyMatch::FiveTuple,
                },
            )?;
            Ok(send_recv_value(flow_id, &outcome))
        }
        other => Err(HostError::BadArgs(format!("unknown l4 verb `{other}`"))),
    }
}

// ===========================================================================
// Shared verb logic — one implementation behind both faces
// ===========================================================================

/// `l4.interfaces` — the capture-capable interfaces (fail-closed to empty).
fn do_interfaces() -> Value {
    let devices = ::pcap::Device::list().unwrap_or_default();
    Value::Array(
        devices
            .into_iter()
            .map(|d| {
                let mut o = BTreeMap::new();
                o.insert("name".to_string(), Value::Str(d.name));
                if let Some(desc) = d.desc {
                    o.insert("description".to_string(), Value::Str(desc));
                }
                Value::Object(o)
            })
            .collect(),
    )
}

/// `l4.craft` — build on-wire bytes from a spec (pure; no guard, no wire).
fn do_craft(spec: &PacketSpec) -> Result<Value, HostError> {
    let bytes = spec
        .build()
        .map_err(|e| HostError::BadArgs(format!("craft failed: {e}")))?;
    let summary = PacketSpec::summarize(&bytes);
    let mut sum = BTreeMap::new();
    sum.insert(
        "layers".to_string(),
        Value::Array(summary.layers.iter().cloned().map(Value::Str).collect()),
    );
    sum.insert(
        "length".to_string(),
        Value::Int(i64::try_from(summary.length).unwrap_or(i64::MAX)),
    );
    let mut obj = BTreeMap::new();
    obj.insert(
        "length".to_string(),
        Value::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
    );
    obj.insert("summary".to_string(), Value::Object(sum));
    obj.insert("bytes".to_string(), Value::Bytes(bytes));
    Ok(Value::Object(obj))
}

/// `l4.scope.add` — a runtime (bus) scope widening, gated by the guard's **widen**
/// gate (`L4Guard::add_runtime_scope`, deny-by-default) for every runtime caller.
fn do_scope_add(live: &L4Live, obj: &BTreeMap<String, Value>) -> Result<Value, HostError> {
    use crate::commands::{parse_capability, parse_cidr, parse_direction, parse_ports};
    use crate::types::{L4ScopeEntry, L4ScopeId, L4ScopeSource, RateCap};

    let field = |k: &str| -> Result<String, HostError> {
        match obj.get(k) {
            Some(Value::Str(s)) => Ok(s.clone()),
            _ => Err(HostError::BadArgs(format!(
                "`scope.add` missing string `{k}`"
            ))),
        }
    };
    let cidr = parse_cidr(&field("cidr")?).map_err(bad)?;
    let interface = field("interface")?;
    let direction = parse_direction(&field("direction")?).map_err(bad)?;
    let capability = parse_capability(&field("capability")?).map_err(bad)?;
    let ports = match obj.get("ports") {
        Some(Value::Str(s)) => parse_ports(s).map_err(bad)?,
        _ => parse_ports("*").map_err(bad)?,
    };
    let pps = obj
        .get("inject_rate_pps")
        .and_then(value_as_u32)
        .unwrap_or(0);
    let entry = L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr,
        ports,
        interface,
        direction,
        capability,
        inject_rate: RateCap { pps, burst: pps },
        source: L4ScopeSource::Runtime,
    };
    let id = live.guard.add_runtime_scope(entry).map_err(guard_err)?;
    Ok(Value::Str(crate::commands::scope_id_to_string(id)))
}

/// `l4.scope.remove` — drop a runtime scope entry by id; `false` if unknown.
fn do_scope_remove(live: &L4Live, id: &str) -> Result<Value, HostError> {
    let id = crate::commands::scope_id_from_str(id).map_err(bad)?;
    Ok(Value::Bool(live.guard.remove_scope(id)))
}

/// `l4.scope.list` — the current scope entries.
fn do_scope_list(live: &L4Live) -> Value {
    Value::Array(
        live.guard
            .list_scope()
            .iter()
            .map(crate::commands::scope_entry_to_value)
            .collect(),
    )
}

/// `l4.flow.list` — the stored L4 flow ids.
fn do_flow_list(live: &L4Live) -> Value {
    Value::Array(
        live.store
            .list()
            .into_iter()
            .map(|id| Value::Str(crate::commands::flow_id_to_string(id)))
            .collect(),
    )
}

/// `l4.flow.get` — a summary of one stored L4 flow.
fn do_flow_get(live: &L4Live, id: &str) -> Result<Value, HostError> {
    let id = crate::commands::flow_id_from_str(id).map_err(bad)?;
    let flow = live
        .store
        .get(id)
        .ok_or_else(|| HostError::BadArgs(format!("no L4 flow with id {id:?}")))?;
    Ok(crate::commands::flow::flow_to_value(&flow))
}

/// `l4.inject` — guarded wire write of a crafted packet, `count` copies, through
/// the single [`send_on_wire`] choke point over an `L4Guard::check` permit.
fn do_inject(
    live: &L4Live,
    spec: &PacketSpec,
    dst: IpAddr,
    interface: &str,
    count: u32,
) -> Result<Value, HostError> {
    let bytes = spec
        .build()
        .map_err(|e| HostError::BadArgs(format!("craft failed: {e}")))?;
    // Gate the destination actually on the wire (the crafted bytes), not the `dst`
    // argument — the choke point the command path uses.
    let real_target = crate::capture::packet_target(&bytes, interface, L4Direction::Outbound)
        .ok_or_else(|| {
            guard_err(L4GuardError::OutOfL4Scope(
                "crafted packet has no decodable IP destination; cannot verify scope".into(),
            ))
        })?;
    if real_target.dst != Some(dst) {
        return Err(guard_err(L4GuardError::OutOfL4Scope(
            real_target
                .dst
                .map_or_else(|| dst.to_string(), |d| d.to_string()),
        )));
    }
    let mut permit = live
        .guard
        .check(L4Action::Inject, &real_target)
        .map_err(guard_err)?;

    let flow_id = live.store.insert(L4Flow {
        id: L4FlowId::new(),
        kind: L4FlowKind::Craft,
        bind: L4Bind {
            interface: interface.to_string(),
            filter: None,
            queue: None,
        },
        packets: Vec::new().into(),
        metadata: L4Meta::default(),
    });
    // `count` already defaults to 1 for an *absent* arg (the Rhai/PoC callers use
    // `unwrap_or(1)`); an *explicit* `count: 0` is a deliberate no-op, so iterate
    // `0..count` rather than forcing at least one copy with `.max(1)`.
    let mut sent: i64 = 0;
    for _ in 0..count {
        send_on_wire(&mut permit, live.backend.as_ref(), interface, &bytes).map_err(l4_err)?;
        live.store.append_packet(
            flow_id,
            L4Packet {
                dir: L4Direction::Outbound,
                timestamp: SystemTime::now(),
                decoded: PacketSpec::summarize(&bytes),
                bytes: bytes.clone(),
                injected: true,
            },
        );
        sent += 1;
    }
    let mut obj = BTreeMap::new();
    obj.insert(
        "flow_id".to_string(),
        Value::Str(crate::commands::flow_id_to_string(flow_id)),
    );
    obj.insert("sent".to_string(), Value::Int(sent));
    Ok(Value::Object(obj))
}

/// `l4.send_recv` — scapy `sr1`: inject the stimulus and await the correlated
/// reply, all gated inside [`send_recv`] (Inject + Capture permits before any I/O).
fn do_send_recv(
    live: &L4Live,
    spec: SendRecvSpec,
) -> Result<(L4FlowId, SendRecvOutcome), HostError> {
    send_recv(&live.guard, live.backend.clone(), live.store.clone(), spec).map_err(l4_err)
}

/// A [`SendRecvOutcome`] as the object the Rhai `l4.send_recv` returns.
fn send_recv_value(flow_id: L4FlowId, outcome: &SendRecvOutcome) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert(
        "flow_id".to_string(),
        Value::Str(crate::commands::flow_id_to_string(flow_id)),
    );
    let mut out = BTreeMap::new();
    match outcome {
        SendRecvOutcome::Response(pkt) | SendRecvOutcome::Other(pkt) => {
            let kind = if matches!(outcome, SendRecvOutcome::Response(_)) {
                "response"
            } else {
                "other"
            };
            out.insert("kind".to_string(), Value::Str(kind.to_string()));
            out.insert(PACKET_SOURCE.to_string(), packet_to_value(&pkt.bytes));
        }
        SendRecvOutcome::Responses(pkts) => {
            out.insert("kind".to_string(), Value::Str("responses".to_string()));
            out.insert(
                "packets".to_string(),
                Value::Array(pkts.iter().map(|p| packet_to_value(&p.bytes)).collect()),
            );
        }
        SendRecvOutcome::NoResponse { waited } => {
            out.insert("kind".to_string(), Value::Str("no_response".to_string()));
            out.insert(
                "waited_ms".to_string(),
                Value::Int(i64::try_from(waited.as_millis()).unwrap_or(i64::MAX)),
            );
        }
    }
    obj.insert("outcome".to_string(), Value::Object(out));
    Value::Object(obj)
}

// ===========================================================================
// The native `l4:` PoC step
// ===========================================================================

/// The `l4:` PoC step handler. Its body is human-friendly, scapy-style YAML:
///
/// ```yaml
/// - l4:
///     op: send_recv
///     packet:
///       layers:
///         - ipv4: { dst: "{{target_ip}}" }
///         - tcp:  { dport: 80, flags: S }     # SYN
///     timeout_ms: 1000
///   extract:
///     - name: synack_flags
///       type: packet                          # the `packet` source
///       field: tcp.flags                       # dotted-walked by the runner
/// ```
///
/// `op: send_recv` injects the stimulus (fully gated by the shared `L4Guard` and,
/// for an agent-sourced engine, the `allow_agent_inject` gate) and binds the
/// received reply as the [`PACKET_SOURCE`] source — an object whose `tcp.flags`
/// renders scapy-style (`"SA"` for SYN-ACK), so a sibling `extract` + a `dsl`
/// success assert on it.
pub(crate) struct L4StepHandler {
    live: L4Live,
    agent_sourced: bool,
}

impl PocStepHandler for L4StepHandler {
    fn ns(&self) -> &str {
        NAMESPACE
    }

    fn run(
        &self,
        body: &serde_yaml::Value,
        inputs: &PocStepInputs,
    ) -> Result<PocStepOutcome, HostError> {
        let op = body
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HostError::BadArgs("`l4:` step missing `op`".to_string()))?
            .to_string();

        // The agent gate (first dimension) runs here, mirroring the command path,
        // before the verb's own `L4Guard` scope check (second dimension).
        agent_gate_check(
            self.agent_sourced,
            &self.live.guard.agent_gates(),
            &op,
            gate_for(&op),
        )?;

        match op.as_str() {
            "send_recv" => self.run_send_recv(body, &inputs.vars),
            "inject" => self.run_inject(body, &inputs.vars),
            "craft" => {
                let spec = step_packet(body, &inputs.vars)?;
                let value = do_craft(&spec)?;
                Ok(bind_result(value))
            }
            // The query / session verbs are valid l4 vocabulary (one vocabulary,
            // AC8) but are not one-shot assertion steps: drive them from a Rhai
            // `script:` step (`l4.scope.list()`, …). A `l4:` step is for the wire
            // verbs that yield a `packet` to assert on.
            "interfaces" | "scope.add" | "scope.remove" | "scope.list" | "flow.list"
            | "flow.get" => Err(HostError::BadArgs(format!(
                "`l4:` step `op: {op}` is not a one-shot step verb; call `l4.{op}(...)` from a \
                 `script:` step instead"
            ))),
            other => Err(HostError::BadArgs(format!(
                "`l4:` step: unknown op `{other}`"
            ))),
        }
    }
}

impl L4StepHandler {
    /// `op: send_recv` — inject + await, binding the reply as the `packet` source.
    fn run_send_recv(
        &self,
        body: &serde_yaml::Value,
        vars: &BTreeMap<String, Value>,
    ) -> Result<PocStepOutcome, HostError> {
        let spec = step_packet(body, vars)?;
        let dst = packet_dst(&spec)
            .ok_or_else(|| HostError::BadArgs("`l4:` packet has no IP `dst`".to_string()))?;
        let dst_port = packet_dst_port(&spec);
        let interface = step_interface(body);
        let timeout_ms = body
            .get("timeout_ms")
            .and_then(serde_yaml::Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_MS);

        let (flow_id, outcome) = do_send_recv(
            &self.live,
            SendRecvSpec {
                packet: spec,
                dst,
                dst_port,
                interface,
                timeout: Duration::from_millis(timeout_ms),
                expect: ReplyMatch::FiveTuple,
            },
        )?;

        let mut sources = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let kind = match &outcome {
            SendRecvOutcome::Response(pkt) | SendRecvOutcome::Other(pkt) => {
                sources.insert(PACKET_SOURCE.to_string(), packet_to_value(&pkt.bytes));
                if matches!(outcome, SendRecvOutcome::Response(_)) {
                    "response"
                } else {
                    "other"
                }
            }
            SendRecvOutcome::Responses(_) => "responses",
            SendRecvOutcome::NoResponse { .. } => "no_response",
        };
        bindings.insert("l4_outcome".to_string(), Value::Str(kind.to_string()));
        bindings.insert(
            "l4_flow_id".to_string(),
            Value::Str(crate::commands::flow_id_to_string(flow_id)),
        );
        Ok(PocStepOutcome { sources, bindings })
    }

    /// `op: inject` — guarded wire write, binding the flow id and sent count.
    fn run_inject(
        &self,
        body: &serde_yaml::Value,
        vars: &BTreeMap<String, Value>,
    ) -> Result<PocStepOutcome, HostError> {
        let spec = step_packet(body, vars)?;
        let dst = packet_dst(&spec)
            .ok_or_else(|| HostError::BadArgs("`l4:` packet has no IP `dst`".to_string()))?;
        let interface = step_interface(body);
        let count = body
            .get("count")
            .and_then(serde_yaml::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1);
        let value = do_inject(&self.live, &spec, dst, &interface, count)?;
        Ok(bind_result(value))
    }
}

/// Bind a verb's result object under a `l4_result` binding (visible to later
/// steps and `success`).
fn bind_result(value: Value) -> PocStepOutcome {
    let mut bindings = BTreeMap::new();
    bindings.insert("l4_result".to_string(), value);
    PocStepOutcome {
        sources: BTreeMap::new(),
        bindings,
    }
}

/// The interface a `l4:` step binds to: its `interface` field, else the default.
fn step_interface(body: &serde_yaml::Value) -> String {
    body.get("interface")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_INTERFACE)
        .to_string()
}

// ===========================================================================
// scapy-style layer parsing (the `l4:` step's human-friendly packet form)
// ===========================================================================

/// Parse a `l4:` step's `packet.layers` into a [`PacketSpec`], expanding
/// `{{placeholder}}`s from the step inputs. Scapy-friendly: `tcp.dport`,
/// `tcp.flags: "S"`, `ipv4.dst`, a `raw` string/byte payload — the normative
/// human-readable shape, distinct from the serde `PacketSpec` the Rhai host fns
/// take (which mirrors the `l4.craft` command).
fn step_packet(
    body: &serde_yaml::Value,
    vars: &BTreeMap<String, Value>,
) -> Result<PacketSpec, HostError> {
    let layers = body
        .get("packet")
        .and_then(|p| p.get("layers"))
        .and_then(|l| l.as_sequence())
        .ok_or_else(|| HostError::BadArgs("`l4:` step missing `packet.layers`".to_string()))?;
    let mut out = Vec::with_capacity(layers.len());
    for layer in layers {
        out.push(parse_layer(layer, vars)?);
    }
    if out.is_empty() {
        return Err(HostError::BadArgs(
            "`l4:` `packet.layers` is empty".to_string(),
        ));
    }
    Ok(PacketSpec { layers: out })
}

/// Parse one `{ <proto>: { ... } }` scapy layer map.
fn parse_layer(
    layer: &serde_yaml::Value,
    vars: &BTreeMap<String, Value>,
) -> Result<Layer, HostError> {
    let map = layer
        .as_mapping()
        .ok_or_else(|| HostError::BadArgs("a `l4:` layer must be a map".to_string()))?;
    let (key, fields) = map
        .iter()
        .next()
        .ok_or_else(|| HostError::BadArgs("an empty `l4:` layer map".to_string()))?;
    let key = key
        .as_str()
        .ok_or_else(|| HostError::BadArgs("a `l4:` layer key must be a string".to_string()))?;
    match key {
        "ipv4" => Ok(Layer::Ipv4(Ipv4Spec {
            src: opt_ip4(fields, "src", vars)?,
            dst: opt_ip4(fields, "dst", vars)?,
            ttl: opt_u8(fields, "ttl")?,
            ..Ipv4Spec::default()
        })),
        "ipv6" => Ok(Layer::Ipv6(Ipv6Spec {
            src: opt_ip6(fields, "src", vars)?,
            dst: opt_ip6(fields, "dst", vars)?,
            hop_limit: opt_u8(fields, "hop_limit")?,
            ..Ipv6Spec::default()
        })),
        "tcp" => Ok(Layer::Tcp(TcpSpec {
            src_port: opt_u16_any(fields, &["sport", "src_port"])?,
            dst_port: opt_u16_any(fields, &["dport", "dst_port"])?,
            seq: opt_u32(fields, "seq")?,
            ack: opt_u32(fields, "ack")?,
            flags: opt_tcp_flags(fields)?,
            window: opt_u16(fields, "window")?,
            ..TcpSpec::default()
        })),
        "udp" => Ok(Layer::Udp(UdpSpec {
            src_port: opt_u16_any(fields, &["sport", "src_port"])?,
            dst_port: opt_u16_any(fields, &["dport", "dst_port"])?,
            ..UdpSpec::default()
        })),
        "icmp" => Ok(Layer::Icmp(IcmpSpec {
            icmp_type: opt_u8(fields, "type")?,
            code: opt_u8(fields, "code")?,
            ..IcmpSpec::default()
        })),
        "ether" => Ok(Layer::Ether(Default::default())),
        "raw" => Ok(Layer::Raw(parse_raw(fields, vars)?)),
        other => Err(HostError::BadArgs(format!("unknown `l4:` layer `{other}`"))),
    }
}

/// `tcp.flags`: a scapy letter string (`"SA"`), an integer, or absent.
fn opt_tcp_flags(fields: &serde_yaml::Value) -> Result<Option<u8>, HostError> {
    match fields.get("flags") {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(flags_from_letters(s))),
        Some(v) => v
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| {
                HostError::BadArgs("`tcp.flags` must be a letter string or a byte".into())
            }),
    }
}

/// scapy flag letters → the TCP flags byte (`"SA"` ⇒ SYN|ACK = 0x12).
fn flags_from_letters(s: &str) -> u8 {
    let mut bits = 0u8;
    for c in s.chars() {
        bits |= match c.to_ascii_uppercase() {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' => 0x40,
            'C' => 0x80,
            _ => 0,
        };
    }
    bits
}

/// A `raw` layer: a string payload or a byte array (`[80, 81, …]`).
fn parse_raw(
    fields: &serde_yaml::Value,
    vars: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, HostError> {
    match fields {
        serde_yaml::Value::String(s) => Ok(expand(s, vars).into_bytes()),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| HostError::BadArgs("`raw` bytes must be 0..=255".into()))
            })
            .collect(),
        _ => Err(HostError::BadArgs(
            "`raw` must be a string or a byte array".into(),
        )),
    }
}

fn opt_u8(fields: &serde_yaml::Value, key: &str) -> Result<Option<u8>, HostError> {
    match fields.get(key).and_then(serde_yaml::Value::as_u64) {
        Some(n) => u8::try_from(n)
            .map(Some)
            .map_err(|_| HostError::BadArgs(format!("`{key}` out of range (0..=255)"))),
        None => Ok(None),
    }
}

fn opt_u16(fields: &serde_yaml::Value, key: &str) -> Result<Option<u16>, HostError> {
    match fields.get(key).and_then(serde_yaml::Value::as_u64) {
        Some(n) => u16::try_from(n)
            .map(Some)
            .map_err(|_| HostError::BadArgs(format!("`{key}` out of range (0..=65535)"))),
        None => Ok(None),
    }
}

/// Parse the first present key among `keys` as a u16 port, parsing it **once** and
/// propagating its range error. Unlike `opt_u16(a).or(opt_u16(b))?` — where
/// `Result::or` returns `self` on `Ok(None)`, leaving the alias dead code and
/// *swallowing* an out-of-range primary port's `Err` — this picks the first key
/// that is actually present (so the alias is live) and never silently drops an
/// invalid, agent-controlled port value.
fn opt_u16_any(fields: &serde_yaml::Value, keys: &[&str]) -> Result<Option<u16>, HostError> {
    for key in keys {
        match fields.get(key) {
            None | Some(serde_yaml::Value::Null) => continue,
            Some(v) => {
                return match v.as_u64() {
                    Some(n) => u16::try_from(n).map(Some).map_err(|_| {
                        HostError::BadArgs(format!("`{key}` out of range (0..=65535)"))
                    }),
                    None => Err(HostError::BadArgs(format!(
                        "`{key}` must be a number (0..=65535)"
                    ))),
                };
            }
        }
    }
    Ok(None)
}

fn opt_u32(fields: &serde_yaml::Value, key: &str) -> Result<Option<u32>, HostError> {
    match fields.get(key).and_then(serde_yaml::Value::as_u64) {
        Some(n) => u32::try_from(n)
            .map(Some)
            .map_err(|_| HostError::BadArgs(format!("`{key}` out of range"))),
        None => Ok(None),
    }
}

fn opt_ip4(
    fields: &serde_yaml::Value,
    key: &str,
    vars: &BTreeMap<String, Value>,
) -> Result<Option<std::net::Ipv4Addr>, HostError> {
    match fields.get(key).and_then(|v| v.as_str()) {
        Some(s) => expand(s, vars)
            .parse()
            .map(Some)
            .map_err(|_| HostError::BadArgs(format!("`{key}` is not an IPv4 address"))),
        None => Ok(None),
    }
}

fn opt_ip6(
    fields: &serde_yaml::Value,
    key: &str,
    vars: &BTreeMap<String, Value>,
) -> Result<Option<std::net::Ipv6Addr>, HostError> {
    match fields.get(key).and_then(|v| v.as_str()) {
        Some(s) => expand(s, vars)
            .parse()
            .map(Some)
            .map_err(|_| HostError::BadArgs(format!("`{key}` is not an IPv6 address"))),
        None => Ok(None),
    }
}

/// The destination IP a crafted spec targets (first ipv4/ipv6 `dst`).
fn packet_dst(spec: &PacketSpec) -> Option<IpAddr> {
    for layer in &spec.layers {
        match layer {
            Layer::Ipv4(s) => return s.dst.map(IpAddr::V4),
            Layer::Ipv6(s) => return s.dst.map(IpAddr::V6),
            _ => {}
        }
    }
    None
}

/// The destination port a crafted spec targets (first tcp/udp `dst_port`).
fn packet_dst_port(spec: &PacketSpec) -> Option<u16> {
    for layer in &spec.layers {
        match layer {
            Layer::Tcp(s) => return s.dst_port,
            Layer::Udp(s) => return s.dst_port,
            _ => {}
        }
    }
    None
}

// ===========================================================================
// The `packet` matcher/extractor source (a decoded reply, dotted-walkable)
// ===========================================================================

/// Decode a received frame into the `packet` source: a dotted-walkable object so
/// a PoC `extract { type: packet, field: tcp.flags }` resolves. Unparseable input
/// yields just `{ length }` (never an error — a frame is data, not a bad arg).
fn packet_to_value(bytes: &[u8]) -> Value {
    use etherparse::{NetSlice, TransportSlice};

    let mut obj = BTreeMap::new();
    obj.insert(
        "length".to_string(),
        Value::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
    );

    if let Some(parsed) = crate::craft::parse_frame(bytes) {
        match parsed.net {
            Some(NetSlice::Ipv4(ip)) => {
                let mut o = BTreeMap::new();
                o.insert(
                    "src".to_string(),
                    Value::Str(ip.header().source_addr().to_string()),
                );
                o.insert(
                    "dst".to_string(),
                    Value::Str(ip.header().destination_addr().to_string()),
                );
                o.insert("ttl".to_string(), Value::Int(i64::from(ip.header().ttl())));
                obj.insert("ipv4".to_string(), Value::Object(o));
            }
            Some(NetSlice::Ipv6(ip)) => {
                let mut o = BTreeMap::new();
                o.insert(
                    "src".to_string(),
                    Value::Str(ip.header().source_addr().to_string()),
                );
                o.insert(
                    "dst".to_string(),
                    Value::Str(ip.header().destination_addr().to_string()),
                );
                obj.insert("ipv6".to_string(), Value::Object(o));
            }
            _ => {}
        }
        match parsed.transport {
            Some(TransportSlice::Tcp(t)) => {
                let mut o = BTreeMap::new();
                o.insert("sport".to_string(), Value::Int(i64::from(t.source_port())));
                o.insert(
                    "dport".to_string(),
                    Value::Int(i64::from(t.destination_port())),
                );
                o.insert("flags".to_string(), Value::Str(tcp_flag_letters(&t)));
                o.insert(
                    "seq".to_string(),
                    Value::Int(i64::from(t.sequence_number())),
                );
                o.insert(
                    "ack".to_string(),
                    Value::Int(i64::from(t.acknowledgment_number())),
                );
                o.insert("window".to_string(), Value::Int(i64::from(t.window_size())));
                obj.insert("tcp".to_string(), Value::Object(o));
            }
            Some(TransportSlice::Udp(u)) => {
                let mut o = BTreeMap::new();
                o.insert("sport".to_string(), Value::Int(i64::from(u.source_port())));
                o.insert(
                    "dport".to_string(),
                    Value::Int(i64::from(u.destination_port())),
                );
                obj.insert("udp".to_string(), Value::Object(o));
            }
            _ => {}
        }
    }
    Value::Object(obj)
}

/// A TCP slice's flags as a scapy letter string (SYN-ACK ⇒ `"SA"`).
fn tcp_flag_letters(t: &etherparse::TcpSlice<'_>) -> String {
    let mut s = String::new();
    if t.fin() {
        s.push('F');
    }
    if t.syn() {
        s.push('S');
    }
    if t.rst() {
        s.push('R');
    }
    if t.psh() {
        s.push('P');
    }
    if t.ack() {
        s.push('A');
    }
    if t.urg() {
        s.push('U');
    }
    if t.ece() {
        s.push('E');
    }
    if t.cwr() {
        s.push('C');
    }
    s
}

// ===========================================================================
// arg / value helpers
// ===========================================================================

/// Expand a whole-string `{{name}}` placeholder from `vars`; any other input is
/// returned verbatim (mirrors the test namespace's minimal expander).
fn expand(input: &str, vars: &BTreeMap<String, Value>) -> String {
    let trimmed = input.trim();
    if let Some(name) = trimmed
        .strip_prefix("{{")
        .and_then(|s| s.strip_suffix("}}"))
    {
        if let Some(Value::Str(s)) = vars.get(name.trim()) {
            return s.clone();
        }
    }
    input.to_string()
}

/// Parse a Rhai `spec` argument (the serde `PacketSpec` form, as `l4.craft`).
fn parse_spec_arg(arg: Option<&Value>) -> Result<PacketSpec, HostError> {
    let spec = arg.ok_or_else(|| HostError::BadArgs("missing `spec` argument".to_string()))?;
    crate::commands::parse_packet_spec(spec).map_err(bad)
}

fn object_arg(arg: Option<&Value>) -> Result<&BTreeMap<String, Value>, HostError> {
    match arg {
        Some(Value::Object(o)) => Ok(o),
        _ => Err(HostError::BadArgs(
            "expected an object argument".to_string(),
        )),
    }
}

fn str_arg(arg: Option<&Value>, name: &str) -> Result<String, HostError> {
    match arg {
        Some(Value::Str(s)) => Ok(s.clone()),
        _ => Err(HostError::BadArgs(format!(
            "missing string argument `{name}`"
        ))),
    }
}

fn ip_arg(arg: Option<&Value>, name: &str) -> Result<IpAddr, HostError> {
    str_arg(arg, name)?
        .parse()
        .map_err(|_| HostError::BadArgs(format!("argument `{name}` is not an IP address")))
}

fn value_as_u16(v: &Value) -> Option<u16> {
    match v {
        Value::Int(i) => u16::try_from(*i).ok(),
        _ => None,
    }
}

fn value_as_u32(v: &Value) -> Option<u32> {
    match v {
        Value::Int(i) => u32::try_from(*i).ok(),
        _ => None,
    }
}

fn value_as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Int(i) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// Map a crate [`L4Error`](crate::backend::L4Error) to a seam [`HostError`]: a
/// guard refusal stays a `GuardRefused`; anything else carries its message.
fn l4_err(e: crate::backend::L4Error) -> HostError {
    match e {
        crate::backend::L4Error::Guard(ge) => guard_err(ge),
        other => HostError::BadArgs(other.to_string()),
    }
}

/// Map a typed [`L4GuardError`] to a seam [`HostError::GuardRefused`].
fn guard_err(e: L4GuardError) -> HostError {
    HostError::GuardRefused {
        namespace: NAMESPACE.to_string(),
        reason: e.to_string(),
    }
}

/// Map an `anyhow` parse error to a seam [`HostError::BadArgs`].
fn bad(e: anyhow::Error) -> HostError {
    HostError::BadArgs(e.to_string())
}

// ===========================================================================
// catalog (static data; works without live state)
// ===========================================================================

/// The `l4.*` host-fn signatures for `rhai.api.json` — one entry per [`VERBS`]
/// verb, so the catalog, the Rhai namespace, and the `l4.*` command names are the
/// one shared vocabulary (AC8). The `l4:` step `op` enum is the [`WIRE_VERBS`]
/// subset of this set (a consistent subset, not a divergent vocabulary).
fn catalog_host_fns() -> Vec<HostFnSig> {
    let p = |name: &str, ty: &str, desc: &str| ParamSig {
        name: name.to_string(),
        ty: ty.to_string(),
        description: desc.to_string(),
    };
    vec![
        HostFnSig {
            name: "interfaces".to_string(),
            params: vec![],
            returns: "array".to_string(),
            description: "List the capture-capable network interfaces (read-only).".to_string(),
        },
        HostFnSig {
            name: "craft".to_string(),
            params: vec![p("spec", "object", "A scapy-style PacketSpec (layers).")],
            returns: "object".to_string(),
            description: "Build on-wire bytes from a PacketSpec (pure; no guard, no wire)."
                .to_string(),
        },
        HostFnSig {
            name: "scope.add".to_string(),
            params: vec![p(
                "entry",
                "object",
                "A scope entry: cidr, interface, direction, capability, ports?, inject_rate_pps?.",
            )],
            returns: "string".to_string(),
            description: "Add a runtime L4 scope entry (gated by the guard's widen capability)."
                .to_string(),
        },
        HostFnSig {
            name: "scope.remove".to_string(),
            params: vec![p("id", "string", "The scope entry id to remove.")],
            returns: "bool".to_string(),
            description: "Remove a runtime L4 scope entry by id.".to_string(),
        },
        HostFnSig {
            name: "scope.list".to_string(),
            params: vec![],
            returns: "array".to_string(),
            description: "List the current L4 scope entries (read-only).".to_string(),
        },
        HostFnSig {
            name: "flow.list".to_string(),
            params: vec![],
            returns: "array".to_string(),
            description: "List the ids of stored L4 flows (read-only).".to_string(),
        },
        HostFnSig {
            name: "flow.get".to_string(),
            params: vec![p("id", "string", "The L4 flow id to summarize.")],
            returns: "object".to_string(),
            description: "Summarize one stored L4 flow and its packets (read-only).".to_string(),
        },
        HostFnSig {
            name: "inject".to_string(),
            params: vec![
                p("spec", "object", "The stimulus PacketSpec (layers)."),
                p("dst", "string", "The destination IP the stimulus targets."),
                p("interface", "string", "The interface to inject on."),
                p("count", "int", "How many copies to send (default 1)."),
            ],
            returns: "object".to_string(),
            description: "Guarded wire write of a crafted packet (Inject capability).".to_string(),
        },
        HostFnSig {
            name: "send_recv".to_string(),
            params: vec![
                p("spec", "object", "The stimulus PacketSpec (layers)."),
                p(
                    "dst",
                    "string",
                    "The destination IP (and FiveTuple reply host).",
                ),
                p(
                    "interface",
                    "string",
                    "The interface to inject on and capture from.",
                ),
                p(
                    "port",
                    "int",
                    "The destination port, matched in correlation.",
                ),
                p(
                    "timeout_ms",
                    "int",
                    "How long to await the reply (default 1000).",
                ),
            ],
            returns: "object".to_string(),
            description: "Scapy sr1: inject a stimulus and return the correlated reply \
                          (Inject+Capture)."
                .to_string(),
        },
    ]
}

/// The `l4:` PoC step schema for `poc-yaml.schema.json`. Its `op` enum is the
/// [`WIRE_VERBS`] subset of the [`VERBS`] host-fn names — the one vocabulary's wire
/// verbs (AC8: the step `op` set is a *consistent subset* of the host-fn /
/// command vocabulary, never a divergent one) — and it contributes the
/// [`PACKET_SOURCE`] matcher/extractor source.
fn catalog_poc_step() -> PocStepSchema {
    PocStepSchema {
        step: NAMESPACE.to_string(),
        description: "Run a native L4 verb and assert on the received `packet` (scapy-style, \
                      human-readable). `op: send_recv` injects a stimulus and binds the reply as \
                      the `packet` source (e.g. `field: tcp.flags`)."
            .to_string(),
        enums: BTreeMap::from([(
            "op".to_string(),
            WIRE_VERBS.iter().map(|v| (*v).to_string()).collect(),
        )]),
        sources: vec![PACKET_SOURCE.to_string()],
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn layer(src: &str) -> serde_yaml::Value {
        serde_yaml::from_str(src).expect("the test layer YAML parses")
    }

    /// The `src_port`/`dst_port` aliases are live (not dead code): a layer using
    /// the alias form sets the port, exactly as the scapy `sport`/`dport` form does.
    #[test]
    fn tcp_port_aliases_are_live() {
        let vars = BTreeMap::new();
        match parse_layer(&layer("tcp: { src_port: 1234, dst_port: 80 }"), &vars)
            .expect("the aliased tcp layer parses")
        {
            Layer::Tcp(spec) => {
                assert_eq!(spec.src_port, Some(1234));
                assert_eq!(spec.dst_port, Some(80));
            }
            other => panic!("expected a TCP layer, got {other:?}"),
        }
    }

    /// An out-of-range port is **rejected**, not silently left unset — the `?`
    /// range error is propagated rather than swallowed by `Result::or`.
    #[test]
    fn tcp_out_of_range_port_is_rejected() {
        let vars = BTreeMap::new();
        let err = parse_layer(&layer("tcp: { sport: 99999 }"), &vars)
            .expect_err("a port above 65535 is rejected");
        assert!(
            err.to_string().contains("out of range"),
            "the range error must surface, got: {err}"
        );
    }

    /// The UDP alias is live too (the same helper governs both transports).
    #[test]
    fn udp_port_alias_is_live() {
        let vars = BTreeMap::new();
        match parse_layer(&layer("udp: { dst_port: 53 }"), &vars)
            .expect("the aliased udp layer parses")
        {
            Layer::Udp(spec) => assert_eq!(spec.dst_port, Some(53)),
            other => panic!("expected a UDP layer, got {other:?}"),
        }
    }

    /// The `l4:` step `op` enum is the wire subset of the shared host-fn
    /// vocabulary — every op is a real verb, and it is exactly the three wire verbs.
    #[test]
    fn poc_step_op_enum_is_the_wire_subset() {
        let step = catalog_poc_step();
        let ops = step.enums.get("op").expect("the l4: step has an op enum");
        assert_eq!(ops, &vec!["craft", "inject", "send_recv"]);
        let verbs: BTreeSet<&str> = VERBS.iter().map(|(v, _)| *v).collect();
        for op in ops {
            assert!(
                verbs.contains(op.as_str()),
                "the step op `{op}` must be a real host-fn verb"
            );
        }
    }
}
