//! The `l4.*` command surface (M5 Task 9 — the active, no-wire commands).
//!
//! Every deterministic L4 capability is a registered [`Command`] with a
//! [`ParamSchema`], so MCP (`tools/list` / `tools/call`), the `aitm` CLI, and the
//! M3 Rhai tier all reach it through the one command bus (AC18). This task lands
//! the commands that **never touch the wire** — their sensitivity, matching the
//! spec's command-surface table, is one of:
//!
//! - **read-only:** `l4.interfaces`, `l4.flow.list`, `l4.flow.get`.
//! - **manages scope:** `l4.scope.add`, `l4.scope.remove`, `l4.scope.list` — the
//!   deny-by-default [`L4Guard`](crate::guard::L4Guard) scope the wire commands
//!   (M5 Task 10) later check against.
//! - **pure:** `l4.craft` — builds bytes from a [`PacketSpec`](crate::craft::PacketSpec),
//!   no privilege, no guard, no wire.
//!
//! The wire-touching commands (`l4.capture.*`, `l4.inject`, `l4.send_recv`,
//! `l4.intercept.*`) are **not** here: they compose [`L4Guard::check`] with the
//! core [`ScopeRateGuard::check_active`] at this same command layer in M5 Tasks 10
//! and 12. This module deliberately mints no [`L4Permit`].
//!
//! [`Command`]: aitm_core::Command
//! [`ParamSchema`]: aitm_core::ParamSchema
//! [`L4Guard::check`]: crate::guard::L4Guard::check
//! [`L4Permit`]: crate::guard::L4Permit
//! [`ScopeRateGuard::check_active`]: aitm_core::ScopeRateGuard::check_active

pub mod craft;
pub mod flow;
pub mod intercept;
pub mod scope;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use aitm_core::{Command, CommandHost, ParamSchema, Params, TypeDesc, Value};

use crate::flow::L4FlowId;
use crate::types::{IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, PortRange};

pub use craft::Craft;
pub use flow::{FlowGet, FlowList};
pub use scope::{ScopeAdd, ScopeList, ScopeRemove};

/// `l4.interfaces` → list the capture-capable interfaces libpcap can see.
///
/// Sensitivity: **read-only**. It enumerates local interfaces (no raw socket, no
/// wire, no guard). Fail-closed: when libpcap cannot enumerate (absent / no
/// privilege) it reports an empty list rather than erroring, so a disabled or
/// unprivileged host degrades honestly instead of panicking.
pub struct L4Interfaces;

impl Command for L4Interfaces {
    fn name(&self) -> &str {
        "l4.interfaces"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the capture-capable network interfaces (read-only).".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(interface_fields()))),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        // Fail-closed: an enumeration failure (libpcap absent / no privilege to
        // list) degrades to "no interfaces visible", never a panic or error.
        let devices = ::pcap::Device::list().unwrap_or_default();
        let out = devices
            .into_iter()
            .map(|d| {
                let mut o = BTreeMap::new();
                o.insert("name".to_string(), Value::Str(d.name));
                if let Some(desc) = d.desc {
                    o.insert("description".to_string(), Value::Str(desc));
                }
                Value::Object(o)
            })
            .collect();
        Ok(Value::Array(out))
    }
}

/// The fields one `l4.interfaces` entry reports.
fn interface_fields() -> Vec<aitm_core::ParamDef> {
    vec![
        aitm_core::ParamDef {
            name: "name".into(),
            ty: TypeDesc::Str,
            required: true,
            description: "The interface name (e.g. `lo0`, `eth0`).".into(),
        },
        aitm_core::ParamDef {
            name: "description".into(),
            ty: TypeDesc::Str,
            required: false,
            description: "A human-readable description, when the OS supplies one.".into(),
        },
    ]
}

// ---- shared helpers for the command layer -------------------------------------

/// A transport-neutral [`Value`] as a `serde_json::Value`, so a structured craft
/// spec / scope entry can be deserialized into its serde-derived Rust type.
///
/// Unlike the MCP layer's encoder, `Bytes` becomes a JSON **array of numbers**
/// (not base64): a craft `Raw(Vec<u8>)` layer deserializes from that array, so a
/// caller may pass raw payload bytes as either an array or a `Bytes` value.
fn value_to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => J::Number((*i).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(J::Null, J::Number),
        Value::Str(s) => J::String(s.clone()),
        Value::Bytes(b) => J::Array(b.iter().map(|byte| J::Number((*byte).into())).collect()),
        Value::Array(items) => J::Array(items.iter().map(value_to_json).collect()),
        Value::Object(fields) => J::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
    }
}

/// A uuid-backed scope id as the string it carries on the bus (via its serde
/// derive — the newtype serializes as its inner uuid string).
pub(crate) fn scope_id_to_string(id: L4ScopeId) -> String {
    match serde_json::to_value(id) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Parse a bus string back into a scope id (the inverse of [`scope_id_to_string`]).
fn scope_id_from_str(s: &str) -> anyhow::Result<L4ScopeId> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("not a valid scope id `{s}`: {e}"))
}

/// A uuid-backed flow id as the string it carries on the bus.
pub(crate) fn flow_id_to_string(id: L4FlowId) -> String {
    match serde_json::to_value(id) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Parse a bus string into an L4 flow id.
fn flow_id_from_str(s: &str) -> anyhow::Result<L4FlowId> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|e| anyhow::anyhow!("not a valid L4 flow id `{s}`: {e}"))
}

/// Parse a human-friendly `addr/prefix` CIDR (e.g. `127.0.0.1/32`, `10.0.0.0/8`,
/// `::1/128`). A bare address defaults to a host prefix (`/32` v4, `/128` v6).
fn parse_cidr(s: &str) -> anyhow::Result<IpCidr> {
    let (addr_str, prefix_str) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr_str
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("bad CIDR address `{addr_str}`: {e}"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_str {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .map_err(|e| anyhow::anyhow!("bad CIDR prefix `{p}`: {e}"))?,
        None => max,
    };
    if prefix > max {
        anyhow::bail!("CIDR prefix /{prefix} exceeds /{max} for this address family");
    }
    Ok(IpCidr { addr, prefix })
}

/// `addr/prefix` for display / round-trip.
fn cidr_to_string(cidr: &IpCidr) -> String {
    format!("{}/{}", cidr.addr, cidr.prefix)
}

/// Parse a direction string (`inbound` / `outbound`).
fn parse_direction(s: &str) -> anyhow::Result<L4Direction> {
    match s.trim().to_ascii_lowercase().as_str() {
        "inbound" => Ok(L4Direction::Inbound),
        "outbound" => Ok(L4Direction::Outbound),
        other => anyhow::bail!("unknown direction `{other}` (want `inbound` or `outbound`)"),
    }
}

/// A direction as its bus string.
fn direction_to_string(dir: L4Direction) -> &'static str {
    match dir {
        L4Direction::Inbound => "inbound",
        L4Direction::Outbound => "outbound",
    }
}

/// Parse a capability string (`capture` / `inject` / `intercept`).
fn parse_capability(s: &str) -> anyhow::Result<L4Capability> {
    match s.trim().to_ascii_lowercase().as_str() {
        "capture" => Ok(L4Capability::Capture),
        "inject" => Ok(L4Capability::Inject),
        "intercept" => Ok(L4Capability::Intercept),
        other => {
            anyhow::bail!("unknown capability `{other}` (want `capture`, `inject`, or `intercept`)")
        }
    }
}

/// A capability as its bus string.
fn capability_to_string(cap: L4Capability) -> &'static str {
    match cap {
        L4Capability::Capture => "capture",
        L4Capability::Inject => "inject",
        L4Capability::Intercept => "intercept",
    }
}

/// Parse a port range: `lo-hi`, a single `port`, or `*` / empty ⇒ any (`0-65535`).
fn parse_ports(s: &str) -> anyhow::Result<PortRange> {
    let s = s.trim();
    if s.is_empty() || s == "*" || s.eq_ignore_ascii_case("any") {
        return Ok(PortRange { lo: 0, hi: 65535 });
    }
    if let Some((lo, hi)) = s.split_once('-') {
        let lo = lo
            .trim()
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("bad low port `{lo}`: {e}"))?;
        let hi = hi
            .trim()
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("bad high port `{hi}`: {e}"))?;
        if lo > hi {
            anyhow::bail!("port range low {lo} exceeds high {hi}");
        }
        Ok(PortRange { lo, hi })
    } else {
        let p = s
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("bad port `{s}`: {e}"))?;
        Ok(PortRange { lo: p, hi: p })
    }
}

/// `lo-hi` for display / round-trip.
fn ports_to_string(ports: &PortRange) -> String {
    format!("{}-{}", ports.lo, ports.hi)
}

/// A scope entry as a transport-neutral object for `l4.scope.list`.
fn scope_entry_to_value(entry: &L4ScopeEntry) -> Value {
    let mut rate = BTreeMap::new();
    rate.insert(
        "pps".to_string(),
        Value::Int(i64::from(entry.inject_rate.pps)),
    );
    rate.insert(
        "burst".to_string(),
        Value::Int(i64::from(entry.inject_rate.burst)),
    );

    let mut obj = BTreeMap::new();
    obj.insert("id".to_string(), Value::Str(scope_id_to_string(entry.id)));
    obj.insert("cidr".to_string(), Value::Str(cidr_to_string(&entry.cidr)));
    obj.insert(
        "ports".to_string(),
        Value::Str(ports_to_string(&entry.ports)),
    );
    obj.insert("interface".to_string(), Value::Str(entry.interface.clone()));
    obj.insert(
        "direction".to_string(),
        Value::Str(direction_to_string(entry.direction).to_string()),
    );
    obj.insert(
        "capability".to_string(),
        Value::Str(capability_to_string(entry.capability).to_string()),
    );
    obj.insert("inject_rate".to_string(), Value::Object(rate));
    Value::Object(obj)
}

/// The fields a scope entry reports — shared by the `scope.add` result and
/// `scope.list` elements.
fn scope_entry_fields() -> Vec<aitm_core::ParamDef> {
    let field = |name: &str, ty: TypeDesc, required: bool, description: &str| aitm_core::ParamDef {
        name: name.into(),
        ty,
        required,
        description: description.into(),
    };
    vec![
        field("id", TypeDesc::Str, true, "The scope entry's stable id."),
        field(
            "cidr",
            TypeDesc::Str,
            true,
            "The entry's CIDR (`addr/prefix`).",
        ),
        field("ports", TypeDesc::Str, true, "The port range (`lo-hi`)."),
        field("interface", TypeDesc::Str, true, "The bound interface."),
        field("direction", TypeDesc::Str, true, "`inbound` or `outbound`."),
        field(
            "capability",
            TypeDesc::Str,
            true,
            "`capture`, `inject`, or `intercept`.",
        ),
        field(
            "inject_rate",
            TypeDesc::Object(vec![
                field(
                    "pps",
                    TypeDesc::Int,
                    true,
                    "Packets per second (0 ⇒ refuse).",
                ),
                field("burst", TypeDesc::Int, true, "Burst allowance."),
            ]),
            true,
            "The per-entry injection ceiling.",
        ),
    ]
}

/// Build the full ordered list of Task 9 commands over the shared guard + store.
///
/// Returned as trait objects so [`crate::module::L4Module::load`] registers them
/// in one place; the wire commands (Tasks 10/12) extend this list later.
pub(crate) fn active_commands(
    guard: Arc<crate::guard::L4Guard>,
    store: Arc<dyn crate::flow::L4FlowStore>,
) -> Vec<Arc<dyn Command>> {
    vec![
        Arc::new(L4Interfaces),
        Arc::new(ScopeAdd::new(guard.clone())),
        Arc::new(ScopeRemove::new(guard.clone())),
        Arc::new(ScopeList::new(guard)),
        Arc::new(FlowList::new(store.clone())),
        Arc::new(FlowGet::new(store)),
        Arc::new(Craft),
    ]
}

/// A missing required value-typed argument (for params typed `Any`, which
/// [`Params`] has no dedicated getter for). Used by the sibling command modules.
fn require<'a>(args: &'a Params, name: &str) -> anyhow::Result<&'a Value> {
    args.get(name)
        .ok_or_else(|| anyhow::anyhow!("missing required param `{name}`"))
}
