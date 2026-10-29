//! `l4.scope.add` / `.remove` / `.list` — manage the deny-by-default L4 scope.
//!
//! Sensitivity: **manages scope**. These commands do not touch the wire; they edit
//! the [`L4Guard`](crate::guard::L4Guard) scope list the wire commands (M5 Task 10)
//! later check against. `scope.add` is the single explicit escape hatch that brings
//! a CIDR + port + interface + direction + capability into play (deny-by-default);
//! `scope.remove` reverts a target to denied. No injection is authorized here — no
//! [`L4Permit`](crate::guard::L4Permit) is minted.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::commands::agent::{AgentGate, L4AgentGates};
use crate::guard::{L4Guard, L4GuardError};
use crate::types::{L4ScopeEntry, L4ScopeId, L4ScopeSource, RateCap};

/// `l4.scope.add {..}` → add a scope entry; returns its minted id.
pub struct ScopeAdd {
    guard: Arc<L4Guard>,
    /// The shared per-capability agent gates; `scope.add` reads the **widen** gate.
    /// Mirrors `ca.allow_agent_install`: **false** by default, so the one escape
    /// hatch out of deny-by-default stays with the operator's config. The gate now
    /// lives in the shared [`L4AgentGates`] (seeded from `L4Config::allow_agent_widen`)
    /// so the operator's `l4.agent.set {capability:"widen"}` governs it live. Unlike
    /// the wire verbs, widening is refused for **every** runtime bus caller when the
    /// gate is off (the operator declares scope in config), not just the agent.
    gates: Arc<L4AgentGates>,
}

impl ScopeAdd {
    /// A command over the shared guard + agent gates.
    pub fn new(guard: Arc<L4Guard>, gates: Arc<L4AgentGates>) -> Self {
        Self { guard, gates }
    }
}

impl Command for ScopeAdd {
    fn name(&self) -> &str {
        "l4.scope.add"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Widens L4 authority (the one escape hatch out of deny-by-default) — gated
        // like `scope.add` / `ca.install`.
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add an entry to the deny-by-default L4 scope (CIDR, ports, interface, \
                          direction, capability, injection rate). The single escape hatch that \
                          brings a target into play."
                .into(),
            params: vec![
                ParamDef {
                    name: "cidr".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`addr/prefix` (e.g. `127.0.0.1/32`); a bare address ⇒ host."
                        .into(),
                },
                ParamDef {
                    name: "interface".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The interface this entry covers (e.g. `lo0`).".into(),
                },
                ParamDef {
                    name: "direction".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`inbound` or `outbound`.".into(),
                },
                ParamDef {
                    name: "capability".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`capture`, `inject`, or `intercept`.".into(),
                },
                ParamDef {
                    name: "ports".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "`lo-hi`, a single port, or `*`/omitted ⇒ any.".into(),
                },
                ParamDef {
                    name: "inject_rate_pps".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Per-entry injection rate (packets/sec); 0 ⇒ refuse. Default 0."
                        .into(),
                },
                ParamDef {
                    name: "inject_rate_burst".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: "Per-entry injection burst; default = `inject_rate_pps`.".into(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        // Deny-by-default: runtime bus widening is gated by the shared **widen** gate.
        // When it is off, refuse with the typed [`L4GuardError::ScopeWideningDisabled`]
        // and add nothing — the operator declares scope in the `l4.scope` config block
        // or opens the gate with `l4.agent.set`. Widening is the one escape hatch out
        // of deny-by-default, so it is refused for every runtime caller when off (not
        // operator-bypassed like the wire verbs, which are confirmed instead).
        if !self.gates.allowed(AgentGate::Widen) {
            return Err(anyhow::Error::new(L4GuardError::ScopeWideningDisabled));
        }
        let entry = entry_from_params(&args)?;
        let id = self
            .guard
            .add_scope(entry)
            .map_err(|e| anyhow::anyhow!("scope add refused: {e}"))?;
        Ok(Value::Str(super::scope_id_to_string(id)))
    }
}

/// `l4.scope.remove {id}` → remove the entry with that id; returns whether one was.
pub struct ScopeRemove {
    guard: Arc<L4Guard>,
}

impl ScopeRemove {
    /// A command over the shared guard.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
    }
}

impl Command for ScopeRemove {
    fn name(&self) -> &str {
        "l4.scope.remove"
    }

    fn sensitivity(&self) -> Sensitivity {
        // Narrows authority: mutating, but safe-ward (never touches the wire).
        Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove an L4 scope entry by id (reverts that target to deny-by-default)."
                .into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The scope entry id to remove.".into(),
            }],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let id = super::scope_id_from_str(args.get_str("id")?)?;
        Ok(Value::Bool(self.guard.remove_scope(id)))
    }
}

/// `l4.scope.list` → the current scope entries.
pub struct ScopeList {
    guard: Arc<L4Guard>,
}

impl ScopeList {
    /// A command over the shared guard.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
    }
}

impl Command for ScopeList {
    fn name(&self) -> &str {
        "l4.scope.list"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the current L4 scope entries (read-only).".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(super::scope_entry_fields()))),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            self.guard
                .list_scope()
                .iter()
                .map(super::scope_entry_to_value)
                .collect(),
        ))
    }
}

/// Build a scope entry from the flattened, human-friendly `scope.add` params.
fn entry_from_params(args: &Params) -> anyhow::Result<L4ScopeEntry> {
    let cidr = super::parse_cidr(args.get_str("cidr")?)?;
    let interface = args.get_str("interface")?.to_string();
    let direction = super::parse_direction(args.get_str("direction")?)?;
    let capability = super::parse_capability(args.get_str("capability")?)?;
    let ports = match args.get("ports") {
        Some(Value::Str(s)) => super::parse_ports(s)?,
        Some(other) => anyhow::bail!("param `ports` must be a string, got {other:?}"),
        None => super::parse_ports("")?,
    };
    let pps = match args.get("inject_rate_pps") {
        Some(_) => u32::try_from(args.get_int("inject_rate_pps")?)
            .map_err(|_| anyhow::anyhow!("`inject_rate_pps` must be a non-negative integer"))?,
        None => 0,
    };
    let burst = match args.get("inject_rate_burst") {
        Some(_) => u32::try_from(args.get_int("inject_rate_burst")?)
            .map_err(|_| anyhow::anyhow!("`inject_rate_burst` must be a non-negative integer"))?,
        None => pps,
    };
    Ok(L4ScopeEntry {
        id: L4ScopeId::new(),
        cidr,
        ports,
        interface,
        direction,
        capability,
        inject_rate: RateCap { pps, burst },
        // Runtime bus adds are never operator-authorized: they cannot lift the
        // dangerous-destination denylist (guard.rs enforces this on `source`).
        source: L4ScopeSource::Runtime,
    })
}
