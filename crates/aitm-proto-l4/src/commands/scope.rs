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

use crate::guard::L4Guard;
use crate::types::{L4ScopeEntry, L4ScopeId, L4ScopeSource, RateCap};

/// `l4.scope.add {..}` → add a scope entry; returns its minted id.
pub struct ScopeAdd {
    guard: Arc<L4Guard>,
}

impl ScopeAdd {
    /// A command over the shared guard. The SEC-2 widen gate (reading the shared
    /// [`L4AgentGates`](crate::gates::L4AgentGates) **widen** gate, so
    /// `l4.agent.set {capability:"widen"}` governs it live) and the forced
    /// `source = Runtime` both live in [`L4Guard::add_runtime_scope`], so the command
    /// is a thin wrapper and carries no gate of its own.
    pub fn new(guard: Arc<L4Guard>) -> Self {
        Self { guard }
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
        // Deny-by-default widening is enforced in the guard: `add_runtime_scope`
        // refuses with the typed `L4GuardError::ScopeWideningDisabled` (adding nothing)
        // when the shared **widen** gate is off, and forces `source = Runtime`. Keeping
        // the gate in the guard (not this command) is SEC-2: no second in-process
        // caller of the shared guard can bypass it, and an operator `l4.agent.set`
        // flips the very gate the guard reads.
        let entry = entry_from_params(&args)?;
        let id = self
            .guard
            .add_runtime_scope(entry)
            .map_err(anyhow::Error::new)?;
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
        // Provenance is set here for completeness, but `L4Guard::add_runtime_scope`
        // re-forces `source = Runtime` at the boundary — a runtime add can never mint
        // operator (`Config`) provenance and so can never lift the denylist.
        source: L4ScopeSource::Runtime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::L4Config;
    use crate::types::{IpCidr, L4Capability, L4Direction, PortRange};

    struct StubClient;
    impl aitm_core::ProxyClient for StubClient {
        fn send(
            &self,
            _req: aitm_core::HttpRequest,
        ) -> futures::future::BoxFuture<'_, anyhow::Result<aitm_core::HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    fn entry(ports: PortRange, source: L4ScopeSource) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().expect("literal v4 address"),
                prefix: 32,
            },
            ports,
            interface: "lo0".to_string(),
            direction: L4Direction::Inbound,
            capability: L4Capability::Capture,
            inject_rate: RateCap { pps: 0, burst: 0 },
            source,
        }
    }

    /// Plan Task A5 (L4PAR-AC5, the `source` half): `l4.scope.list` labels each
    /// entry's provenance — `"config"` for an operator config-block entry, `"runtime"`
    /// for one added over the bus — in list order, so UIs can label them.
    #[test]
    fn scope_list_reports_source() {
        let cfg = L4Config {
            scope: vec![entry(
                PortRange { lo: 9000, hi: 9999 },
                L4ScopeSource::Config,
            )],
            ..L4Config::default()
        };
        let guard = Arc::new(L4Guard::new(&cfg));
        // Test-only push (no widen gate): the provenance is whatever the entry says.
        guard
            .add_scope(entry(
                PortRange { lo: 9100, hi: 9199 },
                L4ScopeSource::Runtime,
            ))
            .expect("test-only add_scope never refuses");

        let mem = aitm_core::MemFlowStore::new();
        let client = StubClient;
        let core = aitm_core::StdGuard::default();
        let host = CommandHost::new(&mem, &client, &core, None);

        let listed = ScopeList::new(guard)
            .invoke(Params::default(), &host)
            .expect("l4.scope.list ok");
        let Value::Array(entries) = listed else {
            panic!("l4.scope.list must return an array, got {listed:?}");
        };
        assert_eq!(entries.len(), 2);

        let field = |i: usize, key: &str| -> Option<Value> {
            let Value::Object(obj) = &entries[i] else {
                panic!("a scope entry must be an object, got {:?}", entries[i]);
            };
            obj.get(key).cloned()
        };
        assert_eq!(field(0, "ports"), Some(Value::Str("9000-9999".into())));
        assert_eq!(field(0, "source"), Some(Value::Str("config".into())));
        assert_eq!(field(1, "ports"), Some(Value::Str("9100-9199".into())));
        assert_eq!(field(1, "source"), Some(Value::Str("runtime".into())));
    }

    /// The `l4.scope.list` result schema declares `source` as a required string, so
    /// `tools/list` consumers learn the field without reading a live entry.
    #[test]
    fn scope_list_schema_declares_source() {
        let cfg = L4Config::default();
        let schema = ScopeList::new(Arc::new(L4Guard::new(&cfg))).schema();
        let TypeDesc::Array(elem) = schema.result else {
            panic!(
                "l4.scope.list result must be an array, got {:?}",
                schema.result
            );
        };
        let TypeDesc::Object(fields) = *elem else {
            panic!("l4.scope.list elements must be objects, got {elem:?}");
        };
        let source = fields
            .iter()
            .find(|f| f.name == "source")
            .unwrap_or_else(|| {
                panic!(
                    "scope entry fields must list `source`; got {:?}",
                    fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>()
                )
            });
        assert!(
            matches!(source.ty, TypeDesc::Str),
            "`source` must be a Str, got {:?}",
            source.ty
        );
        assert!(source.required, "`source` must be required");
        assert!(
            source.description.contains("config") && source.description.contains("runtime"),
            "the description names both provenances, got {}",
            source.description
        );
    }
}
