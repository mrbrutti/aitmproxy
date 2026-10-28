//! The scope plugin: `scope.add`, `scope.remove`, and `scope.list` over the
//! guard's scope set.
//!
//! Scope is deny-by-default (enforced by the guard); `scope.add` is the single,
//! explicit escape hatch that brings a host into play for active actions. Because
//! adding a host is an authorisation decision, `scope.add` is refused from an
//! agent frontend (MCP) unless the operator set `scope.allow_agent_widen` — the
//! same posture as `ca.allow_agent_install`. `scope.remove` only narrows scope,
//! so it is never gated.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry, ScopeEntry,
    TypeDesc, Value,
};

/// Registers `scope.add`, `scope.remove`, and `scope.list`. Observes no events.
pub struct ScopePlugin {
    allow_agent_widen: bool,
}

impl ScopePlugin {
    /// `allow_agent_widen` lets an MCP (agent) frontend call `scope.add`; off by
    /// default the human CLI is the only frontend that may widen scope.
    pub fn new(allow_agent_widen: bool) -> Self {
        Self { allow_agent_widen }
    }
}

impl Default for ScopePlugin {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Plugin for ScopePlugin {
    fn name(&self) -> &str {
        "scope"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(ScopeAdd {
            allow_agent_widen: self.allow_agent_widen,
        }));
        reg.add_command(Arc::new(ScopeRemove));
        reg.add_command(Arc::new(ScopeList));
    }
}

fn host_param(description: &str) -> ParamDef {
    ParamDef {
        name: "host".into(),
        ty: TypeDesc::Str,
        required: true,
        description: description.into(),
    }
}

/// `scope.add {host}` → add a host (or `host:port`, or `*.wildcard`) to scope.
struct ScopeAdd {
    allow_agent_widen: bool,
}

impl Command for ScopeAdd {
    fn name(&self) -> &str {
        "scope.add"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add a host, host:port, or *.wildcard to the active scope. Refused from \
                          an agent frontend (MCP) unless scope.allow_agent_widen is set."
                .into(),
            params: vec![host_param("The scope entry to add.")],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Widening scope is a human authorisation decision: refuse it from a
        // non-CLI frontend unless the operator opted in (mirrors ca.install).
        if host.frontend() != Frontend::Cli && !self.allow_agent_widen {
            anyhow::bail!(
                "scope.add refused: widening scope from an agent frontend is disabled. Set \
                 scope.allow_agent_widen = true in the aitmproxy config to allow it, or add the \
                 host from the human CLI."
            );
        }
        let entry = args.get_str("host")?.to_string();
        host.guard().add_scope(ScopeEntry {
            host: entry.clone(),
        });
        Ok(Value::Str(entry))
    }
}

/// `scope.remove {host}` → remove a scope entry; returns whether one was removed.
struct ScopeRemove;

impl Command for ScopeRemove {
    fn name(&self) -> &str {
        "scope.remove"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove a scope entry (exact match). Narrowing scope is allowed from any \
                          frontend; returns true if an entry was removed."
                .into(),
            params: vec![host_param("The scope entry to remove (exact match).")],
            result: TypeDesc::Bool,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let entry = args.get_str("host")?;
        Ok(Value::Bool(host.guard().remove_scope(entry)))
    }
}

/// `scope.list` → the current scope entries, in order.
struct ScopeList;

impl Command for ScopeList {
    fn name(&self) -> &str {
        "scope.list"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the current scope entries.".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::Str)),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            host.guard()
                .list_scope()
                .into_iter()
                .map(|e| Value::Str(e.host))
                .collect(),
        ))
    }
}
