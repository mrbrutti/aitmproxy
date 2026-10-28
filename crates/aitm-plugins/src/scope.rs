//! The scope plugin: `scope.add` and `scope.list` over the guard's scope set.
//!
//! Scope is deny-by-default (enforced by the guard); `scope.add` is the single,
//! explicit escape hatch that brings a host into play for active actions.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Plugin, Registry, ScopeEntry, TypeDesc,
    Value,
};

/// Registers `scope.add` and `scope.list`. Observes no events.
pub struct ScopePlugin;

impl ScopePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ScopePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for ScopePlugin {
    fn name(&self) -> &str {
        "scope"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(ScopeAdd));
        reg.add_command(Arc::new(ScopeList));
    }
}

/// `scope.add {host}` → add a host (or `host:port`, or `*.wildcard`) to scope.
struct ScopeAdd;

impl Command for ScopeAdd {
    fn name(&self) -> &str {
        "scope.add"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add a host, host:port, or *.wildcard to the active scope.".into(),
            params: vec![ParamDef {
                name: "host".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "The scope entry to add.".into(),
            }],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let entry = args.get_str("host")?.to_string();
        host.guard().add_scope(ScopeEntry {
            host: entry.clone(),
        });
        Ok(Value::Str(entry))
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
