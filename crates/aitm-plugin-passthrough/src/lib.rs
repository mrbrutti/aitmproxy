//! `aitm-plugin-passthrough`: the shared TLS-passthrough host list and the
//! `tls.passthrough.*` command family (`list`/`add`/`remove`).
//!
//! Passthrough is "do not decrypt this host's TLS" — it only ever *reduces* what
//! the proxy sees, which is safe for the operator but lets an agent *hide*
//! traffic. So list mutation (`add`/`remove`) is refused from a non-CLI frontend
//! unless the operator set `allow_agent_passthrough`, mirroring
//! `scope.allow_agent_widen`. Reading the list (`list`) is never gated.
//!
//! The `PassthroughList` is `Arc`-shared: this plugin mutates it and the
//! `PassthroughModule` (Task 11) reads it — both hold clones of one `Arc`.

mod list;
mod module;

pub use list::PassthroughList;
pub use module::PassthroughModule;

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc,
    Value,
};

/// Owns the shared passthrough list and registers the `tls.passthrough.*`
/// commands over it. The agent gate (`allow_agent_passthrough`) defaults off.
pub struct PassthroughPlugin {
    list: PassthroughList,
    allow_agent_passthrough: bool,
}

impl PassthroughPlugin {
    /// Seed the list from config and set the agent-mutation gate.
    pub fn new(seed: Vec<String>, allow_agent_passthrough: bool) -> Self {
        Self {
            list: PassthroughList::new(seed),
            allow_agent_passthrough,
        }
    }

    /// A handle to the shared list for the `PassthroughModule` (Task 11).
    pub fn list_handle(&self) -> PassthroughList {
        self.list.clone()
    }
}

impl Plugin for PassthroughPlugin {
    fn name(&self) -> &str {
        "passthrough"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(PassthroughListCmd {
            list: self.list.clone(),
        }));
        reg.add_command(Arc::new(PassthroughAdd {
            list: self.list.clone(),
            allow_agent_passthrough: self.allow_agent_passthrough,
        }));
        reg.add_command(Arc::new(PassthroughRemove {
            list: self.list.clone(),
            allow_agent_passthrough: self.allow_agent_passthrough,
        }));
    }
}

/// `{host}` parameter shared by `add`/`remove`.
fn host_param(description: &str) -> ParamDef {
    ParamDef {
        name: "host".into(),
        ty: TypeDesc::Str,
        required: true,
        description: description.into(),
    }
}

/// The `{hosts: [Str]}` result shape every `tls.passthrough.*` command returns.
fn hosts_result() -> TypeDesc {
    TypeDesc::Object(vec![ParamDef {
        name: "hosts".into(),
        ty: TypeDesc::Array(Box::new(TypeDesc::Str)),
        required: true,
        description: "The current passthrough entries, in insertion order.".into(),
    }])
}

/// Build a `{hosts: [...]}` value from the current list.
fn hosts_value(list: &PassthroughList) -> Value {
    Value::Object(
        [(
            "hosts".to_string(),
            Value::Array(list.hosts().into_iter().map(Value::Str).collect()),
        )]
        .into_iter()
        .collect(),
    )
}

/// Refuse list mutation from a non-CLI frontend unless the operator opted in
/// (mirrors `scope.add`'s posture and message shape).
fn gate_mutation(
    cmd: &str,
    host: &CommandHost,
    allow_agent_passthrough: bool,
) -> anyhow::Result<()> {
    if host.frontend() != Frontend::Cli && !allow_agent_passthrough {
        anyhow::bail!(
            "{cmd} refused: changing the TLS passthrough list from an agent frontend is \
             disabled. Set tls.allow_agent_passthrough = true in the aitmproxy config to allow \
             it, or change the list from the human CLI."
        );
    }
    Ok(())
}

/// `tls.passthrough.list` → the current entries. Never gated (read-only).
struct PassthroughListCmd {
    list: PassthroughList,
}

impl Command for PassthroughListCmd {
    fn name(&self) -> &str {
        "tls.passthrough.list"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List the hosts whose TLS is tunnelled (not decrypted).".into(),
            params: vec![],
            result: hosts_result(),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(hosts_value(&self.list))
    }
}

/// `tls.passthrough.add {host}` → add a host (or `*.wildcard`) to the list.
/// Agent-gated by `allow_agent_passthrough`.
struct PassthroughAdd {
    list: PassthroughList,
    allow_agent_passthrough: bool,
}

impl Command for PassthroughAdd {
    fn name(&self) -> &str {
        "tls.passthrough.add"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Add a host or *.wildcard to the TLS passthrough list (tunnel, do not \
                          decrypt). Refused from an agent frontend (MCP) unless \
                          tls.allow_agent_passthrough is set."
                .into(),
            params: vec![host_param("The host or *.wildcard to tunnel.")],
            result: hosts_result(),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        gate_mutation(self.name(), host, self.allow_agent_passthrough)?;
        self.list.add(args.get_str("host")?.to_string());
        Ok(hosts_value(&self.list))
    }
}

/// `tls.passthrough.remove {host}` → drop an entry. Agent-gated: removing
/// passthrough forces a host back into MITM, a behaviour-changing edit.
struct PassthroughRemove {
    list: PassthroughList,
    allow_agent_passthrough: bool,
}

impl Command for PassthroughRemove {
    fn name(&self) -> &str {
        "tls.passthrough.remove"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Remove an entry from the TLS passthrough list. Refused from an agent \
                          frontend (MCP) unless tls.allow_agent_passthrough is set."
                .into(),
            params: vec![host_param("The passthrough entry to remove.")],
            result: hosts_result(),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        gate_mutation(self.name(), host, self.allow_agent_passthrough)?;
        self.list.remove(args.get_str("host")?);
        Ok(hosts_value(&self.list))
    }
}
