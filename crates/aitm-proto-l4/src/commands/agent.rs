//! The Mcp-only per-capability gate wrapper and the operator-only `l4.agent.*`
//! surface (Stage B). The gate *state* lives in [`crate::gates::L4AgentGates`], owned
//! by the guard; this module is the command-layer face of it.
//!
//! The M4 model governs an agent (`Frontend::Mcp`) L4 call on **two** independent
//! dimensions, both of which must pass:
//!
//! 1. **`AgentPolicy`** — enforced in the MCP server's `call_tool` gate against each
//!    command's [`Sensitivity`](aitm_core::Sensitivity). A `Sensitive` L4 verb is
//!    refused under `Auto`/`ReadOnly`/`Paused`, parked under `Ask`, and — under
//!    `All` — deferred to the command's own gate (the server's
//!    `defers_to_command_gate` lists the L4 Sensitive verbs).
//! 2. **The per-capability flag** — enforced *here*, in [`L4AgentGate`], a thin
//!    wrapper the module places around each gated wire verb. For an untrusted (agent)
//!    caller it refuses unless the matching gate is open; the operator and CLI roles
//!    bypass it (the wire verbs are confirmed over the wire instead). The **widen**
//!    gate for `l4.scope.add` is enforced in the guard
//!    ([`add_runtime_scope`](crate::guard::L4Guard::add_runtime_scope)), not here.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::gates::{AgentGate, L4AgentGates};

/// A per-capability agent gate wrapped around one Sensitive `l4.*` command (the
/// second M4 dimension). For an untrusted (agent) caller it refuses unless the matching
/// gate is open; the trusted-control roles (operator and CLI) bypass it. `name` / `schema` /
/// `sensitivity` / `confirm_prompt` delegate to the inner command, so the command
/// still appears and classifies honestly in `tools/list` and the operator confirm
/// handshake still runs.
pub(crate) struct L4AgentGate {
    inner: Arc<dyn Command>,
    gate: AgentGate,
    gates: Arc<L4AgentGates>,
}

impl L4AgentGate {
    pub(crate) fn new(inner: Arc<dyn Command>, gate: AgentGate, gates: Arc<L4AgentGates>) -> Self {
        Self { inner, gate, gates }
    }
}

impl Command for L4AgentGate {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn schema(&self) -> ParamSchema {
        self.inner.schema()
    }

    fn sensitivity(&self) -> Sensitivity {
        self.inner.sensitivity()
    }

    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        self.inner.confirm_prompt(args)
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Only an untrusted (agent) caller is flag-gated; the operator and CLI are
        // the control and author freely (the hardest verbs ask the operator for
        // confirm-over-the-wire instead).
        if !host.caller_is_trusted_control() && !self.gates.allowed(self.gate) {
            anyhow::bail!(
                "`{}` refused: agent access to the L4 `{}` capability is disabled. An operator can \
                 enable it with `l4.agent.set {{capability: \"{}\", allowed: true}}` (or the \
                 `l4.allow_agent_{}` config flag).",
                self.inner.name(),
                self.gate.label(),
                self.gate.label(),
                self.gate.label(),
            );
        }
        self.inner.invoke(args, host)
    }
}

// ---- l4.agent.status ----------------------------------------------------------

/// `l4.agent.status` → the four per-capability agent gate states (Read).
pub(crate) struct AgentStatus {
    gates: Arc<L4AgentGates>,
}

impl AgentStatus {
    pub(crate) fn new(gates: Arc<L4AgentGates>) -> Self {
        Self { gates }
    }
}

impl Command for AgentStatus {
    fn name(&self) -> &str {
        "l4.agent.status"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Report the four per-capability agent gate states (inject, capture, \
                          intercept, widen) that govern the agent (MCP) L4 path. Read-only."
                .into(),
            params: vec![],
            result: TypeDesc::Object(gate_fields()),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(gates_to_value(&self.gates))
    }
}

// ---- l4.agent.set -------------------------------------------------------------

/// `l4.agent.set {capability, allowed}` → open/close one agent gate (operator-only).
pub(crate) struct AgentSet {
    gates: Arc<L4AgentGates>,
}

impl AgentSet {
    pub(crate) fn new(gates: Arc<L4AgentGates>) -> Self {
        Self { gates }
    }
}

impl Command for AgentSet {
    fn name(&self) -> &str {
        "l4.agent.set"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Open or close one per-capability agent gate (capability: inject | \
                          capture | intercept | widen). The deliberate operator act that governs \
                          the agent L4 path — operator/CLI only; the agent can neither call it nor \
                          read-then-flip its own gates."
                .into(),
            params: vec![
                ParamDef {
                    name: "capability".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "`inject`, `capture`, `intercept`, or `widen`.".into(),
                },
                ParamDef {
                    name: "allowed".into(),
                    ty: TypeDesc::Bool,
                    required: true,
                    description: "`true` opens the gate to the agent; `false` closes it.".into(),
                },
            ],
            result: TypeDesc::Object(gate_fields()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Operator/CLI only. The policy gate refuses the agent for most policies, but
        // `All` would let a Sensitive call through — so the command self-gates too:
        // the agent can never flip its own gates (and `l4.agent.set` is deliberately
        // kept out of `defers_to_command_gate`, so `All` never defers it here).
        if !host.caller_is_trusted_control() {
            anyhow::bail!(
                "l4.agent.set refused: the agent cannot change its own L4 gates; only an operator \
                 or the human CLI may set them."
            );
        }
        let cap = args.get_str("capability")?;
        let gate = AgentGate::parse(cap).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown capability `{cap}`; expected inject | capture | intercept | widen"
            )
        })?;
        let allowed = match args.get("allowed") {
            Some(Value::Bool(b)) => *b,
            Some(other) => anyhow::bail!("param `allowed` must be a boolean, got {other:?}"),
            None => anyhow::bail!("missing required param `allowed`"),
        };
        self.gates.set(gate, allowed);
        Ok(gates_to_value(&self.gates))
    }
}

/// Build the operator-only `l4.agent.*` commands over the shared gates.
pub(crate) fn agent_commands(gates: Arc<L4AgentGates>) -> Vec<Arc<dyn Command>> {
    vec![
        Arc::new(AgentStatus::new(gates.clone())),
        Arc::new(AgentSet::new(gates)),
    ]
}

/// The four gate states as a transport-neutral object (`l4.agent.status` / `.set`).
fn gates_to_value(gates: &L4AgentGates) -> Value {
    let mut o = BTreeMap::new();
    for gate in AgentGate::all() {
        o.insert(gate.label().to_string(), Value::Bool(gates.allowed(gate)));
    }
    Value::Object(o)
}

/// The four gate fields `l4.agent.status` / `l4.agent.set` report.
fn gate_fields() -> Vec<ParamDef> {
    AgentGate::all()
        .into_iter()
        .map(|gate| ParamDef {
            name: gate.label().into(),
            ty: TypeDesc::Bool,
            required: true,
            description: format!(
                "Whether the agent may use the `{}` L4 capability.",
                gate.label()
            ),
        })
        .collect()
}
