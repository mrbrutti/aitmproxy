//! Per-capability agent gates and the operator-only `l4.agent.*` surface (Stage B).
//!
//! The M4 identity/policy model governs an agent (`Frontend::Mcp`) L4 call on **two**
//! independent dimensions, both of which must pass:
//!
//! 1. **`AgentPolicy`** — enforced in the MCP server's `call_tool` gate against each
//!    command's [`Sensitivity`](aitm_core::Sensitivity). A `Sensitive` L4 verb is
//!    refused under `Auto`/`ReadOnly`/`Paused`, parked under `Ask`, and — under
//!    `All` — deferred to the command's own gate (the server's
//!    `defers_to_command_gate` lists the L4 Sensitive verbs).
//! 2. **The per-capability flag** — enforced *here*, in [`L4AgentGate`], a thin
//!    wrapper the module places around each gated command. For a `Frontend::Mcp`
//!    caller it refuses unless the matching [`L4AgentGates`] flag is on; the operator
//!    and CLI roles bypass it (humans author freely — the wire-writers are instead
//!    confirmed over the wire).
//!
//! The gates are a single shared [`L4AgentGates`] (atomics), seeded from config and
//! shared by the wrapper, `l4.agent.status` (reports them), and `l4.agent.set`
//! (flips one, operator-only) — exactly as M4's `AgentState` is shared by the policy
//! gate and `agent.set`. So an operator `l4.agent.set` is seen by the gate at once,
//! and the toggle governs the real agent path (never a cosmetic switch).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Sensitivity, TypeDesc, Value,
};

use crate::config::L4Config;

/// One per-capability agent gate. The four map 1:1 to the `l4.allow_agent_*` config
/// flags and to the operator-facing MCP toggles (Capture / Inject / Intercept /
/// Widen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGate {
    /// Gates agent `l4.inject` / `l4.send_recv` (`l4.allow_agent_inject`).
    Inject,
    /// Gates agent `l4.capture.start` (`l4.allow_agent_capture`).
    Capture,
    /// Gates agent `l4.intercept.start` / `.mutate` / `.forward` / `.drop`
    /// (`l4.allow_agent_intercept`).
    Intercept,
    /// Gates agent `l4.scope.add` (`l4.allow_agent_widen`).
    Widen,
}

impl AgentGate {
    /// The lower-case wire label (`l4.agent.set` argument, `l4.agent.status` field).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AgentGate::Inject => "inject",
            AgentGate::Capture => "capture",
            AgentGate::Intercept => "intercept",
            AgentGate::Widen => "widen",
        }
    }

    /// Parse a wire label back into a gate; `None` for an unknown string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "inject" => AgentGate::Inject,
            "capture" => AgentGate::Capture,
            "intercept" => AgentGate::Intercept,
            "widen" => AgentGate::Widen,
            _ => return None,
        })
    }
}

/// The four per-capability agent gates in effect — the single source of truth read
/// by [`L4AgentGate`] (and `l4.scope.add`), reported by `l4.agent.status`, and
/// mutated by `l4.agent.set`. Lock-free (atomics) so the gate never contends with an
/// operator toggling a flag.
#[derive(Debug)]
pub struct L4AgentGates {
    inject: AtomicBool,
    capture: AtomicBool,
    intercept: AtomicBool,
    widen: AtomicBool,
}

impl L4AgentGates {
    /// Seed the gates from config (every flag defaults false — deny-by-default).
    #[must_use]
    pub fn from_config(cfg: &L4Config) -> Arc<Self> {
        Arc::new(Self {
            inject: AtomicBool::new(cfg.allow_agent_inject),
            capture: AtomicBool::new(cfg.allow_agent_capture),
            intercept: AtomicBool::new(cfg.allow_agent_intercept),
            widen: AtomicBool::new(cfg.allow_agent_widen),
        })
    }

    /// Whether `gate` is currently open to the agent.
    #[must_use]
    pub fn allowed(&self, gate: AgentGate) -> bool {
        self.cell(gate).load(Ordering::Relaxed)
    }

    /// Open or close `gate` (the operator's `l4.agent.set`).
    pub fn set(&self, gate: AgentGate, allowed: bool) {
        self.cell(gate).store(allowed, Ordering::Relaxed);
    }

    fn cell(&self, gate: AgentGate) -> &AtomicBool {
        match gate {
            AgentGate::Inject => &self.inject,
            AgentGate::Capture => &self.capture,
            AgentGate::Intercept => &self.intercept,
            AgentGate::Widen => &self.widen,
        }
    }

    /// The four gate states as a transport-neutral object (for `l4.agent.status`).
    fn to_value(&self) -> Value {
        let mut o = BTreeMap::new();
        for gate in [
            AgentGate::Inject,
            AgentGate::Capture,
            AgentGate::Intercept,
            AgentGate::Widen,
        ] {
            o.insert(gate.label().to_string(), Value::Bool(self.allowed(gate)));
        }
        Value::Object(o)
    }

    /// All gates open — a test convenience so a command's own guard/logic is reached
    /// without the agent-gate short-circuiting first.
    #[cfg(test)]
    #[must_use]
    pub fn all_open() -> Arc<Self> {
        Arc::new(Self {
            inject: AtomicBool::new(true),
            capture: AtomicBool::new(true),
            intercept: AtomicBool::new(true),
            widen: AtomicBool::new(true),
        })
    }
}

/// A per-capability agent gate wrapped around one Sensitive `l4.*` command (the
/// second M4 dimension). For a `Frontend::Mcp` caller it refuses unless the matching
/// [`L4AgentGates`] flag is on; the operator and CLI roles bypass it (the wire
/// verbs are confirmed over the wire instead). `name` / `schema` / `sensitivity` /
/// `confirm_prompt` delegate to the inner command, so the command still appears and
/// classifies honestly in `tools/list` and the operator confirm handshake still runs.
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
        // Only the agent (`Frontend::Mcp`) is flag-gated; the operator and CLI are
        // the control and author freely (the hardest verbs ask the operator for
        // confirm-over-the-wire instead).
        if host.frontend() == Frontend::Mcp && !self.gates.allowed(self.gate) {
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
        Ok(self.gates.to_value())
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
        if host.frontend() == Frontend::Mcp {
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
        Ok(self.gates.to_value())
    }
}

/// Build the operator-only `l4.agent.*` commands over the shared gates.
pub(crate) fn agent_commands(gates: Arc<L4AgentGates>) -> Vec<Arc<dyn Command>> {
    vec![
        Arc::new(AgentStatus::new(gates.clone())),
        Arc::new(AgentSet::new(gates)),
    ]
}

/// The four gate fields `l4.agent.status` / `l4.agent.set` report.
fn gate_fields() -> Vec<ParamDef> {
    ["inject", "capture", "intercept", "widen"]
        .into_iter()
        .map(|cap| ParamDef {
            name: cap.into(),
            ty: TypeDesc::Bool,
            required: true,
            description: format!("Whether the agent may use the `{cap}` L4 capability."),
        })
        .collect()
}
