//! The agent plugin: `agent.status` (any role) and `agent.set` (operator/CLI
//! only), over the shared [`AgentState`].
//!
//! The policy itself is enforced in the MCP server's `call_tool` gate (Task 4);
//! these two commands only read and change it. Both the gate and this plugin hold
//! the same `Arc<AgentState>`, so an operator `agent.set` is seen by the gate at
//! once. `agent.set` is refused from the agent role: the agent can never change
//! its own policy (Review Focus #2). `agent.status` is Read and open to any role.
//!
//! `actions_last_minute` and `connected_clients` are part of the declared
//! `agent.status` shape; their data sources (the F2 audit ring and the connection
//! registry) land in later M4 tasks, so they report `0` and `[]` for now.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    AgentPolicy, AgentState, Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin,
    Registry, Sensitivity, TypeDesc, Value,
};
use anyhow::{anyhow, bail};

/// Registers `agent.status` and `agent.set` over a shared [`AgentState`].
pub struct AgentPlugin {
    state: Arc<AgentState>,
}

impl AgentPlugin {
    /// Build the plugin over the policy state shared with the server's gate.
    pub fn new(state: Arc<AgentState>) -> Self {
        Self { state }
    }
}

impl Plugin for AgentPlugin {
    fn name(&self) -> &str {
        "agent"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(AgentStatus(self.state.clone())));
        reg.add_command(Arc::new(AgentSet(self.state.clone())));
    }
}

fn param(name: &str, ty: TypeDesc, required: bool, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty,
        required,
        description: description.to_string(),
    }
}

/// `agent.status {} -> {policy, actions_last_minute, connected_clients}` (Read).
struct AgentStatus(Arc<AgentState>);

impl Command for AgentStatus {
    fn name(&self) -> &str {
        "agent.status"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Report the current agent policy and recent agent activity. Read-only and \
                          readable by any role."
                    .to_string(),
            params: vec![],
            result: TypeDesc::Object(vec![
                param(
                    "policy",
                    TypeDesc::Str,
                    true,
                    "all | auto | ask | readonly | paused.",
                ),
                param(
                    "actions_last_minute",
                    TypeDesc::Int,
                    true,
                    "Agent tool calls in the last minute (sourced from the audit ring; 0 until it \
                     is wired).",
                ),
                param(
                    "connected_clients",
                    TypeDesc::Array(Box::new(TypeDesc::Object(vec![
                        param("role", TypeDesc::Str, true, "operator | mcp | cli."),
                        param("client", TypeDesc::Str, true, "The client label."),
                        param("since", TypeDesc::Str, true, "When it connected."),
                    ]))),
                    true,
                    "Connected MCP clients (sourced from the connection registry; empty until it \
                     is wired).",
                ),
            ]),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let mut fields = BTreeMap::new();
        fields.insert(
            "policy".to_string(),
            Value::Str(self.0.policy().label().to_string()),
        );
        fields.insert("actions_last_minute".to_string(), Value::Int(0));
        fields.insert("connected_clients".to_string(), Value::Array(vec![]));
        Ok(Value::Object(fields))
    }
}

/// `agent.set {policy} -> {policy}` (Sensitive; operator/CLI only).
struct AgentSet(Arc<AgentState>);

impl Command for AgentSet {
    fn name(&self) -> &str {
        "agent.set"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Set the agent policy (all | auto | ask | readonly | paused). The \
                          deliberate operator act that governs the agent — operator/CLI only; the \
                          agent cannot change its own policy."
                .to_string(),
            params: vec![param(
                "policy",
                TypeDesc::Str,
                true,
                "all | auto | ask | readonly | paused.",
            )],
            result: TypeDesc::Object(vec![param(
                "policy",
                TypeDesc::Str,
                true,
                "The policy now in effect.",
            )]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Operator/CLI only. The policy gate already refuses this for the agent
        // under most policies, but `All` would let it through — so the command
        // self-gates too: the agent can never change its own policy.
        if host.frontend() == Frontend::Mcp {
            bail!(
                "agent.set refused: the agent cannot change its own policy; only an operator or \
                 the human CLI may set it."
            );
        }
        let want = args.get_str("policy")?;
        let policy = AgentPolicy::parse(want).ok_or_else(|| {
            anyhow!("unknown policy `{want}`; expected all | auto | ask | readonly | paused")
        })?;
        self.0.set_policy(policy);
        let mut fields = BTreeMap::new();
        fields.insert("policy".to_string(), Value::Str(policy.label().to_string()));
        Ok(Value::Object(fields))
    }
}
