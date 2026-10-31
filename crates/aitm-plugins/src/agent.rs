//! The agent plugin: `agent.status` (any role) and `agent.set` (operator/CLI
//! only), over the shared [`AgentState`].
//!
//! The policy itself is enforced in the MCP server's `call_tool` gate (Task 4);
//! these two commands only read and change it. Both the gate and this plugin hold
//! the same `Arc<AgentState>`, so an operator `agent.set` is seen by the gate at
//! once. `agent.set` is refused from the agent role: the agent can never change
//! its own policy (Review Focus #2). `agent.status` is Read and open to any role.
//!
//! `connected_clients` is part of the declared `agent.status` shape; its data
//! source (the connection registry) lands in a later M4 task, so it reports `[]`
//! for now. `actions_last_minute` is sourced from the F2 audit ring (Task 8).
//! `agent.activity` (Read, any role) reads the same ring so a surface or a
//! reconnecting agent can catch up on recent activity (spec D3a.4).
//!
//! The audit ring has two lanes: an evidence lane (refusals, failures, and every
//! Write or Sensitive run) and a routine lane (successful reads only), so a burst
//! of reads cannot push evidence out. `actions_last_minute` counts both lanes,
//! across every surface: a UI that polls `agent.status` counts too.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aitm_core::audit::{DEFAULT_AUDIT_CAPACITY, DEFAULT_ROUTINE_AUDIT_CAPACITY};
use aitm_core::{
    AgentPolicy, AgentState, AuditRing, Command, CommandHost, ParamDef, ParamSchema, Params,
    Plugin, Registry, Sensitivity, TypeDesc, Value,
};
use anyhow::{anyhow, bail};

/// Registers `agent.status`, `agent.set`, and `agent.activity` over a shared
/// [`AgentState`] and the F2 [`AuditRing`].
pub struct AgentPlugin {
    state: Arc<AgentState>,
    audit: Arc<AuditRing>,
}

impl AgentPlugin {
    /// Build the plugin over the policy state shared with the server's gate. The
    /// audit ring defaults to a fresh, standalone ring; wiring that shares the
    /// server's ring (so `agent.activity` sees every invocation `call_tool`
    /// records) sets it with [`AgentPlugin::with_audit_ring`].
    pub fn new(state: Arc<AgentState>) -> Self {
        Self {
            state,
            audit: Arc::new(AuditRing::default()),
        }
    }

    /// Share the server's audit ring, so `agent.activity`/`agent.status` read the
    /// same entries the MCP server's `call_tool` appends.
    pub fn with_audit_ring(mut self, audit: Arc<AuditRing>) -> Self {
        self.audit = audit;
        self
    }
}

impl Plugin for AgentPlugin {
    fn name(&self) -> &str {
        "agent"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(AgentStatus {
            state: self.state.clone(),
            audit: self.audit.clone(),
        }));
        reg.add_command(Arc::new(AgentSet(self.state.clone())));
        reg.add_command(Arc::new(AgentActivity(self.audit.clone())));
        reg.add_command(Arc::new(AgentApprove));
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
struct AgentStatus {
    state: Arc<AgentState>,
    audit: Arc<AuditRing>,
}

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
                    "Command invocations still held in the audit ring that were recorded in the \
                     last minute, across both lanes and every surface (a polling UI counts). \
                     Saturates at what the ring holds.",
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
        let last_minute = self
            .audit
            .count_since(SystemTime::now() - Duration::from_secs(60));
        let mut fields = BTreeMap::new();
        fields.insert(
            "policy".to_string(),
            Value::Str(self.state.policy().label().to_string()),
        );
        fields.insert(
            "actions_last_minute".to_string(),
            Value::Int(last_minute as i64),
        );
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
        // self-gates too: the agent can never change its own policy. Only a trusted
        // control role passes: see `CommandHost::caller_is_trusted_control`.
        if !host.caller_is_trusted_control() {
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

/// `agent.activity {since?, limit?} -> [AuditEntry]` (Read; any role).
///
/// Reads the F2 audit ring so a surface or a reconnecting agent can catch up on
/// recent command activity without replaying the whole `notifications/aitm/agent`
/// stream (spec D3a.4). `since` is Unix-epoch milliseconds (entries strictly
/// after it); `limit` keeps the most recent `limit` of those.
///
/// Entries merge oldest-first across the ring's two lanes. The ring is a live
/// view, not a complete record. A source that already holds one of a lane's table
/// slots keeps a floor of its entries against a flood. That is not isolation: a
/// source that arrives after the slots are taken, or that shares a label with a
/// flooder, can be flushed, and every agent-token connection of the web bridge is
/// ONE source, `(mcp, web-bridge)`. Labels are unauthenticated display strings;
/// `origin` is authoritative. A call with no `limit` can return up to
/// `DEFAULT_AUDIT_CAPACITY + DEFAULT_ROUTINE_AUDIT_CAPACITY` entries with the
/// default lane sizes (both lanes full), so passing `limit` is advisable.
struct AgentActivity(Arc<AuditRing>);

impl Command for AgentActivity {
    fn name(&self) -> &str {
        "agent.activity"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: format!(
                "Recent command-invocation audit entries (who ran what, with what redacted \
                 arguments, and the outcome), merged oldest first across the ring's two lanes. \
                 The ring is a live view, not a complete record. A source that already holds \
                 one of a lane's table slots keeps a floor of its entries against a flood; a \
                 source that arrives after the slots are taken, or that shares a label with a \
                 flooder, can be flushed, and every agent-token bridge connection is ONE \
                 source (`mcp`, `web-bridge`). Labels are unauthenticated display strings; \
                 `origin` is authoritative. A call with no `limit` can return up to {} \
                 entries (both lanes full, default sizes), so passing `limit` is advisable. \
                 Read-only and readable by any role.",
                DEFAULT_AUDIT_CAPACITY + DEFAULT_ROUTINE_AUDIT_CAPACITY
            ),
            params: vec![
                param(
                    "since",
                    TypeDesc::Int,
                    false,
                    "Keep only entries recorded strictly after this Unix-epoch-milliseconds time.",
                ),
                param(
                    "limit",
                    TypeDesc::Int,
                    false,
                    "Keep at most this many of the most recent matching entries.",
                ),
            ],
            result: TypeDesc::Array(Box::new(TypeDesc::Object(vec![
                param("at", TypeDesc::Int, true, "Unix-epoch milliseconds."),
                param("origin", TypeDesc::Str, true, "operator | mcp | cli."),
                param(
                    "client_label",
                    TypeDesc::Str,
                    false,
                    "The client label: the server-minted `web-bridge` for the web bridge, \
                     otherwise the client's declared `initialize.clientInfo.name`, sanitised to \
                     at most 64 characters. Display-only; `origin` is authoritative.",
                ),
                param("command", TypeDesc::Str, true, "The dotted command name."),
                param(
                    "args",
                    TypeDesc::Str,
                    true,
                    "The redacted, size-capped argument summary.",
                ),
                param(
                    "result",
                    TypeDesc::Any,
                    true,
                    "`\"ok\"`, or `{error: <reason>}` for a refusal/failure.",
                ),
            ]))),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let since = match args.get("since") {
            Some(Value::Int(ms)) if *ms >= 0 => {
                Some(UNIX_EPOCH + Duration::from_millis(*ms as u64))
            }
            _ => None,
        };
        let limit = match args.get("limit") {
            Some(Value::Int(n)) if *n >= 0 => Some(*n as usize),
            _ => None,
        };
        let entries = self
            .0
            .recent(since, limit)
            .iter()
            .map(|e| e.to_value())
            .collect();
        Ok(Value::Array(entries))
    }
}

/// `agent.approve {request_id, allow} -> {}` (Sensitive; operator/CLI only).
///
/// The operator's half of the `Ask` policy handshake (spec D4): it resolves a
/// Sensitive agent call the server parked for approval. The command is
/// **server-handled** — the MCP server intercepts it in `call_tool` and resolves
/// the request against its own parked-request table (which this plugin, in a
/// separate crate, cannot reach). This `invoke` is only a fallback for a context
/// with no such table and always refuses; the agent role can never approve
/// (Review Focus #2), refused both by the server's intercept and here.
struct AgentApprove;

impl Command for AgentApprove {
    fn name(&self) -> &str {
        "agent.approve"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Approve or deny a Sensitive agent command the server parked under the \
                          `ask` policy. Operator/CLI only; the agent cannot approve its own \
                          requests."
                .to_string(),
            params: vec![
                param(
                    "request_id",
                    TypeDesc::Str,
                    true,
                    "The parked request's id, from the approval_requested notification.",
                ),
                param(
                    "allow",
                    TypeDesc::Bool,
                    true,
                    "true runs the parked command and returns its result to the waiting agent; \
                     false refuses it.",
                ),
            ],
            result: TypeDesc::Object(vec![]),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Only a trusted control role (operator or CLI) may even reach the fallback:
        // see `CommandHost::caller_is_trusted_control`.
        if !host.caller_is_trusted_control() {
            bail!(
                "agent.approve refused: the agent cannot approve its own requests; only an \
                 operator or the human CLI may approve a parked sensitive command."
            );
        }
        bail!(
            "agent.approve is resolved by the MCP server against its parked-request table; it \
             cannot be invoked in this context."
        );
    }
}
