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
//! for now. `actions_last_minute` is sourced from the F2 audit ring (Task 8), as
//! the caller may see it, and `exclude_self` leaves out the caller's own connection.
//! `agent.activity` (Read, any role) reads the same ring so a surface or a
//! reconnecting agent can catch up on recent activity (spec D3a.4); a caller that
//! is not trusted control gets only the entries it may see (`AuditEntry::visible_to`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// `agent.status {exclude_self?} -> {policy, actions_last_minute, connected_clients}`
/// (Read; any role).
///
/// `actions_last_minute` is the caller's view of the ring
/// ([`AuditRing::count_since_for`] with the caller's frontend): a caller that is not
/// trusted control does not count entries made by trusted control (operator, CLI),
/// so it equals what `agent.activity` would return to the same caller for the last
/// minute. With `exclude_self: true` the entries made by the caller's own
/// connection (the server-assigned id on [`CommandHost::connection_id`]) are left
/// out, so a client's own polling does not inflate the number it reads. A caller
/// with no connection id has nothing to exclude. The flag changes only the count
/// this caller receives; it cannot lower what any other connection sees.
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
                          readable by any role, but the activity count covers only the entries \
                          the caller may see: a caller that is not trusted control does not \
                          count entries made by trusted control (operator, CLI)."
                    .to_string(),
            params: vec![param(
                "exclude_self",
                TypeDesc::Bool,
                false,
                "When true, leave out the calls made by this connection (for example a UI's own \
                 polling) from `actions_last_minute`. Default false; a caller with no connection \
                 id excludes nothing.",
            )],
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
                    "Command invocations recorded in the last minute that the caller may see \
                     (sourced from the F2 audit ring).",
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

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // `exclude_self` is a schema-declared optional boolean: a non-boolean never
        // reaches here (the schema coercion refuses it as invalid params), and
        // absent means off. The excluded id is the server-assigned one the host
        // carries, never anything the caller sent; with none, nothing is excluded.
        let exclude_self = matches!(args.get("exclude_self"), Some(Value::Bool(true)));
        let exclude = if exclude_self {
            host.connection_id()
        } else {
            None
        };
        let last_minute = self.audit.count_since_for(
            host.frontend(),
            SystemTime::now() - Duration::from_secs(60),
            exclude,
        );
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
/// Callable by any role, but the result is the caller's view of the ring
/// ([`AuditRing::recent_for`] with the caller's frontend): a caller that is not
/// trusted control never receives an entry made by trusted control (operator,
/// CLI), and `limit` counts only the entries it may see. The ring itself, and
/// the durable log, are never filtered.
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
            description: "Recent command-invocation audit entries (who ran what, with what \
                          redacted arguments, and the outcome), oldest first. Read-only and \
                          callable by any role, but a caller that is not trusted control does \
                          not see entries made by trusted control (operator, CLI)."
                .to_string(),
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
                    "The client label, when one was declared.",
                ),
                param(
                    "connection_id",
                    TypeDesc::Str,
                    false,
                    "The server-assigned id of the connection that made the call; null when not \
                     attributable.",
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

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
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
            .recent_for(host.frontend(), since, limit)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A registry carrying the real `AgentPlugin` over a fresh state.
    fn registry() -> Registry {
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(AgentPlugin::new(Arc::new(AgentState::new(
            AgentPolicy::Auto,
        )))));
        reg
    }

    /// AC16 (activity half): the `agent.activity` result object declares an optional
    /// string `connection_id`, and its description says a caller that is not trusted
    /// control does not see trusted-control entries.
    #[test]
    fn agent_activity_schema_declares_connection_id() {
        let reg = registry();
        let schema = reg
            .command("agent.activity")
            .expect("agent.activity is registered")
            .schema();

        let TypeDesc::Array(item) = &schema.result else {
            panic!("agent.activity returns an array, got {:?}", schema.result);
        };
        let TypeDesc::Object(fields) = item.as_ref() else {
            panic!("agent.activity items are objects, got {item:?}");
        };
        let field = fields
            .iter()
            .find(|f| f.name == "connection_id")
            .unwrap_or_else(|| panic!("no connection_id field in {fields:?}"));
        assert!(
            matches!(field.ty, TypeDesc::Str),
            "connection_id is a string, got {:?}",
            field.ty
        );
        assert!(
            !field.required,
            "connection_id is optional (null when unattributable)"
        );

        assert!(
            schema.description.contains("trusted control"),
            "the description names the viewer filter: {}",
            schema.description
        );
    }

    /// AC16 (status half): `agent.status` declares exactly one param, an optional
    /// boolean `exclude_self`, and its description says the count covers only the
    /// entries the caller may see (a caller that is not trusted control).
    #[test]
    fn agent_status_schema_declares_exclude_self() {
        let reg = registry();
        let schema = reg
            .command("agent.status")
            .expect("agent.status is registered")
            .schema();

        let field = schema
            .params
            .iter()
            .find(|p| p.name == "exclude_self")
            .unwrap_or_else(|| panic!("no exclude_self param in {:?}", schema.params));
        assert!(
            matches!(field.ty, TypeDesc::Bool),
            "exclude_self is a boolean, got {:?}",
            field.ty
        );
        assert!(!field.required, "exclude_self is optional (default off)");
        assert_eq!(
            schema.params.len(),
            1,
            "exclude_self is the only param: {:?}",
            schema.params
        );

        assert!(
            schema.description.contains("trusted control"),
            "the description names the viewer filter: {}",
            schema.description
        );
    }
}
