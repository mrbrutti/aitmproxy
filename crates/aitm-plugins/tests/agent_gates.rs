//! The `agent.set` and `agent.approve` command self-gates, invoked directly (not
//! through the MCP server): the agent role (`Frontend::Mcp`) is refused with the
//! exact text, and the present-human roles (`Frontend::Operator` and
//! `Frontend::Cli`) pass the gate. The server-side path is covered separately by
//! `aitm-mcp/tests/mcp.rs`; this file pins the command's own check, which is the
//! last line of defence when the policy gate lets a call through (`AgentPolicy::All`).

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    AgentPolicy, AgentState, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params,
    ProxyClient, Registry, StdGuard, Value,
};
use aitm_plugins::AgentPlugin;
use futures::future::BoxFuture;

/// A `ProxyClient` that fails if a command ever reaches for the network: neither
/// gate under test may send a request.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// A registry holding only the agent plugin over `state`.
fn agent_registry(state: &Arc<AgentState>) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(AgentPlugin::new(state.clone())));
    reg
}

/// Invoke `name` with `args` as `frontend`, over a fresh store, stub client and
/// default guard.
fn invoke_as(
    reg: &Registry,
    name: &str,
    args: Params,
    frontend: Frontend,
) -> anyhow::Result<Value> {
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(frontend);
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(args, &host)
}

/// The `{policy: <label>}` object `agent.set` returns on success.
fn policy_object(label: &str) -> Value {
    Value::Object(BTreeMap::from([(
        "policy".to_string(),
        Value::Str(label.to_string()),
    )]))
}

#[test]
fn agent_set_refuses_the_agent_and_admits_operator_and_cli() {
    let state = Arc::new(AgentState::new(AgentPolicy::All));
    let reg = agent_registry(&state);

    // The agent can never change its own policy; the policy is left untouched.
    let err = invoke_as(
        &reg,
        "agent.set",
        params(&[("policy", Value::Str("paused".into()))]),
        Frontend::Mcp,
    )
    .expect_err("agent.set must be refused for the agent");
    assert_eq!(
        err.to_string(),
        "agent.set refused: the agent cannot change its own policy; only an operator or the \
         human CLI may set it."
    );
    assert_eq!(state.policy(), AgentPolicy::All);

    // An operator-token connection may set it.
    let out = invoke_as(
        &reg,
        "agent.set",
        params(&[("policy", Value::Str("paused".into()))]),
        Frontend::Operator,
    )
    .expect("operator agent.set is allowed");
    assert_eq!(out, policy_object("paused"));
    assert_eq!(state.policy(), AgentPolicy::Paused);

    // So may the human CLI.
    let out = invoke_as(
        &reg,
        "agent.set",
        params(&[("policy", Value::Str("readonly".into()))]),
        Frontend::Cli,
    )
    .expect("CLI agent.set is allowed");
    assert_eq!(out, policy_object("readonly"));
    assert_eq!(state.policy(), AgentPolicy::ReadOnly);
}

#[test]
fn agent_approve_command_refuses_the_agent_and_lets_humans_reach_the_fallback() {
    let state = Arc::new(AgentState::new(AgentPolicy::All));
    let reg = agent_registry(&state);
    let args = || {
        params(&[
            ("request_id", Value::Str("x".into())),
            ("allow", Value::Bool(true)),
        ])
    };

    // The agent can never approve its own parked request.
    let err = invoke_as(&reg, "agent.approve", args(), Frontend::Mcp)
        .expect_err("agent.approve must be refused for the agent");
    assert_eq!(
        err.to_string(),
        "agent.approve refused: the agent cannot approve its own requests; only an operator or \
         the human CLI may approve a parked sensitive command."
    );

    // Operator and CLI pass the role check and reach the fallback, which always
    // refuses because only the MCP server owns the parked-request table.
    let fallback = "agent.approve is resolved by the MCP server against its parked-request \
                    table; it cannot be invoked in this context.";
    for frontend in [Frontend::Operator, Frontend::Cli] {
        let err = invoke_as(&reg, "agent.approve", args(), frontend)
            .expect_err("the in-process fallback always refuses");
        assert_eq!(err.to_string(), fallback, "frontend {frontend:?}");
    }
}
