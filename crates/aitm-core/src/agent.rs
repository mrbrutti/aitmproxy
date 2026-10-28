//! The agent policy posture.
//!
//! `AgentPolicy` is the operator-set rule that governs what an agent-role
//! connection may do over MCP. It is enforced in the MCP server (Task 4) against
//! each command's declared `Sensitivity` (Task 1). `AgentState` holds the policy
//! that is in effect: one instance is seeded from `McpConfig.policy` at wiring and
//! shared (`Arc`) between the server's policy gate and the `AgentPlugin`'s
//! `agent.status`/`agent.set` commands, so an operator `agent.set` is seen at once
//! by the gate. Operator and CLI roles are never gated by this policy.

use std::sync::atomic::{AtomicU8, Ordering};

/// How much latitude an agent-role connection has. Set by the operator
/// (`agent.set`, seeded from config); an agent can never change its own policy.
///
/// `#[non_exhaustive]` so future postures can be added without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPolicy {
    /// Every agent call runs (still subject to scope/rate/SSRF and the always-on
    /// per-command config gates).
    All,
    /// Autonomous: `Read` and `Write` commands run; `Sensitive` is refused unless
    /// its own config gate allows it (no human in the loop).
    Auto,
    /// `Read` and `Write` commands run; a `Sensitive` command prompts the operator
    /// and runs only on approval (human in the loop).
    Ask,
    /// Only non-mutating (`Read`) commands run.
    ReadOnly,
    /// Nothing from the agent runs.
    Paused,
}

impl AgentPolicy {
    /// The lower-case wire label (`agent.set` argument, `agent.status` field).
    pub fn label(self) -> &'static str {
        match self {
            AgentPolicy::All => "all",
            AgentPolicy::Auto => "auto",
            AgentPolicy::Ask => "ask",
            AgentPolicy::ReadOnly => "readonly",
            AgentPolicy::Paused => "paused",
        }
    }

    /// Parse a wire label back into a policy; `None` for an unknown string.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "all" => AgentPolicy::All,
            "auto" => AgentPolicy::Auto,
            "ask" => AgentPolicy::Ask,
            "readonly" => AgentPolicy::ReadOnly,
            "paused" => AgentPolicy::Paused,
            _ => return None,
        })
    }

    /// The compact discriminant [`AgentState`] stores atomically.
    fn to_u8(self) -> u8 {
        match self {
            AgentPolicy::All => 0,
            AgentPolicy::Auto => 1,
            AgentPolicy::Ask => 2,
            AgentPolicy::ReadOnly => 3,
            AgentPolicy::Paused => 4,
        }
    }

    /// Inverse of [`AgentPolicy::to_u8`]; only ever reads values it wrote, so an
    /// out-of-range byte falls back to the fail-closed [`AgentPolicy::Paused`].
    fn from_u8(v: u8) -> Self {
        match v {
            0 => AgentPolicy::All,
            1 => AgentPolicy::Auto,
            2 => AgentPolicy::Ask,
            3 => AgentPolicy::ReadOnly,
            _ => AgentPolicy::Paused,
        }
    }
}

/// The agent policy currently in effect — the single source of truth read by the
/// MCP server's policy gate and mutated by `agent.set`. Lock-free (one atomic),
/// so the gate never contends with an operator changing the policy.
#[derive(Debug)]
pub struct AgentState {
    policy: AtomicU8,
}

impl AgentState {
    /// Seed the state with `policy` (from `McpConfig.policy` at wiring).
    pub fn new(policy: AgentPolicy) -> Self {
        Self {
            policy: AtomicU8::new(policy.to_u8()),
        }
    }

    /// The policy in effect.
    pub fn policy(&self) -> AgentPolicy {
        AgentPolicy::from_u8(self.policy.load(Ordering::Relaxed))
    }

    /// Replace the policy (the operator's `agent.set`).
    pub fn set_policy(&self, policy: AgentPolicy) {
        self.policy.store(policy.to_u8(), Ordering::Relaxed);
    }
}
