//! The agent policy posture.
//!
//! `AgentPolicy` is the operator-set rule that governs what an agent-role
//! connection may do over MCP. It is enforced in the MCP server (Task 4) against
//! each command's declared `Sensitivity` (Task 1); this module only defines the
//! enum so the config and server layers can name it. Operator and CLI roles are
//! never gated by it.

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
