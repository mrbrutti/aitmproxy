//! The per-capability agent gates — the single source of truth for whether an agent
//! (`Frontend::Mcp`) may use each L4 capability (Stage B).
//!
//! The four gates (inject / capture / intercept / widen) map 1:1 to the
//! `l4.allow_agent_*` config flags and to the operator-facing MCP toggles. They live
//! in one shared [`L4AgentGates`] (atomics) owned by the [`L4Guard`](crate::guard::L4Guard)
//! and seeded from config, so **one** object governs every enforcement point:
//!
//! - the guard's [`add_runtime_scope`](crate::guard::L4Guard::add_runtime_scope)
//!   reads the **widen** gate (SEC-2 stays in the guard, the security boundary);
//! - the Mcp-only [`L4AgentGate`](crate::commands::agent::L4AgentGate) wrapper reads
//!   the **inject / capture / intercept** gate for the wire verbs;
//! - the operator-only `l4.agent.set` flips a gate and `l4.agent.status` reports all
//!   four — over the very same object, so an operator toggle governs the real agent
//!   path at once (never a cosmetic switch).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::config::L4Config;

/// One per-capability agent gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGate {
    /// Gates agent `l4.inject` / `l4.send_recv` (`l4.allow_agent_inject`).
    Inject,
    /// Gates agent `l4.capture.start` (`l4.allow_agent_capture`).
    Capture,
    /// Gates agent `l4.intercept.start` / `.mutate` / `.forward` / `.drop`
    /// (`l4.allow_agent_intercept`).
    Intercept,
    /// Gates agent `l4.scope.add` (`l4.allow_agent_widen`); enforced in the guard.
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

    /// Every gate, in a stable order (for status / iteration).
    #[must_use]
    pub fn all() -> [AgentGate; 4] {
        [
            AgentGate::Inject,
            AgentGate::Capture,
            AgentGate::Intercept,
            AgentGate::Widen,
        ]
    }
}

/// The four per-capability agent gates in effect. Lock-free (atomics), so a gate read
/// on the hot path never contends with an operator toggling a flag.
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

    /// All gates open — a test convenience so a command's own guard/logic is reached
    /// without the agent gate short-circuiting first.
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
