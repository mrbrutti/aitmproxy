//! AC-R14-7 (unit): `McpConfig::default()` is unchanged by R14 except for the
//! new `operator_bus` field. The five pre-existing defaults are pinned
//! literally so a later edit cannot move the agent posture by accident (the
//! agent policy, the stdio agent transport and the agent token are untouched,
//! spec D10); the operator bus itself is on, with an ephemeral port.
//!
//! Spec: docs/superpowers/specs/2026-11-01-cli-oneshot-live-core-design.md (D2, D10)
//! Plan: docs/superpowers/plans/2026-11-01-cli-oneshot-live-core-plan.md (Task 2)

use aitm_core::{AgentPolicy, Frontend, McpConfig, McpTransport, OperatorBusConfig};

#[test]
fn defaults_are_unchanged_except_the_operator_bus() {
    let cfg = McpConfig::default();
    assert!(
        matches!(cfg.transport, McpTransport::Stdio),
        "transport: {:?}",
        cfg.transport
    );
    assert_eq!(cfg.policy, AgentPolicy::Auto);
    assert_eq!(cfg.stdio_role, Frontend::Mcp);
    assert_eq!(cfg.agent_token, None);
    assert_eq!(cfg.operator_token, None);
    assert_eq!(
        cfg.operator_bus,
        OperatorBusConfig {
            enabled: true,
            port: 0
        }
    );
    // The field's own `Default` is the same value `McpConfig::default()` carries.
    assert_eq!(
        OperatorBusConfig::default(),
        OperatorBusConfig {
            enabled: true,
            port: 0
        }
    );
}
