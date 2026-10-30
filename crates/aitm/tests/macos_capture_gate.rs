//! NE-AC11 — the macOS system-extension install/activation is an **operator**
//! action. An agent (`Frontend::Mcp`) cannot trigger it unless the operator
//! explicitly opts in with `allow_agent_sysex_install`. This mirrors the
//! deny-by-default `ca.allow_agent_install` trust-store gate.

use aitm::macos_capture::activation_gate::{
    check_activation_caller, ActivationRefused, SysexActivationConfig,
};
use aitm_core::Frontend;

#[test]
fn agent_cannot_trigger_sysex_install() {
    // Deny-by-default: the flag is off unless the operator sets it.
    let cfg = SysexActivationConfig::default();
    assert!(
        !cfg.allow_agent_sysex_install,
        "allow_agent_sysex_install must default to false"
    );

    // The agent is refused the privileged install under the default config.
    assert_eq!(
        check_activation_caller(Frontend::Mcp, &cfg),
        Err(ActivationRefused),
        "an agent-origin sysex install must be refused by default"
    );

    // A present human operator may trigger it.
    assert!(
        check_activation_caller(Frontend::Operator, &cfg).is_ok(),
        "an operator-origin sysex install must be allowed"
    );

    // The human-driven CLI may trigger it.
    assert!(
        check_activation_caller(Frontend::Cli, &cfg).is_ok(),
        "a cli-origin sysex install must be allowed"
    );

    // Explicit operator opt-in lets the agent through.
    let opted_in = SysexActivationConfig {
        allow_agent_sysex_install: true,
    };
    assert!(
        check_activation_caller(Frontend::Mcp, &opted_in).is_ok(),
        "with allow_agent_sysex_install = true the agent-origin call must succeed"
    );
}
