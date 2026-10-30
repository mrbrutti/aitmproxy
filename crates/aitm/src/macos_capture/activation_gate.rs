//! NE-AC11 — operator-only gate for the macOS system-extension install.
//!
//! Installing or activating the `NETransparentProxyProvider` system extension is
//! a privileged, human-present action. Mirroring the deny-by-default posture of
//! `ca.allow_agent_install` (`crates/aitm-core/src/config.rs`) and
//! `l4.allow_agent_widen` (`crates/aitm-proto-l4/src/config.rs`), an untrusted
//! (agent) caller, any origin `Frontend::is_trusted_control` does not trust, is
//! refused unless the operator explicitly sets
//! [`SysexActivationConfig::allow_agent_sysex_install`].

use std::fmt;

use aitm_core::Frontend;

/// Policy for who may trigger the macOS system-extension install/activation.
///
/// The one knob, [`allow_agent_sysex_install`](Self::allow_agent_sysex_install),
/// defaults to `false`: deny-by-default, exactly like `ca.allow_agent_install`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SysexActivationConfig {
    /// Allow an untrusted (agent) caller, any origin `Frontend::is_trusted_control`
    /// does not trust, to trigger the sysex install/activation. **Default false**
    /// — installing a system extension is an operator action, so an agent must
    /// never reach it unless a human operator opts in.
    pub allow_agent_sysex_install: bool,
}

/// The sysex install/activation was refused because an agent attempted it while
/// [`SysexActivationConfig::allow_agent_sysex_install`] was off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationRefused;

impl ActivationRefused {
    /// The config setting an operator sets to permit agent-driven activation.
    pub const SETTING: &'static str = "allow_agent_sysex_install";
}

impl fmt::Display for ActivationRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refused: installing or activating the macOS system extension is an \
             operator action; an agent cannot trigger it. Set `{}` = true in the \
             aitmproxy config to permit agent-driven activation.",
            Self::SETTING
        )
    }
}

impl std::error::Error for ActivationRefused {}

/// Gate the macOS system-extension install/activation on the caller's origin.
///
/// Who counts as a human-present, trusted origin is decided in one place,
/// [`Frontend::is_trusted_control`] (which delegates to
/// `aitm_core::CallerTrust::is_trusted_control`). A trusted origin may always
/// trigger the operator action; every other origin is treated as agent-driven
/// and refused unless the operator has set
/// [`SysexActivationConfig::allow_agent_sysex_install`]. Deny-by-default: a new
/// origin must be classified in `aitm-core` (default: agent), so it is never
/// silently allowed through.
pub fn check_activation_caller(
    origin: Frontend,
    cfg: &SysexActivationConfig,
) -> Result<(), ActivationRefused> {
    if origin.is_trusted_control() || cfg.allow_agent_sysex_install {
        Ok(())
    } else {
        Err(ActivationRefused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_deny_by_default() {
        assert!(!SysexActivationConfig::default().allow_agent_sysex_install);
    }

    #[test]
    fn agent_refused_unless_opted_in() {
        let off = SysexActivationConfig::default();
        assert_eq!(
            check_activation_caller(Frontend::Mcp, &off),
            Err(ActivationRefused)
        );
        let on = SysexActivationConfig {
            allow_agent_sysex_install: true,
        };
        assert!(check_activation_caller(Frontend::Mcp, &on).is_ok());
    }

    #[test]
    fn humans_always_allowed() {
        let off = SysexActivationConfig::default();
        assert!(check_activation_caller(Frontend::Cli, &off).is_ok());
        assert!(check_activation_caller(Frontend::Operator, &off).is_ok());
    }

    #[test]
    fn activation_matrix_covers_every_variant_and_flag() {
        let off = SysexActivationConfig::default();
        let on = SysexActivationConfig {
            allow_agent_sysex_install: true,
        };
        let cells = [
            (Frontend::Cli, off, Ok(())),
            (Frontend::Cli, on, Ok(())),
            (Frontend::Operator, off, Ok(())),
            (Frontend::Operator, on, Ok(())),
            (Frontend::Mcp, off, Err(ActivationRefused)),
            (Frontend::Mcp, on, Ok(())),
        ];
        for (origin, cfg, expected) in cells {
            assert_eq!(
                check_activation_caller(origin, &cfg),
                expected,
                "origin {origin:?}, allow_agent_sysex_install {}",
                cfg.allow_agent_sysex_install
            );
        }
    }

    #[test]
    fn refusal_message_names_the_setting() {
        assert!(ActivationRefused
            .to_string()
            .contains("allow_agent_sysex_install"));
    }
}
