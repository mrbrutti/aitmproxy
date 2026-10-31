//! The `macos_capture` enable config (LF-AC1, LF-AC12).
//!
//! Enabling the macOS NE live-capture feeder is a **deny-by-default,
//! operator-only** action: the feeder runs iff `macos_capture.enabled` is `true`
//! **and** the build is macOS. There is no existing NE/capture switch — `l4.enabled`
//! builds the Linux-only raw-packet module, which is the wrong one — so this is a
//! new config section, deserialized into [`MacosCaptureConfig`], riding alongside
//! `l4` in the config-file `Settings`/`Features` exactly as `l4` does. It lives in
//! the `aitm` crate (not `aitm-core`) because it reuses
//! [`SysexActivationConfig`](super::activation_gate::SysexActivationConfig).
//!
//! ```yaml
//! macos_capture:
//!   enabled: false            # the exact enable flag; default off
//!   activation:
//!     allow_agent_sysex_install: false   # existing activation_gate knob, reused
//! ```
//!
//! `enabled` is authored only in the config file — operator authority. No
//! bus/MCP/agent command flips it. The `activation` knob is nested here (rather
//! than left standalone) so that if a runtime enable trigger is ever added it must
//! pass [`check_activation_caller`](super::activation_gate::check_activation_caller),
//! the same gate that governs the sysex install.

use super::activation_gate::SysexActivationConfig;

/// The `macos_capture:` config section.
///
/// `Default` is **disabled** (`enabled: false`): the default build does not run
/// the feeder. `#[serde(default, deny_unknown_fields)]` means an absent key keeps
/// its disabled default and a misspelled knob is an error, not a silently kept
/// default.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MacosCaptureConfig {
    /// The exact enable flag. **Default `false`** — deny-by-default; the feeder
    /// runs only when an operator sets this to `true` in the config file (and only
    /// on macOS).
    pub enabled: bool,
    /// The reused operator-only activation gate. Nested here so a future runtime
    /// enable trigger is governed by the same `check_activation_caller` the sysex
    /// install uses.
    pub activation: SysexActivationConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LF-AC1: the feeder's on-switch defaults off.
    #[test]
    fn default_is_disabled() {
        assert!(!MacosCaptureConfig::default().enabled);
    }

    /// The nested activation gate also defaults to deny-by-default.
    #[test]
    fn default_activation_denies_agents() {
        assert!(
            !MacosCaptureConfig::default()
                .activation
                .allow_agent_sysex_install
        );
    }
}
