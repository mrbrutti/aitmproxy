//! L4 module configuration (M5 Task 1).
//!
//! `L4Config` is opt-in and fail-closed: `enabled` defaults to false, the scope
//! is empty (deny-by-default), and in-path interception is off unless an
//! `intercept` block is present. The binary (M5 Task 13) is the only constructor
//! of the live module; here we define the shapes and their conservative defaults.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::L4ScopeEntry;

/// The L4 module configuration. Missing keys fall back to [`L4Config::default`],
/// so an operator writes only what they want to change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct L4Config {
    /// Opt-in: the module is not even constructed while this is false.
    pub enabled: bool,
    /// Capture/inject backend. `Pcap` by default.
    pub capture_backend: L4Backend,
    /// Deny-by-default scope: an empty list means nothing is active.
    pub scope: Vec<L4ScopeEntry>,
    /// Tool-wide injection ceiling in packets/sec. `0` ⇒ refuse.
    pub global_inject_pps: u32,
    /// Hard cap on a single crafted/injected packet.
    pub max_packet_bytes: usize,
    /// Hard cap on packets emitted by one command invocation.
    pub max_packets_per_call: u32,
    /// Default wait for a `send_recv` reply when the caller gives none.
    pub default_recv_timeout: Duration,
    /// In-path interception config. `None` ⇒ in-path disabled even if `enabled`.
    pub intercept: Option<InterceptConfig>,
    /// The dangerous-destination denylist is never globally disabled; this only
    /// relaxes it where an explicit scope entry already covers the target.
    pub dangerous_dst_override: bool,
    /// Whether a runtime bus/MCP caller may widen the deny-by-default scope via
    /// `l4.scope.add`. **Default false** (mirrors `ca.allow_agent_install`): the
    /// one escape hatch out of deny-by-default stays with the operator, who
    /// declares scope in the `scope` block above. Pre-M4 the bus cannot tell
    /// operator from agent, so runtime widening is gated by this flag rather than
    /// by caller identity. Even when true, a runtime-added entry can never lift the
    /// dangerous-destination denylist (only config-declared scope can).
    pub allow_agent_widen: bool,
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_backend: L4Backend::Pcap,
            scope: Vec::new(),
            // Conservative, configurable ceilings — this is a testing tool, not a
            // flood primitive (anti-goal). Non-zero so an explicitly scoped,
            // enabled target can inject at all; the per-entry `inject_rate` and
            // the scope still gate every send.
            global_inject_pps: 100,
            max_packet_bytes: 65_535,
            max_packets_per_call: 128,
            default_recv_timeout: Duration::from_secs(2),
            intercept: None,
            dangerous_dst_override: false,
            // Deny-by-default: runtime bus scope widening is off until the operator
            // opts in. Mirrors `ca.allow_agent_install`'s conservative default.
            allow_agent_widen: false,
        }
    }
}

/// Capture/inject backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Backend {
    /// libpcap (default).
    #[default]
    Pcap,
    /// `pnet` datalink fallback.
    PnetDatalink,
}

/// In-path (NFQUEUE) interception settings. Fail-open by default so the target's
/// unrelated traffic is never stalled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterceptConfig {
    /// The `nft` queue number aitmproxy binds.
    pub queue_num: u16,
    /// aitm-enforced verdict deadline (the kernel gives none).
    pub verdict_timeout: Duration,
    /// Applied on deadline expiry — default `Forward` (fail open).
    pub on_timeout: Verdict,
    /// Parked-queue cap aitmproxy honours.
    pub max_parked: u32,
    /// Applied on overflow / no listener — default `Forward` (fail open).
    pub on_overflow: Verdict,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            queue_num: 0,
            verdict_timeout: Duration::from_secs(5),
            on_timeout: Verdict::Forward,
            max_parked: 256,
            on_overflow: Verdict::Forward,
        }
    }
}

/// An interception verdict. `Forward` carries the (possibly mutated) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Forward,
    Drop,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{L4Capability, L4Direction};

    /// An operator-authored L4 config round-trips from YAML: `enabled` defaults
    /// to false when omitted, the scope entry carries its capability and
    /// per-entry injection rate, and the intercept block's fail-open
    /// `on_timeout` is `Forward`.
    #[test]
    fn config_deserializes_yaml() {
        let yaml = r#"
scope:
  - cidr:
      addr: 127.0.0.1
      prefix: 32
    ports:
      lo: 0
      hi: 65535
    interface: lo0
    direction: outbound
    capability: inject
    inject_rate:
      pps: 5
      burst: 10
intercept:
  queue_num: 100
  verdict_timeout:
    secs: 5
    nanos: 0
  on_timeout: forward
  max_parked: 64
  on_overflow: forward
"#;

        let cfg: L4Config = serde_yaml::from_str(yaml).expect("config parses");

        // `enabled` omitted ⇒ false (opt-in, fail-closed default).
        assert!(!cfg.enabled);

        assert_eq!(cfg.scope.len(), 1);
        let entry = &cfg.scope[0];
        assert_eq!(entry.capability, L4Capability::Inject);
        assert_eq!(entry.direction, L4Direction::Outbound);
        assert_eq!(entry.inject_rate.pps, 5);
        assert_eq!(entry.inject_rate.burst, 10);

        let intercept = cfg.intercept.expect("intercept block present");
        assert_eq!(intercept.on_timeout, Verdict::Forward);
        assert_eq!(intercept.on_overflow, Verdict::Forward);
        assert_eq!(intercept.queue_num, 100);
    }
}
