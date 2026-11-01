//! Scope / guard value types (M5 Task 1).
//!
//! These are the authorization vocabulary shared by the `L4Guard`, the command
//! surface, the flow model, and the config. Signatures are copied verbatim from
//! the M5 design spec; later tasks add behaviour (guard matching, rate buckets)
//! without changing these shapes.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What a guard check is about — Capture, Inject, or Intercept are separate,
/// separately-scoped capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Action {
    Capture,
    Inject,
    Intercept,
}

/// The target of a check — resolved from a capture/interception bind or from a
/// decoded packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4Target {
    pub interface: String,
    pub direction: L4Direction,
    pub dst: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub proto: L4Proto,
}

/// Traffic direction, relative to the host running aitmproxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Direction {
    Inbound,
    Outbound,
}

/// Transport/network protocol selector. `Other(u8)` and `Raw` keep the model
/// open to any protocol, matching the craft layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
    Raw,
}

impl L4Proto {
    /// The name `l4.flow.get` puts on the wire for a packet's transport: the
    /// same names [`PacketSpec::summarize`](crate::craft::PacketSpec::summarize)
    /// uses, so a flow row and its packet detail agree.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
            L4Proto::Icmp => "ICMP",
            L4Proto::IcmpV6 => "ICMPv6",
            L4Proto::Other(_) => "other",
            L4Proto::Raw => "raw",
        }
    }
}

/// A deny-by-default scope entry. Nothing captures, injects, or intercepts until
/// an entry exists and matches; Capture / Inject / Intercept are distinct
/// capabilities on the entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4ScopeEntry {
    /// Generated when omitted, so operators author scope without writing UUIDs.
    #[serde(default)]
    pub id: L4ScopeId,
    pub cidr: IpCidr,
    /// `Any` == `0..=65535`; matched for Tcp/Udp.
    pub ports: PortRange,
    pub interface: String,
    pub direction: L4Direction,
    /// Capture | Inject | Intercept — the capability this entry grants.
    pub capability: L4Capability,
    /// Per-entry injection ceiling (pps + burst).
    pub inject_rate: RateCap,
    /// Provenance: operator config vs runtime bus add. `#[serde(default)]` ⇒ a
    /// config-declared entry deserializes as [`L4ScopeSource::Config`] (operator
    /// authority); `l4.scope.add` stamps [`L4ScopeSource::Runtime`]. Only a
    /// `Config`-sourced entry may lift the dangerous-destination denylist.
    #[serde(default)]
    pub source: L4ScopeSource,
}

/// Where a scope entry came from. The operator's config block carries operator
/// authority; a runtime bus add (`l4.scope.add`) does not, and can never lift the
/// dangerous-destination denylist (deny-by-default's one escape hatch stays with
/// the operator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4ScopeSource {
    /// Declared in the operator's `l4.scope` config block (operator authority).
    #[default]
    Config,
    /// Added at runtime via `l4.scope.add` over the command bus.
    Runtime,
}

/// Stable identifier for a scope entry (uuid-backed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L4ScopeId(Uuid);

impl L4ScopeId {
    /// Mint a fresh scope id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for L4ScopeId {
    fn default() -> Self {
        Self::new()
    }
}

/// The capability a scope entry grants. Mirrors `L4Action`, but names what an
/// entry *authorizes* rather than what a check *requests*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L4Capability {
    Capture,
    Inject,
    Intercept,
}

/// An inclusive port range. [`PortRange::ANY`] (`0..=65535`) means "any port".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    /// The full range, meaning "any port" (`*`, `any` or an omitted `ports` in
    /// `l4.scope.add`; `all ports` in its confirm prompt).
    pub const ANY: PortRange = PortRange { lo: 0, hi: 65535 };

    /// Whether this is the full range, [`PortRange::ANY`].
    #[must_use]
    pub fn is_any(self) -> bool {
        self == Self::ANY
    }
}

/// A CIDR block: a base address plus a prefix length in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

/// An injection rate ceiling. `pps == 0` means **refuse** (the `per_host_rps`
/// "0 means refuse" convention, not "1 pps").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCap {
    pub pps: u32,
    pub burst: u32,
}

#[cfg(test)]
mod tests {
    use super::{L4Proto, PortRange};

    /// `PortRange::ANY` is the full range and the only range `is_any` accepts.
    #[test]
    fn port_range_any() {
        assert_eq!(PortRange::ANY, PortRange { lo: 0, hi: 65535 });
        assert!(PortRange::ANY.is_any());
        assert!(!PortRange { lo: 0, hi: 65534 }.is_any());
        assert!(!PortRange { lo: 1, hi: 65535 }.is_any());
        assert!(!PortRange { lo: 80, hi: 80 }.is_any());
    }

    /// A15 (L4PAR-AC1): the names `l4.flow.get` puts on the wire for the four
    /// transports `PacketSpec::endpoints` decodes, the same as `summarize`'s.
    #[test]
    fn wire_names() {
        assert_eq!(
            [L4Proto::Tcp, L4Proto::Udp, L4Proto::Icmp, L4Proto::IcmpV6].map(L4Proto::wire_name),
            ["TCP", "UDP", "ICMP", "ICMPv6"]
        );
        assert_eq!(L4Proto::Other(47).wire_name(), "other");
        assert_eq!(L4Proto::Raw.wire_name(), "raw");
    }
}
