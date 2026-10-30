//! NE-AC4: raw packet-level L4 is honestly unavailable on the macOS embedded core.
//!
//! The macOS capture path is a `NETransparentProxyProvider` — flow-level only:
//! TCP byte streams and UDP datagrams, never the on-wire IP bytes the raw-packet
//! machinery in `crates/aitm-proto-l4/src/flow.rs` assumes. So the raw-packet
//! verbs (`l4.inject`, `l4.send_recv`, `l4.intercept.*`) have no footing here.
//! Rather than panic or fall silent, the macOS core maps each to a typed
//! [`L4GuardError::L4Unavailable`] whose reason names the flow-level ceiling and
//! points at Linux/CLI for raw-packet L4.

use aitm_proto_l4::guard::L4GuardError;

/// A raw-packet-level L4 verb — one that needs the on-wire IP-packet machinery
/// that the macOS flow-level capture path cannot provide. On the macOS embedded
/// core each of these is honestly unavailable (NE-AC4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPacketVerb {
    /// `l4.inject` — craft and inject a raw packet onto the wire.
    Inject,
    /// `l4.send_recv` — send a crafted packet and read the raw reply.
    SendRecv,
    /// `l4.intercept.*` — in-path raw-packet interception (NFQUEUE on Linux).
    Intercept,
}

impl RawPacketVerb {
    /// Every raw-packet verb the macOS core must refuse, for exhaustive mapping.
    pub const ALL: [RawPacketVerb; 3] = [
        RawPacketVerb::Inject,
        RawPacketVerb::SendRecv,
        RawPacketVerb::Intercept,
    ];

    /// The verb's name as it appears on the bus/MCP surface.
    pub fn wire_name(self) -> &'static str {
        match self {
            RawPacketVerb::Inject => "l4.inject",
            RawPacketVerb::SendRecv => "l4.send_recv",
            RawPacketVerb::Intercept => "l4.intercept.*",
        }
    }
}

/// Map a raw-packet-level L4 verb to the typed refusal the macOS embedded core
/// returns for it. macOS capture is flow-level (TCP byte streams and UDP
/// datagrams), so the raw-packet craft/inject/intercept machinery is never
/// present — never a panic, never silence (NE-AC4).
pub fn raw_packet_verb_unavailable(verb: RawPacketVerb) -> L4GuardError {
    L4GuardError::L4Unavailable(format!(
        "{verb} is unavailable on the macOS embedded core: capture here is \
         flow-level only (TCP byte streams and UDP datagrams), and raw-packet \
         L4 craft/inject/intercept is Linux-only",
        verb = verb.wire_name(),
    ))
}
