//! macOS NE Task 5 (NE-AC4): raw packet-level L4 is honestly unavailable on the
//! macOS embedded core. The flow-level capture path (TCP byte streams, UDP
//! datagrams) has no on-wire IP-packet machinery, so the raw-packet verbs
//! `l4.inject` / `l4.send_recv` / `l4.intercept.*` must map to a typed
//! `L4Unavailable` whose reason names macOS as flow-level and raw-packet L4 as
//! Linux-only — never a panic, never silence.

use aitm::macos_capture::availability::{raw_packet_verb_unavailable, RawPacketVerb};
use aitm_proto_l4::guard::L4GuardError;

/// Every raw-packet verb maps to `L4Unavailable` with an honest reason naming
/// the flow-level ceiling and the Linux-only raw-packet path.
#[test]
fn raw_packet_verbs_unavailable_on_macos() {
    for verb in RawPacketVerb::ALL {
        let err = raw_packet_verb_unavailable(verb);
        let L4GuardError::L4Unavailable(reason) = err else {
            panic!("{verb:?} must map to L4Unavailable, got {err:?}");
        };
        assert!(
            reason.contains("flow-level"),
            "{verb:?} reason must name the flow-level ceiling, got: {reason}"
        );
        assert!(
            reason.contains("Linux-only"),
            "{verb:?} reason must name raw-packet L4 as Linux-only, got: {reason}"
        );
    }
}
