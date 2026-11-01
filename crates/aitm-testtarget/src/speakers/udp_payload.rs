//! `l4-udp-payload-crash`: the raw UDP echo speaker (spec D5), the packet
//! lane's `raw` oracle.
//!
//! Every datagram is echoed back. The deliberate bug: a datagram of at least
//! 8 bytes starting `DE AD BE EF` crashes the Vulnerable origin (AC T5-2b);
//! the Patched control echoes it like any other.

// consumed by A19 (the driver registers `DEF`); nothing links it yet.
#![allow(dead_code)]

use super::{Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// The crash prefix (AC T5-2b).
const MAGIC: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// Shortest datagram that triggers when it starts with [`MAGIC`].
const MIN_TRIGGER_LEN: usize = 8;

/// Largest UDP payload; one datagram is always one message.
const MAX_DATAGRAM: usize = 65_535;

/// The service entry for the shared driver.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-udp-payload-crash",
    grammar: "raw",
    proto: Proto::Udp,
    new_conn,
};

fn new_conn() -> Box<dyn Speaker> {
    Box::new(UdpPayload)
}

/// The raw UDP echo speaker; it keeps no state between datagrams.
pub struct UdpPayload;

impl Speaker for UdpPayload {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        if buf.is_empty() {
            return Parsed::Incomplete;
        }
        let is_trigger = buf.len() >= MIN_TRIGGER_LEN && buf.starts_with(&MAGIC);
        let step = match (is_trigger, mode) {
            (true, SeedMode::Vulnerable) => Step::Trigger,
            // The Patched control echoes the magic like any other datagram
            // (spec D5 P reply: "echo").
            _ => Step::Reply(buf.to_vec()),
        };
        Parsed::Message {
            consumed: buf.len(),
            verb: Some("raw".to_string()),
            step,
        }
    }

    fn on_idle(&mut self, _mode: SeedMode, _buf: &[u8]) -> Step {
        // A datagram is whole on arrival; idle with bytes left cannot happen.
        Step::Close(None)
    }

    fn max_buffer(&self) -> usize {
        MAX_DATAGRAM
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{Parsed, Proto, Speaker, Step};
    use crate::SeedMode;

    const MAGIC8: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];

    #[test]
    fn udp_crash_shape() {
        let mut s = UdpPayload;
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &MAGIC8),
            Parsed::Message {
                consumed: 8,
                verb: Some("raw".to_string()),
                step: Step::Trigger,
            }
        );
        assert_eq!(
            s.parse(SeedMode::Patched, &MAGIC8),
            Parsed::Message {
                consumed: 8,
                verb: Some("raw".to_string()),
                step: Step::Reply(MAGIC8.to_vec()),
            }
        );
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0x61, 0x62, 0x63]),
            Parsed::Message {
                consumed: 3,
                verb: Some("raw".to_string()),
                step: Step::Reply(vec![0x61, 0x62, 0x63]),
            }
        );
        // Seven bytes with the magic prefix are one short of the trigger.
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &MAGIC8[..7]),
            Parsed::Message {
                consumed: 7,
                verb: Some("raw".to_string()),
                step: Step::Reply(MAGIC8[..7].to_vec()),
            }
        );
        // Longer than eight still triggers; the prefix must be exact.
        let mut long = MAGIC8.to_vec();
        long.extend_from_slice(b"tail");
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &long),
            Parsed::Message {
                consumed: 12,
                verb: Some("raw".to_string()),
                step: Step::Trigger,
            }
        );
        let near_miss = [0xDE, 0xAD, 0xBE, 0xEE, 0, 0, 0, 0];
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &near_miss),
            Parsed::Message {
                consumed: 8,
                verb: Some("raw".to_string()),
                step: Step::Reply(near_miss.to_vec()),
            }
        );
    }

    #[test]
    fn udp_empty_datagram_is_incomplete() {
        let mut s = UdpPayload;
        assert_eq!(s.parse(SeedMode::Vulnerable, &[]), Parsed::Incomplete);
    }

    #[test]
    fn udp_idle_and_def() {
        let mut s = UdpPayload;
        assert_eq!(s.on_idle(SeedMode::Vulnerable, &[0x61]), Step::Close(None));
        assert_eq!(s.on_idle(SeedMode::Patched, &[0x61]), Step::Close(None));
        assert_eq!(DEF.name, "l4-udp-payload-crash");
        assert_eq!(DEF.grammar, "raw");
        assert_eq!(DEF.proto, Proto::Udp);
        let d = (DEF.new_conn)();
        assert_eq!(d.name(), "l4-udp-payload-crash");
        assert_eq!(d.banner(), None);
        assert_eq!(d.max_buffer(), 65_535);
    }
}
