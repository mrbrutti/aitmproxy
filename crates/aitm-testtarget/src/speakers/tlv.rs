//! `l4-tlv-crash`: the TLV echo speaker (spec D5).
//!
//! A frame is a u16 big-endian length followed by that many payload bytes;
//! the speaker echoes every frame it receives. The deliberate bug: a
//! declared length over [`MAX_TLV`], or a declared length longer than the
//! bytes that arrived before the read went idle, crashes the Vulnerable
//! origin; the Patched control answers `00 03 45 52 52` (`ERR`) and closes.

use super::{mode_bug, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// Largest payload a frame may declare (spec D5: "TLV at 4096").
pub const MAX_TLV: usize = 4096;

/// Size of the length prefix.
const HEADER: usize = 2;

/// The service entry for the shared driver.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-tlv-crash",
    grammar: "tlv",
    proto: Proto::Tcp,
    new_conn,
};

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Tlv)
}

/// Build one frame: u16 BE length + payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    // Callers only frame constant payloads far below u16::MAX; a longer one
    // is a programming error here, so saturate rather than wrap.
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The Patched-mode answer to the bug: `00 03 45 52 52`.
fn err_frame() -> Vec<u8> {
    frame(b"ERR")
}

/// The TLV speaker; it keeps no state between frames.
pub struct Tlv;

impl Speaker for Tlv {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        let Some(header) = buf.get(..HEADER) else {
            return Parsed::Incomplete;
        };
        let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let verb = Some("frame".to_string());
        if len > MAX_TLV {
            return Parsed::Message {
                consumed: HEADER,
                verb,
                step: mode_bug(mode, err_frame()),
            };
        }
        let total = HEADER + len;
        let Some(whole) = buf.get(..total) else {
            return Parsed::Incomplete;
        };
        Parsed::Message {
            consumed: total,
            verb,
            step: Step::Reply(whole.to_vec()),
        }
    }

    fn on_idle(&mut self, mode: SeedMode, _buf: &[u8]) -> Step {
        // The driver only calls this with a non-empty buffer `parse` left
        // incomplete: a declared length longer than what arrived.
        mode_bug(mode, err_frame())
    }

    fn max_buffer(&self) -> usize {
        HEADER + MAX_TLV
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{Parsed, Proto, Speaker, Step};
    use crate::SeedMode;

    #[test]
    fn tlv_echoes() {
        let mut s = Tlv;
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0, 3, 0x61, 0x62, 0x63]),
            Parsed::Message {
                consumed: 5,
                verb: Some("frame".to_string()),
                step: Step::Reply(vec![0, 3, 0x61, 0x62, 0x63]),
            }
        );
        // Trailing bytes belong to the next frame: only one frame is consumed.
        assert_eq!(
            s.parse(SeedMode::Patched, &[0, 1, 0x41, 0, 0]),
            Parsed::Message {
                consumed: 3,
                verb: Some("frame".to_string()),
                step: Step::Reply(vec![0, 1, 0x41]),
            }
        );
    }

    #[test]
    fn tlv_liveness() {
        let mut s = Tlv;
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0, 0]),
            Parsed::Message {
                consumed: 2,
                verb: Some("frame".to_string()),
                step: Step::Reply(vec![0, 0]),
            }
        );
    }

    #[test]
    fn tlv_incomplete() {
        let mut s = Tlv;
        assert_eq!(s.parse(SeedMode::Vulnerable, &[]), Parsed::Incomplete);
        assert_eq!(s.parse(SeedMode::Vulnerable, &[0]), Parsed::Incomplete);
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0, 0x10, 0x61, 0x62]),
            Parsed::Incomplete
        );
        // Exactly the cap is still a legal frame once its bytes arrive.
        let mut full = vec![0x10, 0x00];
        full.extend(std::iter::repeat_n(0x61, 4096));
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &full[..100]),
            Parsed::Incomplete
        );
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &full),
            Parsed::Message {
                consumed: 4098,
                verb: Some("frame".to_string()),
                step: Step::Reply(full.clone()),
            }
        );
    }

    #[test]
    fn tlv_oversize_triggers_in_v() {
        let mut s = Tlv;
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0xFF, 0xFF]),
            Parsed::Message {
                consumed: 2,
                verb: Some("frame".to_string()),
                step: Step::Trigger,
            }
        );
        assert_eq!(
            s.parse(SeedMode::Patched, &[0xFF, 0xFF]),
            Parsed::Message {
                consumed: 2,
                verb: Some("frame".to_string()),
                step: Step::Fault(vec![0, 3, b'E', b'R', b'R']),
            }
        );
        // 4097 is the first length over the cap.
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0x10, 0x01]),
            Parsed::Message {
                consumed: 2,
                verb: Some("frame".to_string()),
                step: Step::Trigger,
            }
        );
    }

    #[test]
    fn tlv_idle_short_frame() {
        let mut s = Tlv;
        assert_eq!(
            s.on_idle(SeedMode::Vulnerable, &[0, 0x10, 0x61, 0x62]),
            Step::Trigger
        );
        assert_eq!(
            s.on_idle(SeedMode::Patched, &[0, 0x10, 0x61, 0x62]),
            Step::Fault(vec![0, 3, b'E', b'R', b'R'])
        );
        // A lone length byte is an incomplete frame too.
        assert_eq!(s.on_idle(SeedMode::Vulnerable, &[0]), Step::Trigger);
    }

    #[test]
    fn tlv_def_and_limits() {
        assert_eq!(MAX_TLV, 4096);
        assert_eq!(DEF.name, "l4-tlv-crash");
        assert_eq!(DEF.grammar, "tlv");
        assert_eq!(DEF.proto, Proto::Tcp);
        let s = (DEF.new_conn)();
        assert_eq!(s.name(), "l4-tlv-crash");
        assert_eq!(s.banner(), None);
        assert_eq!(s.max_buffer(), 4098);
    }
}
