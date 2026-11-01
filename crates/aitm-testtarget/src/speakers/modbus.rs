//! `l4-modbus`: a minimal Modbus/TCP responder (spec D5 row `l4-modbus`).
//!
//! Function code 3 (Read Holding Registers) is answered with registers whose
//! value is `addr + i`; the write and diagnostic codes 5/6/8/15/16/22/23 are
//! answered with exception `0x01` and classified `denylisted`; any other
//! code is a `protocol_error` with exception `0x01`. The one deliberate parse
//! bug is an MBAP length past the 260-byte PDU cap or shorter than unit id +
//! function code: the Vulnerable origin crashes, the Patched control answers
//! exception `0x03` and closes.

use crate::speakers::{mode_bug, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// MBAP header: transaction id, protocol id, length, unit id.
const MBAP_LEN: usize = 7;
/// Largest Modbus/TCP PDU plus the unit id the MBAP length counts.
const MAX_LENGTH: u16 = 260;
/// Smallest MBAP length that still covers unit id + function code.
const MIN_LENGTH: u16 = 2;
/// Read Holding Registers.
const FC_READ_HOLDING: u8 = 0x03;
/// Write/diagnostic codes the spec denylists (D5): fc 5/6/8/15/16/22/23.
const DENYLISTED: [u8; 7] = [0x05, 0x06, 0x08, 0x0F, 0x10, 0x16, 0x17];
/// Exception codes.
const EX_ILLEGAL_FUNCTION: u8 = 0x01;
const EX_ILLEGAL_DATA_VALUE: u8 = 0x03;

/// The `/services` row for this speaker.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-modbus",
    grammar: "modbus",
    proto: Proto::Tcp,
    new_conn,
};

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Modbus)
}

/// The stateless Modbus/TCP responder; one per connection.
pub struct Modbus;

/// A Modbus exception ADU: `tid, 00 00, 00 03, uid, fc|0x80, code`.
pub fn exception(tid: u16, uid: u8, fc: u8, code: u8) -> Vec<u8> {
    let [t0, t1] = tid.to_be_bytes();
    vec![t0, t1, 0x00, 0x00, 0x00, 0x03, uid, fc | 0x80, code]
}

/// The MBAP fields the exception reply needs, from however much of the
/// frame has arrived (missing bytes read as 0).
fn header_fields(buf: &[u8]) -> (u16, u8, u8) {
    let tid = u16::from_be_bytes([byte(buf, 0), byte(buf, 1)]);
    (tid, byte(buf, 6), byte(buf, 7))
}

fn byte(buf: &[u8], i: usize) -> u8 {
    buf.get(i).copied().unwrap_or(0)
}

fn be16(buf: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([byte(buf, i), byte(buf, i + 1)])
}

impl Speaker for Modbus {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        if buf.len() < MBAP_LEN {
            return Parsed::Incomplete;
        }
        let (tid, uid, fc) = header_fields(buf);
        let pid = be16(buf, 2);
        let len = be16(buf, 4);

        // The deliberate bug: a length past the PDU cap or shorter than
        // unit id + function code.
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&len) {
            return Parsed::Message {
                consumed: buf.len(),
                verb: None,
                step: mode_bug(mode, exception(tid, uid, fc, EX_ILLEGAL_DATA_VALUE)),
            };
        }

        let adu_len = 6 + usize::from(len);
        if buf.len() < adu_len {
            return Parsed::Incomplete;
        }
        let verb = Some(format!("fc{fc}"));

        if pid != 0 {
            return Parsed::Message {
                consumed: adu_len,
                verb,
                step: Step::ProtocolError(exception(tid, uid, fc, EX_ILLEGAL_DATA_VALUE)),
            };
        }

        let data = &buf[MBAP_LEN + 1..adu_len];
        let step = if fc == FC_READ_HOLDING {
            read_holding(tid, uid, data)
        } else if DENYLISTED.contains(&fc) {
            Step::Denylisted(exception(tid, uid, fc, EX_ILLEGAL_FUNCTION))
        } else {
            Step::ProtocolError(exception(tid, uid, fc, EX_ILLEGAL_FUNCTION))
        };
        Parsed::Message {
            consumed: adu_len,
            verb,
            step,
        }
    }

    fn on_idle(&mut self, mode: SeedMode, buf: &[u8]) -> Step {
        // A partial ADU after the idle: the same bug as a bad length.
        let (tid, uid, fc) = header_fields(buf);
        mode_bug(mode, exception(tid, uid, fc, EX_ILLEGAL_DATA_VALUE))
    }

    fn max_buffer(&self) -> usize {
        MBAP_LEN + usize::from(MAX_LENGTH)
    }
}

/// fc 3: `addr, qty` -> registers `addr + i` as u16 BE, `qty` in 1..=125;
/// anything else is exception 0x03.
fn read_holding(tid: u16, uid: u8, data: &[u8]) -> Step {
    if data.len() != 4 {
        return Step::ProtocolError(exception(tid, uid, FC_READ_HOLDING, EX_ILLEGAL_DATA_VALUE));
    }
    let addr = be16(data, 0);
    let qty = be16(data, 2);
    if !(1..=125).contains(&qty) {
        return Step::ProtocolError(exception(tid, uid, FC_READ_HOLDING, EX_ILLEGAL_DATA_VALUE));
    }
    let byte_count = qty * 2;
    let mut out = Vec::with_capacity(9 + usize::from(byte_count));
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&(3 + byte_count).to_be_bytes());
    out.push(uid);
    out.push(FC_READ_HOLDING);
    // qty <= 125 so the byte count fits one byte.
    out.push(byte_count as u8);
    for i in 0..qty {
        out.extend_from_slice(&addr.wrapping_add(i).to_be_bytes());
    }
    Step::Reply(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{msg, Parsed, Proto, Speaker, Step};
    use crate::SeedMode;

    fn parse(mode: SeedMode, buf: &[u8]) -> Parsed {
        Modbus.parse(mode, buf)
    }

    #[test]
    fn def_is_the_spec_row() {
        assert_eq!(DEF.name, "l4-modbus");
        assert_eq!(DEF.grammar, "modbus");
        assert_eq!(DEF.proto, Proto::Tcp);
        let conn = (DEF.new_conn)();
        assert_eq!(conn.name(), "l4-modbus");
        assert_eq!(conn.banner(), None);
        assert_eq!(conn.max_buffer(), 267);
    }

    #[test]
    fn read_holding_one_register() {
        // The D5 benign (and liveness) exchange: fc 3, addr 0, qty 1.
        let req = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let want = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc3", Step::Reply(want.clone()))
        );
        assert_eq!(
            parse(SeedMode::Patched, &req),
            msg(12, "fc3", Step::Reply(want))
        );
    }

    #[test]
    fn read_from_addr_5_two_registers() {
        let req = [
            0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x05, 0x00, 0x02,
        ];
        let want = vec![
            0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x11, 0x03, 0x04, 0x00, 0x05, 0x00, 0x06,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc3", Step::Reply(want))
        );
    }

    #[test]
    fn write_single_is_denylisted() {
        let req = [
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x00, 0x00, 0x01,
        ];
        let want = vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x01];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc6", Step::Denylisted(want.clone()))
        );
        assert_eq!(
            parse(SeedMode::Patched, &req),
            msg(12, "fc6", Step::Denylisted(want))
        );
    }

    #[test]
    fn diagnostics_is_denylisted() {
        // fc 8 sub-function 0 (return query data), data 0xBEEF.
        let req = [
            0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x08, 0x00, 0x00, 0xBE, 0xEF,
        ];
        let want = vec![0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x01, 0x88, 0x01];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc8", Step::Denylisted(want))
        );
    }

    #[test]
    fn every_denylisted_code_gets_exception_01() {
        for fc in [5u8, 6, 8, 15, 16, 22, 23] {
            let req = [
                0x00, 0x0A, 0x00, 0x00, 0x00, 0x06, 0x01, fc, 0x00, 0x00, 0x00, 0x01,
            ];
            let want = vec![0x00, 0x0A, 0x00, 0x00, 0x00, 0x03, 0x01, fc | 0x80, 0x01];
            assert_eq!(
                parse(SeedMode::Vulnerable, &req),
                msg(12, &format!("fc{fc}"), Step::Denylisted(want)),
                "fc {fc}"
            );
        }
    }

    #[test]
    fn unknown_fc_is_protocol_error() {
        // fc 4 (read input registers) is not served: exception 0x01, keep the
        // connection.
        let req = [
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
        ];
        let want = vec![0x00, 0x0B, 0x00, 0x00, 0x00, 0x03, 0x01, 0x84, 0x01];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc4", Step::ProtocolError(want))
        );
    }

    #[test]
    fn mbap_too_long() {
        // len 0x0105 = 261 > 260.
        let req = [
            0x00, 0x03, 0x00, 0x00, 0x01, 0x05, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            Parsed::Message {
                consumed: 12,
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, &req),
            Parsed::Message {
                consumed: 12,
                verb: None,
                step: Step::Fault(vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03]),
            }
        );
    }

    #[test]
    fn mbap_too_short() {
        // len 0x0001 < 2: shorter than unit id + function code.
        let req = [0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            Parsed::Message {
                consumed: 8,
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, &req),
            Parsed::Message {
                consumed: 8,
                verb: None,
                step: Step::Fault(vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03]),
            }
        );
    }

    #[test]
    fn protocol_id_nonzero_is_protocol_error() {
        // pid 0x0001: exception 0x03, connection kept, whole ADU consumed.
        let req = [
            0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let want = vec![0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03];
        assert_eq!(
            parse(SeedMode::Vulnerable, &req),
            msg(12, "fc3", Step::ProtocolError(want.clone()))
        );
        assert_eq!(
            parse(SeedMode::Patched, &req),
            msg(12, "fc3", Step::ProtocolError(want))
        );
    }

    #[test]
    fn incomplete_frames_wait() {
        assert_eq!(parse(SeedMode::Vulnerable, &[]), Parsed::Incomplete);
        // Six bytes: the unit id has not arrived.
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0x00, 0x01, 0x00, 0x00, 0x00, 0x06]),
            Parsed::Incomplete
        );
        // A valid header announcing 6 more bytes, only 3 of them here.
        assert_eq!(
            parse(
                SeedMode::Vulnerable,
                &[0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00]
            ),
            Parsed::Incomplete
        );
    }

    #[test]
    fn two_adus_parse_one_at_a_time() {
        let mut buf = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        buf.extend_from_slice(&[
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x00, 0x00, 0x01,
        ]);
        let first = parse(SeedMode::Vulnerable, &buf);
        assert_eq!(
            first,
            msg(
                12,
                "fc3",
                Step::Reply(vec![
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00
                ])
            )
        );
        let second = parse(SeedMode::Vulnerable, &buf[12..]);
        assert_eq!(
            second,
            msg(
                12,
                "fc6",
                Step::Denylisted(vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x01])
            )
        );
    }

    #[test]
    fn partial_adu_on_idle_splits_by_mode() {
        // Header says 6 more bytes; only the fc arrived, then silence.
        let partial = [0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03];
        assert_eq!(
            Modbus.on_idle(SeedMode::Vulnerable, &partial),
            Step::Trigger
        );
        assert_eq!(
            Modbus.on_idle(SeedMode::Patched, &partial),
            Step::Fault(vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03])
        );
        // Not even a whole header: tid is read, uid and fc default to 0.
        assert_eq!(
            Modbus.on_idle(SeedMode::Patched, &[0x00, 0x06, 0x00]),
            Step::Fault(vec![0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x03])
        );
    }

    #[test]
    fn fc3_bad_quantity_is_illegal_data_value() {
        // qty 0 and qty 126 are outside 1..=125: exception 0x03, keep the
        // connection.
        for qty in [0u8, 126] {
            let req = [
                0x00, 0x0C, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, qty,
            ];
            assert_eq!(
                parse(SeedMode::Vulnerable, &req),
                msg(
                    12,
                    "fc3",
                    Step::ProtocolError(vec![0x00, 0x0C, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03])
                ),
                "qty {qty}"
            );
        }
    }

    #[test]
    fn exception_bytes() {
        assert_eq!(
            exception(0x1234, 0x11, 0x03, 0x03),
            vec![0x12, 0x34, 0x00, 0x00, 0x00, 0x03, 0x11, 0x83, 0x03]
        );
        assert_eq!(
            exception(0x0002, 0x01, 0x06, 0x01),
            vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x01]
        );
    }
}
