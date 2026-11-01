//! `l4-mqtt`: a minimal MQTT 3.1.1 responder (spec D5 row `l4-mqtt`).
//!
//! Answers CONNECT, PUBLISH (QoS 0/1), SUBSCRIBE, PINGREQ and DISCONNECT;
//! a retained PUBLISH is accepted silently and logged `denylisted`. The one
//! deliberate parse bug is the remaining-length varint: a 4th byte that still
//! carries the continuation bit (so a 5th byte would be needed; MQTT allows
//! four) or a decoded value over [`MAX_REMAINING`] crashes the Vulnerable
//! origin ([`Step::Trigger`]) and makes the Patched control close with no
//! bytes ([`Step::Fault`]; MQTT has no error reply). Reserved packet types 0
//! and 15, and wrong reserved flag bits, are a `Fault` with no bytes in both
//! modes.

// consumed by A19 (the driver registers `DEF`); nothing links it yet.

use super::{mode_bug, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// Largest remaining length accepted (spec D5: "MQTT at 65 536").
pub const MAX_REMAINING: usize = 65_536;

/// Fixed header (1 byte) + the longest legal varint (4 bytes).
const MAX_HEADER: usize = 5;

/// The `l4-mqtt` service.
pub static DEF: ServiceDef = ServiceDef {
    name: "l4-mqtt",
    grammar: "mqtt",
    proto: Proto::Tcp,
    new_conn,
};

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Mqtt)
}

/// One MQTT connection. The responder is stateless: every control packet is
/// answered on its own.
#[derive(Default, Debug, Clone, Copy)]
pub struct Mqtt;

/// MQTT 3.1.1 control packet type (fixed header high nibble).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
}

impl PacketType {
    /// `None` for the reserved types 0 and 15.
    fn from_nibble(n: u8) -> Option<Self> {
        Some(match n {
            1 => Self::Connect,
            2 => Self::Connack,
            3 => Self::Publish,
            4 => Self::Puback,
            5 => Self::Pubrec,
            6 => Self::Pubrel,
            7 => Self::Pubcomp,
            8 => Self::Subscribe,
            9 => Self::Suback,
            10 => Self::Unsubscribe,
            11 => Self::Unsuback,
            12 => Self::Pingreq,
            13 => Self::Pingresp,
            14 => Self::Disconnect,
            _ => return None,
        })
    }

    /// The packet type name the driver logs as `verb`.
    fn verb(self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
        }
    }

    /// Whether the fixed-header flag nibble is legal for this type
    /// (MQTT 3.1.1 section 2.2.2). PUBLISH owns its flags, PUBREL,
    /// SUBSCRIBE and UNSUBSCRIBE must carry `0010`, every other type `0000`.
    fn flags_ok(self, flags: u8) -> bool {
        match self {
            Self::Publish => true,
            Self::Pubrel | Self::Subscribe | Self::Unsubscribe => flags == 0x02,
            _ => flags == 0x00,
        }
    }
}

/// Outcome of decoding the remaining-length varint after the first byte.
enum Varint {
    /// Fewer than the needed bytes have arrived.
    Incomplete,
    /// `len` decoded from `bytes` varint bytes.
    Done { len: usize, bytes: usize },
    /// A 4th byte still had the continuation bit set: a 5th byte would be
    /// needed, which MQTT does not allow. The deliberate bug.
    FifthByte,
}

/// Decode the MQTT remaining-length varint starting at `buf[1]`.
fn remaining_length(buf: &[u8]) -> Varint {
    let mut len: usize = 0;
    for (i, &b) in buf.iter().skip(1).take(MAX_HEADER - 1).enumerate() {
        len |= usize::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Varint::Done { len, bytes: i + 1 };
        }
        if i == MAX_HEADER - 2 {
            return Varint::FifthByte;
        }
    }
    Varint::Incomplete
}

/// Read the big-endian u16 at `at`, if the slice has it.
fn u16_at(body: &[u8], at: usize) -> Option<u16> {
    let hi = *body.get(at)?;
    let lo = *body.get(at + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// PUBLISH: `flags` are the fixed-header low nibble, `body` the variable
/// header plus payload.
fn publish(flags: u8, body: &[u8]) -> Step {
    let qos = (flags >> 1) & 0x03;
    let retain = flags & 0x01 != 0;
    if qos == 3 {
        // Reserved QoS value: malformed, close without bytes.
        return Step::Fault(Vec::new());
    }
    // Topic name: u16 length + bytes; a packet identifier follows for QoS > 0.
    let Some(topic_len) = u16_at(body, 0) else {
        return Step::Fault(Vec::new());
    };
    let pid_at = 2 + usize::from(topic_len);
    if body.len() < pid_at {
        return Step::Fault(Vec::new());
    }
    if retain {
        return Step::Denylisted(Vec::new());
    }
    match qos {
        0 => Step::Reply(Vec::new()),
        1 => match u16_at(body, pid_at) {
            Some(pid) => {
                let [hi, lo] = pid.to_be_bytes();
                Step::Reply(vec![0x40, 0x02, hi, lo])
            }
            None => Step::Fault(Vec::new()),
        },
        // QoS 2 is well-formed but unsupported: no reply, keep the connection.
        _ => Step::ProtocolError(Vec::new()),
    }
}

/// SUBSCRIBE: packet identifier then topic filters; answered with one
/// granted QoS 0 (spec D5 `90 03 <pid> 00`).
fn subscribe(body: &[u8]) -> Step {
    match u16_at(body, 0) {
        Some(pid) => {
            let [hi, lo] = pid.to_be_bytes();
            Step::Reply(vec![0x90, 0x03, hi, lo, 0x00])
        }
        None => Step::Fault(Vec::new()),
    }
}

impl Speaker for Mqtt {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        let Some(&first) = buf.first() else {
            return Parsed::Incomplete;
        };
        let (remaining, header_len) = match remaining_length(buf) {
            Varint::Incomplete => return Parsed::Incomplete,
            Varint::FifthByte => {
                return Parsed::Message {
                    consumed: MAX_HEADER,
                    verb: None,
                    step: mode_bug(mode, Vec::new()),
                }
            }
            Varint::Done { len, bytes } => (len, 1 + bytes),
        };
        if remaining > MAX_REMAINING {
            return Parsed::Message {
                consumed: header_len,
                verb: None,
                step: mode_bug(mode, Vec::new()),
            };
        }
        let total = header_len + remaining;
        let flags = first & 0x0F;
        let Some(kind) = PacketType::from_nibble(first >> 4) else {
            return Parsed::Message {
                consumed: total.min(buf.len()),
                verb: None,
                step: Step::Fault(Vec::new()),
            };
        };
        let verb = Some(kind.verb().to_string());
        if !kind.flags_ok(flags) {
            return Parsed::Message {
                consumed: total.min(buf.len()),
                verb,
                step: Step::Fault(Vec::new()),
            };
        }
        if buf.len() < total {
            return Parsed::Incomplete;
        }
        let body = &buf[header_len..total];
        let step = match kind {
            PacketType::Connect => Step::Reply(vec![0x20, 0x02, 0x00, 0x00]),
            PacketType::Publish => publish(flags, body),
            PacketType::Subscribe => subscribe(body),
            PacketType::Pingreq => Step::Reply(vec![0xD0, 0x00]),
            PacketType::Disconnect => Step::Close(None),
            // Well-formed packets this responder does not serve (QoS 2 flow,
            // UNSUBSCRIBE, server-only types): no reply, keep the connection.
            _ => Step::ProtocolError(Vec::new()),
        };
        Parsed::Message {
            consumed: total,
            verb,
            step,
        }
    }

    fn on_idle(&mut self, mode: SeedMode, _buf: &[u8]) -> Step {
        // A packet that never completed (or outgrew the buffer) is the bug.
        mode_bug(mode, Vec::new())
    }

    fn max_buffer(&self) -> usize {
        MAX_REMAINING + MAX_HEADER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{Parsed, Proto, Speaker, Step};
    use crate::SeedMode;

    fn parse(mode: SeedMode, bytes: &[u8]) -> Parsed {
        Mqtt.parse(mode, bytes)
    }

    fn msg(consumed: usize, verb: &str, step: Step) -> Parsed {
        Parsed::Message {
            consumed,
            verb: Some(verb.to_string()),
            step,
        }
    }

    #[test]
    fn def_names_the_service() {
        assert_eq!(DEF.name, "l4-mqtt");
        assert_eq!(DEF.grammar, "mqtt");
        assert_eq!(DEF.proto, Proto::Tcp);
        let mut s = (DEF.new_conn)();
        assert_eq!(s.name(), "l4-mqtt");
        assert_eq!(s.banner(), None);
        assert_eq!(s.max_buffer(), 65_541);
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &[0xC0, 0x00]),
            msg(2, "PINGREQ", Step::Reply(vec![0xD0, 0x00]))
        );
    }

    #[test]
    fn connect_connack() {
        let connect = [
            0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
        ];
        let want = msg(14, "CONNECT", Step::Reply(vec![0x20, 0x02, 0x00, 0x00]));
        assert_eq!(parse(SeedMode::Vulnerable, &connect), want);
        assert_eq!(parse(SeedMode::Patched, &connect), want);
    }

    #[test]
    fn connect_with_flags_is_a_fault() {
        let bad = [
            0x11, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &bad),
            msg(14, "CONNECT", Step::Fault(vec![]))
        );
    }

    #[test]
    fn pingreq() {
        let want = msg(2, "PINGREQ", Step::Reply(vec![0xD0, 0x00]));
        assert_eq!(parse(SeedMode::Vulnerable, &[0xC0, 0x00]), want);
        assert_eq!(parse(SeedMode::Patched, &[0xC0, 0x00]), want);
    }

    #[test]
    fn publish_qos1_puback() {
        let publish = [
            0x32, 0x09, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x00, 0x01, 0x68, 0x69,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &publish),
            msg(11, "PUBLISH", Step::Reply(vec![0x40, 0x02, 0x00, 0x01]))
        );
    }

    #[test]
    fn plan_literal_with_remaining_0a_is_one_byte_short() {
        // Pins the corrected PUBLISH literal (remaining length `09`, as the
        // manifest and the live suite now spell it): with `0A` only 9 bytes
        // follow the length byte, so the speaker sees a partial packet (and
        // the bug after a 200 ms idle), never a PUBLISH.
        let as_written = [
            0x32, 0x0A, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x00, 0x01, 0x68, 0x69,
        ];
        assert_eq!(parse(SeedMode::Vulnerable, &as_written), Parsed::Incomplete);
    }

    #[test]
    fn publish_qos0_silent() {
        let publish = [0x30, 0x07, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x68, 0x69];
        assert_eq!(
            parse(SeedMode::Vulnerable, &publish),
            msg(9, "PUBLISH", Step::Reply(vec![]))
        );
    }

    #[test]
    fn publish_retain_denylisted() {
        let publish = [0x31, 0x07, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x68, 0x69];
        let want = msg(9, "PUBLISH", Step::Denylisted(vec![]));
        assert_eq!(parse(SeedMode::Vulnerable, &publish), want);
        assert_eq!(parse(SeedMode::Patched, &publish), want);
    }

    #[test]
    fn publish_qos2_is_a_protocol_error_and_keeps_the_connection() {
        let publish = [
            0x34, 0x09, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x00, 0x01, 0x68, 0x69,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, &publish),
            msg(11, "PUBLISH", Step::ProtocolError(vec![]))
        );
    }

    #[test]
    fn publish_qos3_is_a_fault() {
        let publish = [0x36, 0x07, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x68, 0x69];
        assert_eq!(
            parse(SeedMode::Vulnerable, &publish),
            msg(9, "PUBLISH", Step::Fault(vec![]))
        );
    }

    #[test]
    fn publish_qos1_too_short_for_its_packet_id_is_a_fault() {
        // remaining 4: topic len 3 "a/b", no room for the packet id.
        let publish = [0x32, 0x05, 0x00, 0x03, 0x61, 0x2F, 0x62];
        assert_eq!(
            parse(SeedMode::Vulnerable, &publish),
            msg(7, "PUBLISH", Step::Fault(vec![]))
        );
    }

    #[test]
    fn subscribe_suback() {
        // pid 00 05, one filter "a/#" at QoS 0.
        let subscribe = [0x82, 0x08, 0x00, 0x05, 0x00, 0x03, 0x61, 0x2F, 0x23, 0x00];
        assert_eq!(
            parse(SeedMode::Vulnerable, &subscribe),
            msg(
                10,
                "SUBSCRIBE",
                Step::Reply(vec![0x90, 0x03, 0x00, 0x05, 0x00])
            )
        );
        // SUBSCRIBE's reserved flags must be 0010.
        let bad_flags = [0x80, 0x08, 0x00, 0x05, 0x00, 0x03, 0x61, 0x2F, 0x23, 0x00];
        assert_eq!(
            parse(SeedMode::Vulnerable, &bad_flags),
            msg(10, "SUBSCRIBE", Step::Fault(vec![]))
        );
    }

    #[test]
    fn disconnect_closes() {
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0xE0, 0x00]),
            msg(2, "DISCONNECT", Step::Close(None))
        );
    }

    #[test]
    fn reserved_types_are_faults_without_bytes() {
        for first in [0x00u8, 0xF0] {
            assert_eq!(
                parse(SeedMode::Vulnerable, &[first, 0x00]),
                Parsed::Message {
                    consumed: 2,
                    verb: None,
                    step: Step::Fault(vec![]),
                },
                "type {:#x}",
                first >> 4
            );
            assert_eq!(
                parse(SeedMode::Patched, &[first, 0x00]),
                Parsed::Message {
                    consumed: 2,
                    verb: None,
                    step: Step::Fault(vec![]),
                }
            );
        }
    }

    #[test]
    fn server_only_type_from_a_client_is_a_protocol_error() {
        // PINGRESP (13) is only ever sent by the server.
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0xD0, 0x00]),
            msg(2, "PINGRESP", Step::ProtocolError(vec![]))
        );
    }

    #[test]
    fn five_byte_varint_is_the_bug() {
        let bug = [0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(
            parse(SeedMode::Vulnerable, &bug),
            Parsed::Message {
                consumed: 5,
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, &bug),
            Parsed::Message {
                consumed: 5,
                verb: None,
                step: Step::Fault(vec![]),
            }
        );
    }

    #[test]
    fn remaining_over_cap() {
        // 0x0FFF_FFFF, far over MAX_REMAINING.
        let bug = [0x30, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(
            parse(SeedMode::Vulnerable, &bug),
            Parsed::Message {
                consumed: 5,
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, &bug),
            Parsed::Message {
                consumed: 5,
                verb: None,
                step: Step::Fault(vec![]),
            }
        );
        // 65 537 = 0x10001 -> varint 81 80 04: one over the cap.
        let one_over = [0x30, 0x81, 0x80, 0x04];
        assert_eq!(
            parse(SeedMode::Vulnerable, &one_over),
            Parsed::Message {
                consumed: 4,
                verb: None,
                step: Step::Trigger,
            }
        );
        // 65 536 = 0x10000 -> varint 80 80 04: exactly the cap, not the bug.
        let at_cap = [0x30, 0x80, 0x80, 0x04];
        assert_eq!(parse(SeedMode::Vulnerable, &at_cap), Parsed::Incomplete);
    }

    #[test]
    fn partial_packets_are_incomplete_and_idle_is_the_bug() {
        assert_eq!(parse(SeedMode::Vulnerable, &[]), Parsed::Incomplete);
        assert_eq!(parse(SeedMode::Vulnerable, &[0x10]), Parsed::Incomplete);
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0x30, 0x80]),
            Parsed::Incomplete
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0x30, 0x08, 0x00, 0x03]),
            Parsed::Incomplete
        );
        let mut s = Mqtt;
        assert_eq!(
            s.on_idle(SeedMode::Vulnerable, &[0x30, 0x08, 0x00, 0x03]),
            Step::Trigger
        );
        assert_eq!(
            s.on_idle(SeedMode::Patched, &[0x30, 0x08, 0x00, 0x03]),
            Step::Fault(vec![])
        );
    }

    #[test]
    fn consumed_leaves_pipelined_bytes_for_the_next_call() {
        let two = [0xC0, 0x00, 0xE0, 0x00];
        let Parsed::Message { consumed, .. } = parse(SeedMode::Vulnerable, &two) else {
            panic!("first packet should parse");
        };
        assert_eq!(consumed, 2);
        assert_eq!(
            parse(SeedMode::Vulnerable, &two[consumed..]),
            msg(2, "DISCONNECT", Step::Close(None))
        );
    }
}
