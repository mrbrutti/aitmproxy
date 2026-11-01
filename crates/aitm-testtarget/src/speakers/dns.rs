//! Speaker `l4-dns-fault`: a minimal DNS-over-UDP responder (spec D5).
//!
//! One datagram is one message. The header is parsed, then exactly one
//! question (uncompressed labels, QTYPE, QCLASS). An A query is answered with
//! `127.0.0.1` (TTL 60) and the question echoed; any other QTYPE is NOTIMP
//! (RCODE 4); QDCOUNT != 1, a truncated header or question, or a compression
//! pointer in the name is FORMERR (RCODE 1).
//!
//! The deliberate bug: a label length byte that reaches **past the end of the
//! datagram**. A careful parser answers FORMERR; the Vulnerable origin crashes
//! ([`Step::Trigger`]), the Patched control answers FORMERR and closes
//! ([`Step::Fault`]) via [`mode_bug`].

// consumed by A19 (the driver registers `DEF`).

use super::{mode_bug, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// The service as the driver registers it.
pub static DEF: ServiceDef = ServiceDef {
    name: "l4-dns-fault",
    grammar: "dns",
    proto: Proto::Udp,
    new_conn: || Box::new(Dns),
};

/// Largest datagram the speaker looks at (classic DNS-over-UDP payload).
pub const MAX_DATAGRAM: usize = 512;

/// DNS header length.
const HEADER_LEN: usize = 12;
/// QTYPE + QCLASS.
const QFIXED_LEN: usize = 4;
/// QTYPE A.
const QTYPE_A: u16 = 1;
/// Response flags: QR, RD, RA, RCODE 0.
const FLAGS_NOERROR: [u8; 2] = [0x81, 0x80];
/// Response flags: QR, RD, RA, RCODE 1 (FORMERR).
const FLAGS_FORMERR: [u8; 2] = [0x81, 0x81];
/// Response flags: QR, RD, RA, RCODE 4 (NOTIMP).
const FLAGS_NOTIMP: [u8; 2] = [0x81, 0x84];
/// The one answer RR: pointer to the question name, A, IN, TTL 60,
/// RDLENGTH 4, 127.0.0.1.
const ANSWER_RR: [u8; 16] = [
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01,
];

/// The stateless DNS speaker (UDP: one instance per service).
pub struct Dns;

/// FORMERR reply: `id`, flags `81 81`, all four counts zero.
pub fn formerr(id: u16) -> Vec<u8> {
    error_reply(id, FLAGS_FORMERR)
}

/// NOTIMP reply: `id`, flags `81 84`, all four counts zero.
pub fn notimp(id: u16) -> Vec<u8> {
    error_reply(id, FLAGS_NOTIMP)
}

fn error_reply(id: u16, flags: [u8; 2]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags);
    out.extend_from_slice(&[0u8; 8]);
    out
}

/// The A answer: `id`, flags `81 80`, QD 1, AN 1, NS 0, AR 0, the question
/// echoed, then [`ANSWER_RR`].
pub fn answer(id: u16, question: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + question.len() + ANSWER_RR.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAGS_NOERROR);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(question);
    out.extend_from_slice(&ANSWER_RR);
    out
}

/// What one datagram parsed to.
enum Query<'a> {
    /// A well-formed question: its QTYPE and the raw question bytes.
    Question { qtype: u16, question: &'a [u8] },
    /// Malformed in a way a careful parser rejects.
    Malformed,
    /// The deliberate bug: a label length past the datagram end.
    LabelPastEnd,
}

/// The id, or `0` when fewer than two bytes arrived.
fn id_of(buf: &[u8]) -> u16 {
    match buf {
        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
        _ => 0,
    }
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let hi = *buf.get(at)?;
    let lo = *buf.get(at + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Parse the header and the single question of `buf`.
fn parse_query(buf: &[u8]) -> Query<'_> {
    if buf.len() < HEADER_LEN {
        return Query::Malformed;
    }
    if read_u16(buf, 4) != Some(1) {
        return Query::Malformed;
    }
    let mut pos = HEADER_LEN;
    loop {
        let Some(&len) = buf.get(pos) else {
            // The name never terminated inside the datagram.
            return Query::Malformed;
        };
        pos += 1;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            // Compression pointers are not accepted in a question.
            return Query::Malformed;
        }
        let len = usize::from(len);
        if pos + len > buf.len() {
            return Query::LabelPastEnd;
        }
        pos += len;
    }
    let Some(qtype) = read_u16(buf, pos) else {
        return Query::Malformed;
    };
    if pos + QFIXED_LEN > buf.len() {
        return Query::Malformed;
    }
    Query::Question {
        qtype,
        question: &buf[HEADER_LEN..pos + QFIXED_LEN],
    }
}

impl Speaker for Dns {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        if buf.is_empty() {
            return Parsed::Incomplete;
        }
        let id = id_of(buf);
        let (verb, step) = match parse_query(buf) {
            Query::Question { qtype, question } if qtype == QTYPE_A => {
                (Some("A".to_string()), Step::Reply(answer(id, question)))
            }
            Query::Question { qtype, .. } => (
                Some(format!("qtype{qtype}")),
                Step::ProtocolError(notimp(id)),
            ),
            Query::Malformed => (None, Step::ProtocolError(formerr(id))),
            Query::LabelPastEnd => (None, mode_bug(mode, formerr(id))),
        };
        Parsed::Message {
            consumed: buf.len(),
            verb,
            step,
        }
    }

    fn on_idle(&mut self, _mode: SeedMode, _buf: &[u8]) -> Step {
        Step::Close(None)
    }

    fn max_buffer(&self) -> usize {
        MAX_DATAGRAM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec D5: the A query for `example.test`, id `0x1234`.
    const EXAMPLE_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't',
        0x00, // name
        0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
    ];

    fn parse(mode: SeedMode, buf: &[u8]) -> Parsed {
        let mut s = (DEF.new_conn)();
        assert_eq!(s.name(), "l4-dns-fault");
        s.parse(mode, buf)
    }

    #[test]
    fn answers_a_query() {
        let expected: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01,
            0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
            0x7f, 0x00, 0x00, 0x01,
        ];
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(
                parse(mode, EXAMPLE_QUERY),
                Parsed::Message {
                    consumed: EXAMPLE_QUERY.len(),
                    verb: Some("A".to_string()),
                    step: Step::Reply(expected.clone()),
                }
            );
        }
        assert_eq!(DEF.grammar, "dns");
        assert_eq!(DEF.proto, Proto::Udp);
    }

    #[test]
    fn liveness_root_query() {
        let query: &[u8] = &[
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        match parse(SeedMode::Vulnerable, query) {
            Parsed::Message {
                consumed,
                verb,
                step: Step::Reply(bytes),
            } => {
                assert_eq!(consumed, query.len());
                assert_eq!(verb.as_deref(), Some("A"));
                assert_eq!(&bytes[..2], &[0x00, 0x01]);
                assert_eq!(&bytes[2..4], &[0x81, 0x80]);
                assert_eq!(&bytes[bytes.len() - 4..], &[0x7f, 0x00, 0x00, 0x01]);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }

    #[test]
    fn label_past_end_is_the_fault() {
        // Header (id 0x1234, QDCOUNT 1) then a label claiming 63 bytes with 2 present.
        let bad: &[u8] = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x61,
            0x62,
        ];
        assert_eq!(
            parse(SeedMode::Vulnerable, bad),
            Parsed::Message {
                consumed: bad.len(),
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, bad),
            Parsed::Message {
                consumed: bad.len(),
                verb: None,
                step: Step::Fault(vec![
                    0x12, 0x34, 0x81, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ]),
            }
        );
        assert_eq!(
            formerr(0x1234),
            vec![0x12, 0x34, 0x81, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn non_a_is_notimp() {
        let mut aaaa = EXAMPLE_QUERY.to_vec();
        let n = aaaa.len();
        aaaa[n - 3] = 28; // QTYPE 28 (AAAA)
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            match parse(mode, &aaaa) {
                Parsed::Message {
                    consumed,
                    verb,
                    step: Step::ProtocolError(bytes),
                } => {
                    assert_eq!(consumed, aaaa.len());
                    assert_eq!(verb.as_deref(), Some("qtype28"));
                    assert_eq!(&bytes[..2], &[0x12, 0x34]);
                    assert_eq!(bytes[3] & 0x0f, 4, "RCODE must be NOTIMP");
                    assert_eq!(bytes.len(), 12);
                }
                other => panic!("expected ProtocolError, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_is_a_protocol_error_not_a_crash() {
        // Truncated header: id present, nothing else -> FORMERR with the id.
        let short: &[u8] = &[0x12, 0x34, 0x01];
        assert_eq!(
            parse(SeedMode::Vulnerable, short),
            Parsed::Message {
                consumed: 3,
                verb: None,
                step: Step::ProtocolError(formerr(0x1234)),
            }
        );
        // One byte: no id -> FORMERR with id 0.
        assert_eq!(
            parse(SeedMode::Vulnerable, &[0x12]),
            Parsed::Message {
                consumed: 1,
                verb: None,
                step: Step::ProtocolError(formerr(0)),
            }
        );
        // QDCOUNT 2 -> FORMERR.
        let mut two = EXAMPLE_QUERY.to_vec();
        two[5] = 2;
        assert_eq!(
            parse(SeedMode::Vulnerable, &two),
            Parsed::Message {
                consumed: two.len(),
                verb: None,
                step: Step::ProtocolError(formerr(0x1234)),
            }
        );
        // A compression pointer in the question -> FORMERR, never the fault.
        let mut ptr = EXAMPLE_QUERY[..12].to_vec();
        ptr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(
            parse(SeedMode::Vulnerable, &ptr),
            Parsed::Message {
                consumed: ptr.len(),
                verb: None,
                step: Step::ProtocolError(formerr(0x1234)),
            }
        );
        // Name ends but QTYPE/QCLASS are missing -> FORMERR.
        let mut cut = EXAMPLE_QUERY.to_vec();
        cut.truncate(cut.len() - 2);
        assert_eq!(
            parse(SeedMode::Vulnerable, &cut),
            Parsed::Message {
                consumed: cut.len(),
                verb: None,
                step: Step::ProtocolError(formerr(0x1234)),
            }
        );
        // Empty buffer: nothing to parse yet.
        assert_eq!(parse(SeedMode::Vulnerable, &[]), Parsed::Incomplete);
        // Idle and size bounds.
        let mut s = (DEF.new_conn)();
        assert_eq!(s.max_buffer(), 512);
        assert_eq!(s.on_idle(SeedMode::Vulnerable, b"\x12"), Step::Close(None));
        assert_eq!(s.banner(), None);
    }
}
