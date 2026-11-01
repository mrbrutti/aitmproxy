//! The per-grammar denylist: the destructive commands the lane never sends
//! (spec S3, "Denylist semantics").
//!
//! [`refuses`] is a pure function of the grammar and the rendered bytes of the
//! message about to be written. It takes **no** profile, config key, flag or
//! confirmation, so there is nothing an operator, a profile or a future caller
//! can set to make a destructive command sendable; `host.rs` calls it
//! unconditionally before every write, preludes included. A refused case is
//! skipped and counted, never sent and never retried.
//!
//! Text grammars (RESP, memcached, SMTP, FTP) match their verb list
//! case-insensitively at token boundaries over the **whole** buffer, so one bad
//! command in a pipelined or element-repeated message refuses the message as a
//! whole; RESP additionally decodes the first bulk string of every array.
//! Binary grammars (Modbus, MQTT, DNS) decode the command field out of the
//! rendered bytes rather than the tree, so a byte-level mutation that lands on
//! a denylisted value is caught too. Over-blocking (a memcached key that
//! contains `flush_all`) is accepted; under-blocking is not. `tlv` and `raw`
//! have no command vocabulary and therefore no denylist.

use std::net::IpAddr;

use crate::spec::GrammarKind;

// ---------------------------------------------------------------------------
// The lists
// ---------------------------------------------------------------------------

/// Redis commands that destroy data, reconfigure the server, run code, change
/// replication or evict a client (spec S3 row 2).
const RESP: &[&str] = &[
    "FLUSHALL",
    "FLUSHDB",
    "SHUTDOWN",
    "CONFIG",
    "DEBUG",
    "SAVE",
    "BGSAVE",
    "BGREWRITEAOF",
    "SLAVEOF",
    "REPLICAOF",
    "MIGRATE",
    "RESTORE",
    "SCRIPT",
    "EVAL",
    "EVALSHA",
    "FUNCTION",
    "FCALL",
    "ACL",
    "CLUSTER",
    "FAILOVER",
    "MODULE",
    "SYNC",
    "PSYNC",
    "SWAPDB",
    "DEL",
    "UNLINK",
    "RENAME",
    "RENAMENX",
    "MONITOR",
    "CLIENT",
    "KILL",
];

/// memcached commands that flush, reconfigure or stop the server, plus the two
/// meta debug commands (spec S3 row 3).
const MEMCACHED: &[&str] = &[
    "flush_all",
    "shutdown",
    "slabs",
    "lru",
    "lru_crawler",
    "cache_memlimit",
    "watch",
    "verbosity",
    "misbehave",
    "me",
    "mn",
];

/// SMTP verbs that open a message body, trigger a queue run or authenticate,
/// plus `RCPT`, which is refused unless [`smtp_rcpt_allowed`] says the address
/// is the target's own (spec S3 row 7).
const SMTP: &[&str] = &["DATA", "BDAT", "ETRN", "TURN", "ATRN", "AUTH", "RCPT"];

/// FTP verbs that write, delete, rename or open a data channel, and the ones
/// that make the server connect out (spec S3 row 8).
const FTP: &[&str] = &[
    "DELE", "STOR", "STOU", "APPE", "RMD", "RNFR", "RNTO", "MKD", "SITE", "PORT", "EPRT", "PASV",
    "EPSV", "RETR", "LIST", "NLST", "MLSD", "MLST",
];

/// The Modbus function codes that write, reset or diagnose: write single coil
/// and register, diagnostics, write multiple coils and registers, write file
/// record, mask write, read/write multiple (spec S3 row 5).
const MODBUS_FC: &[(u8, &str)] = &[
    (5, "fc 5"),
    (6, "fc 6"),
    (8, "fc 8"),
    (15, "fc 15"),
    (16, "fc 16"),
    (21, "fc 21"),
    (22, "fc 22"),
    (23, "fc 23"),
];

/// Nothing the lane knows about the target can lift a denylist entry; it can
/// only decide whether an SMTP `RCPT` addresses the target itself rather than
/// relaying through it (spec S3 row 7). Everything else ignores it.
#[derive(Debug, Clone, Copy)]
pub struct DenyContext<'a> {
    /// The address the lane is connected to.
    pub target_ip: IpAddr,
    /// The hostname the server announced in its 220 banner, when one was read.
    pub banner_host: Option<&'a str>,
}

/// The text verbs this grammar refuses, for tests and for the documentation
/// that lists them. Binary grammars and the two grammars without a command
/// vocabulary return an empty slice; their rules live in [`refuses`].
#[must_use]
pub fn verbs(kind: GrammarKind) -> &'static [&'static str] {
    match kind {
        GrammarKind::Resp => RESP,
        GrammarKind::Memcached => MEMCACHED,
        GrammarKind::Smtp => SMTP,
        GrammarKind::Ftp => FTP,
        GrammarKind::Tlv
        | GrammarKind::Dns
        | GrammarKind::Modbus
        | GrammarKind::Mqtt
        | GrammarKind::Raw => &[],
    }
}

/// The destructive command in `rendered`, if there is one: the message must
/// not be written.
///
/// Takes the grammar and the bytes, and nothing else. With no context, every
/// SMTP `RCPT` is refused, because without the target's address and banner
/// there is no way to tell a recipient on the target itself from a relay.
#[must_use]
pub fn refuses(kind: GrammarKind, rendered: &[u8]) -> Option<&'static str> {
    decide(kind, rendered, None)
}

/// [`refuses`], with what the host knows about the target. The context relaxes
/// exactly one rule — SMTP `RCPT` to the target's own address literal,
/// `localhost` or its banner hostname — and no other.
#[must_use]
pub fn refuses_with_context(
    kind: GrammarKind,
    rendered: &[u8],
    ctx: &DenyContext<'_>,
) -> Option<&'static str> {
    decide(kind, rendered, Some(ctx))
}

fn decide(
    kind: GrammarKind,
    rendered: &[u8],
    ctx: Option<&DenyContext<'_>>,
) -> Option<&'static str> {
    match kind {
        GrammarKind::Tlv | GrammarKind::Raw => None,
        GrammarKind::Resp => text_verb(RESP, rendered).or_else(|| resp_bulk_verb(rendered)),
        GrammarKind::Memcached => text_verb(MEMCACHED, rendered),
        GrammarKind::Ftp => text_verb(FTP, rendered),
        GrammarKind::Smtp => smtp(rendered, ctx),
        GrammarKind::Modbus => modbus(rendered),
        GrammarKind::Mqtt => mqtt(rendered),
        GrammarKind::Dns => dns(rendered),
    }
}

// ---------------------------------------------------------------------------
// Text grammars
// ---------------------------------------------------------------------------

/// A byte that is part of a word. `-` deliberately is not one, so `lru-crawler`
/// still trips `lru`: over-blocking is accepted, missing a command is not.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `needle` appears in `hay` as a whole word, ignoring ASCII case.
fn contains_token(hay: &[u8], needle: &str) -> bool {
    token_positions(hay, needle).next().is_some()
}

/// Every offset at which `needle` appears in `hay` as a whole word.
fn token_positions<'a>(hay: &'a [u8], needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    let n = needle.as_bytes();
    let windows = if n.is_empty() {
        0
    } else {
        hay.len().checked_sub(n.len()).map_or(0, |last| last + 1)
    };
    (0..windows).filter(move |&i| {
        hay[i..i + n.len()].eq_ignore_ascii_case(n)
            && !(i > 0 && is_token_byte(hay[i - 1]))
            && !hay.get(i + n.len()).copied().is_some_and(is_token_byte)
    })
}

/// The first listed verb that appears as a whole word anywhere in the buffer.
fn text_verb(list: &'static [&'static str], rendered: &[u8]) -> Option<&'static str> {
    list.iter()
        .copied()
        .find(|verb| contains_token(rendered, verb))
}

/// The command of every `*N\r\n$M\r\n<cmd>` array in the buffer, checked
/// against the RESP list. The token scan already catches a well-formed array;
/// this catches a bulk string whose declared length hides the word boundary
/// (`*1\r\n$8\r\nFLUSHALLxx`).
fn resp_bulk_verb(rendered: &[u8]) -> Option<&'static str> {
    for (start, _) in rendered.iter().enumerate().filter(|(_, b)| **b == b'*') {
        let Some(after_count) = skip_decimal_line(rendered, start + 1) else {
            continue;
        };
        if rendered.get(after_count) != Some(&b'$') {
            continue;
        }
        let Some((len, after_len)) = read_decimal(rendered, after_count + 1) else {
            continue;
        };
        let Some(after_crlf) = skip_crlf(rendered, after_len) else {
            continue;
        };
        let end = after_crlf.saturating_add(len);
        let Some(cmd) = rendered.get(after_crlf..end.min(rendered.len())) else {
            continue;
        };
        if let Some(verb) = RESP
            .iter()
            .copied()
            .find(|verb| cmd.eq_ignore_ascii_case(verb.as_bytes()))
        {
            return Some(verb);
        }
    }
    None
}

/// Read ASCII digits at `at`, returning the value and the offset after them.
fn read_decimal(buf: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    let mut end = at;
    while let Some(digit) = buf.get(end).and_then(|b| (*b as char).to_digit(10)) {
        value = value.checked_mul(10)?.checked_add(digit as usize)?;
        end += 1;
        if end - at > 10 {
            return None;
        }
    }
    (end > at).then_some((value, end))
}

fn skip_crlf(buf: &[u8], at: usize) -> Option<usize> {
    (buf.get(at) == Some(&b'\r') && buf.get(at + 1) == Some(&b'\n')).then_some(at + 2)
}

fn skip_decimal_line(buf: &[u8], at: usize) -> Option<usize> {
    let (_, end) = read_decimal(buf, at)?;
    skip_crlf(buf, end)
}

// ---------------------------------------------------------------------------
// SMTP
// ---------------------------------------------------------------------------

fn smtp(rendered: &[u8], ctx: Option<&DenyContext<'_>>) -> Option<&'static str> {
    for verb in SMTP {
        if *verb == "RCPT" {
            if rcpt_refused(rendered, ctx) {
                return Some("RCPT");
            }
            continue;
        }
        if contains_token(rendered, verb) {
            return Some(verb);
        }
    }
    None
}

/// Whether any `RCPT` in the buffer addresses somewhere other than the target.
/// Without a context there is nothing to compare against, so any `RCPT` at all
/// is refused.
fn rcpt_refused(rendered: &[u8], ctx: Option<&DenyContext<'_>>) -> bool {
    for at in token_positions(rendered, "RCPT") {
        let Some(ctx) = ctx else {
            return true;
        };
        let rest = &rendered[at + "RCPT".len()..];
        let line_end = rest
            .iter()
            .position(|b| *b == b'\r' || *b == b'\n')
            .unwrap_or(rest.len());
        if !smtp_rcpt_allowed(&rest[..line_end], ctx.target_ip, ctx.banner_host) {
            return true;
        }
    }
    false
}

/// Whether an SMTP `RCPT` argument (everything after the verb, up to the end of
/// the line) addresses the target itself rather than relaying through it: the
/// domain must be the target's IP as an address literal (`[127.0.0.1]`),
/// `localhost`, or the hostname the server announced in its banner. Anything
/// else — including a domain the lane cannot find — is not allowed.
#[must_use]
pub fn smtp_rcpt_allowed(arg: &[u8], target_ip: IpAddr, banner_host: Option<&str>) -> bool {
    let Some(at) = arg.iter().rposition(|b| *b == b'@') else {
        return false;
    };
    let rest = &arg[at + 1..];
    let end = rest
        .iter()
        .position(|b| *b == b'>' || b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    let Ok(domain) = std::str::from_utf8(&rest[..end]) else {
        return false;
    };
    if domain.is_empty() {
        return false;
    }
    if domain.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if domain.eq_ignore_ascii_case(&format!("[{target_ip}]")) {
        return true;
    }
    banner_host.is_some_and(|host| domain.eq_ignore_ascii_case(host))
}

// ---------------------------------------------------------------------------
// Binary grammars
// ---------------------------------------------------------------------------

/// Byte 7 of an MBAP-framed message is the function code (spec S2's example:
/// 6 header bytes, unit id, then the PDU).
fn modbus(rendered: &[u8]) -> Option<&'static str> {
    let function = *rendered.get(7)?;
    MODBUS_FC
        .iter()
        .find(|(code, _)| *code == function)
        .map(|(_, name)| *name)
}

/// The MQTT rules, decoded from the fixed header out: a PUBLISH with the retain
/// bit, a PUBLISH to a `$` topic, a CONNECT with will-retain.
fn mqtt(rendered: &[u8]) -> Option<&'static str> {
    let first = *rendered.first()?;
    let packet_type = first >> 4;
    let flags = first & 0x0f;

    // The retain bit is in the first byte, so a truncated PUBLISH is caught too.
    if packet_type == 3 && flags & 0x01 != 0 {
        return Some("publish retain");
    }

    let after_length = mqtt_remaining_length(rendered, 1)?;
    match packet_type {
        // PUBLISH: the variable header starts with the topic.
        3 => {
            let topic = mqtt_string(rendered, after_length)?.0;
            (topic.first() == Some(&b'$')).then_some("publish $topic")
        }
        // CONNECT: protocol name, level, then the connect flags.
        1 => {
            let (_, after_name) = mqtt_string(rendered, after_length)?;
            let connect_flags = *rendered.get(after_name + 1)?;
            (connect_flags & 0x20 != 0).then_some("connect will-retain")
        }
        _ => None,
    }
}

/// Skip MQTT's 7-bit continuation-encoded remaining length, returning the
/// offset of the variable header.
fn mqtt_remaining_length(buf: &[u8], at: usize) -> Option<usize> {
    let mut end = at;
    for _ in 0..4 {
        let byte = *buf.get(end)?;
        end += 1;
        if byte & 0x80 == 0 {
            return Some(end);
        }
    }
    None
}

/// An MQTT UTF-8 string: a big-endian u16 length and that many bytes. Returns
/// the bytes and the offset after them.
fn mqtt_string(buf: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let len = usize::from(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]));
    let start = at + 2;
    let end = start.checked_add(len)?;
    Some((buf.get(start..end)?, end))
}

/// The DNS rules: the opcode nibble of header byte 2, and the first question's
/// qtype.
fn dns(rendered: &[u8]) -> Option<&'static str> {
    let opcode = (*rendered.get(2)? >> 3) & 0x0f;
    match opcode {
        4 => return Some("opcode notify"),
        5 => return Some("opcode update"),
        _ => {}
    }
    let qtype = dns_first_qtype(rendered)?;
    match qtype {
        251 => Some("qtype ixfr"),
        252 => Some("qtype axfr"),
        _ => None,
    }
}

/// Walk the first question's name from the end of the 12-byte header and read
/// the qtype that follows it. A compression pointer ends the name in two bytes.
fn dns_first_qtype(buf: &[u8]) -> Option<u16> {
    let mut at = 12;
    loop {
        let len = *buf.get(at)?;
        if len & 0xc0 == 0xc0 {
            at += 2;
            break;
        }
        at += 1;
        if len == 0 {
            break;
        }
        at += usize::from(len);
    }
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The grammars whose denylist is a list of text verbs (spec S3 table).
    const TEXT_GRAMMARS: [GrammarKind; 4] = [
        GrammarKind::Resp,
        GrammarKind::Memcached,
        GrammarKind::Smtp,
        GrammarKind::Ftp,
    ];

    /// `FlUsHaLl`: every other letter upper-cased.
    fn mixed_case(verb: &str) -> String {
        verb.char_indices()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }

    /// `*2\r\n$4\r\nPING\r\n$<n>\r\n<verb>\r\n`.
    fn resp_array(verb: &str) -> Vec<u8> {
        format!("*2\r\n$4\r\nPING\r\n${len}\r\n{verb}\r\n", len = verb.len()).into_bytes()
    }

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn every_listed_verb_is_refused_in_every_case_form() {
        for kind in TEXT_GRAMMARS {
            let listed = verbs(kind);
            assert!(!listed.is_empty(), "{kind} has no denylist");
            for verb in listed {
                let forms: Vec<(&str, Vec<u8>)> = vec![
                    ("exact", verb.as_bytes().to_vec()),
                    ("lowercase", verb.to_ascii_lowercase().into_bytes()),
                    ("mixed case", mixed_case(verb).into_bytes()),
                    ("resp array", resp_array(verb)),
                    ("pipelined", format!("PING\r\n{verb}\r\n").into_bytes()),
                ];
                for (form, bytes) in forms {
                    let hit = refuses(kind, &bytes);
                    let Some(hit) = hit else {
                        panic!("{kind}: {form} of '{verb}' is not refused");
                    };
                    assert!(
                        hit.eq_ignore_ascii_case(verb),
                        "{kind}: {form} of '{verb}' is refused as '{hit}'"
                    );
                }
            }
        }
    }

    #[test]
    fn token_boundaries() {
        // `GET` is not listed at all, so `GETRANGE` is plain text either way.
        assert_eq!(
            refuses(GrammarKind::Resp, b"*3\r\n$8\r\nGETRANGE\r\n"),
            None
        );
        // `DEL` is listed; `DELETE` is a different word.
        assert_eq!(refuses(GrammarKind::Resp, b"DELETE k\r\n"), None);
        assert_eq!(refuses(GrammarKind::Resp, b"DEL k\r\n"), Some("DEL"));
        // memcached: the boundary is the whole word, both ways.
        assert_eq!(refuses(GrammarKind::Memcached, b"get flush_allx\r\n"), None);
        assert_eq!(
            refuses(GrammarKind::Memcached, b"get flush_all\r\n"),
            Some("flush_all")
        );
        // A bulk string the token scan cannot see as a word is still decoded.
        assert_eq!(
            refuses(GrammarKind::Resp, b"*1\r\n$8\r\nFLUSHALLxx"),
            Some("FLUSHALL")
        );
    }

    #[test]
    fn binary_grammars() {
        // Modbus: FC is byte 7 of the MBAP-framed message.
        let write_coil = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x00, 0xff, 0x00,
        ];
        assert_eq!(refuses(GrammarKind::Modbus, &write_coil), Some("fc 5"));
        let read_holding = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(refuses(GrammarKind::Modbus, &read_holding), None);
        assert_eq!(verbs(GrammarKind::Modbus), &[] as &[&str]);

        // MQTT: retain bit, `$` topic, will-retain.
        assert_eq!(
            refuses(GrammarKind::Mqtt, &mqtt_publish(0x31, b"a/b", b"v")),
            Some("publish retain")
        );
        assert_eq!(
            refuses(GrammarKind::Mqtt, &mqtt_publish(0x30, b"$SYS/x", b"v")),
            Some("publish $topic")
        );
        assert_eq!(
            refuses(GrammarKind::Mqtt, &mqtt_publish(0x30, b"a/b", b"v")),
            None
        );
        assert_eq!(
            refuses(GrammarKind::Mqtt, &mqtt_connect(0x20)),
            Some("connect will-retain")
        );
        assert_eq!(refuses(GrammarKind::Mqtt, &mqtt_connect(0x02)), None);

        // DNS: opcode nibble of byte 2, first question's qtype.
        assert_eq!(
            refuses(GrammarKind::Dns, &dns_query(0x28, 1)),
            Some("opcode update")
        );
        assert_eq!(
            refuses(GrammarKind::Dns, &dns_query(0x20, 1)),
            Some("opcode notify")
        );
        assert_eq!(
            refuses(GrammarKind::Dns, &dns_query(0x00, 252)),
            Some("qtype axfr")
        );
        assert_eq!(
            refuses(GrammarKind::Dns, &dns_query(0x00, 251)),
            Some("qtype ixfr")
        );
        assert_eq!(refuses(GrammarKind::Dns, &dns_query(0x00, 1)), None);
    }

    /// `<first byte> <remaining length> <u16 topic len> <topic> <payload>`.
    fn mqtt_publish(first: u8, topic: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut variable = Vec::new();
        let len = u16::try_from(topic.len()).expect("test topic fits in u16");
        variable.extend_from_slice(&len.to_be_bytes());
        variable.extend_from_slice(topic);
        variable.extend_from_slice(payload);
        let mut out = vec![
            first,
            u8::try_from(variable.len()).expect("test message is short"),
        ];
        out.extend_from_slice(&variable);
        out
    }

    /// A CONNECT whose connect-flags byte is `flags`.
    fn mqtt_connect(flags: u8) -> Vec<u8> {
        let mut variable = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, flags, 0x00, 0x3c];
        variable.extend_from_slice(&[0x00, 0x01, b'a']); // client id
        let mut out = vec![
            0x10,
            u8::try_from(variable.len()).expect("test message is short"),
        ];
        out.extend_from_slice(&variable);
        out
    }

    /// A one-question query whose header byte 2 is `byte2` and qtype `qtype`.
    fn dns_query(byte2: u8, qtype: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, byte2, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        out.push(0x03);
        out.extend_from_slice(b"www");
        out.push(0x00);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    #[test]
    fn smtp_rcpt_rule() {
        let ctx = DenyContext {
            target_ip: loopback(),
            banner_host: None,
        };
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"RCPT TO:<a@other.example>\r\n", &ctx),
            Some("RCPT")
        );
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"RCPT TO:<a@[127.0.0.1]>\r\n", &ctx),
            None
        );
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"RCPT TO:<a@localhost>\r\n", &ctx),
            None
        );
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"RCPT TO:<a@mail.test>\r\n", &ctx),
            Some("RCPT")
        );
        let banner = DenyContext {
            target_ip: loopback(),
            banner_host: Some("mail.test"),
        };
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"RCPT TO:<a@mail.test>\r\n", &banner),
            None
        );
        // One bad recipient in a pipelined pair refuses the whole message.
        assert_eq!(
            refuses_with_context(
                GrammarKind::Smtp,
                b"RCPT TO:<a@localhost>\r\nRCPT TO:<a@other.example>\r\n",
                &banner
            ),
            Some("RCPT")
        );
        // Without context every RCPT is refused.
        assert_eq!(
            refuses(GrammarKind::Smtp, b"RCPT TO:<a@[127.0.0.1]>\r\n"),
            Some("RCPT")
        );
        // Context relaxes RCPT and nothing else.
        assert_eq!(
            refuses_with_context(GrammarKind::Smtp, b"DATA\r\n", &ctx),
            Some("DATA")
        );
        assert_eq!(
            refuses_with_context(GrammarKind::Ftp, b"STOR f\r\n", &ctx),
            Some("STOR")
        );

        assert!(smtp_rcpt_allowed(b" TO:<a@localhost>", loopback(), None));
        assert!(smtp_rcpt_allowed(b" TO:<a@[127.0.0.1]>", loopback(), None));
        assert!(!smtp_rcpt_allowed(
            b" TO:<a@other.example>",
            loopback(),
            None
        ));
        assert!(smtp_rcpt_allowed(
            b" TO:<a@mail.test>",
            loopback(),
            Some("MAIL.TEST")
        ));
        // No domain at all is not the target.
        assert!(!smtp_rcpt_allowed(b" TO:<postmaster>", loopback(), None));
    }

    #[test]
    fn tlv_and_raw_have_no_denylist() {
        assert_eq!(refuses(GrammarKind::Tlv, b"FLUSHALL"), None);
        assert_eq!(
            refuses(GrammarKind::Raw, b"FLUSHALL\r\nflush_all\r\nDELE f\r\n"),
            None
        );
        assert_eq!(verbs(GrammarKind::Tlv), &[] as &[&str]);
        assert_eq!(verbs(GrammarKind::Raw), &[] as &[&str]);
    }

    #[test]
    fn signature_has_no_knob() {
        // If `refuses` ever grew a profile, config or confirmation parameter,
        // this assignment would not compile (spec S3, C4).
        let check: fn(GrammarKind, &[u8]) -> Option<&'static str> = refuses;
        assert_eq!(check(GrammarKind::Resp, b"FLUSHALL\r\n"), Some("FLUSHALL"));
    }
}
