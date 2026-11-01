//! `l4-resp`: a minimal Redis-protocol (RESP) responder (spec D5).
//!
//! Parses inline commands (`PING\r\n`) and `*N` arrays of `$len` bulk strings
//! from the buffered bytes. No state is kept between calls: an array is only
//! consumed once it is whole, so the driver re-offers the same prefix until
//! it is. The deliberate bug: a bulk length over [`MAX_BULK`] (or negative)
//! crashes the Vulnerable origin, and so does an array still short of its `N`
//! elements after [`super::IDLE_TIMEOUT`]; the Patched control answers the
//! row's `-ERR Protocol error` and closes. Destructive commands get
//! `-ERR denylisted command` and are logged `denylisted` (spec D5).

use super::{mode_bug, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// The service as the driver's table lists it.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-resp",
    grammar: "resp",
    proto: Proto::Tcp,
    new_conn,
};

/// Largest `$len` accepted; one byte more is the bug (spec D5: 1 MiB).
pub const MAX_BULK: usize = 1_048_576;

/// Commands answered with an error and logged `denylisted` (spec D5).
const DENYLIST: [&[u8]; 6] = [
    b"FLUSHALL",
    b"FLUSHDB",
    b"SHUTDOWN",
    b"CONFIG",
    b"DEBUG",
    b"SAVE",
];

/// Longest command name echoed in `-ERR unknown command '<name>'` and
/// reported as `verb`; a bulk name can be up to [`MAX_BULK`] bytes.
const NAME_ECHO_MAX: usize = 128;

const PONG: &[u8] = b"+PONG\r\n";
const NULL_BULK: &[u8] = b"$-1\r\n";
const OK: &[u8] = b"+OK\r\n";
const DENIED: &[u8] = b"-ERR denylisted command\r\n";
const INVALID_BULK: &[u8] = b"-ERR Protocol error: invalid bulk length\r\n";
const INCOMPLETE_MULTIBULK: &[u8] = b"-ERR Protocol error: incomplete multibulk\r\n";

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Resp)
}

/// One RESP connection. Stateless: see the module docs.
#[derive(Default)]
pub struct Resp;

impl Speaker for Resp {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        match buf.first() {
            None => Parsed::Incomplete,
            Some(b'*') => parse_array(mode, buf),
            Some(_) => parse_inline(buf),
        }
    }

    fn on_idle(&mut self, mode: SeedMode, buf: &[u8]) -> Step {
        if buf.first() == Some(&b'*') {
            // `*N` with fewer than N elements after the idle: the bug.
            mode_bug(mode, INCOMPLETE_MULTIBULK.to_vec())
        } else {
            // A stalled inline line is not a protocol event; just hang up.
            Step::Close(None)
        }
    }

    fn max_buffer(&self) -> usize {
        MAX_BULK + 64
    }
}

/// The first CRLF-terminated line of `buf`: `(line without CRLF, bytes
/// consumed including it)`.
fn line(buf: &[u8]) -> Option<(&[u8], usize)> {
    let cr = buf.windows(2).position(|w| w == b"\r\n")?;
    Some((&buf[..cr], cr + 2))
}

/// A RESP length field (`N` after `*` or `$`).
enum Len {
    Value(i64),
    /// Well-formed digits that do not fit an `i64`: treated as huge.
    Overflow,
    Malformed,
}

fn parse_len(digits: &[u8]) -> Len {
    let body = digits.strip_prefix(b"-").unwrap_or(digits);
    if body.is_empty() || !body.iter().all(u8::is_ascii_digit) {
        return Len::Malformed;
    }
    match std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
    {
        Some(n) => Len::Value(n),
        None => Len::Overflow,
    }
}

fn parse_inline(buf: &[u8]) -> Parsed {
    let Some((line, consumed)) = line(buf) else {
        return Parsed::Incomplete;
    };
    let mut words = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty());
    let Some(name) = words.next() else {
        // An empty inline line is ignored, as redis does.
        return Parsed::Message {
            consumed,
            verb: None,
            step: Step::Reply(Vec::new()),
        };
    };
    let args: Vec<&[u8]> = words.collect();
    let (verb, step) = command(name, &args);
    Parsed::Message {
        consumed,
        verb: Some(verb),
        step,
    }
}

fn parse_array(mode: SeedMode, buf: &[u8]) -> Parsed {
    let Some((header, mut pos)) = line(buf) else {
        return Parsed::Incomplete;
    };
    let count = match parse_len(&header[1..]) {
        Len::Value(n) if n >= 0 => n.unsigned_abs() as usize,
        // Too many to ever arrive: stays incomplete until the idle trigger.
        Len::Overflow => usize::MAX,
        // A negative or garbled count desynchronises the stream: close.
        Len::Value(_) | Len::Malformed => {
            return Parsed::Message {
                consumed: pos,
                verb: None,
                step: Step::Fault(Vec::new()),
            }
        }
    };
    let mut elems: Vec<&[u8]> = Vec::new();
    while elems.len() < count {
        let Some((l, n)) = line(&buf[pos..]) else {
            return Parsed::Incomplete;
        };
        let after_header = pos + n;
        let Some(digits) = l.strip_prefix(b"$") else {
            // Clients only send arrays of bulk strings.
            return Parsed::Message {
                consumed: after_header,
                verb: None,
                step: Step::Fault(Vec::new()),
            };
        };
        let len = match parse_len(digits) {
            Len::Value(len) if (0..=MAX_BULK as i64).contains(&len) => len.unsigned_abs() as usize,
            // Negative or over the cap: the deliberate bug.
            Len::Value(_) | Len::Overflow => {
                return Parsed::Message {
                    consumed: after_header,
                    verb: None,
                    step: mode_bug(mode, INVALID_BULK.to_vec()),
                };
            }
            Len::Malformed => {
                return Parsed::Message {
                    consumed: after_header,
                    verb: None,
                    step: Step::Fault(INVALID_BULK.to_vec()),
                };
            }
        };
        pos = after_header;
        let end = pos + len;
        if buf.len() < end + 2 {
            return Parsed::Incomplete;
        }
        elems.push(&buf[pos..end]);
        // Like redis, the two bytes after the data are skipped unchecked.
        pos = end + 2;
    }
    let Some((name, args)) = elems.split_first() else {
        // `*0` carries no command and is ignored.
        return Parsed::Message {
            consumed: pos,
            verb: None,
            step: Step::Reply(Vec::new()),
        };
    };
    let (verb, step) = command(name, args);
    Parsed::Message {
        consumed: pos,
        verb: Some(verb),
        step,
    }
}

/// Dispatch one command: `(verb as logged, step)`.
fn command(name: &[u8], args: &[&[u8]]) -> (String, Step) {
    let typed = printable_name(name);
    let verb = typed.to_ascii_uppercase();
    let is = |cmd: &[u8]| name.eq_ignore_ascii_case(cmd);
    let step = if is(b"PING") {
        Step::Reply(PONG.to_vec())
    } else if is(b"ECHO") {
        Step::Reply(bulk(args.first().copied().unwrap_or(b"")))
    } else if is(b"GET") {
        Step::Reply(NULL_BULK.to_vec())
    } else if is(b"QUIT") {
        Step::Close(Some(OK.to_vec()))
    } else if DENYLIST.iter().any(|d| is(d)) {
        Step::Denylisted(DENIED.to_vec())
    } else {
        Step::ProtocolError(format!("-ERR unknown command '{typed}'\r\n").into_bytes())
    };
    (verb, step)
}

/// The command name as typed, safe to echo inside a simple-error line:
/// lossy UTF-8, control bytes (CR, LF, ...) dropped, at most
/// [`NAME_ECHO_MAX`] chars.
fn printable_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .take(NAME_ECHO_MAX)
        .collect()
}

/// `$<len>\r\n<data>\r\n`.
fn bulk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("${}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{Parsed, Speaker, Step};
    use crate::SeedMode;

    fn parse(mode: SeedMode, buf: &[u8]) -> Parsed {
        Resp.parse(mode, buf)
    }

    fn msg(consumed: usize, verb: &str, step: Step) -> Parsed {
        Parsed::Message {
            consumed,
            verb: Some(verb.to_string()),
            step,
        }
    }

    #[test]
    fn resp_def() {
        assert_eq!(DEF.name, "l4-resp");
        assert_eq!(DEF.grammar, "resp");
        assert_eq!(DEF.proto, crate::speakers::Proto::Tcp);
        assert_eq!((DEF.new_conn)().name(), "l4-resp");
        assert_eq!(MAX_BULK, 1_048_576);
        assert_eq!(Resp.max_buffer(), 1_048_576 + 64);
    }

    #[test]
    fn resp_ping_both_forms() {
        let pong = Step::Reply(b"+PONG\r\n".to_vec());
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$4\r\nPING\r\n"),
            msg(14, "PING", pong.clone())
        );
        assert_eq!(
            parse(SeedMode::Patched, b"PING\r\n"),
            msg(6, "PING", pong.clone())
        );
        // Case-insensitive, and the verb is reported uppercase.
        assert_eq!(parse(SeedMode::Patched, b"ping\r\n"), msg(6, "PING", pong));
    }

    #[test]
    fn resp_echo_get() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*2\r\n$4\r\nECHO\r\n$2\r\nhi\r\n"),
            msg(22, "ECHO", Step::Reply(b"$2\r\nhi\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"ECHO hi\r\n"),
            msg(9, "ECHO", Step::Reply(b"$2\r\nhi\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"),
            msg(20, "GET", Step::Reply(b"$-1\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Patched, b"GET k\r\n"),
            msg(7, "GET", Step::Reply(b"$-1\r\n".to_vec()))
        );
    }

    #[test]
    fn resp_quit_and_unknown() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"QUIT\r\n"),
            msg(6, "QUIT", Step::Close(Some(b"+OK\r\n".to_vec())))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$4\r\nquit\r\n"),
            msg(14, "QUIT", Step::Close(Some(b"+OK\r\n".to_vec())))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"FOO bar\r\n"),
            msg(
                9,
                "FOO",
                Step::ProtocolError(b"-ERR unknown command 'FOO'\r\n".to_vec())
            )
        );
        // The name is echoed as typed.
        assert_eq!(
            parse(SeedMode::Patched, b"*1\r\n$3\r\nfoo\r\n"),
            msg(
                13,
                "FOO",
                Step::ProtocolError(b"-ERR unknown command 'foo'\r\n".to_vec())
            )
        );
    }

    #[test]
    fn resp_denylist() {
        let deny = Step::Denylisted(b"-ERR denylisted command\r\n".to_vec());
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$8\r\nFLUSHALL\r\n"),
            msg(18, "FLUSHALL", deny.clone())
        );
        for (line, verb) in [
            (&b"FLUSHALL\r\n"[..], "FLUSHALL"),
            (b"flushdb\r\n", "FLUSHDB"),
            (b"SHUTDOWN NOSAVE\r\n", "SHUTDOWN"),
            (b"CONFIG SET dir /tmp\r\n", "CONFIG"),
            (b"DEBUG SEGFAULT\r\n", "DEBUG"),
            (b"SAVE\r\n", "SAVE"),
        ] {
            assert_eq!(
                parse(SeedMode::Patched, line),
                msg(line.len(), verb, deny.clone()),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn resp_huge_bulk() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$2000000\r\n"),
            Parsed::Message {
                consumed: 14,
                verb: None,
                step: Step::Trigger
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, b"*1\r\n$2000000\r\n"),
            Parsed::Message {
                consumed: 14,
                verb: None,
                step: Step::Fault(b"-ERR Protocol error: invalid bulk length\r\n".to_vec())
            }
        );
        // Exactly the cap is not the bug.
        let mut at_cap = b"*1\r\n$1048576\r\n".to_vec();
        at_cap.extend(std::iter::repeat_n(b'x', 1_048_576));
        at_cap.extend_from_slice(b"\r\n");
        assert_eq!(
            parse(SeedMode::Vulnerable, &at_cap),
            Parsed::Message {
                consumed: at_cap.len(),
                verb: Some("X".repeat(128)),
                step: Step::ProtocolError(
                    format!("-ERR unknown command '{}'\r\n", "x".repeat(128)).into_bytes()
                )
            }
        );
        // A negative length is the bug too.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$-1\r\n"),
            Parsed::Message {
                consumed: 9,
                verb: None,
                step: Step::Trigger
            }
        );
    }

    #[test]
    fn resp_incomplete() {
        assert_eq!(parse(SeedMode::Vulnerable, b""), Parsed::Incomplete);
        assert_eq!(parse(SeedMode::Vulnerable, b"PIN"), Parsed::Incomplete);
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*2\r\n$4\r\nPING\r\n"),
            Parsed::Incomplete
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$4\r\nPI"),
            Parsed::Incomplete
        );
        assert_eq!(parse(SeedMode::Vulnerable, b"*1\r\n$4"), Parsed::Incomplete);
    }

    #[test]
    fn resp_idle_multibulk() {
        let mut v = Resp;
        assert_eq!(
            v.on_idle(SeedMode::Vulnerable, b"*5\r\n$4\r\nPING\r\n"),
            Step::Trigger
        );
        let mut p = Resp;
        assert_eq!(
            p.on_idle(SeedMode::Patched, b"*5\r\n$4\r\nPING\r\n"),
            Step::Fault(b"-ERR Protocol error: incomplete multibulk\r\n".to_vec())
        );
        // A stalled inline line is not the bug: the connection just closes.
        assert_eq!(
            Resp.on_idle(SeedMode::Vulnerable, b"PIN"),
            Step::Close(None)
        );
    }
}
