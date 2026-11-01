//! `l4-resp`: a minimal Redis-protocol (RESP) responder (spec D5).
//!
//! Parses inline commands (`PING\r\n`) and `*N` arrays of `$len` bulk strings
//! from the buffered bytes. Every call parses from the buffer's front again:
//! an array is only consumed once it is whole, so the driver re-offers the
//! same prefix until it is. The one piece of per-connection state is a memo
//! of how far the scan for a pending line's CRLF has got ([`Resp::scanned`]),
//! so a line arriving in pieces is never rescanned from its start and the
//! absorb of a 1 MiB line costs O(n), not O(n^2) (T10 PR C fix round 2);
//! nothing is shared across connections. The deliberate bug: a bulk length
//! over [`MAX_BULK`] (or negative) crashes the Vulnerable origin, and so
//! does an array still short of its `N` elements after
//! [`super::IDLE_TIMEOUT`]; the Patched control answers the row's `-ERR
//! Protocol error` and closes. Malformed framing that is not the bug (a
//! garbled `*N` or `$len`, an element not starting with `$`, an inline line
//! past [`MAX_BULK`]) is answered with a specific `-ERR Protocol error: ...`
//! and then closed in both modes: no close is ever silent, and a stalled
//! inline line waits for its CRLF (T10 PR C). Destructive commands get
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
const INVALID_MULTIBULK: &[u8] = b"-ERR Protocol error: invalid multibulk length\r\n";
const TOO_BIG_INLINE: &[u8] = b"-ERR Protocol error: too big inline request\r\n";

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Resp::default())
}

/// One RESP connection. Its only state is the CRLF-scan memo (see the
/// module docs): the parse itself restarts from the buffer's front on every
/// call.
#[derive(Default)]
pub struct Resp {
    /// Start, in the buffer last offered, of the line whose CRLF has not
    /// arrived: `0` for an inline command, the pending `*N` or `$len` line
    /// inside an array.
    stalled_at: usize,
    /// `buf[stalled_at..scanned]` of the buffer last offered holds no CRLF,
    /// so the next scan of that line resumes at `scanned - 1` (a CR may be
    /// the last byte seen). Dropped once a message is returned (the driver
    /// drains it, so the next buffer is a different one) and whenever the
    /// buffer offered is shorter than the memo. Sound because the driver
    /// only ever appends to the buffer between `parse` calls unless `parse`
    /// returned a message (memo dropped) or an idle step ended the
    /// connection; `on_idle` drops it on every non-`Wait` step so the memo
    /// never outlives the buffer it describes, and stays O(1) otherwise.
    scanned: usize,
}

impl Resp {
    fn forget_scan(&mut self) {
        self.stalled_at = 0;
        self.scanned = 0;
    }

    /// The CRLF-terminated line of `buf` starting at `pos`: `(line without
    /// its CRLF, index after it)`; `None` while the CRLF has not arrived,
    /// after which the memo records how far the scan got. The memo is only
    /// applied to the line it was taken on (`pos == stalled_at`): a complete
    /// earlier line of an array is scanned from its own start.
    fn line<'a>(&mut self, buf: &'a [u8], pos: usize) -> Option<(&'a [u8], usize)> {
        let from = if pos == self.stalled_at {
            pos.max(self.scanned.saturating_sub(1))
        } else {
            pos
        };
        let found = buf
            .get(from..)
            .and_then(|tail| tail.windows(2).position(|w| w == b"\r\n"));
        match found {
            Some(i) => {
                let cr = from + i;
                Some((&buf[pos..cr], cr + 2))
            }
            None => {
                self.stalled_at = pos;
                self.scanned = buf.len();
                None
            }
        }
    }
}

impl Speaker for Resp {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        if buf.len() < self.scanned {
            // Not the buffer the memo was taken on.
            self.forget_scan();
        }
        let parsed = match buf.first() {
            None => Parsed::Incomplete,
            Some(b'*') => self.parse_array(mode, buf),
            Some(_) => self.parse_inline(buf),
        };
        if matches!(parsed, Parsed::Message { .. }) {
            // The driver drains the message; the next buffer starts after it.
            self.forget_scan();
        }
        parsed
    }

    fn on_idle(&mut self, mode: SeedMode, buf: &[u8]) -> Step {
        if buf.first() == Some(&b'*') {
            // `*N` with fewer than N elements after the idle: the bug. The
            // step ends the connection, so the scan memo is dropped with it.
            self.forget_scan();
            mode_bug(mode, INCOMPLETE_MULTIBULK.to_vec())
        } else if buf.len() > MAX_BULK {
            // An inline line past the bulk cap can never be served (redis:
            // "too big inline request"): say so, then close, both modes.
            self.forget_scan();
            Step::Fault(TOO_BIG_INLINE.to_vec())
        } else {
            // A stalled inline line is not a protocol event; wait for its
            // CRLF as redis does. The memo stays: the line is still arriving.
            Step::Wait
        }
    }

    fn max_buffer(&self) -> usize {
        MAX_BULK + 64
    }
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

impl Resp {
    fn parse_inline(&mut self, buf: &[u8]) -> Parsed {
        let Some((line, consumed)) = self.line(buf, 0) else {
            return Parsed::Incomplete;
        };
        parse_inline_line(line, consumed)
    }

    fn parse_array(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        let Some((header, mut pos)) = self.line(buf, 0) else {
            return Parsed::Incomplete;
        };
        let count = match parse_len(&header[1..]) {
            Len::Value(n) if n >= 0 => n.unsigned_abs() as usize,
            // Too many to ever arrive: stays incomplete until the idle trigger.
            Len::Overflow => usize::MAX,
            // A negative or garbled count desynchronises the stream: say so,
            // then close (in both modes; this is not the D5 trigger).
            Len::Value(_) | Len::Malformed => {
                return Parsed::Message {
                    consumed: pos,
                    verb: None,
                    step: Step::Fault(INVALID_MULTIBULK.to_vec()),
                }
            }
        };
        let mut elems: Vec<&[u8]> = Vec::new();
        while elems.len() < count {
            let Some((l, after_header)) = self.line(buf, pos) else {
                return Parsed::Incomplete;
            };
            let Some(digits) = l.strip_prefix(b"$") else {
                // Clients only send arrays of bulk strings: name the byte we
                // found instead, then close (in both modes).
                return Parsed::Message {
                    consumed: after_header,
                    verb: None,
                    step: Step::Fault(expected_dollar(l)),
                };
            };
            let len = match parse_len(digits) {
                Len::Value(len) if (0..=MAX_BULK as i64).contains(&len) => {
                    len.unsigned_abs() as usize
                }
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
}

/// Dispatch one complete inline `line` (without its CRLF; `consumed`
/// includes it).
fn parse_inline_line(line: &[u8], consumed: usize) -> Parsed {
    if line.len() > MAX_BULK {
        // A complete inline line past the bulk cap is never dispatched
        // (redis: "too big inline request"): say so, then close, both modes.
        return Parsed::Message {
            consumed,
            verb: None,
            step: Step::Fault(TOO_BIG_INLINE.to_vec()),
        };
    }
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

/// `-ERR Protocol error: expected '$', got '<c>'` for an array element line
/// that does not start with `$` (redis's own wording); `<c>` is its first
/// byte when that is printable ASCII (`is_ascii_graphic()` or the space),
/// empty otherwise: a control, high-bit or lossily decoded byte is never
/// echoed, and the element itself is never decoded or copied (spec D5).
fn expected_dollar(elem: &[u8]) -> Vec<u8> {
    let mut out = b"-ERR Protocol error: expected '$', got '".to_vec();
    if let Some(&b) = elem.first() {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b);
        }
    }
    out.extend_from_slice(b"'\r\n");
    out
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
    use crate::speakers::{msg, Parsed, Speaker, Step};
    use crate::SeedMode;

    fn parse(mode: SeedMode, buf: &[u8]) -> Parsed {
        Resp::default().parse(mode, buf)
    }

    #[test]
    fn resp_def() {
        assert_eq!(DEF.name, "l4-resp");
        assert_eq!(DEF.grammar, "resp");
        assert_eq!(DEF.proto, crate::speakers::Proto::Tcp);
        assert_eq!((DEF.new_conn)().name(), "l4-resp");
        assert_eq!(MAX_BULK, 1_048_576);
        assert_eq!(Resp::default().max_buffer(), 1_048_576 + 64);
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
        // One byte over the cap is already the bug (the `> MAX_BULK` boundary).
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$1048577\r\n"),
            Parsed::Message {
                consumed: 14,
                verb: None,
                step: Step::Trigger
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, b"*1\r\n$1048577\r\n"),
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
        let mut v = Resp::default();
        assert_eq!(
            v.on_idle(SeedMode::Vulnerable, b"*5\r\n$4\r\nPING\r\n"),
            Step::Trigger
        );
        let mut p = Resp::default();
        assert_eq!(
            p.on_idle(SeedMode::Patched, b"*5\r\n$4\r\nPING\r\n"),
            Step::Fault(b"-ERR Protocol error: incomplete multibulk\r\n".to_vec())
        );
        // A stalled inline line is not the bug and not a protocol event:
        // wait for the CRLF silently, in both modes (T10 PR C).
        assert_eq!(
            Resp::default().on_idle(SeedMode::Vulnerable, b"PIN"),
            Step::Wait
        );
        assert_eq!(
            Resp::default().on_idle(SeedMode::Patched, b"PIN"),
            Step::Wait
        );
        // An inline line that has outgrown the bulk cap can never be
        // served: say so, then close, in both modes (never silently).
        let too_big = vec![b'a'; MAX_BULK + 1];
        let reply = Step::Fault(b"-ERR Protocol error: too big inline request\r\n".to_vec());
        assert_eq!(
            Resp::default().on_idle(SeedMode::Vulnerable, &too_big),
            reply
        );
        assert_eq!(Resp::default().on_idle(SeedMode::Patched, &too_big), reply);
        assert_eq!(
            Resp::default().on_idle(SeedMode::Patched, &too_big[..MAX_BULK]),
            Step::Wait
        );
    }

    // --- Tester additions (stage 5): malformed lengths never panic or crash ---

    #[test]
    fn resp_malformed_lengths_reply_then_close() {
        // A garbled or negative array count desynchronises the stream: the
        // protocol-error reply, then close, in both modes (never the crash
        // window, never a silent close; T10 PR C).
        let bad_count = Step::Fault(b"-ERR Protocol error: invalid multibulk length\r\n".to_vec());
        for buf in [&b"*abc\r\n"[..], b"*-1\r\n", b"*\r\n"] {
            for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
                assert_eq!(
                    parse(mode, buf),
                    Parsed::Message {
                        consumed: buf.len(),
                        verb: None,
                        step: bad_count.clone(),
                    },
                    "{:?}",
                    String::from_utf8_lossy(buf)
                );
            }
        }
        // An array element that is not a bulk string: reply, then close.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n+PING\r\n"),
            Parsed::Message {
                consumed: 11,
                verb: None,
                step: Step::Fault(b"-ERR Protocol error: expected '$', got '+'\r\n".to_vec()),
            }
        );
        // A garbled bulk length is the protocol-error reply in both modes.
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(
                parse(mode, b"*1\r\n$abc\r\n"),
                Parsed::Message {
                    consumed: 10,
                    verb: None,
                    step: Step::Fault(b"-ERR Protocol error: invalid bulk length\r\n".to_vec()),
                }
            );
        }
        // A bulk length that overflows i64 counts as huge: the bug.
        let huge = b"*1\r\n$99999999999999999999\r\n";
        assert_eq!(
            parse(SeedMode::Vulnerable, huge),
            Parsed::Message {
                consumed: huge.len(),
                verb: None,
                step: Step::Trigger,
            }
        );
        // `*0` and an empty inline line are ignored no-ops.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*0\r\n"),
            Parsed::Message {
                consumed: 4,
                verb: None,
                step: Step::Reply(Vec::new()),
            }
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"\r\n"),
            Parsed::Message {
                consumed: 2,
                verb: None,
                step: Step::Reply(Vec::new()),
            }
        );
        // ECHO without an argument is an empty bulk; an unknown name is echoed
        // with its control bytes dropped.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"ECHO\r\n"),
            msg(6, "ECHO", Step::Reply(b"$0\r\n\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"*1\r\n$3\r\na\x01b\r\n"),
            msg(
                13,
                "AB",
                Step::ProtocolError(b"-ERR unknown command 'ab'\r\n".to_vec())
            )
        );
    }

    // --- T10 PR C: malformed framing replies before closing, in both modes ---

    #[test]
    fn resp_malformed_framing_replies_then_closes() {
        let cases: [(&[u8], usize, &[u8]); 5] = [
            // `*1$4` is not a number: the multibulk header is garbled.
            (
                b"*1$4\r\nPING\r\n",
                6,
                b"-ERR Protocol error: invalid multibulk length\r\n",
            ),
            // The element after `*1` does not start with `$`.
            (
                b"*1\r\n4\r\nPING\r\n",
                7,
                b"-ERR Protocol error: expected '$', got '4'\r\n",
            ),
            // An empty element line: nothing to quote after `got`.
            (
                b"*1\r\n\r\nPING\r\n",
                6,
                b"-ERR Protocol error: expected '$', got ''\r\n",
            ),
            // A control byte where `$` should be is not echoed raw.
            (
                b"*1\r\n\x01PING\r\n",
                11,
                b"-ERR Protocol error: expected '$', got ''\r\n",
            ),
            // A high-bit byte where `$` should be is not echoed either:
            // `<c>` is printable ASCII or nothing (spec D5).
            (
                b"*1\r\n\xffPING\r\n",
                11,
                b"-ERR Protocol error: expected '$', got ''\r\n",
            ),
        ];
        for (buf, consumed, reply) in cases {
            for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
                assert_eq!(
                    parse(mode, buf),
                    Parsed::Message {
                        consumed,
                        verb: None,
                        step: Step::Fault(reply.to_vec()),
                    },
                    "{mode:?} {:?}",
                    String::from_utf8_lossy(buf)
                );
            }
        }
    }

    /// A complete inline line longer than `MAX_BULK` (1 MiB) is never
    /// dispatched as a command: `too big inline request`, then close, in
    /// both modes (spec D5 "an inline line past 1 MiB"); exactly 1 MiB is
    /// still a command (T10 PR C fix round 1, item 11).
    #[test]
    fn resp_over_long_inline_line_is_too_big_in_both_modes() {
        let too_big = Step::Fault(b"-ERR Protocol error: too big inline request\r\n".to_vec());
        // `PING` padded with spaces to one byte over the cap, then its CRLF.
        let mut padded_ping = b"PING".to_vec();
        padded_ping.resize(MAX_BULK + 1, b' ');
        padded_ping.extend_from_slice(b"\r\n");
        // One byte over the cap, no spaces at all.
        let mut over = vec![b'a'; MAX_BULK + 1];
        over.extend_from_slice(b"\r\n");
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            for buf in [&padded_ping, &over] {
                assert_eq!(
                    parse(mode, buf),
                    Parsed::Message {
                        consumed: MAX_BULK + 3,
                        verb: None,
                        step: too_big.clone(),
                    },
                    "{mode:?} {} bytes",
                    buf.len()
                );
            }
        }
        // Exactly the cap plus CRLF is an ordinary (unknown) command.
        let mut at_cap = vec![b'a'; MAX_BULK];
        at_cap.extend_from_slice(b"\r\n");
        assert_eq!(
            parse(SeedMode::Patched, &at_cap),
            msg(
                MAX_BULK + 2,
                &"A".repeat(128),
                Step::ProtocolError(
                    format!("-ERR unknown command '{}'\r\n", "a".repeat(128)).into_bytes()
                )
            )
        );
    }

    /// A high-bit byte in an argument never breaks verb matching, and a
    /// non-UTF-8 verb is an ordinary unknown command: reply, keep (T10 PR C).
    #[test]
    fn resp_high_bit_bytes_get_a_normal_reply() {
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(
                parse(mode, b"ECHO \xff\r\n"),
                msg(8, "ECHO", Step::Reply(b"$1\r\n\xff\r\n".to_vec()))
            );
            assert_eq!(
                parse(mode, b"GET k\xff\r\n"),
                msg(8, "GET", Step::Reply(b"$-1\r\n".to_vec()))
            );
            assert_eq!(
                parse(mode, b"*2\r\n$3\r\nGET\r\n$2\r\nk\xff\r\n"),
                msg(21, "GET", Step::Reply(b"$-1\r\n".to_vec()))
            );
            // A NUL in an argument is an ordinary byte: inline words split
            // on ASCII whitespace only, so it is echoed back verbatim.
            assert_eq!(
                parse(mode, b"ECHO a\x00b\r\n"),
                msg(10, "ECHO", Step::Reply(b"$3\r\na\x00b\r\n".to_vec()))
            );
            assert_eq!(
                parse(mode, b"*2\r\n$3\r\nGET\r\n$3\r\nk\x00v\r\n"),
                msg(22, "GET", Step::Reply(b"$-1\r\n".to_vec()))
            );
            // The verb itself carries the high-bit byte: unknown, echoed
            // lossily, connection kept.
            assert_eq!(
                parse(mode, b"PI\xffNG\r\n"),
                msg(
                    7,
                    "PI\u{FFFD}NG",
                    Step::ProtocolError(
                        "-ERR unknown command 'PI\u{FFFD}NG'\r\n"
                            .as_bytes()
                            .to_vec()
                    )
                )
            );
        }
    }

    // --- Tester additions (stage 5, T10 PR C) ---

    /// `expected '$', got '<c>'` quotes the element's first byte only when
    /// it is printable ASCII (`is_ascii_graphic()` or the space): a
    /// control byte (DEL, TAB, NUL), a lone high-bit byte, a truncated
    /// UTF-8 lead and even a complete multi-byte char all give `got ''`
    /// (spec D5: never a control, high-bit or lossily decoded byte). The
    /// reply is always a single well-formed ASCII error line (no raw byte,
    /// no embedded CR/LF), then the connection closes, in both modes.
    #[test]
    fn resp_expected_dollar_quotes_one_printable_char() {
        let reply = |got: &str| {
            Step::Fault(format!("-ERR Protocol error: expected '$', got '{got}'\r\n").into_bytes())
        };
        let cases: [(&[u8], usize, Step); 10] = [
            (b"*1\r\n\x7fPING\r\n", 11, reply("")),
            (b"*1\r\n\tPING\r\n", 11, reply("")),
            (b"*1\r\n\x00PING\r\n", 11, reply("")),
            (b"*1\r\n\xffPING\r\n", 11, reply("")),
            (b"*1\r\n\xc3PING\r\n", 11, reply("")),
            (b"*1\r\n\xc3\xa9\r\n", 8, reply("")),
            (b"*1\r\n PING\r\n", 11, reply(" ")),
            (b"*1\r\n:1\r\n", 8, reply(":")),
            (b"*1\r\n4\r\n", 7, reply("4")),
            (b"*2\r\n$4\r\nPING\r\n-x\r\n", 18, reply("-")),
        ];
        for (buf, consumed, step) in cases {
            for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
                let got = parse(mode, buf);
                assert_eq!(
                    got,
                    Parsed::Message {
                        consumed,
                        verb: None,
                        step: step.clone(),
                    },
                    "{mode:?} {:?}",
                    String::from_utf8_lossy(buf)
                );
                // The reply is one line: no CR/LF before its terminator.
                let Parsed::Message {
                    step: Step::Fault(bytes),
                    ..
                } = got
                else {
                    unreachable!()
                };
                let body = &bytes[..bytes.len() - 2];
                assert!(
                    !body.iter().any(|b| *b == b'\r' || *b == b'\n'),
                    "{:?}",
                    String::from_utf8_lossy(&bytes)
                );
                assert!(bytes.is_ascii(), "{:?}", String::from_utf8_lossy(&bytes));
            }
        }
        // The literal bytes of the high-bit case: nothing between the quotes.
        assert_eq!(
            parse(SeedMode::Patched, b"*1\r\n\xffPING\r\n"),
            Parsed::Message {
                consumed: 11,
                verb: None,
                step: Step::Fault(b"-ERR Protocol error: expected '$', got ''\r\n".to_vec()),
            }
        );
    }

    /// The speaker never waits past its `max_buffer()` (spec D5): an inline
    /// buffer one byte over the cap is `too big inline request` (reply,
    /// then close) in both modes, never `Wait`; an array over the cap is
    /// the row's bug. So the driver's `CloseOversize` containment path
    /// (a silent close) is unreachable through this speaker.
    #[test]
    fn resp_never_waits_past_its_buffer_cap() {
        let over = Resp::default().max_buffer() + 1;
        let inline = vec![b'a'; over];
        let too_big = Step::Fault(b"-ERR Protocol error: too big inline request\r\n".to_vec());
        // `*2`: a 64-byte first element, then a 1 MiB second element still
        // 22 bytes short of complete when the buffer is one over the cap.
        let mut array = b"*2\r\n$64\r\n".to_vec();
        array.extend(std::iter::repeat_n(b'p', 64));
        array.extend_from_slice(b"\r\n$1048576\r\n");
        array.resize(over, b'x');
        assert_eq!(
            Resp::default().parse(SeedMode::Patched, &array),
            Parsed::Incomplete
        );
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(Resp::default().on_idle(mode, &inline), too_big, "{mode:?}");
            assert_ne!(
                Resp::default().on_idle(mode, &array),
                Step::Wait,
                "{mode:?}"
            );
        }
        assert_eq!(
            Resp::default().on_idle(SeedMode::Vulnerable, &array),
            Step::Trigger
        );
        assert_eq!(
            Resp::default().on_idle(SeedMode::Patched, &array),
            Step::Fault(b"-ERR Protocol error: incomplete multibulk\r\n".to_vec())
        );
        // Exactly the cap, no CRLF: still a line that could complete.
        assert_eq!(
            Resp::default().on_idle(SeedMode::Vulnerable, &inline[..MAX_BULK]),
            Step::Wait
        );
    }

    // --- T10 PR C fix round 2: the CRLF scan is memoised per connection ---

    /// An inline line arriving in 8 KiB slices (the driver's read chunk) is
    /// never rescanned from byte 0: the `scanned` frontier advances to the
    /// bytes seen after every slice, so a 1 MiB line costs O(n) compares in
    /// total instead of O(n^2). The three over-cap inline shapes decide
    /// exactly as before through the same memoised instance (exactly the cap
    /// waits at the idle and then completes as the unknown command; one byte
    /// over is `too big inline request` at the idle and, with its CRLF, as a
    /// complete line in both modes), a CR that was the last byte seen is
    /// re-examined when its LF lands, and the memo is dropped once a message
    /// is returned or a shorter buffer is offered.
    #[test]
    fn resp_inline_scan_resumes_where_it_stopped() {
        const SLICE: usize = 8192;
        let pong = Step::Reply(b"+PONG\r\n".to_vec());
        let too_big = Step::Fault(b"-ERR Protocol error: too big inline request\r\n".to_vec());

        // Exactly the cap: 128 slices, each leaves the memo at the bytes seen.
        let mut at_cap = Resp::default();
        let mut line = vec![b'a'; MAX_BULK];
        line.extend_from_slice(b"\r\n");
        let mut seen = 0;
        while seen < MAX_BULK {
            seen = (seen + SLICE).min(MAX_BULK);
            assert_eq!(
                at_cap.parse(SeedMode::Patched, &line[..seen]),
                Parsed::Incomplete
            );
            assert_eq!(at_cap.scanned, seen, "memo after {seen} bytes");
        }
        assert_eq!(
            at_cap.on_idle(SeedMode::Patched, &line[..MAX_BULK]),
            Step::Wait
        );
        // `on_idle` is O(1) and leaves the memo alone.
        assert_eq!(at_cap.scanned, MAX_BULK);
        assert_eq!(
            at_cap.parse(SeedMode::Patched, &line),
            msg(
                MAX_BULK + 2,
                &"A".repeat(128),
                Step::ProtocolError(
                    format!("-ERR unknown command '{}'\r\n", "a".repeat(128)).into_bytes()
                )
            )
        );
        assert_eq!(at_cap.scanned, 0, "a returned message drops the memo");

        // One byte over the cap, fed the same way.
        let mut over = Resp::default();
        let mut too_long = vec![b'a'; MAX_BULK + 1];
        let mut seen = 0;
        while seen < MAX_BULK + 1 {
            seen = (seen + SLICE).min(MAX_BULK + 1);
            assert_eq!(
                over.parse(SeedMode::Vulnerable, &too_long[..seen]),
                Parsed::Incomplete
            );
            assert_eq!(over.scanned, seen, "memo after {seen} bytes");
        }
        assert_eq!(over.on_idle(SeedMode::Vulnerable, &too_long), too_big);
        assert_eq!(over.on_idle(SeedMode::Patched, &too_long), too_big);
        too_long.extend_from_slice(b"\r\n");
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(
                over.parse(mode, &too_long),
                Parsed::Message {
                    consumed: MAX_BULK + 3,
                    verb: None,
                    step: too_big.clone(),
                },
                "{mode:?}"
            );
            assert_eq!(over.scanned, 0, "{mode:?}");
        }

        // A CR as the last byte seen is where the next scan resumes.
        let mut split_crlf = Resp::default();
        assert_eq!(
            split_crlf.parse(SeedMode::Patched, b"PING\r"),
            Parsed::Incomplete
        );
        assert_eq!(split_crlf.scanned, 5);
        assert_eq!(
            split_crlf.parse(SeedMode::Patched, b"PING\r\n"),
            msg(6, "PING", pong.clone())
        );
        assert_eq!(split_crlf.scanned, 0);

        // A shorter buffer than the memo covers is a new buffer: scan it all.
        let mut shrunk = Resp::default();
        assert_eq!(
            shrunk.parse(SeedMode::Patched, b"PINGPING"),
            Parsed::Incomplete
        );
        assert_eq!(shrunk.scanned, 8);
        assert_eq!(
            shrunk.parse(SeedMode::Patched, b"PING\r\n"),
            msg(6, "PING", pong)
        );
    }

    /// Inside an array the memo covers the one line whose CRLF has not
    /// arrived (`stalled_at` is its start): a `$len` line dribbled in a byte
    /// at a time advances `scanned` without rescanning, the complete `$4`
    /// line before it is still found when the array completes, and a
    /// dribbled over-cap length is still the row's bug / fault.
    #[test]
    fn resp_array_scan_resumes_at_the_stalled_line() {
        let pong = Step::Reply(b"+PONG\r\n".to_vec());
        let mut resp = Resp::default();
        // `*2`, a complete `$4\r\nPING\r\n`, then `$` of the second length.
        let mut buf = b"*2\r\n$4\r\nPING\r\n$".to_vec();
        assert_eq!(resp.parse(SeedMode::Vulnerable, &buf), Parsed::Incomplete);
        assert_eq!((resp.stalled_at, resp.scanned), (14, 15));
        buf.push(b'2');
        assert_eq!(resp.parse(SeedMode::Vulnerable, &buf), Parsed::Incomplete);
        assert_eq!((resp.stalled_at, resp.scanned), (14, 16));
        buf.push(b'\r');
        assert_eq!(resp.parse(SeedMode::Vulnerable, &buf), Parsed::Incomplete);
        assert_eq!((resp.stalled_at, resp.scanned), (14, 17));
        buf.extend_from_slice(b"\nhi\r\n");
        assert_eq!(
            resp.parse(SeedMode::Vulnerable, &buf),
            msg(buf.len(), "PING", pong)
        );
        assert_eq!((resp.stalled_at, resp.scanned), (0, 0));

        // Data short of its announced length is a stall without a scan.
        let mut short_data = Resp::default();
        assert_eq!(
            short_data.parse(SeedMode::Patched, b"*1\r\n$4\r\nPI"),
            Parsed::Incomplete
        );
        assert_eq!((short_data.stalled_at, short_data.scanned), (0, 0));

        // `$2000000` dribbled a digit at a time: the bug once its CRLF lands.
        for (mode, step) in [
            (SeedMode::Vulnerable, Step::Trigger),
            (
                SeedMode::Patched,
                Step::Fault(b"-ERR Protocol error: invalid bulk length\r\n".to_vec()),
            ),
        ] {
            let mut dribbled = Resp::default();
            let mut buf = b"*1\r\n$".to_vec();
            for digit in b"2000000" {
                buf.push(*digit);
                assert_eq!(dribbled.parse(mode, &buf), Parsed::Incomplete, "{mode:?}");
                assert_eq!(
                    (dribbled.stalled_at, dribbled.scanned),
                    (4, buf.len()),
                    "{mode:?}"
                );
            }
            buf.extend_from_slice(b"\r\n");
            assert_eq!(
                dribbled.parse(mode, &buf),
                Parsed::Message {
                    consumed: 14,
                    verb: None,
                    step,
                },
                "{mode:?}"
            );
        }
    }
}
