//! `l4-memcached`: a minimal memcached text-protocol responder (spec D5).
//!
//! One CRLF-terminated command line per message, `set` followed by its
//! announced data block. No state is kept between calls: a `set` is only
//! consumed once its data and trailing CRLF are buffered. The deliberate
//! bug: a `set` announcing more than [`MAX_DATA`] bytes, or a line over
//! [`MAX_LINE`] bytes (spec D5's over-long-line rule via
//! [`super::take_line`]), crashes the Vulnerable origin; the Patched control
//! answers the row's `CLIENT_ERROR` and closes. `flush_all` is answered with
//! `CLIENT_ERROR denylisted` and logged `denylisted`.

use super::{mode_bug, take_line, LineScan, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// The service as the driver's table lists it.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-memcached",
    grammar: "memcached",
    proto: Proto::Tcp,
    new_conn,
};

/// Longest command line (spec D5: memcached 2048).
pub const MAX_LINE: usize = 2048;
/// Largest `set` data block; one byte more is the bug (spec D5: 1 MiB).
pub const MAX_DATA: usize = 1_048_576;

const VERSION: &[u8] = b"VERSION 1.6.0-aitm\r\n";
const END: &[u8] = b"END\r\n";
const STORED: &[u8] = b"STORED\r\n";
const ERROR: &[u8] = b"ERROR\r\n";
const DENIED: &[u8] = b"CLIENT_ERROR denylisted\r\n";
const BAD_DATA_CHUNK: &[u8] = b"CLIENT_ERROR bad data chunk\r\n";
const LINE_TOO_LONG: &[u8] = b"CLIENT_ERROR line too long\r\n";

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Memcached)
}

/// One memcached connection. Stateless: see the module docs.
#[derive(Default)]
pub struct Memcached;

impl Speaker for Memcached {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        let (line, consumed) = match take_line(buf, MAX_LINE) {
            LineScan::Incomplete => return Parsed::Incomplete,
            LineScan::TooLong => {
                return Parsed::Message {
                    consumed: buf.len(),
                    verb: None,
                    step: mode_bug(mode, LINE_TOO_LONG.to_vec()),
                }
            }
            LineScan::Complete { line, consumed } => (line, consumed),
        };
        let mut words = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|w| !w.is_empty());
        let Some(cmd) = words.next() else {
            return Parsed::Message {
                consumed,
                verb: None,
                step: Step::ProtocolError(ERROR.to_vec()),
            };
        };
        // Commands are case-sensitive, as in memcached (`VERSION` is ERROR).
        let verb = Some(String::from_utf8_lossy(cmd).into_owned());
        let step = match cmd {
            b"version" => Step::Reply(VERSION.to_vec()),
            b"get" => Step::Reply(END.to_vec()),
            b"quit" => Step::Close(None),
            b"flush_all" => Step::Denylisted(DENIED.to_vec()),
            b"set" => return parse_set(mode, buf, consumed, verb, words),
            _ => Step::ProtocolError(ERROR.to_vec()),
        };
        Parsed::Message {
            consumed,
            verb,
            step,
        }
    }

    fn on_idle(&mut self, _mode: SeedMode, _buf: &[u8]) -> Step {
        // A stalled line or data block is not a protocol event; hang up.
        Step::Close(None)
    }

    fn max_buffer(&self) -> usize {
        MAX_DATA + MAX_LINE
    }
}

/// `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`; `line_end` is where
/// the command line's CRLF ended, `rest` the words after `set`.
fn parse_set<'a>(
    mode: SeedMode,
    buf: &[u8],
    line_end: usize,
    verb: Option<String>,
    mut rest: impl Iterator<Item = &'a [u8]>,
) -> Parsed {
    let (key, flags, exptime, bytes) = (rest.next(), rest.next(), rest.next(), rest.next());
    let announced = match (key, flags, exptime, bytes) {
        (Some(_), Some(_), Some(_), Some(bytes)) => parse_bytes(bytes),
        _ => None,
    };
    let Some(announced) = announced else {
        return Parsed::Message {
            consumed: line_end,
            verb,
            step: Step::ProtocolError(ERROR.to_vec()),
        };
    };
    if announced > MAX_DATA {
        // The deliberate bug.
        return Parsed::Message {
            consumed: line_end,
            verb,
            step: mode_bug(mode, BAD_DATA_CHUNK.to_vec()),
        };
    }
    let data_end = line_end + announced;
    let end = data_end + 2;
    if buf.len() < end {
        return Parsed::Incomplete;
    }
    // The data block is swallowed either way; memcached refuses one that
    // is not followed by CRLF and keeps the connection.
    let step = if &buf[data_end..end] == b"\r\n" {
        Step::Reply(STORED.to_vec())
    } else {
        Step::ProtocolError(BAD_DATA_CHUNK.to_vec())
    };
    Parsed::Message {
        consumed: end,
        verb,
        step,
    }
}

/// The announced byte count: `None` unless it is all digits; digits that
/// overflow `usize` are treated as huge (the bug), not as malformed.
fn parse_bytes(token: &[u8]) -> Option<usize> {
    if token.is_empty() || !token.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        std::str::from_utf8(token)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(usize::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::{Parsed, Speaker, Step};
    use crate::SeedMode;

    fn parse(mode: SeedMode, buf: &[u8]) -> Parsed {
        Memcached.parse(mode, buf)
    }

    fn msg(consumed: usize, verb: &str, step: Step) -> Parsed {
        Parsed::Message {
            consumed,
            verb: Some(verb.to_string()),
            step,
        }
    }

    #[test]
    fn mc_def() {
        assert_eq!(DEF.name, "l4-memcached");
        assert_eq!(DEF.grammar, "memcached");
        assert_eq!(DEF.proto, crate::speakers::Proto::Tcp);
        assert_eq!((DEF.new_conn)().name(), "l4-memcached");
        assert_eq!(MAX_LINE, 2048);
        assert_eq!(MAX_DATA, 1_048_576);
        assert_eq!(Memcached.max_buffer(), 1_048_576 + 2048);
    }

    #[test]
    fn mc_version_get_set() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"version\r\n"),
            msg(
                9,
                "version",
                Step::Reply(b"VERSION 1.6.0-aitm\r\n".to_vec())
            )
        );
        assert_eq!(
            parse(SeedMode::Patched, b"get k\r\n"),
            msg(7, "get", Step::Reply(b"END\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 2\r\nhi\r\n"),
            msg(17, "set", Step::Reply(b"STORED\r\n".to_vec()))
        );
        // Trailing bytes belong to the next command.
        assert_eq!(
            parse(SeedMode::Patched, b"set k 0 0 2\r\nhi\r\nversion\r\n"),
            msg(17, "set", Step::Reply(b"STORED\r\n".to_vec()))
        );
    }

    #[test]
    fn mc_set_waits_for_data() {
        assert_eq!(parse(SeedMode::Vulnerable, b""), Parsed::Incomplete);
        assert_eq!(parse(SeedMode::Vulnerable, b"vers"), Parsed::Incomplete);
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 2\r\n"),
            Parsed::Incomplete
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 2\r\nhi\r"),
            Parsed::Incomplete
        );
        // Data not followed by CRLF is swallowed and refused, connection kept.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 2\r\nhixx"),
            msg(
                17,
                "set",
                Step::ProtocolError(b"CLIENT_ERROR bad data chunk\r\n".to_vec())
            )
        );
        // A malformed set line is a plain ERROR.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0\r\n"),
            msg(11, "set", Step::ProtocolError(b"ERROR\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 abc\r\n"),
            msg(15, "set", Step::ProtocolError(b"ERROR\r\n".to_vec()))
        );
    }

    #[test]
    fn mc_quit_and_unknown() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"quit\r\n"),
            msg(6, "quit", Step::Close(None))
        );
        assert_eq!(
            parse(SeedMode::Patched, b"bogus 1 2\r\n"),
            msg(11, "bogus", Step::ProtocolError(b"ERROR\r\n".to_vec()))
        );
        // Commands are case-sensitive, as in memcached.
        assert_eq!(
            parse(SeedMode::Patched, b"VERSION\r\n"),
            msg(9, "VERSION", Step::ProtocolError(b"ERROR\r\n".to_vec()))
        );
        assert_eq!(
            parse(SeedMode::Patched, b"\r\n"),
            Parsed::Message {
                consumed: 2,
                verb: None,
                step: Step::ProtocolError(b"ERROR\r\n".to_vec())
            }
        );
    }

    #[test]
    fn mc_flush_all_denylisted() {
        let deny = Step::Denylisted(b"CLIENT_ERROR denylisted\r\n".to_vec());
        assert_eq!(
            parse(SeedMode::Vulnerable, b"flush_all\r\n"),
            msg(11, "flush_all", deny.clone())
        );
        assert_eq!(
            parse(SeedMode::Patched, b"flush_all 30\r\n"),
            msg(14, "flush_all", deny)
        );
    }

    #[test]
    fn mc_huge_set() {
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 2000000\r\n"),
            msg(19, "set", Step::Trigger)
        );
        assert_eq!(
            parse(SeedMode::Patched, b"set k 0 0 2000000\r\n"),
            msg(
                19,
                "set",
                Step::Fault(b"CLIENT_ERROR bad data chunk\r\n".to_vec())
            )
        );
        // Exactly the cap is not the bug: it waits for the data.
        assert_eq!(
            parse(SeedMode::Vulnerable, b"set k 0 0 1048576\r\n"),
            Parsed::Incomplete
        );
    }

    #[test]
    fn mc_long_line() {
        let long = vec![b'a'; 2049];
        assert_eq!(
            parse(SeedMode::Vulnerable, &long),
            Parsed::Message {
                consumed: 2049,
                verb: None,
                step: Step::Trigger
            }
        );
        assert_eq!(
            parse(SeedMode::Patched, &long),
            Parsed::Message {
                consumed: 2049,
                verb: None,
                step: Step::Fault(b"CLIENT_ERROR line too long\r\n".to_vec())
            }
        );
        // 2048 bytes without CRLF could still complete.
        assert_eq!(
            parse(SeedMode::Vulnerable, &long[..2048]),
            Parsed::Incomplete
        );
        // A complete line whose CRLF lies past the cap is over-long too.
        let mut past_cap = vec![b'a'; 4096];
        past_cap.extend_from_slice(b"\r\n");
        assert_eq!(
            parse(SeedMode::Vulnerable, &past_cap),
            Parsed::Message {
                consumed: 4098,
                verb: None,
                step: Step::Trigger
            }
        );
    }

    #[test]
    fn mc_idle_closes() {
        assert_eq!(
            Memcached.on_idle(SeedMode::Vulnerable, b"vers"),
            Step::Close(None)
        );
        assert_eq!(
            Memcached.on_idle(SeedMode::Patched, b"set k 0 0 2\r\nh"),
            Step::Close(None)
        );
    }
}
