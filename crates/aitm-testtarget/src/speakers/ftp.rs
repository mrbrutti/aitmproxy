//! `l4-ftp`: a minimal FTP control-channel responder (spec D5 row `l4-ftp`).
//!
//! Greets with `220 aitm ftp`, answers `USER`, `PASS`, `NOOP`, `PWD`, `TYPE`
//! and `QUIT`; the destructive verbs `DELE STOR APPE RMD RNFR RNTO MKD` are
//! the denylist and get `550 denied`. No data channel is ever opened. The one
//! deliberate bug is a command line longer than [`MAX_LINE`] bytes (CRLF past
//! the cap, or no CRLF within cap + 1 bytes): the Vulnerable origin crashes
//! ([`Step::Trigger`]), the Patched control answers `500 line too long` and
//! closes ([`Step::Fault`]). A partial line at idle just waits
//! ([`Step::Wait`], T10 PR C).

use super::{mode_bug, take_line, LineScan, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// Longest command line accepted, excluding its CRLF (spec D5).
pub const MAX_LINE: usize = 1024;

/// Verbs that would write to or delete from a real server; answered `550
/// denied` and logged `denylisted` (spec D5 denylist observation).
const DENYLIST: [&str; 7] = ["DELE", "STOR", "APPE", "RMD", "RNFR", "RNTO", "MKD"];

/// `/services` entry for the FTP speaker.
pub const DEF: ServiceDef = ServiceDef {
    name: "l4-ftp",
    grammar: "ftp",
    proto: Proto::Tcp,
    new_conn,
};

fn new_conn() -> Box<dyn Speaker> {
    Box::new(Ftp)
}

/// One FTP control connection. Stateless: `PASS` logs in without a `USER`.
#[derive(Debug)]
pub struct Ftp;

impl Speaker for Ftp {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn banner(&self) -> Option<Vec<u8>> {
        Some(b"220 aitm ftp\r\n".to_vec())
    }

    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed {
        let (line, consumed) = match take_line(buf, MAX_LINE) {
            LineScan::Incomplete => return Parsed::Incomplete,
            LineScan::TooLong => {
                return Parsed::Message {
                    consumed: buf.len(),
                    verb: None,
                    step: mode_bug(mode, b"500 line too long\r\n".to_vec()),
                }
            }
            LineScan::Complete { line, consumed } => (line, consumed),
        };
        let Some(verb) = split_verb(line) else {
            return Parsed::Message {
                consumed,
                verb: None,
                step: Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            };
        };
        let step = match verb.as_str() {
            "USER" => Step::Reply(b"331 password required\r\n".to_vec()),
            "PASS" => Step::Reply(b"230 logged in\r\n".to_vec()),
            "NOOP" | "TYPE" => Step::Reply(b"200 ok\r\n".to_vec()),
            "PWD" => Step::Reply(b"257 \"/\"\r\n".to_vec()),
            "QUIT" => Step::Close(Some(b"221 bye\r\n".to_vec())),
            v if DENYLIST.contains(&v) => Step::Denylisted(b"550 denied\r\n".to_vec()),
            _ => Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
        };
        Parsed::Message {
            consumed,
            verb: Some(verb),
            step,
        }
    }

    fn on_idle(&mut self, _mode: SeedMode, _buf: &[u8]) -> Step {
        // A line without its CRLF yet (or with a damaged terminator) is not
        // a protocol event; a real server waits for the rest. An over-long
        // line never gets here: `take_line` reports it `TooLong` in `parse`.
        Step::Wait
    }

    fn max_buffer(&self) -> usize {
        MAX_LINE + 2
    }
}

/// The uppercased first token of a command line; `None` for a blank line.
fn split_verb(line: &[u8]) -> Option<String> {
    let start = line.iter().position(|b| !b.is_ascii_whitespace())?;
    let rest = &line[start..];
    let end = rest
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speakers::msg;
    use crate::SeedMode;

    #[test]
    fn ftp_banner() {
        let s = Ftp;
        assert_eq!(s.name(), "l4-ftp");
        assert_eq!(s.banner(), Some(b"220 aitm ftp\r\n".to_vec()));
        assert_eq!(s.max_buffer(), 1026);
        assert_eq!(DEF.name, "l4-ftp");
        assert_eq!(DEF.grammar, "ftp");
        assert_eq!(DEF.proto, Proto::Tcp);
        assert_eq!((DEF.new_conn)().name(), "l4-ftp");
    }

    #[test]
    fn ftp_session() {
        let mut s = Ftp;
        let v = SeedMode::Vulnerable;
        assert_eq!(
            s.parse(v, b"USER a\r\n"),
            msg(
                8,
                "USER",
                Step::Reply(b"331 password required\r\n".to_vec())
            )
        );
        assert_eq!(
            s.parse(v, b"pass b\r\n"),
            msg(8, "PASS", Step::Reply(b"230 logged in\r\n".to_vec()))
        );
        assert_eq!(
            s.parse(v, b"NOOP\r\n"),
            msg(6, "NOOP", Step::Reply(b"200 ok\r\n".to_vec()))
        );
        assert_eq!(
            s.parse(v, b"PWD\r\n"),
            msg(5, "PWD", Step::Reply(b"257 \"/\"\r\n".to_vec()))
        );
        assert_eq!(
            s.parse(v, b"TYPE I\r\n"),
            msg(8, "TYPE", Step::Reply(b"200 ok\r\n".to_vec()))
        );
        assert_eq!(
            s.parse(v, b"DELE x\r\n"),
            msg(8, "DELE", Step::Denylisted(b"550 denied\r\n".to_vec()))
        );
        for verb in ["STOR", "APPE", "RMD", "RNFR", "RNTO", "MKD", "mkd"] {
            let line = format!("{verb} x\r\n");
            assert_eq!(
                s.parse(v, line.as_bytes()),
                msg(
                    line.len(),
                    &verb.to_ascii_uppercase(),
                    Step::Denylisted(b"550 denied\r\n".to_vec())
                ),
                "{verb}"
            );
        }
        assert_eq!(
            s.parse(v, b"SYST\r\n"),
            msg(
                6,
                "SYST",
                Step::ProtocolError(b"500 unknown command\r\n".to_vec())
            )
        );
        // Only the first line is consumed; the rest stays for the next call.
        assert_eq!(
            s.parse(v, b"QUIT\r\nNOOP\r\n"),
            msg(6, "QUIT", Step::Close(Some(b"221 bye\r\n".to_vec())))
        );
        // Patched mode answers the benign exchange identically.
        assert_eq!(
            s.parse(SeedMode::Patched, b"NOOP\r\n"),
            msg(6, "NOOP", Step::Reply(b"200 ok\r\n".to_vec()))
        );
    }

    #[test]
    fn ftp_incomplete_idle_and_empty() {
        let mut s = Ftp;
        assert_eq!(s.parse(SeedMode::Vulnerable, b""), Parsed::Incomplete);
        assert_eq!(s.parse(SeedMode::Vulnerable, b"NOO"), Parsed::Incomplete);
        assert_eq!(s.parse(SeedMode::Vulnerable, b"NOOP\r"), Parsed::Incomplete);
        // A partial line after the idle is not a protocol event: wait for
        // the CRLF silently, in both modes (T10 PR C). A damaged terminator
        // (`\r\t`) is still just a partial line.
        for buf in [&b"NOO"[..], b"NOOP\r", b"NOOP\r\t", b"USER a"] {
            assert_eq!(s.on_idle(SeedMode::Vulnerable, buf), Step::Wait);
            assert_eq!(s.on_idle(SeedMode::Patched, buf), Step::Wait);
        }
        assert_eq!(
            s.parse(SeedMode::Vulnerable, b"\r\n"),
            Parsed::Message {
                consumed: 2,
                verb: None,
                step: Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            }
        );
    }

    /// A high-bit byte (or a NUL) in an argument never breaks verb
    /// matching; one in the verb is an ordinary unknown command: reply,
    /// keep (T10 PR C).
    #[test]
    fn ftp_high_bit_bytes_get_a_normal_reply() {
        let mut s = Ftp;
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            assert_eq!(
                s.parse(mode, b"USER a\xff\r\n"),
                msg(
                    9,
                    "USER",
                    Step::Reply(b"331 password required\r\n".to_vec())
                )
            );
            assert_eq!(
                s.parse(mode, b"PASS b\x00c\r\n"),
                msg(10, "PASS", Step::Reply(b"230 logged in\r\n".to_vec()))
            );
            assert_eq!(
                s.parse(mode, b"US\xffER a\r\n"),
                msg(
                    9,
                    "US\u{FFFD}ER",
                    Step::ProtocolError(b"500 unknown command\r\n".to_vec())
                )
            );
        }
    }

    #[test]
    fn ftp_long_line() {
        let mut s = Ftp;
        let no_crlf = vec![b'a'; 1025];
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &no_crlf),
            Parsed::Message {
                consumed: 1025,
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            s.parse(SeedMode::Patched, &no_crlf),
            Parsed::Message {
                consumed: 1025,
                verb: None,
                step: Step::Fault(b"500 line too long\r\n".to_vec()),
            }
        );
        // A complete over-long line, CRLF and all, is the trigger too (T6).
        let mut complete = b"NOOP ".to_vec();
        complete.extend(std::iter::repeat_n(b'a', 4096));
        complete.extend_from_slice(b"\r\n");
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &complete),
            Parsed::Message {
                consumed: complete.len(),
                verb: None,
                step: Step::Trigger,
            }
        );
        assert_eq!(
            s.parse(SeedMode::Patched, &complete),
            Parsed::Message {
                consumed: complete.len(),
                verb: None,
                step: Step::Fault(b"500 line too long\r\n".to_vec()),
            }
        );
        // Exactly 1024 bytes before the CRLF is still a (unknown) command.
        let mut exact = vec![b'a'; 1024];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(
            s.parse(SeedMode::Vulnerable, &exact),
            Parsed::Message {
                consumed: 1026,
                verb: Some("A".repeat(1024)),
                step: Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            }
        );
    }
}
