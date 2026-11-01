//! `l4-smtp`: a minimal SMTP line responder (spec D5 row `l4-smtp`).
//!
//! Greets with `220 target.test ESMTP aitm`, answers `EHLO`/`HELO`, `MAIL
//! FROM:`, `RCPT TO:` (only `@target.test` recipients; anything else is the
//! denylisted relay attempt, `550 relay denied`), `NOOP`, `DATA` (`451 not
//! accepted`) and `QUIT`. The one deliberate bug is a command line longer
//! than [`MAX_LINE`] bytes (CRLF past the cap, or no CRLF within cap + 1
//! bytes): the Vulnerable origin crashes ([`Step::Trigger`]), the Patched
//! control answers `500 line too long` and closes ([`Step::Fault`]).

use super::{mode_bug, take_line, LineScan, Parsed, Proto, ServiceDef, Speaker, Step};
use crate::SeedMode;

/// Longest command line accepted, excluding its CRLF (spec D5).
pub const MAX_LINE: usize = 1024;

/// The only domain `RCPT TO:` may name; anything else is a relay attempt.
const LOCAL_DOMAIN: &str = "target.test";

/// `/services` entry for the SMTP speaker.
pub static DEF: ServiceDef = ServiceDef {
    name: "l4-smtp",
    grammar: "smtp",
    proto: Proto::Tcp,
    new_conn: || Box::new(Smtp),
};

/// One SMTP connection. Stateless: every verb is answered on its own.
#[derive(Debug)]
pub struct Smtp;

impl Speaker for Smtp {
    fn name(&self) -> &'static str {
        DEF.name
    }

    fn banner(&self) -> Option<Vec<u8>> {
        Some(b"220 target.test ESMTP aitm\r\n".to_vec())
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
        let Some((verb, args)) = split_verb(line) else {
            return Parsed::Message {
                consumed,
                verb: None,
                step: Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            };
        };
        let step = match verb.as_str() {
            "EHLO" | "HELO" => Step::Reply(b"250 target.test\r\n".to_vec()),
            "MAIL" if strip_prefix_ci(args, b"FROM:").is_some() => {
                Step::Reply(b"250 OK\r\n".to_vec())
            }
            "RCPT" => match strip_prefix_ci(args, b"TO:") {
                Some(addr) if is_local_recipient(addr) => Step::Reply(b"250 OK\r\n".to_vec()),
                Some(_) => Step::Denylisted(b"550 relay denied\r\n".to_vec()),
                None => Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            },
            "NOOP" => Step::Reply(b"250 OK\r\n".to_vec()),
            "DATA" => Step::ProtocolError(b"451 not accepted\r\n".to_vec()),
            "QUIT" => Step::Close(Some(b"221 bye\r\n".to_vec())),
            _ => Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
        };
        Parsed::Message {
            consumed,
            verb: Some(verb),
            step,
        }
    }

    fn on_idle(&mut self, _mode: SeedMode, _buf: &[u8]) -> Step {
        Step::Close(None)
    }

    fn max_buffer(&self) -> usize {
        MAX_LINE + 2
    }
}

/// Split a command line into its uppercased verb and the trimmed remainder;
/// `None` for a blank line.
fn split_verb(line: &[u8]) -> Option<(String, &[u8])> {
    let line = trim_ws(line);
    if line.is_empty() {
        return None;
    }
    let end = line
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let verb = String::from_utf8_lossy(&line[..end]).to_ascii_uppercase();
    Some((verb, trim_ws(&line[end..])))
}

/// `bytes` without leading and trailing ASCII whitespace.
fn trim_ws(bytes: &[u8]) -> &[u8] {
    let Some(start) = bytes.iter().position(|b| !b.is_ascii_whitespace()) else {
        return &[];
    };
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(bytes.len(), |i| i + 1);
    &bytes[start..end]
}

/// `bytes` with a case-insensitive `prefix` removed, or `None` if absent.
fn strip_prefix_ci<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = bytes.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| trim_ws(&bytes[prefix.len()..]))
}

/// Whether a `RCPT TO:` path (`<x@dom>` or `x@dom`, optional brackets) names
/// a mailbox at [`LOCAL_DOMAIN`]; the domain is compared case-insensitively.
fn is_local_recipient(path: &[u8]) -> bool {
    let path = path.strip_prefix(b"<").unwrap_or(path);
    let path = path.strip_suffix(b">").unwrap_or(path);
    match path.iter().rposition(|&b| b == b'@') {
        Some(at) => path[at + 1..].eq_ignore_ascii_case(LOCAL_DOMAIN.as_bytes()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeedMode;

    fn msg(step: Step, consumed: usize, verb: &str) -> Parsed {
        Parsed::Message {
            consumed,
            verb: Some(verb.to_string()),
            step,
        }
    }

    #[test]
    fn smtp_banner() {
        let s = Smtp;
        assert_eq!(s.name(), "l4-smtp");
        assert_eq!(s.banner(), Some(b"220 target.test ESMTP aitm\r\n".to_vec()));
        assert_eq!(s.max_buffer(), 1026);
        assert_eq!(DEF.name, "l4-smtp");
        assert_eq!(DEF.grammar, "smtp");
        assert_eq!(DEF.proto, Proto::Tcp);
        assert_eq!((DEF.new_conn)().name(), "l4-smtp");
    }

    #[test]
    fn smtp_session() {
        let mut s = Smtp;
        let v = SeedMode::Vulnerable;
        assert_eq!(
            s.parse(v, b"EHLO x\r\n"),
            msg(Step::Reply(b"250 target.test\r\n".to_vec()), 8, "EHLO")
        );
        assert_eq!(
            s.parse(v, b"helo x\r\n"),
            msg(Step::Reply(b"250 target.test\r\n".to_vec()), 8, "HELO")
        );
        assert_eq!(
            s.parse(v, b"MAIL FROM:<a@target.test>\r\n"),
            msg(Step::Reply(b"250 OK\r\n".to_vec()), 27, "MAIL")
        );
        assert_eq!(
            s.parse(v, b"RCPT TO:<b@target.test>\r\n"),
            msg(Step::Reply(b"250 OK\r\n".to_vec()), 25, "RCPT")
        );
        assert_eq!(
            s.parse(v, b"RCPT TO:<b@TARGET.Test>\r\n"),
            msg(Step::Reply(b"250 OK\r\n".to_vec()), 25, "RCPT")
        );
        assert_eq!(
            s.parse(v, b"RCPT TO:<b@other.example>\r\n"),
            msg(
                Step::Denylisted(b"550 relay denied\r\n".to_vec()),
                27,
                "RCPT"
            )
        );
        assert_eq!(
            s.parse(v, b"RCPT TO:<b@target.test.evil>\r\n"),
            msg(
                Step::Denylisted(b"550 relay denied\r\n".to_vec()),
                30,
                "RCPT"
            )
        );
        assert_eq!(
            s.parse(v, b"NOOP\r\n"),
            msg(Step::Reply(b"250 OK\r\n".to_vec()), 6, "NOOP")
        );
        assert_eq!(
            s.parse(v, b"DATA\r\n"),
            msg(
                Step::ProtocolError(b"451 not accepted\r\n".to_vec()),
                6,
                "DATA"
            )
        );
        assert_eq!(
            s.parse(v, b"VRFY root\r\n"),
            msg(
                Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
                11,
                "VRFY"
            )
        );
        // Only the first line is consumed; the rest stays for the next call.
        assert_eq!(
            s.parse(v, b"QUIT\r\nNOOP\r\n"),
            msg(Step::Close(Some(b"221 bye\r\n".to_vec())), 6, "QUIT")
        );
        // Patched mode answers the benign exchange identically.
        assert_eq!(
            s.parse(SeedMode::Patched, b"NOOP\r\n"),
            msg(Step::Reply(b"250 OK\r\n".to_vec()), 6, "NOOP")
        );
    }

    #[test]
    fn smtp_incomplete_idle_and_empty() {
        let mut s = Smtp;
        assert_eq!(s.parse(SeedMode::Vulnerable, b""), Parsed::Incomplete);
        assert_eq!(s.parse(SeedMode::Vulnerable, b"NOO"), Parsed::Incomplete);
        assert_eq!(s.parse(SeedMode::Vulnerable, b"NOOP\r"), Parsed::Incomplete);
        assert_eq!(s.on_idle(SeedMode::Vulnerable, b"NOO"), Step::Close(None));
        assert_eq!(s.on_idle(SeedMode::Patched, b"NOO"), Step::Close(None));
        assert_eq!(
            s.parse(SeedMode::Vulnerable, b"\r\n"),
            Parsed::Message {
                consumed: 2,
                verb: None,
                step: Step::ProtocolError(b"500 unknown command\r\n".to_vec()),
            }
        );
    }

    #[test]
    fn smtp_long_line() {
        let mut s = Smtp;
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
