//! The `smtp` grammar (spec S3 row 7): one command line per message.
//!
//! SMTP is a line protocol, so the whole grammar is a verb, an optional
//! space and the rest of the line up to its CRLF. The server speaks first:
//! [`Smtp::expects_banner`] is `true`, so the host reads the 220 banner
//! before it writes, and [`banner_host`] recovers the hostname the server
//! announced there for the `RCPT` rule in [`crate::denylist`].
//!
//! This module also owns the reply rules both line grammars share — three
//! ASCII digits, then a space on the final line or a hyphen on a
//! continuation — because spec S3 row 8 defines FTP's replies as "as SMTP";
//! [`crate::grammars::ftp`] uses them rather than restating them.
//!
//! Nothing here opens a mail transaction: `DATA`, `BDAT` and the relay verbs
//! are refused by [`crate::denylist`] before any write, and `AUTH` lines are
//! dropped from the corpus by [`Smtp::is_credential_message`].

use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{self, Tree};

/// The grammar document, embedded at build time (spec S3).
const YAML: &str = include_str!("../../grammars/smtp.yaml");

/// The ports SMTP is the convention on.
const PORTS: &[u16] = &[25, 587];

/// The commands [`Smtp::generate`] invents, all of which read the server's
/// state and none of which starts a mail transaction: `MAIL FROM` names a
/// sender and is never followed by a `RCPT`, so nothing is ever queued.
const GENERATED: [&[u8]; 4] = [
    b"NOOP\r\n",
    b"HELP\r\n",
    b"VRFY postmaster\r\n",
    b"MAIL FROM:<a@target.test>\r\n",
];

/// The verbs whose line carries a credential, so the seed never enters the
/// corpus (spec S3 "Credential filter").
const CREDENTIAL_VERBS: &[&str] = &["AUTH"];

/// The SMTP command grammar.
#[derive(Debug)]
pub struct Smtp {
    spec: MessageSpec,
}

impl Smtp {
    /// The grammar, built from the embedded document.
    ///
    /// # Panics
    ///
    /// Never for the shipped file: the embedded grammar is parsed and
    /// validated by this crate's tests, and it is not operator input (crate
    /// hygiene: `expect` is allowed on the embedded grammars alone).
    #[must_use]
    pub fn new() -> Smtp {
        Smtp {
            spec: MessageSpec::from_yaml(YAML).expect("the embedded smtp grammar is valid"),
        }
    }
}

impl Default for Smtp {
    fn default() -> Smtp {
        Smtp::new()
    }
}

/// The `smtp` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Smtp::new())
}

impl Grammar for Smtp {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Smtp
    }

    fn name(&self) -> &'static str {
        GrammarKind::Smtp.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        PORTS
    }

    fn transport(&self) -> Transport {
        self.spec.transport
    }

    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        tree::parse(&self.spec, bytes)
    }

    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let at = rng.random_range(0..GENERATED.len());
        GENERATED.get(at).copied().unwrap_or(b"NOOP\r\n").to_vec()
    }

    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        classify_code_line(reply)
    }

    fn reply_complete(&self, buf: &[u8]) -> bool {
        final_line_complete(buf)
    }

    /// `NOOP` asks the server for nothing but a 250, and the best-effort
    /// `QUIT` closes the session politely (spec S3 row 7, amendment A3).
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: b"NOOP\r\n".to_vec(),
            expect: Expect::Prefix(b"250".to_vec()),
            after: Some(b"QUIT\r\n".to_vec()),
        }
    }

    /// One `EHLO` from a name that resolves nowhere: the lane announces
    /// itself without claiming to be a host the server might trust.
    fn prelude(&self) -> Vec<Vec<u8>> {
        vec![b"EHLO aitm.scan.invalid\r\n".to_vec()]
    }

    fn expects_banner(&self) -> bool {
        true
    }

    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        has_verb(bytes, CREDENTIAL_VERBS)
    }
}

// ---------------------------------------------------------------------------
// The reply rules both line grammars share (spec S3 rows 7 and 8)
// ---------------------------------------------------------------------------

/// What a three-digit reply says about the peer.
///
/// The verdict is the final line's — the line whose fourth byte is a space —
/// because a multi-line reply only states its outcome there; a reply read
/// before its final line arrived is judged by its first line instead. Bytes
/// that are not a coded line at all are [`ReplyClass::Unknown`].
#[must_use]
pub(crate) fn classify_code_line(reply: &[u8]) -> ReplyClass {
    let mut first: Option<u8> = None;
    let mut last_final: Option<u8> = None;
    for line in crlf_lines(reply) {
        let Some((digit, is_final)) = line_code(line) else {
            continue;
        };
        if first.is_none() {
            first = Some(digit);
        }
        if is_final {
            last_final = Some(digit);
        }
    }
    match last_final.or(first) {
        Some(b'2' | b'3') => ReplyClass::Ok,
        Some(b'4' | b'5') => ReplyClass::ProtocolError,
        _ => ReplyClass::Unknown,
    }
}

/// `true` when `buf` already holds a whole reply: a CRLF-terminated last
/// line whose fourth byte is a space. A `250-` line continues the reply, so
/// the reader goes on (spec S3 "Reply reading").
#[must_use]
pub(crate) fn final_line_complete(buf: &[u8]) -> bool {
    if !buf.ends_with(b"\r\n") {
        return false;
    }
    crlf_lines(buf)
        .last()
        .and_then(|line| line_code(line))
        .is_some_and(|(_, is_final)| is_final)
}

/// `true` when any line of `bytes` begins with one of `verbs`, compared
/// case-insensitively. A seed is judged line by line, so a credential hidden
/// behind a harmless first line is still caught.
#[must_use]
pub(crate) fn has_verb(bytes: &[u8], verbs: &[&str]) -> bool {
    crlf_lines(bytes).into_iter().any(|line| {
        leading_verb(line).is_some_and(|verb| {
            verbs
                .iter()
                .any(|wanted| verb.eq_ignore_ascii_case(wanted.as_bytes()))
        })
    })
}

/// The hostname the server announced in its 220 banner — the word after the
/// code — for [`crate::denylist::DenyContext::banner_host`].
///
/// `None` when the banner is not a 220 line or announces no name.
#[must_use]
pub fn banner_host(banner: &[u8]) -> Option<String> {
    let first = crlf_lines(banner).into_iter().next()?;
    line_code(first)?;
    if first.get(..3)? != b"220" {
        return None;
    }
    let rest = first.get(4..)?;
    let end = rest
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(rest.len());
    let word = rest.get(..end)?;
    if word.is_empty() {
        return None;
    }
    std::str::from_utf8(word).ok().map(ToString::to_string)
}

/// The reply code's first digit and whether the line is the final one:
/// three ASCII digits, then a space (final) or a hyphen (continuation).
fn line_code(line: &[u8]) -> Option<(u8, bool)> {
    let head = line.get(..4)?;
    if !head.get(..3)?.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match head.get(3)? {
        b' ' => Some((*head.first()?, true)),
        b'-' => Some((*head.first()?, false)),
        _ => None,
    }
}

/// The line's leading run of ASCII letters: its verb, or `None` when the
/// line does not start with one.
fn leading_verb(line: &[u8]) -> Option<&[u8]> {
    let end = line
        .iter()
        .position(|byte| !byte.is_ascii_alphabetic())
        .unwrap_or(line.len());
    line.get(..end).filter(|verb| !verb.is_empty())
}

/// `buf` split at every CRLF, terminators dropped, with any trailing partial
/// line kept so an unterminated reply still classifies.
fn crlf_lines(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut at = 0usize;
    while at + 1 < buf.len() {
        if buf.get(at) == Some(&b'\r') && buf.get(at + 1) == Some(&b'\n') {
            if let Some(line) = buf.get(start..at) {
                out.push(line);
            }
            at += 2;
            start = at;
        } else {
            at += 1;
        }
    }
    if let Some(tail) = buf.get(start..) {
        if !tail.is_empty() {
            out.push(tail);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{banner_host, grammar};
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Expect, ReplyClass};
    use crate::grammars::testkit;
    use crate::spec::{GrammarKind, MessageSpec, Transport};
    use crate::tree::{render, FieldPath};

    #[test]
    fn smtp_yaml_round_trips() {
        let smtp = grammar();
        assert_eq!(smtp.kind(), GrammarKind::Smtp);
        assert_eq!(smtp.name(), "smtp");
        assert_eq!(smtp.transport(), Transport::Tcp);
        assert_eq!(smtp.default_ports(), &[25, 587]);
        assert_eq!(smtp.spec().grammar, "smtp");
        assert_eq!(smtp.spec().default_ports, vec![25, 587]);
        assert!(!smtp.close_on_malformed_is_expected());
        assert!(smtp.expects_banner());

        let yaml = smtp.spec().to_yaml().expect("the spec serialises");
        let again = MessageSpec::from_yaml(&yaml).expect("and parses back");
        assert_eq!(&again, smtp.spec());
    }

    #[test]
    fn smtp_generate_parses_back() {
        let smtp = grammar();
        let mut rng = ChaCha8Rng::seed_from_u64(12);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for _ in 0..200 {
            let message = smtp.generate(&mut rng);
            let tree = smtp
                .parse(&message)
                .expect("a generated message is a message of its own grammar");
            assert_eq!(tree.grammar, "smtp");
            assert_eq!(render(&tree), message);
            assert_eq!(denylist::refuses(GrammarKind::Smtp, &message), None);
            if !seen.contains(&message) {
                seen.push(message);
            }
        }
        seen.sort();
        let expected: Vec<Vec<u8>> = vec![
            b"HELP\r\n".to_vec(),
            b"MAIL FROM:<a@target.test>\r\n".to_vec(),
            b"NOOP\r\n".to_vec(),
            b"VRFY postmaster\r\n".to_vec(),
        ];
        assert_eq!(seen, expected);
    }

    #[test]
    fn line_classify() {
        let smtp = grammar();
        assert_eq!(smtp.classify_reply(b"250 OK\r\n"), ReplyClass::Ok);
        assert_eq!(
            smtp.classify_reply(b"500 unknown\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            smtp.classify_reply(b"220 target.test ESMTP aitm\r\n"),
            ReplyClass::Ok
        );
        assert_eq!(smtp.classify_reply(b"hello\r\n"), ReplyClass::Unknown);
        assert_eq!(smtp.classify_reply(b""), ReplyClass::Unknown);
        assert_eq!(smtp.classify_reply(b"354 go ahead\r\n"), ReplyClass::Ok);
        assert_eq!(
            smtp.classify_reply(b"421 closing\r\n"),
            ReplyClass::ProtocolError
        );
        // A multi-line reply is judged by its final line.
        assert_eq!(
            smtp.classify_reply(b"250-PIPELINING\r\n250 HELP\r\n"),
            ReplyClass::Ok
        );
    }

    #[test]
    fn multiline_reply_complete() {
        let smtp = grammar();
        assert!(!smtp.reply_complete(b""));
        assert!(!smtp.reply_complete(b"250 OK"));
        assert!(smtp.reply_complete(b"250 OK\r\n"));
        assert!(!smtp.reply_complete(b"250-a\r\n"));
        assert!(smtp.reply_complete(b"250-a\r\n250 b\r\n"));
    }

    #[test]
    fn credential_filters() {
        let smtp = grammar();
        assert!(smtp.is_credential_message(b"AUTH PLAIN x\r\n"));
        assert!(smtp.is_credential_message(b"auth login\r\n"));
        assert!(smtp.is_credential_message(b"EHLO a\r\nAUTH PLAIN x\r\n"));
        assert!(!smtp.is_credential_message(b"NOOP\r\n"));
        assert!(!smtp.is_credential_message(b"MAIL FROM:<a@target.test>\r\n"));
        // SMTP never strips: a seed carrying a credential is dropped whole.
        assert_eq!(smtp.strip_credentials(b"AUTH PLAIN x\r\n"), None);
    }

    #[test]
    fn banner_host_is_the_word_after_220() {
        assert_eq!(
            banner_host(b"220 target.test ESMTP aitm\r\n"),
            Some("target.test".to_string())
        );
        assert_eq!(
            banner_host(b"220-target.test ESMTP\r\n220 ready\r\n"),
            Some("target.test".to_string())
        );
        assert_eq!(
            banner_host(b"220 mail.test\r\n"),
            Some("mail.test".to_string())
        );
        assert_eq!(banner_host(b"220\r\n"), None);
        assert_eq!(banner_host(b"220 \r\n"), None);
        assert_eq!(banner_host(b"554 no service\r\n"), None);
        assert_eq!(banner_host(b""), None);
    }

    #[test]
    fn long_line_is_a_mutable_leaf_path() {
        let smtp = grammar();
        let mut long = b"VRFY ".to_vec();
        long.extend(std::iter::repeat_n(b'A', 2000));
        long.extend_from_slice(b"\r\n");

        let tree = smtp.parse(&long).expect("a long line is still a command");
        assert_eq!(render(&tree), long);
        let paths: Vec<&str> = tree
            .mutable_leaves()
            .iter()
            .map(|node| node.path.as_str())
            .collect();
        assert_eq!(paths, ["command.verb", "command.sp.present", "command.arg"]);

        let arg = tree
            .get(&"command.arg".into())
            .expect("the argument is a node of its own");
        assert_eq!(arg.bytes.len(), 2002);

        // Without an argument the separator's empty alternative stands in, and
        // the two mutable leaves are the same two.
        let bare = smtp.parse(b"NOOP\r\n").expect("NOOP is a command");
        assert_eq!(render(&bare), b"NOOP\r\n".to_vec());
        let leaves: Vec<&str> = bare
            .leaves()
            .iter()
            .map(|node| node.path.as_str())
            .collect();
        assert_eq!(leaves, ["command.verb", "command.sp.absent", "command.arg"]);
        let mutable: Vec<&str> = bare
            .mutable_leaves()
            .iter()
            .map(|node| node.path.as_str())
            .collect();
        assert_eq!(mutable, ["command.verb", "command.arg"]);

        assert!(
            smtp.parse(b"NOOP").is_none(),
            "an unterminated line is not a message"
        );
        assert!(
            smtp.parse(b"ZZZZ x\r\n").is_none(),
            "an unknown verb is not a message"
        );
    }

    /// S6.4 runs `delim_remove`, `delim_dup` and `delim_inject` on every
    /// `delim` node, so the separator the line grammar is built around has to
    /// be a mutable one (S2 keeps `mutable: false` for ids and magic). The
    /// empty alternative stays immutable: there is no separator to move.
    #[test]
    fn the_present_separator_is_a_delim_point() {
        let smtp = grammar();
        testkit::assert_separator_is_a_delim_point(
            smtp.as_ref(),
            b"VRFY postmaster\r\n",
            "command.sp.present",
            b"VRFYpostmaster\r\n",
            b"VRFY  postmaster\r\n",
        );

        // The empty alternative stays immutable: there is no separator to move.
        let absent = smtp
            .parse(b"NOOP\r\n")
            .expect("NOOP is a command")
            .get(&FieldPath::new("command.sp.absent"))
            .expect("the empty alternative is a node of its own")
            .mutable;
        assert!(!absent, "the empty alternative stays immutable");
    }

    #[test]
    fn liveness_and_prelude() {
        let smtp = grammar();
        let probe = smtp.liveness_probe();
        assert_eq!(probe.send, b"NOOP\r\n".to_vec());
        assert_eq!(probe.expect, Expect::Prefix(b"250".to_vec()));
        assert_eq!(probe.after, Some(b"QUIT\r\n".to_vec()));
        assert!(probe.matches(b"250 2.0.0 OK\r\n", Ended::Replied));
        assert!(!probe.matches(b"500 unknown\r\n", Ended::Replied));
        assert!(!probe.matches(b"", Ended::Silence));

        assert_eq!(smtp.prelude(), vec![b"EHLO aitm.scan.invalid\r\n".to_vec()]);
        assert_eq!(smtp.prelude_for(b"NOOP\r\n"), smtp.prelude());
        for message in smtp.prelude() {
            assert_eq!(denylist::refuses(GrammarKind::Smtp, &message), None);
        }
    }
}
