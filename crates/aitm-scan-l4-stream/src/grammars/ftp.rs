//! The `ftp` grammar (spec S3 row 8): one control-channel command per
//! message.
//!
//! FTP's control channel is framed and replied to exactly as SMTP is — spec
//! S3 row 8 says "as SMTP" — so the reply rules come from
//! [`crate::grammars::smtp`] rather than being restated here: three ASCII
//! digits, a space on the final line, a hyphen on a continuation.
//!
//! The server speaks first, so [`Ftp::expects_banner`] is `true` and the
//! host reads the 220 banner before it writes. The prelude logs in
//! anonymously; a refusal there is recorded and the campaign runs
//! unauthenticated. The lane never opens a data channel: every verb that
//! would (`RETR`, `STOR`, `PASV`, `PORT`, the listings) and every verb that
//! would destroy something (`DELE`, `RMD`, ...) is refused by
//! [`crate::denylist`] before the write, and captured `USER`/`PASS` lines
//! are dropped from the corpus by [`Ftp::is_credential_message`].

use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::grammars::smtp::{classify_code_line, final_line_complete, has_verb};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{self, Tree};

/// The grammar document, embedded at build time (spec S3).
const YAML: &str = include_str!("../../grammars/ftp.yaml");

/// The ports FTP's control channel is the convention on.
const PORTS: &[u16] = &[21];

/// The commands [`Ftp::generate`] invents. All four read the session's own
/// state; none names a path, opens a data channel or changes anything.
const GENERATED: [&[u8]; 4] = [b"NOOP\r\n", b"SYST\r\n", b"PWD\r\n", b"TYPE I\r\n"];

/// The verbs whose line carries a credential, so the seed never enters the
/// corpus (spec S3 "Credential filter").
const CREDENTIAL_VERBS: &[&str] = &["USER", "PASS"];

/// The FTP control-channel command grammar.
#[derive(Debug)]
pub struct Ftp {
    spec: MessageSpec,
}

impl Ftp {
    /// The grammar, built from the embedded document.
    ///
    /// # Panics
    ///
    /// Never for the shipped file: the embedded grammar is parsed and
    /// validated by this crate's tests, and it is not operator input (crate
    /// hygiene: `expect` is allowed on the embedded grammars alone).
    #[must_use]
    pub fn new() -> Ftp {
        Ftp {
            spec: MessageSpec::from_yaml(YAML).expect("the embedded ftp grammar is valid"),
        }
    }
}

impl Default for Ftp {
    fn default() -> Ftp {
        Ftp::new()
    }
}

/// The `ftp` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Ftp::new())
}

impl Grammar for Ftp {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Ftp
    }

    fn name(&self) -> &'static str {
        GrammarKind::Ftp.name()
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

    /// `NOOP` asks the server for nothing but a 200, and the best-effort
    /// `QUIT` closes the session politely (spec S3 row 8, amendment A3).
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: b"NOOP\r\n".to_vec(),
            expect: Expect::Prefix(b"200".to_vec()),
            after: Some(b"QUIT\r\n".to_vec()),
        }
    }

    /// The anonymous login every FTP server either grants or refuses with a
    /// 530; the password is an address at a domain that resolves nowhere.
    fn prelude(&self) -> Vec<Vec<u8>> {
        vec![
            b"USER anonymous\r\n".to_vec(),
            b"PASS aitm@scan.invalid\r\n".to_vec(),
        ]
    }

    fn expects_banner(&self) -> bool {
        true
    }

    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        has_verb(bytes, CREDENTIAL_VERBS)
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::grammar;
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Expect, ReplyClass};
    use crate::grammars::testkit;
    use crate::spec::{GrammarKind, MessageSpec, Transport};
    use crate::tree::{render, FieldPath};

    #[test]
    fn ftp_yaml_round_trips() {
        let ftp = grammar();
        assert_eq!(ftp.kind(), GrammarKind::Ftp);
        assert_eq!(ftp.name(), "ftp");
        assert_eq!(ftp.transport(), Transport::Tcp);
        assert_eq!(ftp.default_ports(), &[21]);
        assert_eq!(ftp.spec().grammar, "ftp");
        assert_eq!(ftp.spec().default_ports, vec![21]);
        assert!(!ftp.close_on_malformed_is_expected());
        assert!(ftp.expects_banner());

        let yaml = ftp.spec().to_yaml().expect("the spec serialises");
        let again = MessageSpec::from_yaml(&yaml).expect("and parses back");
        assert_eq!(&again, ftp.spec());
    }

    #[test]
    fn ftp_generate_parses_back() {
        let ftp = grammar();
        let mut rng = ChaCha8Rng::seed_from_u64(12);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for _ in 0..200 {
            let message = ftp.generate(&mut rng);
            let tree = ftp
                .parse(&message)
                .expect("a generated message is a message of its own grammar");
            assert_eq!(tree.grammar, "ftp");
            assert_eq!(render(&tree), message);
            assert_eq!(denylist::refuses(GrammarKind::Ftp, &message), None);
            if !seen.contains(&message) {
                seen.push(message);
            }
        }
        seen.sort();
        let expected: Vec<Vec<u8>> = vec![
            b"NOOP\r\n".to_vec(),
            b"PWD\r\n".to_vec(),
            b"SYST\r\n".to_vec(),
            b"TYPE I\r\n".to_vec(),
        ];
        assert_eq!(seen, expected);
    }

    #[test]
    fn line_classify() {
        let ftp = grammar();
        assert_eq!(ftp.classify_reply(b"200 OK\r\n"), ReplyClass::Ok);
        assert_eq!(ftp.classify_reply(b"331 need password\r\n"), ReplyClass::Ok);
        assert_eq!(
            ftp.classify_reply(b"530 not logged in\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            ftp.classify_reply(b"220 target.test FTP aitm\r\n"),
            ReplyClass::Ok
        );
        assert_eq!(ftp.classify_reply(b"hello\r\n"), ReplyClass::Unknown);
        assert_eq!(ftp.classify_reply(b""), ReplyClass::Unknown);
    }

    #[test]
    fn multiline_reply_complete() {
        let ftp = grammar();
        assert!(!ftp.reply_complete(b""));
        assert!(!ftp.reply_complete(b"211-features:"));
        assert!(ftp.reply_complete(b"200 OK\r\n"));
        assert!(!ftp.reply_complete(b"211-a\r\n"));
        assert!(ftp.reply_complete(b"211-a\r\n211 b\r\n"));
    }

    #[test]
    fn credential_filters() {
        let ftp = grammar();
        assert!(ftp.is_credential_message(b"USER a\r\n"));
        assert!(ftp.is_credential_message(b"PASS b\r\n"));
        assert!(ftp.is_credential_message(b"pass b\r\n"));
        assert!(ftp.is_credential_message(b"NOOP\r\nPASS b\r\n"));
        assert!(!ftp.is_credential_message(b"NOOP\r\n"));
        assert!(!ftp.is_credential_message(b"SYST\r\n"));
        assert_eq!(ftp.strip_credentials(b"PASS b\r\n"), None);
    }

    #[test]
    fn long_line_is_a_mutable_leaf_path() {
        let ftp = grammar();
        let mut long = b"STAT ".to_vec();
        long.extend(std::iter::repeat_n(b'A', 2000));
        long.extend_from_slice(b"\r\n");

        let tree = ftp.parse(&long).expect("a long line is still a command");
        assert_eq!(render(&tree), long);
        let paths: Vec<&str> = tree
            .mutable_leaves()
            .iter()
            .map(|node| node.path.as_str())
            .collect();
        assert_eq!(paths, ["command.verb", "command.sp.present", "command.arg"]);

        let bare = ftp.parse(b"NOOP\r\n").expect("NOOP is a command");
        let leaves: Vec<&str> = bare
            .leaves()
            .iter()
            .map(|node| node.path.as_str())
            .collect();
        assert_eq!(leaves, ["command.verb", "command.sp.absent", "command.arg"]);

        assert!(
            ftp.parse(b"NOOP").is_none(),
            "an unterminated line is not a message"
        );
        assert!(
            ftp.parse(b"ZZZZ x\r\n").is_none(),
            "an unknown verb is not a message"
        );
    }

    /// The same S6.4 point SMTP has: the separator is a `delim` node, so the
    /// three delimiter mutators must reach it.
    #[test]
    fn the_present_separator_is_a_delim_point() {
        let ftp = grammar();
        testkit::assert_separator_is_a_delim_point(
            ftp.as_ref(),
            b"STAT /tmp\r\n",
            "command.sp.present",
            b"STAT/tmp\r\n",
            b"STAT  /tmp\r\n",
        );

        // The empty alternative stays immutable: there is no separator to move.
        let absent = ftp
            .parse(b"NOOP\r\n")
            .expect("NOOP is a command")
            .get(&FieldPath::new("command.sp.absent"))
            .expect("the empty alternative is a node of its own")
            .mutable;
        assert!(!absent, "the empty alternative stays immutable");
    }

    #[test]
    fn liveness_and_prelude() {
        let ftp = grammar();
        let probe = ftp.liveness_probe();
        assert_eq!(probe.send, b"NOOP\r\n".to_vec());
        assert_eq!(probe.expect, Expect::Prefix(b"200".to_vec()));
        assert_eq!(probe.after, Some(b"QUIT\r\n".to_vec()));
        assert!(probe.matches(b"200 NOOP ok\r\n", Ended::Replied));
        assert!(!probe.matches(b"530 not logged in\r\n", Ended::Replied));

        assert_eq!(
            ftp.prelude(),
            vec![
                b"USER anonymous\r\n".to_vec(),
                b"PASS aitm@scan.invalid\r\n".to_vec()
            ]
        );
        assert_eq!(ftp.prelude_for(b"NOOP\r\n"), ftp.prelude());
        for message in ftp.prelude() {
            assert_eq!(denylist::refuses(GrammarKind::Ftp, &message), None);
        }
    }
}
