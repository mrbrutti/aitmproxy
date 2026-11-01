//! The `memcached` grammar (spec S3 row 3): the memcached text protocol.
//!
//! A request is one command line — `get mykey\r\n`, `version\r\n` — except
//! for the storage commands, which declare a byte count on the command line
//! and put the data on the line after it (`set mykey 0 0 2\r\nhi\r\n`).
//! `grammars/memcached.yaml` holds both forms as two YAML documents;
//! [`Memcached::parse`] tries the command form first and falls back to the
//! storage one, so each form keeps the key field its own syntax needs.
//!
//! The lane generates only read-only commands (`version`, `get`, `gets`,
//! `touch`); everything that flushes, reconfigures or stops the server is
//! refused by [`crate::denylist`] before any write.

use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{self, Tree};

/// Both forms of the grammar, as the operator reads them.
const YAML: &str = include_str!("../../grammars/memcached.yaml");

/// The commands the generator may send. All four are read-only.
const COMMANDS: usize = 4;

/// The alphabet of a generated key: a memcached key may hold no space and no
/// control byte.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// The replies that mean the server rejected what it was sent.
const ERRORS: &[&[u8]] = &[b"ERROR", b"CLIENT_ERROR", b"SERVER_ERROR"];

/// The replies that are well-formed answers, whatever they say.
const ANSWERS: &[&[u8]] = &[
    b"STORED",
    b"NOT_STORED",
    b"EXISTS",
    b"NOT_FOUND",
    b"VALUE",
    b"END",
    b"DELETED",
    b"TOUCHED",
    b"VERSION",
    b"OK",
    b"STAT",
];

/// The memcached text protocol: the command line, with the storage form as a
/// fallback.
#[derive(Debug, Clone)]
pub struct Memcached {
    command: MessageSpec,
    storage: MessageSpec,
}

impl Memcached {
    /// The grammar, loaded from the embedded `grammars/memcached.yaml`.
    ///
    /// # Panics
    ///
    /// Never at run time: the only input is the grammar file compiled into
    /// the binary, and a test parses it.
    #[must_use]
    pub fn new() -> Memcached {
        let (command, storage) = documents(YAML);
        Memcached {
            command: MessageSpec::from_yaml(command)
                .expect("the embedded memcached grammar is valid"),
            storage: MessageSpec::from_yaml(storage)
                .expect("the embedded memcached storage grammar is valid"),
        }
    }
}

impl Default for Memcached {
    fn default() -> Memcached {
        Memcached::new()
    }
}

/// The `memcached` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Memcached::new())
}

/// The two documents of `grammars/memcached.yaml`, split at the `---` line:
/// the command form, then the storage form.
fn documents(text: &str) -> (&str, &str) {
    text.split_once("\n---\n")
        .expect("the embedded memcached grammar holds two documents")
}

impl Grammar for Memcached {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Memcached
    }

    fn name(&self) -> &'static str {
        GrammarKind::Memcached.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.command
    }

    /// Both documents of `grammars/memcached.yaml`, in the order
    /// [`Memcached::parse`] tries them.
    fn specs(&self) -> Vec<&MessageSpec> {
        vec![&self.command, &self.storage]
    }

    fn default_ports(&self) -> &'static [u16] {
        &[11211]
    }

    fn transport(&self) -> Transport {
        self.command.transport
    }

    /// A command line if the bytes are one, else a storage command and its
    /// data block.
    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        tree::parse(&self.command, bytes).or_else(|| tree::parse(&self.storage, bytes))
    }

    /// One read-only command line.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let choice = rng.random_range(0..COMMANDS);
        if choice == 0 {
            return b"version\r\n".to_vec();
        }
        let (verb, arguments): (&[u8], &[u8]) = match choice {
            1 => (b"get", b""),
            2 => (b"gets", b""),
            // The new expiry: 0 is "never", which is also the default, so
            // this reads whether the key is there and changes nothing.
            _ => (b"touch", b" 0"),
        };
        let mut out = verb.to_vec();
        out.push(b' ');
        out.extend_from_slice(&random_key(rng));
        out.extend_from_slice(arguments);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// By the reply's first word: the three `*ERROR` words are the server
    /// rejecting the request, the status words and a bare number are
    /// well-formed answers, anything else is not this protocol.
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        let word = first_word(reply);
        if word.is_empty() {
            return ReplyClass::Unknown;
        }
        if ERRORS.iter().any(|error| word.eq_ignore_ascii_case(error)) {
            return ReplyClass::ProtocolError;
        }
        if ANSWERS
            .iter()
            .any(|answer| word.eq_ignore_ascii_case(answer))
            || word.iter().all(u8::is_ascii_digit)
        {
            return ReplyClass::Ok;
        }
        ReplyClass::Unknown
    }

    /// `true` once the whole reply has arrived: one CRLF-terminated line, or,
    /// for a retrieval, everything up to and including the `END` line that
    /// closes it.
    fn reply_complete(&self, buf: &[u8]) -> bool {
        if buf.starts_with(b"VALUE") {
            return buf.windows(7).any(|window| window == b"\r\nEND\r\n");
        }
        buf.windows(2).any(|pair| pair == b"\r\n")
    }

    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: b"version\r\n".to_vec(),
            expect: Expect::Prefix(b"VERSION ".to_vec()),
            after: None,
        }
    }

    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// The text protocol has no credential command — SASL authentication is
    /// the binary protocol's, which this grammar does not speak — so no seed
    /// is dropped for carrying one.
    fn is_credential_message(&self, _bytes: &[u8]) -> bool {
        false
    }
}

/// The reply's first word: everything up to the first space or CR.
fn first_word(reply: &[u8]) -> &[u8] {
    let end = reply
        .iter()
        .position(|byte| matches!(byte, b' ' | b'\r' | b'\n'))
        .unwrap_or(reply.len());
    &reply[..end]
}

/// A key of the lane's own, so a generated command cannot read somebody
/// else's data by accident.
fn random_key(rng: &mut ChaCha8Rng) -> Vec<u8> {
    let mut key = b"aitm-scan-".to_vec();
    key.extend((0..8).map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())]));
    key
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{grammar, Memcached};
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Grammar, ReplyClass};
    use crate::spec::{GrammarKind, LenOf, Relation, Transport};
    use crate::tree::{render, resatisfy, FieldPath, Tree};

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has a node at '{path}'"))
            .bytes
            .clone()
    }

    #[test]
    fn memcached_identity() {
        let memcached = grammar();
        assert_eq!(memcached.kind(), GrammarKind::Memcached);
        assert_eq!(memcached.name(), "memcached");
        assert_eq!(memcached.transport(), Transport::Tcp);
        assert_eq!(memcached.default_ports(), &[11211]);
        assert_eq!(memcached.spec().grammar, "memcached");
        assert_eq!(memcached.spec().default_ports, vec![11211]);
        assert!(
            memcached
                .spec()
                .reply
                .as_ref()
                .is_some_and(|reply| reply.contains("CRLF-terminated line")),
            "the grammar file explains its replies in prose"
        );
        assert!(memcached.prelude().is_empty());
        assert!(!memcached.expects_banner());
        assert!(!memcached.close_on_malformed_is_expected());
        assert!(
            !memcached.is_credential_message(b"set k 0 0 2\r\nhi\r\n"),
            "the text protocol has no credential command"
        );
        assert!(memcached.strip_credentials(b"version\r\n").is_none());
        assert_eq!(Memcached::new().name(), "memcached");
    }

    #[test]
    fn memcached_generate_parses_back() {
        let memcached = grammar();
        let known: [Vec<u8>; 4] = [
            b"version".to_vec(),
            b"get".to_vec(),
            b"gets".to_vec(),
            b"touch".to_vec(),
        ];
        let mut verbs: Vec<Vec<u8>> = Vec::new();

        for seed in 0..64_u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let case = memcached.generate(&mut rng);

            let tree = memcached
                .parse(&case)
                .unwrap_or_else(|| panic!("the case generated from seed {seed} parses back"));
            assert_eq!(
                render(&tree),
                case,
                "the case generated from seed {seed} renders unchanged"
            );
            assert_eq!(
                denylist::refuses(GrammarKind::Memcached, &case),
                None,
                "a generated case is never a denylisted command"
            );
            assert!(
                case.ends_with(b"\r\n"),
                "every command is one CRLF-terminated line"
            );

            verbs.push(bytes_at(&tree, "line.cmd"));
        }

        for verb in &known {
            assert!(
                verbs.contains(verb),
                "64 seeds cover every generated command, including {}",
                String::from_utf8_lossy(verb)
            );
        }
        assert!(
            verbs.iter().all(|verb| known.contains(verb)),
            "and nothing else"
        );
    }

    #[test]
    fn memcached_classify() {
        let memcached = grammar();
        assert_eq!(memcached.classify_reply(b"VERSION 1.6\r\n"), ReplyClass::Ok);
        assert_eq!(
            memcached.classify_reply(b"CLIENT_ERROR bad\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(memcached.classify_reply(b"STORED\r\n"), ReplyClass::Ok);
        assert_eq!(memcached.classify_reply(b"wat\r\n"), ReplyClass::Unknown);
        assert_eq!(memcached.classify_reply(b""), ReplyClass::Unknown);
        assert_eq!(memcached.classify_reply(b"END\r\n"), ReplyClass::Ok);
        assert_eq!(memcached.classify_reply(b"NOT_FOUND\r\n"), ReplyClass::Ok);
        assert_eq!(
            memcached.classify_reply(b"ERROR\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            memcached.classify_reply(b"SERVER_ERROR out of memory\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            memcached.classify_reply(b"42\r\n"),
            ReplyClass::Ok,
            "incr and decr answer with a bare number"
        );
    }

    #[test]
    fn memcached_storage_len_relation() {
        let memcached = grammar();
        let wire = b"set k 0 0 2\r\nhi\r\n";
        let mut tree = memcached.parse(wire).expect("a storage command parses");

        assert_eq!(bytes_at(&tree, "storage.bytes"), b"2".to_vec());
        assert_eq!(
            tree.get(&FieldPath::new("storage.bytes"))
                .expect("storage.bytes")
                .relation,
            Some(Relation::Len {
                of: LenOf::Fields(vec!["data".to_string()]),
                inclusive: false,
                adjust: 0,
            })
        );
        assert_eq!(bytes_at(&tree, "storage.data"), b"hi".to_vec());
        assert_eq!(bytes_at(&tree, "line.cmd"), b"set".to_vec());
        assert_eq!(bytes_at(&tree, "line.key"), b"k ".to_vec());
        assert_eq!(render(&tree), wire.to_vec());

        tree.get_mut(&FieldPath::new("storage.data"))
            .expect("storage.data")
            .bytes
            .push(b'!');
        resatisfy(&mut tree, None);

        assert_eq!(bytes_at(&tree, "storage.bytes"), b"3".to_vec());
        assert_eq!(render(&tree), b"set k 0 0 3\r\nhi!\r\n".to_vec());
    }

    #[test]
    fn memcached_command_paths() {
        let memcached = grammar();

        let get = memcached
            .parse(b"get mykey\r\n")
            .expect("a retrieval parses");
        let paths: Vec<String> = get
            .mutable_leaves()
            .iter()
            .map(|node| node.path.to_string())
            .collect();
        assert_eq!(
            paths,
            vec![
                "line.cmd",
                "line.tail.with_args.sp",
                "line.tail.with_args.key",
            ]
        );
        assert_eq!(bytes_at(&get, "line.cmd"), b"get".to_vec());
        assert_eq!(
            bytes_at(&get, "line.tail.with_args.key"),
            b"mykey\r\n".to_vec(),
            "the key field holds the rest of the line, its CRLF included"
        );
        assert_eq!(render(&get), b"get mykey\r\n".to_vec());

        let version = memcached
            .parse(b"version\r\n")
            .expect("a command with no argument parses");
        let paths: Vec<String> = version
            .mutable_leaves()
            .iter()
            .map(|node| node.path.to_string())
            .collect();
        assert_eq!(paths, vec!["line.cmd", "line.tail.crlf"]);
        assert_eq!(render(&version), b"version\r\n".to_vec());

        let touch = memcached
            .parse(b"touch mykey 0\r\n")
            .expect("a command with further arguments parses");
        assert_eq!(
            bytes_at(&touch, "line.tail.with_args.key"),
            b"mykey 0\r\n".to_vec()
        );

        assert!(memcached.parse(b"nonsense mykey\r\n").is_none());
        assert!(memcached.parse(b"get mykey").is_none());
    }

    #[test]
    fn memcached_reply_complete() {
        let memcached = grammar();
        assert!(!memcached.reply_complete(b""));
        assert!(!memcached.reply_complete(b"VERSION 1."));
        assert!(memcached.reply_complete(b"VERSION 1.6\r\n"));
        assert!(memcached.reply_complete(b"STORED\r\n"));
        assert!(
            !memcached.reply_complete(b"VALUE k 0 2\r\nhi\r\n"),
            "a retrieval runs to its END line, not to the first CRLF"
        );
        assert!(memcached.reply_complete(b"VALUE k 0 2\r\nhi\r\nEND\r\n"));
        assert!(memcached.reply_complete(b"END\r\n"));
    }

    #[test]
    fn memcached_liveness_asks_the_version() {
        let probe = grammar().liveness_probe();
        assert_eq!(probe.send, b"version\r\n".to_vec());
        assert_eq!(probe.after, None);
        assert!(probe.matches(b"VERSION 1.6.21\r\n", Ended::Replied));
        assert!(!probe.matches(b"ERROR\r\n", Ended::Replied));
        assert!(!probe.matches(b"", Ended::Silence));
    }
}
