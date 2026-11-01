//! The `resp` grammar (spec S3 row 2): Redis RESP requests.
//!
//! A request is an array of bulk strings — `*2\r\n$4\r\nECHO\r\n$2\r\nhi\r\n`
//! — or, for a client that sends them, one inline command line (`PING\r\n`).
//! `grammars/resp.yaml` holds both forms as two YAML documents; [`Resp::parse`]
//! tries the array form first and falls back to the inline one, so a captured
//! inline seed is not lost.
//!
//! The lane generates only read-only commands (`PING`, `ECHO`, `GET`,
//! `EXISTS`, `TYPE`); everything that writes, reconfigures or runs code is
//! refused by [`crate::denylist`] before any write, whatever a mutator did to
//! the bytes.

use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{self, FieldPath, Tree};

/// Both forms of the grammar, as the operator reads them.
const YAML: &str = include_str!("../../grammars/resp.yaml");

/// How deep a reply may nest before the reader stops trying to find its end.
const MAX_FRAME_DEPTH: usize = 8;

/// The commands the generator may send. All five are read-only.
const COMMANDS: usize = 5;

/// The alphabet of a generated key or argument: nothing that needs quoting,
/// nothing that could read as a verb.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Redis RESP: the array form, with the inline form as a fallback.
#[derive(Debug, Clone)]
pub struct Resp {
    array: MessageSpec,
    inline: MessageSpec,
}

impl Resp {
    /// The grammar, loaded from the embedded `grammars/resp.yaml`.
    ///
    /// # Panics
    ///
    /// Never at run time: the only input is the grammar file compiled into
    /// the binary, and a test parses it.
    #[must_use]
    pub fn new() -> Resp {
        let (array, inline) = documents(YAML);
        Resp {
            array: MessageSpec::from_yaml(array).expect("the embedded resp grammar is valid"),
            inline: MessageSpec::from_yaml(inline)
                .expect("the embedded resp inline grammar is valid"),
        }
    }
}

impl Default for Resp {
    fn default() -> Resp {
        Resp::new()
    }
}

/// The `resp` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Resp::new())
}

/// The two documents of `grammars/resp.yaml`, split at the `---` line: the
/// array form, then the inline form.
fn documents(text: &str) -> (&str, &str) {
    text.split_once("\n---\n")
        .expect("the embedded resp grammar holds two documents")
}

impl Grammar for Resp {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Resp
    }

    fn name(&self) -> &'static str {
        GrammarKind::Resp.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.array
    }

    fn default_ports(&self) -> &'static [u16] {
        &[6379]
    }

    fn transport(&self) -> Transport {
        self.array.transport
    }

    /// The array form if the bytes are one, else the inline form.
    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        tree::parse(&self.array, bytes).or_else(|| tree::parse(&self.inline, bytes))
    }

    /// One read-only command as a bulk-string array.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let arguments: Vec<Vec<u8>> = match rng.random_range(0..COMMANDS) {
            0 => vec![b"PING".to_vec()],
            1 => vec![b"ECHO".to_vec(), random_word(rng, 8)],
            2 => vec![b"GET".to_vec(), random_key(rng)],
            3 => vec![b"EXISTS".to_vec(), random_key(rng)],
            _ => vec![b"TYPE".to_vec(), random_key(rng)],
        };
        encode_array(&arguments)
    }

    /// By the reply's type byte: `-` is the server refusing, every other RESP
    /// type is a well-formed answer, anything else is not RESP at all.
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        match reply.first() {
            Some(b'-') => ReplyClass::ProtocolError,
            Some(byte) if b"+$:*_#,(!=%~>".contains(byte) => ReplyClass::Ok,
            _ => ReplyClass::Unknown,
        }
    }

    /// `true` once a whole frame has arrived: a line type at its CRLF, a bulk
    /// string after its declared bytes, an array once every element is in.
    /// A reply nested deeper than [`MAX_FRAME_DEPTH`] is never called
    /// complete, so the read ends on the caller's own size or time bound
    /// rather than on a guess.
    fn reply_complete(&self, buf: &[u8]) -> bool {
        frame_len(buf, 0).is_some()
    }

    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: b"PING\r\n".to_vec(),
            expect: Expect::Prefix(b"+PONG".to_vec()),
            after: None,
        }
    }

    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// `true` for `AUTH <password>` and for `HELLO <v> AUTH <user> <pass>`, in
    /// either the array or the inline form, so neither ever enters the corpus
    /// (spec S3, "Credential filter"). Bytes this grammar cannot parse are
    /// judged on the word `AUTH` alone: a desynced seed is dropped rather
    /// than kept with a password in it.
    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        let Some(tree) = self.parse(bytes) else {
            return mentions_auth(bytes);
        };
        let arguments = arguments(&tree);
        let Some(verb) = arguments.first() else {
            return false;
        };
        if verb.eq_ignore_ascii_case(b"AUTH") {
            return true;
        }
        verb.eq_ignore_ascii_case(b"HELLO")
            && arguments
                .iter()
                .skip(1)
                .any(|argument| argument.eq_ignore_ascii_case(b"AUTH"))
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// The arguments of a parsed request: the bulk strings of an array, or the
/// words of an inline command line, which the server splits on spaces itself.
fn arguments(tree: &Tree) -> Vec<Vec<u8>> {
    if let Some(args) = tree.get(&FieldPath::new("args")) {
        return args
            .children
            .iter()
            .filter_map(|element| {
                element
                    .children
                    .iter()
                    .find(|child| child.path.last() == "data")
            })
            .map(|data| data.bytes.clone())
            .collect();
    }
    match tree.get(&FieldPath::new("inline")) {
        Some(line) => line
            .bytes
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|word| !word.is_empty())
            .map(<[u8]>::to_vec)
            .collect(),
        None => Vec::new(),
    }
}

/// `AUTH` as a whole word anywhere in bytes the grammar could not parse.
/// Over-blocking a seed costs one seed; under-blocking one logs a password.
fn mentions_auth(bytes: &[u8]) -> bool {
    let needle = b"AUTH";
    bytes.windows(needle.len()).enumerate().any(|(at, window)| {
        let before = at.checked_sub(1).and_then(|before| bytes.get(before));
        let after = bytes.get(at + needle.len());
        window.eq_ignore_ascii_case(needle)
            && !before.is_some_and(u8::is_ascii_alphanumeric)
            && !after.is_some_and(u8::is_ascii_alphanumeric)
    })
}

/// A bulk-string array of these arguments.
fn encode_array(arguments: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(b'*');
    out.extend_from_slice(arguments.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    for argument in arguments {
        out.push(b'$');
        out.extend_from_slice(argument.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(argument);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// `n` bytes of [`ALPHABET`].
fn random_word(rng: &mut ChaCha8Rng, n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())])
        .collect()
}

/// A key of the lane's own, so a generated command cannot read somebody
/// else's data by accident.
fn random_key(rng: &mut ChaCha8Rng) -> Vec<u8> {
    let mut key = b"aitm-scan-".to_vec();
    key.extend_from_slice(&random_word(rng, 8));
    key
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// How many bytes the first complete frame of `buf` takes, or `None` when it
/// has not all arrived (or nests deeper than [`MAX_FRAME_DEPTH`]).
fn frame_len(buf: &[u8], depth: usize) -> Option<usize> {
    if depth > MAX_FRAME_DEPTH {
        return None;
    }
    let kind = *buf.first()?;
    match kind {
        // A line type: status, error, integer, null, boolean, double, big
        // number. The frame is the line.
        b'+' | b'-' | b':' | b'_' | b'#' | b',' | b'(' => line_end(buf, 1),
        // A length-prefixed string: the declared bytes and their CRLF follow
        // the header line. A negative length is the null string.
        b'$' | b'!' | b'=' => {
            let (declared, after) = decimal_line(buf, 1)?;
            if declared < 0 {
                return Some(after);
            }
            let end = after
                .checked_add(usize::try_from(declared).ok()?)?
                .checked_add(2)?;
            (buf.len() >= end).then_some(end)
        }
        // An aggregate: the header line declares how many frames follow. A
        // map declares pairs.
        b'*' | b'~' | b'>' | b'%' => {
            let (declared, after) = decimal_line(buf, 1)?;
            if declared < 0 {
                return Some(after);
            }
            let elements = usize::try_from(declared)
                .ok()?
                .checked_mul(if kind == b'%' { 2 } else { 1 })?;
            let mut at = after;
            for _ in 0..elements {
                at = at.checked_add(frame_len(buf.get(at..)?, depth + 1)?)?;
            }
            Some(at)
        }
        _ => None,
    }
}

/// Just past the CRLF that ends the line starting at `from`.
fn line_end(buf: &[u8], from: usize) -> Option<usize> {
    let rest = buf.get(from..)?;
    let at = rest.windows(2).position(|pair| pair == b"\r\n")?;
    from.checked_add(at)?.checked_add(2)
}

/// The decimal at `from` and the offset just past the CRLF closing its line.
fn decimal_line(buf: &[u8], from: usize) -> Option<(i64, usize)> {
    let end = line_end(buf, from)?;
    let digits = buf.get(from..end.checked_sub(2)?)?;
    let value = std::str::from_utf8(digits)
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()?;
    Some((value, end))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{grammar, Resp};
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Grammar, ReplyClass};
    use crate::spec::{GrammarKind, Transport};
    use crate::tree::{render, FieldPath, Tree};

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has a node at '{path}'"))
            .bytes
            .clone()
    }

    #[test]
    fn resp_identity() {
        let resp = grammar();
        assert_eq!(resp.kind(), GrammarKind::Resp);
        assert_eq!(resp.name(), "resp");
        assert_eq!(resp.transport(), Transport::Tcp);
        assert_eq!(resp.default_ports(), &[6379]);
        assert_eq!(resp.spec().grammar, "resp");
        assert_eq!(resp.spec().default_ports, vec![6379]);
        assert!(
            resp.spec()
                .reply
                .as_ref()
                .is_some_and(|reply| reply.contains("bulk string")),
            "the grammar file explains its replies in prose"
        );
        assert!(resp.prelude().is_empty());
        assert!(resp.prelude_for(b"*1\r\n$4\r\nPING\r\n").is_empty());
        assert!(!resp.expects_banner());
        assert!(!resp.close_on_malformed_is_expected());
        assert_eq!(Resp::new().name(), "resp");
    }

    #[test]
    fn resp_generate_parses_back() {
        let resp = grammar();
        let known: [Vec<u8>; 5] = [
            b"PING".to_vec(),
            b"ECHO".to_vec(),
            b"GET".to_vec(),
            b"EXISTS".to_vec(),
            b"TYPE".to_vec(),
        ];
        let mut verbs: Vec<Vec<u8>> = Vec::new();

        for seed in 0..64_u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let case = resp.generate(&mut rng);

            let tree = resp
                .parse(&case)
                .unwrap_or_else(|| panic!("the case generated from seed {seed} parses back"));
            assert_eq!(
                render(&tree),
                case,
                "the case generated from seed {seed} renders unchanged"
            );
            assert_eq!(
                denylist::refuses(GrammarKind::Resp, &case),
                None,
                "a generated case is never a denylisted command"
            );
            assert!(!resp.is_credential_message(&case));
            assert!(case.starts_with(b"*"), "every case is a bulk-string array");

            verbs.push(bytes_at(&tree, "args[0].data"));
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
    fn resp_classify() {
        let resp = grammar();
        assert_eq!(resp.classify_reply(b"+PONG\r\n"), ReplyClass::Ok);
        assert_eq!(
            resp.classify_reply(b"-ERR x\r\n"),
            ReplyClass::ProtocolError
        );
        assert_eq!(resp.classify_reply(b"$-1\r\n"), ReplyClass::Ok);
        assert_eq!(resp.classify_reply(b"?"), ReplyClass::Unknown);
        assert_eq!(resp.classify_reply(b""), ReplyClass::Unknown);
        assert_eq!(resp.classify_reply(b":7\r\n"), ReplyClass::Ok);
        assert_eq!(resp.classify_reply(b"*0\r\n"), ReplyClass::Ok);
        assert_eq!(resp.classify_reply(b"_\r\n"), ReplyClass::Ok);
        assert_eq!(resp.classify_reply(b">2\r\n"), ReplyClass::Ok);
    }

    #[test]
    fn resp_reply_complete() {
        let resp = grammar();
        assert!(!resp.reply_complete(b""));
        assert!(!resp.reply_complete(b"+PON"));
        assert!(resp.reply_complete(b"+PONG\r\n"));
        assert!(resp.reply_complete(b"-ERR nope\r\n"));
        assert!(resp.reply_complete(b":7\r\n"));
        assert!(!resp.reply_complete(b"$5\r\nhell"));
        assert!(resp.reply_complete(b"$5\r\nhello\r\n"));
        assert!(resp.reply_complete(b"$-1\r\n"));
        assert!(!resp.reply_complete(b"*2\r\n$1\r\na\r\n"));
        assert!(resp.reply_complete(b"*2\r\n$1\r\na\r\n$1\r\nb\r\n"));

        let mut nest = b"+ok\r\n".to_vec();
        for _ in 0..8 {
            let mut outer = b"*1\r\n".to_vec();
            outer.extend_from_slice(&nest);
            nest = outer;
        }
        assert!(
            resp.reply_complete(&nest),
            "eight levels of nesting is read"
        );
        let mut deeper = b"*1\r\n".to_vec();
        deeper.extend_from_slice(&nest);
        assert!(
            !resp.reply_complete(&deeper),
            "past the depth bound the reader stops guessing and reads on to its own limits"
        );
    }

    #[test]
    fn resp_credential_filter() {
        let resp = grammar();
        assert!(resp.is_credential_message(b"*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n"));
        assert!(resp.is_credential_message(b"auth abc\r\n"));
        assert!(resp
            .is_credential_message(b"*4\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$1\r\nx\r\n"));
        assert!(!resp.is_credential_message(b"PING\r\n"));
        assert!(!resp.is_credential_message(b"*1\r\n$4\r\nPING\r\n"));
        assert!(
            !resp.is_credential_message(b"*2\r\n$3\r\nGET\r\n$6\r\nauthor\r\n"),
            "AUTH is a word, not a substring"
        );
        assert!(
            !resp.is_credential_message(b"*3\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nname\r\n"),
            "HELLO without an AUTH argument carries no credential"
        );
        assert!(
            resp.is_credential_message(b"*2\r\n$9\r\nAUTH\r\n$3\r\nabc\r\n"),
            "a seed whose length is already desynced is dropped on the word alone"
        );
        assert!(resp
            .strip_credentials(b"*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n")
            .is_none());
    }

    #[test]
    fn resp_points_paths() {
        let resp = grammar();
        let wire = b"*2\r\n$4\r\nECHO\r\n$2\r\nhi\r\n";
        let tree = resp.parse(wire).expect("a two-argument array parses");

        let paths: Vec<String> = tree
            .mutable_leaves()
            .iter()
            .map(|node| node.path.to_string())
            .collect();
        assert_eq!(
            paths,
            vec![
                "array.star",
                "array.count",
                "array.crlf",
                "args[0].dollar",
                "args[0].len",
                "args[0].crlf",
                "args[0].data",
                "args[0].crlf2",
                "args[1].dollar",
                "args[1].len",
                "args[1].crlf",
                "args[1].data",
                "args[1].crlf2",
            ]
        );
        assert_eq!(bytes_at(&tree, "array.count"), b"2".to_vec());
        assert_eq!(bytes_at(&tree, "args[0].data"), b"ECHO".to_vec());
        assert_eq!(bytes_at(&tree, "args[1].len"), b"2".to_vec());
        assert_eq!(bytes_at(&tree, "args[1].data"), b"hi".to_vec());
        assert_eq!(render(&tree), wire.to_vec());
    }

    #[test]
    fn resp_parses_the_inline_form_too() {
        let resp = grammar();
        let tree = resp.parse(b"PING\r\n").expect("an inline command parses");
        assert_eq!(bytes_at(&tree, "inline"), b"PING\r\n".to_vec());
        assert_eq!(render(&tree), b"PING\r\n".to_vec());

        let get = resp.parse(b"GET mykey\r\n").expect("an inline GET parses");
        assert_eq!(render(&get), b"GET mykey\r\n".to_vec());

        assert!(
            resp.parse(b"*2\r\n$4\r\nECHO\r\n").is_none(),
            "an array that is shorter than its count is not a message"
        );
        assert!(resp.parse(b"no terminator").is_none());
    }

    #[test]
    fn resp_liveness_pings() {
        let probe = grammar().liveness_probe();
        assert_eq!(probe.send, b"PING\r\n".to_vec());
        assert_eq!(probe.after, None);
        assert!(probe.matches(b"+PONG\r\n", Ended::Replied));
        assert!(!probe.matches(b"-ERR unknown command\r\n", Ended::Replied));
        assert!(!probe.matches(b"", Ended::Silence));
    }
}
