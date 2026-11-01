//! The `dns` grammar (spec S3 row 4): DNS over UDP, with `hickory-proto` as
//! the validator, the builder and the reply reader.
//!
//! hickory decides what is a DNS message at all: [`Dns::parse`] refuses any
//! datagram [`Message::from_vec`] refuses, so a seed that is not DNS never
//! enters the corpus, and [`Dns::classify_reply`] reads the RCODE out of a
//! reply with the same parser. The [`MessageSpec`] in `grammars/dns.yaml`
//! does the other half: hickory reports no byte offsets, and the lane mutates
//! bytes at a named path. The path that matters most is
//! `questions[0].name.labels[0].len` — the label length a `len_desync`
//! mutation sets past the end of the datagram (umbrella T6-2).
//!
//! One note on the YAML: the `questions` repeat is written `count_from:
//! questions`, not `count_from: qdcount`. [`crate::tree`]'s parser keys a
//! declared count by the name of the *repeat* it counts — the `of` of
//! `qdcount`'s `count: { of: questions }` — and [`crate::spec`]'s validator
//! resolves a name against the field's own level and outwards, so `qdcount`,
//! which sits inside the `header` group, is not a name the top-level
//! `questions` field can reach. `count_from: questions` is therefore the one
//! spelling that both validates and makes `qdcount` bound the repeat;
//! `dns_qdcount_bounds_the_questions` pins that it does.

use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{self, Tree};

/// The grammar document, embedded at build time (spec S3).
const DNS_YAML: &str = include_str!("../../grammars/dns.yaml");

/// How many lowercase letters a generated name's first label has.
const GENERATED_LABEL_LEN: usize = 8;

/// DNS over UDP.
#[derive(Debug, Clone)]
pub struct Dns {
    spec: MessageSpec,
    /// The id of the liveness query, fresh per instance so two jobs against
    /// one resolver do not share one.
    liveness_id: u16,
}

impl Dns {
    /// The grammar, with a random liveness id.
    #[must_use]
    pub fn new() -> Dns {
        Dns::with_liveness_id(rand::rng().random::<u16>())
    }

    /// The grammar, with the liveness query's id fixed.
    #[must_use]
    pub fn with_liveness_id(liveness_id: u16) -> Dns {
        Dns {
            // The one `expect` the crate allows: the embedded grammar is a
            // build-time constant, so a bad one is a broken build.
            spec: MessageSpec::from_yaml(DNS_YAML).expect("the embedded dns grammar is valid"),
            liveness_id,
        }
    }
}

impl Default for Dns {
    fn default() -> Dns {
        Dns::new()
    }
}

/// The `dns` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Dns::new())
}

/// One `A` question for `name`, as a query with RD set.
///
/// hickory is the builder; the hand-assembled root query is the fallback, so
/// the function is total and no serialisation error reaches a caller.
fn query_bytes(id: u16, name: Name) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::A));
    message.to_vec().unwrap_or_else(|_| root_query_bytes(id))
}

/// The seventeen bytes of an `A`/`IN` query for the root name with RD set.
fn root_query_bytes(id: u16) -> Vec<u8> {
    let [hi, lo] = id.to_be_bytes();
    vec![
        hi, lo, // id
        0x01, 0x00, // RD
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        0x00, // the root name
        0x00, 0x01, // qtype A
        0x00, 0x01, // qclass IN
    ]
}

impl Grammar for Dns {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Dns
    }

    fn name(&self) -> &'static str {
        GrammarKind::Dns.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        &[53]
    }

    fn transport(&self) -> Transport {
        Transport::Udp
    }

    /// The message tree, when hickory accepts the bytes as a DNS message and
    /// the spec accounts for every one of them.
    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        Message::from_vec(bytes).ok()?;
        tree::parse(&self.spec, bytes)
    }

    /// An `A` query for `<eight lowercase letters>.test.`, a name reserved by
    /// RFC 6761 and so never a real delegation.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let id = rng.random::<u16>();
        let mut label = String::with_capacity(GENERATED_LABEL_LEN);
        for _ in 0..GENERATED_LABEL_LEN {
            label.push(char::from(b'a' + rng.random_range(0..26u8)));
        }
        let name = Name::from_ascii(format!("{label}.test.")).unwrap_or_else(|_| Name::root());
        query_bytes(id, name)
    }

    /// The RCODE of a reply hickory parses (spec S3 row 4): a name that does
    /// not exist is still a working server, every other error code is the
    /// server rejecting the message, and a datagram hickory refuses says
    /// nothing at all.
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        let Ok(message) = Message::from_vec(reply) else {
            return ReplyClass::Unknown;
        };
        match message.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => ReplyClass::Ok,
            // FormErr, ServFail, NotImp and Refused are the four a resolver
            // sends in practice; the rest of the registry is a refusal too.
            _ => ReplyClass::ProtocolError,
        }
    }

    /// Always: a DNS reply over UDP is one datagram, so the first read holds
    /// all of it.
    fn reply_complete(&self, _buf: &[u8]) -> bool {
        true
    }

    /// An `A` query for the root name with this instance's id; any reply
    /// carrying that id, whatever its RCODE, says the resolver is alive.
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: query_bytes(self.liveness_id, Name::root()),
            expect: Expect::DnsSameId,
            after: None,
        }
    }

    /// None: a query stands on its own datagram.
    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// DNS carries no credential this lane can recognise.
    fn is_credential_message(&self, _bytes: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{grammar, Dns};
    use crate::client::Ended;
    use crate::grammar::{Expect, Grammar, ReplyClass};
    use crate::spec::{GrammarKind, MessageSpec, Transport};
    use crate::tree::{render, FieldPath, Tree};

    /// T10's liveness query: id 1, RD set, one question for the root name,
    /// type `A`, class `IN`.
    const LIVENESS: [u8; 17] = [
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01,
    ];

    /// T10's benign query: id 0x1234, RD set, one question for
    /// `example.test.`, type `A`, class `IN`.
    const EXAMPLE_TEST: [u8; 30] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // label "example"
        0x04, b't', b'e', b's', b't', // label "test"
        0x00, // root
        0x00, 0x01, // qtype A
        0x00, 0x01, // qclass IN
    ];

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has a node at '{path}'"))
            .bytes
            .clone()
    }

    fn leaf_paths(tree: &Tree) -> Vec<String> {
        tree.leaves()
            .iter()
            .map(|node| node.path.as_str().to_string())
            .collect()
    }

    fn mutable_paths(tree: &Tree) -> Vec<String> {
        tree.mutable_leaves()
            .iter()
            .map(|node| node.path.as_str().to_string())
            .collect()
    }

    /// A hickory-built response for the root name with one RCODE.
    fn response(id: u16, code: ResponseCode) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Response, OpCode::Query);
        message.metadata.response_code = code;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::root(), RecordType::A));
        message.to_vec().expect("a hickory response serialises")
    }

    #[test]
    fn dns_identity_and_yaml_round_trip() {
        let dns = grammar();
        assert_eq!(dns.kind(), GrammarKind::Dns);
        assert_eq!(dns.name(), "dns");
        assert_eq!(dns.transport(), Transport::Udp);
        assert_eq!(dns.default_ports(), &[53]);
        assert_eq!(dns.spec().grammar, "dns");
        assert!(dns.prelude().is_empty());
        assert!(!dns.expects_banner());
        assert!(!dns.close_on_malformed_is_expected());
        assert!(!dns.is_credential_message(&EXAMPLE_TEST));
        assert!(dns.strip_credentials(&EXAMPLE_TEST).is_none());
        assert!(dns.reply_complete(b""));
        assert!(dns.reply_complete(&LIVENESS));

        let text = dns.spec().to_yaml().expect("the dns spec serialises");
        let again = MessageSpec::from_yaml(&text).expect("the dns spec round-trips");
        assert_eq!(&again, dns.spec());
    }

    #[test]
    fn dns_generate_parses_back() {
        let dns = grammar();
        for seed in 0..64u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let generated = dns.generate(&mut rng);

            Message::from_vec(&generated).unwrap_or_else(|e| {
                panic!("seed {seed}: hickory refused the generated query: {e}")
            });

            let tree = dns
                .parse(&generated)
                .unwrap_or_else(|| panic!("seed {seed}: the generated query does not parse"));
            assert_eq!(render(&tree), generated, "seed {seed} does not round-trip");

            // `<8 lowercase>.test.`: two labels, the first eight bytes long.
            assert_eq!(bytes_at(&tree, "header.qdcount"), vec![0x00, 0x01]);
            assert_eq!(bytes_at(&tree, "questions[0].name.labels[0].len"), vec![8]);
            assert_eq!(
                bytes_at(&tree, "questions[0].name.labels[1].text"),
                b"test".to_vec()
            );
            assert_eq!(bytes_at(&tree, "questions[0].qtype"), vec![0x00, 0x01]);
            assert!(bytes_at(&tree, "rest").is_empty());
            let label = bytes_at(&tree, "questions[0].name.labels[0].text");
            assert!(
                label.iter().all(u8::is_ascii_lowercase),
                "seed {seed}: label {label:?} is not eight lowercase letters"
            );
        }

        // Seeded generation is reproducible.
        let first = dns.generate(&mut ChaCha8Rng::seed_from_u64(11));
        let again = dns.generate(&mut ChaCha8Rng::seed_from_u64(11));
        assert_eq!(first, again);
    }

    #[test]
    fn dns_tree_paths() {
        let dns = grammar();

        let liveness = dns.parse(&LIVENESS).expect("the liveness query parses");
        assert_eq!(liveness.grammar, "dns");
        assert_eq!(bytes_at(&liveness, "header.id"), vec![0x00, 0x01]);
        assert_eq!(bytes_at(&liveness, "header.flags"), vec![0x01, 0x00]);
        assert_eq!(bytes_at(&liveness, "header.qdcount"), vec![0x00, 0x01]);
        assert_eq!(bytes_at(&liveness, "header.arcount"), vec![0x00, 0x00]);
        assert_eq!(bytes_at(&liveness, "questions[0].name.root"), vec![0x00]);
        assert_eq!(bytes_at(&liveness, "questions[0].qclass"), vec![0x00, 0x01]);
        assert!(bytes_at(&liveness, "rest").is_empty());
        assert_eq!(render(&liveness), LIVENESS.to_vec());
        // The root name has no labels at all.
        assert!(liveness
            .get(&FieldPath::new("questions[0].name.labels"))
            .expect("the root name still has a labels node")
            .children
            .is_empty());

        let benign = dns.parse(&EXAMPLE_TEST).expect("the benign query parses");
        assert_eq!(
            bytes_at(&benign, "questions[0].name.labels[0].len"),
            vec![7]
        );
        assert_eq!(
            bytes_at(&benign, "questions[0].name.labels[0].text"),
            b"example".to_vec()
        );
        assert_eq!(
            bytes_at(&benign, "questions[0].name.labels[1].len"),
            vec![4]
        );
        assert_eq!(
            bytes_at(&benign, "questions[0].name.labels[1].text"),
            b"test".to_vec()
        );
        assert_eq!(bytes_at(&benign, "questions[0].name.root"), vec![0x00]);
        assert_eq!(bytes_at(&benign, "questions[0].qtype"), vec![0x00, 0x01]);
        assert_eq!(render(&benign), EXAMPLE_TEST.to_vec());
        assert!(
            !benign
                .get(&FieldPath::new("questions[0].name.labels[0].len"))
                .expect("the label length")
                .relation_broken,
            "the label length agrees with its label"
        );

        // Bytes hickory refuses are not a DNS message, whatever they look like.
        assert!(dns.parse(b"").is_none());
        assert!(dns.parse(b"\x00").is_none());
        assert!(dns.parse(b"not a dns message").is_none());
    }

    #[test]
    fn dns_qdcount_bounds_the_questions() {
        // A response with no question and one `A` answer for `www.`: every
        // byte after the header belongs to `rest`, because `qdcount` is zero.
        let mut reply: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let answer: [u8; 19] = [
            0x03, b'w', b'w', b'w', 0x00, // name "www."
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3c, // ttl 60
            0x00, 0x04, // rdlength
            0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
        ];
        reply.extend_from_slice(&answer);

        let dns = grammar();
        let tree = dns.parse(&reply).expect("the answer-only reply parses");
        assert!(
            tree.get(&FieldPath::new("questions"))
                .expect("a questions node")
                .children
                .is_empty(),
            "qdcount is zero, so no question is parsed"
        );
        assert_eq!(bytes_at(&tree, "rest"), answer.to_vec());
        assert_eq!(render(&tree), reply);
    }

    #[test]
    fn dns_classify() {
        let dns = grammar();
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::NoError)),
            ReplyClass::Ok
        );
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::NXDomain)),
            ReplyClass::Ok
        );
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::FormErr)),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::ServFail)),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::NotImp)),
            ReplyClass::ProtocolError
        );
        assert_eq!(
            dns.classify_reply(&response(1, ResponseCode::Refused)),
            ReplyClass::ProtocolError
        );
        assert_eq!(dns.classify_reply(b"\x00"), ReplyClass::Unknown);
        assert_eq!(dns.classify_reply(b""), ReplyClass::Unknown);
    }

    #[test]
    fn dns_liveness_same_id() {
        let dns = Dns::with_liveness_id(0x4142);
        let probe = dns.liveness_probe();
        assert_eq!(probe.expect, Expect::DnsSameId);
        assert_eq!(probe.after, None);
        assert!(probe.matches(&response(0x4142, ResponseCode::NoError), Ended::Replied));
        assert!(probe.matches(&response(0x4142, ResponseCode::Refused), Ended::Replied));
        assert!(!probe.matches(&response(0x4143, ResponseCode::NoError), Ended::Replied));
        assert!(!probe.matches(b"", Ended::Silence));

        // Byte for byte, T10's liveness query: an `A` question for the root.
        let one = Dns::with_liveness_id(1);
        assert_eq!(one.liveness_probe().send, LIVENESS.to_vec());
    }

    #[test]
    fn dns_label_len_is_mutable_leaf() {
        let dns = grammar();
        let tree = dns.parse(&EXAMPLE_TEST).expect("the benign query parses");

        let mutable = mutable_paths(&tree);
        assert!(
            mutable.contains(&"questions[0].name.labels[0].len".to_string()),
            "the label length is the len_desync target: {mutable:?}"
        );
        assert!(
            mutable.contains(&"questions[0].name.labels[0].text".to_string()),
            "{mutable:?}"
        );
        assert!(
            !mutable.contains(&"header.id".to_string()),
            "the id matches a reply to its query and is never mutated: {mutable:?}"
        );
        assert!(
            leaf_paths(&tree).contains(&"header.id".to_string()),
            "the id is still a leaf, it is only immutable"
        );
    }
}
