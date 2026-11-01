//! The `raw` grammar (spec S3): one opaque `bytes` field.
//!
//! `raw` is the fallback when no grammar is named, no port convention
//! applies, and TLV inference refuses. It parses anything into a single
//! mutable leaf named `message`, so only the byte-level mutators apply.

use std::sync::Arc;

use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{FieldKind, FieldSpec, GrammarKind, MessageSpec, Transport};
use crate::tree::{FieldPath, Node, Tree};

/// The opaque fallback grammar.
pub struct Raw {
    spec: MessageSpec,
    liveness_seed: Vec<u8>,
}

// Hand-written so the seed's bytes never reach a log (spec S9).
impl std::fmt::Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Raw")
            .field(
                "liveness_seed",
                &format_args!("<{len} bytes>", len = self.liveness_seed.len()),
            )
            .finish()
    }
}

impl Raw {
    /// `raw` with no liveness seed: the liveness probe then writes nothing
    /// and asks only that the connection stay open.
    #[must_use]
    pub fn new() -> Raw {
        Raw {
            spec: raw_spec(),
            liveness_seed: Vec::new(),
        }
    }

    /// `raw` whose liveness probe replays one captured seed unmutated.
    #[must_use]
    pub fn with_seed(seed: Vec<u8>) -> Raw {
        Raw {
            spec: raw_spec(),
            liveness_seed: seed,
        }
    }
}

impl Default for Raw {
    fn default() -> Raw {
        Raw::new()
    }
}

/// The one-field spec every `Raw` carries.
fn raw_spec() -> MessageSpec {
    MessageSpec {
        grammar: GrammarKind::Raw.name().to_string(),
        transport: Transport::Tcp,
        default_ports: Vec::new(),
        close_on_malformed_is_expected: false,
        reply: Some(
            "Opaque: any byte is a reply, nothing is parsed, nothing is expected.".to_string(),
        ),
        message: vec![FieldSpec {
            name: "message".to_string(),
            kind: FieldKind::Bytes { size: None },
            ..FieldSpec::default()
        }],
    }
}

/// The `raw` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Raw::new())
}

impl Grammar for Raw {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Raw
    }

    fn name(&self) -> &'static str {
        GrammarKind::Raw.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        &[]
    }

    fn transport(&self) -> Transport {
        self.spec.transport
    }

    /// Always `Some`: every byte string is a `raw` message.
    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        Some(Tree {
            grammar: self.spec.grammar.clone(),
            root: vec![Node {
                path: FieldPath::new("message"),
                kind: FieldKind::Bytes { size: None },
                bytes: bytes.to_vec(),
                children: Vec::new(),
                relation: None,
                mutable: true,
                secret: false,
                relation_broken: false,
            }],
        })
    }

    /// `raw` invents nothing: it has no idea what a well-formed message is.
    fn generate(&self, _rng: &mut ChaCha8Rng) -> Vec<u8> {
        Vec::new()
    }

    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        if reply.is_empty() {
            ReplyClass::Unknown
        } else {
            ReplyClass::Ok
        }
    }

    /// The first read is the whole reply: `raw` has no framing.
    fn reply_complete(&self, _buf: &[u8]) -> bool {
        true
    }

    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: self.liveness_seed.clone(),
            expect: Expect::ReplyOrOpen,
            after: None,
        }
    }

    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// `raw` cannot tell a credential from any other byte, so it claims none.
    fn is_credential_message(&self, _bytes: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{grammar, Raw};
    use crate::client::Ended;
    use crate::grammar::{Grammar, ReplyClass};
    use crate::spec::{GrammarKind, Transport};
    use crate::tree::render;

    #[test]
    fn raw_parses_any_bytes_into_one_leaf() {
        let raw = grammar();
        assert_eq!(raw.kind(), GrammarKind::Raw);
        assert_eq!(raw.name(), "raw");
        assert_eq!(raw.transport(), Transport::Tcp);
        assert!(raw.default_ports().is_empty());

        let tree = raw.parse(b"\x00\xffhello").expect("raw parses anything");
        assert_eq!(tree.grammar, "raw");
        assert_eq!(tree.root.len(), 1);
        assert_eq!(tree.root[0].path.as_str(), "message");
        assert_eq!(tree.root[0].bytes, b"\x00\xffhello".to_vec());
        assert!(tree.root[0].mutable);
        assert_eq!(render(&tree), b"\x00\xffhello".to_vec());

        let empty = raw.parse(b"").expect("even no bytes are a raw message");
        assert_eq!(render(&empty), Vec::<u8>::new());
    }

    #[test]
    fn raw_liveness_replays_the_seed_and_accepts_an_open_connection() {
        let raw: Arc<dyn Grammar> = Arc::new(Raw::with_seed(b"\x00\x01ping".to_vec()));
        let probe = raw.liveness_probe();
        assert_eq!(probe.send, b"\x00\x01ping".to_vec());
        assert_eq!(probe.after, None);
        assert!(probe.matches(b"", Ended::Silence));
        assert!(!probe.matches(b"", Ended::Eof));
        assert!(probe.matches(b"\x00", Ended::Replied));
    }

    #[test]
    fn raw_classifies_any_reply_and_filters_no_credential() {
        let raw = grammar();
        assert_eq!(raw.classify_reply(b"\x01"), ReplyClass::Ok);
        assert_eq!(raw.classify_reply(b""), ReplyClass::Unknown);
        assert!(raw.reply_complete(b""));
        assert!(raw.prelude().is_empty());
        assert!(raw.prelude_for(b"a case").is_empty());
        assert!(!raw.expects_banner());
        assert!(!raw.is_credential_message(b"AUTH hunter2"));
        assert!(raw.strip_credentials(b"AUTH hunter2").is_none());
        assert!(!raw.close_on_malformed_is_expected());
        assert!(raw.generate(&mut seeded_rng()).is_empty());
    }

    fn seeded_rng() -> rand_chacha::ChaCha8Rng {
        use rand::SeedableRng;
        rand_chacha::ChaCha8Rng::seed_from_u64(7)
    }
}
