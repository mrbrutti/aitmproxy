//! The `tlv` grammar: the one grammar inference writes (spec S3 row 1, S4).
//!
//! `tlv` has no fixed fields of its own. [`from_seeds`] hands the captured
//! seeds to [`crate::infer::infer`], and the recovered
//! [`LenDescriptor`] becomes an ordinary [`MessageSpec`] of `prefix`,
//! `length` and `payload` — so a service nobody wrote a grammar for is
//! mutated, re-satisfied and reported exactly like a hand-written one.
//!
//! [`grammar`] is the stub the registry hands out *before* inference has run:
//! it knows its name and parses nothing, so selection never keeps it on the
//! strength of a seed.
//!
//! `grammars/tlv.yaml` holds the shape this module generates, so the file
//! reads as the grammar it is; [`template`] parses it and a test asserts the
//! two have not drifted.

use std::fmt;
use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::grammars::Pending;
use crate::infer::{descriptor_to_spec, infer, InferRefusal, LenDescriptor};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::{render, resatisfy, FieldPath, Tree};

/// The worked `tlv` document, kept beside the eight hand-written grammars.
pub const TEMPLATE_YAML: &str = include_str!("../../grammars/tlv.yaml");

/// An inferred TLV grammar: the generated spec, the relation it came from,
/// and the shortest captured seed, which is both the liveness probe and the
/// skeleton [`Grammar::generate`] reshapes.
pub struct Tlv {
    spec: MessageSpec,
    descriptor: LenDescriptor,
    liveness_seed: Vec<u8>,
}

// Hand-written so the seed's bytes never reach a log (spec S9).
impl fmt::Debug for Tlv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tlv")
            .field("descriptor", &self.descriptor)
            .field("transport", &self.spec.transport)
            .field(
                "liveness_seed",
                &format_args!("<{len} bytes>", len = self.liveness_seed.len()),
            )
            .finish()
    }
}

impl Tlv {
    /// The grammar one recovered relation describes, speaking `transport`
    /// and replaying `liveness_seed` to prove the service alive.
    #[must_use]
    pub fn from_descriptor(
        descriptor: LenDescriptor,
        liveness_seed: Vec<u8>,
        transport: Transport,
    ) -> Tlv {
        let mut spec = descriptor_to_spec(&descriptor);
        spec.transport = transport;
        Tlv {
            spec,
            descriptor,
            liveness_seed,
        }
    }

    /// The length relation this grammar was built from.
    #[must_use]
    pub fn descriptor(&self) -> &LenDescriptor {
        &self.descriptor
    }
}

/// The `tlv` stub the registry hands out before inference has run: it knows
/// its name and transport and parses nothing.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Pending::grammar(GrammarKind::Tlv)
}

/// The `MessageSpec` of the embedded `grammars/tlv.yaml`.
///
/// # Panics
///
/// Never in a shipped binary: the document is embedded at compile time and a
/// test parses it.
#[must_use]
pub fn template() -> MessageSpec {
    MessageSpec::from_yaml(TEMPLATE_YAML).expect("the embedded tlv.yaml is a valid MessageSpec")
}

/// Infer a TCP TLV grammar from captured seeds, with the relation it
/// recovered.
///
/// The pair is what [`crate::grammar::InferFn`] hands
/// [`crate::grammar::select_grammar`], which records the descriptor in
/// [`crate::grammar::SelectionReason::Inferred`].
///
/// # Errors
///
/// The [`InferRefusal`] of [`crate::infer::infer`]; the lane then falls back
/// to `raw` and names the refusal.
pub fn from_seeds(seeds: &[Vec<u8>]) -> Result<(Arc<dyn Grammar>, LenDescriptor), InferRefusal> {
    from_seeds_on(seeds, Transport::Tcp)
}

/// [`from_seeds`] for a target that speaks `transport`: a UDP TLV service
/// has to answer to be called alive, where a TCP one may just stay open.
///
/// # Errors
///
/// The [`InferRefusal`] of [`crate::infer::infer`].
pub fn from_seeds_on(
    seeds: &[Vec<u8>],
    transport: Transport,
) -> Result<(Arc<dyn Grammar>, LenDescriptor), InferRefusal> {
    let descriptor = infer(seeds)?;
    let shortest = seeds
        .iter()
        .min_by_key(|seed| seed.len())
        .cloned()
        .unwrap_or_default();
    let tlv = Tlv::from_descriptor(descriptor.clone(), shortest, transport);
    Ok((Arc::new(tlv), descriptor))
}

impl Grammar for Tlv {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Tlv
    }

    fn name(&self) -> &'static str {
        GrammarKind::Tlv.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    /// `tlv` is inferred, never conventional: it owns no port.
    fn default_ports(&self) -> &'static [u16] {
        &[]
    }

    fn transport(&self) -> Transport {
        self.spec.transport
    }

    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        crate::tree::parse(&self.spec, bytes)
    }

    /// The shortest seed with a fresh payload of the same length: `tlv`
    /// knows the framing and nothing about what the body means, so it keeps
    /// the shape it was shown.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let Some(mut tree) = self.parse(&self.liveness_seed) else {
            return self.liveness_seed.clone();
        };
        if let Some(payload) = tree.get_mut(&FieldPath::new("payload")) {
            let width = payload.bytes.len();
            payload.bytes = (0..width).map(|_| rng.random::<u8>()).collect();
        }
        resatisfy(&mut tree, None);
        render(&tree)
    }

    /// Opaque framing: a byte is an answer, nothing is an answer this
    /// grammar understands.
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        if reply.is_empty() {
            ReplyClass::Unknown
        } else {
            ReplyClass::Ok
        }
    }

    /// The first read is the whole reply: the recovered relation describes
    /// what `tlv` sends, not what comes back.
    fn reply_complete(&self, _buf: &[u8]) -> bool {
        true
    }

    /// Replay the shortest seed unmutated. Over TCP a service that stays
    /// open without answering is still alive; over UDP silence says nothing,
    /// so a reply is required.
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: self.liveness_seed.clone(),
            expect: match self.spec.transport {
                Transport::Tcp => Expect::ReplyOrOpen,
                Transport::Udp => Expect::AnyReply,
            },
            after: None,
        }
    }

    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// `tlv` has no command vocabulary, so it cannot recognise a credential
    /// and claims none.
    fn is_credential_message(&self, _bytes: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{from_seeds, from_seeds_on, grammar, template};
    use crate::codec::decode_hex;
    use crate::grammar::{Expect, ReplyClass};
    use crate::infer::{descriptor_to_spec, Counts, LenDescriptor};
    use crate::spec::{Endian, GrammarKind, Transport};
    use crate::tree::FieldPath;

    fn hex(text: &str) -> Vec<u8> {
        decode_hex(text).expect("the test literal is hex")
    }

    fn seeds() -> Vec<Vec<u8>> {
        vec![hex("0002aabb"), hex("00050102030405"), hex("0001ff")]
    }

    #[test]
    fn tlv_from_seeds_parses_and_generates() {
        let (tlv, descriptor) = from_seeds(&seeds()).expect("the seed set fits one relation");
        assert_eq!(tlv.name(), "tlv");
        assert_eq!(tlv.kind(), GrammarKind::Tlv);
        assert_eq!(tlv.transport(), Transport::Tcp);
        assert!(tlv.default_ports().is_empty());
        assert_eq!(
            descriptor,
            LenDescriptor {
                offset: 0,
                width: 2,
                endian: Endian::Be,
                counts: Counts::BodyOnly,
                adjust: 0,
            }
        );

        let tree = tlv.parse(&hex("0002aabb")).expect("a seed parses");
        assert_eq!(
            tree.get(&FieldPath::new("payload"))
                .expect("payload node")
                .bytes,
            vec![0xaa, 0xbb]
        );

        let generated = tlv.generate(&mut ChaCha8Rng::seed_from_u64(7));
        assert_eq!(
            generated.len(),
            3,
            "generate reshapes the shortest seed, so the length is its own"
        );
        assert_eq!(&generated[..2], &hex("0001")[..]);
        assert!(tlv.parse(&generated).is_some(), "generated output parses");

        let probe = tlv.liveness_probe();
        assert_eq!(probe.send, hex("0001ff"), "the shortest seed");
        assert_eq!(probe.expect, Expect::ReplyOrOpen);
        assert_eq!(probe.after, None);
    }

    #[test]
    fn tlv_over_udp_needs_a_real_reply() {
        let (tlv, _) =
            from_seeds_on(&seeds(), Transport::Udp).expect("the seed set fits one relation");
        assert_eq!(tlv.transport(), Transport::Udp);
        assert_eq!(tlv.liveness_probe().expect, Expect::AnyReply);
    }

    #[test]
    fn tlv_classifies_any_byte_as_ok_and_filters_no_credential() {
        let (tlv, _) = from_seeds(&seeds()).expect("the seed set fits one relation");
        assert_eq!(tlv.classify_reply(b"\x00"), ReplyClass::Ok);
        assert_eq!(tlv.classify_reply(b""), ReplyClass::Unknown);
        assert!(tlv.reply_complete(b""));
        assert!(tlv.prelude().is_empty());
        assert!(!tlv.is_credential_message(b"AUTH hunter2"));
        assert!(!tlv.close_on_malformed_is_expected());
    }

    #[test]
    fn the_stub_grammar_parses_nothing_before_inference() {
        let stub = grammar();
        assert_eq!(stub.name(), "tlv");
        assert_eq!(stub.kind(), GrammarKind::Tlv);
        assert!(stub.parse(&hex("0002aabb")).is_none());
    }

    #[test]
    fn the_embedded_template_is_what_inference_generates() {
        let template = template();
        assert_eq!(
            template,
            descriptor_to_spec(&LenDescriptor {
                offset: 2,
                width: 2,
                endian: Endian::Be,
                counts: Counts::BodyOnly,
                adjust: 0,
            }),
            "grammars/tlv.yaml has drifted from descriptor_to_spec"
        );
    }
}
