//! The [`Grammar`] trait, the registry of the nine grammars, and grammar
//! selection (spec S3).
//!
//! A grammar is the lane's whole knowledge of one wire protocol: the
//! [`MessageSpec`] it parses with, the ports it is the convention on, how a
//! reply is classified and when a reply is complete, the liveness
//! [`Exchange`], the prelude a connection needs before a case, and the
//! credential filter that keeps a captured secret out of the corpus.
//!
//! [`select_grammar`] implements S3's order: a named grammar, else the port's
//! grammar when at least one seed parses under it, else TLV inference over the
//! seeds, else [`crate::grammars::raw`].

use std::fmt;
use std::sync::Arc;

use aitm_scan_model::L4Transport;
use anyhow::anyhow;
use rand_chacha::ChaCha8Rng;

use crate::infer::LenDescriptor;
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::Tree;

/// How a read ended, as the client reports it (spec S5.3).
///
/// Re-exported here because [`Exchange::matches`] is written against it: the
/// expectation and the client must agree on one type.
pub use crate::client::Ended;

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// One wire protocol the lane can speak.
///
/// Every method is pure with respect to the network: a grammar never opens a
/// socket, it only says what to send and what an answer means.
pub trait Grammar: Send + Sync {
    /// Which of the nine grammars this is.
    fn kind(&self) -> GrammarKind;

    /// The canonical name, matching [`GrammarKind::name`].
    fn name(&self) -> &'static str;

    /// The message format this grammar parses and renders.
    fn spec(&self) -> &MessageSpec;

    /// Every document this grammar parses with, in the order
    /// [`Grammar::parse`] tries them, opening with [`Grammar::spec`].
    ///
    /// Two grammar files hold a second YAML document for a second form of the
    /// same protocol — RESP's inline command line, memcached's storage
    /// command — and override this so that document is validated and
    /// round-tripped with the rest of the registry (spec C1).
    fn specs(&self) -> Vec<&MessageSpec> {
        vec![self.spec()]
    }

    /// The ports this grammar is selected for when no grammar is named.
    fn default_ports(&self) -> &'static [u16];

    /// The transport the grammar speaks.
    fn transport(&self) -> Transport;

    /// The message tree for `bytes`, or `None` when the bytes are not a
    /// message of this grammar.
    fn parse(&self, bytes: &[u8]) -> Option<Tree>;

    /// A fresh well-formed message, built from the seeded generator so a run
    /// is reproducible.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8>;

    /// What a reply says about the peer (spec S3's per-grammar table).
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass;

    /// `true` when `buf` already holds a whole reply, so the reader stops
    /// before its timeout.
    fn reply_complete(&self, buf: &[u8]) -> bool;

    /// The exchange that proves the service is still alive.
    fn liveness_probe(&self) -> Exchange;

    /// Messages that must be sent, in order, before a case on a fresh
    /// connection.
    fn prelude(&self) -> Vec<Vec<u8>>;

    /// The prelude for one specific case. Defaults to [`Grammar::prelude`];
    /// a grammar overrides it when a case subsumes its own prelude (MQTT: a
    /// CONNECT case goes on a connection of its own).
    fn prelude_for(&self, case: &[u8]) -> Vec<Vec<u8>> {
        let _ = case;
        self.prelude()
    }

    /// `true` when the server speaks first and the client must read a banner
    /// before writing (SMTP, FTP).
    fn expects_banner(&self) -> bool {
        false
    }

    /// `true` when `bytes` is a message that carries a credential, so the
    /// seed never enters the corpus (spec S3 "Credential filter").
    fn is_credential_message(&self, bytes: &[u8]) -> bool;

    /// The same message with its credentials removed, when the grammar can
    /// strip them (MQTT CONNECT), or `None` when the seed must be dropped.
    fn strip_credentials(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let _ = bytes;
        None
    }

    /// `true` when the protocol mandates closing on a malformed message, so a
    /// close is not evidence of a fault.
    fn close_on_malformed_is_expected(&self) -> bool {
        self.spec().close_on_malformed_is_expected
    }
}

/// What a reply says about the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplyClass {
    /// A well-formed, successful reply.
    Ok,
    /// The peer rejected the message at the protocol level.
    ProtocolError,
    /// Nothing arrived, or nothing this grammar recognises.
    Unknown,
}

// ---------------------------------------------------------------------------
// Liveness exchanges (spec S3, amendment A3)
// ---------------------------------------------------------------------------

/// One send and what counts as a good answer to it.
///
/// The expectation is stored data rather than a closure, so an `Exchange` is
/// `Clone`, comparable and printable without capturing the sent bytes twice.
#[derive(Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The bytes to write.
    pub send: Vec<u8>,
    /// What makes the answer acceptable.
    pub expect: Expect,
    /// A best-effort message written after the answer (MQTT DISCONNECT, a
    /// line protocol's `QUIT`). Its reply is not read and never judged.
    pub after: Option<Vec<u8>>,
}

// Hand-written so that no message byte ever reaches a log (spec S9).
impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field(
                "send",
                &format_args!("<{len} bytes>", len = self.send.len()),
            )
            .field("expect", &self.expect)
            .field(
                "after",
                &format_args!(
                    "<{} bytes>",
                    match &self.after {
                        Some(bytes) => bytes.len(),
                        None => 0,
                    }
                ),
            )
            .finish()
    }
}

/// What makes an answer to an [`Exchange`] acceptable (spec A3).
#[derive(Clone, PartialEq, Eq)]
pub enum Expect {
    /// The reply starts with these bytes.
    Prefix(Vec<u8>),
    /// The reply repeats the sent bytes at `offset..offset + width` (a
    /// Modbus transaction id).
    SameIdAt {
        /// Where the id sits in both messages.
        offset: usize,
        /// How wide the id is.
        width: usize,
    },
    /// Any reply byte at all.
    AnyReply,
    /// Any reply byte, or silence with the connection still open.
    ReplyOrOpen,
    /// The reply is a DNS message whose id equals the query's.
    DnsSameId,
}

// Hand-written so a `Prefix`'s bytes never reach a log (spec S9).
impl fmt::Debug for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expect::Prefix(prefix) => {
                write!(f, "Prefix(<{len} bytes>)", len = prefix.len())
            }
            Expect::SameIdAt { offset, width } => {
                write!(f, "SameIdAt {{ offset: {offset}, width: {width} }}")
            }
            Expect::AnyReply => f.write_str("AnyReply"),
            Expect::ReplyOrOpen => f.write_str("ReplyOrOpen"),
            Expect::DnsSameId => f.write_str("DnsSameId"),
        }
    }
}

impl Exchange {
    /// `true` when `reply`, read until `ended`, satisfies the expectation.
    #[must_use]
    pub fn matches(&self, reply: &[u8], ended: Ended) -> bool {
        match &self.expect {
            Expect::Prefix(prefix) => reply.starts_with(prefix),
            Expect::SameIdAt { offset, width } => {
                let end = offset.saturating_add(*width);
                reply.len() >= end
                    && self.send.len() >= end
                    && reply[*offset..end] == self.send[*offset..end]
            }
            Expect::AnyReply => !reply.is_empty(),
            Expect::ReplyOrOpen => !reply.is_empty() || ended == Ended::Silence,
            Expect::DnsSameId => match (dns_id(&self.send), dns_id(reply)) {
                (Some(query), Some(answer)) => query == answer,
                _ => false,
            },
        }
    }
}

/// The DNS header id of a message hickory accepts, or `None` when the bytes
/// are not a DNS message.
fn dns_id(bytes: &[u8]) -> Option<u16> {
    hickory_proto::op::Message::from_vec(bytes)
        .ok()
        .map(|message| message.metadata.id)
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// The nine grammar names, in delivery order, for an operator-facing error.
pub const KNOWN_GRAMMARS: &str = "tlv, resp, memcached, dns, modbus, mqtt, smtp, ftp, raw";

/// Every grammar, in the umbrella's delivery order.
#[must_use]
pub fn registry() -> Vec<Arc<dyn Grammar>> {
    vec![
        by_kind(GrammarKind::Tlv),
        by_kind(GrammarKind::Resp),
        by_kind(GrammarKind::Memcached),
        by_kind(GrammarKind::Dns),
        by_kind(GrammarKind::Modbus),
        by_kind(GrammarKind::Mqtt),
        by_kind(GrammarKind::Smtp),
        by_kind(GrammarKind::Ftp),
        by_kind(GrammarKind::Raw),
    ]
}

/// The grammar for one kind.
#[must_use]
pub fn by_kind(kind: GrammarKind) -> Arc<dyn Grammar> {
    match kind {
        GrammarKind::Tlv => crate::grammars::tlv::grammar(),
        GrammarKind::Resp => crate::grammars::resp::grammar(),
        GrammarKind::Memcached => crate::grammars::memcached::grammar(),
        GrammarKind::Dns => crate::grammars::dns::grammar(),
        GrammarKind::Modbus => crate::grammars::modbus::grammar(),
        GrammarKind::Mqtt => crate::grammars::mqtt::grammar(),
        GrammarKind::Smtp => crate::grammars::smtp::grammar(),
        GrammarKind::Ftp => crate::grammars::ftp::grammar(),
        GrammarKind::Raw => crate::grammars::raw::grammar(),
    }
}

/// The S3 default-port table: the convention for one `(port, transport)`.
const PORT_TABLE: &[(u16, Transport, GrammarKind)] = &[
    (6379, Transport::Tcp, GrammarKind::Resp),
    (11211, Transport::Tcp, GrammarKind::Memcached),
    (53, Transport::Udp, GrammarKind::Dns),
    (502, Transport::Tcp, GrammarKind::Modbus),
    (1883, Transport::Tcp, GrammarKind::Mqtt),
    (25, Transport::Tcp, GrammarKind::Smtp),
    (587, Transport::Tcp, GrammarKind::Smtp),
    (21, Transport::Tcp, GrammarKind::Ftp),
];

/// The grammar conventionally spoken on `port` over `transport`.
#[must_use]
pub fn by_port(port: u16, transport: Transport) -> Option<GrammarKind> {
    PORT_TABLE
        .iter()
        .find(|(table_port, table_transport, _)| {
            *table_port == port && *table_transport == transport
        })
        .map(|(_, _, kind)| *kind)
}

/// The ports one grammar is the convention on, the inverse of [`by_port`].
#[must_use]
pub fn default_ports_for(kind: GrammarKind) -> &'static [u16] {
    match kind {
        GrammarKind::Resp => &[6379],
        GrammarKind::Memcached => &[11211],
        GrammarKind::Dns => &[53],
        GrammarKind::Modbus => &[502],
        GrammarKind::Mqtt => &[1883],
        GrammarKind::Smtp => &[25, 587],
        GrammarKind::Ftp => &[21],
        // Inferred and opaque messages have no port convention.
        GrammarKind::Tlv | GrammarKind::Raw => &[],
    }
}

/// The transport one grammar speaks. `tlv` and `raw` take the target's, and
/// are reported as `tcp` here; [`select_grammar`] does not transport-check
/// either of them for that reason.
#[must_use]
pub fn transport_for(kind: GrammarKind) -> Transport {
    match kind {
        GrammarKind::Dns => Transport::Udp,
        _ => Transport::Tcp,
    }
}

/// The grammar [`Transport`] of a target's [`L4Transport`].
#[must_use]
pub fn transport_of(proto: L4Transport) -> Transport {
    match proto {
        L4Transport::Tcp => Transport::Tcp,
        L4Transport::Udp => Transport::Udp,
    }
}

/// `tcp` or `udp`, for an operator-facing message.
fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    }
}

// ---------------------------------------------------------------------------
// Selection (spec S3)
// ---------------------------------------------------------------------------

/// Why [`select_grammar`] chose the grammar it chose. The reason reaches the
/// node's `path_template` and every verdict's `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionReason {
    /// The profile named it.
    Named,
    /// It is the convention on this port.
    DefaultPort(u16),
    /// Inference over the corpus recovered this length relation.
    Inferred(LenDescriptor),
    /// Nothing else fitted; the text says what was tried.
    RawFallback(String),
}

/// A chosen grammar and the reason for it.
#[derive(Clone)]
pub struct Selected {
    /// The grammar the lane will speak.
    pub grammar: Arc<dyn Grammar>,
    /// Why this grammar.
    pub reason: SelectionReason,
}

// Hand-written: `Arc<dyn Grammar>` is not `Debug`, and a grammar is identified
// by its name anyway.
impl fmt::Debug for Selected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Selected")
            .field("grammar", &self.grammar.name())
            .field("reason", &self.reason)
            .finish()
    }
}

/// TLV inference, as [`select_grammar`] consumes it: the grammar it built and
/// the relation it recovered, or the snake_case token of its refusal.
///
/// The descriptor travels with the grammar because
/// [`SelectionReason::Inferred`] records it; see the task-7 note in the plan's
/// review log.
pub type InferFn<'a> = dyn Fn(&[Vec<u8>]) -> Result<(Arc<dyn Grammar>, LenDescriptor), String> + 'a;

/// Choose a grammar for one target (spec S3's order).
///
/// 1. the named grammar, with `modbus-tcp` accepted for `modbus`;
/// 2. else the port's grammar, when the corpus is empty or at least one seed
///    parses under it (a port is a convention, a seed is evidence);
/// 3. else TLV inference over the corpus;
/// 4. else `raw`, naming what was refused.
///
/// # Errors
///
/// `scan: invalid_profile: ...` when the named grammar is unknown, or when it
/// speaks a transport the target does not.
pub fn select_grammar(
    named: Option<&str>,
    proto: L4Transport,
    port: u16,
    seeds: &[Vec<u8>],
    infer: &InferFn<'_>,
) -> anyhow::Result<Selected> {
    let transport = transport_of(proto);

    if let Some(name) = named {
        let Some(kind) = GrammarKind::parse(name) else {
            return Err(anyhow!(
                "scan: invalid_profile: unknown grammar '{name}'; known: {KNOWN_GRAMMARS}"
            ));
        };
        let grammar = by_kind(kind);
        // `tlv` and `raw` speak whatever the target speaks; the seven others
        // are fixed to one transport.
        let fixed_transport = !matches!(kind, GrammarKind::Tlv | GrammarKind::Raw);
        if fixed_transport && grammar.transport() != transport {
            return Err(anyhow!(
                "scan: invalid_profile: grammar '{name}' speaks {grammar_transport}, but the target's transport is {target_transport}",
                grammar_transport = transport_name(grammar.transport()),
                target_transport = transport_name(transport),
            ));
        }
        return Ok(Selected {
            grammar,
            reason: SelectionReason::Named,
        });
    }

    if let Some(kind) = by_port(port, transport) {
        let grammar = by_kind(kind);
        let any_seed_parses = seeds.iter().any(|seed| grammar.parse(seed).is_some());
        if seeds.is_empty() || any_seed_parses {
            return Ok(Selected {
                grammar,
                reason: SelectionReason::DefaultPort(port),
            });
        }
    }

    match infer(seeds) {
        Ok((grammar, descriptor)) => Ok(Selected {
            grammar,
            reason: SelectionReason::Inferred(descriptor),
        }),
        Err(refusal) => Ok(Selected {
            grammar: crate::grammars::raw::grammar(),
            reason: SelectionReason::RawFallback(format!("tlv inference refused: {refusal}")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_scan_model::L4Transport;

    use super::{
        by_kind, by_port, registry, select_grammar, Exchange, Expect, Grammar, SelectionReason,
    };
    use crate::client::Ended;
    use crate::infer::LenDescriptor;
    use crate::spec::{GrammarKind, MessageSpec, Transport};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    /// An inference that always refuses, so selection never reaches a real
    /// TLV grammar in these tests.
    fn never(_seeds: &[Vec<u8>]) -> Result<(Arc<dyn Grammar>, LenDescriptor), String> {
        Err("too_few_seeds".to_string())
    }

    #[test]
    fn registry_names_in_delivery_order() {
        let names: Vec<&'static str> = registry().iter().map(|g| g.name()).collect();
        assert_eq!(
            names,
            [
                "tlv",
                "resp",
                "memcached",
                "dns",
                "modbus",
                "mqtt",
                "smtp",
                "ftp",
                "raw"
            ]
        );
    }

    #[test]
    fn select_by_name_and_alias() {
        let named = select_grammar(Some("modbus"), L4Transport::Tcp, 1, &[], &never)
            .expect("modbus is a known grammar");
        assert_eq!(named.grammar.kind(), GrammarKind::Modbus);
        assert_eq!(named.reason, SelectionReason::Named);

        let alias = select_grammar(Some("modbus-tcp"), L4Transport::Tcp, 1, &[], &never)
            .expect("modbus-tcp is the one accepted alias");
        assert_eq!(alias.grammar.kind(), GrammarKind::Modbus);
        assert_eq!(alias.reason, SelectionReason::Named);

        let unknown = select_grammar(Some("nope"), L4Transport::Tcp, 1, &[], &never)
            .expect_err("an unknown name is refused")
            .to_string();
        assert!(
            unknown.starts_with("scan: invalid_profile: unknown grammar 'nope'"),
            "{unknown}"
        );
        assert!(unknown.contains("known: tlv, resp"), "{unknown}");

        let mismatch = select_grammar(Some("dns"), L4Transport::Tcp, 53, &[], &never)
            .expect_err("dns over tcp is refused")
            .to_string();
        assert!(
            mismatch.starts_with("scan: invalid_profile: "),
            "{mismatch}"
        );
        assert!(mismatch.contains("transport"), "{mismatch}");
    }

    #[test]
    fn select_by_port() {
        assert_eq!(by_port(6379, Transport::Tcp), Some(GrammarKind::Resp));
        assert_eq!(by_port(11211, Transport::Tcp), Some(GrammarKind::Memcached));
        assert_eq!(by_port(53, Transport::Udp), Some(GrammarKind::Dns));
        assert_eq!(by_port(53, Transport::Tcp), None);
        assert_eq!(by_port(502, Transport::Tcp), Some(GrammarKind::Modbus));
        assert_eq!(by_port(1883, Transport::Tcp), Some(GrammarKind::Mqtt));
        assert_eq!(by_port(25, Transport::Tcp), Some(GrammarKind::Smtp));
        assert_eq!(by_port(587, Transport::Tcp), Some(GrammarKind::Smtp));
        assert_eq!(by_port(21, Transport::Tcp), Some(GrammarKind::Ftp));
        assert_eq!(by_port(80, Transport::Tcp), None);
    }

    #[test]
    fn every_default_port_resolves_back_to_its_grammar() {
        for grammar in registry() {
            for port in grammar.default_ports() {
                assert_eq!(
                    by_port(*port, grammar.transport()),
                    Some(grammar.kind()),
                    "port {port} of grammar {}",
                    grammar.name()
                );
            }
        }
    }

    #[test]
    fn port_grammar_rejecting_all_seeds_falls_to_infer() {
        let refuse = |_: &[Vec<u8>]| -> Result<(Arc<dyn Grammar>, LenDescriptor), String> {
            Err("same_length".to_string())
        };
        // One byte is not a Modbus frame, so the port's grammar parses no seed.
        let seeds = vec![vec![0x00_u8]];
        let chosen = select_grammar(None, L4Transport::Tcp, 502, &seeds, &refuse)
            .expect("the fallback never fails");
        assert_eq!(chosen.grammar.kind(), GrammarKind::Raw);
        assert_eq!(
            chosen.reason,
            SelectionReason::RawFallback("tlv inference refused: same_length".to_string())
        );
    }

    #[test]
    fn expect_matches() {
        let ping = Exchange {
            send: b"PING\r\n".to_vec(),
            expect: Expect::Prefix(b"+PONG".to_vec()),
            after: None,
        };
        assert!(ping.matches(b"+PONG\r\n", Ended::Replied));
        assert!(!ping.matches(b"-ERR unknown command\r\n", Ended::Replied));

        let modbus = Exchange {
            send: vec![0x00, 0x07, 0x00, 0x00, 0x00, 0x06],
            expect: Expect::SameIdAt {
                offset: 0,
                width: 2,
            },
            after: None,
        };
        assert!(modbus.matches(&[0x00, 0x07, 0x00, 0x00, 0x00, 0x03], Ended::Replied));
        assert!(!modbus.matches(&[0x00, 0x08, 0x00, 0x00, 0x00, 0x03], Ended::Replied));
        assert!(!modbus.matches(&[0x00], Ended::Replied));

        let open = Exchange {
            send: vec![0x01],
            expect: Expect::ReplyOrOpen,
            after: None,
        };
        assert!(open.matches(b"", Ended::Silence));
        assert!(!open.matches(b"", Ended::Eof));
        assert!(open.matches(b"x", Ended::Replied));

        let any = Exchange {
            send: vec![0x01],
            expect: Expect::AnyReply,
            after: None,
        };
        assert!(any.matches(b"x", Ended::Replied));
        assert!(!any.matches(b"", Ended::Silence));
    }

    #[test]
    fn dns_same_id_matches_the_parsed_id() {
        // Header id 0x1234, one question for the root name, qtype A, class IN.
        let query: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        let exchange = Exchange {
            send: query,
            expect: Expect::DnsSameId,
            after: None,
        };
        let same: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        let other: Vec<u8> = vec![
            0x43, 0x21, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        assert!(exchange.matches(&same, Ended::Replied));
        assert!(!exchange.matches(&other, Ended::Replied));
        assert!(!exchange.matches(b"not dns", Ended::Replied));
        assert!(!exchange.matches(b"", Ended::Silence));
    }

    /// C1's round-trip half for **every** document of every grammar, not only
    /// the three whose own module asserts it: each embedded spec validates,
    /// serialises with `serde_yaml` and re-parses to an equal value, and names
    /// itself.
    ///
    /// The loop walks [`Grammar::specs`] rather than [`Grammar::spec`],
    /// because two grammar files hold a second YAML document — RESP's inline
    /// command line and memcached's storage command — that `spec()` does not
    /// return and that would otherwise never be round-tripped here.
    #[test]
    fn every_grammar_spec_validates_and_round_trips() {
        let mut documents = 0usize;
        for grammar in registry() {
            assert_eq!(
                grammar.specs().first().copied(),
                Some(grammar.spec()),
                "{}: specs() opens with the document spec() returns",
                grammar.name()
            );

            for spec in grammar.specs() {
                documents += 1;
                spec.validate().unwrap_or_else(|e| {
                    panic!("{}: embedded spec is invalid: {e}", grammar.name())
                });

                let yaml = spec
                    .to_yaml()
                    .unwrap_or_else(|e| panic!("{}: spec does not serialise: {e}", grammar.name()));
                let again = MessageSpec::from_yaml(&yaml).unwrap_or_else(|e| {
                    panic!("{}: serialised spec does not parse: {e}", grammar.name())
                });
                assert_eq!(
                    &again,
                    spec,
                    "{}: the YAML round trip is not the identity",
                    grammar.name()
                );

                assert_eq!(
                    spec.grammar,
                    grammar.name(),
                    "the document names the grammar it belongs to"
                );
                assert_eq!(spec.transport, grammar.transport());
                assert_eq!(spec.default_ports, grammar.default_ports().to_vec());
                assert!(
                    !yaml.is_empty() && yaml.contains("grammar:"),
                    "{}: serialised to {yaml:?}",
                    grammar.name()
                );
            }
        }
        // Nine grammars, two of which (resp, memcached) carry a second
        // document of their own.
        assert_eq!(
            documents, 11,
            "the registry holds eleven grammar documents in all"
        );
    }

    /// Every grammar survives the inputs a fuzzing lane will inevitably hand
    /// it: nothing, one byte, a 64 KiB run and 10 000 random strings. A
    /// grammar may refuse any of them, but it may not panic, and anything it
    /// does parse must render back unchanged.
    #[test]
    fn grammars_survive_empty_oversized_and_random_bytes() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xC0FF_EE00);
        let fixed: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0x00],
            vec![0xff],
            b"\r\n".to_vec(),
            vec![b'A'; 65_536],
            vec![0x80; 16],
        ];

        for grammar in registry() {
            for bytes in &fixed {
                if let Some(tree) = grammar.parse(bytes) {
                    assert_eq!(
                        crate::tree::render(&tree),
                        *bytes,
                        "{}: parse/render is not the identity on {} bytes",
                        grammar.name(),
                        bytes.len()
                    );
                }
                // The reply side takes the same abuse.
                let _ = grammar.classify_reply(bytes);
                let _ = grammar.reply_complete(bytes);
                let _ = grammar.is_credential_message(bytes);
                let _ = grammar.strip_credentials(bytes);
                let _ = grammar.prelude_for(bytes);
            }

            let mut buf = [0u8; 96];
            for _ in 0..10_000 {
                let len = rng.random_range(0..=96usize);
                let bytes = &mut buf[..len];
                rng.fill_bytes(bytes);
                if let Some(tree) = grammar.parse(bytes) {
                    assert_eq!(
                        crate::tree::render(&tree),
                        bytes.to_vec(),
                        "{}: parse/render is not the identity on {bytes:?}",
                        grammar.name()
                    );
                }
                let _ = grammar.classify_reply(bytes);
                let _ = grammar.reply_complete(bytes);
                let _ = grammar.is_credential_message(bytes);
            }
        }
    }

    #[test]
    fn by_kind_returns_the_named_grammar() {
        for kind in [
            GrammarKind::Tlv,
            GrammarKind::Resp,
            GrammarKind::Memcached,
            GrammarKind::Dns,
            GrammarKind::Modbus,
            GrammarKind::Mqtt,
            GrammarKind::Smtp,
            GrammarKind::Ftp,
            GrammarKind::Raw,
        ] {
            let grammar = by_kind(kind);
            assert_eq!(grammar.kind(), kind);
            assert_eq!(grammar.name(), kind.name());
            assert_eq!(grammar.spec().transport, grammar.transport());
        }
    }
}
