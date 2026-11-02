//! One module per grammar; each embeds its `grammars/<name>.yaml` (spec S3).
//!
//! [`Pending`] stands in for a grammar whose module has not been written yet,
//! so the registry is complete and selection behaves (it parses nothing, so
//! the port rule falls through to inference) from the first task that needs
//! it.

pub mod dns;
pub mod ftp;
pub mod memcached;
pub mod modbus;
pub mod mqtt;
pub mod raw;
pub mod resp;
pub mod smtp;
pub mod tlv;

use std::sync::Arc;

use rand_chacha::ChaCha8Rng;

use crate::grammar::{default_ports_for, transport_for, Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, MessageSpec, Transport};
use crate::tree::Tree;

/// A declared but not yet implemented grammar.
///
/// It knows only its name, transport and default ports: it parses no bytes,
/// generates nothing and recognises no reply. Selection therefore never keeps
/// it on the strength of a seed, and a lane that is handed one does nothing
/// destructive with it.
pub(crate) struct Pending {
    kind: GrammarKind,
    spec: MessageSpec,
}

impl Pending {
    /// The pending grammar for one kind.
    pub(crate) fn new(kind: GrammarKind) -> Pending {
        let spec = MessageSpec {
            grammar: kind.name().to_string(),
            transport: transport_for(kind),
            default_ports: default_ports_for(kind).to_vec(),
            ..MessageSpec::default()
        };
        Pending { kind, spec }
    }

    /// The pending grammar for one kind, behind the trait object the registry
    /// hands out.
    pub(crate) fn grammar(kind: GrammarKind) -> Arc<dyn Grammar> {
        Arc::new(Pending::new(kind))
    }
}

impl Grammar for Pending {
    fn kind(&self) -> GrammarKind {
        self.kind
    }

    fn name(&self) -> &'static str {
        self.kind.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        default_ports_for(self.kind)
    }

    fn transport(&self) -> Transport {
        transport_for(self.kind)
    }

    fn parse(&self, _bytes: &[u8]) -> Option<Tree> {
        None
    }

    fn generate(&self, _rng: &mut ChaCha8Rng) -> Vec<u8> {
        Vec::new()
    }

    fn classify_reply(&self, _reply: &[u8]) -> ReplyClass {
        ReplyClass::Unknown
    }

    fn reply_complete(&self, _buf: &[u8]) -> bool {
        true
    }

    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: Vec::new(),
            expect: Expect::AnyReply,
            after: None,
        }
    }

    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn is_credential_message(&self, _bytes: &[u8]) -> bool {
        false
    }
}

/// Test helpers shared across the grammar modules.
#[cfg(test)]
pub(crate) mod testkit {
    use crate::grammar::Grammar;
    use crate::mutate::structure::structure_cases;
    use crate::tree::FieldPath;

    /// Assert that the separator at `path`, parsed out of `line`, is a live
    /// `delim` point: it is a mutable node carrying a single space, and
    /// S6.4's three delimiter mutators all reach it — `delim_remove` renders
    /// `removed`, `delim_dup` renders `doubled`, and `delim_inject` names the
    /// `command.verb` the separator's choice sits after. SMTP and FTP share
    /// this point exactly, so both pin the same renderings here.
    pub(crate) fn assert_separator_is_a_delim_point(
        grammar: &dyn Grammar,
        line: &[u8],
        path: &str,
        removed: &[u8],
        doubled: &[u8],
    ) {
        let tree = grammar
            .parse(line)
            .expect("a command with an argument parses");
        let point = FieldPath::new(path);
        let separator = tree
            .get(&point)
            .expect("the separator is a node of its own");
        assert_eq!(separator.bytes, b" ".to_vec());
        assert!(separator.mutable, "the separator must be mutable");

        let cases = structure_cases(&tree, grammar.spec(), &point, grammar.kind());
        let chains: Vec<String> = cases.iter().flat_map(|case| case.chain.clone()).collect();
        assert!(
            chains.contains(&format!("delim_remove({path})")),
            "{chains:?}"
        );
        assert!(chains.contains(&format!("delim_dup({path})")), "{chains:?}");
        assert!(
            chains
                .iter()
                .any(|entry| entry.starts_with("delim_inject(command.verb,")),
            "{chains:?}"
        );

        let removed_case = cases
            .iter()
            .find(|case| case.chain == [format!("delim_remove({path})")])
            .expect("the separator can be removed");
        assert_eq!(removed_case.bytes, removed.to_vec());
        let doubled_case = cases
            .iter()
            .find(|case| case.chain == [format!("delim_dup({path})")])
            .expect("the separator can be doubled");
        assert_eq!(doubled_case.bytes, doubled.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::Pending;
    use crate::spec::{GrammarKind, Transport};

    #[test]
    fn pending_parses_nothing_and_knows_its_ports() {
        let resp = Pending::grammar(GrammarKind::Resp);
        assert_eq!(resp.name(), "resp");
        assert_eq!(resp.kind(), GrammarKind::Resp);
        assert_eq!(resp.transport(), Transport::Tcp);
        assert_eq!(resp.default_ports(), &[6379]);
        assert_eq!(resp.spec().grammar, "resp");
        assert_eq!(resp.spec().default_ports, vec![6379]);
        assert!(resp.parse(b"+PONG\r\n").is_none());
        assert!(resp.prelude().is_empty());
        assert!(!resp.close_on_malformed_is_expected());

        let dns = Pending::grammar(GrammarKind::Dns);
        assert_eq!(dns.transport(), Transport::Udp);
        assert_eq!(dns.default_ports(), &[53]);
    }
}
