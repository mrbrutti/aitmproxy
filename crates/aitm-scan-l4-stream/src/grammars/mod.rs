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

    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        let _ = bytes;
        None
    }

    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let _ = rng;
        Vec::new()
    }

    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        let _ = reply;
        ReplyClass::Unknown
    }

    fn reply_complete(&self, buf: &[u8]) -> bool {
        let _ = buf;
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

    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        let _ = bytes;
        false
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
