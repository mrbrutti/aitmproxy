//! The `modbus` grammar (spec S3 row 5): Modbus/TCP read requests.
//!
//! The message is spec S2's worked example, loaded from
//! `grammars/modbus.yaml`: an MBAP header (transaction id, protocol id, a
//! length that measures the unit id and the PDU, unit id) and a PDU of a
//! function code, an address and a quantity.
//!
//! Only the four read function codes are ever generated. The write and
//! diagnostic codes live in the grammar's `one_of` as the type-substitution
//! mutator's vocabulary, and both the generator and
//! [`crate::denylist::refuses`] filter them out, so nothing this module emits
//! writes to a register or resets a device.

use std::fmt;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::denylist;
use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{GrammarKind, Literal, MessageSpec, Transport};
use crate::tree::{self, Tree};

/// The grammar document, embedded so the lane needs no files at run time.
const MODBUS_YAML: &str = include_str!("../../grammars/modbus.yaml");

/// Where the MBAP length sits: bytes 4 and 5, big endian.
const LENGTH_AT: usize = 4;
/// How many bytes precede the length's own count (transaction id, protocol
/// id, length): a whole frame is `6 + length` bytes.
const BEFORE_BODY: usize = 6;
/// Where the function code sits in a request and in a reply.
const FUNCTION_AT: usize = 7;
/// The exception bit of a reply's function code.
const EXCEPTION_BIT: u8 = 0x80;
/// The unit id the lane addresses (spec S2's example).
const UNIT_ID: u8 = 1;
/// Read holding registers: the function code of the liveness probe.
const READ_HOLDING_REGISTERS: u8 = 3;
/// The highest register address the generator asks for.
const MAX_ADDRESS: u16 = 100;
/// The most registers the generator asks for in one request.
const MAX_QUANTITY: u16 = 10;

/// Modbus/TCP.
pub struct Modbus {
    spec: MessageSpec,
    /// The next liveness transaction id. A probe takes a fresh one so a late
    /// reply to an earlier probe cannot be read as an answer to this one.
    transaction: AtomicU16,
}

// Hand-written: a grammar is identified by its name, and nothing it holds
// belongs in a log (spec S9).
impl fmt::Debug for Modbus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Modbus")
            .field("grammar", &self.spec.grammar)
            .finish()
    }
}

impl Modbus {
    /// Modbus/TCP, with its embedded grammar.
    ///
    /// # Panics
    ///
    /// Never in practice: the only fallible step is parsing the grammar this
    /// crate embeds at compile time, which a test parses too.
    #[must_use]
    pub fn new() -> Modbus {
        Modbus {
            spec: MessageSpec::from_yaml(MODBUS_YAML).expect("embedded grammar"),
            transaction: AtomicU16::new(1),
        }
    }

    /// The next transaction id, wrapping. Ids are sequential rather than
    /// random so a run is reproducible; they only have to differ.
    fn next_transaction(&self) -> u16 {
        self.transaction.fetch_add(1, Ordering::Relaxed)
    }

    /// The function codes the grammar declares, in the order it declares
    /// them.
    fn declared_functions(&self) -> Vec<u8> {
        self.spec
            .message
            .iter()
            .filter(|field| field.name == "pdu")
            .flat_map(|pdu| pdu.fields.iter())
            .filter(|field| field.name == "function")
            .flat_map(|function| function.one_of.iter())
            .filter_map(|literal| match literal {
                Literal::Int(value) => u8::try_from(*value).ok(),
                Literal::Hex(bytes) => match bytes.as_slice() {
                    [byte] => Some(*byte),
                    _ => None,
                },
                Literal::Text(_) => None,
            })
            .collect()
    }

    /// The declared function codes a request may actually carry: the ones the
    /// denylist does not refuse once the request is rendered.
    fn allowed_functions(&self) -> Vec<u8> {
        self.declared_functions()
            .into_iter()
            .filter(|function| {
                let probe = request(0, *function, 0, 1);
                denylist::refuses(GrammarKind::Modbus, &probe).is_none()
            })
            .collect()
    }
}

impl Default for Modbus {
    fn default() -> Modbus {
        Modbus::new()
    }
}

/// One read request: MBAP header and a five-byte PDU.
fn request(transaction: u16, function: u8, address: u16, quantity: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&transaction.to_be_bytes());
    // Protocol id: 0 is Modbus.
    out.extend_from_slice(&0_u16.to_be_bytes());
    // Length: the unit id and the five PDU bytes.
    out.extend_from_slice(&6_u16.to_be_bytes());
    out.push(UNIT_ID);
    out.push(function);
    out.extend_from_slice(&address.to_be_bytes());
    out.extend_from_slice(&quantity.to_be_bytes());
    out
}

/// The `modbus` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Modbus::new())
}

impl Grammar for Modbus {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Modbus
    }

    fn name(&self) -> &'static str {
        GrammarKind::Modbus.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        &[502]
    }

    fn transport(&self) -> Transport {
        self.spec.transport
    }

    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        tree::parse(&self.spec, bytes)
    }

    /// A read of one to ten registers at a low address, with a random
    /// transaction id and a function code the denylist allows.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let transaction: u16 = rng.random();
        let address: u16 = rng.random_range(0..=MAX_ADDRESS);
        let quantity: u16 = rng.random_range(1..=MAX_QUANTITY);
        let allowed = self.allowed_functions();
        let function = match allowed.get(rng.random_range(0..allowed.len().max(1))) {
            Some(function) => *function,
            // The grammar declares no allowed code: read holding registers,
            // which no denylist entry covers, rather than invent one.
            None => READ_HOLDING_REGISTERS,
        };
        request(transaction, function, address, quantity)
    }

    /// A reply carrying a function code is an answer; the exception bit makes
    /// it a protocol error. Anything shorter than the MBAP header plus a
    /// function code says nothing.
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        match reply.get(FUNCTION_AT) {
            None => ReplyClass::Unknown,
            Some(function) if function & EXCEPTION_BIT != 0 => ReplyClass::ProtocolError,
            Some(_) => ReplyClass::Ok,
        }
    }

    /// MBAP framing: the declared length counts the unit id and the PDU, so a
    /// whole frame is `6 + length` bytes.
    fn reply_complete(&self, buf: &[u8]) -> bool {
        let (Some(high), Some(low)) = (buf.get(LENGTH_AT), buf.get(LENGTH_AT + 1)) else {
            return false;
        };
        let declared = usize::from(u16::from_be_bytes([*high, *low]));
        buf.len() >= BEFORE_BODY.saturating_add(declared)
    }

    /// Read one holding register at address 0, and take any reply carrying
    /// this probe's transaction id — an exception reply included, because an
    /// exception still comes from a live server.
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: request(self.next_transaction(), READ_HOLDING_REGISTERS, 0, 1),
            expect: Expect::SameIdAt {
                offset: 0,
                width: 2,
            },
            after: None,
        }
    }

    /// Modbus has no handshake: a case goes straight onto the connection.
    fn prelude(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Modbus/TCP carries no credentials.
    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        let _ = bytes;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{grammar, Modbus};
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Expect, Grammar, ReplyClass};
    use crate::spec::{GrammarKind, Transport};
    use crate::tree::{render, FieldPath, Tree};

    /// T10's benign request: transaction 1, protocol 0, length 6, unit 1,
    /// function 3 (read holding registers), address 0, one register.
    const BENIGN: [u8; 12] = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
    ];

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has no node at {path}"))
            .bytes
            .clone()
    }

    #[test]
    fn modbus_t10_benign_bytes_parse() {
        let modbus = grammar();
        assert_eq!(modbus.name(), "modbus");
        assert_eq!(modbus.kind(), GrammarKind::Modbus);
        assert_eq!(modbus.transport(), Transport::Tcp);
        assert_eq!(modbus.default_ports(), &[502]);

        let tree = modbus.parse(&BENIGN).expect("T10's request is Modbus/TCP");
        assert_eq!(tree.grammar, "modbus");
        assert_eq!(bytes_at(&tree, "pdu.function"), vec![3]);
        assert_eq!(bytes_at(&tree, "header.transaction_id"), vec![0x00, 0x01]);
        assert_eq!(bytes_at(&tree, "header.protocol_id"), vec![0x00, 0x00]);
        assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0x06]);
        assert_eq!(bytes_at(&tree, "header.unit_id"), vec![0x01]);
        assert_eq!(bytes_at(&tree, "pdu.address"), vec![0x00, 0x00]);
        assert_eq!(bytes_at(&tree, "pdu.quantity"), vec![0x00, 0x01]);
        assert_eq!(render(&tree), BENIGN.to_vec());

        // The transaction id is the one field no mutator touches (spec S2).
        let mutable: Vec<String> = tree
            .mutable_leaves()
            .iter()
            .map(|node| node.path.to_string())
            .collect();
        assert_eq!(
            mutable,
            [
                "header.protocol_id",
                "header.length",
                "header.unit_id",
                "pdu.function",
                "pdu.address",
                "pdu.quantity"
            ]
        );

        // Not a Modbus frame: too short, and with bytes left over.
        assert!(modbus.parse(&[0x00, 0x01, 0x00]).is_none());
        assert!(modbus
            .parse(&[BENIGN.as_slice(), &[0x00]].concat())
            .is_none());
    }

    #[test]
    fn modbus_generate_parses_back() {
        let modbus = grammar();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        for case in 0..64 {
            let bytes = modbus.generate(&mut rng);
            assert_eq!(bytes.len(), 12, "case {case}");
            let tree = modbus
                .parse(&bytes)
                .unwrap_or_else(|| panic!("case {case} must parse back"));
            assert_eq!(render(&tree), bytes, "case {case}");

            assert_eq!(bytes_at(&tree, "header.protocol_id"), vec![0x00, 0x00]);
            assert_eq!(bytes_at(&tree, "header.length"), vec![0x00, 0x06]);
            assert_eq!(bytes_at(&tree, "header.unit_id"), vec![0x01]);

            let address = u16::from_be_bytes([bytes[8], bytes[9]]);
            let quantity = u16::from_be_bytes([bytes[10], bytes[11]]);
            assert!(address <= 100, "case {case}: address {address}");
            assert!(
                (1..=10).contains(&quantity),
                "case {case}: quantity {quantity}"
            );
        }
    }

    #[test]
    fn modbus_generate_is_never_denylisted() {
        let modbus = grammar();
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let mut seen = BTreeSet::new();
        for case in 0..64 {
            let bytes = modbus.generate(&mut rng);
            assert_eq!(
                denylist::refuses(GrammarKind::Modbus, &bytes),
                None,
                "case {case} renders a denylisted function code"
            );
            seen.insert(bytes[7]);
        }
        assert!(
            seen.is_subset(&BTreeSet::from([1, 2, 3, 4])),
            "generated function codes {seen:?} must be reads only"
        );
    }

    #[test]
    fn modbus_classify() {
        let modbus = grammar();
        // A reply: two bytes of register data for the one register read.
        let ok: [u8; 11] = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00,
        ];
        assert_eq!(modbus.classify_reply(&ok), ReplyClass::Ok);
        // Function 3 with the high bit set, exception code 3.
        let exception: [u8; 9] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03];
        assert_eq!(modbus.classify_reply(&exception), ReplyClass::ProtocolError);
        assert_eq!(
            modbus.classify_reply(&[0x00, 0x01, 0x00]),
            ReplyClass::Unknown
        );
        assert_eq!(modbus.classify_reply(&[]), ReplyClass::Unknown);

        // MBAP framing: the declared length counts the unit id and the PDU.
        assert!(modbus.reply_complete(&ok));
        assert!(!modbus.reply_complete(&ok[..10]));
        assert!(modbus.reply_complete(&exception));
        assert!(!modbus.reply_complete(&[0x00, 0x01, 0x00]));
        assert!(!modbus.reply_complete(&[]));
    }

    #[test]
    fn modbus_liveness_matches_same_tid() {
        let modbus = grammar();
        let first = modbus.liveness_probe();
        let second = modbus.liveness_probe();

        // FC 3, address 0, quantity 1, unit 1: everything but the id is fixed.
        assert_eq!(
            first.send[2..],
            [0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            first.expect,
            Expect::SameIdAt {
                offset: 0,
                width: 2
            }
        );
        assert_eq!(first.after, None);
        assert_ne!(first.send[..2], second.send[..2], "a fresh transaction id");

        let reply = [
            first.send[0],
            first.send[1],
            0x00,
            0x00,
            0x00,
            0x05,
            0x01,
            0x03,
            0x02,
            0x00,
            0x00,
        ];
        assert!(first.matches(&reply, Ended::Replied));
        assert!(!second.matches(&reply, Ended::Replied));
        assert!(!first.matches(&[], Ended::Silence));

        // An exception reply with the same id is still a live server.
        let exception = [first.send[0], first.send[1], 0, 0, 0, 3, 1, 0x83, 3];
        assert!(first.matches(&exception, Ended::Replied));
    }

    #[test]
    fn modbus_has_no_prelude_and_no_credentials() {
        let modbus: Arc<dyn Grammar> = Arc::new(Modbus::new());
        assert!(modbus.prelude().is_empty());
        assert!(modbus.prelude_for(&BENIGN).is_empty());
        assert!(!modbus.expects_banner());
        assert!(!modbus.is_credential_message(&BENIGN));
        assert!(modbus.strip_credentials(&BENIGN).is_none());
        assert!(!modbus.close_on_malformed_is_expected());
    }
}
