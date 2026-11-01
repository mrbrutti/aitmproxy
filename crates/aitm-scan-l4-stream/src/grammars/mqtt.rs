//! The `mqtt` grammar (spec S3 row 6): MQTT 3.1.1 over TCP.
//!
//! The message format is `grammars/mqtt.yaml`: the fixed header
//! (`type_flags`, a varint `remaining_length` measuring everything after it)
//! and a `variable` choice of CONNECT, PUBLISH, SUBSCRIBE, PINGREQ and
//! DISCONNECT. The format has no conditional field, so the two places where
//! MQTT needs one are resolved here and documented in the YAML:
//!
//! * the choice is resolved **by packet type** — [`Mqtt::parse`] narrows the
//!   spec to the alternative the type nibble selects, because "the first
//!   alternative that parses" would read a SUBSCRIBE as a PUBLISH;
//! * `publish` is the QoS-0 shape, the only one the lane generates.
//!
//! Nothing here sends a credential: the liveness CONNECT carries neither
//! username nor password, and a captured CONNECT that does is stripped of
//! both before it can enter the corpus (spec S3 "Credential filter").

use std::fmt;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::grammar::{Exchange, Expect, Grammar, ReplyClass};
use crate::spec::{FieldSpec, GrammarKind, MessageSpec, Transport};
use crate::tree::{self, render, resatisfy, FieldPath, Tree};

/// The grammar document, embedded so the lane needs no files at run time.
const MQTT_YAML: &str = include_str!("../../grammars/mqtt.yaml");

/// Packet types, as the high nibble of the first byte.
const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const PUBREC: u8 = 5;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const PINGREQ: u8 = 12;
const PINGRESP: u8 = 13;
const DISCONNECT: u8 = 14;

/// The connect flags that announce a credential: username (bit 7) and
/// password (bit 6).
const CREDENTIAL_FLAGS: u8 = 0xc0;
/// Clean session, no will, no credentials.
const CLEAN_SESSION: u8 = 0x02;
/// MQTT 3.1.1.
const PROTOCOL_LEVEL: u8 = 4;
/// The keepalive the liveness CONNECT asks for, in seconds.
const KEEPALIVE: u16 = 60;
/// A SUBACK return code with this bit set is a refused subscription.
const SUBACK_FAILURE: u8 = 0x80;
/// The most bytes a remaining-length varint may use.
const VARINT_MAX_BYTES: usize = 4;
/// The largest value that varint can carry.
const VARINT_MAX_VALUE: usize = 268_435_455;

/// The paths this module reads and rewrites in a parsed CONNECT.
const CONNECT_FLAGS_PATH: &str = "variable.connect.connect_flags";
const CREDENTIALS_PATH: &str = "variable.connect.credentials";

/// Which `variable` alternative each packet type selects.
const ALTERNATIVES: &[(u8, &str)] = &[
    (CONNECT, "connect"),
    (PUBLISH, "publish"),
    (SUBSCRIBE, "subscribe"),
    (PINGREQ, "pingreq"),
    (DISCONNECT, "disconnect"),
];

/// MQTT 3.1.1.
pub struct Mqtt {
    /// The whole grammar, as the YAML declares it: what `spec()` hands out
    /// and what an operator reads.
    spec: MessageSpec,
    /// The same grammar once per packet type, with the `variable` choice
    /// narrowed to that type's alternative.
    by_type: Vec<(u8, MessageSpec)>,
    /// The suffix of the next liveness client id.
    client: AtomicU16,
}

// Hand-written: a grammar is identified by its name, and nothing it holds
// belongs in a log (spec S9).
impl fmt::Debug for Mqtt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mqtt")
            .field("grammar", &self.spec.grammar)
            .field("types", &self.by_type.len())
            .finish()
    }
}

impl Mqtt {
    /// MQTT, with its embedded grammar.
    ///
    /// # Panics
    ///
    /// Never in practice: the only fallible step is parsing the grammar this
    /// crate embeds at compile time, which a test parses too.
    #[must_use]
    pub fn new() -> Mqtt {
        let spec: MessageSpec = MessageSpec::from_yaml(MQTT_YAML).expect("embedded grammar");
        let by_type = ALTERNATIVES
            .iter()
            .filter_map(|(packet_type, name)| {
                narrowed(&spec, name).map(|narrowed| (*packet_type, narrowed))
            })
            .collect();
        Mqtt {
            spec,
            by_type,
            client: AtomicU16::new(1),
        }
    }

    /// The spec to parse `bytes` with: the one narrowed to the packet type
    /// the first byte names, or the whole grammar when the type is one this
    /// module does not describe.
    fn spec_for(&self, bytes: &[u8]) -> &MessageSpec {
        let Some(first) = bytes.first() else {
            return &self.spec;
        };
        let packet_type = first >> 4;
        self.by_type
            .iter()
            .find(|(declared, _)| *declared == packet_type)
            .map_or(&self.spec, |(_, spec)| spec)
    }

    /// The CONNECT the lane opens a connection with: clean session, keepalive
    /// 60, no will, no credentials, and a client id of its own.
    fn connect_message(&self) -> Vec<u8> {
        let suffix = self.client.fetch_add(1, Ordering::Relaxed);
        let client_id = format!("aitm-scan-{suffix:04x}");

        let mut body = Vec::with_capacity(26);
        push_string(&mut body, b"MQTT");
        body.push(PROTOCOL_LEVEL);
        body.push(CLEAN_SESSION);
        body.extend_from_slice(&KEEPALIVE.to_be_bytes());
        push_string(&mut body, client_id.as_bytes());
        packet(CONNECT << 4, &body)
    }
}

impl Default for Mqtt {
    fn default() -> Mqtt {
        Mqtt::new()
    }
}

/// `spec` with the `variable` choice reduced to the one named alternative, or
/// `None` when the grammar has no such alternative.
fn narrowed(spec: &MessageSpec, alternative: &str) -> Option<MessageSpec> {
    let mut narrowed = spec.clone();
    let variable: &mut FieldSpec = narrowed
        .message
        .iter_mut()
        .find(|field| field.name == "variable")?;
    let chosen = variable
        .fields
        .iter()
        .find(|field| field.name == alternative)?
        .clone();
    variable.fields = vec![chosen];
    Some(narrowed)
}

/// One packet: the first byte, the body's length as a varint, the body.
fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(first);
    push_varint(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// An MQTT string: a big-endian u16 length and that many bytes.
fn push_string(out: &mut Vec<u8>, text: &[u8]) {
    let len = u16::try_from(text.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&text[..usize::from(len)]);
}

/// A remaining length: seven bits at a time, high bit set while more follow.
fn push_varint(out: &mut Vec<u8>, value: usize) {
    let mut left = value.min(VARINT_MAX_VALUE);
    loop {
        let byte = u8::try_from(left & 0x7f).unwrap_or(0);
        left >>= 7;
        if left == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The remaining length encoded at `at`, and the offset just after it.
fn read_varint(buf: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut end = at;
    for step in 0..VARINT_MAX_BYTES {
        let byte = *buf.get(end)?;
        end += 1;
        value += usize::from(byte & 0x7f) << (7 * step);
        if byte & 0x80 == 0 {
            return Some((value, end));
        }
    }
    None
}

/// An MQTT string at `at`: its bytes and the offset just after them.
fn read_string(buf: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let len = usize::from(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]));
    let start = at + 2;
    let end = start.checked_add(len)?;
    Some((buf.get(start..end)?, end))
}

/// The connect flags of a CONNECT, read from the bytes rather than from a
/// tree so an unparsed captured packet is still judged.
fn connect_flags(bytes: &[u8]) -> Option<u8> {
    let (_, after_length) = read_varint(bytes, 1)?;
    let (_, after_name) = read_string(bytes, after_length)?;
    // The protocol level sits between the name and the flags.
    bytes.get(after_name + 1).copied()
}

/// The packet type of `bytes`, or `None` for an empty buffer.
fn packet_type(bytes: &[u8]) -> Option<u8> {
    bytes.first().map(|first| first >> 4)
}

/// The `mqtt` grammar.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Arc::new(Mqtt::new())
}

impl Grammar for Mqtt {
    fn kind(&self) -> GrammarKind {
        GrammarKind::Mqtt
    }

    fn name(&self) -> &'static str {
        GrammarKind::Mqtt.name()
    }

    fn spec(&self) -> &MessageSpec {
        &self.spec
    }

    fn default_ports(&self) -> &'static [u16] {
        &[1883]
    }

    fn transport(&self) -> Transport {
        self.spec.transport
    }

    fn parse(&self, bytes: &[u8]) -> Option<Tree> {
        tree::parse(self.spec_for(bytes), bytes)
    }

    /// A PINGREQ, a QoS-0 PUBLISH of a few bytes to `a/b`, or a SUBSCRIBE to
    /// `a/#`: three packets a broker answers and none a denylist refuses.
    fn generate(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        match rng.random_range(0..3u8) {
            0 => packet(PINGREQ << 4, &[]),
            1 => {
                let len = rng.random_range(1..=8usize);
                let mut body = Vec::with_capacity(len + 5);
                push_string(&mut body, b"a/b");
                for _ in 0..len {
                    // A printable payload, so an excerpt of a case reads.
                    body.push(rng.random_range(b'a'..=b'z'));
                }
                // Flags 0: QoS 0, no retain, not a duplicate.
                packet(PUBLISH << 4, &body)
            }
            _ => {
                let packet_id: u16 = rng.random_range(1..=u16::MAX);
                let mut body = Vec::with_capacity(8);
                body.extend_from_slice(&packet_id.to_be_bytes());
                push_string(&mut body, b"a/#");
                // The granted QoS asked for.
                body.push(0x00);
                // SUBSCRIBE's flags nibble is fixed at 2 by the standard.
                packet((SUBSCRIBE << 4) | 0x02, &body)
            }
        }
    }

    /// CONNACK's return code, SUBACK's per-topic codes, and the three
    /// acknowledgements that mean nothing more than "received" (spec S3
    /// row 6).
    fn classify_reply(&self, reply: &[u8]) -> ReplyClass {
        match packet_type(reply) {
            Some(CONNACK) => match reply.get(3) {
                Some(0) => ReplyClass::Ok,
                Some(_) => ReplyClass::ProtocolError,
                None => ReplyClass::Unknown,
            },
            Some(SUBACK) => {
                let Some((_, after_length)) = read_varint(reply, 1) else {
                    return ReplyClass::Unknown;
                };
                // The packet id, then one return code per topic.
                match reply.get(after_length + 2..) {
                    None | Some([]) => ReplyClass::Unknown,
                    Some(codes) if codes.contains(&SUBACK_FAILURE) => ReplyClass::ProtocolError,
                    Some(_) => ReplyClass::Ok,
                }
            }
            Some(PUBACK | PUBREC | PINGRESP) => ReplyClass::Ok,
            _ => ReplyClass::Unknown,
        }
    }

    /// The fixed header plus the length it declares.
    fn reply_complete(&self, buf: &[u8]) -> bool {
        let Some((remaining, after_length)) = read_varint(buf, 1) else {
            return false;
        };
        buf.len() >= after_length.saturating_add(remaining)
    }

    /// CONNECT and wait for a CONNACK of any return code, then DISCONNECT.
    fn liveness_probe(&self) -> Exchange {
        Exchange {
            send: self.connect_message(),
            expect: Expect::Prefix(vec![CONNACK << 4]),
            after: Some(packet(DISCONNECT << 4, &[])),
        }
    }

    /// Every connection starts with a CONNECT.
    fn prelude(&self) -> Vec<Vec<u8>> {
        vec![self.connect_message()]
    }

    /// A CONNECT case is its own CONNECT: it goes on a fresh connection
    /// alone, because a broker answers a second CONNECT by closing.
    fn prelude_for(&self, case: &[u8]) -> Vec<Vec<u8>> {
        if packet_type(case) == Some(CONNECT) {
            return Vec::new();
        }
        self.prelude()
    }

    /// A CONNECT whose flags announce a username or a password. A CONNECT
    /// this grammar cannot decode counts as one: a seed that cannot be shown
    /// to be free of credentials is treated as carrying them.
    fn is_credential_message(&self, bytes: &[u8]) -> bool {
        if packet_type(bytes) != Some(CONNECT) {
            return false;
        }
        connect_flags(bytes).is_none_or(|flags| flags & CREDENTIAL_FLAGS != 0)
    }

    /// The CONNECT with both credential flags cleared, the username and
    /// password dropped, and `remaining_length` re-satisfied over the shorter
    /// body. `None` for anything that is not a CONNECT, or a CONNECT this
    /// grammar cannot parse — such a seed is dropped, not guessed at.
    fn strip_credentials(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if packet_type(bytes) != Some(CONNECT) {
            return None;
        }
        let mut tree = self.parse(bytes)?;

        let flags = tree.get_mut(&FieldPath::new(CONNECT_FLAGS_PATH))?;
        let cleared = flags.bytes.first()? & !CREDENTIAL_FLAGS;
        flags.bytes = vec![cleared];

        let credentials = tree.get_mut(&FieldPath::new(CREDENTIALS_PATH))?;
        credentials.children.clear();

        resatisfy(&mut tree, None);
        Some(render(&tree))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::{grammar, Mqtt};
    use crate::client::Ended;
    use crate::denylist;
    use crate::grammar::{Expect, Grammar, ReplyClass};
    use crate::spec::{GrammarKind, Transport};
    use crate::tree::{render, FieldPath, Tree};

    /// T10's CONNECT: protocol `MQTT` level 4, clean session, keepalive 60,
    /// an empty client id, no will and no credentials.
    const CONNECT: [u8; 14] = [
        0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
    ];

    /// A CONNECT with the username and password flags set, client id `c`,
    /// username `u`, password `p`.
    const CONNECT_WITH_CREDENTIALS: [u8; 21] = [
        0x10, 0x13, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0xc2, 0x00, 0x3c, 0x00, 0x01, 0x63,
        0x00, 0x01, 0x75, 0x00, 0x01, 0x70,
    ];

    fn bytes_at(tree: &Tree, path: &str) -> Vec<u8> {
        tree.get(&FieldPath::new(path))
            .unwrap_or_else(|| panic!("the tree has no node at {path}"))
            .bytes
            .clone()
    }

    #[test]
    fn mqtt_connect_bytes_parse() {
        let mqtt = grammar();
        assert_eq!(mqtt.name(), "mqtt");
        assert_eq!(mqtt.kind(), GrammarKind::Mqtt);
        assert_eq!(mqtt.transport(), Transport::Tcp);
        assert_eq!(mqtt.default_ports(), &[1883]);
        // The 3.1.1 specification tells a broker to close on a malformed
        // packet, so a close is the protocol working (spec S3 row 6).
        assert!(mqtt.close_on_malformed_is_expected());
        assert!(!mqtt.expects_banner());

        let tree = mqtt.parse(&CONNECT).expect("T10's CONNECT is MQTT 3.1.1");
        assert_eq!(tree.grammar, "mqtt");
        assert_eq!(bytes_at(&tree, "fixed.type_flags"), vec![0x10]);
        assert_eq!(bytes_at(&tree, "fixed.remaining_length"), vec![0x0c]);
        assert_eq!(bytes_at(&tree, "variable.connect.keepalive"), vec![0, 0x3c]);
        assert_eq!(
            bytes_at(&tree, "variable.connect.proto_name.text"),
            b"MQTT".to_vec()
        );
        assert_eq!(bytes_at(&tree, "variable.connect.level"), vec![0x04]);
        assert_eq!(
            bytes_at(&tree, "variable.connect.connect_flags"),
            vec![0x02]
        );
        assert_eq!(
            bytes_at(&tree, "variable.connect.client_id.len"),
            vec![0x00, 0x00]
        );
        assert_eq!(render(&tree), CONNECT.to_vec());
    }

    #[test]
    fn mqtt_generate_parses_back() {
        let mqtt = grammar();
        let mut rng = ChaCha8Rng::seed_from_u64(17);
        let mut kinds = BTreeSet::new();
        for case in 0..64 {
            let bytes = mqtt.generate(&mut rng);
            let tree = mqtt
                .parse(&bytes)
                .unwrap_or_else(|| panic!("case {case} must parse back"));
            assert_eq!(render(&tree), bytes, "case {case}");
            assert_eq!(
                denylist::refuses(GrammarKind::Mqtt, &bytes),
                None,
                "case {case} renders a denylisted publish"
            );
            assert!(mqtt.reply_complete(&bytes), "case {case} is a whole packet");

            let first = bytes[0];
            kinds.insert(first);
            match first {
                // PINGREQ.
                0xc0 => assert_eq!(bytes, vec![0xc0, 0x00], "case {case}"),
                // PUBLISH, QoS 0, no retain.
                0x30 => {
                    assert_eq!(
                        bytes_at(&tree, "variable.publish.topic.text"),
                        b"a/b".to_vec(),
                        "case {case}"
                    );
                    assert!(
                        !bytes_at(&tree, "variable.publish.payload").is_empty(),
                        "case {case}"
                    );
                }
                // SUBSCRIBE, whose flags nibble is fixed at 2.
                0x82 => {
                    assert_eq!(
                        bytes_at(&tree, "variable.subscribe.topics[0].text"),
                        b"a/#".to_vec(),
                        "case {case}"
                    );
                    assert_eq!(
                        bytes_at(&tree, "variable.subscribe.topics[0].qos"),
                        vec![0x00],
                        "case {case}"
                    );
                }
                other => panic!("case {case}: unexpected packet type byte {other:#04x}"),
            }
        }
        assert_eq!(kinds, BTreeSet::from([0x30, 0x82, 0xc0]));
    }

    #[test]
    fn mqtt_classify() {
        let mqtt = grammar();
        // CONNACK, no session present, accepted / refused (bad credentials).
        assert_eq!(
            mqtt.classify_reply(&[0x20, 0x02, 0x00, 0x00]),
            ReplyClass::Ok
        );
        assert_eq!(
            mqtt.classify_reply(&[0x20, 0x02, 0x00, 0x05]),
            ReplyClass::ProtocolError
        );
        // PINGRESP, PUBACK, PUBREC.
        assert_eq!(mqtt.classify_reply(&[0xd0, 0x00]), ReplyClass::Ok);
        assert_eq!(
            mqtt.classify_reply(&[0x40, 0x02, 0x00, 0x01]),
            ReplyClass::Ok
        );
        assert_eq!(
            mqtt.classify_reply(&[0x50, 0x02, 0x00, 0x01]),
            ReplyClass::Ok
        );
        // SUBACK: a granted QoS, then a refusal.
        assert_eq!(
            mqtt.classify_reply(&[0x90, 0x03, 0x00, 0x01, 0x00]),
            ReplyClass::Ok
        );
        assert_eq!(
            mqtt.classify_reply(&[0x90, 0x03, 0x00, 0x01, 0x80]),
            ReplyClass::ProtocolError
        );
        assert_eq!(mqtt.classify_reply(&[]), ReplyClass::Unknown);
        assert_eq!(mqtt.classify_reply(&[0x70, 0x00]), ReplyClass::Unknown);

        // Framing: the fixed header plus the varint remaining length.
        assert!(mqtt.reply_complete(&[0x20, 0x02, 0x00, 0x00]));
        assert!(!mqtt.reply_complete(&[0x20, 0x02, 0x00]));
        assert!(mqtt.reply_complete(&[0xd0, 0x00]));
        assert!(!mqtt.reply_complete(&[0xd0]));
        assert!(!mqtt.reply_complete(&[]));
    }

    #[test]
    fn mqtt_strip_credentials() {
        let mqtt = grammar();
        assert!(mqtt.is_credential_message(&CONNECT_WITH_CREDENTIALS));

        let before = mqtt
            .parse(&CONNECT_WITH_CREDENTIALS)
            .expect("a CONNECT with credentials parses");
        assert_eq!(
            bytes_at(
                &before,
                "variable.connect.credentials.user_pass.password.text"
            ),
            b"p".to_vec()
        );
        assert!(
            before
                .get(&FieldPath::new(
                    "variable.connect.credentials.user_pass.password.text"
                ))
                .is_some_and(|node| node.secret),
            "the password field is secret (spec S3 row 6)"
        );

        let stripped = mqtt
            .strip_credentials(&CONNECT_WITH_CREDENTIALS)
            .expect("a CONNECT's credentials are stripped, not dropped");
        assert_eq!(
            stripped,
            vec![
                0x10, 0x0d, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x01,
                0x63
            ]
        );
        assert!(!mqtt.is_credential_message(&stripped));

        let after = mqtt.parse(&stripped).expect("the stripped CONNECT parses");
        assert_eq!(bytes_at(&after, "fixed.remaining_length"), vec![0x0d]);
        assert_eq!(
            bytes_at(&after, "variable.connect.connect_flags"),
            vec![0x02]
        );
        assert_eq!(
            bytes_at(&after, "variable.connect.client_id.text"),
            b"c".to_vec()
        );
        assert!(after
            .get(&FieldPath::new(
                "variable.connect.credentials.user_pass.password.text"
            ))
            .is_none());

        // A CONNECT without credentials carries none and survives unchanged;
        // a packet that is not a CONNECT is not a credential message.
        assert!(!mqtt.is_credential_message(&CONNECT));
        assert_eq!(mqtt.strip_credentials(&CONNECT), Some(CONNECT.to_vec()));
        assert!(!mqtt.is_credential_message(&[0xc0, 0x00]));
        assert_eq!(mqtt.strip_credentials(&[0xc0, 0x00]), None);
        // A CONNECT this grammar cannot decode is treated as carrying one.
        assert!(mqtt.is_credential_message(&[0x10, 0x02, 0x00]));
    }

    #[test]
    fn mqtt_prelude_for_connect_case_is_empty() {
        let mqtt = grammar();
        let prelude = mqtt.prelude();
        assert_eq!(prelude.len(), 1);
        assert_eq!(prelude[0][0], 0x10, "the prelude is the liveness CONNECT");

        // A CONNECT case is its own prelude and goes on a fresh connection.
        assert!(mqtt.prelude_for(&CONNECT).is_empty());
        assert!(mqtt.prelude_for(&[0x10, 0x00]).is_empty());
        // Anything else needs the CONNECT first.
        assert_eq!(mqtt.prelude_for(&[0xc0, 0x00]).len(), 1);
        assert_eq!(mqtt.prelude_for(&[0x30, 0x05]).len(), 1);
        assert_eq!(mqtt.prelude_for(&[]).len(), 1);
    }

    #[test]
    fn mqtt_liveness_connects_with_a_fresh_client_id() {
        let mqtt: Arc<dyn Grammar> = Arc::new(Mqtt::new());
        let first = mqtt.liveness_probe();
        let second = mqtt.liveness_probe();

        assert_eq!(first.expect, Expect::Prefix(vec![0x20]));
        assert_eq!(first.after, Some(vec![0xe0, 0x00]));
        assert_eq!(
            denylist::refuses(GrammarKind::Mqtt, &first.send),
            None,
            "the liveness CONNECT sets no will-retain bit"
        );

        let tree = mqtt
            .parse(&first.send)
            .expect("the liveness CONNECT is a CONNECT");
        assert_eq!(bytes_at(&tree, "variable.connect.level"), vec![0x04]);
        assert_eq!(
            bytes_at(&tree, "variable.connect.connect_flags"),
            vec![0x02]
        );
        assert_eq!(
            bytes_at(&tree, "variable.connect.keepalive"),
            vec![0x00, 0x3c]
        );
        let client_id = bytes_at(&tree, "variable.connect.client_id.text");
        assert_eq!(client_id.len(), 14, "aitm-scan- and four hex digits");
        assert!(client_id.starts_with(b"aitm-scan-"));
        assert!(!mqtt.is_credential_message(&first.send));

        assert_ne!(first.send, second.send, "a fresh client id per probe");
        assert!(first.matches(&[0x20, 0x02, 0x00, 0x00], Ended::Replied));
        // Any return code proves the broker is alive (spec S3 row 6).
        assert!(first.matches(&[0x20, 0x02, 0x00, 0x05], Ended::Replied));
        assert!(!first.matches(&[0xd0, 0x00], Ended::Replied));
        assert!(!first.matches(&[], Ended::Eof));
    }
}
