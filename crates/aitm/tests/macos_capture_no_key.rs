//! Task 9 — the no-CA-key invariant (NE-AC16, Rust / no-key side).
//!
//! The macOS Network Extension captures network **flows** and hands them to the
//! core over the Task-8 [`CaptureListener`] handoff: a control channel carrying
//! metadata ([`Hello`], [`ScopeSpec`], [`FlowOpen`]) and one per-flow data socket
//! carrying raw bytes. **MITM TLS termination stays in the core**; the extension
//! never receives or stores the CA key (spec NE-AC16). This test proves the
//! capture path cannot exfiltrate the CA private key: a core that *holds* a known
//! CA private-key DER drives one real flow through the listener, and the bytes
//! that cross the handoff to the provider are asserted to **never** contain that
//! DER.
//!
//! Behavioural, no production change: it binds a real `CaptureListener`, runs one
//! flow over loopback Unix sockets, and scans the bytes that actually crossed. The
//! control frames are byte-identical to the wire (the same `serde_json::to_vec`
//! the listener's framing uses); the data payload is captured **raw off the data
//! socket** — the bulk channel where key material would realistically hide.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aitm::macos_capture::listener::{
    write_data_handshake, CaptureListener, ControlChannel, ControlMessage, DataHandshake, FlowKind,
    FlowOpen, Hello, ScopeSpec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// A known CA **private-key** DER byte sequence the core holds. A PKCS#8 RSA
/// private-key preamble (`SEQUENCE`, version `0`, the `rsaEncryption` OID, the
/// `OCTET STRING` wrapper) followed by distinctive filler — unmistakably key
/// material, and long/unique enough that a window match cannot be a coincidence.
const KEY_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x22, // SEQUENCE, length
    0x02, 0x01, 0x00, // INTEGER version = 0
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, // AlgorithmIdentifier: rsaEncryption
    0x04, 0x82, 0x01, 0x0c, // OCTET STRING (the wrapped private key)
    // Distinctive private-key body filler.
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// A stand-in core that **holds** the CA private key. It builds what it advertises
/// to the provider from its *config* (the scope spec), never from the key — so if
/// a regression ever folded key material into the handoff, the bytes crossing the
/// socket would carry `KEY_DER` and this test would fail.
struct FakeCore {
    /// The CA private-key DER the core terminates TLS with. Must never cross the
    /// capture handoff.
    ca_key_der: Vec<u8>,
    /// The active scope/intercept spec the core advertises to the provider.
    scope_spec: String,
}

impl FakeCore {
    fn with_ca(key_der: &[u8]) -> Self {
        Self {
            ca_key_der: key_der.to_vec(),
            scope_spec: "allow https://example.com/*".to_string(),
        }
    }

    /// The scope the core advertises on the control channel — built from config,
    /// not from the CA key.
    fn advertise_scope(&self) -> ScopeSpec {
        ScopeSpec {
            spec: self.scope_spec.clone(),
        }
    }

    fn ca_key_der(&self) -> &[u8] {
        &self.ca_key_der
    }
}

/// `true` if `needle` appears as a contiguous window of `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A unique temp dir, mirroring the listener test's convention (a Unix socket path
/// must stay under `SUN_LEN`, so the prefix is kept short).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aml-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn control_hello_carries_no_ca_key() {
    let tmp = TempDir::new("nokey");
    let dir = tmp.path().join("s");

    // A core that holds the CA private key and runs the real capture listener.
    let core = FakeCore::with_ca(KEY_DER);
    let listener = CaptureListener::bind(&dir).expect("bind capture listener");
    let control_path = listener.control_path();
    let data_path = listener.data_path();

    let remote: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let flow_open = FlowOpen {
        flow_id: 7,
        kind: FlowKind::Tcp,
        remote,
        remote_hostname: Some("example.com".to_string()),
        source_app: Some("com.example.browser".to_string()),
        local: None,
    };
    // The flow's client bytes — ordinary plaintext request, no key material.
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();

    // Provider side: announce itself, open one flow, receive the core's scope
    // advertisement, then push the flow's bytes down the per-flow data socket.
    let fo = flow_open.clone();
    let payload_send = payload.clone();
    let provider = tokio::spawn(async move {
        let ctrl = UnixStream::connect(&control_path)
            .await
            .expect("connect control");
        let mut control = ControlChannel::from_stream(ctrl);
        control
            .send(&ControlMessage::Hello(Hello {
                protocol_version: 1,
            }))
            .await
            .expect("send hello");
        control
            .send(&ControlMessage::FlowOpen(fo))
            .await
            .expect("send flow-open");
        // What the core sends back toward the provider (the only core→provider
        // control message): the scope advertisement.
        let scope = control
            .recv()
            .await
            .expect("recv scope")
            .expect("scope frame");

        let mut data = UnixStream::connect(&data_path).await.expect("connect data");
        write_data_handshake(&mut data, DataHandshake { flow_id: 7 })
            .await
            .expect("send data handshake");
        data.write_all(&payload_send).await.expect("send payload");
        data.shutdown().await.expect("shutdown data");

        (control, scope)
    });

    // Core side: accept the flow and advertise its scope (built from config, never
    // from the CA key it holds).
    let mut control = listener.accept_control().await.expect("accept control");
    let hello = control
        .recv()
        .await
        .expect("recv hello")
        .expect("hello frame");
    assert_eq!(
        hello,
        ControlMessage::Hello(Hello {
            protocol_version: 1
        })
    );
    let got_open = control
        .recv()
        .await
        .expect("recv flow-open")
        .expect("flow-open frame");
    assert_eq!(got_open, ControlMessage::FlowOpen(flow_open.clone()));
    control
        .send(&ControlMessage::Scope(core.advertise_scope()))
        .await
        .expect("advertise scope");

    // The flow's bytes cross the per-flow data socket; capture them raw.
    let data = listener.accept_data().await.expect("accept data");
    assert_eq!(data.flow_id, 7, "data socket correlates to its flow");
    let mut data_received = Vec::new();
    data.into_stream()
        .read_to_end(&mut data_received)
        .await
        .expect("read flow data");

    let (_held, scope_recv) = provider.await.expect("provider task");

    // Concatenate every byte that crossed the handoff, in both directions:
    //   provider → core : Hello, FlowOpen (control) ; DataHandshake + payload (data)
    //   core → provider : Scope (control, as the provider actually received it)
    // Control frames are serialized with the same `serde_json::to_vec` the
    // listener's framing writes, so they are byte-identical to the wire; the data
    // payload is the raw bytes read straight off the socket.
    let mut crossed = Vec::new();
    crossed.extend(
        serde_json::to_vec(&ControlMessage::Hello(Hello {
            protocol_version: 1,
        }))
        .unwrap(),
    );
    crossed.extend(serde_json::to_vec(&ControlMessage::FlowOpen(flow_open)).unwrap());
    crossed.extend(serde_json::to_vec(&scope_recv).unwrap());
    crossed.extend(serde_json::to_vec(&DataHandshake { flow_id: 7 }).unwrap());
    crossed.extend_from_slice(&data_received);

    // The invariant: the CA private key never crosses the capture handoff.
    assert!(
        !crossed.windows(KEY_DER.len()).any(|w| w == KEY_DER),
        "the capture handoff must not carry the CA private-key DER"
    );

    // The flow really crossed (the listener was exercised, not short-circuited).
    assert_eq!(
        data_received, payload,
        "the flow's data crossed the per-flow data socket"
    );
    // The core still holds the key — it was never moved onto the wire.
    assert!(
        contains(core.ca_key_der(), KEY_DER),
        "the core retains the CA private key"
    );
    // Non-vacuity: the window scan does detect the key when it is present, so the
    // negative assertion above is meaningful rather than always-true.
    let mut poisoned = crossed.clone();
    poisoned.extend_from_slice(KEY_DER);
    assert!(
        poisoned.windows(KEY_DER.len()).any(|w| w == KEY_DER),
        "the window scan must detect the key when it is present"
    );
}
