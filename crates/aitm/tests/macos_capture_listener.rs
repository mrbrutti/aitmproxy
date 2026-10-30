//! Task 8 — core-listener handoff topology: control/data separation, a private
//! 0700 socket directory, and per-flow data sockets (NE-AC6 socket-dir side,
//! NE-AC7 Rust loopback round-trip).
//!
//! The provider half of the handoff is Band C (Swift); here a loopback UDS client
//! stands in for it so the topology is provable in the sandbox with no Mac.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aitm::macos_capture::listener::{
    write_data_handshake, CaptureListener, ControlChannel, ControlMessage, DataHandshake, FlowKind,
    FlowOpen, Hello,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// A unique temp dir, mirroring the repo's `std::env::temp_dir()` convention.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aitm-macos-listener-{tag}-{}-{}",
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
async fn control_and_data_separation_roundtrip() {
    let tmp = TempDir::new("roundtrip");
    // `bind` creates and locks the socket directory itself.
    let dir = tmp.path().join("sock");
    let listener = CaptureListener::bind(&dir).expect("bind capture listener");
    let control_path = listener.control_path();
    let data_path = listener.data_path();

    let remote: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
    let flow_open = FlowOpen {
        flow_id: 1,
        kind: FlowKind::Tcp,
        remote,
        remote_hostname: Some("example.com".to_string()),
        source_app: Some("com.example.browser".to_string()),
        local: None,
    };
    let flow_open_expected = flow_open.clone();

    // Provider side: control carries metadata only (hello + one flow-open); the
    // 65536-byte bulk payload travels the per-flow data socket after its handshake.
    let payload = vec![0xABu8; 65536];
    let payload_len = payload.len();
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
            .send(&ControlMessage::FlowOpen(flow_open))
            .await
            .expect("send flow-open");

        let mut data = UnixStream::connect(&data_path).await.expect("connect data");
        write_data_handshake(&mut data, DataHandshake { flow_id: 1 })
            .await
            .expect("send data handshake");
        data.write_all(&payload).await.expect("send bulk payload");
        data.shutdown().await.expect("shutdown data");

        // Hold the control channel open until the core has read both frames.
        control
    });

    // Core side.
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
    assert_eq!(got_open, ControlMessage::FlowOpen(flow_open_expected));

    let data = listener.accept_data().await.expect("accept data");
    assert_eq!(data.flow_id, 1, "data socket correlates to its flow");
    let mut stream = data.into_stream();
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.expect("read bulk");

    let _held = provider.await.expect("provider task");

    // Separation: the full bulk crossed the data socket; the control channel saw
    // only the two small metadata frames, never the bulk.
    assert_eq!(
        received.len(),
        payload_len,
        "the data socket carried the full bulk payload"
    );
    assert!(
        control.bytes_read() < 1024,
        "control channel carried only metadata (0 bulk bytes), saw {} bytes",
        control.bytes_read()
    );

    // The socket directory is private.
    let mode = std::fs::metadata(listener.dir())
        .expect("stat socket dir")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "socket directory is private 0700");
}
