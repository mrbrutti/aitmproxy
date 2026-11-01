//! `TcpTransport` against a real loopback listener (task 2 of the T4 plan).
//!
//! Every test here binds a port, which the Claude sandbox refuses, so each is
//! `#[ignore]`d and run from the Terminal panel:
//!
//! ```text
//! cargo test -p aitm-scan-ws --test tcp_transport -- --ignored
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aitm_scan_ws::transport::{TcpTransport, WsTransport};
use aitm_scan_ws::types::TlsPolicy;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A server config holding a fresh self-signed certificate for `127.0.0.1`.
fn self_signed_server() -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("fixture versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .expect("fixture server config");
    Arc::new(cfg)
}

#[tokio::test]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn tcp_plain_connect_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let serving = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut byte = [0u8; 1];
        sock.read_exact(&mut byte).await.expect("server read");
        sock.write_all(&byte).await.expect("server write");
        sock.flush().await.expect("server flush");
    });

    let transport = TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(2));
    let mut stream = transport
        .connect(addr, false, "127.0.0.1")
        .await
        .expect("plain connect");
    stream.write_all(b"x").await.expect("client write");
    stream.flush().await.expect("client flush");

    let mut back = [0u8; 1];
    stream.read_exact(&mut back).await.expect("client read");
    assert_eq!(&back, b"x");
    serving.await.expect("server task");
}

#[tokio::test]
#[ignore = "binds a loopback port; run in the Terminal"]
async fn tcp_tls_accept_any_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    let acceptor = TlsAcceptor::from(self_signed_server());
    let serving = tokio::spawn(async move {
        // Two connections: the accept-any client, then the verifying one.
        for _ in 0..2 {
            let (sock, _) = listener.accept().await.expect("accept");
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(sock).await {
                    let _ = tls.write_all(b"tls-ok").await;
                    let _ = tls.flush().await;
                }
            });
        }
    });

    let accept_any = TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(5));
    let mut stream = accept_any
        .connect(addr, true, "127.0.0.1")
        .await
        .expect("accept-any TLS connect");
    let mut got = [0u8; 6];
    stream.read_exact(&mut got).await.expect("client read");
    assert_eq!(&got, b"tls-ok");

    let verifying = TcpTransport::new(TlsPolicy::Verify, Duration::from_secs(5));
    let text = match verifying.connect(addr, true, "127.0.0.1").await {
        Ok(_) => panic!("verify must reject a self-signed certificate"),
        Err(err) => format!("{err:#}"),
    };
    assert!(
        text.contains("certificate"),
        "expected a certificate error, got: {text}"
    );

    serving.await.expect("listener task");
}
