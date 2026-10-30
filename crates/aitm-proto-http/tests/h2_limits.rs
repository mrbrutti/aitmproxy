//! M7 Task 5 (AC-H2.10): the per-connection concurrent-stream bound holds.
//!
//! An `HttpModule` built `with_max_concurrent_streams(2)` must advertise that
//! `SETTINGS_MAX_CONCURRENT_STREAMS` to the client, so a client holding two
//! streams open cannot open a third until one of the two completes — the bound
//! is enforced, not merely buffered. The test stands up a *gated* in-process h2
//! origin behind a forged-leaf TLS listener: the origin accepts a request but
//! withholds its response until the test releases a permit, so two streams stay
//! genuinely in flight while the third is attempted.
//!
//! These bind loopback ports, so they run under the Terminal panel, not the
//! sandbox (CLAUDE.md).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{Config, Proxy, ScopeConfig, ScopeEntry};
use aitm_proto_http::{CertAuthority, HttpModule};
use bytes::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const ALPN_H2: &[u8] = b"h2";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-h2limits-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
}

/// How many request streams the origin has accepted so far.
#[derive(Default)]
struct OriginLog {
    accepted: usize,
}

/// A TLS h2 origin on `127.0.0.1` that records every request it accepts but
/// withholds each response until a permit is available on `gate`. Each accepted
/// stream acquires one permit before answering `200` with `body`, so the test
/// controls exactly how many streams complete.
async fn spawn_gated_origin(
    log: Arc<Mutex<OriginLog>>,
    gate: Arc<Semaphore>,
    body: Vec<u8>,
) -> SocketAddr {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("fixture versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("fixture server config");
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let log = log.clone();
            let gate = gate.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(accepted) = conn.accept().await {
                    let Ok((req, mut respond)) = accepted else {
                        break;
                    };
                    let (_parts, mut rbody) = req.into_parts();
                    while let Some(Ok(chunk)) = rbody.data().await {
                        let _ = rbody.flow_control().release_capacity(chunk.len());
                    }
                    if let Ok(mut l) = log.lock() {
                        l.accepted += 1;
                    }
                    let gate = gate.clone();
                    let body = body.clone();
                    // Answer on a task so a withheld stream does not stall its
                    // siblings on the same connection.
                    tokio::spawn(async move {
                        // Block until the test releases a permit for this stream.
                        let _permit = gate.acquire().await.expect("gate open");
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(Bytes::from(body), true);
                        }
                    });
                }
            });
        }
    });
    addr
}

/// Run a `Proxy` with the HTTP module (trusting self-signed origins), its h2
/// concurrency bounded to `max_streams`; `127.0.0.1` is in scope.
async fn run_proxy_bounded(ca: Arc<CertAuthority>, max_streams: u32) -> SocketAddr {
    let config = Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
            ..ScopeConfig::default()
        },
        ..Config::default()
    };
    let module = HttpModule::with_ca(ca)
        .with_insecure(true)
        .with_max_concurrent_streams(max_streams as usize);
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(module))
        .build()
        .expect("build proxy");
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    addr
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).await.expect("read head");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        assert!(buf.len() < 64 * 1024, "head never terminated");
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// CONNECT to `upstream` through `proxy`, finish TLS trusting only the proxy CA,
/// offering h2, and open an h2 client connection. Returns the `SendRequest`.
async fn connect_h2(
    proxy: SocketAddr,
    upstream: SocketAddr,
    root_pem: &str,
) -> h2::client::SendRequest<Bytes> {
    let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
    tcp.write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let reply = read_head(&mut tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "CONNECT was not accepted: {reply:?}"
    );

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(root_pem.as_bytes()).expect("root PEM"))
        .expect("add root");
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_H2.to_vec()];
    let name = ServerName::try_from(upstream.ip().to_string()).expect("server name");
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the proxy impersonating upstream");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "proxy must mirror h2 down to the client"
    );
    let (send_req, conn) = h2::client::handshake(tls)
        .await
        .expect("h2 client handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send_req
}

fn get_req(upstream: SocketAddr, path: &str) -> http::Request<()> {
    http::Request::builder()
        .method("GET")
        .uri(format!("https://{upstream}{path}"))
        .body(())
        .unwrap()
}

/// Wait until the origin has accepted at least `n` request streams.
async fn wait_for_accepted(log: &Arc<Mutex<OriginLog>>, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if log.lock().unwrap().accepted >= n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "origin accepted only {} of {n} streams",
            log.lock().unwrap().accepted
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// AC-H2.10: with the module bounded to two concurrent streams, a client that is
/// holding two streams open cannot admit a third until one of the two completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_streams_bounded() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    // No permits yet: the origin withholds every response until the test releases one.
    let gate = Arc::new(Semaphore::new(0));
    let origin = spawn_gated_origin(log.clone(), gate.clone(), b"bounded-body".to_vec()).await;
    let proxy = run_proxy_bounded(ca, 2).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;

    // Open two streams; neither can complete (the origin is gated).
    let mut s1 = send_req.clone().ready().await.expect("slot 1 admitted");
    let (resp1, _) = s1
        .send_request(get_req(origin, "/one"), true)
        .expect("send stream 1");
    let mut s2 = send_req.clone().ready().await.expect("slot 2 admitted");
    let (resp2, _) = s2
        .send_request(get_req(origin, "/two"), true)
        .expect("send stream 2");

    // Both reach the origin → two streams genuinely in flight.
    wait_for_accepted(&log, 2).await;

    // Open a third stream. The proxy advertised SETTINGS_MAX_CONCURRENT_STREAMS=2,
    // so the client must hold this stream's HEADERS back while two streams are
    // active: it must NOT reach the origin until one of the first two completes.
    let mut s3 = send_req
        .clone()
        .ready()
        .await
        .expect("third stream readied");
    let (resp3, _) = s3
        .send_request(get_req(origin, "/three"), true)
        .expect("send stream 3");

    // Give the third stream ample time to (wrongly) proceed; under the bound it
    // cannot, so the origin still sees exactly two requests — not three buffered.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        log.lock().unwrap().accepted,
        2,
        "the third stream must not proceed to the origin while two are active \
         (concurrency bound not enforced — all three buffered through)"
    );

    // Free exactly one slot: one of the first two completes, and only then does
    // the third stream reach the origin.
    gate.add_permits(1);
    wait_for_accepted(&log, 3).await;

    // Release the remaining permits; all three streams complete with 200.
    gate.add_permits(2);
    for (resp, label) in [(resp1, "one"), (resp2, "two"), (resp3, "three")] {
        let r = resp
            .await
            .unwrap_or_else(|e| panic!("stream /{label} response: {e}"));
        assert_eq!(r.status(), 200, "stream /{label} must complete with 200");
    }
}
