//! AC1: an HTTPS request through the proxy is MITM'd, captured as an `HttpFlow`,
//! and answered by the real upstream. AC5: a plugin's request mutation reaches
//! that upstream. Both run a real `Proxy` against a local rustls fixture.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    Body, Config, Event, Flow, FlowCtx, FlowStore, HttpFlow, Plugin, Proxy, ScopeConfig,
    ScopeEntry, Verdict,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-https-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A loopback port nobody is listening on right now.
fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
}

/// Read until the blank line that ends an HTTP head; returns the head text.
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

/// The value of header `name` (case-insensitive) in a head.
fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// A TLS server for `127.0.0.1` that answers every request with 200 and a body
/// naming the `X-Aitm` header it saw, so a test can tell what reached upstream.
async fn spawn_fixture() -> SocketAddr {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("fixture versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("fixture server config");
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let addr = listener.local_addr().expect("fixture addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let head = read_head(&mut tls).await;
                let seen = header_value(&head, "x-aitm").unwrap_or_else(|| "none".to_string());
                let body = format!("hello-aitm x-aitm={seen}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Run a `Proxy` with the HTTP module (using `ca`) and `plugins`; `127.0.0.1`
/// is in scope so the guarded upstream connector admits the fixture.
async fn run_proxy(
    ca: Arc<CertAuthority>,
    plugins: Vec<Box<dyn Plugin>>,
) -> (SocketAddr, Arc<dyn FlowStore>) {
    let config = Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
            ..ScopeConfig::default()
        },
        ..Config::default()
    };
    let mut builder = Proxy::builder()
        .with_config(config)
        // The test upstream presents a self-signed leaf; trust it explicitly.
        .register_module(Arc::new(HttpModule::with_ca(ca).with_insecure(true)));
    for plugin in plugins {
        builder = builder.register_plugin(plugin);
    }
    let proxy = builder.build().expect("build proxy");
    let store = proxy.store();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    // Wait until the acceptor is listening.
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, store)
}

/// `GET path` to `upstream` over HTTPS through the proxy: CONNECT, then TLS
/// trusting only the proxy CA, then one request. Returns (status, body).
async fn https_get(
    proxy: SocketAddr,
    upstream: SocketAddr,
    path: &str,
    root_pem: &str,
) -> (u16, String) {
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
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(upstream.ip().to_string()).expect("server name");
    let mut tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the proxy impersonating upstream");

    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("send request");
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response: {e}"),
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// A TLS fixture that answers with a body of exactly `len` bytes.
async fn spawn_big_fixture(len: usize) -> SocketAddr {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("fixture versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("fixture server config");
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let addr = listener.local_addr().expect("fixture addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = read_head(&mut tls).await;
                let body = vec![b'A'; len];
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Run a proxy whose HTTP module caps bodies at `max_body`.
async fn run_proxy_capped(
    ca: Arc<CertAuthority>,
    max_body: usize,
) -> (SocketAddr, Arc<dyn FlowStore>) {
    let config = Config {
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "127.0.0.1".to_string(),
            }],
            ..ScopeConfig::default()
        },
        ..Config::default()
    };
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(
            HttpModule::with_ca(ca)
                .with_insecure(true)
                .with_max_body_bytes(max_body),
        ))
        .build()
        .expect("build proxy");
    let store = proxy.store();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, store)
}

/// A response body over the cap is truncated in the stored copy and the flow is
/// marked truncated, while the client still receives the full body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_body_capped_in_store() {
    let dir = temp_dir();
    let ca = Arc::new(CertAuthority::load_or_generate(&dir, 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();

    let cap = 64usize;
    let upstream = spawn_big_fixture(1000).await;
    let (proxy, store) = run_proxy_capped(ca, cap).await;

    let (status, body) = https_get(proxy, upstream, "/big", &root_pem).await;
    assert_eq!(status, 200);
    // The client received the whole body.
    assert_eq!(body.len(), 1000, "client must get the full streamed body");

    let flow = wait_for_flow(&*store).await;
    assert!(flow.metadata.truncated, "flow must be marked truncated");
    match flow.response.and_then(|r| match r.body {
        Body::Bytes(b) => Some(b.len()),
        _ => None,
    }) {
        Some(len) => assert_eq!(len, cap, "stored response copy must be capped"),
        None => panic!("expected a buffered (truncated) response body"),
    }
}

/// The first captured HTTP flow that has a response, waiting briefly for it.
async fn wait_for_flow(store: &dyn FlowStore) -> HttpFlow {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = store.list().into_iter().find_map(|id| match store.get(id) {
            Some(Flow::Http(f)) if f.response.is_some() => Some(f),
            _ => None,
        });
        if let Some(flow) = found {
            return flow;
        }
        assert!(Instant::now() < deadline, "no completed HttpFlow captured");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_get_captured() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let upstream = spawn_fixture().await;
    let (proxy, store) = run_proxy(ca.clone(), Vec::new()).await;

    let (status, body) = https_get(proxy, upstream, "/hello", ca.root_cert_pem()).await;
    assert_eq!(status, 200);
    assert!(body.contains("hello-aitm"), "client body was {body:?}");

    let flow = wait_for_flow(store.as_ref()).await;
    assert_eq!(flow.request.method, "GET");
    assert_eq!(flow.request.path, "/hello");
    assert_eq!(flow.request.scheme, "https");
    assert_eq!(flow.request.authority, upstream.to_string());
    let response = flow.response.expect("response captured");
    assert_eq!(response.status, 200);
    match &response.body {
        Body::Bytes(bytes) => assert!(
            String::from_utf8_lossy(bytes).contains("hello-aitm"),
            "captured body was {:?}",
            String::from_utf8_lossy(bytes)
        ),
        other => panic!("captured body was {other:?}, want Bytes"),
    }
}

/// Adds `X-Aitm: on` to every request as it passes the chain.
struct AddHeader;

impl Plugin for AddHeader {
    fn name(&self) -> &str {
        "add-header"
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            if let Flow::Http(f) = ctx.flow_mut() {
                f.request.headers.set("X-Aitm", "on");
            }
        }
        Verdict::Continue
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_mutation_reaches_upstream() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let upstream = spawn_fixture().await;
    let (proxy, store) = run_proxy(ca.clone(), vec![Box::new(AddHeader)]).await;

    let (status, body) = https_get(proxy, upstream, "/mutated", ca.root_cert_pem()).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("x-aitm=on"),
        "upstream did not receive X-Aitm: on; it reported {body:?}"
    );

    let flow = wait_for_flow(store.as_ref()).await;
    assert_eq!(flow.request.headers.get("x-aitm"), Some("on"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_connection_hits_leaf_cache() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let upstream = spawn_fixture().await;
    let (proxy, _store) = run_proxy(ca.clone(), Vec::new()).await;

    let (status, _) = https_get(proxy, upstream, "/one", ca.root_cert_pem()).await;
    assert_eq!(status, 200);
    assert!(
        !ca.last_was_cache_hit(),
        "the first connection to a host must mint its leaf"
    );
    let (status, _) = https_get(proxy, upstream, "/two", ca.root_cert_pem()).await;
    assert_eq!(status, 200);
    assert!(
        ca.last_was_cache_hit(),
        "the second connection to the same host must reuse the cached leaf"
    );
}
