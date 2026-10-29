//! Task 2 — ALPN mirror negotiation + the `serve_h2` driver, end to end.
//!
//! Each test stands up an in-process origin (the `h2` crate's server, or a tiny
//! HTTP/1.1 writer) behind a forged-leaf TLS listener the test owns, runs a real
//! `Proxy` with the HTTP module, and drives a client through the proxy via
//! CONNECT. These bind loopback ports, so they run under the Terminal panel, not
//! the sandbox (CLAUDE.md).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{
    Body, Config, Event, Flow, FlowCtx, FlowStore, HeaderMap, HttpFlow, HttpResponse, HttpVersion,
    Plugin, Proxy, ScopeConfig, ScopeEntry, Verdict,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use bytes::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const ALPN_H2: &[u8] = b"h2";
const ALPN_H1: &[u8] = b"http/1.1";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-h2mitm-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
}

/// What an origin saw: one entry per request stream it actually accepted.
#[derive(Default)]
struct OriginLog {
    requests: Vec<RecordedReq>,
}

#[derive(Clone)]
struct RecordedReq {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl OriginLog {
    fn count(&self) -> usize {
        self.requests.len()
    }
    fn header(&self, i: usize, name: &str) -> Option<String> {
        self.requests.get(i).and_then(|r| {
            r.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        })
    }
}

/// A TLS origin on `127.0.0.1` offering `alpn`, answering every request with 200
/// and `body`, and recording every request it received into `log`. Serves HTTP/2
/// when `h2` is negotiated, HTTP/1.1 otherwise.
async fn spawn_origin(alpn: Vec<Vec<u8>>, log: Arc<Mutex<OriginLog>>, body: Vec<u8>) -> SocketAddr {
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
    cfg.alpn_protocols = alpn;
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
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let is_h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
                if is_h2 {
                    serve_h2_origin(tls, log, body).await;
                } else {
                    serve_h1_origin(tls, log, body).await;
                }
            });
        }
    });
    addr
}

async fn serve_h2_origin<S>(tls: S, log: Arc<Mutex<OriginLog>>, body: Vec<u8>)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(mut conn) = h2::server::handshake(tls).await else {
        return;
    };
    while let Some(accepted) = conn.accept().await {
        let Ok((req, mut respond)) = accepted else {
            break;
        };
        let (parts, mut rbody) = req.into_parts();
        // Drain the request body, releasing flow-control capacity.
        while let Some(Ok(chunk)) = rbody.data().await {
            let _ = rbody.flow_control().release_capacity(chunk.len());
        }
        let headers = parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        if let Ok(mut l) = log.lock() {
            l.requests.push(RecordedReq {
                method: parts.method.as_str().to_string(),
                path: parts.uri.path().to_string(),
                headers,
            });
        }
        let resp = http::Response::builder().status(200).body(()).unwrap();
        if let Ok(mut send) = respond.send_response(resp, false) {
            let _ = send.send_data(Bytes::from(body.clone()), true);
        }
    }
}

async fn serve_h1_origin<S>(mut tls: S, log: Arc<Mutex<OriginLog>>, body: Vec<u8>)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let head = read_head(&mut tls).await;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    if let Ok(mut l) = log.lock() {
        l.requests.push(RecordedReq {
            method,
            path,
            headers,
        });
    }
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    let _ = tls.write_all(resp.as_bytes()).await;
    let _ = tls.write_all(&body).await;
    let _ = tls.shutdown().await;
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

/// Run a `Proxy` with the HTTP module (using `ca`, trusting self-signed origins)
/// and `plugins`; `127.0.0.1` is in scope. `max_body` caps bodies when `Some`.
async fn run_proxy(
    ca: Arc<CertAuthority>,
    plugins: Vec<Box<dyn Plugin>>,
    max_body: Option<usize>,
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
    let mut module = HttpModule::with_ca(ca).with_insecure(true);
    if let Some(cap) = max_body {
        module = module.with_max_body_bytes(cap);
    }
    let mut builder = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(module));
    for plugin in plugins {
        builder = builder.register_plugin(plugin);
    }
    let proxy = builder.build().expect("build proxy");
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

/// CONNECT to `upstream` through `proxy`, finish TLS trusting only the proxy CA,
/// offering `alpn`. Returns the decrypted stream and the negotiated protocol.
async fn connect_tls(
    proxy: SocketAddr,
    upstream: SocketAddr,
    root_pem: &str,
    alpn: Vec<Vec<u8>>,
) -> (tokio_rustls::client::TlsStream<TcpStream>, Option<Vec<u8>>) {
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
    cfg.alpn_protocols = alpn;
    let name = ServerName::try_from(upstream.ip().to_string()).expect("server name");
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the proxy impersonating upstream");
    let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    (tls, negotiated)
}

/// An open h2 client connection through the proxy, plus the authority to use in
/// request URIs.
async fn connect_h2(
    proxy: SocketAddr,
    upstream: SocketAddr,
    root_pem: &str,
) -> h2::client::SendRequest<Bytes> {
    let (tls, negotiated) = connect_tls(proxy, upstream, root_pem, vec![ALPN_H2.to_vec()]).await;
    assert_eq!(
        negotiated.as_deref(),
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

/// One `GET path` over an existing h2 connection → (status, body bytes).
async fn h2_get(
    send_req: &h2::client::SendRequest<Bytes>,
    upstream: SocketAddr,
    path: &str,
) -> (u16, Vec<u8>) {
    let mut sr = send_req.clone().ready().await.expect("h2 ready");
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{upstream}{path}"))
        .body(())
        .unwrap();
    let (resp_fut, _send_body) = sr.send_request(req, true).expect("send h2 request");
    let resp = resp_fut.await.expect("h2 response");
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("h2 body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    (status, buf)
}

/// One `GET path` over HTTP/1.1 through the proxy, offering `alpn` → (status, body).
async fn https_get_h1(
    proxy: SocketAddr,
    upstream: SocketAddr,
    path: &str,
    root_pem: &str,
    alpn: Vec<Vec<u8>>,
) -> (u16, String) {
    let (mut tls, _negotiated) = connect_tls(proxy, upstream, root_pem, alpn).await;
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

/// Wait until the store holds at least `n` flows that each have a response.
async fn wait_for_n_flows(store: &dyn FlowStore, n: usize) -> Vec<HttpFlow> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let flows: Vec<HttpFlow> = store
            .list()
            .into_iter()
            .filter_map(|id| match store.get(id) {
                Some(Flow::Http(f)) if f.response.is_some() => Some(f),
                _ => None,
            })
            .collect();
        if flows.len() >= n {
            return flows;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of {n} flows captured",
            flows.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// --- AC-H2.1 -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_end_to_end_capture() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(
        vec![ALPN_H2.to_vec()],
        log.clone(),
        b"h2-origin-body".to_vec(),
    )
    .await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, body) = h2_get(&send_req, origin, "/hello").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"h2-origin-body", "client must get the origin's body");

    let flow = wait_for_flow(store.as_ref()).await;
    assert_eq!(flow.request.version, HttpVersion::H2);
    assert_eq!(flow.request.path, "/hello");
    assert_eq!(flow.client_conn.alpn.as_deref(), Some("h2"));
    assert_eq!(flow.server_conn.and_then(|c| c.alpn).as_deref(), Some("h2"));
}

// --- AC-H2.2 -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_only_origin_falls_back() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    // Origin offers only http/1.1; a client offering h2 must still be served.
    let origin = spawn_origin(vec![ALPN_H1.to_vec()], log.clone(), b"h1-body".to_vec()).await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let (status, body) = https_get_h1(
        proxy,
        origin,
        "/fallback",
        &root_pem,
        vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()],
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("h1-body"), "client body was {body:?}");

    let flow = wait_for_flow(store.as_ref()).await;
    assert_eq!(flow.request.version, HttpVersion::Http11);
    assert_eq!(flow.client_conn.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(
        flow.server_conn.and_then(|c| c.alpn).as_deref(),
        Some("http/1.1")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_only_client_served_over_h1() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    // Origin is h2-capable (offers both); an h1-only client must be served over h1.
    let origin = spawn_origin(
        vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()],
        log.clone(),
        b"dual-body".to_vec(),
    )
    .await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let (status, body) = https_get_h1(
        proxy,
        origin,
        "/h1client",
        &root_pem,
        vec![ALPN_H1.to_vec()],
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("dual-body"), "client body was {body:?}");

    let flow = wait_for_flow(store.as_ref()).await;
    assert_eq!(flow.request.version, HttpVersion::Http11);
    assert_eq!(flow.client_conn.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(
        flow.server_conn.and_then(|c| c.alpn).as_deref(),
        Some("http/1.1")
    );
}

// --- AC-H2.3 -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_concurrent_streams_three_flows() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"multi".to_vec()).await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    // Open three streams concurrently, then await all their responses.
    let paths = ["/a", "/b", "/c"];
    let mut handles = Vec::new();
    for p in paths {
        let sr = send_req.clone();
        handles.push(tokio::spawn(async move { h2_get(&sr, origin, p).await }));
    }
    for h in handles {
        let (status, body) = h.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"multi");
    }

    let flows = wait_for_n_flows(store.as_ref(), 3).await;
    let mut ids: Vec<_> = flows.iter().map(|f| f.id).collect();
    ids.sort_by_key(|i| i.as_uuid());
    ids.dedup();
    assert_eq!(ids.len(), 3, "three distinct flow ids");
    for f in &flows {
        assert!(f.response.is_some(), "each flow has its own response");
    }
}

// --- AC-H2.7 (Map Local short-circuit) ---------------------------------------

struct MapLocal {
    body: Vec<u8>,
}

impl Plugin for MapLocal {
    fn name(&self) -> &str {
        "map-local"
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            let mut headers = HeaderMap::new();
            headers.set("Content-Type", "application/octet-stream");
            ctx.set_response(HttpResponse {
                status: 200,
                version: HttpVersion::H2,
                headers,
                body: Body::Bytes(self.body.clone()),
                timestamp: std::time::SystemTime::now(),
            });
        }
        Verdict::Continue
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn map_local_short_circuits_h2() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"ORIGIN".to_vec()).await;
    let (proxy, _store) = run_proxy(
        ca,
        vec![Box::new(MapLocal {
            body: b"local-fixture".to_vec(),
        })],
        None,
    )
    .await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, body) = h2_get(&send_req, origin, "/logo.png").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"local-fixture", "client must get the mapped body");
    // Give any (erroneous) upstream stream a moment to land before asserting zero.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        log.lock().unwrap().count(),
        0,
        "a short-circuited flow must open no upstream stream"
    );
}

// --- AC-H2.9 (hop-by-hop stripped on encode, e2e) ----------------------------

struct InjectConnectionHeader;

impl Plugin for InjectConnectionHeader {
    fn name(&self) -> &str {
        "inject-connection-header"
    }
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if matches!(ev, Event::Request(_)) {
            if let Flow::Http(f) = ctx.flow_mut() {
                f.request.headers.set("Connection", "keep-alive");
                f.request.headers.set("X-Keep", "1");
            }
        }
        Verdict::Continue
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_with_connection_header_succeeds() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"ok".to_vec()).await;
    let (proxy, _store) = run_proxy(ca, vec![Box::new(InjectConnectionHeader)], None).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, body) = h2_get(&send_req, origin, "/with-connection").await;
    // The hop-by-hop header is stripped on encode; the stream completes normally.
    assert_eq!(status, 200);
    assert_eq!(body, b"ok");

    let l = log.lock().unwrap();
    assert_eq!(l.count(), 1, "the request must reach the origin");
    assert_eq!(l.requests[0].method, "GET");
    assert_eq!(l.requests[0].path, "/with-connection");
    assert!(
        l.header(0, "connection").is_none(),
        "the illegal `connection` header must not reach h2 origin"
    );
    assert_eq!(
        l.header(0, "x-keep").as_deref(),
        Some("1"),
        "a legal injected header must be forwarded"
    );
}

// --- AC-H2.10 (response body cap) --------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_over_cap_truncated_copy() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let cap = 64usize;
    let full = vec![b'A'; 1000];
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), full.clone()).await;
    let (proxy, store) = run_proxy(ca, Vec::new(), Some(cap)).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, body) = h2_get(&send_req, origin, "/big").await;
    assert_eq!(status, 200);
    assert_eq!(
        body.len(),
        1000,
        "client must receive the full streamed body"
    );

    let flow = wait_for_flow(store.as_ref()).await;
    assert!(flow.metadata.truncated, "flow must be marked truncated");
    match flow.response.and_then(|r| match r.body {
        Body::Bytes(b) => Some(b.len()),
        _ => None,
    }) {
        Some(len) => assert_eq!(len, cap, "stored response copy must be capped"),
        None => panic!("expected a buffered (truncated) response body"),
    }
}
