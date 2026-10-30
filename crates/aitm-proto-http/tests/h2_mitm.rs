//! Task 2 — ALPN mirror negotiation + the `serve_h2` driver, end to end.
//!
//! Each test stands up an in-process origin (the `h2` crate's server, or a tiny
//! HTTP/1.1 writer) behind a forged-leaf TLS listener the test owns, runs a real
//! `Proxy` with the HTTP module, and drives a client through the proxy via
//! CONNECT. These bind loopback ports, so they run under the Terminal panel, not
//! the sandbox (CLAUDE.md).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{
    Body, CommandHost, Config, Event, Flow, FlowCtx, FlowId, FlowStore, Frontend, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    Proxy, ProxyClient, Registry, ScopeConfig, ScopeEntry, ScopeRateGuard, StdGuard, Value,
    Verdict,
};
use aitm_plugin_maprules::MapRulesPlugin;
use aitm_plugin_sessionio::SessionIoPlugin;
use aitm_plugins::{InterceptPlugin, MutatePlugin};
use aitm_proto_http::{CertAuthority, HttpModule};
use bytes::Bytes;
use futures::future::BoxFuture;
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

/// A forged-leaf TLS acceptor for a self-signed `127.0.0.1` origin offering `alpn`.
fn origin_tls(alpn: Vec<Vec<u8>>) -> TlsAcceptor {
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
    TlsAcceptor::from(Arc::new(cfg))
}

/// A TLS origin on `127.0.0.1` offering `alpn`, answering every request with 200
/// and `body`, and recording every request it received into `log`. Serves HTTP/2
/// when `h2` is negotiated, HTTP/1.1 otherwise.
async fn spawn_origin(alpn: Vec<Vec<u8>>, log: Arc<Mutex<OriginLog>>, body: Vec<u8>) -> SocketAddr {
    let acceptor = origin_tls(alpn);
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

/// A TLS h2 origin that accepts one stream, reads its request, then drops the
/// connection **without responding** — the proxy's upstream response future (or a
/// later body read) then fails, which must surface as `Event::Error`.
async fn spawn_closing_origin(alpn: Vec<Vec<u8>>) -> SocketAddr {
    let acceptor = origin_tls(alpn);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                if let Some(Ok((req, _respond))) = conn.accept().await {
                    let (_parts, mut rbody) = req.into_parts();
                    while let Some(Ok(chunk)) = rbody.data().await {
                        let _ = rbody.flow_control().release_capacity(chunk.len());
                    }
                }
                // Drop `conn` (and the unused `SendResponse`) here: the connection
                // closes with no response, so the proxy sees the upstream vanish.
            });
        }
    });
    addr
}

/// A plugin that records the flow id of every `Event::Error` the chain dispatches,
/// so a test can assert a failed stream reached the typed error bus.
struct ErrorRecorder {
    errors: Arc<Mutex<Vec<FlowId>>>,
}

impl Plugin for ErrorRecorder {
    fn name(&self) -> &str {
        "error-recorder"
    }
    fn on_event(&mut self, ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        if let Event::Error { flow, .. } = ev {
            if let Ok(mut errs) = self.errors.lock() {
                errs.push(*flow);
            }
        }
        Verdict::Continue
    }
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

// --- Task 3: interception semantics on h2 ------------------------------------
//
// Park / mutate / kill are exercised end to end through the real `InterceptPlugin`
// and its `flow.intercept`/`flow.mutate`/`flow.resume`/`flow.kill` commands,
// invoked through the shared registry — the same plugin set the chain dispatches
// through. Each test stands up an h2 origin behind the forged-leaf TLS listener
// and drives real h2 streams through the proxy.

/// A proxy client the command host never actually sends through; present to
/// satisfy `CommandHost` (the `flow.*` commands here touch only the store).
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Like [`run_proxy`], but also hands back the shared registry and guard so a test
/// can invoke `flow.*` commands against the same plugin set the chain dispatches
/// through. `plugins` should include the real [`InterceptPlugin`].
async fn run_proxy_intercept(
    ca: Arc<CertAuthority>,
    plugins: Vec<Box<dyn Plugin>>,
) -> (
    SocketAddr,
    Arc<Registry>,
    Arc<dyn FlowStore>,
    Arc<dyn ScopeRateGuard>,
) {
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
        .register_module(Arc::new(HttpModule::with_ca(ca).with_insecure(true)));
    for plugin in plugins {
        builder = builder.register_plugin(plugin);
    }
    let proxy = builder.build().expect("build proxy");
    let registry = proxy.registry_arc();
    let store = proxy.store();
    let guard = proxy.guard();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, registry, store, guard)
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Invoke a `flow.*` command through the registry, failing the test on any error.
fn invoke(
    registry: &Registry,
    store: &dyn FlowStore,
    guard: &dyn ScopeRateGuard,
    command: &str,
    args: Params,
) {
    let client = StubClient;
    let host = CommandHost::new(store, &client, guard, None);
    registry
        .command(command)
        .unwrap_or_else(|| panic!("{command} registered"))
        .invoke(args, &host)
        .unwrap_or_else(|e| panic!("{command} failed: {e}"));
}

/// Wait until the flow for `path` is parked (`Intercepted`); return its id.
async fn wait_for_parked_path(store: &dyn FlowStore, path: &str) -> FlowId {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for id in store.list() {
            if let Some(Flow::Http(f)) = store.get(id) {
                if f.request.path == path
                    && matches!(f.intercept, InterceptState::Intercepted { .. })
                {
                    return id;
                }
            }
        }
        assert!(Instant::now() < deadline, "no flow parked for {path}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One `GET path` over an existing h2 connection, surfacing a stream reset (or any
/// h2 error) as `Err` rather than panicking — so a killed stream can be observed.
async fn h2_try_get(
    send_req: &h2::client::SendRequest<Bytes>,
    upstream: SocketAddr,
    path: &str,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut sr = send_req.clone().ready().await?;
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{upstream}{path}"))
        .body(())?;
    let (resp_fut, _send_body) = sr.send_request(req, true)?;
    let resp = resp_fut.await?;
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok((status, buf))
}

/// One request-phase rule object matching `url` (a glob), as it crosses the bus.
fn request_rule(url: &str) -> Value {
    obj(&[
        ("url", Value::Str(url.into())),
        ("phase", Value::Str("request".into())),
    ])
}

// --- AC-H2.4 (per-stream park does not stall siblings) -----------------------

/// Parking one stream at a request breakpoint must not block the connection or
/// its sibling streams: `/admin` parks while `/a` and `/b` complete on the same
/// h2 connection, and `/admin` completes only after `flow.resume`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_one_stream_others_complete() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(
        vec![ALPN_H2.to_vec()],
        log.clone(),
        b"sibling-body".to_vec(),
    )
    .await;
    let (proxy, registry, store, guard) =
        run_proxy_intercept(ca, vec![Box::new(InterceptPlugin::new())]).await;

    // Arm a request-phase breakpoint that matches only `/admin`.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[
            ("enabled", Value::Bool(true)),
            ("rules", Value::Array(vec![request_rule("*/admin")])),
        ]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;

    // `/admin` parks; drive it on its own task so the test can proceed meanwhile.
    let admin = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/admin").await })
    };
    let admin_id = wait_for_parked_path(store.as_ref(), "/admin").await;

    // While `/admin` is parked, two sibling streams complete on the same connection.
    let (sa, ba) = h2_try_get(&send_req, origin, "/a")
        .await
        .expect("/a completes");
    let (sb, bb) = h2_try_get(&send_req, origin, "/b")
        .await
        .expect("/b completes");
    assert_eq!(sa, 200);
    assert_eq!(sb, 200);
    assert_eq!(ba, b"sibling-body");
    assert_eq!(bb, b"sibling-body");

    // `/admin` is still parked (its task has not finished).
    assert!(
        !admin.is_finished(),
        "/admin must stay parked while siblings complete"
    );
    assert!(
        matches!(store.get(admin_id), Some(Flow::Http(f)) if matches!(f.intercept, InterceptState::Intercepted { .. })),
        "/admin must still be Intercepted"
    );

    // Resume `/admin`; it now completes too.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.resume",
        params(&[("id", Value::Str(admin_id.to_string()))]),
    );
    let (sadmin, _) = admin.await.unwrap().expect("/admin completes after resume");
    assert_eq!(sadmin, 200);
}

// --- AC-H2.5 (request-phase edit reaches the origin) -------------------------

/// A request parked at the request phase, mutated with an added header, then
/// resumed, reaches the origin with the injected header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_request_mutate_reaches_origin() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"ok".to_vec()).await;
    let (proxy, registry, store, guard) = run_proxy_intercept(
        ca,
        vec![
            Box::new(InterceptPlugin::new()),
            Box::new(MutatePlugin::new()),
        ],
    )
    .await;

    // Global request-phase arm: every request parks at the request phase.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[("enabled", Value::Bool(true))]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let get = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/edit").await })
    };
    let id = wait_for_parked_path(store.as_ref(), "/edit").await;

    // Add a header to the parked request, then resume it.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.mutate",
        params(&[
            ("id", Value::Str(id.to_string())),
            (
                "edits",
                obj(&[("headers", obj(&[("X-Edit", Value::Str("1".into()))]))]),
            ),
        ]),
    );
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.resume",
        params(&[("id", Value::Str(id.to_string()))]),
    );

    let (status, _) = get.await.unwrap().expect("/edit completes after resume");
    assert_eq!(status, 200);

    let l = log.lock().unwrap();
    assert_eq!(l.count(), 1, "the mutated request must reach the origin");
    assert_eq!(
        l.header(0, "x-edit").as_deref(),
        Some("1"),
        "the injected header must reach the origin"
    );
}

// --- AC-H2.5 (response-phase edit reaches the client) ------------------------

/// A response parked at the response phase (before any client byte), its status
/// edited to 418 and resumed, is delivered to the client as h2 `:status 418` with
/// the origin's body still forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_response_status_418() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"teapot-body".to_vec()).await;
    let (proxy, registry, store, guard) = run_proxy_intercept(
        ca,
        vec![
            Box::new(InterceptPlugin::new()),
            Box::new(MutatePlugin::new()),
        ],
    )
    .await;

    // Response-phase rule: every flow parks at the response phase (none at request).
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[(
            "rules",
            Value::Array(vec![obj(&[("phase", Value::Str("response".into()))])]),
        )]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let get = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/page").await })
    };
    let id = wait_for_parked_path(store.as_ref(), "/page").await;

    // Edit the parked response's status, then resume it.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.mutate",
        params(&[
            ("id", Value::Str(id.to_string())),
            ("edits", obj(&[("status", Value::Int(418))])),
        ]),
    );
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.resume",
        params(&[("id", Value::Str(id.to_string()))]),
    );

    let (status, body) = get.await.unwrap().expect("/page completes after resume");
    assert_eq!(status, 418, "client must receive the edited status");
    assert_eq!(body, b"teapot-body", "the origin body is still forwarded");
}

// --- AC-H2.6 (kill → RST_STREAM) ---------------------------------------------

/// `flow.kill {mode:"reset"}` resets the killed stream with RST_STREAM(CANCEL)
/// while a second stream on the same connection still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_kill_reset_is_rst_stream() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"live-body".to_vec()).await;
    let (proxy, registry, store, guard) =
        run_proxy_intercept(ca, vec![Box::new(InterceptPlugin::new())]).await;

    // Request-phase rule matching only `/kill`, so `/live` sails through.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[
            ("enabled", Value::Bool(true)),
            ("rules", Value::Array(vec![request_rule("*/kill")])),
        ]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let killed = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/kill").await })
    };
    let kill_id = wait_for_parked_path(store.as_ref(), "/kill").await;

    // A sibling stream completes normally while `/kill` is parked.
    let (slive, blive) = h2_try_get(&send_req, origin, "/live")
        .await
        .expect("/live completes");
    assert_eq!(slive, 200);
    assert_eq!(blive, b"live-body");

    // Kill `/kill` with a reset: the client observes RST_STREAM(CANCEL).
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.kill",
        params(&[
            ("id", Value::Str(kill_id.to_string())),
            ("mode", Value::Str("reset".into())),
        ]),
    );

    let err = killed
        .await
        .unwrap()
        .expect_err("a reset kill must surface as an h2 stream error");
    let h2_err = err
        .downcast_ref::<h2::Error>()
        .unwrap_or_else(|| panic!("the error must be an h2 stream error, got {err:?}"));
    assert_eq!(
        h2_err.reason(),
        Some(h2::Reason::CANCEL),
        "the killed stream must be reset with CANCEL (RST_STREAM)"
    );
}

// --- AC-H2.6 (kill 429 opens no upstream) ------------------------------------

/// `flow.kill {mode:"429"}` answers the client with a synthesized `:status 429`
/// and opens no upstream stream (the origin records zero requests).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_kill_429_no_upstream() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"origin".to_vec()).await;
    let (proxy, registry, store, guard) =
        run_proxy_intercept(ca, vec![Box::new(InterceptPlugin::new())]).await;

    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[("enabled", Value::Bool(true))]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let get = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/gone").await })
    };
    let id = wait_for_parked_path(store.as_ref(), "/gone").await;

    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.kill",
        params(&[
            ("id", Value::Str(id.to_string())),
            ("mode", Value::Str("429".into())),
        ]),
    );

    let (status, _) = get.await.unwrap().expect("/gone gets a synthesized 429");
    assert_eq!(status, 429, "client must receive a synthesized 429");

    // Give any (erroneous) upstream stream a moment to land before asserting zero.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        log.lock().unwrap().count(),
        0,
        "a synthesized 429 must open no upstream stream"
    );
}

// --- M7 Task 2 fix: oversized request body → 413, terminal, no upstream --------

/// A request body larger than `max_body` is refused with `:status 413`; the flow
/// is terminal and marked `truncated`, and the origin records zero requests (the
/// refusal happens before any upstream stream is opened).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_over_cap_is_refused_413() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let cap = 64usize;
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"ok".to_vec()).await;
    let (proxy, store) = run_proxy(ca, Vec::new(), Some(cap)).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let mut sr = send_req.clone().ready().await.expect("h2 ready");
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("https://{origin}/upload"))
        .body(())
        .unwrap();
    // Open the stream with a body still to come, then stream well over the cap.
    let (resp_fut, mut body) = sr.send_request(req, false).expect("send h2 request");
    let _ = body.send_data(Bytes::from(vec![b'A'; cap * 8]), true);

    let resp = resp_fut.await.expect("h2 response");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "an over-cap request body must be refused with 413"
    );

    let flow = wait_for_flow(store.as_ref()).await;
    assert!(
        flow.metadata.truncated,
        "the refused flow must be marked truncated"
    );
    assert_eq!(
        flow.response.map(|r| r.status),
        Some(413),
        "the 413 must be recorded as the flow's terminal response"
    );

    // Give any (erroneous) upstream stream a moment to land before asserting zero.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        log.lock().unwrap().count(),
        0,
        "a 413-refused request must open no upstream stream"
    );
}

// --- M7 Task 2 fix: upstream failure → Event::Error ---------------------------

/// An upstream that accepts the request then closes without responding fails the
/// stream, and that failure reaches the typed error bus as `Event::Error` rather
/// than only a `tracing` line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_closing_early_emits_flow_error() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let errors = Arc::new(Mutex::new(Vec::new()));
    let origin = spawn_closing_origin(vec![ALPN_H2.to_vec()]).await;
    let (proxy, _store) = run_proxy(
        ca,
        vec![Box::new(ErrorRecorder {
            errors: errors.clone(),
        })],
        None,
    )
    .await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let result = h2_try_get(&send_req, origin, "/dropme").await;
    assert!(
        result.is_err(),
        "a stream whose upstream vanished must not return a 200"
    );

    // The failure was emitted on the error bus for the flow.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !errors.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no Event::Error was emitted for the failed flow"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// --- Task 4: Map Remote cross-origin over h2 (AC-H2.8) ------------------------
//
// A Map Remote rule rewrites a matching request's authority to a *different* host.
// Because an h2 connection is pinned to one `:authority`, a cross-origin rewrite
// needs a SECOND upstream (spec §6). The real `MapRulesPlugin` is driven through
// the registry (its `map.add` command and its `on_event` rewrite), carrying its own
// scope guard — the deny-by-default point for Map Remote on the MITM listener.

/// A deny-by-default guard with `in_scope` hosts pre-added, as the maprules plugin
/// consults before a rewrite (mirrors the binary's `LateGuard`-bound proxy guard).
fn map_guard(in_scope: &[&str]) -> Arc<dyn ScopeRateGuard> {
    let guard = Arc::new(StdGuard::default());
    for host in in_scope {
        guard.add_scope(ScopeEntry {
            host: (*host).to_string(),
        });
    }
    guard
}

/// Add a Map Remote rule `url glob` → `authority` through the registry.
fn add_map_remote(
    registry: &Registry,
    store: &dyn FlowStore,
    guard: &dyn ScopeRateGuard,
    url_glob: &str,
    to_authority: &str,
) {
    invoke(
        registry,
        store,
        guard,
        "map.add",
        params(&[
            ("kind", Value::Str("remote".into())),
            (
                "condition",
                obj(&[("url", obj(&[("wildcard", Value::Str(url_glob.into()))]))]),
            ),
            (
                "action",
                obj(&[("to", obj(&[("authority", Value::Str(to_authority.into()))]))]),
            ),
        ]),
    );
}

/// An in-scope Map Remote rewrite over h2 opens a second upstream to the rewritten
/// host: the request reaches `new`, not the pinned origin `old`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn map_remote_h2_to_in_scope_host() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    // Two recording h2 origins: `old` is the pinned CONNECT target, `new` is the
    // cross-origin rewrite target (a different port ⇒ a different authority).
    let old_log = Arc::new(Mutex::new(OriginLog::default()));
    let new_log = Arc::new(Mutex::new(OriginLog::default()));
    let old = spawn_origin(
        vec![ALPN_H2.to_vec()],
        old_log.clone(),
        b"old-origin".to_vec(),
    )
    .await;
    let new = spawn_origin(
        vec![ALPN_H2.to_vec()],
        new_log.clone(),
        b"reached-new-origin".to_vec(),
    )
    .await;

    // The maprules plugin's guard has `127.0.0.1` in scope, so the redirect to the
    // `new` origin (also 127.0.0.1) is allowed.
    let maprules = MapRulesPlugin::new(temp_dir(), true, map_guard(&["127.0.0.1"]));
    let (proxy, registry, store, guard) = run_proxy_intercept(ca, vec![Box::new(maprules)]).await;
    add_map_remote(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "*/cross",
        &new.to_string(),
    );

    let send_req = connect_h2(proxy, old, &root_pem).await;
    let (status, body) = h2_get(&send_req, old, "/cross").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, b"reached-new-origin",
        "an in-scope rewrite must reach the new origin, not the pinned one"
    );

    // Give any stray upstream stream a moment to land before counting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let new_l = new_log.lock().unwrap();
    assert_eq!(new_l.count(), 1, "the new origin must receive the request");
    assert_eq!(new_l.requests[0].path, "/cross");
    assert_eq!(
        old_log.lock().unwrap().count(),
        0,
        "the pinned origin must not receive a rewritten request"
    );
}

/// An out-of-scope Map Remote rewrite over h2 is refused by the scope guard: the
/// stream gets an error response and NEITHER origin receives the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn map_remote_h2_out_of_scope_refused() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let old_log = Arc::new(Mutex::new(OriginLog::default()));
    let new_log = Arc::new(Mutex::new(OriginLog::default()));
    let old = spawn_origin(
        vec![ALPN_H2.to_vec()],
        old_log.clone(),
        b"old-origin".to_vec(),
    )
    .await;
    let new = spawn_origin(
        vec![ALPN_H2.to_vec()],
        new_log.clone(),
        b"reached-new-origin".to_vec(),
    )
    .await;

    // The maprules guard scopes `example.com` only, so the redirect to the `new`
    // origin (127.0.0.1) is out of scope and must be refused.
    let maprules = MapRulesPlugin::new(temp_dir(), true, map_guard(&["example.com"]));
    let (proxy, registry, store, guard) = run_proxy_intercept(ca, vec![Box::new(maprules)]).await;
    add_map_remote(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "*/cross",
        &new.to_string(),
    );

    let send_req = connect_h2(proxy, old, &root_pem).await;
    let (status, body) = h2_get(&send_req, old, "/cross").await;
    assert_eq!(
        status, 502,
        "an out-of-scope redirect must be refused with an error status"
    );
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains(&new.to_string()),
        "the refusal must name the refused host: {body:?}"
    );

    // Neither the pinned origin nor the out-of-scope target may receive the request.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        old_log.lock().unwrap().count(),
        0,
        "the pinned origin must not receive a refused request"
    );
    assert_eq!(
        new_log.lock().unwrap().count(),
        0,
        "the out-of-scope target must never be contacted"
    );
}

// --- M7 panel fix: a normal h2 request reuses the single pinned upstream --------
//
// A browser omits the default port from `:authority` (`example.com`, not
// `example.com:443`), while the connection is pinned to the CONNECT authority
// (`host:port`). A raw string compare in `Upstreams::for_authority` made EVERY such
// request look cross-origin — opening a second upstream, bypassing the vetted
// pinned connection, and (on the passive listener) letting unique authorities fan
// out unbounded upstreams (spec §6 / Anti-goals: an h2 flow is not a scope
// loophole). A normal (un-rewritten) request must ride the shared pinned upstream.

/// An h2 TLS origin that counts how many upstream *connections* it accepts (one per
/// TCP+TLS handshake), answering every request 200 + `body`. A single pinned
/// upstream multiplexes all streams, so a correct proxy opens exactly one.
async fn spawn_counting_origin(connections: Arc<AtomicUsize>, body: Vec<u8>) -> SocketAddr {
    let acceptor = origin_tls(vec![ALPN_H2.to_vec()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let connections = connections.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                // Count the upstream connection only once its h2 handshake succeeds,
                // so a bare TCP probe does not inflate the count.
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                while let Some(accepted) = conn.accept().await {
                    let Ok((req, mut respond)) = accepted else {
                        break;
                    };
                    let (_parts, mut rbody) = req.into_parts();
                    while let Some(Ok(chunk)) = rbody.data().await {
                        let _ = rbody.flow_control().release_capacity(chunk.len());
                    }
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    if let Ok(mut send) = respond.send_response(resp, false) {
                        let _ = send.send_data(Bytes::from(body.clone()), true);
                    }
                }
            });
        }
    });
    addr
}

/// One `GET path` over an existing h2 connection whose request `:authority` is set
/// explicitly (e.g. the host with no port), returning (status, body).
async fn h2_get_with_authority(
    send_req: &h2::client::SendRequest<Bytes>,
    authority: &str,
    path: &str,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut sr = send_req.clone().ready().await?;
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{authority}{path}"))
        .body(())?;
    let (resp_fut, _send_body) = sr.send_request(req, true)?;
    let resp = resp_fut.await?;
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok((status, buf))
}

/// A normal h2 request whose `:authority` is the host WITHOUT the default port
/// (`127.0.0.1`), while the connection is pinned to the CONNECT authority
/// (`127.0.0.1:port`), must be served over the SHARED pinned upstream — the origin
/// accepts exactly one upstream connection, and no second upstream is opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_h2_request_reuses_pinned_upstream() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let origin = spawn_counting_origin(connections.clone(), b"pinned-body".to_vec()).await;
    let (proxy, _store) = run_proxy(ca, Vec::new(), None).await;

    // Pin the connection to `127.0.0.1:<port>` via CONNECT.
    let send_req = connect_h2(proxy, origin, &root_pem).await;
    // Send a browser-style request: `:authority` is the bare host, no port.
    let host_only = origin.ip().to_string();
    let (status, body) = h2_get_with_authority(&send_req, &host_only, "/normal")
        .await
        .expect("a normal h2 request must complete over the pinned upstream");
    assert_eq!(status, 200);
    assert_eq!(
        body, b"pinned-body",
        "the request must reach the pinned origin, not a second upstream"
    );

    // Give any (erroneous) second upstream a moment to land before asserting one.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "a normal h2 request must reuse the single pinned upstream, not open a second"
    );
}

// --- Task 6: whole-branch integration sweep + session/HAR version tag ----------
//
// AC-H2.11 asks that an h2 flow captured through the proxy round-trips its version
// through the native session format and tags HAR `httpVersion` as `"HTTP/2"`. These
// tests capture a REAL h2 flow (the Task 2–5 engine) and then drive the actual
// `aitm-plugin-sessionio` serialization surface over it via a standalone registry,
// so the version tag is proven end to end rather than from a hand-built fixture.
// `full_h2_acceptance_sweep` is a smoke guard over Tasks 2–3 (capture → intercept →
// mutate → resume → response) in one test.

/// A standalone registry carrying only the session/flow-export commands, so a test
/// can serialize a captured store the way a frontend does.
fn sessionio_registry() -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(SessionIoPlugin::new(false)));
    reg
}

/// Invoke a `session.*`/`flow.*` command through `reg` against `store` as the human
/// CLI (so host-path reads/writes pass the agent file-I/O gate), returning its
/// result value. The guard/client are passive stubs — these commands never egress.
fn sessionio_invoke(reg: &Registry, store: &dyn FlowStore, command: &str, args: Params) -> Value {
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(store, &client, &guard, None).with_frontend(Frontend::Cli);
    reg.command(command)
        .unwrap_or_else(|| panic!("{command} registered"))
        .invoke(args, &host)
        .unwrap_or_else(|e| panic!("{command} failed: {e}"))
}

/// The single captured HTTP flow in `store` (panics if there is not exactly one).
fn only_http_flow(store: &dyn FlowStore) -> HttpFlow {
    let flows: Vec<HttpFlow> = store
        .list()
        .into_iter()
        .filter_map(|id| match store.get(id) {
            Some(Flow::Http(f)) => Some(f),
            _ => None,
        })
        .collect();
    assert_eq!(flows.len(), 1, "expected exactly one captured http flow");
    flows.into_iter().next().unwrap()
}

/// AC-H2.11 (native session) — an h2 flow captured through the proxy, saved with
/// `session.save` and loaded with `session.load` into a fresh store, keeps
/// `version == HttpVersion::H2` on both its request and response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_flow_session_round_trips() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(
        vec![ALPN_H2.to_vec()],
        log.clone(),
        b"session-body".to_vec(),
    )
    .await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, _) = h2_get(&send_req, origin, "/captured").await;
    assert_eq!(status, 200);

    let captured = wait_for_flow(store.as_ref()).await;
    assert_eq!(
        captured.request.version,
        HttpVersion::H2,
        "precondition: the captured flow is h2"
    );

    // Save the whole store, then load it into a brand-new, empty store.
    let reg = sessionio_registry();
    let path = temp_dir().join("h2-session.json");
    let path_str = path.to_string_lossy().to_string();
    sessionio_invoke(
        &reg,
        store.as_ref(),
        "session.save",
        params(&[("path", Value::Str(path_str.clone()))]),
    );

    let fresh = MemFlowStore::new();
    sessionio_invoke(
        &reg,
        &fresh,
        "session.load",
        params(&[("path", Value::Str(path_str.clone()))]),
    );

    let reloaded = only_http_flow(&fresh);
    assert_eq!(
        reloaded.request.version,
        HttpVersion::H2,
        "session.load must restore the request as HTTP/2"
    );
    assert_eq!(
        reloaded.response.as_ref().map(|r| r.version),
        Some(HttpVersion::H2),
        "session.load must restore the response as HTTP/2"
    );
    assert_eq!(
        reloaded.client_conn.alpn.as_deref(),
        Some("h2"),
        "the reloaded flow keeps its negotiated h2 ALPN"
    );
}

/// AC-H2.11 (HAR) — `flow.export {format:"har"}` of an h2 flow tags both the
/// request and the response `httpVersion` as `"HTTP/2"`, and `flow.import` of those
/// same HAR bytes round-trips the flow back as `HttpVersion::H2`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_flow_har_version_tag() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"har-body".to_vec()).await;
    let (proxy, store) = run_proxy(ca, Vec::new(), None).await;

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let (status, _) = h2_get(&send_req, origin, "/har").await;
    assert_eq!(status, 200);
    let captured = wait_for_flow(store.as_ref()).await;
    assert_eq!(
        captured.request.version,
        HttpVersion::H2,
        "precondition: h2"
    );

    // Export the store as HAR and read the version tag out of the document bytes.
    let reg = sessionio_registry();
    let result = sessionio_invoke(
        &reg,
        store.as_ref(),
        "flow.export",
        params(&[("format", Value::Str("har".into()))]),
    );
    let bytes = match result {
        Value::Object(fields) => match fields.get("bytes") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("flow.export must return `bytes`, got {other:?}"),
        },
        other => panic!("flow.export must return an object, got {other:?}"),
    };
    let doc = String::from_utf8(bytes.clone()).expect("HAR document is UTF-8 JSON");
    // The one entry carries httpVersion on BOTH its request and response, so the
    // exact pretty-printed tag must appear twice and the h1 tag never.
    assert_eq!(
        doc.matches("\"httpVersion\": \"HTTP/2\"").count(),
        2,
        "HAR must tag the h2 request and response as HTTP/2: {doc}"
    );
    assert!(
        !doc.contains("\"httpVersion\": \"HTTP/1.1\""),
        "no part of an h2 flow may be tagged HTTP/1.1: {doc}"
    );

    // The same HAR bytes import back into a fresh store as an h2 flow.
    let fresh = MemFlowStore::new();
    sessionio_invoke(
        &reg,
        &fresh,
        "flow.import",
        params(&[
            ("bytes", Value::Bytes(bytes)),
            ("format", Value::Str("har".into())),
        ]),
    );
    let imported = only_http_flow(&fresh);
    assert_eq!(
        imported.request.version,
        HttpVersion::H2,
        "flow.import of the HAR must round-trip the request as HTTP/2"
    );
    assert_eq!(
        imported.response.as_ref().map(|r| r.version),
        Some(HttpVersion::H2),
        "flow.import of the HAR must round-trip the response as HTTP/2"
    );
}

/// Smoke / regression guard (Tasks 2–3): one h2 stream driven the whole way —
/// captured, parked by an armed request-phase breakpoint, mutated with an injected
/// header, resumed, forwarded to the origin, and answered — all over HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_h2_acceptance_sweep() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let log = Arc::new(Mutex::new(OriginLog::default()));
    let origin = spawn_origin(vec![ALPN_H2.to_vec()], log.clone(), b"swept".to_vec()).await;
    let (proxy, registry, store, guard) = run_proxy_intercept(
        ca,
        vec![
            Box::new(InterceptPlugin::new()),
            Box::new(MutatePlugin::new()),
        ],
    )
    .await;

    // Arm a request-phase breakpoint matching the swept path only.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.intercept",
        params(&[
            ("enabled", Value::Bool(true)),
            ("rules", Value::Array(vec![request_rule("*/sweep")])),
        ]),
    );

    let send_req = connect_h2(proxy, origin, &root_pem).await;
    let swept = {
        let sr = send_req.clone();
        tokio::spawn(async move { h2_try_get(&sr, origin, "/sweep").await })
    };
    let id = wait_for_parked_path(store.as_ref(), "/sweep").await;

    // Mutate the parked request (inject a header), then resume it.
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.mutate",
        params(&[
            ("id", Value::Str(id.to_string())),
            (
                "edits",
                obj(&[("headers", obj(&[("X-Sweep", Value::Str("1".into()))]))]),
            ),
        ]),
    );
    invoke(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        "flow.resume",
        params(&[("id", Value::Str(id.to_string()))]),
    );

    // The client gets the origin's answer end to end over h2.
    let (status, body) = swept.await.unwrap().expect("/sweep completes after resume");
    assert_eq!(status, 200);
    assert_eq!(body, b"swept");

    // The mutation reached the origin, and the captured flow is HTTP/2.
    let l = log.lock().unwrap();
    assert_eq!(l.count(), 1, "the resumed request must reach the origin");
    assert_eq!(l.requests[0].path, "/sweep");
    assert_eq!(
        l.header(0, "x-sweep").as_deref(),
        Some("1"),
        "the injected header must reach the origin"
    );
    drop(l);
    let captured = only_http_flow(store.as_ref());
    assert_eq!(
        captured.request.version,
        HttpVersion::H2,
        "the swept flow is captured as HTTP/2"
    );
}
