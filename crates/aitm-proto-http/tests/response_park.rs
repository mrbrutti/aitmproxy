//! Task 2 — characterization of the response-phase park/suspend point in the
//! HTTP/1.1 module, de-risking M6 Task 4 (response-phase edit).
//!
//! # Finding (for Task 4)
//!
//! **`Event::ResponseHeaders` is the authoritative response-park suspension
//! point.** A plugin that calls [`FlowCtx::intercept()`] while handling
//! `Event::ResponseHeaders` suspends the client *before any response byte is
//! written to it*, and the stored response still carries a streamed (not yet
//! captured) body at that instant — so an edit made while parked there is what
//! the client receives.
//!
//! Why, in `module.rs`'s `serve` loop: on the upstream `ResponseHeaders` event
//! the module stages the response head into the store with a `Body::Streamed`
//! placeholder, then **awaits** `ctx.emit(Event::ResponseHeaders(id))`
//! (module.rs) *before* it calls `machine.enqueue_response(..)` / `flush(..)` to
//! the client. The body is streamed chunk-by-chunk only *after* that emit
//! returns, between the `ResponseHeaders` and `Response` emits. A park on
//! `Event::Response` would therefore be too late (the client already has the
//! head and body); a park on `Event::ResponseHeaders` is exactly early enough.
//! Spec §1 (amended 2026-10-28) and Plan-level call 1 both pin this point.
//!
//! These tests pass **as written** against the current `aitm-proto-http`; no fix
//! to `module.rs` was required — the suspension already holds. They bind a
//! loopback TLS origin, so they run under the Terminal panel, not the sandbox.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm_core::{
    Body, Config, Event, Flow, FlowCtx, FlowId, FlowStore, InterceptState, Plugin, Proxy,
    ResumeHandle, ScopeConfig, ScopeEntry, Verdict,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const UPSTREAM_BODY: &str = "upstream-response-body";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-respark-{}", uuid::Uuid::new_v4()));
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

/// A TLS origin on `127.0.0.1` that answers every request with 200 and a fixed
/// body, so the test can recognise the response the client finally receives.
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
                let _ = read_head(&mut tls).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{UPSTREAM_BODY}",
                    UPSTREAM_BODY.len()
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, store)
}

/// CONNECT to `upstream` through `proxy`, finish TLS trusting only the proxy CA,
/// send one `GET path`, and return the live decrypted stream so the caller
/// controls exactly when it reads the response.
async fn connect_and_send(
    proxy: SocketAddr,
    upstream: SocketAddr,
    path: &str,
    root_pem: &str,
) -> TlsStream<TcpStream> {
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
    tls
}

/// Wait until some flow in the store is parked (`Intercepted`); return its id
/// and a clone of the resume handle its state carries (the same handle
/// `flow.resume` fires in production).
async fn wait_for_parked(store: &dyn FlowStore) -> (FlowId, ResumeHandle) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for id in store.list() {
            if let Some(Flow::Http(f)) = store.get(id) {
                if let InterceptState::Intercepted { resume, .. } = &f.intercept {
                    return (id, resume.clone());
                }
            }
        }
        assert!(Instant::now() < deadline, "no flow was parked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Parse (status, body) from a raw HTTP/1.1 response.
fn parse_response(raw: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(raw);
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

/// What the plugin observed, shared out so the test can inspect it.
#[derive(Default)]
struct ParkRecord {
    /// Every event label the plugin saw, in dispatch order.
    events: Vec<&'static str>,
    /// The kind of the stored response body at the instant the plugin parked on
    /// `ResponseHeaders` (proves whether the body had already been captured).
    park_body_kind: Option<&'static str>,
}

fn event_label(ev: &Event) -> &'static str {
    match ev {
        Event::RequestHeaders(_) => "RequestHeaders",
        Event::Request(_) => "Request",
        Event::ResponseHeaders(_) => "ResponseHeaders",
        Event::Response(_) => "Response",
        Event::WsStart(_) => "WsStart",
        Event::WsEnd(_) => "WsEnd",
        Event::WsMessage { .. } => "WsMessage",
        Event::Error { .. } => "Error",
        _ => "other",
    }
}

fn body_kind(body: &Body) -> &'static str {
    match body {
        Body::Empty => "empty",
        Body::Bytes(_) => "bytes",
        Body::Streamed(_) => "streamed",
    }
}

/// Records event order and parks the response at `Event::ResponseHeaders`,
/// exactly as Task 4's response-phase rule will. The resume handle lives in the
/// flow's stored `Intercepted` state; the test fires it from there.
struct ParkOnResponseHeaders {
    record: Arc<Mutex<ParkRecord>>,
}

impl Plugin for ParkOnResponseHeaders {
    fn name(&self) -> &str {
        "park-on-response-headers"
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if let Ok(mut rec) = self.record.lock() {
            rec.events.push(event_label(ev));
        }
        if matches!(ev, Event::ResponseHeaders(_)) {
            if let (Ok(mut rec), Flow::Http(f)) = (self.record.lock(), ctx.flow()) {
                rec.park_body_kind =
                    Some(f.response.as_ref().map_or("none", |r| body_kind(&r.body)));
            }
            ctx.backup();
            // Parking arms a ResumeHandle; the chain persists it into the flow's
            // Intercepted state. We drop the returned clone — the store keeps one.
            let _ = ctx.intercept();
        }
        Verdict::Continue
    }
}

/// RF#1: a plugin that parks on `Event::ResponseHeaders` suspends the client —
/// it reads **zero** response bytes until the paired resume fires, then reads
/// the full response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_headers_park_suspends_client() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let upstream = spawn_fixture().await;
    let record = Arc::new(Mutex::new(ParkRecord::default()));
    let (proxy, store) = run_proxy(
        ca,
        vec![Box::new(ParkOnResponseHeaders {
            record: record.clone(),
        })],
    )
    .await;

    let mut client = connect_and_send(proxy, upstream, "/parked", &root_pem).await;

    // The flow parks at ResponseHeaders: upstream has answered, and the module
    // is suspended at the `ResponseHeaders` emit before writing to the client.
    let (_id, resume) = wait_for_parked(store.as_ref()).await;

    // While parked, the client has received no response bytes. A read must not
    // complete (it blocks); a short timeout proves nothing was written.
    let mut buf = [0u8; 64];
    let before = tokio::time::timeout(Duration::from_millis(400), client.read(&mut buf)).await;
    assert!(
        before.is_err(),
        "client received response bytes while the response was still parked: {before:?}"
    );

    // The park happened before the body was captured/streamed.
    assert_eq!(
        record.lock().unwrap().park_body_kind,
        Some("streamed"),
        "the stored response body must still be streamed (uncaptured) at the park point"
    );

    // Release the parked response; now the full response reaches the client.
    resume.fire();
    let mut raw = Vec::new();
    match client.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response after resume: {e}"),
    }
    let (status, body) = parse_response(&raw);
    assert_eq!(
        status, 200,
        "client must receive the real response after resume"
    );
    assert!(
        body.contains(UPSTREAM_BODY),
        "resumed response body was {body:?}, want it to contain {UPSTREAM_BODY:?}"
    );
}

/// `ResponseHeaders` is dispatched-and-awaited before the first client body
/// byte: the module streams the body only between the `ResponseHeaders` and
/// `Response` emits, so at the `ResponseHeaders` park point the stored response
/// body is still the uncaptured `Streamed` placeholder, and `Response` has not
/// yet fired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_phase_emit_is_awaited() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let upstream = spawn_fixture().await;
    let record = Arc::new(Mutex::new(ParkRecord::default()));
    let (proxy, store) = run_proxy(
        ca,
        vec![Box::new(ParkOnResponseHeaders {
            record: record.clone(),
        })],
    )
    .await;

    let mut client = connect_and_send(proxy, upstream, "/ordered", &root_pem).await;
    let (_id, resume) = wait_for_parked(store.as_ref()).await;

    // At the park point: RequestHeaders → Request → ResponseHeaders have fired
    // and been awaited in order, `Response` has not, and the response body is
    // still the streamed placeholder (no client body byte has been forwarded).
    {
        let rec = record.lock().unwrap();
        assert_eq!(
            rec.events,
            vec!["RequestHeaders", "Request", "ResponseHeaders"],
            "ResponseHeaders must be awaited before Response (and before any body byte)"
        );
        assert_eq!(
            rec.park_body_kind,
            Some("streamed"),
            "body must not be captured yet when ResponseHeaders is awaited"
        );
    }

    // Resume and drain so the exchange completes and `Response` fires last.
    resume.fire();
    let mut raw = Vec::new();
    match client.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response after resume: {e}"),
    }
    let (status, _) = parse_response(&raw);
    assert_eq!(status, 200);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if record.lock().unwrap().events.last() == Some(&"Response") {
            break;
        }
        assert!(Instant::now() < deadline, "Response was never emitted");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        record.lock().unwrap().events,
        vec!["RequestHeaders", "Request", "ResponseHeaders", "Response"],
        "the full dispatch order must end with Response, after the body streamed"
    );
}
