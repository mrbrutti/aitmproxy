//! Task 5 (F3): `flow.kill` abort modes — reset / 429 / 503.
//!
//! `flow.kill {mode:"429"|"503"}` short-circuits a parked request with a
//! synthesized status and an empty body, answering the client *without opening an
//! upstream connection*. `flow.kill` with no `mode` (or `mode:"reset"`) keeps the
//! historical behaviour: the flow is dropped and the client sees a closed/reset
//! connection, still with no upstream contact.
//!
//! Both tests are end-to-end through the real proxy, `HttpModule`, and
//! `InterceptPlugin`, driven via the command registry — the same path the chain
//! dispatches through. A loopback TLS origin counts the requests it actually
//! receives; the count proves no egress happened for a killed flow. They bind
//! loopback ports, so they run under the Terminal panel, not the sandbox.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    CommandHost, Config, Flow, FlowId, FlowStore, HttpFlow, HttpRequest, InterceptState, Params,
    Plugin, Proxy, ProxyClient, Registry, ScopeConfig, ScopeEntry, ScopeRateGuard, Value,
};
use aitm_plugins::InterceptPlugin;
use aitm_proto_http::{CertAuthority, HttpModule};
use futures::future::BoxFuture;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-killmodes-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

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

/// A TLS origin on `127.0.0.1` that counts every request it receives and answers
/// each with 200. A killed/synthesized flow must never reach it, so the counter
/// proves no egress.
async fn spawn_fixture() -> (SocketAddr, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
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
    let seen = counter.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = read_head(&mut tls).await;
                seen.fetch_add(1, Ordering::SeqCst);
                let body = "upstream";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, counter)
}

/// A proxy client the command host never actually sends through; present to
/// satisfy `CommandHost`.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Run a `Proxy` with the HTTP module and `plugins`; `127.0.0.1` is in scope.
async fn run_proxy(
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

/// CONNECT to `upstream` through `proxy`, finish TLS trusting only the proxy CA,
/// send one `GET path`, and return the live decrypted stream.
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

/// Wait until some flow in the store is parked (`Intercepted`); return its id.
async fn wait_for_parked(store: &dyn FlowStore) -> FlowId {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for id in store.list() {
            if let Some(Flow::Http(f)) = store.get(id) {
                if matches!(f.intercept, InterceptState::Intercepted { .. }) {
                    return id;
                }
            }
        }
        assert!(Instant::now() < deadline, "no flow was parked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Read everything the client receives, tolerating a reset/EOF close.
async fn read_all(wire: &mut TlsStream<TcpStream>) -> Vec<u8> {
    let mut raw = Vec::new();
    // A reset/dropped connection surfaces as EOF or a reset error; both mean the
    // client got no (further) response bytes, so either outcome is fine here.
    let _ = wire.read_to_end(&mut raw).await;
    raw
}

/// Status line code from a raw HTTP/1.1 response, or 0 if there is no response.
fn status_of(raw: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(raw);
    if !text.starts_with("HTTP/") {
        return 0;
    }
    text.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// Arm global request-phase interception, then CONNECT + GET through the proxy and
/// wait for the request to park. Returns the live client wire and the parked id.
async fn arm_and_park(
    registry: &Registry,
    store: &dyn FlowStore,
    guard: &dyn ScopeRateGuard,
    proxy: SocketAddr,
    upstream: SocketAddr,
    root_pem: &str,
) -> (TlsStream<TcpStream>, FlowId) {
    let client = StubClient;
    {
        let host = CommandHost::new(store, &client, guard, None);
        registry
            .command("flow.intercept")
            .expect("flow.intercept registered")
            .invoke(params(&[("enabled", Value::Bool(true))]), &host)
            .expect("arm interception");
    }
    let wire = connect_and_send(proxy, upstream, "/killed", root_pem).await;
    let id = wait_for_parked(store).await;
    (wire, id)
}

/// AC-F3.3: `flow.kill {mode:"429"}` answers the client with a synthesized HTTP
/// 429 and an empty body, and never contacts the upstream (counter stays 0).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_429_synthesizes_response() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let (upstream, counter) = spawn_fixture().await;
    let (proxy, registry, store, guard) =
        run_proxy(ca, vec![Box::new(InterceptPlugin::new())]).await;

    let (mut wire, id) = arm_and_park(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        proxy,
        upstream,
        &root_pem,
    )
    .await;

    {
        let client = StubClient;
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        registry
            .command("flow.kill")
            .expect("flow.kill registered")
            .invoke(
                params(&[
                    ("id", Value::Str(id.to_string())),
                    ("mode", Value::Str("429".into())),
                ]),
                &host,
            )
            .expect("kill the parked flow with a 429");
    }

    let raw = read_all(&mut wire).await;
    assert_eq!(
        status_of(&raw),
        429,
        "client must receive a synthesized 429, got {:?}",
        String::from_utf8_lossy(&raw)
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a synthesized 429 must not contact the upstream"
    );
}

/// AC-F3.3: `flow.kill` with no `mode` (and `mode:"reset"`) drops the flow — the
/// client sees a closed/reset connection (no HTTP response) and the upstream is
/// never contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_reset_closes_connection() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let (upstream, counter) = spawn_fixture().await;
    let (proxy, registry, store, guard) =
        run_proxy(ca, vec![Box::new(InterceptPlugin::new())]).await;

    // Default kill (no `mode`): the client sees the connection dropped.
    let (mut wire, id) = arm_and_park(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        proxy,
        upstream,
        &root_pem,
    )
    .await;
    {
        let client = StubClient;
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        registry
            .command("flow.kill")
            .expect("flow.kill registered")
            .invoke(params(&[("id", Value::Str(id.to_string()))]), &host)
            .expect("kill the parked flow with no mode");
    }
    let raw = read_all(&mut wire).await;
    assert_eq!(
        status_of(&raw),
        0,
        "a reset kill must deliver no HTTP response, got {:?}",
        String::from_utf8_lossy(&raw)
    );

    // Explicit mode:"reset" behaves the same.
    let (mut wire, id) = arm_and_park(
        &registry,
        store.as_ref(),
        guard.as_ref(),
        proxy,
        upstream,
        &root_pem,
    )
    .await;
    {
        let client = StubClient;
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        registry
            .command("flow.kill")
            .expect("flow.kill registered")
            .invoke(
                params(&[
                    ("id", Value::Str(id.to_string())),
                    ("mode", Value::Str("reset".into())),
                ]),
                &host,
            )
            .expect("kill the parked flow with mode:reset");
    }
    let raw = read_all(&mut wire).await;
    assert_eq!(
        status_of(&raw),
        0,
        "an explicit reset kill must deliver no HTTP response, got {:?}",
        String::from_utf8_lossy(&raw)
    );

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "a reset kill must not contact the upstream"
    );
}
