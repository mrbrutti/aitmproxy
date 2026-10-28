//! Task 4 (F3): response-phase park + `flow.mutate` status edit.
//!
//! `flow.intercept {rules:[{phase:"response"}]}` arms a response-phase breakpoint;
//! the intercept plugin parks the flow at `Event::ResponseHeaders` (the suspension
//! point Task 2 pinned in `aitm-proto-http/tests/response_park.rs`), *before* any
//! response byte reaches the client. `flow.mutate {id, edits:{status:418}}` edits
//! the parked response's status; `flow.resume` then forwards it, and the client
//! observably receives HTTP 418.
//!
//! `response_status_edited_then_resumed` is end-to-end: a loopback TLS origin, the
//! real `HttpModule`, and the real `InterceptPlugin`/`MutatePlugin` driven through
//! the proxy's command registry. It binds loopback ports, so it runs under the
//! Terminal panel, not the sandbox. `status_edit_rejected_on_request_phase` is a
//! hermetic unit check that a `status` edit on a non-response flow is an `Err`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, CommandHost, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, Plugin, Proxy, ProxyClient,
    Registry, ScopeConfig, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_plugins::{InterceptPlugin, MutatePlugin};
use aitm_proto_http::{CertAuthority, HttpModule};
use futures::future::BoxFuture;
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

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-respedit-{}", uuid::Uuid::new_v4()));
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

/// A TLS origin on `127.0.0.1` answering every request with 200 and a fixed body.
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

/// A proxy client the command host never actually sends through (flow.mutate /
/// flow.resume touch only the store); present to satisfy `CommandHost`.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Run a `Proxy` with the HTTP module and `plugins`; `127.0.0.1` is in scope.
/// Returns the listen address plus the shared registry/store/guard the test uses
/// to invoke commands against the *same* plugin set the chain dispatches through.
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

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn rule_obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// AC-F3.2: a response-phase rule parks the flow at the response phase; a
/// `flow.mutate {status:418}` edit followed by `flow.resume` delivers HTTP 418 to
/// the client, with the response body still forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_status_edited_then_resumed() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let upstream = spawn_fixture().await;
    let (proxy, registry, store, guard) = run_proxy(
        ca,
        vec![
            Box::new(InterceptPlugin::new()),
            Box::new(MutatePlugin::new()),
        ],
    )
    .await;

    // Arm a response-phase breakpoint: no clauses, so every flow parks at the
    // response phase (and none at the request phase).
    let client = StubClient;
    {
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        registry
            .command("flow.intercept")
            .expect("flow.intercept registered")
            .invoke(
                params(&[(
                    "rules",
                    Value::Array(vec![rule_obj(&[("phase", Value::Str("response".into()))])]),
                )]),
                &host,
            )
            .expect("arm response-phase interception");
    }

    let mut wire = connect_and_send(proxy, upstream, "/resp", &root_pem).await;

    // The flow parks at ResponseHeaders — the request was not parked (the rule is
    // response-phase only), so the first Intercepted state is the response.
    let id = wait_for_parked(store.as_ref()).await;

    // Edit the parked response's status, then resume it.
    {
        let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
        registry
            .command("flow.mutate")
            .expect("flow.mutate registered")
            .invoke(
                params(&[
                    ("id", Value::Str(id.to_string())),
                    (
                        "edits",
                        Value::Object(BTreeMap::from([("status".to_string(), Value::Int(418))])),
                    ),
                ]),
                &host,
            )
            .expect("edit the parked response status");
        registry
            .command("flow.resume")
            .expect("flow.resume registered")
            .invoke(params(&[("id", Value::Str(id.to_string()))]), &host)
            .expect("resume the parked response");
    }

    // The client now receives the edited status and the forwarded body.
    let mut raw = Vec::new();
    match wire.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response after resume: {e}"),
    }
    let (status, body) = parse_response(&raw);
    assert_eq!(status, 418, "client must receive the edited status");
    assert!(
        body.contains(UPSTREAM_BODY),
        "resumed response body was {body:?}, want it to contain {UPSTREAM_BODY:?}"
    );
}

fn http_flow_observed() -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// A `status` edit is only valid for a flow parked at the response phase. On a
/// non-response flow (here `Observed`, no response) it is an `Err`, and the stored
/// flow is left unchanged.
#[test]
fn status_edit_rejected_on_request_phase() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(MutatePlugin::new()));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let id = store.insert(http_flow_observed());
    let err = reg
        .command("flow.mutate")
        .expect("flow.mutate registered")
        .invoke(
            params(&[
                ("id", Value::Str(id.to_string())),
                (
                    "edits",
                    Value::Object(BTreeMap::from([("status".to_string(), Value::Int(200))])),
                ),
            ]),
            &host,
        )
        .expect_err("a status edit on a non-response flow is rejected");
    assert!(
        err.to_string().to_lowercase().contains("status"),
        "error should name the invalid `status` edit: {err}"
    );

    // The stored flow was not mutated.
    match store.get(id) {
        Some(Flow::Http(f)) => assert!(!f.metadata.edited, "a rejected edit leaves `edited` false"),
        other => panic!("expected a stored HTTP flow, got {other:?}"),
    }
}
