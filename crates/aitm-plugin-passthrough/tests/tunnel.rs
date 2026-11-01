//! AC-F11.1 / Review focus #5: a passthrough host is tunnelled byte-for-byte —
//! the client's TLS peer certificate is the **upstream's real cert** and the store
//! holds no decrypted `HttpFlow` for it — while a non-passthrough host on the same
//! proxy is still MITM'd (a leaf issued by the aitm CA, its request captured).
//!
//! The proxy here is a minimal acceptor that mirrors `aitm_core::Proxy`'s next-
//! layer selection (`modules.iter().find(|m| m.matches(&hint))`) over the real
//! `PassthroughModule` (registered first) and the real `HttpModule`, driving each
//! with a real `ModuleCtx`/`Chain`/store. A test `UpstreamConnector` maps the
//! CONNECT authority to a loopback TLS fixture so the test needs no DNS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{
    ByteStream, Chain, Flow, FlowStore, MemFlowStore, ModuleCtx, NextLayerHint, ProtocolModule,
    Registry, ScopeEntry, ScopeRateGuard, StdGuard, UpstreamConnector,
};
use aitm_plugin_passthrough::{PassthroughList, PassthroughModule};
use aitm_proto_http::{CertAuthority, HttpModule};
use futures::future::BoxFuture;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-passthrough-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Read bytes until the blank line that ends an HTTP head; returns the head text.
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

/// A loopback TLS origin presenting a self-signed cert with SAN `san`, answering
/// every request with 200 + a tiny body. Returns its address and its own cert.
async fn spawn_tls_fixture(san: &str) -> (SocketAddr, CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec![san.to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let cert_der = cert.der().clone().into_owned();
    let cfg = ServerConfig::builder_with_provider(provider())
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
                let body = "origin-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, cert_der)
}

/// Dials the CONNECT authority to a fixed loopback fixture, keyed by host name, so
/// the test resolves hosts without DNS. Mirrors the passive connector (dial, no
/// scope check) but routes by name instead of the module-resolved address.
struct MapConnector {
    by_host: HashMap<String, SocketAddr>,
}

impl UpstreamConnector for MapConnector {
    fn connect(
        &self,
        authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        let host = authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
            .to_ascii_lowercase();
        let addr = self.by_host.get(&host).copied();
        Box::pin(async move {
            let addr =
                addr.ok_or_else(|| anyhow::anyhow!("no fixture mapped for host {host:?}"))?;
            let tcp = TcpStream::connect(addr).await?;
            Ok(Box::pin(tcp) as ByteStream)
        })
    }
}

/// Start the split proxy: `PassthroughModule` (first) + `HttpModule`, a real
/// chain/store, a `MapConnector`, and a real `StdGuard` whose Scope is
/// `scope_hosts` — handed to the passthrough module and to every `ModuleCtx`, the
/// way the acceptor wires them (spec D2). Only an in-scope, unpinned host is
/// MITM'd; a pinned or out-of-scope one is tunnelled. Returns the proxy address
/// and the store.
async fn run_split_proxy(
    passthrough_hosts: Vec<String>,
    scope_hosts: Vec<String>,
    by_host: HashMap<String, SocketAddr>,
    ca: Arc<CertAuthority>,
) -> (SocketAddr, Arc<dyn FlowStore>) {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let registry = Arc::new(Registry::new());
    let chain = Arc::new(Chain::new(registry, store.clone()));
    let connector: Arc<dyn UpstreamConnector> = Arc::new(MapConnector { by_host });
    let guard = StdGuard::default();
    for host in scope_hosts {
        guard.add_scope(ScopeEntry { host });
    }
    let guard: Arc<dyn ScopeRateGuard> = Arc::new(guard);

    let list = PassthroughList::new(passthrough_hosts);
    let modules: Arc<[Arc<dyn ProtocolModule>]> = Arc::from(vec![
        Arc::new(PassthroughModule::new(list).with_scope(guard.clone())) as Arc<dyn ProtocolModule>,
        Arc::new(HttpModule::with_ca(ca).with_insecure(true)) as Arc<dyn ProtocolModule>,
    ]);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    let store_for_loop = store.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                break;
            };
            let modules = modules.clone();
            let store = store_for_loop.clone();
            let chain = chain.clone();
            let connector = connector.clone();
            let guard = guard.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let n = tcp.peek(&mut buf).await.unwrap_or(0);
                let first = buf[..n].to_vec();
                let hint = NextLayerHint {
                    dst: peer,
                    is_tls: first.first() == Some(&0x16),
                    client_hello_sni: None,
                    alpn: Vec::new(),
                    first_bytes: first,
                    from_upgrade: false,
                    peer_identity: None,
                    capture_interface: None,
                };
                let Some(module) = modules.iter().find(|m| m.matches(&hint)).cloned() else {
                    return;
                };
                let ctx = ModuleCtx::new(store, chain, connector)
                    .with_modules(modules.clone())
                    .with_hint(hint)
                    .with_scope(guard);
                let io: ByteStream = Box::pin(tcp);
                let _ = module.spawn(io, ctx).await;
            });
        }
    });
    (addr, store)
}

/// CONNECT `authority` through the proxy, asserting a 200, and return the opened
/// TCP stream positioned at the start of the tunnel.
async fn open_tunnel(proxy: SocketAddr, authority: &str) -> TcpStream {
    let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("send CONNECT");
    let reply = read_head(&mut tcp).await;
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "CONNECT was not accepted: {reply:?}"
    );
    tcp
}

/// Finish TLS over `tcp` with `client_cfg` and SNI `sni`, send `GET /secret`, and
/// return (peer leaf cert, status).
async fn tls_get(
    tcp: TcpStream,
    sni: &str,
    client_cfg: Arc<ClientConfig>,
) -> (CertificateDer<'static>, u16) {
    let name = ServerName::try_from(sni.to_string()).expect("server name");
    let mut tls = TlsConnector::from(client_cfg)
        .connect(name, tcp)
        .await
        .expect("client TLS handshake");

    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .expect("a peer certificate")
        .clone()
        .into_owned();

    tls.write_all(b"GET /secret HTTP/1.1\r\nHost: secret.host\r\nConnection: close\r\n\r\n")
        .await
        .expect("send request");
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("read response: {e}"),
    }
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (peer, status)
}

/// A client that accepts any server cert (used to read the real upstream cert a
/// passthrough tunnel presents, without pre-trusting it).
fn accept_any_client() -> Arc<ClientConfig> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert {
            provider: provider(),
        }))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// A client that trusts only `root_pem` (the aitm CA): a successful handshake
/// proves the leaf was issued by that CA (i.e. the host was MITM'd).
fn ca_trusting_client(root_pem: &str) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(root_pem.as_bytes()).expect("root PEM"))
        .expect("add root");
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passthrough_tunnels_mitm_still_decrypts() {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));

    // Two loopback TLS origins, each with its own self-signed cert.
    let (pinned_addr, pinned_cert) = spawn_tls_fixture("localhost").await;
    let (mitm_addr, mitm_cert) = spawn_tls_fixture("127.0.0.1").await;

    // "localhost" is on the passthrough list; "127.0.0.1" is not, and it is in
    // Scope — the only host the proxy may decrypt (spec D1).
    let mut by_host = HashMap::new();
    by_host.insert("localhost".to_string(), pinned_addr);
    by_host.insert("127.0.0.1".to_string(), mitm_addr);
    let (proxy, store) = run_split_proxy(
        vec!["localhost".to_string()],
        vec!["127.0.0.1".to_string()],
        by_host,
        ca.clone(),
    )
    .await;

    // Passthrough host: the client accepts any cert and must see the ORIGIN's own
    // cert — the proxy never terminated TLS.
    let pinned_authority = format!("localhost:{}", pinned_addr.port());
    let tcp = open_tunnel(proxy, &pinned_authority).await;
    let (peer_cert, status) = tls_get(tcp, "localhost", accept_any_client()).await;
    assert_eq!(status, 200, "passthrough origin should answer the client");
    assert_eq!(
        peer_cert.as_ref(),
        pinned_cert.as_ref(),
        "passthrough client must see the upstream's real cert, not a minted leaf"
    );

    // Non-passthrough host: the client trusts ONLY the aitm CA, so a successful
    // handshake proves the leaf was minted by the CA (the host was MITM'd).
    let mitm_authority = format!("127.0.0.1:{}", mitm_addr.port());
    let tcp = open_tunnel(proxy, &mitm_authority).await;
    let (peer_cert, status) =
        tls_get(tcp, "127.0.0.1", ca_trusting_client(ca.root_cert_pem())).await;
    assert_eq!(status, 200, "MITM'd origin should answer the client");
    assert_ne!(
        peer_cert.as_ref(),
        mitm_cert.as_ref(),
        "MITM client must see a CA-minted leaf, not the origin's real cert"
    );

    // The store must hold the decrypted MITM flow (GET /secret) but NO decrypted
    // flow for the passthrough host.
    let flows = collect_flows(store.as_ref()).await;

    let mitm_flow = flows.iter().find_map(|f| match f {
        Flow::Http(h) if h.request.path == "/secret" => Some(h),
        _ => None,
    });
    let mitm_flow = mitm_flow.expect("the MITM'd host must produce a decrypted HttpFlow");
    assert_eq!(mitm_flow.request.method, "GET");
    assert_eq!(
        mitm_flow.response.as_ref().map(|r| r.status),
        Some(200),
        "the decrypted MITM flow must capture the upstream response"
    );

    // Passthrough leaked nothing: no flow carries the decrypted request path.
    let decrypted_passthrough = flows.iter().any(|f| match f {
        Flow::Http(h) => {
            h.request.method == "GET"
                && h.request.path == "/secret"
                && authority_host(&h.request.authority) == "localhost"
        }
        _ => false,
    });
    assert!(
        !decrypted_passthrough,
        "a passthrough host must never produce a decrypted HttpFlow"
    );

    // A minimal tunnel marker was recorded so a UI can show "tunnelled".
    let tunnel = flows.iter().any(|f| match f {
        Flow::Http(h) => {
            h.metadata.marks.iter().any(|m| m == "tunnelled")
                && authority_host(&h.request.authority) == "localhost"
        }
        _ => false,
    });
    assert!(
        tunnel,
        "the passthrough connection should record a tunnel flow"
    );
}

/// Snapshot every stored flow, waiting briefly for the pipeline to settle.
async fn collect_flows(store: &dyn FlowStore) -> Vec<Flow> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let flows: Vec<Flow> = store
            .list()
            .into_iter()
            .filter_map(|id| store.get(id))
            .collect();
        let has_mitm = flows.iter().any(
            |f| matches!(f, Flow::Http(h) if h.request.path == "/secret" && h.response.is_some()),
        );
        let has_tunnel = flows.iter().any(
            |f| matches!(f, Flow::Http(h) if h.metadata.marks.iter().any(|m| m == "tunnelled")),
        );
        if has_mitm && has_tunnel {
            return flows;
        }
        if Instant::now() >= deadline {
            return flows;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The host portion of `host[:port]`, lowercased.
fn authority_host(authority: &str) -> String {
    authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
