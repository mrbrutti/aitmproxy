//! HTTP/1 path hardening, end to end over loopback.
//!
//! The unit tests in `module.rs` and `tests/sansio.rs` pin each fix in
//! isolation. These tests check the same fixes against a real `Proxy`, real
//! sockets and, for the TLS cases, a real handshake with a hand-rolled origin:
//!
//! - a cleartext `CONNECT` tunnel dials the `CONNECT` target, never the `Host`
//!   header of the request inside it, and the SSRF-guarded listener judges that
//!   target, not the `Host`;
//! - a complete response, or a partial head, that an origin writes in the same
//!   read as the end of a legitimate response is neither forwarded nor parsed as
//!   the next response, and the upstream it came from is replaced, over
//!   cleartext and through a TLS tunnel;
//! - the replay sender returns only the first of two responses;
//! - an origin that accepts a TCP connection and never answers the TLS handshake
//!   cannot pin the proxy: the handshake is bounded.
//!
//! They bind loopback ports, so they run under the Terminal panel, not the Bash
//! sandbox (CLAUDE.md). Every wait on the network is bounded and fails with a
//! message naming what it was waiting for; there are no fixed ports.
//!
//! The helpers are adapted from `tests/stale_upstream.rs`.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, Config, Flow, FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpVersion, Proxy,
    RequestSender, ScopeConfig, ScopeEntry,
};
use aitm_proto_http::{CertAuthority, Http1Sender, HttpModule};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The longest any single wait on the proxy, the origin or the store may take
/// before the test fails with a message instead of hanging.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The bound the TLS-stall test gives the proxy on its handshake to the origin.
const TLS_HANDSHAKE_BOUND: Duration = Duration::from_millis(300);

/// A complete, well-formed response nobody asked for.
const STRAY: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON";

/// The start of a response head nobody asked for, cut off before its blank line.
const FRAGMENT: &str = "HTTP/1.1 500 Injected\r\nX-Junk: ";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-h1-hardening-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A loopback port nobody is listening on right now.
fn free_port() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("pick a free port")
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

// ---------------------------------------------------------------------------
// The origins
// ---------------------------------------------------------------------------

/// What a scripted origin does with each connection it accepts.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Answer every request on the connection with a keep-alive 200.
    Normal,
    /// Like `Normal`, but the FIRST response on each connection is written
    /// together with this trailer in a single `write_all`, so the trailer reaches
    /// the proxy in the same read as the end of the legitimate response. The
    /// connection then keeps serving.
    StrayAfterFirst(&'static str),
}

/// A hand-rolled origin on `127.0.0.1` and what it has observed.
struct Origin {
    addr: SocketAddr,
    /// TCP connections accepted so far.
    accepted: Arc<AtomicUsize>,
}

impl Origin {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Bind a loopback listener and run `per_conn` on its own task for every TCP
/// connection it accepts. `per_conn` gets the connection and its 1-based number
/// (the order it was accepted in); the count of accepted connections is what
/// [`Origin::accepted`] reports. The accept loop is the one every origin here
/// shares, whatever it then does with the connection.
async fn spawn_origin<F, Fut>(per_conn: F) -> Origin
where
    F: Fn(TcpStream, usize) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let conn_no = count.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(per_conn(tcp, conn_no));
        }
    });
    Origin { addr, accepted }
}

/// Read one request head (buffering any bytes past it in `buf`) and return its
/// request-target. `None` once the peer closes or errors.
async fn read_request_path<S: AsyncRead + Unpin>(io: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head: Vec<u8> = buf.drain(..end + 4).collect();
            let head = String::from_utf8_lossy(&head).into_owned();
            return head.split_whitespace().nth(1).map(str::to_string);
        }
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Answer requests on one origin connection. Every response is a keep-alive 200
/// whose body names the connection that served it and the path it was asked
/// for, so a test can tell exactly which origin connection answered.
async fn answer_requests<S>(mut io: S, conn_no: usize, behaviour: Behaviour)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut served = 0usize;
    while let Some(path) = read_request_path(&mut io, &mut buf).await {
        served += 1;
        let body = format!("conn={conn_no} path={path}");
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if let (1, Behaviour::StrayAfterFirst(trailer)) = (served, behaviour) {
            resp.push_str(trailer);
        }
        if io.write_all(resp.as_bytes()).await.is_err() || io.flush().await.is_err() {
            return;
        }
    }
}

/// A cleartext origin on `127.0.0.1`.
async fn spawn_plain_origin(behaviour: Behaviour) -> Origin {
    spawn_origin(move |tcp, conn_no| answer_requests(tcp, conn_no, behaviour)).await
}

/// A TLS origin on `127.0.0.1` with a self-signed leaf and no ALPN (so the
/// proxy's MITM lands on the HTTP/1 path).
async fn spawn_tls_origin(behaviour: Behaviour) -> Origin {
    let key = rcgen::KeyPair::generate().expect("origin key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("origin params")
        .self_signed(&key)
        .expect("origin cert");
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("origin versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("origin server config");
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    spawn_origin(move |tcp, conn_no| {
        let acceptor = acceptor.clone();
        async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            answer_requests(tls, conn_no, behaviour).await;
        }
    })
    .await
}

/// An origin that accepts TCP connections and never answers: it writes nothing,
/// so a TLS handshake with it can only stall. It reads and discards whatever the
/// peer sends (the ClientHello) for one reason: that is the only way to learn
/// that the peer closed. Returns the origin and a `Notify` signalled (as a
/// stored permit, so a later wait still sees it) once a peer has closed its end
/// of a connection.
async fn spawn_stall_origin() -> (Origin, Arc<Notify>) {
    let peer_closed = Arc::new(Notify::new());
    let closed = peer_closed.clone();
    let origin = spawn_origin(move |mut tcp, _conn_no| {
        let closed = closed.clone();
        async move {
            let mut sink = [0u8; 1024];
            loop {
                match tcp.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            closed.notify_one();
        }
    })
    .await;
    (origin, peer_closed)
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// Which listener, and so which upstream connector, a test proxy runs.
#[derive(Clone, Copy)]
enum Egress {
    /// `Proxy::run`: the passive connector relays to any address without a scope
    /// gate.
    Passive,
    /// `Proxy::run_browser`: the SSRF-guarded connector refuses a loopback target
    /// unless scope names that address (and port).
    Guarded,
}

/// Run a passive `Proxy` (see [`Egress::Passive`]) with the HTTP module (a fresh
/// CA) and no plugins. The passive connector relays without a scope gate, so the
/// origins need no scope entry. When `tls_handshake_timeout` is given, the module
/// bounds its TLS handshake to an origin by it. Returns the proxy address, the
/// CA's root PEM and the proxy's flow store.
async fn run_proxy(
    tls_handshake_timeout: Option<Duration>,
) -> (SocketAddr, String, Arc<dyn FlowStore>) {
    start_proxy(Egress::Passive, &[], tls_handshake_timeout).await
}

/// Run an SSRF-guarded `Proxy` (see [`Egress::Guarded`]) whose scope is exactly
/// `scope` (`host` or `host:port` entries), with the HTTP module (a fresh CA) and
/// no plugins. Loopback is private, so the guard admits a loopback dial only when
/// an entry names that address and port.
async fn run_guarded_proxy(scope: &[String]) -> (SocketAddr, String, Arc<dyn FlowStore>) {
    start_proxy(Egress::Guarded, scope, None).await
}

/// Build the proxy, start `egress`'s listener on a free loopback port and wait
/// until it accepts connections. Returns the proxy address, the CA's root PEM and
/// the proxy's flow store (taken before the proxy moves into its task).
async fn start_proxy(
    egress: Egress,
    scope: &[String],
    tls_handshake_timeout: Option<Duration>,
) -> (SocketAddr, String, Arc<dyn FlowStore>) {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
    let config = Config {
        scope: ScopeConfig {
            entries: scope
                .iter()
                .map(|host| ScopeEntry { host: host.clone() })
                .collect(),
            ..ScopeConfig::default()
        },
        ..Config::default()
    };
    // The test origins present self-signed leaves; trust them explicitly.
    let mut module = HttpModule::with_ca(ca).with_insecure(true);
    if let Some(within) = tls_handshake_timeout {
        module = module.with_tls_handshake_timeout(within);
    }
    let proxy = Proxy::builder()
        .with_config(config)
        .register_module(Arc::new(module))
        .build()
        .expect("build proxy");
    let store = proxy.store();
    let addr = free_port();
    tokio::spawn(async move {
        let _ = match egress {
            Egress::Passive => proxy.run(addr).await,
            Egress::Guarded => proxy.run_browser(addr).await,
        };
    });
    let deadline = Instant::now() + IO_TIMEOUT;
    while !matches!(
        tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    ) {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, root_pem, store)
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A keep-alive HTTP/1.1 client over any stream. It sends GETs and reads
/// `Content-Length`-framed responses, keeping bytes read past one response in
/// `buf` for the next, so many requests ride one connection and a response that
/// was forwarded behind another one cannot be silently dropped.
struct Client<S> {
    io: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    fn new(io: S) -> Self {
        Self {
            io,
            buf: Vec::new(),
        }
    }

    /// Send `GET target` with `Host: host` and return `(status, body)`, or why no
    /// complete response arrived. The whole exchange is bounded by `IO_TIMEOUT`.
    async fn get(&mut self, target: &str, host: &str) -> Result<(u16, String), String> {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        tokio::time::timeout(IO_TIMEOUT, async {
            self.io
                .write_all(request.as_bytes())
                .await
                .map_err(|e| format!("send request: {e}"))?;
            self.io
                .flush()
                .await
                .map_err(|e| format!("flush request: {e}"))?;
            self.read_response().await
        })
        .await
        .map_err(|_| format!("timed out waiting for the response to GET {target}"))?
    }

    async fn read_response(&mut self) -> Result<(u16, String), String> {
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            let n = self
                .io
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read response head: {e}"))?;
            if n == 0 {
                return Err("connection closed before a response head arrived".to_string());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&self.buf[..head_end]).into_owned();
        let status: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("malformed status line in {head:?}"))?;
        let len: usize = header_value(&head, "content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("no Content-Length in {head:?}"))?;
        let body_start = head_end + 4;
        while self.buf.len() < body_start + len {
            let n = self
                .io
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read response body: {e}"))?;
            if n == 0 {
                return Err("connection closed mid-body".to_string());
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&self.buf[body_start..body_start + len]).into_owned();
        self.buf.drain(..body_start + len);
        Ok((status, body))
    }
}

/// Open a CONNECT tunnel to `authority` through the proxy and return the raw
/// stream, positioned just past the `200` reply.
async fn connect_tunnel(proxy: SocketAddr, authority: SocketAddr) -> TcpStream {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut tcp = TcpStream::connect(proxy).await.expect("connect proxy");
        tcp.write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
        )
        .await
        .expect("send CONNECT");
        let reply = read_head(&mut tcp).await;
        assert!(
            reply.starts_with("HTTP/1.1 200"),
            "CONNECT was not accepted: {reply:?}"
        );
        tcp
    })
    .await
    .expect("the CONNECT exchange with the proxy timed out")
}

/// A TLS connector that trusts only the proxy CA (the proxy impersonates the
/// origin).
fn tls_connector(root_pem: &str) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(root_pem.as_bytes()).expect("root PEM"))
        .expect("add root");
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// A keep-alive client to `origin` over HTTPS through the proxy: CONNECT, then
/// TLS trusting only the proxy CA (the proxy impersonates the origin).
async fn tls_client(
    proxy: SocketAddr,
    origin: SocketAddr,
    root_pem: &str,
) -> Client<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tunnel(proxy, origin).await;
    let name = ServerName::try_from(origin.ip().to_string()).expect("server name");
    let tls = tokio::time::timeout(IO_TIMEOUT, tls_connector(root_pem).connect(name, tcp))
        .await
        .expect("the TLS handshake with the proxy timed out")
        .expect("TLS handshake with the proxy impersonating the origin");
    Client::new(tls)
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Whether the flow's stored response already carries its final, buffered body.
/// A response reaches the client before the store holds its final body.
fn has_captured_body(flow: &HttpFlow) -> bool {
    matches!(
        flow.response.as_ref().map(|r| &r.body),
        Some(Body::Bytes(_))
    )
}

/// Poll up to `IO_TIMEOUT` until the store holds at least `n` HTTP flows whose
/// response body is `Body::Bytes`, and return all such flows in insertion order.
async fn wait_for_flows(store: &Arc<dyn FlowStore>, n: usize) -> Vec<HttpFlow> {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let flows: Vec<HttpFlow> = store
            .list()
            .into_iter()
            .filter_map(|id| match store.get(id) {
                Some(Flow::Http(h)) if has_captured_body(&h) => Some(h),
                _ => None,
            })
            .collect();
        if flows.len() >= n {
            return flows;
        }
        assert!(
            Instant::now() < deadline,
            "the store never held {n} HTTP flows with a captured response body (it has {})",
            flows.len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The stored flow whose request path is `path`.
fn flow_for_path<'a>(flows: &'a [HttpFlow], path: &str) -> &'a HttpFlow {
    flows
        .iter()
        .find(|f| f.request.path == path)
        .unwrap_or_else(|| {
            panic!(
                "no stored flow for {path}; stored paths: {:?}",
                flows
                    .iter()
                    .map(|f| f.request.path.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

/// The flow's stored response body as text; panics if it holds none.
fn body_text(flow: &HttpFlow) -> String {
    match flow.response.as_ref().map(|r| &r.body) {
        Some(Body::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
        other => panic!("flow {} has no captured response body: {other:?}", flow.id),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// In a cleartext CONNECT tunnel the route is the CONNECT target. A request
/// inside it that names another origin in `Host` is still answered by the
/// CONNECT target, and the one upstream connection serves every request in the
/// tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cleartext_tunnel_dials_the_connect_target_not_the_host_header() {
    let target = spawn_plain_origin(Behaviour::Normal).await;
    let decoy = spawn_plain_origin(Behaviour::Normal).await;
    let (proxy, _root, store) = run_proxy(None).await;
    let decoy_host = decoy.addr.to_string();
    let mut client = Client::new(connect_tunnel(proxy, target.addr).await);

    let first = client.get("/one", &decoy_host).await.expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));
    assert_eq!(
        target.accepted(),
        1,
        "the tunnel's upstream connection must go to the CONNECT target"
    );
    assert_eq!(
        decoy.accepted(),
        0,
        "the Host header must not choose the tunnel's upstream"
    );

    let second = client.get("/two", &decoy_host).await.expect("request 2");
    assert_eq!(
        second,
        (200, "conn=1 path=/two".to_string()),
        "request 2 must ride the tunnel's one upstream connection"
    );
    assert_eq!(target.accepted(), 1);
    assert_eq!(decoy.accepted(), 0);

    // The flow keeps the Host the client sent as its authority and records the
    // address the traffic actually went to.
    let flows = wait_for_flows(&store, 2).await;
    let one = flow_for_path(&flows, "/one");
    assert_eq!(one.request.authority, decoy_host);
    assert_eq!(
        one.server_conn.as_ref().map(|c| c.peer),
        Some(target.addr),
        "server_conn.peer must be the CONNECT target the request was dialled to"
    );
}

/// The SSRF-guarded listener (`Proxy::run_browser`) judges a cleartext CONNECT
/// tunnel by its CONNECT target, never by the `Host` of the request inside it.
/// Loopback is private, so the guard admits a loopback dial only when scope
/// names that exact address and port. Two loopback origins, one in scope
/// (`allowed`) and one not (`denied`), make both directions observable:
///
/// - a tunnel to `denied` whose request says `Host: <allowed>` is refused: the
///   client sees the connection close and neither origin accepts anything. A
///   proxy that handed the guard the `Host` would reach `allowed`.
/// - a tunnel to `allowed` whose request says `Host: <denied>` is answered by
///   `allowed`, and `denied` still accepts nothing. A proxy that handed the guard
///   the `Host` would refuse it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_guard_judges_a_cleartext_tunnel_by_its_connect_target_not_the_host_header() {
    let allowed = spawn_plain_origin(Behaviour::Normal).await;
    let denied = spawn_plain_origin(Behaviour::Normal).await;
    let (proxy, _root, _store) = run_guarded_proxy(&[allowed.addr.to_string()]).await;

    // CONNECT to the out-of-scope origin, with a `Host` naming the in-scope one.
    let mut client = Client::new(connect_tunnel(proxy, denied.addr).await);
    let why = client
        .get("/refused", &allowed.addr.to_string())
        .await
        .expect_err("the guard must refuse the dial to the out-of-scope CONNECT target");
    assert!(
        !why.starts_with("timed out"),
        "the proxy must close a refused tunnel, not leave it hanging: {why}"
    );
    assert_eq!(
        denied.accepted(),
        0,
        "the out-of-scope CONNECT target must never be dialled"
    );
    assert_eq!(
        allowed.accepted(),
        0,
        "the Host header must not choose the tunnel's upstream"
    );

    // CONNECT to the in-scope origin, with a `Host` naming the out-of-scope one.
    let mut client = Client::new(connect_tunnel(proxy, allowed.addr).await);
    let reply = client
        .get("/admitted", &denied.addr.to_string())
        .await
        .expect("the in-scope CONNECT target must be reached whatever the Host says");
    assert_eq!(reply, (200, "conn=1 path=/admitted".to_string()));
    assert_eq!(allowed.accepted(), 1);
    assert_eq!(
        denied.accepted(),
        0,
        "the out-of-scope origin named only in Host must never be dialled"
    );
}

/// Two keep-alive GETs, `/one` then `/two`, through `client`, against an origin
/// that writes `STRAY` in the same write as its first response on every
/// connection. `prefix` is `http://<host>` for a forward-proxy client and empty
/// inside a tunnel. The client must read exactly the two legitimate responses
/// (the second from a replacement upstream connection), nothing may be left
/// pending on its connection, and the store must hold only the legitimate
/// bodies.
///
/// A response forwarded behind response 1 would be read by the client ahead of
/// response 2 (TCP keeps the order), so the checks after request 2 are
/// definitive; the one after request 1 only catches a stray the proxy has
/// already written by then.
async fn assert_a_stray_response_never_reaches_the_client<S>(
    client: &mut Client<S>,
    prefix: &str,
    host: &str,
    origin: &Origin,
    store: &Arc<dyn FlowStore>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first = client
        .get(&format!("{prefix}/one"), host)
        .await
        .expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));
    assert!(
        client.buf.is_empty(),
        "bytes beyond response 1 reached the client: {:?}",
        String::from_utf8_lossy(&client.buf)
    );

    let second = client
        .get(&format!("{prefix}/two"), host)
        .await
        .expect("request 2");
    assert_eq!(
        second,
        (200, "conn=2 path=/two".to_string()),
        "request 2 must get its own response from a replacement connection, not the stray one"
    );
    assert!(
        client.buf.is_empty(),
        "bytes beyond response 2 reached the client: {:?}",
        String::from_utf8_lossy(&client.buf)
    );
    assert_eq!(
        origin.accepted(),
        2,
        "the origin that left bytes behind must have lost its connection"
    );

    // The stray response must not have replaced the stored one either.
    let flows = wait_for_flows(store, 2).await;
    assert_eq!(flows.len(), 2);
    for (path, body) in [("/one", "conn=1 path=/one"), ("/two", "conn=2 path=/two")] {
        let flow = flow_for_path(&flows, path);
        assert_eq!(body_text(flow), body);
        let response = flow.response.as_ref().expect("stored response");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("content-length"),
            Some(body.len().to_string().as_str()),
            "the stored head must be the legitimate response's, not the stray's"
        );
    }
}

/// Cleartext forward proxy. The origin writes a complete stray response in the
/// same write as its first response. The client gets only the legitimate
/// response, and request 2 on the same client connection is answered by a fresh
/// upstream connection, not by the stray.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stray_response_in_the_same_read_is_not_forwarded() {
    let origin = spawn_plain_origin(Behaviour::StrayAfterFirst(STRAY)).await;
    let (proxy, _root, store) = run_proxy(None).await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    assert_a_stray_response_never_reaches_the_client(
        &mut client,
        &format!("http://{host}"),
        &host,
        &origin,
        &store,
    )
    .await;
}

/// Through a TLS tunnel. The same stray, but the replacement connection must be
/// a TLS reconnect to the origin (a second TCP accept), never a cleartext
/// fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stray_response_in_the_same_read_is_not_forwarded_through_a_tls_tunnel() {
    let origin = spawn_tls_origin(Behaviour::StrayAfterFirst(STRAY)).await;
    let (proxy, root_pem, store) = run_proxy(None).await;
    let host = origin.addr.to_string();
    let mut client = tls_client(proxy, origin.addr, &root_pem).await;

    assert_a_stray_response_never_reaches_the_client(&mut client, "", &host, &origin, &store).await;
}

/// A partial head. The origin writes the start of a response head after its
/// first response and keeps the connection open, so it would answer request 2 if
/// the proxy sent it there. A fragment left in the buffer of a live upstream
/// would be glued onto that answer and the origin would pick its status line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stray_head_fragment_does_not_corrupt_the_next_response() {
    let origin = spawn_plain_origin(Behaviour::StrayAfterFirst(FRAGMENT)).await;
    let (proxy, _root, _store) = run_proxy(None).await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let first = client
        .get(&format!("http://{host}/one"), &host)
        .await
        .expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    let second = client
        .get(&format!("http://{host}/two"), &host)
        .await
        .expect("request 2");
    assert_eq!(
        second,
        (200, "conn=2 path=/two".to_string()),
        "request 2 must be answered by a replacement connection with its own head \
         (a head corrupted by the fragment would carry status 500)"
    );
    assert_eq!(
        origin.accepted(),
        2,
        "the origin that left a fragment behind must have lost its connection"
    );
}

/// `Http1Sender` (replay, `request.send`, the scanner) drives the same machine
/// and must return only the first of two responses an origin writes in one go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_replay_sender_returns_only_the_first_of_two_responses() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        let _ = read_head(&mut tcp).await;
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit{STRAY}");
        let _ = tcp.write_all(wire.as_bytes()).await;
        let _ = tcp.flush().await;
        let _ = tcp.shutdown().await;
    });

    let request = HttpRequest {
        method: "GET".into(),
        scheme: "http".into(),
        authority: addr.to_string(),
        path: "/".into(),
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    };
    let response = tokio::time::timeout(IO_TIMEOUT, Http1Sender::new().send(&request))
        .await
        .expect("the replay send timed out")
        .expect("the replay send failed");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-length"),
        Some("5"),
        "the head must be the first response's, not the stray's"
    );
    match response.body {
        Body::Bytes(bytes) => assert_eq!(bytes, b"legit".to_vec()),
        other => panic!("expected the first response's buffered body, got {other:?}"),
    }
}

/// The origin accepts the TCP connection and never answers the TLS handshake.
/// The proxy, with a 300 ms bound, gives up on it: the client's own handshake
/// with the proxy fails (the proxy drops the connection) no sooner than 250 ms
/// and well inside the guard, and the origin sees the proxy close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_gives_up_on_an_origin_that_stalls_the_tls_handshake() {
    let (stall, peer_closed) = spawn_stall_origin().await;
    let (proxy, root_pem, _store) = run_proxy(Some(TLS_HANDSHAKE_BOUND)).await;
    let tcp = connect_tunnel(proxy, stall.addr).await;
    let name = ServerName::try_from(stall.addr.ip().to_string()).expect("server name");

    let started = Instant::now();
    let outcome =
        tokio::time::timeout(IO_TIMEOUT, tls_connector(&root_pem).connect(name, tcp)).await;
    let elapsed = started.elapsed();

    match outcome {
        Err(_) => panic!(
            "the client's TLS handshake with the proxy was still pending after {IO_TIMEOUT:?}: \
             the proxy never bounded its handshake to the stalled origin"
        ),
        Ok(Ok(_)) => {
            panic!("the TLS handshake with the proxy succeeded, but the origin never answered")
        }
        Ok(Err(_)) => {}
    }
    assert!(
        elapsed >= Duration::from_millis(250),
        "the handshake failed after {elapsed:?}, before the proxy's 300 ms bound could have expired"
    );

    tokio::time::timeout(IO_TIMEOUT, peer_closed.notified())
        .await
        .expect("the stalled origin never saw the proxy close its connection");
    assert_eq!(
        stall.accepted(),
        1,
        "the proxy must have dialled the stalled origin exactly once"
    );
}
