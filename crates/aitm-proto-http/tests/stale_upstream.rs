//! Fast-follow #2b: the proxy must not forward a request onto a kept-alive
//! upstream connection the origin has already closed.
//!
//! The HTTP/1 module holds ONE upstream connection per client connection and
//! reuses it for every request on that connection. While the client idles, an
//! origin with a keep-alive timeout (Node's http server and Apache both default
//! to 5 s) closes its side. Nothing reads the upstream between requests, so the
//! proxy used to write the next request to the dead socket, read EOF, and drop
//! the client connection before a single response byte reached it. A client that
//! does not retry (the embedded browser) then waited out its whole navigation
//! timeout.
//!
//! These tests drive a real `Proxy` with the HTTP module between a keep-alive
//! client and a hand-rolled origin that can close its idle socket on cue. They
//! bind loopback ports, so they run under the Terminal panel, not the Bash
//! sandbox (CLAUDE.md).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{Config, Proxy, ScopeConfig, ScopeEntry};
use aitm_proto_http::{CertAuthority, HttpModule};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The longest any single wait on the proxy or the origin may take before the
/// test fails with a message instead of hanging.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the origin lets a connection sit idle after its first response
/// before it acts (closes the socket, or writes stray bytes).
const ORIGIN_IDLE_DELAY: Duration = Duration::from_millis(100);

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-stale-{}", uuid::Uuid::new_v4()));
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
// The origin
// ---------------------------------------------------------------------------

/// What the origin does with a connection once it has answered the first request
/// and the connection sits idle.
#[derive(Clone, Copy)]
enum Idle {
    /// Keep the connection open and answer every request on it.
    Stay,
    /// Close the socket, like an origin whose keep-alive timeout expired.
    Close,
    /// Write a complete, well-formed response nobody asked for, then carry on
    /// serving the connection. Reading it as the answer to the next request
    /// would hand the client the wrong response.
    StrayResponse,
}

/// A hand-rolled HTTP/1.1 origin and what it has observed.
struct Origin {
    addr: SocketAddr,
    /// TCP connections accepted so far.
    accepted: Arc<AtomicUsize>,
    /// How many times a connection has gone idle and had its idle act performed
    /// (the socket closed, or the stray bytes written).
    idle_acts: Arc<AtomicUsize>,
}

impl Origin {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Wait until the origin has performed its idle act `n` times, then sleep a
    /// further 100 ms. Waiting on the act removes the dependence on how long the
    /// origin's own idle timer takes to fire. The trailing sleep still rests on
    /// one timing assumption: that the FIN (or the stray bytes) written to the
    /// loopback socket has reached the proxy's end of it within those 100 ms,
    /// which on loopback takes microseconds. A badly stalled machine could break
    /// that and make a test fail spuriously; it would not make one pass wrongly.
    async fn wait_idle_acts(&self, n: usize) {
        let deadline = Instant::now() + IO_TIMEOUT;
        while self.idle_acts.load(Ordering::SeqCst) < n {
            assert!(Instant::now() < deadline, "the origin never went idle");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
async fn answer_requests<S>(mut io: S, conn_no: usize, idle: Idle, idle_acts: Arc<AtomicUsize>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut served = 0usize;
    while let Some(path) = read_request_path(&mut io, &mut buf).await {
        served += 1;
        let body = format!("conn={conn_no} path={path}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if io.write_all(resp.as_bytes()).await.is_err() || io.flush().await.is_err() {
            return;
        }
        if served != 1 {
            continue;
        }
        match idle {
            Idle::Stay => {}
            Idle::Close => {
                tokio::time::sleep(ORIGIN_IDLE_DELAY).await;
                let _ = io.shutdown().await;
                idle_acts.fetch_add(1, Ordering::SeqCst);
                return;
            }
            Idle::StrayResponse => {
                tokio::time::sleep(ORIGIN_IDLE_DELAY).await;
                let stray = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nstray";
                if io.write_all(stray.as_bytes()).await.is_err() || io.flush().await.is_err() {
                    return;
                }
                idle_acts.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// A cleartext origin on `127.0.0.1`.
async fn spawn_plain_origin(idle: Idle) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let idle_acts = Arc::new(AtomicUsize::new(0));
    let (acc, acts) = (accepted.clone(), idle_acts.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let conn_no = acc.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::spawn(answer_requests(tcp, conn_no, idle, acts.clone()));
        }
    });
    Origin {
        addr,
        accepted,
        idle_acts,
    }
}

/// A TLS origin on `127.0.0.1` with a self-signed leaf and no ALPN (so the
/// proxy's MITM lands on the HTTP/1 path).
async fn spawn_tls_origin(idle: Idle) -> Origin {
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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let idle_acts = Arc::new(AtomicUsize::new(0));
    let (acc, acts) = (accepted.clone(), idle_acts.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let conn_no = acc.fetch_add(1, Ordering::SeqCst) + 1;
            let acceptor = acceptor.clone();
            let acts = acts.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                answer_requests(tls, conn_no, idle, acts).await;
            });
        }
    });
    Origin {
        addr,
        accepted,
        idle_acts,
    }
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// Run a `Proxy` with the HTTP module (a fresh CA) and no plugins. `127.0.0.1`
/// is in scope so the guarded upstream connector admits the origins. Returns the
/// proxy address and the CA's root PEM.
async fn run_proxy() -> (SocketAddr, String) {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let root_pem = ca.root_cert_pem().to_string();
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
        // The test origins present self-signed leaves; trust them explicitly.
        .register_module(Arc::new(HttpModule::with_ca(ca).with_insecure(true)))
        .build()
        .expect("build proxy");
    let addr = free_port();
    tokio::spawn(async move {
        let _ = proxy.run(addr).await;
    });
    let deadline = Instant::now() + IO_TIMEOUT;
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, root_pem)
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A keep-alive HTTP/1.1 client over any stream. It sends GETs and reads
/// `Content-Length`-framed responses, keeping bytes read past one response for
/// the next, so many requests ride one connection.
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
    /// complete response arrived.
    async fn get(&mut self, target: &str, host: &str) -> Result<(u16, String), String> {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        self.io
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("send request: {e}"))?;
        self.io
            .flush()
            .await
            .map_err(|e| format!("flush request: {e}"))?;
        tokio::time::timeout(IO_TIMEOUT, self.read_response())
            .await
            .map_err(|_| "timed out waiting for the response".to_string())?
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

/// A keep-alive client to `origin` over HTTPS through the proxy: CONNECT, then
/// TLS trusting only the proxy CA (the proxy impersonates the origin).
async fn tls_client(
    proxy: SocketAddr,
    origin: SocketAddr,
    root_pem: &str,
) -> Client<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = connect_tunnel(proxy, origin).await;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(root_pem.as_bytes()).expect("root PEM"))
        .expect("add root");
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(origin.ip().to_string()).expect("server name");
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("TLS handshake with the proxy impersonating the origin");
    Client::new(tls)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The reported bug, cleartext forward-proxy path: the origin closes its idle
/// keep-alive socket between two requests on one client connection. The second
/// request must still get its own answer, from a fresh upstream connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_survives_the_origin_closing_an_idle_keepalive() {
    let origin = spawn_plain_origin(Idle::Close).await;
    let (proxy, _root) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let first = client
        .get(&format!("http://{host}/one"), &host)
        .await
        .expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    // The origin closes the now-idle upstream socket (its keep-alive timeout).
    origin.wait_idle_acts(1).await;

    let second = client
        .get(&format!("http://{host}/two"), &host)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "request 2 on the same client connection failed after the origin \
                 closed the idle upstream: {e}"
            )
        });
    assert_eq!(second, (200, "conn=2 path=/two".to_string()));
    assert_eq!(
        origin.accepted(),
        2,
        "the proxy must have opened a fresh upstream connection for request 2"
    );
}

/// The same bug through a CONNECT tunnel with TLS MITM: the proxy has to
/// re-handshake TLS to the origin, not just redial TCP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_tunnel_survives_the_origin_closing_an_idle_keepalive() {
    let origin = spawn_tls_origin(Idle::Close).await;
    let (proxy, root_pem) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = tls_client(proxy, origin.addr, &root_pem).await;

    let first = client.get("/one", &host).await.expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    origin.wait_idle_acts(1).await;

    let second = client.get("/two", &host).await.unwrap_or_else(|e| {
        panic!(
            "request 2 on the same TLS tunnel failed after the origin closed the \
             idle upstream: {e}"
        )
    });
    assert_eq!(second, (200, "conn=2 path=/two".to_string()));
    assert_eq!(
        origin.accepted(),
        2,
        "the proxy must have reconnected to the origin for request 2"
    );
}

/// No behaviour change in the common case: an origin that keeps the connection
/// open is reused, so the probe must not reconnect needlessly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_upstream_is_reused() {
    let origin = spawn_plain_origin(Idle::Stay).await;
    let (proxy, _root) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let first = client
        .get(&format!("http://{host}/one"), &host)
        .await
        .expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    // Idle between requests, as in the failing case, but the origin stays up.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let second = client
        .get(&format!("http://{host}/two"), &host)
        .await
        .expect("request 2");
    assert_eq!(second, (200, "conn=1 path=/two".to_string()));
    assert_eq!(
        origin.accepted(),
        1,
        "both requests must ride the single upstream connection"
    );
}

/// The same reuse guarantee through a TLS tunnel, where the liveness probe reads
/// from a TLS session rather than a bare socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_tls_upstream_is_reused() {
    let origin = spawn_tls_origin(Idle::Stay).await;
    let (proxy, root_pem) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = tls_client(proxy, origin.addr, &root_pem).await;

    let first = client.get("/one", &host).await.expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    tokio::time::sleep(Duration::from_millis(400)).await;

    let second = client.get("/two", &host).await.expect("request 2");
    assert_eq!(second, (200, "conn=1 path=/two".to_string()));
    assert_eq!(
        origin.accepted(),
        1,
        "both requests must ride the single TLS upstream connection"
    );
}

/// An origin that writes bytes onto an idle keep-alive connection is not trusted:
/// those bytes could be read as the answer to the NEXT request and hand the
/// client the wrong response. The connection is discarded and the next request
/// answered on a fresh one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsolicited_bytes_on_an_idle_upstream_are_not_trusted() {
    let origin = spawn_plain_origin(Idle::StrayResponse).await;
    let (proxy, _root) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let first = client
        .get(&format!("http://{host}/one"), &host)
        .await
        .expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    // The origin writes its stray response onto the idle connection.
    origin.wait_idle_acts(1).await;

    let second = client
        .get(&format!("http://{host}/two"), &host)
        .await
        .expect("request 2");
    assert_eq!(
        second,
        (200, "conn=2 path=/two".to_string()),
        "request 2 must get its own response from a fresh connection, not the stray one"
    );
    assert_eq!(origin.accepted(), 2);
}

/// A reconnect inside a cleartext CONNECT tunnel goes back to the origin the
/// tunnel was opened to. A later request in the tunnel naming a different `Host`
/// must not steer the replacement connection somewhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_in_a_connect_tunnel_stays_on_the_tunnel_origin() {
    let tunnel_origin = spawn_plain_origin(Idle::Close).await;
    let other_origin = spawn_plain_origin(Idle::Stay).await;
    let (proxy, _root) = run_proxy().await;
    let tunnel_host = tunnel_origin.addr.to_string();
    let other_host = other_origin.addr.to_string();
    let mut client = Client::new(connect_tunnel(proxy, tunnel_origin.addr).await);

    let first = client.get("/one", &tunnel_host).await.expect("request 1");
    assert_eq!(first, (200, "conn=1 path=/one".to_string()));

    tunnel_origin.wait_idle_acts(1).await;

    // Same tunnel, but this request names the other origin in its Host header.
    let second = client
        .get("/two", &other_host)
        .await
        .unwrap_or_else(|e| panic!("request 2 in the tunnel failed after the origin closed: {e}"));
    assert_eq!(
        second,
        (200, "conn=2 path=/two".to_string()),
        "the replacement connection must go to the tunnel's origin"
    );
    assert_eq!(tunnel_origin.accepted(), 2);
    assert_eq!(
        other_origin.accepted(),
        0,
        "a later request's Host header must not redirect the reconnect"
    );
}
