//! `Http1Sender`: the concrete [`RequestSender`] the binary injects into the
//! core `PipelineClient` so `flow.replay` / `request.send` reissue a request for
//! real.
//!
//! It drives the shared [`Http1Machine`] (so framing — `Content-Length`, chunked
//! decode, close-delimited bodies — matches the proxy's own parser and no
//! duplicate `Content-Length`/`Transfer-Encoding` is emitted) over a TCP stream,
//! wrapped in rustls for `https` with the webpki roots verified by default.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    ssrf_check, Authority, Body, HeaderMap, HttpRequest, HttpResponse, RequestSender,
    ScopeRateGuard, SsrfPolicy,
};
use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole exchange after connecting — TLS handshake, write, and the full
/// response — must finish within this. The per-read timeout alone resets on
/// every byte, so an upstream trickling a header forever would otherwise hold
/// the caller (and, through a script's `http.send`, a hook) open indefinitely.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const READ_CHUNK: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Name → addresses. A seam so the SSRF gate is testable without real DNS; the
/// default resolves through tokio's non-blocking resolver.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>>;
}

/// The operating system's resolver, driven on tokio's blocking pool.
struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// The SSRF gate for the reissue path: the same policy + live scope the browser
/// connector uses.
struct SsrfGate {
    policy: SsrfPolicy,
    scope: Arc<dyn ScopeRateGuard>,
}

/// Reissues requests over real HTTP/1.1 (+ TLS for `https`).
pub struct Http1Sender {
    provider: Arc<CryptoProvider>,
    insecure: bool,
    response_timeout: Duration,
    resolver: Arc<dyn HostResolver>,
    ssrf: Option<SsrfGate>,
}

impl Default for Http1Sender {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1Sender {
    /// A sender that verifies upstream TLS against the webpki roots.
    pub fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            insecure: false,
            response_timeout: RESPONSE_TIMEOUT,
            resolver: Arc::new(SystemResolver),
            ssrf: None,
        }
    }

    /// Skip upstream certificate verification when `insecure` (maps to
    /// `Config.ssl_insecure`).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Enforce the SSRF policy against `scope` on every reissue: resolve the
    /// target and refuse a private/loopback/metadata address unless an in-scope
    /// IP literal lifts it — exactly as the browser connector does, so
    /// `flow.replay`, `request.send` and the script `http.send` (which all share
    /// this sender) cannot reach an internal host or rebind a scoped name to one.
    pub fn with_ssrf(mut self, policy: SsrfPolicy, scope: Arc<dyn ScopeRateGuard>) -> Self {
        self.ssrf = Some(SsrfGate { policy, scope });
        self
    }

    /// Replace the DNS resolver. A seam for tests; production uses the default
    /// system resolver.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// The overall deadline for one exchange after the TCP connect (default
    /// 60s).
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    fn client_config(&self) -> Result<Arc<ClientConfig>> {
        let builder = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("replay TLS versions")?;
        let mut cfg = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(crate::module::accept_any_verifier(
                    self.provider.clone(),
                ))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

impl RequestSender for Http1Sender {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, Result<HttpResponse>> {
        let req = prepare(req);
        let scheme = req.scheme.to_ascii_lowercase();
        Box::pin(async move {
            let (host, port) = split_authority(&req.authority, &scheme)?;
            // Resolve once, then (when the SSRF gate is configured) refuse a
            // private/loopback/metadata address before connecting, and connect to
            // an address we actually validated — so the resolve-then-connect
            // (DNS-rebinding) window is closed and every reissue path that shares
            // this sender is covered.
            let ips = self.resolver.resolve(host.clone(), port).await?;
            if let Some(gate) = &self.ssrf {
                let scope = gate.scope.list_scope();
                let authority = Authority::new(&host, port).to_string();
                for ip in &ips {
                    // `confine_to_scope = false`: scope-confined egress is a
                    // browser-only posture (scanner S2). Active reissue is already
                    // scope-gated upstream by `check_active`; it must not be gated
                    // again here (per the egress-confinement spec's anti-goal).
                    ssrf_check(&gate.policy, &scope, false, &authority, *ip)
                        .map_err(|e| anyhow!("SSRF: refusing reissue to {host}: {e}"))?;
                }
            }
            let addr = ips
                .into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, port))
                .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("connect to {addr} timed out"))??;

            let exchange = async {
                if scheme == "https" {
                    let name = ServerName::try_from(host.clone())
                        .map_err(|e| anyhow!("invalid server name {host:?}: {e}"))?;
                    let tls = TlsConnector::from(self.client_config()?)
                        .connect(name, tcp)
                        .await
                        .with_context(|| format!("TLS to {host}"))?;
                    drive(tls, &req).await
                } else {
                    drive(tcp, &req).await
                }
            };
            tokio::time::timeout(self.response_timeout, exchange)
                .await
                .map_err(|_| {
                    anyhow!(
                        "upstream response from {addr} timed out after {:?}",
                        self.response_timeout
                    )
                })?
        })
    }
}

/// Normalise a request for sending: a `Host` header from the authority and
/// `Connection: close` so the exchange ends cleanly. Framing headers are left to
/// `Http1Machine::enqueue_request`, which sets `Content-Length` from the body.
fn prepare(req: &HttpRequest) -> HttpRequest {
    let mut headers = HeaderMap::new();
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        let _ = headers.try_set(name, value);
    }
    let host = req
        .authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(&req.authority);
    let _ = headers.try_set("Host", host);
    let _ = headers.try_set("Connection", "close");
    HttpRequest {
        headers,
        ..req.clone()
    }
}

/// Serialize a request to wire bytes (used only to prime the machine so it knows
/// the method for response framing); `Content-Length` is set from the real body.
fn request_bytes(req: &HttpRequest) -> Vec<u8> {
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, path);
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = match &req.body {
        Body::Bytes(b) => b.as_slice(),
        _ => &[],
    };
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Drive one request/response exchange over `stream` using the shared machine.
async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    req: &HttpRequest,
) -> Result<HttpResponse> {
    let mut machine = Http1Machine::new();
    // Prime the machine by parsing the request (so it tracks the method/flow for
    // response framing), then forward a cleanly-framed copy to the server.
    machine.on_bytes(Side::Client, &request_bytes(req))?;
    machine.enqueue_request(req);
    if let Some(bytes) = machine.poll_outbound(Side::Server) {
        stream.write_all(&bytes).await?;
    }
    stream.flush().await?;

    let mut body: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut done = false;
    while !done {
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Err(anyhow!("upstream read timed out")),
        };
        let events = if n == 0 {
            machine.on_eof(Side::Server)
        } else {
            machine.on_bytes(Side::Server, &buf[..n])?
        };
        for ev in events {
            match ev {
                HttpSansIoEvent::ResponseBodyChunk { bytes, .. } => {
                    let room = MAX_RESPONSE_BYTES.saturating_sub(body.len());
                    let take = room.min(bytes.len());
                    body.extend_from_slice(&bytes[..take]);
                }
                HttpSansIoEvent::ResponseComplete(_) => done = true,
                _ => {}
            }
        }
        if n == 0 {
            break;
        }
    }

    let head = machine
        .response()
        .cloned()
        .ok_or_else(|| anyhow!("no response parsed from upstream"))?;
    Ok(HttpResponse {
        body: if body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(body)
        },
        timestamp: SystemTime::now(),
        ..head
    })
}

/// Split `host[:port]` with the scheme's default port; handles bracketed IPv6.
fn split_authority(authority: &str, scheme: &str) -> Result<(String, u16)> {
    let default = if scheme == "https" { 443 } else { 80 };
    let auth = aitm_core::Authority::parse_with_default(authority, default)
        .map_err(|e| anyhow!("bad authority {authority:?}: {e}"))?;
    let port = if auth.port == 0 { default } else { auth.port };
    Ok((auth.host, port))
}

/// `drive` over an in-memory stream: the reissue path returns the trailers of a
/// chunked response (the machine captures them; the sender needs no change of
/// its own) and fails closed on a trailer section over the machine's caps.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    /// A request for `path` on `127.0.0.1:8080`.
    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: Body) -> HttpRequest {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpRequest {
            method: method.into(),
            scheme: "http".into(),
            authority: "127.0.0.1:8080".into(),
            path: path.into(),
            version: aitm_core::HttpVersion::Http11,
            headers: map,
            body,
            timestamp: SystemTime::now(),
        }
    }

    fn get_x() -> HttpRequest {
        request("GET", "/x", &[("Host", "127.0.0.1:8080")], Body::Empty)
    }

    /// Read one request from `io` (its head and the `Content-Length` body bytes
    /// that follow), returning every byte read.
    async fn read_request(io: &mut DuplexStream) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse::<usize>().expect("numeric Content-Length"))
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length {
                    return seen;
                }
            }
            let n = io.read(&mut buf).await.expect("origin read");
            assert!(n > 0, "the sender closed before it wrote a whole request");
            seen.extend_from_slice(&buf[..n]);
        }
    }

    /// The origin: read one request, record it, then write each segment with a
    /// 10 ms pause between so the machine sees them as separate reads. After the
    /// last segment it holds the connection open until the sender hangs up.
    /// Returns the request bytes it read. A failed write means the sender
    /// already gave up (the case under test), so it just stops.
    async fn origin(mut io: DuplexStream, segments: Vec<Vec<u8>>) -> Vec<u8> {
        let seen = read_request(&mut io).await;
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if io.write_all(segment).await.is_err() || io.flush().await.is_err() {
                return seen;
            }
        }
        let mut sink = [0u8; 1];
        let _ = io.read(&mut sink).await;
        seen
    }

    /// Run `drive` for `req` against an origin that answers with `segments`;
    /// returns what `drive` returned and the request bytes the origin saw.
    async fn exchange(req: HttpRequest, segments: Vec<Vec<u8>>) -> (Result<HttpResponse>, Vec<u8>) {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(origin(server, segments));
        let result = tokio::time::timeout(Duration::from_secs(10), drive(client, &req))
            .await
            .expect("drive finished within the guard");
        let seen = origin.await.expect("origin task");
        (result, seen)
    }

    fn seg(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn trailers(resp: &HttpResponse) -> Vec<(&str, &str)> {
        resp.trailers.iter().collect()
    }

    #[tokio::test]
    async fn drive_returns_the_trailers_of_a_chunked_response() {
        let (result, _) = exchange(
            get_x(),
            vec![seg(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                 5\r\nhello\r\n0\r\nX-Sum: abc\r\nServer-Timing: origin;dur=1\r\n\r\n",
            )],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        assert_eq!(resp.status, 200);
        match &resp.body {
            Body::Bytes(b) => assert_eq!(b.as_slice(), b"hello"),
            other => panic!("body was {other:?}, want Bytes(hello)"),
        }
        assert_eq!(
            trailers(&resp),
            vec![("X-Sum", "abc"), ("Server-Timing", "origin;dur=1")]
        );
        assert_eq!(
            resp.headers.get("x-sum"),
            None,
            "a trailer is never merged into the headers"
        );
        assert_eq!(resp.headers.get("trailer"), Some("X-Sum"));
    }

    #[tokio::test]
    async fn drive_returns_trailers_that_arrive_in_a_later_read() {
        let (result, _) = exchange(
            get_x(),
            vec![
                seg(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                     5\r\nhello\r\n0\r\n",
                ),
                seg("X-Sum: abc\r\n"),
                seg("Server-Timing: origin;dur=1\r\n"),
                seg("\r\n"),
            ],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        match &resp.body {
            Body::Bytes(b) => assert_eq!(b.as_slice(), b"hello"),
            other => panic!("body was {other:?}, want Bytes(hello)"),
        }
        assert_eq!(
            trailers(&resp),
            vec![("X-Sum", "abc"), ("Server-Timing", "origin;dur=1")]
        );
        assert_eq!(resp.headers.get("x-sum"), None);
    }

    #[tokio::test]
    async fn drive_fails_on_a_trailer_section_over_the_cap() {
        let mut section = String::from("0\r\n");
        for i in 0..65 {
            section.push_str(&format!("f{i}: v\r\n"));
        }
        section.push_str("\r\n");
        let (result, _) = exchange(
            get_x(),
            vec![
                seg("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
                seg(&section),
            ],
        )
        .await;
        let err = result.expect_err("65 trailer fields exceed the machine's cap");
        assert!(err.to_string().contains("trailer"), "{err}");
    }

    /// Characterization: a request that carries `Expect: 100-continue` goes out
    /// head and body together, without waiting for the origin to say anything.
    #[tokio::test]
    async fn drive_writes_an_expect_request_head_and_body_together() {
        let req = request(
            "POST",
            "/up",
            &[("Host", "127.0.0.1:8080"), ("Expect", "100-continue")],
            Body::Bytes(b"hello".to_vec()),
        );
        let (result, seen) = exchange(
            req,
            vec![seg("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&seen),
            "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\nhello"
        );
        assert_eq!(result.expect("the exchange succeeds").status, 200);
    }

    /// Characterization: an origin's own interim `100 Continue` is skipped, so
    /// the response `drive` returns is the final one.
    #[tokio::test]
    async fn drive_skips_an_origin_interim_100_for_a_request_that_carries_expect() {
        let req = request(
            "POST",
            "/up",
            &[("Host", "127.0.0.1:8080"), ("Expect", "100-continue")],
            Body::Bytes(b"hello".to_vec()),
        );
        let (result, _) = exchange(
            req,
            vec![seg(
                "HTTP/1.1 100 Continue\r\n\r\n\
                 HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
            )],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        assert_eq!(resp.status, 302);
        assert_eq!(resp.headers.get("location"), Some("/c"));
        assert!(matches!(resp.body, Body::Empty), "body was {:?}", resp.body);
        assert!(resp.trailers.is_empty());
    }
}
