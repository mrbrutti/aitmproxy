//! `Http1Sender`: the concrete [`RequestSender`] the binary injects into the
//! core `PipelineClient` so `flow.replay` / `request.send` reissue a request for
//! real.
//!
//! It drives the shared [`Http1Machine`] (so framing — `Content-Length`, chunked
//! decode, close-delimited bodies — matches the proxy's own parser and no
//! duplicate `Content-Length`/`Transfer-Encoding` is emitted) over a TCP stream,
//! wrapped in rustls for `https` with the webpki roots verified by default.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{Body, HeaderMap, HttpRequest, HttpResponse, RequestSender};
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
const READ_CHUNK: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Reissues requests over real HTTP/1.1 (+ TLS for `https`).
pub struct Http1Sender {
    provider: Arc<CryptoProvider>,
    insecure: bool,
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
        }
    }

    /// Skip upstream certificate verification when `insecure` (maps to
    /// `Config.ssl_insecure`).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
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
            let addr = tokio::net::lookup_host((host.as_str(), port))
                .await
                .with_context(|| format!("resolve {host}:{port}"))?
                .next()
                .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("connect to {addr} timed out"))??;

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
