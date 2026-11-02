//! Real-socket suite for the T10 HTTP surfaces of `aitm-testtarget` (plan
//! Task A21; spec S2, S3, S4, S6 and the target half of S8).
//!
//! Against a real in-process target (`TestTarget::builder(mode)`) over real
//! loopback sockets: the two TLS listeners negotiate ALPN as advertised and
//! log a `tls_handshake` entry each; one h2 connection carrying five requests
//! shows up as one `/log/conns` row with `requests: 5`, `streams: 5` and
//! `conn_req_index` 1..5, and a raw h2 client whose one HEADERS frame hyper
//! rejects leaves a row with `streams: 1`, `requests: 0` (amendment 51);
//! `/ws` behaves per D4 in both modes (origin, login, subprotocol echo,
//! escaping, the 1009 close) and logs the handshake and the close; `/ws` over
//! h2 is a 400; the control origin is a separate 404-everything-else origin
//! whose `/log/http` never stores a raw cookie or authorization value; the
//! patched passive headers ride over TLS; `/services` lists every listener
//! and speaker with the D5 grammar.
//!
//! Every client here is test-local and dependency-free beyond the crate's own
//! deps plus hyper's `client` feature: a rustls client config with a
//! no-verify certificate verifier (the target's certificate is self-signed
//! per process), a byte-level HTTP/1 client, hyper's `http2` connection for
//! the h2 cases and a masked RFC 6455 client mirroring
//! `tests/e2e/aitm_e2e/ws.py`.
//!
//! Binds loopback ports, so it runs in the Terminal panel, never in the Bash
//! sandbox (bind is EPERM there).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_testtarget::{manifest, SeedMode, TestTarget};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http2::SendRequest;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Value};
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// A single socket read may not take longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a control-origin observation is polled for before failing.
const OBSERVE_WITHIN: Duration = Duration::from_secs(3);
/// RFC 6455 section 1.3 handshake GUID (client-side accept check).
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest payload a client frame may declare (spec D4 Control row).
const WS_MAX_FRAME: u64 = 1_048_576;

use SeedMode::{Patched, Vulnerable};

// --- TLS client ---------------------------------------------------------------

/// Accepts any server certificate: the target mints a fresh self-signed
/// certificate per process, so there is nothing to pin. Test-only.
#[derive(Debug)]
struct NoVerify {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for NoVerify {
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A rustls client config over the `ring` provider (as the crate's `tls.rs`
/// does, no global install), no certificate verification, offering `alpn`.
fn client_config(alpn: &[&str]) -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(NoVerify {
        schemes: provider
            .signature_verification_algorithms
            .supported_schemes(),
    });
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Arc::new(cfg)
}

/// `host:port` of an `http://` or `https://` loopback URL.
fn authority(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or_else(|| panic!("url without a scheme: {url}"))
        .trim_end_matches('/')
}

/// Open a TLS connection to the `https://` listener at `url` offering `alpn`;
/// returns the stream and the protocol the server negotiated (`None` when it
/// picked nothing).
async fn tls_connect(url: &str, alpn: &[&str]) -> (TlsStream<TcpStream>, Option<Vec<u8>>) {
    let tcp = TcpStream::connect(authority(url))
        .await
        .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    let connector = TlsConnector::from(client_config(alpn));
    let name = ServerName::try_from("localhost").expect("localhost is a valid server name");
    let stream = tokio::time::timeout(READ_TIMEOUT, connector.connect(name, tcp))
        .await
        .expect("tls handshake timed out")
        .unwrap_or_else(|e| panic!("tls handshake with {url}: {e}"));
    let negotiated = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    (stream, negotiated)
}

// --- HTTP/1 client ------------------------------------------------------------

/// One parsed HTTP response: status, lower-cased header names, body bytes.
#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Read some bytes into `buf`, failing loudly on EOF or a stalled peer.
async fn read_more<IO>(io: &mut IO, buf: &mut Vec<u8>)
where
    IO: AsyncRead + Unpin,
{
    let mut chunk = [0u8; 16 * 1024];
    let n = tokio::time::timeout(READ_TIMEOUT, io.read(&mut chunk))
        .await
        .expect("socket read timed out")
        .expect("socket read");
    assert!(
        n > 0,
        "peer closed the socket early; buffered so far: {:?}",
        String::from_utf8_lossy(buf)
    );
    buf.extend_from_slice(&chunk[..n]);
}

/// Parse a `HTTP/1.1 <status> ...` head into its status and headers.
fn parse_head(head: &str) -> (u16, Vec<(String, String)>) {
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("bad status line {status_line:?}"));
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (status, headers)
}

/// Read one HTTP/1 response (head plus a `Content-Length` body) off `io`,
/// consuming it from `buf`; bytes past the response stay in `buf` (a 101's
/// first WebSocket frame may already be there).
async fn read_response<IO>(io: &mut IO, buf: &mut Vec<u8>) -> Resp
where
    IO: AsyncRead + Unpin,
{
    let head_end = loop {
        if let Some(pos) = find(buf, b"\r\n\r\n") {
            break pos + 4;
        }
        read_more(io, buf).await;
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let (status, headers) = parse_head(&head);
    let len = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        read_more(io, buf).await;
    }
    let body = buf[head_end..head_end + len].to_vec();
    buf.drain(..head_end + len);
    Resp {
        status,
        headers,
        body,
    }
}

/// One HTTP/1.1 request on an already-connected `io` (plain or TLS). Sends
/// `Connection: close` unless `keep_open`; always reads exactly one response.
async fn h1_request<IO>(
    io: &mut IO,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    keep_open: bool,
) -> Resp
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    if !keep_open {
        req.push_str("Connection: close\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if method == "POST" || !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes())
        .await
        .expect("write request head");
    io.write_all(body).await.expect("write request body");
    io.flush().await.expect("flush request");
    let mut buf = Vec::new();
    read_response(io, &mut buf).await
}

/// `GET path` with `headers` on `io`, the server told to close afterwards.
async fn h1_get<IO>(io: &mut IO, host: &str, path: &str, headers: &[(&str, &str)]) -> Resp
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    h1_request(io, host, "GET", path, headers, b"", false).await
}

/// One plain-HTTP request over a fresh loopback socket to `base_url`.
async fn plain_request(
    base_url: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Resp {
    let host = authority(base_url);
    let mut tcp = TcpStream::connect(host)
        .await
        .unwrap_or_else(|e| panic!("connect {base_url}: {e}"));
    h1_request(&mut tcp, host, method, path, headers, body, false).await
}

async fn plain_get(base_url: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
    plain_request(base_url, "GET", path, headers, b"").await
}

/// `GET path` on the control origin, parsed as JSON (status returned too).
async fn control_get_status(control_url: &str, path: &str) -> (u16, Value) {
    let resp = plain_get(control_url, path, &[]).await;
    assert_eq!(
        resp.header("content-type"),
        Some("application/json"),
        "control {path} content-type"
    );
    let value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("control {path} is not JSON ({e}): {}", resp.text()));
    (resp.status, value)
}

/// `GET path` on the control origin, expecting 200 JSON.
async fn control_get(control_url: &str, path: &str) -> Value {
    let (status, value) = control_get_status(control_url, path).await;
    assert_eq!(status, 200, "control {path}: {value}");
    value
}

/// Poll `GET path` on the control origin until `ready(body)` holds (the
/// serving tasks log asynchronously after the client sees its bytes).
async fn wait_for(
    control_url: &str,
    path: &str,
    what: &str,
    ready: impl Fn(&Value) -> bool,
) -> Value {
    let started = Instant::now();
    loop {
        let value = control_get(control_url, path).await;
        if ready(&value) {
            return value;
        }
        assert!(
            started.elapsed() < OBSERVE_WITHIN,
            "{what} not observed on {path} within {OBSERVE_WITHIN:?}; last body: {value}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The `entries` array of a `/log/*` body.
fn entries(body: &Value) -> &[Value] {
    body["entries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("no entries array in {body}"))
}

/// `POST /login` as alice; returns the bare session id.
async fn login(base_url: &str) -> String {
    let resp = plain_request(
        base_url,
        "POST",
        "/login",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        b"user=alice&pass=wonderland",
    )
    .await;
    assert_eq!(resp.status, 302, "login: {}", resp.text());
    assert_eq!(resp.header("location"), Some("/account?tab=overview"));
    let cookie = resp
        .header("set-cookie")
        .expect("login sets the session cookie");
    let id = cookie
        .strip_prefix("session=")
        .and_then(|rest| rest.split(';').next())
        .unwrap_or_else(|| panic!("unexpected set-cookie {cookie:?}"));
    assert_eq!(id.len(), 32, "session id is 32 hex: {id}");
    id.to_string()
}

// --- HTTP/2 client -------------------------------------------------------------

/// A hyper h2 connection over TLS to the `tls` listener at `url` (ALPN must
/// come back `h2`). The connection task is spawned; the sender is returned.
async fn h2_client(url: &str) -> SendRequest<Full<Bytes>> {
    let (stream, negotiated) = tls_connect(url, &["h2"]).await;
    assert_eq!(
        negotiated.as_deref(),
        Some(&b"h2"[..]),
        "ALPN for the h2 client"
    );
    let (send, conn) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send
}

/// One request on an h2 connection; `url` is absolute (`https://host:port/path`).
async fn h2_request(
    send: &mut SendRequest<Full<Bytes>>,
    url: &str,
    headers: &[(&str, &str)],
) -> Resp {
    send.ready().await.expect("h2 connection ready");
    let mut builder = Request::builder().method("GET").uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .expect("h2 request builds");
    let resp = tokio::time::timeout(READ_TIMEOUT, send.send_request(req))
        .await
        .expect("h2 response timed out")
        .unwrap_or_else(|e| panic!("h2 request {url}: {e}"));
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("h2 body")
        .to_bytes()
        .to_vec();
    Resp {
        status,
        headers,
        body,
    }
}

// --- WebSocket client (plain TCP, masked frames; mirror of ws.py) ----------------

/// A deterministic, distinct `Sec-WebSocket-Key` per handshake (base64 of 16
/// bytes, as RFC 6455 requires), so the `/log/ws` entry can be found by it.
fn ws_key(n: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([n; 16])
}

/// The `Sec-WebSocket-Accept` the server must answer `key` with.
fn ws_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// One masked client frame (FIN set) with a 7-, 16- or 64-bit length.
fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut out = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= usize::from(u16::MAX) {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// A client-side frame header declaring `declared` payload bytes (masked,
/// text), followed by no payload at all: the server must refuse it on the
/// header alone.
fn oversize_header(declared: u64) -> Vec<u8> {
    let mut out = vec![0x81, 0x80 | 127];
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(&[0x37, 0xfa, 0x21, 0x3d]);
    out
}

/// An upgraded `/ws` connection: the socket plus bytes read past the 101.
struct WsClient {
    io: TcpStream,
    buf: Vec<u8>,
}

impl WsClient {
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        self.io
            .write_all(&masked_frame(opcode, payload))
            .await
            .expect("write ws frame");
        self.io.flush().await.expect("flush ws frame");
    }

    async fn send_text(&mut self, text: &str) {
        self.send(0x1, text.as_bytes()).await;
    }

    async fn send_close(&mut self, code: u16) {
        self.send(0x8, &code.to_be_bytes()).await;
    }

    async fn send_raw(&mut self, wire: &[u8]) {
        self.io.write_all(wire).await.expect("write raw ws bytes");
        self.io.flush().await.expect("flush raw ws bytes");
    }

    /// Read one (unmasked) server frame: `(opcode, payload)`.
    async fn read_frame(&mut self) -> (u8, Vec<u8>) {
        while self.buf.len() < 2 {
            read_more(&mut self.io, &mut self.buf).await;
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        assert_eq!(b1 & 0x80, 0, "server frames must not be masked");
        let (len, header) = match b1 & 0x7f {
            126 => {
                while self.buf.len() < 4 {
                    read_more(&mut self.io, &mut self.buf).await;
                }
                (
                    usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]])),
                    4,
                )
            }
            127 => {
                while self.buf.len() < 10 {
                    read_more(&mut self.io, &mut self.buf).await;
                }
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.buf[2..10]);
                (
                    usize::try_from(u64::from_be_bytes(raw)).expect("frame length fits"),
                    10,
                )
            }
            n => (usize::from(n), 2),
        };
        while self.buf.len() < header + len {
            read_more(&mut self.io, &mut self.buf).await;
        }
        let payload = self.buf[header..header + len].to_vec();
        self.buf.drain(..header + len);
        (b0 & 0x0f, payload)
    }

    /// Read one frame and require it to be text.
    async fn read_text(&mut self) -> String {
        let (opcode, payload) = self.read_frame().await;
        assert_eq!(opcode, 0x1, "expected a text frame, payload {payload:?}");
        String::from_utf8(payload).expect("text frame is UTF-8")
    }

    /// Read one frame and require it to be a close with exactly `code`.
    async fn expect_close(&mut self, code: u16) {
        let (opcode, payload) = self.read_frame().await;
        assert_eq!(opcode, 0x8, "expected a close frame, payload {payload:?}");
        assert_eq!(payload, code.to_be_bytes().to_vec(), "close code");
    }
}

/// The `/ws` handshake on a fresh plain socket to `base_url` with `key` and
/// `extra` headers (`Origin`, `Cookie`, `Sec-WebSocket-Protocol`). Returns the
/// response and the socket (only meaningful after a 101).
async fn ws_handshake(base_url: &str, key: &str, extra: &[(&str, &str)]) -> (Resp, WsClient) {
    let host = authority(base_url);
    let mut tcp = TcpStream::connect(host)
        .await
        .unwrap_or_else(|e| panic!("connect {base_url}: {e}"));
    let mut req = format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes())
        .await
        .expect("write ws handshake");
    tcp.flush().await.expect("flush ws handshake");
    let mut buf = Vec::new();
    let resp = read_response(&mut tcp, &mut buf).await;
    if resp.status == 101 {
        assert_eq!(
            resp.header("sec-websocket-accept"),
            Some(ws_accept(key).as_str()),
            "accept key for {key}"
        );
        assert_eq!(resp.header("upgrade"), Some("websocket"));
    }
    (resp, WsClient { io: tcp, buf })
}

/// The `/log/ws` handshake entry carrying `key`.
fn handshake_entry<'a>(ws_log: &'a Value, key: &str) -> &'a Value {
    entries(ws_log)
        .iter()
        .find(|e| e["kind"] == "handshake" && e["sec_websocket_key"] == key)
        .unwrap_or_else(|| panic!("no handshake entry for key {key} in {ws_log}"))
}

/// `(listener, alpn)` of every `tls_handshake` entry, in log order.
fn tls_handshakes(http_log: &Value) -> Vec<(String, String)> {
    entries(http_log)
        .iter()
        .filter(|e| e["kind"] == "tls_handshake")
        .map(|e| {
            (
                e["listener"].as_str().unwrap_or("").to_string(),
                e["alpn"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

// --- Tests ---------------------------------------------------------------------

/// S2: the `tls` listener negotiates `h2` when offered and `http/1.1` when
/// that is all the client offers; `tls_h1` negotiates `http/1.1` even when
/// offered `h2`; each handshake is logged with its listener and ALPN.
#[tokio::test]
async fn tls_listener_negotiates_h2_and_h1() {
    let target = TestTarget::builder(Vulnerable)
        .tls(0)
        .tls_h1(0)
        .control(0)
        .start()
        .await
        .expect("start target");
    let tls = target.tls_url().expect("tls listener");
    let tls_h1 = target.tls_h1_url().expect("tls_h1 listener");
    let control = target.control_url().expect("control origin");

    let cases: [(&str, &[&str], &[u8]); 3] = [
        (tls, &["h2", "http/1.1"], b"h2"),
        (tls, &["http/1.1"], b"http/1.1"),
        (tls_h1, &["h2", "http/1.1"], b"http/1.1"),
    ];
    let mut streams = Vec::new();
    let mut leaf_certs: Vec<Vec<u8>> = Vec::new();
    for (i, (url, offered, expected)) in cases.iter().enumerate() {
        let (stream, negotiated) = tls_connect(url, offered).await;
        assert_eq!(
            negotiated.as_deref(),
            Some(*expected),
            "offered {offered:?} to {url}"
        );
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| cert.as_ref().to_vec())
            .unwrap_or_else(|| panic!("{url} presented no certificate"));
        leaf_certs.push(leaf);
        streams.push(stream);
        // The server logs its side of the handshake asynchronously; wait for
        // it before the next connect so the log order is the connect order.
        wait_for(control, "/log/http", "tls_handshake entry", |body| {
            tls_handshakes(body).len() == i + 1
        })
        .await;
    }

    let log = control_get(control, "/log/http").await;
    assert_eq!(
        tls_handshakes(&log),
        vec![
            ("tls".to_string(), "h2".to_string()),
            ("tls".to_string(), "http/1.1".to_string()),
            ("tls_h1".to_string(), "http/1.1".to_string()),
        ]
    );
    let ids: BTreeSet<&str> = entries(&log)
        .iter()
        .filter(|e| e["kind"] == "tls_handshake")
        .filter_map(|e| e["conn_id"].as_str())
        .collect();
    assert_eq!(ids.len(), 3, "three distinct connections: {ids:?}");
    // Spec D1: one self-signed certificate per process, so `tls` and
    // `tls_h1` present the same leaf DER.
    assert_eq!(leaf_certs.len(), 3);
    assert_eq!(
        leaf_certs[0], leaf_certs[2],
        "tls and tls_h1 must present the same certificate"
    );
    assert_eq!(leaf_certs[0], leaf_certs[1]);
    drop(streams);
}

/// S3: five requests over one h2 connection are one `/log/conns` row with
/// `requests: 5`, `streams: 5` (amendment 51: five HEADERS frames on ids
/// 1, 3, 5, 7, 9) and `conn_req_index` 1..5 on `version: "h2"` entries.
#[tokio::test]
async fn h2_connection_counts_requests() {
    let target = TestTarget::builder(Vulnerable)
        .tls(0)
        .control(0)
        .start()
        .await
        .expect("start target");
    let tls = target.tls_url().expect("tls listener");
    let control = target.control_url().expect("control origin");

    let mut send = h2_client(tls).await;
    for i in 1..=5 {
        let resp = h2_request(&mut send, &format!("{tls}/preview?msg=x"), &[]).await;
        assert_eq!(resp.status, 200, "request {i}");
        assert_eq!(resp.text(), "<html><body><p>x</p></body></html>");
    }

    let conns = control_get(control, "/log/conns").await;
    let tls_conns: Vec<&Value> = entries(&conns)
        .iter()
        .filter(|c| c["listener"] == "tls")
        .collect();
    assert_eq!(tls_conns.len(), 1, "one tls connection: {conns}");
    let conn = tls_conns[0];
    assert_eq!(conn["alpn"], json!("h2"));
    assert_eq!(conn["requests"], json!(5));
    assert_eq!(conn["streams"], json!(5), "{conn}");
    assert_eq!(conn["closed_ms"], Value::Null, "still open: {conn}");
    let conn_id = conn["conn_id"].as_str().expect("conn_id");
    assert!(
        conn_id.starts_with("c-") && conn_id.len() == 10,
        "{conn_id}"
    );

    let http = control_get(control, "/log/http").await;
    assert_eq!(
        tls_handshakes(&http),
        vec![("tls".to_string(), "h2".to_string())]
    );
    let requests: Vec<&Value> = entries(&http)
        .iter()
        .filter(|e| e["kind"] == "request" && e["conn_id"] == conn_id)
        .collect();
    let indexes: Vec<u64> = requests
        .iter()
        .filter_map(|e| e["conn_req_index"].as_u64())
        .collect();
    assert_eq!(indexes, vec![1, 2, 3, 4, 5]);
    for e in &requests {
        assert_eq!(e["version"], json!("h2"), "{e}");
        assert_eq!(e["listener"], json!("tls"), "{e}");
        assert_eq!(e["method"], json!("GET"), "{e}");
        assert_eq!(e["path"], json!("/preview"), "{e}");
        assert_eq!(e["query"], json!("msg=x"), "{e}");
        assert_eq!(e["status"], json!(200), "{e}");
    }
}

/// One HTTP/2 frame: 9-byte header (24-bit length, type, flags, 31-bit stream
/// id) followed by `payload`.
fn h2_frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits 24 bits");
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&len.to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream_id.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// S3 (amendment 51): a stream hyper never dispatches still counts. A raw h2
/// client sends the preface, an empty SETTINGS and one HEADERS frame
/// (END_HEADERS | END_STREAM, stream 1) whose header block is not valid HPACK,
/// reads whatever comes back (a GOAWAY, an RST_STREAM or EOF; the bytes are
/// hyper's business) and closes. The connection row says `alpn: "h2"`,
/// `streams: 1`, `requests: 0`.
#[tokio::test]
async fn h2_rejected_header_block_counts_a_stream_but_no_request() {
    let target = TestTarget::builder(Vulnerable)
        .tls(0)
        .control(0)
        .start()
        .await
        .expect("start target");
    let tls = target.tls_url().expect("tls listener");
    let control = target.control_url().expect("control origin");

    let (mut stream, negotiated) = tls_connect(tls, &["h2"]).await;
    assert_eq!(negotiated.as_deref(), Some(&b"h2"[..]), "ALPN h2");

    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend(h2_frame(0x4, 0x0, 0, &[]));
    // 0xFF: an indexed representation whose index (127 + 0) is outside the
    // static table with an empty dynamic table, then a truncated literal:
    // hyper's HPACK decoder rejects the block, so no request is dispatched.
    wire.extend(h2_frame(0x1, 0x05, 1, &[0xff, 0x00, 0x00]));
    stream.write_all(&wire).await.expect("raw h2 write");
    stream.flush().await.expect("raw h2 flush");

    // Drain the server's answer for up to a second; EOF, an error or the
    // deadline all end the read. Nothing about its bytes is asserted.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut buf = [0u8; 1024];
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {}
        }
    }
    drop(stream);

    let conns = wait_for(control, "/log/conns", "the tls h2 row", |body| {
        entries(body)
            .iter()
            .any(|c| c["listener"] == "tls" && c["streams"] == json!(1))
    })
    .await;
    let tls_conns: Vec<&Value> = entries(&conns)
        .iter()
        .filter(|c| c["listener"] == "tls")
        .collect();
    assert_eq!(tls_conns.len(), 1, "one tls connection: {conns}");
    let conn = tls_conns[0];
    assert_eq!(conn["alpn"], json!("h2"), "{conn}");
    assert_eq!(conn["streams"], json!(1), "{conn}");
    assert_eq!(conn["requests"], json!(0), "{conn}");

    // And `/log/http` has the handshake but no `request` entry for it.
    let http = control_get(control, "/log/http").await;
    assert_eq!(
        tls_handshakes(&http),
        vec![("tls".to_string(), "h2".to_string())]
    );
    let conn_id = conn["conn_id"].as_str().expect("conn_id");
    assert!(
        !entries(&http)
            .iter()
            .any(|e| e["kind"] == "request" && e["conn_id"] == conn_id),
        "no request was dispatched for the rejected stream: {http}"
    );
}

/// S4 / D4: the `/ws` handshake, hello, echo, subprotocol, close and oversize
/// rules in both modes, with the `/log/ws` and `/log/conns` evidence.
#[tokio::test]
async fn ws_round_trip_v_and_p() {
    // --- Vulnerable ---------------------------------------------------------
    let v = TestTarget::builder(Vulnerable)
        .control(0)
        .start()
        .await
        .expect("start V");
    let (v_base, v_control) = (v.base_url(), v.control_url().expect("control"));

    // Any Origin is accepted; the hello names anonymous; echo reflects raw.
    let (resp, mut ws) =
        ws_handshake(v_base, &ws_key(1), &[("Origin", "http://evil.example")]).await;
    assert_eq!(resp.status, 101, "V evil origin: {}", resp.text());
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"hello","user":"anonymous"}"#
    );
    ws.send_text(r#"{"type":"echo","msg":"<i>"}"#).await;
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"echo","msg":"<i>","html":"<b><i></b>"}"#
    );
    ws.send_text(r#"{"type":"chat","msg":"x"}"#).await;
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"chat","msg":"x","html":"<b>x</b>"}"#
    );
    ws.send_close(1000).await;
    ws.expect_close(1000).await;
    drop(ws);

    let ws_log = control_get(v_control, "/log/ws").await;
    let hs = handshake_entry(&ws_log, &ws_key(1));
    assert_eq!(hs["origin"], json!("http://evil.example"));
    assert_eq!(hs["accepted"], json!(true));
    assert_eq!(hs["status"], json!(101));
    assert_eq!(hs["session_valid"], json!(false));
    assert_eq!(hs["cookie_names"], json!([]));
    assert_eq!(hs["subprotocol"], Value::Null);
    assert_eq!(hs["path"], json!("/ws"));
    assert_eq!(hs["listener"], json!("plain"));
    let conn_id = hs["conn_id"].as_str().expect("conn_id").to_string();

    // After the client's close: a `close` entry and a stamped connection.
    let ws_log = wait_for(v_control, "/log/ws", "close entry", |body| {
        entries(body)
            .iter()
            .any(|e| e["kind"] == "close" && e["conn_id"] == conn_id.as_str())
    })
    .await;
    let close = entries(&ws_log)
        .iter()
        .find(|e| e["kind"] == "close" && e["conn_id"] == conn_id.as_str())
        .expect("close entry");
    assert_eq!(close["code"], json!(1000));
    let conns = control_get(v_control, "/log/conns").await;
    let row = entries(&conns)
        .iter()
        .find(|c| c["conn_id"] == conn_id.as_str())
        .unwrap_or_else(|| panic!("no /log/conns row for {conn_id}: {conns}"));
    assert!(
        row["closed_ms"].is_u64(),
        "closed_ms must be set after the loop ends: {row}"
    );
    assert!(row["opened_ms"].is_u64(), "{row}");

    // V echoes the first requested subprotocol.
    let (resp, mut ws) =
        ws_handshake(v_base, &ws_key(2), &[("Sec-WebSocket-Protocol", "chat")]).await;
    assert_eq!(resp.status, 101);
    assert_eq!(resp.header("sec-websocket-protocol"), Some("chat"));
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"hello","user":"anonymous"}"#
    );
    ws.send_close(1000).await;
    ws.expect_close(1000).await;
    drop(ws);
    let ws_log = control_get(v_control, "/log/ws").await;
    assert_eq!(
        handshake_entry(&ws_log, &ws_key(2))["subprotocol"],
        json!("chat")
    );

    // After POST /login the hello names alice and the handshake logs the cookie name.
    let v_session = login(v_base).await;
    let v_cookie = format!("session={v_session}");
    let (resp, mut ws) = ws_handshake(v_base, &ws_key(3), &[("Cookie", v_cookie.as_str())]).await;
    assert_eq!(resp.status, 101);
    assert_eq!(ws.read_text().await, r#"{"type":"hello","user":"alice"}"#);
    ws.send_close(1000).await;
    ws.expect_close(1000).await;
    drop(ws);
    let ws_log = control_get(v_control, "/log/ws").await;
    let hs = handshake_entry(&ws_log, &ws_key(3));
    assert_eq!(hs["cookie_names"], json!(["session"]));
    assert_eq!(hs["session_valid"], json!(true));
    assert_eq!(hs["origin"], Value::Null);
    let raw = serde_json::to_string(hs).expect("serialize handshake entry");
    assert!(
        !raw.contains(&v_session),
        "the raw session id must never reach the log: {raw}"
    );

    // A frame declaring 1 048 577 bytes is refused with 1009 on the header alone.
    let (resp, mut ws) = ws_handshake(v_base, &ws_key(4), &[]).await;
    assert_eq!(resp.status, 101);
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"hello","user":"anonymous"}"#
    );
    ws.send_raw(&oversize_header(WS_MAX_FRAME + 1)).await;
    ws.expect_close(1009).await;
    let oversize_conn = handshake_entry(&control_get(v_control, "/log/ws").await, &ws_key(4))
        ["conn_id"]
        .as_str()
        .expect("conn_id")
        .to_string();
    let ws_log = wait_for(v_control, "/log/ws", "1009 close entry", |body| {
        entries(body)
            .iter()
            .any(|e| e["kind"] == "close" && e["conn_id"] == oversize_conn.as_str())
    })
    .await;
    let close = entries(&ws_log)
        .iter()
        .find(|e| e["kind"] == "close" && e["conn_id"] == oversize_conn.as_str())
        .expect("close entry");
    assert_eq!(close["code"], json!(1009));
    drop(ws);

    // --- Patched ------------------------------------------------------------
    let p = TestTarget::builder(Patched)
        .control(0)
        .start()
        .await
        .expect("start P");
    let (p_base, p_control) = (p.base_url(), p.control_url().expect("control"));

    // A foreign Origin is forbidden.
    let (resp, _ws) = ws_handshake(p_base, &ws_key(5), &[("Origin", "http://evil.example")]).await;
    assert_eq!(resp.status, 403);
    assert_eq!(resp.text(), "<p>forbidden origin</p>");

    // No Origin and no cookie: login required.
    let (resp, _ws) = ws_handshake(p_base, &ws_key(6), &[]).await;
    assert_eq!(resp.status, 401);
    assert_eq!(resp.text(), "<p>login required</p>");

    let ws_log = control_get(p_control, "/log/ws").await;
    let hs5 = handshake_entry(&ws_log, &ws_key(5));
    assert_eq!(hs5["accepted"], json!(false));
    assert_eq!(hs5["status"], json!(403));
    let hs6 = handshake_entry(&ws_log, &ws_key(6));
    assert_eq!(hs6["accepted"], json!(false));
    assert_eq!(hs6["status"], json!(401));
    assert_eq!(hs6["session_valid"], json!(false));

    // No Origin plus the login cookie: upgraded, hello alice, escaped echo, no
    // subprotocol header even when one is requested.
    let p_session = login(p_base).await;
    let p_cookie = format!("session={p_session}");
    let (resp, mut ws) = ws_handshake(
        p_base,
        &ws_key(7),
        &[
            ("Cookie", p_cookie.as_str()),
            ("Sec-WebSocket-Protocol", "chat"),
        ],
    )
    .await;
    assert_eq!(resp.status, 101, "P logged in: {}", resp.text());
    assert_eq!(resp.header("sec-websocket-protocol"), None);
    assert_eq!(ws.read_text().await, r#"{"type":"hello","user":"alice"}"#);
    ws.send_text(r#"{"type":"echo","msg":"<i>"}"#).await;
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"echo","msg":"&lt;i&gt;","html":"<b>&lt;i&gt;</b>"}"#
    );
    ws.send_text(r#"{"type":"chat","msg":"x"}"#).await;
    assert_eq!(
        ws.read_text().await,
        r#"{"type":"chat","msg":"x","html":"<b>x</b>"}"#
    );
    ws.send_close(1000).await;
    ws.expect_close(1000).await;
    drop(ws);

    let ws_log = control_get(p_control, "/log/ws").await;
    let hs7 = handshake_entry(&ws_log, &ws_key(7));
    assert_eq!(hs7["accepted"], json!(true));
    assert_eq!(hs7["status"], json!(101));
    assert_eq!(hs7["session_valid"], json!(true));
    assert_eq!(hs7["cookie_names"], json!(["session"]));
    assert_eq!(hs7["subprotocol"], Value::Null);
}

/// D1 TLS row: `/ws` over an h2 connection is 400 `websocket requires HTTP/1.1`.
#[tokio::test]
async fn ws_over_h2_is_400() {
    let target = TestTarget::builder(Vulnerable)
        .tls(0)
        .control(0)
        .start()
        .await
        .expect("start target");
    let tls = target.tls_url().expect("tls listener");
    let control = target.control_url().expect("control origin");

    let mut send = h2_client(tls).await;
    let resp = h2_request(
        &mut send,
        &format!("{tls}/ws"),
        &[
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
        ],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.text(), "websocket requires HTTP/1.1");

    let http = control_get(control, "/log/http").await;
    let req = entries(&http)
        .iter()
        .find(|e| e["kind"] == "request" && e["path"] == "/ws")
        .unwrap_or_else(|| panic!("no /ws request entry: {http}"));
    assert_eq!(req["version"], json!("h2"));
    assert_eq!(req["status"], json!(400));
    let ws_log = control_get(control, "/log/ws").await;
    let hs = handshake_entry(&ws_log, "dGhlIHNhbXBsZSBub25jZQ==");
    assert_eq!(hs["accepted"], json!(false));
    assert_eq!(hs["status"], json!(400));
}

/// S6 over real sockets: the control origin serves nothing but D2, the
/// manifest and every seed id are 404 on both origins, and `/log/http`
/// stores cookie names and hashes but never a raw cookie or authorization.
#[tokio::test]
async fn control_is_separate_and_redacts() {
    let target = TestTarget::builder(Vulnerable)
        .control(0)
        .start()
        .await
        .expect("start target");
    let base = target.base_url();
    let control = target.control_url().expect("control origin");

    let (status, body) = control_get_status(control, "/").await;
    assert_eq!(status, 404);
    assert_eq!(body, json!({ "error": "not found" }));

    let mut paths = vec!["/manifest".to_string(), "/manifest.yaml".to_string()];
    paths.extend(manifest().iter().map(|v| format!("/{}", v.id)));
    assert!(paths.len() > 2, "manifest has rows");
    for path in &paths {
        let (status, body) = control_get_status(control, path).await;
        assert_eq!(status, 404, "control {path}: {body}");
        assert_eq!(body, json!({ "error": "not found" }), "control {path}");
        let resp = plain_get(base, path, &[]).await;
        assert_eq!(resp.status, 404, "target {path}: {}", resp.text());
    }

    let resp = plain_get(
        base,
        "/",
        &[
            ("Cookie", "session=abc; theme=dark"),
            ("Authorization", "Bearer x"),
            ("X-Probe", "1"),
        ],
    )
    .await;
    assert_eq!(resp.status, 200);

    let http = control_get(control, "/log/http").await;
    let entry = entries(&http)
        .iter()
        .rfind(|e| e["kind"] == "request")
        .expect("the request was logged");
    assert_eq!(entry["path"], json!("/"));
    assert_eq!(entry["listener"], json!("plain"));
    assert_eq!(entry["version"], json!("h1"));
    assert_eq!(entry["cookie_names"], json!(["session", "theme"]));
    // First 16 hex of SHA-256 over the raw header values.
    assert_eq!(entry["cookie_sha256"], json!("5c5fc99ebd5b1b93"));
    assert_eq!(entry["auth_sha256"], json!("b937a6fd6074f365"));
    for key in ["cookie_sha256", "auth_sha256"] {
        let hex = entry[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is a string"));
        assert_eq!(hex.len(), 16, "{key}");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{key}: {hex}");
    }
    assert_eq!(entry["headers"]["x-probe"], json!("1"));
    assert_eq!(
        entry["headers"]["host"],
        json!(authority(base)),
        "allowlisted header kept verbatim"
    );
    let raw = serde_json::to_string(entry).expect("serialize request entry");
    for forbidden in [r#""cookie""#, r#""authorization""#, "abc", "Bearer", "dark"] {
        assert!(!raw.contains(forbidden), "{forbidden:?} leaked into {raw}");
    }
    // The whole log, not just this entry, is free of the raw values.
    let whole = serde_json::to_string(&http).expect("serialize log");
    assert!(
        !whole.contains("abc") && !whole.contains("Bearer x"),
        "{whole}"
    );
}

/// D3 passive rows over TLS: P adds the three headers to `/`, V adds none.
#[tokio::test]
async fn patched_headers_over_tls() {
    let expected = [
        ("strict-transport-security", "max-age=31536000"),
        ("content-security-policy", "default-src 'self'"),
        ("x-content-type-options", "nosniff"),
    ];

    let p = TestTarget::builder(Patched)
        .tls(0)
        .start()
        .await
        .expect("start P");
    let p_tls = p.tls_url().expect("tls listener");
    let (mut stream, negotiated) = tls_connect(p_tls, &["http/1.1"]).await;
    assert_eq!(negotiated.as_deref(), Some(&b"http/1.1"[..]));
    let resp = h1_get(&mut stream, authority(p_tls), "/", &[]).await;
    assert_eq!(resp.status, 200);
    for (name, value) in expected {
        assert_eq!(resp.header(name), Some(value), "P {name}");
    }

    let v = TestTarget::builder(Vulnerable)
        .tls(0)
        .start()
        .await
        .expect("start V");
    let v_tls = v.tls_url().expect("tls listener");
    let (mut stream, _) = tls_connect(v_tls, &["http/1.1"]).await;
    let resp = h1_get(&mut stream, authority(v_tls), "/", &[]).await;
    assert_eq!(resp.status, 200);
    for (name, _) in expected {
        assert_eq!(resp.header(name), None, "V must not send {name}");
    }
}

/// D2 `/services`: every listener and every speaker, with D5 grammars and the
/// legacy L4 pair at `grammar: null`.
#[tokio::test]
async fn services_lists_everything() {
    let target = TestTarget::builder(Vulnerable)
        .tls(0)
        .tls_h1(0)
        .control(0)
        .l4(true)
        .start()
        .await
        .expect("start target with every listener");
    let control = target.control_url().expect("control origin");
    assert_eq!(target.l4_services().len(), 9);

    let body = control_get(control, "/services").await;
    assert_eq!(body["mode"], json!("vulnerable"));
    let services = body["services"].as_array().expect("services array");
    let names: BTreeSet<&str> = services.iter().filter_map(|s| s["name"].as_str()).collect();

    let grammars: [(&str, Option<&str>, &str); 11] = [
        ("l4-tlv-crash", Some("tlv"), "tcp"),
        ("l4-dns-fault", Some("dns"), "udp"),
        ("l4-udp-payload-crash", Some("raw"), "udp"),
        ("l4-resp", Some("resp"), "tcp"),
        ("l4-memcached", Some("memcached"), "tcp"),
        ("l4-modbus", Some("modbus"), "tcp"),
        ("l4-mqtt", Some("mqtt"), "tcp"),
        ("l4-smtp", Some("smtp"), "tcp"),
        ("l4-ftp", Some("ftp"), "tcp"),
        ("l4-udp-echo", None, "udp"),
        ("l4-tcp-service", None, "tcp"),
    ];
    let mut expected: BTreeSet<&str> = ["http", "tls", "tls_h1", "control"].into();
    expected.extend(grammars.iter().map(|(n, _, _)| *n));
    assert!(
        expected.is_subset(&names),
        "missing services: {:?}",
        expected.difference(&names).collect::<Vec<_>>()
    );

    let find = |name: &str| {
        services
            .iter()
            .find(|s| s["name"] == name)
            .unwrap_or_else(|| panic!("no service {name}"))
    };
    for (name, grammar, proto) in grammars {
        let s = find(name);
        assert_eq!(s["role"], json!("l4"), "{name}");
        assert_eq!(s["proto"], json!(proto), "{name}");
        assert_eq!(s["grammar"], json!(grammar), "{name}");
        assert!(
            s["addr"]
                .as_str()
                .is_some_and(|a| a.starts_with("127.0.0.1:")),
            "{name} binds loopback: {s}"
        );
    }
    for s in services.iter().filter(|s| s["role"] == "l4") {
        assert!(
            grammars.iter().any(|(n, _, _)| s["name"] == *n),
            "unexpected l4 service {s}"
        );
    }

    for (name, alpn) in [
        ("http", json!(["http/1.1"])),
        ("tls", json!(["h2", "http/1.1"])),
        ("tls_h1", json!(["http/1.1"])),
    ] {
        let s = find(name);
        assert_eq!(s["role"], json!("http"), "{name}");
        assert_eq!(s["proto"], json!("tcp"), "{name}");
        assert_eq!(s["alpn"], alpn, "{name}");
        assert_eq!(s.get("grammar"), None, "{name} is not an l4 row");
    }
    let c = find("control");
    assert_eq!(c["role"], json!("control"));
    assert_eq!(c.get("alpn"), None);
    assert_eq!(c["addr"], json!(authority(control)));
}
