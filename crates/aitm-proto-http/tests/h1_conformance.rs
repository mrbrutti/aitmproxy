//! HTTP/1 `Expect: 100-continue` and chunked-trailer conformance, end to end
//! over loopback.
//!
//! The unit tests in `module.rs`, `sender.rs` and `tests/sansio.rs` pin each
//! behaviour in isolation over in-memory streams. These tests check the same
//! behaviour against a real `Proxy`, real sockets and hand-rolled origins:
//!
//! - a client that sends `Expect: 100-continue` and holds its body back gets
//!   `100 Continue` from the proxy before it sends a byte of the body; the origin
//!   still receives the request exactly as the client sent it, its own interim is
//!   not forwarded, and the connection stays usable. An eager client that sends
//!   head and body together through a cleartext `CONNECT` tunnel gets one final
//!   response;
//! - the trailer section an origin writes after a chunked response body reaches a
//!   client that asked for trailers (minus the fields that cannot work as
//!   trailers), is stored on the flow beside the headers and never in them, and
//!   leaves the connection in step for the next exchange; a section over its caps
//!   ends the connection before any terminator is written;
//! - the replay sender returns the trailers of a chunked response.
//!
//! They bind loopback ports, so they run under the Terminal panel, not the Bash
//! sandbox (CLAUDE.md). Every wait on the network is bounded and fails with a
//! message naming what it was waiting for; there are no fixed ports.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, Config, Flow, FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpVersion, Proxy,
    RequestSender,
};
use aitm_proto_http::{CertAuthority, Http1Sender, HttpModule};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// The longest any single wait on the proxy, an origin or the store may take
/// before the test fails with a message instead of hanging.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the proxy has to answer an `Expect: 100-continue` head, which the
/// client has sent with no body behind it, with the interim response.
const INTERIM_WITHIN: Duration = Duration::from_secs(2);

/// The pause between the pieces a slow origin writes, so that they are likely to
/// reach the proxy in separate reads. Every assertion that depends on them holds
/// however the bytes are split; the pause only makes the split likely.
const PIECE_PAUSE: Duration = Duration::from_millis(50);

/// The interim response the proxy owes a client that expects one.
const CONTINUE: &str = "HTTP/1.1 100 Continue\r\n\r\n";

/// What the origin writes in answer to an upload: its own interim, then the
/// final response, in one write.
const INTERIM_THEN_302: &str = "HTTP/1.1 100 Continue\r\n\r\n\
                                HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n";

/// A plain keep-alive answer, for the exchange after one with trailers.
const PLAIN_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A chunked response's head and its one data chunk. The zero chunk and the
/// trailer section follow, written separately.
const CHUNKED_START: &str = "HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\n\
                             Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";

/// The trailer fields an origin sends that can work as trailers, as the lines it
/// writes (the last one ends the section).
const ALLOWED_SECTION: &[&str] = &["x-sum: abc\r\n", "x-e2e: m1\r\n\r\n"];

/// The same fields, as the client and the store hold them.
const ALLOWED_PAIRS: [(&str, &str); 2] = [("x-sum", "abc"), ("x-e2e", "m1")];

/// A trailer section whose middle fields (a framing field and a cookie) cannot
/// work as trailers and must not reach the client.
const MIXED_SECTION: &[&str] = &[
    "x-sum: abc\r\n",
    "Content-Length: 0\r\n",
    "Set-Cookie: s=1\r\n",
    "x-e2e: m1\r\n\r\n",
];

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-h1-conformance-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// `len` bytes that are not all alike, so a body that arrives truncated,
/// repeated or shifted differs from it.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
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

/// The fields of a header map, in order, as name and value pairs.
fn header_pairs(map: &HeaderMap) -> Vec<(&str, &str)> {
    map.iter().collect()
}

/// The fields of a decoded trailer section, in order, as name and value pairs.
fn as_pairs(fields: &[(String, String)]) -> Vec<(&str, &str)> {
    fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
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

/// One request an origin read off a connection.
struct Seen {
    /// The request head, request line through the blank line.
    head: String,
    /// The `Content-Length` bytes that follow the head.
    body: Vec<u8>,
}

/// Read one request: its head and the `Content-Length` bytes of body after it.
/// Bytes read past the request stay in `buf` for the next one. `None` once the
/// peer closes or errors.
async fn read_request<S: AsyncRead + Unpin>(io: &mut S, buf: &mut Vec<u8>) -> Option<Seen> {
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let len: usize = header_value(&head, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = buf[head_end..head_end + len].to_vec();
    buf.drain(..head_end + len);
    Some(Seen { head, body })
}

/// Every request a recording origin has read, in the order it read them.
type Log = Arc<Mutex<Vec<Seen>>>;

/// An origin that records each request it reads, head and whole body, and answers
/// an upload (a `POST`) with its own `100 Continue` followed by a `302`, written
/// together. Any other request gets a `200` whose body names the path it asked
/// for. Every connection is kept alive.
async fn spawn_recording_origin() -> (Origin, Log) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    let origin = spawn_origin(move |mut tcp, _conn_no| {
        let seen = seen.clone();
        async move {
            let mut buf = Vec::new();
            while let Some(request) = read_request(&mut tcp, &mut buf).await {
                let reply = if request.head.starts_with("POST ") {
                    INTERIM_THEN_302.to_string()
                } else {
                    let path = request.head.split_whitespace().nth(1).unwrap_or("");
                    let body = format!("path={path}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                seen.lock().expect("origin log").push(request);
                if tcp.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
            }
        }
    })
    .await;
    (origin, log)
}

/// An origin that answers its connection's first request with a chunked response
/// whose trailer section arrives in pieces, then answers any later request on the
/// connection with [`PLAIN_OK`]. The head, the data chunk and the zero chunk go
/// out in one write; each entry of `section` follows in a write of its own after
/// a pause.
async fn spawn_trailers_origin(section: &'static [&'static str]) -> Origin {
    spawn_origin(move |mut tcp, _conn_no| async move {
        let _ = tcp.set_nodelay(true);
        let mut buf = Vec::new();
        if read_request(&mut tcp, &mut buf).await.is_none() {
            return;
        }
        let first = format!("{CHUNKED_START}0\r\n");
        if tcp.write_all(first.as_bytes()).await.is_err() {
            return;
        }
        for piece in section {
            tokio::time::sleep(PIECE_PAUSE).await;
            if tcp.write_all(piece.as_bytes()).await.is_err() {
                return;
            }
        }
        while read_request(&mut tcp, &mut buf).await.is_some() {
            if tcp.write_all(PLAIN_OK.as_bytes()).await.is_err() {
                return;
            }
        }
    })
    .await
}

/// An origin that answers its first request with a chunked response, writes the
/// head and the data chunk at once, then holds a trailer section of 65 fields
/// (one over the cap) back until `go` is signalled, and writes it in one go. It
/// then keeps its end of the connection open until the proxy closes it, so the
/// proxy's only reason to end the response is the section.
async fn spawn_over_cap_origin(go: Arc<Notify>) -> Origin {
    spawn_origin(move |mut tcp, _conn_no| {
        let go = go.clone();
        async move {
            let mut buf = Vec::new();
            if read_request(&mut tcp, &mut buf).await.is_none() {
                return;
            }
            if tcp.write_all(CHUNKED_START.as_bytes()).await.is_err() {
                return;
            }
            if tokio::time::timeout(IO_TIMEOUT, go.notified())
                .await
                .is_err()
            {
                return;
            }
            let fields: String = (0..65).map(|n| format!("f{n}: v\r\n")).collect();
            let section = format!("0\r\n{fields}\r\n");
            if tcp.write_all(section.as_bytes()).await.is_err() {
                return;
            }
            let mut sink = [0u8; 1024];
            while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// Run a `Proxy` (the passive listener, which relays to any address without a
/// scope gate) with the HTTP module (a fresh CA) and no plugins, on a loopback
/// listener bound here before the proxy starts, so connections made at once
/// queue until it accepts them. Returns the proxy address and the proxy's flow
/// store (taken before the proxy moves into its task).
async fn run_proxy() -> (SocketAddr, Arc<dyn FlowStore>) {
    let ca = Arc::new(CertAuthority::load_or_generate(&temp_dir(), 0o600).expect("CA"));
    let module = HttpModule::with_ca(ca).with_insecure(true);
    let proxy = Proxy::builder()
        .with_config(Config::default())
        .register_module(Arc::new(module))
        .build()
        .expect("build proxy");
    let store = proxy.store();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the proxy listener");
    let addr = listener.local_addr().expect("proxy listener address");
    tokio::spawn(async move {
        let _ = proxy.run_on(listener).await;
    });
    (addr, store)
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// A response with a `Content-Length` body, as the client read it.
struct Reply {
    /// The status of every interim (`1xx`) head that arrived ahead of the final one.
    interim: Vec<u16>,
    /// The final response's status.
    status: u16,
    /// The final response's head, status line through its last header.
    head: String,
    body: Vec<u8>,
}

/// A chunked response, decoded: its data chunks joined and its trailer section.
struct ChunkedReply {
    body: Vec<u8>,
    /// The trailer fields in the order they arrived, name and value as sent.
    trailers: Vec<(String, String)>,
}

/// A keep-alive HTTP/1.1 client over one TCP connection. Bytes read past one
/// response stay in `buf` for the next, so many exchanges ride one connection and
/// a byte the proxy wrote out of turn cannot be silently dropped.
struct Client {
    io: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    fn new(io: TcpStream) -> Self {
        Self {
            io,
            buf: Vec::new(),
        }
    }

    /// Write `bytes` and flush, bounded by `IO_TIMEOUT`.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        tokio::time::timeout(IO_TIMEOUT, async {
            self.io
                .write_all(bytes)
                .await
                .map_err(|e| format!("send: {e}"))?;
            self.io.flush().await.map_err(|e| format!("flush: {e}"))
        })
        .await
        .map_err(|_| format!("timed out sending {} bytes", bytes.len()))?
    }

    /// Read once more into `buf`; an error when the peer has closed.
    async fn fill(&mut self) -> Result<(), String> {
        let mut chunk = [0u8; 4096];
        match self.io.read(&mut chunk).await {
            Ok(0) => Err(format!(
                "the connection closed with {:?} unread",
                String::from_utf8_lossy(&self.buf)
            )),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
            Err(e) => Err(format!("read: {e}")),
        }
    }

    /// Take `n` bytes off the front of `buf`, reading until they are there.
    async fn take(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            self.fill().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Take everything up to and including the next `delimiter` off the front of
    /// `buf`, reading until it is there, and return it without the delimiter.
    async fn take_until(&mut self, delimiter: &[u8]) -> Result<Vec<u8>, String> {
        loop {
            if let Some(i) = self
                .buf
                .windows(delimiter.len())
                .position(|w| w == delimiter)
            {
                let mut taken: Vec<u8> = self.buf.drain(..i + delimiter.len()).collect();
                taken.truncate(i);
                return Ok(taken);
            }
            self.fill().await?;
        }
    }

    /// Exactly the next `n` bytes the peer sends, within `within`.
    async fn read_exactly(&mut self, n: usize, within: Duration) -> Result<Vec<u8>, String> {
        let outcome = tokio::time::timeout(within, self.take(n)).await;
        match outcome {
            Ok(result) => result,
            Err(_) => Err(format!(
                "{} of {n} bytes arrived within {within:?}: {:?}",
                self.buf.len(),
                String::from_utf8_lossy(&self.buf)
            )),
        }
    }

    /// Everything the peer sends until it closes the connection.
    async fn read_to_eof(&mut self) -> Result<Vec<u8>, String> {
        tokio::time::timeout(IO_TIMEOUT, async {
            let mut chunk = [0u8; 4096];
            loop {
                match self.io.read(&mut chunk).await {
                    Ok(0) => return Ok(std::mem::take(&mut self.buf)),
                    Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                    Err(e) => return Err(format!("read: {e}")),
                }
            }
        })
        .await
        .map_err(|_| "timed out waiting for the connection to close".to_string())?
    }

    /// Read one response with a `Content-Length` body, recording the status of
    /// any interim head that comes before the final one. The whole read is
    /// bounded by `IO_TIMEOUT`.
    async fn read_reply(&mut self) -> Result<Reply, String> {
        tokio::time::timeout(IO_TIMEOUT, async {
            let mut interim = Vec::new();
            loop {
                let head = self.take_until(b"\r\n\r\n").await?;
                let head = String::from_utf8_lossy(&head).into_owned();
                let status = status_of(&head)?;
                if (100..200).contains(&status) {
                    interim.push(status);
                    continue;
                }
                let len: usize = header_value(&head, "content-length")
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| format!("no Content-Length in {head:?}"))?;
                let body = self.take(len).await?;
                return Ok(Reply {
                    interim,
                    status,
                    head,
                    body,
                });
            }
        })
        .await
        .map_err(|_| "timed out waiting for a complete response".to_string())?
    }

    /// Send `GET target` with `Host: host` and read its response.
    async fn get(&mut self, target: &str, host: &str) -> Result<Reply, String> {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        self.send(request.as_bytes()).await?;
        self.read_reply()
            .await
            .map_err(|e| format!("GET {target}: {e}"))
    }

    /// Read one chunked response and decode it: the chunks, then the trailer
    /// section up to the blank line that ends the message. The whole read is
    /// bounded by `IO_TIMEOUT`.
    async fn read_chunked_reply(&mut self) -> Result<ChunkedReply, String> {
        tokio::time::timeout(IO_TIMEOUT, async {
            let head = self.take_until(b"\r\n\r\n").await?;
            let head = String::from_utf8_lossy(&head).into_owned();
            let framing = header_value(&head, "transfer-encoding");
            if !framing
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
            {
                return Err(format!("the response is not chunked: {head:?}"));
            }
            let mut body = Vec::new();
            loop {
                let line = self.take_until(b"\r\n").await?;
                let line = String::from_utf8_lossy(&line).into_owned();
                let size = usize::from_str_radix(line.trim(), 16)
                    .map_err(|_| format!("bad chunk size line {line:?}"))?;
                if size == 0 {
                    break;
                }
                let chunk = self.take(size + 2).await?;
                if !chunk.ends_with(b"\r\n") {
                    return Err(format!("a chunk of {size} bytes is not followed by CRLF"));
                }
                body.extend_from_slice(&chunk[..size]);
            }
            let mut trailers = Vec::new();
            loop {
                let line = self.take_until(b"\r\n").await?;
                if line.is_empty() {
                    break;
                }
                let line = String::from_utf8_lossy(&line).into_owned();
                let (name, value) = line
                    .split_once(':')
                    .ok_or_else(|| format!("bad trailer line {line:?}"))?;
                trailers.push((name.to_string(), value.trim().to_string()));
            }
            Ok(ChunkedReply { body, trailers })
        })
        .await
        .map_err(|_| "timed out waiting for the end of a chunked response".to_string())?
    }
}

/// The status code of a response head.
fn status_of(head: &str) -> Result<u16, String> {
    head.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line in {head:?}"))
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

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Whether the flow's stored response is complete: its body has stopped
/// streaming. A response reaches the client before the store holds its final
/// body, and a response with no body ends as `Body::Empty`, so this is what
/// "the store has caught up" means for every response here.
fn response_complete(flow: &HttpFlow) -> bool {
    flow.response
        .as_ref()
        .is_some_and(|r| !matches!(r.body, Body::Streamed(_)))
}

/// Poll up to `IO_TIMEOUT` until the store holds the HTTP flow whose request
/// path is `path` with a complete response, and return it.
async fn wait_for_flow(store: &Arc<dyn FlowStore>, path: &str) -> HttpFlow {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let found = store.list().into_iter().find_map(|id| match store.get(id) {
            Some(Flow::Http(h)) if h.request.path == path && response_complete(&h) => Some(h),
            _ => None,
        });
        if let Some(flow) = found {
            return flow;
        }
        assert!(
            Instant::now() < deadline,
            "the store never held a completed HTTP flow for {path}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Shared checks
// ---------------------------------------------------------------------------

/// The origin received the upload exactly once, with the client's `Expect` header
/// untouched and all of `body`.
fn assert_origin_saw_the_upload_once(log: &Log, body: &[u8]) {
    let log = log.lock().expect("origin log");
    let uploads: Vec<&Seen> = log.iter().filter(|r| r.head.starts_with("POST ")).collect();
    assert_eq!(
        uploads.len(),
        1,
        "the origin must receive the upload exactly once"
    );
    let upload = uploads[0];
    assert_eq!(
        header_value(&upload.head, "expect")
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("100-continue"),
        "the Expect header must reach the origin untouched: {:?}",
        upload.head
    );
    assert_eq!(
        upload.body.len(),
        body.len(),
        "the origin must receive the whole body, and only the body"
    );
    assert!(
        upload.body == body,
        "the body the origin received differs from the one the client sent"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A strict client holds its body back until it is told to go ahead. The proxy
/// answers the head with its own `100 Continue` before it has seen a byte of the
/// body (so before it can have contacted the origin), the interim reaches the
/// client exactly once, the origin still gets the request as the client sent it
/// with its own interim skipped, and the same connection then serves a plain
/// request with nothing left over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_strict_expect_client_gets_100_continue_before_it_sends_the_body() {
    let (origin, log) = spawn_recording_origin().await;
    let (proxy, store) = run_proxy().await;
    let host = origin.addr.to_string();
    let body = pattern(65536);
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let head = format!(
        "POST http://{host}/up HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\
         Expect: 100-continue\r\n\r\n",
        body.len()
    );
    client
        .send(head.as_bytes())
        .await
        .expect("send the upload's head, with no body behind it");
    let interim = client
        .read_exactly(CONTINUE.len(), INTERIM_WITHIN)
        .await
        .expect("the proxy never answered the Expect: 100-continue head with 100 Continue");
    assert_eq!(
        String::from_utf8_lossy(&interim),
        CONTINUE,
        "the first bytes the proxy writes must be exactly the interim response"
    );
    assert_eq!(
        origin.accepted(),
        0,
        "the 100 must come from the proxy: it has not seen the body, so it cannot have \
         contacted the origin yet"
    );

    client.send(&body).await.expect("send the upload's body");
    let reply = client
        .read_reply()
        .await
        .expect("the final response to the upload");
    assert!(
        reply.interim.is_empty(),
        "a second interim reached the client, or the origin's own did: {:?}",
        reply.interim
    );
    assert_eq!(reply.status, 302, "the final response is the origin's 302");
    assert_eq!(header_value(&reply.head, "location").as_deref(), Some("/c"));
    assert!(reply.body.is_empty());

    let next = client
        .get(&format!("http://{host}/next"), &host)
        .await
        .expect("a plain request on the connection the upload used");
    assert!(
        next.interim.is_empty(),
        "an interim leaked into the next exchange: {:?}",
        next.interim
    );
    assert_eq!(next.status, 200);
    assert_eq!(next.body, b"path=/next");
    assert!(
        client.buf.is_empty(),
        "bytes the client did not ask for arrived: {:?}",
        String::from_utf8_lossy(&client.buf)
    );
    assert_eq!(
        origin.accepted(),
        1,
        "skipping the origin's interim must leave its connection reusable, not replaced"
    );
    assert_origin_saw_the_upload_once(&log, &body);

    let flow = wait_for_flow(&store, "/up").await;
    let response = flow.response.as_ref().expect("stored response");
    assert_eq!(
        response.status, 302,
        "the stored response is the final one, never an interim"
    );
    assert_eq!(flow.request.headers.get("expect"), Some("100-continue"));
    assert!(
        matches!(&flow.request.body, Body::Bytes(b) if b.as_slice() == body.as_slice()),
        "the stored request must hold the whole upload"
    );
}

/// An eager client sends its head and body together without waiting, through a
/// cleartext CONNECT tunnel. It gets one final response: at most one interim, and
/// only a `100`. The origin sees the upload once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_eager_expect_client_in_a_cleartext_tunnel_gets_one_final_response() {
    let (origin, log) = spawn_recording_origin().await;
    let (proxy, _store) = run_proxy().await;
    let host = origin.addr.to_string();
    let body = pattern(4096);
    let mut client = Client::new(connect_tunnel(proxy, origin.addr).await);

    let mut request = format!(
        "POST /up HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    client
        .send(&request)
        .await
        .expect("send the upload's head and body in one write");

    let reply = client
        .read_reply()
        .await
        .expect("the final response to the upload");
    assert_eq!(reply.status, 302, "the final response is the origin's 302");
    assert!(
        reply.interim.len() <= 1 && reply.interim.iter().all(|&status| status == 100),
        "an eager client may get one 100 and nothing else before the final response: {:?}",
        reply.interim
    );
    assert_eq!(header_value(&reply.head, "location").as_deref(), Some("/c"));
    assert!(client.buf.is_empty(), "bytes followed the final response");
    assert_eq!(
        origin.accepted(),
        1,
        "the tunnel must reach the origin it was opened to"
    );
    assert_origin_saw_the_upload_once(&log, &body);
}

/// The trailer fields an origin writes after a chunked body, in pieces, reach a
/// client that sent `TE: trailers`, in order, after the body. The next request on
/// the connection is answered intact from the same upstream connection, and the
/// stored flow holds the trailers beside the headers, never in them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_trailers_reach_the_client_and_the_store() {
    let origin = spawn_trailers_origin(ALLOWED_SECTION).await;
    let (proxy, store) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let request = format!(
        "GET http://{host}/t HTTP/1.1\r\nHost: {host}\r\nTE: trailers\r\nConnection: TE\r\n\r\n"
    );
    client
        .send(request.as_bytes())
        .await
        .expect("send the request that asks for trailers");
    let reply = client
        .read_chunked_reply()
        .await
        .expect("the chunked response and its trailer section");
    assert_eq!(reply.body, b"hello");
    assert_eq!(
        as_pairs(&reply.trailers),
        ALLOWED_PAIRS.to_vec(),
        "the client must receive every trailer field the origin sent, in order"
    );

    let next = client
        .get(&format!("http://{host}/plain"), &host)
        .await
        .expect("a plain request after the response with trailers");
    assert_eq!(next.status, 200);
    assert_eq!(next.body, b"ok", "the next response must arrive intact");
    assert!(
        client.buf.is_empty(),
        "bytes the client did not ask for arrived: {:?}",
        String::from_utf8_lossy(&client.buf)
    );
    assert_eq!(
        origin.accepted(),
        1,
        "the connection must stay in step, so the upstream is reused, not replaced"
    );

    let flow = wait_for_flow(&store, "/t").await;
    let response = flow.response.as_ref().expect("stored response");
    assert_eq!(header_pairs(&response.trailers), ALLOWED_PAIRS.to_vec());
    assert_eq!(
        response.headers.get("x-sum"),
        None,
        "a trailer is never merged into the headers"
    );
    assert_eq!(response.headers.get("x-e2e"), None);
    assert!(matches!(&response.body, Body::Bytes(b) if b.as_slice() == b"hello"));
}

/// A trailer field that cannot work as a trailer (a framing field, a cookie) is
/// withheld from the client, which still gets the others in order and a message
/// that ends where it should, while the stored flow keeps every field the origin
/// sent, in order, apart from the headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forbidden_trailer_is_withheld_from_the_wire_but_kept_in_the_store() {
    let origin = spawn_trailers_origin(MIXED_SECTION).await;
    let (proxy, store) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    let request = format!(
        "GET http://{host}/t HTTP/1.1\r\nHost: {host}\r\nTE: trailers\r\nConnection: TE\r\n\r\n"
    );
    client
        .send(request.as_bytes())
        .await
        .expect("send the request that asks for trailers");
    let reply = client
        .read_chunked_reply()
        .await
        .expect("the chunked response and its trailer section");
    assert_eq!(reply.body, b"hello");
    assert_eq!(
        as_pairs(&reply.trailers),
        ALLOWED_PAIRS.to_vec(),
        "only the fields that can work as trailers may reach the client"
    );

    let next = client
        .get(&format!("http://{host}/plain"), &host)
        .await
        .expect("a plain request after the response with trailers");
    assert_eq!(next.status, 200);
    assert_eq!(next.body, b"ok", "the next response must arrive intact");
    assert!(
        client.buf.is_empty(),
        "bytes the client did not ask for arrived: {:?}",
        String::from_utf8_lossy(&client.buf)
    );

    let flow = wait_for_flow(&store, "/t").await;
    let response = flow.response.as_ref().expect("stored response");
    assert_eq!(
        header_pairs(&response.trailers),
        vec![
            ("x-sum", "abc"),
            ("Content-Length", "0"),
            ("Set-Cookie", "s=1"),
            ("x-e2e", "m1"),
        ],
        "the capture keeps every field the origin sent, forwarded or not"
    );
    for name in ["x-sum", "x-e2e", "content-length", "set-cookie"] {
        assert_eq!(
            response.headers.get(name),
            None,
            "the trailer {name} must not appear among the headers"
        );
    }
}

/// A trailer section over its caps (65 fields) ends the connection. The client has
/// already received the head and the data chunk, and then sees EOF: the message
/// is never closed with a terminator that would claim it was complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trailer_section_over_the_cap_ends_the_connection_without_a_terminator() {
    let go = Arc::new(Notify::new());
    let origin = spawn_over_cap_origin(go.clone()).await;
    let (proxy, _store) = run_proxy().await;
    let host = origin.addr.to_string();
    let mut client = Client::new(TcpStream::connect(proxy).await.expect("connect proxy"));

    client
        .send(format!("GET http://{host}/t HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("send the request");
    let start = client
        .read_exactly(CHUNKED_START.len(), IO_TIMEOUT)
        .await
        .expect("the response head and its data chunk");
    assert_eq!(
        String::from_utf8_lossy(&start),
        CHUNKED_START,
        "the proxy must forward the head and the chunk as they arrive"
    );

    // The client has the chunk, so the origin may send the section that breaks the
    // cap; the proxy will have forwarded the chunk before it parses the section.
    go.notify_one();
    let rest = client
        .read_to_eof()
        .await
        .expect("the proxy never closed the connection after a trailer section over its cap");
    assert!(
        rest.is_empty(),
        "nothing may follow the chunk, least of all a terminator: {:?}",
        String::from_utf8_lossy(&rest)
    );
}

/// `Http1Sender`, which `request.send` and `flow.replay` use, returns the trailers
/// of a chunked response beside its headers, with the body intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_replay_sender_returns_the_trailers_of_a_chunked_response() {
    let origin = spawn_trailers_origin(ALLOWED_SECTION).await;
    let request = HttpRequest {
        method: "GET".into(),
        scheme: "http".into(),
        authority: origin.addr.to_string(),
        path: "/t".into(),
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
    assert_eq!(header_pairs(&response.trailers), ALLOWED_PAIRS.to_vec());
    assert_eq!(
        response.headers.get("x-sum"),
        None,
        "a trailer is never merged into the headers"
    );
    assert_eq!(response.headers.get("trailer"), Some("x-sum, x-e2e"));
    match response.body {
        Body::Bytes(bytes) => assert_eq!(bytes, b"hello".to_vec()),
        other => panic!("expected the buffered chunked body, got {other:?}"),
    }
}
