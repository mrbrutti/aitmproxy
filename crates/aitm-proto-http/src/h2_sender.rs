//! The HTTP/2 half of [`crate::sender::HttpSender`]: one `h2::client`
//! handshake per authority, reused while it stays idle and healthy, and one
//! request/response stream per send.
//!
//! The handshake mirrors the proxy's own outbound path (`crate::h2`'s
//! `Upstreams::open`) — push disabled, the same header-list and header-table
//! limits — so a probe looks on the wire like the traffic the proxy already
//! forwards. Heads are converted by [`crate::translate`], which sets
//! `HttpVersion::H2` on the response and strips the hop-by-hop names that are
//! illegal in HTTP/2 (so no `Connection: close` ever reaches an h2 origin).
//!
//! There is no retry loop here: a reused connection that fails is removed from
//! the pool and the error is returned to the caller, which owns the retry
//! policy (the scanner's probe-error ladder).

use std::collections::HashMap;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use aitm_core::{Body, HttpRequest, HttpResponse};
use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use h2::client::SendRequest;

use crate::sender::ProbeStream;

/// Mirrors `crate::h2`'s outbound settings (the constants there are private to
/// that module, so the sender carries its own copies of the same values).
const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
/// Mirrors `crate::h2`'s outbound HPACK table size.
const HEADER_TABLE_SIZE: u32 = 4 * 1024;
/// Bound on a single h2 **wire** await — the handshake, a frame read, the
/// response future, a send-capacity wait — so a peer that stalls mid-exchange
/// cannot pin the stream open. The whole exchange is additionally bounded by
/// the sender's response timeout.
const H2_WIRE_TIMEOUT: Duration = Duration::from_secs(30);
/// The response-body cap, matching the h1 path in [`crate::sender`].
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// One live h2 connection per authority, reused while idle.
///
/// The map is capped at [`MAX_POOLED_AUTHORITIES`]: past that, an exchange
/// still runs on its own fresh connection, it is simply not remembered.
#[derive(Default)]
pub(crate) struct H2Pool {
    conns: Mutex<HashMap<String, SendRequest<Bytes>>>,
}

/// How many authorities the sender keeps an open h2 connection to.
pub(crate) const MAX_POOLED_AUTHORITIES: usize = 8;

impl H2Pool {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A handle for `authority` when the pooled connection is ready to carry
    /// another stream. A connection that has errored (GOAWAY, a closed socket)
    /// is dropped from the pool and `None` is returned, so the caller redials.
    /// `None` is also returned while the connection is merely busy — the caller
    /// opens a second one rather than queueing behind it.
    pub(crate) fn take(&self, authority: &str) -> Option<SendRequest<Bytes>> {
        let mut conns = self.conns.lock().ok()?;
        let entry = conns.get_mut(authority)?;
        // A no-op waker: this is a readiness *probe*, not a wait. Nothing is
        // ever woken through it, and the next send polls again.
        let mut cx = Context::from_waker(Waker::noop());
        match entry.poll_ready(&mut cx) {
            Poll::Ready(Ok(())) => Some(entry.clone()),
            Poll::Ready(Err(_)) => {
                conns.remove(authority);
                None
            }
            Poll::Pending => None,
        }
    }

    /// Remember `send_req` for `authority`, replacing any previous handle.
    fn store(&self, authority: &str, send_req: SendRequest<Bytes>) {
        if let Ok(mut conns) = self.conns.lock() {
            if conns.len() >= MAX_POOLED_AUTHORITIES && !conns.contains_key(authority) {
                return;
            }
            conns.insert(authority.to_string(), send_req);
        }
    }

    /// Forget the connection to `authority` (it failed mid-exchange).
    fn remove(&self, authority: &str) {
        if let Ok(mut conns) = self.conns.lock() {
            conns.remove(authority);
        }
    }
}

/// Run one request/response exchange over a **new** h2 connection on `stream`,
/// remembering the connection in `pool` for the next send to `authority`.
///
/// `stream` is already the right transport: a TLS stream that negotiated ALPN
/// `h2`, or a plain one for prior-knowledge h2c.
pub(crate) async fn exchange(
    pool: &H2Pool,
    stream: Box<dyn ProbeStream>,
    authority: &str,
    req: &HttpRequest,
    response_timeout: Duration,
) -> Result<HttpResponse> {
    let send_req = handshake(stream, authority).await?;
    pool.store(authority, send_req.clone());
    exchange_pooled(pool, send_req, authority, req, response_timeout).await
}

/// Run one request/response exchange over an already-open connection taken
/// from `pool`. A failure drops the connection from the pool and is returned
/// as-is: the caller, not this layer, decides whether to try again.
pub(crate) async fn exchange_pooled(
    pool: &H2Pool,
    send_req: SendRequest<Bytes>,
    authority: &str,
    req: &HttpRequest,
    response_timeout: Duration,
) -> Result<HttpResponse> {
    let result = match tokio::time::timeout(response_timeout, stream_exchange(send_req, req)).await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "h2 exchange with {authority} timed out after {response_timeout:?}"
        )),
    };
    if result.is_err() {
        pool.remove(authority);
    }
    result
}

/// Handshake a new h2 client connection, with the same settings the proxy's
/// own upstream path uses, and drive it on its own task.
async fn handshake(stream: Box<dyn ProbeStream>, authority: &str) -> Result<SendRequest<Bytes>> {
    let (send_req, connection) = wire(
        "handshake",
        h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .header_table_size(HEADER_TABLE_SIZE)
            .handshake::<_, Bytes>(stream),
    )
    .await?
    .with_context(|| format!("h2 handshake with {authority}"))?;
    let label = authority.to_string();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!("h2 connection to {label} ended with error: {e}");
        }
    });
    Ok(send_req)
}

/// One stream on an open connection: send the head (and body), read the head,
/// the body up to [`MAX_RESPONSE_BYTES`], and the trailers.
async fn stream_exchange(send_req: SendRequest<Bytes>, req: &HttpRequest) -> Result<HttpResponse> {
    let head = crate::translate::h2_request_from(req);
    let body = match &req.body {
        Body::Bytes(bytes) => bytes.clone(),
        _ => Vec::new(),
    };
    let end_of_stream = body.is_empty();

    let mut ready = wire("connection ready", send_req.ready())
        .await?
        .context("h2 connection not ready")?;
    let (response, mut send_stream) = ready
        .send_request(head, end_of_stream)
        .context("send h2 request")?;
    if !end_of_stream {
        send_body(&mut send_stream, Bytes::from(body)).await?;
        send_stream
            .send_data(Bytes::new(), true)
            .context("end h2 request")?;
    }

    let response = wire("response", response)
        .await?
        .context("await h2 response")?;
    let (parts, mut recv) = response.into_parts();
    // `response_from_h2` is what marks the result `HttpVersion::H2`.
    let head = crate::translate::response_from_h2(&parts);

    let mut buffered: Vec<u8> = Vec::new();
    let mut capped = false;
    while let Some(chunk) = wire("response body read", recv.data()).await? {
        let chunk = chunk.context("read h2 response body")?;
        let room = MAX_RESPONSE_BYTES.saturating_sub(buffered.len());
        let take = room.min(chunk.len());
        buffered.extend_from_slice(&chunk[..take]);
        // Release what was consumed so the peer keeps its window; then stop at
        // the cap rather than draining a body we would only throw away. The
        // dropped `RecvStream` makes `h2` reset the stream, which leaves the
        // pooled connection usable.
        let _ = recv.flow_control().release_capacity(chunk.len());
        if buffered.len() >= MAX_RESPONSE_BYTES {
            capped = true;
            break;
        }
    }

    let mut trailers = aitm_core::HeaderMap::new();
    if !capped {
        if let Some(fields) = wire("response trailers", recv.trailers())
            .await?
            .context("read h2 response trailers")?
        {
            for (name, value) in fields.iter() {
                if let Ok(value) = value.to_str() {
                    trailers.set(name.as_str(), value);
                }
            }
        }
    }

    Ok(HttpResponse {
        body: if buffered.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(buffered)
        },
        trailers,
        timestamp: std::time::SystemTime::now(),
        ..head
    })
}

/// Write `data` onto an h2 send stream, honouring flow control (a copy of
/// `crate::h2`'s private `send_body`, which is not visible from here). Never
/// sets end-of-stream; the caller sends the final empty frame.
async fn send_body(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let assigned = wire(
            "send capacity",
            std::future::poll_fn(|cx| send.poll_capacity(cx)),
        )
        .await?
        .ok_or_else(|| anyhow!("h2 stream closed before the body was sent"))?
        .context("h2 send-capacity error")?;
        let take = assigned.min(data.len());
        let piece = data.split_to(take);
        send.send_data(piece, false).context("send h2 data frame")?;
    }
    Ok(())
}

/// Bound one h2 wire await by [`H2_WIRE_TIMEOUT`].
async fn wire<F, T>(what: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(H2_WIRE_TIMEOUT, fut)
        .await
        .map_err(|_| anyhow!("h2 {what} timed out after {H2_WIRE_TIMEOUT:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use aitm_core::{Body, HeaderMap, HttpRequest, HttpVersion, RequestSender, VersionPolicy};
    use anyhow::{anyhow, Result};
    use bytes::Bytes;
    use futures::future::BoxFuture;
    use tokio::io::{duplex, DuplexStream};

    use crate::sender::{Dialer, HostResolver, HttpSender, ProbeStream};

    /// What one h2 origin saw on one stream.
    #[derive(Debug, Clone)]
    struct SeenRequest {
        method: String,
        path: String,
        scheme: String,
        header_names: Vec<String>,
    }

    type Seen = Arc<Mutex<Vec<SeenRequest>>>;

    fn record(seen: &Seen, parts: &http::request::Parts) {
        if let Ok(mut log) = seen.lock() {
            log.push(SeenRequest {
                method: parts.method.as_str().to_string(),
                path: parts.uri.path().to_string(),
                scheme: parts.uri.scheme_str().unwrap_or_default().to_string(),
                header_names: parts
                    .headers
                    .keys()
                    .map(|k| k.as_str().to_string())
                    .collect(),
            });
        }
    }

    /// An h2 origin over one duplex half: record every stream it accepts and
    /// answer it `200` with `body`. With `goaway`, it shuts the connection down
    /// abruptly after the first stream, so the client's pooled handle goes bad.
    async fn h2_origin(io: DuplexStream, body: &'static [u8], seen: Seen, goaway: bool) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        while let Some(accepted) = conn.accept().await {
            let Ok((req, mut respond)) = accepted else {
                break;
            };
            let (parts, mut rbody) = req.into_parts();
            while let Some(Ok(chunk)) = rbody.data().await {
                let _ = rbody.flow_control().release_capacity(chunk.len());
            }
            record(&seen, &parts);
            let Ok(resp) = http::Response::builder().status(200).body(()) else {
                break;
            };
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from_static(body), true);
            }
            if goaway {
                // GOAWAY once this stream has been answered: the response the
                // client is already waiting for still arrives, and the
                // connection is unusable for the next one.
                conn.graceful_shutdown();
            }
        }
    }

    /// Stream `total` bytes onto `send`, honouring h2 flow control. Runs as its
    /// own task so the origin's accept loop keeps driving the connection.
    async fn pump(mut send: h2::SendStream<Bytes>, total: usize) {
        let chunk = vec![b'a'; 64 * 1024];
        let mut left = total;
        while left > 0 {
            let want = chunk.len().min(left);
            send.reserve_capacity(want);
            let Some(Ok(assigned)) = std::future::poll_fn(|cx| send.poll_capacity(cx)).await else {
                return;
            };
            let take = assigned.min(want);
            if send
                .send_data(Bytes::copy_from_slice(&chunk[..take]), false)
                .is_err()
            {
                return;
            }
            left -= take;
        }
        let _ = send.send_data(Bytes::new(), true);
    }

    /// An h2 origin that answers one stream with a `total`-byte body.
    async fn streaming_h2_origin(io: DuplexStream, total: usize) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        let pumping = match conn.accept().await {
            Some(Ok((_req, mut respond))) => http::Response::builder()
                .status(200)
                .body(())
                .ok()
                .and_then(|resp| respond.send_response(resp, false).ok())
                .map(|send| tokio::spawn(pump(send, total))),
            _ => None,
        };
        while conn.accept().await.is_some() {}
        if let Some(task) = pumping {
            task.abort();
        }
    }

    /// An h2 origin that accepts streams and never answers them.
    async fn silent_h2_origin(io: DuplexStream) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        let mut held = Vec::new();
        while let Some(accepted) = conn.accept().await {
            let Ok((_req, respond)) = accepted else {
                break;
            };
            held.push(respond);
        }
    }

    /// Every name resolves to loopback, so the dial seam decides what is talked
    /// to (copied from `sender.rs`'s test module).
    struct FixedResolver;

    impl HostResolver for FixedResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
        }
    }

    /// Hands out pre-made duplex client halves and counts the dials.
    struct DuplexDialer {
        streams: Mutex<VecDeque<DuplexStream>>,
        calls: AtomicUsize,
    }

    impl DuplexDialer {
        fn new(streams: VecDeque<DuplexStream>) -> Self {
            Self {
                streams: Mutex::new(streams),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl Dialer for DuplexDialer {
        fn dial(&self, _addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            let next = self
                .streams
                .lock()
                .expect("dialer queue")
                .pop_front()
                .map(|s| Box::new(s) as Box<dyn ProbeStream>);
            Box::pin(async move { next.ok_or_else(|| anyhow!("the dialer ran out of streams")) })
        }
    }

    fn get(scheme: &str, authority: &str, path: &str) -> HttpRequest {
        let mut headers = HeaderMap::new();
        headers.set("Host", authority);
        HttpRequest {
            method: "GET".into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    /// A `GET https://origin.test/x`.
    fn https_get(path: &str) -> HttpRequest {
        get("https", "origin.test:443", path)
    }

    /// A `GET http://origin.test/x` (the h2c lane).
    fn h2c_get(path: &str) -> HttpRequest {
        get("http", "origin.test:80", path)
    }

    fn body_bytes(resp: &aitm_core::HttpResponse) -> Vec<u8> {
        match &resp.body {
            Body::Bytes(b) => b.clone(),
            Body::Empty => Vec::new(),
            other => panic!("body was {other:?}, want Bytes"),
        }
    }

    /// A sender whose only way out is `dialer`.
    fn sender_with(dialer: Arc<DuplexDialer>) -> HttpSender {
        HttpSender::new()
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer)
    }

    #[tokio::test]
    async fn an_h2_exchange_round_trips_over_a_duplex_server() {
        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"hi", seen.clone(), false));

        let pool = H2Pool::new();
        let resp = exchange(
            &pool,
            Box::new(client),
            "origin.test:443",
            &https_get("/x"),
            Duration::from_secs(10),
        )
        .await
        .expect("the h2 exchange succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, HttpVersion::H2);
        assert_eq!(body_bytes(&resp), b"hi".to_vec());
        let log = seen.lock().expect("seen").clone();
        assert_eq!(log.len(), 1, "one stream, got {log:?}");
        assert_eq!(log[0].method, "GET");
        assert_eq!(log[0].path, "/x");
        assert!(
            !log[0].header_names.iter().any(|n| n == "connection"),
            "h2 request carried a connection header: {:?}",
            log[0].header_names
        );
        origin.abort();
    }

    #[tokio::test]
    async fn h2_requests_carry_no_connection_close() {
        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"hi", seen.clone(), false));

        let mut req = https_get("/x");
        req.headers.set("Connection", "close");
        req.headers.set("Keep-Alive", "timeout=5");
        let pool = H2Pool::new();
        let resp = exchange(
            &pool,
            Box::new(client),
            "origin.test:443",
            &req,
            Duration::from_secs(10),
        )
        .await
        .expect("the h2 exchange succeeds");

        assert_eq!(resp.status, 200);
        let log = seen.lock().expect("seen").clone();
        assert_eq!(
            log[0]
                .header_names
                .iter()
                .filter(|n| *n == "connection" || *n == "keep-alive")
                .count(),
            0,
            "hop-by-hop headers reached the h2 wire: {:?}",
            log[0].header_names
        );
        origin.abort();
    }

    #[tokio::test]
    async fn the_pool_reuses_one_connection_per_authority() {
        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = sender_with(dialer.clone());

        let req = h2c_get("/a");
        for _ in 0..2 {
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                sender.send_with(&req, VersionPolicy::H2c),
            )
            .await
            .expect("the send finished within the guard")
            .expect("the h2c exchange succeeds");
            assert_eq!(resp.status, 200);
            assert_eq!(resp.version, HttpVersion::H2);
        }

        assert_eq!(
            dialer.calls(),
            1,
            "the second send must reuse the pooled connection"
        );
        assert_eq!(seen.lock().expect("seen").len(), 2, "two streams, one dial");
        drop(sender);
        origin.abort();
    }

    #[tokio::test]
    async fn a_failed_connection_is_dropped_and_the_next_send_redials() {
        let (client1, server1) = duplex(64 * 1024);
        let (client2, server2) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let first = tokio::spawn(h2_origin(server1, b"hi", seen.clone(), true));
        let second = tokio::spawn(h2_origin(server2, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client1, client2])));
        let sender = sender_with(dialer.clone());
        let req = h2c_get("/a");

        let first_resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the first h2c exchange succeeds");
        assert_eq!(first_resp.status, 200);

        // The origin has sent GOAWAY and hung up; let the client's connection
        // task observe it before the next send looks in the pool.
        let _ = first.await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let second_resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the second h2c exchange redials and succeeds");
        assert_eq!(second_resp.status, 200);
        assert_eq!(
            dialer.calls(),
            2,
            "a dead pooled connection must be redialled, not reused"
        );
        drop(sender);
        second.abort();
    }

    #[tokio::test]
    async fn an_h2_response_body_is_capped_at_16_mib() {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(streaming_h2_origin(server, 17 * 1024 * 1024));

        let pool = H2Pool::new();
        let resp = exchange(
            &pool,
            Box::new(client),
            "origin.test:443",
            &https_get("/big"),
            Duration::from_secs(60),
        )
        .await
        .expect("the h2 exchange succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.buffered_len(), Some(16 * 1024 * 1024));
        origin.abort();
    }

    #[tokio::test]
    async fn h2c_speaks_prior_knowledge_h2_over_plaintext() {
        // The far end is a bare `h2::server` over a plaintext duplex: it would
        // fail the handshake outright if the sender tried TLS first.
        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = sender_with(dialer.clone());

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&h2c_get("/plain"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("prior-knowledge h2c succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, HttpVersion::H2);
        assert_eq!(body_bytes(&resp), b"hi".to_vec());
        let log = seen.lock().expect("seen").clone();
        assert_eq!(log[0].path, "/plain");
        assert_eq!(log[0].scheme, "http", "h2c keeps the plaintext scheme");
        assert_eq!(dialer.calls(), 1);
        drop(sender);
        origin.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_h2_exchange_times_out_within_the_response_timeout() {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(silent_h2_origin(server));

        let pool = H2Pool::new();
        let err = exchange(
            &pool,
            Box::new(client),
            "origin.test:443",
            &https_get("/hang"),
            Duration::from_secs(5),
        )
        .await
        .expect_err("a server that never answers must time the exchange out");

        assert!(err.to_string().contains("timed out"), "error was {err}");
        assert!(
            err.to_string().contains("origin.test:443"),
            "error was {err}"
        );
        origin.abort();
    }
}
