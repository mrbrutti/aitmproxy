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

/// One live h2 connection per connection key (`scheme://host:port`, the
/// identity the sender's `conn_key` builds), reused while idle.
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

    /// A handle for `key` when the pooled connection is ready to carry
    /// another stream. A connection that has errored (GOAWAY, a closed socket)
    /// is dropped from the pool and `None` is returned, so the caller redials.
    /// `None` is also returned while the connection is merely busy — the caller
    /// opens a second one rather than queueing behind it.
    pub(crate) fn take(&self, key: &str) -> Option<SendRequest<Bytes>> {
        let mut conns = self.conns.lock().ok()?;
        let entry = conns.get_mut(key)?;
        // A no-op waker: this is a readiness *probe*, not a wait. Nothing is
        // ever woken through it, and the next send polls again.
        let mut cx = Context::from_waker(Waker::noop());
        match entry.poll_ready(&mut cx) {
            Poll::Ready(Ok(())) => Some(entry.clone()),
            Poll::Ready(Err(_)) => {
                conns.remove(key);
                None
            }
            Poll::Pending => None,
        }
    }

    /// Remember `send_req` for `key`, replacing any previous handle.
    fn store(&self, key: &str, send_req: SendRequest<Bytes>) {
        if let Ok(mut conns) = self.conns.lock() {
            if conns.len() >= MAX_POOLED_AUTHORITIES && !conns.contains_key(key) {
                return;
            }
            conns.insert(key.to_string(), send_req);
        }
    }

    /// Forget the connection under `key` (it failed mid-exchange).
    fn remove(&self, key: &str) {
        if let Ok(mut conns) = self.conns.lock() {
            conns.remove(key);
        }
    }
}

/// Run one request/response exchange over a **new** h2 connection on `stream`,
/// remembering the connection in `pool` under `key` for the next send to the
/// same scheme, host and port.
///
/// `stream` is already the right transport: a TLS stream that negotiated ALPN
/// `h2`, or a plain one for prior-knowledge h2c.
pub(crate) async fn exchange(
    pool: &H2Pool,
    stream: Box<dyn ProbeStream>,
    key: &str,
    req: &HttpRequest,
    response_timeout: Duration,
) -> Result<HttpResponse> {
    let send_req = handshake(stream, key).await?;
    pool.store(key, send_req.clone());
    exchange_pooled(pool, send_req, key, req, response_timeout).await
}

/// Run one request/response exchange over an already-open connection taken
/// from `pool`. A failure drops the connection from the pool and is returned
/// as-is: the caller, not this layer, decides whether to try again.
pub(crate) async fn exchange_pooled(
    pool: &H2Pool,
    send_req: SendRequest<Bytes>,
    key: &str,
    req: &HttpRequest,
    response_timeout: Duration,
) -> Result<HttpResponse> {
    // Armed for the whole exchange: a deadline *above* this layer (the
    // sender's whole-exchange timeout, which starts before the dial and so
    // fires first on a real connect) drops this future instead of resuming it,
    // so an `if result.is_err()` after the await would never run. The guard
    // runs on that drop too, which is what keeps a stalled connection out of
    // the pool (D8.2 "closed on error").
    let mut eviction = PoolEviction {
        pool,
        key,
        armed: true,
    };
    let result = match tokio::time::timeout(response_timeout, stream_exchange(send_req, req)).await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "h2 exchange with {key} timed out after {response_timeout:?}"
        )),
    };
    if result.is_ok() {
        eviction.armed = false;
    }
    result
}

/// Drops `key`'s pooled connection unless the exchange it guards
/// completed successfully — including when that exchange is cancelled rather
/// than finished, which a plain error branch cannot see.
struct PoolEviction<'a> {
    pool: &'a H2Pool,
    key: &'a str,
    armed: bool,
}

impl Drop for PoolEviction<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.pool.remove(self.key);
        }
    }
}

/// Handshake a new h2 client connection, with the same settings the proxy's
/// own upstream path uses, and drive it on its own task.
async fn handshake(stream: Box<dyn ProbeStream>, key: &str) -> Result<SendRequest<Bytes>> {
    let (send_req, connection) = wire(
        "handshake",
        h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .header_table_size(HEADER_TABLE_SIZE)
            .handshake::<_, Bytes>(stream),
    )
    .await?
    .with_context(|| format!("h2 handshake with {key}"))?;
    let label = key.to_string();
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // Never the error's `Display`: for a peer-sent GOAWAY it appends
            // the frame's opaque debug data, which is peer-controlled text
            // (review finding SEC-7). A classification is all an operator
            // needs, and it belongs at `debug` — a peer ending its own
            // connection is not a fault of ours.
            tracing::debug!(
                peer = %label,
                go_away = e.is_go_away(),
                reset = e.is_reset(),
                reason = ?e.reason(),
                "h2 connection ended with an error"
            );
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
        body: Vec<u8>,
    }

    type Seen = Arc<Mutex<Vec<SeenRequest>>>;

    fn record(seen: &Seen, parts: &http::request::Parts, body: Vec<u8>) {
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
                body,
            });
        }
    }

    /// An h2 origin over one duplex half: record every stream it accepts (head
    /// and full request body) and answer it `200` with `body`. With `goaway`,
    /// it shuts the connection down after the first stream, so the client's
    /// pooled handle goes bad. Each stream runs on its own task so the accept
    /// loop keeps driving the connection while a request body streams in.
    async fn h2_origin(io: DuplexStream, body: &'static [u8], seen: Seen, goaway: bool) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        while let Some(accepted) = conn.accept().await {
            let Ok((req, mut respond)) = accepted else {
                break;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let (parts, mut rbody) = req.into_parts();
                let mut got = Vec::new();
                while let Some(Ok(chunk)) = rbody.data().await {
                    let _ = rbody.flow_control().release_capacity(chunk.len());
                    got.extend_from_slice(&chunk);
                }
                record(&seen, &parts, got);
                let Ok(resp) = http::Response::builder().status(200).body(()) else {
                    return;
                };
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(Bytes::from_static(body), true);
                }
            });
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

    /// An h2 origin that answers its first stream with a `total`-byte body and
    /// every later stream with a small `200 hi`, so a test can check that the
    /// connection is still usable after the client cut the big one short.
    async fn streaming_h2_origin(io: DuplexStream, total: usize) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        let mut pumping = None;
        while let Some(accepted) = conn.accept().await {
            let Ok((_req, mut respond)) = accepted else {
                break;
            };
            let Ok(resp) = http::Response::builder().status(200).body(()) else {
                break;
            };
            let Ok(mut send) = respond.send_response(resp, false) else {
                break;
            };
            if pumping.is_none() {
                pumping = Some(tokio::spawn(pump(send, total)));
            } else {
                let _ = send.send_data(Bytes::from_static(b"hi"), true);
            }
        }
        if let Some(task) = pumping {
            task.abort();
        }
    }

    /// An h2 origin that starts answering its first stream and then drops the
    /// whole connection with the body still open — a peer dying mid-stream.
    async fn h2_origin_dropping_mid_body(io: DuplexStream) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        let Some(Ok((_req, mut respond))) = conn.accept().await else {
            return;
        };
        let Ok(resp) = http::Response::builder().status(200).body(()) else {
            return;
        };
        let Ok(mut send) = respond.send_response(resp, false) else {
            return;
        };
        let _ = send.send_data(Bytes::from_static(b"partial"), false);
        // Drive the connection briefly so the head and the partial frame are
        // actually written, then hang up without ending the stream.
        let _ = tokio::time::timeout(Duration::from_millis(50), conn.accept()).await;
        drop(send);
        drop(conn);
    }

    /// An h2 origin that answers every stream `200`, body `hello`, and a trailer
    /// section `x-sum: abc`.
    async fn h2_origin_with_trailers(io: DuplexStream) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        while let Some(Ok((_req, mut respond))) = conn.accept().await {
            let Ok(resp) = http::Response::builder().status(200).body(()) else {
                break;
            };
            let Ok(mut send) = respond.send_response(resp, false) else {
                break;
            };
            let _ = send.send_data(Bytes::from_static(b"hello"), false);
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-sum", http::HeaderValue::from_static("abc"));
            let _ = send.send_trailers(trailers);
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

    /// A dialer that takes `latency` to connect (virtual time under a paused
    /// clock), so a connect + handshake costs time the way a real TCP dial does.
    struct SlowDialer {
        inner: Arc<DuplexDialer>,
        latency: Duration,
    }

    impl Dialer for SlowDialer {
        fn dial(&self, addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
            let latency = self.latency;
            let next = self.inner.dial(addr);
            Box::pin(async move {
                tokio::time::sleep(latency).await;
                next.await
            })
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

    // ---- Tester pass (plan 2026-10-31-aitmproxy-scanner-v2-t3, Tasks 1 + 3) ---

    /// The request body goes out intact over h2, through `send_body`'s
    /// flow-control loop: 200 KiB is larger than the 64 KiB initial window, so
    /// the sender must wait for `WINDOW_UPDATE`s rather than send once.
    #[tokio::test]
    async fn an_h2_request_body_reaches_the_origin_intact() {
        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"ok", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = sender_with(dialer.clone());

        let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
        let mut req = h2c_get("/upload");
        req.method = "POST".into();
        req.body = Body::Bytes(payload.clone());

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the POST over h2c succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"ok".to_vec());

        let log = seen.lock().expect("seen").clone();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].method, "POST");
        assert_eq!(log[0].path, "/upload");
        assert_eq!(log[0].body.len(), payload.len(), "body length on the wire");
        assert!(log[0].body == payload, "body bytes on the wire differ");
        drop(sender);
        origin.abort();
    }

    /// Plan Task 3 item 3: trailers are collected into `HttpResponse.trailers`
    /// and never merged into the headers.
    #[tokio::test]
    async fn h2_response_trailers_are_returned_separately_from_headers() {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(h2_origin_with_trailers(server));

        let pool = H2Pool::new();
        let resp = exchange(
            &pool,
            Box::new(client),
            "origin.test:443",
            &https_get("/t"),
            Duration::from_secs(10),
        )
        .await
        .expect("the h2 exchange succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"hello".to_vec());
        assert_eq!(resp.trailers.get("x-sum"), Some("abc"));
        assert_eq!(
            resp.headers.get("x-sum"),
            None,
            "a trailer is never merged into the headers"
        );
        origin.abort();
    }

    /// Connection drop mid-stream: the send that was on the wire fails (as a
    /// transport error, not `h2_not_negotiated`), the dead connection is
    /// forgotten, and the next send redials. No retry inside the sender.
    #[tokio::test]
    async fn a_connection_dropped_mid_body_fails_that_send_and_is_forgotten() {
        let (client1, server1) = duplex(64 * 1024);
        let (client2, server2) = duplex(64 * 1024);
        let first = tokio::spawn(h2_origin_dropping_mid_body(server1));
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let second = tokio::spawn(h2_origin(server2, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client1, client2])));
        let sender = sender_with(dialer.clone());

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&h2c_get("/drop"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect_err("a connection that dies mid-body fails the send");
        assert!(
            !crate::sender::is_h2_not_negotiated(&err),
            "a transport failure must not be classified as a version failure: {err}"
        );
        assert_eq!(dialer.calls(), 1, "the failing send itself never redials");
        let _ = first.await;

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&h2c_get("/again"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the next send redials and succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"hi".to_vec());
        assert_eq!(
            dialer.calls(),
            2,
            "the dead connection was dropped from the pool and redialled"
        );
        drop(sender);
        second.abort();
    }

    /// Oversized input: after the 16 MiB cap cut a body short, the pooled
    /// connection is still usable — the next send rides it without a redial.
    #[tokio::test]
    async fn a_capped_h2_body_leaves_the_pooled_connection_usable() {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(streaming_h2_origin(server, 17 * 1024 * 1024));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = sender_with(dialer.clone());

        let big = tokio::time::timeout(
            Duration::from_secs(60),
            sender.send_with(&h2c_get("/big"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the capped exchange succeeds");
        assert_eq!(big.status, 200);
        assert_eq!(big.body.buffered_len(), Some(16 * 1024 * 1024));

        let small = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&h2c_get("/small"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the pooled connection still carries a stream after a capped body");
        assert_eq!(small.status, 200);
        assert_eq!(body_bytes(&small), b"hi".to_vec());
        assert_eq!(dialer.calls(), 1, "no redial after the cap");
        drop(sender);
        origin.abort();
    }

    /// `MAX_POOLED_AUTHORITIES`: the authority past the cap is still served, on
    /// a fresh connection each time, while the first authority stays pooled.
    #[tokio::test]
    async fn the_pool_remembers_at_most_max_pooled_authorities() {
        let n = MAX_POOLED_AUTHORITIES + 1;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let mut clients = VecDeque::new();
        let mut origins = Vec::new();
        // One stream per authority, plus one for the unpooled authority's redial.
        for _ in 0..=n {
            let (client, server) = duplex(64 * 1024);
            clients.push_back(client);
            origins.push(tokio::spawn(h2_origin(server, b"hi", seen.clone(), false)));
        }
        let dialer = Arc::new(DuplexDialer::new(clients));
        let sender = sender_with(dialer.clone());

        let send = |authority: String| {
            let sender = &sender;
            async move {
                let req = get("http", &authority, "/");
                let resp = tokio::time::timeout(
                    Duration::from_secs(10),
                    sender.send_with(&req, VersionPolicy::H2c),
                )
                .await
                .expect("the send finished within the guard")
                .expect("the h2c exchange succeeds");
                assert_eq!(resp.status, 200);
            }
        };

        for i in 1..=n {
            send(format!("a{i}.test:80")).await;
        }
        assert_eq!(dialer.calls(), n, "one dial per new authority");

        // The authority past the cap was served but not remembered.
        send(format!("a{n}.test:80")).await;
        assert_eq!(
            dialer.calls(),
            n + 1,
            "the {n}th authority was not pooled and had to redial"
        );

        // The first authority is still pooled.
        send("a1.test:80".to_string()).await;
        assert_eq!(
            dialer.calls(),
            n + 1,
            "the first authority reused its connection"
        );
        assert_eq!(seen.lock().expect("seen").len(), n + 2);
        drop(sender);
        for origin in origins {
            origin.abort();
        }
    }

    /// The SSRF gate runs on every send, including one that would ride a
    /// pooled h2 connection: a target that became forbidden between two sends
    /// is refused before the pool is consulted, and no stream is opened.
    #[tokio::test]
    async fn the_ssrf_gate_runs_before_a_pooled_h2_connection_is_reused() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        let (client, server) = duplex(64 * 1024);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let origin = tokio::spawn(h2_origin(server, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let guard = Arc::new(StdGuard::default());
        // The resolver answers loopback; scoping the literal lifts the block.
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        let sender = sender_with(dialer.clone()).with_ssrf(SsrfPolicy::default(), guard.clone());
        let req = h2c_get("/a");

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("a scoped loopback literal passes the gate");
        assert_eq!(resp.status, 200);
        assert_eq!(dialer.calls(), 1);

        assert!(guard.remove_scope("127.0.0.1"), "the entry was present");

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect_err("the pooled connection must not bypass the SSRF gate");
        assert!(err.to_string().contains("SSRF"), "error was {err}");
        assert_eq!(dialer.calls(), 1, "a refused send never dials");
        assert_eq!(
            seen.lock().expect("seen").len(),
            1,
            "no stream was opened for the refused send"
        );
        drop(sender);
        origin.abort();
    }

    /// Captures this crate's own tracing events on the current thread. A local
    /// copy: `module.rs`'s equivalent lives in its private test module.
    #[derive(Clone, Default)]
    struct LogCapture {
        events: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    struct Fields(String);

    impl tracing::field::Visit for Fields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={value}", field.name()));
        }
    }

    impl tracing::Subscriber for LogCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            // Only this crate's own events: the `h2` crate's internal tracing
            // is not ours to police.
            if !event.metadata().target().starts_with("aitm_proto_http") {
                return;
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.events
                .lock()
                .expect("events")
                .push((*event.metadata().level(), fields.0));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// A plaintext h2 peer that answers the preface with SETTINGS and then, on
    /// the first thing the client writes, a `GOAWAY(INTERNAL_ERROR)` carrying
    /// `debug_data`. It never hangs up, so the client's connection error is the
    /// GOAWAY and not an EOF.
    async fn goaway_h2_origin(mut io: DuplexStream, debug_data: &'static [u8]) {
        use crate::raw_h2::{frame_header, FrameType, PREFACE};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut preface = vec![0u8; PREFACE.len()];
        if io.read_exact(&mut preface).await.is_err() {
            return;
        }
        if io
            .write_all(&frame_header(0, FrameType::Settings, 0x00, 0))
            .await
            .is_err()
        {
            return;
        }
        let mut buf = vec![0u8; 4096];
        if io.read(&mut buf).await.is_err() {
            return;
        }
        let mut payload = 0u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&2u32.to_be_bytes());
        payload.extend_from_slice(debug_data);
        let len = u32::try_from(payload.len()).expect("a test frame fits in 24 bits");
        let mut out = frame_header(len, FrameType::GoAway, 0x00, 0).to_vec();
        out.extend_from_slice(&payload);
        if io.write_all(&out).await.is_err() {
            return;
        }
        let _ = io.flush().await;
        std::future::pending::<()>().await;
    }

    /// SEC-7: the opaque debug data on a peer's GOAWAY is peer-controlled text
    /// (`h2::Error`'s `Display` appends it). The connection task logs a
    /// classification at `debug`, never that string.
    #[tokio::test]
    async fn a_peer_goaway_debug_blob_never_reaches_the_log() {
        const BLOB: &[u8] = b"goaway-debug-token-7b31";

        let capture = LogCapture::default();
        let events = capture.events.clone();
        let _guard = tracing::subscriber::set_default(capture);

        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(goaway_h2_origin(server, BLOB));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = sender_with(dialer.clone());

        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&h2c_get("/a"), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect_err("a peer that answers GOAWAY serves no response");

        // The connection task logs from its own task; wait for its event.
        let mut logged = Vec::new();
        for _ in 0..10_000 {
            logged = events.lock().expect("events").clone();
            if !logged.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !logged.is_empty(),
            "the connection task logged nothing at all"
        );
        assert!(
            !format!("{logged:?}").contains("goaway-debug-token"),
            "the peer's GOAWAY debug data reached the log: {logged:?}"
        );
        assert!(
            logged
                .iter()
                .all(|(level, _)| *level <= tracing::Level::DEBUG),
            "a peer-triggered connection end is not warn-worthy: {logged:?}"
        );
        assert!(
            logged
                .iter()
                .any(|(_, fields)| fields.contains("go_away=true")),
            "the classification must say it was a GOAWAY: {logged:?}"
        );
        drop(sender);
        origin.abort();
    }

    /// D8.2 "closed on error": an exchange that fails while the connection is
    /// still open (a stream the origin never answers, timed out) must drop the
    /// connection from the pool, so the next send redials instead of reusing a
    /// peer that just stalled. Virtual time: the 5 s response timeout elapses
    /// without a real wait.
    #[tokio::test(start_paused = true)]
    async fn a_timed_out_exchange_drops_the_still_open_connection_from_the_pool() {
        let (client1, server1) = duplex(64 * 1024);
        let (client2, server2) = duplex(64 * 1024);
        let silent = tokio::spawn(silent_h2_origin(server1));
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let healthy = tokio::spawn(h2_origin(server2, b"hi", seen.clone(), false));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client1, client2])));
        // A 10 ms dial, as a real TCP connect costs: the sender's whole-exchange
        // deadline is then earlier than the h2 layer's own, as in production.
        let slow = Arc::new(SlowDialer {
            inner: dialer.clone(),
            latency: Duration::from_millis(10),
        });
        let sender = HttpSender::new()
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(slow)
            .with_response_timeout(Duration::from_secs(5));

        let err = sender
            .send_with(&h2c_get("/hang"), VersionPolicy::H2c)
            .await
            .expect_err("an origin that never answers must time the exchange out");
        assert!(err.to_string().contains("timed out"), "error was {err}");
        assert_eq!(dialer.calls(), 1);

        let resp = sender
            .send_with(&h2c_get("/next"), VersionPolicy::H2c)
            .await
            .expect("the next send redials a healthy origin");
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"hi".to_vec());
        assert_eq!(
            dialer.calls(),
            2,
            "the stalled connection was dropped from the pool, not reused"
        );
        drop(sender);
        silent.abort();
        healthy.abort();
    }
}
