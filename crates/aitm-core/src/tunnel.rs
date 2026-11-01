//! The shared tunnel recorder (spec D5): one place that inserts, closes and fails
//! `CONNECT` rows, relays a passthrough tunnel while counting its bytes, and
//! classifies a client-side failure — so the two producers (the passthrough
//! module and the HTTP module) cannot drift in the shape of a tunnel row.
//!
//! A tunnel row is a [`Flow::Http`] whose request is the `CONNECT` itself
//! (method `CONNECT`, scheme `https`, the normalised `host:port` authority, the
//! CONNECT headers, no path, no body) and whose `metadata.tunnel` carries the
//! outcome ([`TunnelInfo`]). It appears **at the outcome**, never as "pending":
//! `decrypted` once the client's handshake with the proxy's leaf completes,
//! `passthrough` once the origin is dialled and the acknowledgement written,
//! `failed` at the failure. An established tunnel carries a `200` response (the
//! acknowledgement) and stays in flight until [`TunnelRow::close`] or
//! [`TunnelRow::fail`] sets `duration` — the one terminal rule the store applies
//! to tunnel rows. A failed row has no response and is closed on insert.
//!
//! The events a row emits — `RequestHeaders` on insert, `Response` on close or
//! failure — travel the chain's passive dispatch because `tunnel.is_some()`, so
//! only the subscription tap sees them: frontends get a `created` push and a
//! final `response` push, no intercept rule can park a `CONNECT`, no script
//! sees it. A failed tunnel logs one `debug` line here (authority + reason code)
//! and nothing at `warn`; producers should not log it again.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::authority::Authority;
use crate::body::Body;
use crate::event::{Event, Verdict};
use crate::flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, TunnelInfo, TunnelMode, TunnelReason,
};
use crate::header::HeaderMap;
use crate::protocol::ModuleCtx;
use crate::stream::ByteStream;

/// What a producer knows about a `CONNECT` (or raw-TLS) connection when its
/// outcome is decided: everything [`TunnelRow::open`] needs to insert the row.
#[derive(Debug, Clone)]
pub struct TunnelRequest {
    /// The tunnel authority (spec D1), already normalised: it becomes
    /// `request.authority` as `host:port`.
    pub authority: Authority,
    /// The CONNECT request headers; empty for a raw-TLS connection.
    pub headers: HeaderMap,
    /// The client side: `tls: true` for a TLS tunnel, `false` for a cleartext
    /// `CONNECT` the proxy served inside the tunnel.
    pub client: ConnInfo,
    /// The resolved origin when one was dialled; `None` when the tunnel failed
    /// before that.
    pub server: Option<ConnInfo>,
    /// When the CONNECT head (or the ClientHello) was read: becomes
    /// `metadata.created` and the request timestamp, and is what `duration` is
    /// measured from.
    pub opened_at: SystemTime,
    /// Capture attribution, copied to `metadata.source_app`.
    pub source_app: Option<String>,
    /// Capture attribution, copied to `metadata.capture_interface`.
    pub capture_interface: Option<String>,
}

/// A tunnel row that has been inserted into the store. Hold it for the life of
/// the tunnel, then [`close`](Self::close) or [`fail`](Self::fail) it exactly
/// once; a row opened as [`TunnelMode::Failed`] is already closed and should
/// simply be dropped.
#[derive(Debug)]
pub struct TunnelRow {
    id: FlowId,
    created: SystemTime,
    authority: Authority,
}

impl TunnelRow {
    /// Insert the `CONNECT` row for `req` with outcome `info` and emit
    /// `Event::RequestHeaders` for it.
    ///
    /// The row's request is `CONNECT host:port` (scheme `https`, empty path,
    /// `req.headers`, empty body, timestamp `req.opened_at`); `metadata.created`
    /// is `req.opened_at`, `metadata.tunnel` is `info`, `passive` is `false` (a
    /// tunnel row is passive through its tunnel fields) and the attribution is
    /// copied. For `Decrypted` and `Passthrough` the row carries a `200` response
    /// (the `Connection Established` acknowledgement, no headers, empty body) and
    /// stays in flight until closed. For `Failed` the row has **no** response,
    /// its `duration` is set now, `Event::Response` is emitted too, and the
    /// returned row needs no further call.
    pub async fn open(ctx: &ModuleCtx, req: TunnelRequest, info: TunnelInfo) -> TunnelRow {
        let id = FlowId::new();
        let failed = info.mode == TunnelMode::Failed;
        let reason = info.reason;
        let opened_at = req.opened_at;
        let authority = req.authority;

        let mut metadata = FlowMeta::with_attribution(req.source_app, req.capture_interface);
        metadata.created = opened_at;
        metadata.tunnel = Some(info);
        if failed {
            metadata.duration = Some(elapsed_since(opened_at));
        }

        let flow = Flow::Http(HttpFlow {
            id,
            request: HttpRequest {
                method: "CONNECT".to_string(),
                scheme: "https".to_string(),
                authority: authority.to_string(),
                path: String::new(),
                version: HttpVersion::Http11,
                headers: req.headers,
                body: Body::Empty,
                timestamp: opened_at,
            },
            response: (!failed).then(connection_established),
            client_conn: req.client,
            server_conn: req.server,
            metadata,
            intercept: InterceptState::Observed,
        });
        ctx.store().insert(flow);
        let _: Verdict = ctx.emit(Event::RequestHeaders(id)).await;
        if failed {
            log_failed(&authority, reason);
            let _: Verdict = ctx.emit(Event::Response(id)).await;
        }
        TunnelRow {
            id,
            created: opened_at,
            authority,
        }
    }

    /// The row's flow id.
    pub fn id(&self) -> FlowId {
        self.id
    }

    /// Close an established tunnel: `duration` becomes now minus `created`;
    /// when `bytes` is `Some((up, down))` (a passthrough relay's counts) they
    /// become `tunnel.bytes_up` / `tunnel.bytes_down`; then `Event::Response`
    /// is emitted. The `200` acknowledgement stays.
    pub async fn close(self, ctx: &ModuleCtx, bytes: Option<(u64, u64)>) {
        let duration = elapsed_since(self.created);
        ctx.store().update(self.id, &mut |flow| {
            let meta = flow.metadata_mut();
            meta.duration = Some(duration);
            if let (Some((up, down)), Some(tunnel)) = (bytes, meta.tunnel.as_mut()) {
                tunnel.bytes_up = Some(up);
                tunnel.bytes_down = Some(down);
            }
        });
        let _: Verdict = ctx.emit(Event::Response(self.id)).await;
    }

    /// Fail an already-open row (a passthrough relay that errors at once): the
    /// mode becomes [`TunnelMode::Failed`] with `reason`, the `200` is dropped
    /// (`response = None`: it was an acknowledgement, not an outcome), `duration`
    /// is set, and `Event::Response` is emitted.
    pub async fn fail(self, ctx: &ModuleCtx, reason: TunnelReason) {
        let duration = elapsed_since(self.created);
        ctx.store().update(self.id, &mut |flow| {
            if let Flow::Http(h) = flow {
                h.response = None;
                h.metadata.duration = Some(duration);
                h.metadata.tunnel = Some(TunnelInfo::failed(reason));
            }
        });
        log_failed(&self.authority, Some(reason));
        let _: Verdict = ctx.emit(Event::Response(self.id)).await;
    }
}

/// The `200 Connection Established` acknowledgement as a response: no headers,
/// empty body. The timestamp is the moment the row is opened.
fn connection_established() -> HttpResponse {
    HttpResponse {
        status: 200,
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        trailers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    }
}

/// Now minus `since`. A clock that went backwards yields zero rather than
/// `None`: a tunnel row's `duration` is its terminal marker, so it must be set
/// once the row closes or the store could never clear it.
fn elapsed_since(since: SystemTime) -> Duration {
    since.elapsed().unwrap_or_default()
}

/// The one `debug` line a failed tunnel produces (spec D5).
fn log_failed(authority: &Authority, reason: Option<TunnelReason>) {
    tracing::debug!(
        %authority,
        reason = reason.as_ref().map_or("unspecified", TunnelReason::label),
        "tunnel failed"
    );
}

/// Relay `client` and `upstream` byte for byte in both directions until either
/// side closes (an EOF on one side shuts down the other's write half, as
/// [`tokio::io::copy_bidirectional`] does) or an I/O error ends the relay.
///
/// Returns `(bytes_up, bytes_down, result)`: `bytes_up` is what was read from the
/// client toward the origin, `bytes_down` what was written to the client from the
/// origin. Both are counted on the client stream itself, so they are exact even
/// when the relay ends in an error (a reset mid-transfer) and the passthrough row
/// still reports what moved.
pub async fn relay(
    client: &mut ByteStream,
    upstream: &mut ByteStream,
) -> (u64, u64, io::Result<()>) {
    let mut counted = Counted {
        inner: client,
        up: 0,
        down: 0,
    };
    let result = tokio::io::copy_bidirectional(&mut counted, upstream)
        .await
        .map(|_| ());
    (counted.up, counted.down, result)
}

/// The client stream with two counters: bytes read from it (`up`) and bytes
/// written to it (`down`). The counts live outside the copy future, so they are
/// readable after it fails.
struct Counted<'a> {
    inner: &'a mut ByteStream,
    up: u64,
    down: u64,
}

impl AsyncRead for Counted<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = this.inner.as_mut().poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            this.up += (buf.filled().len() - before) as u64;
        }
        polled
    }
}

impl AsyncWrite for Counted<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = this.inner.as_mut().poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            this.down += *n as u64;
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_shutdown(cx)
    }
}

/// Why a client-side tunnel failure happened, decided **by type only** — never
/// by matching message text. Walks `err.chain()` the way `is_benign_disconnect`
/// in [`crate::proxy`] does, looking through an `io::Error` to the
/// `rustls::Error` the TLS layer wraps inside it; the first cause that
/// classifies wins, so `anyhow` context strings around the error change nothing.
///
/// - An `io::Error` of kind `UnexpectedEof`, `ConnectionReset`, `BrokenPipe` or
///   `ConnectionAborted` → [`TunnelReason::ClientClosed`]: the client gave up, a
///   speculative pre-connect, a mid-handshake EOF.
/// - A `rustls::Error::AlertReceived` in the certificate family (`BadCertificate`,
///   `UnsupportedCertificate`, `CertificateRevoked`, `CertificateExpired`,
///   `CertificateUnknown`, `UnknownCA`, `AccessDenied`,
///   `BadCertificateStatusResponse`, `CertificateRequired`) →
///   [`TunnelReason::ClientRejectedCertificate`]: the client does not trust the
///   proxy's CA (Safari, `curl` without `--cacert`).
/// - Any other `rustls::Error` → [`TunnelReason::ClientTlsError`].
/// - Anything else → [`TunnelReason::ProtocolError`].
pub fn classify_client_failure(err: &anyhow::Error) -> TunnelReason {
    err.chain()
        .find_map(classify_cause)
        .unwrap_or(TunnelReason::ProtocolError)
}

/// One link of the error chain: the client-closed io kinds, then a TLS error
/// either bare or as an `io::Error`'s source.
fn classify_cause(cause: &(dyn std::error::Error + 'static)) -> Option<TunnelReason> {
    if let Some(io) = cause.downcast_ref::<io::Error>() {
        if is_client_gone(io.kind()) {
            return Some(TunnelReason::ClientClosed);
        }
        return io
            .get_ref()
            .and_then(|src| src.downcast_ref::<rustls::Error>())
            .map(classify_tls);
    }
    cause.downcast_ref::<rustls::Error>().map(classify_tls)
}

/// The `io::ErrorKind`s that mean the client went away before the tunnel was
/// established.
fn is_client_gone(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
    )
}

/// A TLS-layer error from the client side: a certificate-family alert means the
/// client rejected our leaf; everything else is a TLS error.
fn classify_tls(err: &rustls::Error) -> TunnelReason {
    match err {
        rustls::Error::AlertReceived(alert) if is_certificate_alert(alert) => {
            TunnelReason::ClientRejectedCertificate
        }
        _ => TunnelReason::ClientTlsError,
    }
}

/// The alerts a TLS client sends when it refuses the server's certificate (spec D5).
fn is_certificate_alert(alert: &rustls::AlertDescription) -> bool {
    use rustls::AlertDescription as A;
    matches!(
        alert,
        A::BadCertificate
            | A::UnsupportedCertificate
            | A::CertificateRevoked
            | A::CertificateExpired
            | A::CertificateUnknown
            | A::UnknownCA
            | A::AccessDenied
            | A::BadCertificateStatusResponse
            | A::CertificateRequired
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FlowError;
    use crate::flow::{ConnInfo, Flow, FlowId, HttpFlow, HttpVersion, InterceptState, TunnelMode};
    use crate::protocol::{EventSink, UpstreamConnector};
    use crate::store::{ClearOutcome, FlowStore, MemFlowStore};
    use futures::future::BoxFuture;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Records every event in order; the chain's role in these tests.
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<Event>>,
    }

    impl RecordingSink {
        fn events(&self) -> Vec<Event> {
            self.events.lock().unwrap().clone()
        }
    }

    impl EventSink for RecordingSink {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            Box::pin(async move {
                self.events.lock().unwrap().push(ev);
                Verdict::Continue
            })
        }
    }

    /// The recorder never dials: a connector that fails loudly if it is asked to.
    struct NoDial;

    impl UpstreamConnector for NoDial {
        fn connect(
            &self,
            _authority: &str,
            _dst: SocketAddr,
        ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
            Box::pin(async { anyhow::bail!("the tunnel recorder must not dial") })
        }
    }

    fn harness() -> (ModuleCtx, Arc<MemFlowStore>, Arc<RecordingSink>) {
        let store = Arc::new(MemFlowStore::new());
        let sink = Arc::new(RecordingSink::default());
        let ctx = ModuleCtx::new(store.clone(), sink.clone(), Arc::new(NoDial));
        (ctx, store, sink)
    }

    fn client_peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 51000))
    }

    fn origin() -> SocketAddr {
        SocketAddr::from(([93, 184, 216, 34], 443))
    }

    fn conn(peer: SocketAddr, tls: bool, sni: Option<&str>, at: SystemTime) -> ConnInfo {
        ConnInfo {
            peer,
            sni: sni.map(str::to_string),
            alpn: None,
            tls,
            established: at,
        }
    }

    /// A `CONNECT Example.COM:443` as a producer hands it over: the CONNECT
    /// headers, both ends of the connection and the capture attribution.
    fn request(opened_at: SystemTime) -> TunnelRequest {
        let mut headers = HeaderMap::new();
        headers.set("Host", "example.com:443");
        headers.set("Proxy-Connection", "keep-alive");
        TunnelRequest {
            authority: Authority::new("Example.COM", 443),
            headers,
            client: conn(client_peer(), true, Some("example.com"), opened_at),
            server: Some(conn(origin(), true, None, opened_at)),
            opened_at,
            source_app: Some("com.apple.Safari".to_string()),
            capture_interface: Some("macos-ne".to_string()),
        }
    }

    fn http(store: &MemFlowStore, id: FlowId) -> HttpFlow {
        match store.get(id) {
            Some(Flow::Http(h)) => h,
            other => panic!("expected the CONNECT row {id} in the store, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_passthrough_row_is_200_open_and_pushes_created() {
        let (ctx, store, sink) = harness();
        let opened_at = SystemTime::now() - Duration::from_millis(50);
        let row = TunnelRow::open(
            &ctx,
            request(opened_at),
            TunnelInfo::passthrough(TunnelReason::OutOfScope),
        )
        .await;
        let id = row.id();

        let h = http(&store, id);
        // The request is the CONNECT itself, authority normalised by `Authority`.
        assert_eq!(h.request.method, "CONNECT");
        assert_eq!(h.request.scheme, "https");
        assert_eq!(h.request.authority, "example.com:443");
        assert_eq!(h.request.path, "");
        assert_eq!(h.request.version, HttpVersion::Http11);
        assert_eq!(h.request.headers.get("host"), Some("example.com:443"));
        assert_eq!(
            h.request.headers.get("proxy-connection"),
            Some("keep-alive")
        );
        assert_eq!(h.request.headers.len(), 2);
        assert!(
            matches!(h.request.body, Body::Empty),
            "{:?}",
            h.request.body
        );
        assert_eq!(h.request.timestamp, opened_at);

        // An established tunnel carries its `200 Connection Established` ack.
        let resp = h.response.as_ref().expect("an open tunnel has its 200");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, HttpVersion::Http11);
        assert!(resp.headers.is_empty());
        assert!(resp.trailers.is_empty());
        assert!(matches!(resp.body, Body::Empty), "{:?}", resp.body);

        assert_eq!(h.client_conn.peer, client_peer());
        assert!(h.client_conn.tls);
        assert_eq!(h.client_conn.sni.as_deref(), Some("example.com"));
        assert_eq!(h.server_conn.as_ref().map(|c| c.peer), Some(origin()));

        assert_eq!(h.metadata.created, opened_at);
        assert_eq!(h.metadata.duration, None, "an open tunnel is in flight");
        assert_eq!(
            h.metadata.tunnel,
            Some(TunnelInfo::passthrough(TunnelReason::OutOfScope))
        );
        assert!(
            !h.metadata.passive,
            "a tunnel row is passive through its tunnel fields, not the flag"
        );
        assert_eq!(h.metadata.source_app.as_deref(), Some("com.apple.Safari"));
        assert_eq!(h.metadata.capture_interface.as_deref(), Some("macos-ne"));
        assert!(!h.metadata.truncated);
        assert!(!h.metadata.edited);
        assert!(!h.metadata.is_replay);
        assert!(h.metadata.marks.is_empty());
        assert_eq!(h.metadata.comment, None);
        assert!(matches!(h.intercept, InterceptState::Observed));

        // One `created` push; and the terminal rule keeps the open row.
        assert_eq!(sink.events(), vec![Event::RequestHeaders(id)]);
        assert_eq!(
            store.clear(),
            ClearOutcome {
                cleared: 0,
                skipped_in_flight: 1
            }
        );
        assert!(store.get(id).is_some(), "clear must keep the open tunnel");
    }

    #[tokio::test]
    async fn close_sets_duration_and_bytes_and_pushes_response() {
        let (ctx, store, sink) = harness();
        let opened_at = SystemTime::now() - Duration::from_millis(250);
        let row = TunnelRow::open(
            &ctx,
            request(opened_at),
            TunnelInfo::passthrough(TunnelReason::Pinned),
        )
        .await;
        let id = row.id();

        row.close(&ctx, Some((1234, 56789))).await;

        let h = http(&store, id);
        let duration = h.metadata.duration.expect("close sets the duration");
        assert!(duration >= Duration::from_millis(250), "{duration:?}");
        assert_eq!(h.metadata.created, opened_at);
        assert_eq!(
            h.metadata.tunnel,
            Some(TunnelInfo {
                mode: TunnelMode::Passthrough,
                reason: Some(TunnelReason::Pinned),
                bytes_up: Some(1234),
                bytes_down: Some(56789),
            })
        );
        assert_eq!(
            h.response.as_ref().map(|r| r.status),
            Some(200),
            "closing keeps the acknowledgement"
        );
        assert_eq!(
            sink.events(),
            vec![Event::RequestHeaders(id), Event::Response(id)]
        );
        // Closed: the terminal rule now lets `clear` take it.
        assert_eq!(
            store.clear(),
            ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            }
        );
        assert!(store.get(id).is_none());
    }

    #[tokio::test]
    async fn close_without_bytes_leaves_the_counts_unset() {
        // A decrypted tunnel reports no relayed bytes: its inner rows carry the traffic.
        let (ctx, store, sink) = harness();
        let row = TunnelRow::open(&ctx, request(SystemTime::now()), TunnelInfo::decrypted()).await;
        let id = row.id();

        row.close(&ctx, None).await;

        let h = http(&store, id);
        assert!(h.metadata.duration.is_some());
        assert_eq!(h.metadata.tunnel, Some(TunnelInfo::decrypted()));
        assert_eq!(h.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(
            sink.events(),
            vec![Event::RequestHeaders(id), Event::Response(id)]
        );
    }

    #[tokio::test]
    async fn open_failed_row_has_no_status_and_is_closed() {
        let (ctx, store, sink) = harness();
        let opened_at = SystemTime::now() - Duration::from_millis(100);
        let row = TunnelRow::open(
            &ctx,
            request(opened_at),
            TunnelInfo::failed(TunnelReason::ClientRejectedCertificate),
        )
        .await;
        let id = row.id();

        let h = http(&store, id);
        assert_eq!(h.request.method, "CONNECT");
        assert_eq!(h.request.authority, "example.com:443");
        assert!(
            h.response.is_none(),
            "a failed tunnel has no status: {:?}",
            h.response
        );
        let duration = h
            .metadata
            .duration
            .expect("a failed row is closed on insert");
        assert!(duration >= Duration::from_millis(100), "{duration:?}");
        assert_eq!(h.metadata.created, opened_at);
        assert_eq!(
            h.metadata.tunnel,
            Some(TunnelInfo::failed(TunnelReason::ClientRejectedCertificate))
        );
        assert!(!h.metadata.passive);
        // `created` then its final state, in that order.
        assert_eq!(
            sink.events(),
            vec![Event::RequestHeaders(id), Event::Response(id)]
        );
        assert_eq!(
            store.clear(),
            ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            }
        );
        assert!(store.get(id).is_none());
    }

    #[tokio::test]
    async fn fail_after_open_flips_mode_to_failed() {
        let (ctx, store, sink) = harness();
        let opened_at = SystemTime::now() - Duration::from_millis(30);
        let row = TunnelRow::open(
            &ctx,
            request(opened_at),
            TunnelInfo::passthrough(TunnelReason::OutOfScope),
        )
        .await;
        let id = row.id();
        assert_eq!(
            http(&store, id).response.as_ref().map(|r| r.status),
            Some(200)
        );

        row.fail(&ctx, TunnelReason::UpstreamUnreachable).await;

        let h = http(&store, id);
        assert_eq!(
            h.metadata.tunnel,
            Some(TunnelInfo::failed(TunnelReason::UpstreamUnreachable))
        );
        assert!(
            h.response.is_none(),
            "the 200 was an acknowledgement, not an outcome: {:?}",
            h.response
        );
        let duration = h.metadata.duration.expect("failing closes the row");
        assert!(duration >= Duration::from_millis(30), "{duration:?}");
        assert_eq!(
            sink.events(),
            vec![Event::RequestHeaders(id), Event::Response(id)]
        );
        assert_eq!(
            store.clear(),
            ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            }
        );
    }

    #[tokio::test]
    async fn relay_counts_survive_a_reset() {
        let (client_near, mut client_far) = tokio::io::duplex(1024);
        let (up_near, mut up_far) = tokio::io::duplex(1024);
        let relay_task = tokio::spawn(async move {
            let mut client: ByteStream = Box::pin(client_near);
            let mut upstream: ByteStream = Box::pin(up_near);
            relay(&mut client, &mut upstream).await
        });

        // 5 bytes up: client → origin.
        client_far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        up_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // 7 bytes down: origin → client.
        up_far.write_all(b"goodbye").await.unwrap();
        let mut buf = [0u8; 7];
        client_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"goodbye");

        // The client goes away while the origin keeps talking: the relay's next
        // write to the client fails (a duplex whose far end was dropped reports
        // `BrokenPipe`, as a reset socket does). The counts must still be exact.
        drop(client_far);
        up_far.write_all(b"late").await.unwrap();

        let (up, down, result) = relay_task.await.unwrap();
        assert_eq!((up, down), (5, 7));
        assert_eq!(
            result
                .expect_err("the relay ended in the write error")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// An `io::Error` of `kind`, wrapped in an `anyhow` context the way the HTTP
    /// module wraps a client handshake error.
    fn io_err(kind: io::ErrorKind) -> anyhow::Error {
        anyhow::Error::new(io::Error::new(kind, "peer went away")).context("client TLS handshake")
    }

    /// A `rustls::Error` inside an `InvalidData` `io::Error`, exactly as
    /// `tokio_rustls` surfaces it, under the module's context.
    fn tls_err(err: rustls::Error) -> anyhow::Error {
        anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, err))
            .context("client TLS handshake")
    }

    fn alert(desc: rustls::AlertDescription) -> anyhow::Error {
        tls_err(rustls::Error::AlertReceived(desc))
    }

    #[test]
    fn classifies_client_failures_by_type() {
        use rustls::AlertDescription as A;
        use TunnelReason::*;

        // The certificate family of alerts: the client refused our CA.
        assert_eq!(
            classify_client_failure(&alert(A::UnknownCA)),
            ClientRejectedCertificate
        );
        assert_eq!(
            classify_client_failure(&alert(A::CertificateUnknown)),
            ClientRejectedCertificate
        );
        for desc in [
            A::BadCertificate,
            A::UnsupportedCertificate,
            A::CertificateRevoked,
            A::CertificateExpired,
            A::AccessDenied,
            A::BadCertificateStatusResponse,
            A::CertificateRequired,
        ] {
            assert_eq!(
                classify_client_failure(&alert(desc)),
                ClientRejectedCertificate,
                "{desc:?}"
            );
        }

        // Any other alert, or any other TLS error (wrapped or bare), is a TLS error.
        assert_eq!(
            classify_client_failure(&alert(A::HandshakeFailure)),
            ClientTlsError
        );
        assert_eq!(
            classify_client_failure(&tls_err(rustls::Error::General("internal state".into()))),
            ClientTlsError
        );
        let bare = anyhow::Error::new(rustls::Error::AlertReceived(A::HandshakeFailure))
            .context("client TLS handshake");
        assert_eq!(classify_client_failure(&bare), ClientTlsError);

        // The client went away before the tunnel was established.
        assert_eq!(
            classify_client_failure(&io_err(io::ErrorKind::UnexpectedEof)),
            ClientClosed
        );
        assert_eq!(
            classify_client_failure(&io_err(io::ErrorKind::ConnectionReset)),
            ClientClosed
        );
        assert_eq!(
            classify_client_failure(&io_err(io::ErrorKind::BrokenPipe)),
            ClientClosed
        );
        assert_eq!(
            classify_client_failure(&io_err(io::ErrorKind::ConnectionAborted)),
            ClientClosed
        );

        // Anything else is a protocol error — including an io error of another
        // kind, and a message that merely *talks* about an alert: type, not text.
        let protocol =
            anyhow::Error::new(FlowError::Protocol("bad".into())).context("serving HTTP");
        assert_eq!(classify_client_failure(&protocol), ProtocolError);
        assert_eq!(
            classify_client_failure(&io_err(io::ErrorKind::PermissionDenied)),
            ProtocolError
        );
        assert_eq!(
            classify_client_failure(&anyhow::anyhow!("received fatal alert: UnknownCA")),
            ProtocolError
        );
    }
}
