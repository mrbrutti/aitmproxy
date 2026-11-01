//! The shared tunnel recorder (spec D5): one place that inserts, closes and fails
//! `CONNECT` rows, relays a passthrough tunnel while counting its bytes, and
//! classifies a client-side failure — so the two producers (the passthrough
//! module and the HTTP module) cannot drift in the shape of a tunnel row.
//!
//! A tunnel row is a [`Flow::Http`] whose request is the `CONNECT` itself
//! (method `CONNECT`, scheme `https`, the normalised `host:port` authority, the
//! CONNECT headers with any credential value redacted, no path, no body) and
//! whose `metadata.tunnel` carries the outcome ([`TunnelInfo`]). It appears
//! **at the outcome**, never as "pending":
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
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use futures::future::{select, Either};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use crate::authority::Authority;
use crate::body::Body;
use crate::event::{Event, Verdict};
use crate::flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, TunnelInfo, TunnelMode, TunnelReason,
};
use crate::header::HeaderMap;
use crate::protocol::ModuleCtx;
use crate::redact::is_secret_key;
use crate::stream::ByteStream;

/// What a tunnel row stores in place of a credential header's value.
const REDACTED: &str = "<redacted>";

/// What a producer knows about a `CONNECT` (or raw-TLS) connection when its
/// outcome is decided: everything [`TunnelRow::open`] needs to insert the row.
#[derive(Debug, Clone)]
pub struct TunnelRequest {
    /// The tunnel authority (spec D1), already normalised: it becomes
    /// `request.authority` as `host:port`.
    pub authority: Authority,
    /// The CONNECT request headers; empty for a raw-TLS connection. Stored on
    /// the row with every credential value redacted (see [`TunnelRow::open`]).
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
    /// `req.headers` with the value of every header [`is_secret_key`] flags —
    /// `Proxy-Authorization` above all — stored as the literal `<redacted>`,
    /// because `flow.detail` and session files carry headers verbatim; empty
    /// body, timestamp `req.opened_at`); `metadata.created`
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
                headers: redact_secret_headers(&req.headers),
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
    /// when `bytes` is `Some` (a passthrough relay's [`RelayCounts`]) `up` and
    /// `down` become `tunnel.bytes_up` / `tunnel.bytes_down`; then
    /// `Event::Response` is emitted. The `200` acknowledgement stays.
    pub async fn close(self, ctx: &ModuleCtx, bytes: Option<RelayCounts>) {
        let duration = elapsed_since(self.created);
        ctx.store().update(self.id, &mut |flow| {
            let meta = flow.metadata_mut();
            meta.duration = Some(duration);
            if let (Some(counts), Some(tunnel)) = (bytes, meta.tunnel.as_mut()) {
                tunnel.bytes_up = Some(counts.up);
                tunnel.bytes_down = Some(counts.down);
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

/// The CONNECT headers as a row stores them (spec Constraints, panel S3): the
/// value of every header whose name [`is_secret_key`] flags — `Proxy-Authorization`
/// above all — replaced by the literal `<redacted>`. Names, order and every other
/// value are kept.
fn redact_secret_headers(headers: &HeaderMap) -> HeaderMap {
    let mut stored = HeaderMap::new();
    for (name, value) in headers.iter() {
        stored.set(name, if is_secret_key(name) { REDACTED } else { value });
    }
    stored
}

/// The one `debug` line a failed tunnel produces (spec D5). The authority is
/// Debug-escaped (panel S4): a control byte in a host name reaches no terminal raw.
fn log_failed(authority: &Authority, reason: Option<TunnelReason>) {
    tracing::debug!(
        authority = ?authority.to_string(),
        reason = reason.as_ref().map_or("unspecified", TunnelReason::label),
        "tunnel failed"
    );
}

/// How long a relay may go with no byte moving in either direction before it is
/// shut down (spec Constraints, panel S2): an idle passthrough must not pin an
/// open row, a task and two sockets forever.
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The byte counts of one relayed tunnel: `up` is what was read from the client
/// toward the origin, `down` what was written to the client from the origin —
/// the values a passthrough row reports as `bytes_up` / `bytes_down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayCounts {
    pub up: u64,
    pub down: u64,
}

/// Relay `client` and `upstream` byte for byte in both directions until either
/// side closes (an EOF on one side shuts down the other's write half, as
/// [`tokio::io::copy_bidirectional`] does), an I/O error ends the relay, or no
/// byte has moved in either direction for [`RELAY_IDLE_TIMEOUT`] — then both
/// write halves are shut down and the relay ends cleanly, so the row closes
/// normally with its counts and duration (panel S2).
///
/// Returns the [`RelayCounts`] and the result. The counts are kept on the client
/// stream itself, so they are exact even when the relay ends in an error (a
/// reset mid-transfer) and the passthrough row still reports what moved.
pub async fn relay(
    client: &mut ByteStream,
    upstream: &mut ByteStream,
) -> (RelayCounts, io::Result<()>) {
    let activity = Arc::new(Activity::new());
    let mut counted = Counted {
        inner: client,
        activity: Arc::clone(&activity),
    };
    // `Some(result)` when the copy itself ended; `None` when the idle bound did.
    let outcome = {
        let mut copy = pin!(tokio::io::copy_bidirectional(&mut counted, upstream));
        loop {
            // Sleep until the bound measured from the last byte. When it fires,
            // a byte that moved meanwhile has pushed the bound out: sleep again.
            let deadline = activity.last_active() + RELAY_IDLE_TIMEOUT;
            let idle = pin!(tokio::time::sleep_until(deadline));
            match select(copy.as_mut(), idle).await {
                Either::Left((done, _)) => break Some(done.map(|_| ())),
                Either::Right(((), _)) => {
                    if activity.last_active() + RELAY_IDLE_TIMEOUT <= Instant::now() {
                        break None;
                    }
                }
            }
        }
    };
    let result = match outcome {
        Some(result) => result,
        None => {
            // Idle: shut both write halves so each peer sees EOF. A half that is
            // already gone fails its shutdown, which changes nothing here.
            let _ = counted.shutdown().await;
            let _ = upstream.shutdown().await;
            Ok(())
        }
    };
    (activity.counts(), result)
}

/// What has moved through one relay: the two byte counters and when the last
/// byte moved. Shared between the counting stream wrapper inside the copy
/// future and the idle watchdog beside it, so the counts are readable after
/// the copy fails and the watchdog sees every byte.
struct Activity {
    start: Instant,
    up: AtomicU64,
    down: AtomicU64,
    /// Nanoseconds after `start` of the last byte moved in either direction.
    last_active: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            last_active: AtomicU64::new(0),
        }
    }

    /// `n` bytes read from the client (toward the origin).
    fn moved_up(&self, n: usize) {
        self.moved(&self.up, n);
    }

    /// `n` bytes written to the client (from the origin).
    fn moved_down(&self, n: usize) {
        self.moved(&self.down, n);
    }

    fn moved(&self, counter: &AtomicU64, n: usize) {
        if n == 0 {
            return;
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        let since_start = Instant::now().saturating_duration_since(self.start);
        let nanos = u64::try_from(since_start.as_nanos()).unwrap_or(u64::MAX);
        self.last_active.fetch_max(nanos, Ordering::Relaxed);
    }

    /// When the last byte moved; `start` while nothing has.
    fn last_active(&self) -> Instant {
        let nanos = self.last_active.load(Ordering::Relaxed);
        self.start
            .checked_add(Duration::from_nanos(nanos))
            .unwrap_or(self.start)
    }

    fn counts(&self) -> RelayCounts {
        RelayCounts {
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
        }
    }
}

/// The client stream, reporting every byte read from it (`up`) and written to
/// it (`down`) to the shared [`Activity`].
struct Counted<'a> {
    inner: &'a mut ByteStream,
    activity: Arc<Activity>,
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
            this.activity.moved_up(buf.filled().len() - before);
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
            this.activity.moved_down(*n);
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
/// - A received `close_notify` alert → [`TunnelReason::ClientClosed`]: a graceful
///   close during the handshake, not a protocol fault (spec D5, amended
///   2026-11-01).
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
/// client rejected our leaf, a `close_notify` means it hung up gracefully;
/// everything else is a TLS error.
fn classify_tls(err: &rustls::Error) -> TunnelReason {
    match err {
        rustls::Error::AlertReceived(alert) if is_certificate_alert(alert) => {
            TunnelReason::ClientRejectedCertificate
        }
        rustls::Error::AlertReceived(rustls::AlertDescription::CloseNotify) => {
            TunnelReason::ClientClosed
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
    use crate::redact::is_secret_key;
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

    /// Panel S3: the CONNECT headers are the row's request, but a credential in
    /// them must not reach `flow.detail` or a session file. The value of every
    /// header `is_secret_key` flags — `Proxy-Authorization` above all — is stored
    /// as the literal `<redacted>`; names, order and every other value are kept.
    #[tokio::test]
    async fn open_redacts_proxy_authorization_and_keeps_the_rest() {
        // The rule the redaction rides on, pinned for the names a CONNECT carries.
        assert!(is_secret_key("proxy-authorization"));
        assert!(is_secret_key("Proxy-Authorization"));
        assert!(!is_secret_key("host"));
        assert!(!is_secret_key("proxy-connection"));
        assert!(!is_secret_key("user-agent"));
        // The response-side challenge is not a credential under the shared rule.
        assert!(!is_secret_key("proxy-authenticate"));

        let (ctx, store, _sink) = harness();
        let mut req = request(SystemTime::now());
        req.headers = HeaderMap::new();
        req.headers.set("Proxy-Authorization", "Basic abc");
        req.headers.set("Host", "x");
        req.headers.set("User-Agent", "curl/8.7.1");
        let row =
            TunnelRow::open(&ctx, req, TunnelInfo::passthrough(TunnelReason::OutOfScope)).await;

        let h = http(&store, row.id());
        let stored: Vec<(&str, &str)> = h.request.headers.iter().collect();
        assert_eq!(
            stored,
            vec![
                ("Proxy-Authorization", "<redacted>"),
                ("Host", "x"),
                ("User-Agent", "curl/8.7.1"),
            ]
        );
        assert_eq!(
            h.request.headers.get("proxy-authorization"),
            Some("<redacted>")
        );
        assert_eq!(h.request.headers.get("host"), Some("x"));

        // The same path serves a failed row.
        let mut req = request(SystemTime::now());
        req.headers = HeaderMap::new();
        req.headers
            .set("proxy-authorization", "Bearer eyJ.secret.sig");
        let failed = TunnelRow::open(
            &ctx,
            req,
            TunnelInfo::failed(TunnelReason::UpstreamUnreachable),
        )
        .await;
        assert_eq!(
            http(&store, failed.id())
                .request
                .headers
                .get("Proxy-Authorization"),
            Some("<redacted>")
        );
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

        row.close(
            &ctx,
            Some(RelayCounts {
                up: 1234,
                down: 56789,
            }),
        )
        .await;

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

        let (counts, result) = relay_task.await.unwrap();
        assert_eq!(counts, RelayCounts { up: 5, down: 7 });
        assert_eq!(
            result
                .expect_err("the relay ended in the write error")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// Empty input: a relay whose both ends are already closed moves nothing and
    /// ends cleanly — zero counts and `Ok`, so the row it closes reports zero bytes, not
    /// an error (Tester addition, whole-branch stage 5).
    #[tokio::test]
    async fn relay_with_nothing_to_move_closes_cleanly_with_zero_counts() {
        let (client_near, client_far) = tokio::io::duplex(64);
        let (up_near, up_far) = tokio::io::duplex(64);
        drop(client_far);
        drop(up_far);
        let mut client: ByteStream = Box::pin(client_near);
        let mut upstream: ByteStream = Box::pin(up_near);

        let (counts, result) = relay(&mut client, &mut upstream).await;

        assert_eq!(counts, RelayCounts { up: 0, down: 0 });
        result.expect("two closed ends are a clean close, not an error");
    }

    /// Panel S2: a relay with no byte in either direction for `RELAY_IDLE_TIMEOUT`
    /// is shut down on both halves, so an idle passthrough cannot pin an open
    /// row, a task and two sockets forever. A byte in either direction restarts
    /// the clock; the result is the clean close with the exact counts moved so
    /// far, so the row closes normally with counts and duration. Paused tokio
    /// time: the minutes are virtual.
    #[tokio::test(start_paused = true)]
    async fn relay_ends_after_the_idle_bound_with_the_counts_so_far() {
        assert_eq!(RELAY_IDLE_TIMEOUT, Duration::from_secs(600));
        let (client_near, mut client_far) = tokio::io::duplex(1024);
        let (up_near, mut up_far) = tokio::io::duplex(1024);
        let relay_task = tokio::spawn(async move {
            let mut client: ByteStream = Box::pin(client_near);
            let mut upstream: ByteStream = Box::pin(up_near);
            relay(&mut client, &mut upstream).await
        });
        let almost = RELAY_IDLE_TIMEOUT - Duration::from_secs(1);

        // 5 bytes up, then silence just short of the bound: still relaying.
        client_far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        up_far.read_exact(&mut buf).await.unwrap();
        tokio::time::advance(almost).await;
        assert!(
            !relay_task.is_finished(),
            "a byte {almost:?} ago keeps the relay alive"
        );

        // 7 bytes down restart the clock: the relay survives a second near-bound
        // silence, now well past one bound of total wall time.
        up_far.write_all(b"goodbye").await.unwrap();
        let mut buf = [0u8; 7];
        client_far
            .read_exact(&mut buf)
            .await
            .expect("the relay still forwards after the first silence");
        assert_eq!(&buf, b"goodbye");
        tokio::time::advance(almost).await;
        assert!(
            !relay_task.is_finished(),
            "a byte in the other direction restarts the idle clock"
        );
        client_far.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        up_far
            .read_exact(&mut buf)
            .await
            .expect("the relay still forwards after the second silence");

        // Nothing moves past the bound: the relay shuts both halves and returns.
        tokio::time::advance(RELAY_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        let (counts, result) = tokio::time::timeout(Duration::from_secs(5), relay_task)
            .await
            .expect("the relay ends once the idle bound passes")
            .unwrap();
        assert_eq!(counts, RelayCounts { up: 9, down: 7 });
        result.expect("an idle shutdown is a clean close, not an error");
        // Both peers see EOF: both write halves were shut down.
        assert_eq!(up_far.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(client_far.read(&mut [0u8; 1]).await.unwrap(), 0);
    }

    /// Records the `authority` field of every event exactly as tracing hands it
    /// to a formatter (the panel S4 check on `log_failed`).
    #[derive(Default)]
    struct AuthorityFields(Mutex<Vec<String>>);

    impl tracing::Subscriber for AuthorityFields {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Visitor<'a>(&'a mut Vec<String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "authority" {
                        self.0.push(format!("{value:?}"));
                    }
                }
            }
            event.record(&mut Visitor(&mut self.0.lock().unwrap()));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Panel S4, second half: the one `debug` line a failed tunnel produces
    /// carries the authority Debug-escaped, so a control byte that reached an
    /// `Authority` by any path (`Authority::new` does not validate) cannot
    /// reach a terminal raw.
    #[test]
    fn log_failed_debug_escapes_the_authority() {
        let fields = Arc::new(AuthorityFields::default());
        tracing::subscriber::with_default(fields.clone(), || {
            log_failed(
                &Authority::new("\x1b[2Jevil.example", 443),
                Some(TunnelReason::ProtocolError),
            );
        });
        let recorded = fields.0.lock().unwrap().clone();
        // Quoted and `\u{1b}`-escaped as `str`'s Debug prints it (the host is
        // lowercased by `Authority::new`, hence `2j`).
        assert_eq!(recorded, vec![r#""\u{1b}[2jevil.example:443""#.to_string()]);
        assert!(
            !recorded[0].contains('\x1b'),
            "no raw escape byte in the log field: {recorded:?}"
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

        // A `close_notify` during the handshake is a graceful close, not a fault
        // (spec D5, amended 2026-11-01): the client went away.
        assert_eq!(
            classify_client_failure(&alert(A::CloseNotify)),
            ClientClosed
        );

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
