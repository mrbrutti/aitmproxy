//! A real-protocol test harness: duplex transport, tungstenite server, fixtures.
//!
//! Always compiled and `#[doc(hidden)] pub` (never `#[cfg(test)]`) so that this
//! crate's unit tests, its `tests/` binaries and the live-proof tests all reuse
//! one harness (T4 plan call 12). Nothing here mocks the WebSocket protocol:
//! [`ws_server`] runs tokio-tungstenite's real `accept_hdr_async`, the bytes on
//! the wire are real RFC 6455 frames, and only the socket is a
//! [`tokio::io::duplex`] pair. It is the inner loop, never acceptance evidence.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aitm_core::{
    Body, ByteStream, ConnInfo, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, MemFlowStore, ProxyClient, ScopeEntry,
    ScopeRateGuard, StdGuard, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_scan_model::{
    FlowRef, InsertionKind, InsertionPoint, JobCtx, LaneKind, ProfileTarget, ScanProfile,
    SessionMaterial, WsOptions,
};
use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use tokio::io::{duplex, DuplexStream};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};

use crate::dialer::WsDialer;
use crate::discover::{discover_flow, IdGen};
use crate::host::WsProbeHost;
use crate::transport::WsTransport;
use crate::types::PointSpec;

/// The job marker every [`TestJob`] hands out.
const TEST_MARKER: &str = "mk7f3a9e";

/// A [`WsTransport`] whose every connect is an in-memory duplex pair.
///
/// The client half is returned to the dialer; the server half is handed to the
/// closure given at construction, which is expected to spawn a task that speaks
/// the server side of the protocol.
pub struct DuplexTransport {
    on_connect: Box<dyn Fn(DuplexStream) + Send + Sync>,
    connects: Mutex<Vec<(SocketAddr, bool, String)>>,
}

impl DuplexTransport {
    /// A transport that hands every server half to `on_connect`.
    pub fn new<F>(on_connect: F) -> Arc<Self>
    where
        F: Fn(DuplexStream) + Send + Sync + 'static,
    {
        Arc::new(Self {
            on_connect: Box::new(on_connect),
            connects: Mutex::new(Vec::new()),
        })
    }

    /// Every `(addr, tls, sni)` the dialer asked for, in order.
    ///
    /// The address is what the dialer resolved and passed its SSRF check; a
    /// test asserts on it to prove a refused address never reached the seam.
    #[must_use]
    pub fn connects(&self) -> Vec<(SocketAddr, bool, String)> {
        self.connects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl WsTransport for DuplexTransport {
    fn connect<'a>(
        &'a self,
        addr: SocketAddr,
        tls: bool,
        sni: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
        Box::pin(async move {
            let (client, server) = duplex(64 * 1024);
            self.connects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((addr, tls, sni.to_string()));
            (self.on_connect)(server);
            Ok(Box::pin(client) as ByteStream)
        })
    }
}

/// How a test server answers one upgrade request.
///
/// Returning `Ok` completes the upgrade with that response, `Err` rejects it
/// with that status. A decider that wants the ordinary 101 plus an extra header
/// builds its base with
/// `tokio_tungstenite::tungstenite::handshake::server::create_response`, which
/// derives `Sec-WebSocket-Accept` from the request.
pub type HandshakeDecision = Arc<dyn Fn(&Request) -> Result<Response, ErrorResponse> + Send + Sync>;

/// What a test server saw: handshakes, data frames, connection count.
#[derive(Debug, Default)]
pub struct ServerLog {
    handshakes: Mutex<Vec<Vec<(String, String)>>>,
    received: Mutex<Vec<Vec<u8>>>,
    connections: AtomicUsize,
}

impl ServerLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The request headers of every upgrade attempt, lowercased, in arrival
    /// order (recorded whether the upgrade was accepted or rejected).
    #[must_use]
    pub fn handshakes(&self) -> Vec<Vec<(String, String)>> {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every data-frame payload a handler recorded with [`ServerConn::record`].
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many upgrades completed (a rejected handshake does not count).
    #[must_use]
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn push_handshake(&self, headers: Vec<(String, String)>) {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(headers);
    }

    fn push_received(&self, payload: Vec<u8>) {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(payload);
    }
}

/// One accepted server-side connection, handed to a `ws_server` handler.
///
/// The stream is shared rather than owned so that the harness can keep reading
/// after the handler returns — that is what lets tungstenite flush the Close
/// reply when the client closes an idle connection. A handler takes the stream
/// with [`ServerConn::ws`] and must let the guard drop when it is done.
pub struct ServerConn {
    ws: Arc<AsyncMutex<WebSocketStream<DuplexStream>>>,
    /// The upgrade request's headers, lowercased, in arrival order.
    pub headers: Vec<(String, String)>,
    /// The log this connection belongs to.
    pub log: Arc<ServerLog>,
}

impl ServerConn {
    /// Borrow the live WebSocket stream for this connection.
    pub async fn ws(&self) -> MutexGuard<'_, WebSocketStream<DuplexStream>> {
        self.ws.lock().await
    }

    /// Record a received data-frame payload in the connection's log.
    pub fn record(&self, payload: impl Into<Vec<u8>>) {
        self.log.push_received(payload.into());
    }

    /// The first upgrade-request header with this (lowercase) name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A transport whose server side is a real tungstenite server.
///
/// `decide` answers each upgrade (`None` accepts every well-formed one) and
/// `handler` runs for each accepted connection. Returns the transport to dial
/// through and the log both of them write to.
pub fn ws_server<H, Fut>(
    decide: Option<HandshakeDecision>,
    handler: H,
) -> (Arc<DuplexTransport>, Arc<ServerLog>)
where
    H: Fn(ServerConn) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let log = Arc::new(ServerLog::new());
    let log_for_transport = Arc::clone(&log);
    let transport = DuplexTransport::new(move |server| {
        let log = Arc::clone(&log_for_transport);
        let decide = decide.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
            let seen_in_callback = Arc::clone(&seen);
            let log_in_callback = Arc::clone(&log);
            // The `Err` half is tungstenite's own `ErrorResponse`; the
            // `Callback` contract fixes it, so it cannot be boxed away here.
            #[allow(clippy::result_large_err)]
            let callback = move |request: &Request, response: Response| {
                let headers: Vec<(String, String)> = request
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_ascii_lowercase(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                *seen_in_callback
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = headers.clone();
                log_in_callback.push_handshake(headers);
                match &decide {
                    Some(decide) => decide(request),
                    None => Ok(response),
                }
            };

            let Ok(stream) = accept_hdr_async(server, callback).await else {
                return;
            };
            log.connections.fetch_add(1, Ordering::SeqCst);
            let headers = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
            let ws = Arc::new(AsyncMutex::new(stream));
            let conn = ServerConn {
                ws: Arc::clone(&ws),
                headers,
                log: Arc::clone(&log),
            };
            handler(conn).await;
            // Keep reading after the handler is done so a Close the client sends
            // later is still answered by the tungstenite state machine.
            let mut rest = ws.lock().await;
            while let Some(Ok(_)) = rest.next().await {}
        });
    });
    (transport, log)
}

/// The standard "vulnerable to reflection" server.
///
/// Records every data frame, answers Text with `echo:<text>` and Binary with
/// the same bytes, and returns when the client closes or the stream ends.
pub async fn echo_handler(conn: ServerConn) {
    let mut ws = conn.ws().await;
    while let Some(Ok(message)) = ws.next().await {
        match message {
            Message::Text(text) => {
                conn.record(text.as_bytes().to_vec());
                if ws
                    .send(Message::text(format!("echo:{text}")))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Message::Binary(bytes) => {
                conn.record(bytes.to_vec());
                if ws.send(Message::Binary(bytes)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

/// The canonical captured conversation every in-crate test discovers from.
///
/// A `GET /ws` upgrade to `127.0.0.1:8080` carrying an `Origin`, a `Cookie` and
/// a requested subprotocol, answered `101`, followed by three frames: two
/// client->server JSON texts and one server->client reply. The cookie value is
/// a fixture string and is exactly what the redaction rule must keep out of
/// evidence, examples and logs.
#[must_use]
pub fn captured_conversation() -> (HttpFlow, WsFlow) {
    let peer = SocketAddr::from(([127, 0, 0, 1], 8080));
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_761_000_000);
    let conn = ConnInfo {
        peer,
        sni: None,
        alpn: None,
        tls: false,
        established: at,
    };

    let mut request_headers = HeaderMap::new();
    request_headers.set("Host", "127.0.0.1:8080");
    request_headers.set("Connection", "Upgrade");
    request_headers.set("Upgrade", "websocket");
    request_headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    request_headers.set("Sec-WebSocket-Version", "13");
    request_headers.set("Origin", "https://app.test");
    request_headers.set("Cookie", "sid=s3cr3t-cookie");
    request_headers.set("Sec-WebSocket-Protocol", "chat");
    request_headers.set("User-Agent", "fixture/1");

    let mut response_headers = HeaderMap::new();
    response_headers.set("Upgrade", "websocket");
    response_headers.set("Connection", "Upgrade");
    response_headers.set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    response_headers.set("Sec-WebSocket-Protocol", "chat");

    let handshake = HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".to_string(),
            scheme: "http".to_string(),
            authority: "127.0.0.1:8080".to_string(),
            path: "/ws".to_string(),
            version: HttpVersion::Http11,
            headers: request_headers,
            body: Body::Empty,
            timestamp: at,
        },
        response: Some(HttpResponse {
            status: 101,
            version: HttpVersion::Http11,
            headers: response_headers,
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: at,
        }),
        client_conn: conn.clone(),
        server_conn: Some(conn.clone()),
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    };

    let message = |dir: WsDir, data: &str| WsMessage {
        dir,
        opcode: WsOpcode::Text,
        data: data.as_bytes().to_vec(),
        timestamp: at,
        injected: false,
    };
    let conversation = WsFlow {
        id: FlowId::new(),
        handshake: handshake.id,
        messages: vec![
            message(WsDir::ClientToServer, r#"{"type":"hello"}"#),
            message(WsDir::ClientToServer, r#"{"msg":"hi","user":"bob"}"#),
            message(WsDir::ServerToClient, r#"{"ok":true,"echo":"hi"}"#),
        ],
        client_conn: conn.clone(),
        server_conn: Some(conn),
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    };

    (handshake, conversation)
}

/// A [`ProxyClient`] that refuses: the WS lane never sends through one.
#[derive(Debug, Default)]
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { Err(anyhow::anyhow!("not used by the WS lane")) })
    }
}

/// A [`JobCtx`] over an in-memory store and a real [`StdGuard`].
///
/// The budget is countable: [`TestJob::charged`] reports what a lane spent, and
/// [`JobCtx::charge`] refuses rather than going below zero.
pub struct TestJob {
    job_id: String,
    profile: ScanProfile,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    client: Arc<dyn ProxyClient>,
    budget: AtomicU32,
    charged: AtomicU32,
    cancelled: AtomicBool,
    deadline: Mutex<Instant>,
}

impl TestJob {
    /// A job with `budget` stimuli, the fixture origin in target and in scope.
    #[must_use]
    pub fn new(budget: u32) -> Arc<Self> {
        Self::with(budget, |_| {})
    }

    /// [`TestJob::new`] under a caller-chosen job id.
    ///
    /// The lane's point registry is keyed by job id, so a test that needs two
    /// jobs the lane must keep apart builds the second one through this.
    #[must_use]
    pub fn named(job_id: &str, budget: u32) -> Arc<Self> {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        Self::build(
            job_id,
            Arc::new(MemFlowStore::new()),
            Arc::new(guard),
            budget,
            |_| {},
        )
    }

    /// [`TestJob::new`] with `edit` applied to the profile first.
    #[must_use]
    pub fn with(budget: u32, edit: impl FnOnce(&mut ScanProfile)) -> Arc<Self> {
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1:8080".to_string(),
        });
        Self::over(Arc::new(MemFlowStore::new()), Arc::new(guard), budget, edit)
    }

    /// A job over a caller-supplied store and guard (the live-proof tests build
    /// it over the real pipeline's).
    #[must_use]
    pub fn over(
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
        budget: u32,
        edit: impl FnOnce(&mut ScanProfile),
    ) -> Arc<Self> {
        Self::build("job-1", store, guard, budget, edit)
    }

    /// Every constructor above, with the job id spelled out.
    fn build(
        job_id: &str,
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
        budget: u32,
        edit: impl FnOnce(&mut ScanProfile),
    ) -> Arc<Self> {
        let mut profile = ScanProfile {
            lanes: vec![LaneKind::Ws],
            ws: WsOptions {
                reply_window_ms: 300,
                ..WsOptions::default()
            },
            target: ProfileTarget {
                origins: vec!["http://127.0.0.1:8080".to_string()],
                ..ProfileTarget::default()
            },
            ..ScanProfile::default()
        };
        edit(&mut profile);
        Arc::new(Self {
            job_id: job_id.to_string(),
            profile,
            store,
            guard,
            client: Arc::new(UnusedClient),
            budget: AtomicU32::new(budget),
            charged: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            deadline: Mutex::new(Instant::now() + Duration::from_secs(60)),
        })
    }

    /// Cancel the job, as the engine would.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Move the job's deadline to `at` (the default is a minute from
    /// construction).
    pub fn set_deadline(&self, at: Instant) {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner) = at;
    }

    /// Put the deadline in the past, as a job that ran out of time would be.
    pub fn expire(&self) {
        self.set_deadline(Instant::now());
    }

    /// How many budget units have been charged so far.
    #[must_use]
    pub fn charged(&self) -> u32 {
        self.charged.load(Ordering::SeqCst)
    }
}

impl JobCtx for TestJob {
    fn job_id(&self) -> &str {
        &self.job_id
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn client(&self) -> Arc<dyn ProxyClient> {
        Arc::clone(&self.client)
    }

    fn store(&self) -> Arc<dyn FlowStore> {
        Arc::clone(&self.store)
    }

    fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        Arc::clone(&self.guard)
    }

    fn browser(&self) -> Option<Arc<dyn aitm_core::BrowserDriver>> {
        None
    }

    fn session(&self) -> Option<Arc<SessionMaterial>> {
        None
    }

    fn charge(&self, units: u32) -> bool {
        let mut left = self.budget.load(Ordering::SeqCst);
        loop {
            if units > left {
                return false;
            }
            match self.budget.compare_exchange(
                left,
                left - units,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.charged.fetch_add(units, Ordering::SeqCst);
                    return true;
                }
                Err(actual) => left = actual,
            }
        }
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::SeqCst)
    }

    fn deadline(&self) -> Instant {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn marker(&self) -> String {
        TEST_MARKER.to_string()
    }
}

/// An [`InsertionPoint`] for `spec`, as the lane's discovery would mint it.
#[must_use]
pub fn point(
    kind: InsertionKind,
    name: &str,
    path: Option<&str>,
    spec: PointSpec,
) -> InsertionPoint {
    InsertionPoint {
        id: "ws-test0001".to_string(),
        lane: LaneKind::Ws,
        kind,
        name: name.to_string(),
        path: path.map(str::to_string),
        example: None,
        flow: Some(FlowRef(spec.ws_flow)),
        site_node: None,
        traits: Vec::new(),
        frequency: 1,
        method: None,
        url: None,
    }
}

/// A [`WsProbeHost`] over the fixture conversation's point named `name`.
///
/// Discovery runs over [`captured_conversation`] exactly as the lane's would,
/// so the point and its spec are the real ones; the host dials through
/// `transport` with a fresh [`WsDialer`].
///
/// # Panics
///
/// When the fixture has no point named `name`: a test-harness contract, not a
/// runtime path.
#[must_use]
pub fn host_for(name: &str, job: &Arc<TestJob>, transport: Arc<DuplexTransport>) -> WsProbeHost {
    point_and_host_for(name, job, transport as Arc<dyn WsTransport>).1
}

/// [`host_for`], with the discovered point itself and over any transport.
///
/// A check that reads the point it is aimed at (`ws-subprotocol-observe` and
/// `ws-oversize-frame`) needs both halves; a check that drives a transport of
/// its own (the connect-error cases) needs the `dyn` parameter.
///
/// # Panics
///
/// When the fixture has no point named `name`: a test-harness contract, not a
/// runtime path.
#[must_use]
pub fn point_and_host_for(
    name: &str,
    job: &Arc<TestJob>,
    transport: Arc<dyn WsTransport>,
) -> (InsertionPoint, WsProbeHost) {
    let (handshake, ws) = captured_conversation();
    let mut ids = IdGen::new("job-1");
    let found = discover_flow(&ws, &handshake, &mut ids);
    let at = found
        .points
        .iter()
        .position(|point| point.name == name)
        .unwrap_or_else(|| panic!("the fixture has a point named {name}"));
    let point = found.points[at].clone();
    let host = WsProbeHost::new(
        point.clone(),
        found.specs[at].1.clone(),
        handshake,
        ws,
        Arc::new(WsDialer::new(transport)),
        Arc::clone(job) as Arc<dyn JobCtx>,
    )
    .expect("the fixture point builds a host");
    (point, host)
}

/// The value of one (lowercase) header of the server's `nth` handshake.
#[must_use]
pub fn handshake_header(log: &ServerLog, nth: usize, name: &str) -> Option<String> {
    log.handshakes().get(nth).and_then(|headers| {
        headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.clone())
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::client_async_with_config;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message;

    use super::{captured_conversation, echo_handler, ws_server, DuplexTransport, TestJob};
    use crate::transport::WsTransport;
    use aitm_scan_model::JobCtx;

    #[tokio::test]
    async fn duplex_transport_hands_server_half_to_handler() {
        let transport = DuplexTransport::new(|mut server| {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).await.expect("server read");
                server.write_all(&buf).await.expect("server write");
                server.flush().await.expect("server flush");
            });
        });

        let addr = SocketAddr::from(([10, 0, 0, 1], 1));
        let mut stream = transport
            .connect(addr, false, "h")
            .await
            .expect("duplex connect");
        stream.write_all(b"ping").await.expect("client write");
        stream.flush().await.expect("client flush");

        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.expect("client read");
        assert_eq!(&back, b"ping");
        assert_eq!(transport.connects(), vec![(addr, false, "h".to_string())]);
    }

    #[tokio::test]
    async fn ws_server_echoes_and_logs_handshake() {
        let (transport, log) = ws_server(None, echo_handler);
        let stream = transport
            .connect(SocketAddr::from(([10, 0, 0, 1], 80)), false, "app.test")
            .await
            .expect("duplex connect");

        let mut request = "ws://app.test/ws"
            .into_client_request()
            .expect("client request");
        request
            .headers_mut()
            .insert("cookie", HeaderValue::from_static("a=b"));
        let (mut ws, response) = client_async_with_config(request, stream, None)
            .await
            .expect("client handshake");
        assert_eq!(response.status().as_u16(), 101);

        ws.send(Message::text("hi")).await.expect("send");
        let reply = ws.next().await.expect("a reply").expect("a frame");
        assert_eq!(reply, Message::text("echo:hi"));

        assert_eq!(log.connections(), 1);
        assert!(
            log.handshakes()[0].contains(&("cookie".to_string(), "a=b".to_string())),
            "handshake log missing the cookie header: {:?}",
            log.handshakes()[0]
        );
        assert_eq!(log.received(), vec![b"hi".to_vec()]);
    }

    #[tokio::test]
    async fn captured_conversation_shape() {
        let (handshake, ws) = captured_conversation();

        assert_eq!(ws.messages.len(), 3);
        assert_eq!(
            ws.messages[1].data,
            br#"{"msg":"hi","user":"bob"}"#.to_vec()
        );
        assert_eq!(
            handshake.request.headers.get("cookie"),
            Some("sid=s3cr3t-cookie")
        );
        assert_eq!(ws.handshake, handshake.id);
    }

    #[test]
    fn test_job_charges_and_refuses_past_zero() {
        let job = TestJob::new(2);

        assert!(job.charge(1), "first unit must be affordable");
        assert!(job.charge(1), "second unit must be affordable");
        assert!(!job.charge(1), "third unit must be refused");
        assert_eq!(job.budget_left(), 0);
        assert_eq!(job.charged(), 2);
    }
}

/// What the live-proof tests (`tests/live_lane.rs`, `tests/live_language.rs`)
/// share: the real seeded target process and its control origin.
///
/// Both files spawn T10's `aitm-testtarget-serve` the same way and read the
/// same control endpoints back, so the process handling lives here once
/// (quality finding, live tests). Nothing here is a fixture: it starts a real
/// binary and speaks real HTTP/1.1 to it.
#[doc(hidden)]
pub mod live {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    /// What a run without `$AITM_TESTTARGET_BIN` panics with (plan call 35).
    ///
    /// A missing target must read as a failure to be fixed, never as a silent
    /// green, so every path here panics rather than returning early.
    pub const SKIP: &str =
        "SKIP: set AITM_TESTTARGET_BIN to a serve binary that has /ws (T10 branch)";

    /// How long [`Target::start`] waits for the target's `ready` line.
    const READY_TIMEOUT: Duration = Duration::from_secs(15);

    /// T10's `aitm-testtarget-serve`, running with its control origin.
    pub struct Target {
        child: Child,
        /// Drains the child's stdout for the whole run, so a chatty target
        /// never blocks writing into a full pipe. Ends at EOF, which `Drop`
        /// causes by killing the child.
        _drain: JoinHandle<()>,
        /// `http://127.0.0.1:<port>` of the seeded origin.
        pub origin: String,
        /// `http://127.0.0.1:<port>` of the control origin.
        pub control: String,
    }

    impl Target {
        /// Spawn the binary in `mode` and read its listen lines up to `ready`.
        ///
        /// # Panics
        ///
        /// Without `$AITM_TESTTARGET_BIN`, when the binary will not spawn, when
        /// it exits before `ready`, when it has not printed `ready` within
        /// [`READY_TIMEOUT`], or when it names no origin.
        #[must_use]
        pub fn start(mode: &str) -> Self {
            let Ok(bin) = std::env::var("AITM_TESTTARGET_BIN") else {
                panic!("{SKIP}");
            };
            let mut child = Command::new(&bin)
                .args(["--mode", mode, "--port", "0", "--control-port", "0"])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap_or_else(|err| panic!("{SKIP} (spawning {bin} failed: {err})"));
            let stdout = child.stdout.take().expect("the child's stdout is piped");
            let (lines, drain) = drain_lines(stdout);

            let mut origin = None;
            let mut control = None;
            let deadline = Instant::now() + READY_TIMEOUT;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let line = match lines.recv_timeout(left) {
                    Ok(line) => line,
                    Err(RecvTimeoutError::Timeout) => panic!(
                        "{SKIP} (the target printed no `ready` line within {}s; it reported \
                         {origin:?} / {control:?})",
                        READY_TIMEOUT.as_secs()
                    ),
                    Err(RecvTimeoutError::Disconnected) => panic!(
                        "{SKIP} (the target exited before `ready`; it reported {origin:?} / \
                         {control:?})"
                    ),
                };
                if let Some(rest) = line.strip_prefix("listening ") {
                    origin = Some(rest.to_string());
                } else if let Some(rest) = line.strip_prefix("control ") {
                    control = Some(rest.to_string());
                } else if line == "ready" {
                    break;
                }
            }

            let origin = origin.expect("the target printed a `listening` line");
            let control =
                control.expect("the target printed a `control` line (it needs --control-port)");
            println!("target[{mode}] origin={origin} control={control}");
            Self {
                child,
                _drain: drain,
                origin,
                control,
            }
        }

        /// `127.0.0.1:<port>` of the seeded origin.
        #[must_use]
        pub fn authority(&self) -> String {
            strip_scheme(&self.origin).to_string()
        }
    }

    impl Drop for Target {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Read `stdout` on a thread, forwarding trimmed lines until the receiver
    /// is dropped and swallowing everything after that.
    ///
    /// The swallowing half is the point: once the caller has its `ready` line
    /// it stops reading, and a target that keeps logging would otherwise fill
    /// the pipe buffer and block mid-request.
    fn drain_lines(stdout: impl Read + Send + 'static) -> (Receiver<String>, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                if sender.send(line.trim().to_string()).is_err() {
                    // Nobody is listening any more: keep the pipe empty.
                    let mut rest = Vec::new();
                    let _ = reader.read_to_end(&mut rest);
                    return;
                }
            }
        });
        (receiver, handle)
    }

    /// `http://host:port` without its scheme.
    #[must_use]
    pub fn strip_scheme(origin: &str) -> &str {
        origin.split_once("://").map_or(origin, |(_, rest)| rest)
    }

    /// `GET <path>` on the control origin, parsed as JSON.
    ///
    /// Deliberately hand-written and blocking: the control origin speaks plain
    /// HTTP/1.1 over loopback to a separate process, and the crate takes no
    /// HTTP client dependency for its tests.
    ///
    /// # Panics
    ///
    /// When the control origin will not answer, or answers something that is
    /// not JSON.
    #[must_use]
    pub fn control_json(control: &str, path: &str) -> Value {
        let authority = strip_scheme(control);
        let mut stream = TcpStream::connect(authority)
            .unwrap_or_else(|err| panic!("connect the control origin {authority}: {err}"));
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .unwrap_or_else(|err| panic!("send GET {path}: {err}"));
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .unwrap_or_else(|err| panic!("read GET {path}: {err}"));
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("GET {path} answered no head/body: {text:?}"));
        serde_json::from_str(body)
            .unwrap_or_else(|err| panic!("{path} is not JSON ({err}); head was {head:?}"))
    }
}
