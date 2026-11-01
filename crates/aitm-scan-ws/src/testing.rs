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
    connects: Mutex<Vec<(String, u16, bool, String)>>,
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

    /// Every `(host, port, tls, sni)` the dialer asked for, in order.
    #[must_use]
    pub fn connects(&self) -> Vec<(String, u16, bool, String)> {
        self.connects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl WsTransport for DuplexTransport {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        tls: bool,
        sni: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
        Box::pin(async move {
            let (client, server) = duplex(64 * 1024);
            self.connects
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((host.to_string(), port, tls, sni.to_string()));
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
    profile: ScanProfile,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    client: Arc<dyn ProxyClient>,
    budget: AtomicU32,
    charged: AtomicU32,
    cancelled: AtomicBool,
    deadline: Instant,
}

impl TestJob {
    /// A job with `budget` stimuli, the fixture origin in target and in scope.
    #[must_use]
    pub fn new(budget: u32) -> Arc<Self> {
        Self::with(budget, |_| {})
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
            profile,
            store,
            guard,
            client: Arc::new(UnusedClient),
            budget: AtomicU32::new(budget),
            charged: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            deadline: Instant::now() + Duration::from_secs(60),
        })
    }

    /// Cancel the job, as the engine would.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// How many budget units have been charged so far.
    #[must_use]
    pub fn charged(&self) -> u32 {
        self.charged.load(Ordering::SeqCst)
    }
}

impl JobCtx for TestJob {
    fn job_id(&self) -> &str {
        "job-1"
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
        self.deadline
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

#[cfg(test)]
mod tests {
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

        let mut stream = transport
            .connect("h", 1, false, "h")
            .await
            .expect("duplex connect");
        stream.write_all(b"ping").await.expect("client write");
        stream.flush().await.expect("client flush");

        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.expect("client read");
        assert_eq!(&back, b"ping");
        assert_eq!(
            transport.connects(),
            vec![("h".to_string(), 1u16, false, "h".to_string())]
        );
    }

    #[tokio::test]
    async fn ws_server_echoes_and_logs_handshake() {
        let (transport, log) = ws_server(None, echo_handler);
        let stream = transport
            .connect("app.test", 80, false, "app.test")
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
