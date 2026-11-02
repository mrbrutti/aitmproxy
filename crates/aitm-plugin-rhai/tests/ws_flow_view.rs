//! The script-visible view of a WebSocket flow (spec AC T10-3): a WS flow's
//! `flow.request` is its upgrade handshake, with the URL carrying the `ws://` /
//! `wss://` scheme, so the bundled `scripts/bundled/ws/` passive detectors can
//! read the URL and the handshake headers in `on_ws_start`.
//!
//! Each case loads the real bundled script through the hardened loader, stores
//! the handshake `HttpFlow` the way the WebSocket module does, dispatches
//! `WsStart` on a `WsFlow` linked to it, and asserts the exact findings.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, ProxyClient, StdGuard, WsFlow,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::host_core::{Finding, MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_plugin_rhai::plugin::LoadedScript;
use aitm_plugin_rhai::{ErrorSink, FindingSink};

const MAX_BODY: usize = 1 << 20;

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn bundled_ws(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
        .join("ws")
        .join(format!("{name}.rhai"))
}

fn conn(tls: bool) -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("addr"),
        sni: None,
        alpn: None,
        tls,
        established: SystemTime::now(),
    }
}

/// The upgrade request for `<scheme>://127.0.0.1:8080/ws`, with `extra`
/// headers on top of the mandatory WebSocket ones.
fn handshake(scheme: &str, extra: &[(&str, &str)]) -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "127.0.0.1:8080");
    headers.set("Upgrade", "websocket");
    headers.set("Connection", "Upgrade");
    headers.set("Sec-WebSocket-Version", "13");
    headers.set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    for (k, v) in extra {
        headers.set(k, v);
    }
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: scheme.into(),
            authority: "127.0.0.1:8080".into(),
            path: "/ws".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(scheme == "https"),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// One loaded bundled script over a fresh store and finding sink.
struct Rig {
    store: Arc<MemFlowStore>,
    findings: Arc<MemoryFindingSink>,
    errors: Arc<ErrorSink>,
    script: LoadedScript,
    name: String,
}

impl Rig {
    fn new(script: &str) -> Self {
        let store = Arc::new(MemFlowStore::new());
        let findings = Arc::new(MemoryFindingSink::new());
        let services = ScriptServices {
            store: store.clone(),
            client: Arc::new(StubClient),
            browser: None,
            guard: Arc::new(StdGuard::default()),
            findings: findings.clone(),
            rt: tokio::runtime::Handle::current(),
        };
        let loader = RhaiLoader::new(
            RhaiConfig {
                limits: RhaiLimits::default(),
                ..RhaiConfig::default()
            },
            services,
        )
        .expect("engine builds");
        let errors = Arc::new(ErrorSink::default());
        let script = loader
            .load_one(&ScriptEntry::new(bundled_ws(script)))
            .expect("bundled script loads")
            .with_error_sink(errors.clone());
        let name = script.meta().name.clone();
        Self {
            store,
            findings,
            errors,
            script,
            name,
        }
    }

    /// Store `handshake` the way the WebSocket module does, link a fresh
    /// `WsFlow` to it, and dispatch `on_ws_start`. Returns the findings recorded
    /// and the WS flow's id; a runtime error in the hook fails the test.
    fn ws_start(&self, handshake: Flow) -> (Vec<Finding>, FlowId) {
        let tls = matches!(&handshake, Flow::Http(h) if h.client_conn.tls);
        let hs_id = self.store.insert(handshake);
        let mut flow = Flow::WebSocket(WsFlow {
            id: FlowId::new(),
            handshake: hs_id,
            messages: Vec::new(),
            client_conn: conn(tls),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        });
        let id = flow.id();
        let before = self.findings.list().len();
        self.script
            .dispatch(&Event::WsStart(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
        if let Some(err) = self.errors.last_error(&self.name) {
            panic!("{} raised in on_ws_start: {err}", self.name);
        }
        (self.findings.list().split_off(before), id)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cleartext_ws_handshake_produces_the_ws_cleartext_transport_finding() {
    let rig = Rig::new("ws-cleartext-transport");

    let (found, id) = rig.ws_start(handshake("http", &[]));
    assert_eq!(
        found.len(),
        1,
        "a ws:// handshake must produce exactly one finding, got {found:#?}"
    );
    let f = &found[0];
    assert_eq!(f.source, "ws-cleartext-transport");
    assert_eq!(f.name, "WebSocket over cleartext ws://");
    assert_eq!(f.flow, Some(id));
    assert_eq!(
        f.detail.as_deref(),
        Some(
            "The WebSocket to ws://127.0.0.1:8080/ws uses plaintext ws://; frames can be read \
             and tampered with on-path. Use wss://."
        )
    );
    assert_eq!(f.tags, ["websocket", "transport-security", "owasp-a02"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_ws_handshake_produces_no_cleartext_finding() {
    let rig = Rig::new("ws-cleartext-transport");
    let (found, _) = rig.ws_start(handshake("https", &[]));
    assert!(
        found.is_empty(),
        "a wss:// handshake must not be flagged as cleartext, got {found:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cookie_authenticated_handshake_produces_the_hijack_indicator() {
    let rig = Rig::new("ws-cross-site-hijack-indicator");

    let (found, id) = rig.ws_start(handshake(
        "http",
        &[("Cookie", "sid=abc123"), ("Origin", "https://evil.example")],
    ));
    assert_eq!(
        found.len(),
        1,
        "a cookie-authenticated handshake must produce exactly one finding, got {found:#?}"
    );
    let f = &found[0];
    assert_eq!(f.source, "ws-cross-site-hijack-indicator");
    assert_eq!(f.name, "Cookie-authenticated WebSocket handshake");
    assert_eq!(f.flow, Some(id));
    assert_eq!(
        f.detail.as_deref(),
        Some(
            "The WebSocket handshake to ws://127.0.0.1:8080/ws is authenticated by cookie \
             (Origin: https://evil.example); confirm the server validates Origin to prevent \
             Cross-Site WebSocket Hijacking."
        )
    );
    assert_eq!(f.tags, ["websocket", "cswsh", "owasp-a01"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn cookieless_handshake_produces_no_hijack_indicator() {
    let rig = Rig::new("ws-cross-site-hijack-indicator");
    let (found, _) = rig.ws_start(handshake("http", &[("Origin", "https://evil.example")]));
    assert!(
        found.is_empty(),
        "a handshake without a Cookie is not a CSWSH candidate, got {found:#?}"
    );
}
