//! Task 16: `flow.mutate` edits a stored flow's request in place (AC5 command
//! path); `request.send` crafts a request and sends it through the guarded proxy
//! client (AC16 gating).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_plugins::MutatePlugin;
use futures::future::BoxFuture;

fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

fn captured_get() -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Accept", "*/*");
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/a".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// Records every request it is handed, answers 200, and stores the result as a
/// replay flow — the `ProxyClient` contract without a network.
struct EchoClient {
    store: Arc<MemFlowStore>,
    sent: Mutex<Vec<HttpRequest>>,
}

impl EchoClient {
    fn new(store: Arc<MemFlowStore>) -> Self {
        Self {
            store,
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<HttpRequest> {
        self.sent.lock().expect("sent lock").clone()
    }
}

/// A `RequestSender` that records requests and answers 200 — wrapped in a
/// `PipelineClient` (the single guard chokepoint) by the scope test.
struct EchoSender {
    sent: Mutex<Vec<HttpRequest>>,
}

impl EchoSender {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
        }
    }
    fn sent(&self) -> Vec<HttpRequest> {
        self.sent.lock().expect("sent lock").clone()
    }
}

impl aitm_core::RequestSender for EchoSender {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        self.sent.lock().expect("sent lock").push(req.clone());
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            })
        })
    }
}

impl ProxyClient for EchoClient {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async move {
            self.sent.lock().expect("sent lock").push(req.clone());
            let flow = HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(HttpResponse {
                    status: 200,
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    trailers: HeaderMap::new(),
                    body: Body::Empty,
                    timestamp: SystemTime::now(),
                }),
                client_conn: conn(),
                server_conn: None,
                metadata: FlowMeta {
                    is_replay: true,
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            };
            self.store.insert(Flow::Http(flow.clone()));
            Ok(flow)
        })
    }
}

fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn params(pairs: &[(&str, Value)]) -> Params {
    let Value::Object(map) = obj(pairs) else {
        unreachable!()
    };
    Params::new(map)
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

fn registry() -> Registry {
    let mut reg = Registry::new();
    let plugin = MutatePlugin::new();
    assert_eq!(plugin.name(), "mutate");
    reg.add_plugin(Box::new(plugin));
    reg
}

fn stored_request(store: &MemFlowStore, id: FlowId) -> HttpRequest {
    match store.get(id) {
        Some(Flow::Http(f)) => f.request,
        other => panic!("expected a stored HTTP flow, got {other:?}"),
    }
}

#[test]
fn mutate_edits_flow() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let id = store.insert(captured_get());
    let guard = StdGuard::default();
    let client = EchoClient::new(store.clone());
    let host = CommandHost::new(&*store, &client, &guard, None);
    let mutate = reg.command("flow.mutate").expect("flow.mutate registered");

    // Add a header; everything else is untouched.
    mutate
        .invoke(
            params(&[
                ("id", s(&id.to_string())),
                ("edits", obj(&[("headers", obj(&[("X-Aitm", s("on"))]))])),
            ]),
            &host,
        )
        .expect("header edit applies");
    let req = stored_request(&store, id);
    assert_eq!(req.headers.get("X-Aitm"), Some("on"));
    assert_eq!(req.headers.get("Accept"), Some("*/*"));
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/a");

    // Replace method, path, body, and an existing header (replace, not append).
    mutate
        .invoke(
            params(&[
                ("id", s(&id.to_string())),
                (
                    "edits",
                    obj(&[
                        ("method", s("POST")),
                        ("path", s("/b?x=1")),
                        ("body", s("q=1")),
                        ("headers", obj(&[("Accept", s("text/html"))])),
                    ]),
                ),
            ]),
            &host,
        )
        .expect("request-line edits apply");
    let req = stored_request(&store, id);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/b?x=1");
    assert!(matches!(&req.body, Body::Bytes(b) if b == b"q=1"));
    assert_eq!(req.headers.get("Accept"), Some("text/html"));
    assert_eq!(
        req.headers.iter().filter(|(k, _)| *k == "Accept").count(),
        1,
        "a header edit replaces the existing value"
    );
    assert_eq!(req.headers.get("X-Aitm"), Some("on"));
    assert!(client.sent().is_empty(), "flow.mutate never sends anything");
}

#[test]
fn mutate_rejects_unknown_edit() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let id = store.insert(captured_get());
    let guard = StdGuard::default();
    let client = EchoClient::new(store.clone());
    let host = CommandHost::new(&*store, &client, &guard, None);

    let err = reg
        .command("flow.mutate")
        .expect("flow.mutate registered")
        .invoke(
            params(&[
                ("id", s(&id.to_string())),
                ("edits", obj(&[("bogus", Value::Int(1))])),
            ]),
            &host,
        )
        .expect_err("unknown edit keys are refused");
    assert!(err.to_string().contains("bogus"), "names the key: {err}");
    assert_eq!(stored_request(&store, id).method, "GET");
}

#[test]
fn request_send_scope_gated() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default()); // empty scope
    let sender = Arc::new(EchoSender::new());
    // The PipelineClient is the single scope chokepoint; it must refuse an
    // out-of-scope send before the sender is ever reached.
    let client = aitm_core::PipelineClient::new(store.clone(), guard.clone(), sender.clone());
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
    let send = reg
        .command("request.send")
        .expect("request.send registered");
    let crafted = params(&[
        ("method", s("POST")),
        ("scheme", s("https")),
        ("authority", s("ex.test")),
        ("path", s("/probe")),
        ("headers", obj(&[("X-Probe", s("1"))])),
        ("body", s("p=1")),
    ]);

    let err = send
        .invoke(crafted.clone(), &host)
        .expect_err("out-of-scope send is refused");
    assert!(err.to_string().contains("scope"), "mentions scope: {err}");
    assert!(sender.sent().is_empty(), "nothing reached the client");
    assert!(store.list().is_empty());

    guard.add_scope(ScopeEntry {
        host: "ex.test".into(),
    });
    let out = send.invoke(crafted, &host).expect("in-scope send succeeds");
    let Value::Str(id) = out else {
        panic!("request.send must return the new flow id, got {out:?}");
    };
    let id: FlowId = id.parse().expect("a valid flow id");
    let sent = sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].scheme, "https");
    assert_eq!(sent[0].authority, "ex.test");
    assert_eq!(sent[0].path, "/probe");
    assert_eq!(sent[0].headers.get("X-Probe"), Some("1"));
    assert!(matches!(&sent[0].body, Body::Bytes(b) if b == b"p=1"));
    let Some(Flow::Http(stored)) = store.get(id) else {
        panic!("the sent request is captured");
    };
    assert!(stored.metadata.is_replay);
    assert_eq!(stored.response.map(|r| r.status), Some(200));

    // Only the authority is required; the rest defaults to `GET http …/`.
    let out = send
        .invoke(params(&[("authority", s("ex.test"))]), &host)
        .expect("minimal send succeeds");
    assert!(matches!(out, Value::Str(_)));
    let sent = sender.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].method, "GET");
    assert_eq!(sent[1].scheme, "http");
    assert_eq!(sent[1].path, "/");
    assert!(sent[1].headers.is_empty());
    assert!(matches!(sent[1].body, Body::Empty));
}
