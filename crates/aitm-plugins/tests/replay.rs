//! Task 14 (AC6): `flow.replay` reissues a captured request through the proxy's
//! own client and the result is a fresh flow marked `is_replay`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, PipelineClient,
    Plugin, Registry, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use aitm_plugins::ReplayPlugin;
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

fn captured_get(path: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
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

/// Answers 200 without its own guard; the `PipelineClient` wrapping it is the
/// single scope/rate chokepoint and marks + stores the replay flow.
struct EchoSender;

impl aitm_core::RequestSender for EchoSender {
    fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Bytes(b"echo".to_vec()),
                timestamp: SystemTime::now(),
            })
        })
    }
}

fn id_params(id: FlowId) -> Params {
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    Params::new(map)
}

fn registry() -> Registry {
    let mut reg = Registry::new();
    let plugin = ReplayPlugin::new();
    assert_eq!(plugin.name(), "replay");
    reg.add_plugin(Box::new(plugin));
    reg
}

#[test]
fn replay_marks_is_replay() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let original = store.insert(captured_get("/a"));
    let guard = Arc::new(StdGuard::default());
    guard.add_scope(ScopeEntry {
        host: "ex.test".into(),
    });
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(EchoSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let out = reg
        .command("flow.replay")
        .expect("flow.replay registered")
        .invoke(id_params(original), &host)
        .expect("replay in scope succeeds");
    let Value::Str(new_id) = out else {
        panic!("flow.replay must return the new flow id as a string, got {out:?}");
    };
    let new_id: FlowId = new_id.parse().expect("a valid flow id");
    assert_ne!(new_id, original, "replay must produce a fresh flow");

    let Some(Flow::Http(replayed)) = store.get(new_id) else {
        panic!("replayed flow must be stored");
    };
    assert!(replayed.metadata.is_replay);
    assert_eq!(replayed.request.path, "/a");
    assert_eq!(
        replayed.response.as_ref().map(|r| r.status),
        Some(200),
        "replay carries the fresh response"
    );
    assert_eq!(store.list(), vec![original, new_id]);
}

#[test]
fn replay_out_of_scope_refused() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let original = store.insert(captured_get("/a"));
    let guard = Arc::new(StdGuard::default()); // empty scope: deny by default
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(EchoSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let err = reg
        .command("flow.replay")
        .expect("flow.replay registered")
        .invoke(id_params(original), &host)
        .expect_err("out-of-scope replay must be refused");
    assert!(
        err.to_string().contains("scope"),
        "refusal should mention scope: {err}"
    );
    assert_eq!(store.list(), vec![original], "nothing was sent");
}

#[test]
fn replay_unknown_flow_is_an_error() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(EchoSender));
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let missing = FlowId::new();
    let err = reg
        .command("flow.replay")
        .expect("flow.replay registered")
        .invoke(id_params(missing), &host)
        .expect_err("unknown id must be refused");
    assert!(err.to_string().contains(&missing.to_string()));
}
