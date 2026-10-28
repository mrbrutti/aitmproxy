//! F6: the meta plugin's `flow.mark` and `flow.comment` commands.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, StdGuard, Value,
};
use aitm_plugins::MetaPlugin;
use futures::future::BoxFuture;

fn http_flow() -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/a".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }),
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn marks(flow: &Flow) -> Vec<String> {
    match flow {
        Flow::Http(f) => f.metadata.marks.clone(),
        Flow::WebSocket(f) => f.metadata.marks.clone(),
    }
}

fn comment(flow: &Flow) -> Option<String> {
    match flow {
        Flow::Http(f) => f.metadata.comment.clone(),
        Flow::WebSocket(f) => f.metadata.comment.clone(),
    }
}

#[test]
fn flow_mark_sets_and_replaces_marks() {
    let mut reg = Registry::new();
    let plugin = MetaPlugin::new();
    assert_eq!(plugin.name(), "meta");
    reg.add_plugin(Box::new(plugin));

    let store = MemFlowStore::new();
    let id = store.insert(http_flow());
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    map.insert(
        "marks".to_string(),
        Value::Array(vec![Value::Str("red".into()), Value::Str("blue".into())]),
    );
    let out = reg
        .command("flow.mark")
        .expect("flow.mark registered")
        .invoke(Params::new(map), &host)
        .expect("flow.mark ok");
    assert_eq!(
        out,
        Value::Array(vec![Value::Str("red".into()), Value::Str("blue".into())])
    );
    assert_eq!(marks(&store.get(id).unwrap()), vec!["red", "blue"]);

    // Marking again replaces the set (idempotent), including clearing to empty.
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    map.insert("marks".to_string(), Value::Array(vec![]));
    reg.command("flow.mark")
        .unwrap()
        .invoke(Params::new(map), &host)
        .expect("flow.mark clear ok");
    assert!(marks(&store.get(id).unwrap()).is_empty());
}

#[test]
fn flow_comment_sets_and_clears() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(MetaPlugin::new()));
    let store = MemFlowStore::new();
    let id = store.insert(http_flow());
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    map.insert("text".to_string(), Value::Str("needs review".into()));
    let out = reg
        .command("flow.comment")
        .expect("flow.comment registered")
        .invoke(Params::new(map), &host)
        .expect("flow.comment ok");
    assert_eq!(out, Value::Str("needs review".into()));
    assert_eq!(
        comment(&store.get(id).unwrap()).as_deref(),
        Some("needs review")
    );

    // An empty string clears the comment back to null.
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    map.insert("text".to_string(), Value::Str(String::new()));
    let out = reg
        .command("flow.comment")
        .unwrap()
        .invoke(Params::new(map), &host)
        .expect("flow.comment clear ok");
    assert_eq!(out, Value::Null);
    assert_eq!(comment(&store.get(id).unwrap()), None);
}

#[test]
fn unknown_id_is_an_error() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(MetaPlugin::new()));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let missing = FlowId::new();
    for (cmd, extra) in [
        ("flow.mark", ("marks", Value::Array(vec![]))),
        ("flow.comment", ("text", Value::Str("x".into()))),
    ] {
        let mut map = BTreeMap::new();
        map.insert("id".to_string(), Value::Str(missing.to_string()));
        map.insert(extra.0.to_string(), extra.1);
        let err = reg
            .command(cmd)
            .unwrap()
            .invoke(Params::new(map), &host)
            .expect_err("unknown id must be refused");
        assert!(
            err.to_string().contains(&missing.to_string()),
            "{cmd} error should name the id: {err}"
        );
    }
}
