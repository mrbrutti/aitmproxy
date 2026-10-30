//! Task 13: the capture plugin's read commands, `flow.list` and `flow.get`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, StdGuard, Value, WsFlow,
};
use aitm_plugins::CapturePlugin;
use futures::future::BoxFuture;

fn http_flow(method: &str, path: &str, status: Option<u16>) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: method.into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: status.map(|status| HttpResponse {
            status,
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

/// The read commands never reissue anything; the host still needs a client.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn id_params(id: FlowId) -> Params {
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    Params::new(map)
}

#[test]
fn flow_list_and_get() {
    let mut reg = Registry::new();
    let plugin = CapturePlugin::new();
    assert_eq!(plugin.name(), "capture");
    reg.add_plugin(Box::new(plugin));

    let store = MemFlowStore::new();
    let first = store.insert(http_flow("GET", "/a", None));
    let second = store.insert(http_flow("POST", "/b", Some(201)));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let list = reg
        .command("flow.list")
        .expect("flow.list registered")
        .invoke(Params::default(), &host)
        .expect("flow.list ok");
    assert_eq!(
        list,
        Value::Array(vec![
            Value::Str(first.to_string()),
            Value::Str(second.to_string()),
        ])
    );

    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(first), &host)
        .expect("flow.get ok");
    let Value::Object(obj) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    assert_eq!(obj.get("id"), Some(&Value::Str(first.to_string())));
    assert_eq!(obj.get("method"), Some(&Value::Str("GET".into())));
    assert_eq!(obj.get("path"), Some(&Value::Str("/a".into())));
    assert_eq!(obj.get("status"), Some(&Value::Null));

    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(second), &host)
        .expect("flow.get ok");
    let Value::Object(obj) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    assert_eq!(obj.get("method"), Some(&Value::Str("POST".into())));
    assert_eq!(obj.get("status"), Some(&Value::Int(201)));
}

#[test]
fn flow_get_unknown_id_is_an_error() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let missing = FlowId::new();
    let err = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(missing), &host)
        .expect_err("unknown id must be refused");
    assert!(
        err.to_string().contains(&missing.to_string()),
        "error should name the id: {err}"
    );
}

fn ws_flow(handshake: FlowId) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake,
        messages: Vec::new(),
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

#[test]
fn flow_table_rows() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let store = MemFlowStore::new();
    let http = store.insert(http_flow("GET", "/a", Some(200)));
    let _ws = store.insert(ws_flow(http));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let table = reg
        .command("flow.table")
        .expect("flow.table registered")
        .invoke(Params::default(), &host)
        .expect("flow.table ok");

    let Value::Object(obj) = table else {
        panic!("flow.table must return an object, got {table:?}");
    };
    let Some(Value::Array(rows)) = obj.get("flows") else {
        panic!("flow.table result must have a `flows` array: {obj:?}");
    };
    assert_eq!(rows.len(), 2, "two flows captured");

    let Value::Object(http_row) = &rows[0] else {
        panic!("row 0 must be an object, got {:?}", rows[0]);
    };
    assert_eq!(http_row.get("kind"), Some(&Value::Str("http".into())));
    assert_eq!(http_row.get("method"), Some(&Value::Str("GET".into())));
    assert_eq!(http_row.get("status"), Some(&Value::Int(200)));
    assert_eq!(http_row.get("state"), Some(&Value::Str("observed".into())));
    assert_eq!(
        http_row.get("marks"),
        Some(&Value::Array(vec![])),
        "no marks by default"
    );

    let Value::Object(ws_row) = &rows[1] else {
        panic!("row 1 must be an object, got {:?}", rows[1]);
    };
    assert_eq!(ws_row.get("kind"), Some(&Value::Str("websocket".into())));
    assert_eq!(ws_row.get("method"), Some(&Value::Null));
    assert_eq!(ws_row.get("state"), Some(&Value::Str("observed".into())));
}

#[test]
fn flow_list_unchanged_ids_only() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let store = MemFlowStore::new();
    let first = store.insert(http_flow("GET", "/a", Some(200)));
    let second = store.insert(ws_flow(first));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let list = reg
        .command("flow.list")
        .expect("flow.list registered")
        .invoke(Params::default(), &host)
        .expect("flow.list ok");
    assert_eq!(
        list,
        Value::Array(vec![
            Value::Str(first.to_string()),
            Value::Str(second.to_string()),
        ]),
        "flow.list is a bare array of id strings, oldest first"
    );
}
