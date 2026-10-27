//! Task 13: the capture plugin's read commands, `flow.list` and `flow.get`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, StdGuard, Value,
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
