//! F5: the detail plugin's `flow.detail` command — the full inspector shape.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    StdGuard, Value,
};
use aitm_plugins::DetailPlugin;
use futures::future::BoxFuture;

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.try_set(k, v).unwrap();
    }
    h
}

fn flow_with_bodies() -> Flow {
    let caddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 52114));
    let saddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "api.ex.test".into(),
            path: "/login?q=1".into(),
            version: HttpVersion::H2,
            headers: headers(&[
                ("host", "api.ex.test"),
                ("content-type", "application/json"),
            ]),
            body: Body::Bytes(b"{\"u\":\"a\"}".to_vec()),
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::H2,
            headers: headers(&[("content-type", "application/json")]),
            body: Body::Bytes(b"{\"token\":\"xyz\"}".to_vec()),
            timestamp: SystemTime::now(),
        }),
        client_conn: ConnInfo {
            peer: caddr,
            sni: Some("api.ex.test".into()),
            alpn: Some("h2".into()),
            tls: true,
            established: SystemTime::now(),
        },
        server_conn: Some(ConnInfo {
            peer: saddr,
            sni: Some("api.ex.test".into()),
            alpn: Some("h2".into()),
            tls: true,
            established: SystemTime::now(),
        }),
        metadata: FlowMeta {
            comment: Some("look here".into()),
            duration: Some(Duration::from_millis(2400)),
            ..FlowMeta::default()
        },
        intercept: InterceptState::Observed,
    })
}

fn detail(store: &dyn FlowStore, id: FlowId, body_mode: Option<&str>) -> BTreeMap<String, Value> {
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(DetailPlugin::new()));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(store, &client, &guard, None);
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    if let Some(m) = body_mode {
        map.insert("body".to_string(), Value::Str(m.to_string()));
    }
    let out = reg
        .command("flow.detail")
        .expect("flow.detail registered")
        .invoke(Params::new(map), &host)
        .expect("flow.detail ok");
    match out {
        Value::Object(o) => o,
        other => panic!("flow.detail must return an object, got {other:?}"),
    }
}

fn obj<'a>(m: &'a BTreeMap<String, Value>, k: &str) -> &'a BTreeMap<String, Value> {
    match m.get(k) {
        Some(Value::Object(o)) => o,
        other => panic!("expected object at `{k}`, got {other:?}"),
    }
}

#[test]
fn http_detail_inline_has_headers_bodies_conn_meta() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());
    let d = detail(&store, id, Some("inline"));

    assert_eq!(d.get("id"), Some(&Value::Str(id.to_string())));
    assert_eq!(d.get("kind"), Some(&Value::Str("http".into())));
    assert_eq!(d.get("intercept"), Some(&Value::Str("observed".into())));
    assert_eq!(d.get("edited"), Some(&Value::Bool(false)));

    let req = obj(&d, "request");
    assert_eq!(req.get("method"), Some(&Value::Str("POST".into())));
    assert_eq!(req.get("scheme"), Some(&Value::Str("https".into())));
    assert_eq!(
        req.get("authority"),
        Some(&Value::Str("api.ex.test".into()))
    );
    assert_eq!(req.get("path"), Some(&Value::Str("/login?q=1".into())));
    assert_eq!(req.get("version"), Some(&Value::Str("HTTP/2".into())));
    // Headers are [name, value] pairs, in order.
    assert_eq!(
        req.get("headers"),
        Some(&Value::Array(vec![
            Value::Array(vec![
                Value::Str("host".into()),
                Value::Str("api.ex.test".into())
            ]),
            Value::Array(vec![
                Value::Str("content-type".into()),
                Value::Str("application/json".into())
            ]),
        ]))
    );
    // Inline body is the raw bytes (base64 over the bus).
    assert_eq!(
        req.get("body"),
        Some(&Value::Bytes(b"{\"u\":\"a\"}".to_vec()))
    );
    assert_eq!(req.get("body_size"), Some(&Value::Int(9)));

    let resp = obj(&d, "response");
    assert_eq!(resp.get("status"), Some(&Value::Int(200)));
    assert_eq!(
        resp.get("body"),
        Some(&Value::Bytes(b"{\"token\":\"xyz\"}".to_vec()))
    );

    let cc = obj(&d, "client_conn");
    assert_eq!(cc.get("peer"), Some(&Value::Str("127.0.0.1:52114".into())));
    assert_eq!(cc.get("sni"), Some(&Value::Str("api.ex.test".into())));
    assert_eq!(cc.get("alpn"), Some(&Value::Str("h2".into())));
    assert_eq!(cc.get("tls"), Some(&Value::Bool(true)));
    // Peer→process resolution is deferred (Q6/F2); reported as null, not omitted.
    assert_eq!(cc.get("process"), Some(&Value::Null));

    let sc = obj(&d, "server_conn");
    assert_eq!(sc.get("peer"), Some(&Value::Str("203.0.113.9:443".into())));

    let meta = obj(&d, "meta");
    assert_eq!(meta.get("comment"), Some(&Value::Str("look here".into())));
    assert_eq!(meta.get("is_replay"), Some(&Value::Bool(false)));
    assert_eq!(meta.get("duration_ms"), Some(&Value::Int(2400)));
    assert_eq!(meta.get("marks"), Some(&Value::Array(vec![])));
    // `created` is an RFC3339 string.
    let Some(Value::Str(created)) = meta.get("created") else {
        panic!("meta.created must be a string: {meta:?}");
    };
    assert!(
        created.contains('T') && created.ends_with('Z'),
        "created={created}"
    );
}

#[test]
fn body_none_omits_bytes_but_keeps_size() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());
    let d = detail(&store, id, Some("none"));
    let req = obj(&d, "request");
    assert_eq!(req.get("body"), Some(&Value::Null));
    assert_eq!(req.get("body_size"), Some(&Value::Int(9)));
    let resp = obj(&d, "response");
    assert_eq!(resp.get("body"), Some(&Value::Null));
    assert_eq!(resp.get("body_size"), Some(&Value::Int(15)));
}

#[test]
fn default_body_mode_is_inline() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());
    let d = detail(&store, id, None);
    let req = obj(&d, "request");
    assert_eq!(
        req.get("body"),
        Some(&Value::Bytes(b"{\"u\":\"a\"}".to_vec()))
    );
}

#[test]
fn unknown_id_is_an_error() {
    let store = MemFlowStore::new();
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(DetailPlugin::new()));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let missing = FlowId::new();
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(missing.to_string()));
    let err = reg
        .command("flow.detail")
        .unwrap()
        .invoke(Params::new(map), &host)
        .expect_err("unknown id must be refused");
    assert!(err.to_string().contains(&missing.to_string()), "{err}");
}
