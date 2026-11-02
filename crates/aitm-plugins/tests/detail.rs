//! F5: the detail plugin's `flow.detail` command — the full inspector shape.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    StdGuard, TunnelInfo, TunnelMode, TunnelReason, Value, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_plugins::{DetailPlugin, MutatePlugin};
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
            trailers: HeaderMap::new(),
            body: Body::Bytes(b"{\"token\":\"xyz\"}".to_vec()),
            timestamp: SystemTime::now(),
            peer: None,
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
    // A proxied flow has no source app: `process` is null, not omitted.
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
fn client_conn_process_is_the_source_app_the_backend_observed() {
    // `flow.detail` must agree with `flow.get`: the TUI and web Client columns read
    // `client_conn.process`, so an NE-captured flow names its app there too.
    let store = MemFlowStore::new();
    let mut flow = flow_with_bodies();
    flow.metadata_mut().source_app = Some("com.apple.Safari".into());
    flow.metadata_mut().capture_interface = Some("macos-ne".into());
    let id = store.insert(flow);
    let d = detail(&store, id, Some("none"));
    let cc = obj(&d, "client_conn");
    assert_eq!(
        cc.get("process"),
        Some(&Value::Str("com.apple.Safari".into()))
    );
    // The server side has no process at all.
    let sc = obj(&d, "server_conn");
    assert_eq!(sc.get("process"), None);
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

fn detail_args(store: &dyn FlowStore, id: FlowId, args: &[(&str, Value)]) -> anyhow::Result<Value> {
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(DetailPlugin::new()));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(store, &client, &guard, None);
    let mut map = BTreeMap::new();
    map.insert("id".to_string(), Value::Str(id.to_string()));
    for (k, v) in args {
        map.insert(k.to_string(), v.clone());
    }
    reg.command("flow.detail")
        .unwrap()
        .invoke(Params::new(map), &host)
}

#[test]
fn range_slices_and_clamps_body() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies()); // request body `{"u":"a"}` (9 bytes)

    // offset 2, length 3 -> bytes[2..5].
    let d = detail_args(
        &store,
        id,
        &[
            ("body", Value::Str("range".into())),
            ("offset", Value::Int(2)),
            ("length", Value::Int(3)),
        ],
    )
    .expect("range ok");
    let req = obj_of(&d, "request");
    assert_eq!(req.get("body"), Some(&Value::Bytes(b"u\":".to_vec())));

    // length past the end clamps to the end.
    let d = detail_args(
        &store,
        id,
        &[
            ("body", Value::Str("range".into())),
            ("offset", Value::Int(6)),
            ("length", Value::Int(99)),
        ],
    )
    .expect("clamp ok");
    let req = obj_of(&d, "request");
    assert_eq!(req.get("body"), Some(&Value::Bytes(b"a\"}".to_vec())));

    // offset past the end -> empty slice.
    let d = detail_args(
        &store,
        id,
        &[
            ("body", Value::Str("range".into())),
            ("offset", Value::Int(100)),
        ],
    )
    .expect("past-end ok");
    let req = obj_of(&d, "request");
    assert_eq!(req.get("body"), Some(&Value::Bytes(vec![])));
}

#[test]
fn bad_body_args_are_errors() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());

    let err = detail_args(
        &store,
        id,
        &[
            ("body", Value::Str("range".into())),
            ("offset", Value::Int(-1)),
        ],
    )
    .expect_err("negative offset refused");
    assert!(err.to_string().contains("non-negative"), "{err}");

    let err = detail_args(&store, id, &[("body", Value::Str("bogus".into()))])
        .expect_err("unknown mode refused");
    assert!(err.to_string().contains("none|inline|range"), "{err}");

    let err =
        detail_args(&store, id, &[("body", Value::Int(5))]).expect_err("non-string body refused");
    assert!(err.to_string().contains("string"), "{err}");
}

fn obj_of<'a>(v: &'a Value, k: &str) -> &'a BTreeMap<String, Value> {
    match v {
        Value::Object(o) => match o.get(k) {
            Some(Value::Object(inner)) => inner,
            other => panic!("expected object at {k}, got {other:?}"),
        },
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn websocket_detail_has_handshake_and_messages() {
    let store = MemFlowStore::new();
    let handshake = FlowId::new();
    let caddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ));
    let ws = Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake,
        messages: vec![
            WsMessage {
                dir: WsDir::ClientToServer,
                opcode: WsOpcode::Text,
                data: b"hi".to_vec(),
                timestamp: std::time::SystemTime::now(),
                injected: false,
            },
            WsMessage {
                dir: WsDir::ServerToClient,
                opcode: WsOpcode::Binary,
                data: b"\x00\x01".to_vec(),
                timestamp: std::time::SystemTime::now(),
                injected: true,
            },
        ],
        client_conn: ConnInfo {
            peer: caddr,
            sni: None,
            alpn: None,
            tls: false,
            established: std::time::SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    });
    let id = store.insert(ws);
    let d = detail_args(&store, id, &[("body", Value::Str("inline".into()))]).expect("ok");
    let Value::Object(d) = d else { panic!() };
    assert_eq!(d.get("kind"), Some(&Value::Str("websocket".into())));
    assert_eq!(d.get("handshake"), Some(&Value::Str(handshake.to_string())));
    let Some(Value::Array(msgs)) = d.get("messages") else {
        panic!("messages array: {d:?}");
    };
    assert_eq!(msgs.len(), 2);
    let m0 = match &msgs[0] {
        Value::Object(o) => o,
        _ => panic!(),
    };
    assert_eq!(m0.get("dir"), Some(&Value::Str("client_to_server".into())));
    assert_eq!(m0.get("opcode"), Some(&Value::Str("text".into())));
    assert_eq!(m0.get("length"), Some(&Value::Int(2)));
    assert_eq!(m0.get("data"), Some(&Value::Bytes(b"hi".to_vec())));
}

#[test]
fn mutate_sets_edited_in_detail() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(DetailPlugin::new()));
    reg.add_plugin(Box::new(MutatePlugin::new()));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    // Before mutate: edited is false.
    let before = reg
        .command("flow.detail")
        .unwrap()
        .invoke(id_param(id), &host)
        .unwrap();
    assert!(!field_bool(&before, "edited"));

    // Mutate the request, then detail reports edited == true.
    let mut edits = BTreeMap::new();
    edits.insert("method".to_string(), Value::Str("POST".into()));
    let mut margs = BTreeMap::new();
    margs.insert("id".to_string(), Value::Str(id.to_string()));
    margs.insert("edits".to_string(), Value::Object(edits));
    reg.command("flow.mutate")
        .unwrap()
        .invoke(Params::new(margs), &host)
        .expect("mutate ok");

    let after = reg
        .command("flow.detail")
        .unwrap()
        .invoke(id_param(id), &host)
        .unwrap();
    assert!(field_bool(&after, "edited"));
}

fn id_param(id: FlowId) -> Params {
    let mut m = BTreeMap::new();
    m.insert("id".to_string(), Value::Str(id.to_string()));
    Params::new(m)
}

fn field_bool(v: &Value, k: &str) -> bool {
    match v {
        Value::Object(o) => matches!(o.get(k), Some(Value::Bool(true))),
        _ => panic!("not an object"),
    }
}

/// `flow_with_bodies()` whose response also carries `trailers`, in the given order.
fn flow_with_trailers(pairs: &[(&str, &str)]) -> Flow {
    let mut flow = flow_with_bodies();
    let Flow::Http(f) = &mut flow else {
        panic!("flow_with_bodies builds an HTTP flow");
    };
    let resp = f
        .response
        .as_mut()
        .expect("flow_with_bodies has a response");
    resp.trailers = headers(pairs);
    flow
}

/// A `[name, value]` pair as `flow.detail` renders it.
fn pair(name: &str, value: &str) -> Value {
    Value::Array(vec![Value::Str(name.into()), Value::Str(value.into())])
}

#[test]
fn http_detail_renders_response_trailers_as_name_value_pairs() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_trailers(&[
        ("X-Checksum-SHA256", "abc"),
        ("Server-Timing", "origin;dur=1"),
    ]));
    let d = detail(&store, id, Some("inline"));

    let resp = obj(&d, "response");
    // Trailers are `[name, value]` pairs in wire order, the shape of `headers`;
    // name case is kept as received.
    assert_eq!(
        resp.get("trailers"),
        Some(&Value::Array(vec![
            pair("X-Checksum-SHA256", "abc"),
            pair("Server-Timing", "origin;dur=1"),
        ]))
    );
    // Trailers are never merged into the head: `headers` is untouched.
    assert_eq!(
        resp.get("headers"),
        Some(&Value::Array(vec![pair(
            "content-type",
            "application/json"
        )]))
    );
}

#[test]
fn http_detail_response_has_no_trailers_key_when_there_are_none() {
    let store = MemFlowStore::new();
    let id = store.insert(flow_with_bodies());
    let d = detail(&store, id, Some("inline"));

    // A flow without trailers renders exactly these six keys.
    let keys: Vec<&str> = obj(&d, "response").keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "body",
            "body_size",
            "body_truncated",
            "headers",
            "status",
            "version"
        ]
    );
}

#[test]
fn http_detail_request_object_is_unchanged_by_trailers() {
    let store = MemFlowStore::new();
    let plain = store.insert(flow_with_bodies());
    let trailed = store.insert(flow_with_trailers(&[("X-Checksum-SHA256", "abc")]));

    let plain_d = detail(&store, plain, Some("inline"));
    let trailed_d = detail(&store, trailed, Some("inline"));

    let plain_keys: Vec<&str> = obj(&plain_d, "request")
        .keys()
        .map(String::as_str)
        .collect();
    let trailed_keys: Vec<&str> = obj(&trailed_d, "request")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(trailed_keys, plain_keys);
    // Pin the literal key set too, so two equally wrong objects cannot pass.
    assert_eq!(
        trailed_keys,
        [
            "authority",
            "body",
            "body_size",
            "body_truncated",
            "headers",
            "method",
            "path",
            "scheme",
            "version"
        ]
    );
    // Request trailers are a non-goal: the request headers are the same pairs.
    assert_eq!(
        obj(&trailed_d, "request").get("headers"),
        obj(&plain_d, "request").get("headers")
    );
}

// ---- per-host decryption (spec D7 / AC11): `meta.tunnel` and `meta.passive` ----

/// `flow_with_bodies()` turned into a `CONNECT` row (spec D5): `CONNECT
/// api.ex.test:443`, scheme `https`, empty path, no bodies, the given tunnel
/// outcome, `200` when established (`None` when failed), closed.
fn connect_row(tunnel: TunnelInfo, status: Option<u16>) -> Flow {
    let mut flow = flow_with_bodies();
    let Flow::Http(f) = &mut flow else {
        panic!("flow_with_bodies builds an HTTP flow");
    };
    f.request.method = "CONNECT".into();
    f.request.authority = "api.ex.test:443".into();
    f.request.path = String::new();
    f.request.body = Body::Empty;
    f.response = status.map(|status| HttpResponse {
        status,
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        trailers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: std::time::SystemTime::now(),
        peer: None,
    });
    f.metadata.tunnel = Some(tunnel);
    flow
}

/// A `meta.tunnel` object as `flow.detail` renders it.
fn tunnel_object(mode: &str, reason: Value, bytes_up: Value, bytes_down: Value) -> Value {
    let mut o = BTreeMap::new();
    o.insert("mode".to_string(), Value::Str(mode.into()));
    o.insert("reason".to_string(), reason);
    o.insert("bytes_up".to_string(), bytes_up);
    o.insert("bytes_down".to_string(), bytes_down);
    Value::Object(o)
}

/// Spec D7: `flow.detail`'s `meta` carries `passive` (bool) and `tunnel`, an
/// object `{mode, reason, bytes_up, bytes_down}` for a tunnel row and `null` for
/// every other flow, with the literal wire codes of D5, beside the existing keys.
#[test]
fn detail_meta_reports_tunnel_object_and_passive() {
    let store = MemFlowStore::new();
    let passthrough = store.insert(connect_row(
        TunnelInfo {
            mode: TunnelMode::Passthrough,
            reason: Some(TunnelReason::OutOfScope),
            bytes_up: Some(10),
            bytes_down: Some(20),
        },
        Some(200),
    ));
    let failed = store.insert(connect_row(
        TunnelInfo::failed(TunnelReason::ClientRejectedCertificate),
        None,
    ));
    let decrypted = store.insert(connect_row(TunnelInfo::decrypted(), Some(200)));
    let ordinary = store.insert(flow_with_bodies());
    let mut observed = flow_with_bodies();
    observed.metadata_mut().passive = true;
    let passive = store.insert(observed);

    let d = detail(&store, passthrough, Some("none"));
    assert_eq!(
        obj(&d, "request").get("method"),
        Some(&Value::Str("CONNECT".into()))
    );
    assert_eq!(
        obj(&d, "response").get("status"),
        Some(&Value::Int(200)),
        "an established tunnel carries its 200 acknowledgement"
    );
    let meta = obj(&d, "meta");
    assert_eq!(meta.get("passive"), Some(&Value::Bool(false)));
    assert_eq!(
        meta.get("tunnel"),
        Some(&tunnel_object(
            "passthrough",
            Value::Str("out_of_scope".into()),
            Value::Int(10),
            Value::Int(20)
        )),
        "meta.tunnel on a passthrough row: {meta:?}"
    );
    // Pin the literal key set of `meta`, so two equally wrong objects cannot pass.
    let keys: Vec<&str> = meta.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "comment",
            "created",
            "duration_ms",
            "edited",
            "is_replay",
            "marks",
            "origin",
            "passive",
            "truncated",
            "tunnel",
        ]
    );

    let d = detail(&store, failed, Some("none"));
    assert_eq!(
        d.get("response"),
        Some(&Value::Null),
        "a failed tunnel has no response"
    );
    let meta = obj(&d, "meta");
    assert_eq!(meta.get("passive"), Some(&Value::Bool(false)));
    assert_eq!(
        meta.get("tunnel"),
        Some(&tunnel_object(
            "failed",
            Value::Str("client_rejected_certificate".into()),
            Value::Null,
            Value::Null
        )),
        "meta.tunnel on a failed row: {meta:?}"
    );

    let d = detail(&store, decrypted, Some("none"));
    let meta = obj(&d, "meta");
    assert_eq!(
        meta.get("tunnel"),
        Some(&tunnel_object(
            "decrypted",
            Value::Null,
            Value::Null,
            Value::Null
        )),
        "meta.tunnel on a decrypted row: {meta:?}"
    );

    let d = detail(&store, ordinary, Some("none"));
    let meta = obj(&d, "meta");
    assert_eq!(meta.get("passive"), Some(&Value::Bool(false)));
    assert_eq!(
        meta.get("tunnel"),
        Some(&Value::Null),
        "an ordinary request is not a tunnel row: the key is present and null"
    );

    let d = detail(&store, passive, Some("none"));
    let meta = obj(&d, "meta");
    assert_eq!(meta.get("passive"), Some(&Value::Bool(true)), "{meta:?}");
    assert_eq!(meta.get("tunnel"), Some(&Value::Null));
}

/// A WebSocket flow's `meta` carries the same two keys: `passive` as stamped on
/// its own metadata (the WS module copies it from the handshake) and `tunnel`
/// null, since a WebSocket is never a tunnel row.
#[test]
fn websocket_detail_meta_reports_passive_and_null_tunnel() {
    let store = MemFlowStore::new();
    let caddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let id = store.insert(Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: Vec::new(),
        client_conn: ConnInfo {
            peer: caddr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta {
            passive: true,
            ..FlowMeta::default()
        },
        intercept: InterceptState::Observed,
    }));
    let d = detail(&store, id, Some("none"));
    assert_eq!(d.get("kind"), Some(&Value::Str("websocket".into())));
    let meta = obj(&d, "meta");
    assert_eq!(meta.get("passive"), Some(&Value::Bool(true)), "{meta:?}");
    assert_eq!(meta.get("tunnel"), Some(&Value::Null), "{meta:?}");
}
