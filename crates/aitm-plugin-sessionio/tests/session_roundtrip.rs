//! F10 (Task 8): native session save/load round-trip and import passivity.
//!
//! Both tests drive the real commands through a `Registry` + `CommandHost`, the
//! way a frontend does. AC-F10.1 is the byte-for-byte round-trip; AC-F10.3
//! (Review focus #4) pins that import/load touch only the store and make **zero**
//! upstream requests — the stub client's egress counter must stay at zero.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value,
};
use aitm_plugin_sessionio::SessionIoPlugin;
use futures::future::BoxFuture;

/// A `ProxyClient` that counts every `send` so a test can assert import made no
/// upstream request. Any call is also a hard failure (import must never send).
#[derive(Default)]
struct CountingClient {
    sends: AtomicUsize,
}

impl ProxyClient for CountingClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("stub client: import must not send upstream") })
    }
}

fn registry() -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(SessionIoPlugin::new(false)));
    reg
}

/// An HTTP flow with a distinctive method/URL/status/headers/body to prove the
/// round-trip is byte-for-byte.
fn seeded_flow() -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
    let mut req_headers = HeaderMap::new();
    req_headers.set("Host", "api.example.test");
    req_headers.set("X-Custom", "alpha");
    let mut resp_headers = HeaderMap::new();
    resp_headers.set("Content-Type", "application/json");
    resp_headers.set("Set-Cookie", "a=1");
    resp_headers.set("Set-Cookie", "b=2"); // duplicate name preserved
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "api.example.test".into(),
            path: "/v1/items?page=2".into(),
            version: HttpVersion::Http11,
            headers: req_headers,
            body: Body::Bytes(b"{\"name\":\"widget\"}".to_vec()),
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 201,
            version: HttpVersion::Http11,
            headers: resp_headers,
            trailers: HeaderMap::new(),
            body: Body::Bytes(vec![0u8, 1, 2, 255, 128, 42]),
            timestamp: SystemTime::now(),
        }),
        client_conn: ConnInfo {
            peer: addr,
            sni: Some("api.example.test".into()),
            alpn: Some("http/1.1".into()),
            tls: true,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn plain_flow(path: &str) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
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
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
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

fn headers_vec(flow: &Flow, response: bool) -> Vec<(String, String)> {
    let h = match (flow, response) {
        (Flow::Http(f), false) => &f.request.headers,
        (Flow::Http(f), true) => &f.response.as_ref().unwrap().headers,
        _ => panic!("expected http flow"),
    };
    h.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn body_bytes(b: &Body) -> Vec<u8> {
    match b {
        Body::Bytes(v) => v.clone(),
        Body::Empty => Vec::new(),
        Body::Streamed(_) => panic!("unexpected streamed body"),
    }
}

/// AC-F10.1 — `session.save` then `session.load` into a fresh store restores the
/// flow count and the chosen flow's method, URL, status, headers and body
/// byte-for-byte via the native format.
#[test]
fn native_session_roundtrips() {
    let reg = registry();
    let guard = StdGuard::default();
    let client = CountingClient::default();

    // Seed a store with N flows, one of them the distinctive flow.
    let store = MemFlowStore::new();
    let id = store.insert(seeded_flow());
    store.insert(plain_flow("/a"));
    store.insert(plain_flow("/b"));
    let original = store.get(id).unwrap();

    let path = std::env::temp_dir().join(format!("aitm-sess-{}.json", FlowId::new()));
    let path_str = path.to_string_lossy().to_string();

    // Save. session.save writes a host path, so it runs as the operator (CLI).
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Value::Str(path_str.clone()));
    let saved = reg
        .command("session.save")
        .expect("session.save registered")
        .invoke(Params::new(args), &host)
        .expect("session.save ok");
    let Value::Object(saved) = saved else {
        panic!("session.save returns an object");
    };
    assert_eq!(saved.get("flows"), Some(&Value::Int(3)));
    assert_eq!(saved.get("path"), Some(&Value::Str(path_str.clone())));

    // Load into a fresh store, again as the operator (CLI) reading a host path.
    let fresh = MemFlowStore::new();
    let host = CommandHost::new(&fresh, &client, &guard, None).with_frontend(Frontend::Cli);
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Value::Str(path_str.clone()));
    let loaded = reg
        .command("session.load")
        .expect("session.load registered")
        .invoke(Params::new(args), &host)
        .expect("session.load ok");
    let Value::Object(loaded) = loaded else {
        panic!("session.load returns an object");
    };
    assert_eq!(loaded.get("flows"), Some(&Value::Int(3)));
    assert_eq!(fresh.count(), 3, "same flow count after load");

    // The chosen flow round-trips byte-for-byte.
    let restored = fresh.get(id).expect("chosen flow restored by id");
    let (Flow::Http(o), Flow::Http(r)) = (&original, &restored) else {
        panic!("expected http flows");
    };
    assert_eq!(r.request.method, o.request.method);
    assert_eq!(r.request.scheme, o.request.scheme);
    assert_eq!(r.request.authority, o.request.authority);
    assert_eq!(r.request.path, o.request.path);
    assert_eq!(r.response.as_ref().unwrap().status, 201);
    assert_eq!(headers_vec(&restored, false), headers_vec(&original, false));
    assert_eq!(headers_vec(&restored, true), headers_vec(&original, true));
    assert_eq!(
        body_bytes(&r.request.body),
        body_bytes(&o.request.body),
        "request body round-trips byte-for-byte"
    );
    assert_eq!(
        body_bytes(&r.response.as_ref().unwrap().body),
        body_bytes(&o.response.as_ref().unwrap().body),
        "response body round-trips byte-for-byte"
    );

    // No command in this test may have sent upstream.
    assert_eq!(client.sends.load(Ordering::SeqCst), 0);

    let _ = std::fs::remove_file(&path);
}

/// `seeded_flow()` whose response also carries `pairs` as chunked trailers, the
/// way the HTTP/1 machine records a trailer section after the last chunk.
fn flow_with_trailers(pairs: &[(&str, &str)]) -> Flow {
    let Flow::Http(mut f) = seeded_flow() else {
        panic!("seeded_flow is an http flow");
    };
    let resp = f.response.as_mut().expect("seeded flow has a response");
    for (n, v) in pairs {
        resp.trailers.set(n, v);
    }
    Flow::Http(f)
}

/// The response trailers of an http flow, as owned `(name, value)` pairs in order.
fn response_trailers(flow: &Flow) -> Vec<(String, String)> {
    let Flow::Http(f) = flow else {
        panic!("expected http flow");
    };
    f.response
        .as_ref()
        .expect("flow has a response")
        .trailers
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// `flow.export` (native format, no path) over the whole `store`, as the raw document bytes.
fn export_native(store: &MemFlowStore) -> Vec<u8> {
    let reg = registry();
    let guard = StdGuard::default();
    let client = CountingClient::default();
    let host = CommandHost::new(store, &client, &guard, None);
    let out = reg
        .command("flow.export")
        .expect("flow.export registered")
        .invoke(Params::new(BTreeMap::new()), &host)
        .expect("flow.export ok");
    let Value::Object(out) = out else {
        panic!("flow.export returns an object");
    };
    let Some(Value::Bytes(bytes)) = out.get("bytes") else {
        panic!("flow.export with no path returns bytes");
    };
    bytes.clone()
}

/// `flow.import` of native document `bytes` into `store`; returns the new flow ids.
fn import_native(store: &MemFlowStore, bytes: Vec<u8>) -> Vec<FlowId> {
    let reg = registry();
    let guard = StdGuard::default();
    let client = CountingClient::default();
    let host = CommandHost::new(store, &client, &guard, None);
    let mut args = BTreeMap::new();
    args.insert("bytes".to_string(), Value::Bytes(bytes));
    let out = reg
        .command("flow.import")
        .expect("flow.import registered")
        .invoke(Params::new(args), &host)
        .expect("flow.import ok");
    let Value::Object(out) = out else {
        panic!("flow.import returns an object");
    };
    let Some(Value::Array(ids)) = out.get("ids") else {
        panic!("flow.import returns an ids array");
    };
    ids.iter()
        .map(|v| {
            let Value::Str(s) = v else {
                panic!("ids are strings");
            };
            s.parse().expect("valid flow id")
        })
        .collect()
}

/// AC26 — `session.save` then `session.load` into a fresh store restores the
/// response trailers, including a repeated name (differing only in case) in order.
#[test]
fn native_session_roundtrips_response_trailers() {
    let reg = registry();
    let guard = StdGuard::default();
    let client = CountingClient::default();

    let store = MemFlowStore::new();
    let id = store.insert(flow_with_trailers(&[("X-A", "1"), ("x-a", "2")]));

    let path = std::env::temp_dir().join(format!("aitm-sess-trailers-{}.json", FlowId::new()));
    let path_str = path.to_string_lossy().to_string();

    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Value::Str(path_str.clone()));
    reg.command("session.save")
        .expect("session.save registered")
        .invoke(Params::new(args), &host)
        .expect("session.save ok");

    let fresh = MemFlowStore::new();
    let host = CommandHost::new(&fresh, &client, &guard, None).with_frontend(Frontend::Cli);
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), Value::Str(path_str));
    reg.command("session.load")
        .expect("session.load registered")
        .invoke(Params::new(args), &host)
        .expect("session.load ok");

    let restored = fresh.get(id).expect("flow restored by id");
    assert_eq!(
        response_trailers(&restored),
        vec![
            ("X-A".to_string(), "1".to_string()),
            ("x-a".to_string(), "2".to_string()),
        ],
        "trailers survive save then load, duplicate name and order intact"
    );
    // The trailers ride beside the response, never inside its headers.
    assert_eq!(
        headers_vec(&restored, true),
        headers_vec(&store.get(id).unwrap(), true),
        "response headers are untouched by the trailers"
    );
    assert!(
        !headers_vec(&restored, true).iter().any(|(n, _)| n == "X-A"),
        "a trailer is not merged into the headers"
    );

    let _ = std::fs::remove_file(&path);
}

/// AC26 — a flow with trailers serialises them as an array of `[name, value]`
/// pairs in wire order under `response.trailers`.
#[test]
fn a_flow_with_trailers_serialises_a_trailers_array_of_pairs() {
    let store = MemFlowStore::new();
    store.insert(flow_with_trailers(&[("X-A", "1"), ("x-a", "2")]));

    let doc: serde_json::Value =
        serde_json::from_slice(&export_native(&store)).expect("export is JSON");
    assert_eq!(
        doc["flows"][0]["response"]["trailers"],
        serde_json::json!([["X-A", "1"], ["x-a", "2"]]),
    );
    assert_eq!(
        doc["schema"], "aitm-session/1",
        "the schema tag is unchanged"
    );
    assert_eq!(doc["flows"][0]["kind"], "http", "the flow tag is unchanged");
}

/// AC26 — a flow without trailers serialises exactly as before: no `trailers` key.
#[test]
fn a_flow_without_trailers_serialises_without_a_trailers_key() {
    let store = MemFlowStore::new();
    store.insert(seeded_flow());

    let bytes = export_native(&store);
    let text = String::from_utf8(bytes.clone()).expect("export is UTF-8");
    assert!(
        !text.contains("\"trailers\""),
        "a response with no trailers writes no `trailers` key, got: {text}"
    );

    // The response object is exactly today's five fields (serde_json's map is
    // key-sorted), so the document is the pre-change shape.
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("export is JSON");
    let keys: Vec<&str> = doc["flows"][0]["response"]
        .as_object()
        .expect("response is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["body", "headers", "status", "timestamp", "version"]);
}

/// AC26 — a document saved before this change (no `trailers` key) still loads,
/// with empty trailers. The export of a no-trailers flow IS the old shape.
#[test]
fn an_older_document_loads_with_empty_trailers() {
    let store = MemFlowStore::new();
    store.insert(seeded_flow());
    let old_shape = export_native(&store);
    assert!(
        !String::from_utf8(old_shape.clone())
            .expect("export is UTF-8")
            .contains("\"trailers\""),
        "the fixture is the pre-change shape, with no `trailers` key"
    );

    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, old_shape);
    assert_eq!(ids.len(), 1, "the old document imports its flow");
    let restored = fresh.get(ids[0]).expect("imported flow present");
    assert_eq!(response_trailers(&restored), Vec::<(String, String)>::new());
    let Flow::Http(r) = &restored else {
        panic!("expected http flow");
    };
    assert_eq!(r.response.as_ref().unwrap().status, 201, "the rest loads");
}

/// AC-F10.3 / Review focus #4 — `flow.export` then `flow.import` into a fresh
/// store populates it and triggers **no** upstream request: the stub client's
/// egress counter stays at zero. `session.load` is checked the same way.
#[test]
fn import_is_passive() {
    let reg = registry();
    let guard = StdGuard::default();
    let client = CountingClient::default();

    let store = MemFlowStore::new();
    store.insert(seeded_flow());
    store.insert(plain_flow("/a"));

    // Export the whole store to in-memory bytes.
    let host = CommandHost::new(&store, &client, &guard, None);
    let out = reg
        .command("flow.export")
        .expect("flow.export registered")
        .invoke(Params::new(BTreeMap::new()), &host)
        .expect("flow.export ok");
    let Value::Object(out) = out else {
        panic!("flow.export returns an object");
    };
    let Some(Value::Bytes(bytes)) = out.get("bytes") else {
        panic!("flow.export with no path returns bytes");
    };
    let bytes = bytes.clone();
    assert_eq!(out.get("flows"), Some(&Value::Int(2)));

    // Import into a fresh store; the counter must stay at zero across the import.
    let fresh = MemFlowStore::new();
    let host = CommandHost::new(&fresh, &client, &guard, None);
    let before = client.sends.load(Ordering::SeqCst);
    let mut args = BTreeMap::new();
    args.insert("bytes".to_string(), Value::Bytes(bytes));
    let imported = reg
        .command("flow.import")
        .expect("flow.import registered")
        .invoke(Params::new(args), &host)
        .expect("flow.import ok");
    let Value::Object(imported) = imported else {
        panic!("flow.import returns an object");
    };
    let Some(Value::Array(ids)) = imported.get("ids") else {
        panic!("flow.import returns an ids array");
    };
    assert_eq!(ids.len(), 2, "both flows imported");
    assert_eq!(fresh.count(), 2, "store populated by import");
    assert_eq!(
        client.sends.load(Ordering::SeqCst),
        before,
        "import made zero upstream requests"
    );

    // Imported flows carry the `imported` marker and are not replays.
    for id_v in ids {
        let Value::Str(id_s) = id_v else {
            panic!("ids are strings");
        };
        let id: FlowId = id_s.parse().expect("valid flow id");
        let flow = fresh.get(id).expect("imported flow present");
        assert!(!flow.metadata().is_replay, "import is not a replay");
        assert!(
            flow.metadata().marks.iter().any(|m| m == "imported"),
            "imported flow carries the `imported` mark"
        );
    }

    assert_eq!(
        client.sends.load(Ordering::SeqCst),
        0,
        "no egress for the whole test"
    );
}
