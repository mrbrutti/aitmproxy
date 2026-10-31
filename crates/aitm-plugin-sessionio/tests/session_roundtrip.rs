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
