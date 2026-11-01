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
    Registry, StdGuard, TunnelInfo, TunnelMode, TunnelReason, Value,
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

/// `session.save` then `session.load` into a fresh store restores the
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

/// A flow with trailers serialises them as an array of `[name, value]`
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

/// A flow without trailers serialises with no `trailers` key at all.
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

    // The response object is exactly these five fields, so the document is the
    // shape written before trailers existed. The keys are compared sorted: whether serde_json's map
    // iterates sorted or in insertion order depends on whether another workspace
    // crate (aitm-tui) enables `preserve_order`, which differs between
    // `cargo test -p aitm-plugin-sessionio` and a whole-workspace run.
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("export is JSON");
    let mut keys: Vec<&str> = doc["flows"][0]["response"]
        .as_object()
        .expect("response is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["body", "headers", "status", "timestamp", "version"]);
}

/// A document without the key (the shape written before trailers existed) still
/// loads, with empty trailers. The export of a flow without trailers is that shape.
#[test]
fn an_older_document_loads_with_empty_trailers() {
    let store = MemFlowStore::new();
    store.insert(seeded_flow());
    let old_shape = export_native(&store);
    assert!(
        !String::from_utf8(old_shape.clone())
            .expect("export is UTF-8")
            .contains("\"trailers\""),
        "the fixture is a document without the `trailers` key"
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

/// Tester addition (whole-branch stage 5, SA-AC7 at the document level, through
/// the real `flow.export` / `flow.import` surface rather than `MetaRec` alone): an
/// attributed flow exports with both keys and imports with both values intact, and
/// the same document with the two keys removed — the shape of every
/// pre-attribution session file — imports with `None`/`None`.
#[test]
fn attribution_exports_imports_and_an_older_document_loads_as_none() {
    let store = MemFlowStore::new();
    let mut flow = seeded_flow();
    flow.metadata_mut().source_app = Some("com.apple.Safari".into());
    flow.metadata_mut().capture_interface = Some("macos-ne".into());
    store.insert(flow);
    let exported = export_native(&store);

    // Round trip: the values survive the document.
    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, exported.clone());
    assert_eq!(ids.len(), 1);
    let restored = fresh.get(ids[0]).expect("imported flow present");
    assert_eq!(
        restored.metadata().source_app.as_deref(),
        Some("com.apple.Safari")
    );
    assert_eq!(
        restored.metadata().capture_interface.as_deref(),
        Some("macos-ne")
    );

    // The older shape: the same document without the two keys.
    let mut doc: serde_json::Value = serde_json::from_slice(&exported).expect("the export is JSON");
    let flows = doc["flows"].as_array_mut().expect("a flows array");
    assert_eq!(flows.len(), 1);
    for rec in flows.iter_mut() {
        let meta = rec["metadata"].as_object_mut().expect("a metadata object");
        assert_eq!(
            meta.remove("source_app"),
            Some(serde_json::Value::String("com.apple.Safari".into())),
            "the export wrote source_app"
        );
        assert_eq!(
            meta.remove("capture_interface"),
            Some(serde_json::Value::String("macos-ne".into())),
            "the export wrote capture_interface"
        );
    }
    let older = serde_json::to_vec(&doc).expect("re-serialise");
    assert!(!String::from_utf8_lossy(&older).contains("source_app"));

    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, older);
    assert_eq!(ids.len(), 1, "the older document imports its flow");
    let restored = fresh.get(ids[0]).expect("imported flow present");
    assert_eq!(restored.metadata().source_app, None);
    assert_eq!(restored.metadata().capture_interface, None);
    let Flow::Http(r) = &restored else {
        panic!("expected http flow");
    };
    assert_eq!(
        r.response.as_ref().expect("response").status,
        201,
        "the rest loads"
    );
}

/// The restored flows of a document, keyed by request path, so a test can name
/// each one regardless of store order.
fn restored_by_path(store: &MemFlowStore, ids: &[FlowId]) -> BTreeMap<String, Flow> {
    ids.iter()
        .map(|id| {
            let flow = store.get(*id).expect("imported flow present");
            let Flow::Http(h) = &flow else {
                panic!("expected http flow");
            };
            (h.request.path.clone(), flow)
        })
        .collect()
}

/// Spec D5/D8 persistence: `passive` and the three tunnel shapes (passthrough
/// with bytes and a reason, failed with a reason, decrypted with neither) survive
/// `flow.export` → `flow.import` of a native session, and the document carries
/// the wire labels (`passthrough`, `out_of_scope`, …), not Rust names.
#[test]
fn tunnel_and_passive_round_trip_through_a_native_session() {
    let store = MemFlowStore::new();
    let mut passive = plain_flow("/passive");
    passive.metadata_mut().passive = true;
    store.insert(passive);
    let mut passthrough = plain_flow("/passthrough");
    passthrough.metadata_mut().tunnel = Some(TunnelInfo {
        mode: TunnelMode::Passthrough,
        reason: Some(TunnelReason::OutOfScope),
        bytes_up: Some(1234),
        bytes_down: Some(56789),
    });
    store.insert(passthrough);
    let mut failed = plain_flow("/failed");
    failed.metadata_mut().tunnel =
        Some(TunnelInfo::failed(TunnelReason::ClientRejectedCertificate));
    store.insert(failed);
    let mut decrypted = plain_flow("/decrypted");
    decrypted.metadata_mut().tunnel = Some(TunnelInfo::decrypted());
    store.insert(decrypted);

    let exported = export_native(&store);

    // The document's tunnel objects are the wire labels.
    let doc: serde_json::Value = serde_json::from_slice(&exported).expect("the export is JSON");
    let flows = doc["flows"].as_array().expect("a flows array");
    assert_eq!(flows.len(), 4);
    let meta_of = |path: &str| -> &serde_json::Value {
        &flows
            .iter()
            .find(|rec| rec["request"]["path"] == path)
            .unwrap_or_else(|| panic!("no record for {path}"))["metadata"]
    };
    assert_eq!(meta_of("/passive")["passive"], serde_json::json!(true));
    assert_eq!(meta_of("/passive")["tunnel"], serde_json::Value::Null);
    assert_eq!(meta_of("/passthrough")["passive"], serde_json::json!(false));
    assert_eq!(
        meta_of("/passthrough")["tunnel"],
        serde_json::json!({
            "mode": "passthrough",
            "reason": "out_of_scope",
            "bytes_up": 1234,
            "bytes_down": 56789
        })
    );
    assert_eq!(
        meta_of("/failed")["tunnel"],
        serde_json::json!({
            "mode": "failed",
            "reason": "client_rejected_certificate",
            "bytes_up": null,
            "bytes_down": null
        })
    );
    assert_eq!(
        meta_of("/decrypted")["tunnel"],
        serde_json::json!({
            "mode": "decrypted",
            "reason": null,
            "bytes_up": null,
            "bytes_down": null
        })
    );

    // Round trip: the typed fields come back exactly.
    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, exported);
    assert_eq!(ids.len(), 4);
    let restored = restored_by_path(&fresh, &ids);
    assert!(restored["/passive"].metadata().passive);
    assert_eq!(restored["/passive"].metadata().tunnel, None);
    assert!(!restored["/passthrough"].metadata().passive);
    assert_eq!(
        restored["/passthrough"].metadata().tunnel,
        Some(TunnelInfo {
            mode: TunnelMode::Passthrough,
            reason: Some(TunnelReason::OutOfScope),
            bytes_up: Some(1234),
            bytes_down: Some(56789),
        })
    );
    assert_eq!(
        restored["/failed"].metadata().tunnel,
        Some(TunnelInfo::failed(TunnelReason::ClientRejectedCertificate))
    );
    assert_eq!(
        restored["/decrypted"].metadata().tunnel,
        Some(TunnelInfo::decrypted())
    );
}

/// A document written before `passive`/`tunnel` existed (the same export with
/// the two keys removed) loads with the defaults — not passive, not a tunnel —
/// and the rest of the flow intact. No `aitm-session/1` bump.
#[test]
fn legacy_document_without_the_fields_loads_as_defaults() {
    let store = MemFlowStore::new();
    let mut flow = seeded_flow();
    flow.metadata_mut().passive = true;
    flow.metadata_mut().tunnel = Some(TunnelInfo::passthrough(TunnelReason::Pinned));
    store.insert(flow);
    let exported = export_native(&store);

    let mut doc: serde_json::Value = serde_json::from_slice(&exported).expect("the export is JSON");
    let flows = doc["flows"].as_array_mut().expect("a flows array");
    assert_eq!(flows.len(), 1);
    let meta = flows[0]["metadata"]
        .as_object_mut()
        .expect("a metadata object");
    assert_eq!(
        meta.remove("passive"),
        Some(serde_json::json!(true)),
        "the export wrote passive"
    );
    assert_eq!(
        meta.remove("tunnel"),
        Some(serde_json::json!({
            "mode": "passthrough",
            "reason": "pinned",
            "bytes_up": null,
            "bytes_down": null
        })),
        "the export wrote tunnel"
    );
    let older = serde_json::to_vec(&doc).expect("re-serialise");
    let text = String::from_utf8_lossy(&older);
    assert!(!text.contains("\"passive\"") && !text.contains("\"tunnel\""));

    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, older);
    assert_eq!(ids.len(), 1, "the older document imports its flow");
    let restored = fresh.get(ids[0]).expect("imported flow present");
    assert!(!restored.metadata().passive);
    assert_eq!(restored.metadata().tunnel, None);
    let Flow::Http(r) = &restored else {
        panic!("expected http flow");
    };
    assert_eq!(
        r.response.as_ref().expect("response").status,
        201,
        "the rest loads"
    );
}

/// A tunnel object whose `mode` or `reason` is a code this build does not know
/// (a newer writer, or a hand-edited file) loads as "not a tunnel row" rather
/// than failing the whole document; the flow itself still imports. The sibling
/// flow with a known code in the same document is the positive control: it
/// restores as a tunnel, so the field is read and only the unknown code is dropped.
#[test]
fn a_tunnel_with_an_unknown_code_loads_as_no_tunnel() {
    let store = MemFlowStore::new();
    for path in ["/edited", "/control"] {
        let mut flow = plain_flow(path);
        flow.metadata_mut().tunnel = Some(TunnelInfo::passthrough(TunnelReason::OutOfScope));
        store.insert(flow);
    }
    let exported = export_native(&store);

    for (key, known, bogus) in [
        ("mode", "passthrough", "quantum"),
        ("reason", "out_of_scope", "cosmic_rays"),
    ] {
        let mut doc: serde_json::Value =
            serde_json::from_slice(&exported).expect("the export is JSON");
        let rec = doc["flows"]
            .as_array_mut()
            .expect("a flows array")
            .iter_mut()
            .find(|rec| rec["request"]["path"] == "/edited")
            .expect("the /edited record");
        // The export wrote the known code there; the edit replaces it.
        assert_eq!(rec["metadata"]["tunnel"][key], serde_json::json!(known));
        rec["metadata"]["tunnel"][key] = serde_json::json!(bogus);
        let edited = serde_json::to_vec(&doc).expect("re-serialise");

        let fresh = MemFlowStore::new();
        let ids = import_native(&fresh, edited);
        assert_eq!(
            ids.len(),
            2,
            "unknown {key} {bogus:?} still imports both flows"
        );
        let restored = restored_by_path(&fresh, &ids);
        assert_eq!(
            restored["/edited"].metadata().tunnel,
            None,
            "unknown {key} {bogus:?} loads as no tunnel"
        );
        assert_eq!(
            restored["/control"].metadata().tunnel,
            Some(TunnelInfo::passthrough(TunnelReason::OutOfScope)),
            "the known code beside it still loads as a tunnel"
        );
        let Flow::Http(r) = &restored["/edited"] else {
            panic!("expected http flow");
        };
        assert_eq!(r.response.as_ref().expect("response").status, 200);
    }
}

/// Panel Q3 (Tester addition): every tunnel outcome this build knows — each
/// `TunnelMode` with each `TunnelReason` and with none — survives `flow.export`
/// → `flow.import` of a native session exactly, because the reader reverses the
/// labels through `TunnelMode::ALL` / `TunnelReason::ALL`, the same lists the
/// writer's labels come from. The document carries each wire label verbatim.
#[test]
fn every_tunnel_mode_and_reason_round_trips_through_a_native_session() {
    let store = MemFlowStore::new();
    let mut expected: Vec<(String, TunnelInfo)> = Vec::new();
    for mode in TunnelMode::ALL {
        for reason in TunnelReason::ALL.into_iter().map(Some).chain([None]) {
            let path = format!("/{}/{}", mode.label(), reason.map_or("none", |r| r.label()));
            let relayed = mode == TunnelMode::Passthrough;
            let info = TunnelInfo {
                mode,
                reason,
                bytes_up: relayed.then_some(7),
                bytes_down: relayed.then_some(11),
            };
            let mut flow = plain_flow(&path);
            flow.metadata_mut().tunnel = Some(info.clone());
            store.insert(flow);
            expected.push((path, info));
        }
    }
    assert_eq!(
        expected.len(),
        3 * 9,
        "three modes × (eight reasons + none)"
    );
    let exported = export_native(&store);

    let doc: serde_json::Value = serde_json::from_slice(&exported).expect("the export is JSON");
    let flows = doc["flows"].as_array().expect("a flows array");
    assert_eq!(flows.len(), expected.len());
    for rec in flows {
        let path = rec["request"]["path"].as_str().expect("a path");
        let (_, info) = expected
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("unexpected path {path}"));
        assert_eq!(
            rec["metadata"]["tunnel"]["mode"],
            serde_json::json!(info.mode.label()),
            "{path}"
        );
        assert_eq!(
            rec["metadata"]["tunnel"]["reason"],
            info.reason
                .map_or(serde_json::Value::Null, |r| serde_json::json!(r.label())),
            "{path}"
        );
    }

    let fresh = MemFlowStore::new();
    let ids = import_native(&fresh, exported);
    assert_eq!(ids.len(), expected.len());
    let restored = restored_by_path(&fresh, &ids);
    for (path, info) in &expected {
        assert_eq!(
            restored[path.as_str()].metadata().tunnel.as_ref(),
            Some(info),
            "{path}"
        );
    }
}
