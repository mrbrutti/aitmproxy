//! Task 13: the capture plugin's read commands, `flow.list` and `flow.get`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, StdGuard, TunnelInfo, TunnelMode, TunnelReason, TypeDesc, Value, WsFlow,
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

/// `flow.get` reports the buffered body sizes so a UI can total the traffic it has
/// seen without fetching bodies: an empty body is 0, a buffered one its length, a
/// response not yet seen is null (and so is a body still streaming).
#[test]
fn flow_get_reports_body_sizes() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut sized = http_flow("POST", "/upload", Some(200));
    if let Flow::Http(f) = &mut sized {
        f.request.body = Body::Bytes(vec![b'x'; 412]);
        f.response.as_mut().expect("response").body = Body::Bytes(vec![0u8; 2048]);
    }
    let sized_id = store.insert(sized);
    let pending_id = store.insert(http_flow("GET", "/a", None));
    let mut streaming = http_flow("GET", "/stream", Some(200));
    if let Flow::Http(f) = &mut streaming {
        f.response.as_mut().expect("response").body = Body::Streamed(aitm_core::StreamBody);
    }
    let streaming_id = store.insert(streaming);
    let ws_id = store.insert(ws_flow(sized_id));

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let get = |id: FlowId| -> BTreeMap<String, Value> {
        match reg
            .command("flow.get")
            .expect("flow.get registered")
            .invoke(id_params(id), &host)
            .expect("flow.get ok")
        {
            Value::Object(obj) => obj,
            other => panic!("flow.get must return an object, got {other:?}"),
        }
    };

    let sized = get(sized_id);
    assert_eq!(sized.get("request_bytes"), Some(&Value::Int(412)));
    assert_eq!(sized.get("response_bytes"), Some(&Value::Int(2048)));

    let pending = get(pending_id);
    assert_eq!(pending.get("request_bytes"), Some(&Value::Int(0)));
    assert_eq!(pending.get("response_bytes"), Some(&Value::Null));

    let streaming = get(streaming_id);
    assert_eq!(streaming.get("request_bytes"), Some(&Value::Int(0)));
    assert_eq!(
        streaming.get("response_bytes"),
        Some(&Value::Null),
        "a streaming body has no known size yet"
    );

    // A WebSocket flow has no request/response bodies: it reports neither field.
    let ws = get(ws_id);
    assert_eq!(ws.get("kind"), Some(&Value::Str("websocket".into())));
    assert!(!ws.contains_key("request_bytes"), "got {ws:?}");
    assert!(!ws.contains_key("response_bytes"), "got {ws:?}");
}

/// The declared `flow.get` schema lists both size fields as optional integers, so
/// a frontend reading the schema learns about them and a WebSocket summary (which
/// omits them) is still conformant.
#[test]
fn flow_get_schema_declares_body_sizes() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let schema = reg
        .command("flow.get")
        .expect("flow.get registered")
        .schema();
    let TypeDesc::Object(fields) = schema.result else {
        panic!(
            "flow.get result must be an object schema, got {:?}",
            schema.result
        );
    };
    for name in ["request_bytes", "response_bytes"] {
        let field = fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("{name} missing from the flow.get schema"));
        assert!(
            matches!(field.ty, TypeDesc::Int),
            "{name} is an integer, got {:?}",
            field.ty
        );
        assert!(
            !field.required,
            "{name} is optional (absent for WebSocket flows)"
        );
        assert!(
            field.description.contains("bytes"),
            "{name} says what it counts: {}",
            field.description
        );
    }
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

/// `flow.get` reports when a flow started (ms since the Unix epoch, from
/// `metadata.created`) and how long it took (whole ms, from `metadata.duration`)
/// for both kinds: `duration_ms` is null while in flight, and for a WebSocket flow
/// (no end marker); `started_at` is null when the clock is before the epoch.
#[test]
fn flow_get_reports_started_at_and_duration() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();
    let created = SystemTime::UNIX_EPOCH + Duration::from_millis(1_761_908_698_120);

    let mut timed = http_flow("GET", "/timed", Some(200));
    if let Flow::Http(f) = &mut timed {
        f.metadata.created = created;
        f.metadata.duration = Some(Duration::from_millis(412));
    }
    let timed_id = store.insert(timed);

    let mut in_flight = http_flow("GET", "/pending", None);
    if let Flow::Http(f) = &mut in_flight {
        f.metadata.created = created;
        f.metadata.duration = None;
    }
    let in_flight_id = store.insert(in_flight);

    let mut ws = ws_flow(timed_id);
    if let Flow::WebSocket(f) = &mut ws {
        f.metadata.created = created;
    }
    let ws_id = store.insert(ws);

    let mut before_epoch = http_flow("GET", "/old", Some(200));
    if let Flow::Http(f) = &mut before_epoch {
        f.metadata.created = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
    }
    let before_epoch_id = store.insert(before_epoch);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let get = |id: FlowId| -> BTreeMap<String, Value> {
        match reg
            .command("flow.get")
            .expect("flow.get registered")
            .invoke(id_params(id), &host)
            .expect("flow.get ok")
        {
            Value::Object(obj) => obj,
            other => panic!("flow.get must return an object, got {other:?}"),
        }
    };

    let timed = get(timed_id);
    assert_eq!(
        timed.get("started_at"),
        Some(&Value::Int(1_761_908_698_120))
    );
    assert_eq!(timed.get("duration_ms"), Some(&Value::Int(412)));

    let in_flight = get(in_flight_id);
    assert_eq!(
        in_flight.get("started_at"),
        Some(&Value::Int(1_761_908_698_120))
    );
    assert_eq!(
        in_flight.get("duration_ms"),
        Some(&Value::Null),
        "no duration while the flow is in flight"
    );

    let ws = get(ws_id);
    assert_eq!(ws.get("kind"), Some(&Value::Str("websocket".into())));
    assert_eq!(ws.get("started_at"), Some(&Value::Int(1_761_908_698_120)));
    assert_eq!(
        ws.get("duration_ms"),
        Some(&Value::Null),
        "a WebSocket flow has no end marker"
    );

    let before_epoch = get(before_epoch_id);
    assert_eq!(
        before_epoch.get("started_at"),
        Some(&Value::Null),
        "a clock before the epoch cannot be expressed as epoch ms"
    );
}

/// The declared `flow.get` schema lists both timing fields as optional integers
/// measured in milliseconds.
#[test]
fn flow_get_schema_declares_timing() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let schema = reg
        .command("flow.get")
        .expect("flow.get registered")
        .schema();
    let TypeDesc::Object(fields) = schema.result else {
        panic!(
            "flow.get result must be an object schema, got {:?}",
            schema.result
        );
    };
    for name in ["started_at", "duration_ms"] {
        let field = fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("{name} missing from the flow.get schema"));
        assert!(
            matches!(field.ty, TypeDesc::Int),
            "{name} is an integer, got {:?}",
            field.ty
        );
        assert!(!field.required, "{name} is optional (null while unknown)");
        assert!(
            field.description.contains("milliseconds"),
            "{name} names its unit: {}",
            field.description
        );
    }
}

/// `flow.table` and `flow.get` compute `duration_ms` through one helper, so the
/// same flow reports the same number through both commands.
#[test]
fn flow_table_and_flow_get_agree_on_duration() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut timed = http_flow("GET", "/timed", Some(200));
    if let Flow::Http(f) = &mut timed {
        f.metadata.created = SystemTime::UNIX_EPOCH + Duration::from_millis(1_761_908_698_120);
        f.metadata.duration = Some(Duration::from_millis(412));
    }
    let timed_id = store.insert(timed);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(timed_id), &host)
        .expect("flow.get ok");
    let Value::Object(summary) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    assert_eq!(summary.get("duration_ms"), Some(&Value::Int(412)));

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
    let row = rows
        .iter()
        .find_map(|row| match row {
            Value::Object(r) if r.get("id") == Some(&Value::Str(timed_id.to_string())) => Some(r),
            _ => None,
        })
        .expect("the timed flow has a flow.table row");
    assert_eq!(row.get("duration_ms"), Some(&Value::Int(412)));
    assert_eq!(
        row.get("duration_ms"),
        summary.get("duration_ms"),
        "flow.table and flow.get must agree on duration_ms"
    );
}

/// AC11: once the store finalises a streamed response that failed mid-body
/// (`FlowStore::abandon_response`), `flow.get` reports the captured size, the
/// status that was already stored, and a duration: the flow is terminal.
#[test]
fn flow_get_reports_sizes_for_an_abandoned_response() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut streaming = http_flow("GET", "/stream", Some(200));
    if let Flow::Http(f) = &mut streaming {
        f.response.as_mut().expect("response").body = Body::Streamed(aitm_core::StreamBody);
    }
    let id = store.insert(streaming);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let get = |id: FlowId| -> BTreeMap<String, Value> {
        match reg
            .command("flow.get")
            .expect("flow.get registered")
            .invoke(id_params(id), &host)
            .expect("flow.get ok")
        {
            Value::Object(obj) => obj,
            other => panic!("flow.get must return an object, got {other:?}"),
        }
    };

    let before = get(id);
    assert_eq!(
        before.get("response_bytes"),
        Some(&Value::Null),
        "a streaming body has no known size yet"
    );

    assert!(
        store.abandon_response(id, vec![1, 2, 3]),
        "a streamed response is abandoned exactly once"
    );

    let after = get(id);
    assert_eq!(after.get("response_bytes"), Some(&Value::Int(3)));
    assert_eq!(after.get("status"), Some(&Value::Int(200)));
    assert!(
        matches!(after.get("duration_ms"), Some(&Value::Int(_))),
        "an abandoned response has a duration, got {:?}",
        after.get("duration_ms")
    );
}

// ---- tester additions: empty and oversized inputs on the timing/size paths ----

/// Empty input on the abandon path: a response that failed before any body byte
/// arrived is stored as `Body::Empty`, and `flow.get` reports a concrete
/// `response_bytes: 0` (not null) with a duration, so a UI waiting on the size
/// stops waiting.
#[test]
fn flow_get_reports_zero_bytes_for_an_abandoned_response_with_nothing_captured() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut streaming = http_flow("GET", "/stream-empty", Some(200));
    if let Flow::Http(f) = &mut streaming {
        f.response.as_mut().expect("response").body = Body::Streamed(aitm_core::StreamBody);
    }
    let id = store.insert(streaming);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let get = |id: FlowId| -> BTreeMap<String, Value> {
        match reg
            .command("flow.get")
            .expect("flow.get registered")
            .invoke(id_params(id), &host)
            .expect("flow.get ok")
        {
            Value::Object(obj) => obj,
            other => panic!("flow.get must return an object, got {other:?}"),
        }
    };

    assert_eq!(get(id).get("response_bytes"), Some(&Value::Null));
    assert!(store.abandon_response(id, Vec::new()));
    let after = get(id);
    assert_eq!(
        after.get("response_bytes"),
        Some(&Value::Int(0)),
        "nothing captured is a known size of zero, not an unknown size"
    );
    assert_eq!(after.get("status"), Some(&Value::Int(200)));
    assert!(
        matches!(after.get("duration_ms"), Some(&Value::Int(_))),
        "an abandoned response has a duration, got {:?}",
        after.get("duration_ms")
    );
    assert_eq!(
        store.clear().cleared,
        1,
        "an abandoned response with an empty body is terminal"
    );
}

/// Oversized input: a duration whose millisecond count exceeds `i64` is
/// saturated to `i64::MAX` by both `flow.get` and `flow.table` (the shared
/// helper), never wrapped into a negative or truncated number.
#[test]
fn flow_get_and_flow_table_saturate_an_absurd_duration() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut absurd = http_flow("GET", "/forever", Some(200));
    if let Flow::Http(f) = &mut absurd {
        f.metadata.duration = Some(Duration::MAX);
    }
    let id = store.insert(absurd);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(id), &host)
        .expect("flow.get ok");
    let Value::Object(summary) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    assert_eq!(
        summary.get("duration_ms"),
        Some(&Value::Int(i64::MAX)),
        "flow.get saturates rather than wraps"
    );

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
    let row = rows
        .iter()
        .find_map(|row| match row {
            Value::Object(r) if r.get("id") == Some(&Value::Str(id.to_string())) => Some(r),
            _ => None,
        })
        .expect("the flow has a flow.table row");
    assert_eq!(
        row.get("duration_ms"),
        Some(&Value::Int(i64::MAX)),
        "flow.table saturates the same way"
    );
}

/// Stamps the attribution a capture backend would have recorded on the flow:
/// the macOS Network Extension observed `com.apple.Safari` opening the
/// connection, and the backend names itself `macos-ne`.
fn attributed(mut flow: Flow) -> Flow {
    flow.metadata_mut().source_app = Some("com.apple.Safari".into());
    flow.metadata_mut().capture_interface = Some("macos-ne".into());
    flow
}

/// `flow.get` and `flow.table` emit `source_app` and `capture_interface` on every
/// row: the strings a capture backend recorded, or null (key present) for a
/// proxied flow, for HTTP and WebSocket alike.
#[test]
fn flow_get_and_table_report_source_app() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let store = MemFlowStore::new();
    let captured = store.insert(attributed(http_flow("GET", "/cap", Some(200))));
    let proxied = store.insert(http_flow("GET", "/proxied", Some(200)));
    let ws = store.insert(attributed(ws_flow(captured)));
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let summary = |id: FlowId| -> BTreeMap<String, Value> {
        let got = reg
            .command("flow.get")
            .expect("flow.get registered")
            .invoke(id_params(id), &host)
            .expect("flow.get ok");
        let Value::Object(obj) = got else {
            panic!("flow.get must return an object, got {got:?}");
        };
        obj
    };

    let cap = summary(captured);
    assert_eq!(
        cap.get("source_app"),
        Some(&Value::Str("com.apple.Safari".into())),
        "captured HTTP flow reports the app the backend observed"
    );
    assert_eq!(
        cap.get("capture_interface"),
        Some(&Value::Str("macos-ne".into())),
        "captured HTTP flow names its backend"
    );

    let prox = summary(proxied);
    assert_eq!(
        prox.get("source_app"),
        Some(&Value::Null),
        "proxied flow carries the key with a null value, never a placeholder"
    );
    assert_eq!(
        prox.get("capture_interface"),
        Some(&Value::Null),
        "proxied flow carries the key with a null value, never a placeholder"
    );

    let sock = summary(ws);
    assert_eq!(
        sock.get("source_app"),
        Some(&Value::Str("com.apple.Safari".into())),
        "WebSocket rows carry the attribution too"
    );
    assert_eq!(
        sock.get("capture_interface"),
        Some(&Value::Str("macos-ne".into())),
        "WebSocket rows carry the attribution too"
    );

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
    assert_eq!(rows.len(), 3, "three flows captured, in insertion order");
    let row = |i: usize| -> &BTreeMap<String, Value> {
        let Value::Object(r) = &rows[i] else {
            panic!("row {i} must be an object, got {:?}", rows[i]);
        };
        r
    };

    assert_eq!(row(0).get("id"), Some(&Value::Str(captured.to_string())));
    assert_eq!(
        row(0).get("source_app"),
        Some(&Value::Str("com.apple.Safari".into()))
    );
    assert_eq!(
        row(0).get("capture_interface"),
        Some(&Value::Str("macos-ne".into()))
    );

    assert_eq!(row(1).get("id"), Some(&Value::Str(proxied.to_string())));
    assert_eq!(row(1).get("source_app"), Some(&Value::Null));
    assert_eq!(row(1).get("capture_interface"), Some(&Value::Null));

    assert_eq!(row(2).get("id"), Some(&Value::Str(ws.to_string())));
    assert_eq!(row(2).get("kind"), Some(&Value::Str("websocket".into())));
    assert_eq!(
        row(2).get("source_app"),
        Some(&Value::Str("com.apple.Safari".into()))
    );
    assert_eq!(
        row(2).get("capture_interface"),
        Some(&Value::Str("macos-ne".into()))
    );
}

/// Both result schemas declare `source_app` and `capture_interface` as optional
/// strings whose description says what a proxied flow reports, so a surface that
/// builds its columns from `tools/list` learns about them without hard-coding.
#[test]
fn schemas_declare_source_app_and_capture_interface() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let get_schema = reg
        .command("flow.get")
        .expect("flow.get registered")
        .schema();
    let TypeDesc::Object(get_fields) = get_schema.result else {
        panic!(
            "flow.get result must be an object schema, got {:?}",
            get_schema.result
        );
    };

    let table_schema = reg
        .command("flow.table")
        .expect("flow.table registered")
        .schema();
    let TypeDesc::Object(table_fields) = table_schema.result else {
        panic!(
            "flow.table result must be an object schema, got {:?}",
            table_schema.result
        );
    };
    let flows = table_fields
        .iter()
        .find(|f| f.name == "flows")
        .expect("flow.table result has a `flows` field");
    let TypeDesc::Array(elem) = &flows.ty else {
        panic!("`flows` must be an array, got {:?}", flows.ty);
    };
    let TypeDesc::Object(row_fields) = elem.as_ref() else {
        panic!("`flows` elements must be objects, got {:?}", elem);
    };

    for (command, fields) in [("flow.get", &get_fields), ("flow.table", row_fields)] {
        for name in ["source_app", "capture_interface"] {
            let field = fields
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("{name} missing from the {command} schema"));
            assert!(
                matches!(field.ty, TypeDesc::Str),
                "{command}.{name} is a string, got {:?}",
                field.ty
            );
            assert!(
                !field.required,
                "{command}.{name} is optional (null unless the core could name the client)"
            );
            assert!(
                field.description.contains("proxied"),
                "{command}.{name} says what a proxied flow reports: {}",
                field.description
            );
        }
    }
}

/// Tester addition (whole-branch stage 5). `source_app` is text a capture backend
/// supplied about a client. The read commands pass it through verbatim as a
/// string: quotes, CR/LF, a NUL, non-ASCII and a 64 KiB identifier all survive
/// untouched — no truncation, escaping or interpretation — on both `flow.get` and
/// `flow.table`. Escaping for a wire is the transport's job; what to show is the
/// UI's.
#[test]
fn source_app_text_passes_through_verbatim_on_flow_get_and_flow_table() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let hostile = format!(
        "com.evil.\"quoted\"\r\n\u{0}日本語.{}",
        "x".repeat(64 * 1024)
    );
    let mut flow = http_flow("GET", "/hostile", Some(200));
    flow.metadata_mut().source_app = Some(hostile.clone());
    flow.metadata_mut().capture_interface = Some("macos-ne\n".into());
    let store = MemFlowStore::new();
    let id = store.insert(flow);
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(id), &host)
        .expect("flow.get ok");
    let Value::Object(obj) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    assert_eq!(obj.get("source_app"), Some(&Value::Str(hostile.clone())));
    assert_eq!(
        obj.get("capture_interface"),
        Some(&Value::Str("macos-ne\n".into()))
    );

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
    let Some(Value::Object(row)) = rows.first() else {
        panic!("one row expected, got {rows:?}");
    };
    assert_eq!(row.get("source_app"), Some(&Value::Str(hostile)));
    assert_eq!(
        row.get("capture_interface"),
        Some(&Value::Str("macos-ne\n".into()))
    );
}

// ---- per-host decryption (spec D7 / AC11): tunnel and passive keys on every surface ----

/// A `CONNECT host:port` row as the tunnel recorder stores it (spec D5): scheme
/// `https`, empty path, the tunnel outcome in `metadata.tunnel`, `200` when the
/// tunnel was established (`None` for a failed one), and closed (`duration` set).
fn connect_row(authority: &str, tunnel: TunnelInfo, status: Option<u16>) -> Flow {
    let mut flow = http_flow("CONNECT", "", status);
    if let Flow::Http(f) = &mut flow {
        f.request.scheme = "https".into();
        f.request.authority = authority.into();
        f.metadata.duration = Some(Duration::from_millis(1500));
        f.metadata.tunnel = Some(tunnel);
    }
    flow
}

/// `flow.get {id}` as an object.
fn summary_of(reg: &Registry, host: &CommandHost, id: FlowId) -> BTreeMap<String, Value> {
    let got = reg
        .command("flow.get")
        .expect("flow.get registered")
        .invoke(id_params(id), host)
        .expect("flow.get ok");
    let Value::Object(obj) = got else {
        panic!("flow.get must return an object, got {got:?}");
    };
    obj
}

/// `flow.table` as a list of row objects, oldest first.
fn table_rows(reg: &Registry, host: &CommandHost) -> Vec<BTreeMap<String, Value>> {
    let table = reg
        .command("flow.table")
        .expect("flow.table registered")
        .invoke(Params::default(), host)
        .expect("flow.table ok");
    let Value::Object(obj) = table else {
        panic!("flow.table must return an object, got {table:?}");
    };
    let Some(Value::Array(rows)) = obj.get("flows") else {
        panic!("flow.table result must have a `flows` array: {obj:?}");
    };
    rows.iter()
        .map(|row| match row {
            Value::Object(r) => r.clone(),
            other => panic!("every row must be an object, got {other:?}"),
        })
        .collect()
}

/// The five keys of spec D7 on one object, in the order `tunnel`, `tunnel_reason`,
/// `bytes_up`, `bytes_down`, `passive`. `None` means the key is absent, which is
/// never acceptable: every key is always present, null when it does not apply.
fn tunnel_keys(obj: &BTreeMap<String, Value>) -> [Option<&Value>; 5] {
    [
        obj.get("tunnel"),
        obj.get("tunnel_reason"),
        obj.get("bytes_up"),
        obj.get("bytes_down"),
        obj.get("passive"),
    ]
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

/// Spec D7 / AC11: `flow.table` rows and `flow.get` carry `tunnel`,
/// `tunnel_reason`, `bytes_up`, `bytes_down` and `passive` with the documented
/// values for a passthrough row, a failed row, a decrypted row, an ordinary
/// request and a WebSocket flow, and the two verbs agree on every one of them.
#[test]
fn flow_table_and_flow_get_report_tunnel_fields() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let passthrough = store.insert(connect_row(
        "origin.test:443",
        TunnelInfo {
            mode: TunnelMode::Passthrough,
            reason: Some(TunnelReason::OutOfScope),
            bytes_up: Some(10),
            bytes_down: Some(20),
        },
        Some(200),
    ));
    let failed = store.insert(connect_row(
        "pinned.test:443",
        TunnelInfo::failed(TunnelReason::ClientRejectedCertificate),
        None,
    ));
    let decrypted = store.insert(connect_row(
        "api.test:443",
        TunnelInfo::decrypted(),
        Some(200),
    ));
    let ordinary = store.insert(http_flow("GET", "/a", Some(200)));
    let ws = store.insert(ws_flow(ordinary));

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let got = summary_of(&reg, &host, passthrough);
    assert_eq!(got.get("method"), Some(&s("CONNECT")));
    assert_eq!(got.get("scheme"), Some(&s("https")));
    assert_eq!(got.get("status"), Some(&Value::Int(200)));
    assert_eq!(got.get("duration_ms"), Some(&Value::Int(1500)));
    assert_eq!(
        tunnel_keys(&got),
        [
            Some(&s("passthrough")),
            Some(&s("out_of_scope")),
            Some(&Value::Int(10)),
            Some(&Value::Int(20)),
            Some(&Value::Bool(false)),
        ],
        "flow.get on a passthrough row: {got:?}"
    );

    let got = summary_of(&reg, &host, failed);
    assert_eq!(got.get("method"), Some(&s("CONNECT")));
    assert_eq!(
        got.get("status"),
        Some(&Value::Null),
        "a failed tunnel has no exchange outcome"
    );
    assert_eq!(
        tunnel_keys(&got),
        [
            Some(&s("failed")),
            Some(&s("client_rejected_certificate")),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Bool(false)),
        ],
        "flow.get on a failed row: {got:?}"
    );

    let got = summary_of(&reg, &host, decrypted);
    assert_eq!(got.get("status"), Some(&Value::Int(200)));
    assert_eq!(
        tunnel_keys(&got),
        [
            Some(&s("decrypted")),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Bool(false)),
        ],
        "flow.get on a decrypted row: {got:?}"
    );

    let got = summary_of(&reg, &host, ordinary);
    assert_eq!(got.get("method"), Some(&s("GET")));
    assert_eq!(
        tunnel_keys(&got),
        [
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Bool(false)),
        ],
        "flow.get on an ordinary request: {got:?}"
    );

    let got = summary_of(&reg, &host, ws);
    assert_eq!(got.get("kind"), Some(&s("websocket")));
    assert_eq!(
        tunnel_keys(&got),
        [
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Null),
            Some(&Value::Bool(false)),
        ],
        "flow.get on a WebSocket flow: {got:?}"
    );

    // flow.table: the same five keys, the same values, row for row.
    let rows = table_rows(&reg, &host);
    assert_eq!(rows.len(), 5, "five flows captured, in insertion order");
    let expected: [(FlowId, [Value; 5]); 5] = [
        (
            passthrough,
            [
                s("passthrough"),
                s("out_of_scope"),
                Value::Int(10),
                Value::Int(20),
                Value::Bool(false),
            ],
        ),
        (
            failed,
            [
                s("failed"),
                s("client_rejected_certificate"),
                Value::Null,
                Value::Null,
                Value::Bool(false),
            ],
        ),
        (
            decrypted,
            [
                s("decrypted"),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Bool(false),
            ],
        ),
        (
            ordinary,
            [
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Bool(false),
            ],
        ),
        (
            ws,
            [
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Bool(false),
            ],
        ),
    ];
    for (row, (id, want)) in rows.iter().zip(expected.iter()) {
        assert_eq!(row.get("id"), Some(&s(&id.to_string())));
        let want: [Option<&Value>; 5] = [
            Some(&want[0]),
            Some(&want[1]),
            Some(&want[2]),
            Some(&want[3]),
            Some(&want[4]),
        ];
        assert_eq!(tunnel_keys(row), want, "flow.table row for {id}: {row:?}");
        let summary = summary_of(&reg, &host, *id);
        assert_eq!(
            tunnel_keys(row),
            tunnel_keys(&summary),
            "flow.table and flow.get must agree on the tunnel keys for {id}"
        );
    }
    // `status` on the passthrough and failed rows, through the table too.
    assert_eq!(rows[0].get("status"), Some(&Value::Int(200)));
    assert_eq!(rows[1].get("status"), Some(&Value::Null));
    assert_eq!(rows[1].get("method"), Some(&s("CONNECT")));
}

/// Spec D4 / D7: `passive` is a required boolean on both verbs: `true` for a
/// cleartext request to a host outside Scope (observed only), `false` for an
/// ordinary request and for every tunnel row, and a WebSocket flow reports the
/// value stamped on its own metadata (copied from its handshake by the WS module).
#[test]
fn flow_table_and_flow_get_report_passive() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));
    let store = MemFlowStore::new();

    let mut observed = http_flow("GET", "/p", Some(200));
    observed.metadata_mut().passive = true;
    let passive = store.insert(observed);
    let acted_on = store.insert(http_flow("GET", "/q", Some(200)));
    let tunnel = store.insert(connect_row(
        "origin.test:443",
        TunnelInfo::passthrough(TunnelReason::OutOfScope),
        Some(200),
    ));
    let mut ws_meta = ws_flow(passive);
    ws_meta.metadata_mut().passive = true;
    let passive_ws = store.insert(ws_meta);

    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let got = summary_of(&reg, &host, passive);
    assert_eq!(got.get("passive"), Some(&Value::Bool(true)), "{got:?}");
    assert_eq!(
        got.get("tunnel"),
        Some(&Value::Null),
        "a passive request is not a tunnel row"
    );
    let got = summary_of(&reg, &host, acted_on);
    assert_eq!(got.get("passive"), Some(&Value::Bool(false)), "{got:?}");
    let got = summary_of(&reg, &host, tunnel);
    assert_eq!(
        got.get("passive"),
        Some(&Value::Bool(false)),
        "a tunnel row is dispatched passively by virtue of `tunnel`, not `passive`: {got:?}"
    );
    let got = summary_of(&reg, &host, passive_ws);
    assert_eq!(got.get("kind"), Some(&s("websocket")));
    assert_eq!(got.get("passive"), Some(&Value::Bool(true)), "{got:?}");

    let rows = table_rows(&reg, &host);
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].get("id"), Some(&s(&passive.to_string())));
    assert_eq!(rows[0].get("passive"), Some(&Value::Bool(true)));
    assert_eq!(rows[1].get("id"), Some(&s(&acted_on.to_string())));
    assert_eq!(rows[1].get("passive"), Some(&Value::Bool(false)));
    assert_eq!(rows[2].get("id"), Some(&s(&tunnel.to_string())));
    assert_eq!(rows[2].get("passive"), Some(&Value::Bool(false)));
    assert_eq!(rows[2].get("tunnel"), Some(&s("passthrough")));
    assert_eq!(rows[3].get("id"), Some(&s(&passive_ws.to_string())));
    assert_eq!(rows[3].get("kind"), Some(&s("websocket")));
    assert_eq!(rows[3].get("passive"), Some(&Value::Bool(true)));
}

/// Spec D7: both result schemas declare the five keys with the right types, the
/// four tunnel keys optional (null when they do not apply) and `passive` required,
/// and their descriptions quote the value sets so a surface built from
/// `tools/list` learns the vocabulary without hard-coding it.
#[test]
fn schemas_declare_tunnel_and_passive() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(CapturePlugin::new()));

    let get_schema = reg
        .command("flow.get")
        .expect("flow.get registered")
        .schema();
    let TypeDesc::Object(get_fields) = get_schema.result else {
        panic!(
            "flow.get result must be an object schema, got {:?}",
            get_schema.result
        );
    };
    let table_schema = reg
        .command("flow.table")
        .expect("flow.table registered")
        .schema();
    let TypeDesc::Object(table_fields) = table_schema.result else {
        panic!(
            "flow.table result must be an object schema, got {:?}",
            table_schema.result
        );
    };
    let flows = table_fields
        .iter()
        .find(|f| f.name == "flows")
        .expect("flow.table result has a `flows` field");
    let TypeDesc::Array(elem) = &flows.ty else {
        panic!("`flows` must be an array, got {:?}", flows.ty);
    };
    let TypeDesc::Object(row_fields) = elem.as_ref() else {
        panic!("`flows` elements must be objects, got {:?}", elem);
    };

    // (name, type, required, words the description must quote)
    let want: [(&str, TypeDesc, bool, &[&str]); 5] = [
        (
            "tunnel",
            TypeDesc::Str,
            false,
            &["decrypted", "passthrough", "failed", "null"],
        ),
        (
            "tunnel_reason",
            TypeDesc::Str,
            false,
            &[
                "out_of_scope",
                "pinned",
                "client_rejected_certificate",
                "client_closed",
                "client_tls_error",
                "upstream_unreachable",
                "upstream_tls_failed",
                "protocol_error",
                "null",
            ],
        ),
        ("bytes_up", TypeDesc::Int, false, &["passthrough", "null"]),
        ("bytes_down", TypeDesc::Int, false, &["passthrough", "null"]),
        ("passive", TypeDesc::Bool, true, &["Scope"]),
    ];
    for (command, fields) in [("flow.get", &get_fields), ("flow.table", row_fields)] {
        for (name, ty, required, words) in &want {
            let field = fields
                .iter()
                .find(|f| f.name == *name)
                .unwrap_or_else(|| panic!("{name} missing from the {command} schema"));
            assert!(
                std::mem::discriminant(&field.ty) == std::mem::discriminant(ty),
                "{command}.{name} must be {ty:?}, got {:?}",
                field.ty
            );
            assert_eq!(
                field.required, *required,
                "{command}.{name} required flag (the tunnel keys are null when they do not \
                 apply; `passive` is always a boolean)"
            );
            for word in *words {
                assert!(
                    field.description.contains(word),
                    "{command}.{name} description must quote `{word}`: {}",
                    field.description
                );
            }
        }
    }
}
