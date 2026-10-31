//! Task 13: the capture plugin's read commands, `flow.list` and `flow.get`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params, Plugin,
    ProxyClient, Registry, StdGuard, TypeDesc, Value, WsFlow,
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
