//! Tester (stage 5) — `aitm-bus-client` against handlers that misbehave, over
//! the in-process transport (no sockets, so these run inside the sandbox).
//! Every malformed reply must become a typed `BusError`, never a panic or a
//! hang; oversized lines must round-trip.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aitm_bus_client::{BusClient, BusError, InProcessHandler, InProcessTransport};
use serde_json::{json, Value};

/// A handler that answers every request with `f(request)`, echoing the id.
fn replying(f: impl Fn(&Value) -> Value + Send + Sync + 'static) -> InProcessHandler {
    Arc::new(move |line: &str| {
        let req: Value = serde_json::from_str(line).ok()?;
        let id = req.get("id")?.clone();
        let mut reply = f(&req);
        if reply.get("id").is_none() {
            reply["id"] = id;
        }
        Some(reply.to_string())
    })
}

fn client(handler: InProcessHandler) -> BusClient {
    BusClient::new(Box::new(InProcessTransport::new(handler)))
}

fn result(v: Value) -> Value {
    json!({"jsonrpc": "2.0", "result": v})
}

#[tokio::test]
async fn in_process_non_json_or_empty_reply_is_a_protocol_error() {
    let c = client(Arc::new(|_| Some("this is not json".into())));
    match c.ping().await {
        Err(BusError::Protocol(m)) => assert!(m.contains("not JSON"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(Arc::new(|_| Some(String::new())));
    assert!(matches!(c.ping().await, Err(BusError::Protocol(_))));
    let c = client(Arc::new(|_| Some("{}".into())));
    match c.ping().await {
        Err(BusError::Protocol(m)) => assert!(m.contains("neither result nor error"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn in_process_rpc_errors_pass_code_and_message_through() {
    let c = client(replying(
        |_| json!({"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"}}),
    ));
    match c.ping().await {
        Err(BusError::Rpc { code, message }) => {
            assert_eq!(code, -32700);
            assert_eq!(message, "parse error");
        }
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| json!({"jsonrpc":"2.0","error":{}})));
    match c.call("x", json!({})).await {
        Err(BusError::Rpc { code, message }) => {
            assert_eq!(code, 0);
            assert_eq!(message, "(no message)");
        }
        other => panic!("{other:?}"),
    }
    let e = BusError::Rpc {
        code: -32602,
        message: "bad".into(),
    };
    assert_eq!(e.to_string(), "bus rpc error -32602: bad");
    assert_eq!(BusError::Tool("t".into()).to_string(), "tool error: t");
    assert_eq!(
        BusError::Protocol("p".into()).to_string(),
        "bus protocol error: p"
    );
}

#[tokio::test]
async fn in_process_tool_result_shapes_that_are_wrong_are_typed_errors() {
    let c = client(replying(|_| result(json!({"isError": true}))));
    match c.call("x", json!({})).await {
        Err(BusError::Tool(m)) => assert_eq!(m, "tool failed without a message"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| result(json!({}))));
    match c.call("x", json!({})).await {
        Err(BusError::Protocol(m)) => {
            assert!(m.contains("neither structuredContent nor text"), "{m}")
        }
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| result(json!(null))));
    assert!(matches!(
        c.call("x", json!({})).await,
        Err(BusError::Protocol(_))
    ));
    assert!(matches!(c.ping().await, Err(BusError::Protocol(_))));
    // `content` present but not an array / without text: still a typed error.
    let c = client(replying(|_| result(json!({"content": "nope"}))));
    assert!(matches!(
        c.call("x", json!({})).await,
        Err(BusError::Protocol(_))
    ));
    let c = client(replying(|_| {
        result(json!({"content": [{"type": "image"}]}))
    }));
    assert!(matches!(
        c.call("x", json!({})).await,
        Err(BusError::Protocol(_))
    ));
    // isError with a non-text first content: the fallback message.
    let c = client(replying(|_| {
        result(json!({"isError": true, "content": [{"type": "image"}]}))
    }));
    assert!(
        matches!(c.call("x", json!({})).await, Err(BusError::Tool(m)) if m == "tool failed without a message")
    );
    // structuredContent wins over text, whatever the text says.
    let c = client(replying(|_| {
        result(
            json!({"content":[{"type":"text","text":"ignored"}],"structuredContent":{"a":1},"isError":false}),
        )
    }));
    assert_eq!(c.call("x", json!({})).await.unwrap(), json!({"a": 1}));
    let c = client(replying(|_| {
        result(json!({"content":[{"type":"text","text":"ignored"}],"structuredContent":null}))
    }));
    assert_eq!(
        c.call("x", json!({})).await.unwrap(),
        Value::Null,
        "an explicit null structuredContent is the result"
    );
}

#[tokio::test]
async fn in_process_handshake_replies_missing_fields_are_protocol_errors() {
    let c = client(replying(|_| {
        result(json!({"protocolVersion": "2025-06-18"}))
    }));
    match c.initialize("aitm-tui", "0").await {
        Err(BusError::Protocol(m)) => assert!(m.contains("serverInfo"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| {
        result(json!({"protocolVersion": "2025-06-18", "serverInfo": {"name": "aitmproxy"}}))
    }));
    match c.initialize("aitm-tui", "0").await {
        Err(BusError::Protocol(m)) => assert!(m.contains("`version`"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| {
        result(json!({"serverInfo": {"name": "a", "version": "1"}}))
    }));
    match c.initialize("aitm-tui", "0").await {
        Err(BusError::Protocol(m)) => assert!(m.contains("protocolVersion"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| result(json!({}))));
    match c.tools_list().await {
        Err(BusError::Protocol(m)) => assert!(m.contains("no tools array"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| {
        result(json!({"tools": [{"description": "nameless"}]}))
    }));
    match c.tools_list().await {
        Err(BusError::Protocol(m)) => assert!(m.contains("`name`"), "{m}"),
        other => panic!("{other:?}"),
    }
    let c = client(replying(|_| result(json!({"tools": [{"name": "bare"}]}))));
    let tools = c.tools_list().await.unwrap();
    assert_eq!(tools[0].name, "bare");
    assert_eq!(tools[0].description, "");
    assert_eq!(tools[0].input_schema, Value::Null);
    let c = client(replying(|_| result(json!({"tools": []}))));
    assert!(c.tools_list().await.unwrap().is_empty());
}

#[tokio::test]
async fn in_process_panicking_handler_is_a_transport_error_not_a_crash() {
    let handler: InProcessHandler =
        Arc::new(|_: &str| -> Option<String> { panic!("handler exploded") });
    let c = client(handler);
    match c.ping().await {
        Err(BusError::Transport(e)) => assert!(format!("{e:#}").contains("panicked"), "{e:#}"),
        other => panic!("{other:?}"),
    }
    // The client is still usable for the next request.
    assert!(matches!(c.ping().await, Err(BusError::Transport(_))));
}

#[tokio::test]
async fn in_process_oversized_lines_round_trip() {
    let five_mb = "x".repeat(5 * 1024 * 1024);
    let seen_len = Arc::new(AtomicU64::new(0));
    let seen = seen_len.clone();
    let c = client(replying(move |req| {
        let arg = req["params"]["arguments"]["blob"].as_str().unwrap_or("");
        seen.store(arg.len() as u64, Ordering::SeqCst);
        result(json!({"structuredContent": {"echo": arg}, "isError": false}))
    }));
    let v = c
        .call("echo", json!({"blob": five_mb.clone()}))
        .await
        .unwrap();
    assert_eq!(seen_len.load(Ordering::SeqCst), five_mb.len() as u64);
    assert_eq!(v["echo"].as_str().unwrap().len(), five_mb.len());
}

#[tokio::test]
async fn in_process_request_ids_increase_and_notifications_carry_none() {
    let ids: Arc<Mutex<Vec<Option<Value>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = ids.clone();
    let handler: InProcessHandler = Arc::new(move |line: &str| {
        let req: Value = serde_json::from_str(line).ok()?;
        seen.lock().unwrap().push(req.get("id").cloned());
        let id = req.get("id")?.clone();
        Some(
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"a","version":"1"}}})
                .to_string(),
        )
    });
    let c = client(handler);
    c.ping().await.unwrap();
    c.initialize("aitm-tui", "0").await.unwrap();
    c.ping().await.unwrap();
    let ids = ids.lock().unwrap().clone();
    assert_eq!(
        ids,
        vec![Some(json!(1)), Some(json!(2)), None, Some(json!(3))],
        "ping, initialize, the id-less initialized notice, ping"
    );
}
