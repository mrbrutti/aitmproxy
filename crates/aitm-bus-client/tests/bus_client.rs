//! `aitm-bus-client` against a fake newline-delimited JSON-RPC server (the shape
//! `aitm-mcp`'s loopback TCP transport speaks), plus the in-process transport
//! and the token-file reader.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{
    read_token_file, BusClient, BusError, InProcessHandler, InProcessTransport, TcpTransport,
    MAX_LINE_BYTES,
};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const TOKEN: &str = "s3cret";

/// What the fake server does when a `tools/call` arrives.
#[derive(Clone, Copy)]
enum CallMode {
    /// Answer `flow.list` and `boom` as the real server would.
    Answer,
    /// Close the connection without replying (simulates a dying proxy).
    DropConnection,
    /// Answer with one line of `MAX_LINE_BYTES + 1` bytes (a reply the client
    /// must refuse to buffer).
    OversizedReply,
}

/// Bind a fake bus on `127.0.0.1:0` and serve connections until the test ends.
///
/// `None` when the bind was refused with `PermissionDenied`: that is the
/// Claude sandbox, which cannot bind ports, not a bug. The caller prints a
/// note and returns; these tests must be run for real in the Terminal panel.
async fn spawn_fake(mode: CallMode) -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "bus_client: skipped — this sandbox refuses to bind 127.0.0.1:0 \
                 (PermissionDenied); run `cargo test -p aitm-bus-client --test bus_client` \
                 in the Terminal panel for the real run"
            );
            return None;
        }
        Err(e) => panic!("bind 127.0.0.1:0: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(serve_one(stream, mode));
        }
    });
    Some(addr)
}

async fn serve_one(stream: TcpStream, mode: CallMode) {
    let (read_half, mut write) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    // The token gate: exactly what `aitm-mcp` does on a bad first line.
    let first = lines.next_line().await.unwrap().unwrap_or_default();
    let ok = serde_json::from_str::<Value>(&first)
        .ok()
        .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|t| t == TOKEN);
    if !ok {
        let refusal =
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"unauthorized"}});
        write
            .write_all(format!("{refusal}\n").as_bytes())
            .await
            .unwrap();
        write.shutdown().await.unwrap();
        return;
    }

    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = serde_json::from_str(&line).unwrap();
        let id = req.get("id").cloned();
        let method = req["method"].as_str().unwrap_or_default().to_owned();
        let Some(id) = id else {
            // A notification: the real server replies nothing.
            continue;
        };
        let reply = match method.as_str() {
            "initialize" => json!({"jsonrpc":"2.0","id":id,"result":{
                "protocolVersion":"2025-06-18",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"aitmproxy-fake","version":"9.9.9"}}}),
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "tools/list" => {
                // An unsolicited push lands while the tools/list reply is in flight.
                let push = json!({"jsonrpc":"2.0","method":"notifications/aitm/state",
                    "params":{"paused":2}});
                write
                    .write_all(format!("{push}\n").as_bytes())
                    .await
                    .unwrap();
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{
                    "name":"flow.list",
                    "description":"List flows.",
                    "inputSchema":{"type":"object","properties":{}}}]}})
            }
            "tools/call" => {
                if let CallMode::DropConnection = mode {
                    drop(write);
                    return;
                }
                if let CallMode::OversizedReply = mode {
                    // A syntactically fine reply whose line is one byte over the cap.
                    let head =
                        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"structuredContent":""#);
                    let tail = "\"}}\n";
                    let pad = MAX_LINE_BYTES + 1 - head.len() - (tail.len() - 1);
                    write.write_all(head.as_bytes()).await.unwrap();
                    let chunk = vec![b'z'; 1024 * 1024];
                    let mut left = pad;
                    while left > 0 {
                        let n = left.min(chunk.len());
                        if write.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        left -= n;
                    }
                    let _ = write.write_all(tail.as_bytes()).await;
                    return;
                }
                match req["params"]["name"].as_str().unwrap_or_default() {
                    "flow.list" => json!({"jsonrpc":"2.0","id":id,"result":{
                        "content":[{"type":"text","text":"[\"a\",\"b\"]"}],
                        "structuredContent":["a","b"],
                        "isError":false}}),
                    "boom" => json!({"jsonrpc":"2.0","id":id,"result":{
                        "content":[{"type":"text","text":"kaboom"}],
                        "isError":true}}),
                    other => json!({"jsonrpc":"2.0","id":id,"error":{
                        "code":-32602,"message":format!("unknown tool `{other}`")}}),
                }
            }
            other => json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32601,"message":format!("unknown method `{other}`")}}),
        };
        write
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .unwrap();
    }
}

async fn connect(addr: SocketAddr, token: &str) -> BusClient {
    let transport = TcpTransport::connect(addr, token).await.unwrap();
    BusClient::new(Box::new(transport))
}

// ------------------------------------------------------------------ TCP

#[tokio::test]
async fn wrong_token_surfaces_unauthorized_rpc_error() {
    let Some(addr) = spawn_fake(CallMode::Answer).await else {
        return;
    };
    let client = connect(addr, "wrong").await;
    let err = timeout(Duration::from_secs(2), client.initialize("aitm-tui", "0.1"))
        .await
        .expect("must not hang")
        .unwrap_err();
    match err {
        BusError::Rpc { code, .. } => assert_eq!(code, -32001),
        other => panic!("expected Rpc -32001, got {other:?}"),
    }
}

#[tokio::test]
async fn initialize_tools_list_and_call_over_tcp() {
    let Some(addr) = spawn_fake(CallMode::Answer).await else {
        return;
    };
    let client = connect(addr, TOKEN).await;

    let info = client.initialize("aitm-tui", "0.1").await.unwrap();
    assert_eq!(info.name, "aitmproxy-fake");
    assert_eq!(info.version, "9.9.9");
    assert_eq!(info.protocol_version, "2025-06-18");

    let tools = client.tools_list().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "flow.list");
    assert_eq!(tools[0].description, "List flows.");
    assert_eq!(tools[0].input_schema["type"], "object");

    let listed = client.call("flow.list", json!({})).await.unwrap();
    assert_eq!(listed, json!(["a", "b"]));

    match client.call("boom", json!({})).await {
        Err(BusError::Tool(m)) => assert_eq!(m, "kaboom"),
        other => panic!("expected Tool(kaboom), got {other:?}"),
    }

    match client.call("nope", json!({})).await {
        Err(BusError::Rpc { code, .. }) => assert_eq!(code, -32602),
        other => panic!("expected Rpc -32602, got {other:?}"),
    }

    client.ping().await.unwrap();
}

#[tokio::test]
async fn unsolicited_notification_reaches_subscribers_without_disturbing_calls() {
    let Some(addr) = spawn_fake(CallMode::Answer).await else {
        return;
    };
    let client = connect(addr, TOKEN).await;
    let mut pushes = client.notifications().expect("TCP delivers notifications");

    client.initialize("aitm-tui", "0.1").await.unwrap();
    // The fake pushes a notification *before* writing the tools/list reply, so
    // the push arrives while this request is in flight.
    let tools = client.tools_list().await.unwrap();
    assert_eq!(tools[0].name, "flow.list");

    let line = timeout(Duration::from_secs(2), pushes.recv())
        .await
        .expect("notification must arrive")
        .unwrap();
    let push: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(push["method"], "notifications/aitm/state");
    assert_eq!(push["params"]["paused"], 2);

    // The connection is still healthy afterwards.
    assert_eq!(
        client.call("flow.list", json!({})).await.unwrap(),
        json!(["a", "b"])
    );
}

#[tokio::test]
async fn connection_dropped_mid_request_fails_with_transport_error() {
    let Some(addr) = spawn_fake(CallMode::DropConnection).await else {
        return;
    };
    let client = connect(addr, TOKEN).await;
    client.initialize("aitm-tui", "0.1").await.unwrap();

    let outcome = timeout(Duration::from_secs(2), client.call("flow.list", json!({})))
        .await
        .expect("a dead connection must fail the call, not hang");
    match outcome {
        Err(BusError::Transport(_)) => {}
        other => panic!("expected Transport error, got {other:?}"),
    }

    // And later requests fail fast too, rather than queueing forever.
    let later = timeout(Duration::from_secs(2), client.ping())
        .await
        .expect("must not hang");
    assert!(matches!(later, Err(BusError::Transport(_))), "{later:?}");
}

/// S7: a reply line over `MAX_LINE_BYTES` is not buffered; the connection is
/// closed as gone and the in-flight call fails with a transport error that
/// names the cap.
#[tokio::test]
async fn a_reply_line_over_the_cap_fails_the_call_and_closes_the_connection() {
    let Some(addr) = spawn_fake(CallMode::OversizedReply).await else {
        return;
    };
    let client = connect(addr, TOKEN).await;
    client.initialize("aitm-tui", "0.1").await.unwrap();

    let outcome = timeout(Duration::from_secs(20), client.call("flow.list", json!({})))
        .await
        .expect("an oversized reply must fail the call, not hang");
    match outcome {
        Err(BusError::Transport(e)) => {
            assert!(format!("{e:#}").contains("reply line over 64 MiB"), "{e:#}")
        }
        other => panic!("expected Transport error, got {other:?}"),
    }
    let later = timeout(Duration::from_secs(2), client.ping())
        .await
        .expect("must not hang");
    assert!(matches!(later, Err(BusError::Transport(_))), "{later:?}");
}

// ----------------------------------------------------------- in-process

/// A handler that behaves like `McpServer::handle` for the methods we need.
fn fake_handler() -> InProcessHandler {
    Arc::new(|line: &str| {
        let req: Value = serde_json::from_str(line).ok()?;
        let id = req.get("id")?.clone();
        let reply = match req["method"].as_str()? {
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "initialize" => json!({"jsonrpc":"2.0","id":id,"result":{
                "protocolVersion": req["params"]["protocolVersion"],
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"aitmproxy","version":"0.1.0"}}}),
            "tools/call" => match req["params"]["name"].as_str()? {
                // Text-only content, JSON inside: parsed.
                "text.json" => json!({"jsonrpc":"2.0","id":id,"result":{
                    "content":[{"type":"text","text":"{\"x\":1}"}],"isError":false}}),
                // Text-only content, not JSON: returned as a string.
                "text.plain" => json!({"jsonrpc":"2.0","id":id,"result":{
                    "content":[{"type":"text","text":"hello"}],"isError":false}}),
                // Garbage result shape.
                _ => json!({"jsonrpc":"2.0","id":id,"result":"not an object"}),
            },
            m => json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32601,"message":format!("unknown method `{m}`")}}),
        };
        Some(reply.to_string())
    })
}

#[tokio::test]
async fn in_process_ping_and_initialize() {
    let client = BusClient::new(Box::new(InProcessTransport::new(fake_handler())));
    client.ping().await.unwrap();
    let info = client.initialize("aitm-tui", "0.1").await.unwrap();
    assert_eq!(info.name, "aitmproxy");
    assert_eq!(info.version, "0.1.0");
    assert_eq!(info.protocol_version, "2025-06-18");
    assert!(client.notifications().is_none());
}

#[tokio::test]
async fn in_process_call_result_shapes() {
    let client = BusClient::new(Box::new(InProcessTransport::new(fake_handler())));
    assert_eq!(
        client.call("text.json", json!({})).await.unwrap(),
        json!({"x": 1})
    );
    assert_eq!(
        client.call("text.plain", json!({})).await.unwrap(),
        json!("hello")
    );
    assert!(matches!(
        client.call("weird", json!({})).await,
        Err(BusError::Protocol(_))
    ));
    assert!(matches!(
        client.tools_list().await,
        Err(BusError::Rpc { code: -32601, .. })
    ));
}

#[tokio::test]
async fn in_process_handler_that_never_replies_is_a_protocol_error() {
    let silent: InProcessHandler = Arc::new(|_| None);
    let client = BusClient::new(Box::new(InProcessTransport::new(silent)));
    assert!(matches!(client.ping().await, Err(BusError::Protocol(_))));
}

// ------------------------------------------------------------ token file

#[test]
fn read_token_file_trims_and_rejects_empty() {
    let dir = std::env::temp_dir().join(format!("aitm-bus-client-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let good = dir.join("good");
    std::fs::write(&good, " tok \n").unwrap();
    assert_eq!(read_token_file(&good).unwrap(), "tok");

    let empty = dir.join("empty");
    std::fs::write(&empty, "\n  \n").unwrap();
    assert!(read_token_file(&empty).is_err());

    assert!(read_token_file(&dir.join("missing")).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bus_error_displays_and_converts_from_anyhow() {
    let e: BusError = anyhow::anyhow!("socket closed").into();
    assert!(matches!(e, BusError::Transport(_)));
    assert!(e.to_string().contains("socket closed"));
    let rpc = BusError::Rpc {
        code: -32001,
        message: "unauthorized".into(),
    };
    assert!(rpc.to_string().contains("-32001"));
    let _: &dyn std::error::Error = &rpc;
}
