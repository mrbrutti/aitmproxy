//! Task 4 (AC8–AC12): the streamable-HTTP MCP transport's four fail-closed
//! guards and its end-to-end parity with the other transports.
//!
//! These tests bind a real loopback listener and drive it with a raw `hyper`
//! client. **Port binding is blocked in the Claude sandbox** (`bind` → EPERM),
//! so they are written to run in a real shell (the Terminal panel) — the
//! in-sandbox proof for Task 4 is `cargo fmt/clippy/build` over the workspace,
//! plus the pure-function guard unit tests in `src/http.rs`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, McpTransport, ParamSchema, Params, Registry, Sensitivity, TypeDesc, Value,
};
use aitm_mcp::{McpServer, StreamableHttp, StreamableHttpCfg};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value as JsonValue};
use tokio::net::TcpStream;

const TOKEN: &str = "s3cret-bearer-token";

// --------------------------------------------------------------- fixtures

/// A trivial read-only command so `tools/list` has something to enumerate.
struct PingCmd;

impl Command for PingCmd {
    fn name(&self) -> &str {
        "demo.ping"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Replies pong.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("pong".into()))
    }
}

fn test_server() -> Arc<McpServer> {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(PingCmd));
    Arc::new(McpServer::new(Arc::new(reg), McpTransport::Stdio))
}

/// Bind the transport on `127.0.0.1:0` with `allowed_origins`, spawn `serve`,
/// and return the bound address.
async fn spawn(allowed_origins: Vec<String>) -> SocketAddr {
    let server = test_server();
    let http = StreamableHttp::bind(StreamableHttpCfg {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        token: TOKEN.into(),
        allowed_origins,
        path: "/mcp".into(),
    })
    .await
    .expect("bind 127.0.0.1:0");
    let addr = http.local_addr();
    tokio::spawn(async move {
        let _ = http.serve(server).await;
    });
    addr
}

/// One request/response over a fresh connection. `headers` are added verbatim
/// (so a test can set a hostile `Host`/`Origin`); the body is sent as-is.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("request");
    let resp = sender.send_request(req).await.expect("send");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn initialize_body() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).to_string()
}

fn authz() -> String {
    format!("Bearer {TOKEN}")
}

// ------------------------------------------------------------------ tests

/// AC8 — auth: a POST with no or a wrong Bearer is `401` and never dispatched;
/// a correct token is accepted (`200`).
#[tokio::test]
async fn rejects_missing_and_wrong_token() {
    let addr = spawn(vec![]).await;
    let host = addr.to_string();

    // No Authorization header.
    let (status, body) =
        request(addr, "POST", "/mcp", &[("Host", &host)], &initialize_body()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        !body.contains("\"result\""),
        "an unauthorized request must not reach a tool: {body:?}"
    );

    // Wrong Bearer token.
    let (status, body) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", "Bearer wrong")],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("\"result\""), "{body:?}");

    // Correct token is accepted.
    let (status, body) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: JsonValue = serde_json::from_str(&body).expect("json reply");
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
}

/// AC9 — Origin: a present Origin not in the allowlist is `403`; no Origin is
/// accepted (`200`).
#[tokio::test]
async fn rejects_foreign_origin() {
    let addr = spawn(vec![]).await;
    let host = addr.to_string();

    let (status, _) = request(
        addr,
        "POST",
        "/mcp",
        &[
            ("Host", &host),
            ("Authorization", &authz()),
            ("Origin", "https://evil.test"),
        ],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Same request with no Origin is accepted.
    let (status, _) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// AC10 — rebinding/Host: a non-loopback, non-allowlisted Host is `403`; a
/// loopback Host is accepted.
#[tokio::test]
async fn rejects_rebound_host() {
    let addr = spawn(vec![]).await;
    let host = addr.to_string();

    let (status, _) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", "attacker.example"), ("Authorization", &authz())],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// AC11 — bind default: the default config binds a loopback address; binding
/// preserves the loopback interface.
#[tokio::test]
async fn binds_loopback_by_default() {
    let default = McpTransport::streamable_http_default("t".into());
    let McpTransport::StreamableHttp { bind, .. } = default else {
        panic!("streamable_http_default is StreamableHttp");
    };
    assert!(bind.ip().is_loopback(), "the default bind is loopback");

    // Bind the default interface on an ephemeral port to avoid a fixed-port clash.
    let http = StreamableHttp::bind(StreamableHttpCfg {
        bind: SocketAddr::new(bind.ip(), 0),
        token: "t".into(),
        allowed_origins: vec![],
        path: "/mcp".into(),
    })
    .await
    .expect("bind default loopback");
    assert!(http.local_addr().ip().is_loopback());
}

/// AC12 — end-to-end: authorized, same-origin `initialize`, `tools/list`, and
/// `resources/read` over POST return the shapes AC1–AC3 assert over stdio.
#[tokio::test]
async fn end_to_end_matches_stdio() {
    let addr = spawn(vec![]).await;
    let host = addr.to_string();

    // initialize (AC1).
    let (status, body) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &initialize_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: JsonValue = serde_json::from_str(&body).expect("json");
    assert!(v["result"]["capabilities"]["tools"].is_object());
    assert!(v["result"]["capabilities"]["resources"].is_object());
    assert!(v["result"]["serverInfo"].is_object());

    // tools/list.
    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string();
    let (status, body) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &list,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: JsonValue = serde_json::from_str(&body).expect("json");
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"demo.ping"), "{names:?}");

    // resources/read for the first widget (AC3).
    let uri = aitm_mcp::widgets()[0].uri;
    let read =
        json!({"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri": uri}}).to_string();
    let (status, body) = request(
        addr,
        "POST",
        "/mcp",
        &[("Host", &host), ("Authorization", &authz())],
        &read,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: JsonValue = serde_json::from_str(&body).expect("json");
    assert_eq!(
        v["result"]["contents"][0]["mimeType"],
        "text/html;profile=mcp-app"
    );
    assert!(v["result"]["contents"][0]["text"]
        .as_str()
        .expect("text")
        .starts_with("<!DOCTYPE html>"));
}
