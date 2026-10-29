//! Task 25: the MCP frontend — tool derivation, `tools/list`, `tools/call`,
//! and the loopback-TCP token gate. Commands here are test stubs; the exact
//! 18-tool AC7 set is asserted at integration (Task 28/29) when every
//! command-providing crate is on one branch.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, Command, CommandHost, ConnInfo, Flow, FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, McpTransport, MemFlowStore, ParamDef, ParamSchema,
    Params, Plugin, ProxyClient, Registry, StdGuard, TypeDesc, Value,
};
use aitm_mcp::json::{from_json, to_json};
use aitm_mcp::transport::LoopbackTcp;
use aitm_mcp::{McpSchemaDerive, McpServer, StdSchemaDerive};
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

// ---------------------------------------------------------------- fixtures

/// `demo.ping`, registered by a plugin's `load` (AC-P2 wording).
struct PingCmd;

impl Command for PingCmd {
    fn name(&self) -> &str {
        "demo.ping"
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

struct DemoPlugin;

impl Plugin for DemoPlugin {
    fn name(&self) -> &str {
        "demo"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(PingCmd));
    }
}

/// A capture-style stub: inserts an `HttpFlow` for `authority`+`path` into the
/// host's store and returns its id. Stands in for the proxy's capture path so
/// AC9 can be driven purely over MCP.
struct CaptureCmd;

impl Command for CaptureCmd {
    fn name(&self) -> &str {
        "demo.capture"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Simulate capturing one GET request.".into(),
            params: vec![
                ParamDef {
                    name: "authority".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "host[:port]".into(),
                },
                ParamDef {
                    name: "path".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: String::new(),
                },
            ],
            result: TypeDesc::FlowId,
        }
    }
    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let flow = http_flow(args.get_str("authority")?, args.get_str("path")?);
        let id = host.store().insert(flow);
        Ok(Value::Str(id.to_string()))
    }
}

/// `flow.get {id}` → `{id, method, authority, path}` from the host's store.
struct FlowGetCmd;

impl Command for FlowGetCmd {
    fn name(&self) -> &str {
        "flow.get"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Fetch one captured flow.".into(),
            params: vec![ParamDef {
                name: "id".into(),
                ty: TypeDesc::FlowId,
                required: true,
                description: "flow id".into(),
            }],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let Some(Flow::Http(f)) = host.store().get(id) else {
            anyhow::bail!("no such flow {id}");
        };
        let mut out = BTreeMap::new();
        out.insert("id".to_string(), Value::Str(f.id.to_string()));
        out.insert("method".to_string(), Value::Str(f.request.method));
        out.insert("authority".to_string(), Value::Str(f.request.authority));
        out.insert("path".to_string(), Value::Str(f.request.path));
        Ok(Value::Object(out))
    }
}

/// `flow.list` → array of flow ids.
struct FlowListCmd;

impl Command for FlowListCmd {
    fn name(&self) -> &str {
        "flow.list"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "List captured flow ids.".into(),
            params: vec![],
            result: TypeDesc::Array(Box::new(TypeDesc::FlowId)),
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Array(
            host.store()
                .list()
                .into_iter()
                .map(|id| Value::Str(id.to_string()))
                .collect(),
        ))
    }
}

/// A command whose schema exercises every `TypeDesc` variant; echoes its args.
struct EchoCmd;

impl Command for EchoCmd {
    fn name(&self) -> &str {
        "demo.echo"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Echo typed arguments back.".into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "a flow id".into(),
                },
                ParamDef {
                    name: "limit".into(),
                    ty: TypeDesc::Int,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "ratio".into(),
                    ty: TypeDesc::Float,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "verbose".into(),
                    ty: TypeDesc::Bool,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "raw".into(),
                    ty: TypeDesc::Bytes,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "tags".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Str)),
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "edits".into(),
                    ty: TypeDesc::Object(vec![ParamDef {
                        name: "method".into(),
                        ty: TypeDesc::Str,
                        required: true,
                        description: String::new(),
                    }]),
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "extra".into(),
                    ty: TypeDesc::Any,
                    required: false,
                    description: String::new(),
                },
            ],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Object(
            args.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        ))
    }
}

/// A command that always fails, to prove invoke errors become tool errors.
struct FailCmd;

impl Command for FailCmd {
    fn name(&self) -> &str {
        "demo.fail"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Always fails.".into(),
            params: vec![],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        anyhow::bail!("boom: nothing to see")
    }
}

/// `demo.frontend`: reports which frontend built the host it ran on.
struct FrontendCmd;

impl Command for FrontendCmd {
    fn name(&self) -> &str {
        "demo.frontend"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Names the invoking frontend.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let label = match host.frontend() {
            Frontend::Cli => "cli",
            Frontend::Mcp => "mcp",
            _ => "other",
        };
        Ok(Value::Str(label.into()))
    }
}

/// The host needs a `ProxyClient`; no stub command here calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn http_flow(authority: &str, path: &str) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: aitm_core::FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
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

/// A registry with `demo.ping` (via plugin) plus the flow stubs.
fn registry() -> Arc<Registry> {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(DemoPlugin));
    reg.add_command(Arc::new(CaptureCmd));
    reg.add_command(Arc::new(FlowGetCmd));
    reg.add_command(Arc::new(FlowListCmd));
    reg.add_command(Arc::new(EchoCmd));
    reg.add_command(Arc::new(FailCmd));
    Arc::new(reg)
}

/// A stdio-configured server with services attached (the transport is unused
/// when driving `handle` in-process).
fn server_with(store: Arc<MemFlowStore>) -> McpServer {
    McpServer::new(registry(), McpTransport::Stdio).with_services(
        store,
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
}

fn server() -> McpServer {
    server_with(Arc::new(MemFlowStore::new()))
}

/// The in-process MCP client: one JSON-RPC request in, the parsed response out.
fn rpc(server: &McpServer, id: u64, method: &str, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let resp = server
        .handle(&req.to_string())
        .expect("a request gets a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

fn tool_names(list_resp: &JsonValue) -> Vec<String> {
    list_resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_string())
        .collect()
}

// ------------------------------------------------------------------- tests

#[test]
fn tool_schema_derives_from_param_schema() {
    let tool = StdSchemaDerive.to_mcp_tool(&EchoCmd);
    assert_eq!(tool.name, "demo.echo");
    assert_eq!(tool.description, "Echo typed arguments back.");
    assert_eq!(
        tool.input_schema,
        json!({
            "type": "object",
            "properties": {
                "id":      {"type": "string", "format": "uuid", "description": "a flow id"},
                "limit":   {"type": "integer"},
                "ratio":   {"type": "number"},
                "verbose": {"type": "boolean"},
                "raw":     {"type": "string", "contentEncoding": "base64"},
                "tags":    {"type": "array", "items": {"type": "string"}},
                "edits":   {
                    "type": "object",
                    "properties": {"method": {"type": "string"}},
                    "required": ["method"],
                    "additionalProperties": false
                },
                "extra":   {}
            },
            "required": ["id"],
            "additionalProperties": false
        })
    );
    // No params → still an object schema (MCP requires `type: object`).
    let ping = StdSchemaDerive.to_mcp_tool(&PingCmd);
    assert_eq!(
        ping.input_schema,
        json!({"type": "object", "properties": {}, "additionalProperties": false})
    );
    assert_eq!(
        ping.to_json(),
        json!({
            "name": "demo.ping",
            "description": "Replies pong.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        })
    );
}

#[test]
fn initialize_handshake() {
    let srv = server();
    let resp = rpc(
        &srv,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(resp["result"]["serverInfo"]["name"], "aitmproxy");
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    // Notifications get no response.
    assert_eq!(
        srv.handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        None
    );
    assert_eq!(rpc(&srv, 2, "ping", json!({}))["result"], json!({}));
}

/// AC7-shaped: `tools/list` is exactly the registered command set (plugin
/// commands included). The exact 18-tool M1 set is asserted at integration.
#[test]
fn tools_list_enumerates_registered_commands() {
    let srv = server();
    let resp = rpc(&srv, 1, "tools/list", json!({}));
    let mut names = tool_names(&resp);
    names.sort();
    assert_eq!(
        names,
        vec![
            "demo.capture",
            "demo.echo",
            "demo.fail",
            "demo.ping",
            "flow.get",
            "flow.list"
        ]
    );
    let ping = resp["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["name"] == "demo.ping")
        .expect("demo.ping listed");
    assert_eq!(ping["description"], "Replies pong.");
    assert_eq!(ping["inputSchema"]["type"], "object");
}

/// AC-P2 (MCP half): a plugin-registered command is callable over MCP.
#[test]
fn ping_over_mcp() {
    let srv = server();
    let resp = rpc(
        &srv,
        7,
        "tools/call",
        json!({"name": "demo.ping", "arguments": {}}),
    );
    assert_eq!(resp["id"], 7);
    assert_eq!(resp["result"]["structuredContent"], json!("pong"));
    assert_eq!(
        resp["result"]["content"],
        json!([{"type": "text", "text": "\"pong\""}])
    );
    assert_eq!(resp["result"]["isError"], json!(false));
}

/// AC9: driving only an MCP client, a flow is captured and retrieved via `flow.get`.
#[test]
fn mcp_only_capture() {
    let store = Arc::new(MemFlowStore::new());
    let srv = server_with(store.clone());

    let cap = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "demo.capture", "arguments": {"authority": "target.test:8080", "path": "/search?q=x"}}),
    );
    let id = cap["result"]["structuredContent"]
        .as_str()
        .expect("capture returns the flow id")
        .to_string();
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.list()[0].to_string(), id);

    let got = rpc(
        &srv,
        2,
        "tools/call",
        json!({"name": "flow.get", "arguments": {"id": id}}),
    );
    assert_eq!(
        got["result"]["structuredContent"],
        json!({"id": id, "method": "GET", "authority": "target.test:8080", "path": "/search?q=x"})
    );
    assert_eq!(got["result"]["isError"], json!(false));
}

#[test]
fn arguments_are_coerced_by_type_desc() {
    let srv = server();
    let id = aitm_core::FlowId::new().to_string();
    let resp = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {
            "id": id, "limit": 5, "ratio": 0.5, "verbose": true,
            "raw": "TWFu", "tags": ["a", "b"], "edits": {"method": "POST"},
            "extra": {"n": 1, "s": "x", "f": 1.5, "l": [true, null]}
        }}),
    );
    assert_eq!(
        resp["result"]["structuredContent"],
        json!({
            "id": id, "limit": 5, "ratio": 0.5, "verbose": true,
            "raw": "TWFu", "tags": ["a", "b"], "edits": {"method": "POST"},
            "extra": {"n": 1, "s": "x", "f": 1.5, "l": [true, null]}
        })
    );

    // Wrong type, bad flow id, unknown argument, missing required: each is a
    // tool error naming the parameter.
    let bad_type = rpc(
        &srv,
        2,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": id, "limit": "five"}}),
    );
    assert_eq!(bad_type["result"]["isError"], json!(true));
    let text = bad_type["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.contains("limit") && text.contains("integer"), "{text}");

    let bad_id = rpc(
        &srv,
        3,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": "not-a-uuid"}}),
    );
    assert_eq!(bad_id["result"]["isError"], json!(true));
    assert!(bad_id["result"]["content"][0]["text"]
        .as_str()
        .expect("text")
        .contains("id"));

    let unknown = rpc(
        &srv,
        4,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": id, "bogus": 1}}),
    );
    assert_eq!(unknown["result"]["isError"], json!(true));
    assert!(unknown["result"]["content"][0]["text"]
        .as_str()
        .expect("text")
        .contains("bogus"));

    let missing = rpc(
        &srv,
        5,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {}}),
    );
    assert_eq!(missing["result"]["isError"], json!(true));
    let text = missing["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.contains("missing") && text.contains("id"), "{text}");
}

#[test]
fn value_json_roundtrip_including_bytes() {
    let mut obj = BTreeMap::new();
    obj.insert("b".to_string(), Value::Bytes(b"Man".to_vec()));
    obj.insert("n".to_string(), Value::Null);
    obj.insert("i".to_string(), Value::Int(-3));
    obj.insert("f".to_string(), Value::Float(2.5));
    obj.insert(
        "a".to_string(),
        Value::Array(vec![Value::Bool(true), Value::Str("s".into())]),
    );
    let v = Value::Object(obj);
    let j = to_json(&v);
    assert_eq!(
        j,
        json!({"b": "TWFu", "n": null, "i": -3, "f": 2.5, "a": [true, "s"]})
    );
    // Bytes are typed: decoding needs the TypeDesc, which is how `tools/call`
    // sees them. Everything else round-trips structurally under `Any`.
    assert_eq!(
        from_json(&json!("TWFu"), &TypeDesc::Bytes).expect("decodes"),
        Value::Bytes(b"Man".to_vec())
    );
    assert_eq!(
        from_json(
            &json!({"i": -3, "f": 2.5, "a": [true, "s"], "n": null}),
            &TypeDesc::Any
        )
        .expect("structural"),
        {
            let mut m = BTreeMap::new();
            m.insert("i".to_string(), Value::Int(-3));
            m.insert("f".to_string(), Value::Float(2.5));
            m.insert(
                "a".to_string(),
                Value::Array(vec![Value::Bool(true), Value::Str("s".into())]),
            );
            m.insert("n".to_string(), Value::Null);
            Value::Object(m)
        }
    );
    assert!(from_json(&json!("not base64!"), &TypeDesc::Bytes).is_err());
}

#[test]
fn command_failure_is_a_tool_error_not_a_protocol_error() {
    let srv = server();
    let resp = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "demo.fail", "arguments": {}}),
    );
    assert!(resp.get("error").is_none(), "{resp}");
    assert_eq!(resp["result"]["isError"], json!(true));
    assert_eq!(
        resp["result"]["content"],
        json!([{"type": "text", "text": "boom: nothing to see"}])
    );
}

#[test]
fn protocol_errors() {
    let srv = server();
    // Unknown tool → invalid params.
    let resp = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "nope.nothing", "arguments": {}}),
    );
    assert_eq!(resp["error"]["code"], -32602);
    assert!(resp["error"]["message"]
        .as_str()
        .expect("msg")
        .contains("nope.nothing"));
    // Unknown method.
    let resp = rpc(&srv, 2, "bogus/method", json!({}));
    assert_eq!(resp["error"]["code"], -32601);
    // Malformed JSON → parse error with null id.
    let resp: JsonValue =
        serde_json::from_str(&srv.handle("{not json").expect("parse errors are answered"))
            .expect("json");
    assert_eq!(resp["error"]["code"], -32700);
    assert_eq!(resp["id"], JsonValue::Null);
    // Valid JSON, not a request.
    let resp: JsonValue =
        serde_json::from_str(&srv.handle("[1,2]").expect("invalid requests are answered"))
            .expect("json");
    assert_eq!(resp["error"]["code"], -32600);
}

#[test]
fn call_without_services_is_an_internal_error_but_list_works() {
    let srv = McpServer::new(registry(), McpTransport::Stdio);
    assert_eq!(tool_names(&rpc(&srv, 1, "tools/list", json!({}))).len(), 6);
    let resp = rpc(
        &srv,
        2,
        "tools/call",
        json!({"name": "demo.ping", "arguments": {}}),
    );
    assert_eq!(resp["error"]["code"], -32603);
    assert!(resp["error"]["message"]
        .as_str()
        .expect("msg")
        .contains("with_services"));
}

/// M2 Task 18 (CA-AC19 mechanics): the host `tools/call` builds declares
/// itself `Frontend::Mcp`, so a gated command sees an agent, not a human.
#[test]
fn frontend_is_mcp() {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(FrontendCmd));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio).with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    );
    let resp = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "demo.frontend", "arguments": {}}),
    );
    assert_eq!(resp["result"]["isError"], json!(false));
    assert_eq!(resp["result"]["structuredContent"], json!("mcp"));
}

/// The transports share one newline-JSON loop; prove it over an in-memory pipe.
#[tokio::test]
async fn serve_lines_answers_each_request_on_its_own_line() {
    let srv = Arc::new(server());
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(server_side);
    let task = tokio::spawn(aitm_mcp::transport::serve_lines(
        srv,
        BufReader::new(srv_r),
        srv_w,
    ));

    let (cli_r, mut cli_w) = tokio::io::split(client_side);
    let mut lines = BufReader::new(cli_r).lines();
    cli_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.ping\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
        .await
        .expect("write");
    let first: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("line")).expect("json");
    assert_eq!(first["id"], 1);
    assert_eq!(first["result"]["structuredContent"], "pong");
    let second: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("line")).expect("json");
    assert_eq!(second["id"], 2);
    // Closing the client's write side is EOF for the server's reader.
    cli_w.shutdown().await.expect("shutdown");
    task.await.expect("join").expect("loop ends cleanly at EOF");
}

/// A loopback-TCP call without the token is refused; with it, it is served.
#[tokio::test]
async fn loopback_requires_token() {
    let srv = Arc::new(server());
    let listener = LoopbackTcp::bind(0, "s3cret".into(), None)
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr();
    assert!(addr.ip().is_loopback());
    tokio::spawn(listener.serve(srv));

    // No token: the first line is a request, not the auth preamble.
    let mut no_token = TcpStream::connect(addr).await.expect("connect");
    no_token
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
        .await
        .expect("write");
    let (r, _w) = no_token.split();
    let mut lines = BufReader::new(r).lines();
    let reply: JsonValue = serde_json::from_str(
        &lines
            .next_line()
            .await
            .expect("io")
            .expect("a refusal line"),
    )
    .expect("json");
    assert_eq!(reply["error"]["code"], -32001);
    assert_eq!(reply["error"]["message"], "unauthorized");
    assert!(reply.get("result").is_none());
    assert_eq!(
        lines.next_line().await.expect("io"),
        None,
        "connection closed"
    );

    // Wrong token: same refusal.
    let mut wrong = TcpStream::connect(addr).await.expect("connect");
    wrong
        .write_all(b"{\"token\":\"nope\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
        .await
        .expect("write");
    let (r, _w) = wrong.split();
    let mut lines = BufReader::new(r).lines();
    let reply: JsonValue = serde_json::from_str(
        &lines
            .next_line()
            .await
            .expect("io")
            .expect("a refusal line"),
    )
    .expect("json");
    assert_eq!(reply["error"]["code"], -32001);
    assert_eq!(
        lines.next_line().await.expect("io"),
        None,
        "connection closed"
    );

    // Right token: served.
    let mut ok = TcpStream::connect(addr).await.expect("connect");
    ok.write_all(b"{\"token\":\"s3cret\"}\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.ping\",\"arguments\":{}}}\n")
        .await
        .expect("write");
    let (r, _w) = ok.split();
    let mut lines = BufReader::new(r).lines();
    let reply: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("a reply line"))
            .expect("json");
    assert_eq!(reply["id"], 9);
    assert_eq!(reply["result"]["structuredContent"], "pong");
}

/// `McpServer::serve` with a `LoopbackTcp` config binds 127.0.0.1 and serves
/// the token-gated loop; the bound address is reported through `on_bound`.
#[tokio::test]
async fn serve_binds_loopback_from_config() {
    let srv = McpServer::new(
        registry(),
        McpTransport::LoopbackTcp {
            port: 0,
            token: "tok".into(),
            endpoint_file: None,
        },
    )
    .with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    );
    let (tx, rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    tokio::spawn(
        srv.on_bound(move |addr| {
            let _ = tx.send(addr);
        })
        .serve(),
    );
    let addr = rx.await.expect("serve reports its bound address");
    assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);

    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(b"{\"token\":\"tok\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
        .await
        .expect("write");
    let (r, _w) = s.split();
    let mut lines = BufReader::new(r).lines();
    let reply: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("line")).expect("json");
    assert_eq!(tool_names(&reply).len(), 6);
}
