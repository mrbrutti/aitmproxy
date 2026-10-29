//! Task 25: the MCP frontend — tool derivation, `tools/list`, `tools/call`,
//! and the loopback-TCP token gate. Commands here are test stubs; the exact
//! 18-tool AC7 set is asserted at integration (Task 28/29) when every
//! command-providing crate is on one branch.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    AgentPolicy, AgentState, AuditRing, Body, Command, CommandHost, Config, ConnInfo, Flow,
    FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState,
    McpTransport, MemFlowStore, ParamDef, ParamSchema, Params, Plugin, ProxyClient, Registry,
    Sensitivity, StdGuard, TypeDesc, Value,
};
use aitm_mcp::json::{from_json, to_json};
use aitm_mcp::transport::LoopbackTcp;
use aitm_mcp::{ConnCtx, McpSchemaDerive, McpServer, StdSchemaDerive};
use aitm_plugins::AgentPlugin;
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
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
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
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
            Frontend::Operator => "operator",
            _ => "other",
        };
        Ok(Value::Str(label.into()))
    }
}

/// `demo.client`: reports the host's client label (`<none>` when unset), so a
/// test can prove the `initialize.clientInfo.name` capture reaches `CommandHost`.
struct ClientLabelCmd;

impl Command for ClientLabelCmd {
    fn name(&self) -> &str {
        "demo.client"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Names the connection's client label.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str(host.client_label().unwrap_or("<none>").into()))
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

/// The ungated policy. Tests that predate the M4 Task 4 policy gate (transport,
/// coercion, roles) drive stub commands that declare a `Read`/`Write` tier (not
/// the fail-closed `Sensitive` default), so any non-restrictive policy runs them;
/// `All` is used here. The policy gate itself is tested with the `Sensitive`
/// `TierCmd`/`GatedCmd` and an explicit `AgentState` in the Task 4 section.
fn ungated() -> Arc<AgentState> {
    Arc::new(AgentState::new(AgentPolicy::All))
}

/// A stdio-configured server with services attached (the transport is unused
/// when driving `handle` in-process).
fn server_with(store: Arc<MemFlowStore>) -> McpServer {
    McpServer::new(registry(), McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
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
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "confirmable": false
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
    let srv = McpServer::new(registry(), McpTransport::Stdio).with_agent_state(ungated());
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
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
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
        ConnCtx::agent(),
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
    let listener = LoopbackTcp::bind(0, "s3cret".into())
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

// ----------------------------------------------------- M4 Task 3: conn role

/// A registry exposing the two role/label reporter stubs.
fn role_registry() -> Arc<Registry> {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(FrontendCmd));
    reg.add_command(Arc::new(ClientLabelCmd));
    Arc::new(reg)
}

/// A loopback-TCP server over `role_registry`, agent token `agent`, operator
/// token `op`, bound on a free port; returns the bound address.
async fn serve_role_server() -> SocketAddr {
    let srv = McpServer::new(
        role_registry(),
        McpTransport::LoopbackTcp {
            port: 0,
            token: "agent".into(),
        },
    )
    .with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
    .with_agent_state(ungated())
    .with_mcp_roles(Some("op".into()), Frontend::Mcp);
    let (tx, rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    tokio::spawn(
        srv.on_bound(move |addr| {
            let _ = tx.send(addr);
        })
        .serve(),
    );
    rx.await.expect("serve reports its bound address")
}

/// Open a connection, send `first_line` (the auth preamble) then `calls`, and
/// return the first reply line parsed as JSON.
async fn first_reply(addr: SocketAddr, lines_in: &str) -> JsonValue {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(lines_in.as_bytes()).await.expect("write");
    let (r, _w) = s.split();
    let mut lines = BufReader::new(r).lines();
    serde_json::from_str(&lines.next_line().await.expect("io").expect("a reply line"))
        .expect("json")
}

/// AC-M4-1: the operator token sets `Frontend::Operator`.
#[tokio::test]
async fn operator_token_sets_operator_role() {
    let addr = serve_role_server().await;
    let reply = first_reply(
        addr,
        "{\"token\":\"op\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n",
    )
    .await;
    assert_eq!(reply["result"]["structuredContent"], json!("operator"));
}

/// AC-M4-1: the agent token sets `Frontend::Mcp`.
#[tokio::test]
async fn agent_token_sets_agent_role() {
    let addr = serve_role_server().await;
    let reply = first_reply(
        addr,
        "{\"token\":\"agent\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n",
    )
    .await;
    assert_eq!(reply["result"]["structuredContent"], json!("mcp"));
}

/// AC-M4-1: an unknown token is refused `-32001`, no role assigned.
#[tokio::test]
async fn unknown_token_refused() {
    let addr = serve_role_server().await;
    let reply = first_reply(
        addr,
        "{\"token\":\"bogus\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n",
    )
    .await;
    assert_eq!(reply["error"]["code"], json!(-32001));
    assert_eq!(reply["error"]["message"], json!("unauthorized"));
}

/// AC-M4-1: stdio defaults to the agent role, threaded through `serve_lines`.
#[tokio::test]
async fn stdio_default_role_is_agent() {
    let srv = Arc::new(
        McpServer::new(role_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            ),
    );
    assert_eq!(srv.stdio_role(), Frontend::Mcp);

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (srv_r, srv_w) = tokio::io::split(server_side);
    let conn = ConnCtx::new(srv.stdio_role());
    let task = tokio::spawn(aitm_mcp::transport::serve_lines(
        srv,
        BufReader::new(srv_r),
        srv_w,
        conn,
    ));

    let (cli_r, mut cli_w) = tokio::io::split(client_side);
    let mut lines = BufReader::new(cli_r).lines();
    cli_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n")
        .await
        .expect("write");
    let reply: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("line")).expect("json");
    assert_eq!(reply["result"]["structuredContent"], json!("mcp"));
    cli_w.shutdown().await.expect("shutdown");
    task.await.expect("join").expect("loop ends cleanly at EOF");
}

/// The `initialize.clientInfo.name` is captured onto the connection and reaches
/// `CommandHost::client_label` for subsequent calls (unset before any call).
#[tokio::test]
async fn client_label_captured_from_initialize() {
    let addr = serve_role_server().await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(
        b"{\"token\":\"op\"}\n\
          {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"aitm-mac\",\"version\":\"0\"}}}\n\
          {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.client\",\"arguments\":{}}}\n",
    )
    .await
    .expect("write");
    let (r, _w) = s.split();
    let mut lines = BufReader::new(r).lines();
    let init: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("init reply"))
            .expect("json");
    assert_eq!(init["id"], json!(1));
    let call: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("call reply"))
            .expect("json");
    assert_eq!(call["id"], json!(2));
    assert_eq!(call["result"]["structuredContent"], json!("aitm-mac"));
}

// ------------------------------------------------- M4 Task 4: policy gate

/// A no-op command of a declared [`Sensitivity`], so the policy matrix can be
/// exercised tier by tier. Returns `"ran"` when the gate lets it through.
struct TierCmd {
    name: &'static str,
    sens: Sensitivity,
}

impl Command for TierCmd {
    fn name(&self) -> &str {
        self.name
    }
    fn sensitivity(&self) -> Sensitivity {
        self.sens
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "stub".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ran".into()))
    }
}

/// A Sensitive stub that self-governs on its own config gate, mirroring the real
/// `ca.install`/`scope.add`: it refuses an agent (non-CLI) frontend unless the
/// gate is on, exactly as `scope.rs`/`commands.rs` do. So a test can prove the
/// `All` policy defers a config-gated Sensitive command *to the command* (gate
/// off → refused, on → runs) instead of pre-empting it, while `Auto` refuses it
/// outright before `invoke` ever runs.
struct GatedCmd {
    name: &'static str,
    gate: fn(&Config) -> bool,
}

impl Command for GatedCmd {
    fn name(&self) -> &str {
        self.name
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "gated stub".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let gate_on = host.config().is_some_and(self.gate);
        if host.frontend() != Frontend::Cli && !gate_on {
            anyhow::bail!("`{}` refused: its config gate is off", self.name);
        }
        Ok(Value::Str("ran".into()))
    }
}

/// A server whose registry carries one command per tier, two config-gated
/// Sensitive stubs named after the real config-gated commands (`ca.install` →
/// `ca.allow_agent_install`, `scope.add` → `scope.allow_agent_widen`), and the
/// real `AgentPlugin` (so `agent.status`/`agent.set` are exercised end to end).
/// `state` is shared with the server's policy gate; `config` feeds the
/// per-command config gates that the `All` policy defers Sensitive commands to.
fn policy_server(state: Arc<AgentState>, config: Option<Arc<Config>>) -> McpServer {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(TierCmd {
        name: "demo.read",
        sens: Sensitivity::Read,
    }));
    reg.add_command(Arc::new(TierCmd {
        name: "demo.write",
        sens: Sensitivity::Write,
    }));
    reg.add_command(Arc::new(TierCmd {
        name: "demo.sensitive",
        sens: Sensitivity::Sensitive,
    }));
    reg.add_command(Arc::new(GatedCmd {
        name: "ca.install",
        gate: |c| c.ca.allow_agent_install,
    }));
    reg.add_command(Arc::new(GatedCmd {
        name: "scope.add",
        gate: |c| c.scope.allow_agent_widen,
    }));
    reg.add_plugin(Box::new(AgentPlugin::new(state.clone())));
    let mut srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state);
    if let Some(cfg) = config {
        srv = srv.with_config(cfg);
    }
    srv
}

/// Call `name` with no arguments on a connection of `role`; parse the reply.
fn call_as(srv: &McpServer, role: Frontend, name: &str) -> JsonValue {
    call_as_args(srv, role, name, json!({}))
}

/// Call `name` with `args` on a connection of `role`; parse the reply.
fn call_as_args(srv: &McpServer, role: Frontend, name: &str, args: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    let resp = srv
        .handle_on(&ConnCtx::new(role), &req.to_string())
        .expect("a request gets a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

/// Whether a `tools/call` reply is a tool error (a policy refusal, or any other
/// command error).
fn is_refused(resp: &JsonValue) -> bool {
    resp["result"]["isError"] == json!(true)
}

/// AC-M4-4: the five-mode policy matrix, enforced for the agent role, over a
/// Read / Write / Sensitive (no config gate) command. Expected `[read, write,
/// sensitive]` run-outcomes per the spec D2 table. `demo.sensitive` carries no
/// config gate, so every policy refuses it: `Auto`/`Ask` never run Sensitive, and
/// `All` only defers *config-gated* Sensitive commands to their own gate — a
/// gateless one is refused outright (proven on/off in `all_sensitive_honors_config_gate`).
#[test]
fn policy_matrix_for_agent() {
    let cases = [
        (AgentPolicy::Paused, [false, false, false]),
        (AgentPolicy::ReadOnly, [true, false, false]),
        // `Auto` is autonomous: Read+Write run, Sensitive is always refused.
        (AgentPolicy::Auto, [true, true, false]),
        // `Ask` allows Read+Write; a Sensitive call is parked for operator
        // approval (Task 9) and until then refused, so it does not run here.
        (AgentPolicy::Ask, [true, true, false]),
        // `All` allows Read+Write; a Sensitive command runs only if it has its own
        // config gate — `demo.sensitive` has none, so it is refused.
        (AgentPolicy::All, [true, true, false]),
    ];
    for (policy, [read, write, sensitive]) in cases {
        let srv = policy_server(Arc::new(AgentState::new(policy)), None);
        let ran = |name: &str| !is_refused(&call_as(&srv, Frontend::Mcp, name));
        assert_eq!(ran("demo.read"), read, "read under {policy:?}");
        assert_eq!(ran("demo.write"), write, "write under {policy:?}");
        assert_eq!(
            ran("demo.sensitive"),
            sensitive,
            "sensitive under {policy:?}"
        );
    }
}

/// AC-M4-4: an operator (and the CLI) connection is never policy-gated — even a
/// Write under `Paused` runs, where the agent is refused outright.
#[test]
fn operator_bypasses_policy() {
    let srv = policy_server(Arc::new(AgentState::new(AgentPolicy::Paused)), None);
    assert!(
        is_refused(&call_as(&srv, Frontend::Mcp, "demo.write")),
        "agent Write refused under Paused"
    );
    assert!(
        !is_refused(&call_as(&srv, Frontend::Operator, "demo.write")),
        "operator Write runs under Paused"
    );
    assert!(
        !is_refused(&call_as(&srv, Frontend::Cli, "demo.write")),
        "CLI Write runs under Paused"
    );
}

/// Review Focus #2: the agent cannot change its own policy. Even under `All`
/// (where the policy gate would not block a Sensitive call), `agent.set` is
/// refused for the agent role and the policy is unchanged; an operator may set it.
#[test]
fn agent_cannot_set_policy() {
    let state = Arc::new(AgentState::new(AgentPolicy::All));
    let srv = policy_server(state.clone(), None);

    let agent = call_as_args(
        &srv,
        Frontend::Mcp,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert!(is_refused(&agent), "agent agent.set is refused");
    assert_eq!(
        state.policy(),
        AgentPolicy::All,
        "policy unchanged by the agent"
    );

    let op = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert!(!is_refused(&op), "operator agent.set runs");
    assert_eq!(op["result"]["structuredContent"]["policy"], json!("paused"));
    assert_eq!(
        state.policy(),
        AgentPolicy::Paused,
        "operator set takes effect"
    );
}

/// AC-M4-5: `agent.status` is Read and readable by every role, reporting the
/// current policy.
#[test]
fn agent_status_readable_by_any_role() {
    let srv = policy_server(Arc::new(AgentState::new(AgentPolicy::Auto)), None);
    for role in [Frontend::Mcp, Frontend::Operator, Frontend::Cli] {
        let resp = call_as(&srv, role, "agent.status");
        assert!(!is_refused(&resp), "agent.status refused for {role:?}");
        assert_eq!(
            resp["result"]["structuredContent"]["policy"],
            json!("auto"),
            "policy reported to {role:?}"
        );
    }
}

/// A config with both agent capability gates turned on, so a test can prove the
/// *policy* refuses Sensitive under `Auto` even when the command's own gate would
/// permit it — the two dimensions (spec D2) are independent.
fn config_gates_on() -> Arc<Config> {
    let mut cfg = Config::default();
    cfg.ca.allow_agent_install = true;
    cfg.scope.allow_agent_widen = true;
    Arc::new(cfg)
}

/// AC-M4-4 / spec D2: `Auto` is autonomous with *zero* Sensitive actions — it
/// refuses every Sensitive command for the agent, config-gated or not, and does
/// so **before** the command runs. Even with `ca.allow_agent_install` /
/// `scope.allow_agent_widen` on (the command's own gate would permit it), the
/// policy refuses: the policy dimension and the config gate are independent, and
/// `Auto` never permits the policy dimension. (Operators are never policy-gated.)
#[test]
fn auto_refuses_all_sensitive() {
    let srv = policy_server(
        Arc::new(AgentState::new(AgentPolicy::Auto)),
        Some(config_gates_on()),
    );
    for name in ["ca.install", "scope.add", "demo.sensitive"] {
        assert!(
            is_refused(&call_as(&srv, Frontend::Mcp, name)),
            "`{name}` must be refused under Auto even with its config gate on"
        );
    }
}

/// AC-M4-4 / spec D2: under `All` the policy permits the Sensitive dimension and
/// *defers a config-gated command to its own gate* — it runs iff that gate is on.
/// Proven both ways with the same command: gate off → refused, gate on → runs.
/// A gateless Sensitive command (`demo.sensitive`) is refused regardless, since it
/// carries no gate for `All` to defer to.
#[test]
fn all_sensitive_honors_config_gate() {
    let gate_off = policy_server(
        Arc::new(AgentState::new(AgentPolicy::All)),
        Some(Arc::new(Config::default())),
    );
    assert!(
        is_refused(&call_as(&gate_off, Frontend::Mcp, "ca.install")),
        "All + ca.install with ca.allow_agent_install off must be refused by the command gate"
    );
    assert!(
        is_refused(&call_as(&gate_off, Frontend::Mcp, "demo.sensitive")),
        "All refuses a Sensitive command that has no config gate to defer to"
    );

    let gate_on = policy_server(
        Arc::new(AgentState::new(AgentPolicy::All)),
        Some(config_gates_on()),
    );
    assert!(
        !is_refused(&call_as(&gate_on, Frontend::Mcp, "ca.install")),
        "All + ca.install with ca.allow_agent_install on must run"
    );
    assert!(
        !is_refused(&call_as(&gate_on, Frontend::Mcp, "scope.add")),
        "All + scope.add with scope.allow_agent_widen on must run"
    );
}

// ------------------------------------------------ M4 Task 7: F4 server push

use aitm_core::Event;
use aitm_mcp::NotificationSink;
use aitm_plugins::SubscriptionPlugin;
use std::time::Duration;
use tokio::io::{duplex, split, DuplexStream, Lines, ReadHalf, WriteHalf};
use tokio::sync::broadcast;

/// A registry carrying the subscription commands (so `tools/list` shows them).
fn push_registry() -> Arc<Registry> {
    let (tx, _rx) = broadcast::channel::<Event>(64);
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(SubscriptionPlugin::new(tx)));
    reg.add_command(Arc::new(CaptureCmd));
    Arc::new(reg)
}

/// A server with the subscription commands registered, services over `store`, an
/// ungated policy, and a small per-connection push `capacity` so overflow is
/// cheap to force.
fn push_server(store: Arc<MemFlowStore>, capacity: usize) -> Arc<McpServer> {
    Arc::new(
        McpServer::new(push_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_push_capacity(capacity)
            .with_services(
                store,
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            ),
    )
}

type ClientReader = Lines<BufReader<ReadHalf<DuplexStream>>>;

/// Open a streaming connection to `srv` over an in-memory duplex of `buf` bytes.
/// The connection's push sink is injected (so the test can observe its bound
/// state) with `capacity`. Returns the client write half, a line reader over the
/// client read half, the injected sink, and the server task.
fn open_push_conn(
    srv: Arc<McpServer>,
    role: Frontend,
    buf: usize,
    capacity: usize,
) -> (
    WriteHalf<DuplexStream>,
    ClientReader,
    NotificationSink,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (client, server_side) = duplex(buf);
    let (s_r, s_w) = split(server_side);
    let sink = NotificationSink::new(capacity);
    let mut conn = ConnCtx::new(role);
    conn.out = Some(sink.clone());
    let task = tokio::spawn(aitm_mcp::transport::serve_lines(
        srv,
        BufReader::new(s_r),
        s_w,
        conn,
    ));
    let (c_r, c_w) = split(client);
    (c_w, BufReader::new(c_r).lines(), sink, task)
}

async fn write_req(w: &mut WriteHalf<DuplexStream>, req: &JsonValue) {
    let mut line = req.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).await.expect("write");
    w.flush().await.expect("flush");
}

async fn next_json(lines: &mut ClientReader) -> JsonValue {
    let line = lines
        .next_line()
        .await
        .expect("io")
        .expect("a line was expected");
    serde_json::from_str(&line).expect("json line")
}

/// The bounded sink drops the oldest notification on overflow and flags the lag;
/// a drain surfaces the lag marker and clears it (RF#1, unit level).
#[test]
fn notification_sink_drops_oldest_and_flags_lag() {
    let sink = NotificationSink::new(2);
    sink.push("a".into());
    sink.push("b".into());
    assert_eq!(sink.queued_len(), 2);
    assert!(!sink.lagged());

    sink.push("c".into()); // over capacity: oldest ("a") is dropped, lag set
    assert_eq!(
        sink.queued_len(),
        2,
        "the sink never grows past its capacity"
    );
    assert!(sink.lagged());

    let drained = sink.drain();
    assert!(
        drained
            .iter()
            .any(|l| l.contains("notifications/aitm/state") && l.contains("\"lagged\":true")),
        "the drain carries a lagged state marker: {drained:?}"
    );
    assert!(drained.iter().any(|l| l == "b"));
    assert!(drained.iter().any(|l| l == "c"));
    assert!(!drained.iter().any(|l| l == "a"), "oldest was dropped");
    assert!(!sink.lagged(), "lag flag cleared after it is surfaced");
    assert_eq!(sink.queued_len(), 0);
}

/// Replies are never dropped, even when the notification lane has overflowed.
#[test]
fn notification_sink_never_drops_replies() {
    let sink = NotificationSink::new(1);
    sink.push_reply("r1".into());
    sink.push("n1".into());
    sink.push("n2".into()); // drops n1
    sink.push_reply("r2".into());
    let drained = sink.drain();
    assert!(drained.iter().any(|l| l == "r1"));
    assert!(drained.iter().any(|l| l == "r2"));
    assert!(drained.iter().any(|l| l == "n2"));
    assert!(!drained.iter().any(|l| l == "n1"));
}

/// After `flow.subscribe`, a new flow through the proxy produces a
/// `notifications/aitm/flow {event:"created"}` line on that connection with no
/// further request (AC-M4-6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_pushes_created_on_new_flow() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 1024);
    let (mut w, mut lines, _sink, task) =
        open_push_conn(srv.clone(), Frontend::Operator, 64 * 1024, 1024);

    write_req(
        &mut w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let reply = next_json(&mut lines).await;
    assert_eq!(reply["id"], 1);
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "subscribe returns a sub_id: {reply}"
    );

    // A new flow arrives through the proxy (the chain dispatches RequestHeaders).
    let id = store.insert(http_flow("example.com:443", "/a"));
    srv.push_flow_event(&Event::RequestHeaders(id));

    let note = next_json(&mut lines).await;
    assert_eq!(note["method"], "notifications/aitm/flow");
    assert_eq!(note["params"]["event"], "created");
    assert_eq!(note["params"]["id"], id.to_string());
    assert_eq!(note["params"]["summary"]["authority"], "example.com:443");

    // Shutting down the client's write side is EOF for the server's reader, so
    // the read loop ends and the writer task drains and exits.
    let _ = w.shutdown().await;
    let _ = task.await;
}

/// `flow.unsubscribe` stops the push (AC-M4-6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsubscribe_stops_push() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 1024);
    let (mut w, mut lines, _sink, task) =
        open_push_conn(srv.clone(), Frontend::Operator, 64 * 1024, 1024);

    write_req(
        &mut w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let reply = next_json(&mut lines).await;
    let sub_id = reply["result"]["structuredContent"]["sub_id"]
        .as_u64()
        .expect("sub_id");

    write_req(
        &mut w,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"flow.unsubscribe","arguments":{"sub_id":sub_id}}}),
    )
    .await;
    let reply = next_json(&mut lines).await;
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["result"]["isError"], false);

    // A flow after unsubscribe produces no push.
    let id = store.insert(http_flow("example.com:443", "/b"));
    srv.push_flow_event(&Event::RequestHeaders(id));
    let quiet = tokio::time::timeout(Duration::from_millis(250), lines.next_line()).await;
    assert!(
        quiet.is_err(),
        "no notification should arrive after unsubscribe"
    );

    // Shutting down the client's write side is EOF for the server's reader, so
    // the read loop ends and the writer task drains and exits.
    let _ = w.shutdown().await;
    let _ = task.await;
}

/// The `state` stream emits on change (AC-M4-6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_pushed_on_change() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 1024);
    let (mut w, mut lines, _sink, task) =
        open_push_conn(srv.clone(), Frontend::Operator, 64 * 1024, 1024);

    write_req(
        &mut w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let _ = next_json(&mut lines).await;

    srv.push_state(json!({"intercept_armed": true, "agent": "auto"}));

    let note = next_json(&mut lines).await;
    assert_eq!(note["method"], "notifications/aitm/state");
    assert_eq!(note["params"]["intercept_armed"], true);
    assert_eq!(note["params"]["agent"], "auto");

    // Shutting down the client's write side is EOF for the server's reader, so
    // the read loop ends and the writer task drains and exits.
    let _ = w.shutdown().await;
    let _ = task.await;
}

/// RF#1 (pinned): a subscriber that stops reading has its sink bounded (drop
/// oldest + a `lagged` marker) and never blocks the proxy or a second
/// subscriber's flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_subscriber_lags_not_blocks() {
    const CAP: usize = 4;
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), CAP);

    // A: a slow subscriber over a tiny duplex that it stops reading.
    let (mut a_w, mut a_lines, a_sink, a_task) =
        open_push_conn(srv.clone(), Frontend::Operator, 256, CAP);
    write_req(
        &mut a_w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let _ = next_json(&mut a_lines).await; // A reads its subscribe reply, then stops.

    // B: a healthy subscriber that keeps reading.
    let (mut b_w, mut b_lines, _b_sink, b_task) =
        open_push_conn(srv.clone(), Frontend::Operator, 64 * 1024, 1024);
    write_req(
        &mut b_w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let _ = next_json(&mut b_lines).await;

    // Drive many flows. `push_flow_event` must never block on A's stalled socket.
    for i in 0..(CAP * 50) {
        let id = store.insert(http_flow("example.com:443", &format!("/{i}")));
        srv.push_flow_event(&Event::RequestHeaders(id));
    }

    // A's sink is bounded and flagged lagged (give the blocked writer a moment).
    assert!(
        a_sink.queued_len() <= CAP,
        "a stalled subscriber's sink never grows past its capacity: {}",
        a_sink.queued_len()
    );
    let mut lagged = false;
    for _ in 0..50 {
        if a_sink.lagged() {
            lagged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(lagged, "the stalled subscriber is flagged lagged");

    // B's flows still flow despite A being stuck.
    let note = next_json(&mut b_lines).await;
    assert_eq!(note["method"], "notifications/aitm/flow");
    assert_eq!(note["params"]["event"], "created");

    // Teardown: drop A fully (both halves) so its blocked writer sees a closed
    // socket and exits; A's writer is parked on the stalled duplex, so merely
    // closing the read direction would leave it hanging.
    drop(a_w);
    drop(a_lines);
    drop(b_w);
    drop(b_lines);
    a_task.abort();
    b_task.abort();
    let _ = a_task.await;
    let _ = b_task.await;
}

// ------------------------------------------ M4 Task 5: confirm-over-the-wire

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

/// A confirmable command: `confirm_prompt` always returns `Some`, and each run
/// bumps a shared counter so a test can tell "ran" from "refused" / "asked".
struct ConfirmStub {
    ran: Arc<AtomicUsize>,
}

impl Command for ConfirmStub {
    fn name(&self) -> &str {
        "demo.confirm"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "A confirmable stub.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        self.ran.fetch_add(1, AtomicOrdering::SeqCst);
        Ok(Value::Str("ran".into()))
    }
    fn confirm_prompt(&self, _args: &Params) -> Option<String> {
        Some("Really do the thing?".into())
    }
}

/// A Sensitive, confirmable, config-gated stub named like the real `ca.install`,
/// so the `All` policy defers it to its own gate (via `defers_to_command_gate`)
/// exactly as the real command — letting a test prove the agent is offered no
/// handshake even though the command is confirmable.
struct GatedConfirmStub {
    ran: Arc<AtomicUsize>,
    gate: fn(&Config) -> bool,
}

impl Command for GatedConfirmStub {
    fn name(&self) -> &str {
        "ca.install"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "A gated, confirmable stub.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let gate_on = host.config().is_some_and(self.gate);
        if host.frontend() != Frontend::Cli && !gate_on {
            anyhow::bail!("`ca.install` refused: its config gate is off");
        }
        self.ran.fetch_add(1, AtomicOrdering::SeqCst);
        Ok(Value::Str("ran".into()))
    }
    fn confirm_prompt(&self, _args: &Params) -> Option<String> {
        Some("Install the CA into the OS trust store?".into())
    }
}

/// A stdio server over `reg` with services and an ungated (`All`) policy, so the
/// agent role reaches a command's own config gate and the operator role is never
/// policy-blocked. `confirm_ttl` overrides the default (short, for the expiry test).
fn confirm_server(
    reg: Arc<Registry>,
    config: Option<Arc<Config>>,
    confirm_ttl: Option<Duration>,
) -> McpServer {
    let mut srv = McpServer::new(reg, McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        );
    if let Some(cfg) = config {
        srv = srv.with_config(cfg);
    }
    if let Some(ttl) = confirm_ttl {
        srv = srv.with_confirm_ttl(ttl);
    }
    srv
}

/// AC-M4-8: `tools/list` marks a confirmable command `confirmable:true` and a
/// plain one `false`.
#[test]
fn tools_list_marks_confirmable() {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConfirmStub {
        ran: Arc::new(AtomicUsize::new(0)),
    }));
    reg.add_command(Arc::new(PingCmd));
    let srv = confirm_server(Arc::new(reg), None, None);

    let resp = rpc(&srv, 1, "tools/list", json!({}));
    let tools = resp["result"]["tools"].as_array().expect("tools");
    let confirm = tools
        .iter()
        .find(|t| t["name"] == "demo.confirm")
        .expect("demo.confirm listed");
    assert_eq!(confirm["confirmable"], json!(true));
    let ping = tools
        .iter()
        .find(|t| t["name"] == "demo.ping")
        .expect("demo.ping listed");
    assert_eq!(ping["confirmable"], json!(false));
}

/// AC-M4-7: an operator call to a confirm-gated command returns `needs_confirmation`
/// with a prompt + token and does not run; re-sending with the token runs it.
#[test]
fn operator_confirm_handshake() {
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConfirmStub { ran: ran.clone() }));
    let srv = confirm_server(Arc::new(reg), None, None);

    let asked = call_as_args(&srv, Frontend::Operator, "demo.confirm", json!({}));
    assert_eq!(asked["result"]["isError"], json!(false));
    assert_eq!(
        asked["result"]["structuredContent"]["status"],
        json!("needs_confirmation")
    );
    let prompt = asked["result"]["structuredContent"]["prompt"]
        .as_str()
        .expect("prompt");
    assert!(prompt.contains("Really"), "{prompt}");
    let token = asked["result"]["structuredContent"]["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();
    assert_eq!(
        ran.load(AtomicOrdering::SeqCst),
        0,
        "the command must not run before confirmation"
    );

    let done = call_as_args(
        &srv,
        Frontend::Operator,
        "demo.confirm",
        json!({ "_confirm": token }),
    );
    assert_eq!(done["result"]["isError"], json!(false));
    assert_eq!(done["result"]["structuredContent"], json!("ran"));
    assert_eq!(
        ran.load(AtomicOrdering::SeqCst),
        1,
        "the re-send with a valid token runs the command once"
    );
}

/// AC-M4-7: a wrong, replayed, or expired confirm token is refused and the
/// command does not run.
#[test]
fn confirm_token_wrong_or_expired_or_replayed_refused() {
    // Wrong token: refused, nothing runs.
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConfirmStub { ran: ran.clone() }));
    let srv = confirm_server(Arc::new(reg), None, None);
    let wrong = call_as_args(
        &srv,
        Frontend::Operator,
        "demo.confirm",
        json!({"_confirm": "cfm_deadbeefdeadbeef"}),
    );
    assert!(is_refused(&wrong), "a wrong token is refused: {wrong}");
    assert_eq!(ran.load(AtomicOrdering::SeqCst), 0);

    // Replayed token: valid once, refused on the second use (single-use).
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConfirmStub { ran: ran.clone() }));
    let srv = confirm_server(Arc::new(reg), None, None);
    let asked = call_as_args(&srv, Frontend::Operator, "demo.confirm", json!({}));
    let token = asked["result"]["structuredContent"]["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();
    let first = call_as_args(
        &srv,
        Frontend::Operator,
        "demo.confirm",
        json!({ "_confirm": token.clone() }),
    );
    assert!(!is_refused(&first), "the first use runs");
    let replay = call_as_args(
        &srv,
        Frontend::Operator,
        "demo.confirm",
        json!({ "_confirm": token }),
    );
    assert!(is_refused(&replay), "a replayed token is refused: {replay}");
    assert_eq!(
        ran.load(AtomicOrdering::SeqCst),
        1,
        "the command ran exactly once"
    );

    // Expired token: a short TTL, then a re-send after it lapses, refused.
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConfirmStub { ran: ran.clone() }));
    let srv = confirm_server(Arc::new(reg), None, Some(Duration::from_millis(20)));
    let asked = call_as_args(&srv, Frontend::Operator, "demo.confirm", json!({}));
    let token = asked["result"]["structuredContent"]["confirm_token"]
        .as_str()
        .expect("confirm_token")
        .to_string();
    std::thread::sleep(Duration::from_millis(60));
    let expired = call_as_args(
        &srv,
        Frontend::Operator,
        "demo.confirm",
        json!({ "_confirm": token }),
    );
    assert!(
        is_refused(&expired),
        "an expired token is refused: {expired}"
    );
    assert_eq!(ran.load(AtomicOrdering::SeqCst), 0);
}

/// Review Focus #2 / AC-M4-8: the agent is never offered the confirm handshake.
/// A confirm-gated command stays governed by its config gate: refused with the
/// gate off (no `needs_confirmation`), run with it on — still no handshake.
#[test]
fn agent_gets_no_confirm_handshake() {
    // Gate off → refused outright, no handshake offered.
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(GatedConfirmStub {
        ran: ran.clone(),
        gate: |c| c.ca.allow_agent_install,
    }));
    let srv = confirm_server(Arc::new(reg), Some(Arc::new(Config::default())), None);
    let off = call_as(&srv, Frontend::Mcp, "ca.install");
    assert!(
        is_refused(&off),
        "agent ca.install with the gate off is refused"
    );
    assert_ne!(
        off["result"]["structuredContent"]["status"],
        json!("needs_confirmation"),
        "no handshake is offered to the agent"
    );
    assert_eq!(ran.load(AtomicOrdering::SeqCst), 0);

    // Gate on → runs via its own config gate, still no handshake.
    let ran = Arc::new(AtomicUsize::new(0));
    let mut reg = Registry::new();
    reg.add_command(Arc::new(GatedConfirmStub {
        ran: ran.clone(),
        gate: |c| c.ca.allow_agent_install,
    }));
    let srv = confirm_server(Arc::new(reg), Some(config_gates_on()), None);
    let on = call_as(&srv, Frontend::Mcp, "ca.install");
    assert!(
        !is_refused(&on),
        "agent ca.install with the gate on runs: {on}"
    );
    assert_eq!(on["result"]["structuredContent"], json!("ran"));
    assert_eq!(ran.load(AtomicOrdering::SeqCst), 1);
}

// ----------------------------------------- M4 Task 6: result rendering (D3b)

use aitm_plugins::{MutatePlugin, ReplayPlugin, ScopePlugin};

/// Build a typed argument bag from `(name, value)` pairs.
fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    )
}

/// A `poc.run`-shaped result value (verdict + the three artifacts + evaluated).
fn poc_shaped_value() -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("passed".to_string(), Value::Bool(true));
    obj.insert(
        "finding_capture".to_string(),
        Value::Str("cap-1".to_string()),
    );
    obj.insert(
        "poc_path".to_string(),
        Value::Str("/x/poc.yaml".to_string()),
    );
    obj.insert(
        "screenshot_path".to_string(),
        Value::Str("/x/shot.png".to_string()),
    );
    let mut ev = BTreeMap::new();
    ev.insert(
        "assertion".to_string(),
        Value::Str("status == 200".to_string()),
    );
    ev.insert("matched".to_string(), Value::Bool(true));
    obj.insert(
        "evaluated".to_string(),
        Value::Array(vec![Value::Object(ev)]),
    );
    Value::Object(obj)
}

/// A command that returns a `poc.run`-shaped result and a one-line summary, so the
/// render path (summary + pretty JSON; `structuredContent` unchanged) can be
/// asserted without running a real PoC.
struct PocShapedCmd;

impl Command for PocShapedCmd {
    fn name(&self) -> &str {
        "demo.poc"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Returns a poc.run-shaped result.".into(),
            params: vec![],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(poc_shaped_value())
    }
    fn summarize(&self, _args: &Params, _result: &Value) -> Option<String> {
        Some("PoC passed — 3 artifacts".into())
    }
}

/// AC-M4-8b: a success result's `content` text is the summary line followed by
/// pretty, indented JSON, while `structuredContent` is the exact machine value.
#[test]
fn content_is_formatted_summary_plus_pretty() {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(PocShapedCmd));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        );

    let resp = rpc(
        &srv,
        1,
        "tools/call",
        json!({"name": "demo.poc", "arguments": {}}),
    );
    assert_eq!(resp["result"]["isError"], json!(false));

    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("content text");
    // Starts with the summary line.
    assert!(
        text.starts_with("PoC passed — 3 artifacts\n"),
        "content must open with the summary line: {text}"
    );
    // Contains indented (pretty) JSON, not a jammed one-liner.
    assert!(
        text.contains("\n  \""),
        "content must contain indented JSON: {text}"
    );
    assert!(
        text.contains("\"passed\": true"),
        "pretty JSON names the verdict: {text}"
    );

    // `structuredContent` is the exact machine value, byte-for-byte (the raw
    // value, not the rendered text).
    assert_eq!(
        resp["result"]["structuredContent"],
        json!({
            "passed": true,
            "finding_capture": "cap-1",
            "poc_path": "/x/poc.yaml",
            "screenshot_path": "/x/shot.png",
            "evaluated": [{"assertion": "status == 200", "matched": true}],
        })
    );
    // And it is distinct from the rendered content text.
    assert_ne!(
        resp["result"]["structuredContent"].to_string(),
        text,
        "the structured value and the rendered text differ"
    );
}

/// AC-M4-8b: the representative set (`flow.replay`, `request.send`, `scope.add`,
/// `poc.run`) each provide a real `summarize`, grounded in their result fields.
#[test]
fn summarize_present_for_representative_set() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ReplayPlugin::new()));
    reg.add_plugin(Box::new(MutatePlugin));
    reg.add_plugin(Box::new(ScopePlugin::new(true)));
    reg.add_command(Arc::new(aitm_poc::PocRunCommand));

    let src = aitm_core::FlowId::new().to_string();
    let new = aitm_core::FlowId::new().to_string();

    let replay = reg.command("flow.replay").expect("flow.replay registered");
    assert!(replay
        .summarize(
            &params(&[("id", Value::Str(src.clone()))]),
            &Value::Str(new.clone()),
        )
        .is_some());

    let send = reg
        .command("request.send")
        .expect("request.send registered");
    assert!(send
        .summarize(
            &params(&[("authority", Value::Str("api.example.com:443".into()))]),
            &Value::Str(new.clone()),
        )
        .is_some());

    let add = reg.command("scope.add").expect("scope.add registered");
    assert!(add
        .summarize(
            &params(&[("host", Value::Str("example.com".into()))]),
            &Value::Str("example.com".into()),
        )
        .is_some());

    let run = reg.command("poc.run").expect("poc.run registered");
    assert!(run
        .summarize(&Params::default(), &poc_shaped_value())
        .is_some());
}

// ------------------------------------------------- F2 audit ring (Task 8)

/// A Read command that accepts a `token` arg and a `headers` map, so a test can
/// drive secrets through the audit path and prove they are redacted. Echoes its
/// arguments so a careless implementation that logged the raw value would be
/// caught both in the result and (if unredacted) the audit entry.
struct SecretEchoCmd;

impl Command for SecretEchoCmd {
    fn name(&self) -> &str {
        "demo.secret"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Echo, accepting a token and headers.".into(),
            params: vec![
                ParamDef {
                    name: "token".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "headers".into(),
                    ty: TypeDesc::Map(Box::new(TypeDesc::Str)),
                    required: false,
                    description: String::new(),
                },
                ParamDef {
                    name: "note".into(),
                    ty: TypeDesc::Str,
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

/// A server whose registry carries a Read command (`demo.read`), a gateless
/// Sensitive command (`demo.sensitive`), the secret-echo command, and the real
/// `AgentPlugin` — all sharing `ring`, so `agent.activity` reads exactly what
/// `call_tool` appends. The policy is `Auto`, so Read runs and Sensitive is
/// refused (both are audited).
fn audit_server(ring: Arc<AuditRing>) -> McpServer {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(TierCmd {
        name: "demo.read",
        sens: Sensitivity::Read,
    }));
    reg.add_command(Arc::new(TierCmd {
        name: "demo.sensitive",
        sens: Sensitivity::Sensitive,
    }));
    reg.add_command(Arc::new(SecretEchoCmd));
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    reg.add_plugin(Box::new(
        AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
    ));
    McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state)
        .with_audit_ring(ring)
}

/// AC-M4-6b / spec D3a.1: every invocation is recorded after the gates — a
/// successful call and a policy-refused one each produce one entry, and the
/// refusal carries its reason as an error.
#[test]
fn every_invoke_is_audited_including_refusals() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());

    // A Read runs under Auto; a gateless Sensitive is refused under Auto.
    assert!(!is_refused(&call_as(&srv, Frontend::Mcp, "demo.read")));
    assert!(is_refused(&call_as(&srv, Frontend::Mcp, "demo.sensitive")));

    let entries = ring.recent(None, None);
    assert_eq!(
        entries.len(),
        2,
        "one entry per invocation, refusals included"
    );

    let ok = &entries[0];
    assert_eq!(ok.command, "demo.read");
    assert_eq!(ok.origin, Frontend::Mcp);
    assert_eq!(ok.result, aitm_core::AuditResult::Ok);

    let refused = &entries[1];
    assert_eq!(refused.command, "demo.sensitive");
    match &refused.result {
        aitm_core::AuditResult::Error(reason) => {
            assert!(reason.contains("auto"), "refusal reason carried: {reason}");
        }
        other => panic!("expected an error result, got {other:?}"),
    }
}

/// AC-M4-6b / Review Focus #3: an `Authorization` header and a token argument
/// must not appear in the audit entry or the pushed `agent` line. The redaction
/// is by key name, recursively, so a secret nested in `headers` is caught too.
#[test]
fn audit_redacts_secrets() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());

    // Subscribe a second connection so the pushed `agent` line can be inspected.
    let watcher = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(aitm_mcp::NotificationSink::new(64)),
    };
    let sub = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"flow.subscribe","arguments":{}}});
    srv.handle_on(&watcher, &sub.to_string())
        .expect("subscribe reply");

    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
    "name":"demo.secret",
    "arguments":{
        "token":"SECRET-TOKEN-123",
        "headers":{"Authorization":"Bearer SECRET-AUTH-XYZ"},
        "note":"keep-this"
    }}});
    srv.handle_on(&ConnCtx::new(Frontend::Mcp), &call.to_string())
        .expect("secret call reply");

    let entry = ring
        .recent(None, None)
        .into_iter()
        .find(|e| e.command == "demo.secret")
        .expect("the secret call was audited");
    assert!(
        !entry.args_summary.contains("SECRET-TOKEN-123"),
        "token value leaked into the audit entry: {}",
        entry.args_summary
    );
    assert!(
        !entry.args_summary.contains("SECRET-AUTH-XYZ"),
        "auth header leaked into the audit entry: {}",
        entry.args_summary
    );
    assert!(
        entry.args_summary.contains("keep-this"),
        "non-secret args should survive redaction: {}",
        entry.args_summary
    );

    // The pushed `notifications/aitm/agent` line must be redacted too.
    let pushed = watcher.out.as_ref().unwrap().drain().join("\n");
    assert!(
        pushed.contains("notifications/aitm/agent"),
        "agent line pushed"
    );
    assert!(
        !pushed.contains("SECRET-TOKEN-123"),
        "token leaked into push"
    );
    assert!(!pushed.contains("SECRET-AUTH-XYZ"), "auth leaked into push");
}

/// AC-M4-6b / spec D3a.4: `agent.activity` reads recent entries, honouring
/// `since` and `limit`.
#[test]
fn agent_activity_returns_recent() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());

    // Three invocations.
    call_as(&srv, Frontend::Mcp, "demo.read");
    call_as(&srv, Frontend::Mcp, "demo.read");
    call_as(&srv, Frontend::Mcp, "demo.read");

    // `limit` keeps the most recent N (plus the agent.activity call itself).
    let resp = call_as_args(&srv, Frontend::Mcp, "agent.activity", json!({"limit": 2}));
    let activity = &resp["result"]["structuredContent"];
    let list = activity.as_array().expect("activity is an array");
    assert_eq!(list.len(), 2, "limit honoured");

    // `since` in the future returns nothing.
    let future_ms = (std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let resp = call_as_args(
        &srv,
        Frontend::Mcp,
        "agent.activity",
        json!({"since": future_ms}),
    );
    let list = resp["result"]["structuredContent"]
        .as_array()
        .expect("activity is an array");
    assert!(list.is_empty(), "since in the future returns nothing");

    // `agent.activity` is readable by any role (Read, not policy-gated).
    assert!(!is_refused(&call_as(
        &srv,
        Frontend::Operator,
        "agent.activity"
    )));
}
