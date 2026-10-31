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
use aitm_mcp::server::{INVALID_PARAMS, PROTOCOL_VERSION};
use aitm_mcp::transport::LoopbackTcp;
use aitm_mcp::{ConnCtx, McpSchemaDerive, McpServer, StdSchemaDerive};
use aitm_plugins::AgentPlugin;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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

/// AC6 + Decision C: `initialize` echoes a top-level `role` of `"operator"` for
/// an operator connection (alongside `protocolVersion`, not inside `serverInfo`).
#[test]
fn initialize_echoes_operator_role() {
    let srv = server();
    let resp: JsonValue = serde_json::from_str(
        &srv.handle_on(
            &ConnCtx::new(Frontend::Operator),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .expect("initialize gets a reply"),
    )
    .expect("response is JSON");
    assert_eq!(resp["result"]["role"], json!("operator"));
    // It sits at the top level of the result, not inside `serverInfo`.
    assert!(resp["result"]["serverInfo"]["role"].is_null());
}

/// AC6 + Decision C: `initialize` echoes `role: "agent"` for an agent connection.
#[test]
fn initialize_echoes_agent_role() {
    let srv = server();
    let resp: JsonValue = serde_json::from_str(
        &srv.handle_on(
            &ConnCtx::agent(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .expect("initialize gets a reply"),
    )
    .expect("response is JSON");
    assert_eq!(resp["result"]["role"], json!("agent"));
}

/// Minor (a): `initialize` answers with the server's own `PROTOCOL_VERSION`,
/// not whatever version the client asked for.
#[test]
fn initialize_pins_the_server_protocol_version() {
    let srv = server();
    let resp = rpc(
        &srv,
        1,
        "initialize",
        json!({"protocolVersion": "1999-01-01"}),
    );
    assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_ne!(resp["result"]["protocolVersion"], "1999-01-01");
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

    // Wrong type, bad flow id, unknown argument, missing required: each is an
    // INVALID_PARAMS JSON-RPC error (the command never runs) naming the
    // parameter — the same envelope as a missing `name` or unknown tool.
    let bad_type = rpc(
        &srv,
        2,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": id, "limit": "five"}}),
    );
    assert_eq!(
        bad_type["error"]["code"],
        json!(INVALID_PARAMS),
        "{bad_type}"
    );
    let text = bad_type["error"]["message"].as_str().expect("message");
    assert!(text.contains("limit") && text.contains("integer"), "{text}");

    let bad_id = rpc(
        &srv,
        3,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": "not-a-uuid"}}),
    );
    assert_eq!(bad_id["error"]["code"], json!(INVALID_PARAMS), "{bad_id}");
    assert!(bad_id["error"]["message"]
        .as_str()
        .expect("message")
        .contains("id"));

    let unknown = rpc(
        &srv,
        4,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {"id": id, "bogus": 1}}),
    );
    assert_eq!(unknown["error"]["code"], json!(INVALID_PARAMS), "{unknown}");
    assert!(unknown["error"]["message"]
        .as_str()
        .expect("message")
        .contains("bogus"));

    let missing = rpc(
        &srv,
        5,
        "tools/call",
        json!({"name": "demo.echo", "arguments": {}}),
    );
    assert_eq!(missing["error"]["code"], json!(INVALID_PARAMS), "{missing}");
    let text = missing["error"]["message"].as_str().expect("message");
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
            endpoint_file: None,
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

/// Task 2 Review Focus: an empty-string `operator_token` is treated as *not
/// configured*. It must not enable operator, and an empty presented token must
/// match neither the agent token nor a (nonexistent) operator token, so it is
/// refused `-32001` and never resolves to operator. Guards the transport's
/// existing empty-token filter (`LoopbackTcp::with_operator_token`).
#[tokio::test]
async fn empty_operator_token_is_not_operator() {
    let srv = McpServer::new(
        role_registry(),
        McpTransport::LoopbackTcp {
            port: 0,
            token: "agent".into(),
            endpoint_file: None,
        },
    )
    .with_services(
        Arc::new(MemFlowStore::new()),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
    .with_agent_state(ungated())
    .with_mcp_roles(Some(String::new()), Frontend::Mcp);
    let (tx, rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    tokio::spawn(
        srv.on_bound(move |addr| {
            let _ = tx.send(addr);
        })
        .serve(),
    );
    let addr = rx.await.expect("serve reports its bound address");

    // An empty presented token matches neither token → refused, never operator.
    let refused = first_reply(
        addr,
        "{\"token\":\"\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n",
    )
    .await;
    assert_eq!(refused["error"]["code"], json!(-32001));
    assert_eq!(refused["error"]["message"], json!("unauthorized"));

    // The agent token still works and resolves to agent — an empty operator
    // token is simply ignored, not treated as a second match.
    let agent = first_reply(
        addr,
        "{\"token\":\"agent\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo.frontend\",\"arguments\":{}}}\n",
    )
    .await;
    assert_eq!(agent["result"]["structuredContent"], json!("mcp"));
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

/// AC11: the client label is cut at ingestion, in the real `serve_lines` loop, so
/// a 1 MiB `clientInfo.name` reaches the command host and the audit entry as
/// 64 characters (the bound of the label sanitiser, `MAX_CLIENT_LABEL_CHARS`).
/// Assertions are on lengths so a red run prints short numbers.
#[tokio::test]
async fn client_label_is_capped_at_ingestion() {
    let ring = Arc::new(AuditRing::default());
    let srv = Arc::new(
        McpServer::new(role_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_audit_ring(ring.clone()),
    );

    // The pipe holds the whole 1 MiB `initialize` line, so the client's write
    // never waits on the server's read.
    let (client_side, server_side) = tokio::io::duplex(4 * 1024 * 1024);
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
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "a".repeat(1 << 20), "version": "0"}}});
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "demo.client", "arguments": {}}});
    cli_w
        .write_all(format!("{init}\n{call}\n").as_bytes())
        .await
        .expect("write");

    let init_reply: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("init reply"))
            .expect("json");
    assert_eq!(init_reply["id"], json!(1));
    let call_reply: JsonValue =
        serde_json::from_str(&lines.next_line().await.expect("io").expect("call reply"))
            .expect("json");
    assert_eq!(call_reply["id"], json!(2));
    let seen = call_reply["result"]["structuredContent"]
        .as_str()
        .unwrap_or_else(|| panic!("demo.client returns a string: {call_reply}"));
    assert_eq!(seen.len(), 64, "the command host sees a capped label");
    assert_eq!(seen, "a".repeat(64));

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1, "one tools/call, one audit entry");
    assert_eq!(
        entries[0]
            .client_label
            .as_ref()
            .expect("the entry carries the label")
            .len(),
        64,
        "the audit entry carries the same capped label"
    );

    cli_w.shutdown().await.expect("shutdown");
    task.await.expect("join").expect("loop ends cleanly at EOF");
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
    // F8: a Sensitive authoring command with its own config gate that is
    // deliberately NOT in `defers_to_command_gate`, so `All` must still refuse it
    // (its gate is always on here, to prove the policy refuses before the gate is
    // even consulted). Mirrors `script.save`/`reload`/`enable`/`disable`.
    reg.add_command(Arc::new(GatedCmd {
        name: "script.save",
        gate: |_| true,
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

/// F8 AC8: agent script-authoring is supported under `Ask` (parked for operator
/// approval) and **refused under `All`**. `script.save` is `Sensitive` with its
/// own config gate, but it is deliberately NOT in `defers_to_command_gate`, so an
/// autonomous `All` agent cannot self-authorize it — even with its gate on — the
/// way `ca.install` can. A human must be in the loop (`Ask`). `Auto` refuses it;
/// an operator is never policy-gated. This locks the posture that an autonomous
/// agent cannot write executable, live-traffic-mutating Rhai hooks on a flag alone.
#[test]
fn f8_script_authoring_not_auto_authorized_under_all() {
    let cfg = config_gates_on(); // ca.install's gate is on, for the contrast below.

    let all = policy_server(
        Arc::new(AgentState::new(AgentPolicy::All)),
        Some(cfg.clone()),
    );
    assert!(
        is_refused(&call_as(&all, Frontend::Mcp, "script.save")),
        "All must refuse script.save (not in defers_to_command_gate), even with its gate on"
    );
    assert!(
        !is_refused(&call_as(&all, Frontend::Mcp, "ca.install")),
        "contrast: ca.install IS auto-authorizable under All with its gate on"
    );
    assert!(
        !is_refused(&call_as(&all, Frontend::Operator, "script.save")),
        "an operator is never policy-gated and authors freely"
    );

    let auto = policy_server(
        Arc::new(AgentState::new(AgentPolicy::Auto)),
        Some(cfg.clone()),
    );
    assert!(
        is_refused(&call_as(&auto, Frontend::Mcp, "script.save")),
        "Auto refuses a Sensitive script command outright"
    );

    // `Ask` parks a Sensitive agent call for operator approval; until approved it
    // does not run inline, so the call is not successful here.
    let ask = policy_server(Arc::new(AgentState::new(AgentPolicy::Ask)), Some(cfg));
    assert!(
        is_refused(&call_as(&ask, Frontend::Mcp, "script.save")),
        "Ask parks script.save for approval (not run inline)"
    );
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

/// Web `/bus` push AC8: `is_closed` reports the close flag, so the registry can
/// tell a torn-down connection from a live one before accepting a subscription.
#[test]
fn sink_is_closed_after_close() {
    let sink = NotificationSink::new(4);
    assert!(!sink.is_closed(), "a fresh sink is open");
    sink.close();
    assert!(sink.is_closed(), "close() marks the sink closed");
}

/// A streaming operator connection over `sink` for `srv`, as a transport builds
/// it after auth (a minted `conn_id`, the sink as `out`).
fn conn_over(srv: &McpServer, sink: &NotificationSink) -> ConnCtx {
    ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(sink.clone()),
    }
}

/// `tools/call flow.subscribe` with `args` on `conn`, parsed.
fn subscribe_on(srv: &McpServer, conn: &ConnCtx, args: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"flow.subscribe","arguments":args}});
    let reply = srv
        .handle_on(conn, &req.to_string())
        .expect("flow.subscribe replies");
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// Web `/bus` push AC8 / spec D4: a `flow.subscribe` that reaches the registry
/// after its connection's sink was closed (a detached frame still running at
/// disconnect) is refused as a tool error and registers nothing: neither the
/// `since` replay nor a later live push lands in the dead sink.
#[test]
fn subscribe_on_a_closed_sink_is_refused_and_registers_nothing() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 16);
    let early = store.insert(http_flow("example.com:443", "/early"));
    let replayable = store.insert(http_flow("example.com:443", "/replayable"));

    let sink = NotificationSink::new(16);
    let conn = conn_over(&srv, &sink);
    sink.close();

    let reply = subscribe_on(&srv, &conn, json!({"since": early.to_string()}));
    assert!(
        is_refused(&reply),
        "subscribe on a closed sink is a tool error: {reply}"
    );
    assert_eq!(
        reply["result"]["content"][0]["text"],
        "flow.subscribe refused: this connection is closed"
    );
    assert!(
        reply["result"].get("structuredContent").is_none(),
        "no sub_id is minted for a refused subscribe: {reply}"
    );
    assert_eq!(
        sink.queued_len(),
        0,
        "the since replay of {replayable} must not run for a refused subscribe"
    );

    let live = store.insert(http_flow("example.com:443", "/live"));
    srv.push_flow_event(&Event::RequestHeaders(live));
    assert_eq!(
        sink.queued_len(),
        0,
        "nothing was registered, so a live flow push has nowhere to land"
    );
}

/// Web `/bus` push AC8 (regression): an open sink subscribes exactly as before:
/// `{sub_id}` comes back and a pushed flow lands in the sink as one
/// `notifications/aitm/flow` line for that flow.
#[test]
fn subscribe_on_an_open_sink_still_works() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 16);
    let sink = NotificationSink::new(16);
    let conn = conn_over(&srv, &sink);

    let reply = subscribe_on(&srv, &conn, json!({}));
    assert!(!is_refused(&reply), "an open sink subscribes: {reply}");
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "subscribe returns a sub_id: {reply}"
    );

    let id = store.insert(http_flow("example.com:443", "/live"));
    srv.push_flow_event(&Event::RequestHeaders(id));
    assert_eq!(sink.queued_len(), 1, "exactly one line was pushed");
    let lines = sink.drain();
    let note: JsonValue = serde_json::from_str(&lines[0]).expect("the push is JSON");
    assert_eq!(note["method"], "notifications/aitm/flow");
    assert_eq!(note["params"]["event"], "created");
    assert_eq!(note["params"]["id"], id.to_string());
}

/// `tools/call flow.unsubscribe {sub_id}` on `conn`, parsed.
fn unsubscribe_on(srv: &McpServer, conn: &ConnCtx, sub_id: u64) -> JsonValue {
    let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"flow.unsubscribe","arguments":{"sub_id": sub_id}}});
    let reply = srv
        .handle_on(conn, &req.to_string())
        .expect("flow.unsubscribe replies");
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// The `sub_id` a successful subscribe reply carries.
fn sub_id_of(reply: &JsonValue) -> u64 {
    reply["result"]["structuredContent"]["sub_id"]
        .as_u64()
        .unwrap_or_else(|| panic!("subscribe returns a sub_id: {reply}"))
}

/// The literal refusal for a connection at the per-connection subscription cap.
const TOO_MANY_SUBS_TEXT: &str =
    "flow.subscribe refused: too many subscriptions on this connection (max 32); flow.unsubscribe first";

/// Web `/bus` push AC11: one connection holds at most 32 subscriptions. The 33rd
/// `flow.subscribe` is a tool error that mints no `sub_id` and replays nothing,
/// and a second connection on the same server is unaffected (the `sub_id` it gets
/// is the one the refusal did not consume).
#[test]
fn the_33rd_subscribe_is_refused_while_another_connection_still_subscribes() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 64);
    let since = store.insert(http_flow("example.com:443", "/since"));
    store.insert(http_flow("example.com:443", "/replayable"));
    let sink = NotificationSink::new(64);
    let conn = conn_over(&srv, &sink);

    let ids: Vec<u64> = (0..32)
        .map(|_| sub_id_of(&subscribe_on(&srv, &conn, json!({}))))
        .collect();
    assert_eq!(
        ids,
        (1..=32).collect::<Vec<u64>>(),
        "32 subscribes on one connection succeed"
    );

    let refused = subscribe_on(&srv, &conn, json!({"since": since.to_string()}));
    assert!(
        is_refused(&refused),
        "the 33rd subscribe is a tool error: {refused}"
    );
    assert_eq!(refused["result"]["content"][0]["text"], TOO_MANY_SUBS_TEXT);
    assert!(
        refused["result"].get("structuredContent").is_none(),
        "no sub_id is minted past the cap: {refused}"
    );
    // The refusal is audited to every subscriber, this connection included, so
    // the sink is not empty; what must be absent is any replayed flow line.
    let lines: Vec<JsonValue> = sink
        .drain()
        .iter()
        .map(|l| serde_json::from_str(l).expect("a drained line is JSON"))
        .collect();
    assert!(
        lines
            .iter()
            .all(|l| l["method"] != "notifications/aitm/flow"),
        "the since replay must not run for a refused subscribe: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l["method"] == "notifications/aitm/agent"
                && l["params"]["command"] == "flow.subscribe"),
        "the refusal itself is audited to the connection's subscribers: {lines:?}"
    );

    let other_sink = NotificationSink::new(64);
    let other = conn_over(&srv, &other_sink);
    let reply = subscribe_on(&srv, &other, json!({}));
    assert!(
        !is_refused(&reply),
        "the cap is per connection, so another connection still subscribes: {reply}"
    );
    assert_eq!(sub_id_of(&reply), 33, "the refusal consumed no sub_id");
}

/// Web `/bus` push AC11: `flow.unsubscribe` frees a slot under the cap, and only
/// one.
#[test]
fn unsubscribe_frees_a_subscription_slot() {
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store, 64);
    let sink = NotificationSink::new(64);
    let conn = conn_over(&srv, &sink);
    let ids: Vec<u64> = (0..32)
        .map(|_| sub_id_of(&subscribe_on(&srv, &conn, json!({}))))
        .collect();
    let at_cap = subscribe_on(&srv, &conn, json!({}));
    assert_eq!(
        at_cap["result"]["content"][0]["text"], TOO_MANY_SUBS_TEXT,
        "the connection is at the cap: {at_cap}"
    );

    let reply = unsubscribe_on(&srv, &conn, ids[0]);
    assert!(!is_refused(&reply), "{reply}");
    let reply = subscribe_on(&srv, &conn, json!({}));
    assert!(
        !is_refused(&reply),
        "after flow.unsubscribe one more subscribe fits: {reply}"
    );
    assert_eq!(sub_id_of(&reply), 33);
    let at_cap = subscribe_on(&srv, &conn, json!({}));
    assert_eq!(
        at_cap["result"]["content"][0]["text"], TOO_MANY_SUBS_TEXT,
        "one unsubscribe frees exactly one slot: {at_cap}"
    );
}

/// `http_flow` with `method` in place of `GET`.
fn http_flow_with_method(authority: &str, path: &str, method: &str) -> Flow {
    let mut flow = http_flow(authority, path);
    if let Flow::Http(f) = &mut flow {
        f.request.method = method.into();
    }
    flow
}

/// Web `/bus` push AC11: a `filter.host` or `filter.method` over 1024 bytes is a
/// tool error naming the field and registers nothing. The stored and pushed flows
/// carry the over-long value themselves, so a filter registered whole would have
/// matched: neither the `since` replay nor a live push may land in the sink. The
/// literal refusal text is what rules out a truncating implementation, since a
/// filter cut to 1024 bytes equals none of those flows.
#[test]
fn an_over_long_filter_value_is_refused_and_registers_nothing() {
    const OVER: usize = 1025;
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 16);
    let long_host = "h".repeat(OVER);
    let long_method = "m".repeat(OVER);
    let since = store.insert(http_flow(&long_host, "/since"));
    store.insert(http_flow(&long_host, "/replayable-host"));
    store.insert(http_flow_with_method(
        "example.com:443",
        "/replayable-method",
        &long_method,
    ));
    let sink = NotificationSink::new(16);
    let conn = conn_over(&srv, &sink);

    let cases = [
        (
            json!({"host": long_host}),
            "flow.subscribe refused: filter.host is longer than 1024 bytes",
        ),
        (
            json!({"method": long_method}),
            "flow.subscribe refused: filter.method is longer than 1024 bytes",
        ),
    ];
    for (filter, text) in cases {
        let reply = subscribe_on(
            &srv,
            &conn,
            json!({"filter": filter, "since": since.to_string()}),
        );
        assert!(
            is_refused(&reply),
            "a filter value of {OVER} bytes is refused: {reply}"
        );
        assert_eq!(reply["result"]["content"][0]["text"], text);
        assert!(
            reply["result"].get("structuredContent").is_none(),
            "no sub_id is minted for a refused filter: {reply}"
        );
    }
    assert_eq!(
        sink.queued_len(),
        0,
        "the since replay must not run for a refused filter"
    );

    let live_host = store.insert(http_flow(&long_host, "/live-host"));
    srv.push_flow_event(&Event::RequestHeaders(live_host));
    let live_method = store.insert(http_flow_with_method(
        "example.com:443",
        "/live-method",
        &long_method,
    ));
    srv.push_flow_event(&Event::RequestHeaders(live_method));
    assert_eq!(
        sink.queued_len(),
        0,
        "nothing was registered, so a live push has nowhere to land"
    );
}

/// Web `/bus` push AC11: the bound is inclusive. A `filter.host` and a
/// `filter.method` of exactly 1024 bytes are accepted, and each is retained whole:
/// a flow carrying that value is pushed.
#[test]
fn a_filter_value_of_exactly_1024_bytes_is_accepted() {
    const EXACT: usize = 1024;
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), 16);
    let host = "h".repeat(EXACT);
    let method = "m".repeat(EXACT);

    let host_sink = NotificationSink::new(16);
    let host_conn = conn_over(&srv, &host_sink);
    let reply = subscribe_on(&srv, &host_conn, json!({"filter": {"host": host}}));
    assert!(
        !is_refused(&reply),
        "a filter.host of {EXACT} bytes is within the bound: {reply}"
    );
    assert_eq!(sub_id_of(&reply), 1);

    let method_sink = NotificationSink::new(16);
    let method_conn = conn_over(&srv, &method_sink);
    let reply = subscribe_on(&srv, &method_conn, json!({"filter": {"method": method}}));
    assert!(
        !is_refused(&reply),
        "a filter.method of {EXACT} bytes is within the bound: {reply}"
    );
    assert_eq!(sub_id_of(&reply), 2);

    let by_host = store.insert(http_flow(&host, "/by-host"));
    srv.push_flow_event(&Event::RequestHeaders(by_host));
    let by_method = store.insert(http_flow_with_method(
        "example.com:443",
        "/by-method",
        &method,
    ));
    srv.push_flow_event(&Event::RequestHeaders(by_method));
    assert_eq!(
        host_sink.queued_len(),
        1,
        "the host filter matched its flow"
    );
    assert_eq!(
        method_sink.queued_len(),
        1,
        "the method filter matched its flow"
    );
    let host_note: JsonValue =
        serde_json::from_str(&host_sink.drain()[0]).expect("the push is JSON");
    assert_eq!(host_note["params"]["id"], by_host.to_string());
    let method_note: JsonValue =
        serde_json::from_str(&method_sink.drain()[0]).expect("the push is JSON");
    assert_eq!(method_note["params"]["id"], by_method.to_string());
}

/// Web `/bus` push, spec Goals (bounded push memory), added by the tester: the
/// `since` replay rides the same bounded notification lane as live pushes. A
/// subscribe that replays more flows than `push_capacity` keeps only the newest
/// `push_capacity`, flagged `lagged`, and a drain puts the `lagged` marker before
/// the surviving events. Also the positive control for
/// `subscribe_on_a_closed_sink_is_refused_and_registers_nothing`: the same `since`
/// argument does replay on an open sink, so that test's "no replay" is not vacuous.
#[test]
fn since_replay_is_bounded_by_the_sink_and_flags_lag() {
    const CAPACITY: usize = 4;
    const REPLAYABLE: usize = 10;
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store.clone(), CAPACITY);
    let since = store.insert(http_flow("example.com:443", "/since"));
    let replayable: Vec<String> = (0..REPLAYABLE)
        .map(|i| {
            store
                .insert(http_flow("example.com:443", &format!("/replay/{i}")))
                .to_string()
        })
        .collect();

    // Sized exactly as the web bridge sizes a connection's sink.
    let sink = NotificationSink::new(srv.push_capacity());
    let conn = conn_over(&srv, &sink);
    let reply = subscribe_on(&srv, &conn, json!({"since": since.to_string()}));
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "an open sink subscribes: {reply}"
    );
    assert_eq!(
        sink.queued_len(),
        CAPACITY,
        "the replay of {REPLAYABLE} flows is held to push_capacity"
    );
    assert!(sink.lagged(), "a replay that overflowed is flagged lagged");

    let lines: Vec<JsonValue> = sink
        .drain()
        .iter()
        .map(|l| serde_json::from_str(l).expect("a drained line is JSON"))
        .collect();
    assert_eq!(
        lines.len(),
        CAPACITY + 1,
        "marker then survivors: {lines:?}"
    );
    assert_eq!(lines[0]["method"], "notifications/aitm/state", "{lines:?}");
    assert_eq!(lines[0]["params"]["lagged"], true, "{lines:?}");
    let mut survivors = Vec::new();
    for note in &lines[1..] {
        assert_eq!(note["method"], "notifications/aitm/flow", "{note}");
        assert_eq!(note["params"]["event"], "created", "{note}");
        survivors.push(note["params"]["id"].as_str().unwrap_or_default());
    }
    assert_eq!(
        survivors,
        replayable[REPLAYABLE - CAPACITY..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "drop-oldest keeps the newest replayed flows, oldest first"
    );
}

/// Web `/bus` push AC9 / spec D1: `spawn_push_dispatcher` feeds a server that is
/// never `serve`d (the web bridge drives its own `McpServer` through `handle_on`):
/// a core `Event` sent on the broadcast reaches that server's subscriber as one
/// `notifications/aitm/flow` line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_push_dispatcher_delivers_a_broadcast_event() {
    let store = Arc::new(MemFlowStore::new());
    // The channel's own receiver is dropped at once, so a successful `send`
    // below proves the dispatcher subscribed its own.
    let (tx, _) = broadcast::channel::<Event>(16);
    let srv = Arc::new(
        McpServer::new(push_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_services(
                store.clone(),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_push(tx.clone()),
    );
    srv.spawn_push_dispatcher();

    let sink = NotificationSink::new(16);
    let conn = conn_over(&srv, &sink);
    let reply = subscribe_on(&srv, &conn, json!({}));
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "subscribe returns a sub_id: {reply}"
    );

    let id = store.insert(http_flow("example.com:443", "/bus"));
    tx.send(Event::RequestHeaders(id))
        .expect("the dispatcher holds a broadcast receiver");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while sink.queued_len() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        sink.queued_len(),
        1,
        "the dispatcher delivered exactly one line within the deadline"
    );
    let lines = sink.drain();
    let note: JsonValue = serde_json::from_str(&lines[0]).expect("the push is JSON");
    assert_eq!(note["method"], "notifications/aitm/flow");
    assert_eq!(note["params"]["event"], "created");
    assert_eq!(note["params"]["id"], id.to_string());
}

/// `spawn_push_dispatcher` is idempotent: a second call on the same server spawns
/// nothing, so the broadcast keeps one receiver and a subscriber receives each
/// event once rather than once per call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_push_dispatcher_twice_delivers_each_event_once() {
    let store = Arc::new(MemFlowStore::new());
    let (tx, _) = broadcast::channel::<Event>(16);
    let srv = Arc::new(
        McpServer::new(push_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_services(
                store.clone(),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_push(tx.clone()),
    );
    srv.spawn_push_dispatcher();
    srv.spawn_push_dispatcher();
    assert_eq!(
        tx.receiver_count(),
        1,
        "the second call spawns no second dispatcher"
    );

    let sink = NotificationSink::new(16);
    let conn = conn_over(&srv, &sink);
    sub_id_of(&subscribe_on(&srv, &conn, json!({})));
    let id = store.insert(http_flow("example.com:443", "/once"));
    tx.send(Event::RequestHeaders(id))
        .expect("the dispatcher holds a broadcast receiver");
    tokio::time::timeout(Duration::from_secs(5), sink.wait())
        .await
        .expect("the dispatcher delivered within the deadline");
    // A second dispatcher would push its own copy moments after the first; give
    // it that moment so a duplicate is seen, not missed.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let lines = sink.drain();
    assert_eq!(lines.len(), 1, "each event is delivered once: {lines:?}");
    let note: JsonValue = serde_json::from_str(&lines[0]).expect("the push is JSON");
    assert_eq!(note["method"], "notifications/aitm/flow");
    assert_eq!(note["params"]["id"], id.to_string());
}

/// Web `/bus` push AC9, second clause, added by the tester: `serve` still spawns
/// the push dispatcher now that the spawn lives in `spawn_push_dispatcher`. The
/// primary server's loopback-TCP subscribers depend on it, and no other
/// default-gate test drives `serve` with a broadcast attached (the scripted e2e
/// that does is gated on `AITM_OBSCURA`). Binds loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_still_spawns_the_push_dispatcher() {
    let store = Arc::new(MemFlowStore::new());
    // The channel's own receiver is dropped at once, so a successful `send`
    // below proves `serve` subscribed a dispatcher of its own.
    let (tx, _) = broadcast::channel::<Event>(16);
    let srv = McpServer::new(
        push_registry(),
        McpTransport::LoopbackTcp {
            port: 0,
            token: "tok".into(),
            endpoint_file: None,
        },
    )
    .with_agent_state(ungated())
    .with_services(
        store.clone(),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
    .with_push(tx.clone());
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    tokio::spawn(
        srv.on_bound(move |addr| {
            let _ = bound_tx.send(addr);
        })
        .serve(),
    );
    let addr = bound_rx.await.expect("serve reports its bound address");

    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(b"{\"token\":\"tok\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"flow.subscribe\",\"arguments\":{}}}\n")
        .await
        .expect("write");
    let (r, _w) = s.split();
    let mut lines = BufReader::new(r).lines();
    let reply: JsonValue = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("the subscribe reply within the deadline")
            .expect("io")
            .expect("a reply line"),
    )
    .expect("json");
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "flow.subscribe over loopback TCP returns a sub_id: {reply}"
    );

    let id = store.insert(http_flow("example.com:443", "/served"));
    tx.send(Event::RequestHeaders(id))
        .expect("serve's dispatcher holds a broadcast receiver");
    let note: JsonValue = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("the dispatched push within the deadline")
            .expect("io")
            .expect("a pushed line"),
    )
    .expect("json");
    assert_eq!(note["method"], "notifications/aitm/flow", "{note}");
    assert_eq!(note["params"]["event"], "created", "{note}");
    assert_eq!(note["params"]["id"], id.to_string(), "{note}");
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

/// RF#3 (fix, unit): `await_reply_capacity` parks while the reply lane is at its
/// high-water mark and releases once a drain frees room — or the sink closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn await_reply_capacity_releases_on_drain_and_close() {
    let sink = NotificationSink::with_limits(16, 2);
    sink.push_reply("a".into());
    sink.push_reply("b".into()); // reply lane now at the high-water mark (2)

    let s2 = sink.clone();
    let waiter = tokio::spawn(async move { s2.await_reply_capacity().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "a reader parks while the reply lane is full"
    );

    let _ = sink.drain(); // frees the lane and wakes the waiter
    tokio::time::timeout(Duration::from_millis(500), waiter)
        .await
        .expect("the waiter is released after a drain")
        .expect("waiter task");

    // When the sink is closed, capacity is granted at once even while full, so a
    // reader never hangs on a writer that has gone.
    sink.push_reply("x".into());
    sink.push_reply("y".into());
    sink.close();
    tokio::time::timeout(Duration::from_millis(500), sink.await_reply_capacity())
        .await
        .expect("await returns at once once the sink is closed");
}

/// RF#3 (fix, end-to-end): a client that pipelines requests but never reads its
/// socket does not grow the reply lane without bound — the server read loop
/// backpressures (pauses) at the reply high-water mark, and no reply is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_without_read_client_backpressures_not_unbounded() {
    const HIGH_WATER: usize = 8;
    let store = Arc::new(MemFlowStore::new());
    let srv = push_server(store, 64);

    // A tiny duplex so the writer blocks almost at once once the client stops
    // reading; a small reply high-water so the reader parks quickly.
    let (client, server_side) = duplex(256);
    let (s_r, s_w) = split(server_side);
    let sink = NotificationSink::with_limits(64, HIGH_WATER);
    let mut conn = ConnCtx::new(Frontend::Operator);
    conn.out = Some(sink.clone());
    let task = tokio::spawn(aitm_mcp::transport::serve_lines(
        srv,
        BufReader::new(s_r),
        s_w,
        conn,
    ));

    // The client writes many tiny requests and NEVER reads replies. Its own writes
    // will themselves block once the server stops reading (end-to-end backpressure),
    // so drive them from a task we simply let run as far as it can.
    let (c_r, mut c_w) = split(client);
    let writer = tokio::spawn(async move {
        for i in 0..5_000u32 {
            let line = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/call\",\
                 \"params\":{{\"name\":\"nope\",\"arguments\":{{}}}}}}\n"
            );
            if c_w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = c_w.flush().await;
        }
        c_w
    });

    // Give the pipeline time to fill and the reader to park.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        sink.reply_queued_len() <= HIGH_WATER,
        "the reply lane grew past the high-water mark ({HIGH_WATER}): {}",
        sink.reply_queued_len()
    );
    assert!(
        !task.is_finished(),
        "the server read loop is parked (backpressured), not finished/crashed"
    );

    // Teardown: closing the client fully makes the server writer error and close
    // the sink, which unblocks the parked reader so it exits.
    drop(c_r);
    writer.abort();
    task.abort();
    let _ = task.await;
    let _ = writer.await;
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

/// A Read command whose `invoke` always fails, returning the caller-supplied
/// `reason` verbatim as the error — so a test can prove the audited error reason
/// is scrubbed by content before it is recorded.
struct ErrEchoCmd;

impl Command for ErrEchoCmd {
    fn name(&self) -> &str {
        "demo.errecho"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Fail with the given reason.".into(),
            params: vec![ParamDef {
                name: "reason".into(),
                ty: TypeDesc::Str,
                required: true,
                description: String::new(),
            }],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Err(anyhow::anyhow!(args.get_str("reason")?.to_string()))
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

/// RF#3 (fix): a secret carried inside a *non-secret-named* value — a token in a
/// query string, a credential in a form body — must be masked by content, not
/// just by key. The audit entry and the pushed `agent` line must both be clean.
#[test]
fn audit_redacts_secret_inside_non_secret_named_value() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());

    // A subscribed operator so the pushed line can be inspected too.
    let watcher = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(aitm_mcp::NotificationSink::new(64)),
    };
    srv.handle_on(
        &watcher,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"flow.subscribe","arguments":{}}})
        .to_string(),
    )
    .expect("subscribe reply");

    // `note` is a plain string arg (NOT a secret-named key), carrying both a
    // query-string token and a form-body credential.
    srv.handle_on(
        &ConnCtx::new(Frontend::Mcp),
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"demo.secret",
        "arguments":{
            "note":"GET /v1?access_token=sk-SECRET-IN-QUERY then body user=admin&password=hunter2"
        }}})
        .to_string(),
    )
    .expect("call reply");

    let entry = ring
        .recent(None, None)
        .into_iter()
        .find(|e| e.command == "demo.secret")
        .expect("the call was audited");
    assert!(
        !entry.args_summary.contains("sk-SECRET-IN-QUERY"),
        "query-string token leaked into the audit entry: {}",
        entry.args_summary
    );
    assert!(
        !entry.args_summary.contains("hunter2"),
        "body credential leaked into the audit entry: {}",
        entry.args_summary
    );
    assert!(
        entry.args_summary.contains("[redacted]"),
        "redaction marker present: {}",
        entry.args_summary
    );

    let pushed = watcher.out.as_ref().unwrap().drain().join("\n");
    assert!(
        !pushed.contains("sk-SECRET-IN-QUERY"),
        "token leaked into push"
    );
    assert!(!pushed.contains("hunter2"), "credential leaked into push");
}

/// RF#3 (fix): an error/refusal *reason* that echoes a bad argument value is
/// scrubbed by content before it is recorded (a header-error or coercion error
/// must not persist a secret fragment). Driven by a command whose `invoke`
/// returns an error reason quoting a credential.
#[test]
fn audit_redacts_secret_in_error_reason() {
    let ring = Arc::new(AuditRing::default());
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ErrEchoCmd));
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    reg.add_plugin(Box::new(
        AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
    ));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state)
        .with_audit_ring(ring.clone());

    srv.handle_on(
        &ConnCtx::new(Frontend::Mcp),
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"demo.errecho",
            "arguments":{"reason":"rejected header value token=sk-LEAK-IN-ERR"}}})
        .to_string(),
    )
    .expect("call reply");

    let entry = ring
        .recent(None, None)
        .into_iter()
        .find(|e| e.command == "demo.errecho")
        .expect("the failed call was audited");
    match &entry.result {
        aitm_core::AuditResult::Error(reason) => {
            assert!(
                !reason.contains("sk-LEAK-IN-ERR"),
                "secret leaked into the error reason: {reason}"
            );
            assert!(reason.contains("[redacted]"), "reason scrubbed: {reason}");
        }
        other => panic!("expected an error result, got {other:?}"),
    }
}

/// RF#6: a refused subscription verb is audited (a gate decision), while a
/// successful one is not (it is connection management, not a command invocation).
#[test]
fn subscription_refusal_is_audited_but_success_is_not() {
    let ring = Arc::new(AuditRing::default());
    let state = Arc::new(AgentState::new(AgentPolicy::Paused));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
    ));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state)
        .with_audit_ring(ring.clone());

    // Agent `flow.subscribe` under `Paused` is refused — and now audited.
    assert!(is_refused(&call_as(&srv, Frontend::Mcp, "flow.subscribe")));
    let subs: Vec<_> = ring
        .recent(None, None)
        .into_iter()
        .filter(|e| e.command == "flow.subscribe")
        .collect();
    assert_eq!(subs.len(), 1, "a refused subscribe is audited");
    assert!(
        matches!(subs[0].result, aitm_core::AuditResult::Error(_)),
        "the audited subscribe refusal carries an error result"
    );

    // Operator `flow.subscribe` (with a push sink) succeeds — and is NOT audited.
    let watcher = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(aitm_mcp::NotificationSink::new(16)),
    };
    srv.handle_on(
        &watcher,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"flow.subscribe","arguments":{}}})
        .to_string(),
    )
    .expect("subscribe reply");
    let after = ring
        .recent(None, None)
        .into_iter()
        .filter(|e| e.command == "flow.subscribe")
        .count();
    assert_eq!(after, 1, "a successful subscribe is not audited");
}

/// Trusted-control allow-list (agent gates fail closed), on `flow.subscribe`. Under
/// `Paused` only the agent role is refused; `Operator` and the `Cli` subscribe
/// (each with a push sink, so a success is distinguishable from the "no sink"
/// error the verb returns on a non-streaming connection).
#[test]
fn subscribe_under_paused_refuses_only_the_agent() {
    let srv = policy_server(Arc::new(AgentState::new(AgentPolicy::Paused)), None);
    let subscribe = |role: Frontend| -> JsonValue {
        let conn = ConnCtx {
            role,
            client_label: None,
            conn_id: srv.next_conn_id(),
            out: Some(aitm_mcp::NotificationSink::new(16)),
        };
        let resp = srv
            .handle_on(
                &conn,
                &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":"flow.subscribe","arguments":{}}})
                .to_string(),
            )
            .expect("subscribe reply");
        serde_json::from_str(&resp).expect("response is JSON")
    };

    let agent = subscribe(Frontend::Mcp);
    assert!(is_refused(&agent), "agent subscribe refused under Paused");
    let text = agent["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("the agent policy is `paused`"),
        "the refusal names the paused policy: {text}"
    );

    for role in [Frontend::Operator, Frontend::Cli] {
        let resp = subscribe(role);
        assert!(!is_refused(&resp), "{role:?} subscribe runs under Paused");
        assert!(
            resp["result"]["structuredContent"]["sub_id"].is_u64(),
            "{role:?} gets a sub_id: {resp}"
        );
    }
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

// ------------------------------------------------ M4 Task 9: Ask policy

/// A server under the `Ask` policy: one gateless Sensitive stub (`demo.sensitive`),
/// the real `AgentPlugin` (so `agent.approve` is registered and exercised), and a
/// bounded `approval_timeout` so `ask_timeout_refuses` is cheap. Returned as an
/// `Arc` so an agent connection and an operator connection share the one
/// parked-request table.
fn ask_server(approval_timeout: Duration) -> Arc<McpServer> {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(TierCmd {
        name: "demo.sensitive",
        sens: Sensitivity::Sensitive,
    }));
    let state = Arc::new(AgentState::new(AgentPolicy::Ask));
    reg.add_plugin(Box::new(AgentPlugin::new(state.clone())));
    Arc::new(
        McpServer::new(Arc::new(reg), McpTransport::Stdio)
            .with_agent_state(state)
            .with_approval_timeout(approval_timeout)
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            ),
    )
}

/// Read JSON lines until one satisfies `pred` (skips interleaved audit
/// notifications an operator connection also receives); panics after 100 reads.
async fn read_until(lines: &mut ClientReader, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
    for _ in 0..100 {
        let v = next_json(lines).await;
        if pred(&v) {
            return v;
        }
    }
    panic!("no matching line within 100 reads");
}

/// Open an operator connection and subscribe it, so it is a connected operator
/// that receives `approval_requested` pushes. Returns its write half, reader, task.
async fn operator_subscribed(
    srv: Arc<McpServer>,
) -> (
    WriteHalf<DuplexStream>,
    ClientReader,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (mut w, mut lines, _sink, task) = open_push_conn(srv, Frontend::Operator, 64 * 1024, 1024);
    write_req(
        &mut w,
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"flow.subscribe","arguments":{}}}),
    )
    .await;
    let reply = read_until(&mut lines, |v| v["id"] == json!(1)).await;
    assert!(
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "operator subscribe returns a sub_id: {reply}"
    );
    (w, lines, task)
}

/// AC-M4-5b / spec D4: under `Ask`, a Sensitive agent call is parked (not run, not
/// returned as `needs_confirmation`); an operator sees `approval_requested`, and
/// `agent.approve{allow:true}` runs the parked command, whose real result reaches
/// the waiting agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ask_parks_then_approves() {
    let srv = ask_server(Duration::from_secs(10));
    let (mut op_w, mut op_lines, op_task) = operator_subscribed(srv.clone()).await;

    // The agent, on its own connection, calls the Sensitive command — it parks.
    let (mut ag_w, mut ag_lines, _sink, ag_task) =
        open_push_conn(srv.clone(), Frontend::Mcp, 64 * 1024, 1024);
    write_req(
        &mut ag_w,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"demo.sensitive","arguments":{}}}),
    )
    .await;

    // The operator receives the approval request naming the parked command.
    let req = read_until(&mut op_lines, |v| {
        v["method"] == "notifications/aitm/agent" && v["params"]["event"] == "approval_requested"
    })
    .await;
    assert_eq!(req["params"]["command"], "demo.sensitive");
    let request_id = req["params"]["request_id"]
        .as_str()
        .expect("approval request carries a request_id")
        .to_string();

    // The operator approves it.
    write_req(
        &mut op_w,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"agent.approve","arguments":{"request_id":request_id,"allow":true}}}),
    )
    .await;

    // The waiting agent call now completes with the command's real result.
    let done = read_until(&mut ag_lines, |v| v["id"] == json!(2)).await;
    assert_eq!(
        done["result"]["isError"],
        json!(false),
        "the approved agent call ran: {done}"
    );
    assert_eq!(done["result"]["structuredContent"], json!("ran"));

    let _ = ag_w.shutdown().await;
    let _ = op_w.shutdown().await;
    let _ = ag_task.await;
    let _ = op_task.await;
}

/// AC-M4-5b: `agent.approve{allow:false}` refuses the parked call; the waiting
/// agent gets a tool error, and the command never ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ask_deny_refuses() {
    let srv = ask_server(Duration::from_secs(10));
    let (mut op_w, mut op_lines, op_task) = operator_subscribed(srv.clone()).await;

    let (mut ag_w, mut ag_lines, _sink, ag_task) =
        open_push_conn(srv.clone(), Frontend::Mcp, 64 * 1024, 1024);
    write_req(
        &mut ag_w,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"demo.sensitive","arguments":{}}}),
    )
    .await;

    let req = read_until(&mut op_lines, |v| {
        v["params"]["event"] == "approval_requested"
    })
    .await;
    let request_id = req["params"]["request_id"].as_str().unwrap().to_string();

    write_req(
        &mut op_w,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"agent.approve","arguments":{"request_id":request_id,"allow":false}}}),
    )
    .await;

    let done = read_until(&mut ag_lines, |v| v["id"] == json!(2)).await;
    assert_eq!(
        done["result"]["isError"],
        json!(true),
        "a denied agent call is refused: {done}"
    );

    let _ = ag_w.shutdown().await;
    let _ = op_w.shutdown().await;
    let _ = ag_task.await;
    let _ = op_task.await;
}

/// RF#4 / spec D4: a parked call whose approval never arrives is refused on the
/// bounded timeout — it never hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ask_timeout_refuses() {
    let srv = ask_server(Duration::from_millis(300));
    // An operator is present (subscribed) but never approves.
    let (mut op_w, _op_lines, op_task) = operator_subscribed(srv.clone()).await;

    let (mut ag_w, mut ag_lines, _sink, ag_task) =
        open_push_conn(srv.clone(), Frontend::Mcp, 64 * 1024, 1024);
    write_req(
        &mut ag_w,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"demo.sensitive","arguments":{}}}),
    )
    .await;

    let done = read_until(&mut ag_lines, |v| v["id"] == json!(2)).await;
    assert_eq!(
        done["result"]["isError"],
        json!(true),
        "a timed-out parked call is refused: {done}"
    );
    let text = done["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("timeout") || text.contains("approv"),
        "the refusal explains the timeout: {text}"
    );

    let _ = ag_w.shutdown().await;
    let _ = op_w.shutdown().await;
    let _ = ag_task.await;
    let _ = op_task.await;
}

/// RF#4 / spec D4: a Sensitive agent call under `Ask` with no operator connected is
/// refused at once (not parked forever) with a clear reason.
#[test]
fn ask_without_operator_refuses() {
    let srv = ask_server(Duration::from_secs(10));
    let resp = call_as(&srv, Frontend::Mcp, "demo.sensitive");
    assert!(is_refused(&resp), "no-operator Sensitive call is refused");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("operator"),
        "the refusal explains no operator is connected: {text}"
    );
}

/// RF#2: an agent calling `agent.approve` is refused — it can never approve its own
/// parked request. Only trusted control (`Operator` and the `Cli`) clears the role
/// gate; an unknown id is then a plain "no parked request" error, which is how a
/// role refusal is told apart from a request that merely does not exist.
#[test]
fn agent_cannot_approve_own_request() {
    let srv = ask_server(Duration::from_secs(10));
    let error_text = |role: Frontend| -> String {
        let resp = call_as_args(
            &srv,
            role,
            "agent.approve",
            json!({"request_id": "nope", "allow": true}),
        );
        assert!(is_refused(&resp), "unknown id is an error for {role:?}");
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    assert!(
        error_text(Frontend::Mcp).contains("agent cannot approve its own requests"),
        "the agent role is role-refused"
    );
    for role in [Frontend::Operator, Frontend::Cli] {
        let text = error_text(role);
        assert!(
            text.contains("no parked request `nope`"),
            "{role:?} clears the role gate and gets a no-such-request error: {text}"
        );
    }
}

// --------------------------------------------------- Task 3 (W2): resources/*

/// AC1: `initialize` advertises both `tools` and `resources` capabilities and
/// the `io.modelcontextprotocol/ui` extension, while keeping the existing
/// top-level `role` and `serverInfo`.
#[test]
fn initialize_advertises_resources() {
    let srv = server();
    let resp = rpc(&srv, 1, "initialize", json!({}));
    let caps = &resp["result"]["capabilities"];
    assert!(caps["tools"].is_object(), "tools capability kept: {resp}");
    assert!(
        caps["resources"].is_object(),
        "resources capability: {resp}"
    );
    assert_eq!(
        caps["extensions"]["io.modelcontextprotocol/ui"]["mimeTypes"][0],
        "text/html;profile=mcp-app",
        "ui extension advertised: {resp}"
    );
    // Existing fields survive.
    assert_eq!(resp["result"]["serverInfo"]["name"], "aitmproxy");
    assert!(
        resp["result"]["role"].is_string(),
        "top-level role kept: {resp}"
    );
}

/// AC2: `resources/list` returns exactly seven widget entries, each with the
/// MCP-app mime, a `ui://aitm/` uri, and the resource `_meta` keys.
#[test]
fn resources_list_seven() {
    let srv = server();
    let resp = rpc(&srv, 1, "resources/list", json!({}));
    let list = resp["result"]["resources"]
        .as_array()
        .expect("resources array");
    assert_eq!(list.len(), 7, "seven widgets: {resp}");
    for entry in list {
        assert_eq!(
            entry["mimeType"], "text/html;profile=mcp-app",
            "mime: {entry}"
        );
        assert!(
            entry["uri"]
                .as_str()
                .expect("uri")
                .starts_with("ui://aitm/"),
            "uri scheme: {entry}"
        );
        let meta = &entry["_meta"];
        assert_eq!(meta["ui"]["csp"]["connectDomains"], json!([]), "{entry}");
        assert_eq!(meta["ui"]["csp"]["resourceDomains"], json!([]), "{entry}");
        assert_eq!(
            meta["openai/widgetCSP"]["connect_domains"],
            json!([]),
            "{entry}"
        );
        assert_eq!(meta["ui"]["domain"], "aitmproxy.widget", "{entry}");
        assert_eq!(meta["openai/widgetDomain"], "aitmproxy.widget", "{entry}");
        assert!(meta["ui"]["prefersBorder"].is_boolean(), "{entry}");
        assert_eq!(
            meta["openai/ui"]["availableDisplayModes"],
            json!(["inline"]),
            "{entry}"
        );
    }
}

/// AC3: `resources/read` for each widget uri returns the MCP-app mime and a
/// `<!DOCTYPE html>` body; an unknown uri is a JSON-RPC INVALID_PARAMS error.
#[test]
fn resources_read_doctype_and_unknown() {
    let srv = server();
    let list = rpc(&srv, 1, "resources/list", json!({}));
    let uris: Vec<String> = list["result"]["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .map(|e| e["uri"].as_str().expect("uri").to_string())
        .collect();
    assert_eq!(uris.len(), 7);
    for uri in &uris {
        let resp = rpc(&srv, 2, "resources/read", json!({"uri": uri}));
        let item = &resp["result"]["contents"][0];
        assert_eq!(item["mimeType"], "text/html;profile=mcp-app", "{resp}");
        assert_eq!(item["uri"], json!(uri), "{resp}");
        assert!(
            item["text"]
                .as_str()
                .expect("text")
                .starts_with("<!DOCTYPE html>"),
            "doctype: {resp}"
        );
        // Design B: the read item carries the same resource `_meta` as the list
        // entry (CSP, domain, border, display modes — standard + `openai/*`).
        let meta = &item["_meta"];
        assert_eq!(meta["ui"]["csp"]["connectDomains"], json!([]), "{resp}");
        assert_eq!(meta["ui"]["csp"]["resourceDomains"], json!([]), "{resp}");
        assert_eq!(
            meta["openai/widgetCSP"]["connect_domains"],
            json!([]),
            "{resp}"
        );
        assert_eq!(meta["ui"]["domain"], "aitmproxy.widget", "{resp}");
        assert_eq!(meta["openai/widgetDomain"], "aitmproxy.widget", "{resp}");
        assert!(meta["ui"]["prefersBorder"].is_boolean(), "{resp}");
        assert_eq!(
            meta["openai/ui"]["availableDisplayModes"],
            json!(["inline"]),
            "{resp}"
        );
    }
    // Unknown uri → INVALID_PARAMS.
    let bad = rpc(&srv, 3, "resources/read", json!({"uri": "ui://aitm/nope"}));
    assert_eq!(bad["error"]["code"], json!(INVALID_PARAMS), "{bad}");
    // Missing uri → INVALID_PARAMS.
    let missing = rpc(&srv, 4, "resources/read", json!({}));
    assert_eq!(missing["error"]["code"], json!(INVALID_PARAMS), "{missing}");
}

// ------------------------------------------------- Task 5: widget tool overlay

/// A name/result-only stub so `tools/list` carries a given tool name through the
/// `widget_meta_for` overlay (the overlay keys off `Command::name()` and uses the
/// command's `schema().result` for `outputSchema`).
struct WidgetStub {
    tool: &'static str,
    result: TypeDesc,
}

impl Command for WidgetStub {
    fn name(&self) -> &str {
        self.tool
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "widget stub".into(),
            params: vec![],
            result: self.result.clone(),
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        match &self.result {
            TypeDesc::Array(_) => Ok(Value::Array(vec![])),
            _ => Ok(Value::Object(BTreeMap::new())),
        }
    }
}

/// A server whose registry carries the widget-named stub tools (object-result
/// unless the name is an array tool), so `tools/list` exercises the overlay.
fn widget_server() -> McpServer {
    let obj = || TypeDesc::Object(vec![]);
    let arr = || TypeDesc::Array(Box::new(TypeDesc::Str));
    let mut reg = Registry::new();
    for (tool, result) in [
        ("flow.table", obj()),
        ("flow.detail", obj()),
        ("findings.list", arr()),
        ("findings.get", obj()),
        ("scope.list", arr()),
        ("poc.run", obj()),
        ("poc.get", obj()),
        ("proxy.status", obj()),
        ("tls.passthrough.list", arr()),
    ] {
        reg.add_command(Arc::new(WidgetStub { tool, result }));
    }
    McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
}

/// Find the `tools/list` entry for `name`.
fn tool_entry(list_resp: &JsonValue, name: &str) -> JsonValue {
    list_resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} listed: {list_resp}"))
        .clone()
}

/// AC4: a render widget tool carries its `_meta` link (standard + `openai/*`
/// alias, equal), ≤ 64-char invocation strings; the data-only widget-accessible
/// tool carries `ui.visibility` + legacy `openai/widgetAccessible` and **no**
/// resource link.
#[test]
fn widget_tools_carry_meta() {
    let srv = widget_server();
    let resp = rpc(&srv, 1, "tools/list", json!({}));

    let table = tool_entry(&resp, "flow.table");
    let meta = &table["_meta"];
    assert_eq!(meta["ui"]["resourceUri"], "ui://aitm/flows", "{table}");
    assert_eq!(
        meta["openai/outputTemplate"], "ui://aitm/flows",
        "alias: {table}"
    );
    assert_eq!(
        meta["ui"]["resourceUri"], meta["openai/outputTemplate"],
        "standard == alias: {table}"
    );
    let invoking = meta["openai/toolInvocation/invoking"]
        .as_str()
        .expect("invoking string");
    let invoked = meta["openai/toolInvocation/invoked"]
        .as_str()
        .expect("invoked string");
    assert_eq!(invoking, "Fetching flows", "{table}");
    assert_eq!(invoked, "Flows ready", "{table}");
    assert!(invoking.len() <= 64 && invoked.len() <= 64, "<=64: {table}");

    let tls = tool_entry(&resp, "tls.passthrough.list");
    let tmeta = &tls["_meta"];
    assert_eq!(tmeta["ui"]["visibility"], json!(["model", "app"]), "{tls}");
    assert_eq!(tmeta["openai/widgetAccessible"], json!(true), "{tls}");
    assert!(
        tmeta["ui"]["resourceUri"].is_null(),
        "no resourceUri: {tls}"
    );
    assert!(
        tmeta["openai/outputTemplate"].is_null(),
        "no output template: {tls}"
    );
}

/// AC5: every widget tool carries all three annotation hints; all read-only
/// except `poc.run`; `outputSchema.type` is `object` for object tools and
/// `array` for `findings.list`/`scope.list`.
#[test]
fn widget_annotations_and_output_schema() {
    let srv = widget_server();
    let resp = rpc(&srv, 1, "tools/list", json!({}));

    for name in [
        "flow.table",
        "flow.detail",
        "findings.list",
        "findings.get",
        "scope.list",
        "poc.run",
        "poc.get",
        "proxy.status",
    ] {
        let e = tool_entry(&resp, name);
        let ann = &e["annotations"];
        assert!(ann["readOnlyHint"].is_boolean(), "readOnlyHint: {e}");
        assert!(ann["destructiveHint"].is_boolean(), "destructiveHint: {e}");
        assert!(ann["openWorldHint"].is_boolean(), "openWorldHint: {e}");
        assert_eq!(ann["destructiveHint"], json!(false), "{e}");
        if name == "poc.run" {
            assert_eq!(ann["readOnlyHint"], json!(false), "{e}");
            assert_eq!(ann["openWorldHint"], json!(true), "{e}");
        } else {
            assert_eq!(ann["readOnlyHint"], json!(true), "{e}");
            assert_eq!(ann["openWorldHint"], json!(false), "{e}");
        }
    }

    for name in ["flow.table", "flow.detail", "findings.get", "poc.run"] {
        let e = tool_entry(&resp, name);
        assert_eq!(e["outputSchema"]["type"], "object", "object tool: {e}");
    }
    for name in ["findings.list", "scope.list"] {
        let e = tool_entry(&resp, name);
        assert_eq!(e["outputSchema"]["type"], "array", "array tool: {e}");
    }
}

/// AC6 no-regression: a non-widget tool's `tools/list` entry gains no overlay
/// keys and is byte-identical to `to_mcp_tool(..).to_json()`; a widget tool's
/// `tools/call` result gains no `_meta`.
#[test]
fn non_widget_tools_byte_identical() {
    let srv = server();
    let resp = rpc(&srv, 1, "tools/list", json!({}));

    let non_widget: Vec<(&str, Box<dyn Command>)> = vec![
        ("demo.ping", Box::new(PingCmd)),
        ("demo.echo", Box::new(EchoCmd)),
        ("demo.fail", Box::new(FailCmd)),
        ("demo.capture", Box::new(CaptureCmd)),
        ("flow.get", Box::new(FlowGetCmd)),
        ("flow.list", Box::new(FlowListCmd)),
    ];
    for (name, cmd) in &non_widget {
        let entry = tool_entry(&resp, name);
        assert!(
            entry.get("annotations").is_none(),
            "no annotations: {entry}"
        );
        assert!(
            entry.get("outputSchema").is_none(),
            "no outputSchema: {entry}"
        );
        assert!(entry.get("_meta").is_none(), "no _meta: {entry}");
        assert_eq!(
            entry,
            StdSchemaDerive.to_mcp_tool(cmd.as_ref()).to_json(),
            "byte-identical to the overlay-free derivation: {name}"
        );
    }

    // A widget tool's tools/call result gains NO `_meta`.
    let wsrv = widget_server();
    let call = rpc(
        &wsrv,
        2,
        "tools/call",
        json!({"name": "proxy.status", "arguments": {}}),
    );
    assert_eq!(call["result"]["isError"], json!(false), "{call}");
    assert!(
        call["result"].get("_meta").is_none(),
        "no result _meta: {call}"
    );
}

// ---- Schema enforcement on the server-handled verbs -----------------------
//
// `flow.subscribe`/`flow.unsubscribe`/`agent.approve` are answered in
// `run_tool` before the normal `params_from_json` path, so without explicit
// enforcement they would bypass their own published schema: undeclared keys,
// wrong-typed values, and a non-flow-id `since` would all slip through the
// validation every other tool gets. Each bad call must be the same
// INVALID_PARAMS JSON-RPC error a mistyped regular command returns.

/// An undeclared argument to `flow.subscribe` is rejected (`additionalProperties:
/// false`), not silently accepted.
#[test]
fn subscribe_rejects_undeclared_argument() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.subscribe",
        json!({"bogus": 1}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// A wrong-typed value inside the nested `filter` object is rejected.
#[test]
fn subscribe_rejects_nonstring_method_in_filter() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.subscribe",
        json!({"filter": {"method": 123}}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// An undeclared key *inside* the nested `filter` object is rejected too (the
/// schema is enforced recursively, like any other object param).
#[test]
fn subscribe_rejects_undeclared_key_inside_filter() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.subscribe",
        json!({"filter": {"bogus": "x"}}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// A non-flow-id `since` is rejected instead of being silently dropped (before
/// the fix `since.parse::<FlowId>().ok()` swallowed a bad value, so a client's
/// typo produced a full live stream with no catch-up and no error).
#[test]
fn subscribe_rejects_non_flow_id_since() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.subscribe",
        json!({"since": "not-a-flow-id"}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// A well-formed `filter` + `since` still passes validation and subscribes
/// (the enforcement rejects only genuinely invalid arguments).
#[test]
fn subscribe_accepts_valid_filter_and_since() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let since = aitm_core::FlowId::new().to_string();
    let conn = ConnCtx {
        role: Frontend::Operator,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(aitm_mcp::NotificationSink::new(16)),
    };
    let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"flow.subscribe",
            "arguments":{"filter":{"host":"a.test","method":"post"},"since":since}}});
    let resp: JsonValue =
        serde_json::from_str(&srv.handle_on(&conn, &req.to_string()).expect("reply"))
            .expect("json");
    assert_eq!(
        resp["result"]["isError"],
        json!(false),
        "a valid subscribe succeeds: {resp}"
    );
    assert!(
        resp["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "returns a sub_id: {resp}"
    );
}

/// An undeclared argument to `flow.unsubscribe` is rejected even alongside a
/// valid `sub_id`.
#[test]
fn unsubscribe_rejects_undeclared_argument() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.unsubscribe",
        json!({"sub_id": 1, "bogus": 2}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// `flow.unsubscribe` requires its declared `sub_id` — a missing required param
/// is rejected (before the fix an absent `sub_id` reached the hand-rolled handler
/// as a tool error rather than the INVALID_PARAMS every other tool returns).
#[test]
fn unsubscribe_rejects_missing_sub_id() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(&srv, Frontend::Operator, "flow.unsubscribe", json!({}));
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// A wrong-typed `sub_id` (the verb's one declared param, an `Int`) is rejected
/// by the schema, like any mistyped regular command.
#[test]
fn unsubscribe_rejects_nonint_sub_id() {
    let srv = push_server(Arc::new(MemFlowStore::new()), 16);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "flow.unsubscribe",
        json!({"sub_id": "not-an-int"}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// An undeclared argument to `agent.approve` (from an operator — a trusted
/// control role past the role gate) is rejected.
#[test]
fn approve_rejects_undeclared_argument() {
    let srv = policy_server(ungated(), None);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": "apr_deadbeef", "allow": true, "bogus": 1}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// A wrong-typed `allow` for `agent.approve` is rejected by the schema.
#[test]
fn approve_rejects_wrong_typed_allow() {
    let srv = policy_server(ungated(), None);
    let resp = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": "apr_deadbeef", "allow": "yes"}),
    );
    assert_eq!(resp["error"]["code"], json!(INVALID_PARAMS), "{resp}");
}

/// Security: for `agent.approve` the role gate decides on the role alone, *before*
/// any argument validation. An agent sending malformed `agent.approve` is refused
/// for being the agent (a tool error) — it is never told its arguments were bad,
/// so argument shape can never become an oracle around the role gate (RF#2).
#[test]
fn approve_role_gate_precedes_schema_for_the_agent() {
    let srv = policy_server(ungated(), None);
    let resp = call_as_args(
        &srv,
        Frontend::Mcp,
        "agent.approve",
        json!({"bogus": 1, "allow": "not-a-bool"}),
    );
    assert!(
        resp.get("error").is_none(),
        "a role refusal, not a protocol error: {resp}"
    );
    assert!(is_refused(&resp), "the agent is refused: {resp}");
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("cannot approve"),
        "refused for the role, not the arguments: {resp}"
    );
}

// ------------- server-assigned connection id (plan 2026-10-30-bus-audit-connection-id)

/// A streaming connection of `role` as a transport builds it after auth: a minted
/// non-zero `conn_id`, no client label, no push sink.
fn minted(srv: &McpServer, role: Frontend) -> ConnCtx {
    ConnCtx {
        role,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: None,
    }
}

/// `tools/call name args` on `conn`; the whole parsed reply.
fn call_on(srv: &McpServer, conn: &ConnCtx, name: &str, args: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args}});
    let resp = srv
        .handle_on(conn, &req.to_string())
        .expect("a request gets a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

/// `initialize` with `params` on `conn`; the whole parsed reply.
fn initialize_on(srv: &McpServer, conn: &ConnCtx, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params});
    let resp = srv
        .handle_on(conn, &req.to_string())
        .expect("initialize gets a reply");
    serde_json::from_str(&resp).expect("response is JSON")
}

/// The connection id `initialize` hands `conn`, as a string; panics if the reply
/// carries anything else.
fn init_id(srv: &McpServer, conn: &ConnCtx) -> String {
    let reply = initialize_on(srv, conn, json!({}));
    reply["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initialize carries no string connection_id: {reply}"))
        .to_string()
}

/// A subscribed watcher: a minted connection of `role` with a push sink, already
/// `flow.subscribe {}`d, so every audit line the server pushes lands in its sink.
fn watcher(srv: &McpServer, role: Frontend) -> ConnCtx {
    let conn = ConnCtx {
        out: Some(NotificationSink::new(64)),
        ..minted(srv, role)
    };
    let reply = call_on(srv, &conn, "flow.subscribe", json!({}));
    assert!(!is_refused(&reply), "the watcher subscribes: {reply}");
    conn
}

/// The `notifications/aitm/agent` lines in `conn`'s sink, parsed, oldest first.
fn agent_lines(conn: &ConnCtx) -> Vec<JsonValue> {
    conn.out
        .as_ref()
        .expect("a watcher has a sink")
        .drain()
        .iter()
        .map(|l| serde_json::from_str::<JsonValue>(l).expect("a pushed line is JSON"))
        .filter(|v| v["method"] == "notifications/aitm/agent")
        .collect()
}

/// AC7: `initialize` tells a streaming connection its own id, at the top level of
/// the result (never inside `serverInfo`), stable across repeats and different for
/// another connection of the same server.
#[test]
fn initialize_echoes_connection_id() {
    let srv = server();
    let a = minted(&srv, Frontend::Mcp);

    let first = initialize_on(&srv, &a, json!({}));
    let id = first["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("connection_id is a string: {first}"))
        .to_string();
    assert!(!id.is_empty(), "the id is not empty");
    assert!(id.len() <= 64, "the id is at most 64 bytes: {id}");
    assert!(
        id.bytes().all(|b| b.is_ascii_graphic()),
        "the id is printable ASCII: {id}"
    );
    assert!(
        first["result"]["serverInfo"]["connection_id"].is_null(),
        "the id describes the connection, not the server: {first}"
    );

    assert_eq!(
        init_id(&srv, &a),
        id,
        "a repeated initialize repeats the id"
    );

    let b = minted(&srv, Frontend::Mcp);
    assert_ne!(init_id(&srv, &b), id, "another connection has another id");
}

/// AC7: a caller that is not a streaming connection (`conn_id == 0`: in-process,
/// HTTP POST, the embedded TUI) gets `null`, and the key is still present so every
/// reply has one shape.
#[test]
fn initialize_connection_id_is_null_without_a_connection() {
    let srv = server();
    let reply = initialize_on(&srv, &ConnCtx::new(Frontend::Operator), json!({}));
    assert_eq!(reply["result"]["connection_id"], JsonValue::Null);
    assert!(
        reply["result"]
            .as_object()
            .expect("the result is an object")
            .contains_key("connection_id"),
        "the key is present even when null: {reply}"
    );
}

/// AC8: every audit entry carries the id of the connection that made the call,
/// the same id that connection's `initialize` returned; a call with no connection
/// carries `None`; the pushed line carries exactly the entry's id.
#[test]
fn audit_entries_carry_the_connections_id() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = watcher(&srv, Frontend::Operator);

    let a = minted(&srv, Frontend::Mcp);
    let b = minted(&srv, Frontend::Mcp);
    let a_id = init_id(&srv, &a);
    let b_id = init_id(&srv, &b);
    assert_ne!(a_id, b_id);

    assert!(!is_refused(&call_on(&srv, &a, "demo.read", json!({}))));
    assert!(!is_refused(&call_on(&srv, &b, "demo.read", json!({}))));
    let anon = ConnCtx::new(Frontend::Mcp);
    assert!(!is_refused(&call_on(&srv, &anon, "demo.read", json!({}))));

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 3, "three audited calls: {entries:?}");
    assert_eq!(entries[0].connection_id, Some(a_id));
    assert_eq!(entries[1].connection_id, Some(b_id));
    assert_eq!(entries[2].connection_id, None);

    let lines = agent_lines(&op);
    assert_eq!(lines.len(), 3, "three pushed lines: {lines:?}");
    for (line, entry) in lines.iter().zip(&entries) {
        assert_eq!(
            line["params"]["connection_id"],
            json!(entry.connection_id),
            "the pushed line carries the entry's id: {line}"
        );
    }
    assert!(lines[0]["params"]["connection_id"].is_string());
    assert!(lines[1]["params"]["connection_id"].is_string());
    assert!(lines[2]["params"]["connection_id"].is_null());
}

/// AC9: two servers each count connections from 1, so the raw counter collides;
/// the per-server salt keeps their ids apart.
#[test]
fn connection_ids_are_distinct_across_servers() {
    let one = server();
    let two = server();
    let a = minted(&one, Frontend::Mcp);
    let b = minted(&two, Frontend::Mcp);
    assert_eq!(a.conn_id, 1);
    assert_eq!(b.conn_id, 1);
    assert_ne!(
        init_id(&one, &a),
        init_id(&two, &b),
        "the same conn_id on two servers must not render the same id"
    );
}

/// AC10: nothing a request carries reaches the id. A forged `connection_id` in
/// `clientInfo`, in `_meta` and at the top of the params, and a forged client
/// label, change neither the `initialize` id nor the id the connection's audit
/// entries carry.
#[test]
fn forged_claims_never_change_the_connection_id() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = ConnCtx {
        client_label: Some("conn_victim".into()),
        ..minted(&srv, Frontend::Mcp)
    };

    let plain = init_id(&srv, &conn);
    let forged = initialize_on(
        &srv,
        &conn,
        json!({
            "clientInfo": {"name": "conn_victim", "connection_id": "conn_victim"},
            "_meta": {"connection_id": "conn_victim"},
            "connection_id": "conn_victim",
        }),
    );
    let forged_id = forged["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("connection_id is a string: {forged}"));
    assert_ne!(forged_id, "conn_victim");
    assert_eq!(forged_id, plain);

    assert!(!is_refused(&call_on(&srv, &conn, "demo.read", json!({}))));
    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].connection_id.as_deref(), Some(plain.as_str()));
    assert_eq!(entries[0].client_label.as_deref(), Some("conn_victim"));
}

// ------------- connection id reaches CommandHost (plan 2026-10-30-bus-audit-connection-id, T7)

/// `demo.connection`: reports the host's server-assigned connection id (`<none>`
/// when the call came over no streaming connection), so a test can prove
/// `run_tool` plumbs `McpServer::connection_id` into `CommandHost`.
struct ConnectionIdCmd;

impl Command for ConnectionIdCmd {
    fn name(&self) -> &str {
        "demo.connection"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Names the connection's server-assigned id.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str(host.connection_id().unwrap_or("<none>").into()))
    }
}

/// A stdio-configured server whose registry carries only `demo.connection`.
fn connection_server() -> McpServer {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(ConnectionIdCmd));
    McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_agent_state(ungated())
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
}

/// AC15 (plumbing): a command sees the id the server assigned to the calling
/// connection, the same one `initialize` returned, and sees none when the call
/// came over no streaming connection.
#[test]
fn command_host_carries_the_connection_id() {
    let srv = connection_server();

    let conn = minted(&srv, Frontend::Mcp);
    let id = init_id(&srv, &conn);
    let reply = call_on(&srv, &conn, "demo.connection", json!({}));
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!(id),
        "the command sees the id initialize returned: {reply}"
    );

    let anon = ConnCtx::new(Frontend::Mcp);
    let reply = call_on(&srv, &anon, "demo.connection", json!({}));
    assert_eq!(
        reply["result"]["structuredContent"],
        json!("<none>"),
        "no streaming connection, no id: {reply}"
    );
}

// ------------- role-filtered audit push (plan 2026-10-30-bus-audit-connection-id, T9)

/// AC12: an agent-role subscriber never receives an operator-origin audit line,
/// while an operator subscriber receives every line, in order. The filter is
/// the shared `AuditEntry::visible_to`, applied per subscription inside the
/// fan-out, so the line is still rendered once.
#[test]
fn an_agent_subscriber_never_receives_operator_audit_lines() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = watcher(&srv, Frontend::Operator);
    let agent = watcher(&srv, Frontend::Mcp);

    assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    assert!(!is_refused(&call_on(&srv, &agent, "demo.read", json!({}))));

    let op_lines = agent_lines(&op);
    let op_origins: Vec<&str> = op_lines
        .iter()
        .map(|l| l["params"]["origin"].as_str().expect("origin is a string"))
        .collect();
    assert_eq!(
        op_origins,
        ["operator", "mcp"],
        "the operator sees both lines: {op_lines:?}"
    );

    let agent_seen = agent_lines(&agent);
    assert_eq!(
        agent_seen.len(),
        1,
        "the agent sees only its own line: {agent_seen:?}"
    );
    assert_eq!(agent_seen[0]["params"]["origin"], json!("mcp"));
    assert_eq!(
        agent_seen[0]["params"]["connection_id"],
        json!(init_id(&srv, &agent)),
        "and it is the agent's own line: {agent_seen:?}"
    );

    assert_eq!(
        ring.recent(None, None).len(),
        2,
        "the ring is never filtered, only the push"
    );
}

// ------------- role-filtered agent.activity (plan 2026-10-30-bus-audit-connection-id, T10)

/// The `(command, origin)` of each entry in an `agent.activity` reply, oldest
/// first; panics if the reply is not an array of entries.
fn activity_rows(reply: &JsonValue) -> Vec<(String, String)> {
    reply["result"]["structuredContent"]
        .as_array()
        .unwrap_or_else(|| panic!("agent.activity returns an array: {reply}"))
        .iter()
        .map(|e| {
            (
                e["command"].as_str().expect("command is a string").into(),
                e["origin"].as_str().expect("origin is a string").into(),
            )
        })
        .collect()
}

/// AC13: `agent.activity` is callable by any role but returns only what the
/// caller may see. An agent never reads operator-origin entries, and its `limit`
/// counts the entries it can see (the operator's newest entry is skipped, not
/// returned and not an empty result); the operator reads everything.
#[test]
fn agent_activity_hides_trusted_control_entries_from_agents() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = minted(&srv, Frontend::Operator);
    let agent = minted(&srv, Frontend::Mcp);

    assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    assert!(!is_refused(&call_on(&srv, &agent, "demo.read", json!({}))));

    // The agent sees one entry: its own demo.read. The two operator entries are
    // in the ring but not in its view.
    let rows = activity_rows(&call_on(&srv, &agent, "agent.activity", json!({})));
    assert_eq!(rows.len(), 1, "the agent sees only its own entry: {rows:?}");
    assert_eq!(rows, [("demo.read".to_string(), "mcp".to_string())]);

    // The operator sees all four: its two reads, the agent's read, and the
    // agent's own agent.activity call (audited when it returned).
    let rows = activity_rows(&call_on(&srv, &op, "agent.activity", json!({})));
    let origins: Vec<&str> = rows.iter().map(|(_, o)| o.as_str()).collect();
    assert_eq!(
        origins,
        ["operator", "operator", "mcp", "mcp"],
        "the operator sees every entry: {rows:?}"
    );

    // The operator's agent.activity is now the newest ring entry. An agent
    // asking for the last one gets the last it may see: its own earlier
    // agent.activity call, not the operator's.
    let rows = activity_rows(&call_on(
        &srv,
        &agent,
        "agent.activity",
        json!({"limit": 1}),
    ));
    assert_eq!(
        rows,
        [("agent.activity".to_string(), "mcp".to_string())],
        "limit counts visible entries, never the operator's"
    );

    assert_eq!(
        ring.recent(None, None).len(),
        6,
        "the ring itself is never filtered, only the read"
    );
}

// ------------- role-filtered agent.status count (plan 2026-10-30-bus-audit-connection-id, T11)

/// `actions_last_minute` from an `agent.status` reply; panics, quoting the reply,
/// if the call did not return a status object (a refusal or a protocol error).
fn actions_last_minute(reply: &JsonValue) -> i64 {
    reply["result"]["structuredContent"]["actions_last_minute"]
        .as_i64()
        .unwrap_or_else(|| panic!("agent.status returns actions_last_minute: {reply}"))
}

/// AC14: `actions_last_minute` is the count of what the caller may see. An agent
/// does not count the operator's entries (they are in the ring, not in its view);
/// the operator counts every entry. An entry is recorded after its call returns,
/// so a call never counts itself.
#[test]
fn agent_status_counts_only_what_the_caller_may_see() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = minted(&srv, Frontend::Operator);
    let a = minted(&srv, Frontend::Mcp);
    let b = minted(&srv, Frontend::Mcp);

    for _ in 0..4 {
        assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    }
    for _ in 0..3 {
        assert!(!is_refused(&call_on(&srv, &a, "demo.read", json!({}))));
    }
    assert_eq!(ring.len(), 7, "4 operator entries and A's 3");

    // B has made no call yet. Its view of the ring is A's three entries; the
    // operator's four are hidden, so the count is 3 and not 7.
    let reply = call_on(&srv, &b, "agent.status", json!({}));
    assert!(!is_refused(&reply), "B reads agent.status: {reply}");
    assert_eq!(
        actions_last_minute(&reply),
        3,
        "an agent counts only agent entries: {reply}"
    );
    assert_eq!(ring.len(), 8, "B's agent.status was recorded after it ran");

    // The operator sees everything: its 4, A's 3 and B's agent.status.
    let reply = call_on(&srv, &op, "agent.status", json!({}));
    assert!(
        !is_refused(&reply),
        "the operator reads agent.status: {reply}"
    );
    assert_eq!(
        actions_last_minute(&reply),
        8,
        "a trusted-control caller counts every entry: {reply}"
    );
}

/// AC15: `exclude_self: true` drops exactly the caller's own connection from its
/// own count; it never lowers anyone else's, a caller with no connection id has
/// nothing to exclude, and a non-boolean value is the ordinary `-32602` and is
/// not audited. The schema advertises the optional boolean.
#[test]
fn agent_status_exclude_self_skips_only_the_callers_connection() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let a = minted(&srv, Frontend::Mcp);
    let b = minted(&srv, Frontend::Mcp);

    for _ in 0..3 {
        assert!(!is_refused(&call_on(&srv, &a, "demo.read", json!({}))));
    }
    for _ in 0..2 {
        assert!(!is_refused(&call_on(&srv, &b, "demo.read", json!({}))));
    }
    assert_eq!(ring.len(), 5, "A's 3 and B's 2");

    // 5 agent entries, A's own 3 excluded.
    let reply = call_on(&srv, &a, "agent.status", json!({"exclude_self": true}));
    assert!(!is_refused(&reply), "exclude_self is accepted: {reply}");
    assert_eq!(actions_last_minute(&reply), 2, "B's two only: {reply}");
    assert_eq!(ring.len(), 6);

    // Without the flag, A counts its own entries too: 5 plus its previous status.
    let reply = call_on(&srv, &a, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 6, "off by default: {reply}");
    assert_eq!(ring.len(), 7);

    // A call with no streaming connection has no id of its own, so nothing is
    // excluded: the count can only err toward more.
    let anon = ConnCtx::new(Frontend::Mcp);
    let reply = call_on(&srv, &anon, "agent.status", json!({"exclude_self": true}));
    assert_eq!(
        actions_last_minute(&reply),
        7,
        "no own id, nothing excluded: {reply}"
    );
    assert_eq!(ring.len(), 8);

    // A wrongly typed flag is the schema's ordinary invalid-params error; the
    // command never ran, so nothing is recorded.
    let reply = call_on(&srv, &a, "agent.status", json!({"exclude_self": "yes"}));
    assert_eq!(
        reply["error"]["code"],
        json!(-32602),
        "a non-boolean exclude_self is invalid params: {reply}"
    );
    assert_eq!(ring.len(), 8, "a protocol error is not audited");

    // tools/list advertises the optional boolean.
    let list = rpc(&srv, 1, "tools/list", json!({}));
    let tool = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "agent.status")
        .expect("agent.status is listed");
    assert_eq!(
        tool["inputSchema"]["properties"]["exclude_self"]["type"],
        json!("boolean"),
        "exclude_self is a boolean property: {tool}"
    );
    let required = tool["inputSchema"]["required"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !required.iter().any(|r| r == "exclude_self"),
        "exclude_self is optional: {tool}"
    );
}

/// `(command, origin)` of every `notifications/aitm/agent` line in `conn`'s sink,
/// oldest first; drains the sink.
fn agent_line_pairs(conn: &ConnCtx) -> Vec<(String, String)> {
    agent_lines(conn)
        .iter()
        .map(|l| {
            (
                l["params"]["command"]
                    .as_str()
                    .expect("command is a string")
                    .to_string(),
                l["params"]["origin"]
                    .as_str()
                    .expect("origin is a string")
                    .to_string(),
            )
        })
        .collect()
}

fn pair(command: &str, origin: &str) -> (String, String) {
    (command.to_string(), origin.to_string())
}

/// `fanout_audit` sends each line once per *connection*, however many
/// subscriptions the connection holds. AC12 subscribes each watcher once, so a
/// `fanout_audit` that lost its `seen` dedup (one line per subscription) passes
/// it; here each connection holds three subscriptions and must still get one line.
/// The agent's three subscriptions also get zero lines for an operator call, not
/// three.
#[test]
fn an_audit_line_is_delivered_once_per_connection_however_many_subscriptions_it_holds() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = watcher(&srv, Frontend::Operator);
    let agent = watcher(&srv, Frontend::Mcp);
    for conn in [&op, &agent] {
        for _ in 0..2 {
            let reply = call_on(&srv, conn, "flow.subscribe", json!({}));
            assert!(
                !is_refused(&reply),
                "an extra subscription is accepted: {reply}"
            );
        }
    }

    // An agent call is visible to both roles: one line each, not three.
    assert!(!is_refused(&call_on(&srv, &agent, "demo.read", json!({}))));
    assert_eq!(agent_line_pairs(&op), [pair("demo.read", "mcp")]);
    assert_eq!(agent_line_pairs(&agent), [pair("demo.read", "mcp")]);

    // An operator call reaches the operator once and the agent not at all.
    assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    assert_eq!(agent_line_pairs(&op), [pair("demo.read", "operator")]);
    assert_eq!(agent_line_pairs(&agent), Vec::<(String, String)>::new());
}

/// A refused `flow.subscribe` is audited like any refusal, under the server-assigned
/// id of the connection that made it, and the audit fan-out routes it by role: the
/// operator receives it under that id, while the agent-role connections, its author
/// and a peer, are muted for as long as the policy is `paused` (agent policy
/// revocation, PR 166: a refused subscribe only happens under `paused`), so neither
/// is sent it. The pre-existing refusal test calls with no streaming connection
/// (id `None`) and has no watchers, so it cannot see a refusal line lose its id or
/// be dropped from a role's stream.
#[test]
fn a_refused_subscribe_is_audited_under_its_callers_id_and_fanned_by_role() {
    let ring = Arc::new(AuditRing::default());
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        AgentPlugin::new(state.clone()).with_audit_ring(ring.clone()),
    ));
    let srv = McpServer::new(Arc::new(reg), McpTransport::Stdio)
        .with_services(
            Arc::new(MemFlowStore::new()),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
        .with_agent_state(state.clone())
        .with_audit_ring(ring.clone());

    // All three subscribe while the policy still allows it (a successful subscribe
    // is not audited, so the ring is still empty afterwards).
    let op = watcher(&srv, Frontend::Operator);
    let peer = watcher(&srv, Frontend::Mcp);
    let author = watcher(&srv, Frontend::Mcp);
    let author_id = init_id(&srv, &author);
    assert_eq!(ring.len(), 0);

    state.set_policy(AgentPolicy::Paused);
    let reply = call_on(&srv, &author, "flow.subscribe", json!({}));
    assert!(
        is_refused(&reply),
        "an agent subscribe is refused under Paused: {reply}"
    );

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1, "the refusal is audited once: {entries:?}");
    assert_eq!(entries[0].command, "flow.subscribe");
    assert_eq!(entries[0].origin, Frontend::Mcp);
    assert_eq!(
        entries[0].connection_id.as_deref(),
        Some(author_id.as_str()),
        "the refusal carries the id its client was told at initialize"
    );
    assert!(
        matches!(entries[0].result, aitm_core::AuditResult::Error(_)),
        "the entry records a refusal: {:?}",
        entries[0]
    );

    for (who, conn, delivered) in [
        ("operator", &op, true),
        ("peer agent", &peer, false),
        ("author", &author, false),
    ] {
        let lines = agent_lines(conn);
        if !delivered {
            assert!(
                lines.is_empty(),
                "the {who} is muted while the policy is Paused: {lines:?}"
            );
            continue;
        }
        assert_eq!(
            lines.len(),
            1,
            "the {who} receives the refusal line: {lines:?}"
        );
        let params = &lines[0]["params"];
        assert_eq!(
            params["command"],
            json!("flow.subscribe"),
            "{who}: {params}"
        );
        assert_eq!(params["origin"], json!("mcp"), "{who}: {params}");
        assert_eq!(params["connection_id"], json!(author_id), "{who}: {params}");
        assert!(params["result"]["error"].is_string(), "{who}: {params}");
    }
}

/// `actions_last_minute` is a one-minute window. The AC14/AC15 tests record every
/// entry just now, so an `agent.status` that dropped the window (or widened it)
/// still passes them; here two entries are two minutes old and one is thirty
/// seconds old. The old ones count for no viewer and the recent one counts for the
/// agent that may see it.
#[test]
fn agent_status_counts_only_the_last_minute() {
    use aitm_core::AuditSink as _;
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let aged = |origin: Frontend, command: &str, age_secs: u64| aitm_core::AuditEntry {
        at: SystemTime::now() - Duration::from_secs(age_secs),
        origin,
        client_label: None,
        connection_id: None,
        command: command.to_string(),
        args_summary: "{}".to_string(),
        result: aitm_core::AuditResult::Ok,
    };
    ring.append(aged(Frontend::Mcp, "old-agent", 120));
    ring.append(aged(Frontend::Operator, "old-operator", 120));
    ring.append(aged(Frontend::Mcp, "recent-agent", 30));
    let agent = minted(&srv, Frontend::Mcp);
    let op = minted(&srv, Frontend::Operator);

    // The agent: only the 30-second-old entry is in the window.
    let reply = call_on(&srv, &agent, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 1, "{reply}");
    // The operator: that entry and the agent's status call just recorded; the two
    // two-minute-old entries are out for it too.
    let reply = call_on(&srv, &op, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 2, "{reply}");
    // The agent again: still its own two, never the operator's status call.
    let reply = call_on(&srv, &agent, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 2, "{reply}");
}

/// `exclude_self: false` is "off", exactly like absent, and the flag is per caller.
/// AC15 passes `true` and absent but never an explicit `false`, so an `invoke` that
/// excluded whenever the key was merely present would pass it. B's own
/// `exclude_self: true` leaves out B's calls and counts A's.
#[test]
fn agent_status_exclude_self_false_counts_everything() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let a = minted(&srv, Frontend::Mcp);
    let b = minted(&srv, Frontend::Mcp);
    for _ in 0..3 {
        assert!(!is_refused(&call_on(&srv, &a, "demo.read", json!({}))));
    }
    for _ in 0..2 {
        assert!(!is_refused(&call_on(&srv, &b, "demo.read", json!({}))));
    }

    // A, explicit false: all five entries count, A's own three included.
    let reply = call_on(&srv, &a, "agent.status", json!({"exclude_self": false}));
    assert_eq!(
        actions_last_minute(&reply),
        5,
        "false excludes nothing: {reply}"
    );

    // B, true: A's three reads and A's status call count; B's two reads do not.
    let reply = call_on(&srv, &b, "agent.status", json!({"exclude_self": true}));
    assert_eq!(
        actions_last_minute(&reply),
        4,
        "B leaves out only B: {reply}"
    );
}

/// Malformed `exclude_self`, and the forging attempts the new surface invites: every
/// non-boolean is `-32602` (no truthy coercion of `1`, `"true"`, `null`), and a
/// caller cannot name a connection to leave out, nor filter `agent.activity` by one:
/// the id is server-assigned and read-only for a client. A refused call is a
/// protocol error, so none of these is audited.
#[test]
fn agent_status_refuses_a_non_boolean_exclude_self_and_any_connection_it_is_told_to_name() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let a = minted(&srv, Frontend::Mcp);
    let b = minted(&srv, Frontend::Mcp);
    let b_id = init_id(&srv, &b);
    assert!(!is_refused(&call_on(&srv, &a, "demo.read", json!({}))));
    let before = ring.len();

    for bad in [
        json!(1),
        json!(0),
        json!(null),
        json!("true"),
        json!("false"),
        json!([]),
        json!({}),
    ] {
        let reply = call_on(
            &srv,
            &a,
            "agent.status",
            json!({"exclude_self": bad.clone()}),
        );
        assert_eq!(
            reply["error"]["code"],
            json!(-32602),
            "exclude_self {bad} must be invalid params: {reply}"
        );
    }
    for args in [
        json!({"connection_id": b_id}),
        json!({"exclude_self": true, "connection_id": b_id}),
        json!({"exclude_connection": b_id}),
    ] {
        let reply = call_on(&srv, &a, "agent.status", args.clone());
        assert_eq!(
            reply["error"]["code"],
            json!(-32602),
            "agent.status {args} must not accept a named connection: {reply}"
        );
    }
    let reply = call_on(&srv, &a, "agent.activity", json!({"connection_id": b_id}));
    assert_eq!(
        reply["error"]["code"],
        json!(-32602),
        "agent.activity takes no connection filter: {reply}"
    );
    assert_eq!(ring.len(), before, "protocol errors are not audited");
}

/// AC10 forges the id inside `initialize`; the id is stamped when a `tools/call`
/// is audited, so forge it there: `_meta`, a top-level `connection_id`, a label and
/// an `origin` in the call's params change nothing about the entry, and the same
/// claim as a tool argument is refused by the schema instead of being stored.
#[test]
fn forged_tools_call_fields_never_set_the_entrys_connection_id_label_or_origin() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let conn = minted(&srv, Frontend::Mcp);
    let id = init_id(&srv, &conn);

    let forged = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "demo.read", "arguments": {},
        "_meta": {"connection_id": "conn_victim", "client_label": "victim", "origin": "operator"},
        "connection_id": "conn_victim", "client_label": "victim", "origin": "operator"}});
    let reply: JsonValue = serde_json::from_str(
        &srv.handle_on(&conn, &forged.to_string())
            .expect("a tools/call gets a reply"),
    )
    .expect("json");
    assert!(
        !is_refused(&reply) && reply.get("error").is_none(),
        "the extra fields are ignored, not an error: {reply}"
    );

    let reply = call_on(
        &srv,
        &conn,
        "demo.read",
        json!({"connection_id": "conn_victim"}),
    );
    assert_eq!(
        reply["error"]["code"],
        json!(-32602),
        "an argument named connection_id is refused: {reply}"
    );

    let entries = ring.recent(None, None);
    assert_eq!(entries.len(), 1, "only the first call ran: {entries:?}");
    assert_eq!(entries[0].connection_id.as_deref(), Some(id.as_str()));
    assert_eq!(entries[0].client_label, None);
    assert_eq!(entries[0].origin, Frontend::Mcp);
}

/// Drive `requests` through the real [`aitm_mcp::transport::serve_lines`] loop on a
/// fresh in-memory pipe, as a connection the transport has not numbered yet
/// (`conn_id == 0`, which is how `serve_stdio` and the TCP listener hand it over),
/// and return one reply per request, in order. Nothing subscribes, so no
/// notification interleaves with the replies.
async fn serve_lines_exchange(srv: &Arc<McpServer>, requests: Vec<JsonValue>) -> Vec<JsonValue> {
    let (client_side, server_side) = tokio::io::duplex(256 * 1024);
    let (srv_r, srv_w) = tokio::io::split(server_side);
    let task = tokio::spawn(aitm_mcp::transport::serve_lines(
        srv.clone(),
        BufReader::new(srv_r),
        srv_w,
        ConnCtx::new(srv.stdio_role()),
    ));
    let (cli_r, mut cli_w) = tokio::io::split(client_side);
    let mut lines = BufReader::new(cli_r).lines();
    let mut payload = String::new();
    for request in &requests {
        payload.push_str(&request.to_string());
        payload.push('\n');
    }
    cli_w.write_all(payload.as_bytes()).await.expect("write");
    let mut replies = Vec::new();
    for _ in &requests {
        let line = lines
            .next_line()
            .await
            .expect("io")
            .expect("one reply per request");
        replies.push(serde_json::from_str(&line).expect("a reply is JSON"));
    }
    cli_w.shutdown().await.expect("shutdown");
    task.await.expect("join").expect("loop ends cleanly at EOF");
    replies
}

/// The transport path, not just `handle_on`: `serve_lines` numbers a fresh
/// connection (`conn_id` 0 becomes a minted one), so its `initialize` reports a
/// non-null id that a repeated or forged `initialize` and a later call all agree
/// on, and a second connection to the same server gets a different one. The
/// in-process tests hand `handle_on` a pre-numbered `ConnCtx`, so a `serve_lines`
/// that stopped numbering connections (every id `null`) passes all of them.
#[tokio::test]
async fn serve_lines_numbers_each_connection_and_stamps_its_id_on_its_entries() {
    let ring = Arc::new(AuditRing::default());
    let srv = Arc::new(audit_server(ring.clone()));
    let init = |id: u64, params: JsonValue| json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": params});
    let read = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "demo.read", "arguments": {}}})
    };
    let forged = json!({
        "clientInfo": {"name": "conn_victim", "connection_id": "conn_victim"},
        "_meta": {"connection_id": "conn_victim"},
        "connection_id": "conn_victim",
    });

    // Connection one: initialize, a forged re-initialize, a call, initialize again.
    let one = serve_lines_exchange(
        &srv,
        vec![
            init(1, json!({})),
            init(2, forged),
            read(3),
            init(4, json!({})),
        ],
    )
    .await;
    let id_one = one[0]["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("serve_lines numbered the connection: {}", one[0]))
        .to_string();
    assert_ne!(id_one, "conn_victim");
    assert_eq!(
        one[1]["result"]["connection_id"],
        json!(id_one),
        "forged initialize"
    );
    assert_eq!(
        one[3]["result"]["connection_id"],
        json!(id_one),
        "initialize after a call"
    );

    // Connection two on the same server.
    let two = serve_lines_exchange(&srv, vec![init(1, json!({})), read(2)]).await;
    let id_two = two[0]["result"]["connection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("serve_lines numbered the second connection: {}", two[0]))
        .to_string();
    assert_ne!(id_one, id_two, "two connections, two ids");

    let entries = ring.recent(None, None);
    assert_eq!(
        entries.len(),
        2,
        "one demo.read per connection: {entries:?}"
    );
    assert_eq!(entries[0].connection_id.as_deref(), Some(id_one.as_str()));
    assert_eq!(entries[1].connection_id.as_deref(), Some(id_two.as_str()));
    // The forged name became a label (a label is not an identity), capped; the id
    // is untouched.
    assert_eq!(entries[0].client_label.as_deref(), Some("conn_victim"));
    assert_eq!(entries[1].client_label, None);
}

/// Every trusted-control role reads the whole ring by every surface, and no agent
/// reads the CLI's entries either (the AC tests exercise the operator only).
/// Sequence and the ring after each call: operator read (1), agent read (2), CLI
/// read (3), CLI `agent.activity` (4), CLI `agent.status` (5), agent
/// `agent.activity` (6), agent `agent.status` (7).
#[test]
fn the_cli_reads_the_whole_ring_by_every_surface_and_no_agent_reads_the_clis_entries() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let op = minted(&srv, Frontend::Operator);
    let cli = minted(&srv, Frontend::Cli);
    let agent = minted(&srv, Frontend::Mcp);
    let cli_watch = watcher(&srv, Frontend::Cli);
    let agent_watch = watcher(&srv, Frontend::Mcp);

    for conn in [&op, &agent, &cli] {
        assert!(!is_refused(&call_on(&srv, conn, "demo.read", json!({}))));
    }

    // The CLI reads all three entries, whatever their origin.
    let rows = activity_rows(&call_on(&srv, &cli, "agent.activity", json!({})));
    assert_eq!(
        rows,
        [
            pair("demo.read", "operator"),
            pair("demo.read", "mcp"),
            pair("demo.read", "cli"),
        ]
    );
    // And counts four: the three reads and its own agent.activity.
    let reply = call_on(&srv, &cli, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 4, "{reply}");

    // The agent reads only its own read, not the operator's nor the CLI's entries,
    // and counts its read plus its own agent.activity.
    let rows = activity_rows(&call_on(&srv, &agent, "agent.activity", json!({})));
    assert_eq!(rows, [pair("demo.read", "mcp")]);
    let reply = call_on(&srv, &agent, "agent.status", json!({}));
    assert_eq!(actions_last_minute(&reply), 2, "{reply}");

    // Pushed: the CLI's subscription got all seven lines; the agent's got its own
    // three and never an operator or CLI line.
    assert_eq!(
        agent_line_pairs(&cli_watch),
        [
            pair("demo.read", "operator"),
            pair("demo.read", "mcp"),
            pair("demo.read", "cli"),
            pair("agent.activity", "cli"),
            pair("agent.status", "cli"),
            pair("agent.activity", "mcp"),
            pair("agent.status", "mcp"),
        ]
    );
    assert_eq!(
        agent_line_pairs(&agent_watch),
        [
            pair("demo.read", "mcp"),
            pair("agent.activity", "mcp"),
            pair("agent.status", "mcp"),
        ]
    );
    assert_eq!(ring.len(), 7, "the ring holds everything, for every viewer");
}

/// A recording stand-in for the durable JSONL sink.
#[derive(Default)]
struct RecordingSink(std::sync::Mutex<Vec<aitm_core::AuditEntry>>);

impl aitm_core::AuditSink for RecordingSink {
    fn append(&self, entry: aitm_core::AuditEntry) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
    }
}

/// The durable sink is never filtered: it records the operator's entry as well as
/// the agent's, each with its connection id, in call order, even though an agent
/// cannot read the operator's entry from the ring or the stream. The AC tests assert
/// the ring is whole; a role filter moved from the read side into `record_audit`
/// (so the durable log lost the operator's lines) passes all of them.
#[test]
fn the_durable_audit_sink_keeps_every_entry_even_those_an_agent_may_not_read() {
    let ring = Arc::new(AuditRing::default());
    let sink = Arc::new(RecordingSink::default());
    let srv = audit_server(ring.clone()).with_durable_audit(sink.clone());
    let op = minted(&srv, Frontend::Operator);
    let agent = minted(&srv, Frontend::Mcp);
    let op_id = init_id(&srv, &op);
    let agent_id = init_id(&srv, &agent);

    assert!(!is_refused(&call_on(&srv, &op, "demo.read", json!({}))));
    assert!(!is_refused(&call_on(&srv, &agent, "demo.read", json!({}))));

    let durable = sink
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        durable
            .iter()
            .map(|e| aitm_core::origin_label(e.origin))
            .collect::<Vec<_>>(),
        ["operator", "mcp"]
    );
    assert_eq!(
        durable
            .iter()
            .map(|e| e.connection_id.clone())
            .collect::<Vec<_>>(),
        [Some(op_id), Some(agent_id)]
    );
    // The agent's own view of the same history is only its entry.
    let seen_by_agent = ring.recent_for(Frontend::Mcp, None, None);
    assert_eq!(seen_by_agent.len(), 1);
    assert_eq!(seen_by_agent[0].command, "demo.read");
}

/// A subscriber whose socket went away (its sink closed) or whose connection ended
/// (its subscriptions dropped) neither stops the fan-out from reaching the
/// subscribers after it in the registry nor hears a later line. The dead operator
/// connection subscribed first, so the loop reaches it before the live ones. This is
/// a regression guard for `fanout_audit` (no current-code mutation but an abort at a
/// dead subscriber fails it).
#[test]
fn a_closed_or_dropped_subscriber_neither_starves_the_others_nor_hears_further_lines() {
    let ring = Arc::new(AuditRing::default());
    let srv = audit_server(ring.clone());
    let closed = watcher(&srv, Frontend::Operator);
    let dropped = watcher(&srv, Frontend::Mcp);
    let live_agent = watcher(&srv, Frontend::Mcp);
    let live_op = watcher(&srv, Frontend::Operator);

    // The transport's writer task closes the sink when the client goes away; the
    // read loop drops the connection's subscriptions when its stream ends.
    closed.out.as_ref().expect("a watcher has a sink").close();
    srv.drop_connection(dropped.conn_id);

    let caller = minted(&srv, Frontend::Mcp);
    assert!(!is_refused(&call_on(&srv, &caller, "demo.read", json!({}))));

    assert_eq!(agent_line_pairs(&live_agent), [pair("demo.read", "mcp")]);
    assert_eq!(agent_line_pairs(&live_op), [pair("demo.read", "mcp")]);
    assert_eq!(
        agent_line_pairs(&dropped),
        Vec::<(String, String)>::new(),
        "a dropped connection hears nothing further"
    );
}

/// The label cap's call site, end to end, on hostile input. AC11 proves the length
/// cut through `serve_lines`, and `sanitize_client_label` is unit-tested alone, but
/// nothing proves the transport applies the *whole* function: a call site that cut
/// to 64 characters without the control-character and scrub steps passes both. Here a
/// name carrying an ANSI escape and a `token=` secret reaches the command host and
/// the audit entry sanitised. Around it the connection survives malformed input: a
/// message that is not a request object, and `initialize` calls whose name is a
/// number, `null`, absent (`clientInfo` a string) or empty each leave the label
/// unset and the connection serving; the first valid name wins and a later
/// `initialize` cannot relabel the connection.
#[tokio::test]
async fn serve_lines_sanitises_a_hostile_client_name_and_survives_malformed_ones() {
    let ring = Arc::new(AuditRing::default());
    let srv = Arc::new(
        McpServer::new(role_registry(), McpTransport::Stdio)
            .with_agent_state(ungated())
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            )
            .with_audit_ring(ring.clone()),
    );
    let init = |id: u64, client_info: JsonValue| {
        json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": client_info}})
    };
    let label_probe = |id: u64| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "demo.client", "arguments": {}}})
    };

    let replies = serve_lines_exchange(
        &srv,
        vec![
            json!("this is a JSON string, not a request object"),
            init(2, json!({"name": 12345})),
            init(3, json!({"name": null})),
            init(4, json!("just a string")),
            init(5, json!({"name": ""})),
            label_probe(6),
            init(7, json!({"name": "agent\u{1b}[2J token=abc123"})),
            label_probe(8),
            init(9, json!({"name": "second-name"})),
            label_probe(10),
        ],
    )
    .await;

    assert_eq!(
        replies[0]["error"]["code"],
        json!(-32600),
        "a non-object message is an invalid request, not a dropped connection: {}",
        replies[0]
    );
    for (i, reply) in replies.iter().enumerate().skip(1) {
        assert!(
            reply.get("error").is_none(),
            "message {i} is answered, not an error: {reply}"
        );
    }
    let seen = |reply: &JsonValue| reply["result"]["structuredContent"].clone();
    assert_eq!(
        seen(&replies[5]),
        json!("<none>"),
        "no valid name yet: the label is unset"
    );
    // Control character dropped (PR 171's sanitiser deletes it), secret masked,
    // both at the real call site.
    assert_eq!(seen(&replies[7]), json!("agent[2J token=[redacted]"));
    // First valid name wins: a later initialize does not relabel the connection.
    assert_eq!(seen(&replies[9]), json!("agent[2J token=[redacted]"));

    // Every initialize reply names the same connection, never null.
    let ids: Vec<&JsonValue> = [1, 2, 3, 4, 6, 8]
        .iter()
        .map(|&i| &replies[i]["result"]["connection_id"])
        .collect();
    assert!(ids[0].is_string(), "{}", replies[1]);
    assert!(
        ids.iter().all(|id| *id == ids[0]),
        "one connection, one id across every initialize: {ids:?}"
    );

    let labels: Vec<Option<String>> = ring
        .recent(None, None)
        .into_iter()
        .map(|e| e.client_label)
        .collect();
    assert_eq!(
        labels,
        [
            None,
            Some("agent[2J token=[redacted]".to_string()),
            Some("agent[2J token=[redacted]".to_string()),
        ],
        "the audit entries carry the same sanitised label"
    );
}

// ----------------------- agent policy revocation: pushes follow the live policy

/// A registry holding the subscription verbs (so `flow.subscribe` has its
/// published schema) and the real `agent.*` verbs over `state`.
fn rv_registry(state: &Arc<AgentState>) -> Arc<Registry> {
    let (tx, _rx) = broadcast::channel::<Event>(64);
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(SubscriptionPlugin::new(tx)));
    reg.add_plugin(Box::new(AgentPlugin::new(state.clone())));
    Arc::new(reg)
}

/// A stdio-configured server over `registry` with services over `store`, whose
/// policy gate and push mute both read `state`.
fn rv_server(
    registry: Arc<Registry>,
    store: &Arc<MemFlowStore>,
    state: &Arc<AgentState>,
) -> McpServer {
    McpServer::new(registry, McpTransport::Stdio)
        .with_agent_state(state.clone())
        .with_services(
            store.clone(),
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        )
}

/// One server plus the store and the policy state it runs over.
struct RvRig {
    srv: McpServer,
    store: Arc<MemFlowStore>,
    state: Arc<AgentState>,
}

impl RvRig {
    fn new(policy: AgentPolicy) -> Self {
        let state = Arc::new(AgentState::new(policy));
        let store = Arc::new(MemFlowStore::new());
        let srv = rv_server(rv_registry(&state), &store, &state);
        Self { srv, store, state }
    }

    /// Insert a flow for `authority`/`path` and push its `RequestHeaders` event;
    /// returns the flow id as the push renders it.
    fn flow(&self, authority: &str, path: &str) -> String {
        rv_flow(&self.srv, &self.store, authority, path)
    }
}

/// A streaming connection of some role on a server, with its own push sink.
struct RvConn {
    conn: ConnCtx,
    sink: NotificationSink,
}

/// A connection of `role` on `srv` with a fresh `NotificationSink::new(64)`, not
/// yet subscribed.
fn rv_conn(srv: &McpServer, role: Frontend) -> RvConn {
    let sink = NotificationSink::new(64);
    let conn = ConnCtx {
        role,
        client_label: None,
        conn_id: srv.next_conn_id(),
        out: Some(sink.clone()),
    };
    RvConn { conn, sink }
}

/// A connection of `role` on `srv`, subscribed with `args`. The subscribe must be
/// accepted (a `sub_id` comes back): that is test setup, not the thing under test.
fn rv_subscribe(srv: &McpServer, role: Frontend, args: JsonValue) -> RvConn {
    let c = rv_conn(srv, role);
    let reply = subscribe_on(srv, &c.conn, args);
    assert!(
        sub_id_of(&reply) >= 1,
        "setup: the {role:?} subscribe is accepted: {reply}"
    );
    c
}

/// Insert a flow and push its `RequestHeaders` event on `srv`; returns the id.
fn rv_flow(srv: &McpServer, store: &Arc<MemFlowStore>, authority: &str, path: &str) -> String {
    let id = store.insert(http_flow(authority, path));
    srv.push_flow_event(&Event::RequestHeaders(id));
    id.to_string()
}

/// An audit push: an operator `agent.status` call on a separate, sinkless
/// connection. Its audit line is fanned to every subscriber, and the subscriber
/// under test is not the caller.
fn rv_audit(srv: &McpServer) {
    let reply = call_as(srv, Frontend::Operator, "agent.status");
    assert!(
        !is_refused(&reply),
        "setup: the operator's agent.status runs: {reply}"
    );
}

/// An audit push an agent-role subscriber may see: an agent-origin `agent.status`
/// call on a separate, sinkless connection. Its audit line has origin `mcp`, so it
/// is delivered to every agent subscriber (the caller is not the subscriber under
/// test), unlike [`rv_audit`]'s operator line, which an agent is never sent. The
/// policy must allow the call (a Read), so it is not usable under `Paused`.
fn rv_audit_as_agent(srv: &McpServer) {
    let reply = call_as(srv, Frontend::Mcp, "agent.status");
    assert!(
        !is_refused(&reply),
        "setup: the agent's agent.status runs: {reply}"
    );
}

/// Whether `line` is the `lagged` marker: a `notifications/aitm/state` line whose
/// params are exactly `{"lagged": true}`.
fn rv_is_marker(line: &JsonValue) -> bool {
    line["method"] == "notifications/aitm/state" && line["params"] == json!({"lagged": true})
}

/// Drain `sink` and describe each line in one short string, so an assertion and
/// its failure message read as the stream: `marker`, `flow <id>`, `state
/// <params>`, `agent <command>`.
fn rv_drain(sink: &NotificationSink) -> Vec<String> {
    sink.drain()
        .iter()
        .map(|raw| {
            let line: JsonValue = serde_json::from_str(raw)
                .unwrap_or_else(|e| panic!("a pushed line is JSON ({e}): {raw}"));
            if rv_is_marker(&line) {
                return "marker".to_string();
            }
            let params = &line["params"];
            match line["method"].as_str().unwrap_or("?") {
                "notifications/aitm/flow" => {
                    format!("flow {}", params["id"].as_str().unwrap_or("?"))
                }
                "notifications/aitm/state" => format!("state {params}"),
                "notifications/aitm/agent" => {
                    format!("agent {}", params["command"].as_str().unwrap_or("?"))
                }
                other => format!("other {other}"),
            }
        })
        .collect()
}

/// `sink` holds nothing: the drain is `[]`, `queued_len()` is 0, and `lagged()`
/// is false. The three are read in an order that puts the drained lines in the
/// failure message first.
fn rv_assert_silent(sink: &NotificationSink, what: &str) {
    let queued = sink.queued_len();
    let lagged = sink.lagged();
    let drained = rv_drain(sink);
    assert_eq!(
        drained,
        Vec::<String>::new(),
        "{what}: the drain must be empty"
    );
    assert_eq!(queued, 0, "{what}: nothing may be queued");
    assert!(!lagged, "{what}: the sink must not be flagged lagged");
}

/// The `state` line `push_state(json!({"k": 1}))` renders, in `rv_drain` form.
const RV_STATE_LINE: &str = r#"state {"k":1}"#;

/// AC1: under `Paused`, a flow push is not enqueued for an agent subscription.
#[test]
fn revoke_push_paused_mutes_flow_pushes() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    let one = rig.flow("example.com:443", "/one");
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {one}")],
        "under Auto the agent receives the flow push"
    );

    rig.state.set_policy(AgentPolicy::Paused);
    let _two = rig.flow("example.com:443", "/two");
    rv_assert_silent(&agent.sink, "a flow push under Paused");
}

/// AC2: under `Paused`, state and agent (audit) pushes are not enqueued for an
/// agent subscription, while the operator subscription receives both.
#[test]
fn revoke_push_paused_mutes_state_and_agent_pushes() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    let operator = rv_subscribe(&rig.srv, Frontend::Operator, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);

    rig.srv.push_state(json!({"k": 1}));
    rv_audit(&rig.srv);

    rv_assert_silent(
        &agent.sink,
        "a state push and an operator-run audited call under Paused",
    );
    assert_eq!(
        rv_drain(&operator.sink),
        vec![RV_STATE_LINE.to_string(), "agent agent.status".to_string()],
        "the operator still receives the state line and the agent line"
    );
}

/// AC3: operator and CLI subscriptions are never muted, even under `Paused`.
#[test]
fn revoke_push_trusted_control_is_never_muted() {
    for role in [Frontend::Operator, Frontend::Cli] {
        let rig = RvRig::new(AgentPolicy::Paused);
        let conn = rv_subscribe(&rig.srv, role, json!({}));

        let id = rig.flow("example.com:443", "/x");
        rig.srv.push_state(json!({"k": 1}));
        rv_audit(&rig.srv);

        assert_eq!(
            rv_drain(&conn.sink),
            vec![
                format!("flow {id}"),
                RV_STATE_LINE.to_string(),
                "agent agent.status".to_string(),
            ],
            "{role:?} gets flow, state, agent in that order under Paused, and no marker"
        );
    }
}

/// AC4: the behaviour table for every policy, and resume from `Paused` on the
/// same connection and subscription.
#[test]
fn revoke_push_policy_table_and_resume() {
    for policy in [
        AgentPolicy::All,
        AgentPolicy::Auto,
        AgentPolicy::Ask,
        AgentPolicy::ReadOnly,
    ] {
        let rig = RvRig::new(AgentPolicy::Auto);
        let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
        rig.state.set_policy(policy);

        let id = rig.flow("example.com:443", "/x");
        rig.srv.push_state(json!({"k": 1}));
        rv_audit_as_agent(&rig.srv);

        assert_eq!(
            rv_drain(&agent.sink),
            vec![
                format!("flow {id}"),
                RV_STATE_LINE.to_string(),
                "agent agent.status".to_string(),
            ],
            "policy {policy:?}: the agent receives flow, state and agent lines"
        );
    }

    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);
    let _suppressed = rig.flow("example.com:443", "/paused");
    rig.srv.push_state(json!({"k": 1}));
    rv_audit(&rig.srv);
    assert_eq!(
        rv_drain(&agent.sink),
        Vec::<String>::new(),
        "policy Paused: the agent receives none of the three pushes"
    );

    rig.state.set_policy(AgentPolicy::Auto);
    let after = rig.flow("example.com:443", "/after");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {after}")],
        "after resume the same connection and subscription gets the marker, then the flow"
    );
}

/// AC5: one predicate. For every policy, "a fresh `flow.subscribe` is accepted"
/// and "a flow push reaches an already-subscribed agent" are the same answer, and
/// it is `false` only for `Paused`. `Paused` is last on purpose.
#[test]
fn revoke_push_one_predicate_for_subscribe_and_delivery() {
    for (policy, expected) in [
        (AgentPolicy::All, true),
        (AgentPolicy::Auto, true),
        (AgentPolicy::Ask, true),
        (AgentPolicy::ReadOnly, true),
        (AgentPolicy::Paused, false),
    ] {
        let rig = RvRig::new(AgentPolicy::Auto);
        let a = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
        rig.state.set_policy(policy);

        let b = rv_conn(&rig.srv, Frontend::Mcp);
        let accepted = !is_refused(&subscribe_on(&rig.srv, &b.conn, json!({})));
        // A refused subscribe is itself audited and fanned out, so discard what the
        // subscribe attempt put in A's sink: only the flow push below is measured.
        let _ = a.sink.drain();

        let id = rig.flow("example.com:443", "/x");
        let reached = rv_drain(&a.sink).contains(&format!("flow {id}"));

        assert_eq!(
            (accepted, reached),
            (expected, expected),
            "policy {policy:?}: (a fresh subscribe is accepted, a flow push reaches A)"
        );
    }
}

/// AC6: the marker comes exactly once, in front of the first post-gap line, and
/// each agent connection gets its own.
#[test]
fn revoke_push_marker_exactly_once_before_first_post_gap_line() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);
    let _gap = rig.flow("example.com:443", "/gap");
    rig.state.set_policy(AgentPolicy::Auto);

    let first = rig.flow("example.com:443", "/first");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {first}")],
        "the first push after the gap is preceded by exactly one marker"
    );
    let second = rig.flow("example.com:443", "/second");
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {second}")],
        "a further push carries no marker"
    );

    // Two agent connections, both unfiltered: each gets its own marker.
    let rig = RvRig::new(AgentPolicy::Auto);
    let a1 = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    let a2 = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);
    let _gap = rig.flow("example.com:443", "/gap");
    rig.state.set_policy(AgentPolicy::Auto);

    let first = rig.flow("example.com:443", "/first");
    for (name, conn) in [("first", &a1), ("second", &a2)] {
        assert_eq!(
            rv_drain(&conn.sink),
            vec!["marker".to_string(), format!("flow {first}")],
            "the {name} agent connection gets exactly one marker before its first post-gap line"
        );
    }
    let second = rig.flow("example.com:443", "/second");
    for (name, conn) in [("first", &a1), ("second", &a2)] {
        assert_eq!(
            rv_drain(&conn.sink),
            vec![format!("flow {second}")],
            "the {name} agent connection gets no second marker"
        );
    }
}

/// AC7: no marker while the policy is still `Paused`, after each suppressed push
/// and again after a further drain.
#[test]
fn revoke_push_no_marker_while_paused() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);

    let _ = rig.flow("example.com:443", "/x");
    rv_assert_silent(&agent.sink, "after a suppressed flow push");
    rv_assert_silent(&agent.sink, "after a flow push, drained a second time");

    rig.srv.push_state(json!({"k": 1}));
    rv_assert_silent(&agent.sink, "after a suppressed state push");
    rv_assert_silent(&agent.sink, "after a state push, drained a second time");

    rv_audit(&rig.srv);
    rv_assert_silent(&agent.sink, "after a suppressed agent push");
    rv_assert_silent(&agent.sink, "after an agent push, drained a second time");
}

/// AC8(i): `Paused` then `Auto` flipped directly on `AgentState`, with no push in
/// between, suppresses nothing, so there is no marker.
#[test]
fn revoke_push_direct_flip_without_a_suppressed_push_has_no_marker() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    rig.state.set_policy(AgentPolicy::Paused);
    rig.state.set_policy(AgentPolicy::Auto);

    let id = rig.flow("example.com:443", "/x");
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {id}")],
        "nothing was suppressed, so the next push is the flow line alone"
    );
}

/// AC8(ii): a connection whose own subscription matched nothing that was
/// suppressed gets no marker; one that lost a line does.
#[test]
fn revoke_push_connection_with_nothing_suppressed_gets_no_marker() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let a = rv_subscribe(
        &rig.srv,
        Frontend::Mcp,
        json!({"filter": {"host": "a.example"}}),
    );
    let b = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    rig.state.set_policy(AgentPolicy::Paused);
    let _suppressed = rig.flow("b.example:443", "/x");
    assert_eq!(
        rv_drain(&a.sink),
        Vec::<String>::new(),
        "A (host a.example) does not want the b.example flow"
    );
    assert_eq!(
        rv_drain(&b.sink),
        Vec::<String>::new(),
        "B (unfiltered) is muted under Paused"
    );

    rig.state.set_policy(AgentPolicy::Auto);
    let id = rig.flow("a.example:443", "/y");
    assert_eq!(
        rv_drain(&a.sink),
        vec![format!("flow {id}")],
        "A lost nothing, so it gets the flow line and no marker"
    );
    assert_eq!(
        rv_drain(&b.sink),
        vec!["marker".to_string(), format!("flow {id}")],
        "B lost a line, so it gets the marker, then the flow line"
    );
}

/// AC9, amended by the audit-visibility rule (plan 2026-10-30-bus-audit-connection-id,
/// spec A4 and AC31): through the real `agent.set` verb a pause is an audited
/// operator call, and an agent is never sent an operator's audit line, neither
/// while paused nor on resume. A hidden line is not wanted by the agent's
/// subscription, so it is not a suppressed push and records no gap: after the
/// resume the agent's stream is empty, with no marker. (A marker follows only a
/// push the agent may see and was refused, as in the flow-line tests here.)
#[test]
fn revoke_push_real_verb_pause_then_resume_without_a_visible_push_has_no_marker() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    let paused = call_as_args(
        &rig.srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "setup: the operator's agent.set paused ran: {paused}"
    );
    rv_assert_silent(
        &agent.sink,
        "after the operator's agent.set paused (its own audit line is pushed after the flip)",
    );

    let resumed = call_as_args(
        &rig.srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "auto"}),
    );
    assert_eq!(
        resumed["result"]["structuredContent"]["policy"],
        json!("auto"),
        "setup: the operator's agent.set auto ran: {resumed}"
    );
    assert_eq!(
        rv_drain(&agent.sink),
        Vec::<String>::new(),
        "the resume's audit line is the operator's, so it is not delivered and no marker is due"
    );
}

/// AC10: two servers over one registry and one `AgentState` (the `aitm web`
/// topology: P, the primary, and W, the `/bus` server). `agent.set` runs on P; the
/// subscribers of W are muted and resumed, because the policy is read at use.
#[test]
fn revoke_push_cross_server_pause_mutes_the_other_server() {
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    let store = Arc::new(MemFlowStore::new());
    let registry = rv_registry(&state);
    let p = rv_server(registry.clone(), &store, &state);
    let w = rv_server(registry, &store, &state);
    let agent = rv_subscribe(&w, Frontend::Mcp, json!({}));
    let operator = rv_subscribe(&w, Frontend::Operator, json!({}));

    let paused = call_as_args(
        &p,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "setup: agent.set paused ran on P: {paused}"
    );

    let id = rv_flow(&w, &store, "example.com:443", "/x");
    rv_assert_silent(
        &agent.sink,
        "W's agent subscriber after agent.set paused ran on P",
    );
    assert_eq!(
        rv_drain(&operator.sink),
        vec![format!("flow {id}")],
        "W's operator subscriber still gets the flow line"
    );

    let resumed = call_as_args(
        &p,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "auto"}),
    );
    assert_eq!(
        resumed["result"]["structuredContent"]["policy"],
        json!("auto"),
        "setup: agent.set auto ran on P: {resumed}"
    );
    let after = rv_flow(&w, &store, "example.com:443", "/after");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {after}")],
        "after the resume on P, W's agent gets the marker, then the flow line"
    );
}

/// AC12(ii) (pins that lines already queued are not purged): a line enqueued
/// while `Auto` and not yet drained is still returned after the policy goes
/// `Paused`. Nothing is purged.
#[test]
fn revoke_push_queued_lines_are_not_purged() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    let id = rig.flow("example.com:443", "/queued");
    rig.state.set_policy(AgentPolicy::Paused);

    assert_eq!(
        agent.sink.queued_len(),
        1,
        "the line queued under Auto is still queued after the pause"
    );
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {id}")],
        "the line queued under Auto is still delivered by the next drain"
    );
}

// ----------- pushes under pause: bursts, drops, several subs, cycles, full sink, late join

/// A burst of suppressed pushes records one gap, not one per push: after resume
/// the first delivery carries exactly one marker and the next deliveries carry
/// none. (Also pins that nothing accumulates in the sink while paused.)
#[test]
fn revoke_push_a_burst_while_paused_yields_exactly_one_marker() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);

    for n in 0..50 {
        let _ = rig.flow("example.com:443", &format!("/burst/{n}"));
        rig.srv.push_state(json!({ "k": n }));
        rv_audit(&rig.srv);
    }
    rv_assert_silent(&agent.sink, "after a burst of 150 suppressed pushes");

    rig.state.set_policy(AgentPolicy::Auto);
    let first = rig.flow("example.com:443", "/first");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {first}")],
        "the first delivery after the burst is preceded by exactly one marker"
    );
    for n in 0..3 {
        let id = rig.flow("example.com:443", &format!("/next/{n}"));
        assert_eq!(
            rv_drain(&agent.sink),
            vec![format!("flow {id}")],
            "delivery {n} after the marker carries no further marker"
        );
    }
}

/// A connection dropped while it holds a gap (the transport closes its sink, then
/// calls `drop_connection`) is not delivered to, and dropping it does not erase
/// another connection's gap: that one still gets its marker.
#[test]
fn revoke_push_dropping_one_gapped_connection_keeps_the_others_gap() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let gone = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    let stays = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));

    rig.state.set_policy(AgentPolicy::Paused);
    let _gap = rig.flow("example.com:443", "/gap");
    gone.sink.close();
    rig.srv.drop_connection(gone.conn.conn_id);

    rig.state.set_policy(AgentPolicy::Auto);
    let id = rig.flow("example.com:443", "/after");
    assert_eq!(
        rv_drain(&stays.sink),
        vec!["marker".to_string(), format!("flow {id}")],
        "the surviving connection still gets its marker, then the flow"
    );
    assert_eq!(
        rv_drain(&gone.sink),
        Vec::<String>::new(),
        "the dropped connection is not delivered to"
    );
}

/// Several subscriptions on one connection are still one connection: one gap, one
/// marker, and one copy of the line, however many of them match. A subscription
/// that does not want a line does not stop a later one on the same connection
/// from taking it.
#[test]
fn revoke_push_several_subscriptions_on_one_connection_get_one_marker_and_one_line() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_conn(&rig.srv, Frontend::Mcp);
    for args in [
        json!({"filter": {"host": "a.example"}}),
        json!({"filter": {"host": "b.example"}}),
        json!({}),
    ] {
        let reply = subscribe_on(&rig.srv, &agent.conn, args.clone());
        assert!(
            sub_id_of(&reply) >= 1,
            "setup: subscribe {args} is accepted: {reply}"
        );
    }

    rig.state.set_policy(AgentPolicy::Paused);
    let _gap = rig.flow("b.example:443", "/gap");
    rv_assert_silent(&agent.sink, "three subscriptions under Paused");

    rig.state.set_policy(AgentPolicy::Auto);
    let after = rig.flow("b.example:443", "/after");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {after}")],
        "a flow matched by two of the three subscriptions is one line, behind one marker"
    );
    let next = rig.flow("a.example:443", "/next");
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {next}")],
        "no second marker, and again one line"
    );
}

/// The marker rides the first *delivery*, not the first push: a connection that
/// lost a `b.example` flow gets nothing, and no marker, for a later flow it does
/// not want, and the marker for the first one it does.
#[test]
fn revoke_push_marker_waits_for_a_delivery_not_just_a_push() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(
        &rig.srv,
        Frontend::Mcp,
        json!({"filter": {"host": "b.example"}}),
    );

    rig.state.set_policy(AgentPolicy::Paused);
    let _lost = rig.flow("b.example:443", "/lost");
    rig.state.set_policy(AgentPolicy::Auto);

    let _unwanted = rig.flow("a.example:443", "/unwanted");
    rv_assert_silent(&agent.sink, "a flow the filter does not want, after resume");

    let wanted = rig.flow("b.example:443", "/wanted");
    assert_eq!(
        rv_drain(&agent.sink),
        vec!["marker".to_string(), format!("flow {wanted}")],
        "the first flow the filter wants carries the marker for the one that was lost"
    );
}

/// Pause and resume more than once, with three agent connections: every cycle
/// marks every connection exactly once (the gap is cleared by a delivery and
/// recorded afresh by the next suppression, whatever order the records are in).
#[test]
fn revoke_push_each_pause_resume_cycle_marks_every_agent_once() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agents: Vec<RvConn> = (0..3)
        .map(|_| rv_subscribe(&rig.srv, Frontend::Mcp, json!({})))
        .collect();

    for cycle in 0..3 {
        rig.state.set_policy(AgentPolicy::Paused);
        let _lost = rig.flow("example.com:443", &format!("/lost/{cycle}"));
        rig.srv.push_state(json!({ "cycle": cycle }));
        rig.state.set_policy(AgentPolicy::Auto);

        let first = rig.flow("example.com:443", &format!("/first/{cycle}"));
        for (i, agent) in agents.iter().enumerate() {
            assert_eq!(
                rv_drain(&agent.sink),
                vec!["marker".to_string(), format!("flow {first}")],
                "cycle {cycle}, connection {i}: one marker, then the flow"
            );
        }
        let next = rig.flow("example.com:443", &format!("/next/{cycle}"));
        for (i, agent) in agents.iter().enumerate() {
            assert_eq!(
                rv_drain(&agent.sink),
                vec![format!("flow {next}")],
                "cycle {cycle}, connection {i}: no second marker"
            );
        }
    }
}

/// The marker is an ordinary note enqueued *before* the line, so a sink that is
/// full never loses the newest line to it. With room for two, both arrive and the
/// overflow flag stays clear; with room for one, the line evicts the marker and
/// the drain's own overflow marker takes its place: the agent is told either way
/// and the line survives.
#[test]
fn revoke_push_marker_is_enqueued_before_the_line_even_in_a_full_sink() {
    for (capacity, overflows) in [(2usize, false), (1, true)] {
        let rig = RvRig::new(AgentPolicy::Auto);
        let sink = NotificationSink::new(capacity);
        let conn = ConnCtx {
            role: Frontend::Mcp,
            client_label: None,
            conn_id: rig.srv.next_conn_id(),
            out: Some(sink.clone()),
        };
        let reply = subscribe_on(&rig.srv, &conn, json!({}));
        assert!(
            sub_id_of(&reply) >= 1,
            "setup: the subscribe is accepted: {reply}"
        );

        rig.state.set_policy(AgentPolicy::Paused);
        let _lost = rig.flow("example.com:443", "/lost");
        rv_assert_silent(&sink, &format!("capacity {capacity}, while paused"));
        rig.state.set_policy(AgentPolicy::Auto);

        let id = rig.flow("example.com:443", "/after");
        assert_eq!(
            sink.lagged(),
            overflows,
            "capacity {capacity}: the sink's overflow flag is set only if the marker and the line did not both fit"
        );
        assert_eq!(
            rv_drain(&sink),
            vec!["marker".to_string(), format!("flow {id}")],
            "capacity {capacity}: the agent is told it has a gap and the newest line survives"
        );
    }
}

/// A subscriber that joins after the gap was not listening during it, so it is
/// not marked: pushes made while no agent was subscribed record no gap.
#[test]
fn revoke_push_a_subscriber_that_joins_after_the_gap_is_not_marked() {
    let rig = RvRig::new(AgentPolicy::Paused);
    let operator = rv_subscribe(&rig.srv, Frontend::Operator, json!({}));

    let lost = rig.flow("example.com:443", "/before-anyone-listened");
    rig.srv.push_state(json!({"k": 1}));
    rv_audit(&rig.srv);
    assert_eq!(
        rv_drain(&operator.sink),
        vec![
            format!("flow {lost}"),
            RV_STATE_LINE.to_string(),
            "agent agent.status".to_string(),
        ],
        "setup: the pushes were made, and the operator received them under Paused"
    );

    rig.state.set_policy(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    let id = rig.flow("example.com:443", "/after");
    assert_eq!(
        rv_drain(&agent.sink),
        vec![format!("flow {id}")],
        "a connection that was not subscribed during the gap gets no marker"
    );
}

/// `push_state` takes any JSON. Whatever its shape or size, an agent subscription
/// gets nothing under `Paused` and the operator gets the payload verbatim; after
/// resume the agent's first line is the marker, then the payload verbatim.
#[test]
fn revoke_push_odd_state_payloads_are_muted_for_agents_and_intact_for_operators() {
    let rig = RvRig::new(AgentPolicy::Auto);
    let agent = rv_subscribe(&rig.srv, Frontend::Mcp, json!({}));
    let operator = rv_subscribe(&rig.srv, Frontend::Operator, json!({}));
    rig.state.set_policy(AgentPolicy::Paused);

    let payloads = [
        json!(null),
        json!([1, 2, 3]),
        json!({}),
        json!("x".repeat(1 << 20)),
    ];
    for (i, payload) in payloads.iter().enumerate() {
        rig.srv.push_state(payload.clone());
        assert_eq!(
            agent.sink.queued_len(),
            0,
            "payload {i}: nothing is queued for the muted agent"
        );
        assert!(
            !agent.sink.lagged(),
            "payload {i}: the muted agent's sink is not flagged lagged"
        );
        let lines = operator.sink.drain();
        assert_eq!(lines.len(), 1, "payload {i}: the operator gets one line");
        let line: JsonValue = serde_json::from_str(&lines[0]).expect("a state line is JSON");
        assert_eq!(line["method"], "notifications/aitm/state", "payload {i}");
        assert!(
            line["params"] == *payload,
            "payload {i}: the operator receives the payload verbatim"
        );
    }

    rig.state.set_policy(AgentPolicy::Auto);
    rig.srv.push_state(json!([1, 2, 3]));
    let lines: Vec<JsonValue> = agent
        .sink
        .drain()
        .iter()
        .map(|raw| serde_json::from_str(raw).expect("a pushed line is JSON"))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "after resume: the marker, then the state line"
    );
    assert!(rv_is_marker(&lines[0]), "the first line is the marker");
    assert_eq!(
        lines[1]["params"],
        json!([1, 2, 3]),
        "the state line follows, verbatim"
    );
}

// ----------------------- agent policy revocation: parked requests follow the live policy

/// A registry holding one Sensitive stub (`demo.sensitive`, which returns `"ran"`
/// if the gate lets it through) and the real `agent.*` verbs over `state`.
fn revoke_ask_registry(state: &Arc<AgentState>) -> Arc<Registry> {
    let mut reg = Registry::new();
    reg.add_command(Arc::new(TierCmd {
        name: "demo.sensitive",
        sens: Sensitivity::Sensitive,
    }));
    reg.add_plugin(Box::new(AgentPlugin::new(state.clone())));
    Arc::new(reg)
}

/// A stdio-configured server over `registry` whose policy gate, parked-request
/// table and approval timeout are its own, reading the policy from `state`.
fn revoke_ask_server(
    registry: Arc<Registry>,
    state: &Arc<AgentState>,
    approval_timeout: Duration,
) -> Arc<McpServer> {
    Arc::new(
        McpServer::new(registry, McpTransport::Stdio)
            .with_agent_state(state.clone())
            .with_approval_timeout(approval_timeout)
            .with_services(
                Arc::new(MemFlowStore::new()),
                Arc::new(StubClient),
                Arc::new(StdGuard::default()),
                None,
            ),
    )
}

/// A server under `Ask` and the state it reads. Like `ask_server`, but the state
/// is handed back, so a test can change the policy directly.
fn revoke_ask_rig(approval_timeout: Duration) -> (Arc<McpServer>, Arc<AgentState>) {
    let state = Arc::new(AgentState::new(AgentPolicy::Ask));
    let srv = revoke_ask_server(revoke_ask_registry(&state), &state, approval_timeout);
    (srv, state)
}

/// P and W: two servers over one registry and one `AgentState`, each with its own
/// parked-request table (the `aitm web` topology: P is the primary, W the `/bus`
/// server). Returns `(P, W, state)`.
fn revoke_ask_pair(
    approval_timeout: Duration,
) -> (Arc<McpServer>, Arc<McpServer>, Arc<AgentState>) {
    let state = Arc::new(AgentState::new(AgentPolicy::Ask));
    let registry = revoke_ask_registry(&state);
    let p = revoke_ask_server(registry.clone(), &state, approval_timeout);
    let w = revoke_ask_server(registry, &state, approval_timeout);
    (p, w, state)
}

/// Poll `sink` every 10 ms for the `approval_requested` line and return its
/// `request_id`. The panic text lists every line the operator did receive.
fn revoke_wait_for_approval_request(sink: &NotificationSink, within: Duration) -> String {
    let started = std::time::Instant::now();
    let mut seen: Vec<String> = Vec::new();
    loop {
        for raw in sink.drain() {
            let line: JsonValue = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("a pushed line is JSON ({e}): {raw}"));
            if line["params"]["event"] == "approval_requested" {
                return line["params"]["request_id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("an approval request carries a request_id: {raw}"))
                    .to_string();
            }
            seen.push(raw);
        }
        assert!(
            started.elapsed() < within,
            "no approval_requested line within {within:?}; the operator received: {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run a `demo.sensitive` call as an agent-role connection on a `std::thread`; the
/// reply (the whole JSON-RPC response) arrives on the returned channel.
fn revoke_spawn_agent_call(srv: &Arc<McpServer>) -> std::sync::mpsc::Receiver<JsonValue> {
    let (tx, rx) = std::sync::mpsc::channel();
    let srv = srv.clone();
    std::thread::spawn(move || {
        let req = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "demo.sensitive", "arguments": {}}});
        let reply = srv
            .handle_on(&ConnCtx::new(Frontend::Mcp), &req.to_string())
            .expect("a request gets a response");
        let _ = tx.send(serde_json::from_str::<JsonValue>(&reply).expect("response is JSON"));
    });
    rx
}

/// An operator `agent.approve {request_id, allow: false}` on `srv`: the release
/// that ends a parked wait.
fn revoke_deny(srv: &McpServer, request_id: &str) -> JsonValue {
    call_as_args(
        srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": false}),
    )
}

/// Receive the parked call's reply within `within`. On a timeout, first deny the
/// request on `srv` (so the parked thread ends now, not at the approval timeout),
/// then panic with `what`.
fn revoke_recv_or_release(
    rx: &std::sync::mpsc::Receiver<JsonValue>,
    srv: &McpServer,
    request_id: &str,
    within: Duration,
    what: &str,
) -> JsonValue {
    match rx.recv_timeout(within) {
        Ok(reply) => reply,
        Err(e) => {
            let _ = revoke_deny(srv, request_id);
            panic!("{what} ({e:?})");
        }
    }
}

/// Denies `request_id` on `srv` when dropped, so any panic between "the call
/// parked" and "the call returned" still releases the parked thread. After a
/// normal finish the request is gone and the deny is a harmless error.
struct RevokeRelease {
    srv: Arc<McpServer>,
    request_id: String,
}

impl Drop for RevokeRelease {
    fn drop(&mut self) {
        let _ = revoke_deny(&self.srv, &self.request_id);
    }
}

/// The first text content of a `tools/call` reply.
fn revoke_reply_text(reply: &JsonValue) -> String {
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// AC14: a parked call is denied promptly, with no `agent.approve` at all, when
/// the policy leaves `ask`, for every policy it can move to. The design bound is
/// one 200 ms slice; the test allows 5 s.
#[test]
fn revoke_park_waiter_denies_promptly_when_the_policy_leaves_ask() {
    for policy in [
        AgentPolicy::Paused,
        AgentPolicy::ReadOnly,
        AgentPolicy::Auto,
        AgentPolicy::All,
    ] {
        let (srv, state) = revoke_ask_rig(Duration::from_secs(60));
        let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));
        let rx = revoke_spawn_agent_call(&srv);
        let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
        let _release = RevokeRelease {
            srv: srv.clone(),
            request_id: request_id.clone(),
        };

        state.set_policy(policy);

        let reply = revoke_recv_or_release(
            &rx,
            &srv,
            &request_id,
            Duration::from_secs(5),
            &format!(
                "the agent call did not return within 5s after set_policy({})",
                policy.label()
            ),
        );
        let text = revoke_reply_text(&reply);
        assert!(
            is_refused(&reply),
            "a parked call must be refused once the policy is {policy:?}: {reply}"
        );
        assert!(
            text.contains("the agent policy changed")
                && text.contains(&format!("`{}`", policy.label())),
            "the refusal names the policy change and the new policy ({policy:?}): {text}"
        );
        assert_ne!(
            reply["result"]["structuredContent"],
            json!("ran"),
            "the command must not have run under {policy:?}: {reply}"
        );
    }
}

/// AC15: `ask` to `ask` is not a change. The parked call is still parked four
/// slices later and is still approvable.
#[test]
fn revoke_park_ask_to_ask_does_not_deny() {
    let (srv, _state) = revoke_ask_rig(Duration::from_secs(60));
    let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));
    let rx = revoke_spawn_agent_call(&srv);
    let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release = RevokeRelease {
        srv: srv.clone(),
        request_id: request_id.clone(),
    };

    let set = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "ask"}),
    );
    assert_eq!(
        set["result"]["structuredContent"]["policy"],
        json!("ask"),
        "setup: agent.set ask ran: {set}"
    );

    match rx.recv_timeout(Duration::from_millis(800)) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        other => panic!("an `ask` to `ask` set must not end the parked call: {other:?}"),
    }

    let approve = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert!(
        !is_refused(&approve),
        "the approve still succeeds under `ask`: {approve}"
    );
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &request_id,
        Duration::from_secs(5),
        "the approved agent call did not return within 5s",
    );
    assert!(!is_refused(&reply), "the approved call ran: {reply}");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!("ran"),
        "the approved call returns the command's result: {reply}"
    );
}

/// AC17: P and W share a registry and a policy but not a parked-request table.
/// An agent call is parked on W; `agent.set paused` runs on P; W's call is denied
/// anyway, because the waiter reads the shared state, not a flag set on P.
#[test]
fn revoke_park_cross_server_pause_denies_the_other_servers_call() {
    let (p, w, _state) = revoke_ask_pair(Duration::from_secs(60));
    let operator = rv_subscribe(&w, Frontend::Operator, json!({}));
    let rx = revoke_spawn_agent_call(&w);
    let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release = RevokeRelease {
        srv: w.clone(),
        request_id: request_id.clone(),
    };

    let paused = call_as_args(
        &p,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "setup: agent.set paused ran on P: {paused}"
    );

    let reply = revoke_recv_or_release(
        &rx,
        &w,
        &request_id,
        Duration::from_secs(5),
        "the call parked on W did not return within 5s after agent.set paused ran on P",
    );
    let text = revoke_reply_text(&reply);
    assert!(
        is_refused(&reply),
        "W's parked call must be refused after the pause on P: {reply}"
    );
    assert!(
        text.contains("the agent policy changed") && text.contains("`paused`"),
        "the refusal names the policy change and the new policy: {text}"
    );
    assert_ne!(
        reply["result"]["structuredContent"],
        json!("ran"),
        "the command must not have run: {reply}"
    );
}

// ----------------- parked-request edge cases and races (in-process, every wait bounded)

/// A waiter that was denied (for the policy change, and for a timeout) has removed
/// its entry from the parked-request table, so a late `agent.approve`, either way, is
/// told no such request exists. Without the cleanup the stale entry would answer a
/// late approve with success for a call that is already gone.
#[test]
fn revoke_park_a_late_approve_after_the_waiter_gave_up_finds_nothing() {
    // The policy-change denial.
    let (srv, state) = revoke_ask_rig(Duration::from_secs(60));
    let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));
    let rx = revoke_spawn_agent_call(&srv);
    let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release = RevokeRelease {
        srv: srv.clone(),
        request_id: request_id.clone(),
    };
    state.set_policy(AgentPolicy::Paused);
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &request_id,
        Duration::from_secs(5),
        "the agent call did not return within 5s after set_policy(paused)",
    );
    assert!(
        is_refused(&reply) && revoke_reply_text(&reply).contains("the agent policy changed"),
        "the waiter was denied for the policy change: {reply}"
    );
    for allow in [true, false] {
        let late = call_as_args(
            &srv,
            Frontend::Operator,
            "agent.approve",
            json!({"request_id": request_id, "allow": allow}),
        );
        assert!(
            is_refused(&late)
                && revoke_reply_text(&late).contains(&format!("no parked request `{request_id}`")),
            "a late approve(allow={allow}) after the policy denial finds nothing: {late}"
        );
    }

    // The timeout denial, under a policy that never changed.
    let state = Arc::new(AgentState::new(AgentPolicy::Ask));
    let srv = revoke_ask_server(
        revoke_ask_registry(&state),
        &state,
        Duration::from_millis(400),
    );
    let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));
    let rx = revoke_spawn_agent_call(&srv);
    let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release = RevokeRelease {
        srv: srv.clone(),
        request_id: request_id.clone(),
    };
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &request_id,
        Duration::from_secs(5),
        "the agent call did not time out within 5s",
    );
    assert!(
        is_refused(&reply) && revoke_reply_text(&reply).contains("within the approval timeout"),
        "the unchanged timeout refusal: {reply}"
    );
    let late = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": request_id, "allow": true}),
    );
    assert!(
        is_refused(&late)
            && revoke_reply_text(&late).contains(&format!("no parked request `{request_id}`")),
        "a late approve after the timeout finds nothing: {late}"
    );
}

/// The operator connection that was asked to approve drops mid-park. The parked
/// waiter is not stranded: the next policy change still denies it within the bound.
/// And with the operator gone, a fresh call under `ask` is refused at once because
/// nobody is there to approve it.
#[test]
fn revoke_park_the_operator_dropping_mid_park_does_not_strand_the_waiter() {
    let (srv, state) = revoke_ask_rig(Duration::from_secs(60));
    let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));
    let rx = revoke_spawn_agent_call(&srv);
    let request_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release = RevokeRelease {
        srv: srv.clone(),
        request_id: request_id.clone(),
    };

    srv.drop_connection(operator.conn.conn_id);
    state.set_policy(AgentPolicy::Paused);
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &request_id,
        Duration::from_secs(5),
        "the call whose operator dropped did not return within 5s after set_policy(paused)",
    );
    let text = revoke_reply_text(&reply);
    assert!(
        is_refused(&reply)
            && text.contains("the agent policy changed")
            && text.contains("`paused`"),
        "the stranded waiter is denied for the policy change: {reply}"
    );

    // Nobody is subscribed as an operator now: a new call under `ask` is refused
    // before it parks, with the unchanged no-operator text.
    state.set_policy(AgentPolicy::Ask);
    let rx = revoke_spawn_agent_call(&srv);
    let reply = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a call with no operator connected is refused at once, not parked");
    assert!(
        is_refused(&reply) && revoke_reply_text(&reply).contains("no operator is connected"),
        "the unchanged no-operator refusal: {reply}"
    );
}

/// One `agent.set paused` run on P denies every parked call on both servers, two on
/// each (a stand-in for several agents parked at once), and none of them runs.
#[test]
fn revoke_park_one_pause_denies_every_parked_call_on_every_server() {
    let (p, w, _state) = revoke_ask_pair(Duration::from_secs(60));
    let op_p = rv_subscribe(&p, Frontend::Operator, json!({}));
    let op_w = rv_subscribe(&w, Frontend::Operator, json!({}));

    let mut calls = Vec::new();
    let mut releases = Vec::new();
    for (name, srv, sink) in [
        ("P", &p, &op_p.sink),
        ("P", &p, &op_p.sink),
        ("W", &w, &op_w.sink),
        ("W", &w, &op_w.sink),
    ] {
        let rx = revoke_spawn_agent_call(srv);
        let request_id = revoke_wait_for_approval_request(sink, Duration::from_secs(5));
        releases.push(RevokeRelease {
            srv: srv.clone(),
            request_id: request_id.clone(),
        });
        calls.push((name, srv.clone(), rx, request_id));
    }

    let paused = call_as_args(
        &p,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "setup: agent.set paused ran on P: {paused}"
    );

    for (name, srv, rx, request_id) in &calls {
        let reply = revoke_recv_or_release(
            rx,
            srv,
            request_id,
            Duration::from_secs(5),
            &format!("a call parked on {name} did not return within 5s after the pause"),
        );
        let text = revoke_reply_text(&reply);
        assert!(
            is_refused(&reply)
                && text.contains("the agent policy changed")
                && text.contains("`paused`"),
            "the call parked on {name} is denied for the policy change: {reply}"
        );
        assert_ne!(
            reply["result"]["structuredContent"],
            json!("ran"),
            "the call parked on {name} must not have run: {reply}"
        );
    }
    drop(releases);
}

/// After a revocation the agent can re-issue: the denied request's id is dead (an
/// approve for it finds nothing), and once the operator is back on `ask` the same
/// call parks under a fresh id and an approve of that one runs it.
#[test]
fn revoke_park_after_a_revocation_the_agent_can_reissue_under_a_fresh_id() {
    let (srv, _state) = revoke_ask_rig(Duration::from_secs(60));
    let operator = rv_subscribe(&srv, Frontend::Operator, json!({}));

    let rx = revoke_spawn_agent_call(&srv);
    let first_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release_first = RevokeRelease {
        srv: srv.clone(),
        request_id: first_id.clone(),
    };
    let paused = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "paused"}),
    );
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "setup: agent.set paused ran: {paused}"
    );
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &first_id,
        Duration::from_secs(5),
        "the first call did not return within 5s after the pause",
    );
    assert!(
        is_refused(&reply) && revoke_reply_text(&reply).contains("the agent policy changed"),
        "the first call is denied for the policy change: {reply}"
    );

    let dead = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": first_id, "allow": true}),
    );
    assert!(
        is_refused(&dead)
            && revoke_reply_text(&dead).contains(&format!("no parked request `{first_id}`")),
        "the revoked request id is dead: {dead}"
    );

    let ask = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.set",
        json!({"policy": "ask"}),
    );
    assert_eq!(
        ask["result"]["structuredContent"]["policy"],
        json!("ask"),
        "setup: agent.set ask ran: {ask}"
    );
    let rx = revoke_spawn_agent_call(&srv);
    let second_id = revoke_wait_for_approval_request(&operator.sink, Duration::from_secs(5));
    let _release_second = RevokeRelease {
        srv: srv.clone(),
        request_id: second_id.clone(),
    };
    assert_ne!(
        second_id, first_id,
        "the re-issued call parks under a fresh id"
    );
    let approve = call_as_args(
        &srv,
        Frontend::Operator,
        "agent.approve",
        json!({"request_id": second_id, "allow": true}),
    );
    assert!(
        !is_refused(&approve),
        "the approve of the fresh id works: {approve}"
    );
    let reply = revoke_recv_or_release(
        &rx,
        &srv,
        &second_id,
        Duration::from_secs(5),
        "the re-issued call did not return within 5s",
    );
    assert_eq!(
        reply["result"]["structuredContent"],
        json!("ran"),
        "the re-issued, approved call ran: {reply}"
    );
}

// ------------ agent policy revocation: the real-socket test, AC18 (binds a port)

/// How long the socket test waits for a line or a reply it expects.
const RV_SOCK_EXPECT: Duration = Duration::from_secs(5);

/// How long A must stay silent, after the fence, for the negative assertion.
const RV_SOCK_QUIET: Duration = Duration::from_millis(250);

/// One authenticated loopback-TCP connection. Every line it receives, replies
/// and pushes alike, is collected in arrival order in `seen`, so an assertion can
/// print the whole stream. Every read and write carries a deadline.
struct RvSock {
    label: &'static str,
    lines: Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
    seen: Vec<JsonValue>,
}

impl RvSock {
    /// Connect to `addr` and present `token` as the first line. Nothing is read
    /// here: a refused token surfaces in the dump of the first read that fails.
    async fn open(label: &'static str, addr: SocketAddr, token: &str) -> Self {
        let stream = tokio::time::timeout(RV_SOCK_EXPECT, TcpStream::connect(addr))
            .await
            .unwrap_or_else(|_| panic!("{label}: connecting to {addr} timed out"))
            .unwrap_or_else(|e| panic!("{label}: connecting to {addr} failed: {e}"));
        let (read_half, write_half) = stream.into_split();
        let mut conn = Self {
            label,
            lines: BufReader::new(read_half).lines(),
            writer: write_half,
            seen: Vec::new(),
        };
        conn.send(&json!({ "token": token })).await;
        conn
    }

    /// Every line received so far, one per row, for an assertion message.
    fn dump(&self) -> String {
        let mut out = format!("{} received {} line(s):", self.label, self.seen.len());
        for (i, line) in self.seen.iter().enumerate() {
            out.push_str(&format!("\n  [{i}] {line}"));
        }
        out
    }

    /// Write `req` as one line.
    async fn send(&mut self, req: &JsonValue) {
        let mut line = req.to_string();
        line.push('\n');
        let sent = tokio::time::timeout(RV_SOCK_EXPECT, async {
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.flush().await
        })
        .await;
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("{}: writing {req} failed: {e}\n{}", self.label, self.dump()),
            Err(_) => panic!("{}: writing {req} timed out\n{}", self.label, self.dump()),
        }
    }

    /// The next line, collected; `None` if none arrives within `within`. A closed
    /// connection, an I/O error, or a line that is not JSON is a failure, never a
    /// `None`, so silence is only ever the timeout elapsing.
    async fn next_within(&mut self, within: Duration) -> Option<JsonValue> {
        match tokio::time::timeout(within, self.lines.next_line()).await {
            Err(_elapsed) => None,
            Ok(Ok(Some(raw))) => {
                let line: JsonValue = serde_json::from_str(&raw).unwrap_or_else(|e| {
                    panic!(
                        "{}: a received line is not JSON ({e}): {raw}\n{}",
                        self.label,
                        self.dump()
                    )
                });
                self.seen.push(line.clone());
                Some(line)
            }
            Ok(Ok(None)) => panic!("{}: the connection closed\n{}", self.label, self.dump()),
            Ok(Err(e)) => panic!("{}: reading failed: {e}\n{}", self.label, self.dump()),
        }
    }

    /// Read, collecting every line, until `pred` matches one; returns that line.
    /// One `RV_SOCK_EXPECT` budget covers the whole wait, so a stream of lines
    /// that never matches cannot extend it.
    async fn read_until(&mut self, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
        let deadline = tokio::time::Instant::now() + RV_SOCK_EXPECT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next_within(left).await {
                Some(line) if pred(&line) => return line,
                Some(_) => {}
                None => panic!(
                    "{}: no {what} within {RV_SOCK_EXPECT:?}\n{}",
                    self.label,
                    self.dump()
                ),
            }
        }
    }

    /// `tools/call` `name` with `args` as request `id`; returns its reply. Any
    /// push that arrives first is collected on the way.
    async fn call(&mut self, id: u64, name: &str, args: JsonValue) -> JsonValue {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }))
        .await;
        self.read_until(&format!("reply to {name} (id {id})"), |l| {
            l["id"] == json!(id)
        })
        .await
    }

    /// `ping` as request `id`; returns its reply.
    async fn ping(&mut self, id: u64) -> JsonValue {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"}))
            .await;
        self.read_until(&format!("reply to ping (id {id})"), |l| {
            l["id"] == json!(id)
        })
        .await
    }
}

/// Insert a flow for `path` and send its `RequestHeaders` event on `tx` (the
/// server's dispatcher turns it into a push); returns the flow id as a push
/// renders it.
fn rv_sock_flow(store: &Arc<MemFlowStore>, tx: &broadcast::Sender<Event>, path: &str) -> String {
    let id = store.insert(http_flow("example.com:443", path));
    tx.send(Event::RequestHeaders(id))
        .expect("serve's dispatcher holds a broadcast receiver");
    id.to_string()
}

/// Whether `line` is the `notifications/aitm/flow` push for flow `id`.
fn rv_sock_is_flow(line: &JsonValue, id: &str) -> bool {
    line["method"] == "notifications/aitm/flow" && line["params"]["id"] == id
}

/// Whether `line` is the `notifications/aitm/agent` audit push of an `agent.set`.
fn rv_sock_is_agent_set_audit(line: &JsonValue) -> bool {
    line["method"] == "notifications/aitm/agent" && line["params"]["command"] == "agent.set"
}

/// One short word per line, so an ordering assertion and its failure message read
/// as the stream: `marker`, `flow <id>`, `agent <command>`, `reply <id>`.
fn rv_sock_kind(line: &JsonValue) -> String {
    if rv_is_marker(line) {
        return "marker".to_string();
    }
    if let Some(id) = line.get("id").filter(|v| !v.is_null()) {
        return format!("reply {id}");
    }
    let params = &line["params"];
    match line["method"].as_str().unwrap_or("?") {
        "notifications/aitm/flow" => format!("flow {}", params["id"].as_str().unwrap_or("?")),
        "notifications/aitm/agent" => {
            format!("agent {}", params["command"].as_str().unwrap_or("?"))
        }
        other => format!("other {other}"),
    }
}

/// AC18: over real loopback TCP, a real agent A (token `tok`) goes quiet when a
/// real operator O (token `op`) pauses the agent policy, and resumes with the
/// `lagged` marker in front of its first post-pause line.
///
/// The negative claim ("A receives nothing while paused") is only sound behind a
/// fence, never a bare sleep. A subscribes before O, so the fan-out, which walks
/// subscriptions in insertion order, decides A's line for F2 before it reaches O.
/// O receiving F2's flow line therefore proves A's sink already holds whatever it
/// was going to hold. A's `ping` round trip then flushes that sink through the
/// writer (replies first, then any queued note, in one batch), and only after
/// that does the test wait `RV_SOCK_QUIET` for a line that must not come.
///
/// Binds `127.0.0.1:0`: run from the Terminal panel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_socket_paused_agent_goes_quiet_and_resumes_with_a_marker() {
    let state = Arc::new(AgentState::new(AgentPolicy::Auto));
    let store = Arc::new(MemFlowStore::new());
    // `serve` subscribes its own dispatcher on this channel before it binds, so
    // the `send` in `rv_sock_flow` succeeds although the channel's own receiver is
    // dropped at once.
    let (tx, _) = broadcast::channel::<Event>(16);
    let srv = McpServer::new(
        rv_registry(&state),
        McpTransport::LoopbackTcp {
            port: 0,
            token: "tok".into(),
            endpoint_file: None,
        },
    )
    .with_agent_state(state.clone())
    .with_services(
        store.clone(),
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
    .with_mcp_roles(Some("op".into()), Frontend::Mcp)
    .with_push(tx.clone());
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    tokio::spawn(
        srv.on_bound(move |addr| {
            let _ = bound_tx.send(addr);
        })
        .serve(),
    );
    let addr = tokio::time::timeout(RV_SOCK_EXPECT, bound_rx)
        .await
        .expect("serve reports its bound address within the deadline")
        .expect("serve ended without reporting a bound address");

    // Step 0: A subscribes first, then O, so O's receipt of a push is a fence.
    let mut a = RvSock::open("A (agent, token tok)", addr, "tok").await;
    let a_sub = a.call(1, "flow.subscribe", json!({})).await;
    assert!(
        a_sub["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "step 0: A's flow.subscribe returns a u64 sub_id: {a_sub}\n{}",
        a.dump()
    );
    let mut o = RvSock::open("O (operator, token op)", addr, "op").await;
    let o_sub = o.call(1, "flow.subscribe", json!({})).await;
    assert!(
        o_sub["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .is_some(),
        "step 0: O's flow.subscribe returns a u64 sub_id: {o_sub}\n{}",
        o.dump()
    );

    // Step 1: under `Auto`, both receive F1.
    let f1 = rv_sock_flow(&store, &tx, "/one");
    for conn in [&mut a, &mut o] {
        let line = conn
            .read_until("F1's flow line", |l| rv_sock_is_flow(l, &f1))
            .await;
        assert_eq!(
            line["params"]["summary"]["path"],
            json!("/one"),
            "step 1: F1's flow line carries its path: {line}\n{}",
            conn.dump()
        );
    }

    // Step 2: O pauses; F2 reaches O (the fence) and must not reach A.
    let paused = o.call(2, "agent.set", json!({"policy": "paused"})).await;
    assert_eq!(
        paused["result"]["structuredContent"]["policy"],
        json!("paused"),
        "step 2: O's agent.set paused ran: {paused}\n{}",
        o.dump()
    );
    let f2 = rv_sock_flow(&store, &tx, "/two");
    let fence = o
        .read_until("F2's flow line (the fence)", |l| rv_sock_is_flow(l, &f2))
        .await;
    assert_eq!(
        fence["params"]["summary"]["path"],
        json!("/two"),
        "step 2: O (never muted) receives F2's flow line: {fence}\n{}",
        o.dump()
    );
    // O is a subscriber and the audit push of the pause is fanned to every
    // subscriber, FIFO ahead of F2's line: O must already hold it, or A's
    // absence of it below would prove nothing.
    assert!(
        o.seen.iter().any(rv_sock_is_agent_set_audit),
        "step 2: O received the audit line of its own agent.set before F2's line\n{}",
        o.dump()
    );
    // Flush A's sink through its writer, then look for a line that must not come.
    let pong = a.ping(2).await;
    assert_eq!(
        pong["result"],
        json!({}),
        "step 2: A's ping is answered even while paused: {pong}\n{}",
        a.dump()
    );
    let extra = a.next_within(RV_SOCK_QUIET).await;
    assert!(
        !a.seen.iter().any(|l| l.to_string().contains(f2.as_str())),
        "step 2: no line A received names F2 ({f2})\n{}",
        a.dump()
    );
    assert!(
        !a.seen.iter().any(rv_sock_is_agent_set_audit),
        "step 2: A received no agent.set audit line while paused\n{}",
        a.dump()
    );
    assert!(
        !a.seen.iter().any(rv_is_marker),
        "step 2: A received no lagged marker while paused\n{}",
        a.dump()
    );
    assert!(
        extra.is_none(),
        "step 2: no line may reach A within {RV_SOCK_QUIET:?} of the fence, got {extra:?}\n{}",
        a.dump()
    );

    // Step 3: O resumes; A gets the marker first, then F3, and never F2.
    let mark = a.seen.len();
    let resumed = o.call(3, "agent.set", json!({"policy": "auto"})).await;
    assert_eq!(
        resumed["result"]["structuredContent"]["policy"],
        json!("auto"),
        "step 3: O's agent.set auto ran: {resumed}\n{}",
        o.dump()
    );
    let f3 = rv_sock_flow(&store, &tx, "/three");
    a.read_until("F3's flow line", |l| rv_sock_is_flow(l, &f3))
        .await;
    let since: Vec<String> = a.seen[mark..].iter().map(rv_sock_kind).collect();
    let f3_flow = format!("flow {f3}");
    let allowed = [
        vec!["marker".to_string(), f3_flow.clone()],
        vec!["marker".to_string(), "agent agent.set".to_string(), f3_flow],
    ];
    assert!(
        allowed.contains(&since),
        "step 3: A's lines since step 2 are the marker first, the agent.set audit line optionally, then F3's flow line: got {since:?}\n{}",
        a.dump()
    );
    let markers = a.seen.iter().filter(|l| rv_is_marker(l)).count();
    assert_eq!(
        markers,
        1,
        "step 3: exactly one marker in all\n{}",
        a.dump()
    );
    assert!(
        !a.seen.iter().any(|l| l.to_string().contains(f2.as_str())),
        "step 3: no line A received at any point names F2 ({f2})\n{}",
        a.dump()
    );
}

// ------------ pushes through the real writer over in-memory duplex streams (no port)

type RvTask = tokio::task::JoinHandle<anyhow::Result<()>>;

/// One client of `serve_lines` over an in-memory duplex. Like `RvSock`, every line
/// received is collected in arrival order in `seen`, and every read and write
/// carries a deadline.
struct RvWire {
    label: &'static str,
    w: WriteHalf<DuplexStream>,
    lines: ClientReader,
    seen: Vec<JsonValue>,
}

impl RvWire {
    /// A connection of `role` to `srv`, over a fresh `NotificationSink::new(64)`;
    /// also returns that sink and the server's task for the connection.
    fn open(
        srv: &Arc<McpServer>,
        role: Frontend,
        label: &'static str,
    ) -> (Self, NotificationSink, RvTask) {
        let (w, lines, sink, task) = open_push_conn(srv.clone(), role, 64 * 1024, 64);
        let wire = Self {
            label,
            w,
            lines,
            seen: Vec::new(),
        };
        (wire, sink, task)
    }

    /// Every line received so far, one per row, for an assertion message.
    fn dump(&self) -> String {
        let mut out = format!("{} received {} line(s):", self.label, self.seen.len());
        for (i, line) in self.seen.iter().enumerate() {
            out.push_str(&format!("\n  [{i}] {line}"));
        }
        out
    }

    /// `rv_sock_kind` of every line received from index `from`.
    fn kinds(&self, from: usize) -> Vec<String> {
        self.seen[from..].iter().map(rv_sock_kind).collect()
    }

    /// Write `raw` as one line, as given (it need not be JSON).
    async fn send_raw(&mut self, raw: &str) {
        let mut line = raw.to_string();
        line.push('\n');
        let sent = tokio::time::timeout(RV_SOCK_EXPECT, async {
            self.w.write_all(line.as_bytes()).await?;
            self.w.flush().await
        })
        .await;
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("{}: writing {raw} failed: {e}\n{}", self.label, self.dump()),
            Err(_) => panic!("{}: writing {raw} timed out\n{}", self.label, self.dump()),
        }
    }

    /// The next line, collected; `None` if none arrives within `within`. A closed
    /// connection, an I/O error, or a non-JSON line is a failure, never a `None`.
    async fn next_within(&mut self, within: Duration) -> Option<JsonValue> {
        match tokio::time::timeout(within, self.lines.next_line()).await {
            Err(_elapsed) => None,
            Ok(Ok(Some(raw))) => {
                let line: JsonValue = serde_json::from_str(&raw).unwrap_or_else(|e| {
                    panic!(
                        "{}: a received line is not JSON ({e}): {raw}\n{}",
                        self.label,
                        self.dump()
                    )
                });
                self.seen.push(line.clone());
                Some(line)
            }
            Ok(Ok(None)) => panic!("{}: the connection closed\n{}", self.label, self.dump()),
            Ok(Err(e)) => panic!("{}: reading failed: {e}\n{}", self.label, self.dump()),
        }
    }

    /// Read, collecting every line, until `pred` matches one. One
    /// `RV_SOCK_EXPECT` budget covers the whole wait.
    async fn read_until(&mut self, what: &str, pred: impl Fn(&JsonValue) -> bool) -> JsonValue {
        let deadline = tokio::time::Instant::now() + RV_SOCK_EXPECT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.next_within(left).await {
                Some(line) if pred(&line) => return line,
                Some(_) => {}
                None => panic!(
                    "{}: no {what} within {RV_SOCK_EXPECT:?}\n{}",
                    self.label,
                    self.dump()
                ),
            }
        }
    }

    /// `tools/call` `name` with `args` as request `id`; returns its reply.
    async fn call(&mut self, id: u64, name: &str, args: JsonValue) -> JsonValue {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        });
        self.send_raw(&req.to_string()).await;
        self.read_until(&format!("reply to {name} (id {id})"), |l| {
            l["id"] == json!(id)
        })
        .await
    }

    /// `ping` as request `id`; returns its reply.
    async fn ping(&mut self, id: u64) -> JsonValue {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "ping"});
        self.send_raw(&req.to_string()).await;
        self.read_until(&format!("reply to ping (id {id})"), |l| {
            l["id"] == json!(id)
        })
        .await
    }

    /// `flow.subscribe {}` as request 1; the reply must carry a `sub_id` (setup).
    async fn subscribe(&mut self) {
        let reply = self.call(1, "flow.subscribe", json!({})).await;
        assert!(
            reply["result"]["structuredContent"]["sub_id"]
                .as_u64()
                .is_some(),
            "setup: the subscribe returns a u64 sub_id: {reply}\n{}",
            self.dump()
        );
    }
}

/// `agent.set {"policy": policy}` run by `op`; the reply must report `policy`.
async fn rv_wire_set_policy(op: &mut RvWire, id: u64, policy: &str) {
    let reply = op.call(id, "agent.set", json!({"policy": policy})).await;
    assert_eq!(
        reply["result"]["structuredContent"]["policy"],
        json!(policy),
        "the operator's agent.set {policy} ran: {reply}\n{}",
        op.dump()
    );
}

/// Strengthens AC18 and runs in the sandbox: two agents A1 and A2 and an operator
/// O over the real writer. Under `paused` a burst (two flow pushes and a state
/// push) reaches O in full and reaches neither agent, which receive exactly their
/// own replies and nothing else (the whole stream is compared, not only "no F2").
/// On resume each agent gets exactly `[marker, F4]`: one marker per connection,
/// in front of its own first post-gap line, and none of the suppressed pushes
/// (the operator's `agent.set` audit lines are never sent to an agent, so they
/// are not among them). O is never marked and receives every push in order.
///
/// Why `rv_flow` is a fence here: it runs the fan-out synchronously, so when it
/// returns each agent's sink already holds whatever it was going to hold. O is
/// last in registry order, and its receipt of the final push is what the test
/// waits on; the pings then flush each agent's sink through its writer before the
/// quiet window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_push_real_writer_two_agents_pause_quiet_then_one_marker_each() {
    let RvRig { srv, store, .. } = RvRig::new(AgentPolicy::Auto);
    let srv = Arc::new(srv);
    let host = "example.com:443";

    // Registry order: A1, A2, O.
    let (mut a1, _a1_sink, _a1_task) = RvWire::open(&srv, Frontend::Mcp, "A1 (agent)");
    a1.subscribe().await;
    let (mut a2, _a2_sink, _a2_task) = RvWire::open(&srv, Frontend::Mcp, "A2 (agent)");
    a2.subscribe().await;
    let (mut o, _o_sink, _o_task) = RvWire::open(&srv, Frontend::Operator, "O (operator)");
    o.subscribe().await;

    // Under `Auto` everyone receives F1: the subscriptions are live.
    let f1 = rv_flow(&srv, &store, host, "/one");
    for conn in [&mut a1, &mut a2, &mut o] {
        let line = conn
            .read_until("F1's flow line", |l| rv_sock_is_flow(l, &f1))
            .await;
        assert_eq!(
            line["params"]["summary"]["path"],
            json!("/one"),
            "F1's flow line carries its path: {line}\n{}",
            conn.dump()
        );
    }

    // Pause, then a burst of three pushes while paused.
    rv_wire_set_policy(&mut o, 2, "paused").await;
    let f2 = rv_flow(&srv, &store, host, "/two");
    let f3 = rv_flow(&srv, &store, host, "/three");
    srv.push_state(json!({"k": 1}));
    o.read_until("the burst's last push (the fence)", |l| {
        l["method"] == "notifications/aitm/state" && l["params"] == json!({"k": 1})
    })
    .await;
    for agent in [&mut a1, &mut a2] {
        let pong = agent.ping(2).await;
        assert_eq!(
            pong["result"],
            json!({}),
            "a paused agent's ping is answered: {pong}\n{}",
            agent.dump()
        );
    }
    let (quiet1, quiet2) =
        tokio::join!(a1.next_within(RV_SOCK_QUIET), a2.next_within(RV_SOCK_QUIET));
    for (agent, extra) in [(&a1, quiet1), (&a2, quiet2)] {
        assert!(
            extra.is_none(),
            "no line may reach a paused agent within {RV_SOCK_QUIET:?} of the fence, got {extra:?}\n{}",
            agent.dump()
        );
        assert_eq!(
            agent.kinds(0),
            vec![
                "reply 1".to_string(),
                format!("flow {f1}"),
                "reply 2".to_string()
            ],
            "while paused an agent's whole stream is its own replies and F1\n{}",
            agent.dump()
        );
    }

    // Resume, then one more flow.
    let marks = [a1.seen.len(), a2.seen.len()];
    rv_wire_set_policy(&mut o, 3, "auto").await;
    let f4 = rv_flow(&srv, &store, host, "/four");
    for (agent, mark) in [(&mut a1, marks[0]), (&mut a2, marks[1])] {
        agent
            .read_until("F4's flow line", |l| rv_sock_is_flow(l, &f4))
            .await;
        assert_eq!(
            agent.kinds(mark),
            vec!["marker".to_string(), format!("flow {f4}")],
            "after resume: the marker, then F4 (the operator's agent.set audit line is not for an agent)\n{}",
            agent.dump()
        );
        let markers = agent.seen.iter().filter(|l| rv_is_marker(l)).count();
        assert_eq!(
            markers,
            1,
            "exactly one marker per connection\n{}",
            agent.dump()
        );
        for suppressed in [&f2, &f3] {
            assert!(
                !agent
                    .seen
                    .iter()
                    .any(|l| l.to_string().contains(suppressed.as_str())),
                "a suppressed flow ({suppressed}) must never reach the agent\n{}",
                agent.dump()
            );
        }
    }

    // O is never muted and never marked: every push, in order.
    o.read_until("F4's flow line", |l| rv_sock_is_flow(l, &f4))
        .await;
    let o_pushes: Vec<String> = o
        .kinds(0)
        .into_iter()
        .filter(|k| !k.starts_with("reply "))
        .collect();
    assert_eq!(
        o_pushes,
        vec![
            format!("flow {f1}"),
            "agent agent.set".to_string(),
            format!("flow {f2}"),
            format!("flow {f3}"),
            "other notifications/aitm/state".to_string(),
            "agent agent.set".to_string(),
            format!("flow {f4}"),
        ],
        "the operator receives every push, in order, with no marker\n{}",
        o.dump()
    );
}

/// A connection dropped mid-stream. Agent A1 is gapped by a push under `paused`
/// and then disconnects while the policy is still `paused`. The transport must
/// sweep its subscription (A1's sink is closed and stays empty through the rest of
/// the test, including after resume, when a leaked subscription would be handed
/// the marker and the next flow), and the surviving agent A2 and the operator O
/// must be undisturbed: A2 stays quiet, then gets exactly one marker in front of
/// its own first post-gap line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_push_an_agent_dropping_while_paused_leaves_the_others_intact() {
    let RvRig { srv, store, .. } = RvRig::new(AgentPolicy::Auto);
    let srv = Arc::new(srv);
    let host = "example.com:443";

    let (mut a1, a1_sink, a1_task) = RvWire::open(&srv, Frontend::Mcp, "A1 (agent, drops)");
    a1.subscribe().await;
    let (mut a2, _a2_sink, _a2_task) = RvWire::open(&srv, Frontend::Mcp, "A2 (agent)");
    a2.subscribe().await;
    let (mut o, _o_sink, _o_task) = RvWire::open(&srv, Frontend::Operator, "O (operator)");
    o.subscribe().await;

    rv_wire_set_policy(&mut o, 2, "paused").await;
    let f2 = rv_flow(&srv, &store, host, "/two");
    assert!(
        !a1_sink.is_closed(),
        "setup: A1's connection is still open before it drops"
    );

    // A1 drops with a gap recorded; wait for the transport to finish its teardown.
    drop(a1);
    tokio::time::timeout(RV_SOCK_EXPECT, a1_task)
        .await
        .expect("A1's connection task ends within the deadline once the client is gone")
        .expect("A1's connection task did not panic")
        .expect("A1's connection task ends cleanly at EOF");
    assert!(
        a1_sink.is_closed(),
        "the transport closes a dropped connection's sink"
    );

    // Still paused, now with A1 gone: O receives it, A2 stays quiet.
    let f3 = rv_flow(&srv, &store, host, "/three");
    o.read_until("F3's flow line (the fence)", |l| rv_sock_is_flow(l, &f3))
        .await;
    let pong = a2.ping(2).await;
    assert_eq!(pong["result"], json!({}), "{pong}\n{}", a2.dump());
    let extra = a2.next_within(RV_SOCK_QUIET).await;
    assert!(
        extra.is_none(),
        "A2 stays quiet while paused, got {extra:?}\n{}",
        a2.dump()
    );
    assert_eq!(
        a2.kinds(0),
        vec!["reply 1".to_string(), "reply 2".to_string()],
        "A2's whole stream while paused is its own replies\n{}",
        a2.dump()
    );

    // Resume: A2 is marked once; the dropped A1 is neither marked nor fed.
    let mark = a2.seen.len();
    rv_wire_set_policy(&mut o, 3, "auto").await;
    let f4 = rv_flow(&srv, &store, host, "/four");
    a2.read_until("F4's flow line", |l| rv_sock_is_flow(l, &f4))
        .await;
    assert_eq!(
        a2.kinds(mark),
        vec!["marker".to_string(), format!("flow {f4}")],
        "after resume A2 gets the marker, then F4 (the operator's audit line is not for an agent)\n{}",
        a2.dump()
    );
    o.read_until("F4's flow line", |l| rv_sock_is_flow(l, &f4))
        .await;
    let o_pushes: Vec<String> = o
        .kinds(0)
        .into_iter()
        .filter(|k| !k.starts_with("reply "))
        .collect();
    assert_eq!(
        o_pushes,
        vec![
            "agent agent.set".to_string(),
            format!("flow {f2}"),
            format!("flow {f3}"),
            "agent agent.set".to_string(),
            format!("flow {f4}"),
        ],
        "the operator's stream is undisturbed by A1 dropping\n{}",
        o.dump()
    );
    rv_assert_silent(
        &a1_sink,
        "the dropped A1's sink after the resume, the audit line, and F4",
    );
}

/// Malformed input and a refused call while muted. The mute is about pushes only.
/// A paused agent's replies ride a different lane and must keep flowing: a
/// malformed line gets its parse error, a command gets the policy refusal, a
/// `ping` gets `{}`. If muting were ever done in the writer instead of at the
/// fan-out (a rejected design) these replies would stop and the agent would hang.
/// Meanwhile the agent receives no push (no line with a `method`), and on resume
/// its first push is the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_push_a_paused_agent_still_gets_every_reply_but_no_push() {
    let RvRig { srv, store, .. } = RvRig::new(AgentPolicy::Auto);
    let srv = Arc::new(srv);
    let host = "example.com:443";

    let (mut a, _a_sink, _a_task) = RvWire::open(&srv, Frontend::Mcp, "A (agent)");
    a.subscribe().await;
    let (mut o, _o_sink, _o_task) = RvWire::open(&srv, Frontend::Operator, "O (operator)");
    o.subscribe().await;

    rv_wire_set_policy(&mut o, 2, "paused").await;
    let f2 = rv_flow(&srv, &store, host, "/two");
    o.read_until("F2's flow line (the fence)", |l| rv_sock_is_flow(l, &f2))
        .await;

    // Malformed input: answered with a parse error, not swallowed, not a push.
    a.send_raw("{this is not json").await;
    let parse = a
        .read_until("the parse-error reply", |l| {
            l["error"]["code"] == json!(aitm_mcp::server::PARSE_ERROR)
        })
        .await;
    assert!(
        parse["id"].is_null(),
        "a parse error carries a null id: {parse}\n{}",
        a.dump()
    );
    // A command: refused by the policy gate, and the refusal still comes back.
    let refused = a.call(3, "agent.status", json!({})).await;
    assert_eq!(
        refused["result"]["isError"],
        json!(true),
        "a paused agent's command is refused: {refused}\n{}",
        a.dump()
    );
    let text = refused["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("the agent policy is `paused`"),
        "the refusal names the policy: {refused}\n{}",
        a.dump()
    );
    let pong = a.ping(4).await;
    assert_eq!(pong["result"], json!({}), "{pong}\n{}", a.dump());

    let extra = a.next_within(RV_SOCK_QUIET).await;
    assert!(
        extra.is_none(),
        "no push reaches the paused agent, got {extra:?}\n{}",
        a.dump()
    );
    assert_eq!(
        a.seen.len(),
        4,
        "exactly four lines so far: the subscribe reply, the parse error, the refusal, the pong\n{}",
        a.dump()
    );
    assert!(
        a.seen.iter().all(|l| l.get("method").is_none()),
        "every line the paused agent received is a reply, none a push\n{}",
        a.dump()
    );

    // Resume: the first push the agent gets is the marker.
    let mark = a.seen.len();
    rv_wire_set_policy(&mut o, 3, "auto").await;
    let f3 = rv_flow(&srv, &store, host, "/three");
    a.read_until("F3's flow line", |l| rv_sock_is_flow(l, &f3))
        .await;
    assert_eq!(
        a.kinds(mark),
        vec!["marker".to_string(), format!("flow {f3}")],
        "after resume the agent's pushes are the marker, then F3 (the operator's audit line is not for an agent)\n{}",
        a.dump()
    );
}
