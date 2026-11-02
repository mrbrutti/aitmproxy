//! Task 26: the CLI frontend — argv subcommand path → `Command::name()`, flags →
//! `ParamDef`s, and parity with the MCP path (AC8, AC-P2). Commands are test
//! stubs; the real command providers are verified together at integration.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_cli::{Cli, Confirmer, TtyConfirmer};
use aitm_core::{
    AgentPolicy, AgentState, Body, Command, CommandHost, ConnInfo, Flow, FlowId, FlowMeta,
    FlowStore, Frontend, HeaderMap, HttpFlow, HttpRequest, HttpVersion, InterceptState,
    McpTransport, MemFlowStore, ParamDef, ParamSchema, Params, Plugin, ProxyClient, Registry,
    StdGuard, TypeDesc, Value,
};
use aitm_mcp::json::from_json;
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

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

/// `flow.get {id}` → `{id, method, authority, path}`.
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

/// A command whose schema exercises every `TypeDesc` variant; echoes its args.
struct EchoCmd;

impl Command for EchoCmd {
    fn name(&self) -> &str {
        "demo.echo"
    }
    fn schema(&self) -> ParamSchema {
        let p = |name: &str, ty: TypeDesc, required: bool| ParamDef {
            name: name.into(),
            ty,
            required,
            description: String::new(),
        };
        ParamSchema {
            description: "Echo typed arguments back.".into(),
            params: vec![
                p("id", TypeDesc::FlowId, true),
                p("limit", TypeDesc::Int, false),
                p("ratio", TypeDesc::Float, false),
                p("verbose", TypeDesc::Bool, false),
                p("raw", TypeDesc::Bytes, false),
                p("tags", TypeDesc::Array(Box::new(TypeDesc::Str)), false),
                p(
                    "edits",
                    TypeDesc::Object(vec![p("method", TypeDesc::Str, true)]),
                    false,
                ),
                p("extra", TypeDesc::Any, false),
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

struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn http_flow(authority: &str, path: &str) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
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

fn registry() -> Arc<Registry> {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(DemoPlugin));
    reg.add_command(Arc::new(FlowListCmd));
    reg.add_command(Arc::new(FlowGetCmd));
    reg.add_command(Arc::new(EchoCmd));
    Arc::new(reg)
}

fn cli_with(reg: Arc<Registry>, store: Arc<MemFlowStore>) -> Cli {
    Cli::new(reg).with_services(
        store,
        Arc::new(StubClient),
        Arc::new(StdGuard::default()),
        None,
    )
}

fn cli() -> Cli {
    cli_with(registry(), Arc::new(MemFlowStore::new()))
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn err_text(r: anyhow::Result<Value>) -> String {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => format!("{e:#}"),
    }
}

// ------------------------------------------------------------------- tests

/// AC-P2 (CLI half): a plugin-registered command is callable from argv.
#[test]
fn ping_over_cli() {
    let out = cli()
        .dispatch(&argv(&["demo", "ping"]))
        .expect("dispatch ok");
    assert_eq!(out, Value::Str("pong".into()));
    // A single already-dotted token is the same command.
    let out = cli().dispatch(&argv(&["demo.ping"])).expect("dispatch ok");
    assert_eq!(out, Value::Str("pong".into()));
}

/// AC8: `flow.list` over the CLI and over MCP `tools/call` return equal `Value`s.
#[test]
fn cli_matches_mcp() {
    let reg = registry();
    let store = Arc::new(MemFlowStore::new());
    let a = store.insert(http_flow("a.test", "/one"));
    let b = store.insert(http_flow("b.test", "/two"));

    let via_cli = cli_with(reg.clone(), store.clone())
        .dispatch(&argv(&["flow", "list"]))
        .expect("cli dispatch ok");

    // The local `flow.list` stub declares no `sensitivity()`, so it is the
    // fail-closed `Sensitive` default with no config gate. Under the corrected
    // policy (spec D2) the *agent* may not call such a command under any policy, so
    // — since this test compares the CLI and MCP result values, not the policy gate
    // — the MCP call is made over an operator connection, which is never
    // policy-gated. (`All` agent state kept only to exercise the policy-free path.)
    let mcp = McpServer::new(reg, McpTransport::Stdio)
        .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)))
        .with_services(
            store,
            Arc::new(StubClient),
            Arc::new(StdGuard::default()),
            None,
        );
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "flow.list", "arguments": {}}});
    let resp: JsonValue = serde_json::from_str(
        &mcp.handle_on(
            &aitm_mcp::ConnCtx::new(Frontend::Operator),
            &req.to_string(),
        )
        .expect("reply"),
    )
    .expect("json");
    assert_eq!(resp["result"]["isError"], json!(false));
    let via_mcp =
        from_json(&resp["result"]["structuredContent"], &TypeDesc::Any).expect("to Value");

    assert_eq!(via_cli, via_mcp);
    assert_eq!(
        via_cli,
        Value::Array(vec![Value::Str(a.to_string()), Value::Str(b.to_string())])
    );
}

#[test]
fn subcommand_path_and_flags_map_onto_command_and_params() {
    let store = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow("target.test", "/search?q=x"));
    let cli = cli_with(registry(), store);

    let got = cli
        .dispatch(&argv(&["flow", "get", "--id", &id.to_string()]))
        .expect("flow get ok");
    let Value::Object(fields) = got else {
        panic!("expected object, got {got:?}")
    };
    assert_eq!(fields["method"], Value::Str("GET".into()));
    assert_eq!(fields["authority"], Value::Str("target.test".into()));

    // Every TypeDesc from argv: `--flag value` and `--flag=value`; bare bool;
    // JSON for arrays/objects; UTF-8 text for bytes; Any tries JSON then text.
    let id = FlowId::new().to_string();
    let out = cli
        .dispatch(&argv(&[
            "demo",
            "echo",
            "--id",
            &id,
            "--limit=5",
            "--ratio",
            "0.5",
            "--verbose",
            "--raw",
            "Man",
            "--tags",
            r#"["a","b"]"#,
            "--edits",
            r#"{"method":"POST"}"#,
            "--extra",
            r#"{"n":1}"#,
        ]))
        .expect("echo ok");
    let mut want = BTreeMap::new();
    want.insert("id".to_string(), Value::Str(id.clone()));
    want.insert("limit".to_string(), Value::Int(5));
    want.insert("ratio".to_string(), Value::Float(0.5));
    want.insert("verbose".to_string(), Value::Bool(true));
    want.insert("raw".to_string(), Value::Bytes(b"Man".to_vec()));
    want.insert(
        "tags".to_string(),
        Value::Array(vec![Value::Str("a".into()), Value::Str("b".into())]),
    );
    let mut edits = BTreeMap::new();
    edits.insert("method".to_string(), Value::Str("POST".into()));
    want.insert("edits".to_string(), Value::Object(edits));
    let mut extra = BTreeMap::new();
    extra.insert("n".to_string(), Value::Int(1));
    want.insert("extra".to_string(), Value::Object(extra));
    assert_eq!(out, Value::Object(want));

    // Bool forms and Any-as-text.
    let out = cli
        .dispatch(&argv(&[
            "demo",
            "echo",
            "--id",
            &id,
            "--verbose",
            "false",
            "--extra",
            "hello",
        ]))
        .expect("echo ok");
    let Value::Object(fields) = out else {
        panic!("expected object")
    };
    assert_eq!(fields["verbose"], Value::Bool(false));
    assert_eq!(fields["extra"], Value::Str("hello".into()));
    let out = cli
        .dispatch(&argv(&["demo", "echo", "--id", &id, "--verbose=true"]))
        .expect("echo ok");
    let Value::Object(fields) = out else {
        panic!("expected object")
    };
    assert_eq!(fields["verbose"], Value::Bool(true));
    assert_eq!(fields.len(), 2, "optional flags absent stay absent");
}

#[test]
fn errors_name_the_command_or_flag() {
    let cli = cli();
    let id = FlowId::new().to_string();

    let e = err_text(cli.dispatch(&argv(&[])));
    assert!(
        e.contains("expected a command") && e.contains("Usage: aitm <group> <verb>"),
        "{e}"
    );

    let e = err_text(cli.dispatch(&argv(&["flow", "nope"])));
    assert!(e.contains("unknown command `flow nope`"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["--id", &id])));
    assert!(e.contains("command") && e.contains("before"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["flow", "get"])));
    assert!(e.contains("missing") && e.contains("--id"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["flow", "get", "--id"])));
    assert!(e.contains("--id") && e.contains("value"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["flow", "get", "--id", &id, "--bogus", "1"])));
    assert!(e.contains("unknown flag --bogus"), "{e}");
    assert!(e.contains("--id"), "lists the accepted flags: {e}");

    let e = err_text(cli.dispatch(&argv(&["flow", "get", "--id", "not-a-uuid"])));
    assert!(e.contains("--id"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["demo", "echo", "--id", &id, "--limit", "five"])));
    assert!(e.contains("--limit") && e.contains("integer"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["demo", "echo", "--id", &id, "--id", &id])));
    assert!(e.contains("--id") && e.contains("once"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["demo", "echo", "--id", &id, "stray"])));
    assert!(e.contains("stray"), "{e}");

    let e = err_text(cli.dispatch(&argv(&["demo", "echo", "--id", &id, "--tags", "[1]"])));
    assert!(e.contains("--tags"), "{e}");
}

#[test]
fn dispatch_without_services_is_an_error() {
    let cli = Cli::new(registry());
    let e = err_text(cli.dispatch(&argv(&["demo", "ping"])));
    assert!(e.contains("with_services"), "{e}");
}

// ------------------------------------------ M2 Task 17: Frontend::Cli, --yes

/// `demo.confirm`: asks `Proceed?` before running and reports which frontend
/// ran it; counts its invocations so a test can prove nothing ran.
struct ConfirmCmd {
    invoked: AtomicUsize,
}

impl Command for ConfirmCmd {
    fn name(&self) -> &str {
        "demo.confirm"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Asks before running.".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        let label = match host.frontend() {
            Frontend::Cli => "cli",
            Frontend::Mcp => "mcp",
            _ => "other",
        };
        Ok(Value::Str(label.into()))
    }
    fn confirm_prompt(&self, _args: &Params) -> Option<String> {
        Some("Proceed?".into())
    }
}

/// Answers every prompt the same way and records what it was asked.
struct ScriptedConfirmer {
    answer: bool,
    prompts: Mutex<Vec<String>>,
}

impl ScriptedConfirmer {
    fn new(answer: bool) -> Arc<Self> {
        Arc::new(Self {
            answer,
            prompts: Mutex::new(Vec::new()),
        })
    }
    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().unwrap().clone()
    }
}

impl Confirmer for ScriptedConfirmer {
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        self.prompts.lock().unwrap().push(prompt.to_string());
        Ok(self.answer)
    }
}

/// A CLI whose registry holds `demo.ping` and `demo.confirm`, plus the handle
/// to the confirm command so its invoke count can be read.
fn confirm_cli(confirmer: Option<Arc<dyn Confirmer>>) -> (Cli, Arc<ConfirmCmd>) {
    let cmd = Arc::new(ConfirmCmd {
        invoked: AtomicUsize::new(0),
    });
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(DemoPlugin));
    reg.add_command(cmd.clone());
    let mut cli = cli_with(Arc::new(reg), Arc::new(MemFlowStore::new()));
    if let Some(c) = confirmer {
        cli = cli.with_confirmer(c);
    }
    (cli, cmd)
}

/// CA-AC22 mechanics: the CLI host declares itself `Frontend::Cli`.
#[test]
fn frontend_is_cli() {
    let (cli, cmd) = confirm_cli(None);
    let out = cli
        .dispatch(&argv(&["demo", "confirm", "--yes"]))
        .expect("--yes skips the prompt");
    assert_eq!(out, Value::Str("cli".into()));
    assert_eq!(cmd.invoked.load(Ordering::SeqCst), 1);
}

/// CA-AC23 mechanics: `confirm_prompt` gates `invoke` through the `Confirmer`.
#[test]
fn confirmer_gates_invoke() {
    let no = ScriptedConfirmer::new(false);
    let (cli, cmd) = confirm_cli(Some(no.clone()));
    let e = err_text(cli.dispatch(&argv(&["demo", "confirm"])));
    assert!(e.contains("aborted"), "{e}");
    assert!(e.contains("demo confirm"), "names the command: {e}");
    assert_eq!(cmd.invoked.load(Ordering::SeqCst), 0, "nothing ran");
    assert_eq!(no.prompts(), vec!["Proceed?".to_string()]);

    let yes = ScriptedConfirmer::new(true);
    let (cli, cmd) = confirm_cli(Some(yes.clone()));
    let out = cli
        .dispatch(&argv(&["demo", "confirm"]))
        .expect("confirmed");
    assert_eq!(out, Value::Str("cli".into()));
    assert_eq!(cmd.invoked.load(Ordering::SeqCst), 1);
    assert_eq!(yes.prompts(), vec!["Proceed?".to_string()]);

    // With --yes the confirmer is never consulted.
    let yes = ScriptedConfirmer::new(true);
    let (cli, cmd) = confirm_cli(Some(yes.clone()));
    cli.dispatch(&argv(&["demo", "confirm", "--yes"]))
        .expect("--yes");
    assert_eq!(cmd.invoked.load(Ordering::SeqCst), 1);
    assert!(
        yes.prompts().is_empty(),
        "confirmer was asked: {:?}",
        yes.prompts()
    );
}

/// A non-interactive `TtyConfirmer` cannot ask, so it points at `--yes`.
#[test]
fn non_interactive_needs_yes() {
    let e = match TtyConfirmer::new(false).confirm("Proceed?") {
        Ok(v) => panic!("expected an error, got {v}"),
        Err(e) => format!("{e:#}"),
    };
    assert!(e.contains("--yes"), "{e}");
    assert!(e.contains("not a terminal"), "{e}");

    let (cli, cmd) = confirm_cli(Some(Arc::new(TtyConfirmer::new(false))));
    let e = err_text(cli.dispatch(&argv(&["demo", "confirm"])));
    assert!(e.contains("--yes"), "{e}");
    assert!(e.contains("demo confirm"), "names the command: {e}");
    assert_eq!(cmd.invoked.load(Ordering::SeqCst), 0);
}

/// `--yes` is reserved: accepted as a no-op by commands without a prompt, never
/// an unknown flag, and documented once in usage.
#[test]
fn yes_is_a_noop_elsewhere() {
    let cli = cli();
    let out = cli
        .dispatch(&argv(&["demo", "ping", "--yes"]))
        .expect("--yes is accepted everywhere");
    assert_eq!(out, Value::Str("pong".into()));

    let store = Arc::new(MemFlowStore::new());
    let id = store.insert(http_flow("target.test", "/"));
    let cli = cli_with(registry(), store);
    let got = cli
        .dispatch(&argv(&["flow", "get", "--yes", "--id", &id.to_string()]))
        .expect("--yes among real flags");
    let Value::Object(fields) = got else {
        panic!("expected object, got {got:?}")
    };
    assert_eq!(fields["authority"], Value::Str("target.test".into()));

    // Real unknown flags are still reported, and never blamed on --yes.
    let e = err_text(cli.dispatch(&argv(&["demo", "ping", "--yes", "--bogus"])));
    assert!(e.contains("unknown flag --bogus"), "{e}");
    assert!(!e.contains("unknown flag --yes"), "{e}");

    assert_eq!(cli.usage().matches("--yes").count(), 1, "{}", cli.usage());
}
