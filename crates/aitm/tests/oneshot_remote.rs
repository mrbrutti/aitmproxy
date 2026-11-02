//! R14 Task 10 (AC-R14-24, spec D8): the one-shot's remote path, in-process.
//!
//! Every test here drives `oneshot::remote` through `aitm_bus_client::
//! BusClient` over `InProcessTransport`, whose handler is `McpServer::
//! handle_on(&ConnCtx::new(role), line)` on a server built exactly as the
//! binary builds its operator bus (`tui::server` + `with_mcp_roles`) over a
//! real assembly (`support::assemble_services`). No socket is bound, so the
//! file runs in the sandbox; the TCP half (`remote::connect`) is proved live.

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm::oneshot::args::BusArgs;
use aitm::oneshot::refuse::{is_cli_only_gate, CoreRef};
use aitm::oneshot::remote::{
    self, absolutize_paths, generic_arguments, prepare, Prepared, RemoteError,
};
use aitm::oneshot::resolve::{Source, Target};
use aitm::oneshot::run::{refusal, OneShotError, Site, Stage};
use aitm::render::render_cli_value;
use aitm::tui;
use aitm_bus_client::{BusClient, InProcessHandler, InProcessTransport};
use aitm_cli::{Cli, Confirmer};
use aitm_core::{
    Command, CommandHost, Frontend, McpTransport, ParamDef, ParamSchema, Params, Registry,
    TypeDesc, Value,
};
use aitm_mcp::{ConnCtx, McpServer};
use aitm_term::error::FixCommand;
use serde_json::{json, Value as JsonValue};
use support::{assemble_services, config};

/// A test-only operator token (plan rule 6: never one that looks real).
const OP_TOKEN: &str = "optoken-test-op";
/// The handshake and call budgets the one-shot uses (spec D8).
const HANDSHAKE: Duration = Duration::from_secs(2);
const CALL: Duration = Duration::from_secs(30);
/// A log path for the `with_log` pin.
const LOG: &str = "/l/aitm.log";
/// A fixed clock for the age words.
const NOW: u64 = 1_761_998_645;

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Answers every prompt the same way and keeps what it was asked.
struct Always {
    answer: bool,
    prompts: Mutex<Vec<String>>,
}

impl Always {
    fn new(answer: bool) -> Self {
        Self {
            answer,
            prompts: Mutex::new(Vec::new()),
        }
    }

    fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompts").clone()
    }
}

impl Confirmer for Always {
    fn confirm(&self, prompt: &str) -> anyhow::Result<bool> {
        self.prompts
            .lock()
            .expect("prompts")
            .push(prompt.to_string());
        Ok(self.answer)
    }
}

/// A `BusClient` whose every line is handled by `server` as one connection
/// speaking as `role`.
fn client_over(server: Arc<McpServer>, role: Frontend) -> BusClient {
    let handler: InProcessHandler =
        Arc::new(move |line: &str| server.handle_on(&ConnCtx::new(role), line));
    BusClient::new(Box::new(InProcessTransport::new(handler)))
}

/// A full assembly served in-process to one connection of `role`, the server
/// built as the binary builds its operator bus.
struct Rig {
    _proxy: aitm_core::Proxy,
    services: tui::Services,
    client: BusClient,
}

fn rig(tag: &str, operator_token: Option<&str>, role: Frontend) -> Rig {
    let cfg = config(tag);
    let (proxy, services, _governance) = assemble_services(&cfg);
    let server = Arc::new(
        tui::server(&cfg, McpTransport::Stdio, &services)
            .with_mcp_roles(operator_token.map(str::to_string), Frontend::Mcp),
    );
    let client = client_over(server, role);
    Rig {
        _proxy: proxy,
        services,
        client,
    }
}

/// A server over a fresh registry holding only `commands`, with a real
/// assembly's services behind it, served to one operator connection.
fn rig_with(tag: &str, commands: Vec<Arc<dyn Command>>) -> Rig {
    let cfg = config(tag);
    let (proxy, services, _governance) = assemble_services(&cfg);
    let mut registry = Registry::new();
    for cmd in commands {
        registry.add_command(cmd);
    }
    let server = Arc::new(
        McpServer::new(Arc::new(registry), McpTransport::Stdio)
            .with_mcp_roles(Some(OP_TOKEN.to_string()), Frontend::Mcp)
            .with_services(
                services.store.clone(),
                services.client.clone(),
                services.guard.clone(),
                None,
            ),
    );
    let client = client_over(server, Frontend::Operator);
    Rig {
        _proxy: proxy,
        services,
        client,
    }
}

fn target(addr: &str, source: Source, config: Option<&str>) -> Target {
    Target {
        addr: addr.parse().expect("socket addr"),
        token: OP_TOKEN.to_string(),
        source,
        config: config.map(PathBuf::from),
    }
}

fn site<'a>(target: &'a Target, dotted: &'a str, bus_args: &'a BusArgs) -> Site<'a> {
    Site {
        dotted,
        target,
        bus_args,
        effective_path: Path::new("/x/config.yaml"),
        explicit_config: false,
        budget: CALL,
        now_unix: NOW,
    }
}

fn report(err: OneShotError) -> aitm_term::error::ErrorReport {
    match err {
        OneShotError::Report(r) => r,
        OneShotError::Other(e) => panic!("expected a report, got an error: {e:#}"),
    }
}

// ------------------------------------------------------------------ tests

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_add_then_list_over_the_bus_renders_like_local() {
    let rig = rig("remote-scope", Some(OP_TOKEN), Frontend::Operator);
    let info = remote::handshake(&rig.client, HANDSHAKE)
        .await
        .expect("handshake");
    assert_eq!(info.role.as_deref(), Some("operator"));

    let yes = Always::new(true);
    let added = remote::call(
        &rig.client,
        "scope.add",
        json!({"host": "example.com"}),
        CALL,
        &yes,
        false,
    )
    .await
    .expect("scope.add");
    assert_eq!(added, JsonValue::String("example.com".into()));
    assert_eq!(
        remote::render(&added, &TypeDesc::Str).expect("render"),
        b"example.com\n"
    );

    let listed = remote::call(&rig.client, "scope.list", json!({}), CALL, &yes, false)
        .await
        .expect("scope.list");
    assert_eq!(listed, json!(["example.com"]));
    let remote_bytes =
        remote::render(&listed, &TypeDesc::Array(Box::new(TypeDesc::Str))).expect("render");
    assert_eq!(remote_bytes, b"[\n  \"example.com\"\n]\n");

    // The local `Cli` over the same registry and guard renders byte-identically
    // (decision (f), AC-R14-24).
    let cli = Cli::new(rig.services.registry.clone()).with_services(
        rig.services.store.clone(),
        rig.services.client.clone(),
        rig.services.guard.clone(),
        None,
    );
    let local = cli
        .dispatch(&args(&["scope", "list"]))
        .expect("local scope.list");
    assert_eq!(render_cli_value(&local), remote_bytes);
    assert!(yes.prompts().is_empty(), "scope verbs ask nothing");
}

/// `demo.bytes` → four bytes that are not UTF-8 (a PNG signature start).
struct DemoBytes;

impl Command for DemoBytes {
    fn name(&self) -> &str {
        "demo.bytes"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "four bytes".into(),
            params: Vec::new(),
            result: TypeDesc::Bytes,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Bytes(vec![0x89, b'P', b'N', b'G']))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_round_trip_through_base64() {
    let rig = rig_with("remote-bytes", vec![Arc::new(DemoBytes)]);
    remote::handshake(&rig.client, HANDSHAKE)
        .await
        .expect("handshake");
    let result = remote::call(
        &rig.client,
        "demo.bytes",
        json!({}),
        CALL,
        &Always::new(true),
        false,
    )
    .await
    .expect("demo.bytes");
    // On the wire the bytes are base64 (research F10) …
    assert_eq!(result, JsonValue::String("iVBORw==".into()));
    // … and the one-shot prints the original bytes, raw.
    assert_eq!(
        remote::render(&result, &TypeDesc::Bytes).expect("render"),
        [0x89, 0x50, 0x4e, 0x47]
    );
}

/// `demo.confirm --what <x>`: asks `really <x>?` (with a control sequence the
/// one-shot must neutralise) and counts how often it actually ran.
struct DemoConfirm {
    runs: AtomicUsize,
}

impl Command for DemoConfirm {
    fn name(&self) -> &str {
        "demo.confirm"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "a confirm-gated demo".into(),
            params: vec![ParamDef {
                name: "what".into(),
                ty: TypeDesc::Str,
                required: true,
                description: "what to do".into(),
            }],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(Value::Str(format!("did {}", args.get_str("what")?)))
    }
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        let what = args.get_str("what").unwrap_or("it");
        Some(format!("really {what}?\x1b[2J"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn needs_confirmation_is_resent_with_the_token_or_aborted() {
    let cmd = Arc::new(DemoConfirm {
        runs: AtomicUsize::new(0),
    });
    let rig = rig_with("remote-confirm", vec![cmd.clone()]);
    remote::handshake(&rig.client, HANDSHAKE)
        .await
        .expect("handshake");

    // Yes: the identical call is re-sent with `_confirm` and the command runs once.
    let yes = Always::new(true);
    let result = remote::call(
        &rig.client,
        "demo.confirm",
        json!({"what": "x"}),
        CALL,
        &yes,
        false,
    )
    .await
    .expect("confirmed call");
    assert_eq!(result, JsonValue::String("did x".into()));
    assert_eq!(cmd.runs.load(Ordering::SeqCst), 1);
    // The core's prompt reached the confirmer sanitized (plan C8): the escape
    // byte is U+FFFD, the rest verbatim.
    assert_eq!(yes.prompts(), vec!["really x?\u{FFFD}[2J".to_string()]);

    // No: aborted with today's wording in the space form; the command did not run.
    let no = Always::new(false);
    let err = remote::call(
        &rig.client,
        "demo.confirm",
        json!({"what": "y"}),
        CALL,
        &no,
        false,
    )
    .await
    .expect_err("a no aborts");
    match err {
        RemoteError::Aborted(text) => assert_eq!(text, "aborted: demo confirm not run"),
        other => panic!("expected Aborted, got {other:?}"),
    }
    assert_eq!(cmd.runs.load(Ordering::SeqCst), 1);
    assert_eq!(no.prompts(), vec!["really y?\u{FFFD}[2J".to_string()]);

    // --yes: nobody is asked; the token is re-sent at once.
    let counting = Always::new(false);
    let result = remote::call(
        &rig.client,
        "demo.confirm",
        json!({"what": "z"}),
        CALL,
        &counting,
        true,
    )
    .await
    .expect("--yes call");
    assert_eq!(result, JsonValue::String("did z".into()));
    assert_eq!(cmd.runs.load(Ordering::SeqCst), 2);
    assert!(counting.prompts().is_empty(), "--yes asks nobody");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_error_and_gate_sentence_map_to_the_right_reports() {
    let rig = rig("remote-gate", Some(OP_TOKEN), Frontend::Operator);
    remote::handshake(&rig.client, HANDSHAKE)
        .await
        .expect("handshake");
    let yes = Always::new(true);

    // The real `Frontend::Cli`-only gate (research F14) refuses an operator.
    let err = remote::call(
        &rig.client,
        "tls.passthrough.add",
        json!({"host": "example.com"}),
        CALL,
        &yes,
        false,
    )
    .await
    .expect_err("the gate refuses an operator connection");
    let gate = match err {
        RemoteError::Tool(text) => text,
        other => panic!("expected Tool, got {other:?}"),
    };
    assert!(gate.starts_with("tls.passthrough.add refused: "), "{gate}");
    assert!(is_cli_only_gate(&gate));

    let bus = BusArgs::default();
    let pointer = target(
        "127.0.0.1:50512",
        Source::Pointer {
            path: "/r/4821.json".into(),
            pid: 4821,
            started_unix: NOW - 720,
        },
        Some("/y/config.yaml"),
    );
    let r9 = report(refusal(
        RemoteError::Tool(gate.clone()),
        Stage::Call,
        &site(&pointer, "tls.passthrough.add", &bus),
        &[],
        Some(PathBuf::from(LOG)),
    ));
    assert_eq!(r9.what, gate);
    assert_eq!(
        r9.why,
        vec![
            "This one-shot reached the core at 127.0.0.1:50512 as an operator; that verb admits \
             only an in-process CLI, which has no running core to change. The app and the TUI \
             are refused by the same gate. Nothing was changed."
                .to_string()
        ]
    );
    assert_eq!(
        r9.fix.as_deref(),
        Some("Set the config key the sentence names in /y/config.yaml and restart the core.")
    );
    assert_eq!(r9.command, None);
    assert_eq!(r9.log, Some(PathBuf::from(LOG)));

    // Any other `isError` text is the core's sentence, verbatim and alone (T6).
    let err = remote::call(
        &rig.client,
        "scope.add",
        json!({"host": ""}),
        CALL,
        &yes,
        false,
    )
    .await
    .expect_err("an empty host is refused");
    let text = match err {
        RemoteError::Tool(text) => text,
        other => panic!("expected Tool, got {other:?}"),
    };
    assert_eq!(
        text,
        "scope.add: \"\" is not a host, host:port, or *.wildcard"
    );
    assert!(!is_cli_only_gate(&text));
    let failure = report(refusal(
        RemoteError::Tool(text.clone()),
        Stage::Call,
        &site(&pointer, "scope.add", &bus),
        &[],
        None,
    ));
    assert_eq!(failure.what, text);
    assert!(failure.why.is_empty());
    assert_eq!(failure.fix, None);
    assert_eq!(failure.command, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_role_is_refused() {
    let rig = rig("remote-agent", None, Frontend::Mcp);
    let err = remote::handshake(&rig.client, HANDSHAKE)
        .await
        .expect_err("an agent connection is refused");
    assert!(matches!(err, RemoteError::Agent), "{err:?}");

    let bus = BusArgs::default();
    let port = target("127.0.0.1:9090", Source::ConfigPort, Some("/x/config.yaml"));
    let r8 = report(refusal(
        RemoteError::Agent,
        Stage::Handshake,
        &site(&port, "scope.add", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r8.what,
        "the core at 127.0.0.1:9090 would treat this as an agent"
    );
    assert_eq!(
        r8.command,
        Some(FixCommand("aitm operator-token generate --force".into()))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_keeps_w1_usage_errors() {
    let (_proxy, services, _governance) = assemble_services(&config("remote-prepare"));
    let reg = &services.registry;

    let err = prepare(reg, &args(&["nonsense"])).expect_err("unknown command");
    assert!(
        err.to_string().starts_with("unknown command `nonsense`"),
        "{err}"
    );
    let err = prepare(reg, &args(&["--x"])).expect_err("flag first");
    assert!(
        err.to_string()
            .starts_with("expected a command before flags, got `--x`"),
        "{err}"
    );
    let err = prepare(reg, &args(&["flow", "list", "--bogus", "1"])).expect_err("unknown flag");
    assert!(
        err.to_string()
            .starts_with("unknown flag --bogus for `flow.list`"),
        "{err}"
    );

    match prepare(reg, &args(&["custom", "verb", "--k", "1", "--flag"])).expect("unresolved") {
        Prepared::Unresolved { dotted, flags, yes } => {
            assert_eq!(dotted, "custom.verb");
            assert_eq!(flags, args(&["--k", "1", "--flag"]));
            assert!(!yes);
        }
        Prepared::Typed { .. } => panic!("a verb the registry lacks is Unresolved"),
    }
    match prepare(
        reg,
        &args(&["scope", "add", "--host", "example.com", "--yes"]),
    )
    .expect("typed")
    {
        Prepared::Typed { cmd, params, yes } => {
            assert_eq!(cmd.name(), "scope.add");
            assert_eq!(params.get("host"), Some(&Value::Str("example.com".into())));
            assert!(yes);
        }
        Prepared::Unresolved { .. } => panic!("scope.add is in the registry"),
    }
}

#[test]
fn generic_arguments_and_absolutize() {
    let got = generic_arguments(&args(&[
        "--k",
        "1",
        "--s",
        "text",
        "--b",
        "--j",
        "{\"a\":1}",
    ]))
    .expect("parses");
    assert_eq!(
        JsonValue::Object(got),
        json!({"k": 1, "s": "text", "b": true, "j": {"a": 1}})
    );
    let eq = generic_arguments(&args(&["--k=v", "--n=2"])).expect("inline form");
    assert_eq!(JsonValue::Object(eq), json!({"k": "v", "n": 2}));
    let err = generic_arguments(&args(&["--k", "1", "--k", "2"])).expect_err("repeated");
    assert_eq!(err.to_string(), "flag --k given more than once");

    let mut v = json!({"poc_path": "x.yaml", "path": "/abs", "other": "y"});
    absolutize_paths(&mut v, Path::new("/w"));
    assert_eq!(
        v,
        json!({"poc_path": "/w/x.yaml", "path": "/abs", "other": "y"})
    );
}

#[test]
fn connect_and_call_failures_map_by_source_and_stage() {
    let bus = BusArgs::default();
    let log = Some(PathBuf::from(LOG));

    // R2: the config's port refuses; a live pointer elsewhere is named.
    let port = target("127.0.0.1:9090", Source::ConfigPort, Some("/x/config.yaml"));
    let others = [CoreRef {
        addr: "127.0.0.1:50512".parse().expect("addr"),
        pid: Some(4821),
        started_unix: Some(NOW - 720),
        config: Some("/y/c.yaml".into()),
    }];
    let r2 = report(refusal(
        RemoteError::Lost("refused".into()),
        Stage::Connect,
        &site(&port, "scope.list", &bus),
        &others,
        log.clone(),
    ));
    assert_eq!(r2.what, "no running core at 127.0.0.1:9090");
    assert_eq!(
        r2.why[1],
        "A different core is running at 127.0.0.1:50512 (pid 4821, started 12 min ago, config \
         /y/c.yaml); pass --bus 127.0.0.1:50512 to use it."
    );
    assert_eq!(r2.command, Some(FixCommand("aitm".into())));
    assert_eq!(r2.log, log);

    // R2': an explicit address refuses (env form).
    let env = target("127.0.0.1:1", Source::ExplicitEnv, None);
    let r2e = report(refusal(
        RemoteError::Lost("refused".into()),
        Stage::Handshake,
        &site(&env, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(r2e.what, "no running core at 127.0.0.1:1");
    assert_eq!(
        r2e.why,
        vec![
            "Nothing is listening at the address AITM_BUS named, so scope list has nothing to \
              change. Nothing was changed."
                .to_string()
        ]
    );

    // R3: the endpoint file's address refuses.
    let endpoint = target(
        "127.0.0.1:60680",
        Source::ConfigEndpointFile("/e/bus.addr".into()),
        Some("/x/config.yaml"),
    );
    let r3 = report(refusal(
        RemoteError::Lost("refused".into()),
        Stage::Connect,
        &site(&endpoint, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(r3.what, "no running core at 127.0.0.1:60680");
    assert_eq!(
        r3.why,
        vec![
            "The endpoint file /e/bus.addr names an address nothing is listening on; the core \
              that wrote it has exited. Nothing was changed."
                .to_string()
        ]
    );

    // R4: a locked pointer's address refuses.
    let pointer = target(
        "127.0.0.1:50512",
        Source::Pointer {
            path: "/r/4821.json".into(),
            pid: 4821,
            started_unix: NOW - 720,
        },
        Some("/y/config.yaml"),
    );
    let r4 = report(refusal(
        RemoteError::Lost("refused".into()),
        Stage::Connect,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(r4.what, "no running core at 127.0.0.1:50512");
    assert_eq!(
        r4.why,
        vec![
            "The core pointer /r/4821.json names process 4821, which is running but not \
              listening there, so scope list has nothing to change. If that core has exited, \
              delete the file. Nothing was changed."
                .to_string()
        ]
    );

    // R10: the handshake budget (no verb) and the call budget (with the verb).
    let r10h = report(refusal(
        RemoteError::Timeout(Duration::from_millis(300)),
        Stage::Handshake,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r10h.what,
        "the core at 127.0.0.1:50512 accepted the connection but did not answer within 2 s"
    );
    let r10c = report(refusal(
        RemoteError::Timeout(CALL),
        Stage::Call,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r10c.what,
        "the core at 127.0.0.1:50512 accepted the connection but did not answer scope list \
         within 30 s"
    );

    // R12: the connection drops mid-call.
    let r12 = report(refusal(
        RemoteError::Lost("bus connection closed: eof".into()),
        Stage::Call,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r12.what,
        "lost the core at 127.0.0.1:50512 while running scope list"
    );
    assert_eq!(
        r12.why,
        vec!["bus connection closed: eof. Whether anything changed is unknown.".to_string()]
    );

    // R7: the token's locator follows the source.
    let flag = target("127.0.0.1:1", Source::ExplicitFlag, None);
    let with_file = BusArgs {
        bus: Some("127.0.0.1:1".into()),
        token_file: Some("/t/token".into()),
    };
    let r7f = report(refusal(
        RemoteError::Refused,
        Stage::Handshake,
        &site(&flag, "scope.list", &with_file),
        &[],
        None,
    ));
    assert_eq!(
        r7f.what,
        "the core at 127.0.0.1:1 refused the operator token in /t/token"
    );
    let r7e = report(refusal(
        RemoteError::Refused,
        Stage::Handshake,
        &site(&env, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r7e.what,
        "the core at 127.0.0.1:1 refused the operator token in AITM_BUS_TOKEN"
    );
    let r7c = report(refusal(
        RemoteError::Refused,
        Stage::Handshake,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ));
    assert_eq!(
        r7c.what,
        "the core at 127.0.0.1:50512 refused the operator token in /y/config.yaml"
    );

    // An abort is today's plain error (exit 1 through `report_for`), not a panel.
    match refusal(
        RemoteError::Aborted("aborted: scope list not run".into()),
        Stage::Call,
        &site(&pointer, "scope.list", &bus),
        &[],
        None,
    ) {
        OneShotError::Other(e) => assert_eq!(e.to_string(), "aborted: scope list not run"),
        OneShotError::Report(r) => panic!("an abort is not a panel: {r:?}"),
    }
}
