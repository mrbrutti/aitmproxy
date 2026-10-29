//! M2 Task 21 (CA-AC19–23): the `ca.*` family end to end through both
//! frontends. The proxy is assembled with a prebuilt `CaPlugin` over a
//! scripted executor, an in-memory audit log and a fixed macOS platform, so
//! the tests see every command line that would run and every audit record,
//! and the host's trust store is never touched.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm::wire::{assemble_with, Features};
use aitm_ca::testing::{MemoryAuditLog, ScriptedExecutor, FIXTURE_FP256};
use aitm_ca::{AuditRecord, CaPlugin, Platform};
use aitm_cli::{Cli, Confirmer, TtyConfirmer};
use aitm_core::{
    AgentPolicy, AgentState, CaConfig, Config, HttpFlow, HttpRequest, McpTransport, Proxy,
    ProxyClient, Value,
};
use aitm_mcp::McpServer;
use futures::future::BoxFuture;
use serde_json::{json, Value as JsonValue};

/// The checked-in fixture CA, placed in the scripted file map at `/ca/ca.crt`.
const FIXTURE: &[u8] = include_bytes!("../../aitm-ca/tests/fixtures/ca.crt");

const Q_USER: &str = "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db";
const ADD_USER: &str = "security add-trusted-cert -r trustRoot -p ssl -p basic -k \
                        /Users/t/Library/Keychains/login.keychain-db /ca/ca.crt";

/// CA-AC9: the exact lines a user-scope install runs against an absent store.
fn ac9_lines() -> Vec<String> {
    vec![Q_USER.to_string(), ADD_USER.to_string()]
}

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-cafe-{tag}-{nanos}-{n}"))
}

/// A `ProxyClient` no `ca.*` command calls.
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

/// Answers every prompt the same way and keeps what it was asked.
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

/// The assembled proxy plus the doubles behind its `ca.*` commands.
struct Harness {
    proxy: Proxy,
    exec: Arc<ScriptedExecutor>,
    audit: Arc<MemoryAuditLog>,
}

impl Harness {
    /// A real proxy (its own CA in a temp dir) whose `ca.*` commands run
    /// against the scripted `/ca/ca.crt` = fixture and an absent store.
    fn new(tag: &str, allow_agent_install: bool) -> Self {
        let mut cfg = Config::default();
        cfg.ca.dir = temp_ca_dir(tag);

        let ca_cfg = CaConfig {
            dir: PathBuf::from("/ca"),
            allow_agent_install,
            audit_log: PathBuf::from("/audit/ca-audit.jsonl"),
            ..cfg.ca.clone()
        };
        let exec = Arc::new(ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE));
        let audit = Arc::new(MemoryAuditLog::new());
        let plugin = CaPlugin::with_backend(ca_cfg, exec.clone(), audit.clone(), Platform::MacOs);

        let assembled = assemble_with(
            &cfg,
            &Features {
                ca_plugin: Some(plugin),
                ..Features::default()
            },
        )
        .expect("assemble");
        Self {
            proxy: assembled.proxy,
            exec,
            audit,
        }
    }

    fn mcp(&self) -> McpServer {
        let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
        // These CA tests exercise the agent reaching `ca.install`'s own config gate
        // (CA-AC19/20/21). Per spec D2 the agent reaches a Sensitive command's gate
        // only under `All` (or `Ask` with approval); the default `Auto` refuses every
        // Sensitive command outright, never deferring to the gate. Run them under
        // `All` so the config gate — not the policy — is what decides.
        McpServer::new(self.proxy.registry_arc(), McpTransport::Stdio)
            .with_services(self.proxy.store(), client, self.proxy.guard(), None)
            .with_agent_state(Arc::new(AgentState::new(AgentPolicy::All)))
    }

    fn cli(&self) -> Cli {
        let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
        Cli::new(self.proxy.registry_arc()).with_services(
            self.proxy.store(),
            client,
            self.proxy.guard(),
            None,
        )
    }

    fn records(&self) -> Vec<AuditRecord> {
        self.audit.records()
    }
}

fn rpc(server: &McpServer, id: u64, method: &str, params: JsonValue) -> JsonValue {
    let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let resp = server.handle(&req.to_string()).expect("a response");
    serde_json::from_str(&resp).expect("response is JSON")
}

fn call_tool(server: &McpServer, name: &str, arguments: JsonValue) -> JsonValue {
    let resp = rpc(
        server,
        1,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    );
    resp["result"].clone()
}

fn tool_text(result: &JsonValue) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    match v {
        Value::Object(fields) => fields
            .get(name)
            .unwrap_or_else(|| panic!("no field {name} in {fields:?}")),
        other => panic!("not an object: {other:?}"),
    }
}

// CA-AC19 then CA-AC20: with the flag off an agent is refused and nothing
// runs; with it on the install goes through with the CA-AC9 lines.
#[test]
fn mcp_refused_then_allowed() {
    for name in ["ca.install", "ca.uninstall"] {
        let h = Harness::new("refused", false);
        let server = h.mcp();

        let listed = rpc(&server, 1, "tools/list", json!({}));
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in ["ca.export", "ca.status", "ca.install", "ca.uninstall"] {
            assert!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }

        let result = call_tool(&server, name, json!({}));
        assert_eq!(result["isError"], json!(true), "{name}: {result}");
        let text = tool_text(&result);
        assert!(text.contains("ca.allow_agent_install"), "{name}: {text}");
        assert!(
            text.contains("AITM_CA_ALLOW_AGENT_INSTALL"),
            "{name}: {text}"
        );
        assert!(
            text.starts_with(&format!("{name} refused")),
            "{name}: {text}"
        );
        assert_eq!(h.exec.runs(), Vec::<String>::new(), "{name} ran something");

        let records = h.records();
        assert_eq!(records.len(), 1, "{name}: {records:?}");
        assert_eq!(records[0].command, name);
        assert_eq!(records[0].frontend, "mcp");
        assert_eq!(records[0].outcome, "refused");
        assert_eq!(
            records[0].fingerprint_sha256.as_deref(),
            Some(FIXTURE_FP256)
        );
    }

    let h = Harness::new("allowed", true);
    let server = h.mcp();
    let result = call_tool(&server, "ca.install", json!({}));
    assert_eq!(result["isError"], json!(false), "{result}");
    let structured = &result["structuredContent"];
    assert_eq!(structured["changed"], json!(true), "{structured}");
    assert_eq!(structured["dry_run"], json!(false));
    assert_eq!(structured["scope"], json!("user"));
    assert_eq!(structured["platform"], json!("macos"));
    assert_eq!(structured["fingerprint_sha256"], json!(FIXTURE_FP256));
    assert_eq!(structured["commands"], json!(ac9_lines()));
    assert_eq!(h.exec.runs(), ac9_lines());

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.install");
    assert_eq!(records[0].outcome, "ok");
    assert_eq!(records[0].frontend, "mcp");
    assert_eq!(records[0].scope.as_deref(), Some("user"));
    assert_eq!(records[0].platform.as_deref(), Some("macos"));
}

// CA-AC21: dry_run passes the gate, lists the mutation, runs only the query.
#[test]
fn mcp_dry_run() {
    let h = Harness::new("dry", false);
    let server = h.mcp();
    let result = call_tool(&server, "ca.install", json!({"dry_run": true}));
    assert_eq!(result["isError"], json!(false), "{result}");
    let structured = &result["structuredContent"];
    assert_eq!(structured["dry_run"], json!(true));
    assert_eq!(structured["changed"], json!(true));
    let commands: Vec<&str> = structured["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(commands.contains(&ADD_USER), "{commands:?}");
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string()]);

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome, "dry_run");
    assert_eq!(records[0].frontend, "mcp");
    assert_eq!(records[0].command, "ca.install");
}

// CA-AC22: the human CLI is never gated by the flag.
#[test]
fn cli_ungated_with_yes() {
    let h = Harness::new("cli-yes", false);
    let v = h
        .cli()
        .dispatch(&argv(&["ca", "install", "--yes"]))
        .expect("ca install --yes");
    assert_eq!(field(&v, "changed"), &Value::Bool(true));
    assert_eq!(field(&v, "scope"), &Value::Str("user".into()));
    assert_eq!(h.exec.runs(), ac9_lines());

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.install");
    assert_eq!(records[0].frontend, "cli");
    assert_eq!(records[0].outcome, "ok");
}

// CA-AC23: the CLI asks before a trust-store change, and only then.
#[test]
fn cli_confirmation() {
    // "no": asked once, nothing invoked, nothing recorded.
    let h = Harness::new("confirm-no", false);
    let confirmer = ScriptedConfirmer::new(false);
    let err = h
        .cli()
        .with_confirmer(confirmer.clone())
        .dispatch(&argv(&["ca", "install"]))
        .expect_err("a refused prompt must abort");
    let text = format!("{err:#}");
    assert!(text.contains("aborted"), "{text}");
    let prompts = confirmer.prompts();
    assert_eq!(prompts.len(), 1, "{prompts:?}");
    assert!(prompts[0].contains(FIXTURE_FP256), "{}", prompts[0]);
    assert!(prompts[0].contains("scope user"), "{}", prompts[0]);
    assert!(prompts[0].contains("--ca-cert"), "{}", prompts[0]);
    assert_eq!(h.exec.runs(), Vec::<String>::new(), "nothing may run");
    assert!(h.records().is_empty(), "{:?}", h.records());

    // "yes": asked once, then the install runs.
    let h = Harness::new("confirm-yes", false);
    let confirmer = ScriptedConfirmer::new(true);
    let v = h
        .cli()
        .with_confirmer(confirmer.clone())
        .dispatch(&argv(&["ca", "install"]))
        .expect("confirmed install");
    assert_eq!(field(&v, "changed"), &Value::Bool(true));
    assert_eq!(confirmer.prompts().len(), 1);
    assert_eq!(h.exec.runs(), ac9_lines());
    assert_eq!(h.records().len(), 1);

    // --yes: not asked.
    let h = Harness::new("confirm-flag", false);
    let confirmer = ScriptedConfirmer::new(false);
    h.cli()
        .with_confirmer(confirmer.clone())
        .dispatch(&argv(&["ca", "install", "--yes"]))
        .expect("--yes skips the prompt");
    assert!(confirmer.prompts().is_empty(), "{:?}", confirmer.prompts());
    assert_eq!(h.exec.runs(), ac9_lines());

    // --dry_run: not asked, nothing mutated.
    let h = Harness::new("confirm-dry", false);
    let confirmer = ScriptedConfirmer::new(false);
    let v = h
        .cli()
        .with_confirmer(confirmer.clone())
        .dispatch(&argv(&["ca", "install", "--dry_run"]))
        .expect("dry run needs no prompt");
    assert_eq!(field(&v, "dry_run"), &Value::Bool(true));
    assert!(confirmer.prompts().is_empty(), "{:?}", confirmer.prompts());
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string()]);

    // No terminal: refused with the way out named.
    let h = Harness::new("confirm-tty", false);
    let err = h
        .cli()
        .with_confirmer(Arc::new(TtyConfirmer::new(false)))
        .dispatch(&argv(&["ca", "install"]))
        .expect_err("no tty must refuse");
    assert!(format!("{err:#}").contains("--yes"), "{err:#}");
    assert_eq!(h.exec.runs(), Vec::<String>::new());

    // The reserved flag is a no-op on a command that does not ask.
    let h = Harness::new("status-yes", false);
    let confirmer = ScriptedConfirmer::new(false);
    let v = h
        .cli()
        .with_confirmer(confirmer.clone())
        .dispatch(&argv(&["ca", "status", "--yes"]))
        .expect("ca status --yes");
    assert_eq!(field(&v, "exists"), &Value::Bool(true));
    assert!(confirmer.prompts().is_empty());
}
