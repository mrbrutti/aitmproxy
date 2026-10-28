//! M2 Task 7: the additive core types — engine selection and obscura defaults,
//! the CA agent-install gate and audit-log path, the frontend a `CommandHost`
//! declares, and the defaulted `Command::confirm_prompt`.

use std::collections::BTreeMap;
use std::time::Duration;

use aitm_core::{
    BrowserConfig, BrowserEngine, CaConfig, Command, CommandHost, Frontend, HttpFlow, HttpRequest,
    MemFlowStore, ObscuraConfig, ParamSchema, Params, ProxyClient, StdGuard, TypeDesc, Value,
};
use futures::future::BoxFuture;

#[test]
fn browser_defaults() {
    let cfg = BrowserConfig::default();
    assert_eq!(cfg.engine, BrowserEngine::Obscura);
    let obscura: ObscuraConfig = cfg.obscura;
    assert_eq!(obscura.binary, None);
    assert_eq!(obscura.start_timeout, Duration::from_secs(15));
    assert_eq!(obscura.stop_timeout, Duration::from_secs(5));
}

#[test]
fn ca_defaults() {
    let cfg = CaConfig::default();
    assert!(
        !cfg.allow_agent_install,
        "agent install must be off by default"
    );
    assert_eq!(
        cfg.audit_log.file_name().and_then(|n| n.to_str()),
        Some("ca-audit.jsonl")
    );
    // A sibling of the CA dir, never inside it: the commands open exactly one
    // file in the CA directory.
    assert_eq!(cfg.audit_log.parent(), cfg.dir.parent());
    assert!(
        !cfg.audit_log.starts_with(&cfg.dir),
        "audit log {:?} must not live inside the CA dir {:?}",
        cfg.audit_log,
        cfg.dir
    );
}

/// A `ProxyClient` stub: the host needs one, but nothing here calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

#[test]
fn frontend_defaults_to_mcp() {
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    assert_eq!(host.frontend(), Frontend::Mcp);
    let host = host.with_frontend(Frontend::Cli);
    assert_eq!(host.frontend(), Frontend::Cli);
}

/// A command that does not override `confirm_prompt`.
struct PlainCmd;

impl Command for PlainCmd {
    fn name(&self) -> &str {
        "demo.plain"
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "plain".into(),
            params: vec![],
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str("ok".into()))
    }
}

#[test]
fn confirm_prompt_defaults_to_none() {
    assert_eq!(PlainCmd.confirm_prompt(&Params::new(BTreeMap::new())), None);
}
