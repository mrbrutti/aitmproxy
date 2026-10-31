//! `agent.status.durable_audit` (spec Design 11; AC32, AC33, AC35).
//!
//! The commands are invoked directly, the way `agent_gates.rs` and `control.rs` do:
//! a `Registry` carrying the real plugins, a `CommandHost` per call that declares
//! (or, for the agent, never declares) its frontend. The durable sink is a stub
//! with a fixed status; the real writer lives in the `aitm` binary.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use aitm_core::{
    AgentPolicy, AgentState, AuditEntry, AuditLane, AuditLogSetting, AuditRing, CommandHost,
    Config, DurableAudit, DurableAuditStatus, Frontend, HttpFlow, HttpRequest, MemFlowStore,
    ParamDef, Params, ProxyClient, Registry, StdGuard, TypeDesc, Value,
};
use aitm_plugins::{AgentPlugin, ControlPlugin};
use futures::future::BoxFuture;

/// The path the AC35 guard looks for. It lives only on the stub sink's `Debug` and
/// in the `Config` handed to `config.get`: no command may ever echo it.
const SECRET_PATH: &str = "/secret/audit.jsonl";

/// A `ProxyClient` that fails if a command ever reaches for the network.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A durable sink with a fixed health snapshot. It also carries a path (as the
/// real writer does), which `status()` never reports.
#[derive(Debug)]
struct StubSink {
    status: DurableAuditStatus,
    #[allow(dead_code)] // read through `Debug` only: the guard's canary
    path: PathBuf,
}

impl StubSink {
    fn new(status: DurableAuditStatus) -> Arc<Self> {
        Arc::new(Self {
            status,
            path: PathBuf::from(SECRET_PATH),
        })
    }
}

impl DurableAudit for StubSink {
    fn record(&self, _lane: AuditLane, _entry: AuditEntry) {}

    fn status(&self) -> DurableAuditStatus {
        self.status
    }
}

/// A registry holding the real `AgentPlugin` over `ring`.
fn status_registry(ring: &Arc<AuditRing>) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        AgentPlugin::new(Arc::new(AgentState::new(AgentPolicy::Auto)))
            .with_audit_ring(ring.clone()),
    ));
    reg
}

/// Invoke `name` as `frontend` (`None` = a host never given a frontend, which is the
/// agent role), over a fresh store, stub client and default guard.
fn invoke(
    reg: &Registry,
    name: &str,
    frontend: Option<Frontend>,
    config: Option<Arc<Config>>,
) -> Value {
    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    let host = match frontend {
        Some(f) => host.with_frontend(f),
        None => host,
    };
    let host = match config {
        Some(c) => host.with_config(c),
        None => host,
    };
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(Params::default(), &host)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The `durable_audit` object of an `agent.status` result; panics, quoting the
/// result, when it is absent or not an object.
fn durable_audit(result: &Value) -> BTreeMap<String, Value> {
    let Value::Object(top) = result else {
        panic!("agent.status is an object: {result:?}");
    };
    match top.get("durable_audit") {
        Some(Value::Object(map)) => map.clone(),
        Some(other) => panic!("durable_audit is not an object: {other:?}"),
        None => panic!("missing durable_audit in {top:?}"),
    }
}

/// An object value's map from `(key, value)` pairs.
fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// A stub status as the spec's AC32 gives it.
fn degraded_status() -> DurableAuditStatus {
    DurableAuditStatus {
        degraded: true,
        dropped: 7,
        write_failures: 3,
    }
}

/// AC32: `enabled` and `degraded` reach every role; `dropped` and `write_failures`
/// reach trusted control only. Without a sink the object is the disabled one.
#[test]
fn agent_status_reports_durable_audit_by_role() {
    let ring = Arc::new(AuditRing::default());
    let reg = status_registry(&ring);

    // No sink attached.
    let operator = invoke(&reg, "agent.status", Some(Frontend::Operator), None);
    assert_eq!(
        durable_audit(&operator),
        map(&[
            ("enabled", Value::Bool(false)),
            ("degraded", Value::Bool(false)),
            ("dropped", Value::Int(0)),
            ("write_failures", Value::Int(0)),
        ]),
        "operator, no sink: {operator:?}"
    );
    let agent = invoke(&reg, "agent.status", None, None);
    assert_eq!(
        durable_audit(&agent),
        map(&[
            ("enabled", Value::Bool(false)),
            ("degraded", Value::Bool(false)),
        ]),
        "agent, no sink: {agent:?}"
    );
    let agent_debug = format!("{agent:?}");
    for word in ["dropped", "write_failures"] {
        assert!(
            !agent_debug.contains(word),
            "the agent's result (no sink) names `{word}`: {agent_debug}"
        );
    }

    // A degraded sink with counters attached to the same ring.
    assert!(
        ring.attach_durable(StubSink::new(degraded_status())),
        "the first sink attaches"
    );
    let operator = invoke(&reg, "agent.status", Some(Frontend::Operator), None);
    assert_eq!(
        durable_audit(&operator),
        map(&[
            ("enabled", Value::Bool(true)),
            ("degraded", Value::Bool(true)),
            ("dropped", Value::Int(7)),
            ("write_failures", Value::Int(3)),
        ]),
        "operator, degraded sink: {operator:?}"
    );
    let cli = invoke(&reg, "agent.status", Some(Frontend::Cli), None);
    assert_eq!(
        durable_audit(&cli),
        durable_audit(&operator),
        "the human CLI is trusted control too: {cli:?}"
    );
    let agent = invoke(&reg, "agent.status", None, None);
    assert_eq!(
        durable_audit(&agent),
        map(&[
            ("enabled", Value::Bool(true)),
            ("degraded", Value::Bool(true)),
        ]),
        "agent, degraded sink: {agent:?}"
    );
    let agent_debug = format!("{agent:?}");
    for word in ["dropped", "write_failures"] {
        assert!(
            !agent_debug.contains(word),
            "the agent's result (degraded sink) names `{word}`: {agent_debug}"
        );
    }

    // A healthy sink is still `enabled`: presence of a sink, not its health.
    let healthy = Arc::new(AuditRing::default());
    assert!(healthy.attach_durable(StubSink::new(DurableAuditStatus::default())));
    let reg = status_registry(&healthy);
    let operator = invoke(&reg, "agent.status", Some(Frontend::Operator), None);
    assert_eq!(
        durable_audit(&operator),
        map(&[
            ("enabled", Value::Bool(true)),
            ("degraded", Value::Bool(false)),
            ("dropped", Value::Int(0)),
            ("write_failures", Value::Int(0)),
        ]),
        "operator, healthy sink: {operator:?}"
    );
    let agent = invoke(&reg, "agent.status", None, None);
    assert_eq!(
        durable_audit(&agent),
        map(&[
            ("enabled", Value::Bool(true)),
            ("degraded", Value::Bool(false)),
        ]),
        "agent, healthy sink: {agent:?}"
    );
}

/// The declared names of an object's members, in declaration order.
fn names(defs: &[ParamDef]) -> Vec<&str> {
    defs.iter().map(|d| d.name.as_str()).collect()
}

/// The member of `defs` named `name`.
fn def<'a>(defs: &'a [ParamDef], name: &str) -> &'a ParamDef {
    defs.iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no `{name}` in {:?}", names(defs)))
}

/// AC33: the result type declares every key `invoke` can emit (the generated
/// `outputSchema` forbids undeclared properties); the other members and the
/// description string are unchanged.
#[test]
fn agent_status_output_schema_declares_every_durable_audit_key() {
    let reg = status_registry(&Arc::new(AuditRing::default()));
    let schema = reg
        .command("agent.status")
        .expect("agent.status is registered")
        .schema();

    // The description is byte-identical to the base.
    assert_eq!(
        schema.description,
        concat!(
            "Report the current agent policy and recent agent activity. Read-only and ",
            "readable by any role, but the activity count covers only the entries the ",
            "caller may see: a caller that is not trusted control does not count entries ",
            "made by trusted control (operator, CLI)."
        )
    );

    let TypeDesc::Object(defs) = &schema.result else {
        panic!("agent.status returns an object, got {:?}", schema.result);
    };
    assert_eq!(
        names(defs),
        [
            "policy",
            "actions_last_minute",
            "connected_clients",
            "durable_audit"
        ]
    );

    // The first three are unchanged.
    let policy = def(defs, "policy");
    assert!(matches!(policy.ty, TypeDesc::Str), "{:?}", policy.ty);
    assert!(policy.required);
    let actions = def(defs, "actions_last_minute");
    assert!(matches!(actions.ty, TypeDesc::Int), "{:?}", actions.ty);
    assert!(actions.required);
    let clients = def(defs, "connected_clients");
    assert!(clients.required);
    let TypeDesc::Array(item) = &clients.ty else {
        panic!("connected_clients is an array, got {:?}", clients.ty);
    };
    let TypeDesc::Object(client_defs) = item.as_ref() else {
        panic!("connected_clients items are objects, got {item:?}");
    };
    assert_eq!(names(client_defs), ["role", "client", "since"]);
    assert!(client_defs.iter().all(|d| d.required));
    assert!(client_defs.iter().all(|d| matches!(d.ty, TypeDesc::Str)));

    // The new member is a required object with exactly the four declared keys.
    let durable = def(defs, "durable_audit");
    assert!(durable.required, "durable_audit is a required member");
    assert!(
        !durable.description.is_empty(),
        "durable_audit carries its explanation"
    );
    let TypeDesc::Object(inner) = &durable.ty else {
        panic!("durable_audit is an object, got {:?}", durable.ty);
    };
    let mut sorted = names(inner);
    sorted.sort_unstable();
    assert_eq!(sorted, ["degraded", "dropped", "enabled", "write_failures"]);
    let mut required: Vec<&str> = inner
        .iter()
        .filter(|d| d.required)
        .map(|d| d.name.as_str())
        .collect();
    required.sort_unstable();
    assert_eq!(required, ["degraded", "enabled"]);
    for key in ["enabled", "degraded"] {
        assert!(matches!(def(inner, key).ty, TypeDesc::Bool), "{key}");
    }
    for key in ["dropped", "write_failures"] {
        assert!(matches!(def(inner, key).ty, TypeDesc::Int), "{key}");
    }
    for d in inner {
        assert!(
            !d.description.is_empty(),
            "`{}` carries a description",
            d.name
        );
    }
}

/// AC35 `[guard]`: nothing registered by the agent or control plugin reads the
/// audit file or reveals where it is. (The whole-registry check is W16's.)
#[test]
fn no_command_reads_or_reveals_the_audit_file() {
    let ring = Arc::new(AuditRing::default());
    assert!(ring.attach_durable(StubSink::new(degraded_status())));
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        AgentPlugin::new(Arc::new(AgentState::new(AgentPolicy::Auto)))
            .with_audit_ring(ring.clone()),
    ));
    reg.add_plugin(Box::new(ControlPlugin::new(
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    )));

    let all: Vec<String> = reg.commands().map(|c| c.name().to_string()).collect();
    assert!(
        all.iter().any(|n| n == "agent.status") && all.iter().any(|n| n == "config.get"),
        "the two plugins registered: {all:?}"
    );
    let audit_named: Vec<&String> = all.iter().filter(|n| n.starts_with("audit.")).collect();
    assert!(
        audit_named.is_empty(),
        "a command named audit.* exists: {audit_named:?}"
    );

    // `config.get` over a config that names the audit file.
    let mut config = Config::default();
    config.mcp.audit_log = AuditLogSetting::Path(PathBuf::from(SECRET_PATH));
    let got = invoke(
        &reg,
        "config.get",
        Some(Frontend::Operator),
        Some(Arc::new(config)),
    );
    let rendered = format!("{got:?}");
    assert!(
        !rendered.contains(SECRET_PATH),
        "config.get reveals the audit path: {rendered}"
    );
    assert!(
        !rendered.contains("audit_log"),
        "config.get names the audit_log key: {rendered}"
    );

    // `agent.status`, for the operator and for the agent, with a sink attached.
    for (who, frontend) in [("operator", Some(Frontend::Operator)), ("agent", None)] {
        let rendered = format!("{:?}", invoke(&reg, "agent.status", frontend, None));
        assert!(
            !rendered.contains(SECRET_PATH),
            "agent.status reveals the audit path to the {who}: {rendered}"
        );
    }
}
