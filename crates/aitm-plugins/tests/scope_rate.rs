//! Task 17: `scope.add`/`scope.list` (AC16 scope commands), the `per_host_rps`
//! option throttling a burst (AC17), and the option changing observed behavior
//! (AC-P4).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, HeaderMap, HttpRequest, HttpResponse, HttpVersion, LimitConfig,
    MemFlowStore, Params, PipelineClient, Plugin, Registry, RequestSender, StdGuard, Value,
};
use aitm_plugins::{MutatePlugin, RateLimitPlugin, ScopePlugin};
use futures::future::BoxFuture;

/// Answers 200 without its own guard: the single scope/rate chokepoint is the
/// `PipelineClient` wrapping it, so one `request.send` is exactly one token.
struct EchoSender;

impl RequestSender for EchoSender {
    fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            })
        })
    }
}

/// A `PipelineClient` (the real guard chokepoint) over the echo sender.
fn pipe(store: &Arc<MemFlowStore>, guard: &Arc<StdGuard>) -> PipelineClient {
    PipelineClient::new(store.clone(), guard.clone(), Arc::new(EchoSender))
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

#[test]
fn scope_add_then_list() {
    let mut reg = Registry::new();
    // Agent-widen allowed so this mechanics test (default MCP host) can add scope;
    // the gate itself is covered by `scope_add_gated_from_agent_frontend`.
    let plugin = ScopePlugin::new(true);
    assert_eq!(plugin.name(), "scope");
    reg.add_plugin(Box::new(plugin));

    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let client = pipe(&store, &guard);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    let added = reg
        .command("scope.add")
        .expect("scope.add registered")
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.add ok");
    assert_eq!(added, Value::Str("ex.test".into()));

    let listed = reg
        .command("scope.list")
        .expect("scope.list registered")
        .invoke(Params::default(), &host)
        .expect("scope.list ok");
    assert_eq!(listed, Value::Array(vec![Value::Str("ex.test".into())]));
}

#[test]
fn scope_remove_narrows_scope() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ScopePlugin::new(true)));
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let client = pipe(&store, &guard);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);

    reg.command("scope.add")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.add ok");
    // Removing a present entry reports true and drops it from the list.
    let removed = reg
        .command("scope.remove")
        .expect("scope.remove registered")
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.remove ok");
    assert_eq!(removed, Value::Bool(true));
    let listed = reg
        .command("scope.list")
        .unwrap()
        .invoke(Params::default(), &host)
        .unwrap();
    assert_eq!(listed, Value::Array(vec![]));
    // Removing an absent entry is idempotent: false, no error.
    let again = reg
        .command("scope.remove")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.remove idempotent");
    assert_eq!(again, Value::Bool(false));
}

#[test]
fn scope_add_gated_from_agent_frontend() {
    use aitm_core::Frontend;

    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(StdGuard::default());
    let client = pipe(&store, &guard);

    // Gate ON (allow_agent_widen = false): an MCP (agent) host is refused, a CLI
    // (human) host is allowed; scope.remove stays allowed from either.
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ScopePlugin::new(false)));

    let agent = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_frontend(Frontend::Mcp);
    let err = reg
        .command("scope.add")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &agent)
        .expect_err("agent scope.add must be refused when the gate is on");
    assert!(
        err.to_string().contains("scope.allow_agent_widen"),
        "refusal should name the config flag: {err}"
    );

    let human = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None)
        .with_frontend(Frontend::Cli);
    reg.command("scope.add")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &human)
        .expect("human CLI scope.add is always allowed");

    // Even the gated agent may narrow scope.
    let removed = reg
        .command("scope.remove")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &agent)
        .expect("scope.remove is never gated");
    assert_eq!(removed, Value::Bool(true));

    // Gate OFF (allow_agent_widen = true): the agent host may add scope.
    let mut reg_open = Registry::new();
    reg_open.add_plugin(Box::new(ScopePlugin::new(true)));
    reg_open
        .command("scope.add")
        .unwrap()
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &agent)
        .expect("agent scope.add allowed when scope.allow_agent_widen is set");
}

/// A guard whose only limiter is the per-host bucket: global and concurrency
/// are set generously so the burst exercises `per_host_rps` alone.
fn permissive_guard(per_host_rps: u32) -> StdGuard {
    StdGuard::new(LimitConfig {
        global_rps: 10_000,
        per_host_rps,
        max_concurrency: 1_000,
        host_error_budget: 0,
        ..LimitConfig::default()
    })
}

/// Fire `n` `request.send`s at an in-scope host; return how many were refused
/// for rate limiting.
fn burst_rate_limited(reg: &Registry, host: &CommandHost, n: usize) -> usize {
    let send = reg
        .command("request.send")
        .expect("request.send registered");
    (0..n)
        .filter(|_| {
            match send.invoke(params(&[("authority", Value::Str("ex.test".into()))]), host) {
                Ok(_) => false,
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("rate limited"),
                        "the only expected refusal is rate limiting, got: {msg}"
                    );
                    true
                }
            }
        })
        .count()
}

fn registry_with_option(default_rps: u32) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(ScopePlugin::new(true)));
    reg.add_plugin(Box::new(MutatePlugin::new()));
    let plugin = RateLimitPlugin::new(default_rps);
    assert_eq!(plugin.name(), "rate-limit");
    reg.add_plugin(Box::new(plugin));
    reg
}

#[test]
fn rate_limit_throttles_burst() {
    let reg = registry_with_option(2);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(permissive_guard(100)); // deliberately high; the option overrides it

    // The rate-limit plugin's option drives the guard's per-host bucket.
    assert_eq!(RateLimitPlugin::configured(&reg), Some(2));
    RateLimitPlugin::apply(&reg, guard.as_ref());

    let client = pipe(&store, &guard);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
    reg.command("scope.add")
        .expect("registered")
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.add ok");

    // per_host_rps=2 → the bucket holds 2 tokens; a 6-burst passes exactly 2 and
    // refuses the remaining 4 (an instant burst refills a negligible fraction).
    assert_eq!(
        burst_rate_limited(&reg, &host, 6),
        4,
        "a 6-burst against per_host_rps=2 refuses exactly 4"
    );
}

#[test]
fn option_changes_behavior() {
    let mut reg = registry_with_option(2);
    let store = Arc::new(MemFlowStore::new());
    let guard = Arc::new(permissive_guard(2));

    let client = pipe(&store, &guard);
    let host = CommandHost::new(store.as_ref(), &client, guard.as_ref(), None);
    reg.command("scope.add")
        .expect("registered")
        .invoke(params(&[("host", Value::Str("ex.test".into()))]), &host)
        .expect("scope.add ok");

    // Low option → the 6-burst passes 2 and refuses the other 4.
    RateLimitPlugin::apply(&reg, guard.as_ref());
    assert_eq!(
        burst_rate_limited(&reg, &host, 6),
        4,
        "low per_host_rps throttles all but the 2-token burst"
    );

    // Raise the option and re-apply (resets the bucket) → the same burst passes.
    reg.set_option(RateLimitPlugin::OPTION, Value::Int(10_000));
    assert_eq!(RateLimitPlugin::configured(&reg), Some(10_000));
    RateLimitPlugin::apply(&reg, guard.as_ref());
    assert_eq!(
        burst_rate_limited(&reg, &host, 6),
        0,
        "raising per_host_rps lets the same burst through with no refusals"
    );
}
