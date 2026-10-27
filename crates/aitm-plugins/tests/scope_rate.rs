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
    let plugin = ScopePlugin::new();
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
    reg.add_plugin(Box::new(ScopePlugin::new()));
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

    let refused = burst_rate_limited(&reg, &host, 6);
    assert!(
        refused >= 1,
        "a 6-burst against per_host_rps=2 must be throttled at least once, refused={refused}"
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

    // Low option → throttled.
    RateLimitPlugin::apply(&reg, guard.as_ref());
    assert!(
        burst_rate_limited(&reg, &host, 6) >= 1,
        "low per_host_rps must throttle"
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
