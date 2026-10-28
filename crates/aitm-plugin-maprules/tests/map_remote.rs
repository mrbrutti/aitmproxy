//! Task 13 — `aitm-plugin-maprules`: Map Remote rewrite + the scope guard.
//!
//! Map Remote rewrites a matching request's target host/URL before it goes
//! upstream. Because that is active egress to a (possibly new) host, the plugin
//! **must** pass the rewritten authority through [`ScopeRateGuard::check_active`]
//! *before* altering the request — the deny-by-default point for Map Remote.
//!
//! Events are driven the way `Chain::dispatch` drives them (as in the Map Local
//! and intercept plugin tests): the plugin's `on_event` runs over a `FlowCtx`, and
//! the command surface is reached through the shared `Registry`. The plugin holds
//! its own `Arc<dyn ScopeRateGuard>` (constructor-injected) because `FlowCtx` does
//! not carry the guard.
//!
//! - `map_remote_rewrites_in_scope` — AC-M2: `old.example` → `new.example` (in
//!   scope) rewrites the request so it goes upstream to `new.example`.
//! - `map_remote_out_of_scope_refused` — AC-M2 / review focus #7: the same mapping
//!   to a target **not** in scope is refused by the guard and the original request
//!   is **not** sent (authority left untouched, the flow short-circuited).
//! - `map_remote_url_target_rewrites` — the `RemoteTarget::Url` branch swaps
//!   scheme, authority and path together.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, Frontend, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient,
    Registry, ScopeEntry, ScopeRateGuard, StdGuard, Value, Verdict,
};
use aitm_plugin_maprules::MapRulesPlugin;
use futures::future::BoxFuture;

/// A proxy client that counts egress attempts; the plugin must never reach it
/// (Map Remote rewrites the flow for the pipeline, it does not send itself).
#[derive(Default)]
struct CountingClient {
    sends: Arc<std::sync::atomic::AtomicUsize>,
}

impl ProxyClient for CountingClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// An HTTP flow addressed at `scheme://authority{path}`, carrying a `Host` header
/// (every real request has one) so a rewrite's Host update is observable.
fn http_flow(scheme: &str, authority: &str, path: &str) -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("host", authority);
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: scheme.into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
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

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// A registry with a Map plugin that shares `guard`. The map root is irrelevant
/// to Map Remote (no file is read), so a throwaway temp dir is enough.
fn registry(guard: Arc<dyn ScopeRateGuard>) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(MapRulesPlugin::new(
        std::env::temp_dir(),
        true,
        guard,
    )));
    reg
}

/// A fresh deny-by-default guard with `in_scope` hosts pre-added.
fn guard_with_scope(in_scope: &[&str]) -> Arc<dyn ScopeRateGuard> {
    let guard = Arc::new(StdGuard::default());
    for host in in_scope {
        guard.add_scope(ScopeEntry {
            host: (*host).to_string(),
        });
    }
    guard
}

/// Add a Map Remote rule rewriting requests whose host is `from` to the target
/// `to` object. Returns the new map id.
fn add_remote(reg: &Registry, from: &str, to: Value) {
    let store = MemFlowStore::new();
    let client = CountingClient::default();
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);
    reg.command("map.add")
        .expect("map.add registered")
        .invoke(
            params(&[
                ("kind", Value::Str("remote".into())),
                (
                    "condition",
                    obj(&[("host", obj(&[("exact", Value::Str(from.into()))]))]),
                ),
                ("action", obj(&[("to", to)])),
            ]),
            &host,
        )
        .expect("map.add remote succeeds");
}

/// Run one event through the registry's plugin chain the way `Chain::dispatch`
/// does, returning the (possibly rewritten/short-circuited) flow and the verdict.
fn dispatch(reg: &Registry, ev: &Event, mut flow: Flow) -> (Flow, Verdict) {
    let mut verdict = Verdict::Continue;
    {
        let mut ctx = FlowCtx::new(&mut flow);
        for plugin in reg.plugins() {
            verdict = plugin.lock().expect("plugin lock").on_event(ev, &mut ctx);
            if verdict == Verdict::Halt {
                break;
            }
        }
    }
    (flow, verdict)
}

fn as_http(flow: &Flow) -> &HttpFlow {
    match flow {
        Flow::Http(f) => f,
        other => panic!("expected an HTTP flow, got {other:?}"),
    }
}

#[test]
fn map_remote_rewrites_in_scope() {
    // `new.example` is in scope, so the redirect is allowed.
    let reg = registry(guard_with_scope(&["new.example"]));
    add_remote(
        &reg,
        "old.example",
        obj(&[("authority", Value::Str("new.example".into()))]),
    );

    let (served, verdict) = dispatch(
        &reg,
        &Event::RequestHeaders(FlowId::new()),
        http_flow("http", "old.example", "/orders"),
    );

    assert_eq!(
        verdict,
        Verdict::Continue,
        "an in-scope rewrite lets the (rewritten) request go upstream"
    );
    let f = as_http(&served);
    assert_eq!(
        f.request.authority, "new.example",
        "the request target is rewritten to the new host"
    );
    assert_eq!(
        f.request.headers.get("host"),
        Some("new.example"),
        "the Host header follows the rewritten authority so the new upstream routes it"
    );
    assert_eq!(
        f.request.path, "/orders",
        "a host swap keeps the original path"
    );
    assert_eq!(
        f.request.scheme, "http",
        "a host swap without a scheme keeps the original scheme"
    );
    assert!(
        f.response.is_none(),
        "an allowed rewrite synthesizes no response; it continues upstream"
    );
}

#[test]
fn map_remote_out_of_scope_refused() {
    // `new.example` is NOT added to scope: deny-by-default must refuse the redirect.
    let reg = registry(guard_with_scope(&["old.example"]));
    add_remote(
        &reg,
        "old.example",
        obj(&[("authority", Value::Str("new.example".into()))]),
    );

    let (served, verdict) = dispatch(
        &reg,
        &Event::RequestHeaders(FlowId::new()),
        http_flow("http", "old.example", "/orders"),
    );

    // The flow is short-circuited (Halt), so the pipeline never forwards it —
    // the original request is not sent to `new.example` *or* `old.example`.
    assert_eq!(
        verdict,
        Verdict::Halt,
        "an out-of-scope rewrite is refused and the request is not forwarded"
    );
    let f = as_http(&served);
    assert_eq!(
        f.request.authority, "old.example",
        "a refused rewrite leaves the request target untouched (never points at the out-of-scope host)"
    );
    let resp = f
        .response
        .as_ref()
        .expect("the refusal is surfaced as an in-band error response, not a silent pass-through");
    assert!(
        (400..=599).contains(&resp.status),
        "the refusal is an error status, got {}",
        resp.status
    );
    let body = match &resp.body {
        Body::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        other => panic!("expected a buffered error body, got {other:?}"),
    };
    assert!(
        body.contains("new.example"),
        "the refusal names the refused host: {body:?}"
    );
}

#[test]
fn map_remote_url_target_rewrites() {
    // A full-URL target in scope swaps scheme, authority and path together.
    let reg = registry(guard_with_scope(&["cdn.example"]));
    add_remote(
        &reg,
        "old.example",
        obj(&[(
            "url",
            Value::Str("https://cdn.example/assets/app.js".into()),
        )]),
    );

    let (served, verdict) = dispatch(
        &reg,
        &Event::RequestHeaders(FlowId::new()),
        http_flow("http", "old.example", "/orders"),
    );

    assert_eq!(
        verdict,
        Verdict::Continue,
        "an in-scope URL rewrite continues"
    );
    let f = as_http(&served);
    assert_eq!(f.request.scheme, "https", "the URL scheme is applied");
    assert_eq!(
        f.request.authority, "cdn.example",
        "the URL authority is applied"
    );
    assert_eq!(
        f.request.path, "/assets/app.js",
        "the URL path replaces the original path"
    );
    assert_eq!(
        f.request.headers.get("host"),
        Some("cdn.example"),
        "the Host header follows the URL authority"
    );
}
