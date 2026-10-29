//! Task 15: the intercept plugin parks requests while armed; `flow.resume` and
//! `flow.kill` release a parked flow.
//!
//! Events are driven the way `Chain::dispatch` drives them: the plugin's
//! `on_event` runs over a `FlowCtx`, the edited flow is persisted, and the parked
//! receiver stands in for the chain's pausable future.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, FlowStore, HeaderMap,
    HttpFlow, HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, Plugin, ProxyClient,
    Registry, StdGuard, Value, Verdict,
};
use aitm_plugins::InterceptPlugin;
use futures::future::BoxFuture;
use tokio::sync::oneshot;

fn http_flow() -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
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

struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn id_params(id: FlowId) -> Params {
    params(&[("id", Value::Str(id.to_string()))])
}

/// `flow.intercept` returns `{enabled, rules}`; read the armed flag out of it.
fn intercept_enabled(value: &Value) -> bool {
    match value {
        Value::Object(o) => match o.get("enabled") {
            Some(Value::Bool(b)) => *b,
            other => panic!("flow.intercept result missing enabled bool, got {other:?}"),
        },
        other => panic!("flow.intercept should return an object, got {other:?}"),
    }
}

fn registry() -> Registry {
    let mut reg = Registry::new();
    let plugin = InterceptPlugin::new();
    assert_eq!(plugin.name(), "intercept");
    reg.add_plugin(Box::new(plugin));
    reg
}

/// Run `Request(id)` through the registry's plugin chain as `Chain::dispatch`
/// does, persist the flow, and return the parked receiver if any plugin parked it.
fn dispatch_request(
    reg: &Registry,
    store: &MemFlowStore,
    id: FlowId,
) -> Option<oneshot::Receiver<()>> {
    let mut flow = store.get(id).expect("flow stored");
    let parked = {
        let mut ctx = FlowCtx::new(&mut flow);
        for plugin in reg.plugins() {
            let verdict = plugin
                .lock()
                .expect("plugin lock")
                .on_event(&Event::Request(id), &mut ctx);
            assert_eq!(verdict, Verdict::Continue);
        }
        ctx.take_parked()
    };
    store.insert(flow);
    parked
}

fn state_label(store: &MemFlowStore, id: FlowId) -> &'static str {
    match store.get(id) {
        Some(Flow::Http(f)) => match f.intercept {
            InterceptState::Observed => "observed",
            InterceptState::Intercepted { .. } => "intercepted",
            InterceptState::Resumed => "resumed",
            InterceptState::Killed => "killed",
        },
        other => panic!("expected a stored HTTP flow, got {other:?}"),
    }
}

#[test]
fn park_then_resume() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let armed = reg
        .command("flow.intercept")
        .expect("flow.intercept registered")
        .invoke(Params::default(), &host)
        .expect("arming succeeds");
    assert!(intercept_enabled(&armed));

    let id = store.insert(http_flow());
    let mut parked = dispatch_request(&reg, &store, id).expect("armed plugin parks the request");
    assert_eq!(state_label(&store, id), "intercepted");
    assert!(parked.try_recv().is_err(), "still parked before resume");

    let out = reg
        .command("flow.resume")
        .expect("flow.resume registered")
        .invoke(id_params(id), &host)
        .expect("resume succeeds");
    assert_eq!(out, Value::Str("resumed".into()));
    assert_eq!(state_label(&store, id), "resumed");
    assert_eq!(parked.try_recv(), Ok(()), "the parked future was woken");
}

#[test]
fn kill_drops() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    reg.command("flow.intercept")
        .expect("flow.intercept registered")
        .invoke(Params::default(), &host)
        .expect("arming succeeds");
    let id = store.insert(http_flow());
    let mut parked = dispatch_request(&reg, &store, id).expect("armed plugin parks the request");
    assert_eq!(state_label(&store, id), "intercepted");

    let out = reg
        .command("flow.kill")
        .expect("flow.kill registered")
        .invoke(id_params(id), &host)
        .expect("kill succeeds");
    assert_eq!(out, Value::Str("killed".into()));
    assert_eq!(state_label(&store, id), "killed");
    assert_eq!(parked.try_recv(), Ok(()), "the parked future was woken");
}

#[test]
fn disarmed_requests_pass_through() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    // Never armed.
    let id = store.insert(http_flow());
    assert!(dispatch_request(&reg, &store, id).is_none());
    assert_eq!(state_label(&store, id), "observed");

    // Armed, then explicitly disarmed.
    let intercept = reg.command("flow.intercept").expect("registered");
    intercept
        .invoke(Params::default(), &host)
        .expect("arming succeeds");
    let disarmed = intercept
        .invoke(params(&[("enabled", Value::Bool(false))]), &host)
        .expect("disarming succeeds");
    assert!(!intercept_enabled(&disarmed));
    let id = store.insert(http_flow());
    assert!(dispatch_request(&reg, &store, id).is_none());
    assert_eq!(state_label(&store, id), "observed");
}

#[test]
fn resume_of_unparked_flow_is_an_error() {
    let reg = registry();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);

    let id = store.insert(http_flow());
    let err = reg
        .command("flow.resume")
        .expect("flow.resume registered")
        .invoke(id_params(id), &host)
        .expect_err("an observed flow cannot be resumed");
    assert!(
        err.to_string().contains("not intercepted"),
        "error should say why: {err}"
    );
    assert_eq!(state_label(&store, id), "observed");
}
