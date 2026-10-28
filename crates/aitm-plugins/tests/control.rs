//! F7: the control plugin — proxy.status/pause/resume, flow.clear, config.get.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, McpConfig, McpTransport, MemFlowStore, Params,
    ProxyClient, ScopeConfig, ScopeEntry, StdGuard, Value,
};
use aitm_plugins::ControlPlugin;
use futures::future::BoxFuture;

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn flow(intercept: InterceptState) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
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
            peer: addr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept,
    })
}

fn reg_with(armed: Arc<AtomicBool>) -> aitm_core::Registry {
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(ControlPlugin::new(armed)));
    reg
}

fn call(
    reg: &aitm_core::Registry,
    store: &dyn FlowStore,
    guard: &StdGuard,
    config: Option<Arc<Config>>,
    name: &str,
) -> Value {
    let client = StubClient;
    let host = CommandHost::new(store, &client, guard, None);
    let host = match config {
        Some(c) => host.with_config(c),
        None => host,
    };
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(Params::default(), &host)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    match v {
        Value::Object(o) => o.get(k).unwrap_or_else(|| panic!("missing {k} in {o:?}")),
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn proxy_status_reports_armed_capturing_paused_and_listening() {
    let armed = Arc::new(AtomicBool::new(true));
    let reg = reg_with(armed.clone());
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    // One observed + one intercepted flow -> paused == 1, flows == 2.
    store.insert(flow(InterceptState::Observed));
    let (h, _rx) = aitm_core::ResumeHandle::new();
    store.insert(flow(InterceptState::Intercepted {
        backup: Box::new(flow(InterceptState::Observed)),
        resume: h,
    }));

    let cfg = Config {
        listen: "127.0.0.1:9191".parse().unwrap(),
        ..Config::default()
    };
    let status = call(&reg, &store, &guard, Some(Arc::new(cfg)), "proxy.status");
    assert_eq!(field(&status, "intercept_armed"), &Value::Bool(true));
    assert_eq!(field(&status, "capturing"), &Value::Bool(true));
    assert_eq!(field(&status, "paused"), &Value::Int(1));
    assert_eq!(field(&status, "flows"), &Value::Int(2));
    assert_eq!(
        field(&status, "listening"),
        &Value::Str("127.0.0.1:9191".into())
    );

    // The armed flag is shared: flipping it is visible without re-arming.
    armed.store(false, Ordering::Relaxed);
    let status = call(&reg, &store, &guard, None, "proxy.status");
    assert_eq!(field(&status, "intercept_armed"), &Value::Bool(false));
    // No config attached -> listening is null, not an error.
    assert_eq!(field(&status, "listening"), &Value::Null);
}

#[test]
fn pause_resume_toggles_capture_and_drops_inserts() {
    let reg = reg_with(Arc::new(AtomicBool::new(false)));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    assert!(store.is_capturing());
    let paused = call(&reg, &store, &guard, None, "proxy.pause");
    assert_eq!(field(&paused, "capturing"), &Value::Bool(false));
    assert!(!store.is_capturing());

    // While paused, an insert is dropped (returns an id but is not retained).
    let id = store.insert(flow(InterceptState::Observed));
    assert!(
        store.get(id).is_none(),
        "paused capture must not retain the flow"
    );
    assert!(store.list().is_empty());

    let resumed = call(&reg, &store, &guard, None, "proxy.resume");
    assert_eq!(field(&resumed, "capturing"), &Value::Bool(true));
    let id = store.insert(flow(InterceptState::Observed));
    assert!(
        store.get(id).is_some(),
        "resumed capture retains the flow again"
    );
}

#[test]
fn flow_clear_empties_the_store() {
    let reg = reg_with(Arc::new(AtomicBool::new(false)));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    store.insert(flow(InterceptState::Observed));
    store.insert(flow(InterceptState::Observed));
    assert_eq!(store.list().len(), 2);

    let cleared = call(&reg, &store, &guard, None, "flow.clear");
    assert_eq!(field(&cleared, "cleared"), &Value::Int(2));
    assert!(store.list().is_empty());
    assert_eq!(store.resident_bytes(), 0);
}

#[test]
fn config_get_is_redacted_and_requires_config() {
    let reg = reg_with(Arc::new(AtomicBool::new(false)));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    // Without a config, config.get is a clear error, not a panic or empty object.
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None);
    let err = reg
        .command("config.get")
        .unwrap()
        .invoke(Params::default(), &host)
        .expect_err("config.get needs a config");
    assert!(err.to_string().contains("configuration"), "{err}");

    // With a config, it returns a redacted view that never carries the MCP token.
    let cfg = Config {
        listen: "127.0.0.1:8080".parse().unwrap(),
        scope: ScopeConfig {
            entries: vec![ScopeEntry {
                host: "ex.test".into(),
            }],
            ..ScopeConfig::default()
        },
        mcp: McpConfig {
            transport: McpTransport::LoopbackTcp {
                port: 9090,
                token: "SECRET-TOKEN".into(),
            },
        },
        ..Config::default()
    };
    let got = call(&reg, &store, &guard, Some(Arc::new(cfg)), "config.get");
    assert_eq!(field(&got, "listen"), &Value::Str("127.0.0.1:8080".into()));
    let mcp = field(&got, "mcp");
    assert_eq!(field(mcp, "transport"), &Value::Str("loopback_tcp".into()));
    assert_eq!(field(mcp, "port"), &Value::Int(9090));
    // The token must never appear anywhere in the serialized config.
    let dump = format!("{got:?}");
    assert!(
        !dump.contains("SECRET-TOKEN"),
        "config.get leaked the MCP token: {dump}"
    );
}
