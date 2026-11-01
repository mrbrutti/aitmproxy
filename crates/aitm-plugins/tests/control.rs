//! F7: the control plugin — proxy.status/pause/resume, flow.clear, config.get.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, Config, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, McpConfig, McpTransport,
    MemFlowStore, Params, ProxyClient, ScopeConfig, ScopeEntry, StdGuard, Value,
};
use aitm_plugins::{ControlPlugin, ScopePlugin};
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

/// An Observed HTTP flow with a complete (buffered) response: a terminal flow
/// `flow.clear` may remove.
fn terminal_flow() -> Flow {
    match flow(InterceptState::Observed) {
        Flow::Http(mut f) => {
            f.response = Some(HttpResponse {
                status: 200,
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                trailers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            });
            Flow::Http(f)
        }
        other => other,
    }
}

fn reg_with(armed: Arc<AtomicBool>, listening: Arc<AtomicBool>) -> aitm_core::Registry {
    let mut reg = aitm_core::Registry::new();
    reg.add_plugin(Box::new(ControlPlugin::new(armed, listening)));
    reg
}

/// A registry whose control status flags are both off, when a test does not care.
fn reg() -> aitm_core::Registry {
    reg_with(
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    )
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
    let listening = Arc::new(AtomicBool::new(true));
    let reg = reg_with(armed.clone(), listening.clone());
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
    // listening reflects the serving flag; address is the configured listen addr.
    assert_eq!(field(&status, "listening"), &Value::Bool(true));
    assert_eq!(
        field(&status, "address"),
        &Value::Str("127.0.0.1:9191".into())
    );

    // Both shared flags reflect the real state: not serving + disarmed, no config.
    armed.store(false, Ordering::Relaxed);
    listening.store(false, Ordering::Relaxed);
    let status = call(&reg, &store, &guard, None, "proxy.status");
    assert_eq!(field(&status, "intercept_armed"), &Value::Bool(false));
    assert_eq!(field(&status, "listening"), &Value::Bool(false));
    assert_eq!(field(&status, "address"), &Value::Null);
}

/// The web sidebar shows the core's version from here, so it must be the real build's version, not a
/// number baked into a UI. `env!("CARGO_PKG_VERSION")` here is this crate's version, which is the
/// workspace version (every crate sets `version.workspace = true`) and so the binary's.
#[test]
fn proxy_status_reports_the_workspace_crate_version() {
    let reg = reg();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    let status = call(&reg, &store, &guard, None, "proxy.status");
    assert_eq!(
        field(&status, "version"),
        &Value::Str(env!("CARGO_PKG_VERSION").into())
    );
    // Not an empty or placeholder string. Deliberately no semver-shape check: a pre-release such as
    // `0.6.0-rc.1` or a build-metadata suffix is a legitimate version and must not break this test.
    let Value::Str(v) = field(&status, "version") else {
        panic!("version is a string");
    };
    assert!(!v.is_empty(), "version is empty");
    assert!(
        v.starts_with(|c: char| c.is_ascii_digit()),
        "version should start with a digit: {v}"
    );

    // The schema documents it, so tools/list tells a client the key exists.
    let schema = reg.command("proxy.status").expect("registered").schema();
    assert!(
        schema.description.contains("`version`"),
        "schema should mention version: {}",
        schema.description
    );
}

#[test]
fn pause_resume_marks_inserts_hidden() {
    let reg = reg();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    assert!(store.is_capturing());
    let paused = call(&reg, &store, &guard, None, "proxy.pause");
    assert_eq!(field(&paused, "capturing"), &Value::Bool(false));
    assert!(!store.is_capturing());

    // While paused, an insert is still RESIDENT (so the pipeline can get/update it
    // and intercept/replay work) but hidden from `list`/`count`. No retire: it ages
    // out via normal eviction.
    let id = store.insert(flow(InterceptState::Observed));
    assert!(
        store.get(id).is_some(),
        "paused capture keeps the flow resident for the pipeline"
    );
    assert!(store.list().is_empty(), "hidden flows are not listed");
    assert_eq!(store.count(), 0);

    let resumed = call(&reg, &store, &guard, None, "proxy.resume");
    assert_eq!(field(&resumed, "capturing"), &Value::Bool(true));
    let id = store.insert(flow(InterceptState::Observed));
    assert!(
        store.list().contains(&id),
        "resumed capture is visible again"
    );
}

#[test]
fn flow_clear_removes_terminal_keeps_in_flight() {
    let reg = reg();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    store.insert(terminal_flow());
    store.insert(terminal_flow());
    // An in-flight (Observed, no response) flow and a parked one must be kept.
    let in_flight = store.insert(flow(InterceptState::Observed));
    let (h, _rx) = aitm_core::ResumeHandle::new();
    let parked = store.insert(flow(InterceptState::Intercepted {
        backup: Box::new(flow(InterceptState::Observed)),
        resume: h,
    }));
    assert_eq!(store.list().len(), 4);

    let cleared = call(&reg, &store, &guard, None, "flow.clear");
    assert_eq!(field(&cleared, "cleared"), &Value::Int(2));
    assert_eq!(field(&cleared, "skipped_in_flight"), &Value::Int(2));
    // The in-flight and parked flows survive; the parked one stays resolvable.
    assert!(store.get(in_flight).is_some());
    assert!(store.get(parked).is_some());
    assert_eq!(store.count(), 2);
}

#[test]
fn config_get_is_redacted_and_requires_config() {
    let reg = reg();
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
                endpoint_file: None,
            },
            ..McpConfig::default()
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

/// Call `name` with `params` as the human CLI (`Frontend::Cli`), the way
/// `aitm scope add --host …` reaches the bus: a trusted-control caller the
/// `scope.add` gate admits without `scope.allow_agent_widen`.
fn call_as_cli(
    reg: &aitm_core::Registry,
    store: &dyn FlowStore,
    guard: &StdGuard,
    name: &str,
    params: Params,
) -> Value {
    let client = StubClient;
    let host = CommandHost::new(store, &client, guard, None).with_frontend(Frontend::Cli);
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(params, &host)
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The literal `decrypt` object of AC13.
fn decrypt_object(scope_hosts: i64, decrypting: bool, advice: Value) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("scope_hosts".to_string(), Value::Int(scope_hosts));
    obj.insert("decrypting".to_string(), Value::Bool(decrypting));
    obj.insert("advice".to_string(), advice);
    Value::Object(obj)
}

/// AC13 (status + advice), empty Scope: `proxy.status.decrypt` is the literal
/// `{scope_hosts: 0, decrypting: false, advice: "Nothing is decrypted until a
/// host is in Scope."}`. The sentence is the one constant every surface prints
/// and never composes, so it is pinned here, word for word.
#[test]
fn proxy_status_reports_decrypt_advice_on_empty_scope() {
    let reg = reg();
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    let status = call(&reg, &store, &guard, None, "proxy.status");
    assert_eq!(
        field(&status, "decrypt"),
        &decrypt_object(
            0,
            false,
            Value::Str("Nothing is decrypted until a host is in Scope.".into()),
        )
    );
    assert_eq!(
        aitm_core::NOTHING_DECRYPTED_ADVICE,
        "Nothing is decrypted until a host is in Scope."
    );

    // The schema documents the sub-object, so `tools/list` tells a client it exists.
    let schema = reg.command("proxy.status").expect("registered").schema();
    assert!(
        schema.description.contains("`decrypt`"),
        "schema should mention decrypt: {}",
        schema.description
    );
}

/// AC13 (status + advice), after `scope.add`: the same read is
/// `{scope_hosts: 1, decrypting: true, advice: null}`. The count comes from the
/// live guard (what the proxy actually decrypts), not from the launch config.
#[test]
fn proxy_status_reports_decrypt_advice_after_scope_add() {
    let mut reg = reg();
    reg.add_plugin(Box::new(ScopePlugin::default()));
    let store = MemFlowStore::new();
    let guard = StdGuard::default();

    let mut args = BTreeMap::new();
    args.insert("host".to_string(), Value::Str("api.example.test".into()));
    let added = call_as_cli(&reg, &store, &guard, "scope.add", Params::new(args));
    assert_eq!(added, Value::Str("api.example.test".into()));

    let status = call(&reg, &store, &guard, None, "proxy.status");
    assert_eq!(
        field(&status, "decrypt"),
        &decrypt_object(1, true, Value::Null)
    );
}
