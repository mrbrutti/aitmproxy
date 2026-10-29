//! Panel finding #2 (Matt-approved): the session/flow file-I/O commands take an
//! unconfined host path, so an agent (MCP) frontend could read or overwrite
//! arbitrary files. `session.save`/`session.load`/`flow.export`/`flow.import` are
//! gated against the agent frontend unless `session_io.allow_agent_file_io` is set;
//! the human CLI keeps full path access, and an agent may still use in-memory
//! `bytes` (no host path), which stays passive. Mirrors the `scope.allow_agent_widen`
//! / `maps.allow_agent_authoring` gates.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient, Registry,
    StdGuard, Value,
};
use aitm_plugin_sessionio::SessionIoPlugin;
use futures::future::BoxFuture;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::UNIX_EPOCH;

#[derive(Default)]
struct CountingClient {
    sends: AtomicUsize,
}

impl ProxyClient for CountingClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("stub client: must not send upstream") })
    }
}

fn registry(allow_agent_file_io: bool) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(SessionIoPlugin::new(allow_agent_file_io)));
    reg
}

fn seeded_store() -> MemFlowStore {
    let store = MemFlowStore::new();
    let conn = ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
        sni: None,
        alpn: None,
        tls: false,
        established: UNIX_EPOCH,
    };
    store.insert(Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "api.test".into(),
            path: "/".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: UNIX_EPOCH,
        },
        response: None,
        client_conn: conn.clone(),
        server_conn: Some(conn),
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }));
    store
}

fn tmp_path() -> String {
    std::env::temp_dir()
        .join(format!("aitm-fileio-{}.json", FlowId::new()))
        .to_string_lossy()
        .into_owned()
}

fn call(
    reg: &Registry,
    store: &MemFlowStore,
    command: &str,
    frontend: Frontend,
    args: &[(&str, Value)],
) -> anyhow::Result<Value> {
    let guard = StdGuard::default();
    let client = CountingClient::default();
    let host = CommandHost::new(store, &client, &guard, None).with_frontend(frontend);
    let args = Params::new(
        args.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    );
    reg.command(command)
        .unwrap_or_else(|| panic!("{command} registered"))
        .invoke(args, &host)
}

/// AC: an agent (MCP) frontend is refused a path-bearing `session.save` by default,
/// and the error names the config flag that would allow it.
#[test]
fn session_save_agent_refused_by_default() {
    let reg = registry(false);
    let store = seeded_store();
    let err = call(
        &reg,
        &store,
        "session.save",
        Frontend::Mcp,
        &[("path", Value::Str(tmp_path()))],
    )
    .expect_err("an agent must be refused a host-path save by default");
    assert!(
        err.to_string().contains("session_io.allow_agent_file_io"),
        "the refusal names the config flag: {err:#}"
    );
}

/// AC: the human CLI keeps full path access regardless of the flag.
#[test]
fn session_save_cli_allowed() {
    let reg = registry(false);
    let store = seeded_store();
    let path = tmp_path();
    call(
        &reg,
        &store,
        "session.save",
        Frontend::Cli,
        &[("path", Value::Str(path.clone()))],
    )
    .expect("the CLI operator may always write a host path");
    let _ = std::fs::remove_file(&path);
}

/// AC: with the flag set, the agent frontend is allowed the path-bearing call.
#[test]
fn session_save_agent_allowed_with_flag() {
    let reg = registry(true);
    let store = seeded_store();
    let path = tmp_path();
    call(
        &reg,
        &store,
        "session.save",
        Frontend::Mcp,
        &[("path", Value::Str(path.clone()))],
    )
    .expect("an agent may write a host path once session_io.allow_agent_file_io is set");
    let _ = std::fs::remove_file(&path);
}

/// `session.load` reads a host path, so it is gated the same way.
#[test]
fn session_load_agent_refused_by_default() {
    let reg = registry(false);
    let store = seeded_store();
    let err = call(
        &reg,
        &store,
        "session.load",
        Frontend::Mcp,
        &[("path", Value::Str(tmp_path()))],
    )
    .expect_err("an agent must be refused a host-path load by default");
    assert!(err.to_string().contains("session_io.allow_agent_file_io"));
}

/// `flow.export`/`flow.import` are gated only when a host path is given. An agent
/// exporting to / importing from in-memory `bytes` stays allowed (passive), so the
/// gate does not break the agent's legitimate zero-filesystem interchange.
#[test]
fn flow_export_agent_path_refused_but_bytes_allowed() {
    let reg = registry(false);
    let store = seeded_store();

    // Path export from an agent: refused.
    let err = call(
        &reg,
        &store,
        "flow.export",
        Frontend::Mcp,
        &[
            ("format", Value::Str("aitm".into())),
            ("path", Value::Str(tmp_path())),
        ],
    )
    .expect_err("an agent must be refused a host-path export by default");
    assert!(err.to_string().contains("session_io.allow_agent_file_io"));

    // Bytes export from the same agent: allowed (no host path touched).
    let out = call(
        &reg,
        &store,
        "flow.export",
        Frontend::Mcp,
        &[("format", Value::Str("aitm".into()))],
    )
    .expect("an agent may export to in-memory bytes");
    let Value::Object(out) = out else {
        panic!("flow.export returns an object");
    };
    assert!(
        matches!(out.get("bytes"), Some(Value::Bytes(_))),
        "a path-less export returns bytes"
    );
}

/// `flow.import` from a host path is gated; importing supplied `bytes` is not.
#[test]
fn flow_import_agent_path_refused_but_bytes_allowed() {
    let reg = registry(false);
    let store = seeded_store();

    let err = call(
        &reg,
        &store,
        "flow.import",
        Frontend::Mcp,
        &[
            ("format", Value::Str("aitm".into())),
            ("path", Value::Str(tmp_path())),
        ],
    )
    .expect_err("an agent must be refused a host-path import by default");
    assert!(err.to_string().contains("session_io.allow_agent_file_io"));

    // Export native bytes via the CLI, then re-import them via the agent's `bytes`.
    let out = call(
        &reg,
        &store,
        "flow.export",
        Frontend::Cli,
        &[("format", Value::Str("aitm".into()))],
    )
    .expect("cli export");
    let Value::Object(out) = out else {
        panic!("object");
    };
    let Some(Value::Bytes(bytes)) = out.get("bytes") else {
        panic!("bytes");
    };
    let fresh = MemFlowStore::new();
    call(
        &reg,
        &fresh,
        "flow.import",
        Frontend::Mcp,
        &[
            ("format", Value::Str("aitm".into())),
            ("bytes", Value::Bytes(bytes.clone())),
        ],
    )
    .expect("an agent may import supplied bytes without the flag");
    assert_eq!(fresh.count(), 1, "the bytes import populated the store");
}
