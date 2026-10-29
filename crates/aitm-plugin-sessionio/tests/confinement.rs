//! Audit finding I1 (path confinement) + I2 (read-size cap).
//!
//! Once `session_io.allow_agent_file_io` is on, the session/flow file-I/O commands
//! take a raw host path, so an agent could read or overwrite **any** host file and
//! a hostile document could force an unbounded allocation. With a `session_root`
//! set, every path argument must resolve under it (traversal/absolute escapes are
//! refused), and a document over the configured cap is refused before it is read.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use aitm_core::{
    Body, CommandHost, ConnInfo, Flow, FlowId, FlowMeta, FlowStore, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Params, ProxyClient, Registry,
    StdGuard, Value,
};
use aitm_plugin_sessionio::SessionIoPlugin;
use futures::future::BoxFuture;

/// A fresh, empty directory under the OS temp dir; removed when the guard drops.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aitm-sessionio-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct StubClient;

impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client: must not send upstream") })
    }
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

fn call(
    reg: &Registry,
    store: &MemFlowStore,
    command: &str,
    args: &[(&str, Value)],
) -> anyhow::Result<Value> {
    let guard = StdGuard::default();
    let client = StubClient;
    // The human CLI frontend keeps the agent gate out of the way: these tests are
    // about path confinement and the read cap, not the agent gate.
    let host = CommandHost::new(store, &client, &guard, None).with_frontend(Frontend::Cli);
    let args = Params::new(
        args.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    );
    reg.command(command)
        .unwrap_or_else(|| panic!("{command} registered"))
        .invoke(args, &host)
}

/// AC-I1: with a `session_root` set, a traversal path that escapes the root is
/// refused by `session.save`, and the error names the confinement violation.
#[test]
fn save_traversal_outside_root_refused() {
    let parent = TempDir::new("save-escape");
    let root = parent.path().join("root");
    std::fs::create_dir_all(&root).expect("create root");

    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(true).with_session_root(Some(root.clone())),
    ));
    let store = seeded_store();

    let err = call(
        &reg,
        &store,
        "session.save",
        &[("path", Value::Str("../escape.json".into()))],
    )
    .expect_err("a path escaping the session root must be refused");
    assert!(
        err.to_string().contains("escapes the session root"),
        "the error names the confinement violation: {err:#}"
    );
    // Nothing was written outside the root.
    assert!(!parent.path().join("escape.json").exists());
}

/// AC-I1: an absolute path outside the root is refused too.
#[test]
fn load_absolute_outside_root_refused() {
    let root = TempDir::new("load-abs");
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(true).with_session_root(Some(root.path().to_path_buf())),
    ));
    let store = seeded_store();

    let err = call(
        &reg,
        &store,
        "session.load",
        &[("path", Value::Str("/etc/hosts".into()))],
    )
    .expect_err("an absolute path outside the root must be refused");
    assert!(
        err.to_string().contains("escapes the session root"),
        "the error names the confinement violation: {err:#}"
    );
}

/// AC-I1: a path that resolves under the root is accepted — save then load round
/// trips through a confined file.
#[test]
fn path_inside_root_accepted_roundtrip() {
    let root = TempDir::new("inside");
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(true).with_session_root(Some(root.path().to_path_buf())),
    ));
    let store = seeded_store();

    call(
        &reg,
        &store,
        "session.save",
        &[("path", Value::Str("capture.json".into()))],
    )
    .expect("a path inside the root is accepted");
    assert!(
        root.path().join("capture.json").exists(),
        "the confined file was written under the root"
    );

    let fresh = MemFlowStore::new();
    let loaded = call(
        &reg,
        &fresh,
        "session.load",
        &[("path", Value::Str("capture.json".into()))],
    )
    .expect("loading the confined file is accepted");
    assert_eq!(
        loaded,
        Value::Object([("flows".to_string(), Value::Int(1))].into_iter().collect()),
        "the round-tripped session restored its one flow"
    );
}

/// AC-I2: a document larger than the configured cap is refused before it is read.
#[test]
fn load_over_cap_refused() {
    let root = TempDir::new("cap");
    // A valid session file, then a 10-byte cap it clearly exceeds.
    let mut reg_big = Registry::new();
    reg_big.add_plugin(Box::new(
        SessionIoPlugin::new(true).with_session_root(Some(root.path().to_path_buf())),
    ));
    let store = seeded_store();
    call(
        &reg_big,
        &store,
        "session.save",
        &[("path", Value::Str("doc.json".into()))],
    )
    .expect("write a real session document to cap");

    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(true)
            .with_session_root(Some(root.path().to_path_buf()))
            .with_max_doc_bytes(10),
    ));
    let err = call(
        &reg,
        &MemFlowStore::new(),
        "session.load",
        &[("path", Value::Str("doc.json".into()))],
    )
    .expect_err("a document over the cap must be refused");
    assert!(
        err.to_string().contains("over the 10-byte limit"),
        "the error names the size cap: {err:#}"
    );
}

/// AC-I2: a document within the cap loads normally (the cap does not block a
/// legitimately sized document).
#[test]
fn load_within_cap_accepted() {
    let root = TempDir::new("under-cap");
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(
        SessionIoPlugin::new(true)
            .with_session_root(Some(root.path().to_path_buf()))
            .with_max_doc_bytes(1024 * 1024),
    ));
    let store = seeded_store();
    call(
        &reg,
        &store,
        "session.save",
        &[("path", Value::Str("ok.json".into()))],
    )
    .expect("write");
    let fresh = MemFlowStore::new();
    call(
        &reg,
        &fresh,
        "session.load",
        &[("path", Value::Str("ok.json".into()))],
    )
    .expect("a document within the cap loads");
    assert_eq!(fresh.count(), 1);
}
