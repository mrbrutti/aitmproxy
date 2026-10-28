//! Task 12 — `aitm-plugin-maprules`: Map Local + the `map.*` agent gate + path
//! confinement.
//!
//! Events are driven the way `Chain::dispatch` drives them (as in the intercept
//! plugin's tests): the plugin's `on_event` runs over a `FlowCtx`, and the
//! command surface is reached through the shared `Registry`.
//!
//! - `map_local_serves_file` — AC-M1: a `*/logo.png` → fixture map, a matching
//!   request is answered 200 with the fixture bytes and **no upstream call**.
//! - `map_add_agent_refused` — AC-M3: `map.add` from an agent (MCP) frontend is
//!   refused while `allow_agent_authoring` is off.
//! - `map_local_path_escape_rejected` — AC-M3: a `path` resolving outside the map
//!   root is rejected at `map.add`, with no file read.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CommandHost, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, Frontend, HeaderMap,
    HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState, MemFlowStore, Params,
    ProxyClient, Registry, StdGuard, Value, Verdict,
};
use aitm_plugin_maprules::MapRulesPlugin;
use futures::future::BoxFuture;

/// A fresh, empty directory under the OS temp dir (no `tempfile` crate in this
/// workspace); removed when the guard drops.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aitm-maprules-{tag}-{}-{nanos}",
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

/// A proxy client that counts egress attempts; Map Local must never reach it.
#[derive(Default)]
struct CountingClient {
    sends: Arc<AtomicUsize>,
}

impl ProxyClient for CountingClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn http_flow(path: &str) -> Flow {
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: path.into(),
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

fn registry(map_root: &Path, allow_agent_authoring: bool) -> Registry {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(MapRulesPlugin::new(
        map_root.to_path_buf(),
        allow_agent_authoring,
    )));
    reg
}

/// Run one event through the registry's plugin chain the way `Chain::dispatch`
/// does, returning the (possibly short-circuited) flow and the last verdict.
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

#[test]
fn map_local_serves_file() {
    let root = TempDir::new("serve");
    let body = b"\x89PNG\r\n\x1a\nFAKE-LOGO-BYTES";
    std::fs::write(root.path().join("logo.png"), body).expect("write fixture");

    let reg = registry(root.path(), true);
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = CountingClient::default();
    let sends = client.sends.clone();
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);

    // Add a Map Local rule: any request whose target ends in `/logo.png`.
    let added = reg
        .command("map.add")
        .expect("map.add registered")
        .invoke(
            params(&[
                ("kind", Value::Str("local".into())),
                (
                    "condition",
                    obj(&[("url", obj(&[("wildcard", Value::Str("*/logo.png".into()))]))]),
                ),
                ("action", obj(&[("path", Value::Str("logo.png".into()))])),
            ]),
            &host,
        )
        .expect("map.add succeeds");
    let Value::Object(added) = &added else {
        panic!("map.add returns an object, got {added:?}")
    };
    assert!(
        matches!(added.get("id"), Some(Value::Str(_))),
        "map.add returns {{id}}: {added:?}"
    );

    // A matching request is served from the file; a non-matching one is not.
    let (served, verdict) = dispatch(
        &reg,
        &Event::RequestHeaders(FlowId::new()),
        http_flow("/static/logo.png"),
    );
    assert_eq!(verdict, Verdict::Halt, "Map Local short-circuits the chain");
    let Flow::Http(f) = &served else {
        panic!("expected an HTTP flow")
    };
    let resp = f.response.as_ref().expect("Map Local set a response");
    assert_eq!(resp.status, 200, "default status is 200");
    assert_eq!(
        resp.body_bytes(),
        body,
        "the fixture bytes are served verbatim"
    );
    assert_eq!(
        resp.headers.get("content-type"),
        Some("image/png"),
        "content-type inferred from the .png extension"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        0,
        "Map Local performs no egress (upstream counter stays 0)"
    );

    // A request that does not match the rule is left untouched.
    let (passed, verdict) = dispatch(
        &reg,
        &Event::RequestHeaders(FlowId::new()),
        http_flow("/other"),
    );
    assert_eq!(verdict, Verdict::Continue, "non-matching request passes");
    let Flow::Http(f) = &passed else {
        panic!("expected an HTTP flow")
    };
    assert!(f.response.is_none(), "no response synthesized for a miss");
}

#[test]
fn map_add_agent_refused() {
    let root = TempDir::new("gate");
    std::fs::write(root.path().join("logo.png"), b"x").expect("write fixture");

    // Agent authoring off (default posture).
    let reg = registry(root.path(), false);
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = CountingClient::default();
    // An agent (MCP) frontend.
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Mcp);

    let err = reg
        .command("map.add")
        .expect("map.add registered")
        .invoke(
            params(&[
                ("kind", Value::Str("local".into())),
                (
                    "condition",
                    obj(&[("url", obj(&[("wildcard", Value::Str("*/logo.png".into()))]))]),
                ),
                ("action", obj(&[("path", Value::Str("logo.png".into()))])),
            ]),
            &host,
        )
        .expect_err("agent authoring is refused while the gate is off");
    assert!(
        err.to_string().contains("refused"),
        "the error explains the refusal: {err}"
    );

    // Nothing was stored: an MCP `map.list` shows no maps.
    let list = reg
        .command("map.list")
        .expect("map.list registered")
        .invoke(Params::default(), &host)
        .expect("map.list is read-only, not gated");
    assert_eq!(
        list,
        obj(&[("maps", Value::Array(vec![]))]),
        "the refused add stored nothing"
    );
}

#[test]
fn map_local_path_escape_rejected() {
    let parent = TempDir::new("escape");
    let map_root = parent.path().join("root");
    std::fs::create_dir_all(&map_root).expect("create map root");
    // A secret file OUTSIDE the map root, reachable only by traversal.
    std::fs::write(parent.path().join("secret.txt"), b"TOP SECRET").expect("write secret");

    let reg = registry(&map_root, true);
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = CountingClient::default();
    let host = CommandHost::new(&store, &client, &guard, None).with_frontend(Frontend::Cli);

    let err = reg
        .command("map.add")
        .expect("map.add registered")
        .invoke(
            params(&[
                ("kind", Value::Str("local".into())),
                (
                    "condition",
                    obj(&[("url", obj(&[("wildcard", Value::Str("*".into()))]))]),
                ),
                (
                    "action",
                    obj(&[("path", Value::Str("../secret.txt".into()))]),
                ),
            ]),
            &host,
        )
        .expect_err("a path escaping the map root is rejected at map.add");
    assert!(
        err.to_string().contains("map root"),
        "the error names the confinement violation: {err}"
    );
}

/// Local helper: the buffered bytes of a response body (test fixtures are always
/// buffered). Kept here so the test reads clearly.
trait ResponseBytes {
    fn body_bytes(&self) -> &[u8];
}

impl ResponseBytes for HttpResponse {
    fn body_bytes(&self) -> &[u8] {
        match &self.body {
            Body::Bytes(b) => b,
            Body::Empty => &[],
            Body::Streamed(_) => panic!("fixture body should be buffered"),
        }
    }
}
