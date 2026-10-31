//! The shipped detection catalogue (`scripts/bundled/`) must (1) compile under
//! the real hardened engine and (2) run its passive hooks over representative
//! flows without raising a runtime error. Both guard the default-loaded scripts
//! against shipping broken.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, MemFlowStore, ProxyClient, StdGuard, WsDir, WsFlow,
    WsMessage, WsOpcode,
};
use aitm_plugin_rhai::config::{RhaiConfig, RhaiLimits, ScriptEntry};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_plugin_rhai::{ErrorSink, FindingSink};

const MAX_BODY: usize = 1 << 20;

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn services(findings: Arc<MemoryFindingSink>) -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings,
        rt: tokio::runtime::Handle::current(),
    }
}

fn bundled_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
}

fn rhai_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else { return };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rhai_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rhai") {
            out.push(path);
        }
    }
}

fn conn(tls: bool) -> ConnInfo {
    ConnInfo {
        peer: "127.0.0.1:0".parse().expect("addr"),
        sni: None,
        alpn: None,
        tls,
        established: SystemTime::now(),
    }
}

/// A deliberately vulnerable HTTP flow, request and response populated, so a
/// passive detector exercises its finding-recording path. `scheme` is "http" or
/// "https" to cover both transport branches.
fn vuln_http_flow(scheme: &str) -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "ex.test");
    headers.set("Cookie", "sid=abcdef123456");
    headers.set("Origin", "https://evil.example");
    headers.set("X-Forwarded-Host", "evil.example");
    headers.set("Content-Length", "6");
    headers.set("Transfer-Encoding", "chunked");
    if scheme == "http" {
        headers.set("Authorization", "Basic dXNlcjpwYXNz");
    }

    let mut rh = HeaderMap::new();
    rh.set("Content-Type", "text/html");
    rh.set("Set-Cookie", "sid=abcdef123456");
    rh.set(
        "Location",
        "https://evil.example/landing?token=abcdef123456",
    );
    rh.set("Access-Control-Allow-Origin", "https://evil.example");
    rh.set("Access-Control-Allow-Credentials", "true");
    rh.set("Server", "nginx/1.2.3");
    rh.set("X-Powered-By", "PHP/7.4.1");
    rh.set("Allow", "GET, POST, PUT, DELETE, TRACE");

    let body = concat!(
        "<title>Index of /</title>",
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL",
        " <script>alert(1)</script> ",
        "__schema queryType ",
        "AKIAIOSFODNN7EXAMPLE 10.0.0.5 ",
        "src=\"http://cdn.example/x.js\" ",
        "Traceback (most recent call last) ",
        "-----BEGIN RSA PRIVATE KEY-----"
    );

    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: scheme.into(),
            authority: "ex.test".into(),
            path: "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&token=abcdef123456&next=https%3A%2F%2Fevil.example".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(b"name=x".to_vec()),
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 302,
            version: HttpVersion::Http11,
            headers: rh,
            trailers: HeaderMap::new(),
            body: Body::Bytes(body.as_bytes().to_vec()),
            timestamp: SystemTime::now(),
        }),
        client_conn: conn(scheme == "https"),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn ws_flow() -> Flow {
    Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: vec![WsMessage {
            dir: WsDir::ClientToServer,
            opcode: WsOpcode::Text,
            data: b"{\"password\":\"hunter2abcdef\",\"email\":\"a@b.com\"}".to_vec(),
            timestamp: SystemTime::now(),
            injected: false,
        }],
        client_conn: conn(false),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn loader(findings: Arc<MemoryFindingSink>) -> RhaiLoader {
    RhaiLoader::new(
        RhaiConfig {
            limits: RhaiLimits::default(),
            ..RhaiConfig::default()
        },
        services(findings),
    )
    .expect("engine builds")
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bundled_script_compiles() {
    let findings = Arc::new(MemoryFindingSink::new());
    let loader = loader(findings);

    let mut files = Vec::new();
    rhai_files(&bundled_dir(), &mut files);
    files.sort();
    assert!(
        files.len() >= 20,
        "expected the bundled catalogue to ship at least 20 scripts, found {}",
        files.len()
    );

    let mut failures = Vec::new();
    for path in &files {
        if let Err(err) = loader.validate(path) {
            failures.push(format!("{}: {err}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "bundled scripts failed to compile:\n{}",
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn passive_scripts_run_without_error_and_record_findings() {
    let findings = Arc::new(MemoryFindingSink::new());
    let loader = loader(findings.clone());

    let mut http_scripts = Vec::new();
    rhai_files(&bundled_dir().join("http"), &mut http_scripts);
    let mut ws_scripts = Vec::new();
    rhai_files(&bundled_dir().join("ws"), &mut ws_scripts);
    http_scripts.sort();
    ws_scripts.sort();
    assert!(!http_scripts.is_empty() && !ws_scripts.is_empty());

    let mut errors = Vec::new();

    for path in &http_scripts {
        let sink = Arc::new(ErrorSink::default());
        let plugin = loader
            .load_one(&ScriptEntry::new(path))
            .expect("loads")
            .with_error_sink(sink.clone());
        let name = plugin.meta().name.clone();
        for scheme in ["http", "https"] {
            let mut flow = vuln_http_flow(scheme);
            let id = match &flow {
                Flow::Http(f) => f.id,
                _ => unreachable!(),
            };
            plugin.dispatch(&Event::Request(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
            plugin.dispatch(&Event::Response(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
        }
        if let Some(e) = sink.last_error(&name) {
            errors.push(format!("{}: {e}", path.display()));
        }
    }

    for path in &ws_scripts {
        let sink = Arc::new(ErrorSink::default());
        let plugin = loader
            .load_one(&ScriptEntry::new(path))
            .expect("loads")
            .with_error_sink(sink.clone());
        let name = plugin.meta().name.clone();
        let mut flow = ws_flow();
        let id = match &flow {
            Flow::WebSocket(f) => f.id,
            _ => unreachable!(),
        };
        plugin.dispatch(&Event::WsStart(id), &mut FlowCtx::new(&mut flow), MAX_BODY);
        plugin.dispatch(
            &Event::WsMessage { flow: id, index: 0 },
            &mut FlowCtx::new(&mut flow),
            MAX_BODY,
        );
        if let Some(e) = sink.last_error(&name) {
            errors.push(format!("{}: {e}", path.display()));
        }
    }

    assert!(
        errors.is_empty(),
        "passive scripts raised runtime errors:\n{}",
        errors.join("\n")
    );
    assert!(
        findings.list().len() >= 10,
        "expected the vulnerable flows to trip many detectors, got {}",
        findings.list().len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_scripts_register_their_commands() {
    let findings = Arc::new(MemoryFindingSink::new());
    let loader = loader(findings);

    for sub in ["active", "l4"] {
        let mut files = Vec::new();
        rhai_files(&bundled_dir().join(sub), &mut files);
        files.sort();
        assert!(!files.is_empty(), "{sub}/ should ship command scripts");
        for path in &files {
            let v = loader
                .validate_with_registers(path)
                .unwrap_or_else(|e| panic!("{} failed to validate: {e}", path.display()));
            assert!(
                !v.registers.commands.is_empty(),
                "{} registers no command (an operator-invoked script must)",
                path.display()
            );
        }
    }
}
