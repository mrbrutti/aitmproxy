//! Task 17 — the deterministic scripted-driver e2e (spec §D7; AC-M4-13, AC-M4-14,
//! AC-M4-15b).
//!
//! A **non-LLM** generic MCP client ([`scripted_driver`]) drives the whole
//! find → reproduce → record → report loop against the hermetic multi-vuln
//! [`aitm-testtarget`](aitm_testtarget) over nothing but the public command
//! surface — the loopback-TCP bus with the agent token — proving the surface
//! suffices to run the thesis loop with no model in it. The driver crawls the
//! **vulnerable** origin through a real browser (obscura), enumerates candidate
//! abuse points from the observed `flow.detail`, confirms each with its own probe
//! via `request.send`, and reproduces it with `poc.build` + `poc.run` — a PoC that
//! passes on the vulnerable origin and fails on the **patched** control — then
//! `findings.record`s it and renders the report.
//!
//! Gated on a real browser: with `AITM_OBSCURA` unset the tests return early, so
//! the default `cargo test` stays hermetic (no browser, no port binding, no
//! network). Run them for real with:
//!
//! ```text
//! AITM_OBSCURA=1 AITM_OBSCURA_BIN=/path/to/obscura \
//!   cargo test -p aitm --test m4_scripted_e2e -- --nocapture
//! ```
//!
//! The test harness here stands the rig (two origins, the proxy with the findings
//! store wired, the browser, and the TCP MCP server); the driver under test speaks
//! only MCP. The findings-store commands (`findings.*`) are not yet wired into the
//! `aitm` binary (the M4 wiring gap other sessions flagged), so this harness
//! registers `FindingsPlugin` the way Task 16's validator does — the driver still
//! reaches them only over the bus.

#[path = "../../aitm-browser/tests/support/engines.rs"]
#[allow(dead_code)] // only `config_for` is used here; `engines` serves other suites
mod engines;
#[path = "support/scripted_driver.rs"]
mod scripted_driver;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm::wire::{assemble_with_scripts, Assembled, Features, Http1Sender, ScriptWiring};
use aitm_browser::{launch_owned, LaunchedBrowser};
use aitm_core::{
    AgentPolicy, BrowserEngine, Config, Flow, FlowId, FlowStore, McpTransport, PipelineClient,
    ProxyClient, ScopeEntry,
};
use aitm_findings::{render_index, render_report, DiskFindingStore, FindingFilter, FindingStore};
use aitm_mcp::McpServer;
use aitm_testtarget::{SeedMode, TestTarget};
use tokio::net::TcpStream;

use scripted_driver::{Client, ScriptedDriver};

/// The agent token the harness configures and the driver presents.
const AGENT_TOKEN: &str = "scripted-driver-agent-token";

/// The eight-byte PNG signature a real screenshot artifact starts with.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The six vulnerable endpoint paths the driver should reproduce, and the classes
/// it should file them under.
const EXPECTED_CLASSES: [&str; 6] = [
    "reflected-xss",
    "stored-xss",
    "ssrf",
    "idor",
    "auth-bypass",
    "open-redirect",
];

/// Whether obscura is enabled for this run. With it unset every test returns early
/// and the default suite stays hermetic.
fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (with AITM_OBSCURA_BIN) to run the scripted-driver e2e"
        );
        return false;
    }
    true
}

/// One real browser at a time across the tests: each launches obscura, whose start
/// timeout is a function of host load if several race.
fn obscura_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

// ---- temp dirs --------------------------------------------------------------

/// A fresh directory under the OS temp dir, unique per call, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aitm-m4-scripted-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
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

// ---- the rig ----------------------------------------------------------------

/// A standing aitmproxy with the findings store wired, two origins in scope
/// (vulnerable + patched control), the browser launched and routed through the
/// proxy, and the MCP server listening on loopback TCP with the agent token.
struct Rig {
    addr: SocketAddr,
    vuln_base: String,
    patched_base: String,
    store: Arc<dyn FlowStore>,
    findings_dir: PathBuf,
    poc_dir: PathBuf,
    browser: LaunchedBrowser,
    // Kept alive for the run.
    _vuln: TestTarget,
    _patched: TestTarget,
    _ca_dir: TempDir,
    _findings_tmp: TempDir,
    _poc_tmp: TempDir,
}

impl Rig {
    async fn start() -> Rig {
        let vuln = TestTarget::start(SeedMode::Vulnerable).await;
        let patched = TestTarget::start(SeedMode::Patched).await;
        let vuln_base = vuln.base_url().to_string();
        let patched_base = patched.base_url().to_string();
        let vuln_authority = authority_of(&vuln_base);
        let patched_authority = authority_of(&patched_base);

        let ca_dir = TempDir::new("ca");
        let findings_tmp = TempDir::new("findings");
        let poc_tmp = TempDir::new("poc");

        let browser_listen = free_addr();
        let mut cfg = Config::default();
        cfg.ca.dir = ca_dir.path().to_path_buf();
        cfg.browser = engines::config_for(BrowserEngine::Obscura, browser_listen);
        cfg.scope.entries = vec![
            ScopeEntry {
                host: vuln_authority.clone(),
            },
            ScopeEntry {
                host: patched_authority.clone(),
            },
        ];
        // The browser-facing listener's SSRF guard forwards loopback only for an
        // in-scope host; this e2e authorizes the two loopback origins above.
        cfg.scope.allow_agent_widen = true;
        // Arm the agent fully (as the operator would with `agent.set {all}`).
        cfg.mcp.policy = AgentPolicy::All;
        // Where `findings.record` persists and the report is rendered from.
        cfg.findings.dir = Some(findings_tmp.path().to_path_buf());

        // Assemble WITH the findings store commands wired in (the binary does not
        // yet; Task 16's validator wires them the same way).
        let Assembled {
            proxy,
            ca,
            agent_state,
            push_tx,
            ..
        } = assemble_with_scripts(
            &cfg,
            &Features::default(),
            ScriptWiring {
                plugins: Vec::new(),
                executor: None,
                commands: Some(Box::new(aitm_findings::FindingsPlugin::new())),
            },
        )
        .expect("assemble the proxy with the findings store");

        let store = proxy.store();
        let guard = proxy.guard();
        let registry = proxy.registry_arc();
        let client: Arc<dyn ProxyClient> = Arc::new(PipelineClient::new(
            store.clone(),
            guard.clone(),
            Arc::new(Http1Sender::new()),
        ));

        // Browser-facing accept loop, so the engine reaches the targets through it.
        tokio::spawn(async move {
            let _ = proxy.run_browser(browser_listen).await;
        });
        wait_listening(browser_listen).await;

        let browser = launch_owned(&cfg.browser, ca.cert_path())
            .await
            .unwrap_or_else(|err| panic!("launch obscura through {browser_listen}: {err:#}"));

        // The MCP server on loopback TCP (port 0 → a free port), authenticated by
        // the agent token. `serve` runs the push dispatcher too (F4).
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let server = McpServer::new(
            registry,
            McpTransport::LoopbackTcp {
                port: 0,
                token: AGENT_TOKEN.to_string(),
            },
        )
        .with_ssrf_policy(cfg.browser.ssrf.clone())
        .with_config(Arc::new(cfg.clone()))
        .with_agent_state(agent_state)
        .with_push(push_tx)
        .with_services(store.clone(), client, guard, Some(browser.driver.clone()))
        .on_bound(move |addr| {
            let _ = addr_tx.send(addr);
        });
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        let addr = addr_rx.await.expect("MCP server bound address");

        Rig {
            addr,
            vuln_base,
            patched_base,
            store,
            findings_dir: findings_tmp.path().to_path_buf(),
            poc_dir: poc_tmp.path().to_path_buf(),
            browser,
            _vuln: vuln,
            _patched: patched,
            _ca_dir: ca_dir,
            _findings_tmp: findings_tmp,
            _poc_tmp: poc_tmp,
        }
    }

    /// Connect the non-LLM driver to the bus with the agent token.
    async fn driver(&self) -> ScriptedDriver {
        let mut client = Client::connect(self.addr, AGENT_TOKEN)
            .await
            .expect("connect the scripted driver to the bus");
        client
            .initialize()
            .await
            .expect("initialize the MCP session");
        ScriptedDriver::new(
            client,
            self.vuln_base.clone(),
            self.patched_base.clone(),
            self.poc_dir.clone(),
        )
    }

    async fn finish(self) {
        self.browser.close().await.expect("close the browser");
    }
}

// ---- AC-M4-13 ---------------------------------------------------------------

/// The driver crawls the vulnerable target through a real browser and enumerates
/// its candidate abuse points **from the observed index flow** — each candidate's
/// path is present in the `flow.detail` body of the flow it was read from, and the
/// six vulnerable endpoints are all discovered. The crawl's flows also arrive as
/// F4 push notifications. Nothing here (or in the driver module) reads the
/// target's planted-vuln manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_finds_from_observation() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let candidates = driver.discover().await.expect("discover candidates");

    // The six vulnerable endpoints are discovered from the crawl.
    for path in [
        "/search",
        "/comments",
        "/fetch",
        "/account/1",
        "/admin",
        "/redirect",
    ] {
        assert!(
            candidates.iter().any(|c| c.path == path),
            "endpoint {path} was not discovered from the crawl; got {:?}",
            candidates.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
    }

    // Every candidate was derived from an observed flow: its path appears in the
    // `flow.detail` body of the source flow it was read out of.
    for candidate in &candidates {
        let detail = driver
            .client
            .tool_call(
                "flow.detail",
                serde_json::json!({"id": candidate.source_flow, "body": "inline"}),
            )
            .await
            .expect("flow.detail for the candidate's source flow");
        let body = response_body_text(&detail);
        assert!(
            body.contains(&candidate.path),
            "candidate {} was not present in its source flow's observed body",
            candidate.path
        );
    }

    // F4: the crawl's flows (captured after subscribing) pushed notifications.
    assert!(
        driver.client.flow_notifications() > 0,
        "no notifications/aitm/flow arrived during the crawl"
    );

    rig.finish().await;
}

// ---- AC-M4-14 ---------------------------------------------------------------

/// For each discovered vuln the driver builds and runs a PoC that passes on the
/// vulnerable origin and fails on the patched control, emitting the three
/// artifacts (a finding-capture flow in the store, a re-parsable PoC file, a PNG
/// screenshot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_reproduces_each() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let candidates = driver.discover().await.expect("discover candidates");
    let findings = driver
        .reproduce_all(&candidates)
        .await
        .expect("reproduce the discovered vulns");

    let classes: Vec<&str> = findings.iter().map(|f| f.class.as_str()).collect();
    for class in EXPECTED_CLASSES {
        assert!(
            classes.contains(&class),
            "class {class} was not reproduced; got {classes:?}"
        );
    }

    for f in &findings {
        // The reproduction bar: passed on the vulnerable path, failed the control.
        assert!(
            f.passed,
            "[{}] PoC did not pass on the vulnerable origin",
            f.class
        );
        assert_eq!(
            f.control_passed,
            Some(false),
            "[{}] PoC did not fail on the patched control",
            f.class
        );

        // Artifact 1: the finding-capture flow is in the store.
        let fid: FlowId = f
            .finding_capture
            .parse()
            .unwrap_or_else(|e| panic!("[{}] bad finding_capture id: {e}", f.class));
        assert!(
            matches!(rig.store.get(fid), Some(Flow::Http(_))),
            "[{}] finding-capture flow is not in the store",
            f.class
        );

        // Artifact 2: the PoC file re-parses as a PoC.
        let poc_text = std::fs::read_to_string(&f.poc_path)
            .unwrap_or_else(|e| panic!("[{}] read PoC artifact: {e}", f.class));
        let _: aitm_poc::Poc = serde_yaml::from_str(&poc_text)
            .unwrap_or_else(|e| panic!("[{}] PoC artifact does not re-parse: {e}", f.class));

        // Artifact 3: the screenshot is a PNG.
        let png = std::fs::read(&f.screenshot_path)
            .unwrap_or_else(|e| panic!("[{}] read screenshot artifact: {e}", f.class));
        assert!(
            png.starts_with(PNG_MAGIC),
            "[{}] screenshot artifact is not a PNG ({} bytes)",
            f.class,
            png.len()
        );
    }

    rig.finish().await;
}

// ---- AC-M4-15b --------------------------------------------------------------

/// The driver records a `FindingRecord` per reproduced vuln (reachable again over
/// `findings.list`), and the aitm-findings renderer produces `report.md` +
/// `findings.index.json` from the persisted store — one report section and one
/// index entry per finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_driver_records_and_reports() {
    if !obscura_enabled() {
        return;
    }
    let _serial = obscura_lock().lock().await;
    let rig = Rig::start().await;
    let mut driver = rig.driver().await;

    let (findings, ids) = driver.run().await.expect("run the full driver loop");
    assert_eq!(ids.len(), findings.len(), "one recorded id per finding");
    assert!(
        findings.len() >= EXPECTED_CLASSES.len(),
        "expected at least {} findings, got {}",
        EXPECTED_CLASSES.len(),
        findings.len()
    );

    // The records are reachable again over the bus.
    let listed = driver
        .client
        .tool_call("findings.list", serde_json::json!({}))
        .await
        .expect("findings.list over MCP");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(findings.len()),
        "findings.list did not return every recorded finding"
    );

    // Read the persisted records and render the report + index from them (D8a).
    let store = DiskFindingStore::new(&rig.findings_dir);
    let mut records = Vec::new();
    for id in &ids {
        records.push(
            store
                .get(id)
                .unwrap_or_else(|| panic!("recorded finding {id} is not in the store")),
        );
    }

    let report = render_report(&records);
    let sections = report.matches("\n## ").count();
    assert_eq!(
        sections,
        records.len(),
        "report must have one section per finding:\n{report}"
    );
    for f in &findings {
        assert!(
            report.contains(&f.target),
            "report missing endpoint {}",
            f.target
        );
    }

    let index = render_index(&records);
    assert_eq!(
        index.as_array().map(Vec::len),
        Some(records.len()),
        "the index must have one entry per finding"
    );

    // The deliverables land as files next to the store.
    let report_path = rig.findings_dir.join("report.md");
    let index_path = rig.findings_dir.join("findings.index.json");
    std::fs::write(&report_path, &report).expect("write report.md");
    std::fs::write(&index_path, serde_json::to_string_pretty(&index).unwrap())
        .expect("write findings.index.json");
    assert!(report_path.exists() && index_path.exists());

    // Sanity: the store's own filter path agrees with the rendered set.
    assert_eq!(
        store.list(&FindingFilter::default()).len(),
        records.len(),
        "the store lists every recorded finding"
    );

    rig.finish().await;
}

// ---- helpers ----------------------------------------------------------------

/// The base64-free body text of a `flow.detail` structured result.
fn response_body_text(detail: &serde_json::Value) -> String {
    // Request and response bodies are base64 (`Value::Bytes`); for discovery the
    // index is a request path echoed in the response body, so decode the response.
    match detail
        .get("response")
        .and_then(|r| r.get("body"))
        .and_then(serde_json::Value::as_str)
    {
        Some(b64) => String::from_utf8_lossy(&base64_decode(b64)).into_owned(),
        None => String::new(),
    }
}

/// Standard padded base64 decode (mirrors the driver's, for the test's own read).
fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for c in s.bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn authority_of(base: &str) -> String {
    base.strip_prefix("http://")
        .unwrap_or(base)
        .trim_end_matches('/')
        .to_string()
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "listener {addr} never came up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
