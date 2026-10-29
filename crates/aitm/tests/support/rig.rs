//! Shared test rig for the M4 deterministic scripted-driver suites (Tasks 17, 18).
//!
//! Stands a complete aitmproxy (two origins in scope, the findings store wired, a
//! real browser routed through the proxy, and the MCP server on loopback TCP) and
//! connects the non-LLM [`ScriptedDriver`](crate::scripted_driver) to it over the
//! bus. Both the Task 17 e2e and the Task 18 grader gate drive the same rig, so the
//! wiring lives here once rather than once per suite.
//!
//! Including files must declare the two sibling support modules this one references
//! at their crate root (so `crate::engines` / `crate::scripted_driver` resolve):
//!
//! ```ignore
//! #[path = "../../aitm-browser/tests/support/engines.rs"]
//! mod engines;
//! #[path = "support/scripted_driver.rs"]
//! mod scripted_driver;
//! #[path = "support/rig.rs"]
//! mod rig;
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm::wire::{assemble_with_scripts, Assembled, Features, Http1Sender, ScriptWiring};
use aitm_browser::{launch_owned, LaunchedBrowser};
use aitm_core::{
    AgentPolicy, BrowserEngine, Config, FlowStore, McpTransport, PipelineClient, ProxyClient,
    ScopeEntry,
};
use aitm_mcp::McpServer;
use aitm_testtarget::{SeedMode, TestTarget};
use tokio::net::TcpStream;

use crate::engines;
use crate::scripted_driver::{Client, ScriptedDriver};

/// The agent token the harness configures and the driver presents.
pub const AGENT_TOKEN: &str = "scripted-driver-agent-token";

/// The six vulnerable endpoint classes the driver should reproduce.
pub const EXPECTED_CLASSES: [&str; 6] = [
    "reflected-xss",
    "stored-xss",
    "ssrf",
    "idor",
    "auth-bypass",
    "open-redirect",
];

/// Whether obscura is enabled for this run. With it unset every gated test returns
/// early and the default suite stays hermetic (no browser, no port binding).
pub fn obscura_enabled() -> bool {
    if std::env::var_os("AITM_OBSCURA").is_none() {
        eprintln!(
            "skipped; set AITM_OBSCURA=1 (with AITM_OBSCURA_BIN) to run the scripted-driver gate"
        );
        return false;
    }
    true
}

/// One real browser at a time within a test binary: each launches obscura, whose
/// start timeout is a function of host load if several race.
pub fn obscura_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

// ---- temp dirs --------------------------------------------------------------

/// A fresh directory under the OS temp dir, unique per call, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aitm-m4-scripted-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
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
pub struct Rig {
    /// The loopback-TCP address of the MCP bus the driver connects to.
    pub addr: SocketAddr,
    /// The vulnerable origin (`http://host:port`).
    pub vuln_base: String,
    /// The patched control origin (`http://host:port`).
    pub patched_base: String,
    /// The flow store, so a test can confirm a finding-capture flow landed.
    pub store: Arc<dyn FlowStore>,
    /// Where `findings.record` persists and the report/index are rendered from.
    pub findings_dir: PathBuf,
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
    pub async fn start() -> Rig {
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
    pub async fn driver(&self) -> ScriptedDriver {
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

    pub async fn finish(self) {
        self.browser.close().await.expect("close the browser");
    }
}

// ---- helpers ----------------------------------------------------------------

/// The `host:port` authority of an `http://host:port` base URL.
pub fn authority_of(base: &str) -> String {
    base.strip_prefix("http://")
        .unwrap_or(base)
        .trim_end_matches('/')
        .to_string()
}

pub fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
}

pub async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "listener {addr} never came up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
