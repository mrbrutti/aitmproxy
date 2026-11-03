//! Coordinator items (g) and the T3 live-run bug (2026-11-01) — the
//! multi-verdict contract of `reg.add_check` and the `remediation` meta key.
//!
//! A check closure may return one verdict map, a string, or an **array** of
//! verdict maps: the first is the root verdict and the rest are its `more`
//! siblings, each optionally carrying `location: #{ path, name }` so an
//! origin-scoped check (Burp-style "exposed path") yields one issue per path.
//! The assertions here go through the public surface — the registry's check,
//! the verdict it hands back — the way the engine will consume them.
//!
//! `tests/check_bridge.rs` is left alone: a tester owns it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, Registry, StdGuard};
use aitm_plugin_rhai::command::ScriptRegHandle;
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_scan_model::check::{Verdict, VerdictLocation};
use aitm_scan_model::registry::CheckRegistry;
use aitm_scan_model::testing::{query_point, RecordingHost};
use aitm_scan_model::traits::ProbeHost;
use aitm_scan_model::vocab::{CheckOrigin, Confidence, Outcome};
use rhai::{Engine, AST};

/// A client no check here reaches: every probe goes through the `RecordingHost`.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

fn loader() -> RhaiLoader {
    RhaiLoader::new(RhaiConfig::default(), services()).expect("the loader builds")
}

fn compile_named(engine: &Engine, name: &str, src: &str) -> Arc<AST> {
    let mut ast = engine.compile(src).expect("the script compiles");
    ast.set_source(name);
    Arc::new(ast)
}

/// Run `src`'s `load(reg)` through the real bridge, registering its checks into
/// `checks` under the script's own name.
fn run_load(
    loader: &RhaiLoader,
    checks: &Arc<CheckRegistry>,
    name: &str,
    src: &str,
) -> Result<Registry, ScriptError> {
    let engine = loader.engine();
    let ast = compile_named(&engine, name, src);
    let mut registry = Registry::new();
    ScriptRegHandle::new(&mut registry)
        .with_checks(
            Arc::clone(checks),
            CheckOrigin::Custom {
                path: name.to_string(),
            },
        )
        .run_load(&engine, &ast)?;
    Ok(registry)
}

/// The meta map every well-formed check in this file declares; `extra` is
/// spliced in so one test can add exactly one key.
fn meta_src(extra: &str) -> String {
    format!(
        r#"#{{ id: "exposed-path", name: "Exposed path", class: "exposed-path",
             lanes: ["http"], kinds: ["query"], intensity: "light", cost: "light",
             technique: "observe", severity: "medium", confidence_max: "firm",
             scope: "origin", description: "d"{extra} }}"#
    )
}

fn check_script(meta: &str, body: &str) -> String {
    format!("fn load(reg) {{\n    reg.add_check({meta}, |point| {body});\n}}")
}

/// Load one check with `body` as its closure and run it against a recording
/// host answering 200 `ok`.
async fn verdict_of(body: &str) -> Verdict {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<multi>",
        &check_script(&meta_src(""), body),
    )
    .expect("the script loads");
    let snapshot = checks.snapshot();
    assert_eq!(snapshot.len(), 1, "exactly one check is registered");
    let point = query_point("http://127.0.0.1:8080/", "q");
    let host = RecordingHost::shared_new(200, "ok");
    let probe_host: &dyn ProbeHost = host.as_ref();
    snapshot[0].run(&point, probe_host).await
}

fn path_of(verdict: &Verdict) -> Option<&str> {
    verdict.location.as_ref().and_then(|l| l.path.as_deref())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_array_of_verdicts_becomes_root_plus_more() {
    let verdict = verdict_of(
        r#"[
            #{ outcome: "vulnerable", confidence: "firm", location: #{ path: "/.git/" }, detail: "a" },
            #{ outcome: "vulnerable", confidence: "firm", location: #{ path: "/.env" }, detail: "b" }
        ]"#,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(verdict.confidence, Confidence::Firm);
    assert_eq!(verdict.detail, "a");
    assert_eq!(path_of(&verdict), Some("/.git/"));
    assert_eq!(
        verdict.location,
        Some(VerdictLocation {
            path: Some("/.git/".to_string()),
            name: None,
        })
    );

    assert_eq!(verdict.more.len(), 1);
    let sibling = &verdict.more[0];
    assert_eq!(sibling.outcome, Outcome::Vulnerable);
    assert_eq!(sibling.confidence, Confidence::Firm);
    assert_eq!(sibling.detail, "b");
    assert_eq!(path_of(sibling), Some("/.env"));
    assert!(sibling.more.is_empty(), "the bridge nests one level only");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_map_with_a_named_location_round_trips_both_fields() {
    let verdict = verdict_of(
        r#"#{ outcome: "vulnerable", confidence: "firm",
             location: #{ path: "/backup.zip", name: "backup" }, detail: "c" }"#,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(
        verdict.location,
        Some(VerdictLocation {
            path: Some("/backup.zip".to_string()),
            name: Some("backup".to_string()),
        })
    );
    assert!(verdict.more.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_map_array_element_is_an_error_verdict() {
    let verdict = verdict_of(
        r#"[
            #{ outcome: "vulnerable", confidence: "firm", location: #{ path: "/.git/" }, detail: "a" },
            42
        ]"#,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Error, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("[1]") || verdict.detail.contains("index 1"),
        "the error names the offending index: {}",
        verdict.detail
    );
    assert!(
        verdict.more.is_empty(),
        "nothing from a refused array survives"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_array_is_an_error_verdict() {
    let verdict = verdict_of("[]").await;
    assert_eq!(verdict.outcome, Outcome::Error, "{}", verdict.detail);
    assert!(verdict.more.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_location_key_is_refused() {
    let verdict = verdict_of(
        r#"#{ outcome: "vulnerable", confidence: "firm",
             location: #{ path: "/.git/", nme: "typo" }, detail: "a" }"#,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Error, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("nme"),
        "the error names the unknown key: {}",
        verdict.detail
    );
    assert_eq!(verdict.location, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_location_that_is_not_a_map_is_refused() {
    let verdict = verdict_of(
        r#"#{ outcome: "vulnerable", confidence: "firm", location: "/.git/", detail: "a" }"#,
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Error, "{}", verdict.detail);
    assert!(verdict.detail.contains("location"), "{}", verdict.detail);
}

/// T3 live-run bug: `remediation` is a documented optional `CheckMeta` key the
/// bridge refused as "not a check metadata key".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remediation_is_an_accepted_optional_key() {
    let loader = loader();

    let with = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &with,
        "<with-remediation>",
        &check_script(&meta_src(r#", remediation: "fix it""#), r#""seen""#),
    )
    .expect("a meta declaring remediation loads");
    let snapshot = with.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].meta().remediation.as_deref(), Some("fix it"));

    let without = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &without,
        "<without-remediation>",
        &check_script(&meta_src(""), r#""seen""#),
    )
    .expect("a meta without remediation still loads");
    assert_eq!(without.snapshot()[0].meta().remediation, None);
}

type ProbeFuture<'a> = Pin<
    Box<dyn Future<Output = anyhow::Result<aitm_scan_model::point::ProbeResponse>> + Send + 'a>,
>;

/// A host that can lend itself out (`shared`) but no client: the model's
/// default `client()` is `None`. Every probe it is asked for is counted, so a
/// test can prove the check ran nothing.
struct ClientlessHost {
    me: std::sync::Weak<ClientlessHost>,
    profile: aitm_scan_model::profile::ScanProfile,
    probes: std::sync::atomic::AtomicUsize,
}

impl ClientlessHost {
    fn shared_new() -> Arc<ClientlessHost> {
        Arc::new_cyclic(|me| ClientlessHost {
            me: me.clone(),
            profile: aitm_scan_model::profile::ScanProfile::default(),
            probes: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn response() -> aitm_scan_model::point::ProbeResponse {
        aitm_scan_model::point::ProbeResponse {
            status: Some(200),
            headers: Vec::new(),
            body: b"ok".to_vec(),
            elapsed_ms: 1,
            flow: None,
            ws_frames: None,
            l4: None,
        }
    }
}

impl ProbeHost for ClientlessHost {
    fn baseline(&self) -> ProbeFuture<'_> {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(Self::response()) })
    }
    fn probe<'a>(&'a self, _payload: &'a aitm_scan_model::point::Payload) -> ProbeFuture<'a> {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(Self::response()) })
    }
    fn probe_raw(&self, _req: aitm_scan_model::point::RawProbe) -> ProbeFuture<'_> {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(Self::response()) })
    }
    fn marker(&self) -> String {
        "aitm7f3a".to_string()
    }
    fn budget_left(&self) -> u32 {
        4
    }
    fn deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(60)
    }
    fn profile(&self) -> &aitm_scan_model::profile::ScanProfile {
        &self.profile
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        Vec::new()
    }
    fn shared(&self) -> Option<Arc<dyn ProbeHost>> {
        self.me.upgrade().map(|host| host as Arc<dyn ProbeHost>)
    }
    /// **The point of this host:** it lends no client at all, so the bridge
    /// must refuse a script send rather than route it unbudgeted.
    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        None
    }
    /// No captured flow built this host.
    fn captured(&self) -> Option<aitm_core::HttpFlow> {
        None
    }
    /// Affordable up to `budget_left`, debiting nothing.
    fn charge(&self, units: u32) -> bool {
        self.budget_left() >= units
    }
}

/// Wave-2/3 security fix: a host that lends no client is a wiring bug, exactly
/// like one that lends no shared handle — the check runs nothing (so nothing
/// can go out on the unbudgeted namespace client) and the verdict is an error
/// naming the missing client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_without_a_client_is_a_wiring_error() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<clientless>",
        &check_script(&meta_src(""), r#"{ probe.send("X"); "ran" }"#),
    )
    .expect("the script loads");

    let host = ClientlessHost::shared_new();
    let point = query_point("http://127.0.0.1:8080/", "q");
    let probe_host: &dyn ProbeHost = host.as_ref();
    let verdict = checks.snapshot()[0].run(&point, probe_host).await;

    assert_eq!(verdict.outcome, Outcome::Error, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("client"),
        "the error names the missing client: {}",
        verdict.detail
    );
    assert_eq!(
        host.probes.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the closure did not run"
    );
}

/// A meta map for check `id`, well formed in every other key.
fn meta_with_id(id: &str) -> String {
    format!(
        r#"#{{ id: "{id}", name: "{id}", class: "dup", lanes: ["http"], kinds: ["query"],
             intensity: "light", cost: "light", technique: "observe", severity: "low",
             confidence_max: "firm", description: "d" }}"#
    )
}

/// Wave-2 quality panel: a script refused for a duplicate id must register
/// **nothing** — `checks_from_collected` promises all or nothing, but
/// `replace_source` had already inserted the non-colliding checks when
/// `run_load` returned the error. Script A owns `x`; script B declares `x` and
/// `y`; B fails naming `x` and the registry still holds exactly A's `x`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_id_registers_nothing_from_that_script() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());

    run_load(
        &loader,
        &checks,
        "<a>",
        &format!(
            "fn load(reg) {{\n    reg.add_check({}, |point| \"a\");\n}}",
            meta_with_id("x")
        ),
    )
    .expect("script A loads");

    let err = match run_load(
        &loader,
        &checks,
        "<b>",
        &format!(
            "fn load(reg) {{\n    reg.add_check({}, |point| \"b\");\n    reg.add_check({}, |point| \"b\");\n}}",
            meta_with_id("x"),
            meta_with_id("y")
        ),
    ) {
        Err(err) => err,
        Ok(_) => panic!("script B must be refused on the duplicate id"),
    };
    match &err {
        ScriptError::CheckMeta {
            script, check, key, ..
        } => {
            assert_eq!(script, "<b>");
            assert_eq!(check.as_deref(), Some("x"));
            assert_eq!(key, "id");
        }
        other => panic!("expected CheckMeta, got {other:?}"),
    }

    let ids: Vec<String> = checks
        .snapshot()
        .iter()
        .map(|c| c.meta().id.clone())
        .collect();
    assert_eq!(ids, vec!["x".to_string()], "nothing from B survives");
    let listing = format!("{checks:?}");
    assert!(listing.contains(r#"("x", "<a>")"#), "{listing}");
    assert!(!listing.contains("<b>"), "{listing}");
}
