//! Task 13 — the `reg.add_check(meta, closure)` bridge and the `probe.*` host
//! functions (spec D4, D9.3).
//!
//! A Rhai script declares a check the scanner can schedule: a meta map whose
//! keys are `CheckMeta`'s wire names, and a closure over the point map that
//! returns a verdict map (or a plain string, read as `inconclusive`). The
//! bridge turns that into a native `aitm_scan_model::Check` in a `CheckRegistry`
//! the engine reads, and a check closure reaches the network only through
//! `probe.*`, which is refused anywhere else.
//!
//! The scripts here are written the way an operator would write them, and every
//! assertion is made through the public surface: what the registry holds, what
//! the host was sent, what verdict came back.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{
    CommandHost, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry, StdGuard,
};
use aitm_plugin_rhai::command::ScriptRegHandle;
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_plugin_rhai::{levenshtein_ratio, timing_fit};
use aitm_poc::{Assertion, MatchPart};
use aitm_scan_model::check::{PocHint, Verdict, MAX_EXCERPT_BYTES};
use aitm_scan_model::registry::CheckRegistry;
use aitm_scan_model::testing::{query_point, RecordingHost};
use aitm_scan_model::traits::ProbeHost;
use aitm_scan_model::vocab::{
    CheckOrigin, CheckScope, Confidence, InsertionKind, Outcome, PayloadMode,
};
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

/// The production loader: its engine carries the whole host surface, `probe.*`
/// included, and it owns the `CheckRegistry` the bridge fills.
fn loader() -> RhaiLoader {
    RhaiLoader::new(RhaiConfig::default(), services()).expect("the loader builds")
}

/// Compile `src` as the script named `name`, the way the loader does.
fn compile_named(engine: &Engine, name: &str, src: &str) -> Arc<AST> {
    let mut ast = engine.compile(src).expect("the script compiles");
    ast.set_source(name);
    Arc::new(ast)
}

/// Run `src`'s `load(reg)` through the real bridge, registering its checks into
/// `checks` under the script's own name, and give back the command registry.
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

/// The meta map every well-formed check in this file declares, as script text.
/// `extra` is spliced in so one test can add exactly one key.
fn meta_src(extra: &str) -> String {
    format!(
        r#"#{{ id: "demo-check", name: "Demo", class: "demo", lanes: ["http"],
             kinds: ["query"], intensity: "light", cost: "light",
             technique: "reflected", severity: "low", confidence_max: "certain",
             description: "d"{extra} }}"#
    )
}

/// A script whose `load(reg)` registers one check with `body` as its closure.
fn check_script(meta: &str, body: &str) -> String {
    format!("fn load(reg) {{\n    reg.add_check({meta}, |point| {body});\n}}")
}

/// Load one well-formed check with `body` as its closure, then run it against a
/// recording host answering `status`/`body_text`. Returns the verdict and the host.
async fn verdict_of(body: &str, status: u16, body_text: &str) -> (Verdict, Arc<RecordingHost>) {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&meta_src(""), body),
    )
    .expect("the script loads");

    let snapshot = checks.snapshot();
    assert_eq!(snapshot.len(), 1, "exactly one check is registered");
    let point = query_point("http://127.0.0.1:8080/search", "q");
    let host = RecordingHost::shared_new(status, body_text);
    let probe_host: &dyn ProbeHost = host.as_ref();
    let verdict = snapshot[0].run(&point, probe_host).await;
    (verdict, host)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_check_registers_a_script_check_with_meta() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&meta_src(""), r#""nothing""#),
    )
    .expect("the script loads");

    let snapshot = checks.snapshot();
    assert_eq!(snapshot.len(), 1);
    let meta = snapshot[0].meta();
    assert_eq!(meta.id, "demo-check");
    assert_eq!(meta.name, "Demo");
    assert_eq!(meta.class, "demo");
    assert_eq!(meta.kinds, vec![InsertionKind::Query]);
    assert_eq!(meta.confidence_max, Confidence::Certain);
    assert_eq!(
        meta.origin,
        CheckOrigin::Custom {
            path: "<source>".to_string()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_kinds_is_a_load_error_naming_kinds() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    // The same map with `kinds` removed: the catalogue cannot schedule what it
    // cannot classify, so the load fails naming that key (spec D4).
    let without_kinds = meta_src("").replace(r#"kinds: ["query"],"#, "");
    let Err(err) = run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&without_kinds, r#""nothing""#),
    ) else {
        panic!("a check with no `kinds` must not load");
    };

    match &err {
        ScriptError::CheckMeta { key, .. } => assert_eq!(key, "kinds"),
        other => panic!("expected a CheckMeta error, got {other:?}"),
    }
    assert!(err.to_string().contains("kinds"), "{err}");
    assert!(checks.is_empty(), "a refused check registers nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closure_verdict_map_round_trips() {
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "vulnerable", confidence: "certain",
             evidence: #{ payload: "x", matched: "y" }, detail: "d" }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(verdict.confidence, Confidence::Certain);
    assert_eq!(verdict.evidence.payload.as_deref(), Some("x"));
    assert_eq!(verdict.evidence.matched.as_deref(), Some("y"));
    assert_eq!(verdict.detail, "d");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_string_is_inconclusive() {
    let (verdict, _host) = verdict_of(r#""nothing to report""#, 200, "body").await;

    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.detail, "nothing to report");
    assert_eq!(verdict.confidence, Confidence::Tentative);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_send_reaches_the_host_and_returns_timing() {
    let (verdict, host) = verdict_of(
        r#"{ let r = probe.send("PAY");
             if r.status == 200 { "ok " + r.elapsed_ms } else { "no" } }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(host.payloads(), vec!["PAY".to_string()]);
    assert!(
        verdict.detail.starts_with("ok "),
        "the closure saw the status and the elapsed time: {:?}",
        verdict.detail
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_outside_a_check_is_refused() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    let registry = run_load(
        &loader,
        &checks,
        "<source>",
        r#"fn load(reg) { reg.add_command("demo.probe", "", |args| probe.marker()); }"#,
    )
    .expect("the script loads");

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    let err = registry
        .command("demo.probe")
        .expect("the command is registered")
        .invoke(Params::default(), &host)
        .expect_err("probe.* outside a check must be refused");

    assert!(
        err.to_string().contains("only available inside a check"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_hint_matchers_parse_the_poc_vocabulary() {
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "vulnerable", detail: "d",
             poc_hint: #{ matchers: [ #{ type: "status", status: 200 },
                                      #{ type: "word", word: "AITM" } ] } }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(
        verdict.poc_hint,
        Some(PocHint {
            assertions: vec![Assertion::All(vec![
                Assertion::Status(200),
                Assertion::Word {
                    word: "AITM".to_string(),
                    part: MatchPart::Body,
                },
            ])],
            control: None,
        })
    );
}

#[test]
fn timing_fit_zap_rule() {
    let correlated = timing_fit(&[1.0, 3.0, 1.0, 3.0], &[1050, 3100, 980, 3020]);
    assert!(correlated.correlated, "{correlated:?}");
    assert!(correlated.r > 0.99, "{correlated:?}");
    assert!((correlated.slope - 1.0).abs() < 0.1, "{correlated:?}");

    let flat = timing_fit(&[1.0, 3.0, 1.0, 3.0], &[200, 210, 190, 205]);
    assert!(
        !flat.correlated,
        "a flat response time is no correlation: {flat:?}"
    );
}

#[test]
fn levenshtein_ratio_kitten_sitting() {
    assert!((levenshtein_ratio("kitten", "sitting") - 0.5714).abs() < 1e-3);
    assert_eq!(levenshtein_ratio("", ""), 1.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_style_add_command_scripts_still_register() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/bundled/active/check-sqli.rhai"
    );
    let src = std::fs::read_to_string(path).expect("the shipped script is readable");

    let registry = run_load(&loader, &checks, path, &src).expect("the shipped script loads");

    assert!(
        registry.command("check.sqli").is_some(),
        "an old-style add_command script keeps its verb"
    );
    assert!(
        checks.is_empty(),
        "an old-style script registers no catalogue check"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_replaces_a_scripts_checks() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&meta_src(""), r#""nothing""#),
    )
    .expect("the script loads");
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(
            &meta_src("").replace("demo-check", "demo-check-2"),
            r#""nothing""#,
        ),
    )
    .expect("the reloaded script loads");

    let ids: Vec<String> = checks
        .snapshot()
        .iter()
        .map(|c| c.meta().id.clone())
        .collect();
    assert_eq!(ids, vec!["demo-check-2".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_key_is_optional_and_parsed() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&meta_src(""), r#""nothing""#),
    )
    .expect("the script loads");
    assert_eq!(checks.snapshot()[0].meta().scope, CheckScope::Point);

    let scoped = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &scoped,
        "<source>",
        &check_script(&meta_src(r#", scope: "origin""#), r#""nothing""#),
    )
    .expect("the script loads");
    assert_eq!(scoped.snapshot()[0].meta().scope, CheckScope::Origin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duplicate_id_from_another_source_is_a_load_error() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "first.rhai",
        &check_script(&meta_src(""), r#""nothing""#),
    )
    .expect("the first script loads");

    let Err(err) = run_load(
        &loader,
        &checks,
        "second.rhai",
        &check_script(&meta_src(""), r#""nothing""#),
    ) else {
        panic!("a second source may not claim an id the first owns");
    };

    match &err {
        ScriptError::CheckMeta { key, message, .. } => {
            assert_eq!(key, "id");
            assert!(message.contains("demo-check"), "{message}");
            assert!(message.contains("first.rhai"), "{message}");
        }
        other => panic!("expected a CheckMeta error, got {other:?}"),
    }
    assert_eq!(
        checks.len(),
        1,
        "the refused load leaves the first script's check in place"
    );
}

/// Spec D2: a check returns a verdict in every case, so one failing check never
/// fails the job. A closure that throws is an `Error` outcome carrying why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_throwing_closure_is_an_error_verdict() {
    let (verdict, _host) = verdict_of(r#"throw "boom""#, 200, "body").await;

    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(verdict.detail.contains("boom"), "{:?}", verdict.detail);
}

/// A verdict map whose `outcome` is not an `Outcome` token is an `Error` naming
/// it, never a silent `clean` (spec D4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_outcome_token_is_an_error_verdict() {
    let (verdict, _host) =
        verdict_of(r#"#{ outcome: "probably", detail: "d" }"#, 200, "body").await;

    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(verdict.detail.contains("probably"), "{:?}", verdict.detail);
}

/// `probe.baseline`, `probe.marker` and `probe.budget_left` read the host the
/// bridge seeded, so a check sees the job's figures rather than inventing them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_reads_the_hosts_marker_budget_and_baseline() {
    let (verdict, _host) = verdict_of(
        r#"{ let b = probe.baseline();
             probe.marker() + " " + probe.budget_left() + " " + b.body }"#,
        200,
        "hello",
    )
    .await;

    assert_eq!(verdict.detail, "aitm7f3a 16 hello");
}

/// The point map the closure receives carries the D4 keys, so a check can aim
/// itself at the parameter it was scheduled for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_closure_sees_the_point_map() {
    let (verdict, _host) = verdict_of(
        r#"point.kind + " " + point.name + " " + point.method + " " + point.url"#,
        200,
        "body",
    )
    .await;

    assert_eq!(
        verdict.detail, "query q GET http://127.0.0.1:8080/search",
        "the point map carries kind, name, method and url"
    );
}

/// Evidence is bounded by the model, not by the script: a hostile body cannot
/// put a megabyte of `matched` into an issue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_matched_is_bounded() {
    let (verdict, _host) = verdict_of(
        r#"{ let big = ""; big.pad(400, 'a');
             #{ outcome: "vulnerable", evidence: #{ matched: big } } }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(
        verdict.evidence.matched.as_deref().map(str::len),
        Some(MAX_EXCERPT_BYTES)
    );
}

/// What every `ProbeHost` method below returns: the model's `BoxFuture` spelled
/// with std types, because this crate does not depend on `futures`.
type ProbeFuture<'a> = Pin<
    Box<dyn Future<Output = anyhow::Result<aitm_scan_model::point::ProbeResponse>> + Send + 'a>,
>;

/// A [`ProbeHost`] that records the whole payload, not only its text, so a test
/// can prove `mode` reached the lane. `RecordingHost` keeps the value alone.
struct ModeRecordingHost {
    me: std::sync::Weak<ModeRecordingHost>,
    sent: std::sync::Mutex<Vec<(String, PayloadMode)>>,
    profile: aitm_scan_model::profile::ScanProfile,
}

impl ModeRecordingHost {
    fn shared_new() -> Arc<ModeRecordingHost> {
        Arc::new_cyclic(|me| ModeRecordingHost {
            me: me.clone(),
            sent: std::sync::Mutex::new(Vec::new()),
            profile: aitm_scan_model::profile::ScanProfile::default(),
        })
    }

    fn sent(&self) -> Vec<(String, PayloadMode)> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn response() -> aitm_scan_model::point::ProbeResponse {
        aitm_scan_model::point::ProbeResponse {
            status: Some(200),
            headers: vec![("X-Demo".to_string(), "yes".to_string())],
            body: b"body".to_vec(),
            elapsed_ms: 7,
            flow: None,
            ws_frames: None,
            l4: None,
        }
    }
}

impl ProbeHost for ModeRecordingHost {
    fn baseline(&self) -> ProbeFuture<'_> {
        Box::pin(async { Ok(Self::response()) })
    }
    fn probe<'a>(&'a self, payload: &'a aitm_scan_model::point::Payload) -> ProbeFuture<'a> {
        Box::pin(async move {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((payload.value.clone(), payload.mode));
            Ok(Self::response())
        })
    }
    fn probe_raw(&self, _req: aitm_scan_model::point::RawProbe) -> ProbeFuture<'_> {
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
}

/// T3: `probe.send` takes the map form too, so a check can append to the value
/// the application already expects instead of replacing it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_send_accepts_a_payload_map_with_a_mode() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(
            &meta_src(""),
            r#"{ probe.send(#{ value: "X", mode: "suffix" }); "sent" }"#,
        ),
    )
    .expect("the script loads");

    let host = ModeRecordingHost::shared_new();
    let point = query_point("http://127.0.0.1:8080/search", "q");
    let probe_host: &dyn ProbeHost = host.as_ref();
    let verdict = checks.snapshot()[0].run(&point, probe_host).await;

    assert_eq!(verdict.detail, "sent");
    assert_eq!(host.sent(), vec![("X".to_string(), PayloadMode::Suffix)]);
}

/// An unknown mode names itself rather than silently replacing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_payload_mode_is_refused() {
    let (verdict, _host) = verdict_of(
        r#"{ let out = "no error";
             try { probe.send(#{ value: "X", mode: "sideways" }); }
             catch (e) { out = "" + e; }
             out }"#,
        200,
        "body",
    )
    .await;

    assert!(verdict.detail.contains("sideways"), "{:?}", verdict.detail);
    assert!(
        verdict.detail.contains("replace, prefix, suffix"),
        "{:?}",
        verdict.detail
    );
}

/// T3: a probe response reads exactly like an `http.send` response — same keys,
/// headers as a name-to-string map, body as text — so one script helper can
/// handle both. `http.send`'s half is pinned by
/// `tests/check_run.rs::http_send_keeps_its_keys_and_adds_elapsed_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_response_has_the_http_send_shape() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(
            &meta_src(""),
            r#"{ let r = probe.send("X");
                 let keys = r.keys(); keys.sort();
                 keys.reduce(|acc, k| if acc == () { k } else { acc + "," + k }) + "|" +
                 r.headers["X-Demo"] + "|" + r.body + "|" + r.elapsed_ms + "|" +
                 type_of(r.flow_id) }"#,
        ),
    )
    .expect("the script loads");

    let host = ModeRecordingHost::shared_new();
    let point = query_point("http://127.0.0.1:8080/search", "q");
    let probe_host: &dyn ProbeHost = host.as_ref();
    let verdict = checks.snapshot()[0].run(&point, probe_host).await;

    // `status` and `flow_id` are present but unit when the lane had none, which
    // is how `http.send` reports an exchange with no response.
    assert_eq!(
        verdict.detail, "body,elapsed_ms,flow_id,headers,status|yes|body|7|()",
        "a probe response must read like an http.send response"
    );
}
