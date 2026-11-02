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
    // An old-style script of its own: every bundled `active/` script registers
    // a check since T3 PR 2b, so the fixture is inline, shaped like the shipped
    // `check.sqli` command was before its conversion.
    let src = r#"const NAME = "old-style-check";
const API = "1";
fn load(reg) {
    reg.add_command("check.sqli", "Probe a parameter for SQL injection", |args| { "ok" });
}
"#;

    let registry =
        run_load(&loader, &checks, "<old-style>", src).expect("the old-style script loads");

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

/// PR 3a panel (security Minor 2, quality Minor 5): the bridge scrubs at its
/// one structural exit, so the eval-error arm is covered too. A closure that
/// `throw`s a string carrying a bearer token (a script doing `throw resp.body`
/// on an unexpected answer) yields an `Error` verdict whose `detail` reads
/// `[redacted]` where the token was; the token itself never leaves the bridge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thrown_value_carrying_a_secret_is_scrubbed_in_the_error_verdict() {
    let (verdict, _host) = verdict_of(
        r#"throw "unexpected reply: Authorization: Bearer abc.def.ghi""#,
        200,
        "body",
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(
        verdict
            .detail
            .starts_with("error: <source>:5 — hook 'anon$"),
        "{:?}",
        verdict.detail
    );
    assert!(
        verdict.detail.ends_with(
            "' failed: unexpected reply: Authorization: [redacted]\n  help: the flow was \
             forwarded unchanged. Fix the hook and reload the script."
        ),
        "{:?}",
        verdict.detail
    );
    assert!(
        !verdict.detail.contains("abc.def.ghi"),
        "{:?}",
        verdict.detail
    );
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

/// Amendment 56 (D8.1 / amendment 16): the bridge scrubs `evidence.matched` and
/// `evidence.payload` with `aitm_core::redact::scrub_text_wide` where the verdict
/// is built, so a closure that echoes a session cookie or a bearer token from a
/// target's response hands neither to the job path nor to the manual `check.<id>`
/// path. The exact form is the scrubber's: a secret pair's value and the whole
/// of an `Authorization` line become `[redacted]`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_matched_and_payload_are_scrubbed() {
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "vulnerable",
             evidence: #{ payload: "q=1&access_token=tok-123",
                          matched: "Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi" } }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        verdict.evidence.matched.as_deref(),
        Some("Cookie: [redacted]; Authorization: [redacted]")
    );
    assert_eq!(
        verdict.evidence.payload.as_deref(),
        Some("q=1&access_token=[redacted]")
    );
}

/// Amendment 16's order: scrub first, then bound. 230 bytes of padding followed
/// by the two secrets scrubs to 276 bytes, which the bound cuts to exactly
/// `MAX_EXCERPT_BYTES`; bounded first, the cut would land inside the cookie value
/// and the scrub would then shrink the text to 249 bytes. The literal pins both
/// the redaction and the cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrubbed_evidence_matched_is_still_bounded() {
    let (verdict, _host) = verdict_of(
        r#"{ let pad = ""; pad.pad(230, 'a');
             #{ outcome: "vulnerable",
                evidence: #{ matched: pad + " Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi" } } }"#,
        200,
        "body",
    )
    .await;

    let matched = verdict.evidence.matched.as_deref().expect("matched is set");
    assert_eq!(matched.len(), MAX_EXCERPT_BYTES);
    assert_eq!(
        matched,
        format!("{} Cookie: [redacted]; Autho", "a".repeat(230))
    );
}

/// Amendment 67 (call C5): `detail` is scrubbed with the same `scrub_text_wide`
/// as the evidence, at the root, in every sibling of the array form, and in the
/// plain-string form (which puts the whole string in `detail`). The bridge and
/// the manual `check.<id>` path share one `Verdict::scrub`, so a bearer token a
/// closure echoes into its prose reaches neither the job path nor the bus caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detail_is_scrubbed_at_the_root_in_siblings_and_in_the_string_form() {
    let (verdict, _host) = verdict_of(
        r#"[ #{ outcome: "clean", detail: "echo: Authorization: Bearer abc.def.ghi" },
            #{ outcome: "clean", detail: "sibling Cookie: sid=s3cr3t" } ]"#,
        200,
        "body",
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
    assert_eq!(verdict.detail, "echo: Authorization: [redacted]");
    assert_eq!(verdict.more.len(), 1);
    assert_eq!(verdict.more[0].detail, "sibling Cookie: [redacted]");

    let (verdict, _host) = verdict_of(r#""saw Authorization: Bearer x""#, 200, "body").await;
    assert_eq!(verdict.outcome, Outcome::Inconclusive);
    assert_eq!(verdict.detail, "saw Authorization: [redacted]");
}

/// Tester (amendment 67): the map form scrubs `detail` on its own — not only
/// when it arrives as an element of the array form — and a sibling's evidence
/// is scrubbed and bounded like the root's. Together with
/// `detail_is_scrubbed_at_the_root_in_siblings_and_in_the_string_form` this
/// covers every field of every return shape the bridge accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn map_form_detail_and_sibling_evidence_are_scrubbed() {
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "clean", detail: "saw Cookie: sid=s3cr3t in the reply" }"#,
        200,
        "body",
    )
    .await;
    assert_eq!(verdict.outcome, Outcome::Clean, "{}", verdict.detail);
    assert_eq!(verdict.detail, "saw Cookie: [redacted] in the reply");

    let (verdict, _host) = verdict_of(
        r#"{ let pad = ""; pad.pad(230, 'a');
            [ #{ outcome: "vulnerable", detail: "root" },
              #{ outcome: "vulnerable",
                 evidence: #{ payload: "q=1&access_token=tok-123",
                              matched: pad + " Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi" } } ] }"#,
        200,
        "body",
    )
    .await;
    assert_eq!(verdict.outcome, Outcome::Vulnerable, "{}", verdict.detail);
    assert_eq!(verdict.more.len(), 1);
    let sibling = &verdict.more[0];
    assert_eq!(
        sibling.evidence.payload.as_deref(),
        Some("q=1&access_token=[redacted]")
    );
    let matched = sibling
        .evidence
        .matched
        .as_deref()
        .expect("the sibling's matched is kept");
    assert_eq!(matched.len(), MAX_EXCERPT_BYTES);
    assert_eq!(
        matched,
        format!("{} Cookie: [redacted]; Autho", "a".repeat(230)),
        "scrubbed then bounded, in the sibling too"
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
    /// A script check must never run on the unbudgeted namespace client, so
    /// the bridge treats `client() == None` as an error verdict; this host
    /// lends the model's `NullClient` the way `RecordingHost` does.
    fn client(&self) -> Option<Arc<dyn aitm_core::ProxyClient>> {
        Some(Arc::new(aitm_scan_model::testing::NullClient))
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

// ---- tester additions -------------------------------------------------------

/// Spec D4: `origin` is the bridge's to supply from where the script came from.
/// A script that declares one — claiming to be `native` or `bundled` — is
/// refused on that key at load, and nothing from it is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_declaring_origin_is_refused_on_that_key() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    for claimed in [r#""native""#, r#"#{ kind: "bundled", path: "x" }"#] {
        let Err(err) = run_load(
            &loader,
            &checks,
            "liar.rhai",
            &check_script(&meta_src(&format!(", origin: {claimed}")), r#""nothing""#),
        ) else {
            panic!("a script declaring origin {claimed} must not load");
        };
        match &err {
            ScriptError::CheckMeta {
                key, check, script, ..
            } => {
                assert_eq!(key, "origin", "{err}");
                assert_eq!(check.as_deref(), Some("demo-check"), "{err}");
                assert_eq!(script, "liar.rhai", "{err}");
            }
            other => panic!("expected a CheckMeta error, got {other:?}"),
        }
        assert!(err.to_string().contains("origin"), "{err}");
        assert!(checks.is_empty(), "a refused script registers nothing");
    }
}

/// Spec D4 "a load error naming the key": a key that is not `CheckMeta`'s is
/// refused by name with the legal keys listed, and a legal key holding a token
/// outside its vocabulary is refused on *that* key, not on the map as a whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_invalid_meta_keys_are_refused_by_name() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());

    let Err(err) = run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(&meta_src(r#", colour: "red""#), r#""nothing""#),
    ) else {
        panic!("an unknown meta key must not load");
    };
    match &err {
        ScriptError::CheckMeta { key, message, .. } => {
            assert_eq!(key, "colour");
            assert!(
                message.contains("kinds"),
                "the legal keys are listed: {message}"
            );
            assert!(message.contains("remediation"), "{message}");
        }
        other => panic!("expected a CheckMeta error, got {other:?}"),
    }
    assert!(checks.is_empty());

    for (replace, with, key) in [
        (r#"kinds: ["query"]"#, r#"kinds: ["telepathy"]"#, "kinds"),
        (
            r#"lanes: ["http"]"#,
            r#"lanes: ["carrier-pigeon"]"#,
            "lanes",
        ),
        (r#"severity: "low""#, r#"severity: "scary""#, "severity"),
        (r#"intensity: "light""#, r#"intensity: 3"#, "intensity"),
        (r#"id: "demo-check""#, r#"id: 42"#, "id"),
        (r#"name: "Demo""#, r#"name: ()"#, "name"),
    ] {
        let Err(err) = run_load(
            &loader,
            &checks,
            "<source>",
            &check_script(&meta_src("").replace(replace, with), r#""nothing""#),
        ) else {
            panic!("`{with}` must not load");
        };
        match &err {
            ScriptError::CheckMeta { key: got, .. } => assert_eq!(got, key, "`{with}`: {err}"),
            other => panic!("expected a CheckMeta error for `{with}`, got {other:?}"),
        }
        assert!(checks.is_empty(), "`{with}` registered something");
    }

    // The optional keys are accepted and land on the meta (T3 live-run bug:
    // `remediation` was once refused).
    run_load(
        &loader,
        &checks,
        "<source>",
        &check_script(
            &meta_src(
                r#", remediation: "fix it", cwe: 79, wants_traits: ["url"],
                   needs_baseline: true, targets_session: true"#,
            ),
            r#""nothing""#,
        ),
    )
    .expect("every optional key is legal");
    let meta = checks.snapshot()[0].meta().clone();
    assert_eq!(meta.remediation.as_deref(), Some("fix it"));
    assert_eq!(meta.cwe, Some(79));
    assert_eq!(
        meta.wants_traits,
        Some(vec![aitm_scan_model::vocab::PointTrait::Url])
    );
    assert!(meta.needs_baseline);
    assert!(meta.targets_session);
}

/// The hint speaks the PoC vocabulary in full: `not`, `any` and `regex` parse,
/// and a `control` becomes a `ControlHint` with its own assertion list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_hint_accepts_not_any_regex_and_a_control() {
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "vulnerable", confidence: "firm", detail: "d",
             poc_hint: #{
                 matchers: [ #{ not: #{ type: "status", status: 500 } },
                             #{ any: [ #{ type: "word", word: "AITM" },
                                       #{ type: "regex", regex: "A.TM", part: "header" } ] } ],
                 control: #{ payload: "benign",
                             matchers: [ #{ type: "status", status: 200 } ] } } }"#,
        200,
        "body",
    )
    .await;

    assert_eq!(verdict.outcome, Outcome::Vulnerable);
    assert_eq!(
        verdict.poc_hint,
        Some(PocHint {
            assertions: vec![Assertion::All(vec![
                Assertion::Not(Box::new(Assertion::Status(500))),
                Assertion::Any(vec![
                    Assertion::Word {
                        word: "AITM".to_string(),
                        part: MatchPart::Body,
                    },
                    Assertion::Regex {
                        regex: "A.TM".to_string(),
                        part: MatchPart::Header,
                    },
                ]),
            ])],
            control: Some(aitm_scan_model::check::ControlHint {
                payload: "benign".to_string(),
                expect: vec![Assertion::All(vec![Assertion::Status(200)])],
            }),
        })
    );
}

/// A hint the PoC vocabulary cannot read is an `error` verdict naming
/// `poc_hint` — never a vulnerable verdict with a hint that would later fail
/// to reproduce, and never a silent drop of the hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_poc_hint_is_an_error_verdict() {
    for hint in [
        r#"#{ matchers: "nope" }"#,
        r#"#{ matchers: [ #{ type: "telepathy" } ] }"#,
        r#"#{ }"#,
        r#"#{ matchers: [ #{ type: "status", status: 200 } ], control: #{ matchers: [] } }"#,
        r#""just a string""#,
    ] {
        let (verdict, _host) = verdict_of(
            &format!(r#"#{{ outcome: "vulnerable", detail: "d", poc_hint: {hint} }}"#),
            200,
            "body",
        )
        .await;
        assert_eq!(
            verdict.outcome,
            Outcome::Error,
            "{hint}: {:?}",
            verdict.detail
        );
        assert!(
            verdict.detail.contains("poc_hint"),
            "{hint}: the detail names the field: {:?}",
            verdict.detail
        );
        assert_eq!(verdict.poc_hint, None, "{hint}");
    }

    // An unknown verdict key is refused the same way (spec D4: no silent no-op).
    let (verdict, _host) = verdict_of(
        r#"#{ outcome: "vulnerable", severity: "high" }"#,
        200,
        "body",
    )
    .await;
    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(verdict.detail.contains("severity"), "{:?}", verdict.detail);

    // And an unknown confidence token.
    let (verdict, _host) =
        verdict_of(r#"#{ outcome: "clean", confidence: "sure" }"#, 200, "body").await;
    assert_eq!(verdict.outcome, Outcome::Error);
    assert!(verdict.detail.contains("sure"), "{:?}", verdict.detail);
}

/// `timing_fit`'s three gates, each alone: fewer than two distinct delays is
/// never a correlation; a slope far from one is not; and observations that do
/// not grow with the requested delay are not, however high `r` is. Empty and
/// mismatched inputs are handled, not panicked on.
#[test]
fn timing_fit_edges_and_levenshtein_bounds() {
    let one_delay = timing_fit(&[2.0, 2.0, 2.0], &[2000, 2100, 1900]);
    assert!(!one_delay.correlated, "{one_delay:?}");
    assert_eq!(one_delay.r, 0.0);

    let empty = timing_fit(&[], &[]);
    assert!(!empty.correlated, "{empty:?}");
    let short = timing_fit(&[1.0, 3.0, 1.0], &[1000]);
    assert!(
        !short.correlated,
        "mismatched lengths take the shorter: {short:?}"
    );

    // Perfectly linear, r == 1, but twice as slow as requested: the slope gate.
    let doubled = timing_fit(&[1.0, 3.0, 1.0, 3.0], &[2000, 6000, 2000, 6000]);
    assert!(doubled.r > 0.99, "{doubled:?}");
    assert!((doubled.slope - 2.0).abs() < 0.05, "{doubled:?}");
    assert!(!doubled.correlated, "{doubled:?}");

    // The target got slower while the probes ran: a short delay observed late
    // outlasted a long delay observed early (ZAP's alternating rule).
    let drifting = timing_fit(&[1.0, 3.0, 1.0, 3.0], &[1000, 3000, 3200, 3100]);
    assert!(!drifting.correlated, "{drifting:?}");

    // Two points are enough when they agree.
    let two = timing_fit(&[1.0, 3.0], &[1000, 3000]);
    assert!(two.correlated, "{two:?}");

    assert_eq!(levenshtein_ratio("abc", ""), 0.0);
    assert_eq!(levenshtein_ratio("same", "same"), 1.0);
    assert!((levenshtein_ratio("héllo", "hello") - 0.8).abs() < 1e-6);
    let long = "a".repeat(4_000);
    assert_eq!(levenshtein_ratio(&long, &long), 1.0);
}

/// `probe.*` is refused outside a check for every verb that reaches the host,
/// not only `marker`, and the refusal points the author at `http.send`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_probe_verb_is_refused_outside_a_check() {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    let registry = run_load(
        &loader,
        &checks,
        "<source>",
        r#"fn load(reg) {
               reg.add_command("demo.send", "", |args| probe.send("x"));
               reg.add_command("demo.baseline", "", |args| probe.baseline());
               reg.add_command("demo.raw", "", |args| probe.raw(#{ method: "GET", url: "http://ex.test/" }));
               reg.add_command("demo.budget", "", |args| probe.budget_left());
           }"#,
    )
    .expect("the script loads");

    let store = MemFlowStore::new();
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &client, &guard, None);
    for name in ["demo.send", "demo.baseline", "demo.raw", "demo.budget"] {
        let err = registry
            .command(name)
            .expect("the command is registered")
            .invoke(Params::default(), &host)
            .expect_err("probe.* outside a check must be refused");
        assert!(
            err.to_string().contains("only available inside a check"),
            "{name}: {err}"
        );
        assert!(err.to_string().contains("http.send"), "{name}: {err}");
    }
}

/// `probe.send` with an empty payload and a payload map missing `value` are
/// handled explicitly: the empty string is a legal (if odd) payload the host
/// sees, and a map without `value` is refused by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_send_empty_payload_and_missing_value() {
    let (verdict, host) = verdict_of(
        r#"{ let r = probe.send(""); if r.status == 200 { "sent" } else { "no" } }"#,
        200,
        "body",
    )
    .await;
    assert_eq!(verdict.detail, "sent");
    assert_eq!(host.payloads(), vec![String::new()]);

    let (verdict, host) = verdict_of(
        r#"{ let out = "no error";
             try { probe.send(#{ mode: "suffix" }); } catch (e) { out = "" + e; }
             out }"#,
        200,
        "body",
    )
    .await;
    assert!(
        verdict.detail.contains("value"),
        "a map without `value` is refused by name: {:?}",
        verdict.detail
    );
    assert!(host.payloads().is_empty(), "nothing was sent");

    let (verdict, host) = verdict_of(
        r#"{ let out = "no error";
             try { probe.send(#{ value: "x", colour: "red" }); } catch (e) { out = "" + e; }
             out }"#,
        200,
        "body",
    )
    .await;
    assert!(verdict.detail.contains("colour"), "{:?}", verdict.detail);
    assert!(host.payloads().is_empty(), "nothing was sent");
}
