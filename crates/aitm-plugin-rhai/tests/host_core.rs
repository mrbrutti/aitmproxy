//! Task 6 — the host core: `finding(...)` records a structured observation,
//! `option(name)` is a forgiving read (option C), `log.*` routes to tracing,
//! all wired through the `ScriptCapability` seam (spec §6a).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_core::{
    CallerTrust, FlowId, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard, Value,
};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::host_core::{
    FindingCapability, FindingSink, LogCapability, MemoryFindingSink, ScriptCapability,
    ScriptServices,
};
use aitm_plugin_rhai::seed_call_context;
use aitm_poc::Severity;
use rhai::{Engine, Scope, AST};

/// A client that is never reached: the host core registers no network verb.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// Real store and guard, a stub client, no browser, an in-memory finding sink,
/// and a live multi-thread runtime (returned so its handle stays valid).
fn services() -> (
    tokio::runtime::Runtime,
    ScriptServices,
    Arc<MemoryFindingSink>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let findings = Arc::new(MemoryFindingSink::new());
    let services = ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: findings.clone(),
        rt: rt.handle().clone(),
    };
    (rt, services, findings)
}

/// A hardened engine with the two Task 6 providers registered through the seam.
fn engine_with_host_core(services: &ScriptServices) -> Engine {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    let providers: [&dyn ScriptCapability; 2] = [&LogCapability, &FindingCapability];
    for provider in providers {
        provider.register(&mut engine, services);
    }
    engine
}

/// Compile `src` as the script named `name` (what the loader does with the
/// file stem / `NAME`), so host verbs can attribute what they record.
fn compile_named(engine: &Engine, name: &str, src: &str) -> AST {
    let mut ast = engine.compile(src).expect("script compiles");
    ast.set_source(name);
    ast
}

#[test]
fn seam_names_its_namespaces() {
    assert_eq!(LogCapability.namespace(), "log");
    assert_eq!(FindingCapability.namespace(), "finding");
    assert_eq!(LogCapability.min_api(), "1");
    assert_eq!(FindingCapability.min_api(), "1");
}

#[test]
fn finding_records_fields() {
    let (_rt, services, findings) = services();
    let engine = engine_with_host_core(&services);
    let ast = compile_named(
        &engine,
        "probe",
        r#"finding(#{ name: "x", severity: "medium", tags: ["a"] })"#,
    );

    // The invocation boundary seeds the per-eval caller trust + source; here the
    // source the boundary records is the script name, which `finding` reads off
    // `HostCallCtx::call_source()`.
    let _seed = seed_call_context(CallerTrust::Operator, None, Some("probe".to_string()));
    engine.run_ast(&ast).expect("finding(...) must succeed");

    let recorded = findings.list();
    assert_eq!(recorded.len(), 1, "exactly one finding: {recorded:?}");
    let f = &recorded[0];
    assert_eq!(f.name, "x");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.tags, vec!["a".to_string()]);
    assert_eq!(f.source, "probe", "source is the script name");
    assert_eq!(f.flow, None);
    assert_eq!(f.detail, None);
}

#[test]
fn finding_parses_flow_id_and_detail() {
    let (_rt, services, findings) = services();
    let engine = engine_with_host_core(&services);
    let id = FlowId::new();
    let src =
        format!(r#"finding(#{{ name: "n", severity: "HIGH", flow_id: "{id}", detail: "d" }})"#);
    let _seed = seed_call_context(CallerTrust::Operator, None, Some("s".to_string()));
    engine
        .run_ast(&compile_named(&engine, "s", &src))
        .expect("finding with flow_id/detail must succeed");

    let recorded = findings.list();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].severity,
        Severity::High,
        "severity is case-insensitive"
    );
    assert_eq!(recorded[0].flow, Some(id));
    assert_eq!(recorded[0].detail.as_deref(), Some("d"));
    assert!(recorded[0].tags.is_empty());
}

#[test]
fn finding_rejects_malformed_input() {
    let (_rt, services, findings) = services();
    let engine = engine_with_host_core(&services);
    let _seed = seed_call_context(CallerTrust::Operator, None, Some("s".to_string()));

    // Reporting is an action, not a read: bad input is a catchable error that
    // says what to fix, and nothing is recorded.
    let err = engine
        .run_ast(&compile_named(
            &engine,
            "s",
            r#"finding(#{ name: "n", severity: "bogus" })"#,
        ))
        .expect_err("an unknown severity must be refused");
    let text = err.to_string();
    assert!(
        text.contains("bogus"),
        "error should quote the bad severity: {text}"
    );
    assert!(
        text.contains("medium"),
        "error should list the accepted values: {text}"
    );

    let err = engine
        .run_ast(&compile_named(
            &engine,
            "s",
            r#"finding(#{ severity: "low" })"#,
        ))
        .expect_err("a finding without a name must be refused");
    assert!(
        err.to_string().contains("name"),
        "error should name the field: {err}"
    );

    let err = engine
        .run_ast(&compile_named(
            &engine,
            "s",
            r#"finding(#{ name: "n", severity: "low", flow_id: "not-a-uuid" })"#,
        ))
        .expect_err("a malformed flow_id must be refused");
    assert!(
        err.to_string().contains("flow_id"),
        "error should name the field: {err}"
    );

    // A script can catch it and carry on.
    let caught: String = engine
        .eval_ast(&compile_named(
            &engine,
            "s",
            r#"let r = "sent"; try { finding(#{ name: "n" }); } catch (e) { r = "caught"; } r"#,
        ))
        .expect("try/catch must run");
    assert_eq!(caught, "caught");

    assert!(findings.list().is_empty(), "nothing malformed is recorded");
}

#[test]
fn option_reads_set_value() {
    let (_rt, services, _findings) = services();
    let engine = engine_with_host_core(&services);
    let ast = compile_named(&engine, "s", r#"fn read(name) { option(name) }"#);

    // After the seam migration the script's options ride along as the per-eval
    // *tag* the invocation boundary seeds (an `aitm_core::Value::Object`), which
    // `option(name)` reads via `HostCallCtx::tag()` — no longer the rhai
    // `CallFnOptions::with_tag` custom-type tag.
    let tag = Value::Object(BTreeMap::from([(
        "tag".to_string(),
        Value::Str("v".into()),
    )]));

    let set: String = {
        let _seed = seed_call_context(
            CallerTrust::Operator,
            Some(tag.clone()),
            Some("s".to_string()),
        );
        engine
            .call_fn(&mut Scope::new(), &ast, "read", ("tag",))
            .expect("option(set) must run")
    };
    assert_eq!(set, "v");

    // Option C: an unset option is `()`, never an error.
    let unset: rhai::Dynamic = {
        let _seed = seed_call_context(CallerTrust::Operator, Some(tag), Some("s".to_string()));
        engine
            .call_fn(&mut Scope::new(), &ast, "read", ("absent",))
            .expect("option(unset) must not error")
    };
    assert!(unset.is_unit(), "unset option should be (), got {unset:?}");

    // No options at all (a PoC step, say): still `()`.
    let none: rhai::Dynamic = {
        let _seed = seed_call_context(CallerTrust::Operator, None, Some("s".to_string()));
        engine
            .call_fn(&mut Scope::new(), &ast, "read", ("tag",))
            .expect("option() without options must not error")
    };
    assert!(
        none.is_unit(),
        "option without a tag should be (), got {none:?}"
    );
}

// ===========================================================================
// Task 5 (AC7) — `option`/`finding` migrated onto the host-fn seam: each is a
// `Guarded<HostFn>` reading the per-invocation `HostCallCtx` (the tag for
// `option`, the call source for `finding`) instead of the rhai
// `NativeCallContext` — kept GLOBAL so the call syntax `option(...)` /
// `finding(...)` is unchanged. These prove they read the SEED (what the
// boundary now threads), are fail-closed when unseeded, and are registered once.
// ===========================================================================

/// AC7: `option(name)` reads the tag off `HostCallCtx::tag()` — the value the
/// invocation boundary seeds — and no longer the rhai `with_tag` custom type. The
/// tag here is seeded *only* through `seed_call_context` (no `with_tag`), so this
/// passes only once `option` reads the seam context.
#[test]
fn option_reads_the_tag_from_the_seam_context() {
    let (_rt, services, _findings) = services();
    let engine = engine_with_host_core(&services);
    let ast = compile_named(&engine, "s", r#"fn read(name) { option(name) }"#);

    let tag = Value::Object(BTreeMap::from([(
        "greeting".to_string(),
        Value::Str("hello".into()),
    )]));
    let _seed = seed_call_context(CallerTrust::Operator, Some(tag), Some("s".to_string()));
    let got: String = engine
        .call_fn(&mut Scope::new(), &ast, "read", ("greeting",))
        .expect("option reads the seeded tag");
    assert_eq!(got, "hello", "option(name) must read HostCallCtx::tag()");
}

/// AC7: `finding(...)` records `HostCallCtx::call_source()` — the source the
/// boundary seeds — not the rhai `NativeCallContext` AST source. The AST source
/// is deliberately different from the seeded source, so the old
/// `NativeCallContext::call_source()` reading would record `"ast-name"` and only
/// the migrated seam reading records `"seed-source"`.
#[test]
fn finding_reads_the_call_source_from_the_seam_context() {
    let (_rt, services, findings) = services();
    let engine = engine_with_host_core(&services);
    let ast = compile_named(
        &engine,
        "ast-name",
        r#"finding(#{ name: "x", severity: "low" })"#,
    );

    let _seed = seed_call_context(CallerTrust::Operator, None, Some("seed-source".to_string()));
    engine.run_ast(&ast).expect("finding records");

    let recorded = findings.list();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].source, "seed-source",
        "finding must record HostCallCtx::call_source(), not the AST source"
    );
}

/// AC3 (fail-closed) for the migrated verbs: reached with **no** seeded caller
/// context, both `option` and `finding` are refused with the seam's "no caller
/// context" error — never silently run as the pre-seam global fns did (which read
/// the `NativeCallContext` and ran unseeded). This is the proof the old in-crate
/// `NativeCallContext` registration is gone.
#[test]
fn option_and_finding_fail_closed_when_unseeded() {
    let (_rt, services, findings) = services();
    let engine = engine_with_host_core(&services);

    let err = engine
        .eval::<rhai::Dynamic>(r#"option("x")"#)
        .expect_err("an unseeded option(...) must be refused");
    assert!(
        err.to_string().contains("no caller context"),
        "option must fail closed, got: {err}"
    );

    let err = engine
        .eval::<()>(r#"finding(#{ name: "n", severity: "low" })"#)
        .expect_err("an unseeded finding(...) must be refused");
    assert!(
        err.to_string().contains("no caller context"),
        "finding must fail closed, got: {err}"
    );
    assert!(
        findings.list().is_empty(),
        "fail-closed must refuse before the finding sink is touched"
    );
}

/// AC7: `option` and `finding` are each registered exactly once (the migration
/// deletes the old in-crate registration — never double-registered).
#[test]
fn option_and_finding_are_registered_once() {
    let (_rt, services, _findings) = services();
    let engine = engine_with_host_core(&services);
    let sigs = engine.gen_fn_signatures(false);
    let count = |name: &str| {
        sigs.iter()
            .filter(|s| s.starts_with(&format!("{name}(")))
            .count()
    };
    assert_eq!(
        count("option"),
        1,
        "exactly one `option` overload: {sigs:?}"
    );
    assert_eq!(
        count("finding"),
        1,
        "exactly one `finding` overload: {sigs:?}"
    );
}

/// A `tracing` subscriber that keeps every event's level and message.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<(tracing::Level, String)>>>);

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut events) = self.0.lock() {
            events.push((*event.metadata().level(), visitor.0));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn log_routes_to_tracing() {
    let (_rt, services, _findings) = services();
    let engine = engine_with_host_core(&services);
    let ast = compile_named(
        &engine,
        "s",
        r#"log.warn("hi"); log.info("fyi"); log.error("bad"); log("plain");"#,
    );

    let capture = Capture::default();
    let outcome = tracing::subscriber::with_default(capture.clone(), || engine.run_ast(&ast));
    outcome.expect("log.* must run without error");

    let events = capture.0.lock().expect("capture lock");
    let has =
        |level: tracing::Level, msg: &str| events.iter().any(|(l, m)| *l == level && m == msg);
    assert!(
        has(tracing::Level::WARN, "hi"),
        "missing WARN hi in {events:?}"
    );
    assert!(
        has(tracing::Level::INFO, "fyi"),
        "missing INFO fyi in {events:?}"
    );
    assert!(
        has(tracing::Level::ERROR, "bad"),
        "missing ERROR bad in {events:?}"
    );
    assert!(
        has(tracing::Level::INFO, "plain"),
        "missing INFO plain in {events:?}"
    );
}
