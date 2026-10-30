//! Task 7 (UI-spec AC5 / AC10) — the `rhai.api.json` ↔ engine drift guard.
//!
//! `docs/design/languages/rhai.api.json` is the catalog the three operator UIs
//! generate Rhai completion and hover from. This test pins it to the surface the
//! shipped engine actually registers: it builds the real `RhaiLoader` engine the
//! way production does, enumerates every registered host token with
//! `gen_fn_signatures(false)` (which already drops the standard packages), and
//! asserts a **bijection** with the catalog's *implemented* entries.
//!
//! A catalog entry naming a member the engine does not register, a registered
//! author-facing token missing from the catalog, or a renamed member all make
//! this fail. Entries marked `"status": "planned"` (the `dsl` crypto/encoding
//! helpers, specced but not yet implemented on the engine) are a separate bucket
//! excluded from the bijection; when they land they move out of `planned` and
//! this guard then requires the matching engine token.
//!
//! The comparison is factored into [`diff`] so the companion self-test can feed
//! it a deliberately mutated catalog set and prove the guard bites (AC10).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard, Value};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallCtx, HostError, HostFn, HostFnSig, NamespaceCatalog,
    NamespaceEntry, PocStepHandler, PocStepInputs, PocStepOutcome, PocStepSchema, ProtocolLanguage,
    RegisterError, ScriptHostRegistry,
};
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_plugin_rhai::{
    assemble_namespaces, assemble_poc_steps, poc_face_drift, production_languages,
    registered_host_fns, vocabulary_consistent, AssembleError, PocFaceDrift,
};
use aitm_proto_test::TestLanguage;

/// A token in the common space both sides reduce to: `(receiver_type, member)`.
/// The receiver is the engine's registered type name (`"Flow"`, `"Headers"`,
/// `"browser"`, …) or `""` for a free/global function. Rhai registers one
/// function per `(type, member)` regardless of how many catalog paths reach it
/// (e.g. `flow.request.headers.get` and `flow.response.headers.get` are both the
/// single `get(&mut Headers, …)`), so the common space is `(type, member)`, not
/// the dotted path — the collapse is exactly why this is a set equality.
type Token = (String, String);

// --- the real engine, built as production builds it -------------------------

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

// --- engine side ------------------------------------------------------------

/// Engine tokens that `gen_fn_signatures(false)` still emits but are *not* part
/// of the author-facing host API, so they get no catalog entry. Kept as small
/// and as justified as possible — everything else `false` already dropped.
const EXCLUDED: &[(&str, &str)] = &[
    // The standard `sleep` shadowed with a refusal (engine.rs `no_ambient_authority`):
    // a hardening shim, not an offered API. Two overloads (i64/f64) reduce to one token.
    ("", "sleep"),
    // The `headers[k]` / `headers[k] = v` indexer sugar: the `[]` operator, not a
    // named member an author completes — aliased to `.get` / `.set`, which are
    // catalogued.
    ("Headers", "index$get$"),
    ("Headers", "index$set$"),
    // Generic value conversions every Rhai type gets so `print`/`to_string` work;
    // not a Denied-specific API member (its real surface is capability/host/reason).
    ("Denied", "to_string"),
    ("Denied", "to_debug"),
];

/// Reduce one `gen_fn_signatures` line to its `(receiver_type, member)` token.
fn parse_signature(sig: &str) -> Token {
    let open = sig.find('(').expect("a signature has a parameter list");
    let close = open + sig[open..].find(')').expect("a signature closes its list");
    let name = sig[..open].trim();

    // Rhai spells property access `get$<name>` / `set$<name>`; a method or free
    // function is just its name. The `index$get$` / `index$set$` operators keep
    // their full token (they are excluded by name).
    let member = name
        .strip_prefix("get$")
        .or_else(|| name.strip_prefix("set$"))
        .unwrap_or(name)
        .to_string();

    // The receiver is the first parameter's type when it is `&mut T`; a free
    // function has no `&mut` receiver.
    let params = &sig[open + 1..close];
    let receiver = params
        .split(',')
        .next()
        .and_then(|p| p.split("&mut ").nth(1))
        .map(|t| t.split_whitespace().next().unwrap_or("").to_string())
        .unwrap_or_default();

    (receiver, member)
}

fn engine_tokens() -> BTreeSet<Token> {
    let loader = RhaiLoader::new(RhaiConfig::default(), services()).expect("the loader builds");
    let engine = loader.engine();
    let excluded: BTreeSet<Token> = EXCLUDED
        .iter()
        .map(|(r, m)| (r.to_string(), m.to_string()))
        .collect();
    engine
        .gen_fn_signatures(false)
        .iter()
        .map(|sig| parse_signature(sig))
        .filter(|tok| !excluded.contains(tok))
        .collect()
}

// --- catalog side -----------------------------------------------------------

/// Map a catalog entry's receiver path (everything before the last segment) to
/// the engine type name that path's members are registered on. This is the one
/// piece of structural knowledge bridging a path-keyed catalog and a type-keyed
/// engine; an unmapped path is a loud failure, never a silent skip.
fn receiver_type(prefix: &str) -> String {
    let ty = match prefix {
        "" => "",
        "flow" => "Flow",
        "flow.request" => "Request",
        "flow.response" => "Response",
        "flow.request.headers" | "flow.response.headers" => "Headers",
        "msg" => "WsMessage",
        "log" => "log",
        "http" => "http",
        "browser" => "browser",
        "store" => "store",
        "scope" => "scope",
        "reg" => "reg",
        "vars" => "Vars",
        "denied" => "Denied",
        other => panic!("catalog path prefix {other:?} has no known engine type; map it"),
    };
    ty.to_string()
}

fn catalog_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/languages/rhai.api.json")
}

fn poc_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/design/languages/poc-yaml.schema.json")
}

/// The catalog's *implemented* tokens. Sections other than `hooks` (hooks are
/// author-defined functions, not host callables) are walked; entries marked
/// `"status": "planned"` are the separate not-yet-built bucket and excluded.
fn catalog_tokens() -> BTreeSet<Token> {
    // JSON is a subset of YAML, so the already-present `serde_yaml` dev-dep parses
    // the catalog without adding a `serde_json` dependency.
    let text = std::fs::read_to_string(catalog_path()).expect("the catalog file is readable");
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the catalog is valid JSON");
    let map = doc.as_mapping().expect("the catalog is an object");

    let mut out = BTreeSet::new();
    for (key, section) in map {
        let key = key.as_str().unwrap_or_default();
        if key == "hooks" || key.starts_with('_') || !section.is_sequence() {
            continue;
        }
        for entry in section.as_sequence().expect("a section is an array") {
            let entry = entry.as_mapping().expect("a catalog entry is an object");
            let status = entry
                .get(serde_yaml::Value::from("status"))
                .and_then(|v| v.as_str());
            if status == Some("planned") {
                continue;
            }
            let name = entry
                .get(serde_yaml::Value::from("name"))
                .and_then(|v| v.as_str())
                .expect("a catalog entry has a name");
            let (prefix, member) = match name.rsplit_once('.') {
                Some((prefix, member)) => (prefix, member),
                None => ("", name),
            };
            out.insert((receiver_type(prefix), member.to_string()));
        }
    }
    out
}

// --- the comparison, shared by the guard and the self-test ------------------

/// `(in catalog but not the engine, in the engine but not the catalog)`.
/// Both empty means the surfaces are in exact correspondence.
fn diff(catalog: &BTreeSet<Token>, engine: &BTreeSet<Token>) -> (Vec<Token>, Vec<Token>) {
    let stale = catalog.difference(engine).cloned().collect();
    let unlisted = engine.difference(catalog).cloned().collect();
    (stale, unlisted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_matches_engine_host_surface() {
    let engine = engine_tokens();
    let catalog = catalog_tokens();
    let (stale, unlisted) = diff(&catalog, &engine);
    assert!(
        stale.is_empty() && unlisted.is_empty(),
        "rhai.api.json drifted from the engine host surface.\n  \
         in the catalog, not registered (stale/renamed entry): {stale:?}\n  \
         registered, not in the catalog (uncatalogued host fn): {unlisted:?}"
    );
}

/// AC10 — the guard bites. The same [`diff`] the real test trusts must reject a
/// catalog that gained a member the engine lacks, and one that lost a member the
/// engine has. If this logic could not tell, the real test would be worthless.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diff_rejects_a_mutated_catalog() {
    let engine = engine_tokens();
    let catalog = catalog_tokens();
    assert_eq!(
        diff(&catalog, &engine),
        (Vec::new(), Vec::new()),
        "the real catalog must match before we test the mutations"
    );

    // A bogus implemented entry the engine does not register: stale, must fail.
    let mut with_bogus = catalog.clone();
    with_bogus.insert(("Flow".to_string(), "does_not_exist".to_string()));
    let (stale, _) = diff(&with_bogus, &engine);
    assert!(
        stale.contains(&("Flow".to_string(), "does_not_exist".to_string())),
        "a catalog entry the engine lacks must be reported stale"
    );

    // A real entry removed from the catalog: the engine token is now unlisted.
    let mut without_real = catalog.clone();
    let real = ("Flow".to_string(), "id".to_string());
    assert!(
        without_real.remove(&real),
        "flow.id is a real catalog token"
    );
    let (_, unlisted) = diff(&without_real, &engine);
    assert!(
        unlisted.contains(&real),
        "a registered host token dropped from the catalog must be reported unlisted"
    );
}

// ===========================================================================
// Task 4 (spec AC6 / AC7 / AC8, Review Focus) — the SEAM drift guard.
//
// F8's `catalog_matches_engine_host_surface` above pins the built-in host
// surface via `gen_fn_signatures`, reducing to `(receiver_type, member)`. That
// bijection CANNOT cover seam namespaces: every `<ns>.*` host fn registers on
// one shared `ProtoNamespace` rhai type with runtime `(namespace, method)`
// dispatch, so the engine only shows `("ProtoNamespace","ping")` and cannot
// tell `test.ping` from another namespace's `ping`.
//
// So the seam guard compares a DIFFERENT pair of sets: the `HostRegistry`'s
// explicitly-registered `(namespace, name)` set (`registered_host_fns`, read
// back from the real production registry's store) against the assembled
// `namespaces` map's `(namespace, fn.name)` set (`assemble_namespaces`, built
// from each language's `catalog()`). A registered namespace/fn missing from the
// catalog, or a catalogued fn the registry never registered, fails the guard.
// ===========================================================================

/// A guard that admits every call — the fakes below contribute effect-free host
/// fns, so there is no effect to gate.
struct AllowGuard;

impl GuardHandle for AllowGuard {
    fn guard_name(&self) -> &str {
        "fake"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

/// A minimal in-test `ProtocolLanguage` whose namespace, fns, optional PoC step
/// schema and optional runnable handler are supplied directly, so a test can
/// drive the assembler and both seam guards without depending on a real protocol
/// crate. `has_handler` toggles whether `poc_step()` returns a handler, separate
/// from whether `step` catalogs one — so a test can forge each side of the
/// PoC-face bijection independently.
struct FakeLang {
    ns: String,
    api: String,
    fns: Vec<String>,
    step: Option<PocStepSchema>,
    has_handler: bool,
    sources: Vec<String>,
}

impl FakeLang {
    fn simple(ns: &str, fns: &[&str]) -> Self {
        Self {
            ns: ns.to_string(),
            api: "1".to_string(),
            fns: fns.iter().map(|s| s.to_string()).collect(),
            step: None,
            has_handler: false,
            sources: Vec::new(),
        }
    }
}

/// A do-nothing `<ns>:` PoC step handler, so a `FakeLang` can report a runnable
/// step the PoC-face guard can see.
struct FakePocStep(String);

impl PocStepHandler for FakePocStep {
    fn ns(&self) -> &str {
        &self.0
    }

    fn run(
        &self,
        _body: &serde_yaml::Value,
        _inputs: &PocStepInputs,
    ) -> Result<PocStepOutcome, HostError> {
        Ok(PocStepOutcome::default())
    }
}

impl ProtocolLanguage for FakeLang {
    fn namespace(&self) -> &str {
        &self.ns
    }

    fn api_version(&self) -> &str {
        &self.api
    }

    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError> {
        for name in &self.fns {
            let f: HostFn = Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Null));
            reg.register(&self.ns, name, Guarded::new(Box::new(AllowGuard), f))?;
        }
        Ok(())
    }

    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>> {
        if self.has_handler {
            Some(Box::new(FakePocStep(self.ns.clone())))
        } else {
            None
        }
    }

    fn catalog(&self) -> NamespaceCatalog {
        NamespaceCatalog {
            namespace: self.ns.clone(),
            api_version: self.api.clone(),
            host_fns: self
                .fns
                .iter()
                .map(|n| HostFnSig {
                    name: n.clone(),
                    params: Vec::new(),
                    returns: "null".to_string(),
                    description: format!("fake `{}.{}`", self.ns, n),
                })
                .collect(),
            poc_step: self.step.clone(),
            sources: self.sources.clone(),
        }
    }
}

/// A seam token: `(namespace, fn_name)`. Unlike F8's `Token` (an engine
/// `(receiver_type, member)`), the seam keys on the namespace the registry
/// explicitly registered under.
type NsPair = (String, String);

/// The `(namespace, fn.name)` set an assembled `namespaces` map advertises.
fn pairs_from_doc(doc: &BTreeMap<String, NamespaceEntry>) -> BTreeSet<NsPair> {
    doc.iter()
        .flat_map(|(ns, entry)| entry.fns.iter().map(move |f| (ns.clone(), f.name.clone())))
        .collect()
}

/// `(registered but not catalogued, catalogued but not registered)`. Both empty
/// means the seam registry and the assembled catalog are in exact correspondence
/// — the seam analogue of F8's `diff`.
fn seam_diff(
    registered: &BTreeSet<NsPair>,
    catalog: &BTreeSet<NsPair>,
) -> (Vec<NsPair>, Vec<NsPair>) {
    (
        registered.difference(catalog).cloned().collect(),
        catalog.difference(registered).cloned().collect(),
    )
}

/// AC6 — registering the test namespace adds its fns to the assembled defs as
/// data, with no hand-editing of a file.
#[test]
fn assembled_namespaces_include_the_test_namespace() {
    let test = TestLanguage::new();
    let doc = assemble_namespaces(&[&test]).expect("the test namespace assembles");
    let entry = doc.get("test").expect("the `test` namespace is present");
    assert_eq!(entry.api_version, "0.1.0");
    let names: Vec<&str> = entry.fns.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["ping", "effect"]);
}

/// AC7 — the registry's explicitly-registered `(ns, name)` set is exactly the
/// assembled catalog's `(ns, fn.name)` set. This is the seam bijection, read
/// from the real `HostRegistry` store, not from `gen_fn_signatures`.
#[test]
fn seam_registry_matches_assembled_catalog() {
    let test = TestLanguage::new();
    let registered = registered_host_fns(&[&test]).expect("the test language registers");
    let doc = assemble_namespaces(&[&test]).expect("the test namespace assembles");
    let catalog = pairs_from_doc(&doc);

    assert_eq!(
        seam_diff(&registered, &catalog),
        (Vec::new(), Vec::new()),
        "the registry and the assembled catalog must correspond exactly"
    );
    assert!(registered.contains(&("test".to_string(), "ping".to_string())));
    assert!(registered.contains(&("test".to_string(), "effect".to_string())));
}

/// AC7 self-test — the seam guard bites. The same `seam_diff` the real guard
/// trusts must reject a catalog that dropped a registered fn and one that gained
/// a fn the registry never registered. Mirrors F8's `diff_rejects_a_mutated_catalog`.
#[test]
fn seam_diff_rejects_a_mutated_catalog() {
    let test = TestLanguage::new();
    let registered = registered_host_fns(&[&test]).expect("register");
    let doc = assemble_namespaces(&[&test]).expect("assemble");
    let catalog = pairs_from_doc(&doc);
    assert_eq!(
        seam_diff(&registered, &catalog),
        (Vec::new(), Vec::new()),
        "the real seam surfaces must match before we test the mutations"
    );

    // A registered fn dropped from the catalog: registered-but-uncatalogued.
    let mut without_effect = catalog.clone();
    assert!(without_effect.remove(&("test".to_string(), "effect".to_string())));
    let (registered_not_catalogued, _) = seam_diff(&registered, &without_effect);
    assert!(
        registered_not_catalogued.contains(&("test".to_string(), "effect".to_string())),
        "a registered namespace fn missing from the catalog must fail the guard"
    );

    // A catalog fn the registry never registered: catalogued-but-unregistered.
    let mut with_ghost = catalog.clone();
    with_ghost.insert(("test".to_string(), "ghost".to_string()));
    let (_, catalogued_not_registered) = seam_diff(&registered, &with_ghost);
    assert!(
        catalogued_not_registered.contains(&("test".to_string(), "ghost".to_string())),
        "a catalogued fn the registry never registered must fail the guard"
    );
}

// ===========================================================================
// PoC-face seam guard — the analogue of the host-fn bijection above, on the
// `<ns>:` PoC step. The host-fn guard pins the registry's `(ns, name)` set to
// the catalog but is blind to the PoC step: a `ProtocolLanguage` whose
// `poc_step().is_some()` can ship a runnable `<ns>:` step that never appears in
// `catalog().poc_step` (and so never in `poc-yaml.schema.json` / operator PoC
// completion) — undetected. This guard pins that face: a runnable step must be
// catalogued and a catalogued step must be runnable.
// ===========================================================================

/// The PoC-face bijection holds for every registered language: the test
/// namespace catalogs its runnable `test:` step, and `production_languages()`
/// (empty here) is trivially in correspondence.
#[test]
fn poc_face_registry_matches_catalog() {
    let test = TestLanguage::new();
    assert_eq!(
        poc_face_drift(&[&test]),
        Vec::new(),
        "the test namespace's runnable `test:` step must be catalogued"
    );

    let langs = production_languages();
    let refs: Vec<&dyn ProtocolLanguage> = langs.iter().map(|b| b.as_ref()).collect();
    assert_eq!(
        poc_face_drift(&refs),
        Vec::new(),
        "every shipped namespace's runnable PoC step must be catalogued"
    );
}

/// PoC-face self-test — the guard bites, both ways. A language whose `poc_step()`
/// returns a handler but whose `catalog().poc_step` is `None` is exactly the
/// pre-fix `TestLanguage` bug (a runnable step that silently lags the catalog);
/// the reverse — a catalogued step with no handler — is the mirror drift. The
/// same `poc_face_drift` the real guard trusts must report each. Mirrors the
/// host-fn `seam_diff_rejects_a_mutated_catalog`.
#[test]
fn poc_face_drift_rejects_a_drifted_poc_step() {
    // Runnable but uncatalogued (the pre-fix TestLanguage shape): must bite.
    let runnable_uncatalogued = FakeLang {
        has_handler: true,
        step: None,
        ..FakeLang::simple("ghoststep", &["a"])
    };
    assert_eq!(
        poc_face_drift(&[&runnable_uncatalogued]),
        vec![PocFaceDrift::RunnableButUncatalogued(
            "ghoststep".to_string()
        )],
        "a runnable PoC step missing from the catalog must fail the guard"
    );

    // Catalogued but not runnable: the other direction must bite too.
    let catalogued_not_runnable = FakeLang {
        has_handler: false,
        step: Some(PocStepSchema {
            step: "phantom".to_string(),
            description: "a catalogued step with no handler".to_string(),
            enums: BTreeMap::new(),
            sources: Vec::new(),
        }),
        ..FakeLang::simple("phantom", &["a"])
    };
    assert_eq!(
        poc_face_drift(&[&catalogued_not_runnable]),
        vec![PocFaceDrift::CataloguedButNotRunnable(
            "phantom".to_string()
        )],
        "a catalogued PoC step with no handler must fail the guard"
    );
}

/// Golden — the shipped `rhai.api.json` `namespaces` object equals
/// `assemble_namespaces(production_languages())`. Task 6 adds `l4`, so the `l4`
/// namespace is present and its assembly must match the shipped file byte-for-byte
/// (regenerated when the catalog changes).
#[test]
fn shipped_namespaces_equal_production_assembly() {
    let langs = production_languages();
    let refs: Vec<&dyn ProtocolLanguage> = langs.iter().map(|b| b.as_ref()).collect();
    let doc = assemble_namespaces(&refs).expect("production assembles");
    assert!(
        doc.contains_key("l4"),
        "Task 6 puts the `l4` namespace into production_languages()"
    );

    let text = std::fs::read_to_string(catalog_path()).expect("the catalog is readable");
    let parsed: serde_yaml::Value = serde_yaml::from_str(&text).expect("the catalog is valid JSON");
    let namespaces = parsed
        .get("namespaces")
        .expect("rhai.api.json has a top-level `namespaces` object");
    let expected = serde_yaml::to_value(&doc).expect("the assembled doc serializes");
    assert_eq!(
        namespaces, &expected,
        "shipped `namespaces` must equal assemble_namespaces(production_languages())"
    );
}

/// Golden (PoC face) — the shipped `poc-yaml.schema.json`'s per-namespace `<ns>:`
/// step nodes equal `assemble_poc_steps(production_languages())`. Mirrors
/// `shipped_namespaces_equal_production_assembly` for the PoC face: Task 6 puts the
/// `l4:` step into production, so the shipped schema must ship it and it cannot
/// drift from l4's `poc_step` (regenerate the schema when the catalog changes).
#[test]
fn shipped_poc_steps_equal_production_assembly() {
    let langs = production_languages();
    let refs: Vec<&dyn ProtocolLanguage> = langs.iter().map(|b| b.as_ref()).collect();
    let steps = assemble_poc_steps(&refs).expect("production poc steps assemble");
    assert!(
        steps.contains_key("l4"),
        "Task 6 puts the `l4:` step into production_languages()"
    );

    let text = std::fs::read_to_string(poc_schema_path()).expect("the poc schema is readable");
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&text).expect("the poc schema is valid JSON");
    let step_keys = parsed
        .get("keys")
        .and_then(|k| k.get("steps"))
        .and_then(|s| s.get("items"))
        .and_then(|i| i.get("keys"))
        .expect("poc schema has steps[].items.keys");
    let one_of = parsed
        .get("keys")
        .and_then(|k| k.get("steps"))
        .and_then(|s| s.get("items"))
        .and_then(|i| i.get("one_of_keys"))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("poc schema has steps[].items.one_of_keys");

    for (ns, doc) in &steps {
        let shipped = step_keys
            .get(ns)
            .unwrap_or_else(|| panic!("poc schema must ship the `{ns}:` step node"));
        let expected = serde_yaml::to_value(doc).expect("the assembled step node serializes");
        assert_eq!(
            shipped, &expected,
            "shipped `{ns}:` step node must equal assemble_poc_steps(production_languages())"
        );
        assert!(
            one_of.iter().any(|v| v.as_str() == Some(ns.as_str())),
            "the `{ns}:` step must be listed in steps[].items.one_of_keys"
        );
    }
}

/// Review Focus — two namespaces with a same-named fn stay namespaced; neither
/// overwrites the other.
#[test]
fn same_named_fns_stay_namespaced() {
    let alpha = FakeLang::simple("alpha", &["ping", "scan"]);
    let beta = FakeLang::simple("beta", &["ping"]);
    let doc = assemble_namespaces(&[&alpha, &beta]).expect("two namespaces assemble");

    assert_eq!(doc.len(), 2);
    assert!(doc["alpha"].fns.iter().any(|f| f.name == "ping"));
    assert!(doc["alpha"].fns.iter().any(|f| f.name == "scan"));
    assert!(doc["beta"].fns.iter().any(|f| f.name == "ping"));

    let pairs = pairs_from_doc(&doc);
    assert!(pairs.contains(&("alpha".to_string(), "ping".to_string())));
    assert!(pairs.contains(&("beta".to_string(), "ping".to_string())));
    assert_eq!(pairs.len(), 3, "no fn is dropped or overwritten");
}

/// A duplicate namespace key (two languages claiming the same namespace) is an
/// assembly error — never last-wins (Review Focus).
#[test]
fn duplicate_namespace_is_an_error() {
    let a = FakeLang::simple("dup", &["x"]);
    let b = FakeLang::simple("dup", &["y"]);
    let err = assemble_namespaces(&[&a, &b]).expect_err("a duplicate namespace is rejected");
    assert_eq!(err, AssembleError::DuplicateNamespace("dup".to_string()));
}

/// AC8 (mechanism) — where a namespace contributes a PoC step, its `op` verb
/// vocabulary is a consistent **subset** of its host-fn names: one vocabulary
/// across the Rhai and PoC faces, with the PoC face free to expose only the verbs
/// that fit a one-shot step (e.g. l4's wire verbs). The test namespace contributes
/// no step, so the check holds vacuously; a synthetic namespace exercises the exact
/// match, a proper subset, and a divergent mismatch.
#[test]
fn one_vocabulary_across_script_and_poc() {
    // `test`'s catalogued step declares no `op` enum — vacuously consistent.
    assert!(vocabulary_consistent(&TestLanguage::new().catalog()));

    let step = |verbs: &[&str]| PocStepSchema {
        step: "demo".to_string(),
        description: "a synthetic protocol step".to_string(),
        enums: BTreeMap::from([(
            "op".to_string(),
            verbs.iter().map(|s| s.to_string()).collect(),
        )]),
        sources: vec!["packet".to_string()],
    };

    // op-enum == host-fn names: consistent.
    let good = FakeLang {
        step: Some(step(&["craft", "inject"])),
        ..FakeLang::simple("demo", &["craft", "inject"])
    };
    assert!(vocabulary_consistent(&good.catalog()));

    // op-enum is a proper subset of the host-fn names: still consistent — a one-shot
    // PoC step may offer only some of the shared vocabulary (l4 is exactly this: the
    // `op` enum is the wire subset of the nine `l4.*` host fns).
    let subset = FakeLang {
        step: Some(step(&["craft"])),
        ..FakeLang::simple("demo", &["craft", "inject", "scan"])
    };
    assert!(vocabulary_consistent(&subset.catalog()));

    // op-enum diverges from the host-fn names (a verb the host-fn set lacks):
    // inconsistent — the guard still bites.
    let bad = FakeLang {
        step: Some(step(&["craft", "WRONG"])),
        ..FakeLang::simple("demo", &["craft", "inject"])
    };
    assert!(!vocabulary_consistent(&bad.catalog()));
}

/// The PoC-step assembler turns a namespace's `catalog().poc_step` into the
/// per-`<ns>:` schema node shape (the mechanism Task 6's `l4:` step populates).
/// A namespace with no PoC step contributes nothing.
#[test]
fn assemble_poc_steps_builds_the_per_namespace_node() {
    let demo = FakeLang {
        step: Some(PocStepSchema {
            step: "demo".to_string(),
            description: "a synthetic protocol step".to_string(),
            enums: BTreeMap::from([(
                "op".to_string(),
                vec!["craft".to_string(), "inject".to_string()],
            )]),
            sources: vec!["packet".to_string()],
        }),
        ..FakeLang::simple("demo", &["craft", "inject"])
    };
    let steps = assemble_poc_steps(&[&demo]).expect("the step assembles");
    let node = steps.get("demo").expect("the `demo:` step is present");
    assert_eq!(node.node_type, "map");
    assert_eq!(node.description, "a synthetic protocol step");
    assert_eq!(
        node.keys["op"].values,
        vec!["craft".to_string(), "inject".to_string()]
    );
    assert_eq!(node.keys["op"].node_type, "enum");
    assert_eq!(node.sources, vec!["packet".to_string()]);

    // A namespace with no PoC step contributes no entry.
    let none = FakeLang::simple("quiet", &["a"]);
    assert!(assemble_poc_steps(&[&none]).expect("assembles").is_empty());
}

/// AC8 is enforced at assembly, not merely advisory: a namespace whose PoC `op`
/// vocabulary diverges from its host-fn names fails `assemble_poc_steps` (the
/// build), rather than silently shipping two drifting vocabularies. The
/// consistent sibling still assembles.
#[test]
fn assemble_poc_steps_rejects_a_divergent_vocabulary() {
    let diverge = |verbs: &[&str], fns: &[&str]| FakeLang {
        step: Some(PocStepSchema {
            step: "demo".to_string(),
            description: "a synthetic protocol step".to_string(),
            enums: BTreeMap::from([(
                "op".to_string(),
                verbs.iter().map(|s| s.to_string()).collect(),
            )]),
            sources: vec!["packet".to_string()],
        }),
        ..FakeLang::simple("demo", fns)
    };

    // op-enum diverges from host-fn names: assembly is a hard error.
    let bad = diverge(&["craft", "WRONG"], &["craft", "inject"]);
    let err = assemble_poc_steps(&[&bad]).expect_err("a divergent vocabulary is rejected");
    assert_eq!(
        err,
        AssembleError::VocabularyInconsistent("demo".to_string())
    );

    // op-enum == host-fn names: assembly succeeds.
    let good = diverge(&["craft", "inject"], &["craft", "inject"]);
    assert!(assemble_poc_steps(&[&good])
        .expect("a consistent vocabulary assembles")
        .contains_key("demo"));
}
