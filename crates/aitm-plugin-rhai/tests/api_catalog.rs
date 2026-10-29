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

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;

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
