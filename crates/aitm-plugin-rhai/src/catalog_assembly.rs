//! Task 4 — assemble each registered protocol's [`NamespaceCatalog`] into the
//! two shared operator-UI definition shapes and define the canonical set of
//! namespaces that ship.
//!
//! The three operator UIs generate Rhai completion from `rhai.api.json` and PoC
//! completion from `poc-yaml.schema.json`. A protocol contributes to both by
//! returning a [`NamespaceCatalog`] (plan Task 1); this module concatenates
//! those catalogs:
//!
//! - [`assemble_namespaces`] → `rhai.api.json`'s top-level `namespaces` map,
//!   keyed by namespace, each `{ api_version, fns }`. Two namespaces with a
//!   same-named fn stay separate (Review Focus); a duplicate namespace key is an
//!   error.
//! - [`assemble_poc_steps`] → the per-`<ns>:` step nodes of
//!   `poc-yaml.schema.json`, built from each namespace's `catalog().poc_step`.
//!
//! [`production_languages`] is the canonical set that SHIPS to operators. It is
//! **empty in Task 4** — `http`/`browser` join it in Task 5, `l4` in Task 6 —
//! so the shipped `rhai.api.json` `namespaces` is `{}`. The test namespace is a
//! test-only crate and must never appear here.
//!
//! The seam drift guard (`tests/api_catalog.rs`) pins the shipped `namespaces`
//! to `assemble_namespaces(production_languages())` and pins the engine's
//! explicitly-registered `(namespace, name)` set (from the `HostRegistry` store)
//! to the assembled catalog — a seam-specific guard distinct from F8's
//! signature bijection, which cannot see per-namespace dispatch.

use std::collections::{BTreeMap, BTreeSet};

use aitm_plugin::language::{
    NamespaceCatalog, NamespaceEntry, NamespacesDoc, ProtocolLanguage, ProtocolStepDoc,
    SchemaEnumNode,
};

/// A failure assembling the shared definition files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// Two registered languages claim the same namespace. Assembly never
    /// last-wins; a clash is a hard error (Review Focus).
    DuplicateNamespace(String),
    /// A namespace's PoC `op` verb vocabulary diverges from its Rhai host-fn
    /// names (AC8, "one vocabulary"). Enforced at assembly so a divergent
    /// catalog fails the build rather than shipping two drifting vocabularies.
    VocabularyInconsistent(String),
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::DuplicateNamespace(ns) => {
                write!(f, "two languages claim the namespace `{ns}`")
            }
            AssembleError::VocabularyInconsistent(ns) => write!(
                f,
                "namespace `{ns}`'s PoC `op` vocabulary diverges from its host-fn names (AC8)"
            ),
        }
    }
}

impl std::error::Error for AssembleError {}

/// The namespaces that ship to operators, in catalog order. Task 6 adds `l4`
/// (the first consumer of the seam); Task 5 adds `http`/`browser`/`store`/`scope`.
/// The test namespace (`aitm-proto-test`) is deliberately absent — it must not
/// pollute operator completion.
///
/// `l4` is contributed as [`aitm_proto_l4::L4Language::for_catalog`], which needs
/// only static data (`catalog()` / `namespace()` / `api_version()`); it carries a
/// default deny-by-default guard so no live engagement state is required to
/// describe the surface.
pub fn production_languages() -> Vec<Box<dyn ProtocolLanguage>> {
    vec![Box::new(aitm_proto_l4::L4Language::for_catalog())]
}

/// Concatenate each language's [`NamespaceCatalog`] into `rhai.api.json`'s
/// `namespaces` map. Keyed by namespace, so a same-named fn in two namespaces
/// stays separate; a duplicate namespace key is an [`AssembleError`].
///
/// Returns a `Result` rather than the bare map named in the plan sketch, because
/// the fixed design requires a duplicate namespace to be a hard error rather
/// than a silent overwrite.
pub fn assemble_namespaces(
    languages: &[&dyn ProtocolLanguage],
) -> Result<NamespacesDoc, AssembleError> {
    let mut doc: NamespacesDoc = BTreeMap::new();
    for language in languages {
        let cat = language.catalog();
        if doc.contains_key(&cat.namespace) {
            return Err(AssembleError::DuplicateNamespace(cat.namespace));
        }
        doc.insert(
            cat.namespace.clone(),
            NamespaceEntry {
                api_version: cat.api_version.clone(),
                fns: cat.host_fns.clone(),
            },
        );
    }
    Ok(doc)
}

/// Build the per-`<ns>:` step nodes of `poc-yaml.schema.json` from each
/// namespace's `catalog().poc_step` (and its sources). A namespace that
/// contributes no PoC step contributes no entry; a duplicate namespace key is an
/// [`AssembleError`].
pub fn assemble_poc_steps(
    languages: &[&dyn ProtocolLanguage],
) -> Result<BTreeMap<String, ProtocolStepDoc>, AssembleError> {
    let mut doc: BTreeMap<String, ProtocolStepDoc> = BTreeMap::new();
    for language in languages {
        let cat = language.catalog();
        let Some(step) = cat.poc_step.clone() else {
            continue;
        };
        // AC8 is enforced, not advisory: a namespace whose PoC `op` vocabulary
        // diverges from its host-fn names fails the build here rather than
        // shipping a catalog whose two faces teach different verbs.
        if !vocabulary_consistent(&cat) {
            return Err(AssembleError::VocabularyInconsistent(cat.namespace));
        }
        if doc.contains_key(&cat.namespace) {
            return Err(AssembleError::DuplicateNamespace(cat.namespace));
        }
        let keys = step
            .enums
            .iter()
            .map(|(field, values)| {
                (
                    field.clone(),
                    SchemaEnumNode {
                        node_type: "enum".to_string(),
                        values: values.clone(),
                        description: format!(
                            "Allowed values for `{field}` in a `{}:` step.",
                            cat.namespace
                        ),
                    },
                )
            })
            .collect();
        // The step schema's own sources win; fall back to the namespace's.
        let sources = if step.sources.is_empty() {
            cat.sources.clone()
        } else {
            step.sources.clone()
        };
        doc.insert(
            cat.namespace.clone(),
            ProtocolStepDoc {
                node_type: "map".to_string(),
                description: step.description.clone(),
                keys,
                sources,
            },
        );
    }
    Ok(doc)
}

/// AC8 (one vocabulary) — whether a namespace's PoC `op` verb vocabulary matches
/// its Rhai host-fn names. A namespace with no PoC step, or a step with no `op`
/// enum, is vacuously consistent; otherwise the `op` enum must equal the set of
/// host-fn names, so the same verbs are learned once across both faces.
pub fn vocabulary_consistent(cat: &NamespaceCatalog) -> bool {
    let Some(step) = &cat.poc_step else {
        return true;
    };
    let Some(verbs) = step.enums.get("op") else {
        return true;
    };
    let fn_names: BTreeSet<&str> = cat.host_fns.iter().map(|f| f.name.as_str()).collect();
    let verbs: BTreeSet<&str> = verbs.iter().map(|s| s.as_str()).collect();
    verbs == fn_names
}

/// One namespace whose runnable `<ns>:` PoC step and catalogued PoC step
/// disagree — a violation of the PoC-face seam bijection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocFaceDrift {
    /// `poc_step()` returns a handler but `catalog().poc_step` is `None`: a
    /// runnable `<ns>:` step that no completion / `poc-yaml.schema.json` entry
    /// advertises — the spec's "a catalog that silently lags the engine"
    /// anti-goal, on the PoC face.
    RunnableButUncatalogued(String),
    /// `catalog().poc_step` is `Some` but `poc_step()` is `None`: a catalogued
    /// `<ns>:` step with no handler to run it — completion offers a step the
    /// engine would reject.
    CataloguedButNotRunnable(String),
}

/// The PoC-step analogue of the host-fn seam bijection
/// (`registered_host_fns` ↔ `assemble_namespaces`). The host-fn guard pins the
/// registry's `(ns, name)` set to the catalog, but says nothing about the
/// `<ns>:` PoC step; this guard pins the other face: for every registered
/// language, a runnable PoC step (`poc_step().is_some()`) must be catalogued
/// (`catalog().poc_step.is_some()`) and vice versa. Returns every namespace that
/// breaks the bijection (empty = the PoC faces correspond exactly).
pub fn poc_face_drift(languages: &[&dyn ProtocolLanguage]) -> Vec<PocFaceDrift> {
    let mut out = Vec::new();
    for language in languages {
        let runnable = language.poc_step().is_some();
        let catalogued = language.catalog().poc_step.is_some();
        match (runnable, catalogued) {
            (true, false) => {
                out.push(PocFaceDrift::RunnableButUncatalogued(
                    language.namespace().to_string(),
                ));
            }
            (false, true) => {
                out.push(PocFaceDrift::CataloguedButNotRunnable(
                    language.namespace().to_string(),
                ));
            }
            (true, true) | (false, false) => {}
        }
    }
    out
}
