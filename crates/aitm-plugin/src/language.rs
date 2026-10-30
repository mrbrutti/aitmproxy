//! The `ProtocolLanguage` extensibility seam (plan
//! `2026-10-28-aitmproxy-protocol-extensible-languages`, Task 1).
//!
//! A protocol crate (`aitm-proto-l4`, `aitm-proto-http`, a future
//! `aitm-proto-dns`, …) contributes its **scripting** host namespace, its
//! native **PoC** step, and its completion **catalog** through one trait so
//! neither `aitm-plugin-rhai` nor `aitm-poc` is edited to add a protocol. All
//! the seam types live here and are re-exported from the crate root, so a
//! protocol author imports a single path:
//!
//! ```ignore
//! use aitm_plugin::language::{ProtocolLanguage, ScriptHostRegistry, Guarded, HostFn};
//! ```
//!
//! ## Why the seam lives in `aitm-plugin`
//!
//! The dependency graph must stay acyclic: `aitm-plugin` depends only on
//! `aitm-core`. Everything else (`aitm-plugin-rhai`, `aitm-poc`, every
//! `aitm-proto-*`) may depend on `aitm-plugin`. So the seam is **rhai-free** —
//! a protocol crate writes host fns against [`aitm_core::Value`], and the rhai
//! engine (Task 2, in `aitm-plugin-rhai`) bridges `Value` ⇄ `rhai::Dynamic`
//! via its existing `marshal.rs`. PoC bodies are expressed as
//! `serde_yaml::Value`, never a rhai type.
//!
//! ## What Task 1 delivers vs. later tasks
//!
//! Task 1 is the **shape**: every trait method signature and every data type
//! fully type-checks and the test crate (`aitm-proto-test`) implements
//! [`ProtocolLanguage`] end to end. The *behaviour* behind the shape arrives
//! later:
//!
//! - Task 2 (`aitm-plugin-rhai`) implements a concrete [`ScriptHostRegistry`]
//!   that drives [`ProtocolLanguage::register_host_fns`] and bridges each
//!   [`HostFn`] into the engine, and makes an **unguarded effectful**
//!   registration fail to compile (a `trybuild`/doc-test around [`Guarded`]).
//! - Task 3 (`aitm-poc`) finalizes [`PocStepHandler`] dispatch
//!   (`Step::Protocol { ns, body }` → handler by `ns`).
//! - Task 4 assembles every [`NamespaceCatalog`] into `rhai.api.json` /
//!   `poc-yaml.schema.json` and extends the drift-guard.

use std::collections::BTreeMap;

use aitm_core::Value;
use serde::{Deserialize, Serialize};

/// A protocol's contribution to both language faces (Rhai scripting + PoC) and
/// the shared completion catalog.
///
/// A protocol module that is already a `ProtocolModule` additionally implements
/// this and is registered at load; the engine calls each method in turn. The
/// namespace (`"l4"`, `"http"`, `"test"`, …) is the single prefix under which
/// the protocol's host fns (`<ns>.fn(...)`) and PoC step (`<ns>:`) appear, so a
/// person learns the shape once and every protocol fits it.
pub trait ProtocolLanguage {
    /// The protocol's namespace prefix, e.g. `"l4"`. Every host fn is
    /// `<namespace>.<name>` and the native PoC step is `<namespace>:`.
    fn namespace(&self) -> &str;

    /// A per-namespace, semver-ish API version (like the script tier's
    /// `const API`). A script or PoC may target a namespace version; a mismatch
    /// is warned/refused per the script-tier `API` policy (enforced in Task 7).
    fn api_version(&self) -> &str;

    /// Register this protocol's `<ns>.*` Rhai host functions into the engine's
    /// registry. Each effectful fn is wrapped in a [`Guarded`] so it routes
    /// through the protocol's own guard before any effect; there is no
    /// unguarded registration path. Errors ([`RegisterError`]) on a collision.
    fn register_host_fns(&self, reg: &mut dyn ScriptHostRegistry) -> Result<(), RegisterError>;

    /// The native `<ns>:` PoC step handler, or `None` if this protocol
    /// contributes only a scripting namespace (for now). `aitm-poc` routes a
    /// `Step::Protocol { ns, .. }` to the handler whose [`PocStepHandler::ns`]
    /// matches (Task 3).
    fn poc_step(&self) -> Option<Box<dyn PocStepHandler>>;

    /// The pure-data description of this namespace for the shared definition
    /// files (`rhai.api.json` / `poc-yaml.schema.json`) and hover/help. The
    /// build concatenates every registered namespace's catalog (Task 4).
    fn catalog(&self) -> NamespaceCatalog;
}

/// The abstract registration surface a protocol crate writes against. The
/// concrete implementation is the rhai engine's (Task 2, in
/// `aitm-plugin-rhai`); keeping the trait here lets a protocol crate register
/// its host fns **without a rhai dependency**.
///
/// A [`HostFn`] speaks [`aitm_core::Value`] (args in, value out); the rhai
/// engine bridges `Value` ⇄ `rhai::Dynamic` via its `marshal.rs`. Every
/// registration is [`Guarded`], so an effectful fn cannot reach the wire
/// without its guard's permit.
pub trait ScriptHostRegistry {
    /// Register `<ns>.<name>` backed by a guard-wrapped host fn. Returns
    /// [`RegisterError::Collision`] if `<ns>.<name>` is already registered
    /// (never last-wins — Review Focus, enforced concretely in Task 2).
    fn register(&mut self, ns: &str, name: &str, f: Guarded<HostFn>) -> Result<(), RegisterError>;
}

/// A rhai-agnostic host function: it takes positional [`Value`] arguments and
/// returns a [`Value`] (or a [`HostError`]). The rhai engine marshals the
/// script's arguments into `Value`s and the returned `Value` back into a
/// `Dynamic` (Task 2), so a protocol crate writes host fns with no `rhai`
/// dependency.
pub type HostFn = Box<dyn Fn(&[Value]) -> Result<Value, HostError> + Send + Sync>;

/// A guard-wrapped registration payload. A [`Guarded`] can only be built with a
/// [`GuardHandle`] ([`Guarded::new`]), and [`ScriptHostRegistry::register`]
/// accepts nothing else — so an effectful registration **cannot forget its
/// guard**. Task 2 completes the type-level enforcement (a `trybuild` proving
/// the unguarded-effectful case fails to compile) and performs the permit check
/// on every call; here the wrapper carries the guard handle and the fn.
pub struct Guarded<F> {
    guard: Box<dyn GuardHandle>,
    f: F,
}

impl<F> Guarded<F> {
    /// Wrap a host fn with the guard that must admit every call. The guard is
    /// required by construction: there is no way to build a `Guarded` without
    /// one.
    pub fn new(guard: Box<dyn GuardHandle>, f: F) -> Self {
        Self { guard, f }
    }

    /// The guard that must admit every call to the wrapped fn.
    pub fn guard(&self) -> &dyn GuardHandle {
        self.guard.as_ref()
    }

    /// Consume the wrapper, yielding the guard handle and the fn (Task 2's
    /// engine installs the fn behind a permit check against the guard).
    pub fn into_parts(self) -> (Box<dyn GuardHandle>, F) {
        (self.guard, self.f)
    }
}

/// An opaque handle to a protocol's guard (HTTP's `ScopeRateGuard`, L4's
/// `L4Guard`, …). The seam is guard-agnostic: `aitm-plugin` stays rhai-free and
/// dependency-light, so a guard is a trait object a protocol supplies. The
/// concrete permit check is each protocol's guard's and is invoked by the
/// engine (Task 2).
pub trait GuardHandle: Send + Sync {
    /// A short name for the guard, for diagnostics and the catalog
    /// (e.g. `"l4"`, `"scope"`).
    fn guard_name(&self) -> &str;

    /// Decide whether a call to `<ns>.<fn_name>` may proceed. The engine (Task
    /// 2) calls this **before** the wrapped [`HostFn`] runs, so a refusal stops
    /// the effect from ever reaching the wire; on `Ok(())` the host fn runs.
    ///
    /// **Deny-by-default.** The provided implementation refuses every call with
    /// [`HostError::GuardRefused`], so a guard that admits nothing is the safe
    /// default and a protocol's guard must *opt in* a verb by overriding this.
    ///
    /// Task 6's `L4Guard` overrides this to enforce the per-verb
    /// `allow_agent_*` / sensitivity gates (an agent-driven run may be denied a
    /// verb a human-driven one is allowed); it is not implemented here. The
    /// `fn_name` is the unqualified verb (`"craft"`, `"ping"`), so one guard can
    /// make per-verb decisions.
    fn permit(&self, fn_name: &str) -> Result<(), HostError> {
        Err(HostError::GuardRefused {
            namespace: self.guard_name().to_string(),
            reason: format!("deny-by-default: `{fn_name}` is not permitted by this guard"),
        })
    }
}

/// The native `<ns>:` PoC step handler a protocol contributes. Object-safe so
/// `aitm-poc` can hold `Box<dyn PocStepHandler>` and dispatch by `ns`.
///
/// The runner routes a [`Step::Protocol { ns, body, extract }`] to the handler
/// whose [`ns`](PocStepHandler::ns) matches, hands it the late-parsed `body`
/// (`serde_yaml::Value`, per the spec's "Left to the builder" recommendation)
/// plus the resolved variables ([`PocStepInputs`]), and adapts the returned
/// [`PocStepOutcome`] back into its own bindings/sources — the handler never
/// references an `aitm-poc` type, so the dependency graph stays acyclic.
///
/// A handler contributes **named sources** (e.g. L4's `"packet"`) and/or direct
/// **bindings**. A PoC's sibling `extract` reads a field from a named source
/// (the normative `l4:` shape: `type: packet, field: tcp.flags`); the runner,
/// not the handler, walks the field path. Task 6's L4 handler implements this
/// `run` by dispatching the body's verb through the `l4.*` host functions and
/// returning the received packet as the `"packet"` source.
pub trait PocStepHandler: Send + Sync {
    /// The namespace this handler serves — matched against `Step::Protocol`'s
    /// `ns` by the runner.
    fn ns(&self) -> &str;

    /// Run the late-parsed step `body` against the resolved `inputs`, returning
    /// the sources and bindings it produced (or a [`HostError`] — e.g. the
    /// protocol guard refused the verb, or the body was malformed). The runner
    /// merges the outcome's bindings and feeds its sources to the step's
    /// `extract`.
    fn run(
        &self,
        body: &serde_yaml::Value,
        inputs: &PocStepInputs,
    ) -> Result<PocStepOutcome, HostError>;
}

/// What a [`PocStepHandler::run`] is handed: the PoC's resolved variables, so a
/// handler can expand `{{placeholder}}`s inside its own body. Expressed purely
/// in seam terms ([`aitm_core::Value`]) — it carries none of `aitm-poc`'s
/// run context, keeping the seam acyclic.
#[derive(Debug, Clone, Default)]
pub struct PocStepInputs {
    /// The variables resolved so far (caller bindings over variable defaults,
    /// plus any earlier steps' bindings), by name.
    pub vars: BTreeMap<String, Value>,
}

/// What a [`PocStepHandler::run`] produced, adapted by the runner into its match
/// context: **named sources** a sibling `extract`/matcher reads a field from
/// (e.g. `"packet"` → the received packet as a [`Value::Object`]), and direct
/// **bindings** that reach later steps and `success` the way an extractor
/// binding does.
#[derive(Debug, Clone, Default)]
pub struct PocStepOutcome {
    /// Named sources the step produced; a PoC extractor/matcher reads a field
    /// out of one (e.g. `extract { type: packet, field: tcp.flags }`).
    pub sources: BTreeMap<String, Value>,
    /// Variables bound directly by the step, visible to later steps and
    /// `success`.
    pub bindings: BTreeMap<String, Value>,
}

/// Pure data describing one namespace for the shared operator-UI definition
/// files (`rhai.api.json` / `poc-yaml.schema.json`) and hover/help. Task 4
/// concatenates every registered namespace's catalog into those files; the
/// drift-guard asserts every registered namespace is present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamespaceCatalog {
    /// The namespace name, e.g. `"l4"` — matches [`ProtocolLanguage::namespace`].
    pub namespace: String,
    /// The namespace's API version — matches [`ProtocolLanguage::api_version`].
    pub api_version: String,
    /// The `<ns>.*` host-fn signatures + descriptions, for Rhai completion.
    #[serde(default)]
    pub host_fns: Vec<HostFnSig>,
    /// The native `<ns>:` PoC step schema, if this namespace contributes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_step: Option<PocStepSchema>,
    /// The matcher/extractor source names this namespace contributes
    /// (e.g. `"packet"`).
    #[serde(default)]
    pub sources: Vec<String>,
}

/// One host-fn signature in a [`NamespaceCatalog`] (`<ns>.<name>(params) -> returns`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostFnSig {
    /// The fn name within the namespace (unqualified, e.g. `"craft"`).
    pub name: String,
    /// Positional parameters, in order.
    #[serde(default)]
    pub params: Vec<ParamSig>,
    /// A short description of the return value's type/shape (e.g. `"null"`,
    /// `"object"`).
    pub returns: String,
    /// A one-line human description for hover/help.
    pub description: String,
}

/// One parameter of a [`HostFnSig`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParamSig {
    /// The parameter name.
    pub name: String,
    /// A short description of the parameter's type/shape (e.g. `"string"`,
    /// `"int"`, `"object"`).
    #[serde(rename = "type")]
    pub ty: String,
    /// A one-line human description for hover/help.
    pub description: String,
}

/// The schema of a native `<ns>:` PoC step in a [`NamespaceCatalog`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PocStepSchema {
    /// The step key, i.e. the namespace (`l4:` → `"l4"`).
    pub step: String,
    /// A one-line human description for hover/help.
    pub description: String,
    /// Enumerated values for named fields of the step body (e.g. `op` →
    /// `["craft", "inject", "send_recv", "capture", "intercept"]`).
    #[serde(default)]
    pub enums: BTreeMap<String, Vec<String>>,
    /// The matcher/extractor source names this step contributes
    /// (e.g. `"packet"`).
    #[serde(default)]
    pub sources: Vec<String>,
}

/// The assembled `namespaces` map of `rhai.api.json` (Task 4): each protocol's
/// `NamespaceCatalog` concatenated by namespace. A protocol joins by returning
/// its [`NamespaceCatalog`]; the assembler keys by namespace, so two namespaces
/// with a same-named fn stay separate (Review Focus). These output types are
/// pure data (serde-derived, rhai-free), living beside [`NamespaceCatalog`] so
/// the rhai-free assembler can emit the shared operator-UI files.
pub type NamespacesDoc = BTreeMap<String, NamespaceEntry>;

/// One namespace's entry in [`NamespacesDoc`]: its API version and the `<ns>.*`
/// host-fn signatures, in the shape `rhai.api.json`'s `namespaces` map expects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamespaceEntry {
    /// The namespace's API version — matches [`ProtocolLanguage::api_version`].
    pub api_version: String,
    /// The `<ns>.*` host-fn signatures + descriptions, for Rhai completion.
    #[serde(default)]
    pub fns: Vec<HostFnSig>,
}

/// One `<ns>:` step node of `poc-yaml.schema.json` (Task 4), assembled from a
/// namespace's [`PocStepSchema`]. Mirrors the schema's `map` node shape so the
/// operator-UI schema can consume it directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolStepDoc {
    /// Always `"map"`: a `<ns>:` step body is a map of fields.
    #[serde(rename = "type")]
    pub node_type: String,
    /// A one-line human description for hover/help.
    pub description: String,
    /// The body's enumerated fields (e.g. `op` → its verb vocabulary), as schema
    /// `enum` nodes.
    #[serde(default)]
    pub keys: BTreeMap<String, SchemaEnumNode>,
    /// The matcher/extractor source names this step contributes (e.g. `"packet"`).
    #[serde(default)]
    pub sources: Vec<String>,
}

/// A schema `enum` node inside a [`ProtocolStepDoc`]'s `keys` map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaEnumNode {
    /// Always `"enum"`.
    #[serde(rename = "type")]
    pub node_type: String,
    /// The allowed values for this field.
    #[serde(rename = "enum")]
    pub values: Vec<String>,
    /// A one-line human description for hover/help.
    pub description: String,
}

/// A failure registering a host fn into a [`ScriptHostRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// `<namespace>.<name>` is already registered. Registration never
    /// last-wins; a collision is a hard error (Review Focus).
    Collision {
        /// The namespace of the colliding registration.
        namespace: String,
        /// The fn name of the colliding registration.
        name: String,
    },
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::Collision { namespace, name } => write!(
                f,
                "host function `{namespace}.{name}` is already registered",
            ),
        }
    }
}

impl std::error::Error for RegisterError {}

/// A failure invoking a protocol host fn or PoC step handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The protocol's guard refused the call (deny-by-default).
    GuardRefused {
        /// The namespace whose guard refused.
        namespace: String,
        /// Why the guard refused (out of scope, rate-limited, …).
        reason: String,
    },
    /// The host fn / step received arguments or a body it cannot handle.
    BadArgs(String),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::GuardRefused { namespace, reason } => {
                write!(f, "`{namespace}` guard refused the call: {reason}")
            }
            HostError::BadArgs(msg) => write!(f, "bad arguments: {msg}"),
        }
    }
}

impl std::error::Error for HostError {}
