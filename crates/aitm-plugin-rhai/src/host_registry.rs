//! The concrete [`ScriptHostRegistry`] the engine exposes so a protocol crate
//! injects its `<ns>.*` Rhai host fns **from its own crate** (plan Task 2).
//!
//! [`crate::engine::build_engine_with_languages`] drives each registered
//! [`ProtocolLanguage::register_host_fns`] through a [`HostRegistry`]. Adding a
//! protocol touches no code here — it registers from outside (AC1).
//!
//! **How a namespace reads.** Each `<ns>` becomes a global constant of one
//! shared custom type ([`ProtoNs`]) carrying the namespace name, so a script
//! writes `test.ping()` / `l4.craft(req)` — a dot-call on a namespace value,
//! exactly like the built-in `http.send(req)` — not `test::ping()`. The methods
//! are registered by their unqualified name against [`ProtoNs`] with the
//! argument(s) typed `Dynamic` so one registration accepts any positional
//! shape; dispatch keys on the **receiver's namespace** plus the method name, so
//! the same fn name in two namespaces stays separate.
//!
//! **Guarded by construction.** [`ScriptHostRegistry::register`] accepts only a
//! [`Guarded<HostFn>`]; before the host fn runs, the engine calls the guard's
//! [`GuardHandle::permit`] (deny-by-default), so a refusal stops the effect and
//! there is no path to register an effectful fn without a guard. That the
//! unguarded case does not even type-check:
//!
//! ```compile_fail
//! use aitm_core::Value;
//! use aitm_plugin::language::{HostCallCtx, HostFn, ScriptHostRegistry};
//!
//! fn demo(reg: &mut dyn ScriptHostRegistry) {
//!     let f: HostFn = Box::new(|_ctx: &HostCallCtx, _args: &[Value]| Ok(Value::Null));
//!     // `register` demands a `Guarded<HostFn>`; a bare host fn is rejected, so
//!     // an effectful fn cannot forget its guard.
//!     let _ = reg.register("test", "effect", f);
//! }
//! ```

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};

use aitm_core::{CallerTrust, Value};
use aitm_plugin::language::{
    GuardHandle, Guarded, HostCallContextSource, HostCallCtx, HostError, HostFn, ProtocolLanguage,
    RegisterError, ScriptHostRegistry,
};
use rhai::{Dynamic, Engine, EvalAltResult, Module, NativeCallContext, Position};

use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The most positional arguments a `<ns>.fn(...)` call may take. Each method
/// name is registered once per arity in `0..=MAX_ARITY` (the receiver aside),
/// every argument typed `Dynamic` so any value is accepted; a call with more
/// arguments simply finds no overload and is a normal "function not found"
/// script error.
const MAX_ARITY: usize = 8;

/// The call-source label [`dispatch`] falls back to when neither the seed nor the
/// per-eval [`NativeCallContext`] names an origin.
const DEFAULT_CALL_SOURCE: &str = "rhai";

thread_local! {
    /// The caller context seeded for the eval running on **this** thread, if any.
    ///
    /// Every script/PoC invocation boundary (plugin hook dispatch, the PoC
    /// runner, a `script:` step — all wired in plan Task 3) calls
    /// [`seed_call_context`] *before* evaluating and holds the returned
    /// [`CallContextGuard`] for the eval; [`dispatch`] reads this on every
    /// `<ns>.<fn>` call. An eval that reaches a seam host fn with this unset is
    /// **refused fail-closed** (plan AC3) — never treated as an operator.
    ///
    /// It is a *thread-local* on purpose: `wire::build` shares **one** `Engine`
    /// across all frontends, and rhai (`sync`) runs each eval synchronously on
    /// its own calling thread. A per-thread cell is therefore seen by exactly the
    /// eval that seeded it and every nested host-fn call that eval makes on the
    /// same thread, and never by a concurrent eval on another thread — so two
    /// frontends evaluating at once cannot read each other's trust. Using an
    /// engine-global tag (e.g. `Engine::set_default_tag`) would not be safe here.
    static CALL_CONTEXT: RefCell<Option<SeededCallContext>> = const { RefCell::new(None) };
}

/// The per-eval caller context an invocation boundary seeds and [`dispatch`]
/// reads. Owned (no rhai types) so it can live in [`CALL_CONTEXT`] across the
/// whole eval and be cloned cheaply per host-fn call.
#[derive(Clone)]
struct SeededCallContext {
    caller: CallerTrust,
    tag: Option<Value>,
    source: Option<String>,
}

/// Seed the caller trust (and an optional per-eval `tag` / call-`source` label)
/// for the eval about to run on this thread, returning a guard that clears the
/// seed when it drops.
///
/// **Every production invocation boundary must call this before evaluating.** A
/// seam host fn reached without a live seed is refused fail-closed by
/// [`dispatch`] (plan AC3) — there is no operator default, so an un-seeded eval
/// can never widen an agent's trust.
///
/// Nesting and concurrency: a boundary that runs inside another (a `script:`
/// step inside a PoC) may seed again; the previous seed is restored when the
/// inner guard drops, so nested seam calls on the thread always observe the
/// innermost live seed. Because the seed lives in a thread-local for the whole
/// eval, a seam fn reached through nested calls on the same thread still sees it,
/// and a concurrent eval on another thread never does.
#[must_use = "the seeded caller context is cleared when the guard drops"]
pub fn seed_call_context(
    caller: CallerTrust,
    tag: Option<Value>,
    source: Option<String>,
) -> CallContextGuard {
    let previous = CALL_CONTEXT.with(|cell| {
        cell.borrow_mut().replace(SeededCallContext {
            caller,
            tag,
            source,
        })
    });
    CallContextGuard { previous }
}

/// The RAII guard returned by [`seed_call_context`]: restores the previously
/// seeded context (normally none) when dropped, so a seed never outlives its
/// eval or leaks onto the thread for a later, unrelated one.
#[must_use = "the seeded caller context is cleared when the guard drops"]
pub struct CallContextGuard {
    previous: Option<SeededCallContext>,
}

impl Drop for CallContextGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CALL_CONTEXT.with(|cell| *cell.borrow_mut() = previous);
    }
}

/// The caller context seeded on this thread, if any — a clone, so no borrow of
/// the thread-local is held across the host-fn call.
fn current_call_context() -> Option<SeededCallContext> {
    CALL_CONTEXT.with(|cell| cell.borrow().clone())
}

/// One registered host fn: its guard and the fn itself.
struct Entry {
    guard: Box<dyn GuardHandle>,
    f: HostFn,
}

/// The shared table of registered fns, keyed by `(namespace, name)`. Written
/// while the languages install, read on every call; an [`RwLock`] lets
/// concurrent script evaluations dispatch without serializing.
type Store = RwLock<HashMap<(String, String), Entry>>;

/// The value behind each script-visible namespace constant (`test`, `l4`, …).
/// It carries the namespace name and a handle to the shared table, so a method
/// call dispatches by this value's namespace plus the method name.
#[derive(Clone)]
struct ProtoNs {
    namespace: String,
    store: Arc<Store>,
}

/// The concrete registry a [`ProtocolLanguage`] registers against. Holds the
/// engine (to install the namespace constants and method dispatchers) and the
/// shared fn table.
pub struct HostRegistry<'e> {
    engine: &'e mut Engine,
    store: Arc<Store>,
    /// Namespaces that already have their global constant installed.
    namespaces: HashSet<String>,
    /// Method names whose arity dispatchers are already installed.
    methods: HashSet<String>,
    /// Whether [`ProtoNs`] has been registered as a custom type yet.
    type_registered: bool,
}

impl<'e> HostRegistry<'e> {
    /// A fresh registry over `engine` with an empty fn table.
    fn new(engine: &'e mut Engine) -> Self {
        Self {
            engine,
            store: Arc::new(RwLock::new(HashMap::new())),
            namespaces: HashSet::new(),
            methods: HashSet::new(),
            type_registered: false,
        }
    }

    /// Install the global constant for `ns` (and the shared custom type, once),
    /// so `ns.fn(...)` resolves. Idempotent per namespace.
    fn ensure_namespace(&mut self, ns: &str) {
        if self.namespaces.contains(ns) {
            return;
        }
        if !self.type_registered {
            self.engine
                .register_type_with_name::<ProtoNs>("ProtoNamespace");
            self.type_registered = true;
        }
        let mut module = Module::new();
        module.set_var(
            ns,
            ProtoNs {
                namespace: ns.to_string(),
                store: Arc::clone(&self.store),
            },
        );
        self.engine.register_global_module(module.into());
        self.namespaces.insert(ns.to_string());
    }

    /// Install the arity dispatchers for method `name` (once across all
    /// namespaces — the body dispatches by the receiver's namespace).
    fn ensure_method(&mut self, name: &str) {
        if self.methods.contains(name) {
            return;
        }
        register_method(self.engine, name);
        self.methods.insert(name.to_string());
    }
}

impl ScriptHostRegistry for HostRegistry<'_> {
    fn register(&mut self, ns: &str, name: &str, f: Guarded<HostFn>) -> Result<(), RegisterError> {
        let key = (ns.to_string(), name.to_string());
        {
            let store = self.store.read().unwrap_or_else(PoisonError::into_inner);
            if store.contains_key(&key) {
                // Never last-wins: a second registration of the same
                // `<ns>.<name>` (e.g. two crates claiming `test`) is a hard
                // error (Review Focus).
                return Err(RegisterError::Collision {
                    namespace: ns.to_string(),
                    name: name.to_string(),
                });
            }
        }
        let (guard, func) = f.into_parts();
        self.store
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Entry { guard, f: func });

        self.ensure_namespace(ns);
        self.ensure_method(name);
        Ok(())
    }
}

/// Drive every language's `register_host_fns` through one shared registry, so a
/// collision across languages (two crates claiming a namespace) is caught, and
/// return each installed namespace's `(namespace, api_version)` so the loader's
/// version gate can enforce a seam namespace's `api_version` as its `min_api`,
/// exactly like a built-in capability's (Task 7, AC9).
pub(crate) fn install_languages(
    engine: &mut Engine,
    languages: &[&dyn ProtocolLanguage],
) -> Result<Vec<(String, String)>, RegisterError> {
    let mut registry = HostRegistry::new(engine);
    let mut versions = Vec::with_capacity(languages.len());
    for language in languages {
        language.register_host_fns(&mut registry)?;
        versions.push((
            language.namespace().to_string(),
            language.api_version().to_string(),
        ));
    }
    Ok(versions)
}

/// The `(namespace, name)` set a slice of languages registers, read back from a
/// real [`HostRegistry`] store — the production registration path. The Task 4
/// seam drift guard compares this against the assembled `namespaces` catalog so a
/// registered namespace fn missing from the catalog (or vice versa) fails
/// (AC7). Unlike the engine's `gen_fn_signatures`, which collapses every
/// `<ns>.*` onto one `ProtoNamespace` type, this knows exactly what each
/// namespace registered.
pub fn registered_host_fns(
    languages: &[&dyn ProtocolLanguage],
) -> Result<std::collections::BTreeSet<(String, String)>, RegisterError> {
    // A throwaway engine: registration only writes the shared fn table (and
    // installs the namespace constants/dispatchers on this engine, which we
    // drop). No standard packages or runtime are needed.
    let mut engine = Engine::new_raw();
    let mut registry = HostRegistry::new(&mut engine);
    for language in languages {
        language.register_host_fns(&mut registry)?;
    }
    let store = registry
        .store
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    Ok(store.keys().cloned().collect())
}

/// Keep the hand-written `arity!` overloads below in sync with [`MAX_ARITY`].
const _: () = assert!(
    MAX_ARITY == 8,
    "add/remove arity! overloads to match MAX_ARITY"
);

/// Register one `name` overload taking the receiver plus the named `Dynamic`
/// arguments, forwarding them to [`dispatch`].
macro_rules! arity {
    ($engine:expr, $name:expr, $( $arg:ident ),+ ) => {{
        let n = $name.to_string();
        $engine.register_fn(
            $name,
            move |ctx: NativeCallContext, ns: &mut ProtoNs, $( $arg: Dynamic ),+ |
                -> Result<Dynamic, Box<EvalAltResult>> {
                let args = [ $( $arg ),+ ];
                dispatch(&ctx, ns, &n, &args)
            },
        );
    }};
}

/// Register the `name` method for [`ProtoNs`] at every arity in
/// `0..=MAX_ARITY`, each argument typed `Dynamic`. Each overload marshals its
/// arguments and dispatches by the receiver's namespace.
fn register_method(engine: &mut Engine, name: &str) {
    // Arity 0 (the receiver only).
    let n = name.to_string();
    engine.register_fn(
        name,
        move |ctx: NativeCallContext, ns: &mut ProtoNs| -> Result<Dynamic, Box<EvalAltResult>> {
            dispatch(&ctx, ns, &n, &[])
        },
    );

    arity!(engine, name, a0);
    arity!(engine, name, a0, a1);
    arity!(engine, name, a0, a1, a2);
    arity!(engine, name, a0, a1, a2, a3);
    arity!(engine, name, a0, a1, a2, a3, a4);
    arity!(engine, name, a0, a1, a2, a3, a4, a5);
    arity!(engine, name, a0, a1, a2, a3, a4, a5, a6);
    arity!(engine, name, a0, a1, a2, a3, a4, a5, a6, a7);
}

/// Thread the per-eval [`HostCallCtx`] through one `<ns>.<name>(...)` call:
/// read the caller context seeded at the invocation boundary, marshal the Rhai
/// arguments to `Value`s, run the guard's permit check, call the registered host
/// fn, and marshal its result back.
///
/// This is the **one** place in the codebase that touches [`NativeCallContext`]
/// (plan AC8): it builds a rhai-free [`HostCallContextSource`] from the seeded
/// tag/source and the per-eval context, so the guard and host fn see only
/// `aitm_core` types.
///
/// **Fail-closed (plan AC3).** If no caller context is seeded for this eval the
/// call is refused *before any effect* with a clear "no caller context" error —
/// never defaulted to [`CallerTrust::Operator`]. A guard refusal, a missing
/// context, and a host-fn error all surface as catchable Rhai runtime errors.
fn dispatch(
    ctx: &NativeCallContext,
    ns: &ProtoNs,
    name: &str,
    args: &[Dynamic],
) -> Result<Dynamic, Box<EvalAltResult>> {
    // Fail-closed first: an eval that reaches a seam host fn without a seeded
    // caller context is refused before anything runs — not treated as operator.
    let seed = current_call_context().ok_or_else(|| {
        host_error(HostError::GuardRefused {
            namespace: ns.namespace.clone(),
            reason: format!(
                "no caller context seeded for this evaluation; refusing `{}.{}` \
                 (fail-closed: the invocation boundary must seed the caller trust)",
                ns.namespace, name
            ),
        })
    })?;

    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        values.push(dynamic_to_value(arg).map_err(|err| runtime_error(err.to_string()))?);
    }

    let store = ns.store.read().unwrap_or_else(PoisonError::into_inner);
    let entry = store
        .get(&(ns.namespace.clone(), name.to_string()))
        .ok_or_else(|| {
            runtime_error(format!(
                "no host function `{}.{}` is registered",
                ns.namespace, name
            ))
        })?;

    // The rhai-free source for this call: the seeded tag (falling back to the
    // per-eval `NativeCallContext` tag) and a call-source label (the seed's, else
    // the caller's script source, else a static default).
    let source = RhaiCallSource {
        tag: seed
            .tag
            .or_else(|| ctx.tag().and_then(|tag| dynamic_to_value(tag).ok())),
        call_source: seed
            .source
            .or_else(|| ctx.call_source().map(str::to_string))
            .unwrap_or_else(|| DEFAULT_CALL_SOURCE.to_string()),
    };
    let hostctx = HostCallCtx::new(seed.caller, &source);

    // Deny-by-default: the guard admits the call before any effect runs.
    entry.guard.permit(&hostctx, name).map_err(host_error)?;
    let out = (entry.f)(&hostctx, &values).map_err(host_error)?;
    Ok(value_to_dynamic(&out))
}

/// Run a guard-wrapped seam host fn registered under a **global** (non-namespaced)
/// Rhai name, threading the per-eval [`HostCallCtx`] exactly as [`dispatch`] does
/// for `<ns>.<name>` calls: read the caller context seeded at the invocation
/// boundary, build the rhai-free [`HostCallContextSource`] from the seed's
/// tag/source, run the guard's permit check (permit-before-effect), then the host
/// fn.
///
/// The first-party `option`/`finding` verbs ([`crate::host_core`]) stay **global**
/// Rhai functions for call-syntax back-compat (AC7: `option("x")` /
/// `finding(#{…})` are unchanged), so they cannot take the [`ProtoNs`] receiver
/// [`dispatch`] path; they take this sibling instead. Like [`dispatch`] it is a
/// place rhai meets the seam, but it touches **no** [`NativeCallContext`] — the
/// tag and call source come from the per-eval seed, so the migrated host-fn
/// bodies stay rhai-free (AC8).
///
/// **Fail-closed (AC3).** With no seeded caller context the call is refused before
/// any effect with a clear "no caller context" error — never defaulted to
/// [`CallerTrust::Operator`]. Unlike [`dispatch`], an absent call source falls back
/// to the **empty** string (not [`DEFAULT_CALL_SOURCE`]) so a first-party fn such
/// as `finding` can apply its own `"<unnamed script>"` provenance default and
/// preserve its exact pre-seam behaviour.
pub fn run_seam_global(
    namespace: &str,
    fn_name: &str,
    guard: &dyn GuardHandle,
    f: &HostFn,
    args: &[Value],
) -> Result<Value, HostError> {
    let seed = current_call_context().ok_or_else(|| HostError::GuardRefused {
        namespace: namespace.to_string(),
        reason: format!(
            "no caller context seeded for this evaluation; refusing `{fn_name}` \
             (fail-closed: the invocation boundary must seed the caller trust)"
        ),
    })?;
    let source = RhaiCallSource {
        tag: seed.tag,
        call_source: seed.source.unwrap_or_default(),
    };
    let hostctx = HostCallCtx::new(seed.caller, &source);
    guard.permit(&hostctx, fn_name)?;
    (f)(&hostctx, args)
}

/// The concrete [`HostCallContextSource`] the bridge builds for one call: the
/// per-eval tag and origin resolved by [`dispatch`], owned so it carries no rhai
/// type and the host fn/guard read only `aitm_core` values.
struct RhaiCallSource {
    tag: Option<Value>,
    call_source: String,
}

impl HostCallContextSource for RhaiCallSource {
    fn tag(&self) -> Option<Value> {
        self.tag.clone()
    }

    fn call_source(&self) -> &str {
        &self.call_source
    }
}

/// A catchable runtime error; the engine fills in the call position.
fn runtime_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}

/// A [`HostError`] (a guard refusal or bad arguments) as the script catches it:
/// a runtime error carrying the one-line message.
fn host_error(err: HostError) -> Box<EvalAltResult> {
    runtime_error(err.to_string())
}
