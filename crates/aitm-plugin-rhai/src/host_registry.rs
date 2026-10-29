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
//! use aitm_plugin::language::{HostFn, ScriptHostRegistry};
//!
//! fn demo(reg: &mut dyn ScriptHostRegistry) {
//!     let f: HostFn = Box::new(|_args: &[Value]| Ok(Value::Null));
//!     // `register` demands a `Guarded<HostFn>`; a bare host fn is rejected, so
//!     // an effectful fn cannot forget its guard.
//!     let _ = reg.register("test", "effect", f);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};

use aitm_plugin::language::{
    GuardHandle, Guarded, HostError, HostFn, ProtocolLanguage, RegisterError, ScriptHostRegistry,
};
use rhai::{Dynamic, Engine, EvalAltResult, Module, Position};

use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The most positional arguments a `<ns>.fn(...)` call may take. Each method
/// name is registered once per arity in `0..=MAX_ARITY` (the receiver aside),
/// every argument typed `Dynamic` so any value is accepted; a call with more
/// arguments simply finds no overload and is a normal "function not found"
/// script error.
const MAX_ARITY: usize = 8;

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
            move |ns: &mut ProtoNs, $( $arg: Dynamic ),+ |
                -> Result<Dynamic, Box<EvalAltResult>> {
                let args = [ $( $arg ),+ ];
                dispatch(ns, &n, &args)
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
        move |ns: &mut ProtoNs| -> Result<Dynamic, Box<EvalAltResult>> { dispatch(ns, &n, &[]) },
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

/// Marshal the Rhai arguments to `Value`s, run the guard's permit check, call
/// the registered host fn, and marshal its result back. A guard refusal and a
/// host-fn error both surface as catchable Rhai runtime errors.
fn dispatch(ns: &ProtoNs, name: &str, args: &[Dynamic]) -> Result<Dynamic, Box<EvalAltResult>> {
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

    // Deny-by-default: the guard admits the call before any effect runs.
    entry.guard.permit(name).map_err(host_error)?;
    let out = (entry.f)(&values).map_err(host_error)?;
    Ok(value_to_dynamic(&out))
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
