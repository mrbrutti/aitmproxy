//! `ScriptPlugin`: one compiled script as one `aitm_core::Plugin`, with hook
//! dispatch under `block_in_place`, snapshot/apply, and error isolation
//! (plan Task 8).
//!
//! A script takes a real position in the ordered chain: the `Event` is mapped
//! to its hook name, and if the script defines that hook it runs over a
//! [`FlowState`] snapshot of the flow. When the hook returns, the snapshot's
//! edits and effects are applied to the live flow (spec §5, the effect model)
//! and a recorded `halt()` becomes `Verdict::Halt` — the same short-circuit a
//! Rust plugin's verdict is. When the hook fails — a throw, a runtime fault,
//! the operation or time budget — the snapshot is dropped unapplied, so the
//! flow is byte-for-byte as it was, the [`ScriptError`] is logged, an
//! `Event::Error` reaches the bus, and the chain continues (spec §8,
//! AC-M3-12).
//!
//! The whole hook runs inside `engine::blocking` (`block_in_place`) with a
//! run of kind `Hook` open ([`crate::engine::begin_run`]), so a slow script
//! blocks only this worker, the guarded async host verbs may `block_on` the
//! runtime handle for what is left of the budget, and `browser.*` knows to
//! refuse (spec §6).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use aitm_core::{
    Event, EventSink, FlowCtx, FlowError, FlowId, LimitConfig, Plugin, Registry, Verdict,
};
use arc_swap::ArcSwap;
use rhai::{CallFnOptions, Dynamic, Engine, EvalAltResult, Scope, AST};

use crate::command::ScriptRegHandle;
use crate::config::{RhaiConfig, ScriptMeta};
use crate::engine::{begin_run, blocking, Budget, RunKind};
use crate::error::ScriptError;
use crate::flow_api::{ActiveFlow, ScriptFlow, ScriptWsMessage};
use crate::flow_state::FlowState;
use crate::host_core::{Options, ScriptServices};

/// Log target for hook failures, so an operator can filter script errors.
const SCRIPT_TARGET: &str = "aitm_plugin_rhai::script";

/// One `.rhai` file, compiled once, as a plugin in the ordered chain.
pub struct ScriptPlugin {
    meta: ScriptMeta,
    engine: Arc<Engine>,
    /// The compiled script, shared with the `script.reload` command.
    handle: Arc<ScriptHandle>,
    services: ScriptServices,
    /// Passed to every hook run as its Rhai tag, where `option(name)` reads it.
    options: Options,
    budget: Budget,
    /// How much of a body the snapshot materializes for the script.
    max_body: usize,
    errors: Arc<ErrorSink>,
}

/// A loaded script's identity and its live AST — the hot-reload seam. The
/// plugin reads the AST per event; `script.reload` swaps it from outside the
/// chain, which owns the plugin itself behind its lock. A hook already running
/// finishes on the AST it started with; the next event sees the new one.
pub struct ScriptHandle {
    name: String,
    path: PathBuf,
    /// What the loader parsed from the script: its `API` and the hooks it defines.
    meta: ScriptMeta,
    ast: ArcSwap<AST>,
    /// Whether the script's hooks run. Advisory and read per event: no other
    /// state depends on it, so relaxed ordering is enough.
    enabled: AtomicBool,
}

impl ScriptHandle {
    fn new(meta: &ScriptMeta, ast: AST) -> Self {
        Self {
            name: meta.name.clone(),
            path: meta.path.clone(),
            meta: meta.clone(),
            ast: ArcSwap::from_pointee(named(ast, &meta.name)),
            enabled: AtomicBool::new(true),
        }
    }

    /// The script's `NAME` (or file stem).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file it was compiled from — what a reload recompiles.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The script's declared metadata: `api` and the hooks it defines.
    pub fn meta(&self) -> &ScriptMeta {
        &self.meta
    }

    /// Whether the script's hooks fire. A new handle is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turn the script's hooks on or off; takes effect from the next event.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Put a freshly compiled AST in service. The caller keeps the old one by
    /// simply not calling this when a recompile fails.
    pub fn swap(&self, ast: AST) {
        self.ast.store(Arc::new(named(ast, &self.name)));
    }

    fn current(&self) -> Arc<AST> {
        self.ast.load_full()
    }
}

/// Where a failed hook's `Event::Error` goes. Late-bound: plugins are
/// registered before the chain that dispatches events exists, so the loader
/// hands every script the same unbound sink and the wiring binds the chain
/// into it once built. Until then a failure is logged only.
///
/// Emission is spawned on the runtime, not run inline: the chain holds the
/// plugin's lock while a hook runs, so dispatching through it synchronously
/// would deadlock on the plugin itself.
#[derive(Default)]
pub struct ErrorSink {
    sink: RwLock<Option<Arc<dyn EventSink>>>,
    /// Script name -> the message of its most recent failed hook, cleared when
    /// the script next runs a hook cleanly or is reloaded. What `script.list`
    /// reports as `last_error`.
    last: Mutex<BTreeMap<String, String>>,
}

impl ErrorSink {
    /// Route emitted errors through `sink` (the chain) from now on.
    pub fn bind(&self, sink: Arc<dyn EventSink>) {
        *self.sink.write().unwrap_or_else(PoisonError::into_inner) = Some(sink);
    }

    /// Remember `message` as `script`'s most recent error.
    pub fn record(&self, script: &str, message: String) {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(script.to_string(), message);
    }

    /// Forget `script`'s recorded error (it ran cleanly or was reloaded).
    pub fn clear(&self, script: &str) {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(script);
    }

    /// `script`'s most recent recorded error, if it has one.
    pub fn last_error(&self, script: &str) -> Option<String> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(script)
            .cloned()
    }

    fn current(&self) -> Option<Arc<dyn EventSink>> {
        self.sink
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ScriptPlugin {
    /// Wrap a compiled script. The AST is named after the script when the
    /// loader has not already done so, so `finding(...)` can attribute what it
    /// records. Bodies are snapshotted up to the proxy's default body cap;
    /// [`ScriptPlugin::with_max_body`] overrides it.
    pub fn new(
        meta: ScriptMeta,
        engine: Arc<Engine>,
        ast: AST,
        services: ScriptServices,
        options: Options,
        cfg: &RhaiConfig,
    ) -> Self {
        let handle = Arc::new(ScriptHandle::new(&meta, ast));
        Self {
            meta,
            engine,
            handle,
            services,
            options,
            budget: Budget::of(cfg),
            max_body: LimitConfig::default().max_body_bytes,
            errors: Arc::default(),
        }
    }

    /// Share the sink that failed hooks emit `Event::Error` through.
    pub fn with_error_sink(mut self, errors: Arc<ErrorSink>) -> Self {
        self.errors = errors;
        self
    }

    /// Cap the body bytes a snapshot copies for the script.
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn meta(&self) -> &ScriptMeta {
        &self.meta
    }

    /// Swap in a freshly compiled AST (the hot-reload seam; see
    /// [`ScriptHandle::swap`]).
    pub fn reload(&self, ast: AST) {
        self.handle.swap(ast);
    }

    /// The handle `script.reload` swaps the AST through. Taken by the wiring
    /// before the plugin is boxed into the registry.
    pub fn handle(&self) -> Arc<ScriptHandle> {
        Arc::clone(&self.handle)
    }

    /// Run `hook` over `state` the way the spec's bridge describes: the whole
    /// call as blocking work, inside a `Hook` run with the configured budget,
    /// with `state` bound as the flow a bare `halt()` acts on and the script's
    /// options as the run's tag.
    fn call_hook(
        &self,
        ast: &AST,
        hook: &str,
        state: &Arc<Mutex<FlowState>>,
        args: Vec<Dynamic>,
    ) -> Result<(), Box<EvalAltResult>> {
        blocking(|| {
            let _run = begin_run(RunKind::Hook, self.budget.hook_timeout);
            let _active = ActiveFlow::enter(Arc::clone(state));
            self.engine
                .call_fn_with_options::<Dynamic>(
                    CallFnOptions::new().with_tag(self.options.clone()),
                    &mut Scope::new(),
                    ast,
                    hook,
                    args,
                )
                .map(drop)
        })
    }

    /// Log the failure and surface it on the bus as
    /// `FlowError::Protocol("script: …")` (spec §8, OQ2). A failing `on_error`
    /// hook is logged only: emitting another `Event::Error` for it would feed
    /// the hook its own failure forever.
    fn report(&self, ev: &Event, flow: FlowId, err: &ScriptError) {
        tracing::error!(target: SCRIPT_TARGET, script = %self.meta.name, "{err}");
        self.errors.record(&self.meta.name, err.to_string());
        if matches!(ev, Event::Error { .. }) {
            return;
        }
        let Some(sink) = self.errors.current() else {
            return;
        };
        let event = Event::Error {
            flow,
            kind: FlowError::Protocol(format!("script: {err}")),
        };
        self.services.rt.spawn(async move {
            sink.emit(event).await;
        });
    }
}

impl Plugin for ScriptPlugin {
    fn name(&self) -> &str {
        &self.meta.name
    }

    /// Run the script's `load(reg)` through the command/option bridge
    /// (`command.rs`), so what it registers lands in the platform registry the
    /// frontends read — a script command is an MCP tool and a CLI subcommand
    /// with no special casing (spec §9).
    ///
    /// A `load` that throws is logged and installs nothing; the script keeps
    /// its hooks, because a broken registration is no reason to drop a working
    /// `on_request` (spec §8's error policy, applied to load).
    fn load(&mut self, reg: &mut Registry) {
        let ast = self.handle.current();
        let mut handle = ScriptRegHandle::new(reg)
            .with_options(self.options.clone())
            .with_budget(self.budget);
        if let Err(err) = handle.run_load(&self.engine, &ast) {
            tracing::error!(target: SCRIPT_TARGET, script = %self.meta.name, "{err}");
        }
        // Defaults the script declared join the options its hooks read.
        self.options = handle.into_options();
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        if !self.handle.is_enabled() {
            return Verdict::Continue;
        }
        let Some(hook) = hook_for(ev) else {
            return Verdict::Continue;
        };
        let ast = self.handle.current();
        if !defines(&ast, hook) {
            return Verdict::Continue;
        }

        let state = Arc::new(Mutex::new(FlowState::snapshot(
            ctx.flow(),
            ev,
            self.max_body,
        )));
        let flow_id = lock(&state).id;
        let args = hook_args(ev, &state);

        match self.call_hook(&ast, hook, &state, args) {
            Ok(()) => {
                // A clean `on_error` run is the script handling its own
                // failure's `Event::Error`; it must not erase that failure.
                if !matches!(ev, Event::Error { .. }) {
                    self.errors.clear(&self.meta.name);
                }
                take(state).apply_to(ctx)
            }
            Err(err) => {
                // `state` is dropped unapplied: the flow stays as it was.
                let err = ScriptError::from_eval(&self.meta.name, hook, &err, &self.budget);
                self.report(ev, flow_id, &err);
                Verdict::Continue
            }
        }
    }
}

/// The hook an event fires (spec §3). `Event` is `#[non_exhaustive]`: a
/// lifecycle point this tier has no hook for passes through.
fn hook_for(ev: &Event) -> Option<&'static str> {
    match ev {
        Event::RequestHeaders(_) => Some("on_request_headers"),
        Event::Request(_) => Some("on_request"),
        Event::ResponseHeaders(_) => Some("on_response_headers"),
        Event::Response(_) => Some("on_response"),
        Event::WsStart(_) => Some("on_ws_start"),
        Event::WsMessage { .. } => Some("on_ws_message"),
        Event::WsEnd(_) => Some("on_ws_end"),
        Event::Error { .. } => Some("on_error"),
        _ => None,
    }
}

/// Whether the script defines a function named `hook`.
fn defines(ast: &AST, hook: &str) -> bool {
    ast.iter_functions().any(|f| f.name == hook)
}

/// The arguments the hook receives: `flow`, plus the frame for
/// `on_ws_message(flow, msg)` and the error text for `on_error(flow, err)`.
fn hook_args(ev: &Event, state: &Arc<Mutex<FlowState>>) -> Vec<Dynamic> {
    let flow = Dynamic::from(ScriptFlow(Arc::clone(state)));
    match ev {
        Event::WsMessage { .. } => {
            vec![flow, Dynamic::from(ScriptWsMessage::new(Arc::clone(state)))]
        }
        Event::Error { kind, .. } => vec![flow, Dynamic::from(kind.to_string())],
        _ => vec![flow],
    }
}

/// Name the AST after the script unless the loader already did.
fn named(mut ast: AST, name: &str) -> AST {
    if ast.source().is_none() {
        ast.set_source(name);
    }
    ast
}

/// The state back out of its handle once the hook has returned. Every script
/// handle is normally gone by now; should one linger (a hook that returned
/// `flow`, say), the state is copied out instead.
fn take(state: Arc<Mutex<FlowState>>) -> FlowState {
    match Arc::try_unwrap(state) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(PoisonError::into_inner),
        Err(shared) => lock(&shared).clone(),
    }
}

/// Lock the shared state; a poisoned lock still yields the data (plain values,
/// no invariant a half-finished edit could break).
fn lock(state: &Mutex<FlowState>) -> std::sync::MutexGuard<'_, FlowState> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}
