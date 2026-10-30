//! `ScriptHost`: the one `aitm_core::Plugin` the scripting tier registers, and
//! `LoadedScript`: one compiled script inside it, with hook dispatch under
//! `block_in_place`, snapshot/apply, and error isolation (plan Task 8).
//!
//! **The dynamic dispatch model (F8 Option B).** M3 shipped one `ScriptPlugin`
//! per script, each a separate member of the sealed `Registry` chain — so a
//! script saved at runtime could never join the running chain. Instead one
//! [`ScriptHost`] takes a single chain position and owns a [`ScriptSet`]: a
//! lock-free, copy-on-write list of [`LoadedScript`]s it iterates in order on
//! every event. `script.save` of a brand-new name appends to that set, so the
//! new script's hooks fire with no restart. The host reads the set on the hot
//! path via `ArcSwap`, so an append never blocks dispatch and dispatch never
//! blocks an append.
//!
//! A script takes a real position in the ordered chain: the `Event` is mapped
//! to its hook name, and if the script defines that hook it runs over a
//! [`FlowState`] snapshot of the flow. When the hook returns, the snapshot's
//! edits and effects are applied to the live flow (spec §5, the effect model)
//! and a recorded `halt()` becomes `Verdict::Halt` — the same short-circuit a
//! Rust plugin's verdict is, and it stops the scripts after it in the set just
//! as it stops the plugins after the host in the chain. When the hook fails — a
//! throw, a runtime fault, the operation or time budget — the snapshot is
//! dropped unapplied, so the flow is byte-for-byte as it was, the
//! [`ScriptError`] is logged, an `Event::Error` reaches the bus, and the host
//! goes on to the next script (spec §8, AC-M3-12). One script's failure never
//! touches another's: each runs over its own snapshot and the host holds no
//! mutable state a panic could poison.
//!
//! The whole hook runs inside `engine::blocking` (`block_in_place`) with a
//! run of kind `Hook` open ([`crate::engine::begin_run`]), so a slow script
//! blocks only this worker, the guarded async host verbs may `block_on` the
//! runtime handle for what is left of the budget, and `browser.*` knows to
//! refuse (spec §6).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use aitm_core::{
    CallerTrust, Event, EventSink, FlowCtx, FlowError, FlowId, LimitConfig, Plugin, Registry,
    Verdict,
};
use arc_swap::ArcSwap;
use rhai::{CallFnOptions, Dynamic, Engine, EvalAltResult, Scope, AST};

use crate::command::ScriptRegHandle;
use crate::config::{RhaiConfig, ScriptMeta};
use crate::engine::{begin_run, blocking, Budget, RunKind};
use crate::error::ScriptError;
use crate::flow_api::{ActiveFlow, ResponsePhase, ScriptFlow, ScriptWsMessage};
use crate::flow_state::FlowState;
use crate::host_core::{Options, ScriptServices};
use crate::host_registry::seed_call_context;

/// Log target for hook failures, so an operator can filter script errors.
const SCRIPT_TARGET: &str = "aitm_plugin_rhai::script";

/// The name the host reports to the chain. One entry, whatever the script
/// count; per-script identity lives on the [`ScriptHandle`]s, not here.
const HOST_NAME: &str = "script-host";

/// One `.rhai` file, compiled once, as one script inside the [`ScriptHost`].
///
/// Not an `aitm_core::Plugin`: the host is the single plugin, and it holds
/// every `LoadedScript` behind an `Arc` in its [`ScriptSet`] so it can iterate
/// and dispatch them by shared reference. Everything a hook needs is here; the
/// body cap is the host's and arrives per dispatch, so a script appended at
/// runtime (which the loader builds with the default cap) still honours the
/// proxy's configured cap.
pub struct LoadedScript {
    meta: ScriptMeta,
    engine: Arc<Engine>,
    /// The compiled script, shared with the `script.reload` command.
    handle: Arc<ScriptHandle>,
    services: ScriptServices,
    /// Passed to every hook run as its Rhai tag, where `option(name)` reads it.
    /// Behind an `ArcSwap` because `run_load` merges the script's declared
    /// option defaults in after the script is already shared in the set.
    options: ArcSwap<Options>,
    budget: Budget,
    errors: Arc<ErrorSink>,
}

/// A loaded script's identity and its live AST — the hot-reload seam. The
/// script reads the AST per event; `script.reload` swaps it from outside the
/// chain. A hook already running finishes on the AST it started with; the next
/// event sees the new one.
pub struct ScriptHandle {
    name: String,
    path: PathBuf,
    /// What the loader parsed from the script: its `API` and the hooks it defines.
    /// Live like the AST: a reload can change the hook set, so it is swapped
    /// with the AST. `name` and `path` above are stable across a reload.
    meta: ArcSwap<ScriptMeta>,
    ast: ArcSwap<AST>,
    /// Whether the script's hooks run. Advisory and read per event: no other
    /// state depends on it, so relaxed ordering is enough.
    enabled: AtomicBool,
    /// The script's **authoring trust** — whether a present operator or an
    /// autonomous agent authored it (an agent only while
    /// `scripts.allow_agent_authoring` is on, per F8). A hook and a `load(reg)`
    /// run detached from any frontend (the proxy fires them), so the per-eval
    /// caller trust seeded at those boundaries is this authoring trust, not an
    /// ambient operator default: an agent that authored a hook must not gain
    /// operator-level seam powers at hook time (spec Open-Q 1).
    ///
    /// Stored as an atomic (like [`ScriptHandle::enabled`]) and read per
    /// invocation; a `script.save` over the handle can re-set it to the saver's
    /// trust. Encoded by [`trust_code`]/[`trust_from_code`]; a fresh handle
    /// defaults to the most-restrictive [`CallerTrust::Agent`] (fail-closed).
    authoring: AtomicU8,
}

/// The [`ScriptHandle::authoring`] encoding of a fresh, not-yet-attributed
/// handle: the most-restrictive [`CallerTrust::Agent`], so an unset authoring
/// trust can only ever under-grant, never widen a hook to operator.
const AUTHORING_AGENT: u8 = 0;
/// The [`ScriptHandle::authoring`] encoding of [`CallerTrust::Operator`].
const AUTHORING_OPERATOR: u8 = 1;

/// Encode a caller trust for [`ScriptHandle::authoring`].
fn trust_code(trust: CallerTrust) -> u8 {
    match trust {
        CallerTrust::Agent => AUTHORING_AGENT,
        CallerTrust::Operator => AUTHORING_OPERATOR,
    }
}

/// Decode a [`ScriptHandle::authoring`] value; any non-operator code is the
/// fail-closed [`CallerTrust::Agent`].
fn trust_from_code(code: u8) -> CallerTrust {
    match code {
        AUTHORING_OPERATOR => CallerTrust::Operator,
        _ => CallerTrust::Agent,
    }
}

impl ScriptHandle {
    fn new(meta: &ScriptMeta, ast: AST) -> Self {
        Self {
            name: meta.name.clone(),
            path: meta.path.clone(),
            meta: ArcSwap::from_pointee(meta.clone()),
            ast: ArcSwap::from_pointee(named(ast, &meta.name)),
            enabled: AtomicBool::new(true),
            // Fail-closed until a loader/save explicitly records authorship.
            authoring: AtomicU8::new(AUTHORING_AGENT),
        }
    }

    /// The script's authoring trust, read per hook/`load` invocation.
    pub fn authoring_trust(&self) -> CallerTrust {
        trust_from_code(self.authoring.load(Ordering::Relaxed))
    }

    /// Record who authored (or last saved) the script: the loader seeds the
    /// least-privilege [`CallerTrust::Agent`] for a config-placed script (its
    /// provenance is unknown — a config entry names a file path, not its
    /// author), and only an in-session `script.save` records the saving
    /// frontend's true trust. Read live, so a re-save takes effect on the next
    /// hook.
    pub fn set_authoring_trust(&self, trust: CallerTrust) {
        self.authoring.store(trust_code(trust), Ordering::Relaxed);
    }

    /// The script's `NAME` (or file stem).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file it was compiled from — what a reload recompiles.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The script's declared metadata as of its latest compile: `api` and the
    /// hooks it defines. A snapshot; a later swap does not change it.
    pub fn meta(&self) -> Arc<ScriptMeta> {
        self.meta.load_full()
    }

    /// Whether the script's hooks fire. A new handle is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turn the script's hooks on or off; takes effect from the next event.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Put a freshly compiled AST in service together with the metadata it was
    /// compiled to, so `meta()` never describes a different script than the one
    /// running. The caller keeps the old pair by simply not calling this when a
    /// recompile fails.
    pub fn swap(&self, ast: AST, meta: ScriptMeta) {
        self.ast.store(Arc::new(named(ast, &self.name)));
        self.meta.store(Arc::new(meta));
    }

    fn current(&self) -> Arc<AST> {
        self.ast.load_full()
    }
}

/// Where a failed hook's `Event::Error` goes. Late-bound: the host is
/// registered before the chain that dispatches events exists, so the loader
/// hands every script the same unbound sink and the wiring binds the chain
/// into it once built. Until then a failure is logged only.
///
/// One sink is shared by every script (it is keyed by script name), so a
/// script appended at runtime records and clears through the same instance with
/// no extra wiring — the append path does not need to rebind anything.
///
/// Emission is spawned on the runtime, not run inline: the chain holds the
/// host's lock while a hook runs, so dispatching through it synchronously would
/// deadlock on the host itself.
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

impl LoadedScript {
    /// Wrap a compiled script. The AST is named after the script when the
    /// loader has not already done so, so `finding(...)` can attribute what it
    /// records.
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
            options: ArcSwap::from_pointee(options),
            budget: Budget::of(cfg),
            errors: Arc::default(),
        }
    }

    /// Share the sink that failed hooks emit `Event::Error` through.
    pub fn with_error_sink(self, errors: Arc<ErrorSink>) -> Self {
        Self { errors, ..self }
    }

    /// Record the script's authoring trust on its handle (the loader seeds the
    /// least-privilege [`CallerTrust::Agent`] for a config-placed script of
    /// unknown provenance; only an in-session `script.save` records the saving
    /// frontend's true trust). This is the trust a hook and `load(reg)` seed,
    /// since both run detached from any frontend (spec Open-Q 1). Omitting it
    /// leaves the fail-closed [`CallerTrust::Agent`] default.
    pub fn with_authoring_trust(self, trust: CallerTrust) -> Self {
        self.handle.set_authoring_trust(trust);
        self
    }

    pub fn meta(&self) -> &ScriptMeta {
        &self.meta
    }

    pub fn name(&self) -> &str {
        &self.meta.name
    }

    /// Swap in a freshly compiled AST (the hot-reload seam; see
    /// [`ScriptHandle::swap`]).
    pub fn reload(&self, ast: AST, meta: ScriptMeta) {
        self.handle.swap(ast, meta);
    }

    /// The handle `script.reload` / `script.enable` act through, and the one the
    /// command surface reads `script.list` off. Shared, so a change through it
    /// is seen by the running script.
    pub fn handle(&self) -> Arc<ScriptHandle> {
        Arc::clone(&self.handle)
    }

    /// Run the script's `load(reg)` through the command/option bridge
    /// (`command.rs`), so what it registers lands in the platform registry the
    /// frontends read — a script command is an MCP tool and a CLI subcommand
    /// with no special casing (spec §9). Called once, at startup, by
    /// [`ScriptHost::load`]; a script appended at runtime never reaches it,
    /// because the registry is sealed by then (why such a script's
    /// commands/options still need a restart).
    ///
    /// A `load` that throws is logged and installs nothing; the script keeps
    /// its hooks, because a broken registration is no reason to drop a working
    /// `on_request` (spec §8's error policy, applied to load).
    pub(crate) fn run_load(&self, reg: &mut Registry) {
        let ast = self.handle.current();
        // `load(reg)` can reach a seam host fn (`option`, …); `run_load` seeds this
        // boundary with the script's authoring trust (plus the options tag and the
        // script source) before it evaluates, so such a call is gated on the author
        // — never refused for a missing context, never widened to operator (spec
        // AC3). The seeding lives inside `run_load` so it also covers a direct call.
        let mut handle = ScriptRegHandle::new(reg)
            .with_options((**self.options.load()).clone())
            .with_budget(self.budget)
            .with_caller(self.handle.authoring_trust());
        if let Err(err) = handle.run_load(&self.engine, &ast) {
            tracing::error!(target: SCRIPT_TARGET, script = %self.meta.name, "{err}");
        }
        // Defaults the script declared join the options its hooks read.
        self.options.store(Arc::new(handle.into_options()));
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
        response_forwarded: bool,
    ) -> Result<(), Box<EvalAltResult>> {
        let options = (**self.options.load()).clone();
        // A hook runs detached from any frontend (the proxy fires it), so seed
        // this boundary with the script's authoring trust: an agent-authored
        // hook's seam calls are gated `Agent`, an operator-authored one's
        // `Operator`. The per-eval tag (the options, as a `Value`) and source (the
        // script name) are threaded through the same seed, so the seam-migrated
        // `option`/`finding` read them off `HostCallCtx` (the old
        // `with_tag(Options)` custom-type tag could not cross the rhai-free seam).
        // Held across the whole hook (and any seam call nested in it), never left
        // unseeded — fail-closed, never an operator default (spec AC6, AC3).
        let authoring = self.handle.authoring_trust();
        let tag = options.to_value();
        let source = ast.source().map(str::to_string);
        blocking(|| {
            let _run = begin_run(RunKind::Hook, self.budget);
            let _active = ActiveFlow::enter(Arc::clone(state));
            // on_response fires post-forward: enter the observe-only response phase
            // so a response write in it is refused loudly, not silently dropped.
            let _phase = response_forwarded.then(ResponsePhase::forwarded);
            let _seed = seed_call_context(authoring, Some(tag), source);
            self.engine
                .call_fn_with_options::<Dynamic>(
                    CallFnOptions::new(),
                    &mut Scope::new(),
                    ast,
                    hook,
                    args,
                )
                .map(drop)
        })
    }

    /// Dispatch one event to this script: map it to its hook, run the hook over
    /// a `max_body`-capped snapshot, and apply or discard the result. `max_body`
    /// is the host's configured body cap, passed in so an appended script
    /// honours it too. The [`ScriptHost`] calls this for each loaded script;
    /// it is public so a test can drive one script in isolation.
    pub fn dispatch(&self, ev: &Event, ctx: &mut FlowCtx<'_>, max_body: usize) -> Verdict {
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

        let state = Arc::new(Mutex::new(FlowState::snapshot(ctx.flow(), ev, max_body)));
        let flow_id = lock(&state).id;
        let args = hook_args(ev, &state);

        // on_response is dispatched after the response has been forwarded to the
        // client, so a response write in it cannot reach the client; the setters
        // refuse it in this phase (spec §Design).
        let response_forwarded = matches!(ev, Event::Response(_));
        match self.call_hook(&ast, hook, &state, args, response_forwarded) {
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

/// The ordered, swappable set of loaded scripts the [`ScriptHost`] dispatches
/// and the command surface appends to. A clone shares the same backing list, so
/// a `script.save` through the command's handle is seen by the host's.
///
/// Reads (`snapshot`, on every event) are lock-free `ArcSwap` loads; a write
/// (`append`, on `script.save` of a new name) is a copy-on-write swap, so the
/// hot path never waits on a save and the order a save produces — the new
/// script last — is what the next event sees.
#[derive(Clone, Default)]
pub struct ScriptSet(Arc<ArcSwap<Vec<Arc<LoadedScript>>>>);

impl ScriptSet {
    /// A set over `scripts`, in the order given (declaration order from the
    /// loader, which is chain order).
    pub fn new(scripts: Vec<LoadedScript>) -> Self {
        let scripts: Vec<Arc<LoadedScript>> = scripts.into_iter().map(Arc::new).collect();
        Self(Arc::new(ArcSwap::from_pointee(scripts)))
    }

    /// The current list, for one event's dispatch or one command's read. A
    /// lock-free load: a concurrent `append` either is or is not visible, never
    /// a torn list.
    fn snapshot(&self) -> Arc<Vec<Arc<LoadedScript>>> {
        self.0.load_full()
    }

    /// Append `script` at the end — its chain position after every script
    /// already loaded (spec §8 order). Copy-on-write, so a dispatch reading the
    /// old list finishes on it and the next reads the new.
    pub fn append(&self, script: LoadedScript) {
        let script = Arc::new(script);
        self.0.rcu(|current| {
            let mut next = (**current).clone();
            next.push(Arc::clone(&script));
            next
        });
    }

    /// Append `script` only if no loaded script already has its name, deciding
    /// and pushing in one copy-on-write step. Returns `true` if it appended,
    /// `false` if a script of that name was already present.
    ///
    /// This closes the check-then-append race on `script.save` of a brand-new
    /// name: two concurrent saves of the same not-yet-loaded name must not both
    /// append, or the hook would run twice per event (double traffic mutation)
    /// and `script.list` would show a duplicate. The name check runs inside the
    /// `rcu` closure, so it sees the same snapshot the push extends and `rcu`
    /// retries the whole decision if another writer swapped in between — the
    /// last, committed run is the one `appended` reflects.
    pub fn append_if_absent(&self, script: LoadedScript) -> bool {
        let script = Arc::new(script);
        let mut appended = false;
        self.0.rcu(|current| {
            if current.iter().any(|s| s.name() == script.name()) {
                appended = false;
                (**current).clone()
            } else {
                let mut next = (**current).clone();
                next.push(Arc::clone(&script));
                appended = true;
                next
            }
        });
        appended
    }

    /// Whether any script is loaded.
    pub fn is_empty(&self) -> bool {
        self.0.load().is_empty()
    }

    /// How many scripts are loaded.
    pub fn len(&self) -> usize {
        self.0.load().len()
    }

    /// Every loaded script's handle, in chain order — what `script.list` reads.
    pub fn handles(&self) -> Vec<Arc<ScriptHandle>> {
        self.snapshot().iter().map(|s| s.handle()).collect()
    }

    /// The handle of the loaded script named `name`, if any — the lookup
    /// `script.reload` / `script.enable` / `script.disable` share.
    pub fn find_handle(&self, name: &str) -> Option<Arc<ScriptHandle>> {
        self.snapshot()
            .iter()
            .find(|s| s.name() == name)
            .map(|s| s.handle())
    }

    /// The loaded script names, in chain order — for the "no such script" miss
    /// message and for logging what is loaded.
    pub fn names(&self) -> Vec<String> {
        self.snapshot()
            .iter()
            .map(|s| s.name().to_string())
            .collect()
    }
}

/// The one `aitm_core::Plugin` the scripting tier registers: it holds the whole
/// [`ScriptSet`] and dispatches every loaded script in order from its single
/// chain position (the F8 Option-B dispatch model — see the module docs).
pub struct ScriptHost {
    set: ScriptSet,
    /// How much of a body each script's snapshot materializes — the proxy's
    /// configured cap, shared by every script including any appended at runtime.
    max_body: usize,
}

impl ScriptHost {
    /// A host over `set`. The body cap starts at the engine default;
    /// [`ScriptHost::with_max_body`] raises it to the proxy's configured cap.
    pub fn new(set: ScriptSet) -> Self {
        Self {
            set,
            max_body: LimitConfig::default().max_body_bytes,
        }
    }

    /// Cap the body bytes each script's snapshot copies.
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// The set this host dispatches — the same one the command surface appends
    /// to.
    pub fn set(&self) -> &ScriptSet {
        &self.set
    }
}

impl Plugin for ScriptHost {
    fn name(&self) -> &str {
        HOST_NAME
    }

    /// Run every loaded script's `load(reg)` once, in order, at startup.
    fn load(&mut self, reg: &mut Registry) {
        for script in self.set.snapshot().iter() {
            script.run_load(reg);
        }
    }

    /// Dispatch the event to each loaded script in chain order. A script's
    /// `halt()` short-circuits the rest, exactly as it short-circuits the chain
    /// after the host; a script's error is isolated and the host goes on.
    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        for script in self.set.snapshot().iter() {
            if script.dispatch(ev, ctx, self.max_body) == Verdict::Halt {
                return Verdict::Halt;
            }
        }
        Verdict::Continue
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
