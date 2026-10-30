//! Host core: `ScriptServices`, the `FindingSink`/`Finding` surface, the
//! `ScriptCapability` seam (spec §6a), and its first two providers — the
//! `log`/`finding`/`option` verbs (plan Task 6).
//!
//! Two per-run facts reach `option`/`finding` through the per-invocation
//! [`HostCallCtx`] the seam threads (plan `2026-10-29-aitmproxy-seam-per-invocation-context`
//! Task 5), so the one shared engine never has to know which script is calling,
//! and these verbs read them off the seam rather than rhai's `NativeCallContext`:
//!
//! - **Who is calling.** Each invocation boundary (hook dispatch, command invoke,
//!   `load`, a PoC `script:` step) seeds the script's source into the per-eval
//!   context (`seed_call_context`); `finding(...)` reads it back off
//!   [`HostCallCtx::call_source`] and records it as [`Finding::source`] (an
//!   unnamed source stays `"<unnamed script>"`).
//! - **The script's options.** The same boundary seeds the script's [`Options`]
//!   as the per-eval *tag* (a rhai-free [`Value::Object`], via [`Options::to_value`]);
//!   `option(name)` reads it off [`HostCallCtx::tag`]. A run whose boundary seeded
//!   no options (a PoC step, a bare run) has no tag and every `option(...)` is `()`.
//!
//! Both verbs are [`Guarded`] host fns dispatched through
//! [`run_seam_global`](crate::host_registry::run_seam_global) — kept GLOBAL rhai
//! functions so the call syntax `option(...)` / `finding(#{…})` is unchanged — and
//! are refused fail-closed when an eval reaches them without a seeded caller
//! context (never defaulted to operator).
//!
//! The guarded async namespaces (`http`, `browser`, `store`, `scope`) are
//! Task 7's providers in `host_net`.

use std::collections::{BTreeMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use aitm_core::{BrowserDriver, FlowId, FlowStore, ProxyClient, ScopeRateGuard, Value};
use aitm_plugin::language::{GuardHandle, Guarded, HostCallCtx, HostError, HostFn};
use aitm_poc::Severity;
use rhai::{Dynamic, Engine, EvalAltResult, Module, Position};

use crate::host_registry::run_seam_global;
use crate::marshal::{dynamic_to_value, value_to_dynamic};

/// The host services a script may reach: exactly the handles `CommandHost`
/// exposes, plus the runtime handle the async bridge blocks on (spec §4).
#[derive(Clone)]
pub struct ScriptServices {
    pub store: Arc<dyn FlowStore>,
    pub client: Arc<dyn ProxyClient>,
    pub browser: Option<Arc<dyn BrowserDriver>>,
    pub guard: Arc<dyn ScopeRateGuard>,
    pub findings: Arc<dyn FindingSink>,
    pub rt: tokio::runtime::Handle,
}

/// Where `finding(...)` deposits observations; the command surface
/// (`script.findings`) reads them back. Reporting only — a sink never acts on
/// what it is given.
pub trait FindingSink: Send + Sync {
    fn record(&self, f: Finding);
    /// Everything retained, oldest first.
    fn list(&self) -> Vec<Finding>;
    /// How many findings a bounded sink has discarded to stay bounded.
    fn dropped(&self) -> u64 {
        0
    }
}

/// One structured observation a script reported against the run.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub name: String,
    pub severity: Severity,
    pub flow: Option<FlowId>,
    pub detail: Option<String>,
    pub tags: Vec<String>,
    /// The script that emitted it.
    pub source: String,
    pub at: SystemTime,
}

/// The default sink: a ring of the newest findings, in the order reported. A
/// hook that records on every request of a long engagement cannot grow it
/// without bound; what falls off the front is counted in [`FindingSink::dropped`].
pub struct MemoryFindingSink {
    findings: Mutex<VecDeque<Finding>>,
    capacity: usize,
    dropped: AtomicU64,
}

/// Findings the default sink retains: plenty for an engagement's observations,
/// bounded for a hook that reports per request.
pub const DEFAULT_FINDING_CAPACITY: usize = 10_000;

impl Default for MemoryFindingSink {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_FINDING_CAPACITY)
    }
}

impl MemoryFindingSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink that keeps at most `capacity` findings (the newest).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            findings: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
        }
    }
}

impl FindingSink for MemoryFindingSink {
    fn record(&self, f: Finding) {
        let mut findings = self.findings.lock().unwrap_or_else(PoisonError::into_inner);
        if findings.len() >= self.capacity {
            findings.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        findings.push_back(f);
    }

    fn list(&self) -> Vec<Finding> {
        self.findings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A script's option values, by name (`reg.add_option` defaults overlaid by the
/// config entry's `options:`). Passed to a run as its Rhai tag so `option(name)`
/// can find it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Options(BTreeMap<String, Value>);

impl Options {
    pub fn new(values: BTreeMap<String, Value>) -> Self {
        Self(values)
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        self.0.insert(name.into(), value)
    }

    /// This option set as a seam [`Value::Object`], the shape an invocation
    /// boundary seeds as the per-eval **tag** (`seed_call_context`) so the
    /// seam-migrated `option(name)` can read it via [`HostCallCtx::tag`]. Replaces
    /// the pre-seam rhai `CallFnOptions::with_tag(Options)` custom-type tag, which
    /// the rhai-free seam could not carry.
    pub fn to_value(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

/// The guard for the first-party `option`/`finding` verbs. `option` is a forgiving
/// read of the run's options and `finding` is a report-only sink — neither reaches
/// the wire nor is agent-gated, so this guard deliberately **overrides** the seam's
/// deny-by-default to admit every call. The per-call caller trust still rides in
/// [`HostCallCtx`], and [`run_seam_global`] still refuses an *unseeded* eval
/// fail-closed before this guard is consulted; what this guard documents is that,
/// *once seeded*, these two verbs are open to operator and agent alike (unlike an
/// `l4.*` effect).
struct FirstPartyGuard;

impl GuardHandle for FirstPartyGuard {
    fn guard_name(&self) -> &str {
        "core"
    }

    fn permit(&self, _ctx: &HostCallCtx, _fn_name: &str) -> Result<(), HostError> {
        Ok(())
    }
}

/// One capability == one namespace of script verbs (spec §6a). The engine
/// builder is handed a list of providers and registers each; a namespace that
/// is not registered simply does not exist for scripts (deny by default). A
/// future protocol crate adds its own provider with no change here.
pub trait ScriptCapability: Send + Sync {
    /// Namespace as scripts see it: `"log"`, `"http"`, `"browser"`, `"store"`,
    /// `"scope"`, `"finding"` today.
    fn namespace(&self) -> &str;
    /// Lowest `const API` a script must declare to be offered this namespace.
    fn min_api(&self) -> &str;
    /// Register this namespace's verbs into the shared engine, wired to the
    /// shared services and the guard. Called once when the engine is built.
    fn register(&self, engine: &mut Engine, services: &ScriptServices);
}

/// The `API` version M3's own providers require: the first and only one.
const API_1: &str = "1";

/// The `log` namespace — `log.info` / `log.warn` / `log.error` and the bare
/// `log(msg)` shorthand (same as `log.info`) — all routed to `tracing`, plus the
/// script-context read `option(name)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogCapability;

/// The `finding(#{ name, severity, flow_id?, detail?, tags? })` verb: record an
/// observation through the services' [`FindingSink`]. Reporting only.
#[derive(Debug, Clone, Copy, Default)]
pub struct FindingCapability;

/// The value behind the script-visible `log` constant. Carries nothing: the
/// methods on it only need the message.
#[derive(Debug, Clone, Copy)]
struct LogNs;

/// Log target for everything a script says, so an operator can filter it.
const SCRIPT_TARGET: &str = "aitm_plugin_rhai::script";

impl ScriptCapability for LogCapability {
    fn namespace(&self) -> &str {
        "log"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, _services: &ScriptServices) {
        engine
            .register_type_with_name::<LogNs>("log")
            .register_fn("info", |_: &mut LogNs, msg: &str| {
                tracing::info!(target: SCRIPT_TARGET, "{msg}");
            })
            .register_fn("warn", |_: &mut LogNs, msg: &str| {
                tracing::warn!(target: SCRIPT_TARGET, "{msg}");
            })
            .register_fn("error", |_: &mut LogNs, msg: &str| {
                tracing::error!(target: SCRIPT_TARGET, "{msg}");
            })
            .register_fn("log", |msg: &str| {
                tracing::info!(target: SCRIPT_TARGET, "{msg}");
            });

        // `option(name)` on the host-fn seam: a `Guarded<HostFn>` reading the
        // per-eval tag off `HostCallCtx` (the options the boundary seeds), kept a
        // GLOBAL rhai fn so `option("x")` is unchanged (AC7). Option C: an unset
        // option — or a run whose boundary seeded no options — reads as `()`,
        // never an error.
        let option_fn: HostFn = Box::new(|ctx: &HostCallCtx, args: &[Value]| {
            let name = match args.first() {
                Some(Value::Str(name)) => name.as_str(),
                _ => return Ok(Value::Null),
            };
            match ctx.tag() {
                Some(Value::Object(options)) => {
                    Ok(options.get(name).cloned().unwrap_or(Value::Null))
                }
                _ => Ok(Value::Null),
            }
        });
        let (option_guard, option_fn) =
            Guarded::new(Box::new(FirstPartyGuard), option_fn).into_parts();
        engine.register_fn(
            "option",
            move |name: &str| -> Result<Dynamic, Box<EvalAltResult>> {
                let out = run_seam_global(
                    "log",
                    "option",
                    option_guard.as_ref(),
                    &option_fn,
                    &[Value::Str(name.to_string())],
                )
                .map_err(host_error)?;
                Ok(value_to_dynamic(&out))
            },
        );

        // `log` is a global constant so `log.warn("…")` reads as a namespace.
        let mut module = Module::new();
        module.set_var("log", LogNs);
        engine.register_global_module(module.into());
    }
}

impl ScriptCapability for FindingCapability {
    fn namespace(&self) -> &str {
        "finding"
    }

    fn min_api(&self) -> &str {
        API_1
    }

    fn register(&self, engine: &mut Engine, services: &ScriptServices) {
        let sink = Arc::clone(&services.findings);
        // `finding(...)` on the host-fn seam: a `Guarded<HostFn>` reading the
        // call's provenance off `HostCallCtx::call_source()` (the source the
        // boundary seeds), kept a GLOBAL rhai fn so `finding(#{…})` is unchanged
        // (AC7). The seam context carries no source for a boundary that named none
        // (empty string), preserved as the historical `"<unnamed script>"`.
        let finding_fn: HostFn = Box::new(move |ctx: &HostCallCtx, args: &[Value]| {
            let source = ctx.call_source();
            let source = if source.is_empty() {
                "<unnamed script>"
            } else {
                source
            };
            let map = args
                .first()
                .ok_or_else(|| HostError::BadArgs("finding(...) takes a map".to_string()))?;
            let finding = parse_finding(map, source)?;
            sink.record(finding);
            Ok(Value::Null)
        });
        let (guard, finding_fn) = Guarded::new(Box::new(FirstPartyGuard), finding_fn).into_parts();
        engine.register_fn(
            "finding",
            move |map: rhai::Map| -> Result<Dynamic, Box<EvalAltResult>> {
                // Marshal the rhai map to a rhai-free `Value` before it crosses the
                // seam; a value the bus cannot carry is the same catchable error as
                // before the migration.
                let value = dynamic_to_value(&Dynamic::from_map(map))
                    .map_err(|err| finding_error(format!("finding(...): {err}")))?;
                let out = run_seam_global(
                    "finding",
                    "finding",
                    guard.as_ref(),
                    &finding_fn,
                    std::slice::from_ref(&value),
                )
                .map_err(host_error)?;
                Ok(value_to_dynamic(&out))
            },
        );
    }
}

/// The keys `finding(...)` accepts, for the error a typo gets.
const FINDING_KEYS: [&str; 5] = ["name", "severity", "flow_id", "detail", "tags"];

/// Turn the script's `#{ … }` into a [`Finding`], or an error that says which
/// field is wrong and what it should be (ergonomics rule 6). Reporting is an
/// action, so malformed input is refused, not forgiven.
fn parse_finding(map: &Value, source: &str) -> Result<Finding, HostError> {
    let fields = match map {
        Value::Object(fields) => fields,
        _ => return Err(bad("finding(...) takes a map")),
    };

    if let Some(unknown) = fields.keys().find(|k| !FINDING_KEYS.contains(&k.as_str())) {
        return Err(bad(format!(
            "finding(...) has no field '{unknown}'; the fields are {}",
            FINDING_KEYS.join(", ")
        )));
    }

    let name = match str_field(fields, "name")? {
        Some(name) if !name.is_empty() => name,
        _ => return Err(bad("finding(...) needs a non-empty 'name' string")),
    };

    let severity = match str_field(fields, "severity")? {
        Some(text) => parse_severity(&text).ok_or_else(|| {
            bad(format!(
                "finding(...) has unknown severity \"{text}\"; use info, low, medium, high or critical"
            ))
        })?,
        None => return Err(bad("finding(...) needs a 'severity' string")),
    };

    let flow = match str_field(fields, "flow_id")? {
        Some(id) => Some(FlowId::from_str(&id).map_err(|_| {
            bad(format!(
                "finding(...) 'flow_id' must be a flow id like flow.id, got \"{id}\""
            ))
        })?),
        None => None,
    };

    let detail = str_field(fields, "detail")?;

    let tags = match fields.get("tags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Str(tag) => Ok(tag.clone()),
                other => Err(bad(format!(
                    "finding(...) 'tags' must be an array of strings, found {}",
                    value_kind(other)
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(other) => {
            return Err(bad(format!(
                "finding(...) 'tags' must be an array of strings, got {}",
                value_kind(other)
            )))
        }
    };

    Ok(Finding {
        name,
        severity,
        flow,
        detail,
        tags,
        source: source.to_string(),
        at: SystemTime::now(),
    })
}

/// An optional string field; present-but-not-a-string is an error naming it.
fn str_field(fields: &BTreeMap<String, Value>, key: &str) -> Result<Option<String>, HostError> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(other) => Err(bad(format!(
            "finding(...) '{key}' must be a string, got {}",
            value_kind(other)
        ))),
    }
}

/// The nuclei severity vocabulary `Severity` serializes as — the inverse of
/// [`parse_severity`], for `script.findings`.
pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// The nuclei severity vocabulary `Severity` serializes as, any case.
fn parse_severity(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// What a value is, in the words a script author uses.
fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "()",
        Value::Bool(_) => "a bool",
        Value::Int(_) => "an int",
        Value::Float(_) => "a float",
        Value::Str(_) => "a string",
        Value::Bytes(_) => "a blob",
        Value::Array(_) => "an array",
        Value::Object(_) => "a map",
    }
}

/// A seam [`HostError`] for a malformed `finding(...)` argument: the host-fn body
/// reads only `aitm_core` types, so its parse failures surface as the seam's
/// rhai-free [`HostError::BadArgs`]. [`run_seam_global`]'s caller turns it into the
/// same catchable Rhai runtime error [`finding_error`] builds, so the script sees
/// an identical message before and after the migration.
fn bad(message: impl Into<String>) -> HostError {
    HostError::BadArgs(message.into())
}

/// A seam [`HostError`] as the script catches it: a catchable Rhai runtime error
/// carrying the one-line message. Used where the global `option`/`finding` bridge
/// turns a seam result back into a Rhai value.
fn host_error(err: HostError) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(err.to_string()), Position::NONE).into()
}

/// A catchable runtime error; the engine fills in the call position. Kept for the
/// `finding` bridge's pre-seam marshalling step (a rhai map the bus cannot carry),
/// which fails before the value crosses into the rhai-free host fn.
fn finding_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}
