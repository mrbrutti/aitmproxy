//! Host core: `ScriptServices`, the `FindingSink`/`Finding` surface, the
//! `ScriptCapability` seam (spec §6a), and its first two providers — the
//! `log`/`finding`/`option` verbs (plan Task 6).
//!
//! Two per-run facts reach a host verb through Rhai itself, so the one shared
//! engine never has to know which script is calling:
//!
//! - **Who is calling.** The loader names each compiled `AST` after its script
//!   (`AST::set_source`); `finding(...)` reads it back as the caller's source
//!   and records it as `Finding::source`.
//! - **The script's options.** The hook dispatcher passes the script's
//!   [`Options`] as the run's *tag* (`CallFnOptions::with_tag`); `option(name)`
//!   reads the tag. A run with no tag (a PoC step, a bare `run`) has no options
//!   and every `option(...)` is `()`.
//!
//! The guarded async namespaces (`http`, `browser`, `store`, `scope`) are
//! Task 7's providers in `host_net`.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use aitm_core::{BrowserDriver, FlowId, FlowStore, ProxyClient, ScopeRateGuard, Value};
use aitm_poc::Severity;
use rhai::{Dynamic, Engine, EvalAltResult, Module, NativeCallContext, Position};

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

/// Where `finding(...)` deposits observations; the command surface reads them
/// back. Reporting only — a sink never acts on what it is given.
pub trait FindingSink: Send + Sync {
    fn record(&self, f: Finding);
    fn list(&self) -> Vec<Finding>;
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

/// The default sink: findings kept in memory, in the order reported.
#[derive(Default)]
pub struct MemoryFindingSink(Mutex<Vec<Finding>>);

impl MemoryFindingSink {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FindingSink for MemoryFindingSink {
    fn record(&self, f: Finding) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(f);
    }

    fn list(&self) -> Vec<Finding> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
            })
            .register_fn("option", |ctx: NativeCallContext, name: &str| -> Dynamic {
                // Option C: an unset option — or a run with no options at all
                // — reads as `()`, never an error.
                ctx.tag()
                    .and_then(|tag| tag.read_lock::<Options>())
                    .and_then(|options| options.get(name).map(value_to_dynamic))
                    .unwrap_or(Dynamic::UNIT)
            });

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
        engine.register_fn(
            "finding",
            move |ctx: NativeCallContext, map: rhai::Map| -> Result<(), Box<EvalAltResult>> {
                let source = ctx.call_source().unwrap_or("<unnamed script>");
                let finding = parse_finding(map, source)?;
                sink.record(finding);
                Ok(())
            },
        );
    }
}

/// The keys `finding(...)` accepts, for the error a typo gets.
const FINDING_KEYS: [&str; 5] = ["name", "severity", "flow_id", "detail", "tags"];

/// Turn the script's `#{ … }` into a [`Finding`], or an error that says which
/// field is wrong and what it should be (ergonomics rule 6). Reporting is an
/// action, so malformed input is refused, not forgiven.
fn parse_finding(map: rhai::Map, source: &str) -> Result<Finding, Box<EvalAltResult>> {
    let fields = match dynamic_to_value(&Dynamic::from_map(map)) {
        Ok(Value::Object(fields)) => fields,
        Ok(_) => return Err(finding_error("finding(...) takes a map")),
        Err(err) => return Err(finding_error(format!("finding(...): {err}"))),
    };

    if let Some(unknown) = fields.keys().find(|k| !FINDING_KEYS.contains(&k.as_str())) {
        return Err(finding_error(format!(
            "finding(...) has no field '{unknown}'; the fields are {}",
            FINDING_KEYS.join(", ")
        )));
    }

    let name = match str_field(&fields, "name")? {
        Some(name) if !name.is_empty() => name,
        _ => {
            return Err(finding_error(
                "finding(...) needs a non-empty 'name' string",
            ))
        }
    };

    let severity = match str_field(&fields, "severity")? {
        Some(text) => parse_severity(&text).ok_or_else(|| {
            finding_error(format!(
                "finding(...) has unknown severity \"{text}\"; use info, low, medium, high or critical"
            ))
        })?,
        None => return Err(finding_error("finding(...) needs a 'severity' string")),
    };

    let flow = match str_field(&fields, "flow_id")? {
        Some(id) => Some(FlowId::from_str(&id).map_err(|_| {
            finding_error(format!(
                "finding(...) 'flow_id' must be a flow id like flow.id, got \"{id}\""
            ))
        })?),
        None => None,
    };

    let detail = str_field(&fields, "detail")?;

    let tags = match fields.get("tags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Str(tag) => Ok(tag.clone()),
                other => Err(finding_error(format!(
                    "finding(...) 'tags' must be an array of strings, found {}",
                    value_kind(other)
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(other) => {
            return Err(finding_error(format!(
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
fn str_field(
    fields: &BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<String>, Box<EvalAltResult>> {
    match fields.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s.clone())),
        Some(other) => Err(finding_error(format!(
            "finding(...) '{key}' must be a string, got {}",
            value_kind(other)
        ))),
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

/// A catchable runtime error; the engine fills in the call position.
fn finding_error(message: impl Into<String>) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.into()), Position::NONE).into()
}
