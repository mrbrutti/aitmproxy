//! The intercept plugin: an arm-able mode that parks requests as a pausable
//! future (data-flow 2), plus the commands that release a parked flow.
//!
//! `flow.intercept {enabled?, rules?}` arms or disarms the mode. With no rules it
//! parks *every* request (today's global arm, back-compatible); with rules it
//! parks only a flow that matches a rule at its phase (F3 selective
//! interception, via the shared [`aitm_rules`] matcher) — a request rule at
//! `Event::Request`, a response rule at `Event::ResponseHeaders` (the point Task 2
//! pinned as the last instant before any response byte reaches the client, so a
//! parked response can be edited via `flow.mutate`). While armed and a flow
//! is to be parked, `on_event` backs the flow up and parks it; the chain
//! then awaits the `ResumeHandle` this plugin keeps per flow. `flow.resume` fires
//! that handle so the parked future wakes and forwards the (possibly mutated)
//! request; `flow.kill` marks the flow killed and wakes the future so the client
//! sees the connection dropped.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aitm_core::{
    Body, Command, CommandHost, Event, Flow, FlowCtx, FlowId, HeaderMap, HttpResponse,
    InterceptState, ParamDef, ParamSchema, Params, Plugin, Registry, ResumeHandle, TypeDesc, Value,
    Verdict,
};
use aitm_rules::{bus, compile, CompiledRule, Phase, Rule};

/// State the plugin (which parks flows on events) shares with its commands
/// (which release them).
#[derive(Default)]
struct Shared {
    /// Shared so a read-only observer (e.g. `proxy.status`) can learn the armed
    /// state without reaching into this plugin.
    armed: Arc<AtomicBool>,
    parked: Mutex<HashMap<FlowId, ResumeHandle>>,
    /// The active breakpoint rules (set by `flow.intercept {rules}`). Empty means
    /// "park every request" — the back-compatible global arm. Non-empty means
    /// "park only a request matching a rule at `Phase::Request`".
    rules: Mutex<Vec<CompiledRule>>,
}

/// Registers `flow.intercept`, `flow.resume`, `flow.kill`; parks requests while
/// armed.
pub struct InterceptPlugin {
    shared: Arc<Shared>,
}

impl InterceptPlugin {
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
        }
    }

    /// A shared handle to the armed flag, so `proxy.status` can report whether
    /// interception is armed. Reads reflect `flow.intercept`; this never arms it.
    pub fn armed_flag(&self) -> Arc<AtomicBool> {
        self.shared.armed.clone()
    }
}

impl Default for InterceptPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for InterceptPlugin {
    fn name(&self) -> &str {
        "intercept"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowIntercept {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(FlowResume {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(FlowKill {
            shared: self.shared.clone(),
        }));
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        // A flow parks at the request phase (`Event::Request`) or — for a response
        // rule — at `Event::ResponseHeaders`, the point Task 2 pinned as the last
        // instant before any response byte reaches the client (see
        // `aitm-proto-http/tests/response_park.rs`).
        let park = match ev {
            Event::Request(id) => (self.shared.armed.load(Ordering::SeqCst)
                && self.should_park(ctx, Phase::Request))
            .then_some(*id),
            Event::ResponseHeaders(id) => (self.shared.armed.load(Ordering::SeqCst)
                && self.should_park(ctx, Phase::Response))
            .then_some(*id),
            _ => None,
        };
        if let Some(id) = park {
            ctx.backup();
            let handle = ctx.intercept();
            if let Ok(mut parked) = self.shared.parked.lock() {
                parked.insert(id, handle);
            }
        }
        Verdict::Continue
    }
}

impl InterceptPlugin {
    /// Whether this flow should park at `phase`. With no rules the mode is the
    /// back-compatible global arm: it parks every request but no response (a
    /// response parks only under an explicit response rule). With rules it parks
    /// only a flow that matches a rule at `phase` (`Phase::Any` rules fire too).
    fn should_park(&self, ctx: &FlowCtx<'_>, phase: Phase) -> bool {
        let rules = match self.shared.rules.lock() {
            Ok(rules) => rules,
            // A poisoned lock means a prior panic; fail safe to the global arm.
            Err(poisoned) => poisoned.into_inner(),
        };
        if rules.is_empty() {
            return phase == Phase::Request;
        }
        let flow = ctx.flow();
        rules.iter().any(|rule| rule.matches(flow, phase, None))
    }
}

fn id_param(description: &str) -> ParamDef {
    ParamDef {
        name: "id".into(),
        ty: TypeDesc::FlowId,
        required: true,
        description: description.into(),
    }
}

/// `flow.intercept {enabled?, rules?}` → arm (default) or disarm, optionally with
/// breakpoint rules; returns `{enabled, rules}`.
struct FlowIntercept {
    shared: Arc<Shared>,
}

impl Command for FlowIntercept {
    fn name(&self) -> &str {
        "flow.intercept"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Arm (default) or disarm interception. With no rules every request is \
                          parked (global arm); with rules only a request matching a rule at its \
                          phase is parked. A parked flow waits for flow.resume or flow.kill."
                .into(),
            params: vec![
                ParamDef {
                    name: "enabled".into(),
                    ty: TypeDesc::Bool,
                    required: false,
                    description: "true to arm (default), false to disarm.".into(),
                },
                ParamDef {
                    name: "rules".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Object(rule_param_fields()))),
                    required: false,
                    description: "Breakpoint rules; replaces the active set. Omit to leave the \
                                  current rules unchanged; an empty array restores the global arm. \
                                  An invalid regex rejects the whole call."
                        .into(),
                },
            ],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "enabled".into(),
                    ty: TypeDesc::Bool,
                    required: true,
                    description: "Whether interception is now armed.".into(),
                },
                ParamDef {
                    name: "rules".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Object(rule_param_fields()))),
                    required: true,
                    description: "The active breakpoint rules.".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let enabled = match args.get("enabled") {
            None => true,
            Some(_) => args.get_bool("enabled")?,
        };

        // Compile any supplied rules *before* touching shared state, so a bad
        // regex (or malformed rule) aborts the call without clobbering the active
        // rules. `rules` absent means "leave the current set alone".
        let compiled = match args.get("rules") {
            None => None,
            Some(value) => Some(compile_rules(value)?),
        };

        if let Some(compiled) = compiled {
            *self
                .shared
                .rules
                .lock()
                .map_err(|_| anyhow::anyhow!("intercept rules poisoned"))? = compiled;
        }
        self.shared.armed.store(enabled, Ordering::SeqCst);

        let rules = rules_to_value(
            &self
                .shared
                .rules
                .lock()
                .map_err(|_| anyhow::anyhow!("intercept rules poisoned"))?,
        );
        Ok(Value::Object(BTreeMap::from([
            ("enabled".into(), Value::Bool(enabled)),
            ("rules".into(), rules),
        ])))
    }
}

/// The field set of one rule object, used for both the `rules` input param and
/// the returned rules (drives the MCP tool schema).
fn rule_param_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, description: &str| ParamDef {
        name: name.into(),
        ty,
        required: false,
        description: description.into(),
    };
    vec![
        field(
            "id",
            TypeDesc::Str,
            "Stable rule id; server-assigned if omitted.",
        ),
        field("name", TypeDesc::Str, "Human label for the rule."),
        field(
            "enabled",
            TypeDesc::Bool,
            "Whether the rule is active (default true).",
        ),
        field(
            "phase",
            TypeDesc::Str,
            "Lifecycle point: request (default), response, wsframe, or any.",
        ),
        field(
            "url",
            TypeDesc::Any,
            "URL match: a wildcard string (* = any run), or {wildcard} / {regex}.",
        ),
        field(
            "method",
            TypeDesc::Str,
            "Case-insensitive HTTP method; omit for any.",
        ),
        field(
            "host",
            TypeDesc::Any,
            "Host match: an exact authority string, or {exact} / {wildcard}.",
        ),
        field(
            "ws_dir",
            TypeDesc::Str,
            "WebSocket frame direction: c2s or s2c.",
        ),
    ]
}

/// Compile every rule object in a `rules` array, mapping a bad regex (or a
/// malformed rule) to an `Err` that aborts the `flow.intercept` call.
fn compile_rules(value: &Value) -> anyhow::Result<Vec<CompiledRule>> {
    let Value::Array(items) = value else {
        anyhow::bail!("param `rules` must be an array of rule objects");
    };
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let rule = rule_from_value(item, idx)?;
            compile(rule).map_err(|e| anyhow::anyhow!(e))
        })
        .collect()
}

/// Parse one rule object off the bus via the shared [`aitm_rules::bus`] serde.
/// `idx` seeds a stable id when none is given; a request-phase rule is the default.
fn rule_from_value(value: &Value, idx: usize) -> anyhow::Result<Rule> {
    let Value::Object(obj) = value else {
        anyhow::bail!("each rule must be an object");
    };
    bus::parse_rule(obj, &format!("rule-{idx}"), Phase::Request)
}

/// Serialize the active rules back to the bus through the shared echo, so the
/// phase/ws_dir/url/host tokens match every other rule surface.
fn rules_to_value(rules: &[CompiledRule]) -> Value {
    Value::Array(rules.iter().map(|r| bus::rule_to_value(r.rule())).collect())
}

/// `flow.resume {id}` → fire the parked flow's handle; it forwards.
struct FlowResume {
    shared: Arc<Shared>,
}

impl Command for FlowResume {
    fn name(&self) -> &str {
        "flow.resume"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Release an intercepted flow so its (possibly mutated) request is forwarded.".into(),
            params: vec![id_param("The intercepted flow to resume.")],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        release(&self.shared, host, args.get_flow_id("id")?, Release::Resume)
    }
}

/// `flow.kill {id, mode?}` → abort the parked flow. `reset` (default) drops it so
/// the client sees a reset/closed connection; `429`/`503` synthesize that status
/// to the client with no upstream call.
struct FlowKill {
    shared: Arc<Shared>,
}

impl Command for FlowKill {
    fn name(&self) -> &str {
        "flow.kill"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Abort an intercepted flow. mode=reset (default) drops it so the client \
                          sees a reset/closed connection; mode=429 or mode=503 answers the client \
                          with that status and an empty body, with no upstream request."
                .into(),
            params: vec![
                id_param("The intercepted flow to kill."),
                ParamDef {
                    name: "mode".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Abort mode: reset (default), 429, or 503.".into(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let how = match args.get("mode") {
            None => Release::Reset,
            Some(_) => parse_kill_mode(args.get_str("mode")?)?,
        };
        release(&self.shared, host, args.get_flow_id("id")?, how)
    }
}

/// Parse the `flow.kill` `mode`: `reset` keeps the drop behaviour; `429`/`503`
/// synthesize that status. Any other value is an `Err`.
fn parse_kill_mode(mode: &str) -> anyhow::Result<Release> {
    match mode {
        "reset" => Ok(Release::Reset),
        "429" => Ok(Release::Synthesize(429)),
        "503" => Ok(Release::Synthesize(503)),
        other => anyhow::bail!("unknown kill mode `{other}` (want reset, 429, or 503)"),
    }
}

enum Release {
    Resume,
    /// Drop the flow; the client sees a reset/closed connection.
    Reset,
    /// Short-circuit: answer the client with this status and an empty body, with
    /// no upstream connection.
    Synthesize(u16),
}

/// Release a parked flow: record its new state (and, for a synthesized abort, its
/// response) in the store, then wake the parked future. The handle is the one this
/// plugin parked, or — for a flow another plugin parked — the one its stored
/// `Intercepted` state carries.
fn release(shared: &Shared, host: &CommandHost, id: FlowId, how: Release) -> anyhow::Result<Value> {
    let parked = shared
        .parked
        .lock()
        .map_err(|_| anyhow::anyhow!("intercept state poisoned"))?
        .remove(&id);
    let handle = match parked {
        Some(handle) => handle,
        None => stored_handle(host, id)?,
    };
    // A synthesized abort is `Resumed` with a response already set: the HTTP module
    // short-circuits to the client before any upstream connect. A `reset` abort is
    // `Killed` and drops the connection. Neither opens an upstream connection.
    let (state, label, synth) = match how {
        Release::Resume => (InterceptState::Resumed, "resumed", None),
        Release::Reset => (InterceptState::Killed, "killed", None),
        Release::Synthesize(status) => (InterceptState::Resumed, "killed", Some(status)),
    };
    host.store().update(id, &mut |flow: &mut Flow| {
        if let Some(status) = synth {
            set_short_circuit(flow, status);
        }
        set_intercept(flow, state.clone());
    });
    handle.fire();
    Ok(Value::Str(label.into()))
}

/// Attach a minimal synthesized response (given status, empty body) to an HTTP
/// flow so the module answers the client without an upstream request. Mirrors
/// [`FlowCtx::set_response`] for a flow released outside an event.
fn set_short_circuit(flow: &mut Flow, status: u16) {
    if let Flow::Http(f) = flow {
        f.response = Some(HttpResponse {
            status,
            version: f.request.version,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        });
    }
}

/// The resume handle a stored flow's `Intercepted` state carries.
fn stored_handle(host: &CommandHost, id: FlowId) -> anyhow::Result<ResumeHandle> {
    let flow = host
        .store()
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))?;
    let state = match &flow {
        Flow::Http(f) => &f.intercept,
        Flow::WebSocket(f) => &f.intercept,
    };
    match state {
        InterceptState::Intercepted { resume, .. } => Ok(resume.clone()),
        _ => anyhow::bail!("flow {id} is not intercepted"),
    }
}

fn set_intercept(flow: &mut Flow, state: InterceptState) {
    match flow {
        Flow::Http(f) => f.intercept = state,
        Flow::WebSocket(f) => f.intercept = state,
    }
}
