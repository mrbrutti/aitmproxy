//! The intercept plugin: an arm-able mode that parks requests as a pausable
//! future (data-flow 2), plus the commands that release a parked flow.
//!
//! `flow.intercept {enabled?, rules?}` arms or disarms the mode. With no rules it
//! parks *every* request (today's global arm, back-compatible); with rules it
//! parks only a request that matches a rule at `Phase::Request` (F3 selective
//! interception, via the shared [`aitm_rules`] matcher). While armed and a flow
//! is to be parked, `on_event(Request)` backs the flow up and parks it; the chain
//! then awaits the `ResumeHandle` this plugin keeps per flow. `flow.resume` fires
//! that handle so the parked future wakes and forwards the (possibly mutated)
//! request; `flow.kill` marks the flow killed and wakes the future so the client
//! sees the connection dropped.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aitm_core::{
    Command, CommandHost, Event, Flow, FlowCtx, FlowId, InterceptState, ParamDef, ParamSchema,
    Params, Plugin, Registry, ResumeHandle, TypeDesc, Value, Verdict,
};
use aitm_rules::{CompiledRule, HostMatch, MatchCondition, Phase, Rule, UrlMatch};

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
        if let Event::Request(id) = ev {
            if self.shared.armed.load(Ordering::SeqCst) && self.should_park_request(ctx) {
                ctx.backup();
                let handle = ctx.intercept();
                if let Ok(mut parked) = self.shared.parked.lock() {
                    parked.insert(*id, handle);
                }
            }
        }
        Verdict::Continue
    }
}

impl InterceptPlugin {
    /// Whether this request should park. With no rules the mode parks every
    /// request (global arm); with rules it parks only a request that matches a
    /// rule at `Phase::Request` (`Phase::Any` rules fire here too).
    fn should_park_request(&self, ctx: &FlowCtx<'_>) -> bool {
        let rules = match self.shared.rules.lock() {
            Ok(rules) => rules,
            // A poisoned lock means a prior panic; fail safe to the global arm.
            Err(poisoned) => poisoned.into_inner(),
        };
        if rules.is_empty() {
            return true;
        }
        let flow = ctx.flow();
        rules
            .iter()
            .any(|rule| rule.matches(flow, Phase::Request, None))
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
            aitm_rules::compile(rule).map_err(|e| anyhow::anyhow!(e))
        })
        .collect()
}

/// Parse one rule object off the bus. `idx` seeds a stable id when none is given.
fn rule_from_value(value: &Value, idx: usize) -> anyhow::Result<Rule> {
    let Value::Object(obj) = value else {
        anyhow::bail!("each rule must be an object");
    };
    let str_field = |key: &str| -> anyhow::Result<Option<String>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s.clone())),
            Some(other) => anyhow::bail!("rule field `{key}` must be a string, got {other:?}"),
        }
    };

    let id = str_field("id")?.unwrap_or_else(|| format!("rule-{idx}"));
    let name = str_field("name")?;
    let enabled = match obj.get("enabled") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => anyhow::bail!("rule field `enabled` must be a boolean, got {other:?}"),
    };
    let phase = parse_phase(str_field("phase")?.as_deref())?;
    let url = obj.get("url").map(parse_url_match).transpose()?;
    let method = str_field("method")?;
    let host = obj.get("host").map(parse_host_match).transpose()?;
    let ws_dir = parse_ws_dir(str_field("ws_dir")?.as_deref())?;

    Ok(Rule {
        id,
        name,
        enabled,
        condition: MatchCondition {
            url,
            method,
            host,
            phase,
            ws_dir,
        },
    })
}

fn parse_phase(phase: Option<&str>) -> anyhow::Result<Phase> {
    match phase {
        None => Ok(Phase::Request),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "request" => Ok(Phase::Request),
            "response" => Ok(Phase::Response),
            "wsframe" => Ok(Phase::WsFrame),
            "any" => Ok(Phase::Any),
            other => anyhow::bail!("unknown rule phase `{other}`"),
        },
    }
}

fn parse_ws_dir(dir: Option<&str>) -> anyhow::Result<Option<aitm_core::WsDir>> {
    match dir {
        None => Ok(None),
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "c2s" => Ok(Some(aitm_core::WsDir::ClientToServer)),
            "s2c" => Ok(Some(aitm_core::WsDir::ServerToClient)),
            other => anyhow::bail!("unknown ws_dir `{other}` (want c2s or s2c)"),
        },
    }
}

/// A URL clause: a bare string is a wildcard; an object selects wildcard/regex.
fn parse_url_match(value: &Value) -> anyhow::Result<UrlMatch> {
    match value {
        Value::Str(s) => Ok(UrlMatch::Wildcard(s.clone())),
        Value::Object(o) => match single_variant(o, "url")? {
            ("wildcard", s) => Ok(UrlMatch::Wildcard(s)),
            ("regex", s) => Ok(UrlMatch::Regex(s)),
            (other, _) => {
                anyhow::bail!("url match key must be `wildcard` or `regex`, got `{other}`")
            }
        },
        other => anyhow::bail!("rule field `url` must be a string or object, got {other:?}"),
    }
}

/// A host clause: a bare string is an exact authority; an object selects
/// exact/wildcard.
fn parse_host_match(value: &Value) -> anyhow::Result<HostMatch> {
    match value {
        Value::Str(s) => Ok(HostMatch::Exact(s.clone())),
        Value::Object(o) => match single_variant(o, "host")? {
            ("exact", s) => Ok(HostMatch::Exact(s)),
            ("wildcard", s) => Ok(HostMatch::Wildcard(s)),
            (other, _) => {
                anyhow::bail!("host match key must be `exact` or `wildcard`, got `{other}`")
            }
        },
        other => anyhow::bail!("rule field `host` must be a string or object, got {other:?}"),
    }
}

/// Read a single-key `{key: "pattern"}` object into `(key, pattern)`.
fn single_variant<'a>(
    obj: &'a BTreeMap<String, Value>,
    field: &str,
) -> anyhow::Result<(&'a str, String)> {
    let mut entries = obj.iter();
    let (key, value) = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("rule field `{field}` object is empty"))?;
    if entries.next().is_some() {
        anyhow::bail!("rule field `{field}` object must have exactly one key");
    }
    match value {
        Value::Str(s) => Ok((key.as_str(), s.clone())),
        other => anyhow::bail!("rule field `{field}.{key}` must be a string, got {other:?}"),
    }
}

/// Serialize the active rules back to the bus, round-tripping with
/// [`rule_from_value`].
fn rules_to_value(rules: &[CompiledRule]) -> Value {
    Value::Array(rules.iter().map(|r| rule_to_value(r.rule())).collect())
}

fn rule_to_value(rule: &Rule) -> Value {
    let mut obj = BTreeMap::new();
    obj.insert("id".into(), Value::Str(rule.id.clone()));
    if let Some(name) = &rule.name {
        obj.insert("name".into(), Value::Str(name.clone()));
    }
    obj.insert("enabled".into(), Value::Bool(rule.enabled));
    obj.insert(
        "phase".into(),
        Value::Str(phase_label(rule.condition.phase).into()),
    );
    if let Some(url) = &rule.condition.url {
        obj.insert("url".into(), url_match_value(url));
    }
    if let Some(method) = &rule.condition.method {
        obj.insert("method".into(), Value::Str(method.clone()));
    }
    if let Some(host) = &rule.condition.host {
        obj.insert("host".into(), host_match_value(host));
    }
    if let Some(dir) = rule.condition.ws_dir {
        obj.insert("ws_dir".into(), Value::Str(ws_dir_label(dir).into()));
    }
    Value::Object(obj)
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Request => "request",
        Phase::Response => "response",
        Phase::WsFrame => "wsframe",
        Phase::Any => "any",
    }
}

fn ws_dir_label(dir: aitm_core::WsDir) -> &'static str {
    match dir {
        aitm_core::WsDir::ClientToServer => "c2s",
        aitm_core::WsDir::ServerToClient => "s2c",
    }
}

fn url_match_value(url: &UrlMatch) -> Value {
    let (key, pat) = match url {
        UrlMatch::Wildcard(s) => ("wildcard", s),
        UrlMatch::Regex(s) => ("regex", s),
    };
    Value::Object(BTreeMap::from([(key.into(), Value::Str(pat.clone()))]))
}

fn host_match_value(host: &HostMatch) -> Value {
    let (key, pat) = match host {
        HostMatch::Exact(s) => ("exact", s),
        HostMatch::Wildcard(s) => ("wildcard", s),
    };
    Value::Object(BTreeMap::from([(key.into(), Value::Str(pat.clone()))]))
}

/// `flow.resume {id}` → fire the parked flow's handle; it forwards.
struct FlowResume {
    shared: Arc<Shared>,
}

impl Command for FlowResume {
    fn name(&self) -> &str {
        "flow.resume"
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

/// `flow.kill {id}` → drop the parked flow; the client sees a closed connection.
struct FlowKill {
    shared: Arc<Shared>,
}

impl Command for FlowKill {
    fn name(&self) -> &str {
        "flow.kill"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Drop an intercepted flow; the client sees a reset/closed connection."
                .into(),
            params: vec![id_param("The intercepted flow to kill.")],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        release(&self.shared, host, args.get_flow_id("id")?, Release::Kill)
    }
}

enum Release {
    Resume,
    Kill,
}

/// Release a parked flow: record its new state in the store, then wake the
/// parked future. The handle is the one this plugin parked, or — for a flow
/// another plugin parked — the one its stored `Intercepted` state carries.
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
    let (state, label) = match how {
        Release::Resume => (InterceptState::Resumed, "resumed"),
        Release::Kill => (InterceptState::Killed, "killed"),
    };
    host.store().update(id, &mut |flow: &mut Flow| {
        set_intercept(flow, state.clone())
    });
    handle.fire();
    Ok(Value::Str(label.into()))
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
