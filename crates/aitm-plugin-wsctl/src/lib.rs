//! WebSocket control plugin (F9, Task 6): intercept a live WebSocket frame and
//! edit-then-forward or drop it.
//!
//! `ws.intercept {enabled?, rules?}` arms the plugin with a set of
//! [`aitm_rules::Phase::WsFrame`] rules. While armed, `on_event(WsMessage)` parks
//! a frame that some rule matches (via [`FlowCtx::intercept`]) *before* the
//! WebSocket module forwards it — the module's `emit().await` suspends until a
//! command releases the frame. `ws.frame {id, index, action}` is that command:
//!
//! - `forward` optionally edits the parked frame in place (`data`/`opcode`) in
//!   the store, then fires the resume handle; the module re-reads the stored
//!   frame and forwards the edited bytes.
//! - `drop` marks the flow [`InterceptState::Killed`] and fires the handle; the
//!   module, seeing the kill after it wakes, returns without forwarding the frame
//!   (the peer never receives it).
//!
//! `ws.frame` acts on an already-captured, already-parked frame — no new egress
//! beyond what the flow already carries — so, like editing a parked HTTP request,
//! it is **not** scope-guarded. (`ws.send` live injection, which *does* egress, is
//! Task 7.)
//!
//! ## Drop semantics (known limitation — see Task 7)
//!
//! The `aitm-proto-ws` module's frame loop has two post-park outcomes: forward
//! the (possibly edited) stored frame, or — if the flow is `Killed` — stop. It
//! exposes no per-frame "skip this one, keep the conversation open" hook, so
//! `drop` tears the whole conversation down rather than dropping a single frame
//! and continuing. A true single-frame drop needs an additive hook in
//! `aitm-proto-ws`'s `handle`, which belongs to Task 7 (the task that already
//! edits `aitm-proto-ws`); Task 6 keeps its changes to this crate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aitm_core::{
    Command, CommandHost, Event, Flow, FlowCtx, FlowId, InterceptState, ParamDef, ParamSchema,
    Params, Plugin, Registry, ResumeHandle, TypeDesc, Value, Verdict, WsDir, WsOpcode,
};
use aitm_rules::{compile, CompiledRule, HostMatch, MatchCondition, Phase, Rule, UrlMatch};

/// State the plugin (which parks frames on events) shares with its commands
/// (which arm it and release parked frames).
#[derive(Default)]
struct Shared {
    armed: AtomicBool,
    rules: Mutex<Vec<CompiledRule>>,
    /// Flow id → the resume handle for the frame currently parked on it. Only one
    /// frame per flow is in flight (the module awaits each `WsMessage` emit before
    /// reading the next), so the flow id is key enough.
    parked: Mutex<HashMap<FlowId, ResumeHandle>>,
}

/// Registers `ws.intercept` and `ws.frame`; parks matching WS frames while armed.
pub struct WsCtlPlugin {
    shared: Arc<Shared>,
}

impl WsCtlPlugin {
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
        }
    }
}

impl Default for WsCtlPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for WsCtlPlugin {
    fn name(&self) -> &str {
        "wsctl"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(WsIntercept {
            shared: self.shared.clone(),
        }));
        reg.add_command(Arc::new(WsFrame {
            shared: self.shared.clone(),
        }));
    }

    fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
        let Event::WsMessage { flow, index } = ev else {
            return Verdict::Continue;
        };
        if !self.shared.armed.load(Ordering::SeqCst) {
            return Verdict::Continue;
        }
        // The frame's direction, needed to evaluate `ws_dir` clauses.
        let dir = match ctx.flow() {
            Flow::WebSocket(w) => w.messages.get(*index).map(|m| m.dir),
            _ => None,
        };
        let Some(dir) = dir else {
            return Verdict::Continue;
        };
        let matched = {
            let rules = lock(&self.shared.rules);
            rules
                .iter()
                .any(|r| r.matches(ctx.flow(), Phase::WsFrame, Some(dir)))
        };
        if matched {
            ctx.backup();
            let handle = ctx.intercept();
            lock(&self.shared.parked).insert(*flow, handle);
        }
        Verdict::Continue
    }
}

// --- ws.intercept ------------------------------------------------------------

/// `ws.intercept {enabled?, rules?}` → arm/disarm WS-frame interception and set
/// the active `Phase::WsFrame` rule set.
struct WsIntercept {
    shared: Arc<Shared>,
}

impl Command for WsIntercept {
    fn name(&self) -> &str {
        "ws.intercept"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Arm (default) or disarm WebSocket frame interception and set the \
                          Phase::WsFrame rules that select which live frames are parked for \
                          ws.frame to edit/forward or drop."
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
                    ty: TypeDesc::Array(Box::new(TypeDesc::Object(rule_fields()))),
                    required: false,
                    description: "Rules whose matching frames are parked. Each: {id?, name?, \
                                  enabled?, phase?, ws_dir?, url?, method?, host?}; phase \
                                  defaults to ws_frame. An invalid regex is rejected."
                        .into(),
                },
            ],
            result: TypeDesc::Object(vec![
                ParamDef {
                    name: "enabled".into(),
                    ty: TypeDesc::Bool,
                    required: true,
                    description: "the resulting armed state.".into(),
                },
                ParamDef {
                    name: "rules".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Any)),
                    required: true,
                    description: "the active rules (id/phase/ws_dir).".into(),
                },
            ]),
        }
    }

    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let enabled = match args.get("enabled") {
            None => true,
            Some(_) => args.get_bool("enabled")?,
        };

        // Only replace the rule set when the caller supplies one, so a bare
        // `ws.intercept {enabled:false}` disarms without discarding the rules.
        if let Some(raw) = args.get("rules") {
            let arr = match raw {
                Value::Array(a) => a,
                other => anyhow::bail!("param `rules` must be an array, got {other:?}"),
            };
            let mut compiled = Vec::with_capacity(arr.len());
            for (pos, item) in arr.iter().enumerate() {
                let obj = match item {
                    Value::Object(o) => o,
                    other => anyhow::bail!("each rule must be an object, got {other:?}"),
                };
                let rule = parse_rule(obj, pos)?;
                let cr = compile(rule).map_err(|e| anyhow::anyhow!(e.to_string()))?;
                compiled.push(cr);
            }
            *lock(&self.shared.rules) = compiled;
        }

        self.shared.armed.store(enabled, Ordering::SeqCst);

        let rules = lock(&self.shared.rules).iter().map(echo_rule).collect();
        Ok(Value::Object(
            [
                ("enabled".to_string(), Value::Bool(enabled)),
                ("rules".to_string(), Value::Array(rules)),
            ]
            .into_iter()
            .collect(),
        ))
    }
}

// --- ws.frame ----------------------------------------------------------------

/// `ws.frame {id, index, action, data?, opcode?}` → release a parked frame:
/// `forward` (optionally edited), or `drop`.
struct WsFrame {
    shared: Arc<Shared>,
}

impl Command for WsFrame {
    fn name(&self) -> &str {
        "ws.frame"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Act on a parked WebSocket frame: forward it (optionally editing its \
                          data/opcode first) or drop it so the peer never receives it."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "The WebSocket flow holding the parked frame.".into(),
                },
                ParamDef {
                    name: "index".into(),
                    ty: TypeDesc::Int,
                    required: true,
                    description: "Index of the parked frame in the flow's messages.".into(),
                },
                ParamDef {
                    name: "action".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "\"forward\" or \"drop\".".into(),
                },
                ParamDef {
                    name: "data".into(),
                    ty: TypeDesc::Bytes,
                    required: false,
                    description: "forward only: replacement frame payload.".into(),
                },
                ParamDef {
                    name: "opcode".into(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "forward only: new opcode (text|binary|ping|pong|close).".into(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let index = usize::try_from(args.get_int("index")?)
            .map_err(|_| anyhow::anyhow!("param `index` must be a non-negative integer"))?;
        let action = args.get_str("action")?.to_string();

        match action.as_str() {
            "forward" => {
                let data = opt_bytes(&args, "data")?;
                let opcode = match args.get("opcode") {
                    None => None,
                    Some(_) => Some(parse_opcode(args.get_str("opcode")?)?),
                };
                // Fail before releasing if the frame is gone, so the caller can
                // retry (the flow stays parked until it is released or times out).
                frame_exists(host, id, index)?;
                let handle = self.resolve_handle(host, id)?;
                // Edit the stored frame, then wake the module: it re-reads the
                // store and forwards whatever is there. Order matters — edit first.
                host.store().update(id, &mut |flow: &mut Flow| {
                    if let Flow::WebSocket(w) = flow {
                        if let Some(msg) = w.messages.get_mut(index) {
                            if let Some(bytes) = &data {
                                msg.data = bytes.clone();
                            }
                            if let Some(op) = opcode {
                                msg.opcode = op;
                            }
                        }
                    }
                });
                handle.fire();
                Ok(Value::Str("forwarded".into()))
            }
            "drop" => {
                let handle = self.resolve_handle(host, id)?;
                host.store().update(id, &mut |flow: &mut Flow| {
                    set_intercept(flow, InterceptState::Killed)
                });
                handle.fire();
                Ok(Value::Str("dropped".into()))
            }
            other => anyhow::bail!("param `action` must be \"forward\" or \"drop\", got {other:?}"),
        }
    }
}

impl WsFrame {
    /// The resume handle for the parked frame: the one this plugin recorded, or —
    /// for a frame released via a different path — the one the flow's
    /// `Intercepted` state carries.
    fn resolve_handle(&self, host: &CommandHost, id: FlowId) -> anyhow::Result<ResumeHandle> {
        if let Some(handle) = lock(&self.shared.parked).remove(&id) {
            return Ok(handle);
        }
        match host.store().get(id) {
            Some(flow) => match flow.intercept() {
                InterceptState::Intercepted { resume, .. } => Ok(resume.clone()),
                _ => anyhow::bail!("flow {id} has no parked frame"),
            },
            None => anyhow::bail!("no flow with id {id}"),
        }
    }
}

/// Error unless flow `id` is a WebSocket flow with a frame at `index`.
fn frame_exists(host: &CommandHost, id: FlowId, index: usize) -> anyhow::Result<()> {
    match host.store().get(id) {
        Some(Flow::WebSocket(w)) if w.messages.get(index).is_some() => Ok(()),
        Some(Flow::WebSocket(_)) => {
            anyhow::bail!("no frame at index {index} in WebSocket flow {id}")
        }
        Some(_) => anyhow::bail!("flow {id} is not a WebSocket flow"),
        None => anyhow::bail!("no flow with id {id}"),
    }
}

// --- rule parsing ------------------------------------------------------------

/// The field set of a rule object, for the MCP schema.
fn rule_fields() -> Vec<ParamDef> {
    let field = |name: &str, ty: TypeDesc, desc: &str| ParamDef {
        name: name.into(),
        ty,
        required: false,
        description: desc.into(),
    };
    vec![
        field(
            "id",
            TypeDesc::Str,
            "stable rule id (generated if omitted).",
        ),
        field("name", TypeDesc::Str, "human label."),
        field("enabled", TypeDesc::Bool, "default true."),
        field(
            "phase",
            TypeDesc::Str,
            "request|response|ws_frame|any (default ws_frame).",
        ),
        field("ws_dir", TypeDesc::Str, "c2s|s2c (any if omitted)."),
        field(
            "url",
            TypeDesc::Any,
            "wildcard string, or {wildcard|regex}.",
        ),
        field("method", TypeDesc::Str, "case-insensitive method."),
        field("host", TypeDesc::Any, "exact string, or {exact|wildcard}."),
    ]
}

/// Parse one rule object from the command bus into an [`aitm_rules::Rule`]. `pos`
/// seeds a default id when none is supplied.
fn parse_rule(obj: &std::collections::BTreeMap<String, Value>, pos: usize) -> anyhow::Result<Rule> {
    let id = match obj.get("id") {
        None => format!("ws-{pos}"),
        Some(Value::Str(s)) => s.clone(),
        Some(other) => anyhow::bail!("rule `id` must be a string, got {other:?}"),
    };
    let name = match obj.get("name") {
        None => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(other) => anyhow::bail!("rule `name` must be a string, got {other:?}"),
    };
    let enabled = match obj.get("enabled") {
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(other) => anyhow::bail!("rule `enabled` must be a boolean, got {other:?}"),
    };
    let phase = match obj.get("phase") {
        None => Phase::WsFrame,
        Some(Value::Str(s)) => parse_phase(s)?,
        Some(other) => anyhow::bail!("rule `phase` must be a string, got {other:?}"),
    };
    let ws_dir = match obj.get("ws_dir") {
        None => None,
        Some(Value::Str(s)) => Some(parse_dir(s)?),
        Some(other) => anyhow::bail!("rule `ws_dir` must be a string, got {other:?}"),
    };
    let method = match obj.get("method") {
        None => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(other) => anyhow::bail!("rule `method` must be a string, got {other:?}"),
    };
    let url = parse_url(obj.get("url"))?;
    let host = parse_host(obj.get("host"))?;

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

fn parse_phase(s: &str) -> anyhow::Result<Phase> {
    match s.to_ascii_lowercase().as_str() {
        "request" => Ok(Phase::Request),
        "response" => Ok(Phase::Response),
        "ws_frame" | "wsframe" | "frame" => Ok(Phase::WsFrame),
        "any" => Ok(Phase::Any),
        other => anyhow::bail!("unknown phase {other:?} (request|response|ws_frame|any)"),
    }
}

fn parse_dir(s: &str) -> anyhow::Result<WsDir> {
    match s.to_ascii_lowercase().as_str() {
        "c2s" | "client_to_server" | "clienttoserver" => Ok(WsDir::ClientToServer),
        "s2c" | "server_to_client" | "servertoclient" => Ok(WsDir::ServerToClient),
        other => anyhow::bail!("unknown ws_dir {other:?} (c2s|s2c)"),
    }
}

fn parse_url(v: Option<&Value>) -> anyhow::Result<Option<UrlMatch>> {
    match v {
        None => Ok(None),
        Some(Value::Str(s)) => Ok(Some(UrlMatch::Wildcard(s.clone()))),
        Some(Value::Object(o)) => match (o.get("wildcard"), o.get("regex")) {
            (Some(Value::Str(s)), None) => Ok(Some(UrlMatch::Wildcard(s.clone()))),
            (None, Some(Value::Str(s))) => Ok(Some(UrlMatch::Regex(s.clone()))),
            _ => anyhow::bail!("rule `url` object must be {{wildcard:str}} or {{regex:str}}"),
        },
        Some(other) => anyhow::bail!("rule `url` must be a string or object, got {other:?}"),
    }
}

fn parse_host(v: Option<&Value>) -> anyhow::Result<Option<HostMatch>> {
    match v {
        None => Ok(None),
        Some(Value::Str(s)) => Ok(Some(HostMatch::Exact(s.clone()))),
        Some(Value::Object(o)) => match (o.get("exact"), o.get("wildcard")) {
            (Some(Value::Str(s)), None) => Ok(Some(HostMatch::Exact(s.clone()))),
            (None, Some(Value::Str(s))) => Ok(Some(HostMatch::Wildcard(s.clone()))),
            _ => anyhow::bail!("rule `host` object must be {{exact:str}} or {{wildcard:str}}"),
        },
        Some(other) => anyhow::bail!("rule `host` must be a string or object, got {other:?}"),
    }
}

/// Echo a compiled rule back to the caller as `{id, phase, ws_dir?}`.
fn echo_rule(cr: &CompiledRule) -> Value {
    let rule = cr.rule();
    let mut obj = std::collections::BTreeMap::new();
    obj.insert("id".to_string(), Value::Str(rule.id.clone()));
    obj.insert(
        "phase".to_string(),
        Value::Str(phase_str(rule.condition.phase).to_string()),
    );
    if let Some(dir) = rule.condition.ws_dir {
        obj.insert("ws_dir".to_string(), Value::Str(dir_str(dir).to_string()));
    }
    Value::Object(obj)
}

fn phase_str(p: Phase) -> &'static str {
    match p {
        Phase::Request => "request",
        Phase::Response => "response",
        Phase::WsFrame => "ws_frame",
        Phase::Any => "any",
    }
}

fn dir_str(d: WsDir) -> &'static str {
    match d {
        WsDir::ClientToServer => "c2s",
        WsDir::ServerToClient => "s2c",
    }
}

fn parse_opcode(s: &str) -> anyhow::Result<WsOpcode> {
    match s.to_ascii_lowercase().as_str() {
        "text" => Ok(WsOpcode::Text),
        "binary" => Ok(WsOpcode::Binary),
        "ping" => Ok(WsOpcode::Ping),
        "pong" => Ok(WsOpcode::Pong),
        "close" => Ok(WsOpcode::Close),
        other => anyhow::bail!("unknown opcode {other:?} (text|binary|ping|pong|close)"),
    }
}

/// An optional byte-string argument, accepting raw bytes or a UTF-8 string.
fn opt_bytes(args: &Params, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match args.get(name) {
        None => Ok(None),
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(Value::Str(s)) => Ok(Some(s.clone().into_bytes())),
        Some(other) => anyhow::bail!("param `{name}` must be bytes or a string, got {other:?}"),
    }
}

/// Set a flow's interception state regardless of protocol.
fn set_intercept(flow: &mut Flow, state: InterceptState) {
    match flow {
        Flow::Http(f) => f.intercept = state,
        Flow::WebSocket(f) => f.intercept = state,
    }
}

/// Lock a mutex, recovering a poisoned guard rather than panicking — a prior
/// panic elsewhere must not drop this control plugin out of the chain.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn obj(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn parses_ws_frame_rule_with_dir() {
        let rule = parse_rule(
            &obj(&[
                ("phase", Value::Str("ws_frame".into())),
                ("ws_dir", Value::Str("c2s".into())),
            ]),
            0,
        )
        .expect("parses");
        assert_eq!(rule.condition.phase, Phase::WsFrame);
        assert_eq!(rule.condition.ws_dir, Some(WsDir::ClientToServer));
        assert!(rule.enabled);
        assert_eq!(rule.id, "ws-0");
        compile(rule).expect("compiles");
    }

    #[test]
    fn phase_defaults_to_ws_frame() {
        let rule = parse_rule(&obj(&[("ws_dir", Value::Str("s2c".into()))]), 3).expect("parses");
        assert_eq!(rule.condition.phase, Phase::WsFrame);
        assert_eq!(rule.condition.ws_dir, Some(WsDir::ServerToClient));
        assert_eq!(rule.id, "ws-3");
    }

    #[test]
    fn bad_url_regex_is_rejected_by_compile() {
        let rule = parse_rule(
            &obj(&[(
                "url",
                Value::Object(obj(&[("regex", Value::Str("[unterminated".into()))])),
            )]),
            0,
        )
        .expect("parses (compile is what rejects a bad pattern)");
        assert!(compile(rule).is_err(), "an invalid regex must be rejected");
    }

    #[test]
    fn unknown_phase_and_dir_are_errors() {
        assert!(parse_phase("bogus").is_err());
        assert!(parse_dir("sideways").is_err());
        assert!(parse_opcode("nope").is_err());
    }

    #[test]
    fn url_string_is_wildcard_and_host_string_is_exact() {
        let rule = parse_rule(
            &obj(&[
                ("url", Value::Str("*/login".into())),
                ("host", Value::Str("api.example".into())),
                ("method", Value::Str("POST".into())),
            ]),
            0,
        )
        .expect("parses");
        assert!(matches!(rule.condition.url, Some(UrlMatch::Wildcard(ref s)) if s == "*/login"));
        assert!(matches!(rule.condition.host, Some(HostMatch::Exact(ref s)) if s == "api.example"));
        assert_eq!(rule.condition.method.as_deref(), Some("POST"));
        compile(rule).expect("compiles");
    }
}
