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
//! it is **not** scope-guarded.
//!
//! `ws.send {id, dir, opcode, data}` (Task 7) composes a *new* frame and injects
//! it onto the live socket. It does egress active traffic, so it first passes
//! [`ScopeRateGuard::check_active`](aitm_core::ScopeRateGuard::check_active) on
//! the flow's authority (out of scope → `Err`, surfaced as `isError: true`), then
//! enqueues the frame onto the flow's channel in the shared
//! [`InjectRegistry`]. The `aitm-proto-ws` module drains that channel from its
//! live `select!`, frames the payload towards the side `dir` implies, and appends
//! a `WsMessage { injected: true }`. The plugin and the module share one
//! `InjectRegistry` `Arc` (the module gets its handle via
//! [`WsCtlPlugin::inject_registry`], wired in the binary — Task 14).
//!
//! ## Single-frame drop
//!
//! `ws.frame {action:"drop"}` marks the flow [`InterceptState::Killed`]; Task 7
//! taught the `aitm-proto-ws` relay loop to read that as "skip forwarding this one
//! frame but keep the conversation open" (resetting the park state), mirroring the
//! Rhai `msg.drop()` semantics. `Killed` is only ever set on a WS flow by a frame
//! drop, so there is no ambiguity with a whole-conversation kill.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aitm_core::{
    Command, CommandHost, Event, Flow, FlowCtx, FlowId, FlowStore, InterceptState, ParamDef,
    ParamSchema, Params, Plugin, Registry, ResumeHandle, TypeDesc, Value, Verdict, WsDir, WsOpcode,
};
use aitm_proto_ws::{InjectFrame, InjectRegistry};
use aitm_rules::{bus, check_rule_count, compile, CompiledRule, Phase, Rule};

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

/// Registers `ws.intercept`, `ws.frame` and `ws.send`; parks matching WS frames
/// while armed and injects composed frames onto live sockets.
pub struct WsCtlPlugin {
    shared: Arc<Shared>,
    /// Flow → inject sender, shared with the `aitm-proto-ws` module so `ws.send`
    /// can reach a live conversation's `select!` loop.
    inject: InjectRegistry,
}

impl WsCtlPlugin {
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
            inject: InjectRegistry::default(),
        }
    }

    /// A handle to the shared inject registry, to pass to
    /// [`WsModule::with_inject_registry`](aitm_proto_ws::WsModule::with_inject_registry)
    /// so the plugin and the live WS module share one channel map.
    pub fn inject_registry(&self) -> InjectRegistry {
        self.inject.clone()
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
        reg.add_command(Arc::new(WsSend {
            inject: self.inject.clone(),
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
            check_rule_count(arr.len())?;
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

// --- ws.send -----------------------------------------------------------------

/// `ws.send {id, dir, opcode, data}` → compose a frame and inject it onto a live
/// WebSocket. Scope-guarded (active egress); enqueues onto the shared registry.
struct WsSend {
    inject: InjectRegistry,
}

impl Command for WsSend {
    fn name(&self) -> &str {
        "ws.send"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Compose a new WebSocket frame and inject it onto a live conversation. \
                          Active egress: refused unless the flow's host is in scope."
                .into(),
            params: vec![
                ParamDef {
                    name: "id".into(),
                    ty: TypeDesc::FlowId,
                    required: true,
                    description: "The live WebSocket flow to inject into.".into(),
                },
                ParamDef {
                    name: "dir".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "c2s (towards the server) or s2c (towards the client).".into(),
                },
                ParamDef {
                    name: "opcode".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "text|binary|ping|pong|close.".into(),
                },
                ParamDef {
                    name: "data".into(),
                    ty: TypeDesc::Bytes,
                    required: true,
                    description: "the frame payload (bytes or a UTF-8 string).".into(),
                },
            ],
            result: TypeDesc::Object(vec![ParamDef {
                name: "index".into(),
                ty: TypeDesc::Int,
                required: true,
                description: "index of the appended injected WsMessage.".into(),
            }]),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let dir = parse_dir(args.get_str("dir")?)?;
        let opcode = parse_opcode(args.get_str("opcode")?)?;
        let data = req_bytes(&args, "data")?;

        // Active egress onto a live socket → scope-gated. The permit's RAII slot
        // is released as the frame is handed off; the gate here is scope.
        let authority = ws_authority(host.store(), id)?;
        let _permit = host.guard().check_active(&authority)?;

        // Resolve the live conversation's inject sender.
        let sender = lock(&self.inject).get(&id).cloned();
        let Some(sender) = sender else {
            anyhow::bail!(
                "flow {id} has no live WebSocket inject channel (closed or never opened)"
            );
        };

        // The module appends the injected frame in enqueue order; it will occupy
        // the position after the frames captured so far.
        let index = match host.store().get(id) {
            Some(Flow::WebSocket(w)) => w.messages.len(),
            Some(_) => anyhow::bail!("flow {id} is not a WebSocket flow"),
            None => anyhow::bail!("no flow with id {id}"),
        };

        sender
            .send(InjectFrame { dir, opcode, data })
            .map_err(|_| {
                anyhow::anyhow!("WebSocket flow {id} closed before the frame was injected")
            })?;

        Ok(Value::Object(
            [("index".to_string(), Value::Int(index as i64))]
                .into_iter()
                .collect(),
        ))
    }
}

/// The authority (`host[:port]`) a WebSocket flow talks to, read from its
/// handshake `HttpFlow` — the scope subject for `ws.send`.
fn ws_authority(store: &dyn FlowStore, id: FlowId) -> anyhow::Result<String> {
    let handshake = match store.get(id) {
        Some(Flow::WebSocket(w)) => w.handshake,
        Some(_) => anyhow::bail!("flow {id} is not a WebSocket flow"),
        None => anyhow::bail!("no flow with id {id}"),
    };
    match store.get(handshake) {
        Some(Flow::Http(h)) => Ok(h.request.authority.clone()),
        _ => anyhow::bail!("WebSocket flow {id} has no handshake HTTP flow to resolve its host"),
    }
}

/// A required byte-string argument, accepting raw bytes or a UTF-8 string.
fn req_bytes(args: &Params, name: &str) -> anyhow::Result<Vec<u8>> {
    match args.get(name) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(Value::Str(s)) => Ok(s.clone().into_bytes()),
        Some(other) => anyhow::bail!("param `{name}` must be bytes or a string, got {other:?}"),
        None => anyhow::bail!("missing required param `{name}`"),
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
            "wildcard string, or {wildcard|regex}; matched against the full request URL \
             (scheme://host[:port]/path?query) and against the path alone.",
        ),
        field("method", TypeDesc::Str, "case-insensitive method."),
        field("host", TypeDesc::Any, "exact string, or {exact|wildcard}."),
    ]
}

/// Parse one rule object from the command bus into an [`aitm_rules::Rule`] via the
/// shared [`aitm_rules::bus`] serde. `pos` seeds a default id when none is supplied;
/// a WS-frame rule is the default phase for this surface.
fn parse_rule(obj: &std::collections::BTreeMap<String, Value>, pos: usize) -> anyhow::Result<Rule> {
    bus::parse_rule(obj, &format!("ws-{pos}"), Phase::WsFrame)
}

/// Parse a ws_dir token via the shared helper; also the `dir` arg of `ws.send`.
fn parse_dir(s: &str) -> anyhow::Result<WsDir> {
    bus::parse_ws_dir(s)
}

/// Echo a compiled rule back to the caller as `{id, phase, ws_dir?}`, using the
/// shared canonical tokens so every rule surface agrees.
fn echo_rule(cr: &CompiledRule) -> Value {
    let rule = cr.rule();
    let mut obj = std::collections::BTreeMap::new();
    obj.insert("id".to_string(), Value::Str(rule.id.clone()));
    obj.insert(
        "phase".to_string(),
        Value::Str(bus::phase_token(rule.condition.phase).to_string()),
    );
    if let Some(dir) = rule.condition.ws_dir {
        obj.insert(
            "ws_dir".to_string(),
            Value::Str(bus::ws_dir_token(dir).to_string()),
        );
    }
    Value::Object(obj)
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
    use aitm_rules::{HostMatch, UrlMatch};
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
        assert!(bus::parse_phase("bogus").is_err());
        assert!(parse_dir("sideways").is_err());
        assert!(parse_opcode("nope").is_err());
    }

    /// AC18: `ws.intercept` turns away more than 256 rules before compiling any,
    /// and the previously armed set survives the rejected call; 256 is accepted.
    #[test]
    fn more_than_256_rules_are_rejected_and_leave_the_active_set() {
        use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
        use futures::future::BoxFuture;

        struct StubClient;
        impl ProxyClient for StubClient {
            fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
                Box::pin(async { anyhow::bail!("stub client") })
            }
        }
        let store = MemFlowStore::new();
        let client = StubClient;
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &client, &guard, None);
        let cmd = WsIntercept {
            shared: Arc::default(),
        };
        let rules = |n: usize| {
            Value::Array(
                (0..n)
                    .map(|_| Value::Object(obj(&[("ws_dir", Value::Str("c2s".into()))])))
                    .collect(),
            )
        };
        let params = |rules: Value| Params::new(obj(&[("rules", rules)]));

        cmd.invoke(params(rules(1)), &host).expect("one rule arms");
        let err = cmd
            .invoke(params(rules(257)), &host)
            .expect_err("257 rules are rejected");
        assert_eq!(
            err.to_string(),
            "257 rules supplied; the limit is 256 per call"
        );
        assert_eq!(
            lock(&cmd.shared.rules).len(),
            1,
            "the armed set survives the rejected call"
        );
        cmd.invoke(params(rules(256)), &host)
            .expect("256 rules is the cap, inclusive");
        assert_eq!(lock(&cmd.shared.rules).len(), 256);
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
