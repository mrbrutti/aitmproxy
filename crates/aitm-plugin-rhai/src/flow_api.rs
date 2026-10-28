//! Rhai-visible flow handles (`ScriptFlow`, `ScriptRequest`, …) over a shared
//! `FlowState`, and their registration on the engine (plan Task 5).
//!
//! Every handle is a cheap `Arc` clone over the one [`FlowState`] a hook edits
//! (spec §5): Rhai copies values into function parameters, so the copies all
//! write through to the same state, which the host applies after the hook.
//!
//! Option C ergonomics: reads with an obvious "absent" answer — a missing
//! header or query key, a side the flow does not have — return `""`/`null`
//! instead of erroring, so a script probing for something absent never aborts
//! mid-hook. Mutations record onto the shared state (field edits, or
//! [`FlowEffect`]s for control actions) and are discarded with it on error.
//!
//! Sizes a script can write are bounded by the engine itself: `harden` caps
//! every string at `max_string_size` and every blob at `max_array_size`, so a
//! body setter never sees more than that.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, MutexGuard};

use aitm_core::{FlowKind, Value};
use rhai::{Array, Blob, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Position};

use crate::flow_state::{FlowEffect, FlowState, RequestState, ResponseState, WsMessageState};
use crate::marshal::dynamic_to_value;

/// The flow a hook is about: `flow` in every hook.
#[derive(Clone)]
pub struct ScriptFlow(pub Arc<Mutex<FlowState>>);

/// `flow.request`.
#[derive(Clone)]
pub struct ScriptRequest(Arc<Mutex<FlowState>>);

/// `flow.response`.
#[derive(Clone)]
pub struct ScriptResponse(Arc<Mutex<FlowState>>);

/// A map-like view over one `(name, value)` list of the state: request or
/// response headers, or the request's query parameters.
#[derive(Clone)]
pub struct ScriptHeaders(Arc<Mutex<FlowState>>, HeaderSide);

/// The frame an `on_ws_message(flow, msg)` hook is about.
#[derive(Clone)]
pub struct ScriptWsMessage(Arc<Mutex<FlowState>>);

/// Which pair list a `ScriptHeaders` addresses. Header names compare
/// case-insensitively; query keys compare exactly.
#[derive(Clone, Copy)]
enum HeaderSide {
    RequestHeaders,
    ResponseHeaders,
    RequestQuery,
}

thread_local! {
    /// The flow a bare `halt()` acts on. A global verb has no receiver, and
    /// hooks run synchronously on the thread that evaluates them, so the host
    /// binds the flow here for the duration of the call (see [`ActiveFlow`]).
    static ACTIVE_FLOW: RefCell<Option<Arc<Mutex<FlowState>>>> = const { RefCell::new(None) };
}

/// Binds the flow that bare `halt()` records onto, for as long as the guard
/// lives on this thread. The hook dispatcher enters it around the hook call;
/// dropping it restores whatever was bound before (nested calls stay correct).
/// With no guard active, `halt()` is a no-op.
pub struct ActiveFlow {
    previous: Option<Arc<Mutex<FlowState>>>,
}

impl ActiveFlow {
    /// Make `state` the flow that `halt()` acts on until the guard drops.
    pub fn enter(state: Arc<Mutex<FlowState>>) -> Self {
        let previous = ACTIVE_FLOW.with(|cell| cell.replace(Some(state)));
        Self { previous }
    }
}

impl Drop for ActiveFlow {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE_FLOW.with(|cell| *cell.borrow_mut() = previous);
    }
}

impl ScriptWsMessage {
    /// A message handle over the same state as the flow's `ScriptFlow`.
    pub fn new(state: Arc<Mutex<FlowState>>) -> Self {
        Self(state)
    }
}

/// Register the whole flow surface (spec §5): the five handle types, their
/// properties, the header indexer, the control methods, and the `halt()`
/// global.
pub fn register_flow_api(engine: &mut Engine) {
    register_flow(engine);
    register_request(engine);
    register_response(engine);
    register_headers(engine);
    register_ws_message(engine);
    engine.register_fn("halt", halt);
}

/// Record `FlowEffect::Halt` on the bound flow. `continue` is a Rhai keyword,
/// so "continue" is simply not calling `halt()`: the hook's return value plays
/// no part in the verdict.
fn halt() {
    ACTIVE_FLOW.with(|cell| {
        if let Some(state) = cell.borrow().as_ref() {
            lock(state).effects.push(FlowEffect::Halt);
        }
    });
}

fn register_flow(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptFlow>("Flow")
        .register_get("id", |f: &mut ScriptFlow| -> ImmutableString {
            lock(&f.0).id.to_string().into()
        })
        .register_get("kind", |f: &mut ScriptFlow| -> ImmutableString {
            match lock(&f.0).kind {
                FlowKind::Http => "http",
                FlowKind::WebSocket => "ws",
            }
            .into()
        })
        .register_get("is_replay", |f: &mut ScriptFlow| lock(&f.0).is_replay)
        .register_get("marks", |f: &mut ScriptFlow| -> Array {
            lock(&f.0).marks.iter().map(|m| m.as_str().into()).collect()
        })
        .register_get_set(
            "comment",
            |f: &mut ScriptFlow| -> ImmutableString {
                lock(&f.0).comment.as_deref().unwrap_or_default().into()
            },
            |f: &mut ScriptFlow, comment: ImmutableString| {
                lock(&f.0).comment = (!comment.is_empty()).then(|| comment.to_string());
            },
        )
        .register_get("request", |f: &mut ScriptFlow| {
            ScriptRequest(Arc::clone(&f.0))
        })
        .register_get("response", |f: &mut ScriptFlow| {
            ScriptResponse(Arc::clone(&f.0))
        })
        .register_fn("mark", |f: &mut ScriptFlow, tag: &str| {
            let mut state = lock(&f.0);
            if !state.marks.iter().any(|m| m == tag) {
                state.marks.push(tag.to_string());
            }
        })
        .register_fn(
            "set_response",
            |f: &mut ScriptFlow, status: i64, headers: Map, body: &str| {
                lock(&f.0).effects.push(FlowEffect::SetResponse {
                    status: clamp_status(status),
                    headers: header_pairs(headers),
                    body: body.as_bytes().to_vec(),
                });
            },
        )
        .register_fn("intercept", |f: &mut ScriptFlow| {
            f.push(FlowEffect::Intercept)
        })
        .register_fn("resume", |f: &mut ScriptFlow| f.push(FlowEffect::Resume))
        .register_fn("kill", |f: &mut ScriptFlow| f.push(FlowEffect::Kill))
        .register_fn("backup", |f: &mut ScriptFlow| f.push(FlowEffect::Backup))
        .register_fn("revert", |f: &mut ScriptFlow| f.push(FlowEffect::Revert));
}

fn register_request(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptRequest>("Request")
        .register_get_set(
            "method",
            |r: &mut ScriptRequest| -> ImmutableString { r.read(|q| q.method.as_str().into()) },
            |r: &mut ScriptRequest, v: ImmutableString| r.edit(|q| q.method = v.to_string()),
        )
        .register_get_set(
            "url",
            |r: &mut ScriptRequest| -> ImmutableString { r.read(|q| q.url.as_str().into()) },
            |r: &mut ScriptRequest, v: ImmutableString| r.edit(|q| q.url = v.to_string()),
        )
        .register_get_set(
            "path",
            |r: &mut ScriptRequest| -> ImmutableString { r.read(|q| q.path.as_str().into()) },
            |r: &mut ScriptRequest, v: ImmutableString| r.edit(|q| q.path = v.to_string()),
        )
        .register_get("query", |r: &mut ScriptRequest| {
            ScriptHeaders(Arc::clone(&r.0), HeaderSide::RequestQuery)
        })
        .register_get("headers", |r: &mut ScriptRequest| {
            ScriptHeaders(Arc::clone(&r.0), HeaderSide::RequestHeaders)
        })
        .register_get_set(
            "body",
            |r: &mut ScriptRequest| -> ImmutableString { r.read(|q| text_of(&q.body)) },
            |r: &mut ScriptRequest, v: ImmutableString| r.edit(|q| q.body = v.as_bytes().to_vec()),
        )
        .register_get_set(
            "bytes",
            |r: &mut ScriptRequest| -> Blob { r.read(|q| q.body.clone()) },
            |r: &mut ScriptRequest, v: Blob| r.edit(|q| q.body = v),
        )
        .register_fn(
            "set_json",
            |r: &mut ScriptRequest, value: Map| -> Result<(), Box<EvalAltResult>> {
                let json = json_of(value)?;
                r.edit(|q| {
                    q.body = json.into_bytes();
                    set_pair(
                        &mut q.headers,
                        HeaderSide::RequestHeaders,
                        "Content-Type",
                        "application/json",
                    );
                });
                Ok(())
            },
        );
}

fn register_response(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptResponse>("Response")
        .register_get_set(
            "status",
            |r: &mut ScriptResponse| -> i64 { r.read(|p| i64::from(p.status)) },
            |r: &mut ScriptResponse, v: i64| r.edit(|p| p.status = clamp_status(v)),
        )
        .register_get("headers", |r: &mut ScriptResponse| {
            ScriptHeaders(Arc::clone(&r.0), HeaderSide::ResponseHeaders)
        })
        .register_get_set(
            "body",
            |r: &mut ScriptResponse| -> ImmutableString { r.read(|p| text_of(&p.body)) },
            |r: &mut ScriptResponse, v: ImmutableString| r.edit(|p| p.body = v.as_bytes().to_vec()),
        )
        .register_get_set(
            "bytes",
            |r: &mut ScriptResponse| -> Blob { r.read(|p| p.body.clone()) },
            |r: &mut ScriptResponse, v: Blob| r.edit(|p| p.body = v),
        );
}

fn register_headers(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptHeaders>("Headers")
        .register_fn("get", |h: &mut ScriptHeaders, key: &str| h.get(key))
        .register_fn("set", |h: &mut ScriptHeaders, key: &str, value: &str| {
            h.set(key, value)
        })
        .register_fn("remove", |h: &mut ScriptHeaders, key: &str| {
            let side = h.1;
            h.edit(|pairs| pairs.retain(|(k, _)| !key_matches(side, k, key)));
        })
        .register_fn("has", |h: &mut ScriptHeaders, key: &str| -> bool {
            let side = h.1;
            h.read(|pairs| pairs.iter().any(|(k, _)| key_matches(side, k, key)))
        })
        .register_fn("keys", |h: &mut ScriptHeaders| -> Array {
            h.read(|pairs| pairs.iter().map(|(k, _)| k.as_str().into()).collect())
        })
        .register_indexer_get_set(
            |h: &mut ScriptHeaders, key: ImmutableString| h.get(&key),
            |h: &mut ScriptHeaders, key: ImmutableString, value: ImmutableString| {
                h.set(&key, &value);
            },
        );
}

fn register_ws_message(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptWsMessage>("WsMessage")
        .register_get("direction", |m: &mut ScriptWsMessage| -> ImmutableString {
            m.read(|w| w.direction.as_str().into())
        })
        .register_get("opcode", |m: &mut ScriptWsMessage| -> ImmutableString {
            m.read(|w| w.opcode.as_str().into())
        })
        .register_get_set(
            "text",
            |m: &mut ScriptWsMessage| -> ImmutableString { m.read(|w| text_of(&w.data)) },
            |m: &mut ScriptWsMessage, v: ImmutableString| m.set_text(&v),
        )
        .register_fn("set_text", |m: &mut ScriptWsMessage, v: &str| m.set_text(v))
        .register_get("data", |m: &mut ScriptWsMessage| -> Blob {
            m.read(|w| w.data.clone())
        })
        .register_fn("set_bytes", |m: &mut ScriptWsMessage, v: Blob| {
            m.edit(|w| w.data = v)
        })
        .register_fn("drop", |m: &mut ScriptWsMessage| {
            lock(&m.0).effects.push(FlowEffect::DropWsMessage);
        });
}

impl ScriptFlow {
    fn push(&self, effect: FlowEffect) {
        lock(&self.0).effects.push(effect);
    }
}

impl ScriptRequest {
    /// Read from the request; a flow without one reads as the default (`""`).
    fn read<R: Default>(&self, f: impl FnOnce(&RequestState) -> R) -> R {
        lock(&self.0).request.as_ref().map(f).unwrap_or_default()
    }

    /// Edit the request; a flow without one (WebSocket) has nothing to edit.
    fn edit(&self, f: impl FnOnce(&mut RequestState)) {
        if let Some(request) = lock(&self.0).request.as_mut() {
            f(request);
        }
    }
}

impl ScriptResponse {
    /// Read from the response; a flow without one yet reads as the default.
    fn read<R: Default>(&self, f: impl FnOnce(&ResponseState) -> R) -> R {
        lock(&self.0).response.as_ref().map(f).unwrap_or_default()
    }

    /// Edit the response, creating an empty one on a flow that has none yet so
    /// the edit is kept; `apply_to` then installs it as a fresh response.
    fn edit(&self, f: impl FnOnce(&mut ResponseState)) {
        f(lock(&self.0)
            .response
            .get_or_insert_with(ResponseState::default));
    }
}

impl ScriptHeaders {
    /// The value of the first matching key, or `""` when absent (option C).
    fn get(&self, key: &str) -> ImmutableString {
        let side = self.1;
        self.read(|pairs| {
            pairs
                .iter()
                .find(|(k, _)| key_matches(side, k, key))
                .map(|(_, v)| v.as_str().into())
                .unwrap_or_default()
        })
    }

    fn set(&self, key: &str, value: &str) {
        let side = self.1;
        self.edit(|pairs| set_pair(pairs, side, key, value));
    }

    fn read<R: Default>(&self, f: impl FnOnce(&[(String, String)]) -> R) -> R {
        let state = lock(&self.0);
        self.1.pairs(&state).map(f).unwrap_or_default()
    }

    fn edit(&self, f: impl FnOnce(&mut Vec<(String, String)>)) {
        if let Some(pairs) = self.1.pairs_mut(&mut lock(&self.0)) {
            f(pairs);
        }
    }
}

impl ScriptWsMessage {
    fn read<R: Default>(&self, f: impl FnOnce(&WsMessageState) -> R) -> R {
        lock(&self.0).ws_message.as_ref().map(f).unwrap_or_default()
    }

    fn edit(&self, f: impl FnOnce(&mut WsMessageState)) {
        if let Some(message) = lock(&self.0).ws_message.as_mut() {
            f(message);
        }
    }

    fn set_text(&self, text: &str) {
        self.edit(|w| w.data = text.as_bytes().to_vec());
    }
}

impl HeaderSide {
    fn pairs(self, state: &FlowState) -> Option<&[(String, String)]> {
        match self {
            Self::RequestHeaders => state.request.as_ref().map(|r| r.headers.as_slice()),
            Self::RequestQuery => state.request.as_ref().map(|r| r.query.as_slice()),
            Self::ResponseHeaders => state.response.as_ref().map(|r| r.headers.as_slice()),
        }
    }

    fn pairs_mut(self, state: &mut FlowState) -> Option<&mut Vec<(String, String)>> {
        match self {
            Self::RequestHeaders => state.request.as_mut().map(|r| &mut r.headers),
            Self::RequestQuery => state.request.as_mut().map(|r| &mut r.query),
            Self::ResponseHeaders => state.response.as_mut().map(|r| &mut r.headers),
        }
    }
}

/// Lock the shared state. A poisoned lock (a panic while another handle held
/// it) still yields the data: the state is plain values with no invariant a
/// half-finished edit could break, and the host discards it on error anyway.
fn lock(state: &Mutex<FlowState>) -> MutexGuard<'_, FlowState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn key_matches(side: HeaderSide, have: &str, want: &str) -> bool {
    match side {
        HeaderSide::RequestQuery => have == want,
        HeaderSide::RequestHeaders | HeaderSide::ResponseHeaders => have.eq_ignore_ascii_case(want),
    }
}

/// Replace the value of an existing key (keeping its position and spelling)
/// or append the pair.
fn set_pair(pairs: &mut Vec<(String, String)>, side: HeaderSide, key: &str, value: &str) {
    match pairs.iter_mut().find(|(k, _)| key_matches(side, k, key)) {
        Some((_, v)) => *v = value.to_string(),
        None => pairs.push((key.to_string(), value.to_string())),
    }
}

/// A `#{ name: value }` map as header pairs; a non-string value is written
/// the way Rhai prints it.
fn header_pairs(headers: Map) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn clamp_status(status: i64) -> u16 {
    u16::try_from(status.clamp(0, i64::from(u16::MAX))).unwrap_or(u16::MAX)
}

/// The text view of a body: lossy UTF-8, so a binary body still reads.
fn text_of(bytes: &[u8]) -> ImmutableString {
    String::from_utf8_lossy(bytes).into_owned().into()
}

/// Serialize a Rhai map as JSON. A value with no JSON shape (a function
/// pointer, a custom type) is a runtime error naming the type.
fn json_of(value: Map) -> Result<String, Box<EvalAltResult>> {
    let value = dynamic_to_value(&Dynamic::from_map(value)).map_err(|e| {
        Box::new(EvalAltResult::ErrorRuntime(
            format!("set_json: {e}").into(),
            Position::NONE,
        ))
    })?;
    let mut out = String::new();
    write_json(&value, &mut out);
    Ok(out)
}

fn write_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) if f.is_finite() => out.push_str(&f.to_string()),
        Value::Float(_) => out.push_str("null"),
        Value::Str(s) => write_json_string(s, out),
        Value::Bytes(bytes) => write_json_seq(bytes.iter().map(|b| Value::Int(i64::from(*b))), out),
        Value::Array(items) => write_json_seq(items.iter().cloned(), out),
        Value::Object(fields) => {
            out.push('{');
            for (i, (k, v)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

fn write_json_seq(items: impl Iterator<Item = Value>, out: &mut String) {
    out.push('[');
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_json(&item, out);
    }
    out.push(']');
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
