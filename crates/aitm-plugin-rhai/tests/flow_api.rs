//! Task 5 — the Rhai flow handles over a shared `FlowState`. Each test
//! registers the flow API on a hardened engine, pushes a handle over a seeded
//! state into the scope, runs a script, and asserts the state afterwards.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_core::{FlowId, FlowKind};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::flow_api::{register_flow_api, ActiveFlow, ScriptFlow, ScriptWsMessage};
use aitm_plugin_rhai::flow_state::{FlowEffect, FlowState, RequestState, WsMessageState};
use rhai::{Engine, Scope};

fn engine() -> Engine {
    let mut engine = build_engine(&RhaiLimits::default(), Duration::from_secs(2));
    register_flow_api(&mut engine);
    engine
}

/// `GET http://ex.test/items?q=1` with a `Host` header and a buffered body.
fn http_state() -> Arc<Mutex<FlowState>> {
    Arc::new(Mutex::new(FlowState {
        id: FlowId::new(),
        kind: FlowKind::Http,
        request: Some(RequestState {
            method: "GET".into(),
            url: "http://ex.test/items?q=1".into(),
            path: "/items".into(),
            headers: vec![("Host".into(), "ex.test".into())],
            query: vec![("q".into(), "1".into())],
            body: b"hello".to_vec(),
        }),
        response: None,
        ws_message: None,
        marks: Vec::new(),
        comment: None,
        is_replay: false,
        effects: Vec::new(),
    }))
}

/// A WebSocket flow at a client→server text frame.
fn ws_state() -> Arc<Mutex<FlowState>> {
    Arc::new(Mutex::new(FlowState {
        id: FlowId::new(),
        kind: FlowKind::WebSocket,
        request: None,
        response: None,
        ws_message: Some(WsMessageState {
            direction: "c2s".into(),
            opcode: "text".into(),
            data: b"hello".to_vec(),
        }),
        marks: Vec::new(),
        comment: None,
        is_replay: false,
        effects: Vec::new(),
    }))
}

fn run_with_flow<T: Clone + Send + Sync + 'static>(
    state: &Arc<Mutex<FlowState>>,
    script: &str,
) -> T {
    let engine = engine();
    let mut scope = Scope::new();
    scope.push("flow", ScriptFlow(Arc::clone(state)));
    let _active = ActiveFlow::enter(Arc::clone(state));
    engine
        .eval_with_scope::<T>(&mut scope, script)
        .unwrap_or_else(|e| panic!("script failed: {e}"))
}

fn headers_of(state: &Arc<Mutex<FlowState>>) -> Vec<(String, String)> {
    state
        .lock()
        .unwrap()
        .request
        .as_ref()
        .expect("http state has a request")
        .headers
        .clone()
}

#[test]
fn script_sets_header_both_ways() {
    let state = http_state();
    run_with_flow::<()>(
        &state,
        r#"flow.request.headers.set("X-A", "1"); flow.request.headers["X-B"] = "2";"#,
    );
    let headers = headers_of(&state);
    assert!(
        headers.contains(&("X-A".to_string(), "1".to_string())),
        "{headers:?}"
    );
    assert!(
        headers.contains(&("X-B".to_string(), "2".to_string())),
        "{headers:?}"
    );
}

#[test]
fn script_reads_and_sets_request() {
    let state = http_state();
    let url: String = run_with_flow(&state, r#"flow.request.method = "PUT"; flow.request.url"#);
    assert_eq!(url, "http://ex.test/items?q=1");
    let method = state
        .lock()
        .unwrap()
        .request
        .as_ref()
        .unwrap()
        .method
        .clone();
    assert_eq!(method, "PUT");
}

#[test]
fn set_response_then_halt() {
    let state = http_state();
    run_with_flow::<()>(&state, r#"flow.set_response(403, #{}, "no"); halt();"#);
    let effects = state.lock().unwrap().effects.clone();
    assert_eq!(
        effects,
        vec![
            FlowEffect::SetResponse {
                status: 403,
                headers: Vec::new(),
                body: b"no".to_vec(),
            },
            FlowEffect::Halt,
        ]
    );
}

#[test]
fn ws_message_drop_and_set_text() {
    let state = ws_state();
    let engine = engine();
    let mut scope = Scope::new();
    scope.push("msg", ScriptWsMessage::new(Arc::clone(&state)));
    engine
        .run_with_scope(&mut scope, r#"msg.set_text("redacted"); msg.drop();"#)
        .unwrap_or_else(|e| panic!("script failed: {e}"));
    let st = state.lock().unwrap();
    assert_eq!(st.ws_message.as_ref().unwrap().data, b"redacted".to_vec());
    assert_eq!(st.effects, vec![FlowEffect::DropWsMessage]);
}

/// Option C: a pure read of something absent is `""`, never an error.
#[test]
fn forgiving_missing_header_read() {
    let state = http_state();
    let got: rhai::Array = run_with_flow(
        &state,
        r#"[flow.request.headers.get("Nope"), flow.request.query["absent"]]"#,
    );
    let got: Vec<String> = got.into_iter().map(|d| d.into_string().unwrap()).collect();
    assert_eq!(got, vec!["".to_string(), "".to_string()]);
    // The misses left the state untouched.
    assert_eq!(
        headers_of(&state),
        vec![("Host".to_string(), "ex.test".to_string())]
    );
}
