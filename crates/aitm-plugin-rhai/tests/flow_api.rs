//! Task 5 — the Rhai flow handles over a shared `FlowState`. Each test
//! registers the flow API on a hardened engine, pushes a handle over a seeded
//! state into the scope, runs a script, and asserts the state afterwards.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aitm_core::{FlowId, FlowKind};
use aitm_plugin_rhai::config::RhaiLimits;
use aitm_plugin_rhai::engine::build_engine;
use aitm_plugin_rhai::flow_api::{register_flow_api, ActiveFlow, ScriptFlow, ScriptWsMessage};
use aitm_plugin_rhai::flow_state::{
    FlowEffect, FlowState, RequestState, ResponseState, WsMessageState,
};
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

/// Security review (M3, Important): a script sees the whole body the proxy
/// buffered. The engine's string/blob limits default to the snapshot cap, so a
/// 100 KiB body — well past the 64 KiB that used to throw — reads whole as
/// text and as bytes, and a needle at its very end is found.
#[test]
fn large_bodies_read_whole() {
    let mut body = vec![b'a'; 100 * 1024 - 6];
    body.extend_from_slice(b"needle");
    let state = http_state();
    {
        let mut st = state.lock().unwrap();
        st.request.as_mut().unwrap().body = vec![b'b'; 20 * 1024];
        st.response = Some(ResponseState {
            status: 200,
            headers: Vec::new(),
            body: body.clone(),
        });
    }
    let got: rhai::Array = run_with_flow(
        &state,
        r#"[flow.response.body.len(), "needle" in flow.response.body, flow.response.bytes.len(), flow.request.bytes.len()]"#,
    );
    assert_eq!(got[0].as_int().unwrap(), 100 * 1024);
    assert!(got[1].as_bool().unwrap(), "the needle at the end is found");
    assert_eq!(got[2].as_int().unwrap(), 100 * 1024);
    assert_eq!(got[3].as_int().unwrap(), 20 * 1024);
}

/// Quality review (M3, Important): a response write before a response exists
/// (the request phase) is a loud error, not a fabricated status-0 response the
/// proxy would serve. Reads stay forgiving; the explicit `set_response` is the
/// one way to answer a request.
#[test]
fn response_write_before_a_response_exists_is_an_error() {
    let state = http_state();
    let status: i64 = run_with_flow(&state, "flow.response.status");
    assert_eq!(status, 0, "a forgiving read of the absent response");

    let engine = engine();
    for write in [
        r#"flow.response.status = 403"#,
        r#"flow.response.body = "x""#,
        r#"flow.response.headers.set("X-Seen", "1")"#,
        r#"flow.response.headers["X-Seen"] = "1""#,
        r#"flow.response.headers.remove("X-Seen")"#,
    ] {
        let mut scope = Scope::new();
        scope.push("flow", ScriptFlow(Arc::clone(&state)));
        let err = engine
            .run_with_scope(&mut scope, write)
            .expect_err("a write to the absent response must fail");
        let text = err.to_string();
        assert!(
            text.contains("no response yet") && text.contains("set_response"),
            "{write}: the error says what to do instead: {text}"
        );
    }
    assert!(
        state.lock().unwrap().response.is_none(),
        "no response was fabricated"
    );
}

/// Security review (M3, Minor, SHOULD-fix): the request setters are
/// validated. The method must be an HTTP token, and `url` may change the
/// path and query but not re-target the authority — another host is reached
/// through the guarded `http.send`, never by rewriting a live request.
#[test]
fn request_setters_are_validated() {
    let state = http_state();
    let engine = engine();
    for (write, names) in [
        (r#"flow.request.method = "GE T""#, "token"),
        (r#"flow.request.url = "http://other.internal/x""#, "host"),
        (r#"flow.request.url = "https://ex.test/x""#, "host"),
    ] {
        let mut scope = Scope::new();
        scope.push("flow", ScriptFlow(Arc::clone(&state)));
        let err = engine
            .run_with_scope(&mut scope, write)
            .expect_err("the write must be refused");
        assert!(err.to_string().contains(names), "{write}: {err}");
    }
    {
        let st = state.lock().unwrap();
        let req = st.request.as_ref().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://ex.test/items?q=1");
    }

    // Same origin, a bare path, and a token method all go through.
    let url: String = run_with_flow(
        &state,
        r#"flow.request.method = "PURGE"; flow.request.url = "http://ex.test/moved?x=2"; flow.request.url"#,
    );
    assert_eq!(url, "http://ex.test/moved?x=2");
    let url: String = run_with_flow(&state, r#"flow.request.url = "/again"; flow.request.url"#);
    assert_eq!(url, "http://ex.test/again", "a bare path keeps the origin");
}

/// C2 (Critical): the live request-line setters reject CR/LF, space, and other
/// control characters, so an `on_request` hook cannot split the upstream
/// request or inject a header through `flow.request.path` / `.url` — HTTP
/// request smuggling from the sandboxed scripting surface.
#[test]
fn path_and_url_setters_reject_request_line_injection() {
    let state = http_state();
    let engine = engine();
    for write in [
        r#"flow.request.path = "/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /b""#,
        r#"flow.request.url = "/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /b""#,
        r#"flow.request.path = "/with space""#,
    ] {
        let mut scope = Scope::new();
        scope.push("flow", ScriptFlow(Arc::clone(&state)));
        let err = engine
            .run_with_scope(&mut scope, write)
            .expect_err("a control/space request target must be refused");
        assert!(
            err.to_string().contains("control character"),
            "{write}: {err}"
        );
    }
    let st = state.lock().unwrap();
    let req = st.request.as_ref().unwrap();
    assert_eq!(req.path, "/items", "the injected path was never written");
    assert_eq!(
        req.url, "http://ex.test/items?q=1",
        "the injected url was never written"
    );
}

/// Minor(b): a live header `set` with an invalid name or a control-bearing
/// value is a catchable error, not a silent `Ok` whose value is dropped when
/// the host writes the flow back through `HeaderMap::try_set`.
#[test]
fn header_set_rejects_invalid_name_or_value() {
    let state = http_state();
    let engine = engine();
    for write in [
        r#"flow.request.headers.set("X-Evil", "a\r\nInjected: 1")"#,
        r#"flow.request.headers["X-Evil"] = "a\r\nInjected: 1""#,
        r#"flow.request.headers.set("Bad Name", "ok")"#,
    ] {
        let mut scope = Scope::new();
        scope.push("flow", ScriptFlow(Arc::clone(&state)));
        let err = engine
            .run_with_scope(&mut scope, write)
            .expect_err("an invalid header must be refused");
        assert!(err.to_string().contains("refused"), "{write}: {err}");
    }
    assert_eq!(
        headers_of(&state),
        vec![("Host".to_string(), "ex.test".to_string())],
        "no invalid header was written"
    );
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
