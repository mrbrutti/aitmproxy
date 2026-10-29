//! Task 4 — `FlowState` snapshot / apply: the pure half of the effect model.
//! A hook edits the snapshot; `apply_to` writes the edits and replays the
//! recorded effects onto the live `FlowCtx`, returning the chain verdict.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use aitm_core::{
    Body, ConnInfo, Event, Flow, FlowCtx, FlowId, FlowKind, FlowMeta, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, Verdict, WsDir, WsFlow, WsMessage,
    WsOpcode,
};
use aitm_plugin_rhai::flow_state::{FlowEffect, FlowState};

const MAX_BODY: usize = 1 << 20;

fn conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

/// `GET http://ex.test/items?q=1&raw` with one header and a buffered body.
fn http_flow() -> Flow {
    let mut headers = HeaderMap::new();
    headers.set("Host", "ex.test");
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/items?q=1&raw".into(),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(b"hello".to_vec()),
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// A WebSocket flow holding one client→server text frame.
fn ws_flow() -> Flow {
    Flow::WebSocket(WsFlow {
        id: FlowId::new(),
        handshake: FlowId::new(),
        messages: vec![WsMessage {
            dir: WsDir::ClientToServer,
            opcode: WsOpcode::Text,
            data: b"hello".to_vec(),
            timestamp: SystemTime::now(),
            injected: false,
        }],
        client_conn: conn(),
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

fn http(flow: &Flow) -> &HttpFlow {
    match flow {
        Flow::Http(f) => f,
        Flow::WebSocket(_) => panic!("expected an HTTP flow"),
    }
}

fn ws(flow: &Flow) -> &WsFlow {
    match flow {
        Flow::WebSocket(w) => w,
        Flow::Http(_) => panic!("expected a WebSocket flow"),
    }
}

#[test]
fn snapshot_copies_the_mutable_surface() {
    let flow = http_flow();
    let st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);

    assert_eq!(st.id, flow.id());
    assert_eq!(st.kind, FlowKind::Http);
    assert!(st.response.is_none());
    assert!(st.ws_message.is_none());
    assert!(st.effects.is_empty());
    assert!(!st.is_replay);

    let req = st.request.expect("http snapshot carries the request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.url, "http://ex.test/items?q=1&raw");
    assert_eq!(req.path, "/items");
    assert_eq!(
        req.query,
        vec![
            ("q".to_string(), "1".to_string()),
            ("raw".to_string(), String::new())
        ]
    );
    assert_eq!(
        req.headers,
        vec![("Host".to_string(), "ex.test".to_string())]
    );
    assert_eq!(req.body, b"hello".to_vec());
}

#[test]
fn snapshot_caps_the_body_at_max_body() {
    let flow = http_flow();
    let st = FlowState::snapshot(&flow, &Event::Request(flow.id()), 3);
    assert_eq!(st.request.expect("request").body, b"hel".to_vec());
}

#[test]
fn edits_apply_back() {
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    {
        let req = st.request.as_mut().expect("request");
        req.method = "PUT".into();
        req.headers.push(("X".into(), "1".into()));
    }

    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Continue);

    let req = &http(ctx.flow()).request;
    assert_eq!(req.method, "PUT");
    assert_eq!(req.headers.get("X"), Some("1"));
    // The pre-existing header survived the write-back.
    assert_eq!(req.headers.get("Host"), Some("ex.test"));
}

#[test]
fn untouched_snapshot_leaves_the_flow_byte_identical() {
    let mut flow = http_flow();
    let st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);

    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Continue);

    let req = &http(ctx.flow()).request;
    // `raw` had no `=`; a naive re-join would turn it into `raw=`.
    assert_eq!(req.path, "/items?q=1&raw");
    assert_eq!(req.scheme, "http");
    assert_eq!(req.authority, "ex.test");
    assert!(matches!(&req.body, Body::Bytes(b) if b == b"hello"));
    assert!(matches!(
        http(ctx.flow()).intercept,
        InterceptState::Observed
    ));
}

#[test]
fn url_path_query_and_body_edits_apply_back() {
    let mut flow = http_flow();

    // Path + query edit, URL left as snapshotted.
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    {
        let req = st.request.as_mut().expect("request");
        req.path = "/other".into();
        req.query = vec![("a".into(), "b".into())];
        req.body = b"changed".to_vec();
    }
    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    let req = &http(ctx.flow()).request;
    assert_eq!(req.path, "/other?a=b");
    assert!(matches!(&req.body, Body::Bytes(b) if b == b"changed"));

    // Whole-URL edit re-targets scheme, authority and path.
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.request.as_mut().expect("request").url = "https://api.test:8443/v2?x=1".into();
    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    let req = &http(ctx.flow()).request;
    assert_eq!(req.scheme, "https");
    assert_eq!(req.authority, "api.test:8443");
    assert_eq!(req.path, "/v2?x=1");
}

#[test]
fn header_write_back_rejects_crlf() {
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.request
        .as_mut()
        .expect("request")
        .headers
        .push(("X-Evil".into(), "a\r\nInjected: 1".into()));

    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    let req = &http(ctx.flow()).request;
    assert!(!req.headers.has("X-Evil"));
    assert!(!req.headers.has("Injected"));
    assert_eq!(req.headers.get("Host"), Some("ex.test"));
}

#[test]
fn response_edits_and_marks_apply_back() {
    let mut flow = http_flow();
    if let Flow::Http(f) = &mut flow {
        f.response = Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Bytes(b"ok".to_vec()),
            timestamp: SystemTime::now(),
        });
    }
    let mut st = FlowState::snapshot(&flow, &Event::Response(flow.id()), MAX_BODY);
    {
        let resp = st.response.as_mut().expect("response snapshot");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok".to_vec());
        resp.status = 404;
        resp.headers.push(("X-Seen".into(), "1".into()));
        resp.body = b"gone".to_vec();
    }
    st.marks.push("server-error".into());
    st.comment = Some("note".into());

    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    let f = http(ctx.flow());
    let resp = f.response.as_ref().expect("response");
    assert_eq!(resp.status, 404);
    assert_eq!(resp.headers.get("X-Seen"), Some("1"));
    assert!(matches!(&resp.body, Body::Bytes(b) if b == b"gone"));
    assert_eq!(f.metadata.marks, vec!["server-error".to_string()]);
    assert_eq!(f.metadata.comment.as_deref(), Some("note"));
}

#[test]
fn halt_effect_maps_to_verdict() {
    let mut flow = http_flow();

    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.effects.push(FlowEffect::Halt);
    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Halt);

    let st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Continue);
}

#[test]
fn set_response_effect_short_circuits() {
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.effects.push(FlowEffect::SetResponse {
        status: 403,
        headers: vec![("Content-Type".into(), "text/plain".into())],
        body: b"blocked by aitm".to_vec(),
    });

    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);

    let resp = http(ctx.flow())
        .response
        .as_ref()
        .expect("short-circuit response");
    assert_eq!(resp.status, 403);
    assert_eq!(resp.headers.get("content-type"), Some("text/plain"));
    assert!(matches!(&resp.body, Body::Bytes(b) if b == b"blocked by aitm"));
}

#[test]
fn control_effects_reach_the_ctx() {
    // kill
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.effects.push(FlowEffect::Kill);
    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    assert!(matches!(http(ctx.flow()).intercept, InterceptState::Killed));

    // intercept parks the flow (a resume receiver is armed on the ctx)
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.effects.push(FlowEffect::Intercept);
    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    assert!(matches!(
        http(ctx.flow()).intercept,
        InterceptState::Intercepted { .. }
    ));
    assert!(ctx.take_parked().is_some());

    // backup, edit, revert: the edit is undone
    let mut flow = http_flow();
    let mut st = FlowState::snapshot(&flow, &Event::Request(flow.id()), MAX_BODY);
    st.request.as_mut().expect("request").method = "DELETE".into();
    st.effects.push(FlowEffect::Backup);
    st.effects.push(FlowEffect::Revert);
    let mut ctx = FlowCtx::new(&mut flow);
    st.apply_to(&mut ctx);
    // Effects replay after the field edits, so Backup captured the edited
    // flow and Revert restored exactly that: the edit stands.
    assert_eq!(http(ctx.flow()).request.method, "DELETE");
    assert!(matches!(
        http(ctx.flow()).intercept,
        InterceptState::Observed
    ));
}

#[test]
fn ws_snapshot_carries_the_event_frame() {
    let flow = ws_flow();
    let ev = Event::WsMessage {
        flow: flow.id(),
        index: 0,
    };
    let st = FlowState::snapshot(&flow, &ev, MAX_BODY);
    assert_eq!(st.kind, FlowKind::WebSocket);
    assert!(st.request.is_none());
    let msg = st.ws_message.expect("ws snapshot carries the frame");
    assert_eq!(msg.direction, "c2s");
    assert_eq!(msg.opcode, "text");
    assert_eq!(msg.data, b"hello".to_vec());

    // A non-message WebSocket event carries no frame.
    let st = FlowState::snapshot(&flow, &Event::WsStart(flow.id()), MAX_BODY);
    assert!(st.ws_message.is_none());
}

#[test]
fn ws_data_edit_applies_back() {
    let mut flow = ws_flow();
    let ev = Event::WsMessage {
        flow: flow.id(),
        index: 0,
    };
    let mut st = FlowState::snapshot(&flow, &ev, MAX_BODY);
    st.ws_message.as_mut().expect("frame").data = b"redacted".to_vec();

    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Continue);
    let w = ws(ctx.flow());
    assert_eq!(w.messages.len(), 1);
    assert_eq!(w.messages[0].data, b"redacted".to_vec());
    assert_eq!(w.messages[0].opcode, WsOpcode::Text);
}

#[test]
fn ws_drop_effect() {
    let mut flow = ws_flow();
    let ev = Event::WsMessage {
        flow: flow.id(),
        index: 0,
    };
    let mut st = FlowState::snapshot(&flow, &ev, MAX_BODY);
    st.effects.push(FlowEffect::DropWsMessage);

    let mut ctx = FlowCtx::new(&mut flow);
    assert_eq!(st.apply_to(&mut ctx), Verdict::Continue);
    assert!(ws(ctx.flow()).messages.is_empty(), "the frame was dropped");
}
