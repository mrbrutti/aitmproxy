//! The sans-IO HTTP/1.1 machine: parses heads, streams bodies chunk by chunk
//! without buffering them whole, detects upgrades, and encodes outbound messages.

use std::time::SystemTime;

use aitm_core::{Body, FlowId, HeaderMap, HttpRequest, HttpVersion};
use aitm_proto_http::sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};

/// The flow id carried by the first event, which must be `RequestHeaders`.
fn flow_of(events: &[HttpSansIoEvent]) -> FlowId {
    match events.first() {
        Some(HttpSansIoEvent::RequestHeaders(id)) => *id,
        other => panic!("first event was {other:?}, want RequestHeaders"),
    }
}

#[test]
fn parse_request_headers_and_complete() {
    let mut m = Http1Machine::new();
    let events = m
        .on_bytes(Side::Client, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
        .unwrap();
    let id = flow_of(&events);
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::RequestHeaders(id),
            HttpSansIoEvent::RequestComplete(id)
        ]
    );

    let req = m.request().expect("parsed request is readable");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/x");
    assert_eq!(req.authority, "h");
    assert_eq!(req.version, HttpVersion::Http11);
    assert_eq!(req.headers.get("host"), Some("h"));
}

/// A header value with a control byte must fail the parse, not get silently
/// dropped: dropping `Content-Length` would let the peer frame the message with
/// the header while the machine frames it without — request/response smuggling.
#[test]
fn invalid_header_byte_fails_closed() {
    let mut m = Http1Machine::new();
    let result = m.on_bytes(
        Side::Client,
        b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\x01\r\n\r\n",
    );
    assert!(
        result.is_err(),
        "a control char in a header value must fail the parse, got {result:?}"
    );
}

#[test]
fn chunked_body_streams() {
    let mut m = Http1Machine::new();
    let first = m
        .on_bytes(
            Side::Client,
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n",
        )
        .unwrap();
    let id = flow_of(&first);
    assert_eq!(
        first,
        vec![
            HttpSansIoEvent::RequestHeaders(id),
            HttpSansIoEvent::RequestBodyChunk {
                flow: id,
                bytes: b"ab".to_vec()
            },
        ],
        "first call must yield the first chunk alone, not wait for the body"
    );

    let second = m.on_bytes(Side::Client, b"2\r\ncd\r\n0\r\n\r\n").unwrap();
    assert_eq!(
        second,
        vec![
            HttpSansIoEvent::RequestBodyChunk {
                flow: id,
                bytes: b"cd".to_vec()
            },
            HttpSansIoEvent::RequestComplete(id),
        ],
        "second chunk must arrive on its own, before completion"
    );
}

#[test]
fn detects_ws_upgrade() {
    let mut m = Http1Machine::new();
    let events = m
        .on_bytes(
            Side::Client,
            b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .unwrap();
    let id = flow_of(&events);
    match events.last() {
        Some(HttpSansIoEvent::Upgrade { flow, protocol }) => {
            assert_eq!(*flow, id);
            assert_eq!(protocol, "websocket");
        }
        other => panic!("last event was {other:?}, want Upgrade"),
    }
}

#[test]
fn content_length_response_streams() {
    let mut m = Http1Machine::new();
    let req_events = m
        .on_bytes(Side::Client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
        .unwrap();
    let id = flow_of(&req_events);

    let head = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-A: 1\r\n\r\nab",
        )
        .unwrap();
    assert_eq!(
        head,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"ab".to_vec()
            },
        ]
    );
    let resp = m.response().expect("parsed response is readable");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers.get("x-a"), Some("1"));

    let rest = m.on_bytes(Side::Server, b"cd").unwrap();
    assert_eq!(
        rest,
        vec![
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"cd".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
}

#[test]
fn encodes_request_for_server() {
    let mut m = Http1Machine::new();
    assert_eq!(m.poll_outbound(Side::Server), None, "nothing queued yet");

    let mut headers = HeaderMap::new();
    headers.set("Host", "h");
    let req = HttpRequest {
        method: "GET".to_string(),
        scheme: "http".to_string(),
        authority: "h".to_string(),
        path: "/x".to_string(),
        version: HttpVersion::Http11,
        headers,
        body: Body::Empty,
        timestamp: SystemTime::now(),
    };
    m.enqueue_request(&req);
    assert_eq!(
        m.poll_outbound(Side::Server).as_deref(),
        Some(&b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"[..])
    );
    assert_eq!(m.poll_outbound(Side::Server), None, "queue drains once");
    assert_eq!(
        m.poll_outbound(Side::Client),
        None,
        "nothing for the client"
    );

    // A buffered body is sent with a Content-Length matching its real length,
    // replacing whatever a plugin left behind.
    let mut headers = HeaderMap::new();
    headers.set("Host", "h");
    headers.set("Content-Length", "99");
    let post = HttpRequest {
        method: "POST".to_string(),
        path: "/u".to_string(),
        headers,
        body: Body::Bytes(b"hi".to_vec()),
        ..req
    };
    m.enqueue_request(&post);
    assert_eq!(
        m.poll_outbound(Side::Server).as_deref(),
        Some(&b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi"[..])
    );
}
