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

/// A machine that has been fed `request` on the client side, plus the flow id of
/// the exchange the request opened.
fn exchange(request: &[u8]) -> (Http1Machine, FlowId) {
    let mut m = Http1Machine::new();
    let events = m.on_bytes(Side::Client, request).unwrap();
    let id = flow_of(&events);
    (m, id)
}

/// A `GET` answered in full with `ok`, so the machine is idle and ready for the
/// next exchange. Returns the machine and the completed exchange's flow id.
fn completed_exchange() -> (Http1Machine, FlowId) {
    let (mut m, id) = exchange(b"GET /done HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"ok".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    (m, id)
}

// ---------------------------------------------------------------------------
// Well-behaved server traffic: how the machine answers it. Each of these keeps
// working while server bytes that no request awaits are left unparsed.
// ---------------------------------------------------------------------------

#[test]
fn head_response_completes_without_a_body() {
    let (mut m, id) = exchange(b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn not_modified_response_completes_without_a_body() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn no_content_response_completes_without_a_body() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(Side::Server, b"HTTP/1.1 204 No Content\r\n\r\n")
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn chunked_response_streams_and_completes() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwxyz\r\n0\r\n\r\n",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"wxyz".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn close_delimited_response_completes_at_eof() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(Side::Server, b"HTTP/1.1 200 OK\r\n\r\nbody")
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"body".to_vec()
            },
        ]
    );
    assert_eq!(
        m.on_eof(Side::Server),
        vec![HttpSansIoEvent::ResponseComplete(id)]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn interim_continue_is_skipped_before_the_final_response() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"ok".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(m.response().unwrap().status, 200);
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn switching_protocols_leaves_the_following_bytes_for_the_next_protocol() {
    let (mut m, id) = exchange(
        b"GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    );
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nWSDATA",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert!(m.is_upgraded());
    assert_eq!(m.take_leftover(Side::Server), b"WSDATA".to_vec());
}

#[test]
fn a_pipelined_request_is_parsed_after_the_first_response() {
    let mut m = Http1Machine::new();
    let first = m
        .on_bytes(
            Side::Client,
            b"GET /1 HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\n\r\n",
        )
        .unwrap();
    let id1 = flow_of(&first);
    assert_eq!(
        first,
        vec![
            HttpSansIoEvent::RequestHeaders(id1),
            HttpSansIoEvent::RequestComplete(id1),
        ],
        "the second request stays parked until the first is answered"
    );

    let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let r1 = m.on_bytes(Side::Server, answer).unwrap();
    assert_eq!(
        r1,
        vec![
            HttpSansIoEvent::ResponseHeaders(id1),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id1,
                bytes: b"ok".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id1),
        ]
    );

    let second = m.on_bytes(Side::Client, b"").unwrap();
    let id2 = flow_of(&second);
    assert_ne!(id1, id2);
    assert_eq!(
        second,
        vec![
            HttpSansIoEvent::RequestHeaders(id2),
            HttpSansIoEvent::RequestComplete(id2),
        ]
    );

    let r2 = m.on_bytes(Side::Server, answer).unwrap();
    assert_eq!(
        r2,
        vec![
            HttpSansIoEvent::ResponseHeaders(id2),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id2,
                bytes: b"ok".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id2),
        ]
    );
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn a_response_before_any_request_is_an_error() {
    let mut m = Http1Machine::new();
    let result = m.on_bytes(
        Side::Server,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(
        result.is_err(),
        "response bytes before any request must be an error, got {result:?}"
    );
}

#[test]
fn a_partial_second_head_in_the_same_read_stays_buffered() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegitHTTP/1.1 500 Injected\r\nX-Junk: ",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"legit".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(
        m.take_leftover(Side::Server),
        b"HTTP/1.1 500 Injected\r\nX-Junk: ".to_vec()
    );
}

#[test]
fn unsolicited_server_bytes_beyond_the_head_cap_are_an_error() {
    let (mut m, _id) = completed_exchange();
    let result = m.on_bytes(Side::Server, &vec![b'x'; 64 * 1024 + 1]);
    assert!(
        result.is_err(),
        "unsolicited bytes past the 64 KiB head cap must be an error, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Surplus server bytes: a response head is parsed only while a request awaits
// one. Anything else the server sends stays in its buffer, unparsed.
// ---------------------------------------------------------------------------

#[test]
fn a_second_complete_response_in_the_same_read_is_left_unparsed() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegitHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"legit".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(
        m.response().unwrap().headers.get("content-length"),
        Some("5"),
        "the stray response must not replace the legitimate head"
    );
    assert_eq!(
        m.take_leftover(Side::Server),
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON".to_vec()
    );
}

#[test]
fn a_response_after_the_exchange_completed_is_not_parsed() {
    let (mut m, _id) = completed_exchange();
    let stray = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON";
    let events = m.on_bytes(Side::Server, stray).unwrap();
    assert_eq!(events, vec![]);
    assert_eq!(m.take_leftover(Side::Server), stray.to_vec());
}

#[test]
fn a_response_while_the_request_body_is_arriving_waits_for_the_request() {
    let mut m = Http1Machine::new();
    let first = m
        .on_bytes(
            Side::Client,
            b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab",
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
        ]
    );

    let early = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
    assert_eq!(
        early,
        vec![],
        "a response is not parsed while its request is still arriving"
    );

    let rest = m.on_bytes(Side::Client, b"cd").unwrap();
    assert_eq!(
        rest,
        vec![
            HttpSansIoEvent::RequestBodyChunk {
                flow: id,
                bytes: b"cd".to_vec()
            },
            HttpSansIoEvent::RequestComplete(id),
        ]
    );

    // The parked response is released once the request is complete.
    let released = m.on_bytes(Side::Server, b"").unwrap();
    assert_eq!(
        released,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
}

// ---------------------------------------------------------------------------
// Edge cases a proxy must survive: what a hostile or broken origin can leave
// behind a completed response.
// ---------------------------------------------------------------------------

/// The head cap is a limit on what is buffered, so exactly the cap is fine and
/// one byte more is not. Pins the boundary of the check, not just "big is bad".
#[test]
fn unsolicited_server_bytes_up_to_the_head_cap_are_buffered() {
    let (mut m, _id) = completed_exchange();
    let stray = vec![b'x'; 64 * 1024];
    assert_eq!(m.on_bytes(Side::Server, &stray).unwrap(), vec![]);
    assert_eq!(m.take_leftover(Side::Server), stray);
}

/// A driver that keeps feeding unsolicited bytes in small reads must hit the cap
/// too: it applies to what has piled up, not to each read on its own.
#[test]
fn unsolicited_server_bytes_count_toward_the_head_cap_across_reads() {
    let (mut m, _id) = completed_exchange();
    assert_eq!(
        m.on_bytes(Side::Server, &vec![b'x'; 40 * 1024]).unwrap(),
        vec![]
    );
    let result = m.on_bytes(Side::Server, &vec![b'x'; 40 * 1024]);
    assert!(
        result.is_err(),
        "80 KiB of unsolicited bytes in two reads must pass the 64 KiB cap, got {result:?}"
    );
}

/// The cap holds in the other state that leaves server bytes parked: a request
/// whose body is still arriving.
#[test]
fn unsolicited_server_bytes_beyond_the_head_cap_are_an_error_while_a_request_is_arriving() {
    let mut m = Http1Machine::new();
    m.on_bytes(
        Side::Client,
        b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab",
    )
    .unwrap();
    let result = m.on_bytes(Side::Server, &vec![b'x'; 64 * 1024 + 1]);
    assert!(
        result.is_err(),
        "server bytes parked past the 64 KiB cap must be an error, got {result:?}"
    );
}

/// An empty read after a completed exchange is not an event and not an error.
#[test]
fn an_empty_server_read_after_a_completed_exchange_is_a_no_op() {
    let (mut m, _id) = completed_exchange();
    assert_eq!(m.on_bytes(Side::Server, b"").unwrap(), vec![]);
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

/// Bytes that are not HTTP at all, ending in a blank line, would make a parser
/// that took them for a response head fail the whole connection. Left unparsed,
/// they cost the legitimate response nothing.
#[test]
fn garbage_after_a_completed_response_is_left_unparsed() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit\x00\x01\x02 not http at all\r\n\r\n",
        )
        .unwrap();
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::ResponseHeaders(id),
            HttpSansIoEvent::ResponseBodyChunk {
                flow: id,
                bytes: b"legit".to_vec()
            },
            HttpSansIoEvent::ResponseComplete(id),
        ]
    );
    assert_eq!(
        m.take_leftover(Side::Server),
        b"\x00\x01\x02 not http at all\r\n\r\n".to_vec()
    );
}

/// Some old servers end a body with a bare CRLF. It is surplus like any other
/// byte (the driver treats it as such), and it must not be parsed away.
#[test]
fn a_bare_crlf_after_a_completed_response_is_left_for_the_driver() {
    let (mut m, id) = exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");
    let events = m
        .on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlegit\r\n",
        )
        .unwrap();
    assert_eq!(events.last(), Some(&HttpSansIoEvent::ResponseComplete(id)));
    assert_eq!(m.take_leftover(Side::Server), b"\r\n".to_vec());
}

/// The server hanging up after a completed exchange, with unsolicited bytes
/// still parked, completes nothing and invents no events.
#[test]
fn eof_after_a_completed_exchange_with_parked_bytes_emits_nothing() {
    let (mut m, _id) = completed_exchange();
    assert_eq!(
        m.on_bytes(
            Side::Server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON"
        )
        .unwrap(),
        vec![]
    );
    assert_eq!(m.on_eof(Side::Server), vec![]);
}
