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

// ---------------------------------------------------------------------------
// Chunked trailer sections: captured on the response model, bounded, and
// fail-closed. The trailers ride on `response()`; the event stream is the same
// as it is for a chunked response without any.
// ---------------------------------------------------------------------------

/// A `GET` the machine has parsed, awaiting a response.
fn get_exchange() -> (Http1Machine, FlowId) {
    exchange(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
}

/// A chunked response head that declares two trailers, and its one `wxyz` chunk.
const CH: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-A, X-B\r\n\r\n4\r\nwxyz\r\n";

/// The zero-size chunk and a trailer section of three fields, one repeated.
const SECTION: &[u8] = b"0\r\nX-A: 1\r\nx-b: two words\r\nX-A: 3\r\n\r\n";

/// What `SECTION` carries, in wire order, with the case and the duplicate kept.
const SECTION_FIELDS: [(&str, &str); 3] = [("X-A", "1"), ("x-b", "two words"), ("X-A", "3")];

/// The events a chunked response with one `wxyz` chunk yields, trailers or not.
fn chunked_response_events(id: FlowId) -> Vec<HttpSansIoEvent> {
    vec![
        HttpSansIoEvent::ResponseHeaders(id),
        HttpSansIoEvent::ResponseBodyChunk {
            flow: id,
            bytes: b"wxyz".to_vec(),
        },
        HttpSansIoEvent::ResponseComplete(id),
    ]
}

/// The captured trailers of the current response, as `(name, value)` pairs.
fn trailers_of(m: &Http1Machine) -> Vec<(&str, &str)> {
    m.response()
        .expect("a response head was parsed")
        .trailers
        .iter()
        .collect()
}

/// A machine that has the response head and `wxyz` chunk and the zero-size
/// chunk's line, so the next bytes it is fed are the trailer section.
fn at_trailer_section() -> (Http1Machine, FlowId) {
    let (mut m, id) = get_exchange();
    let events = m.on_bytes(Side::Server, CH).unwrap();
    assert_eq!(events, chunked_response_events(id)[..2].to_vec());
    assert_eq!(m.on_bytes(Side::Server, b"0\r\n").unwrap(), vec![]);
    (m, id)
}

/// `n` trailer fields `f0: v` .. `f{n-1}: v`, then the blank line that ends the
/// section.
fn fields(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..n {
        out.extend_from_slice(format!("f{i}: v\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// One trailer field whose line plus its CRLF is `counted` bytes, then the blank
/// line that ends the section (which is not counted).
fn one_field_counting(counted: usize) -> Vec<u8> {
    let name = "x-a: ";
    let mut out = format!("{name}{}\r\n", "v".repeat(counted - name.len() - 2)).into_bytes();
    out.extend_from_slice(b"\r\n");
    out
}

#[test]
fn chunked_response_trailers_are_captured_in_order() {
    let (mut m, id) = get_exchange();
    let mut wire = CH.to_vec();
    wire.extend_from_slice(SECTION);
    let events = m.on_bytes(Side::Server, &wire).unwrap();
    assert_eq!(events, chunked_response_events(id));

    assert_eq!(trailers_of(&m), SECTION_FIELDS.to_vec());
    let resp = m.response().unwrap();
    assert_eq!(
        resp.headers.get("x-a"),
        None,
        "a trailer is never merged into the headers"
    );
    assert_eq!(resp.headers.get("trailer"), Some("X-A, X-B"));
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn trailers_split_at_every_position_give_the_same_result() {
    // Two reads, split at every byte index of the section.
    for split in 1..SECTION.len() {
        let (mut m, id) = get_exchange();
        let mut events = m.on_bytes(Side::Server, CH).unwrap();
        events.extend(m.on_bytes(Side::Server, &SECTION[..split]).unwrap());
        events.extend(m.on_bytes(Side::Server, &SECTION[split..]).unwrap());
        assert_eq!(events, chunked_response_events(id), "split at {split}");
        assert_eq!(trailers_of(&m), SECTION_FIELDS.to_vec(), "split at {split}");
        assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
    }

    // One byte at a time: the trailers appear on the model when the response
    // completes, never half populated before.
    let (mut m, id) = get_exchange();
    let mut events = m.on_bytes(Side::Server, CH).unwrap();
    for (i, byte) in SECTION.iter().enumerate() {
        assert!(
            trailers_of(&m).is_empty(),
            "no trailer is on the model before the section ends (byte {i})"
        );
        events.extend(m.on_bytes(Side::Server, &[*byte]).unwrap());
    }
    assert_eq!(events, chunked_response_events(id));
    assert_eq!(trailers_of(&m), SECTION_FIELDS.to_vec());
}

#[test]
fn a_chunked_response_without_trailers_has_none() {
    let (mut m, id) = get_exchange();
    let mut wire = CH.to_vec();
    wire.extend_from_slice(b"0\r\n\r\n");
    let events = m.on_bytes(Side::Server, &wire).unwrap();
    assert_eq!(events, chunked_response_events(id));
    assert!(m.response().unwrap().trailers.is_empty());
    assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
}

#[test]
fn a_response_with_trailers_leaves_the_machine_ready_for_the_next_exchange() {
    // Once with the trailer section in the same read as the zero chunk, once
    // with its fields in a later read (the zero chunk's line ends the first).
    for later_read in [false, true] {
        let (mut m, id) = get_exchange();
        let mut wire = CH.to_vec();
        wire.extend_from_slice(SECTION);
        if later_read {
            let split = CH.len() + b"0\r\n".len();
            m.on_bytes(Side::Server, &wire[..split]).unwrap();
            m.on_bytes(Side::Server, &wire[split..]).unwrap();
        } else {
            m.on_bytes(Side::Server, &wire).unwrap();
        }
        assert_eq!(trailers_of(&m), SECTION_FIELDS.to_vec());
        assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());

        let events = m
            .on_bytes(Side::Client, b"GET /y HTTP/1.1\r\nHost: h\r\n\r\n")
            .unwrap();
        let id2 = flow_of(&events);
        assert_ne!(id2, id, "the second request opens a new flow");
        assert_eq!(
            events,
            vec![
                HttpSansIoEvent::RequestHeaders(id2),
                HttpSansIoEvent::RequestComplete(id2)
            ]
        );
        let events = m
            .on_bytes(
                Side::Server,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )
            .unwrap();
        assert_eq!(
            events,
            vec![
                HttpSansIoEvent::ResponseHeaders(id2),
                HttpSansIoEvent::ResponseBodyChunk {
                    flow: id2,
                    bytes: b"ok".to_vec()
                },
                HttpSansIoEvent::ResponseComplete(id2),
            ]
        );
        assert!(
            m.response().unwrap().trailers.is_empty(),
            "the first response's trailers do not carry over (later_read={later_read})"
        );
        assert_eq!(m.take_leftover(Side::Server), Vec::<u8>::new());
    }
}

/// The trailer budget (64 fields, 16 KiB) belongs to one message: a full
/// section on the request and another on the response, twice over on one
/// machine, never runs into a limit carried over from the one before.
#[test]
fn the_trailer_budget_starts_over_for_every_message() {
    let mut m = Http1Machine::new();
    for round in 1..=2 {
        let mut request =
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n"
                .to_vec();
        request.extend_from_slice(&fields(64));
        let events = m
            .on_bytes(Side::Client, &request)
            .unwrap_or_else(|e| panic!("round {round}: the request's 64 fields: {e}"));
        assert_eq!(events.len(), 3, "round {round}");

        let mut response = CH.to_vec();
        response.extend_from_slice(b"0\r\n");
        response.extend_from_slice(&fields(64));
        let events = m
            .on_bytes(Side::Server, &response)
            .unwrap_or_else(|e| panic!("round {round}: the response's 64 fields: {e}"));
        assert_eq!(events.len(), 3, "round {round}");
        assert_eq!(m.response().unwrap().trailers.len(), 64, "round {round}");
    }
}

#[test]
fn trailer_caps_fail_closed() {
    // 64 fields is the limit: accepted, and every one of them captured.
    let (mut m, id) = at_trailer_section();
    let events = m
        .on_bytes(Side::Server, &fields(64))
        .expect("64 trailer fields are within the cap");
    assert_eq!(events, vec![HttpSansIoEvent::ResponseComplete(id)]);
    assert_eq!(m.response().unwrap().trailers.len(), 64);

    // The 65th field is refused, and the error names the trailer limit.
    let (mut m, _) = at_trailer_section();
    let err = m
        .on_bytes(Side::Server, &fields(65))
        .expect_err("65 trailer fields exceed the cap");
    assert!(err.to_string().contains("trailer"), "{err}");

    // 16384 counted bytes (each field line plus its CRLF, not the blank line
    // that ends the section) is the limit: accepted, and captured whole.
    let (mut m, id) = at_trailer_section();
    let events = m
        .on_bytes(Side::Server, &one_field_counting(16384))
        .expect("a section of exactly 16384 counted bytes is within the cap");
    assert_eq!(events, vec![HttpSansIoEvent::ResponseComplete(id)]);
    let captured: Vec<_> = m.response().unwrap().trailers.iter().collect();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "x-a");
    assert_eq!(captured[0].1.len(), 16377);

    // One byte more is refused.
    let (mut m, _) = at_trailer_section();
    let err = m
        .on_bytes(Side::Server, &one_field_counting(16385))
        .expect_err("16385 counted bytes exceed the cap");
    assert!(err.to_string().contains("trailer"), "{err}");

    // An unterminated partial line longer than the cap is refused at once: it
    // can never become a legal line, and waiting for its CRLF would let a peer
    // make the machine buffer without bound.
    let (mut m, _) = at_trailer_section();
    let err = m
        .on_bytes(Side::Server, &vec![b'v'; 16385])
        .expect_err("16385 bytes with no CRLF exceed the cap");
    assert!(err.to_string().contains("trailer"), "{err}");

    // A stream of tiny lines is refused at the 65th line, in the first 16 KiB
    // read, not consumed for as long as the peer keeps sending.
    let block = b"a: b\r\n".repeat(2730);
    assert_eq!(block.len(), 16380);
    let (mut m, _) = at_trailer_section();
    let err = m
        .on_bytes(Side::Server, &block)
        .expect_err("the 65th field line must end the connection");
    assert!(err.to_string().contains("trailer"), "{err}");
    assert_eq!(
        m.take_leftover(Side::Server).len(),
        (2730 - 65) * 6,
        "the parser stopped at the 65th line and did not read on"
    );

    // An endless stream of 1 KiB lines is refused at the line that crosses
    // 16384 counted bytes: the sixteenth is the last that fits.
    let kib = format!("x: {}\r\n", "v".repeat(1019)).into_bytes();
    assert_eq!(kib.len(), 1024);
    let (mut m, _) = at_trailer_section();
    for n in 1..=16 {
        let events = m
            .on_bytes(Side::Server, &kib)
            .unwrap_or_else(|e| panic!("line {n} of 16 is within the cap: {e}"));
        assert_eq!(events, vec![], "the section is still open after line {n}");
    }
    let err = m
        .on_bytes(Side::Server, &kib)
        .expect_err("the 17th 1 KiB line crosses 16384 counted bytes");
    assert!(err.to_string().contains("trailer"), "{err}");
}

#[test]
fn trailer_syntax_fails_closed() {
    let cases: [(&str, &[u8]); 9] = [
        ("control byte in a value", b"x-a: v\x01\r\n\r\n"),
        ("space inside a name", b"bad name: v\r\n\r\n"),
        ("non-token byte in a name", b"x@a: v\r\n\r\n"),
        ("no colon", b"no-colon\r\n\r\n"),
        ("empty name", b": v\r\n\r\n"),
        ("leading space (obs-fold)", b" x-a: v\r\n\r\n"),
        ("leading tab (obs-fold)", b"\tx-a: v\r\n\r\n"),
        ("obs-fold continuation", b"x-a: 1\r\n  more\r\n\r\n"),
        ("not UTF-8", b"x-a: \xff\r\n\r\n"),
    ];
    for (label, section) in cases {
        let (mut m, _) = at_trailer_section();
        let err = m.on_bytes(Side::Server, section).expect_err(label);
        assert!(
            err.to_string().contains("trailer"),
            "{label}: the error names a trailer: {err}"
        );
    }
}

/// Trailer names and values are attacker-controlled; the error that ends the
/// connection is logged by the accept loop, so it must not repeat them.
#[test]
fn trailer_errors_never_echo_the_field() {
    for section in [
        &b"x-leaktoken-7: v\x01\r\n\r\n"[..],
        b"bad leaktoken-7: v\r\n\r\n",
        b"x@leaktoken-7: v\r\n\r\n",
        b"no-colon-leaktoken-7\r\n\r\n",
        b" x-leaktoken-7: v\r\n\r\n",
    ] {
        let (mut m, _) = at_trailer_section();
        let err = m.on_bytes(Side::Server, section).expect_err("invalid");
        assert!(
            !err.to_string().contains("leaktoken"),
            "the error repeats the field: {err}"
        );
    }
}

#[test]
fn request_trailers_are_parsed_bounded_and_dropped() {
    let head = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n";

    // A well-formed trailer section: the events are exactly those of a chunked
    // request without one, and the field is dropped.
    let mut wire = head.to_vec();
    wire.extend_from_slice(b"X-T: 1\r\n\r\n");
    let mut m = Http1Machine::new();
    let events = m.on_bytes(Side::Client, &wire).unwrap();
    let id = flow_of(&events);
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::RequestHeaders(id),
            HttpSansIoEvent::RequestBodyChunk {
                flow: id,
                bytes: b"ab".to_vec()
            },
            HttpSansIoEvent::RequestComplete(id),
        ]
    );
    assert_eq!(m.take_leftover(Side::Client), Vec::<u8>::new());

    // The machine goes on to the next exchange.
    m.on_bytes(
        Side::Server,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    let events = m
        .on_bytes(Side::Client, b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n")
        .unwrap();
    let id2 = flow_of(&events);
    assert_ne!(id2, id);
    assert_eq!(
        events,
        vec![
            HttpSansIoEvent::RequestHeaders(id2),
            HttpSansIoEvent::RequestComplete(id2)
        ]
    );

    // The same section over a cap, or with an invalid line, is an error.
    for (label, section) in [
        ("65 fields", fields(65)),
        ("16385 counted bytes", one_field_counting(16385)),
        ("a name with a space", b"bad name: v\r\n\r\n".to_vec()),
        ("a control byte", b"x-t: v\x01\r\n\r\n".to_vec()),
    ] {
        let mut wire = head.to_vec();
        wire.extend_from_slice(&section);
        let mut m = Http1Machine::new();
        let err = m.on_bytes(Side::Client, &wire).expect_err(label);
        assert!(
            err.to_string().contains("trailer"),
            "{label}: the error names a trailer: {err}"
        );
    }

    // And 64 fields are still accepted and dropped.
    let mut wire = head.to_vec();
    wire.extend_from_slice(&fields(64));
    let mut m = Http1Machine::new();
    let events = m.on_bytes(Side::Client, &wire).unwrap();
    assert_eq!(events.len(), 3, "64 request trailer fields are accepted");
}

/// The origin hangs up inside the trailer section: two fields arrived whole and a
/// third was cut off, and no blank line ever came. A chunked body that was not
/// terminated is not a complete response, so the machine must not report one, and
/// must not capture half a section as if it were the origin's trailers.
#[test]
fn an_eof_inside_the_trailer_section_does_not_complete_the_response() {
    let (mut m, _) = at_trailer_section();
    assert_eq!(
        m.on_bytes(Side::Server, b"X-A: 1\r\nx-b: 2\r\nx-c: par")
            .unwrap(),
        vec![],
        "the section is still open"
    );

    assert_eq!(
        m.on_eof(Side::Server),
        vec![],
        "a cut-short chunked body is not a complete response"
    );
    assert!(
        trailers_of(&m).is_empty(),
        "a section that never ended is not captured"
    );
}

/// The request side's caps hold when the section arrives a line per read, as a
/// hostile client would send it to keep each read under the limit: the budget is
/// the whole section's, not each read's, so the section is refused at the field
/// or the byte that crosses it and cannot be fed forever.
#[test]
fn request_trailer_caps_hold_when_the_section_arrives_a_line_per_read() {
    let head = b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n";

    // 64 fields, each in its own read, are within the cap; the 65th is refused.
    let mut m = Http1Machine::new();
    m.on_bytes(Side::Client, head).unwrap();
    for i in 0..64 {
        let events = m
            .on_bytes(Side::Client, format!("f{i}: v\r\n").as_bytes())
            .unwrap_or_else(|e| panic!("field {i} of 64 is within the cap: {e}"));
        assert_eq!(events, vec![], "the section is still open after field {i}");
    }
    let err = m
        .on_bytes(Side::Client, b"f64: v\r\n")
        .expect_err("the 65th field, alone in its read, crosses the cap");
    assert!(err.to_string().contains("trailer"), "{err}");

    // Sixteen 1 KiB lines, each in its own read, fill 16384 counted bytes; the
    // seventeenth crosses it.
    let kib = format!("x: {}\r\n", "v".repeat(1019)).into_bytes();
    assert_eq!(kib.len(), 1024);
    let mut m = Http1Machine::new();
    m.on_bytes(Side::Client, head).unwrap();
    for n in 1..=16 {
        let events = m
            .on_bytes(Side::Client, &kib)
            .unwrap_or_else(|e| panic!("line {n} of 16 is within the cap: {e}"));
        assert_eq!(events, vec![], "the section is still open after line {n}");
    }
    let err = m
        .on_bytes(Side::Client, &kib)
        .expect_err("the 17th 1 KiB line crosses 16384 counted bytes");
    assert!(err.to_string().contains("trailer"), "{err}");
}
