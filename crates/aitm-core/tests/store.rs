//! Task 5: the flow store (`FlowStore` trait + in-memory `MemFlowStore`).

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, FlowQuery, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, MemFlowStore,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

/// A terminal flow: a fully-buffered response, so the store may evict it.
fn http_flow_terminal(authority: &str, path: &str, body_len: usize) -> Flow {
    let mut flow = http_flow(authority, path);
    if let Flow::Http(h) = &mut flow {
        h.response = Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Bytes(vec![b'x'; body_len]),
            timestamp: SystemTime::now(),
        });
    }
    flow
}

fn http_flow(authority: &str, path: &str) -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: authority.into(),
            path: path.into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        },
        response: None,
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// Eviction must not drop an in-flight (non-terminal) flow, even when it is the
/// oldest — `clear` already guards this, and `drain_oldest` must too, or the
/// pipeline is stranded when a module reads the flow back after dispatch.
#[test]
fn eviction_skips_in_flight_flows() {
    // Tight count cap, generous byte budget so only the count cap fires.
    let store = MemFlowStore::with_limits(3, 100_000_000);
    // The oldest flow is still in flight (no response yet).
    let inflight = store.insert(http_flow("a.test", "/inflight"));
    // Then a run of terminal flows forces eviction past the cap.
    let first_terminal = store.insert(http_flow_terminal("a.test", "/t0", 10));
    for i in 1..20 {
        store.insert(http_flow_terminal("a.test", &format!("/t{i}"), 10));
    }
    assert!(
        store.get(inflight).is_some(),
        "the oldest in-flight flow must survive eviction (it would strand the pipeline)"
    );
    assert!(
        store.get(first_terminal).is_none(),
        "the oldest terminal flow should have been evicted instead"
    );
}

/// The store evicts on a resident-byte budget, not just flow count: a few large
/// captures are dropped (oldest first) long before the count cap is reached.
#[test]
fn byte_budget_evicts_even_under_count_cap() {
    // Generous count cap, small (10 KiB) byte budget. The captures are terminal
    // (a buffered response), the realistic unit the budget evicts — in-flight and
    // parked flows are passed over so the pipeline is never stranded.
    let store = MemFlowStore::with_limits(10_000, 10_000);
    for i in 0..50 {
        store.insert(http_flow_terminal("a.test", &format!("/{i}"), 1000));
    }
    assert!(
        store.list().len() < 50,
        "the byte budget must evict before the count cap (kept {})",
        store.list().len()
    );
    assert!(
        store.resident_bytes() <= 10_000,
        "resident bytes ({}) must stay within the budget",
        store.resident_bytes()
    );
    // The newest flow survives (FIFO drops the oldest).
    let newest = store.query(&FlowQuery {
        method: Some("GET".into()),
        ..Default::default()
    });
    assert!(!newest.is_empty(), "recent flows must be retained");
}

/// An `update` that grows a flow's body is counted and can trigger byte eviction,
/// since most body bytes arrive via update (head inserted first, body later).
#[test]
fn update_growth_counts_toward_byte_budget() {
    let store = MemFlowStore::with_limits(10_000, 10_000);
    let mut ids = Vec::new();
    for i in 0..20 {
        // Terminal (buffered response) so the budget may evict them; bodies are
        // tiny so far.
        ids.push(store.insert(http_flow_terminal("a.test", &format!("/{i}"), 0)));
    }
    // Now grow each response body via update.
    for id in &ids {
        store.update(*id, &mut |f: &mut Flow| {
            if let Flow::Http(h) = f {
                if let Some(r) = &mut h.response {
                    r.body = Body::Bytes(vec![b'x'; 1000]);
                }
            }
        });
    }
    assert!(
        store.resident_bytes() <= 10_000,
        "update growth must be evicted to stay within budget ({} bytes)",
        store.resident_bytes()
    );
}

/// A terminal flow whose response carries `headers` and `trailers` and no body,
/// so any difference in `resident_bytes` between two such flows is the fields.
fn http_flow_with_fields(path: &str, headers: HeaderMap, trailers: HeaderMap) -> Flow {
    let mut flow = http_flow("a.test", path);
    if let Flow::Http(h) = &mut flow {
        h.response = Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers,
            trailers,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        });
    }
    flow
}

/// A response's trailers are resident memory: with the byte budget as the only
/// bound (`max_flows = 0`), a hostile origin attaching trailers to every
/// response must be charged for them like any other field text.
#[test]
fn trailers_count_toward_resident_bytes() {
    let mut trailers = HeaderMap::new();
    trailers.set("X-Sum", "abc");
    trailers.set("x-sum", "def");

    let bare = MemFlowStore::new();
    bare.insert(http_flow_with_fields(
        "/p",
        HeaderMap::new(),
        HeaderMap::new(),
    ));
    let with = MemFlowStore::new();
    with.insert(http_flow_with_fields("/p", HeaderMap::new(), trailers));

    // "X-Sum" + "abc" + "x-sum" + "def" = 16 bytes of field text.
    assert!(
        with.resident_bytes() >= bare.resident_bytes() + 16,
        "trailers must be charged: {} bytes with vs {} without",
        with.resident_bytes(),
        bare.resident_bytes()
    );
}

/// Trailers are charged exactly as headers are, so a field costs the same
/// wherever the response carries it.
#[test]
fn a_trailer_costs_what_the_same_header_costs() {
    let mut fields = HeaderMap::new();
    fields.set("X-Sum", "abc");
    fields.set("x-sum", "def");

    let as_headers = MemFlowStore::new();
    as_headers.insert(http_flow_with_fields(
        "/p",
        fields.clone(),
        HeaderMap::new(),
    ));
    let as_trailers = MemFlowStore::new();
    as_trailers.insert(http_flow_with_fields("/p", HeaderMap::new(), fields));

    assert_eq!(as_trailers.resident_bytes(), as_headers.resident_bytes());
}

/// Trailers stored by an `update` (the response gets them at Response time,
/// after the head was inserted) are counted and can trigger byte eviction.
#[test]
fn update_adding_trailers_counts_toward_byte_budget() {
    let store = MemFlowStore::with_limits(10_000, 10_000);
    let mut ids = Vec::new();
    for i in 0..20 {
        ids.push(store.insert(http_flow_terminal("a.test", &format!("/{i}"), 0)));
    }
    // Each response gains 1000 bytes of trailer text (20 flows: 20,000 bytes).
    for id in &ids {
        store.update(*id, &mut |f: &mut Flow| {
            if let Flow::Http(h) = f {
                if let Some(r) = &mut h.response {
                    r.trailers.set("X-Pad", &"x".repeat(995));
                }
            }
        });
    }
    assert!(
        store.resident_bytes() <= 10_000,
        "trailer growth must be evicted to stay within budget ({} bytes)",
        store.resident_bytes()
    );
    assert!(
        store.list().len() < 20,
        "the byte budget must have evicted some of the 20 flows (kept {})",
        store.list().len()
    );
}

#[test]
fn insert_get_roundtrip() {
    let store = MemFlowStore::new();
    let id = store.insert(http_flow("a.test", "/a"));
    let got = store.get(id).expect("flow present");
    match got {
        Flow::Http(f) => assert_eq!(f.request.path, "/a"),
        other => panic!("expected http flow, got {other:?}"),
    }
}

/// Trailer fields ride beside a response's headers, never in them: the store
/// hands back the same two lists, in wire order, with case and the duplicate kept.
#[test]
fn a_response_keeps_trailers_beside_its_headers_never_in_them() {
    let mut headers = HeaderMap::new();
    headers.set("Content-Type", "text/plain");
    let mut trailers = HeaderMap::new();
    trailers.set("X-Sum", "abc");
    trailers.set("x-sum", "def");

    let mut flow = http_flow("a.test", "/t");
    if let Flow::Http(h) = &mut flow {
        h.response = Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers,
            trailers,
            body: Body::Bytes(b"hello".to_vec()),
            timestamp: SystemTime::now(),
        });
    }

    let store = MemFlowStore::new();
    let id = store.insert(flow);
    let Some(Flow::Http(got)) = store.get(id) else {
        panic!("expected the http flow back from the store");
    };
    let response = got.response.expect("the response was stored");

    assert_eq!(
        response.trailers.iter().collect::<Vec<_>>(),
        [("X-Sum", "abc"), ("x-sum", "def")]
    );
    assert_eq!(response.headers.get("x-sum"), None);
    assert_eq!(response.headers.len(), 1);
}

#[test]
fn query_by_host() {
    let store = MemFlowStore::new();
    let id_a = store.insert(http_flow("a.test", "/a"));
    let _id_b = store.insert(http_flow("b.test", "/b"));
    let hits = store.query(&FlowQuery {
        host: Some("a.test".into()),
        ..Default::default()
    });
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], id_a);
}

/// The method filter is case-insensitive, matching the live subscription path in
/// `aitm-mcp` (`FlowFilter::matches` uses `eq_ignore_ascii_case`). A flow is
/// stored with its canonical uppercase method; a lowercase or mixed-case filter
/// must still match it. Before the fix this compared byte-for-byte, so a
/// subscriber with `method:"post"` saw live POSTs but an *empty* `since` replay —
/// the live and replay paths disagreed (the e2e `flow.list` filter defect).
#[test]
fn query_method_filter_is_case_insensitive() {
    let store = MemFlowStore::new();
    // `http_flow` stores the request with method "GET".
    let id = store.insert(http_flow("a.test", "/a"));

    for want in ["get", "Get", "GET"] {
        let hits = store.query(&FlowQuery {
            method: Some(want.into()),
            ..Default::default()
        });
        assert_eq!(
            hits,
            vec![id],
            "method filter {want:?} must match the stored GET flow"
        );
    }

    // A genuinely different method still does not match.
    let none = store.query(&FlowQuery {
        method: Some("post".into()),
        ..Default::default()
    });
    assert!(none.is_empty(), "a different method must not match");
}
