//! Task 5: the flow store (`FlowStore` trait + in-memory `MemFlowStore`).

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, FlowQuery, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, MemFlowStore,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

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

fn http_flow_with_body(authority: &str, path: &str, body_len: usize) -> Flow {
    let mut flow = http_flow(authority, path);
    if let Flow::Http(h) = &mut flow {
        h.request.body = Body::Bytes(vec![b'x'; body_len]);
    }
    flow
}

/// The store evicts on a resident-byte budget, not just flow count: a few large
/// captures are dropped (oldest first) long before the count cap is reached.
#[test]
fn byte_budget_evicts_even_under_count_cap() {
    // Generous count cap, small (10 KiB) byte budget.
    let store = MemFlowStore::with_limits(10_000, 10_000);
    for i in 0..50 {
        store.insert(http_flow_with_body("a.test", &format!("/{i}"), 1000));
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
        ids.push(store.insert(http_flow("a.test", &format!("/{i}"))));
    }
    // Bodies are tiny so far; now grow each via update.
    for id in &ids {
        store.update(*id, &mut |f: &mut Flow| {
            if let Flow::Http(h) = f {
                h.request.body = Body::Bytes(vec![b'x'; 1000]);
            }
        });
    }
    assert!(
        store.resident_bytes() <= 10_000,
        "update growth must be evicted to stay within budget ({} bytes)",
        store.resident_bytes()
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
