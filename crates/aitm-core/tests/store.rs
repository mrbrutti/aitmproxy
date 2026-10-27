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
