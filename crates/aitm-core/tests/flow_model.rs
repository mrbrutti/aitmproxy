//! Task 2: core flow-model types (`HeaderMap`, `Body`, `HttpFlow`, …).

use aitm_core::{
    Body, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpVersion,
    InterceptState,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;

#[test]
fn headermap_case_insensitive() {
    let mut h = HeaderMap::new();
    h.set("Content-Type", "text/html");
    assert_eq!(h.get("content-type"), Some("text/html"));
}

#[test]
fn headermap_preserves_duplicate_order() {
    let mut h = HeaderMap::new();
    h.set("Set-Cookie", "a=1");
    h.set("Set-Cookie", "b=2");
    let cookies: Vec<&str> = h
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v)
        .collect();
    assert_eq!(cookies, ["a=1", "b=2"]);
}

#[test]
fn httpflow_construct() {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let request = HttpRequest {
        method: "GET".into(),
        scheme: "https".into(),
        authority: "ex.test".into(),
        path: "/a".into(),
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: SystemTime::now(),
    };
    let flow = HttpFlow {
        id: FlowId::new(),
        request,
        response: None,
        client_conn: ConnInfo {
            peer: addr,
            sni: None,
            alpn: None,
            tls: true,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    };

    assert_eq!(flow.request.method, "GET");
    assert!(flow.response.is_none());
    assert!(matches!(flow.intercept, InterceptState::Observed));

    let wrapped = Flow::Http(flow);
    assert!(matches!(wrapped, Flow::Http(_)));
}
