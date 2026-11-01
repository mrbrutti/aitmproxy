//! The subscription tap observes passive flows (spec D4 / AC10): it opts in via
//! `Plugin::observes_passive_flows`, so a passive flow's lifecycle events still
//! reach the broadcast behind server push while every other plugin is skipped.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, Chain, ConnInfo, Event, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, MemFlowStore, Plugin, Registry, Verdict,
};
use aitm_plugins::SubscriptionPlugin;
use tokio::sync::broadcast;

/// A plain-HTTP request to an out-of-scope host: stored, but passive.
fn passive_http_flow() -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "outside.test".into(),
            path: "/".into(),
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
        metadata: FlowMeta {
            passive: true,
            ..FlowMeta::default()
        },
        intercept: InterceptState::Observed,
    })
}

#[tokio::test]
async fn subscription_plugin_observes_passive_flows() {
    let (tx, mut rx) = broadcast::channel::<Event>(8);
    let plugin = SubscriptionPlugin::new(tx);
    assert!(
        plugin.observes_passive_flows(),
        "the subscription tap must opt in to passive flows (spec D4)"
    );

    let mut reg = Registry::new();
    reg.add_plugin(Box::new(plugin));
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let id = store.insert(passive_http_flow());
    let chain = Chain::new(Arc::new(reg), store);

    let verdict = chain.dispatch(Event::Request(id)).await;
    assert_eq!(verdict, Verdict::Continue);

    let pushed = rx
        .try_recv()
        .expect("the passive flow's event must reach the broadcast behind server push");
    assert_eq!(pushed, Event::Request(id));
    assert!(
        rx.try_recv().is_err(),
        "exactly one event is forwarded per dispatch"
    );
}
