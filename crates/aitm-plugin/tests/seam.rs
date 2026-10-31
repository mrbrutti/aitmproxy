//! Task 7 (AC-P5): a protocol module in a separate crate claims a connection and
//! drives flows/events through the seam, importing it from `aitm_plugin` — with no
//! `aitm-core` edit. The seam types are defined in `aitm-core` and re-exported by
//! `aitm-plugin` (accepted structuring call), so both import surfaces work.

use aitm_core::{
    Body, ConnInfo, Event, Flow, FlowId, FlowMeta, FlowStore, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, MemFlowStore, Verdict,
};
use aitm_plugin::{
    ByteStream, EventSink, ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector,
};
use futures::future::BoxFuture;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::SystemTime;

fn http_flow() -> Flow {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Flow::Http(HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
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
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    })
}

/// A module that claims port 9999 and, when driven, inserts one flow and emits a
/// `Request` event through the chain.
struct TestModule;

impl ProtocolModule for TestModule {
    fn id(&self) -> &str {
        "test"
    }
    fn matches(&self, hint: &NextLayerHint) -> bool {
        hint.dst.port() == 9999
    }
    fn spawn(&self, _io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let id = ctx.store().insert(http_flow());
            let verdict = ctx.emit(Event::Request(id)).await;
            assert_eq!(verdict, Verdict::Continue);
            Ok(())
        })
    }
}

/// A minimal in-test chain that runs no plugins: every event continues.
struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(async { Verdict::Continue })
    }
}

struct NoopConnector;

impl UpstreamConnector for NoopConnector {
    fn connect(
        &self,
        _authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        Box::pin(async { anyhow::bail!("no upstream in this test") })
    }
}

#[tokio::test]
async fn toy_module_claims_and_drives() {
    let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
    let ctx = ModuleCtx::new(store.clone(), Arc::new(NoopSink), Arc::new(NoopConnector));

    let module = TestModule;
    let hint = NextLayerHint {
        dst: "127.0.0.1:9999".parse().expect("valid addr"),
        is_tls: false,
        client_hello_sni: None,
        alpn: vec![],
        first_bytes: vec![],
        from_upgrade: false,
        peer_identity: None,
        capture_interface: None,
    };
    assert!(module.matches(&hint), "module should claim port 9999");

    let (client, _server) = tokio::io::duplex(64);
    let io: ByteStream = Box::pin(client);
    module.spawn(io, ctx).await.expect("spawn completes");

    assert_eq!(store.list().len(), 1, "module inserted exactly one flow");
}
