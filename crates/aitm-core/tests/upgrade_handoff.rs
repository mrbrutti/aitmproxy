//! The upgrade hand-off on the protocol seam: after an HTTP upgrade, the HTTP
//! module asks `ModuleCtx` to re-dispatch the connection; the module that
//! claims the `from_upgrade` hint is spawned with the handshake flow id and the
//! already-open upstream stream (no reconnect).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aitm_core::{
    ByteStream, Event, EventSink, FlowId, MemFlowStore, ModuleCtx, NextLayerHint, ProtocolModule,
    UpstreamConnector, Verdict,
};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(async { Verdict::Continue })
    }
}

/// Fails loudly: an upgraded connection must reuse its upstream, not reconnect.
struct NoReconnect;

impl UpstreamConnector for NoReconnect {
    fn connect(
        &self,
        _authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        Box::pin(async { anyhow::bail!("must not reconnect after an upgrade") })
    }
}

#[derive(Default)]
struct Seen {
    spawned: bool,
    handshake: Option<FlowId>,
    upstream_bytes: Vec<u8>,
    protocol: Option<String>,
}

/// A module that claims (or declines) upgrade hints and records what it got.
struct Recorder {
    id: &'static str,
    claims: bool,
    seen: Arc<Mutex<Seen>>,
}

impl ProtocolModule for Recorder {
    fn id(&self) -> &str {
        self.id
    }

    fn matches(&self, hint: &NextLayerHint) -> bool {
        self.claims && hint.from_upgrade
    }

    fn spawn(&self, _io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            let mut upstream = ctx
                .take_upstream()
                .ok_or_else(|| anyhow::anyhow!("no upstream handed over"))?;
            let mut buf = [0u8; 32];
            let n = upstream.read(&mut buf).await?;
            let mut seen = self.seen.lock().unwrap();
            seen.spawned = true;
            seen.handshake = ctx.handshake();
            seen.upstream_bytes = buf[..n].to_vec();
            seen.protocol = ctx.hint().and_then(|h| h.alpn.first().cloned());
            Ok(())
        })
    }
}

fn ctx_with(modules: Vec<Arc<dyn ProtocolModule>>) -> ModuleCtx {
    ModuleCtx::new(
        Arc::new(MemFlowStore::new()),
        Arc::new(NoopSink),
        Arc::new(NoReconnect),
    )
    .with_modules(modules.into())
}

fn upgrade_hint() -> NextLayerHint {
    NextLayerHint {
        dst: "127.0.0.1:1".parse().unwrap(),
        is_tls: false,
        client_hello_sni: None,
        alpn: vec!["websocket".to_string()],
        first_bytes: Vec::new(),
        from_upgrade: true,
    }
}

#[tokio::test]
async fn handoff_reaches_claiming_module_with_handshake_and_upstream() {
    let declined = Arc::new(Mutex::new(Seen::default()));
    let claimed = Arc::new(Mutex::new(Seen::default()));
    let ctx = ctx_with(vec![
        Arc::new(Recorder {
            id: "http",
            claims: false,
            seen: declined.clone(),
        }),
        Arc::new(Recorder {
            id: "ws",
            claims: true,
            seen: claimed.clone(),
        }),
    ]);

    let (client, _client_peer) = tokio::io::duplex(64);
    let (upstream, mut upstream_peer) = tokio::io::duplex(64);
    upstream_peer.write_all(b"from-upstream").await.unwrap();
    let handshake = FlowId::new();

    ctx.handoff_upgrade(
        Box::pin(client),
        Box::pin(upstream),
        handshake,
        upgrade_hint(),
    )
    .await
    .expect("hand-off succeeds");

    let seen = claimed.lock().unwrap();
    assert!(seen.spawned, "the claiming module must be spawned");
    assert_eq!(seen.handshake, Some(handshake));
    assert_eq!(seen.upstream_bytes, b"from-upstream".to_vec());
    assert_eq!(seen.protocol.as_deref(), Some("websocket"));
    assert!(
        !declined.lock().unwrap().spawned,
        "a module that declines the hint must not be spawned"
    );
}

#[tokio::test]
async fn handoff_without_claiming_module_is_an_error() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let ctx = ctx_with(vec![Arc::new(Recorder {
        id: "http",
        claims: false,
        seen,
    })]);
    let (client, _) = tokio::io::duplex(8);
    let (upstream, _) = tokio::io::duplex(8);
    let err = ctx
        .handoff_upgrade(
            Box::pin(client),
            Box::pin(upstream),
            FlowId::new(),
            upgrade_hint(),
        )
        .await
        .expect_err("no module claims the upgrade");
    assert!(
        err.to_string().contains("websocket"),
        "error should name the unclaimed protocol: {err}"
    );
}

#[test]
fn plain_ctx_has_no_handoff_state() {
    let ctx = ctx_with(Vec::new());
    assert_eq!(ctx.handshake(), None);
    assert!(ctx.take_upstream().is_none());
    assert!(ctx.hint().is_none());
}
