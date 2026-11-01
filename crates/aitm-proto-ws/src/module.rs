//! The WebSocket protocol module: takes over a connection the HTTP module hands
//! off after a 101, records the conversation as a `WsFlow` linked to the
//! handshake `HttpFlow`, and runs each frame through the plugin chain before
//! forwarding it (platform spec data-flow 3).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use aitm_core::{
    Event, Flow, FlowId, FlowMeta, InterceptState, WsDir, WsFlow, WsMessage, WsOpcode,
};
use aitm_plugin::{ByteStream, ModuleCtx, NextLayerHint, ProtocolModule};
use anyhow::{anyhow, bail, Result};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::sansio::{Side, WsFrameMachine, WsSansIoEvent, WsStateMachine};

/// Socket read size.
const READ_CHUNK: usize = 16 * 1024;

/// A frame composed by a command (e.g. `ws.send`) for live injection onto an open
/// WebSocket. The module frames it towards the side `dir` implies and records it
/// as a `WsMessage { injected: true }`.
#[derive(Debug, Clone)]
pub struct InjectFrame {
    pub dir: WsDir,
    pub opcode: WsOpcode,
    pub data: Vec<u8>,
}

/// Shared map from a live WebSocket flow to the sender that injects frames into
/// its `drive` loop. The WS module owns the live connection's `select!`, so it
/// registers a flow's sender when the conversation opens and removes it when the
/// conversation ends; a plugin (`aitm-plugin-wsctl`'s `ws.send`) holds the same
/// `Arc` and enqueues frames. Shared state via `Arc` — no `aitm-core` edit.
pub type InjectRegistry = Arc<Mutex<HashMap<FlowId, UnboundedSender<InjectFrame>>>>;

/// The WebSocket protocol module.
#[derive(Default)]
pub struct WsModule {
    /// When present, live conversations register an inject channel here so a
    /// command can compose and send a frame onto the open socket.
    inject: Option<InjectRegistry>,
}

impl WsModule {
    /// A module ready to be registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Share an [`InjectRegistry`] so live conversations accept composed frames
    /// (wired to `ws.send`'s plugin in the binary, Task 14).
    pub fn with_inject_registry(mut self, reg: InjectRegistry) -> Self {
        self.inject = Some(reg);
        self
    }
}

impl ProtocolModule for WsModule {
    fn id(&self) -> &str {
        "ws"
    }

    /// Claims an upgrade hand-off whose protocol is `websocket`.
    fn matches(&self, hint: &NextLayerHint) -> bool {
        hint.from_upgrade
            && hint
                .alpn
                .iter()
                .any(|p| p.eq_ignore_ascii_case("websocket"))
    }

    fn spawn(&self, io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, Result<()>> {
        Box::pin(drive(io, ctx, self.inject.clone()))
    }
}

/// The metadata a WebSocket flow starts with, given its handshake `HttpFlow`'s:
/// exactly the capture attribution (`source_app`, `capture_interface`) and the
/// passive stamp are inherited, so the conversation is attributed to the same
/// client process and backend as the 101 that opened it and, like that 101, is
/// observed only when its host was outside Scope (spec D4). Marks, comment,
/// replay flag and timing are the WebSocket flow's own and start fresh.
fn inherit_meta(handshake: &FlowMeta) -> FlowMeta {
    FlowMeta {
        passive: handshake.passive,
        ..FlowMeta::with_attribution(
            handshake.source_app.clone(),
            handshake.capture_interface.clone(),
        )
    }
}

/// Relay frames between the client and the already-upgraded upstream,
/// capturing and dispatching each one, until either side closes.
async fn drive(
    mut client: ByteStream,
    ctx: ModuleCtx,
    inject: Option<InjectRegistry>,
) -> Result<()> {
    let handshake = ctx
        .handshake()
        .ok_or_else(|| anyhow!("WebSocket module spawned without an upgrade handshake"))?;
    let mut upstream = ctx
        .take_upstream()
        .ok_or_else(|| anyhow!("WebSocket module spawned without the upgraded upstream"))?;
    let (client_conn, server_conn, meta) = match ctx.store().get(handshake) {
        Some(Flow::Http(h)) => (h.client_conn, h.server_conn, h.metadata),
        _ => bail!("handshake flow {handshake} is not a stored HttpFlow"),
    };

    let id = FlowId::new();

    // The inject channel: `tx` is kept local for the whole conversation (so the
    // receiver never yields `None` while we relay), and — when a registry is
    // shared — a clone is published under this flow id *before* the flow becomes
    // visible in the store, so a command that finds the flow can always resolve
    // its sender. It is removed before `WsEnd`.
    let (tx, mut inject_rx) = mpsc::unbounded_channel::<InjectFrame>();
    if let Some(reg) = &inject {
        lock(reg).insert(id, tx.clone());
    }
    let _keep_tx = tx;

    ctx.store().insert(Flow::WebSocket(WsFlow {
        id,
        handshake,
        messages: Vec::new(),
        client_conn,
        server_conn,
        metadata: inherit_meta(&meta),
        intercept: InterceptState::Observed,
    }));

    let mut machine = WsFrameMachine::new();
    let mut client_buf = vec![0u8; READ_CHUNK];
    let mut upstream_buf = vec![0u8; READ_CHUNK];

    // The conversation is open as soon as the hand-off lands.
    let opened = machine.on_bytes(Side::Client, &[])?;
    let mut closed = handle(
        &ctx,
        id,
        &mut machine,
        Side::Client,
        opened,
        &mut client,
        &mut upstream,
    )
    .await?;

    while !closed {
        tokio::select! {
            read = client.read(&mut client_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                let events = machine.on_bytes(Side::Client, &client_buf[..n])?;
                closed = handle(&ctx, id, &mut machine, Side::Client, events, &mut client, &mut upstream).await?;
            }
            read = upstream.read(&mut upstream_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                let events = machine.on_bytes(Side::Server, &upstream_buf[..n])?;
                closed = handle(&ctx, id, &mut machine, Side::Server, events, &mut client, &mut upstream).await?;
            }
            frame = recv_inject(&mut inject_rx) => {
                if let Some(frame) = frame {
                    inject_frame(&ctx, id, &mut machine, frame, &mut client, &mut upstream).await?;
                }
            }
        }
    }

    if let Some(reg) = &inject {
        lock(reg).remove(&id);
    }
    ctx.emit(Event::WsEnd(id)).await;
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}

/// Await the next composed inject frame. A thin wrapper so the `select!` arm reads
/// like the socket arms; the kept-alive sender means this only resolves to `None`
/// if the registry entry is dropped mid-conversation, which the arm ignores.
async fn recv_inject(rx: &mut UnboundedReceiver<InjectFrame>) -> Option<InjectFrame> {
    rx.recv().await
}

/// Frame a composed [`InjectFrame`] towards the side its direction implies, record
/// it as an injected `WsMessage`, and write it out. `ClientToServer` is sent to
/// the server (upstream); `ServerToClient` to the client.
async fn inject_frame(
    ctx: &ModuleCtx,
    id: FlowId,
    machine: &mut WsFrameMachine,
    frame: InjectFrame,
    client: &mut ByteStream,
    upstream: &mut ByteStream,
) -> Result<()> {
    let to = match frame.dir {
        WsDir::ClientToServer => Side::Server,
        WsDir::ServerToClient => Side::Client,
    };
    let msg = WsMessage {
        dir: frame.dir,
        opcode: frame.opcode,
        data: frame.data,
        timestamp: SystemTime::now(),
        injected: true,
    };

    // Append to the stored conversation in wire order alongside captured frames.
    let mut staged = Some(msg.clone());
    ctx.store().update(id, &mut |f: &mut Flow| {
        if let (Flow::WebSocket(w), Some(m)) = (f, staged.take()) {
            w.messages.push(m);
        }
    });

    machine.send_frame(to, msg);
    if let Some(bytes) = machine.poll_outbound(to) {
        let stream = match to {
            Side::Client => &mut *client,
            Side::Server => &mut *upstream,
        };
        stream.write_all(&bytes).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// Act on the coder's events: `Open` emits `WsStart`; `Message` appends the
/// frame to the flow, dispatches `WsMessage { flow, index }`, then forwards
/// whatever the chain left in the store to the other side; `Close` ends the
/// conversation. Returns `true` when the conversation is over.
async fn handle(
    ctx: &ModuleCtx,
    id: FlowId,
    machine: &mut WsFrameMachine,
    from: Side,
    events: Vec<WsSansIoEvent>,
    client: &mut ByteStream,
    upstream: &mut ByteStream,
) -> Result<bool> {
    let mut closed = false;
    for ev in events {
        match ev {
            WsSansIoEvent::Open => {
                ctx.emit(Event::WsStart(id)).await;
            }
            WsSansIoEvent::Message { index } => {
                let Some(msg) = machine.message(index).cloned() else {
                    bail!("coder reported message {index} it does not hold");
                };
                let mut staged = Some(msg);
                let mut at = 0;
                ctx.store().update(id, &mut |f: &mut Flow| {
                    if let (Flow::WebSocket(w), Some(m)) = (f, staged.take()) {
                        w.messages.push(m);
                        at = w.messages.len() - 1;
                    }
                });
                ctx.emit(Event::WsMessage {
                    flow: id,
                    index: at,
                })
                .await;

                let Some(Flow::WebSocket(flow)) = ctx.store().get(id) else {
                    bail!("WsFlow {id} missing from the store after dispatch");
                };
                if matches!(flow.intercept, InterceptState::Killed) {
                    // Single-frame drop (`ws.frame {action:"drop"}`): skip
                    // forwarding *this* frame but keep the conversation open —
                    // mirroring the Rhai `msg.drop()` semantics. `Killed` is only
                    // ever set on a WS flow by a frame drop (there is no command to
                    // kill a whole WS conversation), so reset the park state to
                    // `Resumed` and relay the next frame normally.
                    ctx.store().update(id, &mut |f: &mut Flow| {
                        if let Flow::WebSocket(w) = f {
                            w.intercept = InterceptState::Resumed;
                        }
                    });
                    continue;
                }
                let Some(forward) = flow.messages.get(at).cloned() else {
                    bail!("message {at} missing from WsFlow {id} after dispatch");
                };
                let to = match from {
                    Side::Client => Side::Server,
                    Side::Server => Side::Client,
                };
                machine.send_frame(to, forward);
                if let Some(bytes) = machine.poll_outbound(to) {
                    let stream = match to {
                        Side::Client => &mut *client,
                        Side::Server => &mut *upstream,
                    };
                    stream.write_all(&bytes).await?;
                    stream.flush().await?;
                }
            }
            WsSansIoEvent::Close => closed = true,
        }
    }
    Ok(closed)
}

/// Lock a mutex, recovering a poisoned guard rather than panicking — a prior
/// panic elsewhere must not drop the live WebSocket out of its relay loop.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use aitm_core::{
        Body, ConnInfo, FlowStore, HeaderMap, HttpFlow, HttpRequest, HttpVersion, MemFlowStore,
        Verdict,
    };
    use aitm_plugin::{EventSink, UpstreamConnector};
    use tokio::io::duplex;

    use super::*;

    /// SA-AC0 + spec D4: a WebSocket flow inherits exactly the handshake's capture
    /// attribution and its passive stamp. Marks, comment, replay flag and timing
    /// are the WebSocket flow's own.
    #[test]
    fn inherit_meta_copies_attribution_and_passive_only() {
        let handshake = FlowMeta {
            source_app: Some("com.apple.Safari".into()),
            capture_interface: Some("macos-ne".into()),
            marks: vec!["x".into()],
            comment: Some("c".into()),
            is_replay: true,
            passive: true,
            ..FlowMeta::default()
        };

        let meta = inherit_meta(&handshake);

        assert_eq!(meta.source_app, Some("com.apple.Safari".into()));
        assert_eq!(meta.capture_interface, Some("macos-ne".into()));
        assert!(
            meta.passive,
            "a WebSocket opened by a passive handshake is passive"
        );
        assert!(meta.marks.is_empty());
        assert_eq!(meta.comment, None);
        assert!(!meta.is_replay);
        assert_eq!(meta.tunnel, None);
        assert!(
            !inherit_meta(&FlowMeta::default()).passive,
            "an acted-on handshake opens an acted-on WebSocket"
        );
    }

    // ---- Tester additions (whole-branch stage 5) -----------------------------

    /// Lets every event continue; these tests do not look at events.
    struct NoSink;

    impl EventSink for NoSink {
        fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
            Box::pin(async { Verdict::Continue })
        }
    }

    /// The WebSocket module never dials: it is handed the upgraded upstream.
    struct NoDial;

    impl UpstreamConnector for NoDial {
        fn connect(&self, _authority: &str, _dst: SocketAddr) -> BoxFuture<'_, Result<ByteStream>> {
            Box::pin(async { Err(anyhow!("the WebSocket module never dials")) })
        }
    }

    /// Store a handshake `HttpFlow` carrying `meta`, hand the module an upgrade
    /// context for it (as `ModuleCtx::handoff_upgrade` would), run `drive` until
    /// the client hangs up, and return the `WsFlow` it stored.
    ///
    /// The hint's own `peer_identity` / `capture_interface` are left `None` on
    /// purpose: spec D3 has the WebSocket flow inherit from the stored handshake's
    /// `FlowMeta`, so this is what proves `drive` reads it from there.
    async fn ws_flow_after_drive(meta: FlowMeta) -> WsFlow {
        let store = Arc::new(MemFlowStore::new());
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51000);
        let handshake = store.insert(Flow::Http(HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "chat.test".into(),
                path: "/chat".into(),
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: ConnInfo {
                peer,
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            },
            server_conn: None,
            metadata: meta,
            intercept: InterceptState::Observed,
        }));
        let hint = NextLayerHint {
            dst: peer,
            is_tls: false,
            client_hello_sni: None,
            alpn: vec!["websocket".to_string()],
            first_bytes: Vec::new(),
            from_upgrade: true,
            peer_identity: None,
            capture_interface: None,
        };
        let (client_end, proxy_client) = duplex(1024);
        let (_upstream_end, proxy_upstream) = duplex(1024);
        let parent = ModuleCtx::new(store.clone(), Arc::new(NoSink), Arc::new(NoDial));
        let ctx = parent.for_upgrade(handshake, Box::pin(proxy_upstream), hint);
        let module = WsModule::new();
        assert!(module.matches(ctx.hint().expect("an upgrade hint")));

        // The client hangs up at once: `drive` stores the flow, reads EOF, ends.
        // The upstream end stays open, so the EOF is unambiguously the client's.
        drop(client_end);
        tokio::time::timeout(
            Duration::from_secs(5),
            module.spawn(Box::pin(proxy_client), ctx),
        )
        .await
        .expect("drive must end when the client hangs up")
        .expect("drive ends cleanly");

        let ws = store
            .list()
            .into_iter()
            .find_map(|id| match store.get(id) {
                Some(Flow::WebSocket(w)) => Some(w),
                _ => None,
            })
            .expect("drive stored a WsFlow");
        assert_eq!(ws.handshake, handshake, "linked to its handshake");
        ws
    }

    /// SA-AC0, the live wiring: `drive` stores the `WsFlow` with the attribution of
    /// the handshake flow it reads back from the store, so a captured Safari
    /// WebSocket is attributed to Safari and `macos-ne` — with none of the
    /// handshake's own marks or comment. The unit test above pins the helper; this
    /// pins that `drive` actually applies it to the handshake's metadata.
    #[tokio::test]
    async fn drive_stores_the_ws_flow_with_the_handshakes_attribution() {
        let ws = ws_flow_after_drive(FlowMeta {
            source_app: Some("com.apple.Safari".into()),
            capture_interface: Some("macos-ne".into()),
            marks: vec!["handshake-mark".into()],
            comment: Some("handshake comment".into()),
            ..FlowMeta::default()
        })
        .await;
        assert_eq!(ws.metadata.source_app.as_deref(), Some("com.apple.Safari"));
        assert_eq!(ws.metadata.capture_interface.as_deref(), Some("macos-ne"));
        assert!(
            ws.metadata.marks.is_empty(),
            "marks are the WebSocket flow's own"
        );
        assert_eq!(
            ws.metadata.comment, None,
            "the comment is the WebSocket flow's own"
        );
        assert!(!ws.metadata.is_replay);
    }

    /// A proxied handshake (no attribution) yields a WebSocket flow with
    /// `None`/`None`: never a placeholder.
    #[tokio::test]
    async fn drive_stores_a_proxied_ws_flow_with_no_attribution() {
        let ws = ws_flow_after_drive(FlowMeta::default()).await;
        assert_eq!(ws.metadata.source_app, None);
        assert_eq!(ws.metadata.capture_interface, None);
    }

    /// Spec D4, the live wiring: `drive` stamps the `WsFlow` with its handshake's
    /// `passive` (true → true, false → false), so a WebSocket opened by plain HTTP
    /// to a host outside Scope is observed only, exactly like its handshake.
    #[tokio::test]
    async fn websocket_flow_inherits_passive_from_its_handshake() {
        let passive = ws_flow_after_drive(FlowMeta {
            passive: true,
            ..FlowMeta::default()
        })
        .await;
        assert!(passive.metadata.passive, "true → true");

        let acted_on = ws_flow_after_drive(FlowMeta {
            passive: false,
            ..FlowMeta::default()
        })
        .await;
        assert!(!acted_on.metadata.passive, "false → false");
    }
}
