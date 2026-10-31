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
/// exactly the capture attribution (`source_app`, `capture_interface`) is
/// inherited, so the conversation is attributed to the same client process and
/// backend as the 101 that opened it. Marks, comment, replay flag and timing are
/// the WebSocket flow's own and start fresh.
pub(crate) fn inherit_attribution(handshake: &FlowMeta) -> FlowMeta {
    FlowMeta {
        source_app: handshake.source_app.clone(),
        capture_interface: handshake.capture_interface.clone(),
        ..FlowMeta::default()
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
        metadata: inherit_attribution(&meta),
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
    use super::*;

    /// SA-AC0: a WebSocket flow inherits exactly the handshake's capture attribution.
    /// Marks, comment, replay flag and timing are the WebSocket flow's own.
    #[test]
    fn inherit_attribution_copies_only_the_two_fields() {
        let handshake = FlowMeta {
            source_app: Some("com.apple.Safari".into()),
            capture_interface: Some("macos-ne".into()),
            marks: vec!["x".into()],
            comment: Some("c".into()),
            is_replay: true,
            ..FlowMeta::default()
        };

        let meta = inherit_attribution(&handshake);

        assert_eq!(meta.source_app, Some("com.apple.Safari".into()));
        assert_eq!(meta.capture_interface, Some("macos-ne".into()));
        assert!(meta.marks.is_empty());
        assert_eq!(meta.comment, None);
        assert!(!meta.is_replay);
    }
}
