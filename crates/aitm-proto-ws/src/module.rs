//! The WebSocket protocol module: takes over a connection the HTTP module hands
//! off after a 101, records the conversation as a `WsFlow` linked to the
//! handshake `HttpFlow`, and runs each frame through the plugin chain before
//! forwarding it (platform spec data-flow 3).

use aitm_core::{Event, Flow, FlowId, FlowMeta, InterceptState, WsFlow};
use aitm_plugin::{ByteStream, ModuleCtx, NextLayerHint, ProtocolModule};
use anyhow::{anyhow, bail, Result};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::sansio::{Side, WsFrameMachine, WsSansIoEvent, WsStateMachine};

/// Socket read size.
const READ_CHUNK: usize = 16 * 1024;

/// The WebSocket protocol module.
#[derive(Default)]
pub struct WsModule;

impl WsModule {
    /// A module ready to be registered.
    pub fn new() -> Self {
        Self
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
        Box::pin(drive(io, ctx))
    }
}

/// Relay frames between the client and the already-upgraded upstream,
/// capturing and dispatching each one, until either side closes.
async fn drive(mut client: ByteStream, ctx: ModuleCtx) -> Result<()> {
    let handshake = ctx
        .handshake()
        .ok_or_else(|| anyhow!("WebSocket module spawned without an upgrade handshake"))?;
    let mut upstream = ctx
        .take_upstream()
        .ok_or_else(|| anyhow!("WebSocket module spawned without the upgraded upstream"))?;
    let (client_conn, server_conn) = match ctx.store().get(handshake) {
        Some(Flow::Http(h)) => (h.client_conn, h.server_conn),
        _ => bail!("handshake flow {handshake} is not a stored HttpFlow"),
    };

    let id = FlowId::new();
    ctx.store().insert(Flow::WebSocket(WsFlow {
        id,
        handshake,
        messages: Vec::new(),
        client_conn,
        server_conn,
        metadata: FlowMeta::default(),
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
        let (from, events) = tokio::select! {
            read = client.read(&mut client_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                (Side::Client, machine.on_bytes(Side::Client, &client_buf[..n])?)
            }
            read = upstream.read(&mut upstream_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                (Side::Server, machine.on_bytes(Side::Server, &upstream_buf[..n])?)
            }
        };
        closed = handle(
            &ctx,
            id,
            &mut machine,
            from,
            events,
            &mut client,
            &mut upstream,
        )
        .await?;
    }

    ctx.emit(Event::WsEnd(id)).await;
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
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
                    return Ok(true);
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
