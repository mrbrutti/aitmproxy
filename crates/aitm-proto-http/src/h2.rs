//! The HTTP/2 connection driver. `serve_h2` drives one already-decrypted h2
//! connection (both sides speak h2 — the ALPN mirror in [`crate::module`]
//! guarantees it) and spawns **one task per accepted client stream**, so parking
//! an intercepted stream at a breakpoint suspends only that stream's task while
//! the connection and its sibling streams keep running (spec §2).
//!
//! Each stream becomes an ordinary `Flow::Http` (`version: H2`) emitting the same
//! `RequestHeaders → Request → ResponseHeaders → Response` sequence as the h1
//! path, so every capability above the wire is protocol-agnostic. Task 2 handles
//! capture, multiplexing, forward and short-circuit (Map Local); interception —
//! per-stream park, response-phase edit, and kill-as-RST_STREAM — is Task 3 (a
//! parked stream suspends only its own task, because `emit()` is awaited before
//! any client byte is sent); Map Remote cross-origin is Task 4.
//!
//! Server push is disabled in both directions: the upstream client builder sets
//! `enable_push(false)`, and this driver never calls `push_request`, so the
//! server side never pushes. (`h2::server::Builder` has no `enable_push` method —
//! spec §5's intent is met by not pushing.)

use std::sync::Arc;

use aitm_core::{
    Body, Event, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, InterceptState,
    StreamBody,
};
use aitm_plugin::{ByteStream, ModuleCtx};
use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;

use crate::module::Conn;
use crate::translate;

/// Drive one already-decrypted h2 connection. Both halves speak h2 (the ALPN
/// mirror guarantees it). Spawns one task per accepted client stream; returns
/// when the client stops accepting (GOAWAY / close). In-flight stream tasks,
/// spawned onto the runtime, finish on their own.
pub(crate) async fn serve_h2(
    ctx: ModuleCtx,
    client_tls: ByteStream,
    upstream_tls: ByteStream,
    conn: Conn,
    max_body: usize,
    max_concurrent: usize,
) -> Result<()> {
    // Client-facing h2: accept inbound streams, bounding concurrency via SETTINGS.
    let mut server = h2::server::Builder::new()
        .max_concurrent_streams(max_concurrent as u32)
        .handshake::<_, Bytes>(client_tls)
        .await
        .context("client-facing h2 handshake")?;

    // Upstream-facing h2: one multiplexed client connection with push disabled.
    // The connection future owns upstream framing/flow-control and is driven on
    // its own task; the cloneable `SendRequest` opens upstream streams.
    let (send_req, up_conn) = h2::client::Builder::new()
        .enable_push(false)
        .handshake::<_, Bytes>(upstream_tls)
        .await
        .context("upstream h2 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = up_conn.await {
            tracing::debug!("upstream h2 connection ended: {e}");
        }
    });

    let ctx = Arc::new(ctx);
    let conn = Arc::new(conn);

    while let Some(accepted) = server.accept().await {
        let (request, respond) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("h2 accept error: {e}");
                break;
            }
        };
        let ctx = ctx.clone();
        let conn = conn.clone();
        let send_req = send_req.clone();
        tokio::spawn(async move {
            if let Err(e) = stream_task(ctx, conn, request, respond, send_req, max_body).await {
                tracing::debug!("h2 stream task ended: {e}");
            }
        });
    }
    Ok(())
}

/// The full per-stream lifecycle, mirroring the h1 `serve` ordering so the emitted
/// `Event` sequence is identical.
async fn stream_task(
    ctx: Arc<ModuleCtx>,
    conn: Arc<Conn>,
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    send_req: h2::client::SendRequest<Bytes>,
    max_body: usize,
) -> Result<()> {
    let (parts, mut req_body) = request.into_parts();
    let authority = conn.tunnel_authority.clone().unwrap_or_default();
    let model_req = translate::request_from_h2(&parts, &conn.scheme, &authority);

    // Insert the flow and emit RequestHeaders (body still streaming), as h1 does.
    let id = FlowId::new();
    ctx.store().insert(Flow::Http(HttpFlow {
        id,
        request: HttpRequest {
            body: Body::Empty,
            ..model_req
        },
        response: None,
        client_conn: conn.client_conn.clone(),
        server_conn: conn.server_conn.clone(),
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }));
    ctx.emit(Event::RequestHeaders(id)).await;

    // Drain the request body, capped like h1; release flow-control as consumed.
    let mut body: Vec<u8> = Vec::new();
    let mut oversized = false;
    while let Some(chunk) = req_body.data().await {
        let chunk = chunk.context("read h2 request body")?;
        let len = chunk.len();
        let room = max_body.saturating_sub(body.len());
        if len > room {
            body.extend_from_slice(&chunk[..room]);
            oversized = true;
        } else {
            body.extend_from_slice(&chunk);
        }
        let _ = req_body.flow_control().release_capacity(len);
    }

    // A request body over the cap is refused (413), mirroring h1, rather than
    // forwarded truncated.
    if oversized {
        ctx.store().update(id, &mut |f: &mut Flow| {
            if let Flow::Http(h) = f {
                h.metadata.truncated = true;
            }
        });
        let resp = http::Response::builder()
            .status(413)
            .body(())
            .context("build 413 response")?;
        respond.send_response(resp, true).context("send 413")?;
        return Ok(());
    }

    // Capture the full request body, then emit Request (the request breakpoint).
    let mut captured = Some(std::mem::take(&mut body));
    ctx.store().update(id, &mut |f: &mut Flow| {
        if let (Flow::Http(h), Some(bytes)) = (f, captured.take()) {
            h.request.body = if bytes.is_empty() {
                Body::Empty
            } else {
                Body::Bytes(bytes)
            };
        }
    });
    ctx.emit(Event::Request(id)).await;

    let Some(Flow::Http(flow)) = ctx.store().get(id) else {
        bail!("flow {id} missing from the store after dispatch");
    };

    // Killed (a `reset` kill, or an abandoned interception the chain timed out):
    // reset this stream with RST_STREAM(CANCEL). The h2 reset is per-stream, so the
    // connection and its sibling streams stay alive. The `429`/`503` kill modes are
    // not `Killed` — the kill command leaves them `Resumed` with a synthesized
    // response, handled by the short-circuit branch below (no upstream opened).
    if matches!(flow.intercept, InterceptState::Killed) {
        respond.send_reset(h2::Reason::CANCEL);
        return Ok(());
    }

    let request = flow.request;

    // Short-circuit (Map Local, a plugin-authored reply): answer without upstream.
    if let Some(short_circuit) = flow.response {
        ctx.emit(Event::ResponseHeaders(id)).await;
        ctx.emit(Event::Response(id)).await;
        let response = match ctx.store().get(id) {
            Some(Flow::Http(f)) => f.response.unwrap_or(short_circuit),
            _ => short_circuit,
        };
        send_model_response(&mut respond, &response).await?;
        return Ok(());
    }

    // Forward the (possibly mutated) request upstream. Hop-by-hop headers illegal
    // in h2 are stripped by `translate::h2_request_from`.
    let h2_req = translate::h2_request_from(&request);
    let req_bytes = match &request.body {
        Body::Bytes(b) => b.clone(),
        _ => Vec::new(),
    };
    let req_end = req_bytes.is_empty();
    let mut send_req = send_req.ready().await.context("upstream h2 not ready")?;
    let (resp_fut, mut up_send) = send_req
        .send_request(h2_req, req_end)
        .context("send h2 request upstream")?;
    if !req_end {
        send_body(&mut up_send, Bytes::from(req_bytes)).await?;
        up_send
            .send_data(Bytes::new(), true)
            .context("end upstream h2 request")?;
    }

    // Receive the upstream response head, stage it, and emit ResponseHeaders
    // **before** any response byte reaches the client (the response breakpoint).
    let response = resp_fut.await.context("await upstream h2 response")?;
    let (resp_parts, mut resp_body) = response.into_parts();
    let head = translate::response_from_h2(&resp_parts);
    let staged = HttpResponse {
        body: Body::Streamed(StreamBody),
        ..head
    };
    let mut staged_opt = Some(staged.clone());
    ctx.store().update(id, &mut |f: &mut Flow| {
        if let (Flow::Http(h), Some(r)) = (f, staged_opt.take()) {
            h.response = Some(r);
        }
    });
    ctx.emit(Event::ResponseHeaders(id)).await;

    let to_send = match ctx.store().get(id) {
        Some(Flow::Http(f)) => f.response.unwrap_or_else(|| staged.clone()),
        _ => staged.clone(),
    };
    // A plugin may have replaced the streamed body with its own at ResponseHeaders.
    let forward_chunks = matches!(to_send.body, Body::Streamed(_));
    let client_resp = translate::h2_response_from(&to_send);

    if forward_chunks {
        let mut client_send = respond
            .send_response(client_resp, false)
            .context("send h2 response head")?;
        let mut captured: Vec<u8> = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp_body.data().await {
            let chunk = chunk.context("read upstream h2 response body")?;
            let len = chunk.len();
            let room = max_body.saturating_sub(captured.len());
            if len > room {
                captured.extend_from_slice(&chunk[..room]);
                truncated = true;
            } else {
                captured.extend_from_slice(&chunk);
            }
            // Send to the client (awaiting client flow-control) before releasing
            // upstream capacity, so backpressure spans both hops.
            send_body(&mut client_send, chunk).await?;
            let _ = resp_body.flow_control().release_capacity(len);
        }
        client_send
            .send_data(Bytes::new(), true)
            .context("end h2 response")?;
        finish_response(&ctx, id, captured, truncated).await;
    } else {
        let body_bytes = match &to_send.body {
            Body::Bytes(b) => b.clone(),
            _ => Vec::new(),
        };
        let end = body_bytes.is_empty();
        let mut client_send = respond
            .send_response(client_resp, end)
            .context("send h2 response head")?;
        if !end {
            send_body(&mut client_send, Bytes::from(body_bytes.clone())).await?;
            client_send
                .send_data(Bytes::new(), true)
                .context("end h2 response")?;
        }
        finish_response(&ctx, id, body_bytes, false).await;
    }
    Ok(())
}

/// Send a model `HttpResponse` (head + buffered body) to the client, for the
/// short-circuit path. Hop-by-hop headers are stripped on encode.
async fn send_model_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    resp: &HttpResponse,
) -> Result<()> {
    let head = translate::h2_response_from(resp);
    let body = match &resp.body {
        Body::Bytes(b) => b.clone(),
        _ => Vec::new(),
    };
    let end = body.is_empty();
    let mut send = respond
        .send_response(head, end)
        .context("send short-circuit h2 response")?;
    if !end {
        send_body(&mut send, Bytes::from(body)).await?;
        send.send_data(Bytes::new(), true)
            .context("end short-circuit h2 response")?;
    }
    Ok(())
}

/// Store the captured response body, mark truncation/duration, and emit Response.
async fn finish_response(ctx: &ModuleCtx, id: FlowId, captured: Vec<u8>, truncated: bool) {
    let mut bytes = Some(captured);
    ctx.store().update(id, &mut |f: &mut Flow| {
        if let (Flow::Http(h), Some(b)) = (f, bytes.take()) {
            if let Some(resp) = h.response.as_mut() {
                resp.body = if b.is_empty() {
                    Body::Empty
                } else {
                    Body::Bytes(b)
                };
            }
            h.metadata.truncated |= truncated;
            h.metadata.duration = h.metadata.created.elapsed().ok();
        }
    });
    ctx.emit(Event::Response(id)).await;
}

/// Write `data` onto an h2 send stream, honouring flow control: reserve capacity,
/// wait for the connection to assign it, and send as much as is assigned each
/// round until the buffer is drained. Never sets end-of-stream (the caller sends a
/// final empty frame with END_STREAM).
async fn send_body(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let assigned = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("h2 stream closed before the body was sent"))?
            .context("h2 send-capacity error")?;
        let take = assigned.min(data.len());
        let piece = data.split_to(take);
        send.send_data(piece, false).context("send h2 data frame")?;
    }
    Ok(())
}
