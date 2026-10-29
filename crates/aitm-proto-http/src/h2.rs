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
//!
//! **Resource bounds (spec §4).** Both h2 builders carry finite HPACK caps
//! (`max_header_list_size`, `header_table_size`) so a compression-bomb HEADERS
//! block is rejected rather than buffered, and the server advertises a finite
//! `SETTINGS_MAX_CONCURRENT_STREAMS`. Every h2 **wire** await (handshake, frame
//! read, response future, send-capacity wait) is bounded by [`READ_TIMEOUT`],
//! mirroring the h1 per-read timeout, so a slow or hung peer cannot pin a stream
//! or connection open indefinitely. A failed stream emits [`Event::Error`] before
//! it tears down, as the h1 path does. (The plugin-dispatch `ctx.emit` awaits are
//! never timed out here — a flow parked at a breakpoint is legitimately suspended
//! and the chain owns that timeout, `intercept_timeout`.)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    Body, Event, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse,
    HttpVersion, InterceptState, StreamBody,
};
use aitm_plugin::{ByteStream, ModuleCtx};
use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;

use crate::module::Conn;
use crate::translate;

/// Per-await idle timeout on h2 wire I/O, matching the h1 `READ_TIMEOUT` posture
/// (`crate::module`): a single handshake, frame read, response future or
/// send-capacity wait may block at most this long. A truly idle connection (no
/// in-flight streams) is torn down like an idle h1 one; a parked stream keeps the
/// connection alive, since its timeout belongs to the chain, not the wire.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Finite cap on a decoded HPACK header list (spec §4): a HEADERS block whose
/// decoded header list exceeds this is rejected rather than buffered, bounding a
/// compression-bomb HEADERS frame. Applied to both h2 builders.
const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

/// Finite HPACK dynamic-table size (spec §4), set explicitly on both builders to
/// bound the per-connection header-compression state. (This is the HTTP/2 default
/// table size, pinned so the bound is explicit rather than implied.)
const HEADER_TABLE_SIZE: u32 = 4 * 1024;

/// Drive one already-decrypted h2 connection. Both halves speak h2 (the ALPN
/// mirror guarantees it). Spawns one task per accepted client stream; returns
/// when the client stops accepting (GOAWAY / close) or the connection sits idle
/// with no in-flight streams past [`READ_TIMEOUT`]. In-flight stream tasks,
/// spawned onto the runtime, finish on their own.
pub(crate) async fn serve_h2(
    ctx: ModuleCtx,
    client_tls: ByteStream,
    upstream_tls: ByteStream,
    conn: Conn,
    max_body: usize,
    max_concurrent: usize,
) -> Result<()> {
    // A `usize` cap wider than `u32` saturates rather than wrapping (a wrapped
    // small value would silently throttle the connection to a few streams).
    let max_streams = u32::try_from(max_concurrent).unwrap_or(u32::MAX);

    // Client-facing h2: accept inbound streams, bounding concurrency via SETTINGS
    // and the HPACK header block via finite caps (spec §4).
    let mut server = wire(
        "client-facing handshake",
        h2::server::Builder::new()
            .max_concurrent_streams(max_streams)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .header_table_size(HEADER_TABLE_SIZE)
            .handshake::<_, Bytes>(client_tls),
    )
    .await?
    .context("client-facing h2 handshake")?;

    // Upstream-facing h2: one multiplexed client connection with push disabled and
    // the same finite HPACK caps. The connection future owns upstream
    // framing/flow-control and is driven on its own task; the cloneable
    // `SendRequest` opens upstream streams.
    let (send_req, up_conn) = wire(
        "upstream handshake",
        h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .header_table_size(HEADER_TABLE_SIZE)
            .handshake::<_, Bytes>(upstream_tls),
    )
    .await?
    .context("upstream h2 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = up_conn.await {
            // Surface a connection-level upstream failure above `debug`. In-flight
            // streams also observe it through their own wire awaits (which emit
            // `Event::Error` per flow), but the connection fault itself is worth a
            // visible log for an operator watching one tunnel.
            tracing::warn!("upstream h2 connection ended with error: {e}");
        }
    });

    let ctx = Arc::new(ctx);
    let conn = Arc::new(conn);
    // Number of stream tasks still running (including those parked at a
    // breakpoint). An idle accept window only tears the connection down when this
    // is zero, so a long-parked stream — whose timeout the chain owns — is never
    // killed by the connection-level idle timeout.
    let in_flight = Arc::new(AtomicUsize::new(0));

    loop {
        let accepted = match tokio::time::timeout(READ_TIMEOUT, server.accept()).await {
            Ok(Some(accepted)) => accepted,
            Ok(None) => break, // client sent GOAWAY / closed the connection
            Err(_) => {
                if in_flight.load(Ordering::SeqCst) == 0 {
                    // Truly idle: no new stream and nothing in flight. Tear down.
                    break;
                }
                // A stream is still live (possibly parked); keep the connection up.
                continue;
            }
        };
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
        let in_flight = in_flight.clone();
        in_flight.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            if let Err(e) = stream_task(ctx, conn, request, respond, send_req, max_body).await {
                tracing::debug!("h2 stream task ended: {e}");
            }
            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// The full per-stream lifecycle, mirroring the h1 `serve` ordering so the emitted
/// `Event` sequence is identical. Inserts the flow and emits `RequestHeaders`,
/// then runs the fallible body: on any error (a wire failure, an upstream reset,
/// or a [`READ_TIMEOUT`] expiry) it emits `Event::Error` for the still-open flow
/// before returning, as the h1 path does, so the failure reaches the typed error
/// bus rather than only `tracing`.
async fn stream_task(
    ctx: Arc<ModuleCtx>,
    conn: Arc<Conn>,
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    send_req: h2::client::SendRequest<Bytes>,
    max_body: usize,
) -> Result<()> {
    let (parts, req_body) = request.into_parts();
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

    if let Err(e) = drive_stream(&ctx, id, req_body, respond, send_req, max_body).await {
        // Map the failure to the typed error bus for the still-open flow before
        // bailing, mirroring the h1 arm's `Event::Error` emission.
        ctx.emit(Event::Error {
            flow: id,
            kind: aitm_core::FlowError::Upstream(e.to_string()),
        })
        .await;
        return Err(e);
    }
    Ok(())
}

/// Everything after `RequestHeaders`: drain the (capped) request body, dispatch
/// the request, then forward or short-circuit. All wire awaits are bounded by
/// [`READ_TIMEOUT`]; the `ctx.emit` dispatch awaits are not (a parked flow is a
/// legitimate suspension owned by the chain).
async fn drive_stream(
    ctx: &ModuleCtx,
    id: FlowId,
    mut req_body: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    send_req: h2::client::SendRequest<Bytes>,
    max_body: usize,
) -> Result<()> {
    // Drain the request body, capped like h1; release flow-control as consumed.
    let mut body: Vec<u8> = Vec::new();
    let mut oversized = false;
    while let Some(chunk) = wire("request body read", req_body.data()).await? {
        let chunk = chunk.context("read h2 request body")?;
        let len = chunk.len();
        let room = max_body.saturating_sub(body.len());
        if len > room {
            body.extend_from_slice(&chunk[..room]);
            oversized = true;
            // Stop at the breach: do not release more capacity (which would grant
            // the client window to keep streaming the over-cap body). Returning
            // below drops `req_body`, which RST_STREAMs the still-open inbound
            // half, rather than draining the rest of the request.
            break;
        }
        body.extend_from_slice(&chunk);
        let _ = req_body.flow_control().release_capacity(len);
    }

    // A request body over the cap is refused (413), mirroring h1. Make the flow
    // terminal: it had emitted only RequestHeaders, so record the 413 as the
    // response and emit the response events before answering the client.
    if oversized {
        let mut headers = HeaderMap::new();
        headers.set("Content-Type", "text/plain");
        let model = HttpResponse {
            status: 413,
            version: HttpVersion::H2,
            headers,
            body: Body::Bytes(b"request body exceeds the configured limit".to_vec()),
            timestamp: SystemTime::now(),
        };
        let mut staged = Some(model.clone());
        ctx.store().update(id, &mut |f: &mut Flow| {
            if let Flow::Http(h) = f {
                h.metadata.truncated = true;
                if let Some(r) = staged.take() {
                    h.response = Some(r);
                }
                h.metadata.duration = h.metadata.created.elapsed().ok();
            }
        });
        ctx.emit(Event::ResponseHeaders(id)).await;
        ctx.emit(Event::Response(id)).await;
        let response = match ctx.store().get(id) {
            Some(Flow::Http(f)) => f.response.unwrap_or(model),
            _ => model,
        };
        send_model_response(&mut respond, &response).await?;
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
    let mut send_req = wire("upstream ready", send_req.ready())
        .await?
        .context("upstream h2 not ready")?;
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
    let response = wire("upstream response", resp_fut)
        .await?
        .context("await upstream h2 response")?;
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
        while let Some(chunk) = wire("response body read", resp_body.data()).await? {
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
        finish_response(ctx, id, captured, truncated).await;
    } else {
        // A plugin replaced the streamed body at ResponseHeaders, so the upstream
        // body is not forwarded. Release it now: dropping an undrained `RecvStream`
        // makes `h2` send RST_STREAM(CANCEL) upstream and return the stream's recv
        // window to the connection (h2 `drop_stream_ref`), so the discarded
        // upstream body neither keeps granting capacity nor leaks a half-open
        // stream.
        drop(resp_body);
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
        finish_response(ctx, id, body_bytes, false).await;
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
/// final empty frame with END_STREAM). The capacity wait is a wire await, so it is
/// bounded by [`READ_TIMEOUT`].
async fn send_body(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let assigned = wire(
            "send capacity",
            std::future::poll_fn(|cx| send.poll_capacity(cx)),
        )
        .await?
        .ok_or_else(|| anyhow!("h2 stream closed before the body was sent"))?
        .context("h2 send-capacity error")?;
        let take = assigned.min(data.len());
        let piece = data.split_to(take);
        send.send_data(piece, false).context("send h2 data frame")?;
    }
    Ok(())
}

/// Bound an h2 **wire** await (a handshake, frame read, response future, or
/// send-capacity wait) by [`READ_TIMEOUT`], mirroring the h1 per-read timeout in
/// [`crate::module`]. A slow or hung peer cannot pin a stream or connection open
/// indefinitely. **Never** wrap a `ctx.emit` dispatch await — a flow parked at an
/// intercept breakpoint is legitimately suspended and the chain owns that timeout
/// (`intercept_timeout`).
async fn wire<F, T>(what: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    wire_within(what, READ_TIMEOUT, fut).await
}

/// [`wire`] with an explicit bound, so the timeout behaviour is unit-testable
/// without waiting the full [`READ_TIMEOUT`].
async fn wire_within<F, T>(what: &str, within: Duration, fut: F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(within, fut)
        .await
        .map_err(|_| anyhow!("h2 {what} timed out after {within:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wire await on a future that never completes maps to a timeout `Err` —
    /// the error `stream_task` turns into `Event::Error`. A tiny bound keeps it
    /// fast (the production path uses [`READ_TIMEOUT`]).
    #[tokio::test]
    async fn wire_times_out_on_a_stalled_await() {
        let r: Result<()> = wire_within(
            "stalled",
            Duration::from_millis(20),
            std::future::pending::<()>(),
        )
        .await;
        let err = r.expect_err("a stalled wire await must time out");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    /// A wire await that resolves before the bound passes its value straight
    /// through unchanged.
    #[tokio::test]
    async fn wire_passes_through_a_ready_value() {
        let r: Result<u8> = wire_within("ready", Duration::from_secs(5), async { 7u8 }).await;
        assert_eq!(r.expect("a ready await must not time out"), 7);
    }
}
