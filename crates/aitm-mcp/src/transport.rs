//! Transports: newline-delimited JSON-RPC over stdio, or over a loopback-only
//! TCP listener that requires a token on every connection. Both run the same
//! [`serve_lines`] loop; the TCP transport first consumes one auth line.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use aitm_core::Frontend;
use anyhow::Context as _;
use serde_json::Value as JsonValue;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    Take,
};
use tokio::net::TcpListener;
use tokio::task::JoinError;

use crate::pointer;
use crate::server::{error_response, ConnCtx, McpServer, NotificationSink, UNAUTHORIZED};

/// Longest single message (one line) a transport accepts. Longer lines end the
/// connection instead of growing a buffer without bound.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How long a fresh loopback connection has to send its token line before
/// the listener closes it (security S1). The operator bus is on by default
/// (spec D2), so a same-user process that connects and says nothing must not
/// hold a task and a socket for ever; ten seconds is generous for a client
/// that means to speak and short for one that does not. Overridable per
/// listener with [`LoopbackTcp::with_token_line_timeout`].
pub const TOKEN_LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`LoopbackTcp::serve`] pauses after every `accept()` error
/// before accepting again (see [`accept_failed`]), so a core out of file
/// descriptors, buffers or memory logs at a walking pace instead of
/// spinning.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Serve newline-delimited JSON-RPC on one connection: each line in is one
/// message, each reply out is one line. Returns at EOF, at a read error, or when
/// the writer fails (see below). Commands run on the blocking pool so a slow tool
/// cannot stall the runtime.
///
/// The write half is owned by a dedicated writer task draining the connection's
/// bounded [`NotificationSink`] (F4): both request replies and server-initiated
/// `notifications/aitm/*` lines go through it, so writes are serialized per
/// connection and the read loop never blocks on a slow socket. The sink is the
/// `conn.out` the subscription registry pushes to; when the connection ends its
/// subscriptions are dropped and the writer drains and exits.
///
/// Each write the writer makes (one `write_all` per line, and the `flush`) runs
/// under [`McpServer::write_timeout`], which states what that deadline does and
/// does not detect. Expiry alone would not end the connection, because the read
/// loop sits in `read_line` and a stopped but still-open peer never sends EOF. So
/// if the writer ends in an error before the read loop ends, the read loop is
/// abandoned: the sink is closed, the connection's subscriptions are dropped, and
/// the writer's error is returned. A writer ends in an error when the deadline
/// expires, when a write fails, or when its task panics (the error then says the
/// writer task failed). If the read loop ends first, or the writer ends cleanly,
/// the connection ends when the read loop does; in the first case the writer is
/// given the chance to drain what is queued (still bounded by the deadline). A
/// command already running on the blocking pool when the loop is abandoned
/// finishes, but its reply is lost, as on any disconnect.
///
/// `conn` carries the connection's role (from its auth token, or `stdio_role`)
/// and, once an `initialize` arrives, its `clientInfo.name` label; every message
/// is dispatched through [`McpServer::handle_on`] with it.
pub async fn serve_lines<R, W>(
    server: Arc<McpServer>,
    reader: R,
    writer: W,
    mut conn: ConnCtx,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // The per-connection push sink and the writer task that owns the socket. A
    // caller may inject the sink (so a test can observe its bounds); otherwise it
    // is sized from the server's configured capacity.
    let sink = conn
        .out
        .clone()
        .unwrap_or_else(|| NotificationSink::new(server.push_capacity()));
    conn.out = Some(sink.clone());
    if conn.conn_id == 0 {
        conn.conn_id = server.next_conn_id();
    }
    let conn_id = conn.conn_id;
    let write_timeout = server.write_timeout();
    let mut writer_task = Some(tokio::spawn({
        let sink = sink.clone();
        async move {
            let result = write_loop(writer, sink.clone(), write_timeout).await;
            // When the writer ends (the socket closed, a write failed, or a write
            // hit its deadline) close the sink. That unblocks a read loop parked
            // in `await_reply_capacity`, which would otherwise wait forever for a
            // writer that has gone, so the connection tears down cleanly. A
            // panic skips this line; teardown below closes the sink regardless.
            sink.close();
            result
        }
    }));

    // Race the read loop against the writer. The lib's tokio build omits the
    // `macros` feature (as in `http.rs`), so there is no `select!`: the two
    // futures are polled by hand, the read loop first, so that if it has ended
    // (EOF, a read error) that ends the connection even if the writer ended in the
    // same instant. A `JoinHandle` must not be polled or awaited again once it has
    // completed, so `writer_task` is emptied as soon as it has.
    let mut read = std::pin::pin!(read_loop(server.clone(), reader, conn, sink.clone()));
    let outcome = std::future::poll_fn(|cx| {
        if let Poll::Ready(outcome) = read.as_mut().poll(cx) {
            return Poll::Ready(outcome);
        }
        if let Some(task) = writer_task.as_mut() {
            if let Poll::Ready(joined) = Pin::new(task).poll(cx) {
                writer_task = None;
                // A writer that failed ends the connection now. One that ended
                // cleanly leaves the read loop to end it.
                if let Some(err) = writer_failure(joined) {
                    return Poll::Ready(Err(err));
                }
            }
        }
        Poll::Pending
    })
    .await;

    // Teardown: close the sink, then drop this connection's subscriptions. In that
    // order a `flow.subscribe` still in flight (a command on the blocking pool
    // that outlived the abandoned read loop) is either refused, because the sink
    // is closed, or swept by the drop; it cannot register after the drop and
    // outlive the connection (see `Subscriptions::add`). Then let the writer drain
    // what is queued and exit.
    sink.close();
    server.drop_connection(conn_id);
    if let Some(task) = writer_task {
        if let Some(err) = writer_failure(task.await) {
            tracing::debug!(
                error = %format_args!("{err:#}"),
                "bus connection's writer ended with an error"
            );
        }
    }
    outcome
}

/// The error a finished writer task ended the connection with, if it failed: the
/// writer's own error (the deadline, or a failed write), or the join error of a
/// writer that panicked or was cancelled. `None` when the writer ended cleanly.
fn writer_failure(joined: Result<anyhow::Result<()>, JoinError>) -> Option<anyhow::Error> {
    match joined {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(err),
        Err(join) => Some(anyhow::Error::new(join).context("the connection's writer task failed")),
    }
}

/// The read half of [`serve_lines`]: dispatch each incoming line through
/// `server` and queue its reply on `sink`, until EOF, a read error, or a line
/// over [`MAX_MESSAGE_BYTES`].
async fn read_loop<R>(
    server: Arc<McpServer>,
    reader: R,
    mut conn: ConnCtx,
    sink: NotificationSink,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin + Send,
{
    let mut reader = reader.take(MAX_MESSAGE_BYTES as u64);
    let mut line = String::new();
    while read_message(&mut reader, &mut line).await? {
        let message = line.trim().to_string();
        if message.is_empty() {
            continue;
        }
        // The client names itself once, in `initialize`; carry that label
        // onto the connection for audit (first one wins) without re-parsing.
        if conn.client_label.is_none() {
            if let Some(label) = client_label_from_initialize(&message) {
                conn.client_label = Some(label);
            }
        }
        let srv = server.clone();
        let c = conn.clone();
        let reply = tokio::task::spawn_blocking(move || srv.handle_on(&c, &message)).await?;
        if let Some(reply) = reply {
            // Replies ride the sink too (never dropped); the writer task
            // serializes them with any interleaved notifications.
            sink.push_reply(reply);
        }
        // Backpressure (RF#3): if the client is not draining its socket the
        // writer cannot flush, so replies accumulate. Once the reply lane hits
        // its high-water mark, stop reading new requests until the writer has
        // drained below it — bounding memory without dropping any reply. If the
        // sink has closed (client gone), this returns at once so the loop ends.
        sink.await_reply_capacity().await;
    }
    Ok(())
}

/// Drain `sink` to `writer` until the sink is closed and empty. Each frame is a
/// complete JSON-RPC line; a trailing newline is appended per line. Every
/// `write_all`, and the `flush` after a batch, runs under `write_timeout` (see
/// [`McpServer::write_timeout`]); when one expires the loop returns an error whose
/// text starts `write timed out after` and the connection is given up on (see
/// [`serve_lines`]).
async fn write_loop<W>(
    mut writer: W,
    sink: NotificationSink,
    write_timeout: Duration,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    loop {
        let frames = sink.drain();
        if !frames.is_empty() {
            for mut frame in frames {
                frame.push('\n');
                within(write_timeout, writer.write_all(frame.as_bytes())).await?;
            }
            within(write_timeout, writer.flush()).await?;
            // Re-check for anything queued while we were writing before parking.
            continue;
        }
        if sink.is_closed_and_drained() {
            break;
        }
        sink.wait().await;
    }
    Ok(())
}

/// Run one write-side operation, giving up if it takes longer than `limit`.
/// Expiry is an error whose text starts `write timed out after`; an I/O error
/// from the operation itself passes through unchanged.
async fn within(
    limit: Duration,
    operation: impl Future<Output = io::Result<()>>,
) -> anyhow::Result<()> {
    match tokio::time::timeout(limit, operation).await {
        Ok(result) => Ok(result?),
        Err(_) => anyhow::bail!("write timed out after {limit:?}"),
    }
}

/// The label a client declares in `initialize.clientInfo.name`, if `message` is an
/// `initialize` request that carries one; `None` otherwise.
///
/// The name is client-controlled, so it passes through
/// [`aitm_core::declared_client_label`]: bounded, stripped of control and bidi
/// characters, credential-scrubbed, and a server-minted name such as `web-bridge`
/// is rewritten to `web-bridge (declared)` so a client cannot pose as it. A name
/// that is empty after that yields `None`.
fn client_label_from_initialize(message: &str) -> Option<String> {
    let v: JsonValue = serde_json::from_str(message).ok()?;
    if v.get("method").and_then(JsonValue::as_str)? != "initialize" {
        return None;
    }
    let name = v.get("params")?.get("clientInfo")?.get("name")?.as_str()?;
    aitm_core::declared_client_label(name)
}

/// Serve over this process's stdin/stdout until stdin closes. The stdio
/// connection speaks as `server.stdio_role()` (there is no token line).
pub async fn serve_stdio(server: Arc<McpServer>) -> anyhow::Result<()> {
    let conn = ConnCtx::new(server.stdio_role());
    serve_lines(
        server,
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
        conn,
    )
    .await
}

/// A loopback-only (127.0.0.1) listener. Every connection must send, as its
/// first line, a JSON object `{"token": "<token>"}` matching a configured token;
/// anything else is answered with one `unauthorized` error and closed. The token
/// class picks the connection's role: the `agent_token` (required by
/// [`LoopbackTcp::bind`], absent on [`LoopbackTcp::bind_operator_only`]) →
/// [`Frontend::Mcp`], the optional `operator_token` → [`Frontend::Operator`].
pub struct LoopbackTcp {
    listener: TcpListener,
    local_addr: SocketAddr,
    agent_token: Option<Arc<str>>,
    operator_token: Option<Arc<str>>,
    /// A rendezvous file to remove on drop; see [`LoopbackTcp::bind`].
    endpoint_file: Option<PathBuf>,
    /// The core pointer this listener published (spec D4), if a process
    /// context was published; see [`LoopbackTcp::publish_pointer`]. The handle
    /// holds the pointer's advisory lock and removes the file when it drops.
    pointer: Option<pointer::Published>,
    /// How long a connection has to send its token line; [`TOKEN_LINE_TIMEOUT`]
    /// unless [`LoopbackTcp::with_token_line_timeout`] said otherwise.
    token_line_timeout: Duration,
}

impl LoopbackTcp {
    /// Bind `127.0.0.1:port` (`0` picks a free port). The agent token must be
    /// non-empty; the operator token (if any) is added with
    /// [`LoopbackTcp::with_operator_token`].
    ///
    /// When `endpoint_file` is `Some`, the bound `host:port` (never the token) is
    /// written to that path `0600` once the listener binds, so a parent process
    /// can learn the ephemeral port without parsing stdout; the file is removed
    /// when this `LoopbackTcp` is dropped (clean exit or error). Mirrors the
    /// obscura ready-file precedent.
    pub async fn bind(
        port: u16,
        token: String,
        endpoint_file: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !token.is_empty(),
            "the loopback TCP transport requires a non-empty token"
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let local_addr = listener.local_addr()?;
        if let Some(path) = &endpoint_file {
            write_endpoint_file(path, local_addr)?;
        }
        Ok(Self {
            listener,
            local_addr,
            agent_token: Some(token.into()),
            operator_token: None,
            endpoint_file,
            pointer: None,
            token_line_timeout: TOKEN_LINE_TIMEOUT,
        })
    }

    /// Bind `127.0.0.1:port` (`0` picks a free port) as the dedicated operator
    /// bus (spec D2): no agent token, so only `operator_token` (which must be
    /// non-empty) admits a connection, always as [`Frontend::Operator`]. No
    /// endpoint file; the core pointer ([`LoopbackTcp::publish_pointer`]) is
    /// how a one-shot finds this listener.
    pub async fn bind_operator_only(port: u16, operator_token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !operator_token.is_empty(),
            "the operator bus requires a non-empty operator token"
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            agent_token: None,
            operator_token: Some(operator_token.into()),
            endpoint_file: None,
            pointer: None,
            token_line_timeout: TOKEN_LINE_TIMEOUT,
        })
    }

    /// Also accept an operator token; a connection presenting it is treated as
    /// [`Frontend::Operator`]. An empty token is ignored (no operator token).
    pub fn with_operator_token(mut self, token: Option<String>) -> Self {
        self.operator_token = token.filter(|t| !t.is_empty()).map(Into::into);
        self
    }

    /// Give each connection `limit` instead of [`TOKEN_LINE_TIMEOUT`] to send
    /// its token line (security S1); a test's way to see the close without
    /// waiting ten seconds.
    pub fn with_token_line_timeout(mut self, limit: Duration) -> Self {
        self.token_line_timeout = limit;
        self
    }

    /// The bound address (useful after binding port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Publish this listener's core pointer (spec D4): `<run dir>/<pid>.json`
    /// naming the bound address and whether an operator token is accepted,
    /// written only when a process context was published
    /// ([`pointer::publish`]); otherwise nothing is written. Called once by
    /// [`McpServer::serve_on`] when the listener starts serving. The pointer
    /// lives as long as this listener and is removed when it drops.
    pub fn publish_pointer(&mut self) {
        self.pointer = pointer::publish_pointer(self.local_addr, self.operator_token.is_some());
    }

    /// Accept connections forever, serving each on its own task. An `accept()`
    /// error is logged at `warn!` and the loop goes on (security S1): the
    /// default-on operator bus must not end quietly on the first `EMFILE`,
    /// which a neighbour that opens connections and holds them can provoke;
    /// every error pauses [`ACCEPT_ERROR_BACKOFF`] first so none can spin
    /// it (security S7).
    pub async fn serve(self, server: Arc<McpServer>) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    accept_failed(&err).await;
                    continue;
                }
            };
            // The bind is loopback-only already; this is belt and braces.
            if !peer.ip().is_loopback() {
                continue;
            }
            let srv = server.clone();
            let agent = self.agent_token.clone();
            let operator = self.operator_token.clone();
            let token_line_timeout = self.token_line_timeout;
            tokio::spawn(async move {
                // A failed connection is that client's problem, not the server's:
                // it is logged at debug (never with a token; the errors carry none)
                // and the listener goes on accepting.
                let (read_half, write_half) = stream.into_split();
                if let Err(err) = serve_connection(
                    srv,
                    read_half,
                    write_half,
                    agent.as_deref(),
                    operator.as_deref(),
                    token_line_timeout,
                )
                .await
                {
                    tracing::debug!(
                        error = %format_args!("{err:#}"),
                        "bus connection ended with an error"
                    );
                }
            });
        }
    }
}

impl Drop for LoopbackTcp {
    /// Remove the rendezvous file, if any, so a bound address never outlives the
    /// listener. Idempotent — a missing file is fine. The core pointer, if one
    /// was published, is removed by its own [`pointer::Published`] handle when
    /// the `pointer` field drops right after this.
    fn drop(&mut self) {
        if let Some(path) = &self.endpoint_file {
            remove_endpoint_file(path);
        }
    }
}

/// Write `addr` (the bound `host:port`, never the token) to `path`, truncating
/// any leftover, readable and writable by the owner only on Unix. A single
/// trailing newline makes it `cat`-friendly and unambiguous to a line reader.
///
/// Security: the file is created/truncated through `path` without `O_NOFOLLOW`,
/// so the caller MUST place `endpoint_file` in a directory only the operator can
/// write (e.g. a `0700` per-launch dir, as the embedded macOS core does). In a
/// world-writable directory an attacker could pre-plant a symlink and redirect
/// this write; a private parent directory removes that exposure.
fn write_endpoint_file(path: &Path, addr: SocketAddr) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("writing the bus endpoint file {}", path.display()))?;
    writeln!(file, "{addr}")
        .with_context(|| format!("writing the bus endpoint file {}", path.display()))?;
    Ok(())
}

/// What [`LoopbackTcp::serve`] does with an `accept()` error (security S1,
/// S7): logs it at `warn!` and pauses [`ACCEPT_ERROR_BACKOFF`] before the
/// next `accept()`. Every error pauses and none is inspected: a persistent
/// one (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`) recurs the instant it is
/// retried and would otherwise spin a core at full CPU, logging as fast as
/// it loops, while a per-connection one (`ECONNABORTED`, `EINTR`, a reset)
/// loses nothing to 100 ms; so no class of error can be missed. (tokio's
/// `accept()` never surfaces `WouldBlock`.)
async fn accept_failed(err: &io::Error) {
    tracing::warn!(
        error = %err,
        "the bus listener could not accept a connection; still listening"
    );
    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
}

/// Remove the rendezvous file; a missing one is fine (idempotent).
fn remove_endpoint_file(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "could not remove the bus endpoint file")
        }
    }
}

/// Serve one accepted connection: the token line first, within
/// `token_line_timeout` (security S1), then [`serve_lines`] as the role the
/// token names. A connection that sends no line in time is closed with one
/// content-free `debug!`; the partial line is never logged, since it may be
/// a token or part of one.
async fn serve_connection<R, W>(
    server: Arc<McpServer>,
    read_half: R,
    mut write_half: W,
    agent_token: Option<&str>,
    operator_token: Option<&str>,
    token_line_timeout: Duration,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(read_half).take(MAX_MESSAGE_BYTES as u64);
    let mut first = String::new();
    let Ok(read) =
        tokio::time::timeout(token_line_timeout, read_message(&mut reader, &mut first)).await
    else {
        tracing::debug!(
            limit_secs = token_line_timeout.as_secs_f64(),
            "closing a bus connection that sent no token line within the limit"
        );
        return Ok(());
    };
    if !read? {
        return Ok(());
    }
    let Some(role) = classify_token(&first, agent_token, operator_token) else {
        let mut refusal = error_response(JsonValue::Null, UNAUTHORIZED, "unauthorized").to_string();
        refusal.push('\n');
        write_half.write_all(refusal.as_bytes()).await?;
        write_half.shutdown().await?;
        return Ok(());
    };
    serve_lines(server, reader.into_inner(), write_half, ConnCtx::new(role)).await
}

/// Classify `line` (`{"token": "<t>"}`) by token class: the operator token (if
/// configured) wins and yields [`Frontend::Operator`], the agent token (if
/// configured) yields [`Frontend::Mcp`], and anything else (malformed, an
/// unknown token, or a class this listener has no token for) is `None` — the
/// caller refuses it `-32001`. Tokens are compared in constant time. The object
/// must carry exactly the `token` key (extra keys are rejected, matching the web
/// bridge's `token_line_matches`), so nothing can ride along with the auth line.
fn classify_token(line: &str, agent: Option<&str>, operator: Option<&str>) -> Option<Frontend> {
    let Ok(JsonValue::Object(obj)) = serde_json::from_str::<JsonValue>(line.trim()) else {
        return None;
    };
    if obj.len() != 1 {
        return None;
    }
    let Some(JsonValue::String(given)) = obj.get("token") else {
        return None;
    };
    if let Some(op) = operator {
        if token_matches(given, op) {
            return Some(Frontend::Operator);
        }
    }
    let agent = agent?;
    token_matches(given, agent).then_some(Frontend::Mcp)
}

fn token_matches(given: &str, expected: &str) -> bool {
    let (g, e) = (given.as_bytes(), expected.as_bytes());
    let mut diff = g.len() ^ e.len();
    for (i, &eb) in e.iter().enumerate() {
        diff |= usize::from(eb ^ g.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Read one line into `buf` (cleared first). `Ok(false)` at EOF; an error if the
/// line exceeds [`MAX_MESSAGE_BYTES`].
async fn read_message<R: AsyncBufRead + Unpin>(
    reader: &mut Take<R>,
    buf: &mut String,
) -> anyhow::Result<bool> {
    buf.clear();
    reader.set_limit(MAX_MESSAGE_BYTES as u64);
    let n = reader.read_line(buf).await?;
    if n == 0 {
        return Ok(false);
    }
    if !buf.ends_with('\n') && reader.limit() == 0 {
        anyhow::bail!("message exceeds {MAX_MESSAGE_BYTES} bytes");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use aitm_core::{McpTransport, Registry};
    use serde_json::json;
    use tokio::io::{duplex, split, DuplexStream, Lines, ReadHalf, WriteHalf};
    use tokio::net::{TcpSocket, TcpStream};
    use tokio::task::JoinHandle;

    /// A unique temp path for one test, cleaned up by the test itself.
    fn temp_endpoint_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aitm-bus-endpoint-{}-{tag}.addr",
            std::process::id()
        ))
    }

    /// AC3/O5: after the loopback transport binds with an endpoint file, the file
    /// holds exactly the bound `127.0.0.1:<port>` and never the token, and it is
    /// removed when the listener is dropped.
    #[tokio::test]
    async fn endpoint_file_written_after_bind() {
        let path = temp_endpoint_path("written");
        let _ = std::fs::remove_file(&path);

        let listener = LoopbackTcp::bind(0, "s3cret-token".into(), Some(path.clone()))
            .await
            .expect("bind 127.0.0.1:0 with an endpoint file");
        let addr = listener.local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0, "an ephemeral port was resolved");

        let contents = std::fs::read_to_string(&path).expect("endpoint file exists after bind");
        assert_eq!(
            contents.trim(),
            addr.to_string(),
            "the file holds the bound host:port"
        );
        assert!(
            !contents.contains("s3cret-token"),
            "the token must never enter the endpoint file: {contents:?}"
        );

        drop(listener);
        assert!(
            !path.exists(),
            "the endpoint file is removed when the listener is dropped"
        );
    }

    /// With no endpoint file configured, binding writes no rendezvous file.
    #[tokio::test]
    async fn no_endpoint_file_writes_nothing() {
        let listener = LoopbackTcp::bind(0, "tok".into(), None)
            .await
            .expect("bind 127.0.0.1:0 without an endpoint file");
        assert!(listener.local_addr().ip().is_loopback());
        // Nothing to assert beyond: there is no path, so nothing is written or
        // leaked; dropping must not panic.
        drop(listener);
    }

    /// A bare server for the operator-only listener tests: no commands, no
    /// store; `initialize` needs neither.
    fn bare_server() -> Arc<McpServer> {
        Arc::new(McpServer::new(
            Arc::new(Registry::new()),
            McpTransport::Stdio,
        ))
    }

    /// Spec D2 (`bind_operator_only`): an empty operator token is refused
    /// before anything binds.
    #[tokio::test]
    async fn bind_operator_only_refuses_an_empty_token() {
        let err = LoopbackTcp::bind_operator_only(0, String::new())
            .await
            .err()
            .expect("an empty operator token is an error");
        assert_eq!(
            err.to_string(),
            "the operator bus requires a non-empty operator token"
        );
    }

    /// AC-R14-8 (socket, Terminal): `bind_operator_only` binds `127.0.0.1`; a
    /// connection presenting the operator token is served as `role: "operator"`
    /// and one presenting any other string gets `-32001` and a closed socket.
    #[tokio::test]
    async fn bind_operator_only_binds_loopback_and_refuses_other_tokens() {
        let listener = LoopbackTcp::bind_operator_only(0, "op".into())
            .await
            .expect("bind 127.0.0.1:0 as an operator-only listener");
        let addr = listener.local_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(addr.port(), 0, "an ephemeral port was resolved");
        let serving = tokio::spawn(listener.serve(bare_server()));
        let initialize = initialize_with_name("aitm-cli");

        // What would be the agent token on a shared transport is nobody here:
        // one refusal line, then the socket is closed.
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        write_half
            .write_all(format!("{{\"token\":\"ag\"}}\n{initialize}\n").as_bytes())
            .await
            .expect("send the token line and a request");
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .await
            .expect("read the refusal line");
        assert!(
            reply.contains("\"code\":-32001"),
            "refused with -32001: {reply:?}"
        );
        let mut rest = String::new();
        let closed = match reader.read_line(&mut rest).await {
            Ok(n) => n == 0,
            Err(err) => err.kind() == io::ErrorKind::ConnectionReset,
        };
        assert!(closed, "the socket is closed after the refusal: {rest:?}");

        // The operator token is served as the operator role.
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        write_half
            .write_all(format!("{{\"token\":\"op\"}}\n{initialize}\n").as_bytes())
            .await
            .expect("send the operator token and initialize");
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .await
            .expect("read the initialize reply");
        assert!(
            reply.contains("\"role\":\"operator\""),
            "served as the operator: {reply:?}"
        );

        serving.abort();
    }

    /// AC-R14-12 (socket, Terminal): a test binary publishes no pointer context,
    /// so `publish_pointer` on a bound listener writes nothing and holds no
    /// pointer; dropping the listener then touches no run dir.
    #[tokio::test]
    async fn serving_without_a_context_writes_no_pointer() {
        assert!(
            pointer::context().is_none(),
            "the unit binary never publishes a context"
        );
        let mut listener = LoopbackTcp::bind_operator_only(0, "op".into())
            .await
            .expect("bind 127.0.0.1:0 as an operator-only listener");
        listener.publish_pointer();
        assert!(
            listener.pointer.is_none(),
            "no context, so no pointer was written"
        );
        drop(listener);
    }

    // ---- S1 (security pass 1): the default-on bus against a silent or
    // ---- flooding same-user neighbour.

    /// S1(b), security S7 / quality Q15: every `accept()` error pauses the
    /// listener 100 ms, the per-connection ones (`ECONNABORTED`, `EINTR`, a
    /// reset) as much as the persistent ones (`EMFILE`, `ENFILE`, `ENOBUFS`,
    /// `ENOMEM`), so no class of error can spin it. `WouldBlock` is no
    /// case: tokio's `accept()` never surfaces it. Real time, lower bound
    /// only: a sleep never ends early, and an upper bound would flake under
    /// load.
    #[tokio::test]
    async fn every_accept_error_pauses_the_listener() {
        // `ENOBUFS` differs per platform; `ENFILE`/`EMFILE` do not.
        #[cfg(target_os = "linux")]
        const ENOBUFS: i32 = 105;
        #[cfg(not(target_os = "linux"))]
        const ENOBUFS: i32 = 55;
        for (label, err) in [
            ("ENFILE", io::Error::from_raw_os_error(23)),
            ("EMFILE", io::Error::from_raw_os_error(24)),
            ("ENOBUFS", io::Error::from_raw_os_error(ENOBUFS)),
            ("ENOMEM", io::Error::from(io::ErrorKind::OutOfMemory)),
            (
                "ECONNABORTED",
                io::Error::from(io::ErrorKind::ConnectionAborted),
            ),
            ("EINTR", io::Error::from(io::ErrorKind::Interrupted)),
            (
                "ECONNRESET",
                io::Error::from(io::ErrorKind::ConnectionReset),
            ),
            ("anything else", io::Error::other("anything else")),
        ] {
            let before = Instant::now();
            accept_failed(&err).await;
            let paused = before.elapsed();
            assert!(
                paused >= Duration::from_millis(100),
                "{label}: the listener paused only {paused:?}"
            );
        }
    }

    /// S1(a): a connection that sends no token line within the limit is
    /// closed quietly: the server side ends `Ok(())`, the client reads EOF
    /// and not one byte before it. In-process over a duplex pipe with a
    /// 200 ms limit; the production limit is `TOKEN_LINE_TIMEOUT`, 10 s.
    #[tokio::test]
    async fn a_connection_that_sends_no_token_line_in_time_is_closed() {
        assert_eq!(TOKEN_LINE_TIMEOUT, Duration::from_secs(10));
        let (server_side, client_side) = duplex(4096);
        let (server_read, server_write) = split(server_side);
        let (mut client_read, client_write) = split(client_side);
        let started = Instant::now();
        let serving = tokio::spawn(serve_connection(
            bare_server(),
            server_read,
            server_write,
            None,
            Some("op"),
            Duration::from_millis(200),
        ));

        // The client keeps its write half open and says nothing.
        let mut got = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), client_read.read_to_end(&mut got))
            .await
            .expect("the server closes the connection within 5 s")
            .expect("read to EOF");
        assert_eq!(n, 0, "nothing is written before the close: {got:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "closed no earlier than the limit: {:?}",
            started.elapsed()
        );
        let outcome = serving.await.expect("the connection task did not panic");
        assert!(
            outcome.is_ok(),
            "the expiry is a quiet close, not an error: {outcome:?}"
        );
        drop(client_write);
    }

    /// S1(a): the limit is on the token line only. A client that sends it
    /// within the limit is served (here as the operator) for as long as it
    /// likes afterwards, well past the limit.
    #[tokio::test]
    async fn a_token_line_within_the_limit_is_served_past_it() {
        let (server_side, client_side) = duplex(4096);
        let (server_read, server_write) = split(server_side);
        let (client_read, mut client_write) = split(client_side);
        let serving = tokio::spawn(serve_connection(
            bare_server(),
            server_read,
            server_write,
            None,
            Some("op"),
            Duration::from_millis(200),
        ));
        let mut reader = BufReader::new(client_read);
        client_write
            .write_all(b"{\"token\":\"op\"}\n")
            .await
            .expect("send the token line in time");

        tokio::time::sleep(Duration::from_millis(400)).await;
        let initialize = initialize_with_name("aitm-cli");
        client_write
            .write_all(format!("{initialize}\n").as_bytes())
            .await
            .expect("send initialize after the limit");
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut reply))
            .await
            .expect("a reply within 5 s")
            .expect("read the initialize reply");
        assert!(
            reply.contains("\"role\":\"operator\""),
            "served as the operator after the limit: {reply:?}"
        );

        // A split duplex closes on `shutdown`, not on dropping one half.
        client_write.shutdown().await.expect("client EOF");
        let outcome = tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("the connection ends at client EOF")
            .expect("the connection task did not panic");
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// S1(a) (socket, Terminal): through the served listener, a connection
    /// that sends nothing is closed once the listener's token-line limit
    /// (200 ms here, `with_token_line_timeout`) expires, and the listener
    /// goes on serving: a second connection that sends the operator token is
    /// answered as the operator.
    #[tokio::test]
    async fn served_listener_closes_a_silent_connection_after_the_token_line_limit() {
        let listener = LoopbackTcp::bind_operator_only(0, "op".into())
            .await
            .expect("bind 127.0.0.1:0 as an operator-only listener")
            .with_token_line_timeout(Duration::from_millis(200));
        let addr = listener.local_addr();
        let serving = tokio::spawn(listener.serve(bare_server()));

        let silent = TcpStream::connect(addr).await.expect("connect");
        let (mut silent_read, silent_write) = silent.into_split();
        let mut got = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), silent_read.read_to_end(&mut got))
            .await
            .expect("the silent connection is closed within 5 s")
            .expect("read to EOF");
        assert_eq!(n, 0, "nothing is written to a silent client: {got:?}");
        drop(silent_write);

        let stream = TcpStream::connect(addr).await.expect("connect again");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let initialize = initialize_with_name("aitm-cli");
        write_half
            .write_all(format!("{{\"token\":\"op\"}}\n{initialize}\n").as_bytes())
            .await
            .expect("send the operator token and initialize");
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .await
            .expect("read the initialize reply");
        assert!(
            reply.contains("\"role\":\"operator\""),
            "the listener still serves after closing a silent connection: {reply:?}"
        );
        serving.abort();
    }

    /// An `initialize` request whose `clientInfo.name` is `name`.
    fn initialize_with_name(name: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "clientInfo": { "name": name } },
        })
        .to_string()
    }

    /// AC14: the label captured from `initialize` is bounded (a 10 MiB name
    /// becomes 64 chars), a client cannot claim the server-minted `web-bridge`
    /// name, an ordinary name is kept, and an empty or absent name is `None`.
    #[test]
    fn client_label_from_initialize_is_bounded_and_unforgeable() {
        assert_eq!(
            client_label_from_initialize(&initialize_with_name(&"A".repeat(10 << 20))),
            Some("A".repeat(64))
        );
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("web-bridge")),
            Some("web-bridge (declared)".to_string())
        );
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("aitm-mac")),
            Some("aitm-mac".to_string())
        );
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("")),
            None
        );
        assert_eq!(
            client_label_from_initialize(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#
            ),
            None
        );
    }

    #[test]
    fn token_compare() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abd", "abc"));
        assert!(!token_matches("ab", "abc"));
        assert!(!token_matches("abcd", "abc"));
        assert!(!token_matches("", "abc"));
    }

    #[test]
    fn classify_token_shapes() {
        // Agent-only: a match is the agent role, anything else is refused.
        assert_eq!(
            classify_token(r#"{"token":"t"}"#, Some("t"), None),
            Some(Frontend::Mcp)
        );
        assert_eq!(
            classify_token("  {\"token\":\"t\"}\r\n", Some("t"), None),
            Some(Frontend::Mcp)
        );
        assert_eq!(classify_token(r#"{"token":"x"}"#, Some("t"), None), None);
        assert_eq!(classify_token(r#"{"tok":"t"}"#, Some("t"), None), None);
        assert_eq!(classify_token(r#"{"token":1}"#, Some("t"), None), None);
        // Minor (b): exactly one key — a correct token can't smuggle extra keys.
        assert_eq!(
            classify_token(r#"{"token":"t","x":1}"#, Some("t"), None),
            None
        );
        assert_eq!(
            classify_token(r#"{"token":"t","token2":"t"}"#, Some("t"), None),
            None
        );
        assert_eq!(classify_token(r#"{}"#, Some("t"), None), None);
        assert_eq!(classify_token(r#"["t"]"#, Some("t"), None), None);
        assert_eq!(classify_token("t", Some("t"), None), None);
        assert_eq!(
            classify_token(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                Some("t"),
                None
            ),
            None
        );
    }

    #[test]
    fn classify_token_by_class() {
        // Operator token wins when it matches; the agent token is the fallback.
        assert_eq!(
            classify_token(r#"{"token":"op"}"#, Some("ag"), Some("op")),
            Some(Frontend::Operator)
        );
        assert_eq!(
            classify_token(r#"{"token":"ag"}"#, Some("ag"), Some("op")),
            Some(Frontend::Mcp)
        );
        assert_eq!(
            classify_token(r#"{"token":"no"}"#, Some("ag"), Some("op")),
            None
        );
    }

    /// Spec D2, AC-R14-8: an operator-only listener has no agent token, so only
    /// the operator token admits a connection; when an agent token exists it
    /// still yields the agent role.
    #[test]
    fn classify_token_without_an_agent_token_admits_only_the_operator() {
        assert_eq!(
            classify_token(r#"{"token":"op"}"#, None, Some("op")),
            Some(Frontend::Operator)
        );
        assert_eq!(classify_token(r#"{"token":"ag"}"#, None, Some("op")), None);
        assert_eq!(
            classify_token(r#"{"token":"ag"}"#, Some("ag"), Some("op")),
            Some(Frontend::Mcp)
        );
        // A listener with no token of either class admits nobody.
        assert_eq!(classify_token(r#"{"token":""}"#, None, None), None);
    }

    /// A bare server (no commands, no store: `flow.subscribe` needs neither)
    /// whose line-transport write deadline is `deadline`.
    fn server_with_deadline(deadline: Duration) -> Arc<McpServer> {
        Arc::new(
            McpServer::new(Arc::new(Registry::new()), McpTransport::Stdio)
                .with_write_timeout(deadline),
        )
    }

    /// One `notifications/aitm/state` push carrying `seq` and 4 KiB of padding,
    /// so a handful of them overflow any small pipe.
    fn push_padded(server: &McpServer, seq: u64) {
        server.push_state(json!({"seq": seq, "pad": "p".repeat(4096)}));
    }

    /// The `flow.subscribe` request every test sends first, as one line.
    fn subscribe_line() -> String {
        let mut line = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "flow.subscribe", "arguments": {}},
        })
        .to_string();
        line.push('\n');
        line
    }

    /// Assert that `reply` is the line of a successful `flow.subscribe`, that is,
    /// carries a `sub_id`. No test here needs the id itself.
    fn assert_subscribed_reply(reply: &str) {
        let reply: JsonValue = serde_json::from_str(reply).expect("the reply is JSON");
        assert!(
            reply["result"]["structuredContent"]["sub_id"].is_u64(),
            "the subscribe reply carries a sub_id: {reply}"
        );
    }

    /// The client end of a `serve_lines` connection over an in-memory pipe, plus
    /// the injected push sink and the server task, so a test can watch all three.
    struct LineClient {
        writer: WriteHalf<DuplexStream>,
        lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
        sink: NotificationSink,
        task: JoinHandle<anyhow::Result<()>>,
    }

    /// Serve one `Frontend::Operator` connection of `server` over `duplex(256)`:
    /// a pipe so small that a write blocks exactly like a stopped socket. `sink`
    /// is the connection's injected push sink, so the test can watch its bounds.
    fn serve_over_tiny_pipe(server: &Arc<McpServer>, sink: NotificationSink) -> LineClient {
        serve_through(server, sink, |server_write| server_write)
    }

    /// As [`serve_over_tiny_pipe`], with the server's write half passed through
    /// `wrap` first, for a test that needs a writer with its own behaviour.
    fn serve_through<W>(
        server: &Arc<McpServer>,
        sink: NotificationSink,
        wrap: impl FnOnce(WriteHalf<DuplexStream>) -> W,
    ) -> LineClient
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (client, server_side) = duplex(256);
        let (server_read, server_write) = split(server_side);
        let mut conn = ConnCtx::new(Frontend::Operator);
        conn.out = Some(sink.clone());
        let task = tokio::spawn(serve_lines(
            server.clone(),
            BufReader::new(server_read),
            wrap(server_write),
            conn,
        ));
        let (client_read, writer) = split(client);
        LineClient {
            writer,
            lines: BufReader::new(client_read).lines(),
            sink,
            task,
        }
    }

    impl LineClient {
        /// Send `flow.subscribe {}`, read exactly one line, and assert it is a
        /// successful subscribe reply.
        async fn subscribe(&mut self) {
            self.writer
                .write_all(subscribe_line().as_bytes())
                .await
                .expect("send flow.subscribe");
            self.writer.flush().await.expect("flush flow.subscribe");
            let reply = self
                .lines
                .next_line()
                .await
                .expect("read the subscribe reply")
                .expect("a reply line");
            assert_subscribed_reply(&reply);
        }

        /// The next line from the server, parsed.
        async fn next_json(&mut self) -> JsonValue {
            let line = self
                .lines
                .next_line()
                .await
                .expect("read a line")
                .expect("a line was expected");
            serde_json::from_str(&line).expect("a JSON line")
        }
    }

    /// A client that subscribes and then neither reads nor closes cannot pin the
    /// connection (bus-hardening AC14). The writer's `write_all` stalls on the
    /// full pipe, the write deadline expires, and `serve_lines` returns that error
    /// instead of parking in `read_line` for a peer that never sends EOF; the
    /// subscriptions are dropped and the sink closed, so a later push queues
    /// nothing.
    #[tokio::test]
    async fn a_stopped_line_reader_ends_the_connection_after_the_write_deadline() {
        let server = server_with_deadline(Duration::from_millis(200));
        let mut client = serve_over_tiny_pipe(&server, NotificationSink::new(64));
        client.subscribe().await;

        for seq in 0..16 {
            push_padded(&server, seq);
        }
        // From here the client neither reads nor closes: it holds both halves.

        let ended = tokio::time::timeout(Duration::from_secs(5), client.task)
            .await
            .expect("serve_lines returned within 5 s of the pushes (the deadline is 200 ms)")
            .expect("the serve_lines task did not panic");
        let err = ended.expect_err("a writer that hit its deadline ends the connection in error");
        assert!(
            err.to_string().contains("write timed out"),
            "the error names the write deadline: {err}"
        );
        assert!(
            client.sink.is_closed(),
            "the connection's sink is closed when it ends"
        );

        let before = client.sink.queued_len();
        push_padded(&server, 99);
        assert_eq!(
            client.sink.queued_len(),
            before,
            "the subscription was dropped, so a later push reaches nothing"
        );
        drop((client.writer, client.lines));
    }

    /// A reader that is slow but live is not cut (bus-hardening AC15). It reads
    /// one line per 20 ms, so it frees room for the next write well inside the 1 s
    /// deadline every time (50 times over), yet the 100 lines take 2 s in all,
    /// longer than the deadline: a deadline over the whole batch instead of over
    /// each write would end this connection. The reader receives every pushed
    /// line, in order, and the connection is still up afterwards; it ends only when
    /// the client closes.
    #[tokio::test]
    async fn a_slow_line_reader_is_not_disconnected() {
        const PUSHES: u64 = 100;
        let server = server_with_deadline(Duration::from_secs(1));
        // The sink holds every push, so none is dropped as lag before it is read.
        let mut client = serve_over_tiny_pipe(&server, NotificationSink::new(PUSHES as usize));
        client.subscribe().await;

        for seq in 0..PUSHES {
            push_padded(&server, seq);
        }
        for seq in 0..PUSHES {
            let line = client.next_json().await;
            assert_eq!(
                line["method"], "notifications/aitm/state",
                "push {seq} arrived as a state notification: {line}"
            );
            assert_eq!(
                line["params"]["seq"], seq,
                "the pushes arrive in order, none lost: {line}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !client.task.is_finished(),
            "a slow but live reader is not disconnected"
        );

        drop((client.writer, client.lines));
        let ended = tokio::time::timeout(Duration::from_secs(5), client.task)
            .await
            .expect("serve_lines ends once the client closes")
            .expect("the serve_lines task did not panic");
        ended.expect("a client that closes ends the connection cleanly");
    }

    /// A writer that ends cleanly (here the sink is closed under it with nothing
    /// queued) does not end the connection: the read loop keeps serving until the
    /// client closes, and teardown does not await the finished writer a second
    /// time (which would panic the task).
    #[tokio::test]
    async fn a_writer_that_ends_cleanly_does_not_end_the_connection() {
        let server = server_with_deadline(Duration::from_millis(200));
        let client = serve_over_tiny_pipe(&server, NotificationSink::new(64));
        client.sink.close();
        // Long enough for the writer to see the closed sink and finish.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !client.task.is_finished(),
            "a cleanly ended writer leaves the read loop running"
        );

        drop((client.writer, client.lines));
        let ended = tokio::time::timeout(Duration::from_secs(5), client.task)
            .await
            .expect("serve_lines ends once the client closes")
            .expect("the serve_lines task did not panic at teardown");
        ended.expect("a client that closes ends the connection cleanly");
    }

    /// A writer that takes every byte at once but whose `flush` never completes,
    /// like a stdout whose consumer has stopped. Neither a duplex pipe nor a TCP
    /// socket can make `flush` block (theirs finish at once), so the duplex and TCP
    /// tests cannot tell whether the flush is under the write deadline.
    struct StuckFlush;

    impl AsyncWrite for StuckFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The `flush` after a batch is under the write deadline too, not only each
    /// `write_all`. This is the stdio shape, where `flush` is what waits on a
    /// parent that has stopped reading our stdout.
    #[tokio::test]
    async fn a_flush_that_never_completes_hits_the_write_deadline() {
        let sink = NotificationSink::new(4);
        sink.push("a line".into());
        let ended = tokio::time::timeout(
            Duration::from_secs(5),
            write_loop(StuckFlush, sink, Duration::from_millis(100)),
        )
        .await
        .expect("write_loop returned within 5 s of a 100 ms deadline instead of parking in flush");
        let err = ended.expect_err("a flush that never completes ends the writer in error");
        assert!(
            err.to_string().contains("write timed out"),
            "the error names the write deadline: {err}"
        );
    }

    /// A client that keeps sending requests and never reads the replies is
    /// disconnected, the stop the subscribe-then-stall test does not cover. The
    /// writer stalls on the full pipe and replies pile up to the reply lane's
    /// high-water mark (4 here), so the read loop is normally held back by that
    /// backpressure rather than parked in `read_line` (the test does not assert
    /// which of the two it is in). The client never closes, so only the writer's
    /// failure can end the connection, and it must.
    #[tokio::test]
    async fn a_client_that_floods_requests_and_never_reads_replies_is_disconnected() {
        let server = server_with_deadline(Duration::from_millis(200));
        let LineClient {
            writer: mut client_write,
            lines: client_read,
            sink,
            task,
        } = serve_over_tiny_pipe(&server, NotificationSink::with_limits(64, 4));

        // Both client halves stay alive to the end, so the pipe never closes. The
        // flood is its own task: once the server stops reading, its writes block.
        let flood = tokio::spawn(async move {
            for id in 0..64 {
                let line = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#) + "\n";
                if client_write.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
            client_write
        });

        let ended = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("serve_lines returned within 5 s (the deadline is 200 ms) though the client never closed")
            .expect("the serve_lines task did not panic");
        let err = ended.expect_err("a writer that hit its deadline ends the connection in error");
        assert!(
            err.to_string().contains("write timed out"),
            "the error names the write deadline: {err}"
        );
        assert!(
            sink.is_closed(),
            "the connection's sink is closed when it ends"
        );
        flood.abort();
        drop(client_read);
    }

    /// A client that vanishes while the writer is blocked on a full pipe ends the
    /// connection at once through the I/O error, long before the write deadline
    /// (30 s here), and its subscription goes with it: a dead peer ends the
    /// connection whichever of the reader or the writer notices it first.
    #[tokio::test]
    async fn a_client_that_disconnects_mid_write_ends_the_connection_at_once() {
        let server = server_with_deadline(Duration::from_secs(30));
        let mut client = serve_over_tiny_pipe(&server, NotificationSink::new(64));
        client.subscribe().await;
        for seq in 0..16 {
            push_padded(&server, seq);
        }
        // Let the writer park in `write_all` on the full pipe, then vanish.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop((client.writer, client.lines));

        let ended = tokio::time::timeout(Duration::from_secs(5), client.task)
            .await
            .expect(
                "serve_lines returned within 5 s of the disconnect, far inside the 30 s deadline",
            )
            .expect("the serve_lines task did not panic");
        if let Err(err) = ended {
            assert!(
                !err.to_string().contains("write timed out"),
                "a dead peer is an I/O error, not the write deadline: {err}"
            );
        }
        assert!(
            client.sink.is_closed(),
            "the connection's sink is closed when it ends"
        );
        let before = client.sink.queued_len();
        push_padded(&server, 99);
        assert_eq!(
            client.sink.queued_len(),
            before,
            "the subscription was dropped, so a later push reaches nothing"
        );
    }

    /// Passes writes through to the server half of a pipe until `armed` is set,
    /// then panics in `poll_write`: a writer whose task dies without returning an
    /// error. Until it is armed the client can subscribe and read its reply.
    struct PanicsWhenArmed {
        inner: WriteHalf<DuplexStream>,
        armed: Arc<AtomicBool>,
    }

    impl AsyncWrite for PanicsWhenArmed {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            assert!(
                !self.armed.load(Ordering::SeqCst),
                "the test armed this writer to panic"
            );
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// A writer task that panics ends the connection as an error, the same as one
    /// that returns an error: `serve_lines` returns `Err` naming the writer task
    /// (well inside the 30 s write deadline, so the deadline is not what ended it),
    /// the sink is closed, and the connection's subscriptions are dropped. The
    /// client subscribes and reads a pushed line first, so the subscription is
    /// known to be live before the writer is armed to panic.
    #[tokio::test]
    async fn a_panicking_writer_ends_the_connection() {
        let server = server_with_deadline(Duration::from_secs(30));
        let armed = Arc::new(AtomicBool::new(false));
        let mut client = serve_through(&server, NotificationSink::new(64), {
            let armed = armed.clone();
            move |inner| PanicsWhenArmed { inner, armed }
        });
        client.subscribe().await;
        push_padded(&server, 0);
        let line = client.next_json().await;
        assert_eq!(
            line["params"]["seq"], 0,
            "the subscription is live and the writer works before it is armed: {line}"
        );

        armed.store(true, Ordering::SeqCst);
        push_padded(&server, 1);

        let ended = tokio::time::timeout(Duration::from_secs(5), client.task)
            .await
            .expect("serve_lines returned within 5 s of the writer panicking")
            .expect("the serve_lines task did not panic");
        let err = ended.expect_err("a writer task that panicked ends the connection in error");
        assert!(
            err.to_string().contains("writer task failed"),
            "the error names the failed writer task: {err}"
        );
        assert!(
            client.sink.is_closed(),
            "the connection's sink is closed when it ends"
        );

        let before = client.sink.queued_len();
        push_padded(&server, 99);
        assert_eq!(
            client.sink.queued_len(),
            before,
            "the subscription was dropped, so a later push reaches nothing"
        );
        drop((client.writer, client.lines));
    }

    /// The write deadline reaches a real socket (bus-hardening AC16). The client's
    /// receive buffer is 4096 bytes, it sends the token and a `flow.subscribe`,
    /// reads the reply, and stops reading while the test pushes 16 MiB of state
    /// lines. Once the server's own buffers fill, the 1 s write deadline ends the
    /// writer and the server half-closes, so on resuming the client reads what was
    /// buffered and then hits EOF, having received fewer bytes than were pushed.
    ///
    /// This proves only that the server stops writing and half-closes. It does not
    /// prove that the read loop is abandoned or that the subscriptions are dropped:
    /// dropping the write half sends a FIN whether or not `serve_lines` returns, so
    /// the test stays green if the writer's error is ignored. Those two properties
    /// are proven over a duplex pipe by
    /// `a_stopped_line_reader_ends_the_connection_after_the_write_deadline` and
    /// `a_client_that_floods_requests_and_never_reads_replies_is_disconnected`.
    ///
    /// Assumption: the kernel buffers along the loopback path hold well under
    /// 16 MiB between them, so the pushes overrun them. `LoopbackTcp::bind` does
    /// not let a test shrink the server's send buffer, so nothing here enforces it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopped_tcp_client_is_disconnected_by_the_write_deadline() {
        // The default sink capacity, so every one of the pushes is attempted.
        const LINES: usize = 4096;
        const PAD: usize = 4096;
        let server = server_with_deadline(Duration::from_secs(1));
        let listener = LoopbackTcp::bind(0, "tok".into(), None)
            .await
            .expect("bind 127.0.0.1:0");
        let addr = listener.local_addr();
        let serving = tokio::spawn(listener.serve(server.clone()));

        // The small receive buffer has to be set before connect to take effect.
        let socket = TcpSocket::new_v4().expect("a TCP socket");
        socket
            .set_recv_buffer_size(4096)
            .expect("shrink the receive buffer");
        let stream = socket.connect(addr).await.expect("connect to the listener");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        write_half
            .write_all(b"{\"token\":\"tok\"}\n")
            .await
            .expect("send the token line");
        write_half
            .write_all(subscribe_line().as_bytes())
            .await
            .expect("send flow.subscribe");
        let mut reply = String::new();
        reader
            .read_line(&mut reply)
            .await
            .expect("read the subscribe reply");
        assert_subscribed_reply(&reply);

        for seq in 0..LINES {
            push_padded(&server, seq as u64);
        }
        // Stop reading while the server fills the socket buffers, hits its 1 s
        // deadline, and gives the connection up.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut received = 0usize;
        let reached_eof = tokio::time::timeout(Duration::from_secs(15), async {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received += n,
                }
            }
        })
        .await;
        assert!(
            reached_eof.is_ok(),
            "the server closed the connection once its write deadline expired \
             (received {received} bytes, still open after 15 s)"
        );
        assert!(
            received < LINES * PAD,
            "the connection was cut before every pushed byte was delivered \
             (received {received} of {} bytes)",
            LINES * PAD
        );
        serving.abort();
    }

    // ---- Stage 5 tester additions: what a hostile client can put in `initialize`. ----

    /// A message with `method` and `params`, as JSON text.
    fn message(method: serde_json::Value, params: serde_json::Value) -> String {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            .to_string()
    }

    #[test]
    fn client_label_from_initialize_gives_no_label_for_malformed_messages() {
        let deep_array = "[".repeat(200_000);
        let deep_params = format!(r#"{{"method":"initialize","params":{deep_array}"#);
        let mut rows: Vec<(String, String)> = vec![
            ("empty".into(), String::new()),
            ("blank".into(), "  \n ".into()),
            ("not JSON".into(), "not json".into()),
            (
                "truncated object".into(),
                r#"{"method":"initialize""#.into(),
            ),
            ("null".into(), "null".into()),
            ("array".into(), "[]".into()),
            ("number".into(), "42".into()),
            ("string".into(), r#""initialize""#.into()),
            ("200k-deep array".into(), deep_array),
            ("200k-deep params".into(), deep_params),
            (
                "no method".into(),
                json!({"params": {"clientInfo": {"name": "x"}}}).to_string(),
            ),
        ];
        // The method must be exactly the string `initialize`.
        for method in [
            json!("tools/call"),
            json!("Initialize"),
            json!(" initialize"),
            json!(1),
            json!(null),
            json!(["initialize"]),
        ] {
            rows.push((
                format!("method {method}"),
                message(method, json!({"clientInfo": {"name": "x"}})),
            ));
        }
        // `params.clientInfo.name` must be a string.
        for (what, params) in [
            ("no params", json!(null)),
            ("array params", json!([{"clientInfo": {"name": "x"}}])),
            ("string params", json!("clientInfo")),
            ("no clientInfo", json!({})),
            ("null clientInfo", json!({"clientInfo": null})),
            ("string clientInfo", json!({"clientInfo": "x"})),
            ("array clientInfo", json!({"clientInfo": ["x"]})),
            ("no name", json!({"clientInfo": {}})),
            ("null name", json!({"clientInfo": {"name": null}})),
            ("number name", json!({"clientInfo": {"name": 7}})),
            ("bool name", json!({"clientInfo": {"name": true}})),
            ("array name", json!({"clientInfo": {"name": ["x"]}})),
            ("object name", json!({"clientInfo": {"name": {"a": "x"}}})),
        ] {
            rows.push((what.into(), message(json!("initialize"), params)));
        }
        let leaked: Vec<&str> = rows
            .iter()
            .filter(|(_, text)| client_label_from_initialize(text).is_some())
            .map(|(what, _)| what.as_str())
            .collect();
        assert!(leaked.is_empty(), "these gave a label: {leaked:?}");
    }

    #[test]
    fn client_label_from_initialize_cleans_a_hostile_name() {
        // Blank, invisible, and control-only names leave nothing to label with.
        for name in [
            "   ".to_string(),
            "\t\n".to_string(),
            "\u{200B}\u{FEFF}\u{202E}".to_string(),
            "\u{0}\u{7}\u{1b}".to_string(),
            "\u{200B}".repeat(1 << 20),
            "\u{0}".repeat(1 << 18),
        ] {
            assert_eq!(
                client_label_from_initialize(&initialize_with_name(&name)),
                None,
                "a name of {} chars made a label",
                name.chars().count()
            );
        }
        // Control characters go, a credential is masked, blanks are trimmed.
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("agent\u{0}-x token=abc123zz")),
            Some("agent-x token=[redacted]".to_string())
        );
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("  aitm-tui  ")),
            Some("aitm-tui".to_string())
        );
        // Dressing the reserved name up does not get it past the guard.
        assert_eq!(
            client_label_from_initialize(&initialize_with_name("WEB\u{200B} bridge")),
            Some("WEB bridge (declared)".to_string())
        );
        // JSON allows a name twice; the parser keeps the last, and the guard sees it.
        assert_eq!(
            client_label_from_initialize(
                r#"{"method":"initialize","params":{"clientInfo":{"name":"a","name":"web-bridge"}}}"#
            ),
            Some("web-bridge (declared)".to_string())
        );
    }
}
