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
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Take,
};
use tokio::net::{TcpListener, TcpStream};

use crate::server::{error_response, ConnCtx, McpServer, NotificationSink, UNAUTHORIZED};

/// Longest single message (one line) a transport accepts. Longer lines end the
/// connection instead of growing a buffer without bound.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Serve newline-delimited JSON-RPC on one connection: each line in is one
/// message, each reply out is one line. Returns at EOF. Commands run on the
/// blocking pool so a slow tool cannot stall the runtime.
///
/// The write half is owned by a dedicated writer task draining the connection's
/// bounded [`NotificationSink`] (F4): both request replies and server-initiated
/// `notifications/aitm/*` lines go through it, so writes are serialized per
/// connection and the read loop never blocks on a slow socket. The sink is the
/// `conn.out` the subscription registry pushes to; when the connection ends its
/// subscriptions are dropped and the writer drains and exits.
///
/// Each write the writer makes (one `write_all` per line, and the `flush`) runs
/// under [`McpServer::write_timeout`]. The clock stops when the writer has handed
/// the line to the socket, not when the peer reads it, so a slow reader that
/// keeps freeing room is never cut; a peer that stops reading with its buffers
/// full is. That alone would not end the connection, because the read loop sits
/// in `read_line` and a stopped but still-open peer never sends EOF. So if the
/// writer ends in an error (the deadline, or a failed write) before the read loop
/// ends, the read loop is abandoned: the connection's subscriptions are dropped,
/// the sink is closed, and the writer's error is returned. A writer that ends
/// cleanly, or a read loop that ends first, behaves as it always has: the
/// connection ends when the read loop does, and the writer is given the chance
/// to drain what is queued (still bounded by the deadline). A command already
/// running on the blocking pool when the loop is abandoned finishes, but its
/// reply is lost, as on any disconnect.
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
    // When the writer task ends — the socket closed, `write_all` errored because
    // the client disconnected, or a write hit its deadline — close the sink. That
    // unblocks a read loop parked in `await_reply_capacity` (which would
    // otherwise wait forever for a writer that has gone) so the connection tears
    // down cleanly.
    let write_timeout = server.write_timeout();
    let mut writer_task = tokio::spawn({
        let sink = sink.clone();
        async move {
            let r = write_loop(writer, sink.clone(), write_timeout).await;
            sink.close();
            r
        }
    });

    // Race the read loop against the writer. The lib's tokio build omits the
    // `macros` feature (as in `http.rs`), so there is no `select!`: the two
    // futures are polled by hand, the read loop first, so that if it has ended
    // (EOF, a read error) that ends the connection even if the writer ended in the
    // same instant. A `JoinHandle` must not be polled or awaited again once it has
    // completed, so `writer_joined` records that it has.
    let mut read = std::pin::pin!(read_loop(server.clone(), reader, conn, sink.clone()));
    let mut writer_joined = false;
    let outcome = std::future::poll_fn(|cx| {
        if let Poll::Ready(outcome) = read.as_mut().poll(cx) {
            return Poll::Ready(outcome);
        }
        if !writer_joined {
            if let Poll::Ready(joined) = Pin::new(&mut writer_task).poll(cx) {
                writer_joined = true;
                // A writer that failed ends the connection now. One that ended
                // cleanly leaves the read loop to end it, as before.
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Poll::Ready(Err(err)),
                    Err(join) => {
                        return Poll::Ready(Err(
                            anyhow::Error::new(join).context("the connection's writer task failed")
                        ))
                    }
                }
            }
        }
        Poll::Pending
    })
    .await;

    // Teardown: drop this connection's subscriptions, then let the writer drain
    // what is queued and exit.
    server.drop_connection(conn_id);
    sink.close();
    if !writer_joined {
        let _ = writer_task.await;
    }
    outcome
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
/// `write_all`, and the `flush` after a batch, must finish within
/// `write_timeout`; if one does not, the loop returns an error whose text starts
/// `write timed out after` and the connection is given up on (see
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
async fn within<T>(
    limit: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> anyhow::Result<T> {
    match tokio::time::timeout(limit, operation).await {
        Ok(result) => Ok(result?),
        Err(_) => anyhow::bail!("write timed out after {limit:?}"),
    }
}

/// The `initialize.clientInfo.name`, if `message` is an `initialize` request that
/// carries a non-empty name; `None` otherwise.
fn client_label_from_initialize(message: &str) -> Option<String> {
    let v: JsonValue = serde_json::from_str(message).ok()?;
    if v.get("method").and_then(JsonValue::as_str)? != "initialize" {
        return None;
    }
    let name = v.get("params")?.get("clientInfo")?.get("name")?.as_str()?;
    (!name.is_empty()).then(|| name.to_string())
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
/// class picks the connection's role: the required `agent_token` →
/// [`Frontend::Mcp`], the optional `operator_token` → [`Frontend::Operator`].
pub struct LoopbackTcp {
    listener: TcpListener,
    local_addr: SocketAddr,
    agent_token: Arc<str>,
    operator_token: Option<Arc<str>>,
    /// A rendezvous file to remove on drop; see [`LoopbackTcp::bind`].
    endpoint_file: Option<PathBuf>,
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
            agent_token: token.into(),
            operator_token: None,
            endpoint_file,
        })
    }

    /// Also accept an operator token; a connection presenting it is treated as
    /// [`Frontend::Operator`]. An empty token is ignored (no operator token).
    pub fn with_operator_token(mut self, token: Option<String>) -> Self {
        self.operator_token = token.filter(|t| !t.is_empty()).map(Into::into);
        self
    }

    /// The bound address (useful after binding port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accept connections forever, serving each on its own task.
    pub async fn serve(self, server: Arc<McpServer>) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            // The bind is loopback-only already; this is belt and braces.
            if !peer.ip().is_loopback() {
                continue;
            }
            let srv = server.clone();
            let agent = self.agent_token.clone();
            let operator = self.operator_token.clone();
            tokio::spawn(async move {
                // A failed connection is that client's problem, not the server's.
                let _ = serve_connection(srv, stream, &agent, operator.as_deref()).await;
            });
        }
    }
}

impl Drop for LoopbackTcp {
    /// Remove the rendezvous file, if any, so a bound address never outlives the
    /// listener. Idempotent — a missing file is fine.
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

async fn serve_connection(
    server: Arc<McpServer>,
    stream: TcpStream,
    agent_token: &str,
    operator_token: Option<&str>,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).take(MAX_MESSAGE_BYTES as u64);
    let mut first = String::new();
    if !read_message(&mut reader, &mut first).await? {
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
/// configured) wins and yields [`Frontend::Operator`], the agent token yields
/// [`Frontend::Mcp`], and anything else (malformed, or an unknown token) is
/// `None` — the caller refuses it `-32001`. Tokens are compared in constant time.
/// The object must carry exactly the `token` key (extra keys are rejected,
/// matching the web bridge's `token_line_matches`), so nothing can ride along
/// with the auth line.
fn classify_token(line: &str, agent: &str, operator: Option<&str>) -> Option<Frontend> {
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

    use aitm_core::{McpTransport, Registry};
    use serde_json::json;
    use tokio::io::{duplex, split, DuplexStream, Lines, ReadHalf, WriteHalf};
    use tokio::net::TcpSocket;
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
            classify_token(r#"{"token":"t"}"#, "t", None),
            Some(Frontend::Mcp)
        );
        assert_eq!(
            classify_token("  {\"token\":\"t\"}\r\n", "t", None),
            Some(Frontend::Mcp)
        );
        assert_eq!(classify_token(r#"{"token":"x"}"#, "t", None), None);
        assert_eq!(classify_token(r#"{"tok":"t"}"#, "t", None), None);
        assert_eq!(classify_token(r#"{"token":1}"#, "t", None), None);
        // Minor (b): exactly one key — a correct token can't smuggle extra keys.
        assert_eq!(classify_token(r#"{"token":"t","x":1}"#, "t", None), None);
        assert_eq!(
            classify_token(r#"{"token":"t","token2":"t"}"#, "t", None),
            None
        );
        assert_eq!(classify_token(r#"{}"#, "t", None), None);
        assert_eq!(classify_token(r#"["t"]"#, "t", None), None);
        assert_eq!(classify_token("t", "t", None), None);
        assert_eq!(
            classify_token(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                "t",
                None
            ),
            None
        );
    }

    #[test]
    fn classify_token_by_class() {
        // Operator token wins when it matches; the agent token is the fallback.
        assert_eq!(
            classify_token(r#"{"token":"op"}"#, "ag", Some("op")),
            Some(Frontend::Operator)
        );
        assert_eq!(
            classify_token(r#"{"token":"ag"}"#, "ag", Some("op")),
            Some(Frontend::Mcp)
        );
        assert_eq!(classify_token(r#"{"token":"no"}"#, "ag", Some("op")), None);
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

    /// The `sub_id` a successful `flow.subscribe` reply line carries.
    fn sub_id_in(reply: &str) -> u64 {
        let reply: JsonValue = serde_json::from_str(reply).expect("the reply is JSON");
        reply["result"]["structuredContent"]["sub_id"]
            .as_u64()
            .unwrap_or_else(|| panic!("the subscribe reply carries a sub_id: {reply}"))
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
    /// a pipe so small that a write blocks exactly like a stopped socket. The
    /// connection's push sink is injected, holding `capacity` notification lines.
    fn serve_over_tiny_pipe(server: &Arc<McpServer>, capacity: usize) -> LineClient {
        let (client, server_side) = duplex(256);
        let (server_read, server_write) = split(server_side);
        let sink = NotificationSink::new(capacity);
        let mut conn = ConnCtx::new(Frontend::Operator);
        conn.out = Some(sink.clone());
        let task = tokio::spawn(serve_lines(
            server.clone(),
            BufReader::new(server_read),
            server_write,
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
        /// Send `flow.subscribe {}`, read exactly one line, and return its `sub_id`.
        async fn subscribe(&mut self) -> u64 {
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
            sub_id_in(&reply)
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

    /// AC14: a client that subscribes and then neither reads nor closes cannot
    /// pin the connection. The writer's `write_all` stalls on the full pipe, the
    /// write deadline expires, and `serve_lines` returns that error instead of
    /// parking in `read_line` for a peer that never sends EOF; the subscriptions
    /// are dropped and the sink closed, so a later push queues nothing.
    #[tokio::test]
    async fn a_stopped_line_reader_ends_the_connection_after_the_write_deadline() {
        let server = server_with_deadline(Duration::from_millis(200));
        let mut client = serve_over_tiny_pipe(&server, 64);
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

    /// AC15: a reader that is slow but live (one line per 5 ms) frees room within
    /// the deadline every time, so it receives every pushed line, in order, and
    /// the connection is still up afterwards. It ends only when the client closes.
    #[tokio::test]
    async fn a_slow_line_reader_is_not_disconnected() {
        const PUSHES: u64 = 100;
        let server = server_with_deadline(Duration::from_millis(200));
        // The sink holds every push, so none is dropped as lag before it is read.
        let mut client = serve_over_tiny_pipe(&server, PUSHES as usize);
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
            tokio::time::sleep(Duration::from_millis(5)).await;
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

    /// Not in the plan's three: a writer that ends cleanly (here the sink is
    /// closed under it with nothing queued) does not end the connection. The read
    /// loop keeps serving until the client closes, as it did before the write
    /// deadline existed, and the finished writer's `JoinHandle` is not awaited a
    /// second time at teardown (which would panic the task).
    #[tokio::test]
    async fn a_writer_that_ends_cleanly_does_not_end_the_connection() {
        let server = server_with_deadline(Duration::from_millis(200));
        let client = serve_over_tiny_pipe(&server, 64);
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

    /// Added by the tester (spec D3, "each `write_all` and the `flush`"): the
    /// `flush` after a batch is under the write deadline too. The AC14 duplex test
    /// only reaches `write_all`; this one is the stdio shape, where `flush` is what
    /// waits on a parent that has stopped reading our stdout.
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

    /// Added by the tester: the stop AC14 does not cover, a client that keeps
    /// sending requests and never reads the replies. The writer stalls on the full
    /// pipe, replies pile up to the reply lane's high-water mark (4 here), so the
    /// read loop is normally held back by that backpressure rather than parked in
    /// `read_line` (the test does not assert which of the two it is in). The client
    /// never closes, so only the writer's failure can end the connection, and it
    /// must.
    #[tokio::test]
    async fn a_client_that_floods_requests_and_never_reads_replies_is_disconnected() {
        let server = server_with_deadline(Duration::from_millis(200));
        let (client, server_side) = duplex(256);
        let (server_read, server_write) = split(server_side);
        let sink = NotificationSink::with_limits(64, 4);
        let mut conn = ConnCtx::new(Frontend::Operator);
        conn.out = Some(sink.clone());
        let task = tokio::spawn(serve_lines(
            server.clone(),
            BufReader::new(server_read),
            server_write,
            conn,
        ));

        // Both client halves stay alive to the end, so the pipe never closes. The
        // flood is its own task: once the server stops reading, its writes block.
        let (client_read, mut client_write) = split(client);
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

    /// Added by the tester: a client that vanishes while the writer is blocked on a
    /// full pipe ends the connection at once through the I/O error, long before the
    /// write deadline (30 s here), and its subscription goes with it. This is the
    /// "connection drop mid-stream" case for the reworked `serve_lines` race, which
    /// must still treat a dead peer as the end whichever of the reader or the writer
    /// notices it first.
    #[tokio::test]
    async fn a_client_that_disconnects_mid_write_ends_the_connection_at_once() {
        let server = server_with_deadline(Duration::from_secs(30));
        let mut client = serve_over_tiny_pipe(&server, 64);
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

    /// AC16 (needs a real loopback socket): the same stop over TCP. The client's
    /// receive buffer is 4096 bytes, it sends the token and a `flow.subscribe`,
    /// reads the reply, and stops reading while the test pushes 16 MiB of state
    /// lines. Once the server's own buffers fill, the 1 s write deadline ends the
    /// connection, so on resuming the client reads what was buffered and then hits
    /// EOF, having received fewer bytes than were pushed.
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
        sub_id_in(&reply);

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
}
