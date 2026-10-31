//! Transports: newline-delimited JSON-RPC over stdio, or over a loopback-only
//! TCP listener that requires a token on every connection. Both run the same
//! [`serve_lines`] loop; the TCP transport first consumes one auth line.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    // When the writer task ends — the socket closed, or `write_all` errored
    // because the client disconnected — close the sink. That unblocks a read loop
    // parked in `await_reply_capacity` (which would otherwise wait forever for a
    // writer that has gone) so the connection tears down cleanly.
    let writer_task = tokio::spawn({
        let sink = sink.clone();
        async move {
            let r = write_loop(writer, sink.clone()).await;
            sink.close();
            r
        }
    });

    let mut reader = reader.take(MAX_MESSAGE_BYTES as u64);
    let mut line = String::new();
    let outcome: anyhow::Result<()> = async {
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
    .await;

    // Teardown: drop this connection's subscriptions, then let the writer drain
    // what is queued and exit.
    server.drop_connection(conn.conn_id);
    sink.close();
    let _ = writer_task.await;
    outcome
}

/// Drain `sink` to `writer` until the sink is closed and empty. Each frame is a
/// complete JSON-RPC line; a trailing newline is appended per line.
async fn write_loop<W>(mut writer: W, sink: NotificationSink) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    loop {
        let frames = sink.drain();
        if !frames.is_empty() {
            for mut frame in frames {
                frame.push('\n');
                writer.write_all(frame.as_bytes()).await?;
            }
            writer.flush().await?;
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
}
