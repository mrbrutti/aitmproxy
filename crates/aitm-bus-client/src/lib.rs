//! `aitm-bus-client` — the Rust client for the aitmproxy command bus.
//!
//! The bus is the MCP server in `aitm-mcp`: JSON-RPC 2.0, one JSON object per
//! line, methods `initialize`, `ping`, `tools/list`, `tools/call`. This crate is
//! what a Rust operator surface (the TUI today) talks through. It has two
//! transports behind one trait:
//!
//! - [`TcpTransport`] — the loopback TCP transport. The first line written is
//!   `{"token":"…"}`; a wrong token is answered with one `-32001` error and the
//!   socket closes. Replies are matched to requests by `id`; lines without an
//!   `id` are server notifications and go to a broadcast channel.
//! - [`InProcessTransport`] — a closure with the shape of `McpServer::handle`
//!   (`&str -> Option<String>`), for a surface that embeds the proxy. The
//!   closure runs on the blocking pool because a command may block.
//!
//! [`BusClient`] sits on top: it numbers requests, builds the JSON-RPC lines
//! and turns replies into typed values or a [`BusError`]. A tool result with
//! `isError: true` is [`BusError::Tool`] (the proxy treats a failing command as
//! a result, not a protocol failure); a JSON-RPC `error` is [`BusError::Rpc`].

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt as _, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

/// The MCP protocol revision this client speaks (what `aitm-mcp` serves).
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// How many unsolicited server lines are buffered for slow subscribers.
const NOTIFICATION_CAPACITY: usize = 256;

/// The longest reply line the TCP transport will buffer (64 MiB). A line that
/// grows past this closes the connection as gone instead of growing the
/// client's memory without bound; it is far above any real `flow.detail`
/// with an inline body.
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// A boxed, sendable future, as returned by [`BusTransport::send`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------- errors

/// Everything that can go wrong talking to the bus.
#[derive(Debug)]
pub enum BusError {
    /// The connection or handler failed: socket closed, write error, task died.
    Transport(anyhow::Error),
    /// The server answered with a JSON-RPC `error` object.
    Rpc {
        /// The JSON-RPC error code (`-32001` is the token refusal).
        code: i64,
        /// The server's message.
        message: String,
    },
    /// The tool ran and reported failure (`isError: true`); the text is its message.
    Tool(String),
    /// The server's reply did not have the shape the protocol promises.
    Protocol(String),
}

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusError::Transport(e) => write!(f, "bus transport error: {e:#}"),
            BusError::Rpc { code, message } => write!(f, "bus rpc error {code}: {message}"),
            BusError::Tool(m) => write!(f, "tool error: {m}"),
            BusError::Protocol(m) => write!(f, "bus protocol error: {m}"),
        }
    }
}

impl std::error::Error for BusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BusError::Transport(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for BusError {
    fn from(e: anyhow::Error) -> Self {
        BusError::Transport(e)
    }
}

// ------------------------------------------------------------- transport

/// One way of moving JSON-RPC lines to the server and back.
pub trait BusTransport: Send + Sync + 'static {
    /// Send one JSON-RPC line; `Ok(None)` when the server sends no reply (a notification).
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>>;
    /// Unsolicited server lines (F4 notifications), if the transport can deliver them.
    fn notifications(&self) -> Option<broadcast::Receiver<String>> {
        None
    }
}

/// Why no more replies will come on a TCP connection.
#[derive(Clone)]
enum Closed {
    /// The server refused the token: this is the error line it sent (id `null`),
    /// handed to every request so the caller sees `BusError::Rpc { -32001 }`.
    Refused(String),
    /// The server went away (EOF or read error).
    Gone(String),
}

/// Requests awaiting a reply, keyed by the JSON text of their `id`.
#[derive(Default)]
struct Pending {
    waiters: HashMap<String, oneshot::Sender<String>>,
    closed: Option<Closed>,
}

impl Pending {
    /// Mark the connection dead and wake every waiter. A refusal line is
    /// delivered as the reply; a plain close just drops the senders.
    fn close(&mut self, why: Closed) {
        if self.closed.is_none() {
            self.closed = Some(why.clone());
        }
        for (_, tx) in self.waiters.drain() {
            if let Closed::Refused(line) = &why {
                let _ = tx.send(line.clone());
            }
        }
    }
}

/// The loopback TCP transport: newline-delimited JSON-RPC behind a token line.
pub struct TcpTransport {
    writer: tokio::sync::Mutex<OwnedWriteHalf>,
    pending: Arc<Mutex<Pending>>,
    notify: broadcast::Sender<String>,
    reader: JoinHandle<()>,
}

impl TcpTransport {
    /// Connect to `addr`, write the token line, and start the reader task.
    ///
    /// The token is not verified here: the server only answers it when the first
    /// request arrives, so a wrong token surfaces as `BusError::Rpc { code: -32001 }`
    /// on that first request.
    pub async fn connect(addr: SocketAddr, token: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to the bus at {addr}"))?;
        stream.set_nodelay(true)?;
        let (read_half, mut write_half) = stream.into_split();

        let mut hello = json!({ "token": token }).to_string();
        hello.push('\n');
        write_half
            .write_all(hello.as_bytes())
            .await
            .context("writing the bus token line")?;
        write_half.flush().await?;

        let pending = Arc::new(Mutex::new(Pending::default()));
        let (notify, _) = broadcast::channel(NOTIFICATION_CAPACITY);
        let reader = tokio::spawn(read_loop(read_half, pending.clone(), notify.clone()));
        Ok(Self {
            writer: tokio::sync::Mutex::new(write_half),
            pending,
            notify,
            reader,
        })
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Pending> {
        // A poisoned lock means a panic elsewhere; the map is still usable.
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn send_line(&self, mut line: String) -> anyhow::Result<Option<String>> {
        let id = serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .filter(|id| !id.is_null())
            .map(|id| id.to_string());

        // Register the waiter before writing so a fast reply cannot slip past.
        let rx = {
            let mut pending = self.lock_pending();
            match &pending.closed {
                Some(Closed::Refused(reply)) => return Ok(Some(reply.clone())),
                Some(Closed::Gone(why)) => anyhow::bail!("bus connection closed: {why}"),
                None => {}
            }
            match &id {
                Some(id) => {
                    let (tx, rx) = oneshot::channel();
                    pending.waiters.insert(id.clone(), tx);
                    Some(rx)
                }
                None => None,
            }
        };

        line.push('\n');
        let written = async {
            let mut writer = self.writer.lock().await;
            writer.write_all(line.as_bytes()).await?;
            writer.flush().await?;
            anyhow::Ok(())
        }
        .await;
        let Some(rx) = rx else {
            return written.map(|()| None).map_err(|e| self.closed_error(e));
        };
        if let Err(e) = written {
            // A failed write means the socket is dead; the reader task sees the
            // same and either delivers the server's parting error line (token
            // refusal) to our waiter or drops it. Let it decide which.
            return match rx.await {
                Ok(reply) => Ok(Some(reply)),
                Err(_) => Err(self.closed_error(e.context("writing to the bus"))),
            };
        }
        match rx.await {
            Ok(reply) => Ok(Some(reply)),
            Err(_) => Err(self.closed_error(anyhow::anyhow!(
                "the bus connection closed before the reply arrived"
            ))),
        }
    }

    /// Prefer the recorded close reason over a generic I/O error. A refusal is
    /// still a transport-level failure here (the caller's waiter already got
    /// the refusal line if it was registered in time).
    fn closed_error(&self, fallback: anyhow::Error) -> anyhow::Error {
        match &self.lock_pending().closed {
            Some(Closed::Gone(why)) => anyhow::anyhow!("bus connection closed: {why}"),
            Some(Closed::Refused(_)) => anyhow::anyhow!("bus connection refused the token"),
            None => fallback,
        }
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl BusTransport for TcpTransport {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        Box::pin(self.send_line(line))
    }

    fn notifications(&self) -> Option<broadcast::Receiver<String>> {
        Some(self.notify.subscribe())
    }
}

/// Split the socket into lines and route each: a reply to its waiter, a
/// notification to subscribers, a `null`-id error (the token refusal) to every
/// waiter. On EOF, a read error, or a line over [`MAX_LINE_BYTES`] every
/// waiter is failed so nothing hangs.
async fn read_loop<R: AsyncRead + Unpin + Send + 'static>(
    read_half: R,
    pending: Arc<Mutex<Pending>>,
    notify: broadcast::Sender<String>,
) {
    // `take` caps how much one `read_until` may pull: a line that fills the
    // whole allowance without a newline is over the cap. The limit is reset
    // before every line.
    let allowance = MAX_LINE_BYTES as u64 + 1;
    let mut reader = BufReader::new(read_half).take(allowance);
    let mut buf: Vec<u8> = Vec::new();
    let why = loop {
        buf.clear();
        reader.set_limit(allowance);
        match reader.read_until(b'\n', &mut buf).await {
            Ok(0) => break "server closed the connection".to_string(),
            Ok(_) => {
                if buf.last() != Some(&b'\n') && buf.len() > MAX_LINE_BYTES {
                    break "reply line over 64 MiB".to_string();
                }
                // No trailing newline with room to spare is EOF mid-line: the
                // partial line is handled and the next read reports the close.
                let line = String::from_utf8_lossy(&buf).trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let parsed: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    // Not JSON at all: nothing to correlate; subscribers may still care.
                    Err(_) => {
                        let _ = notify.send(line);
                        continue;
                    }
                };
                let mut pending = pending.lock().unwrap_or_else(|e| e.into_inner());
                match parsed.get("id") {
                    None => {
                        let _ = notify.send(line);
                    }
                    Some(Value::Null) if parsed.get("error").is_some() => {
                        // The server only sends an id-less error when it is about
                        // to hang up (token refusal, parse error on the token line).
                        pending.close(Closed::Refused(line));
                    }
                    Some(id) => {
                        let key = id.to_string();
                        if let Some(tx) = pending.waiters.remove(&key) {
                            let _ = tx.send(line);
                        }
                        // A reply nobody waits for (cancelled request) is dropped.
                    }
                }
            }
            Err(e) => break format!("read error: {e}"),
        }
    };
    pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .close(Closed::Gone(why));
}

/// The handler shape of `McpServer::handle`: one line in, an optional reply out.
pub type InProcessHandler = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A transport that calls the server's line handler directly, on the blocking
/// pool, for a surface that runs the proxy in its own process.
pub struct InProcessTransport {
    handler: InProcessHandler,
}

impl InProcessTransport {
    /// Wrap a handler with the shape of `McpServer::handle`.
    pub fn new(handler: InProcessHandler) -> Self {
        Self { handler }
    }
}

impl BusTransport for InProcessTransport {
    fn send(&self, line: String) -> BoxFuture<'_, anyhow::Result<Option<String>>> {
        let handler = self.handler.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || handler(&line))
                .await
                .context("the in-process bus handler panicked or was cancelled")
        })
    }
}

// ---------------------------------------------------------------- client

/// What the server said about itself in `initialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// `serverInfo.name` (`aitmproxy`).
    pub name: String,
    /// `serverInfo.version`.
    pub version: String,
    /// The protocol revision the server agreed to.
    pub protocol_version: String,
}

/// One entry of `tools/list`: a bus command and the JSON Schema of its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDef {
    /// The command name (`flow.list`, …).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The `inputSchema` object.
    pub input_schema: Value,
}

impl ToolDef {
    /// Decode one `tools/list` entry. `name` is required; a missing
    /// `description` is empty and a missing `inputSchema` is `Null`.
    pub fn from_json(v: &Value) -> Result<Self, BusError> {
        Ok(Self {
            name: required_str(v, "name", "tool")?,
            description: v
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            input_schema: v.get("inputSchema").cloned().unwrap_or(Value::Null),
        })
    }
}

/// A JSON-RPC client over any [`BusTransport`].
pub struct BusClient {
    transport: Box<dyn BusTransport>,
    next_id: AtomicU64,
}

impl BusClient {
    /// Wrap a transport. Request ids start at 1.
    pub fn new(transport: Box<dyn BusTransport>) -> Self {
        Self {
            transport,
            next_id: AtomicU64::new(1),
        }
    }

    /// Unsolicited server lines, if the transport delivers them.
    pub fn notifications(&self) -> Option<broadcast::Receiver<String>> {
        self.transport.notifications()
    }

    /// The MCP handshake: `initialize`, then the `notifications/initialized` notice.
    pub async fn initialize(
        &self,
        client_name: &str,
        client_version: &str,
    ) -> Result<ServerInfo, BusError> {
        let result = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": client_name, "version": client_version},
                }),
            )
            .await?;
        let info = result
            .get("serverInfo")
            .ok_or_else(|| BusError::Protocol("initialize result has no serverInfo".into()))?;
        let server = ServerInfo {
            name: required_str(info, "name", "serverInfo")?,
            version: required_str(info, "version", "serverInfo")?,
            protocol_version: required_str(&result, "protocolVersion", "initialize result")?,
        };
        self.notify("notifications/initialized").await?;
        Ok(server)
    }

    /// `tools/list`: every command the bus exposes.
    pub async fn tools_list(&self) -> Result<Vec<ToolDef>, BusError> {
        let result = self.request("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| BusError::Protocol("tools/list result has no tools array".into()))?;
        tools.iter().map(ToolDef::from_json).collect()
    }

    /// `tools/call`. `Ok` is the `structuredContent` (or the first text content,
    /// parsed as JSON when it is JSON); `Err(BusError::Tool)` when the tool reports
    /// `isError: true`.
    pub async fn call(&self, name: &str, args: Value) -> Result<Value, BusError> {
        let result = self
            .request("tools/call", json!({"name": name, "arguments": args}))
            .await?;
        if !result.is_object() {
            return Err(BusError::Protocol(format!(
                "tools/call result is not an object: {result}"
            )));
        }
        let first_text = result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("text"))
            .and_then(Value::as_str);
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(BusError::Tool(
                first_text
                    .unwrap_or("tool failed without a message")
                    .to_string(),
            ));
        }
        if let Some(structured) = result.get("structuredContent") {
            return Ok(structured.clone());
        }
        match first_text {
            Some(text) => {
                Ok(serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string())))
            }
            None => Err(BusError::Protocol(
                "tools/call result has neither structuredContent nor text content".into(),
            )),
        }
    }

    /// `ping`: a liveness check; `Ok` when the server answers with a result object.
    pub async fn ping(&self) -> Result<(), BusError> {
        let result = self.request("ping", json!({})).await?;
        if result.is_object() {
            Ok(())
        } else {
            Err(BusError::Protocol(format!(
                "ping result is not an object: {result}"
            )))
        }
    }

    /// Send a request and return its `result`; a JSON-RPC error becomes
    /// [`BusError::Rpc`], anything malformed [`BusError::Protocol`].
    async fn request(&self, method: &str, params: Value) -> Result<Value, BusError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let reply = self
            .transport
            .send(line.to_string())
            .await?
            .ok_or_else(|| BusError::Protocol(format!("no reply to `{method}` (id {id})")))?;
        let reply: Value = serde_json::from_str(&reply)
            .map_err(|e| BusError::Protocol(format!("reply to `{method}` is not JSON: {e}")))?;
        if let Some(err) = reply.get("error") {
            return Err(BusError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or_default(),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
                    .to_string(),
            });
        }
        reply.get("result").cloned().ok_or_else(|| {
            BusError::Protocol(format!(
                "reply to `{method}` has neither result nor error: {reply}"
            ))
        })
    }

    /// Send a notification (no `id`, so no reply is expected).
    async fn notify(&self, method: &str) -> Result<(), BusError> {
        let line = json!({"jsonrpc": "2.0", "method": method});
        self.transport.send(line.to_string()).await?;
        Ok(())
    }
}

fn required_str(obj: &Value, key: &str, what: &str) -> Result<String, BusError> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| BusError::Protocol(format!("{what} has no string `{key}`")))
}

// ------------------------------------------------------------- token file

/// Read a bus token from a file (`--token-file`): surrounding whitespace is
/// trimmed and an empty token is an error.
pub fn read_token_file(path: &Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading the bus token file {}", path.display()))?;
    let token = raw.trim();
    anyhow::ensure!(
        !token.is_empty(),
        "the bus token file {} is empty",
        path.display()
    );
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q-4: one decoder for a `tools/list` entry, shared with the fixture
    /// loader: `name` required, the rest defaulted.
    #[test]
    fn a_tool_entry_decodes_with_defaults_and_needs_a_name() {
        let full = ToolDef::from_json(&json!({
            "name": "flow.get",
            "description": "Summarize one flow.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}
        }))
        .expect("a complete entry");
        assert_eq!(full.name, "flow.get");
        assert_eq!(full.description, "Summarize one flow.");
        assert_eq!(full.input_schema["required"], json!(["id"]));
        let bare = ToolDef::from_json(&json!({"name": "flow.list"})).expect("name alone");
        assert_eq!(
            bare,
            ToolDef {
                name: "flow.list".into(),
                description: String::new(),
                input_schema: Value::Null,
            }
        );
        let err = ToolDef::from_json(&json!({"description": "no name"})).unwrap_err();
        assert!(
            matches!(&err, BusError::Protocol(m) if m == "tool has no string `name`"),
            "{err}"
        );
    }

    /// Run `read_loop` over an in-memory pipe and return the close reason it
    /// recorded once the writer side is done.
    async fn close_reason_after(write: impl FnOnce(tokio::io::DuplexStream)) -> Option<Closed> {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let pending = Arc::new(Mutex::new(Pending::default()));
        let (notify, _) = broadcast::channel(4);
        let reader = tokio::spawn(read_loop(client_end, pending.clone(), notify));
        write(server_end);
        reader.await.expect("read_loop does not panic");
        let closed = pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closed
            .clone();
        closed
    }

    #[tokio::test]
    async fn a_line_over_the_cap_closes_the_connection_as_gone() {
        let closed = close_reason_after(|mut server| {
            tokio::spawn(async move {
                let chunk = vec![b'x'; 1024 * 1024];
                let mut left = MAX_LINE_BYTES + 1;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if server.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                }
                let _ = server.write_all(b"\n").await;
            });
        })
        .await;
        match closed {
            Some(Closed::Gone(why)) => assert_eq!(why, "reply line over 64 MiB"),
            Some(Closed::Refused(line)) => panic!("refused? {line}"),
            None => panic!("the connection was not closed"),
        }
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_cap_is_delivered() {
        let pending = Arc::new(Mutex::new(Pending::default()));
        let (tx, rx) = oneshot::channel();
        pending.lock().unwrap().waiters.insert("1".into(), tx);
        let (client_end, mut server_end) = tokio::io::duplex(64 * 1024);
        let (notify, _) = broadcast::channel(4);
        let reader = tokio::spawn(read_loop(client_end, pending.clone(), notify));
        let prefix = br#"{"jsonrpc":"2.0","id":1,"result":""#;
        let suffix = br#""}"#;
        let pad = MAX_LINE_BYTES - prefix.len() - suffix.len();
        tokio::spawn(async move {
            let _ = server_end.write_all(prefix).await;
            let chunk = vec![b'y'; 1024 * 1024];
            let mut left = pad;
            while left > 0 {
                let n = left.min(chunk.len());
                if server_end.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
            let _ = server_end.write_all(suffix).await;
            let _ = server_end.write_all(b"\n").await;
            // Dropping the writer is the server hanging up afterwards.
        });
        let reply = rx.await.expect("the capped line reaches its waiter");
        assert_eq!(reply.len(), MAX_LINE_BYTES);
        reader.await.expect("read_loop ends on EOF");
        assert!(matches!(
            pending.lock().unwrap().closed,
            Some(Closed::Gone(ref why)) if why == "server closed the connection"
        ));
    }
}
