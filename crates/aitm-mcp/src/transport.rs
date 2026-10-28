//! Transports: newline-delimited JSON-RPC over stdio, or over a loopback-only
//! TCP listener that requires a token on every connection. Both run the same
//! [`serve_lines`] loop; the TCP transport first consumes one auth line.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use aitm_core::Frontend;
use serde_json::Value as JsonValue;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Take,
};
use tokio::net::{TcpListener, TcpStream};

use crate::server::{error_response, ConnCtx, McpServer, UNAUTHORIZED};

/// Longest single message (one line) a transport accepts. Longer lines end the
/// connection instead of growing a buffer without bound.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Serve newline-delimited JSON-RPC on one connection: each line in is one
/// message, each reply out is one line. Returns at EOF. Commands run on the
/// blocking pool so a slow tool cannot stall the runtime.
///
/// `conn` carries the connection's role (from its auth token, or `stdio_role`)
/// and, once an `initialize` arrives, its `clientInfo.name` label; every message
/// is dispatched through [`McpServer::handle_on`] with it.
pub async fn serve_lines<R, W>(
    server: Arc<McpServer>,
    reader: R,
    mut writer: W,
    mut conn: ConnCtx,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut reader = reader.take(MAX_MESSAGE_BYTES as u64);
    let mut line = String::new();
    while read_message(&mut reader, &mut line).await? {
        let message = line.trim().to_string();
        if message.is_empty() {
            continue;
        }
        // The client names itself once, in `initialize`; carry that label onto
        // the connection for audit (first one wins) without re-parsing later.
        if conn.client_label.is_none() {
            if let Some(label) = client_label_from_initialize(&message) {
                conn.client_label = Some(label);
            }
        }
        let srv = server.clone();
        let c = conn.clone();
        let reply = tokio::task::spawn_blocking(move || srv.handle_on(&c, &message)).await?;
        if let Some(mut reply) = reply {
            reply.push('\n');
            writer.write_all(reply.as_bytes()).await?;
            writer.flush().await?;
        }
    }
    Ok(())
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
}

impl LoopbackTcp {
    /// Bind `127.0.0.1:port` (`0` picks a free port). The agent token must be
    /// non-empty; the operator token (if any) is added with
    /// [`LoopbackTcp::with_operator_token`].
    pub async fn bind(port: u16, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !token.is_empty(),
            "the loopback TCP transport requires a non-empty token"
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            agent_token: token.into(),
            operator_token: None,
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
fn classify_token(line: &str, agent: &str, operator: Option<&str>) -> Option<Frontend> {
    let Ok(JsonValue::Object(obj)) = serde_json::from_str::<JsonValue>(line.trim()) else {
        return None;
    };
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
