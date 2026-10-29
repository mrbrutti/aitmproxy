//! Transports: newline-delimited JSON-RPC over stdio, or over a loopback-only
//! TCP listener that requires a token on every connection. Both run the same
//! [`serve_lines`] loop; the TCP transport first consumes one auth line.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use serde_json::Value as JsonValue;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Take,
};
use tokio::net::{TcpListener, TcpStream};

use crate::server::{error_response, McpServer, UNAUTHORIZED};

/// Longest single message (one line) a transport accepts. Longer lines end the
/// connection instead of growing a buffer without bound.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Serve newline-delimited JSON-RPC: each line in is one message, each reply out
/// is one line. Returns at EOF. Commands run on the blocking pool so a slow
/// tool cannot stall the runtime.
pub async fn serve_lines<R, W>(
    server: Arc<McpServer>,
    reader: R,
    mut writer: W,
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
        let srv = server.clone();
        let reply = tokio::task::spawn_blocking(move || srv.handle(&message)).await?;
        if let Some(mut reply) = reply {
            reply.push('\n');
            writer.write_all(reply.as_bytes()).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

/// Serve over this process's stdin/stdout until stdin closes.
pub async fn serve_stdio(server: Arc<McpServer>) -> anyhow::Result<()> {
    serve_lines(
        server,
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    )
    .await
}

/// A loopback-only (127.0.0.1) listener. Every connection must send, as its
/// first line, a JSON object `{"token": "<token>"}` matching the configured
/// token; anything else is answered with one `unauthorized` error and closed.
pub struct LoopbackTcp {
    listener: TcpListener,
    local_addr: SocketAddr,
    token: Arc<str>,
    /// A rendezvous file to remove on drop; see [`LoopbackTcp::bind`].
    endpoint_file: Option<PathBuf>,
}

impl LoopbackTcp {
    /// Bind `127.0.0.1:port` (`0` picks a free port). The token must be non-empty.
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
            token: token.into(),
            endpoint_file,
        })
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
            let token = self.token.clone();
            tokio::spawn(async move {
                // A failed connection is that client's problem, not the server's.
                let _ = serve_connection(srv, stream, &token).await;
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
    token: &str,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).take(MAX_MESSAGE_BYTES as u64);
    let mut first = String::new();
    if !read_message(&mut reader, &mut first).await? {
        return Ok(());
    }
    if !authorized(&first, token) {
        let mut refusal = error_response(JsonValue::Null, UNAUTHORIZED, "unauthorized").to_string();
        refusal.push('\n');
        write_half.write_all(refusal.as_bytes()).await?;
        write_half.shutdown().await?;
        return Ok(());
    }
    serve_lines(server, reader.into_inner(), write_half).await
}

/// Whether `line` is `{"token": "<expected>"}`. Compared in constant time
/// relative to the expected token.
fn authorized(line: &str, expected: &str) -> bool {
    let Ok(JsonValue::Object(obj)) = serde_json::from_str::<JsonValue>(line.trim()) else {
        return false;
    };
    let Some(JsonValue::String(given)) = obj.get("token") else {
        return false;
    };
    token_matches(given, expected)
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

    #[test]
    fn token_compare() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abd", "abc"));
        assert!(!token_matches("ab", "abc"));
        assert!(!token_matches("abcd", "abc"));
        assert!(!token_matches("", "abc"));
    }

    #[test]
    fn auth_line_shapes() {
        assert!(authorized(r#"{"token":"t"}"#, "t"));
        assert!(authorized("  {\"token\":\"t\"}\r\n", "t"));
        assert!(!authorized(r#"{"token":"x"}"#, "t"));
        assert!(!authorized(r#"{"tok":"t"}"#, "t"));
        assert!(!authorized(r#"{"token":1}"#, "t"));
        assert!(!authorized(r#"["t"]"#, "t"));
        assert!(!authorized("t", "t"));
        assert!(!authorized(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            "t"
        ));
    }
}
