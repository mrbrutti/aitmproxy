//! The TLS-passthrough protocol module.
//!
//! `PassthroughModule` is a [`ProtocolModule`] that claims a connection whose
//! SNI (or CONNECT authority) is on the shared [`PassthroughList`] and tunnels it
//! byte-for-byte to the real upstream — **no TLS MITM**. The client completes its
//! TLS handshake directly against the origin's own certificate, so a pinned host
//! is never decrypted and produces no editable HTTP flow.
//!
//! It must be registered **before** the HTTP module so it wins the acceptor's
//! `matches` race for a passthrough host (wired in Task 14). A non-passthrough
//! host falls through to the HTTP module and is still MITM'd.
//!
//! A minimal "tunnelled" marker flow is recorded (host, byte counts, no body) so a
//! UI can show that the connection was passed through rather than decrypted.

use std::net::SocketAddr;
use std::time::SystemTime;

use aitm_core::{
    Body, ByteStream, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpVersion, InterceptState, ModuleCtx, NextLayerHint, ProtocolModule,
};
use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};

use crate::list::PassthroughList;

/// Largest CONNECT head accepted before tunnelling (matches the HTTP module's cap).
const MAX_CONNECT_HEAD: usize = 16 * 1024;
/// Default TLS port when a passthrough authority carries no explicit port.
const DEFAULT_TLS_PORT: u16 = 443;

/// Tunnels a TLS connection byte-for-byte when its host is on the shared
/// passthrough list, instead of decrypting it.
pub struct PassthroughModule {
    list: PassthroughList,
}

impl PassthroughModule {
    /// A module reading the same `Arc`-shared list the `tls.passthrough.*`
    /// commands mutate.
    pub fn new(list: PassthroughList) -> Self {
        Self { list }
    }

    /// Open the upstream and copy bytes both ways with no TLS termination.
    async fn tunnel(&self, mut client: ByteStream, ctx: ModuleCtx) -> Result<()> {
        let hint = ctx.hint().cloned();
        let peer = hint
            .as_ref()
            .map(|h| h.dst)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let sni = hint.as_ref().and_then(|h| h.client_hello_sni.clone());
        let first = hint.map(|h| h.first_bytes).unwrap_or_default();

        // Two ways in: a `CONNECT host:port` tunnel (read and acknowledge the head
        // here, then the client's TLS flows through), or a raw TLS connection whose
        // ClientHello SNI the acceptor matched (nothing to read first).
        let authority = if first.starts_with(b"CONNECT ") {
            let head = read_connect_head(&mut client).await?;
            parse_connect(&head)?
        } else if let Some(sni) = &sni {
            format!("{sni}:{DEFAULT_TLS_PORT}")
        } else {
            return Err(anyhow!(
                "passthrough: no CONNECT authority or SNI to tunnel"
            ));
        };

        let (host, port) = split_host_port(&authority, DEFAULT_TLS_PORT)?;
        let dst = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;

        let mut upstream = ctx
            .connect_upstream(&authority, dst)
            .await
            .with_context(|| format!("passthrough connect to {authority}"))?;

        // The upstream is open: acknowledge the CONNECT so the client starts TLS.
        if first.starts_with(b"CONNECT ") {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
        }

        let id = self.record_tunnel(&ctx, &authority, &host, peer, dst, sni);

        // Byte-for-byte relay in both directions until either side closes. The
        // client's TLS terminates at the real upstream, so nothing here is decrypted.
        let copied = copy_bidirectional(&mut client, &mut upstream).await;
        let (up, down) = match &copied {
            Ok((up, down)) => (*up, *down),
            Err(_) => (0, 0),
        };
        ctx.store().update(id, &mut |f| {
            if let Flow::Http(h) = f {
                h.metadata.comment = Some(format!(
                    "tunnelled {host}: up={up} bytes, down={down} bytes"
                ));
            }
        });
        copied.map(|_| ()).map_err(Into::into)
    }

    /// Insert the minimal tunnel marker flow and return its id for the byte-count
    /// update once the relay finishes. It carries no decrypted request/response —
    /// only the host and connection facts — so a UI can show "tunnelled".
    fn record_tunnel(
        &self,
        ctx: &ModuleCtx,
        authority: &str,
        host: &str,
        peer: SocketAddr,
        dst: SocketAddr,
        sni: Option<String>,
    ) -> FlowId {
        let now = SystemTime::now();
        let id = FlowId::new();
        let flow = Flow::Http(HttpFlow {
            id,
            request: HttpRequest {
                method: "CONNECT".to_string(),
                scheme: "https".to_string(),
                authority: authority.to_string(),
                path: String::new(),
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Bytes(Vec::new()),
                timestamp: now,
            },
            response: None,
            client_conn: ConnInfo {
                peer,
                sni,
                alpn: None,
                tls: true,
                established: now,
            },
            server_conn: Some(ConnInfo {
                peer: dst,
                sni: Some(host.to_string()),
                alpn: None,
                tls: true,
                established: now,
            }),
            metadata: FlowMeta {
                marks: vec!["tunnelled".to_string()],
                ..FlowMeta::default()
            },
            intercept: InterceptState::Observed,
        });
        ctx.store().insert(flow)
    }
}

impl ProtocolModule for PassthroughModule {
    fn id(&self) -> &str {
        "passthrough"
    }

    fn matches(&self, hint: &NextLayerHint) -> bool {
        if let Some(sni) = hint.client_hello_sni.as_deref() {
            if self.list.contains_host(sni) {
                return true;
            }
        }
        if let Some(host) = connect_authority_host(&hint.first_bytes) {
            if self.list.contains_host(&host) {
                return true;
            }
        }
        false
    }

    fn spawn(&self, io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.tunnel(io, ctx))
    }
}

/// Read a CONNECT request head one byte at a time so the bytes that follow it (the
/// client's TLS ClientHello) stay unread in the stream for the byte tunnel.
async fn read_connect_head(client: &mut ByteStream) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Err(anyhow!("connection closed before the CONNECT head ended"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > MAX_CONNECT_HEAD {
            return Err(anyhow!("CONNECT head exceeded {MAX_CONNECT_HEAD} bytes"));
        }
    }
}

/// The authority (`host:port`) from a `CONNECT host:port HTTP/1.1` head.
fn parse_connect(head: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(head).context("non-UTF-8 CONNECT head")?;
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(authority)) if !authority.is_empty() => Ok(authority.to_string()),
        _ => Err(anyhow!("malformed CONNECT line {line:?}")),
    }
}

/// The host (no port) of the CONNECT authority in peeked `first_bytes`, if the
/// connection opens with a `CONNECT host:port` line. Lowercased for matching.
fn connect_authority_host(first_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(first_bytes).ok()?;
    let line = text.lines().next()?;
    let authority = line.strip_prefix("CONNECT ")?.split(' ').next()?;
    Some(host_of(authority))
}

/// The host portion of `host[:port]`, lowercased (IPv6 literals keep brackets off).
fn host_of(authority: &str) -> String {
    let (host, _) =
        split_host_port(authority.trim(), 0).unwrap_or((authority.trim().to_string(), 0));
    host.to_ascii_lowercase()
}

/// Split `host[:port]` (default `default_port`), handling bracketed IPv6 literals.
fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unterminated IPv6 literal {authority:?}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse()
                .with_context(|| format!("invalid port in {authority:?}"))?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => {
            let port = port
                .parse()
                .with_context(|| format!("invalid port in {authority:?}"))?;
            Ok((host.to_string(), port))
        }
        _ if authority.is_empty() => Err(anyhow!("empty authority")),
        _ => Ok((authority.to_string(), default_port)),
    }
}
