//! The TLS-passthrough protocol module.
//!
//! `PassthroughModule` is a [`ProtocolModule`] that claims a connection whose
//! tunnel authority (`NextLayerHint::tunnel_authority`: the CONNECT line, else the
//! SNI) is on the shared [`PassthroughList`] **or not in Scope**, and tunnels it
//! byte-for-byte to the real upstream — **no TLS MITM**. The client completes its
//! TLS handshake directly against the origin's own certificate, so a pinned or
//! out-of-scope host is never decrypted and produces no editable HTTP flow.
//!
//! It must be registered **before** the HTTP module so it wins the acceptor's
//! `matches` race (wired in Task 14). An in-scope, unpinned host falls through to
//! the HTTP module and is MITM'd. Without a scope handle
//! ([`PassthroughModule::with_scope`]) nothing is in scope and every TLS/CONNECT
//! connection is tunnelled (deny-by-default, spec D2).
//!
//! A minimal "tunnelled" marker flow is recorded (host, byte counts, no body) so a
//! UI can show that the connection was passed through rather than decrypted.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Authority, Body, ByteStream, ConnInfo, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow,
    HttpRequest, HttpVersion, InterceptState, ModuleCtx, NextLayerHint, ProtocolModule,
    ScopeRateGuard, TunnelReason,
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
/// passthrough list **or not in Scope**, instead of decrypting it (spec D1/D2).
pub struct PassthroughModule {
    list: PassthroughList,
    /// The live scope guard. `None` means nothing is in scope: the module then
    /// claims every TLS/CONNECT connection (deny-by-default), so an embedding
    /// that forgot the handle tunnels everything rather than decrypting it.
    scope: Option<Arc<dyn ScopeRateGuard>>,
}

impl PassthroughModule {
    /// A module reading the same `Arc`-shared list the `tls.passthrough.*`
    /// commands mutate. Without [`with_scope`](Self::with_scope) it claims every
    /// TLS/CONNECT connection.
    pub fn new(list: PassthroughList) -> Self {
        Self { list, scope: None }
    }

    /// Attach the proxy's live scope guard (the one `scope.add` / `scope.remove`
    /// mutate), so only a pinned or out-of-scope authority is tunnelled and an
    /// in-scope one falls through to the HTTP module.
    pub fn with_scope(mut self, guard: Arc<dyn ScopeRateGuard>) -> Self {
        self.scope = Some(guard);
        self
    }

    /// Why this module claims `authority` (spec D5's `tunnel_reason`): `Pinned`
    /// when the host is on the passthrough list (pins win over Scope), else
    /// `OutOfScope`. Meaningful only for an authority [`matches`](ProtocolModule::matches)
    /// accepted.
    pub fn passthrough_reason(&self, authority: &Authority) -> TunnelReason {
        if self.list.contains_host(&authority.host) {
            TunnelReason::Pinned
        } else {
            TunnelReason::OutOfScope
        }
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

    /// Claim a connection whose tunnel authority (spec D1: the CONNECT line, else
    /// the SNI) is pinned **or not in Scope**. No tunnel authority (plain HTTP, an
    /// upgrade hand-off, TLS without SNI) is never claimed. No scope handle means
    /// nothing is in scope, so every TLS/CONNECT connection is claimed.
    fn matches(&self, hint: &NextLayerHint) -> bool {
        let Some(authority) = hint.tunnel_authority() else {
            return false;
        };
        self.list.contains_host(&authority.host)
            || !self
                .scope
                .as_ref()
                .is_some_and(|guard| guard.in_scope(&authority.to_string()))
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aitm_core::{Authority, ScopeEntry, ScopeRateGuard, StdGuard, TunnelReason};

    use super::*;

    fn guard_with(entries: &[&str]) -> Arc<dyn ScopeRateGuard> {
        let guard = StdGuard::default();
        for host in entries {
            guard.add_scope(ScopeEntry {
                host: (*host).to_string(),
            });
        }
        Arc::new(guard)
    }

    fn module(pinned: &[&str], scope: Option<&[&str]>) -> PassthroughModule {
        let list = PassthroughList::new(pinned.iter().map(|h| (*h).to_string()).collect());
        let module = PassthroughModule::new(list);
        match scope {
            Some(entries) => module.with_scope(guard_with(entries)),
            None => module,
        }
    }

    /// A proxied `CONNECT <authority>` connection as the acceptor peeks it.
    fn connect_hint(authority: &str) -> NextLayerHint {
        NextLayerHint {
            dst: "127.0.0.1:54321".parse().expect("peer addr"),
            is_tls: false,
            client_hello_sni: None,
            alpn: Vec::new(),
            first_bytes: format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
                .into_bytes(),
            from_upgrade: false,
            peer_identity: None,
            capture_interface: None,
        }
    }

    /// A raw TLS connection with `sni`, from a capture ingress when `capture` is
    /// set (then `dst` is the original destination) else the proxy path.
    fn sni_hint(sni: &str, dst: &str, capture: Option<&str>) -> NextLayerHint {
        NextLayerHint {
            dst: dst.parse().expect("dst addr"),
            is_tls: true,
            client_hello_sni: Some(sni.to_string()),
            alpn: Vec::new(),
            first_bytes: vec![0x16, 0x03, 0x01],
            from_upgrade: false,
            peer_identity: None,
            capture_interface: capture.map(str::to_string),
        }
    }

    /// AC7: pins win over Scope — a pinned host in Scope is still claimed, as `Pinned`.
    #[test]
    fn claims_pinned_host_even_when_in_scope() {
        let m = module(&["pinned.example"], Some(&["pinned.example"]));
        let hint = connect_hint("pinned.example:443");
        assert!(m.matches(&hint));
        assert_eq!(
            m.passthrough_reason(&Authority::new("pinned.example", 443)),
            TunnelReason::Pinned
        );
        // Also by SNI on the proxy path.
        assert!(m.matches(&sni_hint("pinned.example", "127.0.0.1:54321", None)));
    }

    /// D1/D2: a host that is not in Scope is tunnelled, as `OutOfScope`.
    #[test]
    fn claims_out_of_scope_host() {
        let m = module(&[], Some(&["scoped.example"]));
        assert!(m.matches(&connect_hint("unscoped.example:443")));
        assert!(m.matches(&sni_hint("unscoped.example", "127.0.0.1:54321", None)));
        assert_eq!(
            m.passthrough_reason(&Authority::new("unscoped.example", 443)),
            TunnelReason::OutOfScope
        );
    }

    /// An in-scope, unpinned host falls through to the HTTP module (decrypted).
    #[test]
    fn does_not_claim_in_scope_unpinned_host() {
        let m = module(&["pinned.example"], Some(&["scoped.example"]));
        assert!(!m.matches(&connect_hint("scoped.example:443")));
        assert!(!m.matches(&connect_hint("Scoped.EXAMPLE:8443")));
        assert!(!m.matches(&sni_hint("scoped.example", "127.0.0.1:54321", None)));
        assert!(!m.matches(&sni_hint(
            "scoped.example",
            "93.184.216.34:8443",
            Some("macos-ne")
        )));
    }

    /// AC14: no scope handle means nothing is in scope, so every TLS/CONNECT
    /// connection is claimed (a forgotten handle fails loudly, not by decrypting).
    /// A plain-HTTP connection has no tunnel authority and is never claimed.
    #[test]
    fn without_a_scope_handle_claims_every_tls_connection() {
        let m = module(&[], None);
        assert!(m.matches(&connect_hint("anything.example:443")));
        assert!(m.matches(&connect_hint("127.0.0.1:8443")));
        assert!(m.matches(&sni_hint("anything.example", "127.0.0.1:54321", None)));
        assert!(m.matches(&sni_hint(
            "anything.example",
            "93.184.216.34:443",
            Some("macos-ne")
        )));

        let mut plain = connect_hint("ignored.example:443");
        plain.first_bytes = b"GET / HTTP/1.1\r\nHost: ignored.example\r\n\r\n".to_vec();
        assert!(!m.matches(&plain), "plain HTTP is not a tunnel");
    }

    /// AC8: the decision follows `Authority::matches_scope_entry`: a bare host
    /// admits every port, `host:port` only that port, `*.suffix` the suffix and
    /// its subdomains, case-insensitively; an IPv6 CONNECT literal is normalised.
    #[test]
    fn matching_follows_scope_entry_rules() {
        let bare = module(&[], Some(&["example.com"]));
        assert!(!bare.matches(&connect_hint("example.com:8443")));
        assert!(!bare.matches(&connect_hint("EXAMPLE.com:443")));
        assert!(bare.matches(&connect_hint("notexample.com:443")));

        let ported = module(&[], Some(&["example.com:443"]));
        assert!(!ported.matches(&connect_hint("example.com:443")));
        assert!(ported.matches(&connect_hint("example.com:8443")));
        // The SNI default port is 443 on the proxy path, so a `:443` entry admits it…
        assert!(!ported.matches(&sni_hint("example.com", "127.0.0.1:54321", None)));
        // …while on the capture path the dst port decides.
        assert!(ported.matches(&sni_hint(
            "example.com",
            "93.184.216.34:8443",
            Some("macos-ne")
        )));

        let wild = module(&[], Some(&["*.example.com"]));
        assert!(!wild.matches(&connect_hint("api.example.com:443")));
        assert!(!wild.matches(&connect_hint("example.com:443")));
        assert!(wild.matches(&connect_hint("example.com.evil:443")));

        let v6 = module(&[], Some(&["::1"]));
        assert!(!v6.matches(&connect_hint("[::1]:443")));
        assert!(v6.matches(&connect_hint("[::2]:443")));
    }

    /// An upgrade hand-off (the HTTP module re-dispatching a decrypted connection
    /// after `101 Switching Protocols`) is never a tunnel of its own, so the
    /// passthrough module — first in module order — must not steal it from the WS
    /// module, whatever the scope says.
    #[test]
    fn does_not_claim_an_upgrade_handoff() {
        let m = module(&[], None);
        let mut handoff = sni_hint("ws.example", "127.0.0.1:54321", None);
        handoff.is_tls = false;
        handoff.first_bytes = Vec::new();
        handoff.from_upgrade = true;
        handoff.alpn = vec!["websocket".to_string()];
        assert!(!m.matches(&handoff));
    }
}
