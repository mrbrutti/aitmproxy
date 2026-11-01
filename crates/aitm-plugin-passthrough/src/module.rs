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
//! Every connection it claims is a **tunnel row** (spec D5) recorded through the
//! shared recorder in [`aitm_core::tunnel`]: a `CONNECT host:port` flow whose
//! `metadata.tunnel` is `passthrough` with reason `pinned` or `out_of_scope`,
//! carrying the `200 Connection Established` acknowledgement while the tunnel is
//! open and, once either side closes, its `duration` and exact `bytes_up` /
//! `bytes_down`. A resolve or dial failure is a `failed/upstream_unreachable` row
//! (no status, closed on insert) and the client is dropped without an
//! acknowledgement. The row's headers are the CONNECT head's; a captured
//! connection's attribution (`source_app`, `capture_interface`) is carried over.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    relay, Authority, ByteStream, ConnInfo, HeaderMap, ModuleCtx, NextLayerHint, ProtocolModule,
    ScopeRateGuard, TunnelInfo, TunnelReason, TunnelRequest, TunnelRow,
};
use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::list::PassthroughList;

/// Largest CONNECT head accepted before tunnelling (matches the HTTP module's cap).
const MAX_CONNECT_HEAD: usize = 16 * 1024;

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

    /// Open the upstream and copy bytes both ways with no TLS termination,
    /// recording the connection as one tunnel row (spec D5/D6: parse → dial →
    /// ack → row `passthrough` → relay → close with bytes and duration; a dial
    /// failure is a `failed/upstream_unreachable` row).
    async fn tunnel(&self, mut client: ByteStream, ctx: ModuleCtx) -> Result<()> {
        // The row's `created`, and what its `duration` is measured from.
        let opened_at = SystemTime::now();
        let hint = ctx.hint();
        let peer = hint
            .map(|h| h.dst)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let client_sni = hint.and_then(|h| h.client_hello_sni.clone());
        let source_app = hint.and_then(|h| h.peer_identity.clone());
        let capture_interface = hint.and_then(|h| h.capture_interface.clone());
        let is_connect = hint.is_some_and(|h| h.first_bytes.starts_with(b"CONNECT "));
        // The authority `matches` decided on (spec D1), when the peek held it.
        let hinted = hint.and_then(NextLayerHint::tunnel_authority);

        // Two ways in: a `CONNECT host:port` tunnel (read the head here so the
        // client's TLS that follows stays in the stream; acknowledge it once the
        // origin is up), or a raw TLS connection whose ClientHello SNI the acceptor
        // matched (nothing to read first, no headers).
        let (authority, headers) = if is_connect {
            let head = read_connect_head(&mut client).await?;
            let (line_authority, headers) = parse_connect(&head)?;
            let authority = match hinted {
                Some(authority) => authority,
                None => Authority::parse_with_default(&line_authority, 443)
                    .map_err(|e| anyhow!("passthrough: CONNECT authority: {e}"))?,
            };
            (authority, headers)
        } else {
            let authority = hinted
                .ok_or_else(|| anyhow!("passthrough: no CONNECT authority or SNI to tunnel"))?;
            (authority, HeaderMap::new())
        };

        let mut req = TunnelRequest {
            authority,
            headers,
            client: ConnInfo {
                peer,
                sni: client_sni,
                alpn: None,
                tls: true,
                established: opened_at,
            },
            server: None,
            opened_at,
            source_app,
            capture_interface,
        };

        let (dst, mut upstream) = match dial(&ctx, &req.authority).await {
            Ok(dialled) => dialled,
            Err(err) => {
                // AC6: the origin could not be reached — a visible failed row, not
                // silence. The row is closed on insert; the client is dropped with
                // no acknowledgement, exactly as before.
                TunnelRow::open(
                    &ctx,
                    req,
                    TunnelInfo::failed(TunnelReason::UpstreamUnreachable),
                )
                .await;
                return Err(err);
            }
        };

        // The upstream is open: acknowledge the CONNECT so the client starts TLS.
        if is_connect {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
        }

        req.server = Some(ConnInfo {
            peer: dst,
            sni: Some(req.authority.host.clone()),
            alpn: None,
            tls: true,
            established: SystemTime::now(),
        });
        let reason = self.passthrough_reason(&req.authority);
        let row = TunnelRow::open(&ctx, req, TunnelInfo::passthrough(reason)).await;

        // Byte-for-byte relay in both directions until either side closes. The
        // client's TLS terminates at the real upstream, so nothing here is
        // decrypted; the counts are exact even when the relay ends in an error.
        let (up, down, relayed) = relay(&mut client, &mut upstream).await;
        row.close(&ctx, Some((up, down))).await;
        relayed.map_err(Into::into)
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

/// Resolve `authority` and open the upstream through the connection's connector.
/// An IP literal is dialled as is (no lookup, so a loopback origin needs no
/// resolver); a name goes through the system resolver. Any failure here is the
/// row's `upstream_unreachable` (spec D5: DNS, refused, timed out, any I/O error).
async fn dial(ctx: &ModuleCtx, authority: &Authority) -> Result<(SocketAddr, ByteStream)> {
    let dst = match authority.ip() {
        Some(ip) => SocketAddr::new(ip, authority.port),
        None => tokio::net::lookup_host((authority.host.as_str(), authority.port))
            .await
            .with_context(|| format!("resolve {authority}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {authority}"))?,
    };
    let upstream = ctx
        .connect_upstream(&authority.to_string(), dst)
        .await
        .with_context(|| format!("passthrough connect to {authority}"))?;
    Ok((dst, upstream))
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

/// The authority (`host[:port]`) and the header lines of a `CONNECT host:port
/// HTTP/1.1` head. Headers keep their order and duplicates; they are recorded on
/// the tunnel row for display only (nothing here goes back on the wire), so a
/// line that is not a valid field — no colon, a control byte, a non-token name —
/// is left off the row rather than failing a tunnel that relays bytes regardless.
fn parse_connect(head: &[u8]) -> Result<(String, HeaderMap)> {
    let text = std::str::from_utf8(head).context("non-UTF-8 CONNECT head")?;
    let mut lines = text.lines();
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let authority = match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(authority)) if !authority.is_empty() => authority.to_string(),
        _ => return Err(anyhow!("malformed CONNECT line {line:?}")),
    };
    let mut headers = HeaderMap::new();
    for line in lines.filter(|l| !l.is_empty()) {
        if let Some((name, value)) = line.split_once(':') {
            // Untrusted wire input: `try_set` validates; an invalid field is not
            // worth refusing the tunnel over, so the `Err` is deliberately ignored.
            let _ = headers.try_set(name.trim(), value.trim());
        }
    }
    Ok((authority, headers))
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

    // ---- In-memory tunnel rows (spec D5/D6, AC1 unit half, AC6, AC7) ----------
    //
    // The sandbox cannot bind sockets, so the module is driven end to end over
    // `tokio::io::duplex` pairs: one pair is the client connection, the other is
    // the "origin" the connector hands back. Nothing resolves or dials.

    use std::sync::Mutex;

    use aitm_core::{
        Event, EventSink, Flow, FlowStore, HttpFlow, MemFlowStore, TunnelInfo, TunnelMode,
        UpstreamConnector, Verdict,
    };
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::task::JoinHandle;

    const CONNECT_HEAD: &str = "CONNECT 127.0.0.1:4443 HTTP/1.1\r\nHost: 127.0.0.1:4443\r\nProxy-Connection: keep-alive\r\n\r\n";
    const ACK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    const UP: &[u8] = b"hello-up";
    const DOWN: &[u8] = b"world-down";

    /// Records every event in order: the chain's role in these tests.
    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<Event>>,
    }

    impl RecordingSink {
        fn events(&self) -> Vec<Event> {
            self.events.lock().expect("sink lock").clone()
        }
    }

    impl EventSink for RecordingSink {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            Box::pin(async move {
                self.events.lock().expect("sink lock").push(ev);
                Verdict::Continue
            })
        }
    }

    /// Hands out the module's end of the origin duplex pair on the first dial
    /// (or refuses when it holds none) and records what the module asked for.
    struct DuplexConnector {
        origin: Mutex<Option<ByteStream>>,
        asked: Mutex<Option<(String, SocketAddr)>>,
    }

    impl DuplexConnector {
        fn asked(&self) -> Option<(String, SocketAddr)> {
            self.asked.lock().expect("asked lock").clone()
        }
    }

    impl UpstreamConnector for DuplexConnector {
        fn connect(&self, authority: &str, dst: SocketAddr) -> BoxFuture<'_, Result<ByteStream>> {
            *self.asked.lock().expect("asked lock") = Some((authority.to_string(), dst));
            let origin = self.origin.lock().expect("origin lock").take();
            Box::pin(async move { origin.ok_or_else(|| anyhow!("connection refused")) })
        }
    }

    struct Harness {
        store: Arc<MemFlowStore>,
        sink: Arc<RecordingSink>,
        connector: Arc<DuplexConnector>,
        task: JoinHandle<Result<()>>,
    }

    impl Harness {
        /// The one stored flow, as an `HttpFlow`.
        fn row(&self) -> HttpFlow {
            let ids = self.store.list();
            assert_eq!(ids.len(), 1, "exactly one row for the CONNECT, got {ids:?}");
            match self.store.get(ids[0]).expect("stored flow") {
                Flow::Http(h) => h,
                other => panic!("a tunnel row is an HTTP flow, got {other:?}"),
            }
        }

        /// Wait for `spawn` to return.
        async fn finish(&mut self) -> Result<()> {
            (&mut self.task).await.expect("module task panicked")
        }
    }

    /// Spawn the module on the module ends of two duplex pairs and return the
    /// test ends: the client connection and (when `dial_succeeds`) the origin.
    fn start(
        module: PassthroughModule,
        scope: Option<Arc<dyn ScopeRateGuard>>,
        hint: NextLayerHint,
        dial_succeeds: bool,
    ) -> (DuplexStream, Option<DuplexStream>, Harness) {
        let (client, module_client) = duplex(64 * 1024);
        let (origin, module_origin) = duplex(64 * 1024);
        let store = Arc::new(MemFlowStore::new());
        let sink = Arc::new(RecordingSink::default());
        let connector = Arc::new(DuplexConnector {
            origin: Mutex::new(dial_succeeds.then(|| Box::pin(module_origin) as ByteStream)),
            asked: Mutex::new(None),
        });
        let mut ctx =
            ModuleCtx::new(store.clone(), sink.clone(), connector.clone()).with_hint(hint);
        if let Some(guard) = scope {
            ctx = ctx.with_scope(guard);
        }
        let module = Arc::new(module);
        let task = tokio::spawn(async move {
            let io: ByteStream = Box::pin(module_client);
            module.spawn(io, ctx).await
        });
        (
            client,
            dial_succeeds.then_some(origin),
            Harness {
                store,
                sink,
                connector,
                task,
            },
        )
    }

    /// One complete passthrough exchange from both ends: the CONNECT head plus
    /// 8 payload bytes go in, the ack comes back, the payload reaches the origin,
    /// 10 bytes come back to the client, then both ends close. Returns the row as
    /// it looked while the tunnel was still open.
    async fn round_trip(
        mut client: DuplexStream,
        mut origin: DuplexStream,
        h: &Harness,
    ) -> HttpFlow {
        let mut head = CONNECT_HEAD.as_bytes().to_vec();
        head.extend_from_slice(UP);
        client.write_all(&head).await.expect("client writes");

        let mut ack = vec![0u8; ACK.len()];
        client
            .read_exact(&mut ack)
            .await
            .expect("the ack reaches the client");
        assert_eq!(ack, ACK);

        let mut up = vec![0u8; UP.len()];
        origin
            .read_exact(&mut up)
            .await
            .expect("client bytes reach the origin");
        assert_eq!(up, UP);

        origin.write_all(DOWN).await.expect("origin writes");
        let mut down = vec![0u8; DOWN.len()];
        client
            .read_exact(&mut down)
            .await
            .expect("origin bytes reach the client");
        assert_eq!(down, DOWN);

        // Bytes have moved, so the row was opened before the relay started.
        let open = h.row();
        drop(client);
        drop(origin);
        open
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:54321".parse().expect("peer addr")
    }

    fn origin_addr() -> SocketAddr {
        "127.0.0.1:4443".parse().expect("origin addr")
    }

    /// AC1 (unit half): an out-of-scope CONNECT is a `passthrough/out_of_scope`
    /// row through the shared recorder — 200 while open, exact byte counts and a
    /// duration once closed, no `tunnelled` mark, `RequestHeaders` then `Response`.
    #[tokio::test]
    async fn out_of_scope_connect_is_a_passthrough_row_with_exact_bytes() {
        let guard = guard_with(&["scoped.example"]);
        let module =
            PassthroughModule::new(PassthroughList::new(Vec::new())).with_scope(guard.clone());
        let (client, origin, mut h) =
            start(module, Some(guard), connect_hint("127.0.0.1:4443"), true);

        let open = round_trip(client, origin.expect("origin"), &h).await;
        assert_eq!(open.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(
            open.metadata.tunnel,
            Some(TunnelInfo::passthrough(TunnelReason::OutOfScope)),
            "an open passthrough row has no byte counts yet"
        );
        assert_eq!(open.metadata.duration, None, "open until both ends close");

        h.finish().await.expect("a clean close is not an error");

        let row = h.row();
        assert_eq!(row.request.method, "CONNECT");
        assert_eq!(row.request.scheme, "https");
        assert_eq!(row.request.authority, "127.0.0.1:4443");
        assert_eq!(row.request.path, "");
        assert_eq!(row.response.as_ref().map(|r| r.status), Some(200));
        assert_eq!(
            row.metadata.tunnel,
            Some(TunnelInfo {
                mode: TunnelMode::Passthrough,
                reason: Some(TunnelReason::OutOfScope),
                bytes_up: Some(UP.len() as u64),
                bytes_down: Some(DOWN.len() as u64),
            })
        );
        assert!(row.metadata.duration.is_some(), "closed: duration set");
        assert!(!row.metadata.passive);
        assert!(
            row.metadata.marks.is_empty(),
            "no `tunnelled` mark: the tunnel fields are the outcome"
        );
        assert_eq!(row.metadata.comment, None, "no byte-count comment");
        assert_eq!(row.metadata.source_app, None);
        assert_eq!(row.metadata.capture_interface, None);
        assert_eq!(row.client_conn.peer, peer());
        assert!(row.client_conn.tls);
        let server = row.server_conn.as_ref().expect("the dialled origin");
        assert_eq!(server.peer, origin_addr());
        assert_eq!(server.sni.as_deref(), Some("127.0.0.1"));
        assert!(server.tls);
        assert_eq!(
            h.connector.asked(),
            Some(("127.0.0.1:4443".to_string(), origin_addr())),
            "an IP literal is dialled without a lookup"
        );
        assert_eq!(
            h.sink.events(),
            vec![Event::RequestHeaders(row.id), Event::Response(row.id)]
        );
    }

    /// AC7: a host both pinned and in Scope is a passthrough row with reason `pinned`.
    #[tokio::test]
    async fn pinned_in_scope_connect_is_a_passthrough_row_with_reason_pinned() {
        let guard = guard_with(&["127.0.0.1"]);
        let module = PassthroughModule::new(PassthroughList::new(vec!["127.0.0.1".to_string()]))
            .with_scope(guard.clone());
        let (client, origin, mut h) =
            start(module, Some(guard), connect_hint("127.0.0.1:4443"), true);

        round_trip(client, origin.expect("origin"), &h).await;
        h.finish().await.expect("a clean close is not an error");

        let row = h.row();
        assert_eq!(
            row.metadata.tunnel,
            Some(TunnelInfo {
                mode: TunnelMode::Passthrough,
                reason: Some(TunnelReason::Pinned),
                bytes_up: Some(UP.len() as u64),
                bytes_down: Some(DOWN.len() as u64),
            })
        );
        assert_eq!(row.response.as_ref().map(|r| r.status), Some(200));
        assert!(row.metadata.duration.is_some());
    }

    /// AC6: a dial failure is a `failed/upstream_unreachable` row — no 200, no
    /// ack to the client, closed on insert — and `spawn` returns the error.
    #[tokio::test]
    async fn dial_failure_is_a_failed_upstream_unreachable_row() {
        let guard = guard_with(&[]);
        let module =
            PassthroughModule::new(PassthroughList::new(Vec::new())).with_scope(guard.clone());
        let (mut client, origin, mut h) =
            start(module, Some(guard), connect_hint("127.0.0.1:4443"), false);
        assert!(origin.is_none());

        client
            .write_all(CONNECT_HEAD.as_bytes())
            .await
            .expect("client writes");
        let err = h.finish().await.expect_err("a refused dial is an error");
        assert!(
            format!("{err:#}").contains("connection refused"),
            "the connector's error is returned unchanged: {err:#}"
        );

        // Nothing was acknowledged: the module dropped the client without writing.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.expect("client read");
        assert_eq!(
            rest, b"",
            "no 200 is written when the origin cannot be dialled"
        );

        let row = h.row();
        assert_eq!(row.request.method, "CONNECT");
        assert_eq!(row.request.authority, "127.0.0.1:4443");
        assert!(row.response.is_none(), "a failed tunnel has no status");
        assert_eq!(
            row.metadata.tunnel,
            Some(TunnelInfo::failed(TunnelReason::UpstreamUnreachable))
        );
        assert!(
            row.metadata.duration.is_some(),
            "failed rows are closed on insert"
        );
        assert!(row.server_conn.is_none(), "no origin was reached");
        assert_eq!(row.client_conn.peer, peer());
        assert_eq!(row.request.headers.get("host"), Some("127.0.0.1:4443"));
        assert_eq!(
            h.sink.events(),
            vec![Event::RequestHeaders(row.id), Event::Response(row.id)]
        );
    }

    /// The CONNECT head's header lines land on the row's request, in order.
    #[tokio::test]
    async fn connect_headers_land_on_the_row() {
        let guard = guard_with(&[]);
        let module =
            PassthroughModule::new(PassthroughList::new(Vec::new())).with_scope(guard.clone());
        let (client, origin, mut h) =
            start(module, Some(guard), connect_hint("127.0.0.1:4443"), true);

        round_trip(client, origin.expect("origin"), &h).await;
        h.finish().await.expect("a clean close is not an error");

        let headers = h.row().request.headers;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("host"), Some("127.0.0.1:4443"));
        assert_eq!(headers.get("Proxy-Connection"), Some("keep-alive"));
        assert_eq!(
            headers.iter().collect::<Vec<_>>(),
            vec![
                ("Host", "127.0.0.1:4443"),
                ("Proxy-Connection", "keep-alive")
            ]
        );
    }

    /// A captured connection's attribution (`peer_identity`, `capture_interface`)
    /// is carried onto the row, closing the ne-source-app follow-up.
    #[tokio::test]
    async fn captured_connect_carries_source_app_and_capture_interface() {
        let guard = guard_with(&[]);
        let module =
            PassthroughModule::new(PassthroughList::new(Vec::new())).with_scope(guard.clone());
        let mut hint = connect_hint("127.0.0.1:4443");
        hint.peer_identity = Some("com.apple.Safari".to_string());
        hint.capture_interface = Some("macos-ne".to_string());
        let (client, origin, mut h) = start(module, Some(guard), hint, true);

        round_trip(client, origin.expect("origin"), &h).await;
        h.finish().await.expect("a clean close is not an error");

        let row = h.row();
        assert_eq!(row.metadata.source_app.as_deref(), Some("com.apple.Safari"));
        assert_eq!(row.metadata.capture_interface.as_deref(), Some("macos-ne"));
        assert_eq!(
            row.metadata.tunnel,
            Some(TunnelInfo {
                mode: TunnelMode::Passthrough,
                reason: Some(TunnelReason::OutOfScope),
                bytes_up: Some(UP.len() as u64),
                bytes_down: Some(DOWN.len() as u64),
            })
        );
    }
}
