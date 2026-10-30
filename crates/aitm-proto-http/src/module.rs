//! The HTTP/1.1 protocol module: claims CONNECT, TLS and cleartext HTTP
//! connections, performs TLS MITM with leaves minted by the [`CertAuthority`],
//! drives the sans-IO machine, captures each exchange as an `HttpFlow`, emits
//! the request/response events through the plugin chain, and forwards the
//! (possibly mutated) request upstream (platform spec data-flow 1). After a
//! 101 it hands both streams to the module claiming the upgrade (data-flow 3).
//!
//! Request bodies are gathered before `Event::Request` fires, since plugins
//! mutate the complete request; response bodies stream to the client chunk by
//! chunk while a copy is captured into the flow.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskCx, Poll};
use std::time::SystemTime;

use aitm_core::{
    Body, CaConfig, ConnInfo, Event, Flow, FlowId, FlowMeta, HeaderMap, HttpFlow, HttpRequest,
    HttpResponse, HttpVersion, InterceptState, StreamBody,
};
use aitm_plugin::{ByteStream, ModuleCtx, NextLayerHint, ProtocolModule};
use anyhow::{anyhow, bail, Context as _, Result};
use futures::future::BoxFuture;
use futures::FutureExt as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use x509_parser::prelude::*;

use crate::ca::{CertAuthority, LeafCert};
use crate::sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};

/// First byte of a TLS handshake record.
const TLS_HANDSHAKE: u8 = 0x16;
/// Largest CONNECT head accepted.
const MAX_CONNECT_HEAD: usize = 16 * 1024;
/// Socket read size.
const READ_CHUNK: usize = 16 * 1024;

/// Per-read idle timeout. A single socket read may block at most this long, so a
/// slow client (slowloris) or a hung upstream cannot hold a connection open
/// indefinitely. It resets each read, so a legitimately slow large transfer that
/// keeps delivering chunks is unaffected.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// The bound on the TLS handshake to an origin, on the first connection
/// ([`HttpModule::mitm`]) and on a reconnect ([`Reconnect::connect`]) alike. The
/// TCP dial has its own bound; without this one, an origin that accepts the
/// connection and never answers the ClientHello would pin the task forever.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = READ_TIMEOUT;
/// Request-line prefixes that mark a cleartext HTTP connection.
const HTTP_METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
];

/// The HTTP/1.1 protocol module.
pub struct HttpModule {
    ca: OnceLock<Arc<CertAuthority>>,
    ca_config: CaConfig,
    provider: Arc<CryptoProvider>,
    /// Skip upstream certificate verification (lab self-signed targets). Off by
    /// default: upstream TLS is verified against the webpki roots.
    insecure: bool,
    /// Cap on a buffered request body and the captured copy of a response body.
    max_body_bytes: usize,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to an h2 client, bounding how
    /// many streams one connection may run in parallel.
    max_concurrent_streams: usize,
    /// How long the TLS handshake to an origin may take before it is abandoned
    /// (see [`TLS_HANDSHAKE_TIMEOUT`]).
    tls_handshake_timeout: std::time::Duration,
}

/// Default per-message body cap, matching `LimitConfig::default().max_body_bytes`.
const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Default cap on concurrent h2 streams per connection.
const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 128;

impl Default for HttpModule {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpModule {
    /// A module whose CA is loaded (or generated) from the default
    /// [`CaConfig`] on first TLS connection.
    pub fn new() -> Self {
        Self::with_ca_config(CaConfig::default())
    }

    /// A module whose CA is loaded (or generated) from `cfg` on first use.
    pub fn with_ca_config(cfg: CaConfig) -> Self {
        Self {
            ca: OnceLock::new(),
            ca_config: cfg,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            insecure: false,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
        }
    }

    /// Set the per-message body cap (maps to `LimitConfig.max_body_bytes`).
    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Set the per-connection concurrent-stream cap for h2 (maps to
    /// `LimitConfig.max_concurrent_streams`; wired to config in Task 5).
    pub fn with_max_concurrent_streams(mut self, max: usize) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// A module using an already-loaded CA.
    pub fn with_ca(ca: Arc<CertAuthority>) -> Self {
        let module = Self::new();
        // A fresh OnceLock cannot already be set.
        let _ = module.ca.set(ca);
        module
    }

    /// Skip upstream certificate verification when `insecure` is true (maps to
    /// `Config.ssl_insecure`; default false verifies against the webpki roots).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Bound the TLS handshake to an origin at `within` (default 30 s). Not yet
    /// wired to config.
    pub fn with_tls_handshake_timeout(mut self, within: std::time::Duration) -> Self {
        self.tls_handshake_timeout = within;
        self
    }

    /// The CA, loading it on first use.
    fn ca(&self) -> Result<Arc<CertAuthority>> {
        if let Some(ca) = self.ca.get() {
            return Ok(ca.clone());
        }
        let ca = Arc::new(CertAuthority::load_or_generate(
            &self.ca_config.dir,
            self.ca_config.key_mode,
        )?);
        Ok(self.ca.get_or_init(|| ca).clone())
    }

    /// The client config used towards upstream servers, built on first use.
    ///
    /// Upstream certificates are verified against the webpki root store by
    /// default (R3): a bad or self-signed upstream certificate fails the
    /// handshake, so the proxy never presents a trusted leaf for a server it
    /// could not itself authenticate. `Config.ssl_insecure` (via
    /// [`HttpModule::with_insecure`]) turns verification off for a lab of
    /// self-signed targets.
    fn upstream_tls_alpn(&self, offer: &[Vec<u8>]) -> Result<Arc<ClientConfig>> {
        let builder = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("upstream TLS versions")?;
        let mut cfg = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert {
                    provider: self.provider.clone(),
                }))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        // Offer upstream exactly what the client offered (the ALPN mirror, spec §1).
        cfg.alpn_protocols = offer.to_vec();
        Ok(Arc::new(cfg))
    }

    /// Run the TLS handshake to an origin over `io`, offering `alpn`, and give up
    /// after `tls_handshake_timeout`. The one place either upstream connection
    /// awaits an origin handshake, so both share its bound and its error text.
    /// `authority` (`host:port`) names the origin in the error. Dropping the
    /// timed-out handshake drops `io`, which closes the origin's socket.
    async fn tls_handshake<IO>(
        &self,
        alpn: &[Vec<u8>],
        server_name: ServerName<'static>,
        io: IO,
        authority: &str,
    ) -> Result<tokio_rustls::client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = TlsConnector::from(self.upstream_tls_alpn(alpn)?);
        match tokio::time::timeout(
            self.tls_handshake_timeout,
            connector.connect(server_name, io),
        )
        .await
        {
            Ok(handshake) => handshake.with_context(|| format!("TLS to upstream {authority}")),
            Err(_elapsed) => Err(anyhow!(
                "TLS to upstream {authority} timed out after {:?}",
                self.tls_handshake_timeout
            )),
        }
    }

    /// A server config presenting `leaf` to the client, offering only the
    /// protocol the upstream negotiated (`negotiated`), so the client lands on the
    /// same version as upstream (the ALPN mirror, spec §1).
    fn impersonating_config(
        &self,
        leaf: &LeafCert,
        negotiated: &[u8],
    ) -> Result<Arc<ServerConfig>> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("client-facing TLS versions")?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.cert_der.clone())], key)
            .context("client-facing TLS leaf")?;
        cfg.alpn_protocols = vec![negotiated.to_vec()];
        Ok(Arc::new(cfg))
    }

    /// Peek the first bytes and route: CONNECT tunnel (then TLS or cleartext
    /// inside it), raw TLS (SNI picks the upstream), or cleartext HTTP.
    async fn drive(&self, io: ByteStream, ctx: ModuleCtx) -> Result<()> {
        let peer = ctx.hint().map(|h| h.dst).unwrap_or_else(unknown_peer);
        let mut client = Prefixed::new(io);
        let first = client.peek(8).await?.to_vec();
        if first.starts_with(b"CONNECT ") {
            let head = client.read_head(MAX_CONNECT_HEAD).await?;
            let authority = parse_connect(&head)?;
            let target = Target::resolve(&authority, 443).await?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client.flush().await?;
            let next = client.peek(1).await?.to_vec();
            if next.first() == Some(&TLS_HANDSHAKE) {
                self.mitm(client, ctx, peer, Some(target)).await
            } else {
                let conn = Conn::plain(peer, Some(target.authority()));
                serve(
                    &ctx,
                    Box::pin(client),
                    None,
                    None,
                    conn,
                    self.max_body_bytes,
                )
                .await
            }
        } else if first.first() == Some(&TLS_HANDSHAKE) {
            self.mitm(client, ctx, peer, None).await
        } else {
            serve(
                &ctx,
                Box::pin(client),
                None,
                None,
                Conn::plain(peer, None),
                self.max_body_bytes,
            )
            .await
        }
    }

    /// TLS MITM: read the ClientHello (SNI), connect upstream over TLS, sniff
    /// its leaf's names, mint an impersonating leaf, finish the client
    /// handshake, then serve HTTP between the two decrypted streams.
    async fn mitm(
        &self,
        client: Prefixed<ByteStream>,
        ctx: ModuleCtx,
        peer: SocketAddr,
        target: Option<Target>,
    ) -> Result<()> {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client)
            .await
            .context("read ClientHello")?;
        let sni = start.client_hello().server_name().map(str::to_string);
        // The client's ALPN offer (an absent extension ⇒ assume `http/1.1`). We
        // offer upstream exactly this list and mirror whatever it negotiates.
        let client_alpn: Vec<Vec<u8>> = start
            .client_hello()
            .alpn()
            .map(|offers| offers.map(|p| p.to_vec()).collect())
            .unwrap_or_else(|| vec![b"http/1.1".to_vec()]);
        let target = match target {
            Some(t) => t,
            None => {
                let host = sni
                    .clone()
                    .ok_or_else(|| anyhow!("TLS without CONNECT or SNI: no upstream to pick"))?;
                Target::resolve(&host, 443).await?
            }
        };

        let tcp = ctx
            .connect_upstream(&target.authority(), target.addr)
            .await?;
        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|e| anyhow!("invalid upstream name {:?}: {e}", target.host))?;
        let upstream = self
            .tls_handshake(&client_alpn, server_name.clone(), tcp, &target.authority())
            .await?;
        // What upstream agreed to; mirror it down to the client (absent ⇒ h1).
        let negotiated: Vec<u8> = upstream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p.to_vec())
            .unwrap_or_else(|| b"http/1.1".to_vec());

        // Fail closed: an h1-only client cannot be mirrored to an h2-only upstream
        // (spec §1 edge case). The mirror offers upstream the client's list, so
        // this is only reachable defensively; log and drop rather than bridge.
        if negotiated == b"h2" && !client_alpn.iter().any(|p| p.as_slice() == b"h2") {
            tracing::warn!(
                authority = %target.authority(),
                "upstream negotiated h2 but the client cannot speak it; failing closed"
            );
            bail!(
                "cannot mirror h2 to an h1-only client for {}",
                target.authority()
            );
        }

        let sans = upstream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(cert_names)
            .unwrap_or_default();

        let leaf = self.ca()?.leaf_for(&target.host, &sans)?;
        let client_tls = start
            .into_stream(self.impersonating_config(&leaf, &negotiated)?)
            .await
            .context("client TLS handshake")?;

        let alpn = String::from_utf8_lossy(&negotiated).into_owned();
        let now = SystemTime::now();
        let conn = Conn {
            scheme: "https".to_string(),
            tunnel_authority: Some(target.authority()),
            client_conn: ConnInfo {
                peer,
                sni,
                alpn: Some(alpn.clone()),
                tls: true,
                established: now,
            },
            server_conn: Some(ConnInfo {
                peer: target.addr,
                sni: Some(target.host.clone()),
                alpn: Some(alpn),
                tls: true,
                established: now,
            }),
        };

        // Branch on the negotiated protocol: h2 runs the per-stream `serve_h2`
        // driver; everything else runs the h1 `serve` loop.
        if negotiated == b"h2" {
            // Unlike the h1 branch below, an h2 upstream gets no stale-connection
            // probe or reconnect. That is out of scope here; `serve_h2` has the
            // same exposure and is a follow-up.

            // A Map Remote rewrite to a different authority needs a SECOND upstream
            // (an h2 connection is pinned to one `:authority`, spec §6). The TLS
            // client config lives here (provider + insecure verifier), so hand
            // `serve_h2` an h2-ALPN config it can dial new origins with (Task 4).
            let upstream_h2_tls = self.upstream_tls_alpn(&[b"h2".to_vec()])?;
            crate::h2::serve_h2(
                ctx,
                Box::pin(client_tls),
                Box::pin(upstream),
                conn,
                self.max_body_bytes,
                self.max_concurrent_streams,
                upstream_h2_tls,
            )
            .await
        } else {
            // The h1 loop reuses this one upstream for the whole client connection,
            // so it needs a way to redo the TLS connection if the origin closes it
            // while the client idles. It reuses the address resolved above.
            let reconnect = Reconnect {
                module: self,
                authority: target.authority(),
                addr: target.addr,
                server_name,
            };
            serve(
                &ctx,
                Box::pin(client_tls),
                Some(Box::pin(upstream)),
                Some(reconnect),
                conn,
                self.max_body_bytes,
            )
            .await
        }
    }
}

impl ProtocolModule for HttpModule {
    fn id(&self) -> &str {
        "http"
    }

    fn matches(&self, hint: &NextLayerHint) -> bool {
        if hint.from_upgrade {
            return false;
        }
        hint.is_tls
            || hint.first_bytes.first() == Some(&TLS_HANDSHAKE)
            || looks_like_http(&hint.first_bytes)
    }

    fn spawn(&self, io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.drive(io, ctx))
    }
}

/// Whether the peeked bytes begin (or could begin) an HTTP request line.
fn looks_like_http(first: &[u8]) -> bool {
    if first.is_empty() {
        return false;
    }
    HTTP_METHODS.iter().any(|m| {
        let m = m.as_bytes();
        if first.len() >= m.len() {
            first.starts_with(m)
        } else {
            m.starts_with(first)
        }
    })
}

/// Per-connection facts every flow on it shares.
pub(crate) struct Conn {
    pub(crate) scheme: String,
    /// The CONNECT authority, when the connection is a tunnel.
    pub(crate) tunnel_authority: Option<String>,
    pub(crate) client_conn: ConnInfo,
    pub(crate) server_conn: Option<ConnInfo>,
}

impl Conn {
    fn plain(peer: SocketAddr, tunnel_authority: Option<String>) -> Self {
        Self {
            scheme: "http".to_string(),
            tunnel_authority,
            client_conn: ConnInfo {
                peer,
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            },
            server_conn: None,
        }
    }
}

/// Serve HTTP exchanges between `client` and `upstream` until either side
/// closes, or until a 101 hands both streams to the upgraded protocol's
/// module. With no `upstream` (cleartext forward proxy), one is opened for the
/// first request's authority and reopened when the authority changes.
///
/// An upstream the origin closed while the client idled is replaced before the
/// next request is forwarded on it, and so is one whose origin sent bytes after
/// a completed response (those bytes are discarded, never forwarded or parsed).
/// `reconnect` is how a TLS tunnel (which hands in an already-handshaken
/// `upstream`) redoes its TLS connection; the cleartext paths pass `None` and
/// redial through the ordinary connect step.
async fn serve(
    ctx: &ModuleCtx,
    mut client: ByteStream,
    mut upstream: Option<ByteStream>,
    reconnect: Option<Reconnect<'_>>,
    mut conn: Conn,
    max_body: usize,
) -> Result<()> {
    let mut machine = Http1Machine::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut current_authority: Option<String> = conn.tunnel_authority.clone();
    // Set when the origin sent bytes after a completed response. The framing of
    // that connection can no longer be trusted, so the next request must not
    // ride it; it is replaced through the same path as a closed upstream.
    let mut upstream_tainted = false;

    loop {
        // --- Request: gather head + body, emitting RequestHeaders as soon as
        // the head is in and inserting the flow.
        let mut flow_id: Option<FlowId> = None;
        let mut body: Vec<u8> = Vec::new();
        let mut request_oversized = false;
        let mut upgrade_protocol: Option<String> = None;
        let mut complete = false;
        // Start by draining anything already buffered (a pipelined request).
        let mut feed: Vec<u8> = Vec::new();
        loop {
            let events = machine.on_bytes(Side::Client, &feed)?;
            feed.clear();
            for ev in events {
                match ev {
                    HttpSansIoEvent::RequestHeaders(id) => {
                        let Some(head) = machine.request().cloned() else {
                            bail!("RequestHeaders without a parsed request");
                        };
                        let authority = if head.authority.is_empty() {
                            conn.tunnel_authority.clone().unwrap_or_default()
                        } else {
                            head.authority.clone()
                        };
                        let request = HttpRequest {
                            scheme: conn.scheme.clone(),
                            authority,
                            body: Body::Empty,
                            ..head
                        };
                        ctx.store().insert(Flow::Http(HttpFlow {
                            id,
                            request,
                            response: None,
                            client_conn: conn.client_conn.clone(),
                            server_conn: conn.server_conn.clone(),
                            metadata: FlowMeta::default(),
                            intercept: InterceptState::Observed,
                        }));
                        ctx.emit(Event::RequestHeaders(id)).await;
                        flow_id = Some(id);
                    }
                    HttpSansIoEvent::RequestBodyChunk { bytes, .. } => {
                        // Bound the buffered request: beyond the cap the bytes are
                        // dropped and the request is refused (not forwarded partial).
                        let room = max_body.saturating_sub(body.len());
                        if bytes.len() > room {
                            body.extend_from_slice(&bytes[..room]);
                            request_oversized = true;
                        } else {
                            body.extend_from_slice(&bytes);
                        }
                    }
                    HttpSansIoEvent::RequestComplete(id) => {
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
                        complete = true;
                    }
                    HttpSansIoEvent::Upgrade { protocol, .. } => {
                        upgrade_protocol = Some(protocol);
                    }
                    HttpSansIoEvent::ResponseHeaders(_)
                    | HttpSansIoEvent::ResponseBodyChunk { .. }
                    | HttpSansIoEvent::ResponseComplete(_) => {}
                }
            }
            if complete || request_oversized {
                // Stop reading the moment the body exceeds the cap: respond 413 and
                // close immediately rather than draining the rest of the request.
                break;
            }
            let n = match tokio::time::timeout(READ_TIMEOUT, client.read(&mut buf)).await {
                Ok(r) => r?,
                Err(_) => {
                    // Idle too long between bytes (slowloris): drop the connection.
                    let _ = client.shutdown().await;
                    return Ok(());
                }
            };
            if n == 0 {
                // Client finished (between requests, or gave up mid-request).
                return Ok(());
            }
            feed.extend_from_slice(&buf[..n]);
        }
        let id = flow_id.ok_or_else(|| anyhow!("request completed without headers"))?;

        // A request body over the cap is refused (413) rather than buffered or
        // forwarded truncated; the stored copy is marked truncated.
        if request_oversized {
            ctx.store().update(id, &mut |f: &mut Flow| {
                if let Flow::Http(h) = f {
                    h.metadata.truncated = true;
                }
            });
            let resp = oversized_response();
            machine.enqueue_response(&resp);
            flush(&mut machine, Side::Client, &mut client).await?;
            let _ = client.shutdown().await;
            return Ok(());
        }

        // --- Dispatch the complete request through the chain, then act on
        // what the plugins left in the store.
        ctx.emit(Event::Request(id)).await;
        let Some(Flow::Http(flow)) = ctx.store().get(id) else {
            bail!("flow {id} missing from the store after dispatch");
        };
        if matches!(flow.intercept, InterceptState::Killed) {
            // Killed: the client sees the connection drop.
            return Ok(());
        }
        let request = flow.request;
        let request_close = wants_close(&request.headers);

        if let Some(short_circuit) = flow.response {
            // A plugin answered without upstream.
            ctx.emit(Event::ResponseHeaders(id)).await;
            ctx.emit(Event::Response(id)).await;
            let response = match ctx.store().get(id) {
                Some(Flow::Http(f)) => f.response.unwrap_or(short_circuit),
                _ => short_circuit,
            };
            machine.enqueue_response(&response);
            flush(&mut machine, Side::Client, &mut client).await?;
            if request_close {
                let _ = client.shutdown().await;
                return Ok(());
            }
            // No upstream response ran, so the machine is still parked in
            // `Phase::Waiting`; ready it for the next request or the kept-alive
            // connection never parses one and its receive buffer grows uncapped.
            machine.short_circuit_done();
            continue;
        }

        // --- Make sure a live upstream connection exists for this authority.
        //
        // The origin may have closed a kept-alive upstream (its keep-alive
        // timeout) while this client connection sat idle. Nothing reads the
        // upstream between requests, so the first sign would be writing the
        // request to the dead socket and reading EOF, which fails the request
        // before any byte reaches the client. Probe once and replace a dead
        // connection before it is used. With a live upstream the probe is one
        // non-blocking readiness poll: no blocking I/O, no added latency. Not
        // covered: the origin closing in the instant between this probe and the
        // write below (retrying an idempotent, bodyless request would be a
        // separate change).
        //
        // A tainted upstream (the origin sent bytes after its last response, see
        // below) is replaced here too, never by clearing `upstream` where the
        // taint is found: in a TLS tunnel that would skip the `reconnect` arm and
        // the ordinary connect step below would dial the origin in cleartext.
        let mut redial: Option<String> = None;
        if upstream_tainted || upstream.as_mut().is_some_and(upstream_is_stale) {
            tracing::debug!(
                authority = current_authority.as_deref().unwrap_or_default(),
                "discarding an upstream connection that was closed or is no longer usable"
            );
            upstream = None;
            // Response bytes already read from the discarded connection must not
            // be glued onto the head of the replacement's response.
            let _ = machine.take_leftover(Side::Server);
            match &reconnect {
                // A TLS tunnel redoes its TLS connection to the same origin. A
                // failure surfaces as this request's error, like a failed first
                // connect.
                Some(reconnect) => {
                    upstream = Some(reconnect.connect(ctx).await?);
                    if let Some(previous) = conn.server_conn.clone() {
                        let replacement = ConnInfo {
                            established: SystemTime::now(),
                            ..previous
                        };
                        record_server_conn(ctx, &mut conn, id, replacement);
                    }
                }
                // Never fall back to cleartext for a connection that was TLS.
                None if conn.scheme == "https" => {
                    bail!("upstream TLS connection closed and cannot be re-established")
                }
                // A cleartext tunnel was opened to one origin: redial the origin
                // the replaced connection served, even if a later request in the
                // tunnel names a different Host.
                None if conn.tunnel_authority.is_some() => redial = current_authority.clone(),
                None => {}
            }
            upstream_tainted = false;
        }
        let needs_connect = match (&upstream, &conn.tunnel_authority, &current_authority) {
            (None, _, _) => true,
            (Some(_), None, Some(current)) => current != &request.authority,
            _ => false,
        };
        if needs_connect {
            // A new connection starts with an empty response buffer, whatever
            // made the old one go (an authority change, or the discard above).
            let _ = machine.take_leftover(Side::Server);
            let dial = redial.unwrap_or_else(|| request.authority.clone());
            let target = Target::resolve(&dial, 80).await?;
            upstream = Some(
                ctx.connect_upstream(&target.authority(), target.addr)
                    .await?,
            );
            current_authority = Some(dial);
            let server_conn = ConnInfo {
                peer: target.addr,
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            };
            record_server_conn(ctx, &mut conn, id, server_conn);
        }
        let Some(up) = upstream.as_mut() else {
            bail!("no upstream connection");
        };

        // --- Forward the (possibly mutated) request.
        machine.enqueue_request(&request);
        flush(&mut machine, Side::Server, up).await?;

        // --- Response: capture while streaming it back. The captured copy is
        // bounded by `max_body`; the client still receives the full stream.
        let mut captured: Vec<u8> = Vec::new();
        let mut response_truncated = false;
        let mut done = false;
        let mut response_close = false;
        // Set when a plugin replaced the streamed body with its own on
        // ResponseHeaders; upstream chunks are then captured but not forwarded.
        let mut forward_chunks = true;
        while !done {
            let n = match tokio::time::timeout(READ_TIMEOUT, up.read(&mut buf)).await {
                Ok(r) => r?,
                Err(_) => bail!("upstream read timed out"),
            };
            let events = if n == 0 {
                machine.on_eof(Side::Server)
            } else {
                machine.on_bytes(Side::Server, &buf[..n])?
            };
            for ev in events {
                match ev {
                    HttpSansIoEvent::ResponseHeaders(id) => {
                        let Some(head) = machine.response().cloned() else {
                            bail!("ResponseHeaders without a parsed response");
                        };
                        response_close =
                            wants_close(&head.headers) || close_delimited(&request.method, &head);
                        let streamed = HttpResponse {
                            body: Body::Streamed(StreamBody),
                            ..head
                        };
                        let mut staged = Some(streamed.clone());
                        ctx.store().update(id, &mut |f: &mut Flow| {
                            if let (Flow::Http(h), Some(r)) = (f, staged.take()) {
                                h.response = Some(r);
                            }
                        });
                        ctx.emit(Event::ResponseHeaders(id)).await;
                        let to_send = match ctx.store().get(id) {
                            Some(Flow::Http(f)) => f.response.unwrap_or(streamed),
                            _ => streamed,
                        };
                        forward_chunks = matches!(to_send.body, Body::Streamed(_));
                        machine.enqueue_response(&to_send);
                        flush(&mut machine, Side::Client, &mut client).await?;
                    }
                    HttpSansIoEvent::ResponseBodyChunk { bytes, .. } => {
                        let room = max_body.saturating_sub(captured.len());
                        if bytes.len() > room {
                            captured.extend_from_slice(&bytes[..room]);
                            response_truncated = true;
                        } else {
                            captured.extend_from_slice(&bytes);
                        }
                        if forward_chunks {
                            machine.enqueue_body_chunk(Side::Client, &bytes);
                            flush(&mut machine, Side::Client, &mut client).await?;
                        }
                    }
                    HttpSansIoEvent::ResponseComplete(id) => {
                        if forward_chunks {
                            machine.enqueue_body_end(Side::Client);
                            flush(&mut machine, Side::Client, &mut client).await?;
                        }
                        let mut bytes = Some(std::mem::take(&mut captured));
                        ctx.store().update(id, &mut |f: &mut Flow| {
                            if let (Flow::Http(h), Some(bytes)) = (f, bytes.take()) {
                                if let Some(resp) = h.response.as_mut() {
                                    resp.body = if bytes.is_empty() {
                                        Body::Empty
                                    } else {
                                        Body::Bytes(bytes)
                                    };
                                }
                                h.metadata.truncated |= response_truncated;
                                h.metadata.duration = h.metadata.created.elapsed().ok();
                            }
                        });
                        ctx.emit(Event::Response(id)).await;
                        done = true;
                    }
                    HttpSansIoEvent::RequestHeaders(_)
                    | HttpSansIoEvent::RequestBodyChunk { .. }
                    | HttpSansIoEvent::RequestComplete(_)
                    | HttpSansIoEvent::Upgrade { .. } => {}
                }
            }
            if n == 0 && !done {
                // Map the transport failure to the typed error bus before bailing.
                ctx.emit(Event::Error {
                    flow: id,
                    kind: aitm_core::FlowError::Upstream(
                        "upstream closed before completing the response".to_string(),
                    ),
                })
                .await;
                bail!("upstream closed before completing the response");
            }
        }

        if machine.is_upgraded() {
            // The connection now belongs to the upgraded protocol: hand both
            // streams (with any bytes already read past the 101) and the
            // handshake flow to the module that claims it.
            let protocol = upgrade_protocol.unwrap_or_else(|| "unknown".to_string());
            let Some(upstream_io) = upstream.take() else {
                bail!("upgraded without an upstream stream");
            };
            let client_rest = machine.take_leftover(Side::Client);
            let server_rest = machine.take_leftover(Side::Server);
            let hint = NextLayerHint {
                dst: conn.client_conn.peer,
                is_tls: conn.client_conn.tls,
                client_hello_sni: conn.client_conn.sni.clone(),
                alpn: vec![protocol],
                first_bytes: client_rest.clone(),
                from_upgrade: true,
            };
            let client_io: ByteStream = Box::pin(Prefixed::with_prefix(client, client_rest));
            let upstream_io: ByteStream = Box::pin(Prefixed::with_prefix(upstream_io, server_rest));
            return ctx.handoff_upgrade(client_io, upstream_io, id, hint).await;
        }
        // The response is complete and already forwarded. The machine parses no
        // response while no request awaits one, so whatever the origin sent
        // behind it is still in the machine's buffer, unparsed. Drop it (never
        // log it) and mark the connection tainted: those bytes are not an answer
        // to anything, and a partial head left in the buffer would otherwise be
        // glued onto the next response on this connection.
        let surplus = machine.take_leftover(Side::Server);
        if !surplus.is_empty() {
            tracing::warn!(
                authority = current_authority.as_deref().unwrap_or_default(),
                bytes = surplus.len(),
                "origin sent bytes after a completed response; discarding them and replacing the upstream connection"
            );
            upstream_tainted = true;
        }
        if request_close || response_close {
            let _ = client.shutdown().await;
            return Ok(());
        }
    }
}

/// Record `server_conn` as the connection serving the current request: on the
/// connection facts later flows on this client connection inherit, and on the
/// stored flow `id`. Used wherever the upstream connection is replaced, so every
/// replacement path reports the same metadata.
fn record_server_conn(ctx: &ModuleCtx, conn: &mut Conn, id: FlowId, server_conn: ConnInfo) {
    conn.server_conn = Some(server_conn.clone());
    ctx.store().update(id, &mut |f: &mut Flow| {
        if let Flow::Http(h) = f {
            h.server_conn = Some(server_conn.clone());
        }
    });
}

/// Whether an idle, kept-alive upstream connection can no longer be used.
///
/// Polls the stream for readability exactly once, without blocking. Between
/// requests an HTTP/1 connection has nothing to say, so `Pending` means it is
/// still open and quiet. Anything else means it is unusable: EOF (the origin
/// closed it), an error (reset, TLS alert), or unsolicited bytes, which could be
/// read as the answer to the next request and desynchronise the framing, so they
/// are not trusted. The one byte a probe may consume is irrelevant because an
/// unusable connection is discarded.
///
/// A single poll through `now_or_never`, whose waker does nothing, is sound
/// because `read` is cancel-safe and the future is dropped right after the
/// poll: a `Pending` result leaves the readiness state in the I/O driver (and
/// the TLS state in the stream), so the next real read re-checks it and
/// registers its own waker, and no wakeup can be lost. The poll is
/// `unconstrained` because tokio answers an I/O poll with `Pending` once the
/// task has spent its cooperative budget, even when the socket is ready, which
/// would pass for "quiet and open" and miss a stale upstream after a burst of
/// ready operations. This exempts only this one poll.
fn upstream_is_stale(up: &mut ByteStream) -> bool {
    let mut probe = [0u8; 1];
    tokio::task::coop::unconstrained(up.read(&mut probe))
        .now_or_never()
        .is_some()
}

/// How to re-establish the upstream TLS connection of an HTTP/1 MITM tunnel after
/// the origin closed it while the client idled. Built in [`HttpModule::mitm`],
/// which holds everything a TLS connection to the origin needs.
struct Reconnect<'a> {
    module: &'a HttpModule,
    /// `host:port` of the origin, for the connector's scope and SSRF check.
    authority: String,
    /// The address the first connection resolved to. Reused as is and never
    /// re-resolved, so a changed DNS answer cannot redirect the tunnel.
    addr: SocketAddr,
    server_name: ServerName<'static>,
}

impl Reconnect<'_> {
    /// Open a fresh TLS connection to the same origin. It goes through
    /// `ctx.connect_upstream` exactly as the first connection did, so the scope
    /// and SSRF guard applies again. Only `http/1.1` is offered, since the
    /// tunnel is already committed to HTTP/1; a server that answers with any
    /// other protocol fails the request rather than being bridged. The
    /// handshake is bounded by [`HttpModule::tls_handshake`]; a timeout fails the
    /// request like any handshake error, and nothing is dialled afterwards.
    async fn connect(&self, ctx: &ModuleCtx) -> Result<ByteStream> {
        let tcp = ctx.connect_upstream(&self.authority, self.addr).await?;
        let tls = self
            .module
            .tls_handshake(
                &[b"http/1.1".to_vec()],
                self.server_name.clone(),
                tcp,
                &self.authority,
            )
            .await?;
        // No ALPN at all is HTTP/1.1, as on the first connection.
        match tls.get_ref().1.alpn_protocol() {
            None | Some(b"http/1.1") => Ok(Box::pin(tls)),
            // rustls already refuses a protocol we did not offer, so with an
            // offer of only `http/1.1` this is unreachable today. It guards a
            // future widening of the offer: never bridge a protocol this HTTP/1
            // tunnel cannot speak.
            Some(other) => bail!(
                "upstream {} negotiated {:?} on reconnect, expected http/1.1",
                self.authority,
                String::from_utf8_lossy(other)
            ),
        }
    }
}

/// A `413 Payload Too Large` response for a request body over the cap.
fn oversized_response() -> HttpResponse {
    let mut headers = HeaderMap::new();
    headers.set("Content-Type", "text/plain");
    headers.set("Connection", "close");
    HttpResponse {
        status: 413,
        version: HttpVersion::Http11,
        headers,
        body: Body::Bytes(b"request body exceeds the configured limit".to_vec()),
        timestamp: SystemTime::now(),
    }
}

/// Write whatever the machine has queued for `to` onto `stream`.
async fn flush<S: AsyncWrite + Unpin>(
    machine: &mut Http1Machine,
    to: Side,
    stream: &mut S,
) -> Result<()> {
    if let Some(bytes) = machine.poll_outbound(to) {
        stream.write_all(&bytes).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// Whether a `Connection:` header asks to close after this exchange.
fn wants_close(headers: &aitm_core::HeaderMap) -> bool {
    headers
        .get("connection")
        .map(|c| c.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
        .unwrap_or(false)
}

/// Whether a response body runs to connection close (no length, no chunking,
/// and a status/method that carries a body).
fn close_delimited(method: &str, head: &HttpResponse) -> bool {
    if method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    if (100..200).contains(&head.status) || head.status == 204 || head.status == 304 {
        return false;
    }
    !head.headers.has("content-length") && !head.headers.has("transfer-encoding")
}

/// The CONNECT target `host:port` from a CONNECT head.
fn parse_connect(head: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(head).context("non-UTF-8 CONNECT head")?;
    let line = text.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(authority)) if !authority.is_empty() => Ok(authority.to_string()),
        _ => bail!("malformed CONNECT line {line:?}"),
    }
}

/// An upstream endpoint: the name the client asked for and where it resolves.
struct Target {
    host: String,
    port: u16,
    addr: SocketAddr,
}

impl Target {
    /// Split `host[:port]` (default `default_port`) and resolve it.
    async fn resolve(authority: &str, default_port: u16) -> Result<Self> {
        let (host, port) = split_host_port(authority, default_port)?;
        let addr = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolve {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;
        Ok(Self { host, port, addr })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Split `host[:port]`, including bracketed IPv6 literals.
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
        _ if authority.is_empty() => bail!("empty authority"),
        _ => Ok((authority.to_string(), default_port)),
    }
}

/// The placeholder peer when the acceptor attached no hint.
fn unknown_peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

/// DNS and IP subject alternative names of a certificate; the subject CN when
/// it has none.
fn cert_names(der: &CertificateDer<'_>) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(der.as_ref()) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => names.push((*dns).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Ok(v4) = <[u8; 4]>::try_from(*bytes) {
                        names.push(Ipv4Addr::from(v4).to_string());
                    } else if let Ok(v6) = <[u8; 16]>::try_from(*bytes) {
                        names.push(Ipv6Addr::from(v6).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    if names.is_empty() {
        if let Some(cn) = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
        {
            names.push(cn.to_string());
        }
    }
    names
}

/// Build the accept-any verifier (shared with the replay sender's insecure mode).
pub(crate) fn accept_any_verifier(provider: Arc<CryptoProvider>) -> Arc<dyn ServerCertVerifier> {
    Arc::new(AcceptAnyServerCert { provider })
}

/// Accepts whatever certificate an upstream presents. An intercepting proxy
/// must reach self-signed and internal targets; the presented leaf is still
/// sniffed for the names the impersonating leaf must carry. Signatures are
/// still verified, so the handshake itself is sound.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A stream with a replay buffer in front: lets the module peek at the first
/// bytes (and consume a CONNECT head) before handing the rest to a TLS
/// acceptor or the HTTP machine unchanged, and lets bytes already read past a
/// 101 travel with the stream into the next module.
struct Prefixed<S> {
    prefix: Vec<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> Prefixed<S> {
    fn new(inner: S) -> Self {
        Self::with_prefix(inner, Vec::new())
    }

    /// A stream that yields `prefix` before anything from `inner`.
    fn with_prefix(inner: S, prefix: Vec<u8>) -> Self {
        Self { prefix, inner }
    }

    /// Buffer at least `n` bytes (fewer only at EOF) and return the buffer.
    async fn peek(&mut self, n: usize) -> io::Result<&[u8]> {
        let mut tmp = [0u8; 1024];
        while self.prefix.len() < n {
            let k = self.inner.read(&mut tmp).await?;
            if k == 0 {
                break;
            }
            self.prefix.extend_from_slice(&tmp[..k]);
        }
        Ok(&self.prefix)
    }

    /// Consume and return one HTTP head, through its blank line.
    async fn read_head(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let mut tmp = [0u8; 1024];
        loop {
            if let Some(end) = self.prefix.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(self.prefix.drain(..end + 4).collect());
            }
            if self.prefix.len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP head too large",
                ));
            }
            let k = self.inner.read(&mut tmp).await?;
            if k == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.prefix.extend_from_slice(&tmp[..k]);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = buf.remaining().min(this.prefix.len());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    //! In-memory tests (no sockets) for the stale-upstream pieces: the liveness
    //! probe and the TLS reconnect. The end-to-end behaviour through a real proxy
    //! is in `tests/stale_upstream.rs`.

    use std::sync::Mutex;
    use std::time::Duration;

    use aitm_core::{MemFlowStore, Verdict};
    use aitm_plugin::{EventSink, UpstreamConnector};
    use tokio::io::{duplex, DuplexStream};
    use tokio_rustls::server::TlsStream as ServerTls;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    // ---- the liveness probe on a bare stream ------------------------------

    #[tokio::test]
    async fn probe_treats_a_quiet_open_stream_as_live() {
        let (ours, _peer) = duplex(64);
        let mut up: ByteStream = Box::pin(ours);
        assert!(!upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_treats_eof_as_stale() {
        let (ours, peer) = duplex(64);
        drop(peer);
        let mut up: ByteStream = Box::pin(ours);
        assert!(upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_treats_unsolicited_bytes_as_stale() {
        let (ours, mut peer) = duplex(64);
        peer.write_all(b"x").await.expect("peer write");
        let mut up: ByteStream = Box::pin(ours);
        assert!(upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_sees_a_closed_stream_even_when_the_task_budget_is_spent() {
        // Tokio makes an I/O poll report `Pending` once the task has used up its
        // cooperative budget, whether or not the socket is ready. After a burst of
        // ready operations the probe must not mistake that for "quiet and open".
        let (mut burner, mut feeder) = duplex(4096);
        feeder.write_all(&[0u8; 1024]).await.expect("feed");
        let (ours, peer) = duplex(64);
        drop(peer);
        let mut up: ByteStream = Box::pin(ours);

        // Spend the whole budget with ready reads, within this one poll.
        let mut byte = [0u8; 1];
        while tokio::task::coop::has_budget_remaining() {
            let _ = burner.read(&mut byte).now_or_never();
        }
        assert!(
            up.read(&mut byte).now_or_never().is_none(),
            "premise: a budget-constrained poll of a closed stream reports Pending"
        );

        assert!(upstream_is_stale(&mut up));
    }

    // ---- the liveness probe on a TLS session ------------------------------

    /// A server config for `origin.test` offering `alpn` in preference order.
    fn server_config(alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["origin.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let mut cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .expect("server config");
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(cfg)
    }

    /// A finished in-memory TLS connection: our client end as an upstream
    /// `ByteStream`, and the origin's end.
    async fn tls_pair() -> (ByteStream, ServerTls<DuplexStream>) {
        let (c, s) = duplex(64 * 1024);
        let client_cfg = HttpModule::new()
            .with_insecure(true)
            .upstream_tls_alpn(&[b"http/1.1".to_vec()])
            .expect("client config");
        let name = ServerName::try_from("origin.test").expect("name");
        let (client, server) = tokio::join!(
            TlsConnector::from(client_cfg).connect(name, c),
            TlsAcceptor::from(server_config(&[])).accept(s),
        );
        (
            Box::pin(client.expect("client handshake")),
            server.expect("server handshake"),
        )
    }

    #[tokio::test]
    async fn probe_treats_a_quiet_open_tls_session_as_live() {
        // Post-handshake records (TLS 1.3 session tickets) are consumed inside
        // the probe's read and must not read as "bytes from the origin".
        let (mut up, _server) = tls_pair().await;
        assert!(!upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_treats_a_tls_close_notify_as_stale() {
        let (mut up, mut server) = tls_pair().await;
        server.shutdown().await.expect("close_notify");
        assert!(upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_treats_a_tls_connection_dropped_without_close_notify_as_stale() {
        let (mut up, server) = tls_pair().await;
        drop(server);
        assert!(upstream_is_stale(&mut up));
    }

    #[tokio::test]
    async fn probe_treats_unsolicited_tls_data_as_stale() {
        let (mut up, mut server) = tls_pair().await;
        server.write_all(b"x").await.expect("origin write");
        server.flush().await.expect("origin flush");
        assert!(upstream_is_stale(&mut up));
    }

    // ---- the TLS reconnect ------------------------------------------------

    /// Every `(authority, address)` a connector was asked to dial, in order.
    type DialLog = Arc<Mutex<Vec<(String, SocketAddr)>>>;

    /// Records what it was asked to dial and hands out preset streams; with none
    /// left it refuses, as a scope or SSRF guard would.
    struct StubConnector {
        dialed: DialLog,
        streams: Mutex<Vec<ByteStream>>,
    }

    impl UpstreamConnector for StubConnector {
        fn connect(&self, authority: &str, dst: SocketAddr) -> BoxFuture<'_, Result<ByteStream>> {
            self.dialed
                .lock()
                .expect("dialed lock")
                .push((authority.to_string(), dst));
            let next = {
                let mut streams = self.streams.lock().expect("streams lock");
                (!streams.is_empty()).then(|| streams.remove(0))
            };
            Box::pin(async move { next.ok_or_else(|| anyhow!("scope guard refused the dial")) })
        }
    }

    struct NoSink;

    impl EventSink for NoSink {
        fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
            Box::pin(async { Verdict::Continue })
        }
    }

    /// A context whose connector is a [`StubConnector`] holding `streams`, plus
    /// the log of what it was asked to dial.
    fn ctx_with(streams: Vec<ByteStream>) -> (ModuleCtx, DialLog) {
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let connector = StubConnector {
            dialed: dialed.clone(),
            streams: Mutex::new(streams),
        };
        let ctx = ModuleCtx::new(
            Arc::new(MemFlowStore::new()),
            Arc::new(NoSink),
            Arc::new(connector),
        );
        (ctx, dialed)
    }

    /// Records every event the module emits, in order, and lets it continue.
    struct RecordingSink {
        events: Mutex<Vec<Event>>,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            self.events.lock().expect("events lock").push(ev);
            Box::pin(async { Verdict::Continue })
        }
    }

    /// Like [`ctx_with`], with a [`RecordingSink`] as the event sink.
    fn ctx_recording(streams: Vec<ByteStream>) -> (ModuleCtx, DialLog, Arc<RecordingSink>) {
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let connector = StubConnector {
            dialed: dialed.clone(),
            streams: Mutex::new(streams),
        };
        let sink = Arc::new(RecordingSink {
            events: Mutex::new(Vec::new()),
        });
        let ctx = ModuleCtx::new(
            Arc::new(MemFlowStore::new()),
            sink.clone(),
            Arc::new(connector),
        );
        (ctx, dialed, sink)
    }

    fn origin_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 8443)
    }

    fn reconnect_to(module: &HttpModule) -> Reconnect<'_> {
        Reconnect {
            module,
            authority: "origin.test:8443".to_string(),
            addr: origin_addr(),
            server_name: ServerName::try_from("origin.test").expect("name"),
        }
    }

    #[tokio::test]
    async fn reconnect_dials_the_recorded_origin_through_the_connector_offering_only_http11() {
        let (c, s) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(c)]);
        let module = HttpModule::new().with_insecure(true);
        let reconnect = reconnect_to(&module);
        // An origin that would pick h2 if it were offered.
        let acceptor = TlsAcceptor::from(server_config(&[b"h2", b"http/1.1"]));

        let (up, server) = tokio::join!(reconnect.connect(&ctx), acceptor.accept(s));
        let mut up = up.expect("reconnect");
        let mut server = server.expect("origin handshake");

        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "the dial must go through the connector with the recorded authority and address"
        );
        assert_eq!(
            server.get_ref().1.alpn_protocol(),
            Some(&b"http/1.1"[..]),
            "only http/1.1 may be offered on a reconnect"
        );
        // The returned stream is the live TLS connection to the origin.
        up.write_all(b"ping").await.expect("write");
        up.flush().await.expect("flush");
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.expect("origin read");
        assert_eq!(&got, b"ping");
    }

    #[tokio::test]
    async fn reconnect_surfaces_a_connector_refusal() {
        let (ctx, dialed) = ctx_with(Vec::new());
        let module = HttpModule::new().with_insecure(true);
        let err = reconnect_to(&module)
            .connect(&ctx)
            .await
            .err()
            .expect("a refused dial must fail the reconnect");
        assert_eq!(err.to_string(), "scope guard refused the dial");
        assert_eq!(
            dialed.lock().expect("dialed lock").len(),
            1,
            "the refusal came from the connector, not from skipping it"
        );
    }

    // ---- the bounded upstream TLS handshake -------------------------------

    /// The bound the stall tests give the handshake.
    const SHORT_BOUND: Duration = Duration::from_millis(50);

    /// The most a stall test waits for the bounded call to return. An unbounded
    /// handshake blows through it, so it fails the test instead of hanging it.
    const STALL_GUARD: Duration = Duration::from_secs(5);

    /// A module that gives up on an origin's handshake after [`SHORT_BOUND`].
    fn short_bound_module() -> HttpModule {
        HttpModule::new()
            .with_insecure(true)
            .with_tls_handshake_timeout(SHORT_BOUND)
    }

    /// An origin that accepted the TCP connection and will never speak: our end
    /// boxed as an upstream stream, and the origin's end. The caller must hold
    /// the origin's end for the whole test; dropping it would be an EOF, not a
    /// stall.
    fn stalled_pair() -> (ByteStream, DuplexStream) {
        let (ours, origin) = duplex(64 * 1024);
        (Box::pin(ours), origin)
    }

    #[tokio::test]
    async fn tls_handshake_gives_up_on_an_origin_that_never_answers() {
        let (io, _origin) = stalled_pair();
        let module = short_bound_module();

        let result = tokio::time::timeout(
            STALL_GUARD,
            module.tls_handshake(
                &[b"http/1.1".to_vec()],
                ServerName::try_from("origin.test").expect("name"),
                io,
                "origin.test:8443",
            ),
        )
        .await
        .expect("the handshake was never bounded");

        let err = result
            .err()
            .expect("a stalled handshake must fail, not succeed");
        assert_eq!(
            err.to_string(),
            "TLS to upstream origin.test:8443 timed out after 50ms"
        );
    }

    #[tokio::test]
    async fn tls_handshake_failure_keeps_its_context() {
        let (io, origin) = stalled_pair();
        // The origin hung up before the handshake: a prompt failure, not a stall.
        drop(origin);
        let module = HttpModule::new().with_insecure(true);

        let result = tokio::time::timeout(
            STALL_GUARD,
            module.tls_handshake(
                &[b"http/1.1".to_vec()],
                ServerName::try_from("origin.test").expect("name"),
                io,
                "origin.test:8443",
            ),
        )
        .await
        .expect("a handshake against a closed peer must fail promptly");

        let err = result
            .err()
            .expect("a handshake against a closed peer must fail");
        assert_eq!(err.to_string(), "TLS to upstream origin.test:8443");
    }

    #[tokio::test]
    async fn tls_handshake_succeeds_against_a_live_origin() {
        let (c, s) = duplex(64 * 1024);
        let module = HttpModule::new().with_insecure(true);
        // An origin that would pick h2 if it were offered.
        let acceptor = TlsAcceptor::from(server_config(&[b"h2", b"http/1.1"]));
        let offer = [b"http/1.1".to_vec()];

        let (client, server) = tokio::join!(
            module.tls_handshake(
                &offer,
                ServerName::try_from("origin.test").expect("name"),
                c,
                "origin.test:8443",
            ),
            acceptor.accept(s),
        );

        let client = client.expect("client handshake");
        let server = server.expect("origin handshake");
        // The offer reached the connector: only http/1.1 was on the table.
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        assert_eq!(server.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    }

    #[test]
    fn a_new_module_bounds_the_upstream_handshake_at_the_read_timeout() {
        let module = HttpModule::new();
        assert_eq!(module.tls_handshake_timeout, READ_TIMEOUT);
        assert_eq!(module.tls_handshake_timeout, Duration::from_secs(30));
        // The other constructors share the default.
        assert_eq!(
            HttpModule::with_ca_config(CaConfig::default()).tls_handshake_timeout,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn mitm_gives_up_on_an_origin_that_stalls_the_upstream_handshake() {
        let (stalled, _origin) = stalled_pair();
        let (ctx, dialed) = ctx_with(vec![stalled]);
        let module = short_bound_module();

        // A real client handshake, so the proxy side reads a real ClientHello.
        let (client_end, proxy_side) = duplex(64 * 1024);
        let client_cfg = HttpModule::new()
            .with_insecure(true)
            .upstream_tls_alpn(&[b"http/1.1".to_vec()])
            .expect("client config");
        let _client = tokio::spawn(async move {
            // It ends in an error once the proxy gives up and drops its end.
            let _ = TlsConnector::from(client_cfg)
                .connect(
                    ServerName::try_from("origin.test").expect("name"),
                    client_end,
                )
                .await;
        });
        let proxy_side: ByteStream = Box::pin(proxy_side);

        let result = tokio::time::timeout(
            STALL_GUARD,
            module.mitm(
                Prefixed::new(proxy_side),
                ctx,
                unknown_peer(),
                Some(Target {
                    host: "origin.test".into(),
                    port: 8443,
                    addr: origin_addr(),
                }),
            ),
        )
        .await
        .expect("the handshake was never bounded");

        let err = result.expect_err("a stalled upstream handshake must fail the connection");
        assert_eq!(
            err.to_string(),
            "TLS to upstream origin.test:8443 timed out after 50ms"
        );
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "one dial, and nothing after the timeout"
        );
    }

    #[tokio::test]
    async fn reconnect_gives_up_on_an_origin_that_stalls_the_handshake() {
        let (stalled, _origin) = stalled_pair();
        let (ctx, dialed) = ctx_with(vec![stalled]);
        let module = short_bound_module();
        let reconnect = reconnect_to(&module);

        let result = tokio::time::timeout(STALL_GUARD, reconnect.connect(&ctx))
            .await
            .expect("the handshake was never bounded");

        let err = result
            .err()
            .expect("a stalled handshake must fail the reconnect");
        assert_eq!(
            err.to_string(),
            "TLS to upstream origin.test:8443 timed out after 50ms"
        );
        assert_eq!(
            dialed.lock().expect("dialed lock").len(),
            1,
            "the dial went through the connector once"
        );
    }

    // ---- `serve` end to end over in-memory streams ------------------------

    const MAX_BODY: usize = 1024 * 1024;

    /// An in-memory origin: for each of `bodies`, read one request head and answer
    /// it with a keep-alive 200 carrying that body. Then close the connection if
    /// `then_close`, else hold it open until the proxy hangs up.
    async fn origin_serve<S>(io: S, bodies: Vec<&'static str>, then_close: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        origin_serve_trailing(io, bodies, "", then_close).await;
    }

    /// A partial response head (no blank line yet) that an origin leaves after its
    /// last response. A proxy that carried it over to a replacement connection
    /// would prepend it to that connection's response head and let this origin
    /// choose the status line.
    const INJECTED_HEAD: &str = "HTTP/1.1 500 Injected\r\nX-Junk: ";

    /// A complete second response an origin writes behind its first one, in the
    /// same write. A proxy that parsed it would forward it to the client as the
    /// answer to a request nobody made.
    const STRAY_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nPOISON";

    /// Like [`origin_serve`], with `trailer` appended to the last response in the
    /// same write, so the proxy reads it together with that response.
    async fn origin_serve_trailing<S>(
        io: S,
        bodies: Vec<&'static str>,
        trailer: &'static str,
        then_close: bool,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let last = bodies.len().saturating_sub(1);
        origin_serve_trailing_on(io, bodies, trailer, last, then_close).await;
    }

    /// Like [`origin_serve`], with `trailer` appended to the FIRST response in the
    /// same write. The connection stays open and keeps answering the rest of
    /// `bodies`, so it is a live upstream the proxy could still reuse.
    async fn origin_serve_trailing_after_first<S>(
        io: S,
        bodies: Vec<&'static str>,
        trailer: &'static str,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        origin_serve_trailing_on(io, bodies, trailer, 0, false).await;
    }

    /// The origin behind both helpers above: `trailer` rides in the same write as
    /// the response to the `trailer_on`-th request.
    async fn origin_serve_trailing_on<S>(
        mut io: S,
        bodies: Vec<&'static str>,
        trailer: &'static str,
        trailer_on: usize,
        then_close: bool,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        for (i, body) in bodies.into_iter().enumerate() {
            let mut seen = Vec::new();
            let mut chunk = [0u8; 256];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&chunk[..n]),
                }
            }
            let trailer = if i == trailer_on { trailer } else { "" };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}{trailer}",
                body.len()
            );
            if io.write_all(resp.as_bytes()).await.is_err() || io.flush().await.is_err() {
                return;
            }
        }
        if then_close {
            let _ = io.shutdown().await;
        } else {
            let mut chunk = [0u8; 256];
            while matches!(io.read(&mut chunk).await, Ok(n) if n > 0) {}
        }
    }

    /// Send a GET on the client end and return the `Content-Length`-framed body.
    /// Every origin here answers 200, so any other status fails the test. Bytes
    /// read past the response are dropped; use [`client_get_keep`] to see them.
    async fn client_get(io: &mut DuplexStream, target: &str, host: &str) -> String {
        client_get_keep(io, &mut Vec::new(), target, host).await
    }

    /// Like [`client_get`], but every byte read past the response stays in
    /// `pending`, and `pending` is consumed before the stream is read. A response
    /// the proxy forwarded behind the real one therefore cannot be dropped
    /// unnoticed: it shows up in `pending`, or as the answer to the next request.
    async fn client_get_keep(
        io: &mut DuplexStream,
        pending: &mut Vec<u8>,
        target: &str,
        host: &str,
    ) -> String {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        io.write_all(request.as_bytes()).await.expect("send");
        let mut chunk = [0u8; 512];
        loop {
            if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&pending[..end]).to_ascii_lowercase();
                let status = head.split(' ').nth(1).unwrap_or_default();
                assert_eq!(status, "200", "unexpected response head {head:?}");
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.parse().ok())
                    .expect("response Content-Length");
                if pending.len() >= end + 4 + len {
                    let body =
                        String::from_utf8_lossy(&pending[end + 4..end + 4 + len]).into_owned();
                    pending.drain(..end + 4 + len);
                    return body;
                }
            }
            let n = io.read(&mut chunk).await.expect("read response");
            assert!(n > 0, "connection closed before a full response arrived");
            pending.extend_from_slice(&chunk[..n]);
        }
    }

    fn dial(authority: &str, addr: &str) -> (String, SocketAddr) {
        (authority.to_string(), addr.parse().expect("addr"))
    }

    /// The connection facts of an HTTPS tunnel to `origin.test:8443`, as `mitm()`
    /// sets them. The server connection is stamped as established at the epoch so
    /// a test can tell a refreshed record from the original.
    fn tunnel_conn() -> Conn {
        Conn {
            scheme: "https".to_string(),
            tunnel_authority: Some("origin.test:8443".to_string()),
            client_conn: ConnInfo {
                peer: unknown_peer(),
                sni: None,
                alpn: None,
                tls: true,
                established: SystemTime::now(),
            },
            server_conn: Some(ConnInfo {
                peer: origin_addr(),
                sni: Some("origin.test".to_string()),
                alpn: Some("http/1.1".to_string()),
                tls: true,
                established: SystemTime::UNIX_EPOCH,
            }),
        }
    }

    #[tokio::test]
    async fn serve_replaces_an_upstream_the_origin_closed() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        let origin1 = tokio::spawn(origin_serve(origin1_end, vec!["first"], true));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let first =
                client_get(&mut client, "http://127.0.0.1:8080/one", "127.0.0.1:8080").await;
            // The origin has now closed its end of the idle upstream.
            origin1.await.expect("origin 1");
            let second =
                client_get(&mut client, "http://127.0.0.1:8080/two", "127.0.0.1:8080").await;
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:8080", "127.0.0.1:8080")
            ],
            "the replacement connection goes to the same authority"
        );
    }

    #[tokio::test]
    async fn serve_reuses_a_live_upstream_without_redialing() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1)]);
        let _origin1 = tokio::spawn(origin_serve(origin1_end, vec!["first", "second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let first =
                client_get(&mut client, "http://127.0.0.1:8080/one", "127.0.0.1:8080").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let second =
                client_get(&mut client, "http://127.0.0.1:8080/two", "127.0.0.1:8080").await;
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "a live upstream must be reused, not redialed"
        );
    }

    #[tokio::test]
    async fn serve_redials_a_cleartext_tunnel_to_the_origin_it_was_opened_to() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        let origin1 = tokio::spawn(origin_serve(origin1_end, vec!["first"], true));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), Some("127.0.0.1:8080".to_string()));

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let first = client_get(&mut client, "/one", "127.0.0.1:8080").await;
            origin1.await.expect("origin 1");
            // Same tunnel, but this request names a different Host.
            let second = client_get(&mut client, "/two", "127.0.0.1:9090").await;
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:8080", "127.0.0.1:8080")
            ],
            "a later request's Host must not redirect the redial"
        );
    }

    #[tokio::test]
    async fn serve_redoes_the_tls_connection_when_the_origin_closed_it() {
        // The first upstream is an established TLS connection the origin closes;
        // the connector hands out the transport for the reconnect.
        let (first_up, first_server) = tls_pair().await;
        let (second_c, second_s) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(second_c)]);
        let origin1 = tokio::spawn(origin_serve(first_server, vec!["first"], true));
        let _origin2 = tokio::spawn(async move {
            let tls = TlsAcceptor::from(server_config(&[]))
                .accept(second_s)
                .await
                .expect("origin 2 handshake");
            origin_serve(tls, vec!["second"], false).await;
        });
        let module = HttpModule::new().with_insecure(true);
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let first = client_get(&mut client, "/one", "origin.test:8443").await;
            origin1.await.expect("origin 1");
            let second = client_get(&mut client, "/two", "origin.test:8443").await;
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "exactly one dial, the reconnect, through the connector to the recorded address"
        );
    }

    #[tokio::test]
    async fn serve_fails_closed_instead_of_redialing_cleartext_for_a_dead_tls_upstream() {
        let (up, origin_end) = duplex(1024);
        drop(origin_end);
        let (ctx, dialed) = ctx_with(Vec::new());
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(Box::pin(up)),
            None,
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            client
                .write_all(b"GET /one HTTP/1.1\r\nHost: origin.test:8443\r\n\r\n")
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            got
        };
        let (served, got) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        let err = served.expect_err("a dead TLS upstream with no reconnect must fail the request");
        assert_eq!(
            err.to_string(),
            "upstream TLS connection closed and cannot be re-established"
        );
        assert!(got.is_empty(), "the client must see no response bytes");
        assert!(
            dialed.lock().expect("dialed lock").is_empty(),
            "nothing may be dialed, in particular not in cleartext"
        );
    }

    #[tokio::test]
    async fn serve_fails_the_request_when_the_tls_reconnect_is_refused() {
        let (first_up, first_server) = tls_pair().await;
        // The connector has no stream to give, so the reconnect dial is refused.
        let (ctx, dialed) = ctx_with(Vec::new());
        let origin1 = tokio::spawn(origin_serve(first_server, vec!["first"], true));
        let module = HttpModule::new().with_insecure(true);
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let first = client_get(&mut client, "/one", "origin.test:8443").await;
            origin1.await.expect("origin 1");
            client
                .write_all(b"GET /two HTTP/1.1\r\nHost: origin.test:8443\r\n\r\n")
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            (first, got)
        };
        let (served, (first, got)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        assert_eq!(first, "first");
        let err = served.expect_err("a refused reconnect must fail the request");
        assert_eq!(err.to_string(), "scope guard refused the dial");
        assert!(
            got.is_empty(),
            "the client must see no bytes for the failed request"
        );
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "exactly one dial attempt, the refused reconnect, and no fallback"
        );
    }

    #[tokio::test]
    async fn serve_fails_the_request_when_the_tls_reconnect_handshake_stalls() {
        let (first_up, first_server) = tls_pair().await;
        // The reconnect dial succeeds, but the origin never answers the handshake.
        let (stalled, _origin) = stalled_pair();
        let (ctx, dialed) = ctx_with(vec![stalled]);
        let origin1 = tokio::spawn(origin_serve(first_server, vec!["first"], true));
        let module = short_bound_module();
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let first = client_get(&mut client, "/one", "origin.test:8443").await;
            origin1.await.expect("origin 1");
            client
                .write_all(b"GET /two HTTP/1.1\r\nHost: origin.test:8443\r\n\r\n")
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            (first, got)
        };
        let (served, (first, got)) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("the handshake was never bounded");

        assert_eq!(first, "first");
        let err = served.expect_err("a stalled reconnect handshake must fail the request");
        assert_eq!(
            err.to_string(),
            "TLS to upstream origin.test:8443 timed out after 50ms"
        );
        assert!(
            got.is_empty(),
            "the client must see no bytes for the failed request"
        );
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "one dial, the stalled reconnect, and no cleartext fallback"
        );
    }

    #[tokio::test]
    async fn serve_drops_response_bytes_left_over_from_a_discarded_upstream() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        // Origin 1 answers, leaves a partial response head behind in the same
        // write, then closes. The proxy reads that head fragment with the answer.
        let origin1 = tokio::spawn(origin_serve_trailing(
            origin1_end,
            vec!["first"],
            INJECTED_HEAD,
            true,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let first =
                client_get(&mut client, "http://127.0.0.1:8080/one", "127.0.0.1:8080").await;
            origin1.await.expect("origin 1");
            // `client_get` fails the test if the replacement's response arrives
            // with the leftover fragment's 500 status line in front of it.
            let second =
                client_get(&mut client, "http://127.0.0.1:8080/two", "127.0.0.1:8080").await;
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
    }

    #[tokio::test]
    async fn serve_drops_response_bytes_left_over_across_a_tls_reconnect() {
        // The TLS reconnect never reaches the cleartext connect step, so the
        // discard itself has to empty the response buffer.
        let (first_up, first_server) = tls_pair().await;
        let (second_c, second_s) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(second_c)]);
        let origin1 = tokio::spawn(origin_serve_trailing(
            first_server,
            vec!["first"],
            INJECTED_HEAD,
            true,
        ));
        let _origin2 = tokio::spawn(async move {
            let tls = TlsAcceptor::from(server_config(&[]))
                .accept(second_s)
                .await
                .expect("origin 2 handshake");
            origin_serve(tls, vec!["second"], false).await;
        });
        let module = HttpModule::new().with_insecure(true);
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let first = client_get(&mut client, "/one", "origin.test:8443").await;
            origin1.await.expect("origin 1");
            let second = client_get(&mut client, "/two", "origin.test:8443").await;
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
    }

    #[tokio::test]
    async fn serve_drops_response_bytes_left_over_when_the_authority_changes() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        // Origin 1 stays open, so nothing is stale; the second request simply
        // names another authority and gets a new connection.
        let _origin1 = tokio::spawn(origin_serve_trailing(
            origin1_end,
            vec!["first"],
            INJECTED_HEAD,
            false,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let first =
                client_get(&mut client, "http://127.0.0.1:8080/one", "127.0.0.1:8080").await;
            let second =
                client_get(&mut client, "http://127.0.0.1:9090/two", "127.0.0.1:9090").await;
            drop(client);
            (first, second)
        };
        let (served, (first, second)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:9090", "127.0.0.1:9090")
            ]
        );
    }

    #[tokio::test]
    async fn serve_refreshes_the_server_connection_record_after_a_tls_reconnect() {
        let (first_up, first_server) = tls_pair().await;
        let (second_c, second_s) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(second_c)]);
        let origin1 = tokio::spawn(origin_serve(first_server, vec!["first"], true));
        let _origin2 = tokio::spawn(async move {
            let tls = TlsAcceptor::from(server_config(&[]))
                .accept(second_s)
                .await
                .expect("origin 2 handshake");
            origin_serve(tls, vec!["second"], false).await;
        });
        let module = HttpModule::new().with_insecure(true);
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            client_get(&mut client, "/one", "origin.test:8443").await;
            origin1.await.expect("origin 1");
            client_get(&mut client, "/two", "origin.test:8443").await;
            drop(client);
        };
        let (served, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung");
        served.expect("serve ends cleanly when the client hangs up");

        // The server connection each flow was stored with, by request path.
        let server_conn_of = |path: &str| {
            ctx.store()
                .list()
                .into_iter()
                .find_map(|id| match ctx.store().get(id) {
                    Some(Flow::Http(f)) if f.request.path == path => f.server_conn,
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no stored flow for {path} with a server connection"))
        };
        let before = server_conn_of("/one");
        let after = server_conn_of("/two");
        assert_eq!(
            before.established,
            SystemTime::UNIX_EPOCH,
            "the flow served on the original connection keeps its record"
        );
        assert!(
            after.established > SystemTime::UNIX_EPOCH,
            "the flow served on the replacement connection must record when it was established"
        );
        assert_eq!(
            (
                after.peer,
                after.sni.as_deref(),
                after.alpn.as_deref(),
                after.tls
            ),
            (origin_addr(), Some("origin.test"), Some("http/1.1"), true),
            "only the establishment time changes"
        );
    }

    // ---- surplus bytes after a completed response -------------------------

    #[tokio::test]
    async fn serve_does_not_forward_a_second_response_read_with_the_first() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed, sink) = ctx_recording(vec![Box::pin(up1), Box::pin(up2)]);
        // Origin 1 writes the answer and a complete second response in one write,
        // then stays open. The connection is therefore live, but tainted.
        let _origin1 = tokio::spawn(origin_serve_trailing(
            origin1_end,
            vec!["legit"],
            STRAY_RESPONSE,
            false,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let mut pending = Vec::new();
            let first = client_get_keep(
                &mut client,
                &mut pending,
                "http://127.0.0.1:8080/one",
                "127.0.0.1:8080",
            )
            .await;
            let after_first = pending.clone();
            let second = client_get_keep(
                &mut client,
                &mut pending,
                "http://127.0.0.1:8080/two",
                "127.0.0.1:8080",
            )
            .await;
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (first, after_first, second, pending)
        };
        let (served, (first, after_first, second, pending)) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(serving, script)
            })
            .await
            .expect("serve hung: request 2 went to the tainted upstream, which never answers");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(first, "legit");
        assert!(
            after_first.is_empty(),
            "the stray response must not reach the client: {:?}",
            String::from_utf8_lossy(&after_first)
        );
        assert_eq!(second, "second");
        assert!(
            pending.is_empty(),
            "nothing may follow the second response: {:?}",
            String::from_utf8_lossy(&pending)
        );
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:8080", "127.0.0.1:8080")
            ],
            "the tainted upstream is replaced by a second connection to the same authority"
        );

        // The plugin chain saw each exchange exactly once: four events per flow,
        // and no error for a flow that delivered its response.
        let events = sink.events.lock().expect("events lock");
        assert_eq!(events.len(), 8, "events: {events:?}");
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::ResponseHeaders(_)))
                .count(),
            2,
            "events: {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Response(_)))
                .count(),
            2,
            "events: {events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, Event::Error { .. })),
            "events: {events:?}"
        );

        // The stored response is the legitimate one, not the stray.
        let stored = ctx
            .store()
            .list()
            .into_iter()
            .find_map(|id| match ctx.store().get(id) {
                Some(Flow::Http(f)) if f.request.path == "/one" => Some(f),
                _ => None,
            })
            .expect("a stored flow for /one");
        let response = stored.response.expect("a stored response for /one");
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("content-length"), Some("5"));
        assert!(
            matches!(response.body, Body::Bytes(ref b) if b.as_slice() == b"legit"),
            "stored body: {:?}",
            response.body
        );
    }

    #[tokio::test]
    async fn serve_does_not_glue_a_stray_head_fragment_onto_the_next_response_on_a_live_upstream() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        // Origin 1 stays open and would answer request 2 itself, behind the head
        // fragment it left. Riding that connection would let it pick the status.
        let _origin1 = tokio::spawn(origin_serve_trailing_after_first(
            origin1_end,
            vec!["first", "second"],
            INJECTED_HEAD,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));
        let (mut client, proxy_side) = duplex(64 * 1024);
        let conn = Conn::plain(unknown_peer(), None);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            let mut pending = Vec::new();
            let first = client_get_keep(
                &mut client,
                &mut pending,
                "http://127.0.0.1:8080/one",
                "127.0.0.1:8080",
            )
            .await;
            // `client_get_keep` fails the test if this answer carries the status
            // line of the head fragment (500) instead of a 200.
            let second = client_get_keep(
                &mut client,
                &mut pending,
                "http://127.0.0.1:8080/two",
                "127.0.0.1:8080",
            )
            .await;
            drop(client);
            (first, second, pending)
        };
        let (served, (first, second, pending)) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(serving, script)
            })
            .await
            .expect("serve hung");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!((first.as_str(), second.as_str()), ("first", "second"));
        assert!(pending.is_empty(), "pending: {pending:?}");
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:8080", "127.0.0.1:8080")
            ],
            "the live upstream that left a fragment behind must be replaced"
        );
    }

    #[tokio::test]
    async fn serve_reconnects_over_tls_after_a_stray_response() {
        let (first_up, first_server) = tls_pair().await;
        let (second_c, second_s) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(second_c)]);
        let _origin1 = tokio::spawn(origin_serve_trailing(
            first_server,
            vec!["legit"],
            STRAY_RESPONSE,
            false,
        ));
        let _origin2 = tokio::spawn(async move {
            let tls = TlsAcceptor::from(server_config(&[]))
                .accept(second_s)
                .await
                .expect("origin 2 handshake");
            origin_serve(tls, vec!["second"], false).await;
        });
        let module = HttpModule::new().with_insecure(true);
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(first_up),
            Some(reconnect_to(&module)),
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let mut pending = Vec::new();
            let first =
                client_get_keep(&mut client, &mut pending, "/one", "origin.test:8443").await;
            let after_first = pending.clone();
            let second =
                client_get_keep(&mut client, &mut pending, "/two", "origin.test:8443").await;
            drop(client);
            (first, after_first, second, pending)
        };
        let (served, (first, after_first, second, pending)) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(serving, script)
            })
            .await
            .expect("serve hung: request 2 went to the tainted upstream, which never answers");

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(first, "legit");
        assert!(after_first.is_empty(), "pending: {after_first:?}");
        assert_eq!(second, "second");
        assert!(pending.is_empty(), "pending: {pending:?}");
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![("origin.test:8443".to_string(), origin_addr())],
            "exactly one dial, the TLS reconnect, through the connector"
        );
    }

    #[tokio::test]
    async fn serve_fails_closed_for_a_tainted_tls_upstream_without_a_reconnect() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(Vec::new());
        let _origin = tokio::spawn(origin_serve_trailing(
            origin_end,
            vec!["legit"],
            STRAY_RESPONSE,
            false,
        ));
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(Box::pin(up)),
            None,
            tunnel_conn(),
            MAX_BODY,
        );
        let script = async {
            let mut pending = Vec::new();
            let first =
                client_get_keep(&mut client, &mut pending, "/one", "origin.test:8443").await;
            client
                .write_all(b"GET /two HTTP/1.1\r\nHost: origin.test:8443\r\n\r\n")
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            (first, pending, got)
        };
        let (served, (first, pending, got)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung: request 2 went to the tainted upstream, which never answers");

        assert_eq!(first, "legit");
        assert!(pending.is_empty(), "pending: {pending:?}");
        let err =
            served.expect_err("a tainted TLS upstream with no reconnect must fail the request");
        assert_eq!(
            err.to_string(),
            "upstream TLS connection closed and cannot be re-established"
        );
        assert!(
            got.is_empty(),
            "the client must see no further bytes: {got:?}"
        );
        assert!(
            dialed.lock().expect("dialed lock").is_empty(),
            "nothing may be dialed, in particular not in cleartext"
        );
    }
}
