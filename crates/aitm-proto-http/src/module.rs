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
                serve(&ctx, Box::pin(client), None, conn, self.max_body_bytes).await
            }
        } else if first.first() == Some(&TLS_HANDSHAKE) {
            self.mitm(client, ctx, peer, None).await
        } else {
            serve(
                &ctx,
                Box::pin(client),
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
        let upstream = TlsConnector::from(self.upstream_tls_alpn(&client_alpn)?)
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("TLS to upstream {}", target.authority()))?;
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
        // driver; everything else runs the unchanged h1 `serve` loop.
        if negotiated == b"h2" {
            crate::h2::serve_h2(
                ctx,
                Box::pin(client_tls),
                Box::pin(upstream),
                conn,
                self.max_body_bytes,
                self.max_concurrent_streams,
            )
            .await
        } else {
            serve(
                &ctx,
                Box::pin(client_tls),
                Some(Box::pin(upstream)),
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
async fn serve(
    ctx: &ModuleCtx,
    mut client: ByteStream,
    mut upstream: Option<ByteStream>,
    mut conn: Conn,
    max_body: usize,
) -> Result<()> {
    let mut machine = Http1Machine::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut current_authority: Option<String> = conn.tunnel_authority.clone();

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
            continue;
        }

        // --- Make sure an upstream connection exists for this authority.
        let needs_connect = match (&upstream, &conn.tunnel_authority, &current_authority) {
            (None, _, _) => true,
            (Some(_), None, Some(current)) => current != &request.authority,
            _ => false,
        };
        if needs_connect {
            let target = Target::resolve(&request.authority, 80).await?;
            upstream = Some(
                ctx.connect_upstream(&target.authority(), target.addr)
                    .await?,
            );
            current_authority = Some(request.authority.clone());
            let server_conn = ConnInfo {
                peer: target.addr,
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            };
            conn.server_conn = Some(server_conn.clone());
            ctx.store().update(id, &mut |f: &mut Flow| {
                if let Flow::Http(h) = f {
                    h.server_conn = Some(server_conn.clone());
                }
            });
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
        if request_close || response_close {
            let _ = client.shutdown().await;
            return Ok(());
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
