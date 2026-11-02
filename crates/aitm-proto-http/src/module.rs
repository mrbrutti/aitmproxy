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

use aitm_core::proxy::parse_client_hello_sni;
use aitm_core::tunnel::FIRST_BYTE_TIMEOUT;
use aitm_core::{
    classify_client_failure, relay, Authority, Body, CaConfig, ConnInfo, Event, Flow, FlowId,
    FlowMeta, HeaderMap, HttpFlow, HttpRequest, HttpResponse, HttpVersion, InterceptState,
    StreamBody, TunnelInfo, TunnelReason, TunnelRequest, TunnelRow,
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
use crate::sansio::{content_length, Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};

/// First byte of a TLS handshake record.
const TLS_HANDSHAKE: u8 = 0x16;
/// Largest CONNECT head accepted.
const MAX_CONNECT_HEAD: usize = 16 * 1024;
/// The most of a raw-TLS ClientHello the module buffers itself to read its SNI
/// when the acceptor's peek did not hold it: one TLS record (a 5-byte header and
/// at most 2^14 bytes of payload, RFC 8446 §5.1), which is where a ClientHello's
/// `server_name` lives.
const MAX_CLIENT_HELLO: usize = 5 + 16 * 1024;
/// The acknowledgement a `CONNECT` gets once the tunnel's route is decided.
const CONNECT_ACK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// The port a `CONNECT` authority or an explicit-proxy SNI defaults to (spec D1).
const DEFAULT_TLS_PORT: u16 = 443;
/// The port a cleartext request's `Host` defaults to when it names none: what a
/// forward-proxy request's authority is normalised with before it is judged
/// against Scope (spec D4).
const DEFAULT_HTTP_PORT: u16 = 80;
/// Socket read size.
const READ_CHUNK: usize = 16 * 1024;

// One read can hold a legitimate response's tail plus the surplus behind it. The
// machine fails the connection once more than `MAX_HEAD_BYTES` unsolicited server
// bytes are parked, which would drop that legitimate response; a read of at most
// the cap cannot reach that. The strict `<` keeps a margin the machine's own
// strict `>` does not require.
const _: () = assert!(
    READ_CHUNK < crate::sansio::MAX_HEAD_BYTES,
    "READ_CHUNK must stay below sansio::MAX_HEAD_BYTES"
);

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
/// The mark `aitm-plugin-maprules` leaves on a flow whose authority it rewrote.
/// Matched by value, not through a crate dependency, exactly as `h2.rs` does with
/// its own `MAP_REMOTE_MARK`: keep the two equal.
const MAP_REMOTE_MARK: &str = "map-remote";
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

    /// Bound the TLS handshake to an origin at `within` (default 30 seconds, the
    /// same bound as the per-read idle timeout). Not yet wired to config.
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

    /// Peek the first bytes and route: a `CONNECT` tunnel, a raw TLS connection
    /// (the capture path), or cleartext HTTP. The two TLS-capable routes decide
    /// per connection, against the live Scope, whether the connection is
    /// decrypted or relayed (spec D1/D2), and record every tunnel as a row.
    async fn drive(&self, io: ByteStream, ctx: ModuleCtx) -> Result<()> {
        let peer = ctx.hint().map(|h| h.dst).unwrap_or_else(unknown_peer);
        let mut client = Prefixed::new(io);
        let first = client.peek(8).await?.to_vec();
        if first.starts_with(b"CONNECT ") {
            self.tunnel(client, ctx, peer).await
        } else if first.first() == Some(&TLS_HANDSHAKE) {
            self.raw_tls(client, ctx, peer).await
        } else {
            serve(
                &ctx,
                Box::pin(client),
                None,
                None,
                Conn::plain(peer, None).with_attribution(ctx.hint()),
                self.max_body_bytes,
            )
            .await
        }
    }

    /// A `CONNECT` tunnel, spec D6 step by step. The head is read and its
    /// authority normalised (port 443 when absent); an authority outside the
    /// live Scope is relayed to the origin untouched by [`relay_out_of_scope`]
    /// (D2: the module's own relay, so the invariant does not depend on the
    /// passthrough module having claimed the connection first); one in Scope is
    /// resolved, acknowledged and decrypted — TLS through [`HttpModule::mitm`],
    /// cleartext served inside the tunnel. Every outcome is a tunnel row, through
    /// [`fail_tunnel`] for the early exits decided here:
    ///
    /// - a head that cannot be read (EOF, reset, over the cap) or an authority
    ///   token that is not one → `failed`, with the reason the error's type
    ///   gives (`client_closed` for a client that left, else `protocol_error`);
    /// - an origin that does not resolve → `failed/upstream_unreachable`, with
    ///   no acknowledgement (as before, the client gets no `200` for it);
    /// - the client gone after the acknowledgement, before its first byte — or
    ///   silent for [`FIRST_BYTE_TIMEOUT`] (panel S7) → `failed/client_closed`;
    /// - cleartext inside an in-scope tunnel → `decrypted` with `client.tls =
    ///   false`, closed when the connection ends.
    ///
    /// The row's `client.tls` is `false` until the first byte inside the tunnel
    /// is seen to open a TLS handshake record, so a row for a failure before
    /// that point says no TLS was seen.
    ///
    /// A row needs an authority. A head that does not parse (no token after
    /// `CONNECT`, a non-UTF-8 header line) is a `failed/protocol_error` row
    /// keyed on the authority the acceptor's peek named, with no headers, as
    /// the passthrough module records it; one the peek did not name either
    /// ends the connection with the error and no row: there is nothing to key
    /// a row on ([`fail_before_authority`]). An authority token that does not
    /// parse is recorded under the label `Authority::new(raw, 443)` — the raw
    /// text with every ASCII control byte dropped, lowercased, as the host — so
    /// the operator sees what the client asked for and no escape byte rides on
    /// the row; it is never dialled.
    async fn tunnel(
        &self,
        mut client: Prefixed<ByteStream>,
        ctx: ModuleCtx,
        peer: SocketAddr,
    ) -> Result<()> {
        let opened_at = SystemTime::now();
        // What the acceptor's peek named: the key of a row whose head never parses.
        let hinted = ctx.hint().and_then(NextLayerHint::tunnel_authority);
        let head = match client.read_head(MAX_CONNECT_HEAD).await {
            Ok(head) => head,
            Err(e) => {
                let err = anyhow::Error::from(e);
                let reason = classify_client_failure(&err);
                fail_before_authority(&ctx, peer, hinted, opened_at, false, reason).await;
                return Err(err);
            }
        };
        let ConnectHead {
            authority: raw,
            headers,
        } = match parse_connect(&head) {
            Ok(parsed) => parsed,
            Err(e) => {
                let reason = TunnelReason::ProtocolError;
                fail_before_authority(&ctx, peer, hinted, opened_at, false, reason).await;
                return Err(e);
            }
        };
        let authority = match Authority::parse_with_default(&raw, DEFAULT_TLS_PORT) {
            Ok(authority) => authority,
            Err(e) => {
                // The row's label is the raw token with every ASCII control
                // byte dropped (a terminal escape must never ride on
                // `request.authority` into a table or a session file; the
                // error below still names the token as sent, Debug-escaped).
                let label: String = raw.chars().filter(|c| !c.is_ascii_control()).collect();
                let head = TunnelHead {
                    authority: Authority::new(&label, DEFAULT_TLS_PORT),
                    headers,
                    opened_at,
                };
                let request = tunnel_request(&ctx, peer, head, false);
                fail_tunnel(&ctx, request, TunnelReason::ProtocolError).await;
                bail!("malformed CONNECT authority: {e}");
            }
        };
        let head = TunnelHead {
            authority,
            headers,
            opened_at,
        };
        // Nothing inside the tunnel has been seen yet: `tls` stays false until
        // the first byte says otherwise.
        let mut request = tunnel_request(&ctx, peer, head, false);

        if !ctx.in_scope(&request.authority.to_string()) {
            return relay_out_of_scope(client, &ctx, request, true).await;
        }
        let target = match Target::from_authority(&request.authority).await {
            Ok(target) => target,
            Err(e) => {
                fail_tunnel(&ctx, request, TunnelReason::UpstreamUnreachable).await;
                return Err(e);
            }
        };
        let next = match first_byte_after_ack(&mut client).await {
            Ok(Some(next)) => next,
            Ok(None) => {
                // EOF — or silence for `FIRST_BYTE_TIMEOUT` — before the first
                // byte: a speculative pre-connect, a client that gave up. A row,
                // but not an error worth the acceptor's log; the client is shut
                // so a silent one sees EOF (nothing was dialled yet).
                fail_tunnel(&ctx, request, TunnelReason::ClientClosed).await;
                let _ = client.shutdown().await;
                return Ok(());
            }
            Err(e) => {
                let err = anyhow::Error::from(e);
                fail_tunnel(&ctx, request, classify_client_failure(&err)).await;
                return Err(err);
            }
        };
        if next == TLS_HANDSHAKE {
            request.client.tls = true;
            return self.mitm(client, ctx, target, request).await;
        }

        // Cleartext inside the tunnel (`curl -p`): served as HTTP/1 with the
        // tunnel's route; the row is `decrypted` with a cleartext client side.
        let conn =
            Conn::plain(peer, Some((target.authority(), target.addr))).with_attribution(ctx.hint());
        request.client = conn.client_conn.clone();
        let row = TunnelRow::open(&ctx, request, TunnelInfo::decrypted()).await;
        let served = serve(
            &ctx,
            Box::pin(client),
            None,
            None,
            conn,
            self.max_body_bytes,
        )
        .await;
        row.close(&ctx, None).await;
        served
    }

    /// A TLS connection with no `CONNECT` (a capture ingress, a transparent
    /// client). Its tunnel authority is the hint's (spec D1: the SNI with the
    /// capture destination's port, else `sni:443`); when the acceptor's peek
    /// did not hold the ClientHello, the module buffers its first record itself
    /// — it stays in the stream — and reads the SNI from it. Out of Scope → the
    /// same relay as a CONNECT, with the buffered bytes going first (TLS by
    /// construction: `drive` routed here on the handshake byte, so no
    /// acknowledgement and no first-byte check); in Scope → [`HttpModule::mitm`].
    /// No SNI → `failed/protocol_error` and the error as before: nothing names
    /// an origin to decrypt; a record the client cut off with a reset while it
    /// was being buffered → `failed` with the reason the error's type gives
    /// (panel Q5). A capture ingress knows the destination, so those rows are
    /// keyed on it; on the explicit-proxy path `dst` is the client's own
    /// address, so there is no authority to key a row on and the connection
    /// ends with the error alone.
    async fn raw_tls(
        &self,
        mut client: Prefixed<ByteStream>,
        ctx: ModuleCtx,
        peer: SocketAddr,
    ) -> Result<()> {
        let opened_at = SystemTime::now();
        let captured_dst = ctx
            .hint()
            .filter(|h| h.capture_interface.is_some())
            .map(|h| h.dst);
        // What a row for a connection whose SNI never arrives is keyed on.
        let captured = captured_dst.map(|dst| Authority::new(&dst.ip().to_string(), dst.port()));
        let authority = match ctx.hint().and_then(NextLayerHint::tunnel_authority) {
            Some(authority) => Some(authority),
            None => {
                let port = captured_dst.map_or(DEFAULT_TLS_PORT, |dst| dst.port());
                match client.peek_tls_record(MAX_CLIENT_HELLO).await {
                    Ok(hello) => {
                        parse_client_hello_sni(hello).map(|sni| Authority::new(&sni, port))
                    }
                    Err(e) => {
                        let err = anyhow::Error::from(e);
                        let reason = classify_client_failure(&err);
                        fail_before_authority(&ctx, peer, captured, opened_at, true, reason).await;
                        return Err(err);
                    }
                }
            }
        };
        let Some(authority) = authority else {
            let reason = TunnelReason::ProtocolError;
            fail_before_authority(&ctx, peer, captured, opened_at, true, reason).await;
            bail!("TLS without CONNECT or SNI: no upstream to pick");
        };
        let head = TunnelHead {
            authority,
            headers: HeaderMap::new(),
            opened_at,
        };
        // TLS by construction: `drive` routed here on the handshake byte.
        let request = tunnel_request(&ctx, peer, head, true);

        if !ctx.in_scope(&request.authority.to_string()) {
            return relay_out_of_scope(client, &ctx, request, false).await;
        }
        let target = match Target::from_authority(&request.authority).await {
            Ok(target) => target,
            Err(e) => {
                fail_tunnel(&ctx, request, TunnelReason::UpstreamUnreachable).await;
                return Err(e);
            }
        };
        self.mitm(client, ctx, target, request).await
    }

    /// TLS MITM of an in-scope tunnel (`target` is where `request.authority`
    /// resolved; the caller has seen the client's handshake byte, so
    /// `request.client.tls` is already true): read the ClientHello (SNI),
    /// connect to the origin over TLS, sniff its leaf's names, mint an
    /// impersonating leaf, finish the client handshake, then serve HTTP between
    /// the two decrypted streams. The tunnel row appears at the outcome (spec
    /// D5): `decrypted` once the client handshake completes, closed with its
    /// duration when the connection ends; or `failed` with the step that broke
    /// it ([`HttpModule::establish`]), the connection ending with that step's
    /// error unchanged.
    async fn mitm(
        &self,
        client: Prefixed<ByteStream>,
        ctx: ModuleCtx,
        target: Target,
        mut request: TunnelRequest,
    ) -> Result<()> {
        let peer = request.client.peer;
        let session = match self.establish(client, &ctx, &target, &mut request).await {
            Ok(session) => session,
            Err(Refused { reason, error }) => {
                fail_tunnel(&ctx, request, reason).await;
                return Err(error);
            }
        };
        let Established {
            client_tls,
            upstream,
            server_name,
            sni,
            negotiated,
            h2_upstream_tls,
        } = session;

        let alpn = String::from_utf8_lossy(&negotiated).into_owned();
        let now = SystemTime::now();
        let conn = Conn {
            scheme: "https".to_string(),
            tunnel_authority: Some(target.authority()),
            tunnel_addr: Some(target.addr),
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
            source_app: None,
            capture_interface: None,
            // In Scope when admitted; the decision is per connection (spec D4).
            passive: false,
        }
        .with_attribution(ctx.hint());
        // The row records the two connections exactly as the inner flows will.
        request.client = conn.client_conn.clone();
        request.server = conn.server_conn.clone();
        let row = TunnelRow::open(&ctx, request, TunnelInfo::decrypted()).await;

        // Branch on the negotiated protocol: h2 runs the per-stream `serve_h2`
        // driver; everything else runs the h1 `serve` loop. `serve_h2` shares
        // the context across its stream tasks, so it takes an `Arc`; the row is
        // closed through the same handle once either driver returns, whatever
        // it returned, so the connection's end is the row's duration.
        let ctx = Arc::new(ctx);
        let served = if let Some(upstream_h2_tls) = h2_upstream_tls {
            // Unlike the h1 branch below, an h2 upstream gets no stale-connection
            // probe or reconnect. That is out of scope here; `serve_h2` has the
            // same exposure and is a follow-up.
            crate::h2::serve_h2(
                ctx.clone(),
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
        };
        row.close(&ctx, None).await;
        served
    }

    /// The handshakes of a MITM tunnel, in order, each failure mapped to the
    /// reason its row records (spec D5) with the error itself untouched: the
    /// ClientHello read and the client handshake by the error's type
    /// ([`classify_client_failure`]: a certificate alert is the client
    /// rejecting our leaf, an EOF or reset a client that left, any other TLS
    /// error a client TLS error); the origin dial → `upstream_unreachable`; the
    /// origin handshake, its timeout included → `upstream_tls_failed`; the
    /// h2-to-h1 mirror refusal, an unusable origin name and the proxy's own
    /// leaf/config work → `protocol_error`. Fills in what the row learns on the
    /// way: the client's SNI and the origin once it is dialled.
    async fn establish(
        &self,
        client: Prefixed<ByteStream>,
        ctx: &ModuleCtx,
        target: &Target,
        request: &mut TunnelRequest,
    ) -> std::result::Result<Established, Refused> {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client)
            .await
            .context("read ClientHello")
            .map_err(Refused::client)?;
        let sni = start.client_hello().server_name().map(str::to_string);
        request.client.sni = sni.clone();
        // The client's ALPN offer (an absent extension ⇒ assume `http/1.1`). We
        // offer upstream exactly this list and mirror whatever it negotiates.
        let client_alpn: Vec<Vec<u8>> = start
            .client_hello()
            .alpn()
            .map(|offers| offers.map(|p| p.to_vec()).collect())
            .unwrap_or_else(|| vec![b"http/1.1".to_vec()]);

        let server_name = ServerName::try_from(target.host.clone())
            .map_err(|e| anyhow!("invalid upstream name {:?}: {e}", target.host))
            .map_err(Refused::with(TunnelReason::ProtocolError))?;
        let tcp = ctx
            .connect_upstream(&target.authority(), target.addr)
            .await
            .map_err(Refused::with(TunnelReason::UpstreamUnreachable))?;
        request.server = Some(ConnInfo {
            peer: target.addr,
            sni: Some(target.host.clone()),
            alpn: None,
            tls: true,
            established: SystemTime::now(),
        });
        let upstream = self
            .tls_handshake(&client_alpn, server_name.clone(), tcp, &target.authority())
            .await
            .map_err(Refused::with(TunnelReason::UpstreamTlsFailed))?;
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
            return Err(Refused {
                reason: TunnelReason::ProtocolError,
                error: anyhow!(
                    "cannot mirror h2 to an h1-only client for {}",
                    target.authority()
                ),
            });
        }
        // A Map Remote rewrite to a different authority needs a SECOND upstream
        // (an h2 connection is pinned to one `:authority`, spec §6). The TLS
        // client config lives here (provider + insecure verifier), so hand
        // `serve_h2` an h2-ALPN config it can dial new origins with (Task 4).
        let h2_upstream_tls = if negotiated == b"h2" {
            Some(
                self.upstream_tls_alpn(&[b"h2".to_vec()])
                    .map_err(Refused::with(TunnelReason::ProtocolError))?,
            )
        } else {
            None
        };

        let sans = upstream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(cert_names)
            .unwrap_or_default();
        let config = self
            .ca()
            .and_then(|ca| ca.leaf_for(&target.host, &sans))
            .and_then(|leaf| self.impersonating_config(&leaf, &negotiated))
            .map_err(Refused::with(TunnelReason::ProtocolError))?;
        let client_tls = start
            .into_stream(config)
            .await
            .context("client TLS handshake")
            .map_err(Refused::client)?;

        Ok(Established {
            client_tls,
            upstream,
            server_name,
            sni,
            negotiated,
            h2_upstream_tls,
        })
    }
}

/// What the CONNECT path knows about a tunnel before its outcome: the
/// normalised authority Scope is decided on, the `CONNECT` request headers
/// (empty for a raw-TLS connection) and when the head (or ClientHello) was
/// read — the row's `created`, which its duration is measured from.
struct TunnelHead {
    authority: Authority,
    headers: HeaderMap,
    opened_at: SystemTime,
}

/// Both halves of an established MITM tunnel, as [`HttpModule::establish`]
/// hands them to the serving driver.
struct Established {
    client_tls: tokio_rustls::server::TlsStream<Prefixed<ByteStream>>,
    upstream: tokio_rustls::client::TlsStream<ByteStream>,
    server_name: ServerName<'static>,
    /// The client's SNI, for the connection record.
    sni: Option<String>,
    /// The protocol the origin negotiated, mirrored to the client.
    negotiated: Vec<u8>,
    /// `Some` iff the mirror landed on h2: the TLS client config `serve_h2`
    /// dials a Map Remote origin with.
    h2_upstream_tls: Option<Arc<ClientConfig>>,
}

/// Why a tunnel could not be established: the reason its row records and the
/// error the connection ends with, unchanged.
struct Refused {
    reason: TunnelReason,
    error: anyhow::Error,
}

impl Refused {
    /// Record any error of a step under `reason`.
    fn with(reason: TunnelReason) -> impl FnOnce(anyhow::Error) -> Refused {
        move |error| Refused { reason, error }
    }

    /// A client-side handshake failure, classified by its type.
    fn client(error: anyhow::Error) -> Refused {
        Refused {
            reason: classify_client_failure(&error),
            error,
        }
    }
}

/// The row request for `head` as a connection knows it before anything was
/// dialled: the client peer with `tls` as given (whether a TLS handshake record
/// has been seen from the client: a raw-TLS connection opened with one; a
/// `CONNECT`'s is unknown until its first byte) and no SNI yet, no origin, and
/// the hint's capture attribution. Producers fill in what they learn.
fn tunnel_request(ctx: &ModuleCtx, peer: SocketAddr, head: TunnelHead, tls: bool) -> TunnelRequest {
    let (source_app, capture_interface) = ctx.hint().map_or((None, None), |h| {
        (h.peer_identity.clone(), h.capture_interface.clone())
    });
    TunnelRequest {
        authority: head.authority,
        headers: head.headers,
        client: ConnInfo {
            peer,
            sni: None,
            alpn: None,
            tls,
            established: head.opened_at,
        },
        server: None,
        opened_at: head.opened_at,
        source_app,
        capture_interface,
    }
}

/// Spec D5: a tunnel that was not established is a `failed` row with `reason`
/// — closed on insert, no status — recorded here and nowhere else in this
/// module, so every early exit of the CONNECT, raw-TLS and relay paths leaves
/// the same row. The caller then ends the connection with its error unchanged
/// (or with `Ok(())` for a client that simply left).
async fn fail_tunnel(ctx: &ModuleCtx, request: TunnelRequest, reason: TunnelReason) {
    TunnelRow::open(ctx, request, TunnelInfo::failed(reason)).await;
}

/// [`fail_tunnel`] for a tunnel that failed before its authority was read: the
/// row is keyed on `authority` — what the acceptor's peek named for a `CONNECT`,
/// the capture destination for a raw-TLS connection — with no headers. With
/// `None` there is nothing to key a row on (a `CONNECT` the peek did not name,
/// a raw-TLS connection on the explicit-proxy path; spec D6), so no row is
/// recorded and the connection ends with the error alone.
async fn fail_before_authority(
    ctx: &ModuleCtx,
    peer: SocketAddr,
    authority: Option<Authority>,
    opened_at: SystemTime,
    tls: bool,
    reason: TunnelReason,
) {
    if let Some(authority) = authority {
        let head = TunnelHead {
            authority,
            headers: HeaderMap::new(),
            opened_at,
        };
        fail_tunnel(ctx, tunnel_request(ctx, peer, head, tls), reason).await;
    }
}

/// Write the `200 Connection Established` acknowledgement.
async fn acknowledge<S: AsyncWrite + Unpin>(client: &mut S) -> io::Result<()> {
    client.write_all(CONNECT_ACK).await?;
    client.flush().await
}

/// Acknowledge the `CONNECT` and look at the first byte the client then sends
/// inside the tunnel without consuming it — `None` when the client closed
/// instead, or sent nothing within [`FIRST_BYTE_TIMEOUT`] (panel S7: a client
/// that is acknowledged and goes silent must not hold a dialled origin with no
/// row; it is treated as gone). What the tunnel becomes is decided on that byte
/// (spec D1/D6).
async fn first_byte_after_ack(client: &mut Prefixed<ByteStream>) -> io::Result<Option<u8>> {
    acknowledge(client).await?;
    match tokio::time::timeout(FIRST_BYTE_TIMEOUT, client.peek(1)).await {
        Ok(peeked) => Ok(peeked?.first().copied()),
        Err(_elapsed) => Ok(None),
    }
}

/// Spec D1/D2/D5: a tunnel whose authority is outside the live Scope is not
/// decrypted but relayed — and relays **TLS only**. The origin is resolved and
/// dialled through the connector (a failure there is
/// `failed/upstream_unreachable`, answered with nothing). On the `CONNECT`
/// path (`connect`) the acknowledgement is then written and the first byte the
/// client sends must open a TLS handshake record (`0x16`): EOF before it — or
/// silence for [`FIRST_BYTE_TIMEOUT`] (panel S7) — is `failed/client_closed`
/// (a speculative pre-connect; a row, not an error; both sockets shut), any
/// other byte is `failed/protocol_error` with nothing relayed and the client
/// shut down — the proxy is not a raw relay to an arbitrary `host:port` (panel
/// S1) — and the row's `client.tls` is set only once that byte was seen. A
/// raw-TLS connection expects no acknowledgement and opened with a TLS record
/// by construction, so it skips the check. The `passthrough/out_of_scope` row
/// is then opened and the two streams relayed byte for byte — whatever `client`
/// has buffered (the peeked record, a ClientHello sent before the
/// acknowledgement, the record a raw-TLS connection opened with) goes first —
/// until either side closes; the row closes with the bytes moved and its
/// duration. The client completes TLS with the origin's own certificate;
/// nothing inside the tunnel becomes a row.
async fn relay_out_of_scope(
    mut client: Prefixed<ByteStream>,
    ctx: &ModuleCtx,
    mut request: TunnelRequest,
    connect: bool,
) -> Result<()> {
    let dialled = async {
        let target = Target::from_authority(&request.authority).await?;
        let upstream = ctx
            .connect_upstream(&target.authority(), target.addr)
            .await?;
        anyhow::Ok((target, upstream))
    }
    .await;
    let (target, mut upstream) = match dialled {
        Ok(dialled) => dialled,
        Err(e) => {
            fail_tunnel(ctx, request, TunnelReason::UpstreamUnreachable).await;
            return Err(e);
        }
    };
    request.server = Some(ConnInfo {
        peer: target.addr,
        sni: Some(target.host),
        alpn: None,
        tls: true,
        established: SystemTime::now(),
    });
    if connect {
        match first_byte_after_ack(&mut client).await {
            Ok(Some(TLS_HANDSHAKE)) => request.client.tls = true,
            Ok(Some(other)) => {
                let authority = request.authority.to_string();
                fail_tunnel(ctx, request, TunnelReason::ProtocolError).await;
                let _ = client.shutdown().await;
                bail!(
                    "refused to relay {authority}: the first byte inside the tunnel is \
                     {other:#04x}, not a TLS handshake record"
                );
            }
            Ok(None) => {
                // EOF — or silence for `FIRST_BYTE_TIMEOUT` — before the first
                // byte: the same row; both sockets shut so neither the dialled
                // origin nor a silent client is left waiting on the other.
                fail_tunnel(ctx, request, TunnelReason::ClientClosed).await;
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Ok(());
            }
            Err(e) => {
                let err = anyhow::Error::from(e);
                fail_tunnel(ctx, request, classify_client_failure(&err)).await;
                return Err(err);
            }
        }
    }
    let row = TunnelRow::open(
        ctx,
        request,
        TunnelInfo::passthrough(TunnelReason::OutOfScope),
    )
    .await;
    let mut client: ByteStream = Box::pin(client);
    let (counts, relayed) = relay(&mut client, &mut upstream).await;
    row.close(ctx, Some(counts)).await;
    relayed.map_err(Into::into)
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
    /// The CONNECT authority, when the connection is a tunnel. A tunnel's route
    /// is its CONNECT target: the `Host` of a request inside it is forwarded
    /// untouched and never chooses where the tunnel connects.
    pub(crate) tunnel_authority: Option<String>,
    /// Where `tunnel_authority` resolved to when the tunnel was opened. Set
    /// together with it, and dialed as is, never re-resolved, so a changed DNS
    /// answer (or an authority string that cannot be parsed back, such as an
    /// IPv6 literal) cannot redirect the tunnel.
    pub(crate) tunnel_addr: Option<SocketAddr>,
    pub(crate) client_conn: ConnInfo,
    pub(crate) server_conn: Option<ConnInfo>,
    /// The signing identifier of the client process, as the capture backend that
    /// delivered this connection observed it (the hint's `peer_identity`). `None`
    /// on a proxied connection. Stamped on every flow the connection carries.
    pub(crate) source_app: Option<String>,
    /// The capture backend that delivered this connection (the hint's
    /// `capture_interface`). `None` on a proxied connection.
    pub(crate) capture_interface: Option<String>,
    /// Spec D4: the flows on this connection are observed only, nothing acts on
    /// them. Always `false` on a tunnel connection (`tunnel_authority` set): the
    /// tunnel was in Scope when it was admitted and the decision is per
    /// connection, so its inner requests stay acted on even after
    /// `scope.remove`. On a forward-proxy cleartext connection [`serve`]
    /// recomputes it per request, before the flow is stored, since a keep-alive
    /// connection may carry requests for several hosts.
    pub(crate) passive: bool,
}

impl Conn {
    /// A cleartext connection. `tunnel` is the `CONNECT` authority and the
    /// address it resolved to, for a connection inside a tunnel, and `None` for
    /// a forward-proxy connection. No capture attribution; see
    /// [`Conn::with_attribution`]. Starts acted on (`passive == false`); a
    /// forward-proxy connection is re-stamped per request by [`serve`].
    fn plain(peer: SocketAddr, tunnel: Option<(String, SocketAddr)>) -> Self {
        let (tunnel_authority, tunnel_addr) = match tunnel {
            Some((authority, addr)) => (Some(authority), Some(addr)),
            None => (None, None),
        };
        Self {
            scheme: "http".to_string(),
            tunnel_authority,
            tunnel_addr,
            client_conn: ConnInfo {
                peer,
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            },
            server_conn: None,
            source_app: None,
            capture_interface: None,
            passive: false,
        }
    }

    /// Take the capture attribution the acceptor's hint carries (`peer_identity`,
    /// `capture_interface`). With no hint, or a hint from the explicit-proxy path,
    /// both stay `None`.
    fn with_attribution(mut self, hint: Option<&NextLayerHint>) -> Self {
        if let Some(h) = hint {
            self.source_app = h.peer_identity.clone();
            self.capture_interface = h.capture_interface.clone();
        }
        self
    }

    /// A fresh [`FlowMeta`] for a flow on this connection: exactly the capture
    /// attribution and the passive stamp (spec D4) are carried over; marks,
    /// comment, replay flag and timing are the flow's own.
    pub(crate) fn flow_meta(&self) -> FlowMeta {
        FlowMeta {
            passive: self.passive,
            ..FlowMeta::with_attribution(self.source_app.clone(), self.capture_interface.clone())
        }
    }
}

/// Spec D4: whether a cleartext forward-proxy request to `authority`
/// (`host[:port]`, port 80 when absent) is observed only. In the live Scope it
/// is acted on; outside it, or not an authority at all (nothing could be in
/// Scope), it is passive.
fn cleartext_is_passive(ctx: &ModuleCtx, authority: &str) -> bool {
    match Authority::parse_with_default(authority, DEFAULT_HTTP_PORT) {
        Ok(authority) => !ctx.in_scope(&authority.to_string()),
        Err(_) => true,
    }
}

/// Serve HTTP exchanges between `client` and `upstream` until either side
/// closes, or until a 101 hands both streams to the upgraded protocol's
/// module. With no `upstream`, one is opened.
///
/// A tunnel's route is its `CONNECT` target. On a connection inside a tunnel
/// (`conn.tunnel_authority` and `conn.tunnel_addr` set) every dial, the first
/// and every replacement, goes to the address the tunnel resolved to when it was
/// opened, through the connector, whatever `Host` the requests carry. Without a
/// tunnel (cleartext forward proxy) the upstream is the request's own authority,
/// opened for the first request and reopened when the authority changes.
///
/// An upstream the origin closed while the client idled is replaced before the
/// next request is forwarded on it, and so is one whose origin sent bytes after
/// a completed response (those bytes are discarded, never forwarded or parsed).
/// `reconnect` is how a TLS tunnel (which hands in an already-handshaken
/// `upstream`) redoes its TLS connection; the cleartext paths pass `None` and
/// redial through the ordinary connect step, which for a cleartext tunnel dials
/// the `CONNECT` target again.
///
/// The proxy answers a `100-continue` expectation itself, at head time: once the
/// head is parsed and its flow stored, and before `Event::RequestHeaders` is
/// dispatched or any body byte is read, it writes `100 Continue` to the client
/// (see `Http1Machine::expects_continue` for when). A head that declares a body
/// larger than `max_body` is refused with the `413` instead, with no `100`. The
/// `Expect` header itself is forwarded to the origin untouched, with the whole
/// body in one write, and the origin's own optional `100` is skipped.
///
/// The trailer section of a chunked response is forwarded after the body when
/// the client-bound body is chunk-framed (never after a body a plugin replaced,
/// and without the fields that cannot work as trailers), and is stored on the
/// flow's response, every field of it, when the response completes: before
/// `Event::Response`, so a plugin reads it there, and never merged into the
/// headers. A section over its caps ends the connection with an error, with the
/// terminator unwritten, so the client sees an incomplete message.
///
/// A response that ends early once its head is stored (the origin closed or
/// timed out, sent bytes the machine refused, failed with an I/O error, or the
/// client went away mid-body) is stored as a truncated, finished response
/// holding the bytes captured so far, before any error about it is dispatched
/// or returned (`FlowStore::abandon_response`); nothing changes on the wire.
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
    // Set when the origin sent bytes after a completed response on a connection
    // that stays open (one that closes anyway needs no replacing). The framing of
    // that upstream can no longer be trusted, so the next request must not ride
    // it; it is replaced through the same path as a closed upstream.
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
                        // Spec D4: a forward-proxy request is passive when its
                        // host is outside the live Scope, decided per request. A
                        // tunnel's requests inherit the tunnel's decision instead.
                        if conn.tunnel_authority.is_none() {
                            conn.passive = cleartext_is_passive(ctx, &authority);
                        }
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
                            metadata: conn.flow_meta(),
                            intercept: InterceptState::Observed,
                        }));
                        // A client that sent `Expect: 100-continue` holds its body
                        // back until it is told to go ahead. Tell it here, before
                        // `Event::RequestHeaders` is dispatched, so a plugin that
                        // parks the flow at its head cannot leave the client
                        // waiting. The machine reports the expectation at most once
                        // per request, so this cannot write a second interim.
                        if machine.expects_continue() {
                            // The machine's own parse of `Content-Length`, so this
                            // decision cannot drift from the framing it applies. It
                            // has already rejected a malformed or conflicting value
                            // before the head got here, so `None` means no length.
                            let declared = machine
                                .request()
                                .and_then(|r| content_length(&r.headers).ok().flatten());
                            if declared.is_some_and(|n| n > max_body as u64) {
                                // The body would be refused anyway: say nothing, so
                                // the client does not upload it. The oversize branch
                                // below writes the 413 and closes.
                                request_oversized = true;
                            } else {
                                machine.enqueue_continue();
                                if flush(&mut machine, Side::Client, &mut client)
                                    .await
                                    .is_err()
                                {
                                    // The client went away; nothing to report.
                                    return Ok(());
                                }
                            }
                        }
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

        // A Map Remote rewrite cannot retarget a request inside a tunnel: it goes
        // to the `CONNECT` target. Say so, once per request, so the rewrite is not
        // silently lost. This only reports; the route is chosen below.
        //
        // Cleartext tunnels only (`Conn::plain`'s scheme). A TLS tunnel keeps its
        // existing behaviour, and `differs_from_tunnel_target` assumes port 80 for
        // an authority with no port, which would report a same-host rewrite to an
        // https URL as ignored; a port-aware comparison would be needed first.
        if conn.scheme == "http" {
            if let Some(tunnel) = conn.tunnel_authority.as_deref() {
                let map_remote = flow.metadata.marks.iter().any(|m| m == MAP_REMOTE_MARK);
                if map_remote && differs_from_tunnel_target(&request.authority, tunnel) {
                    tracing::warn!(
                        tunnel = tunnel,
                        "a Map Remote rewrite is ignored inside a CONNECT tunnel; the request goes to the CONNECT target"
                    );
                }
            }
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
                // Cleartext: the ordinary connect step below dials the new
                // connection (a tunnel's `CONNECT` target, else the request's
                // authority).
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
            // `dial` is the authority remembered for the authority-change check,
            // `connector_authority` the one handed to the connector's scope and
            // SSRF check, `addr` where the connection goes.
            let (dial, connector_authority, addr) = match (&conn.tunnel_authority, conn.tunnel_addr)
            {
                // A tunnel dials its `CONNECT` target at the address recorded
                // when it was opened: never the request's `Host` (which may
                // be anything the client or a plugin set), and never
                // re-resolved. This is what a TLS tunnel does too.
                (Some(tunnel), Some(addr)) => {
                    // Only the tunnel's authority is logged: the request's own
                    // is client-supplied text (a URL's userinfo among it).
                    if differs_from_tunnel_target(&request.authority, tunnel) {
                        tracing::debug!(
                            tunnel = tunnel.as_str(),
                            "a request's authority differs from the CONNECT target; dialing the target"
                        );
                    }
                    (tunnel.clone(), tunnel.clone(), addr)
                }
                // A tunnel with no resolved address cannot say where it goes.
                // Falling through to the request's `Host` would let it choose
                // the upstream, so refuse instead. No constructor builds this
                // state; this arm keeps a later edit from reaching it silently.
                (Some(_), None) => {
                    bail!(
                        "tunnel has no resolved CONNECT address; refusing to dial the request Host"
                    )
                }
                // Forward proxy: the request's own authority is the route.
                (None, _) => {
                    let target = Target::resolve(&request.authority, 80).await?;
                    (request.authority.clone(), target.authority(), target.addr)
                }
            };
            upstream = Some(ctx.connect_upstream(&connector_authority, addr).await?);
            current_authority = Some(dial);
            let server_conn = ConnInfo {
                peer: addr,
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
        // The fixed words of the typed error a failed response owes event
        // consumers, set by the two exits that dispatch one (the origin closing
        // early; bytes the machine refused). The other exits dispatch none.
        let mut fault: Option<&'static str> = None;
        // Every exit of the loop, `?` and `bail!` alike, lands after this block,
        // so a response that ended early is finalised in the store before the
        // error about it is dispatched or returned.
        let forwarded = async {
            while !done {
                let n = match tokio::time::timeout(READ_TIMEOUT, up.read(&mut buf)).await {
                    Ok(r) => r?,
                    Err(_) => bail!("upstream read timed out"),
                };
                let events = if n == 0 {
                    machine.on_eof(Side::Server)
                } else {
                    match machine.on_bytes(Side::Server, &buf[..n]) {
                        Ok(events) => events,
                        Err(e) => {
                            // The machine refused the origin's bytes (a bad trailer
                            // line, an over-cap section, malformed framing). Event
                            // consumers see a response only through its events, so
                            // one is owed once the store is finalised below; the
                            // words are fixed because the machine's own text can
                            // quote the origin's bytes.
                            fault = Some("malformed response from upstream");
                            return Err(e);
                        }
                    }
                };
                for ev in events {
                    match ev {
                        HttpSansIoEvent::ResponseHeaders(id) => {
                            let Some(head) = machine.response().cloned() else {
                                bail!("ResponseHeaders without a parsed response");
                            };
                            response_close = wants_close(&head.headers)
                                || close_delimited(&request.method, &head);
                            let streamed = HttpResponse {
                                body: Body::Streamed(StreamBody),
                                // A response that arrived in one read already has its
                                // trailer section on the machine's model. The stored
                                // head holds none until `ResponseComplete` stores
                                // them, so a plugin sees the same at this event
                                // however the origin's bytes were split.
                                trailers: HeaderMap::new(),
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
                            // The trailer section the origin sent after a chunked
                            // body, parsed and bounded by the machine, which holds it
                            // on its response model by now. Empty for any other body.
                            let trailers = machine
                                .response()
                                .map(|r| r.trailers.clone())
                                .unwrap_or_default();
                            if forward_chunks {
                                // Only a chunk-framed client body has a section to put
                                // them in, and the writer withholds the fields that
                                // cannot work as trailers. A plugin that replaced the
                                // body (`forward_chunks` false) gets none of them.
                                let withheld =
                                    machine.enqueue_body_end_with_trailers(Side::Client, &trailers);
                                flush(&mut machine, Side::Client, &mut client).await?;
                                if withheld > 0 {
                                    // A count only: trailer names and values are the
                                    // origin's bytes and never go in a log.
                                    tracing::debug!(
                                        withheld,
                                        "trailer fields were not forwarded to the client"
                                    );
                                }
                            }
                            let mut bytes = Some(std::mem::take(&mut captured));
                            let mut trailers = Some(trailers);
                            ctx.store().update(id, &mut |f: &mut Flow| {
                                if let (Flow::Http(h), Some(bytes)) = (f, bytes.take()) {
                                    if let Some(resp) = h.response.as_mut() {
                                        resp.body = if bytes.is_empty() {
                                            Body::Empty
                                        } else {
                                            Body::Bytes(bytes)
                                        };
                                        // The capture keeps every field the origin
                                        // sent, whether or not it was forwarded, and
                                        // replaces whatever a plugin left here.
                                        resp.trailers = trailers.take().unwrap_or_default();
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
                    // The transport failure reaches the typed error bus once the
                    // store is finalised below, in the same words as the error.
                    let words = "upstream closed before completing the response";
                    fault = Some(words);
                    bail!(words);
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(e) = forwarded {
            // However the response ended (the origin closed or timed out, its
            // bytes were refused, an I/O error on either side), the bytes captured
            // so far, bounded by `max_body` like a completed body, become the
            // stored body and the response is marked truncated, so the flow is
            // terminal for `flow.clear` and eviction and `flow.get` reports a
            // size. With no head stored yet this changes nothing. The store is
            // final before the error is dispatched, so a push or refetch built on
            // that event sees the finished flow.
            ctx.store().abandon_response(id, captured);
            if let Some(words) = fault {
                ctx.emit(Event::Error {
                    flow: id,
                    kind: aitm_core::FlowError::Upstream(words.to_string()),
                })
                .await;
            }
            return Err(e);
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
                // The re-dispatched module sees the same attribution this
                // connection's flows were stamped with.
                peer_identity: conn.source_app.clone(),
                capture_interface: conn.capture_interface.clone(),
            };
            let client_io: ByteStream = Box::pin(Prefixed::with_prefix(client, client_rest));
            let upstream_io: ByteStream = Box::pin(Prefixed::with_prefix(upstream_io, server_rest));
            return ctx.handoff_upgrade(client_io, upstream_io, id, hint).await;
        }
        // The response is complete and already forwarded. Surplus is handled after
        // this close check on purpose: a connection that ends anyway replaces
        // nothing, so it has nothing to warn about. On one that stays open, bytes
        // the origin left behind this response (still unparsed in the machine) are
        // dropped unread and taint the upstream. Never set `upstream = None` here;
        // the replacement must go through the stale path above.
        if request_close || response_close {
            let _ = client.shutdown().await;
            return Ok(());
        }
        let surplus = machine.take_leftover(Side::Server);
        if !surplus.is_empty() {
            tracing::warn!(
                authority = current_authority.as_deref().unwrap_or_default(),
                bytes = surplus.len(),
                "origin sent bytes after a completed response; discarding them and replacing the upstream connection"
            );
            upstream_tainted = true;
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
        trailers: HeaderMap::new(),
        body: Body::Bytes(b"request body exceeds the configured limit".to_vec()),
        timestamp: SystemTime::now(),
        peer: None,
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

/// What a `CONNECT` head says: the authority token as the client wrote it (not
/// yet parsed as an [`Authority`]) and the request headers.
struct ConnectHead {
    authority: String,
    headers: HeaderMap,
}

/// Parse a CONNECT head: the authority token of its request line and its
/// headers. A header line that is not a valid field is left out of the row
/// rather than failing the tunnel over it; the authority is what matters.
fn parse_connect(head: &[u8]) -> Result<ConnectHead> {
    let text = std::str::from_utf8(head).context("non-UTF-8 CONNECT head")?;
    let mut lines = text.lines();
    let line = lines.next().unwrap_or("");
    let mut parts = line.split(' ');
    let authority = match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(authority)) if !authority.is_empty() => authority.to_string(),
        _ => bail!("malformed CONNECT line {line:?}"),
    };
    let mut headers = HeaderMap::new();
    for field in lines.take_while(|l| !l.is_empty()) {
        if let Some((name, value)) = field.split_once(':') {
            // Wire input: `try_set` validates; an invalid field is simply not
            // part of the row.
            let _ = headers.try_set(name.trim(), value.trim());
        }
    }
    Ok(ConnectHead { authority, headers })
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

    /// Resolve a normalised tunnel authority: an IP literal needs no lookup; a
    /// name takes the first address the resolver returns.
    async fn from_authority(authority: &Authority) -> Result<Self> {
        let addr = match authority.ip() {
            Some(ip) => SocketAddr::new(ip, authority.port),
            None => tokio::net::lookup_host((authority.host.as_str(), authority.port))
                .await
                .with_context(|| format!("resolve {authority}"))?
                .next()
                .ok_or_else(|| anyhow!("no address for {authority}"))?,
        };
        Ok(Self {
            host: authority.host.clone(),
            port: authority.port,
            addr,
        })
    }

    /// `host:port` as [`Authority`] prints it: brackets around an IPv6 literal,
    /// the host lowercased. This is the string handed to the connector's scope
    /// and SSRF check, which parses it back through `Authority`, and the one the
    /// passthrough module hands its connector (spec D2: both modules compute the
    /// same string); a bracket-less `::1:8443` would read as an IPv6 host with
    /// no port and be refused as out of scope.
    fn authority(&self) -> String {
        Authority::new(&self.host, self.port).to_string()
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

/// Whether `request`, the authority a request names, is a different origin than
/// `tunnel`, the `CONNECT` target of the tunnel it arrived in: compared
/// case-insensitively, with port 80 assumed where one is absent. Only log lines
/// read this; where a tunnel connects never depends on it. An IPv6-literal
/// tunnel keeps its brackets (`Target::authority` prints through `Authority`),
/// so `split_host_port` reads both sides the same way.
fn differs_from_tunnel_target(request: &str, tunnel: &str) -> bool {
    let origin = |authority: &str| {
        split_host_port(authority, 80)
            .ok()
            .map(|(host, port)| (host.to_ascii_lowercase(), port))
    };
    match (origin(request), origin(tunnel)) {
        (Some(request), Some(tunnel)) => request != tunnel,
        // Not splittable (a malformed `Host`): compare the strings.
        _ => !request.eq_ignore_ascii_case(tunnel),
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

    /// Buffer the first TLS record whole — its 5-byte header declares its
    /// payload length — capped at `max`, and return the buffer. Fewer bytes only
    /// at EOF; a buffer that does not even hold a record header is returned as
    /// is. Nothing is consumed: the record is still the first thing read.
    async fn peek_tls_record(&mut self, max: usize) -> io::Result<&[u8]> {
        const HEADER: usize = 5;
        let total = match self.peek(HEADER).await? {
            [_, _, _, hi, lo, ..] => HEADER + usize::from(u16::from_be_bytes([*hi, *lo])),
            _ => HEADER,
        };
        self.peek(total.min(max)).await
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

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::Mutex;
    use std::time::Duration;

    use aitm_core::{FlowStore, MemFlowStore, Verdict};
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

    /// A context over `store` and `sink` whose connector is a [`StubConnector`]
    /// holding `streams`, plus the log of what it was asked to dial.
    fn ctx_with_sink(
        streams: Vec<ByteStream>,
        store: Arc<MemFlowStore>,
        sink: Arc<dyn EventSink>,
    ) -> (ModuleCtx, DialLog) {
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let connector = StubConnector {
            dialed: dialed.clone(),
            streams: Mutex::new(streams),
        };
        (ModuleCtx::new(store, sink, Arc::new(connector)), dialed)
    }

    /// A context whose connector is a [`StubConnector`] holding `streams`, plus
    /// the log of what it was asked to dial.
    fn ctx_with(streams: Vec<ByteStream>) -> (ModuleCtx, DialLog) {
        ctx_with_sink(streams, Arc::new(MemFlowStore::new()), Arc::new(NoSink))
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
        let sink = Arc::new(RecordingSink {
            events: Mutex::new(Vec::new()),
        });
        let (ctx, dialed) = ctx_with_sink(streams, Arc::new(MemFlowStore::new()), sink.clone());
        (ctx, dialed, sink)
    }

    /// Rewrites a flow's authority and `Host` header to `to` when its request is
    /// dispatched, and marks the flow `map-remote`, as Map Remote does. Shares
    /// `store` with the context it is built into, so the rewrite lands in what
    /// `serve` reads back.
    struct RewriteSink {
        store: Arc<MemFlowStore>,
        to: &'static str,
    }

    impl EventSink for RewriteSink {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            if let Event::Request(id) = ev {
                self.store.update(id, &mut |f: &mut Flow| {
                    if let Flow::Http(h) = f {
                        h.request.authority = self.to.to_string();
                        h.request.headers.set("Host", self.to);
                        h.metadata.marks.push("map-remote".to_string());
                    }
                });
            }
            Box::pin(async { Verdict::Continue })
        }
    }

    /// Like [`ctx_with`], with a [`RewriteSink`] that retargets and marks every
    /// request, rewriting it to `to`.
    fn ctx_rewriting(streams: Vec<ByteStream>, to: &'static str) -> (ModuleCtx, DialLog) {
        let store = Arc::new(MemFlowStore::new());
        let sink = Arc::new(RewriteSink {
            store: store.clone(),
            to,
        });
        ctx_with_sink(streams, store, sink)
    }

    fn origin_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 8443)
    }

    /// `origin.test:8443` as a tunnel: where it resolved ([`origin_addr`]) and
    /// the row request `drive` would have handed `mitm` for it — a TLS tunnel
    /// from an unknown peer, nothing dialled yet.
    fn origin_tunnel() -> (Target, TunnelRequest) {
        let now = SystemTime::now();
        (
            Target {
                host: "origin.test".into(),
                port: 8443,
                addr: origin_addr(),
            },
            TunnelRequest {
                authority: Authority::new("origin.test", 8443),
                headers: HeaderMap::new(),
                client: ConnInfo {
                    peer: unknown_peer(),
                    sni: None,
                    alpn: None,
                    tls: true,
                    established: now,
                },
                server: None,
                opened_at: now,
                source_app: None,
                capture_interface: None,
            },
        )
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

        let (target, request) = origin_tunnel();
        let result = tokio::time::timeout(
            STALL_GUARD,
            module.mitm(Prefixed::new(proxy_side), ctx, target, request),
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

    /// A bodiless GET for `path` whose only header is `Host: host`. A test that
    /// needs another header (`Connection: close`), or no `Host`, writes its
    /// request out itself.
    fn get_request(path: &str, host: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")
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
        client_send_keep(io, pending, &get_request(target, host)).await
    }

    /// Send `request` exactly as given (so a test can leave out a header
    /// [`client_get`] always sends), then read the answer as [`client_get_keep`]
    /// does.
    async fn client_send_keep(
        io: &mut DuplexStream,
        pending: &mut Vec<u8>,
        request: &str,
    ) -> String {
        io.write_all(request.as_bytes()).await.expect("send");
        read_response_keep(io, pending).await
    }

    /// Read one 200 response, consuming `pending` before the stream, and return
    /// its `Content-Length`-framed body. Bytes read past it stay in `pending`.
    async fn read_response_keep(io: &mut DuplexStream, pending: &mut Vec<u8>) -> String {
        let (status, body) = read_status_response_keep(io, pending).await;
        assert_eq!(status, 200, "unexpected response status, body {body:?}");
        body
    }

    // ---- `Expect: 100-continue` helpers -----------------------------------

    /// A strict client's head: five body bytes to come, and an expectation to be
    /// answered first. `Content-Length` precedes `Expect` here; the machine
    /// re-appends the length last when it forwards the request.
    const STRICT_HEAD: &str = "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";

    /// The interim the proxy itself writes.
    const CONTINUE: &str = "HTTP/1.1 100 Continue\r\n\r\n";

    /// A keep-alive 200 with a two-byte body, as an origin writes it and as the
    /// proxy forwards it.
    const REPLY_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    /// What the origin must receive for [`STRICT_HEAD`] followed by `hello`: head
    /// and body together, `Expect` untouched, the length last.
    const FORWARDED_STRICT: &str = "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello";

    /// The body of the proxy's own `413`.
    const OVERSIZED_BODY: &str = "request body exceeds the configured limit";

    /// Read one head (up to and including the blank line) from `io`, a byte at a
    /// time so nothing past it is consumed. `None` when no complete head arrives
    /// within `within`; a partial head at that point, or EOF, panics.
    async fn read_interim(io: &mut DuplexStream, within: Duration) -> Option<String> {
        let mut got: Vec<u8> = Vec::new();
        let reading = async {
            let mut byte = [0u8; 1];
            while !got.ends_with(b"\r\n\r\n") {
                let n = io.read(&mut byte).await.expect("read a head");
                assert!(n > 0, "connection closed while reading a head: {got:?}");
                got.push(byte[0]);
            }
        };
        let complete = tokio::time::timeout(within, reading).await.is_ok();
        assert!(
            complete || got.is_empty(),
            "only part of a head arrived: {got:?}"
        );
        complete.then(|| String::from_utf8_lossy(&got).into_owned())
    }

    /// Read exactly `n` bytes from `io`.
    async fn read_exact_bytes(io: &mut DuplexStream, n: usize) -> Vec<u8> {
        let mut got = vec![0u8; n];
        io.read_exact(&mut got).await.expect("read exact bytes");
        got
    }

    /// Assert that no byte arrives on `io` within `within`. EOF counts as a
    /// failure: every caller expects the connection to stay open.
    async fn assert_quiet(io: &mut DuplexStream, within: Duration) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(within, io.read(&mut byte)).await {
            Err(_) => {}
            Ok(Ok(0)) => panic!("the connection closed when it was expected to stay quiet"),
            Ok(Ok(_)) => panic!("an unexpected byte arrived: {:?}", byte[0]),
            Ok(Err(e)) => panic!("read failed: {e}"),
        }
    }

    /// Like [`read_response_keep`], for any status: returns the status and the
    /// `Content-Length`-framed body, and leaves bytes read past them in `pending`.
    async fn read_status_response_keep(
        io: &mut DuplexStream,
        pending: &mut Vec<u8>,
    ) -> (u16, String) {
        let mut chunk = [0u8; 512];
        loop {
            if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&pending[..end]).to_ascii_lowercase();
                let status: u16 = head
                    .split(' ')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .expect("response status");
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.parse().ok())
                    .expect("response Content-Length");
                if pending.len() >= end + 4 + len {
                    let body =
                        String::from_utf8_lossy(&pending[end + 4..end + 4 + len]).into_owned();
                    pending.drain(..end + 4 + len);
                    return (status, body);
                }
            }
            let n = io.read(&mut chunk).await.expect("read response");
            assert!(n > 0, "connection closed before a full response arrived");
            pending.extend_from_slice(&chunk[..n]);
        }
    }

    /// An in-memory origin that records everything it receives into `seen`. For
    /// each of `exchanges` it reads one request head and its `Content-Length`
    /// body, and only then writes that exchange's reply segments, with a pause
    /// between them so the proxy reads them separately. After the last exchange it
    /// holds the connection open until the proxy hangs up.
    async fn origin_replying<S: AsRef<str>>(
        mut io: DuplexStream,
        seen: Arc<Mutex<Vec<u8>>>,
        exchanges: Vec<Vec<S>>,
    ) {
        let mut held: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 512];
        for segments in exchanges {
            let request_len = loop {
                if let Some(end) = held.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&held[..end]).to_ascii_lowercase();
                    let body_len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if held.len() >= end + 4 + body_len {
                        break end + 4 + body_len;
                    }
                }
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        seen.lock()
                            .expect("seen lock")
                            .extend_from_slice(&chunk[..n]);
                        held.extend_from_slice(&chunk[..n]);
                    }
                }
            };
            held.drain(..request_len);
            for (i, segment) in segments.iter().enumerate() {
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                if io.write_all(segment.as_ref().as_bytes()).await.is_err()
                    || io.flush().await.is_err()
                {
                    return;
                }
            }
        }
        while let Ok(n) = io.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            seen.lock()
                .expect("seen lock")
                .extend_from_slice(&chunk[..n]);
        }
    }

    /// Parks every `Event::RequestHeaders` until `release` fires, as a plugin
    /// that holds a flow at its head would. `entered` is set when the proxy
    /// reaches the park, `released` when the park ends. Every other event passes.
    struct ParkRequestHeaders {
        release: Arc<tokio::sync::Notify>,
        entered: Arc<AtomicBool>,
        released: Arc<AtomicBool>,
    }

    impl EventSink for ParkRequestHeaders {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            if matches!(ev, Event::RequestHeaders(_)) {
                return Box::pin(async move {
                    self.entered.store(true, AtomicOrdering::SeqCst);
                    self.release.notified().await;
                    self.released.store(true, AtomicOrdering::SeqCst);
                    Verdict::Continue
                });
            }
            Box::pin(async { Verdict::Continue })
        }
    }

    /// Run `serve` on `conn` over a fresh in-memory client connection and run
    /// `script` against the client end, which `script` owns: dropping it hangs up
    /// and lets `serve` finish. Returns `serve`'s result and the script's value.
    async fn with_serve<T, F, Fut>(
        ctx: &ModuleCtx,
        conn: Conn,
        upstream: Option<ByteStream>,
        max_body: usize,
        script: F,
    ) -> (Result<()>, T)
    where
        F: FnOnce(DuplexStream) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let (client, proxy_side) = duplex(64 * 1024);
        let serving = serve(ctx, Box::pin(proxy_side), upstream, None, conn, max_body);
        tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script(client)) })
            .await
            .expect("serve hung")
    }

    /// What one client and its origin saw in a [`head_first_exchange`].
    struct HeadFirst {
        /// The head the client read before it sent any body, if one came in time.
        interim: Option<String>,
        status: u16,
        body: String,
        /// Bytes the client read past the final response.
        pending: Vec<u8>,
        /// Everything the origin received, as text.
        origin_saw: String,
    }

    /// A cleartext forward-proxy exchange in which the client sends `head` alone,
    /// waits up to `within` for a head from the proxy, then sends `body` and reads
    /// the final response. The one in-memory origin answers `reply`.
    async fn head_first_exchange(
        head: &str,
        within: Duration,
        body: &[u8],
        reply: &'static str,
    ) -> HeadFirst {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![reply]],
        ));
        let (served, (interim, status, body, pending)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client.write_all(head.as_bytes()).await.expect("send head");
                let interim = read_interim(&mut client, within).await;
                client.write_all(body).await.expect("send body");
                let mut pending = Vec::new();
                let (status, body) = read_status_response_keep(&mut client, &mut pending).await;
                (interim, status, body, pending)
            },
        )
        .await;
        served.expect("serve ends cleanly when the client hangs up");
        let origin_saw =
            String::from_utf8_lossy(&origin_saw.lock().expect("seen lock")).into_owned();
        HeadFirst {
            interim,
            status,
            body,
            pending,
            origin_saw,
        }
    }

    /// A `POST /up` head with `Content-Length: 5` and `extra` header lines (each
    /// ending in CRLF) after it.
    fn post_head(extra: &str) -> String {
        format!("POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 5\r\n{extra}\r\n")
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
            tunnel_addr: Some(origin_addr()),
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
            source_app: None,
            capture_interface: None,
            passive: false,
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
        let conn = Conn::plain(
            unknown_peer(),
            Some((
                "127.0.0.1:8080".to_string(),
                "127.0.0.1:8080".parse().expect("addr"),
            )),
        );

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
                .write_all(get_request("/two", "origin.test:8443").as_bytes())
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

        let (bodies, leftovers) = serve_requests_keep(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            None,
            &[
                get_request("http://127.0.0.1:8080/one", "127.0.0.1:8080"),
                get_request("http://127.0.0.1:8080/two", "127.0.0.1:8080"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["legit", "second"]);
        assert_eq!(
            leftovers,
            vec!["", ""],
            "the stray response must not reach the client, after either answer"
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

        // The helper fails the test if the second answer carries the status line
        // of the head fragment (500) instead of a 200.
        let (bodies, leftovers) = serve_requests_keep(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            None,
            &[
                get_request("http://127.0.0.1:8080/one", "127.0.0.1:8080"),
                get_request("http://127.0.0.1:8080/two", "127.0.0.1:8080"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["first", "second"]);
        assert_eq!(leftovers, vec!["", ""]);
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

        let (bodies, leftovers) = serve_requests_keep(
            &ctx,
            tunnel_conn(),
            Some(first_up),
            Some(reconnect_to(&module)),
            &[
                get_request("/one", "origin.test:8443"),
                get_request("/two", "origin.test:8443"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["legit", "second"]);
        assert_eq!(leftovers, vec!["", ""]);
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
                .write_all(get_request("/two", "origin.test:8443").as_bytes())
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            (first, pending, got)
        };
        let (served, (first, pending, got)) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
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

    // ---- a cleartext tunnel dials its CONNECT target ----------------------

    /// A cleartext `CONNECT` tunnel opened to `authority`, which resolved to
    /// `addr`, as `drive` sets it up.
    fn cleartext_tunnel_conn(authority: &str, addr: &str) -> Conn {
        Conn::plain(
            unknown_peer(),
            Some((authority.to_string(), addr.parse().expect("addr"))),
        )
    }

    /// Run `serve` on `conn` over a fresh in-memory client connection, send each
    /// of `requests` in turn, and return the answers' bodies, plus, for each, the
    /// bytes the client had read past it (as text). A response the proxy
    /// forwarded behind the real one shows up there, or as the next answer.
    /// `upstream` and `reconnect` are what a TLS tunnel hands `serve`; cleartext
    /// tests pass `None`. The client then hangs up; `serve` must end cleanly and
    /// in time, and a hang means a request went to an upstream that never answers.
    async fn serve_requests_keep(
        ctx: &ModuleCtx,
        conn: Conn,
        upstream: Option<ByteStream>,
        reconnect: Option<Reconnect<'_>>,
        requests: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let (mut client, proxy_side) = duplex(64 * 1024);
        let serving = serve(
            ctx,
            Box::pin(proxy_side),
            upstream,
            reconnect,
            conn,
            MAX_BODY,
        );
        let script = async {
            let mut pending = Vec::new();
            let (mut bodies, mut leftovers) = (Vec::new(), Vec::new());
            for request in requests {
                bodies.push(client_send_keep(&mut client, &mut pending, request).await);
                leftovers.push(String::from_utf8_lossy(&pending).into_owned());
            }
            // Hang up, so `serve` sees the client finish and returns.
            drop(client);
            (bodies, leftovers)
        };
        let (served, answers) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("serve hung: a request went to an upstream that never answers");
        served.expect("serve ends cleanly when the client hangs up");
        answers
    }

    /// [`serve_requests_keep`] on a cleartext connection, returning the bodies.
    async fn serve_requests(ctx: &ModuleCtx, conn: Conn, requests: &[String]) -> Vec<String> {
        serve_requests_keep(ctx, conn, None, None, requests).await.0
    }

    /// The stored HTTP flow whose request path is `path`.
    fn stored_http(ctx: &ModuleCtx, path: &str) -> HttpFlow {
        ctx.store()
            .list()
            .into_iter()
            .find_map(|id| match ctx.store().get(id) {
                Some(Flow::Http(f)) if f.request.path == path => Some(f),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no stored flow for {path}"))
    }

    /// One event an [`EventCapture`] saw: its level, its message, and every other
    /// field as `name -> text` (a string field as is, any other as its `Debug`
    /// text).
    #[derive(Debug)]
    struct Captured {
        level: tracing::Level,
        message: String,
        fields: BTreeMap<String, String>,
    }

    /// What an [`EventCapture`] has seen so far, in order.
    type Captures = Arc<Mutex<Vec<Captured>>>;

    /// Every event at or above `max` verbosity emitted on the thread that
    /// installed it. Hand-written on `tracing`'s own `Subscriber` trait so a test
    /// can pin what the proxy tells the operator without a capture dependency.
    struct EventCapture {
        max: tracing::Level,
        events: Captures,
    }

    /// Reads one event's fields, the `message` apart from the rest. A string
    /// field is kept as is, anything else as its `Debug` text.
    struct FieldsOf {
        message: String,
        fields: BTreeMap<String, String>,
    }

    impl FieldsOf {
        fn put(&mut self, field: &tracing::field::Field, text: String) {
            if field.name() == "message" {
                self.message = text;
            } else {
                self.fields.insert(field.name().to_string(), text);
            }
        }
    }

    impl tracing::field::Visit for FieldsOf {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.put(field, format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.put(field, value.to_string());
        }
    }

    impl tracing::Subscriber for EventCapture {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            // `Level` orders by verbosity: ERROR < WARN < INFO < DEBUG < TRACE.
            *metadata.level() <= self.max
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut seen = FieldsOf {
                message: String::new(),
                fields: BTreeMap::new(),
            };
            event.record(&mut seen);
            self.events.lock().expect("events lock").push(Captured {
                level: *event.metadata().level(),
                message: seen.message,
                fields: seen.fields,
            });
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Capture every event up to `max` verbosity on this thread until the guard
    /// drops. `#[tokio::test]` runs the test future on this thread, so it sees
    /// `serve`'s.
    fn capture_events(max: tracing::Level) -> (tracing::subscriber::DefaultGuard, Captures) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let guard = tracing::subscriber::set_default(EventCapture {
            max,
            events: events.clone(),
        });
        (guard, events)
    }

    /// A field set as [`Captured::fields`] holds it, from literal pairs.
    fn field_set(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn serve_dials_the_connect_target_not_the_host_header_in_a_cleartext_tunnel() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:9090")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "the tunnel goes to its CONNECT target, whatever the request's Host says"
        );
    }

    #[tokio::test]
    async fn serve_keeps_one_tunnel_connection_for_requests_naming_different_hosts() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first", "second"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[
                get_request("/one", "127.0.0.1:9090"),
                get_request("/two", "127.0.0.1:7070"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["first", "second"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "one tunnel, one upstream connection, dialed at the CONNECT target"
        );
    }

    #[tokio::test]
    async fn serve_records_the_host_authority_and_the_tunnel_peer_on_the_flow() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:9090")],
        )
        .await;

        let flow = stored_http(&ctx, "/one");
        assert_eq!(
            flow.request.authority, "127.0.0.1:9090",
            "the request keeps the authority the client sent"
        );
        assert_eq!(
            flow.server_conn.map(|c| c.peer),
            Some("127.0.0.1:8080".parse().expect("addr")),
            "the flow records where the traffic actually went"
        );
    }

    #[tokio::test]
    async fn a_plugin_authority_rewrite_does_not_retarget_a_cleartext_tunnel() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_rewriting(vec![Box::pin(up)], "127.0.0.1:9090");
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:8080")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "a rewritten authority must not choose the upstream of a tunnel"
        );
        assert_eq!(
            stored_http(&ctx, "/one").request.authority,
            "127.0.0.1:9090",
            "the stored flow keeps the rewritten authority"
        );
    }

    #[tokio::test]
    async fn serve_records_the_tunnel_authority_for_a_request_without_a_host() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &["GET /x HTTP/1.1\r\n\r\n".to_string()],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            stored_http(&ctx, "/x").request.authority,
            "127.0.0.1:8080",
            "a request with no Host is recorded under the tunnel's authority"
        );
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")]
        );
    }

    #[tokio::test]
    async fn serve_dials_the_connect_target_for_an_absolute_form_request_naming_another_origin() {
        // Both the request line and the `Host` name another origin, so neither a
        // request-target route nor a `Host` route would reach the tunnel's origin.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["from the tunnel"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request(
                "http://other.example:9090/x",
                "other.example:9090",
            )],
        )
        .await;

        assert_eq!(bodies, vec!["from the tunnel"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "the tunnel goes to its CONNECT target, whatever the request line says"
        );
    }

    #[tokio::test]
    async fn serve_keeps_a_request_target_userinfo_out_of_the_log() {
        // The absolute-form target carries `user:secret@` in front of the host, and
        // that string is the request's authority. It differs from the tunnel
        // target, which is what the debug log reports, and must not be in it.
        let (_guard, captured) = capture_events(tracing::Level::DEBUG);
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("http://user:secret@x/", "x")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        let captured = captured.lock().expect("events lock");
        assert!(
            !format!("{captured:?}").contains("secret"),
            "events: {captured:?}"
        );
        // The report itself is still made: the tunnel's authority, and nothing the
        // client wrote.
        let reports: Vec<&Captured> = captured
            .iter()
            .filter(|e| e.message.contains("differs from the CONNECT target"))
            .collect();
        assert_eq!(reports.len(), 1, "events: {captured:?}");
        assert_eq!(reports[0].level, tracing::Level::DEBUG);
        assert_eq!(
            reports[0].fields,
            field_set(&[("tunnel", "127.0.0.1:8080")])
        );
    }

    #[tokio::test]
    async fn serve_warns_once_when_a_map_remote_rewrite_is_ignored_in_a_tunnel() {
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        let (up, origin_end) = duplex(64 * 1024);
        // The sink rewrites the request to 127.0.0.1:9090 and marks it `map-remote`.
        let (ctx, dialed) = ctx_rewriting(vec![Box::pin(up)], "127.0.0.1:9090");
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:8080")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")],
            "the warning changes nothing about the route"
        );
        let warnings = warnings.lock().expect("warnings lock");
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(warnings[0].level, tracing::Level::WARN);
        assert!(
            warnings[0]
                .message
                .contains("Map Remote rewrite is ignored"),
            "message: {:?}",
            warnings[0].message
        );
        assert_eq!(
            warnings[0].fields,
            field_set(&[("tunnel", "127.0.0.1:8080")])
        );
    }

    #[tokio::test]
    async fn serve_does_not_warn_about_map_remote_for_an_unmarked_request_naming_another_host() {
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:9090")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        let warnings = warnings.lock().expect("warnings lock");
        assert!(
            warnings.is_empty(),
            "a differing Host without the mark is no Map Remote rewrite: {warnings:?}"
        );
    }

    #[tokio::test]
    async fn serve_does_not_warn_about_map_remote_when_the_rewrite_names_the_tunnel_target() {
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        let (up, origin_end) = duplex(64 * 1024);
        // Marked, but rewritten to the very origin the tunnel goes to: nothing is
        // ignored.
        let (ctx, _dialed) = ctx_rewriting(vec![Box::pin(up)], "127.0.0.1:8080");
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:9090")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        let warnings = warnings.lock().expect("warnings lock");
        assert!(
            warnings.is_empty(),
            "a rewrite to the tunnel target ignores nothing: {warnings:?}"
        );
    }

    /// The warning is for a cleartext tunnel. A TLS tunnel's behaviour is not
    /// changed here, and the comparison the warning rests on assumes port 80 for
    /// an authority with no port, which is the wrong default for it: `origin.test`
    /// rewritten from `origin.test:8443` would be reported as ignored when it
    /// names the same host.
    #[tokio::test]
    async fn serve_does_not_warn_about_map_remote_inside_a_tls_tunnel() {
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        // The first rewrite names the tunnel's own host without a port, the
        // second another origin altogether; neither may be reported.
        for rewrite_to in ["origin.test", "other.test:9090"] {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, dialed) = ctx_rewriting(Vec::new(), rewrite_to);
            let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

            let (bodies, _) = serve_requests_keep(
                &ctx,
                tunnel_conn(),
                Some(Box::pin(up)),
                None,
                &[get_request("/one", "origin.test:8443")],
            )
            .await;

            assert_eq!(bodies, vec!["first"], "rewritten to {rewrite_to}");
            assert!(
                dialed.lock().expect("dialed lock").is_empty(),
                "the TLS tunnel keeps the upstream it was handed: {rewrite_to}"
            );
            assert_eq!(
                stored_http(&ctx, "/one").request.authority,
                rewrite_to,
                "the sink's rewrite did land on the stored flow"
            );
        }
        let warnings = warnings.lock().expect("warnings lock");
        assert!(
            warnings.is_empty(),
            "a TLS tunnel reports no Map Remote rewrite: {warnings:?}"
        );
    }

    #[test]
    fn a_request_authority_differs_from_the_tunnel_target_only_by_origin() {
        let differs = differs_from_tunnel_target;
        // The same origin, spelled the way clients spell it.
        assert!(!differs("127.0.0.1:8080", "127.0.0.1:8080"));
        assert!(!differs("EXAMPLE.test:80", "example.test:80"));
        assert!(!differs("example.test", "example.test:80"));
        // A different port or host is a different origin.
        assert!(differs("example.test:8080", "example.test:80"));
        assert!(differs("example.test", "example.test:8080"));
        assert!(differs("other.test:80", "example.test:80"));
        // An authority that cannot be split falls back to a case-insensitive match.
        assert!(!differs("[::1", "[::1"));
        assert!(differs("[::1", "example.test:80"));
        // An IPv6-literal tunnel keeps its brackets (`Target::authority`), which
        // `split_host_port` reads back.
        assert!(!differs("[::1]:8080", "[::1]:8080"));
        assert!(differs("[::1]:9090", "[::1]:8080"));
    }

    /// `Target::authority()` prints like `Authority` (spec D2: both modules hand
    /// their connector the same string): an IPv6 literal keeps its brackets, so
    /// the guarded connector's `Authority::parse_with_default` reads `[::1]:8443`
    /// back as host `::1`, port 8443, not as a bracket-less IPv6 host with no
    /// port; IPv4 literals and names are unchanged, and a name is lowercased.
    #[test]
    fn target_authority_prints_like_authority() {
        let target = |host: &str, port: u16| Target {
            host: host.to_string(),
            port,
            addr: unknown_peer(),
        };
        assert_eq!(target("::1", 8443).authority(), "[::1]:8443");
        assert_eq!(target("127.0.0.1", 8443).authority(), "127.0.0.1:8443");
        assert_eq!(target("example.com", 443).authority(), "example.com:443");
        assert_eq!(target("Example.COM", 443).authority(), "example.com:443");
    }

    #[tokio::test]
    async fn serve_dials_an_ipv6_literal_tunnel_at_the_recorded_address() {
        // A tunnel dials the address recorded when it was opened, never one
        // derived from the request's `Host`, which here names another port so
        // the two would be told apart. The tunnel authority is the bracketed
        // `[::1]:8080` that `Target::authority()` writes (through `Authority`),
        // and that is what the connector is handed.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("[::1]:8080", "[::1]:8080"),
            &[get_request("/one", "[::1]:9090")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            dialed.lock().expect("dialed lock").clone(),
            vec![(
                "[::1]:8080".to_string(),
                "[::1]:8080".parse::<SocketAddr>().expect("addr")
            )],
            "the connector gets the tunnel's bracketed authority and its recorded address"
        );
    }

    /// A tunnel whose authority is known but whose address was never resolved
    /// cannot say where it goes. `serve` must refuse it, not fall back to dialing
    /// the request's `Host`, which is the route a tunnel may never take. No
    /// constructor builds this state (`Conn::plain` and `mitm` set both fields
    /// together), so the literal below is the only way to reach it; the test
    /// keeps a later edit from reaching it silently.
    #[tokio::test]
    async fn serve_refuses_a_tunnel_that_has_no_resolved_address() {
        // An origin is on offer, so a dial would succeed and answer: the refusal
        // has to come from `serve`, not from a connector with nothing to give.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));
        let conn = Conn {
            scheme: "http".to_string(),
            tunnel_authority: Some("127.0.0.1:8080".to_string()),
            tunnel_addr: None,
            client_conn: ConnInfo {
                peer: unknown_peer(),
                sni: None,
                alpn: None,
                tls: false,
                established: SystemTime::now(),
            },
            server_conn: None,
            source_app: None,
            capture_interface: None,
            passive: false,
        };
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(&ctx, Box::pin(proxy_side), None, None, conn, MAX_BODY);
        let script = async {
            client
                .write_all(get_request("/one", "127.0.0.1:9090").as_bytes())
                .await
                .expect("send");
            // One read: EOF (no bytes) when `serve` refuses and drops the
            // connection, response bytes if it answered. Reading to EOF would
            // hang on a keep-alive answer instead of failing on it.
            let mut chunk = [0u8; 512];
            let n = client.read(&mut chunk).await.expect("read");
            // Hang up, so a `serve` that answered sees the client finish.
            drop(client);
            chunk[..n].to_vec()
        };
        let (served, got) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("serve hung");

        let err = served.expect_err("a tunnel with no resolved address must be refused");
        assert!(
            err.to_string().contains("no resolved CONNECT address"),
            "error: {err}"
        );
        assert!(
            got.is_empty(),
            "the client reads no response bytes: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(
            dialed.lock().expect("dialed lock").is_empty(),
            "nothing may be dialed, in particular not the request's Host"
        );
    }

    // ---- edge cases: the tunnel route and surplus bytes -------------------

    /// A request whose `Host` names the tunnel target is stored like any
    /// forward-proxy request: the `Host` as authority, a cleartext server
    /// connection to the target, and a complete response.
    #[tokio::test]
    async fn serve_stores_the_usual_flow_when_the_host_names_the_tunnel_target() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], false));

        let bodies = serve_requests(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            &[get_request("/one", "127.0.0.1:8080")],
        )
        .await;

        assert_eq!(bodies, vec!["first"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")]
        );
        let flow = stored_http(&ctx, "/one");
        assert_eq!(flow.request.scheme, "http");
        assert_eq!(flow.request.authority, "127.0.0.1:8080");
        assert_eq!(flow.request.method, "GET");
        assert_eq!(flow.request.version, HttpVersion::Http11);
        assert_eq!(
            flow.request.headers.iter().collect::<Vec<_>>(),
            vec![("Host", "127.0.0.1:8080")]
        );
        assert!(matches!(flow.request.body, Body::Empty));
        assert!(!flow.client_conn.tls);
        let server = flow.server_conn.expect("a server connection is recorded");
        assert_eq!(server.peer, "127.0.0.1:8080".parse().expect("addr"));
        assert!(!server.tls);
        assert_eq!(server.sni, None);
        assert_eq!(server.alpn, None);
        let response = flow.response.expect("a stored response");
        assert_eq!(response.status, 200);
        assert_eq!(response.version, HttpVersion::Http11);
        assert_eq!(
            response.headers.iter().collect::<Vec<_>>(),
            vec![("Content-Length", "5")]
        );
        assert!(
            matches!(response.body, Body::Bytes(ref b) if b.as_slice() == b"first"),
            "stored body: {:?}",
            response.body
        );
        assert!(!flow.metadata.truncated);
        assert_eq!(flow.metadata.marks, Vec::<String>::new());
        // A proxied connection has no capture attribution: both are `None`, never
        // a placeholder.
        assert_eq!(flow.metadata.source_app, None);
        assert_eq!(flow.metadata.capture_interface, None);
        assert!(
            matches!(flow.intercept, InterceptState::Observed),
            "intercept: {:?}",
            flow.intercept
        );
    }

    // ---- capture attribution (SA-AC0) ------------------------------------

    /// `Conn::flow_meta` carries exactly the attribution onto a fresh `FlowMeta`:
    /// marks, comment, replay flag and timing are each flow's own.
    #[test]
    fn conn_flow_meta_carries_only_attribution() {
        let mut conn = Conn::plain(unknown_peer(), None);
        conn.source_app = Some("com.apple.Safari".into());
        conn.capture_interface = Some("macos-ne".into());

        let meta = conn.flow_meta();

        assert_eq!(meta.source_app, Some("com.apple.Safari".into()));
        assert_eq!(meta.capture_interface, Some("macos-ne".into()));
        assert!(meta.marks.is_empty());
        assert!(!meta.is_replay);
        assert_eq!(meta.comment, None);
    }

    /// SA-AC0: the attribution a capture ingress puts on the hint (`peer_identity`,
    /// `capture_interface`) reaches the flow the module stores for a cleartext
    /// request served through `spawn`, as `source_app` / `capture_interface`.
    #[tokio::test]
    async fn drive_stamps_the_hint_attribution_on_the_stored_flow() {
        let (up, origin_end) = duplex(64 * 1024);
        let store = Arc::new(MemFlowStore::new());
        let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store.clone(), Arc::new(NoSink));
        let ctx = ctx.with_hint(NextLayerHint {
            dst: unknown_peer(),
            is_tls: false,
            client_hello_sni: None,
            alpn: vec![],
            first_bytes: b"GET ".to_vec(),
            from_upgrade: false,
            peer_identity: Some("com.apple.Safari".into()),
            capture_interface: Some("macos-ne".into()),
        });
        let _origin = tokio::spawn(origin_serve(origin_end, vec!["first"], true));
        let module = HttpModule::new();

        let (mut client, proxy_side) = duplex(64 * 1024);
        let serving = module.spawn(Box::pin(proxy_side), ctx);
        let script = async {
            let body = client_get(&mut client, "/one", "127.0.0.1:8080").await;
            // Hang up, so the module sees the client finish and returns.
            drop(client);
            body
        };
        let (served, body) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("spawn hung: the request went to an upstream that never answers");
        served.expect("the module ends cleanly when the client hangs up");
        assert_eq!(body, "first");

        // `spawn` took the context, so read the flow back through the shared store.
        let flow = store
            .list()
            .into_iter()
            .find_map(|id| match store.get(id) {
                Some(Flow::Http(f)) if f.request.path == "/one" => Some(f),
                _ => None,
            })
            .expect("a stored flow for /one");
        assert_eq!(flow.metadata.source_app, Some("com.apple.Safari".into()));
        assert_eq!(flow.metadata.capture_interface, Some("macos-ne".into()));
    }

    /// A taint lasts for one replacement. Once the new upstream is in place the
    /// connection is reused again: a flag that was never cleared would redial
    /// for every later request.
    #[tokio::test]
    async fn serve_reuses_the_replacement_upstream_after_a_taint() {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up1), Box::pin(up2)]);
        let _origin1 = tokio::spawn(origin_serve_trailing(
            origin1_end,
            vec!["legit"],
            STRAY_RESPONSE,
            false,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second", "third"], false));

        let bodies = serve_requests(
            &ctx,
            Conn::plain(unknown_peer(), None),
            &[
                get_request("http://127.0.0.1:8080/one", "127.0.0.1:8080"),
                get_request("http://127.0.0.1:8080/two", "127.0.0.1:8080"),
                get_request("http://127.0.0.1:8080/three", "127.0.0.1:8080"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["legit", "second", "third"]);
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![
                dial("127.0.0.1:8080", "127.0.0.1:8080"),
                dial("127.0.0.1:8080", "127.0.0.1:8080")
            ],
            "one replacement for the taint, then the new connection is reused"
        );
    }

    /// With `Connection: close` the connection ends after the response whatever
    /// the origin left behind, but the stray must still not reach the client: it
    /// reads exactly the legitimate response, then EOF.
    #[tokio::test]
    async fn serve_does_not_forward_a_stray_response_when_the_connection_closes_anyway() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed, sink) = ctx_recording(vec![Box::pin(up)]);
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
            None,
            None,
            Conn::plain(unknown_peer(), None),
            MAX_BODY,
        );
        let script = async {
            client
                .write_all(
                    b"GET http://127.0.0.1:8080/one HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            got
        };
        let (served, got) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("serve hung");

        served.expect("a Connection: close request ends cleanly");
        let got = String::from_utf8_lossy(&got).into_owned();
        assert!(got.starts_with("HTTP/1.1 200"), "response: {got:?}");
        assert!(
            got.ends_with("\r\n\r\nlegit"),
            "nothing may follow the legitimate body: {got:?}"
        );
        assert_eq!(
            got.matches("HTTP/1.1").count(),
            1,
            "exactly one response head reached the client: {got:?}"
        );
        assert_eq!(dialed.lock().expect("dialed lock").len(), 1);
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Response(_)))
                .count(),
            1,
            "events: {events:?}"
        );
        assert!(
            !events.iter().any(|e| matches!(e, Event::Error { .. })),
            "events: {events:?}"
        );
    }

    /// An origin that answers a `Connection: close` request and then appends a
    /// bare CRLF is closing anyway: no upstream is replaced, so `serve` must not
    /// say it is replacing one. The warning is for the connection that stays open.
    #[tokio::test]
    async fn serve_does_not_warn_about_surplus_when_the_connection_closes_anyway() {
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve_trailing(
            origin_end,
            vec!["legit"],
            "\r\n",
            false,
        ));
        let (mut client, proxy_side) = duplex(64 * 1024);

        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            None,
            None,
            Conn::plain(unknown_peer(), None),
            MAX_BODY,
        );
        let script = async {
            client
                .write_all(
                    b"GET http://127.0.0.1:8080/one HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("send");
            let mut got = Vec::new();
            client.read_to_end(&mut got).await.expect("read to EOF");
            got
        };
        let (served, got) =
            tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                .await
                .expect("serve hung");

        served.expect("a Connection: close request ends cleanly");
        assert!(
            String::from_utf8_lossy(&got).ends_with("\r\n\r\nlegit"),
            "response: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(dialed.lock().expect("dialed lock").len(), 1);
        let warnings = warnings.lock().expect("warnings lock");
        assert!(
            warnings.is_empty(),
            "a connection that is closing anyway replaces nothing and warns of nothing: {warnings:?}"
        );
    }

    /// The other side of the ordering: on a connection that stays open the same
    /// surplus is an upstream being replaced, and that is worth one warning.
    #[tokio::test]
    async fn serve_warns_once_when_surplus_replaces_the_upstream_of_an_open_connection() {
        // The origin's stray bytes carry a token no log line may repeat.
        const TRAILER: &str = "\r\nSTRAYTOKEN-7f3a";
        let token = TRAILER.trim();
        let (_guard, warnings) = capture_events(tracing::Level::WARN);
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        let _origin = tokio::spawn(origin_serve_trailing(
            origin_end,
            vec!["legit"],
            TRAILER,
            false,
        ));

        let bodies = serve_requests(
            &ctx,
            Conn::plain(unknown_peer(), None),
            &[get_request("http://127.0.0.1:8080/one", "127.0.0.1:8080")],
        )
        .await;

        assert_eq!(bodies, vec!["legit"]);
        assert_eq!(dialed.lock().expect("dialed lock").len(), 1);
        let warnings = warnings.lock().expect("warnings lock");
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(warnings[0].level, tracing::Level::WARN);
        assert!(
            warnings[0].message.contains("after a completed response"),
            "message: {:?}",
            warnings[0].message
        );
        // The authority and the byte count, and nothing else: the stray bytes
        // themselves must never become a field.
        assert_eq!(
            warnings[0].fields,
            field_set(&[("authority", "127.0.0.1:8080"), ("bytes", "17")])
        );
        // Nor may they appear anywhere else in what was logged, the message and
        // every field alike.
        let logged = format!("{warnings:?}");
        assert!(
            !logged.contains(token),
            "the origin's bytes reached the log: {logged}"
        );
        // The `Debug` of the raw bytes is a list of decimal values, not text.
        let decimal = token
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            !logged.contains(&decimal),
            "the origin's bytes reached the log as numbers: {logged}"
        );
    }

    /// An origin writes a legitimate response with `trailer` behind it in the
    /// same write, and stays open. Whatever `trailer` is, the client reads only
    /// the legitimate response, the next request is answered by a replacement
    /// upstream, and `serve` never fails the connection.
    async fn assert_surplus_is_discarded_and_the_upstream_replaced(trailer: &'static str) {
        let (up1, origin1_end) = duplex(64 * 1024);
        let (up2, origin2_end) = duplex(64 * 1024);
        let (ctx, dialed, sink) = ctx_recording(vec![Box::pin(up1), Box::pin(up2)]);
        let _origin1 = tokio::spawn(origin_serve_trailing(
            origin1_end,
            vec!["legit"],
            trailer,
            false,
        ));
        let _origin2 = tokio::spawn(origin_serve(origin2_end, vec!["second"], false));

        // Surplus bytes must not fail the connection: the helper requires `serve`
        // to end cleanly.
        let (bodies, leftovers) = serve_requests_keep(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            None,
            &[
                get_request("http://127.0.0.1:8080/one", "127.0.0.1:8080"),
                get_request("http://127.0.0.1:8080/two", "127.0.0.1:8080"),
            ],
        )
        .await;

        assert_eq!(bodies, vec!["legit", "second"]);
        assert_eq!(leftovers, vec!["", ""], "nothing follows either response");
        assert_eq!(
            dialed.lock().expect("dialed lock").len(),
            2,
            "the upstream that left bytes behind is replaced"
        );
        let events = sink.events.lock().expect("events lock");
        assert!(
            !events.iter().any(|e| matches!(e, Event::Error { .. })),
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
    }

    #[tokio::test]
    async fn serve_replaces_the_upstream_after_garbage_that_is_not_http() {
        // Ends in a blank line, so a parser that took it for a response head would
        // reject it and fail the connection.
        assert_surplus_is_discarded_and_the_upstream_replaced("\u{0}\u{1}\u{2} not http\r\n\r\n")
            .await;
    }

    #[tokio::test]
    async fn serve_replaces_the_upstream_after_a_bare_crlf() {
        // Even this taints the connection: it is not an answer to anything.
        assert_surplus_is_discarded_and_the_upstream_replaced("\r\n").await;
    }

    // ---- upstream TLS that is not (or stops being) TLS --------------------

    /// An origin that answers the ClientHello with cleartext HTTP (a plain server
    /// behind a TLS port) fails the handshake at once, with the handshake's own
    /// context rather than the timeout's.
    #[tokio::test]
    async fn tls_handshake_rejects_an_origin_that_answers_in_cleartext() {
        let (io, mut origin) = stalled_pair();
        let module = HttpModule::new().with_insecure(true);
        // Holds the origin's end open (returned, not dropped) so the failure is
        // the bytes, not an EOF.
        let origin_task = tokio::spawn(async move {
            let mut hello = [0u8; 16];
            let _ = origin.read(&mut hello).await;
            let _ = origin
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = origin.flush().await;
            origin
        });

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
        .expect("a cleartext answer must fail the handshake promptly");

        let err = result.err().expect("cleartext HTTP is not a TLS handshake");
        assert_eq!(err.to_string(), "TLS to upstream origin.test:8443");
        let _origin = origin_task.await.expect("origin task");
    }

    // ---- `Expect: 100-continue` -------------------------------------------

    #[tokio::test]
    async fn serve_answers_a_100_continue_expectation_before_the_body_arrives() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (interim, body, pending)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                // The client now waits for the go-ahead and sends nothing more
                // until it has it.
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client.write_all(b"hello").await.expect("send body");
                let mut pending = Vec::new();
                let body = read_response_keep(&mut client, &mut pending).await;
                (interim, body, pending)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            interim.as_deref(),
            Some("HTTP/1.1 100 Continue\r\n\r\n"),
            "the 25-byte interim must reach the client before it sends the body"
        );
        assert_eq!(body, "ok");
        assert!(
            pending.is_empty(),
            "nothing follows the response: {pending:?}"
        );
    }

    #[tokio::test]
    async fn serve_sends_the_interim_once_when_the_body_trickles_in() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, stream) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let mut stream = read_interim(&mut client, Duration::from_secs(1))
                    .await
                    .unwrap_or_default();
                // The body arrives in two writes, apart.
                client.write_all(b"hel").await.expect("send first part");
                tokio::time::sleep(Duration::from_millis(20)).await;
                client.write_all(b"lo").await.expect("send second part");
                let reply = read_exact_bytes(&mut client, REPLY_OK.len()).await;
                stream.push_str(&String::from_utf8_lossy(&reply));
                // Nothing, in particular no second interim, follows.
                assert_quiet(&mut client, Duration::from_millis(100)).await;
                stream
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            stream,
            format!("{CONTINUE}HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
            "the client reads one interim, then the final response"
        );
        assert_eq!(stream.matches("100 Continue").count(), 1);
    }

    #[tokio::test]
    async fn serve_omits_the_interim_when_the_body_arrived_with_the_head() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, got) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                // Head and body in one write: the go-ahead would be pointless.
                client
                    .write_all(format!("{STRICT_HEAD}hello").as_bytes())
                    .await
                    .expect("send head and body");
                let got = read_exact_bytes(&mut client, REPLY_OK.len()).await;
                assert_quiet(&mut client, Duration::from_millis(100)).await;
                got
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            String::from_utf8_lossy(&got),
            REPLY_OK,
            "the first bytes the client reads are the final response, with no 1xx before it"
        );
        let origin_saw =
            String::from_utf8_lossy(&origin_saw.lock().expect("seen lock")).into_owned();
        assert_eq!(origin_saw, FORWARDED_STRICT);
    }

    #[tokio::test]
    async fn serve_ignores_an_expectation_on_an_http_1_0_request() {
        let head = STRICT_HEAD.replace("POST /up HTTP/1.1", "POST /up HTTP/1.0");
        let seen = head_first_exchange(&head, Duration::from_millis(300), b"hello", REPLY_OK).await;

        assert_eq!(
            seen.interim, None,
            "an HTTP/1.0 request is never answered with a 100"
        );
        assert_eq!((seen.status, seen.body.as_str()), (200, "ok"));
        assert!(
            seen.pending.is_empty(),
            "no 1xx follows: {:?}",
            seen.pending
        );
        assert!(
            seen.origin_saw.ends_with("Content-Length: 5\r\n\r\nhello"),
            "the origin still gets the whole request: {:?}",
            seen.origin_saw
        );
    }

    #[tokio::test]
    async fn serve_sends_no_interim_when_no_content_follows() {
        let head = STRICT_HEAD.replace("Content-Length: 5", "Content-Length: 0");
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (first_head, body)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client.write_all(head.as_bytes()).await.expect("send head");
                // The request is already complete: the first head to arrive is
                // the origin's answer.
                let first_head = read_interim(&mut client, Duration::from_secs(1)).await;
                let body = read_exact_bytes(&mut client, 2).await;
                assert_quiet(&mut client, Duration::from_millis(100)).await;
                (first_head, body)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        let first_head = first_head.expect("the final response never arrived");
        assert_eq!(first_head, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n");
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn serve_matches_the_expectation_case_insensitively_inside_a_list() {
        for lines in [
            "Expect: 100-Continue\r\n",
            "Expect: foo, 100-continue\r\n",
            "Expect: foo\r\nExpect: 100-continue\r\n",
        ] {
            let seen = head_first_exchange(
                &post_head(lines),
                Duration::from_secs(1),
                b"hello",
                REPLY_OK,
            )
            .await;
            assert_eq!(
                seen.interim.as_deref(),
                Some(CONTINUE),
                "the 100 for {lines:?}"
            );
            assert_eq!((seen.status, seen.body.as_str()), (200, "ok"));
            assert!(
                seen.origin_saw.contains(lines),
                "the origin must see {lines:?} unchanged: {:?}",
                seen.origin_saw
            );
        }
        for lines in [
            "Expect: 100-continue-ish\r\n",
            "Expect: 100-continue;x=1\r\n",
        ] {
            let seen = head_first_exchange(
                &post_head(lines),
                Duration::from_millis(300),
                b"hello",
                REPLY_OK,
            )
            .await;
            assert_eq!(seen.interim, None, "no 100 for {lines:?}");
            assert_eq!((seen.status, seen.body.as_str()), (200, "ok"));
        }
    }

    #[tokio::test]
    async fn serve_does_not_answer_an_unknown_expectation_and_forwards_it() {
        let seen = head_first_exchange(
            &post_head("Expect: bogus\r\n"),
            Duration::from_millis(300),
            b"hello",
            "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n",
        )
        .await;

        assert_eq!(seen.interim, None, "the proxy answers only a 100-continue");
        assert_eq!(
            (seen.status, seen.body.as_str()),
            (417, ""),
            "the origin's own refusal reaches the client as sent"
        );
        assert!(seen.pending.is_empty(), "pending: {:?}", seen.pending);
        assert!(
            seen.origin_saw.contains("Expect: bogus\r\n"),
            "the origin sees the expectation: {:?}",
            seen.origin_saw
        );
    }

    /// The origin's first exchange is its own optional `100` then a `302`, in
    /// `first_exchange`'s segments; the second exchange answers a plain `GET`.
    async fn assert_origin_interim_is_skipped(first_exchange: Vec<&'static str>) {
        const REDIRECT: &str = "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n";
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![first_exchange, vec![REPLY_OK]],
        ));

        let (served, (interim, redirect, saw_after_post, next, pending)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client.write_all(b"hello").await.expect("send body");
                let redirect = read_exact_bytes(&mut client, REDIRECT.len()).await;
                let saw_after_post =
                    String::from_utf8_lossy(&origin_saw.lock().expect("seen lock")).into_owned();
                // The same client connection carries a plain request next; it
                // must be answered by its own response, with nothing before it.
                let mut pending = Vec::new();
                let next =
                    client_get_keep(&mut client, &mut pending, "/next", "127.0.0.1:8080").await;
                (interim, redirect, saw_after_post, next, pending)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            interim.as_deref(),
            Some(CONTINUE),
            "the proxy's own 100 comes first"
        );
        assert_eq!(
            String::from_utf8_lossy(&redirect),
            REDIRECT,
            "then the 302, and no second interim from the origin"
        );
        assert_eq!(saw_after_post, FORWARDED_STRICT);
        assert_eq!(next, "ok");
        assert!(pending.is_empty(), "pending: {pending:?}");

        let flow = stored_http(&ctx, "/up");
        let events = sink.events.lock().expect("events lock");
        let for_post = |matches: fn(&Event, FlowId) -> bool| {
            events.iter().filter(|e| matches(e, flow.id)).count()
        };
        assert_eq!(
            for_post(|e, id| matches!(e, Event::ResponseHeaders(f) if *f == id)),
            1,
            "events: {events:?}"
        );
        assert_eq!(
            for_post(|e, id| matches!(e, Event::Response(f) if *f == id)),
            1,
            "events: {events:?}"
        );
        assert_eq!(
            for_post(|e, id| matches!(e, Event::Error { flow, .. } if *flow == id)),
            0,
            "events: {events:?}"
        );
        assert_eq!(
            flow.response.as_ref().map(|r| r.status),
            Some(302),
            "no 1xx is stored as the response"
        );
        assert_eq!(flow.request.headers.get("expect"), Some("100-continue"));
        assert!(
            matches!(flow.request.body, Body::Bytes(ref b) if b.as_slice() == b"hello"),
            "stored request body: {:?}",
            flow.request.body
        );
    }

    #[tokio::test]
    async fn serve_forwards_the_expect_header_untouched_and_skips_the_origin_interim() {
        // The origin's own 100 and the 302 in one write, and in two.
        assert_origin_interim_is_skipped(vec![
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
        ])
        .await;
        assert_origin_interim_is_skipped(vec![
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
        ])
        .await;
    }

    #[tokio::test]
    async fn serve_sends_the_interim_before_the_request_headers_event_returns() {
        let release = Arc::new(tokio::sync::Notify::new());
        let entered = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(ParkRequestHeaders {
            release: release.clone(),
            entered: entered.clone(),
            released: released.clone(),
        });
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], Arc::new(MemFlowStore::new()), sink);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (interim, parked, still_parked, body, pending)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                // Wait until the proxy has reached the park, then check it is
                // still in it: the client had its answer while the flow was held.
                let mut parked = false;
                for _ in 0..200 {
                    if entered.load(AtomicOrdering::SeqCst) {
                        parked = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let still_parked = !released.load(AtomicOrdering::SeqCst);
                release.notify_one();
                client.write_all(b"hello").await.expect("send body");
                let mut pending = Vec::new();
                let body = read_response_keep(&mut client, &mut pending).await;
                (interim, parked, still_parked, body, pending)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            interim.as_deref(),
            Some(CONTINUE),
            "the client must be answered while the RequestHeaders dispatch is still parked"
        );
        assert!(parked, "the proxy never reached the parked sink");
        assert!(
            still_parked,
            "the sink was released before the client had its answer"
        );
        assert_eq!(body, "ok");
        assert!(pending.is_empty(), "pending: {pending:?}");
    }

    /// The head of the oversize tests: ten bytes declared, against a cap of four.
    fn oversize_head(extra: &str) -> String {
        format!("POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 10\r\n{extra}\r\n")
    }

    #[tokio::test]
    async fn serve_refuses_a_declared_length_over_the_cap_before_asking_for_the_body() {
        let (ctx, dialed) = ctx_with(Vec::new());
        let head = oversize_head("Expect: 100-continue\r\n");

        let (served, (first_head, rest)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            4,
            |mut client| async move {
                // The client sends the head and then waits; it never writes a body.
                client.write_all(head.as_bytes()).await.expect("send head");
                let first_head = read_interim(&mut client, Duration::from_secs(1))
                    .await
                    .expect(
                        "neither a 100 nor a 413 arrived: the proxy is waiting for a body \
                         it was never going to accept",
                    );
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.expect("read to EOF");
                (first_head, rest)
            },
        )
        .await;

        served.expect("a refused request ends cleanly");
        assert!(
            first_head.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "the first and only head the client reads is the refusal: {first_head:?}"
        );
        assert!(!first_head.contains("100"), "first head: {first_head:?}");
        assert_eq!(
            String::from_utf8_lossy(&rest),
            OVERSIZED_BODY,
            "the refusal's body, then EOF"
        );
        assert!(
            dialed.lock().expect("dialed lock").is_empty(),
            "nothing may be dialed for a refused request"
        );
        assert!(
            stored_http(&ctx, "/up").metadata.truncated,
            "the stored request is marked truncated"
        );
    }

    #[tokio::test]
    async fn serve_still_reads_an_oversized_body_without_an_expectation() {
        let (ctx, dialed) = ctx_with(Vec::new());
        let head = oversize_head("");

        let (served, got) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            4,
            |mut client| async move {
                client.write_all(head.as_bytes()).await.expect("send head");
                client.write_all(b"0123456789").await.expect("send body");
                let mut got = Vec::new();
                client.read_to_end(&mut got).await.expect("read to EOF");
                got
            },
        )
        .await;

        served.expect("a refused request ends cleanly");
        let got = String::from_utf8_lossy(&got).into_owned();
        assert!(
            got.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "response: {got:?}"
        );
        assert!(got.ends_with(OVERSIZED_BODY), "response: {got:?}");
        assert_eq!(got.matches("HTTP/1.1").count(), 1, "one response: {got:?}");
        assert!(dialed.lock().expect("dialed lock").is_empty());
        assert!(stored_http(&ctx, "/up").metadata.truncated);
    }

    #[tokio::test]
    async fn serve_answers_an_expectation_whose_declared_length_equals_the_cap() {
        // The boundary of the early refusal: a body exactly at the cap is
        // accepted, so the client is told to go ahead.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (interim, body)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            5,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client.write_all(b"hello").await.expect("send body");
                let mut pending = Vec::new();
                let body = read_response_keep(&mut client, &mut pending).await;
                (interim, body)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(interim.as_deref(), Some(CONTINUE));
        assert_eq!(body, "ok");
    }

    /// One strict exchange on `conn`, whose origin is `origin_end` (reached
    /// through `upstream` when given, else through the connector), with the
    /// request naming `host`: the client reads the 100 first and the exchange
    /// completes.
    async fn assert_strict_exchange_on(
        ctx: &ModuleCtx,
        conn: Conn,
        upstream: Option<ByteStream>,
        origin_end: DuplexStream,
        host: &str,
    ) {
        let head = format!(
            "POST /up HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
        );
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (interim, body, pending)) =
            with_serve(ctx, conn, upstream, MAX_BODY, |mut client| async move {
                client.write_all(head.as_bytes()).await.expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client.write_all(b"hello").await.expect("send body");
                let mut pending = Vec::new();
                let body = read_response_keep(&mut client, &mut pending).await;
                (interim, body, pending)
            })
            .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(interim.as_deref(), Some(CONTINUE), "host {host}");
        assert_eq!(body, "ok", "host {host}");
        assert!(pending.is_empty(), "host {host}: {pending:?}");
    }

    #[tokio::test]
    async fn serve_answers_the_expectation_in_a_tls_tunnel_and_a_cleartext_tunnel() {
        // A TLS-shaped tunnel: `serve` is handed an already-handshaken upstream.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(Vec::new());
        assert_strict_exchange_on(
            &ctx,
            tunnel_conn(),
            Some(Box::pin(up)),
            origin_end,
            "origin.test:8443",
        )
        .await;

        // A cleartext `CONNECT` tunnel: `serve` dials the `CONNECT` target.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, dialed) = ctx_with(vec![Box::pin(up)]);
        assert_strict_exchange_on(
            &ctx,
            cleartext_tunnel_conn("127.0.0.1:8080", "127.0.0.1:8080"),
            None,
            origin_end,
            "127.0.0.1:8080",
        )
        .await;
        assert_eq!(
            *dialed.lock().expect("dialed lock"),
            vec![dial("127.0.0.1:8080", "127.0.0.1:8080")]
        );
    }

    /// A chunked upload's head with an expectation: no `Content-Length`, so no
    /// declared size to refuse it on.
    const CHUNKED_STRICT_HEAD: &str = "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n";

    #[tokio::test]
    async fn serve_answers_a_chunked_upload_expectation_and_forwards_it_reframed() {
        // A chunked head declares no length, so it is never refused early on size:
        // it gets the go-ahead, and the origin receives the body framed by length.
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let origin_saw = Arc::new(Mutex::new(Vec::new()));
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            origin_saw.clone(),
            vec![vec![REPLY_OK]],
        ));

        let (served, (interim, body, pending)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(CHUNKED_STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client
                    .write_all(b"3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n")
                    .await
                    .expect("send body");
                let mut pending = Vec::new();
                let body = read_response_keep(&mut client, &mut pending).await;
                (interim, body, pending)
            },
        )
        .await;

        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(
            interim.as_deref(),
            Some(CONTINUE),
            "the go-ahead for a chunked upload"
        );
        assert_eq!(body, "ok");
        assert!(pending.is_empty(), "pending: {pending:?}");
        let origin_saw =
            String::from_utf8_lossy(&origin_saw.lock().expect("seen lock")).into_owned();
        assert!(
            origin_saw.contains("Expect: 100-continue\r\n"),
            "the expectation is forwarded untouched: {origin_saw:?}"
        );
        assert!(
            origin_saw.ends_with("Content-Length: 5\r\n\r\nhello"),
            "the origin gets the whole body, framed by length: {origin_saw:?}"
        );
    }

    #[tokio::test]
    async fn serve_caps_a_chunked_upload_with_an_expectation_as_its_bytes_arrive() {
        // With no declared length the head cannot be refused, so the client is
        // told to go ahead; the cap then bites as the body crosses it.
        let (ctx, dialed) = ctx_with(Vec::new());

        let (served, (interim, rest)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            4,
            |mut client| async move {
                client
                    .write_all(CHUNKED_STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                let interim = read_interim(&mut client, Duration::from_secs(1)).await;
                client
                    .write_all(b"5\r\nhello\r\n0\r\n\r\n")
                    .await
                    .expect("send body");
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.expect("read to EOF");
                (interim, rest)
            },
        )
        .await;

        served.expect("a refused request ends cleanly");
        assert_eq!(
            interim.as_deref(),
            Some(CONTINUE),
            "a chunked head is not refused before its body, whatever the cap"
        );
        let rest = String::from_utf8_lossy(&rest).into_owned();
        assert!(
            rest.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "response: {rest:?}"
        );
        assert!(rest.ends_with(OVERSIZED_BODY), "response: {rest:?}");
        assert!(dialed.lock().expect("dialed lock").is_empty());
        assert!(stored_http(&ctx, "/up").metadata.truncated);
    }

    #[tokio::test]
    async fn serve_ends_quietly_when_the_client_leaves_before_it_can_be_answered() {
        // The client sends its head and hangs up. The write of the interim fails;
        // that is the client going away, not a fault for the accept loop to log,
        // and nothing is dialed for a request that never finished.
        let (ctx, dialed) = ctx_with(Vec::new());

        let (served, ()) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(STRICT_HEAD.as_bytes())
                    .await
                    .expect("send head");
                // Dropping the client end hangs up before the proxy can answer.
            },
        )
        .await;

        served.expect("a client that leaves before the interim is not an error");
        assert!(
            dialed.lock().expect("dialed lock").is_empty(),
            "nothing may be dialed"
        );
    }

    // ---- chunked trailers through `serve` -----------------------------------

    /// The head of a chunked response that announces two trailer fields, and its one
    /// chunk. The trailer section, if any, follows on the wire.
    const TRAILER_HEAD: &str = "HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";

    /// A trailer section of two fields that may be forwarded.
    const TRAILER_SECTION: &str = "0\r\nx-sum: abc\r\nx-e2e: m1\r\n\r\n";

    /// The two ways an origin can deliver [`TRAILER_HEAD`] followed by `section`:
    /// as one write, and in pieces (the head and its chunk, then each line of the
    /// section alone, 10 ms apart), so the proxy reads the trailers in reads that
    /// come after the one that held the head.
    fn trailer_deliveries(section: &str) -> [Vec<String>; 2] {
        let whole = vec![format!("{TRAILER_HEAD}{section}")];
        let mut pieces = vec![TRAILER_HEAD.to_string()];
        pieces.extend(section.split_inclusive("\r\n").map(str::to_string));
        [whole, pieces]
    }

    /// Read until `n` bytes have arrived or `within` has passed, and return what
    /// arrived. A short answer is a result to compare, not a hang.
    async fn read_up_to(io: &mut DuplexStream, n: usize, within: Duration) -> Vec<u8> {
        let mut got = Vec::new();
        let mut chunk = [0u8; 512];
        let _ = tokio::time::timeout(within, async {
            while got.len() < n {
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => got.extend_from_slice(&chunk[..read]),
                }
            }
        })
        .await;
        got
    }

    /// Read until the peer closes or `within` has passed: everything that
    /// arrived, and whether the close came.
    async fn read_to_close(io: &mut DuplexStream, within: Duration) -> (Vec<u8>, bool) {
        let mut got = Vec::new();
        let mut chunk = [0u8; 512];
        let closed = tokio::time::timeout(within, async {
            loop {
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => got.extend_from_slice(&chunk[..read]),
                }
            }
        })
        .await
        .is_ok();
        (got, closed)
    }

    /// One cleartext `GET /t` through `serve`, answered by an in-memory origin that
    /// writes `segments` (10 ms apart). The client reads up to `want_len` bytes,
    /// checks that nothing more follows, and hangs up. Returns `serve`'s result and
    /// the bytes the client read.
    async fn trailer_get(
        ctx: &ModuleCtx,
        origin_end: DuplexStream,
        segments: Vec<String>,
        want_len: usize,
    ) -> (Result<()>, Vec<u8>) {
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            Arc::new(Mutex::new(Vec::new())),
            vec![segments],
        ));
        with_serve(
            ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(get_request("/t", "127.0.0.1:8080").as_bytes())
                    .await
                    .expect("send");
                let got = read_up_to(&mut client, want_len, Duration::from_secs(1)).await;
                assert_quiet(&mut client, Duration::from_millis(100)).await;
                got
            },
        )
        .await
    }

    /// Edits the stored response when `Event::ResponseHeaders` is dispatched, as a
    /// plugin rewriting a response head would. Shares `store` with the context it is
    /// built into, so the edit lands in what `serve` reads back.
    struct EditAtResponseHeaders {
        store: Arc<MemFlowStore>,
        edit: fn(&mut HttpResponse),
    }

    impl EventSink for EditAtResponseHeaders {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            if let Event::ResponseHeaders(id) = ev {
                self.store.update(id, &mut |f: &mut Flow| {
                    if let Flow::Http(h) = f {
                        if let Some(resp) = h.response.as_mut() {
                            (self.edit)(resp);
                        }
                    }
                });
            }
            Box::pin(async { Verdict::Continue })
        }
    }

    /// One look a [`TrailerProbe`] took: the event, how many trailer fields the
    /// stored response held then, and its `x-sum` header.
    type ProbeLook = (&'static str, usize, Option<String>);

    /// Records what the stored response holds when `Event::ResponseHeaders` and
    /// `Event::Response` are dispatched, as a plugin reading the store would see it.
    struct TrailerProbe {
        store: Arc<MemFlowStore>,
        looks: Mutex<Vec<ProbeLook>>,
    }

    impl EventSink for TrailerProbe {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            let (when, id) = match ev {
                Event::ResponseHeaders(id) => ("ResponseHeaders", id),
                Event::Response(id) => ("Response", id),
                _ => return Box::pin(async { Verdict::Continue }),
            };
            if let Some(Flow::Http(HttpFlow {
                response: Some(resp),
                ..
            })) = self.store.get(id)
            {
                self.looks.lock().expect("looks lock").push((
                    when,
                    resp.trailers.len(),
                    resp.headers.get("x-sum").map(str::to_string),
                ));
            }
            Box::pin(async { Verdict::Continue })
        }
    }

    #[tokio::test]
    async fn serve_forwards_the_origin_trailers_in_order() {
        let want = format!("{TRAILER_HEAD}{TRAILER_SECTION}");
        for segments in trailer_deliveries(TRAILER_SECTION) {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);

            let (served, got) = trailer_get(&ctx, origin_end, segments.clone(), want.len()).await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "the origin wrote {segments:?}"
            );
        }
    }

    #[tokio::test]
    async fn serve_keeps_the_connection_in_sync_after_a_response_with_trailers() {
        let want = format!("{TRAILER_HEAD}{TRAILER_SECTION}");
        for first in trailer_deliveries(TRAILER_SECTION) {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
            let _origin = tokio::spawn(origin_replying(
                origin_end,
                Arc::new(Mutex::new(Vec::new())),
                vec![first.clone(), vec![REPLY_OK.to_string()]],
            ));
            let want_len = want.len();

            let (served, (got, body, pending)) = with_serve(
                &ctx,
                Conn::plain(unknown_peer(), None),
                None,
                MAX_BODY,
                |mut client| async move {
                    client
                        .write_all(get_request("/t", "127.0.0.1:8080").as_bytes())
                        .await
                        .expect("send");
                    let got = read_up_to(&mut client, want_len, Duration::from_secs(1)).await;
                    // The next request on the same connection is answered intact.
                    let mut pending = Vec::new();
                    let body = client_send_keep(
                        &mut client,
                        &mut pending,
                        &get_request("/next", "127.0.0.1:8080"),
                    )
                    .await;
                    (got, body, pending)
                },
            )
            .await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "the origin wrote {first:?}"
            );
            assert_eq!(body, "ok");
            assert!(
                pending.is_empty(),
                "nothing follows the second response: {pending:?}"
            );
        }
    }

    #[tokio::test]
    async fn serve_without_trailers_still_ends_the_body_with_a_bare_terminator() {
        let want = format!("{TRAILER_HEAD}0\r\n\r\n");
        for segments in trailer_deliveries("0\r\n\r\n") {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);

            let (served, got) = trailer_get(&ctx, origin_end, segments.clone(), want.len()).await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "the origin wrote {segments:?}"
            );
            let response = stored_http(&ctx, "/t").response.expect("stored response");
            assert!(response.trailers.is_empty(), "no trailer fields were sent");
        }
    }

    #[tokio::test]
    async fn serve_withholds_forbidden_trailers_from_the_wire_but_captures_them() {
        let section = "0\r\nContent-Length: 0\r\nHost: evil.test\r\nSet-Cookie: s=1\r\nAuthorization: Bearer x\r\nX-Keep: yes\r\nLocation: /x\r\n\r\n";
        let want = format!("{TRAILER_HEAD}0\r\nX-Keep: yes\r\n\r\n");
        for segments in trailer_deliveries(section) {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);

            let (served, got) = trailer_get(&ctx, origin_end, segments.clone(), want.len()).await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "only the allowed field is forwarded (origin wrote {segments:?})"
            );
            // The capture keeps all six, in the order the origin sent them.
            let response = stored_http(&ctx, "/t").response.expect("stored response");
            assert_eq!(
                response.trailers.iter().collect::<Vec<_>>(),
                vec![
                    ("Content-Length", "0"),
                    ("Host", "evil.test"),
                    ("Set-Cookie", "s=1"),
                    ("Authorization", "Bearer x"),
                    ("X-Keep", "yes"),
                    ("Location", "/x"),
                ]
            );
            // And none of them leaked into the headers.
            for name in [
                "content-length",
                "host",
                "set-cookie",
                "authorization",
                "x-keep",
                "location",
            ] {
                assert_eq!(response.headers.get(name), None, "{name} is a trailer only");
            }
            assert_eq!(response.headers.get("trailer"), Some("x-sum, x-e2e"));
        }
    }

    #[tokio::test]
    async fn serve_does_not_forward_origin_trailers_after_a_replaced_body() {
        // A plugin swaps the streamed body for its own and drops the chunked
        // framing, so the client gets a `Content-Length` response.
        let want = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nreplaced";
        for segments in trailer_deliveries(TRAILER_SECTION) {
            let (up, origin_end) = duplex(64 * 1024);
            let store = Arc::new(MemFlowStore::new());
            let sink = Arc::new(EditAtResponseHeaders {
                store: store.clone(),
                edit: |resp| {
                    resp.body = Body::Bytes(b"replaced".to_vec());
                    resp.headers.remove("transfer-encoding");
                    resp.headers.remove("trailer");
                },
            });
            let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store, sink);

            let (served, got) = trailer_get(&ctx, origin_end, segments.clone(), want.len()).await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "no terminator and no trailer follows a replaced body (origin wrote {segments:?})"
            );
            let response = stored_http(&ctx, "/t").response.expect("stored response");
            assert_eq!(
                response.trailers.iter().collect::<Vec<_>>(),
                vec![("x-sum", "abc"), ("x-e2e", "m1")],
                "the capture still holds what the origin sent"
            );
        }
    }

    #[tokio::test]
    async fn serve_writes_no_trailers_when_the_client_body_is_not_chunk_framed() {
        // A plugin reframes the still-streamed body by length: the client-bound
        // framing is no longer chunked, so there is no section to put trailers in.
        let want = "HTTP/1.1 200 OK\r\nTrailer: x-sum, x-e2e\r\nContent-Length: 5\r\n\r\nhello";
        let (_guard, captured) = capture_events(tracing::Level::DEBUG);
        for segments in trailer_deliveries(TRAILER_SECTION) {
            captured.lock().expect("events lock").clear();
            let (up, origin_end) = duplex(64 * 1024);
            let store = Arc::new(MemFlowStore::new());
            let sink = Arc::new(EditAtResponseHeaders {
                store: store.clone(),
                edit: |resp| {
                    resp.headers.remove("transfer-encoding");
                    resp.headers.set("Content-Length", "5");
                },
            });
            let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store, sink);

            let (served, got) = trailer_get(&ctx, origin_end, segments.clone(), want.len()).await;

            served.expect("serve ends cleanly when the client hangs up");
            assert_eq!(
                String::from_utf8_lossy(&got),
                want,
                "origin wrote {segments:?}"
            );
            let response = stored_http(&ctx, "/t").response.expect("stored response");
            assert_eq!(response.trailers.len(), 2, "the capture is unaffected");
            // Both fields went unwritten, and that is reported once, as a count.
            let events = captured.lock().expect("events lock");
            let reports: Vec<&Captured> = events
                .iter()
                .filter(|e| e.fields.contains_key("withheld"))
                .collect();
            assert_eq!(reports.len(), 1, "events: {events:?}");
            assert_eq!(reports[0].level, tracing::Level::DEBUG);
            assert_eq!(reports[0].fields, field_set(&[("withheld", "2")]));
        }
    }

    #[tokio::test]
    async fn serve_exposes_trailers_to_plugins_at_response_time() {
        for segments in trailer_deliveries(TRAILER_SECTION) {
            let (up, origin_end) = duplex(64 * 1024);
            let store = Arc::new(MemFlowStore::new());
            let probe = Arc::new(TrailerProbe {
                store: store.clone(),
                looks: Mutex::new(Vec::new()),
            });
            let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store, probe.clone());
            let want_len = TRAILER_HEAD.len() + TRAILER_SECTION.len();

            let (served, _got) = trailer_get(&ctx, origin_end, segments.clone(), want_len).await;

            served.expect("serve ends cleanly when the client hangs up");
            // The head is dispatched with no trailers yet, whatever has already been
            // read; by `Event::Response` the origin's two fields are stored, and the
            // headers are the origin's head, unmerged.
            assert_eq!(
                *probe.looks.lock().expect("looks lock"),
                vec![("ResponseHeaders", 0, None), ("Response", 2, None)],
                "the origin wrote {segments:?}"
            );
        }
    }

    #[tokio::test]
    async fn serve_fails_closed_on_an_oversized_trailer_section() {
        let mut section = String::from("0\r\n");
        for n in 0..65 {
            section.push_str(&format!("f{n}: v\r\n"));
        }
        section.push_str("\r\n");
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        // The head and its chunk are written alone and first, so they are read,
        // forwarded and flushed before the over-cap section arrives. (Were all of it
        // in one read, `on_bytes` would fail for the whole read and the client would
        // get nothing before the close: fail-closed as well, not asserted here.)
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            Arc::new(Mutex::new(Vec::new())),
            vec![vec![TRAILER_HEAD.to_string(), section]],
        ));

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(get_request("/t", "127.0.0.1:8080").as_bytes())
                    .await
                    .expect("send");
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an over-cap trailer section fails the connection");
        assert!(err.to_string().contains("trailer"), "error: {err}");
        assert!(
            closed,
            "the proxy must hang up, not keep the client waiting"
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            TRAILER_HEAD,
            "the client has the head and the chunk, and never a terminator"
        );
    }

    #[tokio::test]
    async fn serve_reports_a_malformed_trailer_section_as_one_typed_error() {
        // Event consumers (the Rhai `on_error` hook and `flow.subscribe` bus
        // subscribers) learn of a response from its events, so a response the
        // machine refuses must still reach them as an error, or one bad trailer
        // line would hide a body from them.
        let mut section = String::from("0\r\n");
        for n in 0..65 {
            section.push_str(&format!("x-evil-91c2-{n}: v\r\n"));
        }
        section.push_str("\r\n");
        let one_read = format!("{TRAILER_HEAD}{section}");
        let deliveries = [
            (
                "head, then section",
                vec![TRAILER_HEAD.to_string(), section],
            ),
            ("head and section together", vec![one_read]),
        ];
        for (delivery, segments) in deliveries {
            let (up, origin_end) = duplex(64 * 1024);
            let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
            let _origin = tokio::spawn(origin_replying(
                origin_end,
                Arc::new(Mutex::new(Vec::new())),
                vec![segments],
            ));

            let (served, _) = with_serve(
                &ctx,
                Conn::plain(unknown_peer(), None),
                None,
                MAX_BODY,
                |mut client| async move {
                    client
                        .write_all(get_request("/t", "127.0.0.1:8080").as_bytes())
                        .await
                        .expect("send");
                    read_to_close(&mut client, Duration::from_secs(2)).await
                },
            )
            .await;

            let err = served.expect_err("an over-cap trailer section fails the connection");
            assert!(err.to_string().contains("trailer"), "error: {err}");
            let flow = stored_http(&ctx, "/t");
            let events = sink.events.lock().expect("events lock");
            let errors: Vec<&aitm_core::FlowError> = events
                .iter()
                .filter_map(|e| match e {
                    Event::Error { flow: f, kind } if *f == flow.id => Some(kind),
                    _ => None,
                })
                .collect();
            assert_eq!(
                errors,
                vec![&aitm_core::FlowError::Upstream(
                    "malformed response from upstream".to_string()
                )],
                "one typed error, in fixed words ({delivery}): {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, Event::Response(f) if *f == flow.id)),
                "a refused response is never dispatched as complete: {events:?}"
            );
            assert!(
                !format!("{events:?}").contains("evil-91c2"),
                "the origin's field names must not reach an event: {events:?}"
            );
            // With the head (and its chunk) stored before the section was refused,
            // the response is finalised as a truncated one and the flow is
            // terminal. Refused in the same read as the head, no head was ever
            // stored (the machine drops the events of a read it refuses), so the
            // flow stays in flight: the documented limitation (spec Non-goals,
            // follow-up F1), pinned here so a later fix flips it knowingly.
            if delivery == "head, then section" {
                let resp = flow
                    .response
                    .as_ref()
                    .expect("the head was stored before the section was refused");
                assert!(
                    matches!(&resp.body, Body::Bytes(b) if b == b"hello"),
                    "the chunk captured before the refusal is the stored body ({delivery}): {:?}",
                    resp.body
                );
                assert!(
                    flow.metadata.truncated,
                    "a refused response is marked truncated ({delivery})"
                );
                assert_eq!(
                    ctx.store().clear().cleared,
                    1,
                    "a refused response is terminal ({delivery})"
                );
            } else {
                assert!(
                    flow.response.is_none(),
                    "no head is stored when the read that held it is refused ({delivery}): {:?}",
                    flow.response
                );
                assert_eq!(
                    ctx.store().clear().skipped_in_flight,
                    1,
                    "a flow with no response stays in flight ({delivery}); spec F1"
                );
            }
        }
    }

    #[tokio::test]
    async fn serve_never_logs_trailer_names_or_values() {
        let (_guard, captured) = capture_events(tracing::Level::TRACE);
        let token = "x-trailertoken-91c2: val-trailertoken-91c2\r\n";

        // Every field is forwarded: nothing to report.
        let section = format!("0\r\n{token}\r\n");
        let want = format!("{TRAILER_HEAD}{section}");
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let segments = trailer_deliveries(&section)[1].clone();
        let (served, got) = trailer_get(&ctx, origin_end, segments, want.len()).await;
        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(String::from_utf8_lossy(&got), want);
        {
            let events = captured.lock().expect("events lock");
            assert!(
                !format!("{events:?}")
                    .to_ascii_lowercase()
                    .contains("trailertoken"),
                "a trailer name or value reached the log: {events:?}"
            );
            assert!(
                events.iter().all(|e| !e.fields.contains_key("withheld")),
                "a response whose trailers are all forwarded has nothing to report: {events:?}"
            );
        }
        captured.lock().expect("events lock").clear();

        // One field is withheld: one debug event, carrying a count and nothing else.
        let section = format!("0\r\n{token}Set-Cookie: s=1\r\n\r\n");
        let want = format!("{TRAILER_HEAD}0\r\n{token}\r\n");
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed) = ctx_with(vec![Box::pin(up)]);
        let segments = trailer_deliveries(&section)[1].clone();
        let (served, got) = trailer_get(&ctx, origin_end, segments, want.len()).await;
        served.expect("serve ends cleanly when the client hangs up");
        assert_eq!(String::from_utf8_lossy(&got), want);
        let events = captured.lock().expect("events lock");
        assert!(
            !format!("{events:?}")
                .to_ascii_lowercase()
                .contains("trailertoken"),
            "a trailer name or value reached the log: {events:?}"
        );
        let reports: Vec<&Captured> = events
            .iter()
            .filter(|e| e.fields.contains_key("withheld"))
            .collect();
        assert_eq!(reports.len(), 1, "events: {events:?}");
        assert_eq!(reports[0].level, tracing::Level::DEBUG);
        assert_eq!(reports[0].fields, field_set(&[("withheld", "1")]));
        assert!(
            !format!("{events:?}")
                .to_ascii_lowercase()
                .contains("cookie"),
            "a withheld field's name must not be logged either: {events:?}"
        );
    }

    #[tokio::test]
    async fn serve_fails_closed_when_the_origin_drops_inside_the_trailer_section() {
        let (up, origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
        // The origin sends the head, the chunk and a section cut off mid-field, then
        // hangs up. Nothing in it is a complete trailer section.
        let _origin = tokio::spawn(async move {
            let mut io = origin_end;
            let mut request = [0u8; 512];
            let _ = io.read(&mut request).await;
            for segment in [TRAILER_HEAD, "0\r\nx-sum: abc\r\nx-e2e: m"] {
                io.write_all(segment.as_bytes())
                    .await
                    .expect("origin write");
                io.flush().await.expect("origin flush");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // `io` is dropped here: the connection closes inside the section.
        });

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                client
                    .write_all(get_request("/t", "127.0.0.1:8080").as_bytes())
                    .await
                    .expect("send");
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an origin that drops mid-section fails the connection");
        assert!(
            err.to_string().contains("closed before completing"),
            "error: {err}"
        );
        assert!(
            closed,
            "the proxy must hang up, not keep the client waiting"
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            TRAILER_HEAD,
            "the client has the head and the chunk, and never a terminator"
        );
        let flow = stored_http(&ctx, "/t");
        assert!(
            flow.response
                .as_ref()
                .is_some_and(|r| r.trailers.is_empty()),
            "half a section is not captured as the origin's trailers"
        );
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Error { flow: f, .. } if *f == flow.id))
                .count(),
            1,
            "one typed error for the broken response: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::Response(f) if *f == flow.id)),
            "an incomplete response is never dispatched as complete: {events:?}"
        );
    }
    // ---- finalising a response that ends early ----------------------------

    /// The head of a response that declares ten body bytes. An origin that stops
    /// after fewer leaves the body incomplete: a `Content-Length` body is never
    /// completed by a close, so an EOF after it is premature.
    const PARTIAL_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";

    /// The path the clients below request, and their flow is stored under.
    const PARTIAL_PATH: &str = "/t";

    /// Read one request head from `io`, an origin's end, and discard it. The
    /// origins below answer whatever was asked, but must not answer before the
    /// proxy has forwarded the request: one that replied and closed first would
    /// fail the forward, not the response.
    async fn read_request_head(io: &mut DuplexStream) {
        let mut held: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 512];
        while !held.windows(4).any(|w| w == b"\r\n\r\n") {
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => held.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Write `bytes` to an origin's end and flush them, as one segment.
    async fn origin_write(io: &mut DuplexStream, bytes: &[u8]) {
        io.write_all(bytes).await.expect("origin write");
        io.flush().await.expect("origin flush");
    }

    /// Send `GET /t` on the client end.
    async fn send_partial_get(client: &mut DuplexStream) {
        client
            .write_all(get_request(PARTIAL_PATH, "127.0.0.1:8080").as_bytes())
            .await
            .expect("send");
    }

    /// The typed errors dispatched for `flow`, in order.
    fn errors_for(events: &[Event], flow: FlowId) -> Vec<&aitm_core::FlowError> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Error { flow: f, kind } if *f == flow => Some(kind),
                _ => None,
            })
            .collect()
    }

    /// Whether `Event::Response` was dispatched for `flow`.
    fn dispatched_as_complete(events: &[Event], flow: FlowId) -> bool {
        events
            .iter()
            .any(|e| matches!(e, Event::Response(f) if *f == flow))
    }

    /// Asserts that `flow`'s response was finalised as abandoned: its body is
    /// `Bytes(body)`, it is marked truncated and it has a duration.
    fn assert_abandoned(flow: &HttpFlow, body: &[u8]) {
        let resp = flow
            .response
            .as_ref()
            .expect("the response head was stored");
        assert!(
            matches!(&resp.body, Body::Bytes(b) if b == body),
            "the bytes captured before the failure are the stored body: {:?}",
            resp.body
        );
        assert!(
            flow.metadata.truncated,
            "an abandoned response is marked truncated"
        );
        assert!(
            flow.metadata.duration.is_some(),
            "an abandoned response has a duration"
        );
    }

    /// Records every event, in order, and, when `Event::Error` is dispatched for
    /// an HTTP flow, what the store held for it at that moment (whether the
    /// response body was already `Bytes(expect_body)`, and whether the flow was
    /// already marked truncated), as a plugin, or the MCP push built from the
    /// store on that event, would see it.
    struct ErrorProbe {
        store: Arc<MemFlowStore>,
        events: Mutex<Vec<Event>>,
        at_error: Mutex<Vec<(bool, bool)>>,
        /// The buffered body the probe expects to find at dispatch time.
        expect_body: &'static [u8],
    }

    impl EventSink for ErrorProbe {
        fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
            if let Event::Error { flow, .. } = &ev {
                if let Some(Flow::Http(f)) = self.store.get(*flow) {
                    let buffered = f.response.as_ref().is_some_and(
                        |r| matches!(&r.body, Body::Bytes(b) if b.as_slice() == self.expect_body),
                    );
                    self.at_error
                        .lock()
                        .expect("at_error lock")
                        .push((buffered, f.metadata.truncated));
                }
            }
            self.events.lock().expect("events lock").push(ev);
            Box::pin(async { Verdict::Continue })
        }
    }

    #[tokio::test]
    async fn serve_finalises_the_response_when_the_upstream_closes_mid_body() {
        // AC3: the flow becomes terminal, holding what was captured. AC4: it is
        // so by the time the typed error is dispatched.
        let (up, mut origin_end) = duplex(64 * 1024);
        let store = Arc::new(MemFlowStore::new());
        let sink = Arc::new(ErrorProbe {
            store: store.clone(),
            events: Mutex::new(Vec::new()),
            at_error: Mutex::new(Vec::new()),
            expect_body: b"abc",
        });
        let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store, sink.clone());
        let _origin = tokio::spawn(async move {
            read_request_head(&mut origin_end).await;
            origin_write(&mut origin_end, PARTIAL_HEAD.as_bytes()).await;
            origin_write(&mut origin_end, b"abc").await;
            // Dropping the origin's end closes the connection seven bytes short.
        });

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                send_partial_get(&mut client).await;
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an origin that closes mid-body fails the connection");
        assert!(
            err.to_string()
                .contains("upstream closed before completing the response"),
            "error: {err}"
        );
        assert!(closed, "the proxy hangs up on the client");
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!("{PARTIAL_HEAD}abc"),
            "the client received what the origin sent, and no more"
        );
        let flow = stored_http(&ctx, PARTIAL_PATH);
        assert_abandoned(&flow, b"abc");
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            errors_for(&events, flow.id),
            vec![&aitm_core::FlowError::Upstream(
                "upstream closed before completing the response".to_string()
            )],
            "one typed error, in fixed words: {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
        assert_eq!(
            *sink.at_error.lock().expect("at_error lock"),
            vec![(true, true)],
            "the store holds the buffered, truncated response when Event::Error is dispatched"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn serve_finalises_the_response_when_the_upstream_read_times_out() {
        // AC5. The clock is paused: the 30 s `READ_TIMEOUT` is reached the moment
        // every task is idle, so the test takes a fraction of a second of wall
        // time. `with_serve` is not used because its 5 s guard would fire first.
        let (up, mut origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(Vec::new());
        let _origin = tokio::spawn(async move {
            read_request_head(&mut origin_end).await;
            origin_write(&mut origin_end, PARTIAL_HEAD.as_bytes()).await;
            origin_write(&mut origin_end, b"abc").await;
            // Hold the connection open and send nothing more.
            std::future::pending::<()>().await;
        });
        let (mut client, proxy_side) = duplex(64 * 1024);
        let serving = serve(
            &ctx,
            Box::pin(proxy_side),
            Some(Box::pin(up)),
            None,
            Conn::plain(unknown_peer(), None),
            MAX_BODY,
        );
        let script = async {
            send_partial_get(&mut client).await;
            let head =
                read_up_to(&mut client, PARTIAL_HEAD.len() + 3, Duration::from_secs(5)).await;
            let (rest, closed) = read_to_close(&mut client, Duration::from_secs(40)).await;
            (head, rest, closed)
        };
        let wall = std::time::Instant::now();
        let (served, (head, rest, closed)) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(serving, script)
        })
        .await
        .expect("serve hung past the read timeout");
        let wall = wall.elapsed();

        let err = served.expect_err("an origin that goes quiet mid-body fails the connection");
        assert!(
            err.to_string().contains("upstream read timed out"),
            "error: {err}"
        );
        assert_eq!(
            String::from_utf8_lossy(&head),
            format!("{PARTIAL_HEAD}abc"),
            "the client received what the origin sent"
        );
        assert!(
            rest.is_empty() && closed,
            "nothing more arrives, then the proxy hangs up: {rest:?}, closed: {closed}"
        );
        // A real 30 s wait would blow this bound: it proves the timeout was
        // reached on the paused clock, with slack for a loaded machine.
        assert!(wall < Duration::from_secs(10), "took {wall:?} of wall time");
        let flow = stored_http(&ctx, PARTIAL_PATH);
        assert_abandoned(&flow, b"abc");
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert!(
            errors_for(&events, flow.id).is_empty(),
            "no typed error is dispatched on this path (spec D4): {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
    }

    #[tokio::test]
    async fn serve_finalises_the_response_when_the_client_goes_away_mid_body() {
        // AC7. The origin stays alive throughout: what fails is the forward of
        // `def` to a client that has hung up.
        let (up, mut origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
        let client_gone = Arc::new(tokio::sync::Notify::new());
        let told = client_gone.clone();
        let _origin = tokio::spawn(async move {
            read_request_head(&mut origin_end).await;
            origin_write(&mut origin_end, PARTIAL_HEAD.as_bytes()).await;
            origin_write(&mut origin_end, b"abc").await;
            told.notified().await;
            origin_write(&mut origin_end, b"def").await;
            // Hold the connection open: the origin never fails this exchange.
            std::future::pending::<()>().await;
        });

        let (served, got) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                send_partial_get(&mut client).await;
                let got =
                    read_up_to(&mut client, PARTIAL_HEAD.len() + 3, Duration::from_secs(2)).await;
                drop(client);
                client_gone.notify_one();
                got
            },
        )
        .await;

        let err = served.expect_err("a client that hangs up mid-body fails the connection");
        assert!(
            !err.to_string().contains("upstream"),
            "the failure is the client's, not the origin's: {err}"
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!("{PARTIAL_HEAD}abc"),
            "the client read the head and the first chunk before hanging up"
        );
        let flow = stored_http(&ctx, PARTIAL_PATH);
        // `def` was captured before its forward failed.
        assert_abandoned(&flow, b"abcdef");
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert!(
            errors_for(&events, flow.id).is_empty(),
            "no typed error is dispatched on this path (spec D4): {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
    }

    // ---- tester additions: the remaining exits and inputs of the funnel -------

    /// An origin whose connection fails with an I/O **error** (not an EOF) once
    /// its scripted reply has been read: `read` returns `ConnectionReset`, which
    /// is the h1 loop's `Ok(r) => r?` exit (spec D4, "upstream I/O error").
    /// Writes are accepted and discarded; the reply is released only after the
    /// request has been written, like a real origin.
    struct ResettingOrigin {
        reply: Vec<u8>,
        pos: usize,
        request_seen: bool,
        waiting: Option<std::task::Waker>,
    }

    impl ResettingOrigin {
        fn replying(reply: Vec<u8>) -> Self {
            Self {
                reply,
                pos: 0,
                request_seen: false,
                waiting: None,
            }
        }
    }

    impl AsyncRead for ResettingOrigin {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskCx<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if !this.request_seen {
                this.waiting = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if this.pos < this.reply.len() {
                let n = buf.remaining().min(this.reply.len() - this.pos);
                buf.put_slice(&this.reply[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "origin connection reset",
            )))
        }
    }

    impl AsyncWrite for ResettingOrigin {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut TaskCx<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.request_seen = true;
            if let Some(waker) = this.waiting.take() {
                waker.wake();
            }
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn serve_finalises_the_response_when_the_upstream_read_fails() {
        // Spec D4, "upstream I/O error": the read itself fails rather than
        // returning EOF. No typed error is owed on this path, but the store must
        // be finalised like on every other exit.
        let origin = ResettingOrigin::replying(format!("{PARTIAL_HEAD}abc").into_bytes());
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(origin)]);

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                send_partial_get(&mut client).await;
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err =
            served.expect_err("an origin whose connection resets mid-body fails the connection");
        assert!(
            err.to_string().contains("origin connection reset"),
            "the connection's own I/O error is what serve returns: {err}"
        );
        assert!(
            !err.to_string().contains("upstream closed"),
            "an I/O error is not mistaken for a clean close: {err}"
        );
        assert!(closed, "the proxy hangs up on the client");
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!("{PARTIAL_HEAD}abc"),
            "the client received what the origin sent before the reset"
        );
        let flow = stored_http(&ctx, PARTIAL_PATH);
        assert_abandoned(&flow, b"abc");
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert!(
            errors_for(&events, flow.id).is_empty(),
            "no typed error is dispatched on this path (spec D4): {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
    }

    #[tokio::test]
    async fn serve_finalises_an_empty_response_when_the_upstream_closes_after_the_head() {
        // Empty input on the abandon path: not one body byte arrived before the
        // origin closed. The response is finalised as `Body::Empty` (never
        // `Bytes(vec![])`), truncated and terminal, with the one typed error any
        // early close owes.
        let (up, mut origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
        let _origin = tokio::spawn(async move {
            read_request_head(&mut origin_end).await;
            origin_write(&mut origin_end, PARTIAL_HEAD.as_bytes()).await;
            // Dropping the origin's end closes the connection with the whole body owed.
        });

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                send_partial_get(&mut client).await;
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an origin that closes after the head fails the connection");
        assert!(
            err.to_string()
                .contains("upstream closed before completing the response"),
            "error: {err}"
        );
        assert!(closed, "the proxy hangs up on the client");
        assert_eq!(
            String::from_utf8_lossy(&got),
            PARTIAL_HEAD,
            "the client received the head and nothing else"
        );
        let flow = stored_http(&ctx, PARTIAL_PATH);
        let resp = flow
            .response
            .as_ref()
            .expect("the response head was stored");
        assert_eq!(resp.status, 200);
        assert!(
            matches!(resp.body, Body::Empty),
            "nothing captured is `Empty`, not `Bytes([])`: {:?}",
            resp.body
        );
        assert!(
            flow.metadata.truncated,
            "an abandoned response is truncated"
        );
        assert!(
            flow.metadata.duration.is_some(),
            "an abandoned response has a duration"
        );
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned empty response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            errors_for(&events, flow.id),
            vec![&aitm_core::FlowError::Upstream(
                "upstream closed before completing the response".to_string()
            )],
            "one typed error, in fixed words: {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
    }

    #[tokio::test]
    async fn serve_caps_an_abandoned_body_at_max_body() {
        // Oversized input: the capture buffer is bounded by `max_body` on the
        // abandon path exactly as on the completed path (spec Constraints,
        // Security), while the client still receives every byte the origin sent.
        const CAP: usize = 4;
        let (up, mut origin_end) = duplex(64 * 1024);
        let (ctx, _dialed, sink) = ctx_recording(vec![Box::pin(up)]);
        let _origin = tokio::spawn(async move {
            read_request_head(&mut origin_end).await;
            origin_write(&mut origin_end, PARTIAL_HEAD.as_bytes()).await;
            origin_write(&mut origin_end, b"abcdef").await;
            // Six of ten bytes, then the origin's end is dropped.
        });

        let (served, (got, closed)) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            CAP,
            |mut client| async move {
                send_partial_get(&mut client).await;
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an origin that closes mid-body fails the connection");
        assert!(
            err.to_string()
                .contains("upstream closed before completing the response"),
            "error: {err}"
        );
        assert!(closed, "the proxy hangs up on the client");
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!("{PARTIAL_HEAD}abcdef"),
            "the wire is unchanged: the client got every byte, cap or no cap"
        );
        let flow = stored_http(&ctx, PARTIAL_PATH);
        // Only the first `CAP` bytes are retained; the marker covers both the
        // cap and the early end.
        assert_abandoned(&flow, b"abcd");
        assert_eq!(
            ctx.store().clear(),
            aitm_core::ClearOutcome {
                cleared: 1,
                skipped_in_flight: 0
            },
            "an abandoned, capped response is terminal"
        );
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            errors_for(&events, flow.id).len(),
            1,
            "one typed error: {events:?}"
        );
        assert!(
            !dispatched_as_complete(&events, flow.id),
            "an abandoned response is never dispatched as complete: {events:?}"
        );
    }

    #[tokio::test]
    async fn serve_finalises_the_store_before_the_malformed_error_is_dispatched() {
        // AC4's store-then-event order on the other path that dispatches a typed
        // error (spec D3): when the machine refuses the origin's bytes after the
        // head and a chunk were stored, the sink handling `Event::Error` already
        // sees the response buffered (`hello`) and truncated.
        let mut section = String::from("0\r\n");
        for n in 0..65 {
            section.push_str(&format!("x-evil-91c2-{n}: v\r\n"));
        }
        section.push_str("\r\n");
        let (up, origin_end) = duplex(64 * 1024);
        let store = Arc::new(MemFlowStore::new());
        let sink = Arc::new(ErrorProbe {
            store: store.clone(),
            events: Mutex::new(Vec::new()),
            at_error: Mutex::new(Vec::new()),
            expect_body: b"hello",
        });
        let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store, sink.clone());
        let _origin = tokio::spawn(origin_replying(
            origin_end,
            Arc::new(Mutex::new(Vec::new())),
            vec![vec![TRAILER_HEAD.to_string(), section]],
        ));

        let (served, _) = with_serve(
            &ctx,
            Conn::plain(unknown_peer(), None),
            None,
            MAX_BODY,
            |mut client| async move {
                send_partial_get(&mut client).await;
                read_to_close(&mut client, Duration::from_secs(2)).await
            },
        )
        .await;

        let err = served.expect_err("an over-cap trailer section fails the connection");
        assert!(err.to_string().contains("trailer"), "error: {err}");
        let flow = stored_http(&ctx, PARTIAL_PATH);
        assert_abandoned(&flow, b"hello");
        let events = sink.events.lock().expect("events lock");
        assert_eq!(
            errors_for(&events, flow.id),
            vec![&aitm_core::FlowError::Upstream(
                "malformed response from upstream".to_string()
            )],
            "one typed error, in fixed words: {events:?}"
        );
        assert_eq!(
            *sink.at_error.lock().expect("at_error lock"),
            vec![(true, true)],
            "the store holds the buffered, truncated response when Event::Error is dispatched"
        );
    }

    // ---- Tester additions (whole-branch stage 5): capture attribution on the
    // TLS, h2 and upgrade paths, which the SA-AC0 tests above do not reach.
    mod attribution {
        use super::*;

        /// A CA in a fresh temp dir, so a MITM test never touches the user's CA.
        pub(super) fn test_ca() -> Arc<CertAuthority> {
            let dir = std::env::temp_dir().join(format!("aitm-attr-ca-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("ca dir");
            Arc::new(CertAuthority::load_or_generate(&dir, 0o600).expect("test CA"))
        }

        /// The hint a capture ingress attaches: Safari on the macOS NE backend.
        fn attributed_hint(is_tls: bool, first_bytes: Vec<u8>) -> NextLayerHint {
            NextLayerHint {
                dst: unknown_peer(),
                is_tls,
                client_hello_sni: None,
                alpn: vec![],
                first_bytes,
                from_upgrade: false,
                peer_identity: Some("com.apple.Safari".into()),
                capture_interface: Some("macos-ne".into()),
            }
        }

        /// The stored HTTP flow for `path` in `store` (the context is consumed by
        /// the driver under test, so the store is read directly).
        fn stored_in(store: &MemFlowStore, path: &str) -> HttpFlow {
            store
                .list()
                .into_iter()
                .find_map(|id| match store.get(id) {
                    Some(Flow::Http(f)) if f.request.path == path => Some(f),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no stored flow for {path}"))
        }

        fn assert_attributed(flow: &HttpFlow) {
            assert_eq!(
                flow.metadata.source_app.as_deref(),
                Some("com.apple.Safari")
            );
            assert_eq!(flow.metadata.capture_interface.as_deref(), Some("macos-ne"));
            assert!(flow.metadata.marks.is_empty());
            assert!(!flow.metadata.is_replay);
        }

        /// Read one `Content-Length`-framed 200 from any stream (the TLS client end
        /// is not a `DuplexStream`, so [`client_get`] does not apply).
        pub(super) async fn read_one_200<S: AsyncRead + Unpin>(io: &mut S) -> String {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                let n = io.read(&mut chunk).await.expect("read head");
                assert!(
                    n > 0,
                    "EOF before the response head: {:?}",
                    String::from_utf8_lossy(&buf)
                );
                buf.extend_from_slice(&chunk[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            assert!(head.starts_with("HTTP/1.1 200"), "status line: {head}");
            let len: usize = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .expect("Content-Length")
                .parse()
                .expect("a numeric Content-Length");
            while buf.len() < head_end + len {
                let n = io.read(&mut chunk).await.expect("read body");
                assert!(n > 0, "EOF before the body ended");
                buf.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned()
        }

        /// SA-AC0 on the TLS path: `mitm` builds its `Conn` from the hint, so a
        /// captured HTTPS request (h1 after the ALPN mirror) is stored attributed.
        /// The cleartext test above never reaches the `Conn` literal in `mitm`.
        #[tokio::test]
        async fn mitm_stamps_the_hint_attribution_on_the_stored_flow() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());

            // The origin: TLS over a duplex, one 200 then close.
            let (up_ours, up_origin) = duplex(64 * 1024);
            let origin = tokio::spawn(async move {
                let tls = TlsAcceptor::from(server_config(&[b"http/1.1"]))
                    .accept(up_origin)
                    .await
                    .expect("origin handshake");
                origin_serve(tls, vec!["first"], true).await;
            });
            let (ctx, _dialed) =
                ctx_with_sink(vec![Box::pin(up_ours)], store.clone(), Arc::new(NoSink));
            let ctx = ctx.with_hint(attributed_hint(true, vec![TLS_HANDSHAKE]));

            // The client: a real handshake against the forged leaf, one GET, hang up.
            let (client_end, proxy_side) = duplex(64 * 1024);
            let client_cfg = HttpModule::new()
                .with_insecure(true)
                .upstream_tls_alpn(&[b"http/1.1".to_vec()])
                .expect("client config");
            let script = async move {
                let mut tls = TlsConnector::from(client_cfg)
                    .connect(
                        ServerName::try_from("origin.test").expect("name"),
                        client_end,
                    )
                    .await
                    .expect("client handshake against the forged leaf");
                tls.write_all(get_request("/one", "origin.test:8443").as_bytes())
                    .await
                    .expect("send");
                tls.flush().await.expect("flush");
                let body = read_one_200(&mut tls).await;
                let _ = tls.shutdown().await;
                body
            };
            let proxy_side: ByteStream = Box::pin(proxy_side);
            let (target, request) = origin_tunnel();
            let serving = module.mitm(Prefixed::new(proxy_side), ctx, target, request);
            let (_served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("mitm hung");
            assert_eq!(
                body, "first",
                "the request went through the MITM to the origin"
            );
            origin.abort();

            assert_attributed(&stored_in(&store, "/one"));
        }

        /// SA-AC0 on the h2 path — the one Safari and Chrome take for a captured
        /// HTTPS site: `stream_task` stamps `conn.flow_meta()` on each stream's flow.
        /// `serve_h2` is driven directly over duplexes with the attributed `Conn`
        /// that `mitm` would have built after the ALPN mirror.
        #[tokio::test]
        async fn serve_h2_stamps_the_connection_attribution_on_the_stored_flow() {
            let module = HttpModule::new().with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, _dialed) = ctx_with_sink(vec![], store.clone(), Arc::new(NoSink));
            let mut conn = Conn::plain(
                unknown_peer(),
                Some(("origin.test:443".to_string(), origin_addr())),
            );
            conn.scheme = "https".to_string();
            conn.source_app = Some("com.apple.Safari".into());
            conn.capture_interface = Some("macos-ne".into());

            // An h2 origin: 200 "first" for every stream, until the connection ends.
            let (up_ours, up_origin) = duplex(64 * 1024);
            let origin = tokio::spawn(async move {
                let mut server = h2::server::handshake(up_origin)
                    .await
                    .expect("origin h2 handshake");
                while let Some(Ok((request, mut respond))) = server.accept().await {
                    let (_head, mut body) = request.into_parts();
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    let response = http::Response::builder()
                        .status(200)
                        .body(())
                        .expect("response");
                    let mut send = respond
                        .send_response(response, false)
                        .expect("send response");
                    send.send_data(bytes::Bytes::from_static(b"first"), true)
                        .expect("send body");
                }
            });

            let (client_end, proxy_side) = duplex(64 * 1024);
            let upstream_h2_tls = module
                .upstream_tls_alpn(&[b"h2".to_vec()])
                .expect("h2 client config");
            let serving = crate::h2::serve_h2(
                Arc::new(ctx),
                Box::pin(proxy_side),
                Box::pin(up_ours),
                conn,
                MAX_BODY,
                16,
                upstream_h2_tls,
            );
            let script = async move {
                let (send_req, connection) = h2::client::handshake(client_end)
                    .await
                    .expect("client h2 handshake");
                let connection = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let mut ready = send_req.ready().await.expect("h2 ready");
                let request = http::Request::builder()
                    .method("GET")
                    .uri("https://origin.test/one")
                    .body(())
                    .expect("request");
                let (response, _body) = ready.send_request(request, true).expect("send request");
                let response = response.await.expect("response");
                assert_eq!(response.status().as_u16(), 200);
                let mut body = response.into_body();
                let mut got = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("body chunk");
                    let _ = body.flow_control().release_capacity(chunk.len());
                    got.extend_from_slice(&chunk);
                }
                // Hang up: dropping the handle and the connection closes the transport.
                drop(ready);
                connection.abort();
                got
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("serve_h2 hung");
            served.expect("serve_h2 ends when the client connection closes");
            assert_eq!(body, b"first");
            origin.abort();

            let flow = stored_in(&store, "/one");
            assert!(
                matches!(flow.request.version, aitm_core::HttpVersion::H2),
                "the flow came through the h2 driver"
            );
            assert_attributed(&flow);
        }

        /// The module an upgrade is re-dispatched to: records the hint it was
        /// spawned with and returns at once.
        struct RecordingUpgradeModule {
            hint: Mutex<Option<NextLayerHint>>,
        }

        impl ProtocolModule for RecordingUpgradeModule {
            fn id(&self) -> &str {
                "recording-upgrade"
            }

            fn matches(&self, hint: &NextLayerHint) -> bool {
                hint.from_upgrade
            }

            fn spawn(&self, _io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, Result<()>> {
                *self.hint.lock().expect("hint lock") = ctx.hint().cloned();
                Box::pin(async { Ok(()) })
            }
        }

        /// Spec D2: the upgrade hint `serve` hands the next module carries the
        /// connection's attribution, so the re-dispatched module sees what the
        /// handshake flow was stamped with — and the handshake flow is stamped too.
        #[tokio::test]
        async fn upgrade_handoff_hint_carries_the_connection_attribution() {
            let (up, origin_end) = duplex(64 * 1024);
            let store = Arc::new(MemFlowStore::new());
            let recorder = Arc::new(RecordingUpgradeModule {
                hint: Mutex::new(None),
            });
            let modules: Arc<[Arc<dyn ProtocolModule>]> =
                Arc::from(vec![recorder.clone() as Arc<dyn ProtocolModule>]);
            let (ctx, _dialed) = ctx_with_sink(vec![Box::pin(up)], store.clone(), Arc::new(NoSink));
            let ctx = ctx
                .with_modules(modules)
                .with_hint(attributed_hint(false, b"GET ".to_vec()));

            // An origin that answers the upgrade with a 101 and then holds the line.
            let origin = tokio::spawn(async move {
                let mut io = origin_end;
                let mut seen = Vec::new();
                let mut chunk = [0u8; 256];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match io.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = io
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    )
                    .await;
                let _ = io.flush().await;
                while matches!(io.read(&mut chunk).await, Ok(n) if n > 0) {}
            });

            let module = HttpModule::new();
            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(
                        b"GET /chat HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                    )
                    .await
                    .expect("send the upgrade request");
                let mut buf = Vec::new();
                let mut chunk = [0u8; 256];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = client.read(&mut chunk).await.expect("read the 101");
                    assert!(
                        n > 0,
                        "EOF before the 101: {:?}",
                        String::from_utf8_lossy(&buf)
                    );
                    buf.extend_from_slice(&chunk[..n]);
                }
                String::from_utf8_lossy(&buf).into_owned()
            };
            let (served, head) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the upgrade hand-off hung");
            served.expect("serve returns the hand-off's result");
            assert!(
                head.starts_with("HTTP/1.1 101"),
                "the 101 reached the client: {head}"
            );
            origin.abort();

            let hint = recorder
                .hint
                .lock()
                .expect("hint lock")
                .clone()
                .expect("the upgrade module was spawned with a hint");
            assert!(hint.from_upgrade);
            assert!(
                hint.alpn
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case("websocket")),
                "alpn: {:?}",
                hint.alpn
            );
            assert_eq!(hint.peer_identity.as_deref(), Some("com.apple.Safari"));
            assert_eq!(hint.capture_interface.as_deref(), Some("macos-ne"));
            assert_attributed(&stored_in(&store, "/chat"));
        }
    }

    mod tunnel_rows {
        //! Spec D5/D6 through `spawn`: every `CONNECT` the HTTP module handles
        //! leaves one tunnel row with its outcome, the module decrypts only hosts
        //! in the live Scope and relays the rest itself (AC16: no passthrough
        //! module is registered here, so the relay is the HTTP module's own), and
        //! the flip follows the guard per connection (AC2–AC4). In-memory
        //! transports throughout: client, proxy and origin are duplex pairs.

        use super::attribution::{read_one_200, test_ca};
        use super::*;
        use aitm_core::tunnel::FIRST_BYTE_TIMEOUT;
        use aitm_core::{
            Chain, FlowCtx, Plugin, Registry, ResumeHandle, ScopeEntry, ScopeRateGuard, StdGuard,
            TunnelInfo, TunnelMode, TunnelReason,
        };
        use rustls::pki_types::pem::PemObject;
        use rustls::RootCertStore;

        /// The authority every test tunnels to: an IP literal, so resolving it
        /// needs no DNS and the forged leaf carries an IP SAN a verifying client
        /// accepts.
        const ORIGIN: &str = "127.0.0.1:8443";

        fn origin_peer() -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], 8443))
        }

        /// A live guard with `entries` in scope: what `scope.add` / `scope.remove`
        /// mutate, handed to the module context as the acceptor hands its own.
        fn scoped(entries: &[&str]) -> Arc<StdGuard> {
            let guard = Arc::new(StdGuard::default());
            for host in entries {
                guard.add_scope(ScopeEntry {
                    host: host.to_string(),
                });
            }
            guard
        }

        /// A context over `store` whose connector hands out `streams` (and refuses
        /// once they are gone), consulting `guard` for Scope.
        fn scoped_ctx(
            streams: Vec<ByteStream>,
            store: Arc<MemFlowStore>,
            guard: Arc<StdGuard>,
        ) -> (ModuleCtx, DialLog) {
            let (ctx, dialed) = ctx_with_sink(streams, store, Arc::new(NoSink));
            (ctx.with_scope(guard), dialed)
        }

        /// An origin's own TLS identity: a self-signed leaf for `origin.test`
        /// offering `http/1.1`, and its DER so a test can check which certificate
        /// a client was shown.
        fn origin_identity() -> (Arc<ServerConfig>, CertificateDer<'static>) {
            origin_identity_named("origin.test")
        }

        /// [`origin_identity`] for an origin named `name` (the raw-TLS route
        /// resolves the SNI, and `localhost` is the one name that resolves offline).
        fn origin_identity_named(name: &str) -> (Arc<ServerConfig>, CertificateDer<'static>) {
            let key = rcgen::KeyPair::generate().expect("key");
            let cert = rcgen::CertificateParams::new(vec![name.to_string()])
                .expect("params")
                .self_signed(&key)
                .expect("cert");
            let der = cert.der().clone();
            let mut cfg = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("server config");
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            (Arc::new(cfg), der)
        }

        /// A TLS origin over a duplex: it accepts a handshake as `identity`, then
        /// answers each request with the next of `bodies` (keep-alive, held open
        /// until the far end hangs up). Returns the proxy-facing end.
        fn tls_origin(
            identity: Arc<ServerConfig>,
            bodies: Vec<&'static str>,
        ) -> (ByteStream, tokio::task::JoinHandle<()>) {
            let (ours, theirs) = duplex(64 * 1024);
            let task = tokio::spawn(async move {
                if let Ok(tls) = TlsAcceptor::from(identity).accept(theirs).await {
                    origin_serve(tls, bodies, false).await;
                }
            });
            (Box::pin(ours), task)
        }

        /// A client config trusting exactly `root`, offering `http/1.1`: a browser
        /// with that one certificate installed.
        fn trusting(root: CertificateDer<'static>) -> Arc<ClientConfig> {
            let mut roots = RootCertStore::empty();
            roots.add(root).expect("add root");
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        }

        /// The proxy CA's root, as a client that trusts the proxy installs it.
        fn ca_root(ca: &CertAuthority) -> CertificateDer<'static> {
            CertificateDer::from_pem_slice(ca.root_cert_pem().as_bytes()).expect("root PEM")
        }

        /// A client config that verifies nothing, for looking at which certificate
        /// the far end presented.
        fn accepting_any() -> Arc<ClientConfig> {
            HttpModule::new()
                .with_insecure(true)
                .upstream_tls_alpn(&[b"http/1.1".to_vec()])
                .expect("client config")
        }

        fn ip_name() -> ServerName<'static> {
            ServerName::try_from("127.0.0.1".to_string()).expect("ip name")
        }

        fn origin_name() -> ServerName<'static> {
            ServerName::try_from("origin.test").expect("name")
        }

        /// Send `CONNECT authority` on `client` and return the proxy's answer head
        /// (empty when the proxy closed without one). Read a byte at a time so
        /// nothing past the head is consumed: the TLS handshake follows it.
        async fn connect(client: &mut DuplexStream, authority: &str) -> String {
            client
                .write_all(
                    format!(
                        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("send CONNECT");
            read_head(client).await
        }

        async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> String {
            let mut got = Vec::new();
            let mut byte = [0u8; 1];
            while !got.ends_with(b"\r\n\r\n") {
                match io.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => got.push(byte[0]),
                }
            }
            String::from_utf8_lossy(&got).into_owned()
        }

        /// `GET path` over `io` (a TLS session through the tunnel) and its 200 body.
        async fn get<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, path: &str) -> String {
            io.write_all(get_request(path, ORIGIN).as_bytes())
                .await
                .expect("send GET");
            io.flush().await.expect("flush");
            read_one_200(io).await
        }

        /// The certificate the far end of `tls` presented.
        fn presented<IO>(tls: &tokio_rustls::client::TlsStream<IO>) -> CertificateDer<'static> {
            tls.get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .cloned()
                .expect("the far end presented a certificate")
        }

        /// The stored tunnel rows (`CONNECT` requests), oldest first.
        fn tunnel_rows(store: &MemFlowStore) -> Vec<HttpFlow> {
            store
                .list()
                .into_iter()
                .filter_map(|id| match store.get(id) {
                    Some(Flow::Http(f)) if f.request.method == "CONNECT" => Some(f),
                    _ => None,
                })
                .collect()
        }

        /// The paths of every stored request that is not a tunnel row, oldest first.
        fn request_paths(store: &MemFlowStore) -> Vec<String> {
            store
                .list()
                .into_iter()
                .filter_map(|id| match store.get(id) {
                    Some(Flow::Http(f)) if f.request.method != "CONNECT" => Some(f.request.path),
                    _ => None,
                })
                .collect()
        }

        /// The stored request row for `path`.
        fn request_row(store: &MemFlowStore, path: &str) -> HttpFlow {
            store
                .list()
                .into_iter()
                .find_map(|id| match store.get(id) {
                    Some(Flow::Http(f)) if f.request.path == path => Some(f),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no stored flow for {path}"))
        }

        /// `(mode, reason)` of a tunnel row's outcome.
        fn outcome(row: &HttpFlow) -> (TunnelMode, Option<TunnelReason>) {
            let tunnel = row
                .metadata
                .tunnel
                .as_ref()
                .expect("a tunnel row carries its outcome");
            (tunnel.mode, tunnel.reason)
        }

        fn status(row: &HttpFlow) -> Option<u16> {
            row.response.as_ref().map(|r| r.status)
        }

        /// AC2 (unit), D5: an in-scope CONNECT is decrypted. One `decrypted` row
        /// with the acknowledgement's 200, open (no duration) while the client
        /// holds the connection and closed with a duration when it leaves; the
        /// request inside it is its own row, not passive, not a tunnel.
        #[tokio::test]
        async fn in_scope_connect_records_a_decrypted_row_and_its_inner_request() {
            let ca = test_ca();
            let module = HttpModule::with_ca(ca.clone()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, _origin_der) = origin_identity();
            let (upstream, origin) = tls_origin(identity, vec!["secret"]);
            let (ctx, dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls = TlsConnector::from(trusting(ca_root(&ca)))
                    .connect(ip_name(), client)
                    .await
                    .expect("a client that trusts the proxy CA completes the handshake");
                let body = get(&mut tls, "/secret").await;
                // While the client holds the tunnel, its row is open.
                let rows = tunnel_rows(&store);
                assert_eq!(rows.len(), 1, "one tunnel row while the tunnel is open");
                assert_eq!(outcome(&rows[0]), (TunnelMode::Decrypted, None));
                assert_eq!(status(&rows[0]), Some(200));
                assert_eq!(
                    rows[0].metadata.duration, None,
                    "an open tunnel has no duration yet"
                );
                let _ = tls.shutdown().await;
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the decrypted tunnel hung");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "secret");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(row.request.scheme, "https");
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(row.request.path, "");
            assert_eq!(row.request.headers.get("host"), Some("127.0.0.1:8443"));
            assert_eq!(
                row.request.headers.get("proxy-connection"),
                Some("keep-alive")
            );
            assert_eq!(status(row), Some(200));
            assert_eq!(row.metadata.tunnel, Some(TunnelInfo::decrypted()));
            assert!(
                row.metadata.duration.is_some(),
                "closing the connection closes the row"
            );
            assert!(!row.metadata.passive);
            assert!(row.client_conn.tls);
            assert_eq!(row.client_conn.alpn.as_deref(), Some("http/1.1"));
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the decrypted row names the origin it dialled"
            );
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![("127.0.0.1:8443".to_string(), origin_peer())]
            );

            let inner = request_row(&store, "/secret");
            assert_eq!(inner.request.method, "GET");
            assert_eq!(inner.request.scheme, "https");
            assert_eq!(inner.request.authority, "127.0.0.1:8443");
            assert_eq!(status(&inner), Some(200));
            assert!(
                !inner.metadata.passive,
                "a request inside a decrypted tunnel is acted on"
            );
            assert_eq!(
                inner.metadata.tunnel, None,
                "an inner request is not a tunnel row"
            );
            assert_eq!(request_paths(&store), vec!["/secret".to_string()]);
        }

        /// AC1 (unit), AC16, D2: with an empty Scope the HTTP module itself relays
        /// the CONNECT byte for byte — the client completes TLS against the
        /// origin's own certificate — and records one `passthrough/out_of_scope`
        /// row with the bytes moved; nothing inside the tunnel becomes a row.
        #[tokio::test]
        async fn out_of_scope_connect_is_relayed_not_decrypted() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, origin_der) = origin_identity();
            let (upstream, origin) = tls_origin(identity, vec!["secret"]);
            let (ctx, dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls = TlsConnector::from(accepting_any())
                    .connect(origin_name(), client)
                    .await
                    .expect("the handshake with the origin goes through the relay");
                assert_eq!(
                    presented(&tls),
                    origin_der,
                    "the client must see the origin's own certificate, not a proxy leaf"
                );
                let body = get(&mut tls, "/secret").await;
                let rows = tunnel_rows(&store);
                assert_eq!(rows.len(), 1, "one tunnel row while the relay is open");
                assert_eq!(
                    outcome(&rows[0]),
                    (TunnelMode::Passthrough, Some(TunnelReason::OutOfScope))
                );
                assert_eq!(status(&rows[0]), Some(200));
                assert_eq!(rows[0].metadata.duration, None, "open: no duration yet");
                let _ = tls.shutdown().await;
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the relayed tunnel hung");
            served.expect("the relay ends cleanly when the client hangs up");
            assert_eq!(body, "secret", "the origin's answer was relayed");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(row.request.headers.get("host"), Some("127.0.0.1:8443"));
            assert_eq!(status(row), Some(200));
            let tunnel = row.metadata.tunnel.clone().expect("tunnel outcome");
            assert_eq!(tunnel.mode, TunnelMode::Passthrough);
            assert_eq!(tunnel.reason, Some(TunnelReason::OutOfScope));
            assert!(tunnel.bytes_up.is_some_and(|n| n > 0), "{tunnel:?}");
            assert!(tunnel.bytes_down.is_some_and(|n| n > 0), "{tunnel:?}");
            assert!(row.metadata.duration.is_some(), "closed: duration set");
            assert!(!row.metadata.passive);
            assert!(row.client_conn.tls);
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer())
            );
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![("127.0.0.1:8443".to_string(), origin_peer())]
            );
            assert!(
                request_paths(&store).is_empty(),
                "nothing inside a relayed tunnel is a row: {:?}",
                request_paths(&store)
            );
            assert_eq!(
                store.count(),
                1,
                "the tunnel row is the only row for the host"
            );
        }

        /// AC5 (unit): an in-scope host, a client that does not trust the proxy CA
        /// (Safari, curl without --cacert). The handshake fails with the client's
        /// alert and the row says so: `failed/client_rejected_certificate`, no
        /// status, closed.
        #[tokio::test]
        async fn client_that_rejects_our_leaf_is_a_failed_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, _origin_der) = origin_identity();
            let (upstream, origin) = tls_origin(identity, vec![]);
            let (ctx, _dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&["127.0.0.1"]));
            // The client trusts one unrelated root and nothing else.
            let (_unrelated, unrelated_root) = origin_identity();

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                TlsConnector::from(trusting(unrelated_root))
                    .connect(ip_name(), client)
                    .await
                    .expect_err("a client that does not trust the proxy CA must refuse the leaf")
            };
            let (served, client_err) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the refused handshake hung");
            origin.abort();
            let err = served.expect_err("the connection ends with the handshake error");
            assert_eq!(err.to_string(), "client TLS handshake");
            assert!(
                client_err.to_string().contains("UnknownIssuer"),
                "the client refused the issuer: {client_err}"
            );

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(
                outcome(row),
                (
                    TunnelMode::Failed,
                    Some(TunnelReason::ClientRejectedCertificate)
                )
            );
            assert_eq!(status(row), None, "a failed tunnel reports no status");
            assert!(row.metadata.duration.is_some(), "a failed row is closed");
            assert!(row.client_conn.tls);
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the origin had been dialled when the client refused"
            );
            assert!(request_paths(&store).is_empty());
        }

        /// AC6: a CONNECT acknowledged and then abandoned before a single byte
        /// (a speculative pre-connect) is `failed/client_closed`; nothing was
        /// dialled.
        #[tokio::test]
        async fn connect_then_eof_is_client_closed() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                drop(client);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the abandoned tunnel hung");
            served.expect("a client that leaves is not an error");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(
                outcome(row),
                (TunnelMode::Failed, Some(TunnelReason::ClientClosed))
            );
            assert_eq!(status(row), None);
            assert!(row.metadata.duration.is_some());
            assert!(!row.client_conn.tls, "no TLS byte was ever seen");
            assert!(row.server_conn.is_none(), "nothing was dialled");
            assert!(dialed.lock().expect("dialed lock").is_empty());
            assert_eq!(store.count(), 1);
        }

        /// AC6: the origin cannot be dialled (the connector refuses) →
        /// `failed/upstream_unreachable`, no origin on the row.
        #[tokio::test]
        async fn unreachable_origin_is_upstream_unreachable() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            // No streams: every dial is refused.
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                // The ClientHello goes out; the handshake fails once the proxy gives up.
                let _ = TlsConnector::from(accepting_any())
                    .connect(ip_name(), client)
                    .await;
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the refused dial hung");
            let err = served.expect_err("the connection ends with the dial error");
            assert_eq!(err.to_string(), "scope guard refused the dial");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(
                outcome(row),
                (TunnelMode::Failed, Some(TunnelReason::UpstreamUnreachable))
            );
            assert_eq!(status(row), None);
            assert!(row.metadata.duration.is_some());
            assert!(row.client_conn.tls);
            assert!(row.server_conn.is_none(), "no origin was reached");
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![("127.0.0.1:8443".to_string(), origin_peer())],
                "the dial was attempted once"
            );
        }

        /// AC6: the origin accepts the connection and closes before the TLS
        /// handshake → `failed/upstream_tls_failed`, with the origin on the row.
        #[tokio::test]
        async fn origin_tls_failure_is_upstream_tls_failed() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, theirs) = duplex(64 * 1024);
            // An origin that hung up right after the TCP accept.
            drop(theirs);
            let (ctx, _dialed) =
                scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let _ = TlsConnector::from(accepting_any())
                    .connect(ip_name(), client)
                    .await;
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the failed origin handshake hung");
            let err = served.expect_err("the connection ends with the origin handshake error");
            assert_eq!(err.to_string(), "TLS to upstream 127.0.0.1:8443");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_eq!(
                outcome(row),
                (TunnelMode::Failed, Some(TunnelReason::UpstreamTlsFailed))
            );
            assert_eq!(status(row), None);
            assert!(row.metadata.duration.is_some());
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the origin was dialled before its handshake failed"
            );
        }

        /// AC6: a CONNECT whose authority is not one (`CONNECT /secret`) is
        /// `failed/protocol_error`, recorded with the raw text as its label and
        /// its headers, and answered with nothing.
        #[tokio::test]
        async fn malformed_connect_is_protocol_error() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(b"CONNECT /secret HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n")
                    .await
                    .expect("send the malformed CONNECT");
                read_head(&mut client).await
            };
            let (served, reply) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the malformed CONNECT hung");
            let err = served.expect_err("a malformed CONNECT fails the connection");
            assert_eq!(
                err.to_string(),
                "malformed CONNECT authority: authority \"/secret\" has an invalid host"
            );
            assert_eq!(reply, "", "the proxy replies nothing and closes");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(
                row.request.authority, "/secret:443",
                "the raw authority text is the row's label"
            );
            assert_eq!(row.request.headers.get("host"), Some("127.0.0.1:8443"));
            assert_eq!(
                outcome(row),
                (TunnelMode::Failed, Some(TunnelReason::ProtocolError))
            );
            assert_eq!(status(row), None);
            assert!(row.metadata.duration.is_some());
            assert!(!row.client_conn.tls);
            assert!(row.server_conn.is_none());
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// AC2 + AC4: `scope.add` while a relayed tunnel is open. That tunnel stays
        /// a relay (its next request is still not captured); the next connection
        /// to the host is decrypted.
        #[tokio::test]
        async fn scope_add_decrypts_the_next_connection_not_the_open_one() {
            let ca = test_ca();
            let module = HttpModule::with_ca(ca.clone()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let guard = scoped(&[]);
            let (identity, origin_der) = origin_identity();
            let (up_a, origin_a) = tls_origin(identity.clone(), vec!["one", "two"]);
            let (up_b, origin_b) = tls_origin(identity, vec!["three"]);
            let (ctx_a, _) = scoped_ctx(vec![up_a], store.clone(), guard.clone());
            let (ctx_b, _) = scoped_ctx(vec![up_b], store.clone(), guard.clone());

            let (mut client_a, proxy_a) = duplex(64 * 1024);
            let (mut client_b, proxy_b) = duplex(64 * 1024);
            let serving_a = module.spawn(Box::pin(proxy_a), ctx_a);
            let serving_b = module.spawn(Box::pin(proxy_b), ctx_b);
            let script = async {
                // A: opened under the empty Scope, so relayed.
                let ack = connect(&mut client_a, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls_a = TlsConnector::from(accepting_any())
                    .connect(origin_name(), client_a)
                    .await
                    .expect("the first connection reaches the origin through the relay");
                assert_eq!(presented(&tls_a), origin_der);
                assert_eq!(get(&mut tls_a, "/one").await, "one");

                // The operator adds the host while A is open.
                guard.add_scope(ScopeEntry {
                    host: "127.0.0.1".to_string(),
                });

                // A is still a relay: its next request is not captured either.
                assert_eq!(get(&mut tls_a, "/two").await, "two");
                assert!(
                    request_paths(&store).is_empty(),
                    "a tunnel opened before scope.add stays a tunnel: {:?}",
                    request_paths(&store)
                );

                // B, opened now, is decrypted with the proxy's leaf.
                let ack = connect(&mut client_b, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls_b = TlsConnector::from(trusting(ca_root(&ca)))
                    .connect(ip_name(), client_b)
                    .await
                    .expect("the next connection is decrypted with the proxy's leaf");
                assert_eq!(get(&mut tls_b, "/three").await, "three");

                let _ = tls_a.shutdown().await;
                let _ = tls_b.shutdown().await;
            };
            let (served_a, served_b, ()) = tokio::time::timeout(STALL_GUARD, async {
                tokio::join!(serving_a, serving_b, script)
            })
            .await
            .expect("the scope.add flip hung");
            served_a.expect("the relay ends cleanly");
            served_b.expect("the decrypted tunnel ends cleanly");
            origin_a.abort();
            origin_b.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 2, "one row per connection");
            assert_eq!(
                outcome(&rows[0]),
                (TunnelMode::Passthrough, Some(TunnelReason::OutOfScope))
            );
            assert!(rows[0].metadata.duration.is_some());
            assert_eq!(outcome(&rows[1]), (TunnelMode::Decrypted, None));
            assert_eq!(status(&rows[1]), Some(200));
            assert_eq!(request_paths(&store), vec!["/three".to_string()]);
            assert!(!request_row(&store, "/three").metadata.passive);
        }

        /// AC3 + AC4: `scope.remove` while a decrypted tunnel is open. That tunnel
        /// keeps serving decrypted, captured requests (not passive); the next
        /// connection to the host is relayed and leaves no request row.
        #[tokio::test]
        async fn scope_remove_tunnels_the_next_connection_not_the_open_one() {
            let ca = test_ca();
            let module = HttpModule::with_ca(ca.clone()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let guard = scoped(&["127.0.0.1"]);
            let (identity, origin_der) = origin_identity();
            let (up_a, origin_a) = tls_origin(identity.clone(), vec!["one", "two"]);
            let (up_b, origin_b) = tls_origin(identity, vec!["three"]);
            let (ctx_a, _) = scoped_ctx(vec![up_a], store.clone(), guard.clone());
            let (ctx_b, _) = scoped_ctx(vec![up_b], store.clone(), guard.clone());

            let (mut client_a, proxy_a) = duplex(64 * 1024);
            let (mut client_b, proxy_b) = duplex(64 * 1024);
            let serving_a = module.spawn(Box::pin(proxy_a), ctx_a);
            let serving_b = module.spawn(Box::pin(proxy_b), ctx_b);
            let script = async {
                // A: opened in scope, so decrypted.
                let ack = connect(&mut client_a, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls_a = TlsConnector::from(trusting(ca_root(&ca)))
                    .connect(ip_name(), client_a)
                    .await
                    .expect("the first connection is decrypted with the proxy's leaf");
                assert_eq!(get(&mut tls_a, "/one").await, "one");
                assert_eq!(request_paths(&store), vec!["/one".to_string()]);

                // The operator removes the host while A is open.
                assert!(guard.remove_scope("127.0.0.1"));

                // A keeps serving decrypted: the next request is captured, not passive.
                assert_eq!(get(&mut tls_a, "/two").await, "two");
                assert_eq!(
                    request_paths(&store),
                    vec!["/one".to_string(), "/two".to_string()],
                    "a tunnel decrypted before scope.remove keeps capturing"
                );
                assert!(!request_row(&store, "/two").metadata.passive);

                // B, opened now, is relayed to the origin's own certificate.
                let ack = connect(&mut client_b, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls_b = TlsConnector::from(accepting_any())
                    .connect(origin_name(), client_b)
                    .await
                    .expect("the next connection reaches the origin through the relay");
                assert_eq!(presented(&tls_b), origin_der);
                assert_eq!(get(&mut tls_b, "/three").await, "three");

                let _ = tls_a.shutdown().await;
                let _ = tls_b.shutdown().await;
            };
            let (served_a, served_b, ()) = tokio::time::timeout(STALL_GUARD, async {
                tokio::join!(serving_a, serving_b, script)
            })
            .await
            .expect("the scope.remove flip hung");
            served_a.expect("the decrypted tunnel ends cleanly");
            served_b.expect("the relay ends cleanly");
            origin_a.abort();
            origin_b.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 2, "one row per connection");
            assert_eq!(outcome(&rows[0]), (TunnelMode::Decrypted, None));
            assert_eq!(
                outcome(&rows[1]),
                (TunnelMode::Passthrough, Some(TunnelReason::OutOfScope))
            );
            assert_eq!(status(&rows[1]), Some(200));
            assert!(rows[1].metadata.duration.is_some());
            assert_eq!(
                request_paths(&store),
                vec!["/one".to_string(), "/two".to_string()],
                "no request inside the relayed tunnel is a row"
            );
        }

        // ---- Spec D4: passive stamping (Task 7) -------------------------------

        /// The cleartext origin the forward-proxy tests request: an IP literal, so
        /// resolving it needs no DNS; port 8080, so the bare `127.0.0.1` Scope
        /// entry is what admits it.
        const PLAIN_ORIGIN: &str = "127.0.0.1:8080";

        fn plain_origin_peer() -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], 8080))
        }

        /// A forward-proxy request for `path` at [`PLAIN_ORIGIN`]: absolute-form
        /// target and a matching `Host`, as a browser sends it to an explicit proxy.
        fn forward_get(path: &str) -> String {
            format!("GET http://{PLAIN_ORIGIN}{path} HTTP/1.1\r\nHost: {PLAIN_ORIGIN}\r\n\r\n")
        }

        /// A cleartext origin over a duplex answering each request with the next
        /// of `bodies` (keep-alive, held open until the proxy hangs up). Returns
        /// the proxy-facing end.
        fn plain_origin(bodies: Vec<&'static str>) -> (ByteStream, tokio::task::JoinHandle<()>) {
            let (ours, theirs) = duplex(64 * 1024);
            let task = tokio::spawn(origin_serve(theirs, bodies, false));
            (Box::pin(ours), task)
        }

        /// Acts on every request: backs the flow up and parks it, as the intercept
        /// plugin does for a breakpoint rule, and logs each event it is shown. A
        /// passive flow must never reach it (spec D4).
        struct ParkOnRequest {
            seen: Arc<Mutex<Vec<&'static str>>>,
        }

        impl Plugin for ParkOnRequest {
            fn name(&self) -> &str {
                "park-on-request"
            }
            fn on_event(&mut self, ev: &Event, ctx: &mut FlowCtx<'_>) -> Verdict {
                let label = match ev {
                    Event::RequestHeaders(_) => "RequestHeaders",
                    Event::Request(_) => "Request",
                    Event::ResponseHeaders(_) => "ResponseHeaders",
                    Event::Response(_) => "Response",
                    _ => "other",
                };
                self.seen.lock().expect("seen lock").push(label);
                if matches!(ev, Event::Request(_)) {
                    ctx.backup();
                    ctx.intercept();
                }
                Verdict::Continue
            }
        }

        /// A context whose events go through a real [`Chain`] over `store` with
        /// exactly `plugins` registered, consulting `guard` for Scope, with a
        /// connector that hands out `streams`.
        fn chained_ctx(
            streams: Vec<ByteStream>,
            store: Arc<MemFlowStore>,
            guard: Arc<StdGuard>,
            plugins: Vec<Box<dyn Plugin>>,
        ) -> (ModuleCtx, DialLog) {
            let mut registry = Registry::new();
            for plugin in plugins {
                registry.add_plugin(plugin);
            }
            let chain = Chain::new(Arc::new(registry), store.clone());
            let (ctx, dialed) = ctx_with_sink(streams, store, Arc::new(chain));
            (ctx.with_scope(guard), dialed)
        }

        /// The resume handle of the flow for `path`, once a plugin has parked it.
        async fn wait_until_parked(store: &MemFlowStore, path: &str) -> ResumeHandle {
            loop {
                let parked = store.list().into_iter().find_map(|id| match store.get(id) {
                    Some(Flow::Http(f)) if f.request.path == path => match f.intercept {
                        InterceptState::Intercepted { resume, .. } => Some(resume),
                        _ => None,
                    },
                    _ => None,
                });
                if let Some(resume) = parked {
                    return resume;
                }
                tokio::task::yield_now().await;
            }
        }

        /// AC9 (unit), spec D4: plain HTTP to a host outside Scope is relayed and
        /// stored, marked passive, and nothing acts on it: a plugin that parks
        /// every request never sees it, so the client has its 200 at once.
        #[tokio::test]
        async fn plain_http_to_an_out_of_scope_host_is_passive_and_not_acted_on() {
            let module = HttpModule::new();
            let store = Arc::new(MemFlowStore::new());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (upstream, origin) = plain_origin(vec!["plain"]);
            let (ctx, dialed) = chained_ctx(
                vec![upstream],
                store.clone(),
                scoped(&[]),
                vec![Box::new(ParkOnRequest { seen: seen.clone() })],
            );

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(forward_get("/x").as_bytes())
                    .await
                    .expect("send GET");
                let body = read_one_200(&mut client).await;
                drop(client);
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("a passive request is answered at once, never parked");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "plain", "the request was relayed to the origin");
            origin.abort();

            let row = request_row(&store, "/x");
            assert_eq!(row.request.method, "GET");
            assert_eq!(row.request.scheme, "http");
            assert_eq!(row.request.authority, "127.0.0.1:8080");
            assert_eq!(status(&row), Some(200));
            assert!(
                row.metadata.passive,
                "plain HTTP to a host outside Scope is passive"
            );
            assert_eq!(
                row.intercept.label(),
                "observed",
                "nothing parks a passive flow"
            );
            assert_eq!(
                row.metadata.tunnel, None,
                "a cleartext request is not a tunnel row"
            );
            let seen = seen.lock().expect("seen lock").clone();
            assert!(
                seen.is_empty(),
                "a plugin that acts on flows never sees a passive one: {seen:?}"
            );
            assert!(tunnel_rows(&store).is_empty());
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![("127.0.0.1:8080".to_string(), plain_origin_peer())],
                "passive means observed, not blocked: the request still reaches the origin"
            );
        }

        /// The mirror: the same request to a host in Scope is acted on. The parking
        /// plugin sees it and parks it (`intercepted`), the row is not passive, and
        /// the client is answered once the flow is resumed.
        #[tokio::test]
        async fn plain_http_to_an_in_scope_host_is_acted_on() {
            let module = HttpModule::new();
            let store = Arc::new(MemFlowStore::new());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let (upstream, origin) = plain_origin(vec!["plain"]);
            let (ctx, _dialed) = chained_ctx(
                vec![upstream],
                store.clone(),
                scoped(&["127.0.0.1"]),
                vec![Box::new(ParkOnRequest { seen: seen.clone() })],
            );

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(forward_get("/x").as_bytes())
                    .await
                    .expect("send GET");
                // The plugin parks the request; the client is left waiting.
                let resume = wait_until_parked(&store, "/x").await;
                let parked = request_row(&store, "/x");
                assert_eq!(parked.intercept.label(), "intercepted");
                assert!(
                    !parked.metadata.passive,
                    "a request to a host in Scope is acted on"
                );
                assert!(parked.response.is_none(), "parked: not forwarded yet");
                assert_eq!(
                    *seen.lock().expect("seen lock"),
                    vec!["RequestHeaders", "Request"]
                );
                // Release it as `flow.resume` does.
                resume.fire();
                let body = read_one_200(&mut client).await;
                drop(client);
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the resumed request hung");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "plain");
            origin.abort();

            let row = request_row(&store, "/x");
            assert!(!row.metadata.passive);
            assert_eq!(row.intercept.label(), "resumed");
            assert_eq!(status(&row), Some(200));
            assert_eq!(
                *seen.lock().expect("seen lock"),
                vec!["RequestHeaders", "Request", "ResponseHeaders", "Response"]
            );
        }

        /// AC4 (inner requests): a tunnel decrypted while its host was in Scope
        /// keeps its decision. After `scope.remove` the next request on the same
        /// connection is still captured and still acted on (`passive == false`);
        /// only a new connection would be tunnelled.
        #[tokio::test]
        async fn requests_inside_a_decrypted_tunnel_are_not_passive_even_after_scope_remove() {
            let ca = test_ca();
            let module = HttpModule::with_ca(ca.clone()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let guard = scoped(&["127.0.0.1"]);
            let (identity, _origin_der) = origin_identity();
            let (upstream, origin) = tls_origin(identity, vec!["one", "two"]);
            let (ctx, _dialed) = scoped_ctx(vec![upstream], store.clone(), guard.clone());

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut tls = TlsConnector::from(trusting(ca_root(&ca)))
                    .connect(ip_name(), client)
                    .await
                    .expect("the in-scope tunnel is decrypted with the proxy's leaf");
                assert_eq!(get(&mut tls, "/one").await, "one");
                assert!(!request_row(&store, "/one").metadata.passive);

                assert!(guard.remove_scope("127.0.0.1"));
                assert!(
                    !guard.in_scope(ORIGIN),
                    "the host is out of Scope from here on"
                );

                assert_eq!(get(&mut tls, "/two").await, "two");
                let _ = tls.shutdown().await;
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the decrypted tunnel hung");
            served.expect("the module ends cleanly when the client hangs up");
            origin.abort();

            assert_eq!(
                request_paths(&store),
                vec!["/one".to_string(), "/two".to_string()],
                "both requests were captured"
            );
            let two = request_row(&store, "/two");
            assert!(
                !two.metadata.passive,
                "a request inside a tunnel decrypted before scope.remove is still acted on"
            );
            assert_eq!(two.request.scheme, "https");
            assert_eq!(status(&two), Some(200));
            assert!(!request_row(&store, "/one").metadata.passive);
            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            assert_eq!(outcome(&rows[0]), (TunnelMode::Decrypted, None));
        }

        /// Spec D4: a keep-alive forward-proxy connection is stamped per request,
        /// not per connection. With an empty Scope the first request is passive;
        /// after `scope.add` the next request on the same connection is acted on.
        #[tokio::test]
        async fn keep_alive_cleartext_connection_recomputes_passive_per_request() {
            let module = HttpModule::new();
            let store = Arc::new(MemFlowStore::new());
            let guard = scoped(&[]);
            let (upstream, origin) = plain_origin(vec!["one", "two"]);
            let (ctx, dialed) = scoped_ctx(vec![upstream], store.clone(), guard.clone());

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let target = format!("http://{PLAIN_ORIGIN}/one");
                assert_eq!(client_get(&mut client, &target, PLAIN_ORIGIN).await, "one");
                assert!(
                    request_row(&store, "/one").metadata.passive,
                    "out of Scope: passive"
                );

                guard.add_scope(ScopeEntry {
                    host: "127.0.0.1".to_string(),
                });

                let target = format!("http://{PLAIN_ORIGIN}/two");
                assert_eq!(client_get(&mut client, &target, PLAIN_ORIGIN).await, "two");
                drop(client);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the keep-alive connection hung");
            served.expect("the module ends cleanly when the client hangs up");
            origin.abort();

            assert_eq!(
                request_paths(&store),
                vec!["/one".to_string(), "/two".to_string()]
            );
            assert!(
                request_row(&store, "/one").metadata.passive,
                "the first row keeps its stamp"
            );
            assert!(
                !request_row(&store, "/two").metadata.passive,
                "in Scope now: acted on"
            );
            assert_eq!(
                dialed.lock().expect("dialed lock").len(),
                1,
                "one upstream connection carried both requests"
            );
        }

        // ---- Tester additions (whole-branch stage 5): edge cases a proxy must survive ----
        //
        // Malformed, cut-short and oversized CONNECT heads; a tunnel that drops
        // mid-relay from either end; bytes after the acknowledgement that look like
        // TLS but are not; IPv6 authorities on both routes; and the raw-TLS
        // (capture ingress) path of `drive`, which nothing above exercises through
        // `spawn`: the relay with the buffered ClientHello, the SNI read from the
        // record when the acceptor's peek missed it, and a hello without SNI.

        /// The client peer the acceptor hands `drive` for a proxied connection:
        /// on the explicit-proxy path the hint's `dst` is the client's own address.
        fn client_peer() -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], 54321))
        }

        /// A proxied `CONNECT <authority>` as the acceptor peeks it: the request
        /// line is in `first_bytes`, so `tunnel_authority()` names the host before
        /// the module has read the head — what a `failed` row for a head that
        /// cannot be read is keyed on.
        fn connect_hint(authority: &str) -> NextLayerHint {
            NextLayerHint {
                dst: client_peer(),
                is_tls: false,
                client_hello_sni: None,
                alpn: Vec::new(),
                first_bytes: format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n")
                    .into_bytes(),
                from_upgrade: false,
                peer_identity: None,
                capture_interface: None,
            }
        }

        /// The original destination a capture ingress (the NE) hands the module.
        fn captured_dst() -> SocketAddr {
            SocketAddr::from(([127, 0, 0, 1], 8443))
        }

        /// A raw-TLS connection from a capture ingress: no CONNECT, `dst` is the
        /// original destination, the SNI as the acceptor peeked it (`None` when the
        /// ClientHello did not fit the peek), and the capture attribution.
        fn capture_tls_hint(sni: Option<&str>) -> NextLayerHint {
            NextLayerHint {
                dst: captured_dst(),
                is_tls: true,
                client_hello_sni: sni.map(str::to_string),
                alpn: Vec::new(),
                first_bytes: vec![TLS_HANDSHAKE, 0x03, 0x01],
                from_upgrade: false,
                peer_identity: Some("com.apple.Safari".into()),
                capture_interface: Some("macos-ne".into()),
            }
        }

        /// `localhost`: the one name that resolves without a network, so the
        /// raw-TLS path (which resolves the SNI) can be driven offline.
        const LOCALHOST_ORIGIN: &str = "localhost:8443";

        fn localhost_name() -> ServerName<'static> {
            ServerName::try_from("localhost").expect("name")
        }

        /// The io error kind at the root of a module error, if it is one.
        fn io_kind(err: &anyhow::Error) -> Option<io::ErrorKind> {
            err.chain()
                .find_map(|cause| cause.downcast_ref::<io::Error>())
                .map(io::Error::kind)
        }

        /// A `failed` row's invariants (spec D5): no status, closed on insert, and
        /// the given outcome.
        fn assert_failed(row: &HttpFlow, reason: TunnelReason) {
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(outcome(row), (TunnelMode::Failed, Some(reason)));
            assert_eq!(status(row), None, "a failed tunnel reports no status");
            assert!(row.metadata.duration.is_some(), "a failed row is closed");
            assert!(!row.metadata.passive);
        }

        /// Oversized input: a CONNECT head past the 16 KiB cap that never reaches
        /// its blank line is cut off and recorded as `failed/protocol_error`, keyed
        /// on the authority the acceptor peeked; nothing is acknowledged or dialled.
        #[tokio::test]
        async fn oversized_connect_head_is_a_failed_protocol_error_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));
            let ctx = ctx.with_hint(connect_hint(ORIGIN));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let mut head =
                    format!("CONNECT {ORIGIN} HTTP/1.1\r\nHost: {ORIGIN}\r\nX-Pad: ").into_bytes();
                head.resize(MAX_CONNECT_HEAD + 1024, b'a');
                client
                    .write_all(&head)
                    .await
                    .expect("send the oversized head");
                read_head(&mut client).await
            };
            let (served, reply) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the oversized head hung");
            let err = served.expect_err("an oversized head fails the connection");
            assert_eq!(io_kind(&err), Some(io::ErrorKind::InvalidData), "{err:#}");
            assert_eq!(reply, "", "no acknowledgement for a head that never ended");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1, "one failed row for the CONNECT");
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert!(row.request.headers.is_empty(), "nothing was parsed");
            assert_failed(row, TunnelReason::ProtocolError);
            assert!(row.server_conn.is_none(), "nothing was dialled");
            assert!(dialed.lock().expect("dialed lock").is_empty());
            assert_eq!(store.count(), 1);
        }

        /// A client that hangs up mid-head (a speculative pre-connect that gave up)
        /// is `failed/client_closed`, keyed on the peeked authority: no ack, no dial.
        #[tokio::test]
        async fn connect_head_cut_short_by_the_client_is_a_failed_client_closed_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));
            let ctx = ctx.with_hint(connect_hint(ORIGIN));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0")
                    .await
                    .expect("send a partial head");
                drop(client);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the cut-short head hung");
            let err = served.expect_err("an unfinished head is an error");
            assert_eq!(io_kind(&err), Some(io::ErrorKind::UnexpectedEof), "{err:#}");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert!(row.request.headers.is_empty());
            assert_failed(row, TunnelReason::ClientClosed);
            assert!(!row.client_conn.tls, "no TLS byte was ever seen");
            assert!(row.server_conn.is_none());
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// Spec D5 "every CONNECT is a row": a head the module can read but not
        /// parse (a non-UTF-8 header line) whose request line the acceptor's peek
        /// did name is still a row — `failed/protocol_error`, keyed on that
        /// authority — exactly as the passthrough module records it
        /// (`malformed_connect_head_is_a_failed_protocol_error_row`). The client
        /// gets no acknowledgement and nothing is dialled.
        ///
        /// Tester finding T1 (stage 5, whole branch): `HttpModule::tunnel` returned
        /// `parse_connect(&head)?` with no row even when `ctx.hint()` named the
        /// authority, so this CONNECT was silent (the store stayed empty).
        #[tokio::test]
        async fn non_utf8_connect_head_is_a_failed_protocol_error_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));
            let ctx = ctx.with_hint(connect_hint(ORIGIN));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\nX-Bad: \xff\xfe\r\n\r\n")
                    .await
                    .expect("send the malformed head");
                read_head(&mut client).await
            };
            let (served, reply) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the malformed head hung");
            let err = served.expect_err("a non-UTF-8 head fails the connection");
            assert!(format!("{err:#}").contains("non-UTF-8"), "{err:#}");
            assert_eq!(
                reply, "",
                "no acknowledgement for a head that did not parse"
            );
            assert!(dialed.lock().expect("dialed lock").is_empty());

            let rows = tunnel_rows(&store);
            assert_eq!(
                rows.len(),
                1,
                "a CONNECT the peek named leaves a row even when its head does not parse"
            );
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_failed(row, TunnelReason::ProtocolError);
            assert!(row.server_conn.is_none());
        }

        /// After the acknowledgement the client sends bytes that start like a TLS
        /// record but carry no ClientHello (invalid TLS). The handshake fails on
        /// the client side with a TLS protocol error, not an alert, so the row is
        /// `failed/client_tls_error`; the origin was never dialled.
        #[tokio::test]
        async fn garbage_that_looks_like_tls_after_the_ack_is_a_failed_client_tls_error_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                // A complete TLS handshake record whose one message has an
                // unknown handshake type (0xff) and an empty body.
                client
                    .write_all(&[
                        TLS_HANDSHAKE,
                        0x03,
                        0x01,
                        0x00,
                        0x04,
                        0xff,
                        0x00,
                        0x00,
                        0x00,
                    ])
                    .await
                    .expect("send the bogus record");
                // The proxy may answer with an alert, then closes.
                let mut rest = Vec::new();
                let _ = client.read_to_end(&mut rest).await;
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the bogus handshake hung");
            let err = served.expect_err("a bogus ClientHello fails the connection");
            assert_eq!(err.to_string(), "read ClientHello");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_failed(row, TunnelReason::ClientTlsError);
            assert!(row.client_conn.tls);
            assert!(
                row.server_conn.is_none(),
                "the ClientHello is read before the origin is dialled"
            );
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// AC8 (IPv6), D5: `CONNECT [::1]:8443` to a host outside Scope is relayed
        /// under the bracketed authority `Authority` prints, dialled as the IPv6
        /// literal it is (no lookup), with exact byte counts once both ends close.
        /// Raw bytes behind a TLS record byte: past the first byte (spec D1, panel
        /// S1) the relay is byte-agnostic.
        #[tokio::test]
        async fn out_of_scope_ipv6_connect_is_relayed_under_its_bracketed_authority() {
            const V6: &str = "[::1]:8443";
            let v6_peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 8443));
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            // `127.0.0.1` is in Scope; `::1` is a different host and is not.
            let (ctx, dialed) =
                scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, V6).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                client.write_all(b"\x16ping").await.expect("client writes");
                let mut buf = [0u8; 5];
                origin
                    .read_exact(&mut buf)
                    .await
                    .expect("the client's bytes reach the origin");
                assert_eq!(&buf, b"\x16ping");
                origin.write_all(b"pong!").await.expect("origin writes");
                let mut buf = [0u8; 5];
                client
                    .read_exact(&mut buf)
                    .await
                    .expect("the origin's bytes reach the client");
                assert_eq!(&buf, b"pong!");
                let open = tunnel_rows(&store);
                assert_eq!(open.len(), 1);
                assert_eq!(open[0].metadata.duration, None, "open while relaying");
                // The client hangs up; the relay passes that on to the origin,
                // which then closes too.
                drop(client);
                let mut rest = Vec::new();
                origin.read_to_end(&mut rest).await.expect("origin read");
                assert!(rest.is_empty(), "nothing after the client's hang-up");
                drop(origin);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the IPv6 relay hung");
            served.expect("a tunnel both ends closed is a clean close");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(row.request.authority, V6, "normalised through Authority");
            assert_eq!(row.request.headers.get("host"), Some(V6));
            assert_eq!(
                row.metadata.tunnel,
                Some(TunnelInfo {
                    mode: TunnelMode::Passthrough,
                    reason: Some(TunnelReason::OutOfScope),
                    bytes_up: Some(5),
                    bytes_down: Some(5),
                })
            );
            assert_eq!(status(row), Some(200));
            assert!(row.metadata.duration.is_some());
            let server = row.server_conn.as_ref().expect("the dialled origin");
            assert_eq!(server.peer, v6_peer);
            assert_eq!(server.sni.as_deref(), Some("::1"));
            // Tester finding T2: the connector is handed the bracketed `[::1]:8443`
            // the row carries and the passthrough module hands its connector (spec
            // D2) — the form the guarded connector's `Authority::parse_with_default`
            // reads back as `::1` on port 8443.
            assert_eq!(
                dialed.lock().expect("dialed lock").clone(),
                vec![(V6.to_string(), v6_peer)],
                "an IPv6 literal is dialled as is, with no lookup, under its bracketed authority"
            );
            assert!(request_paths(&store).is_empty());
        }

        /// AC8 (IPv6) on the decrypting route: with `::1` in Scope, `CONNECT
        /// [::1]:8080` is admitted (`in_scope` matches the bracketed authority), the
        /// cleartext request inside it is served and captured, and the tunnel row
        /// and its inner row share the authority a frontend groups on (spec D9).
        #[tokio::test]
        async fn in_scope_ipv6_connect_is_decrypted_and_shares_its_authority_with_the_inner_row() {
            const V6: &str = "[::1]:8080";
            let v6_peer = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 8080));
            let module = HttpModule::new();
            let store = Arc::new(MemFlowStore::new());
            let (upstream, origin) = plain_origin(vec!["v6"]);
            let (ctx, dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&["::1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, V6).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                // Cleartext inside the tunnel (`curl -p` to a plain origin).
                client
                    .write_all(get_request("/v6", V6).as_bytes())
                    .await
                    .expect("send GET");
                let body = read_one_200(&mut client).await;
                drop(client);
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the IPv6 cleartext tunnel hung");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "v6");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, V6);
            assert_eq!(outcome(row), (TunnelMode::Decrypted, None));
            assert_eq!(status(row), Some(200));
            assert!(row.metadata.duration.is_some());
            assert!(!row.client_conn.tls, "cleartext inside the tunnel");
            assert!(
                row.server_conn.is_none(),
                "the row opens before `serve` dials the origin lazily (spec D5: \"when one was dialled\")"
            );
            assert_eq!(
                dialed.lock().expect("dialed lock").clone(),
                vec![(V6.to_string(), v6_peer)],
                "the connector is handed the bracketed authority (spec D2: the string the \
                 passthrough module hands its connector) and dials the IPv6 literal"
            );

            let inner = request_row(&store, "/v6");
            assert!(!inner.metadata.passive);
            assert_eq!(inner.metadata.tunnel, None);
            assert_eq!(status(&inner), Some(200));
            assert_eq!(
                inner.request.authority, row.request.authority,
                "spec D9: a decrypted tunnel row and its inner rows share their authority"
            );
        }

        /// Connection drop mid-relay from the origin side: the relay passes the EOF
        /// to the client; the client's next bytes have nowhere to go and end the
        /// relay in an error. The row still closes with exact counts (what was read
        /// from the client, what was written to it), keeps its 200 (the tunnel was
        /// established) and gets a duration.
        #[tokio::test]
        async fn relay_row_keeps_exact_counts_when_the_origin_drops_mid_stream() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                client.write_all(b"\x16abc").await.expect("client writes");
                let mut buf = [0u8; 4];
                origin.read_exact(&mut buf).await.expect("origin reads");
                assert_eq!(&buf, b"\x16abc");
                origin.write_all(b"defgh").await.expect("origin writes");
                let mut buf = [0u8; 5];
                client.read_exact(&mut buf).await.expect("client reads");
                assert_eq!(&buf, b"defgh");
                // The origin resets mid-stream.
                drop(origin);
                // The client sees the EOF the relay passes on...
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.expect("client read");
                assert!(rest.is_empty());
                // ...and keeps talking: these bytes are read by the proxy and
                // cannot be written to the origin.
                client
                    .write_all(b"more")
                    .await
                    .expect("the client can still write to the proxy");
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the origin drop hung the relay");
            let err = served.expect_err("the relay ends in the write error");
            assert_eq!(io_kind(&err), Some(io::ErrorKind::BrokenPipe), "{err:#}");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(
                row.metadata.tunnel,
                Some(TunnelInfo {
                    mode: TunnelMode::Passthrough,
                    reason: Some(TunnelReason::OutOfScope),
                    bytes_up: Some(8),
                    bytes_down: Some(5),
                }),
                "counts survive the error: 4 + 4 read from the client, 5 written to it"
            );
            assert_eq!(
                status(row),
                Some(200),
                "an established tunnel that broke later is not a failed tunnel"
            );
            assert!(row.metadata.duration.is_some(), "closed");
        }

        // ---- Spec D1 "a passthrough relays TLS only" (panel S1) -------------------

        /// After the acknowledgement the client sends a cleartext `GET` (`curl -p
        /// http://…` to an out-of-scope host) instead of a TLS handshake record.
        /// The tunnel is refused, not relayed: the origin — already dialled —
        /// receives **nothing**, the client sees the acknowledgement then EOF, the
        /// row is `failed/protocol_error` naming the dialled origin, and the module
        /// ends with the refusal.
        #[tokio::test]
        async fn out_of_scope_connect_whose_first_byte_is_not_tls_is_refused() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                client
                    .write_all(get_request("/", ORIGIN).as_bytes())
                    .await
                    .expect("send cleartext inside the tunnel");
                // The proxy closes without relaying: the client sees EOF…
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.expect("client read");
                assert_eq!(
                    rest, b"",
                    "nothing but the acknowledgement reaches the client"
                );
                // …and the origin never saw a byte.
                let mut got = Vec::new();
                origin.read_to_end(&mut got).await.expect("origin read");
                got
            };
            let (served, got) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the refused tunnel hung");
            let err = served.expect_err("a non-TLS tunnel to an out-of-scope host is refused");
            assert!(
                err.to_string().contains("not a TLS handshake record"),
                "the error names the refusal: {err:#}"
            );
            assert_eq!(got, b"", "not one client byte reached the origin");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_eq!(row.request.headers.get("host"), Some(ORIGIN));
            assert_failed(row, TunnelReason::ProtocolError);
            assert!(!row.client_conn.tls, "the client did not speak TLS");
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the origin had been dialled when the client was refused"
            );
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![(ORIGIN.to_string(), origin_peer())]
            );
            assert!(
                request_paths(&store).is_empty(),
                "the cleartext request was not served either"
            );
            assert_eq!(store.count(), 1);
        }

        /// EOF right after the acknowledgement on the out-of-scope route (a
        /// speculative pre-connect that gave up) is `failed/client_closed` with the
        /// dialled origin on the row — not an open passthrough row with zero
        /// bytes — and not an error.
        #[tokio::test]
        async fn out_of_scope_connect_then_eof_is_a_failed_client_closed_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                drop(client);
                let mut got = Vec::new();
                origin.read_to_end(&mut got).await.expect("origin read");
                got
            };
            let (served, got) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the abandoned tunnel hung");
            served.expect("a client that leaves before its first byte is not an error");
            assert_eq!(got, b"", "nothing was relayed");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_failed(row, TunnelReason::ClientClosed);
            assert!(!row.client_conn.tls, "no TLS byte was ever seen");
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the origin had been dialled"
            );
            assert_eq!(store.count(), 1);
        }

        /// Panel S7 on the module's own relay: a client that is acknowledged and
        /// then sends nothing holds the dialled origin with no row — for
        /// `FIRST_BYTE_TIMEOUT` (30 s) and not a moment longer. The clock is
        /// paused: 31 s later the module has recorded a `failed/client_closed` row
        /// carrying the dialled origin, `client.tls` is `false`, both sockets are
        /// shut (the still-open client and the origin each read EOF) and `spawn`
        /// returns `Ok`, exactly as for a client that closed.
        #[tokio::test(start_paused = true)]
        async fn silent_client_after_the_ack_is_a_failed_client_closed_row_at_the_first_byte_timeout(
        ) {
            assert_eq!(FIRST_BYTE_TIMEOUT, Duration::from_secs(30));
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                tokio::time::advance(Duration::from_secs(31)).await;
                let mut rest = Vec::new();
                client
                    .read_to_end(&mut rest)
                    .await
                    .expect("client read after the module gave up");
                let mut got = Vec::new();
                origin.read_to_end(&mut got).await.expect("origin read");
                (rest, got)
            };
            // The clock is paused, so this guard fires (by auto-advance) only if
            // the module is still waiting past the bound: a hang is a failure.
            let (served, (rest, got)) = tokio::time::timeout(Duration::from_secs(60), async {
                tokio::join!(serving, script)
            })
            .await
            .expect("the module did not give up on the silent client within 60 s");
            served.expect("a client that stays silent is not an error");
            assert_eq!(
                rest, b"",
                "the client was shut down with nothing after the ack"
            );
            assert_eq!(got, b"", "the origin was shut down with nothing relayed");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_failed(row, TunnelReason::ClientClosed);
            assert!(!row.client_conn.tls, "no TLS handshake record was seen");
            assert_eq!(
                row.server_conn.as_ref().map(|c| c.peer),
                Some(origin_peer()),
                "the origin had been dialled"
            );
            assert_eq!(store.count(), 1);
        }

        /// The bound is 30 s, not less: a first byte that arrives 29 s after the
        /// acknowledgement is waited for and relayed like one that came at once —
        /// a `passthrough/out_of_scope` row with exact counts, `client.tls` true.
        #[tokio::test(start_paused = true)]
        async fn first_byte_at_29_seconds_is_still_relayed() {
            const RECORD: &[u8] = &[TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x03, b'a', b'b', b'c'];
            const REPLY: &[u8] = &[TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x02, b'o', b'k'];
            assert_eq!(FIRST_BYTE_TIMEOUT, Duration::from_secs(30));
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                tokio::time::advance(Duration::from_secs(29)).await;
                assert!(tunnel_rows(&store).is_empty(), "no row yet: still waiting");
                client.write_all(RECORD).await.expect("the late record");
                let mut got = vec![0u8; RECORD.len()];
                origin
                    .read_exact(&mut got)
                    .await
                    .expect("the late record reaches the origin");
                assert_eq!(got, RECORD);
                origin.write_all(REPLY).await.expect("origin replies");
                let mut reply = vec![0u8; REPLY.len()];
                client
                    .read_exact(&mut reply)
                    .await
                    .expect("the reply reaches the client");
                assert_eq!(reply, REPLY);
                drop(client);
                let mut rest = Vec::new();
                origin.read_to_end(&mut rest).await.expect("origin read");
                assert!(rest.is_empty());
                drop(origin);
            };
            let (served, ()) = tokio::time::timeout(Duration::from_secs(60), async {
                tokio::join!(serving, script)
            })
            .await
            .expect("the relay hung");
            served.expect("a tunnel both ends closed is a clean close");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(
                row.metadata.tunnel,
                Some(TunnelInfo {
                    mode: TunnelMode::Passthrough,
                    reason: Some(TunnelReason::OutOfScope),
                    bytes_up: Some(8),
                    bytes_down: Some(7),
                })
            );
            assert_eq!(status(row), Some(200));
            assert!(row.client_conn.tls, "a 0x16 first byte was seen");
            assert!(row.metadata.duration.is_some());
        }

        /// The decided-on bytes are not lost: a client that sends its TLS record
        /// right behind the CONNECT head — before the acknowledgement, as browsers
        /// do — has the whole record relayed to the origin first and counted:
        /// `bytes_up` is exactly the record, `bytes_down` exactly the reply, and
        /// the row says the client spoke TLS.
        #[tokio::test]
        async fn out_of_scope_connect_with_tls_first_byte_is_relayed_with_exact_counts() {
            const RECORD: &[u8] = &[
                TLS_HANDSHAKE,
                0x03,
                0x01,
                0x00,
                0x05,
                b'h',
                b'e',
                b'l',
                b'l',
                b'o',
            ];
            const REPLY: &[u8] = &[TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x02, b'o', b'k'];
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let mut head =
                    format!("CONNECT {ORIGIN} HTTP/1.1\r\nHost: {ORIGIN}\r\n\r\n").into_bytes();
                head.extend_from_slice(RECORD);
                client
                    .write_all(&head)
                    .await
                    .expect("send the head and the record in one write");
                let ack = read_head(&mut client).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                let mut got = vec![0u8; RECORD.len()];
                origin
                    .read_exact(&mut got)
                    .await
                    .expect("the whole record reaches the origin");
                assert_eq!(got, RECORD);
                origin.write_all(REPLY).await.expect("origin replies");
                let mut reply = vec![0u8; REPLY.len()];
                client
                    .read_exact(&mut reply)
                    .await
                    .expect("the reply reaches the client");
                assert_eq!(reply, REPLY);
                drop(client);
                let mut rest = Vec::new();
                origin.read_to_end(&mut rest).await.expect("origin read");
                assert!(rest.is_empty());
                drop(origin);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the relay hung");
            served.expect("a tunnel both ends closed is a clean close");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(
                row.metadata.tunnel,
                Some(TunnelInfo {
                    mode: TunnelMode::Passthrough,
                    reason: Some(TunnelReason::OutOfScope),
                    bytes_up: Some(10),
                    bytes_down: Some(7),
                }),
                "the first byte is counted with the rest"
            );
            assert_eq!(status(row), Some(200));
            assert!(row.client_conn.tls, "the first byte was a TLS record");
            assert!(row.metadata.duration.is_some());
        }

        // ---- The raw-TLS route (a capture ingress: no CONNECT) -----------------

        /// D1/D2/AC16 on the raw-TLS route: a captured connection whose SNI the
        /// acceptor peeked is out of Scope, so the HTTP module relays it — the
        /// buffered ClientHello first — and the client completes TLS against the
        /// origin's own certificate. The row is `passthrough/out_of_scope` under
        /// `sni:dst-port`, with no CONNECT headers and the capture attribution; no
        /// acknowledgement is written (a `200` line would have broken the TLS
        /// stream, so the successful handshake proves it).
        #[tokio::test]
        async fn raw_tls_out_of_scope_on_the_capture_path_is_relayed_not_decrypted() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, origin_der) = origin_identity_named("localhost");
            let (upstream, origin) = tls_origin(identity, vec!["secret"]);
            let (ctx, dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&[]));
            let ctx = ctx.with_hint(capture_tls_hint(Some("localhost")));

            let (client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                // No CONNECT: the client's first bytes are its ClientHello.
                let mut tls = TlsConnector::from(accepting_any())
                    .connect(localhost_name(), client)
                    .await
                    .expect("the handshake with the origin goes through the relay");
                assert_eq!(
                    presented(&tls),
                    origin_der,
                    "the client must see the origin's own certificate, not a proxy leaf"
                );
                let body = get(&mut tls, "/secret").await;
                let _ = tls.shutdown().await;
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the raw-TLS relay hung");
            served.expect("the relay ends cleanly when the client hangs up");
            assert_eq!(body, "secret", "the origin's answer was relayed");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.method, "CONNECT");
            assert_eq!(row.request.authority, LOCALHOST_ORIGIN, "sni:dst-port");
            assert!(row.request.headers.is_empty(), "no CONNECT head to record");
            let tunnel = row.metadata.tunnel.clone().expect("tunnel outcome");
            assert_eq!(tunnel.mode, TunnelMode::Passthrough);
            assert_eq!(tunnel.reason, Some(TunnelReason::OutOfScope));
            assert!(tunnel.bytes_up.is_some_and(|n| n > 0), "{tunnel:?}");
            assert!(tunnel.bytes_down.is_some_and(|n| n > 0), "{tunnel:?}");
            assert_eq!(status(row), Some(200));
            assert!(row.metadata.duration.is_some());
            assert!(row.client_conn.tls);
            assert_eq!(row.metadata.source_app.as_deref(), Some("com.apple.Safari"));
            assert_eq!(row.metadata.capture_interface.as_deref(), Some("macos-ne"));
            let dialed = dialed.lock().expect("dialed lock").clone();
            assert_eq!(dialed.len(), 1);
            assert_eq!(dialed[0].0, LOCALHOST_ORIGIN);
            assert!(dialed[0].1.ip().is_loopback() && dialed[0].1.port() == 8443);
            assert!(
                request_paths(&store).is_empty(),
                "nothing inside the relay is a row"
            );
        }

        /// The mirror: the same captured connection with its host in Scope is
        /// decrypted — the client trusting only the proxy CA completes the
        /// handshake — and the row is `decrypted`, with the inner request its own,
        /// acted-on row.
        #[tokio::test]
        async fn raw_tls_in_scope_on_the_capture_path_is_decrypted() {
            let ca = test_ca();
            let module = HttpModule::with_ca(ca.clone()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, _origin_der) = origin_identity_named("localhost");
            let (upstream, origin) = tls_origin(identity, vec!["secret"]);
            let (ctx, _dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&["localhost"]));
            let ctx = ctx.with_hint(capture_tls_hint(Some("localhost")));

            let (client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let mut tls = TlsConnector::from(trusting(ca_root(&ca)))
                    .connect(localhost_name(), client)
                    .await
                    .expect("a client that trusts the proxy CA completes the handshake");
                let body = get(&mut tls, "/secret").await;
                let _ = tls.shutdown().await;
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the decrypted raw-TLS connection hung");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "secret");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, LOCALHOST_ORIGIN);
            assert!(row.request.headers.is_empty());
            assert_eq!(row.metadata.tunnel, Some(TunnelInfo::decrypted()));
            assert_eq!(status(row), Some(200));
            assert!(row.metadata.duration.is_some());
            assert!(row.client_conn.tls);
            assert_eq!(row.client_conn.sni.as_deref(), Some("localhost"));
            assert!(
                row.server_conn.is_some(),
                "the origin it dialled is on the row"
            );
            assert_eq!(row.metadata.source_app.as_deref(), Some("com.apple.Safari"));
            let inner = request_row(&store, "/secret");
            assert!(!inner.metadata.passive);
            assert_eq!(inner.metadata.tunnel, None);
            assert_eq!(status(&inner), Some(200));
        }

        /// Anti-goal "a ClientHello larger than the acceptor's peek": the hint has
        /// no SNI, so the module buffers the first TLS record itself, reads the SNI
        /// from it and decides on that — out of Scope here, so the connection is
        /// relayed and the client sees the origin's certificate. The buffered record
        /// is not consumed: the handshake completes through the relay.
        #[tokio::test]
        async fn raw_tls_whose_sni_the_peek_missed_is_decided_on_the_record_it_buffers() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (identity, origin_der) = origin_identity_named("localhost");
            let (upstream, origin) = tls_origin(identity, vec!["secret"]);
            let (ctx, _dialed) = scoped_ctx(vec![upstream], store.clone(), scoped(&[]));
            let ctx = ctx.with_hint(capture_tls_hint(None));

            let (client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let mut tls = TlsConnector::from(accepting_any())
                    .connect(localhost_name(), client)
                    .await
                    .expect("the handshake goes through the relay");
                assert_eq!(presented(&tls), origin_der, "relayed, not decrypted");
                let body = get(&mut tls, "/secret").await;
                let _ = tls.shutdown().await;
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the peek-missed relay hung");
            served.expect("the relay ends cleanly");
            assert_eq!(body, "secret");
            origin.abort();

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].request.authority, LOCALHOST_ORIGIN,
                "the SNI came from the buffered record, the port from the capture dst"
            );
            assert_eq!(
                outcome(&rows[0]),
                (TunnelMode::Passthrough, Some(TunnelReason::OutOfScope))
            );
            assert!(request_paths(&store).is_empty());
        }

        /// A captured TLS connection whose ClientHello carries no SNI (a client
        /// speaking to an IP) cannot be decrypted by name: `failed/protocol_error`,
        /// keyed on the capture destination, nothing dialled, and the module ends
        /// with the no-upstream error.
        #[tokio::test]
        async fn raw_tls_without_sni_on_the_capture_path_is_a_failed_protocol_error_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));
            let ctx = ctx.with_hint(capture_tls_hint(None));

            let (client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                // An IP server name sends no `server_name` extension.
                TlsConnector::from(accepting_any())
                    .connect(ip_name(), client)
                    .await
                    .expect_err("the proxy closes without serving")
            };
            let (served, _client_err) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the SNI-less hello hung");
            let err = served.expect_err("TLS without SNI cannot pick an upstream");
            assert_eq!(
                err.to_string(),
                "TLS without CONNECT or SNI: no upstream to pick"
            );

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1, "a row, not silence");
            let row = &rows[0];
            assert_eq!(
                row.request.authority, "127.0.0.1:8443",
                "keyed on the capture dst"
            );
            assert!(row.request.headers.is_empty());
            assert_failed(row, TunnelReason::ProtocolError);
            assert!(row.client_conn.tls);
            assert!(row.server_conn.is_none());
            assert_eq!(row.metadata.capture_interface.as_deref(), Some("macos-ne"));
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// Malformed input: a TLS record header announcing a 16 KiB ClientHello
        /// followed by a few bytes and a hang-up. The module reads what there is,
        /// finds no SNI, and records `failed/protocol_error` keyed on the capture
        /// destination rather than waiting or panicking.
        #[tokio::test]
        async fn truncated_client_hello_on_the_capture_path_is_a_failed_protocol_error_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&[]));
            let ctx = ctx.with_hint(capture_tls_hint(None));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(&[
                        TLS_HANDSHAKE,
                        0x03,
                        0x01,
                        0x40,
                        0x00,
                        0x01,
                        0x00,
                        0x3f,
                        0xfc,
                    ])
                    .await
                    .expect("send the truncated hello");
                drop(client);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the truncated hello hung");
            served.expect_err("no SNI could be read");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, "127.0.0.1:8443");
            assert_failed(row, TunnelReason::ProtocolError);
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// Oversized input: a record header announcing a 64 KiB payload, with far
        /// more bytes than one TLS record may hold behind it and the connection held
        /// open. The module buffers at most `MAX_CLIENT_HELLO`, finds no ClientHello
        /// in it, records `failed/protocol_error` and closes — it neither waits for
        /// the rest nor buffers it.
        #[tokio::test]
        async fn oversized_tls_record_on_the_capture_path_is_capped_and_a_failed_row() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&[]));
            let ctx = ctx.with_hint(capture_tls_hint(None));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01, 0xff, 0xff];
                record.resize(MAX_CLIENT_HELLO + 4096, 0);
                client
                    .write_all(&record)
                    .await
                    .expect("send the oversized record");
                // Held open: the proxy must give up on its own.
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).await.expect("client read");
                assert!(rest.is_empty(), "nothing is written back");
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the oversized record hung the module");
            served.expect_err("no ClientHello within the cap");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            assert_failed(&rows[0], TunnelReason::ProtocolError);
            assert_eq!(rows[0].request.authority, "127.0.0.1:8443");
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        /// The proxy side of a client connection that resets — `read` fails with
        /// `ConnectionReset` — once `after` bytes have been delivered. Writes go
        /// through.
        struct ResetAfter {
            inner: DuplexStream,
            after: usize,
            delivered: usize,
        }

        impl AsyncRead for ResetAfter {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut TaskCx<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.get_mut();
                if this.delivered >= this.after {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "client connection reset",
                    )));
                }
                let before = buf.filled().len();
                let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
                if let Poll::Ready(Ok(())) = &polled {
                    this.delivered += buf.filled().len() - before;
                }
                polled
            }
        }

        impl AsyncWrite for ResetAfter {
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

        /// Panel Q5: the one wire read on the raw-TLS route that could end without
        /// a row. A captured connection whose ClientHello the acceptor's peek
        /// missed, reset by the client while the module buffers the record, is a
        /// `failed/client_closed` row keyed on the capture destination — not
        /// silence — and the module ends with the reset.
        #[tokio::test]
        async fn client_reset_while_buffering_the_client_hello_on_the_capture_path_is_a_failed_client_closed_row(
        ) {
            // A record header announcing a 1 KiB ClientHello, four bytes of it, then
            // the reset.
            const PARTIAL: &[u8] = &[
                TLS_HANDSHAKE,
                0x03,
                0x01,
                0x04,
                0x00,
                0x01,
                0x00,
                0x03,
                0xfc,
            ];
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&[]));
            let ctx = ctx.with_hint(capture_tls_hint(None));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let resetting = ResetAfter {
                inner: proxy_side,
                after: PARTIAL.len(),
                delivered: 0,
            };
            let serving = module.spawn(Box::pin(resetting), ctx);
            let script = async {
                client
                    .write_all(PARTIAL)
                    .await
                    .expect("send the start of the hello");
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the reset hello hung");
            let err = served.expect_err("the reset ends the connection");
            assert_eq!(
                io_kind(&err),
                Some(io::ErrorKind::ConnectionReset),
                "{err:#}"
            );

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1, "a row, not silence");
            let row = &rows[0];
            assert_eq!(
                row.request.authority, "127.0.0.1:8443",
                "keyed on the capture dst"
            );
            assert!(row.request.headers.is_empty());
            assert_failed(row, TunnelReason::ClientClosed);
            assert!(
                row.client_conn.tls,
                "the connection opened with a TLS record"
            );
            assert!(row.server_conn.is_none(), "nothing was dialled");
            assert_eq!(row.metadata.source_app.as_deref(), Some("com.apple.Safari"));
            assert_eq!(row.metadata.capture_interface.as_deref(), Some("macos-ne"));
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }

        // ---- Tester additions (panel fix range 18073ee4..57563aa3) ---------------

        /// Panel S1, a slow client on the HTTP module's own relay: the row appears
        /// at the outcome (spec D5), so between the acknowledgement and the first
        /// byte there is no row and nothing at the origin; a TLS record that
        /// arrives late is then relayed with exact counts.
        #[tokio::test]
        async fn out_of_scope_connect_whose_first_byte_arrives_late_is_relayed() {
            const RECORD: &[u8] = &[TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x03, b'a', b'b', b'c'];
            const REPLY: &[u8] = &[TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x02, b'o', b'k'];
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, _dialed) = scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&[]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                tokio::time::sleep(Duration::from_millis(300)).await;
                assert_eq!(
                    store.count(),
                    0,
                    "no row before the first byte: the outcome is not known yet"
                );
                let mut probe = [0u8; 1];
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), origin.read(&mut probe))
                        .await
                        .is_err(),
                    "nothing reached the origin before the first byte"
                );
                client.write_all(RECORD).await.expect("the late record");
                let mut got = vec![0u8; RECORD.len()];
                origin
                    .read_exact(&mut got)
                    .await
                    .expect("the record reaches the origin");
                assert_eq!(got, RECORD);
                origin.write_all(REPLY).await.expect("origin replies");
                let mut reply = vec![0u8; REPLY.len()];
                client
                    .read_exact(&mut reply)
                    .await
                    .expect("the reply reaches the client");
                assert_eq!(reply, REPLY);
                drop(client);
                let mut rest = Vec::new();
                origin.read_to_end(&mut rest).await.expect("origin read");
                assert!(rest.is_empty());
                drop(origin);
            };
            let (served, ()) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the relay hung");
            served.expect("a tunnel both ends closed is a clean close");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(
                row.metadata.tunnel,
                Some(TunnelInfo {
                    mode: TunnelMode::Passthrough,
                    reason: Some(TunnelReason::OutOfScope),
                    bytes_up: Some(RECORD.len() as u64),
                    bytes_down: Some(REPLY.len() as u64),
                })
            );
            assert_eq!(status(row), Some(200));
            assert!(row.client_conn.tls);
            assert!(row.metadata.duration.is_some());
        }

        /// The HTTP module has no pin list: `tls.passthrough` pins belong to the
        /// passthrough module (spec D2), so a pinned host reaches this module only
        /// when that module is absent, and then Scope alone decides. Out of Scope
        /// a non-TLS first byte is refused (above); in Scope it is D6's cleartext
        /// branch — served inside the tunnel as a `decrypted` row with
        /// `client.tls == false`, the inner request its own non-passive row —
        /// never a `passthrough/pinned` row and never a raw relay to the origin.
        #[tokio::test]
        async fn in_scope_connect_whose_first_byte_is_cleartext_is_served_as_a_decrypted_tls_false_row(
        ) {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ours, mut origin) = duplex(64 * 1024);
            let (ctx, dialed) =
                scoped_ctx(vec![Box::pin(ours)], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                let ack = connect(&mut client, ORIGIN).await;
                assert!(ack.starts_with("HTTP/1.1 200 "), "ack: {ack:?}");
                client
                    .write_all(get_request("/plain", ORIGIN).as_bytes())
                    .await
                    .expect("send cleartext inside the tunnel");
                let head = read_head(&mut origin).await;
                assert!(
                    head.starts_with("GET /plain HTTP/1.1\r\n"),
                    "the origin is served the request as HTTP: {head:?}"
                );
                origin
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .expect("origin answers");
                let body = read_one_200(&mut client).await;
                drop(client);
                drop(origin);
                body
            };
            let (served, body) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the cleartext tunnel hung");
            served.expect("the module ends cleanly when the client hangs up");
            assert_eq!(body, "ok");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row.request.authority, ORIGIN);
            assert_eq!(outcome(row), (TunnelMode::Decrypted, None));
            assert_eq!(status(row), Some(200));
            assert!(!row.client_conn.tls, "the client never spoke TLS");
            assert!(
                row.metadata.duration.is_some(),
                "closed when the connection ended"
            );
            assert!(!row.metadata.passive);
            let inner = request_row(&store, "/plain");
            assert_eq!(inner.request.method, "GET");
            assert_eq!(inner.request.authority, ORIGIN);
            assert_eq!(status(&inner), Some(200));
            assert!(
                !inner.metadata.passive,
                "a request inside an in-scope tunnel is acted on"
            );
            assert_eq!(inner.metadata.tunnel, None);
            assert_eq!(request_paths(&store), vec!["/plain".to_string()]);
            assert_eq!(
                *dialed.lock().expect("dialed lock"),
                vec![(ORIGIN.to_string(), origin_peer())]
            );
        }

        /// Panel S4 end to end: a CONNECT whose authority carries an ASCII control
        /// byte (a terminal escape) is refused before anything is acknowledged or
        /// dialled — `Authority` rejects it — and the error the acceptor logs
        /// carries the raw text Debug-escaped: no raw escape byte reaches a log
        /// line. The row is `failed/protocol_error` under the label the module
        /// records for an unparseable token — the raw text with every ASCII
        /// control byte dropped, lowercased (Tester T8: `request.authority` never
        /// carries a control byte; the error text still names the token as sent).
        #[tokio::test]
        async fn connect_authority_with_a_control_byte_is_refused_with_an_escaped_error() {
            let module = HttpModule::with_ca(test_ca()).with_insecure(true);
            let store = Arc::new(MemFlowStore::new());
            let (ctx, dialed) = scoped_ctx(vec![], store.clone(), scoped(&["127.0.0.1"]));

            let (mut client, proxy_side) = duplex(64 * 1024);
            let serving = module.spawn(Box::pin(proxy_side), ctx);
            let script = async {
                client
                    .write_all(
                        b"CONNECT \x1b[2Jevil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
                    )
                    .await
                    .expect("send the CONNECT");
                read_head(&mut client).await
            };
            let (served, reply) =
                tokio::time::timeout(STALL_GUARD, async { tokio::join!(serving, script) })
                    .await
                    .expect("the CONNECT hung");
            let err = served.expect_err("a control byte in the authority fails the connection");
            assert_eq!(
                err.to_string(),
                "malformed CONNECT authority: authority \"\\u{1b}[2Jevil.example:443\" has an invalid host"
            );
            let chain = format!("{err:#}");
            assert!(
                !chain.contains('\x1b'),
                "a raw escape byte in the error text: {chain:?}"
            );
            assert_eq!(reply, "", "the proxy replies nothing and closes");

            let rows = tunnel_rows(&store);
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_failed(row, TunnelReason::ProtocolError);
            // The label as `Authority::new(<raw minus control bytes>, 443)`
            // prints it: `\x1b` dropped, the leading `[` trimmed as an IPv6
            // bracket, lowercased; the token kept a colon, so `Display` brackets
            // it like an IPv6 literal (`[host:port]:443`).
            assert_eq!(
                row.request.authority, "[2jevil.example:443]:443",
                "the raw label with the control byte stripped, lowercased and bracketed"
            );
            assert!(
                !row.request.authority.chars().any(|c| c.is_ascii_control()),
                "no control byte on the row: {:?}",
                row.request.authority
            );
            assert_eq!(row.request.headers.get("host"), Some("evil.example:443"));
            assert!(!row.client_conn.tls);
            assert!(row.server_conn.is_none(), "nothing was dialled");
            assert!(dialed.lock().expect("dialed lock").is_empty());
        }
    }
}
