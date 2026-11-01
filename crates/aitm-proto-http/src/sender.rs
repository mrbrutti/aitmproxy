//! `HttpSender`: the concrete [`RequestSender`] the binary injects into the
//! core `PipelineClient` so `flow.replay` / `request.send` reissue a request for
//! real.
//!
//! For HTTP/1.1 it drives the shared [`Http1Machine`] (so framing —
//! `Content-Length`, chunked decode, close-delimited bodies — matches the
//! proxy's own parser and no duplicate `Content-Length`/`Transfer-Encoding` is
//! emitted) over a TCP stream, wrapped in rustls for `https` with the webpki
//! roots verified by default.
//!
//! The sender negotiates the HTTP version with ALPN: by default it offers
//! `h2, http/1.1`, caches what the authority settled on for
//! [`ALPN_CACHE_TTL`], and dispatches the exchange to the h1 path or the h2
//! path accordingly. A caller that needs a particular version passes a
//! [`VersionPolicy`]; a forced `h2` against a peer that will not speak it fails
//! with [`SendError::H2NotNegotiated`], which the scanner surfaces as a probe
//! error rather than a job failure.
//!
//! `Http1Sender` remains as an alias of [`HttpSender`], so every existing
//! construction site is untouched.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    ssrf_check, Authority, Body, HttpRequest, HttpResponse, RequestSender, ScopeRateGuard,
    SsrfPolicy, VersionPolicy,
};
use anyhow::{anyhow, Context, Result};
use futures::future::BoxFuture;
use moka::sync::Cache;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::h2_sender::H2Pool;
use crate::sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole exchange after connecting — TLS handshake, write, and the full
/// response — must finish within this. The per-read timeout alone resets on
/// every byte, so an upstream trickling a header forever would otherwise hold
/// the caller (and, through a script's `http.send`, a hook) open indefinitely.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const READ_CHUNK: usize = 16 * 1024;
/// The response-body cap, shared with the h2 path in [`crate::h2_sender`].
pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// How long an authority's negotiated protocol is reused before the sender
/// offers both again.
const ALPN_CACHE_TTL: Duration = Duration::from_secs(600);
/// How many authorities the ALPN cache remembers.
const ALPN_CACHE_CAPACITY: u64 = 1024;

/// The ALPN protocol identifier for HTTP/2, shared with [`crate::raw_h2`].
pub(crate) const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Name → addresses. A seam so the SSRF gate is testable without real DNS; the
/// default resolves through tokio's non-blocking resolver.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>>;
}

/// The operating system's resolver, driven on tokio's blocking pool. Shared
/// with [`crate::raw_h2`], which resolves the same way.
pub(crate) struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: String, port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// A byte stream the sender can run an exchange over. Blanket-implemented, so
/// a real `TcpStream` and an in-memory `tokio::io::duplex` half both qualify.
pub trait ProbeStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProbeStream for T {}

/// Address → stream. The seam that lets the whole negotiate/cache/dispatch
/// path be exercised over `tokio::io::duplex` without binding a port;
/// production uses [`TcpDialer`].
pub trait Dialer: Send + Sync {
    fn dial(&self, addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>>;
}

/// A real TCP connection, bounded by the timeout it was built with.
///
/// Shared with [`crate::raw_h2`]: the reissue path allows [`CONNECT_TIMEOUT`]
/// and the raw probe driver its own, shorter one, so the timeout is a
/// constructor argument rather than two copies of this type (review finding
/// Q4).
pub(crate) struct TcpDialer {
    connect_timeout: Duration,
}

impl TcpDialer {
    pub(crate) fn new(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    /// The timeout this dialer was built with.
    #[cfg(test)]
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

impl Dialer for TcpDialer {
    fn dial(&self, addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
        let connect_timeout = self.connect_timeout;
        Box::pin(async move {
            let tcp = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("connect to {addr} timed out"))??;
            Ok(Box::new(tcp) as Box<dyn ProbeStream>)
        })
    }
}

/// The application protocol an authority settled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiated {
    /// HTTP/1.1 — ALPN chose `http/1.1`, or the peer chose nothing.
    H1,
    /// HTTP/2 — ALPN chose `h2`.
    H2,
}

/// A sender failure the caller is expected to recognise rather than treat as a
/// generic transport error.
#[derive(Debug)]
pub enum SendError {
    /// The caller forced HTTP/2 and the peer would not speak it. Rendered as
    /// `h2_not_negotiated: <authority>: <detail>`; the scanner counts this as a
    /// probe error, never a job failure.
    H2NotNegotiated { authority: String, detail: String },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::H2NotNegotiated { authority, detail } => {
                write!(f, "h2_not_negotiated: {authority}: {detail}")
            }
        }
    }
}

impl std::error::Error for SendError {}

/// True when `err` is (or carries, or is the round-tripped text of) a
/// [`SendError::H2NotNegotiated`]. The string check keeps the classification
/// alive after the error has crossed the bus as a message.
pub fn is_h2_not_negotiated(err: &anyhow::Error) -> bool {
    err.chain().any(|link| {
        matches!(
            link.downcast_ref::<SendError>(),
            Some(SendError::H2NotNegotiated { .. })
        ) || link.to_string().starts_with("h2_not_negotiated:")
    })
}

/// The SSRF gate for every outbound path in this crate: the same policy + live
/// scope the browser connector uses. Shared with [`crate::raw_h2`], so the
/// reissue path and the raw h2 probe driver run one implementation of the
/// check rather than two.
pub(crate) struct SsrfGate {
    pub(crate) policy: SsrfPolicy,
    pub(crate) scope: Arc<dyn ScopeRateGuard>,
}

impl SsrfGate {
    /// Refuse the target when **any** address it resolved to is private,
    /// loopback or metadata and no in-scope IP literal lifts the block, so the
    /// resolve-then-connect (DNS-rebinding) window is closed. `what` names the
    /// caller's operation; the message carries the requested host and the
    /// guard's own refusal, never the resolved address.
    pub(crate) fn check(
        &self,
        what: &str,
        authority: &str,
        host: &str,
        ips: &[IpAddr],
    ) -> Result<()> {
        let scope = self.scope.list_scope();
        for ip in ips {
            // `confine_to_scope = false`: scope-confined egress is a
            // browser-only posture (scanner S2). Active reissue is already
            // scope-gated upstream by `check_active`; it must not be gated
            // again here (per the egress-confinement spec's anti-goal).
            ssrf_check(&self.policy, &scope, false, authority, *ip)
                .map_err(|e| anyhow!("SSRF: refusing {what} to {host}: {e}"))?;
        }
        Ok(())
    }
}

/// Reissues requests over real HTTP/1.1 or HTTP/2 (+ TLS for `https`).
pub struct HttpSender {
    provider: Arc<CryptoProvider>,
    insecure: bool,
    response_timeout: Duration,
    resolver: Arc<dyn HostResolver>,
    dialer: Arc<dyn Dialer>,
    ssrf: Option<SsrfGate>,
    alpn: Cache<String, Negotiated>,
    h2_pool: H2Pool,
}

/// The pre-h2 name of [`HttpSender`], kept so every existing construction site
/// compiles unchanged.
pub type Http1Sender = HttpSender;

impl Default for HttpSender {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpSender {
    /// A sender that verifies upstream TLS against the webpki roots.
    pub fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            insecure: false,
            response_timeout: RESPONSE_TIMEOUT,
            resolver: Arc::new(SystemResolver),
            dialer: Arc::new(TcpDialer::new(CONNECT_TIMEOUT)),
            ssrf: None,
            alpn: alpn_cache(ALPN_CACHE_TTL),
            h2_pool: H2Pool::new(),
        }
    }

    /// Skip upstream certificate verification when `insecure` (maps to
    /// `Config.ssl_insecure`).
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Enforce the SSRF policy against `scope` on every reissue: resolve the
    /// target and refuse a private/loopback/metadata address unless an in-scope
    /// IP literal lifts it — exactly as the browser connector does, so
    /// `flow.replay`, `request.send` and the script `http.send` (which all share
    /// this sender) cannot reach an internal host or rebind a scoped name to one.
    pub fn with_ssrf(mut self, policy: SsrfPolicy, scope: Arc<dyn ScopeRateGuard>) -> Self {
        self.ssrf = Some(SsrfGate { policy, scope });
        self
    }

    /// Replace the DNS resolver. A seam for tests; production uses the default
    /// system resolver.
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Replace the dialer. A seam for tests (an in-memory duplex pair stands in
    /// for the origin); production uses a real TCP connection.
    pub fn with_dialer(mut self, dialer: Arc<dyn Dialer>) -> Self {
        self.dialer = dialer;
        self
    }

    /// How long a negotiated protocol is remembered before the sender offers
    /// both again (default [`ALPN_CACHE_TTL`], ten minutes). Rebuilds the
    /// cache, so it is empty afterwards — call it while configuring the
    /// sender, not mid-run. A seam for tests, which cannot wait out the
    /// default.
    pub fn with_alpn_cache_ttl(mut self, ttl: Duration) -> Self {
        self.alpn = alpn_cache(ttl);
        self
    }

    /// The overall deadline for one exchange after the TCP connect (default
    /// 60s).
    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = timeout;
        self
    }

    /// What ALPN settled on for `scheme://authority` (`authority` is
    /// `host:port`), while the cache entry lives. `None` once it has expired or
    /// before the first exchange. The scheme is part of the identity: a
    /// cleartext and a TLS origin on the same host and port are two peers.
    pub fn negotiated_for(&self, scheme: &str, authority: &str) -> Option<Negotiated> {
        self.alpn.get(&conn_key(scheme, authority))
    }

    /// The ALPN protocol list to offer for the connection `key` under
    /// `version`: everything we can speak when nothing is known, the remembered
    /// protocol on a cache hit, and exactly one entry when the caller forces a
    /// version.
    fn alpn_offer(&self, key: &str, version: VersionPolicy) -> Vec<&'static [u8]> {
        match version {
            VersionPolicy::H1 => vec![ALPN_HTTP11],
            VersionPolicy::H2 | VersionPolicy::H2c => vec![ALPN_H2],
            VersionPolicy::Auto => match self.alpn.get(key) {
                Some(Negotiated::H2) => vec![ALPN_H2],
                Some(Negotiated::H1) => vec![ALPN_HTTP11],
                None => vec![ALPN_H2, ALPN_HTTP11],
            },
        }
    }

    /// Whether this send already knows it will speak h2 — the case where a
    /// pooled connection under `key` can carry it instead of a fresh dial.
    /// An `Auto` send only knows that once ALPN has settled on h2 here before;
    /// a forced `h2`/`h2c` always does. (A forced `h2` on a plaintext origin
    /// has already failed by this point, so `tls` decides that arm.)
    fn h2_without_negotiating(&self, key: &str, version: VersionPolicy, tls: bool) -> bool {
        match version {
            VersionPolicy::H1 => false,
            VersionPolicy::H2 => tls,
            VersionPolicy::H2c => true,
            VersionPolicy::Auto => tls && self.alpn.get(key) == Some(Negotiated::H2),
        }
    }

    fn client_config(&self, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>> {
        let builder = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .context("replay TLS versions")?;
        let mut cfg = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(crate::module::accept_any_verifier(
                    self.provider.clone(),
                ))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(cfg))
    }

    /// One reissued exchange: resolve, SSRF-gate, dial, negotiate (for `https`)
    /// and dispatch to the h1 or h2 path.
    async fn send_impl(&self, req: HttpRequest, version: VersionPolicy) -> Result<HttpResponse> {
        let scheme = req.scheme.to_ascii_lowercase();
        let tls = scheme == "https";
        let req = prepare_common(req);
        let (host, port) = split_authority(&req.authority, &scheme)?;
        let authority = Authority::new(&host, port).to_string();
        // Everything connection-shaped — the ALPN cache and the h2 pool — is
        // keyed by scheme *and* authority: `http://h:p` (h2c, cleartext) and
        // `https://h:p` are two different peers and must never share an entry.
        let key = conn_key(&scheme, &authority);

        // A plaintext origin has no ALPN to force h2 with; say so before we
        // spend a connection on it.
        if !tls && matches!(version, VersionPolicy::H2) {
            return Err(SendError::H2NotNegotiated {
                authority,
                detail: "plaintext origin cannot negotiate ALPN; use h2c".into(),
            }
            .into());
        }

        // One deadline for the whole send, taken before the resolve: every
        // layer below — resolve, dial, handshake, exchange — works to this
        // instant rather than starting a budget of its own (review findings
        // Q3, SEC-12).
        let deadline = tokio::time::Instant::now() + self.response_timeout;

        // Resolve once, then (when the SSRF gate is configured) refuse a
        // private/loopback/metadata address before connecting, and connect to
        // an address we actually validated — so the resolve-then-connect
        // (DNS-rebinding) window is closed and every reissue path that shares
        // this sender is covered. The resolve is inside the deadline: a name
        // server that never answers must not hold the caller open.
        let ips = tokio::time::timeout_at(deadline, self.resolver.resolve(host.clone(), port))
            .await
            .map_err(|_| {
                anyhow!(
                    "resolve {host}:{port} timed out after {:?}",
                    self.response_timeout
                )
            })??;
        if let Some(gate) = &self.ssrf {
            gate.check("reissue", &authority, &host, &ips)?;
        }
        let addr = ips
            .into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;

        let leg = ExchangeLeg {
            key: &key,
            host: &host,
            authority: &authority,
            addr,
            tls,
            version,
            deadline,
        };

        // When this send is going to speak h2 whatever ALPN says, a live
        // pooled connection to the authority serves it without a second dial.
        // The resolve and the SSRF gate above still run every time, so reuse
        // never skips the check that decides whether this target is allowed.
        let pooled = if self.h2_without_negotiating(&key, version, tls) {
            self.h2_pool.take(&key)
        } else {
            None
        };

        // The gate above ran on what the name resolves to *now*; a pooled
        // connection goes to the address it was dialled to back then. Check
        // that address too, and refuse the send — dropping the connection —
        // when it is no longer allowed. A fresh answer that passes does not
        // make an open connection to a now-forbidden peer acceptable (review
        // finding SEC-8).
        if let (Some(checkout), Some(gate)) = (&pooled, &self.ssrf) {
            if let Err(e) = gate.check("reissue", &authority, &host, &[checkout.addr.ip()]) {
                self.h2_pool.remove_if(&key, checkout.generation);
                return Err(e);
            }
        }

        let exchange = async {
            if let Some(checkout) = pooled {
                let result = crate::h2_sender::exchange_pooled(
                    &self.h2_pool,
                    checkout,
                    &key,
                    &req,
                    deadline,
                )
                .await;
                match result {
                    Ok(resp) => return Ok(resp),
                    // The redial rule (plan amendment A7, review finding
                    // SEC-10): a POOLED connection is redialled, once, only
                    // when its failure PROVES the request was not processed —
                    // `ready()`/`send_request()` failed before anything was
                    // written, the peer's GOAWAY named a `last_stream_id`
                    // below the stream, or it answered
                    // `RST_STREAM(REFUSED_STREAM)` — and no byte of a
                    // response had arrived. The h2 layer decides that where
                    // the error is in hand; this is the only place that acts
                    // on it. The stale connection is already evicted; fall
                    // through and dial. A freshly dialled connection never
                    // reaches this arm, so one failed send costs at most two
                    // connections and one re-issued request (review finding
                    // Q1).
                    Err(failure) if failure.retryable => {
                        // `Display` of an `anyhow::Error` is its outermost
                        // context only — our own text, never the peer's
                        // GOAWAY debug data (review finding SEC-7).
                        tracing::debug!(
                            peer = %key,
                            error = %failure.error,
                            "pooled h2 connection declined the request unprocessed; redialling once"
                        );
                    }
                    // A wire timeout, an I/O error, any other reset, or
                    // anything after the peer began answering: the request
                    // may be on the record at the origin and is never put on
                    // the wire again.
                    Err(failure) => return Err(failure.error),
                }
            }
            self.dial_and_exchange(&req, &leg).await
        };
        // The same `deadline` the h2 layer was handed, so the two caps are
        // one cap (review finding QM-3).
        tokio::time::timeout_at(deadline, exchange)
            .await
            .map_err(|_| {
                anyhow!(
                    "upstream response from {addr} timed out after {:?}",
                    self.response_timeout
                )
            })?
    }

    /// Dial `leg.addr`, negotiate (for `https`) and run the exchange on the
    /// fresh connection. The whole-exchange cap belongs to `send_impl`, which
    /// wraps this.
    async fn dial_and_exchange(
        &self,
        req: &HttpRequest,
        leg: &ExchangeLeg<'_>,
    ) -> Result<HttpResponse> {
        let ExchangeLeg {
            key,
            host,
            authority,
            addr,
            tls,
            version,
            deadline,
        } = *leg;
        let stream = self.dialer.dial(addr).await?;
        if tls {
            let offer = self.alpn_offer(key, version);
            let name = ServerName::try_from(host.to_string())
                .map_err(|e| anyhow!("invalid server name {host:?}: {e}"))?;
            let tls_stream = match TlsConnector::from(self.client_config(&offer)?)
                .connect(name, stream)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    // An `Auto` offer the peer refused outright was narrowed
                    // by a cache entry the peer has just proven stale (a
                    // first `Auto` send offers everything, and an entry it
                    // never had is nothing to drop). Forget it, so the next
                    // `Auto` send offers both protocols again instead of
                    // failing the same way for the rest of the TTL (plan
                    // amendment A7, review finding SPEC-5). A forced send
                    // never touches the cache.
                    if matches!(version, VersionPolicy::Auto) && alpn_refused(&e) {
                        self.alpn.invalidate(key);
                    }
                    return Err(handshake_error(e, authority, host, &offer));
                }
            };
            let selected = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            let negotiated = match selected.as_deref() {
                Some(ALPN_H2) => Negotiated::H2,
                _ => Negotiated::H1,
            };
            // Only an `Auto` send records what the authority settled on: a
            // forced h1 or h2 offer carries one protocol, so what came
            // back says nothing about what would have been negotiated and
            // must not steer a later `Auto` send (plan Task 3, item 5).
            if matches!(version, VersionPolicy::Auto) {
                self.alpn.insert(key.to_string(), negotiated);
            }
            match negotiated {
                Negotiated::H2 => {
                    crate::h2_sender::exchange(
                        &self.h2_pool,
                        Box::new(tls_stream),
                        key,
                        addr,
                        req,
                        deadline,
                    )
                    .await
                }
                // `h2c` over TLS is just `h2` (session call S2), so both
                // forced-h2 policies fail the same way here.
                Negotiated::H1 if matches!(version, VersionPolicy::H2 | VersionPolicy::H2c) => {
                    Err(SendError::H2NotNegotiated {
                        authority: authority.to_string(),
                        detail: match selected.as_deref() {
                            Some(other) => format!(
                                "server negotiated {} instead of h2",
                                String::from_utf8_lossy(other)
                            ),
                            None => "server negotiated no ALPN protocol".into(),
                        },
                    }
                    .into())
                }
                Negotiated::H1 => drive(tls_stream, &prepare_h1(req)).await,
            }
        } else if matches!(version, VersionPolicy::H2c) {
            // Prior-knowledge cleartext h2: no TLS, no ALPN, straight into
            // the h2 preface on the raw stream.
            crate::h2_sender::exchange(&self.h2_pool, stream, key, addr, req, deadline).await
        } else {
            drive(stream, &prepare_h1(req)).await
        }
    }
}

/// Everything one exchange needs that the request itself does not carry.
struct ExchangeLeg<'a> {
    /// `scheme://host:port`: the ALPN cache and h2 pool identity.
    key: &'a str,
    /// The host to put in SNI and in an error.
    host: &'a str,
    /// `host:port`, as an `h2_not_negotiated` names it.
    authority: &'a str,
    /// The validated address to dial.
    addr: SocketAddr,
    tls: bool,
    version: VersionPolicy,
    /// When the whole send must be done, counted from before the resolve.
    deadline: tokio::time::Instant,
}

impl RequestSender for HttpSender {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, Result<HttpResponse>> {
        let req = req.clone();
        Box::pin(async move { self.send_impl(req, VersionPolicy::Auto).await })
    }

    fn send_with<'a>(
        &'a self,
        req: &'a HttpRequest,
        version: VersionPolicy,
    ) -> BoxFuture<'a, Result<HttpResponse>> {
        let req = req.clone();
        Box::pin(async move { self.send_impl(req, version).await })
    }
}

/// Classify a TLS handshake failure: a `no_application_protocol` alert means
/// the peer refused every protocol we offered — which is `h2_not_negotiated`
/// only when `offer` was h2 and nothing else.
///
/// `offer` decides it, not the [`VersionPolicy`] alone: a forced `h2`/`h2c`
/// offers exactly `h2`, and so does an `Auto` send whose ALPN cache already
/// settled on h2, and both of those really are "this peer will not speak h2".
/// An offer that carried `http/1.1` — a forced `h1`, or a first `Auto` send —
/// tells us nothing about h2 in particular, so the alert stays a plain
/// `TLS to {host}` error rather than being miscounted as a version-negotiation
/// result (review finding SEC-2).
fn handshake_error(
    err: std::io::Error,
    authority: &str,
    host: &str,
    offer: &[&[u8]],
) -> anyhow::Error {
    let asked_only_for_h2 = offer.len() == 1 && offer[0] == ALPN_H2;
    if alpn_refused(&err) && asked_only_for_h2 {
        return SendError::H2NotNegotiated {
            authority: authority.to_string(),
            detail: "server refused ALPN h2 (no_application_protocol)".into(),
        }
        .into();
    }
    anyhow::Error::new(err).context(format!("TLS to {host}"))
}

/// Whether a TLS handshake failure is the peer's `no_application_protocol`
/// alert — it refused every protocol the ClientHello offered.
fn alpn_refused(err: &std::io::Error) -> bool {
    matches!(
        err.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::NoApplicationProtocol
        ))
    )
}

/// Normalise a request for sending, whatever the version: a `Host` header from
/// the authority, and no inherited `Connection` header. Framing headers are
/// left to the version-specific path.
fn prepare_common(mut req: HttpRequest) -> HttpRequest {
    req.headers.remove("host");
    req.headers.remove("connection");
    let host = req
        .authority
        .rsplit_once('@')
        .map(|(_, h)| h.to_string())
        .unwrap_or_else(|| req.authority.clone());
    let _ = req.headers.try_set("Host", &host);
    req
}

/// The HTTP/1.1 form of [`prepare_common`]: add `Connection: close` so the
/// exchange ends cleanly. `Content-Length` is left to
/// `Http1Machine::enqueue_request`, which sets it from the body. The h2 path
/// adds nothing — `translate::h2_request_from` drops hop-by-hop names.
fn prepare_h1(req: &HttpRequest) -> HttpRequest {
    let mut out = req.clone();
    let _ = out.headers.try_set("Connection", "close");
    out
}

/// Serialize a request to wire bytes (used only to prime the machine so it knows
/// the method for response framing); `Content-Length` is set from the real body.
fn request_bytes(req: &HttpRequest) -> Vec<u8> {
    let path = if req.path.is_empty() { "/" } else { &req.path };
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, path);
    for (name, value) in req.headers.iter() {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    let body = match &req.body {
        Body::Bytes(b) => b.as_slice(),
        _ => &[],
    };
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Drive one request/response exchange over `stream` using the shared machine.
async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    req: &HttpRequest,
) -> Result<HttpResponse> {
    let mut machine = Http1Machine::new();
    // Prime the machine by parsing the request (so it tracks the method/flow for
    // response framing), then forward a cleanly-framed copy to the server.
    machine.on_bytes(Side::Client, &request_bytes(req))?;
    machine.enqueue_request(req);
    if let Some(bytes) = machine.poll_outbound(Side::Server) {
        stream.write_all(&bytes).await?;
    }
    stream.flush().await?;

    let mut body: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut done = false;
    while !done {
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Err(anyhow!("upstream read timed out")),
        };
        let events = if n == 0 {
            machine.on_eof(Side::Server)
        } else {
            machine.on_bytes(Side::Server, &buf[..n])?
        };
        for ev in events {
            match ev {
                HttpSansIoEvent::ResponseBodyChunk { bytes, .. } => {
                    let room = MAX_RESPONSE_BYTES.saturating_sub(body.len());
                    let take = room.min(bytes.len());
                    body.extend_from_slice(&bytes[..take]);
                }
                HttpSansIoEvent::ResponseComplete(_) => done = true,
                _ => {}
            }
        }
        if n == 0 {
            break;
        }
    }

    let head = machine
        .response()
        .cloned()
        .ok_or_else(|| anyhow!("no response parsed from upstream"))?;
    Ok(HttpResponse {
        body: if body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(body)
        },
        timestamp: SystemTime::now(),
        ..head
    })
}

/// An empty ALPN cache holding at most [`ALPN_CACHE_CAPACITY`] entries, each
/// for `ttl`.
fn alpn_cache(ttl: Duration) -> Cache<String, Negotiated> {
    Cache::builder()
        .time_to_live(ttl)
        .max_capacity(ALPN_CACHE_CAPACITY)
        .build()
}

/// The identity of one upstream connection: `scheme://host:port`. The single
/// key for both the ALPN cache and the h2 connection pool, so an `h2c` peer and
/// a TLS peer on the same host and port never collide.
fn conn_key(scheme: &str, authority: &str) -> String {
    format!("{scheme}://{authority}")
}

/// Split `host[:port]` with the scheme's default port; handles bracketed IPv6.
/// Shared with [`crate::raw_h2`], which splits its target the same way.
///
/// Userinfo is credential material: everything up to and including the last
/// `@` is dropped before the parse — the rule [`prepare_common`] applies to
/// the `Host` field — so a password never reaches the resolver, the SSRF
/// gate's authority string, or an error message (security review FS-4).
pub(crate) fn split_authority(authority: &str, scheme: &str) -> Result<(String, u16)> {
    let default = if scheme == "https" { 443 } else { 80 };
    let bare = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let auth = aitm_core::Authority::parse_with_default(bare, default)
        .map_err(|e| anyhow!("bad authority {bare:?}: {e}"))?;
    let port = if auth.port == 0 { default } else { auth.port };
    Ok((auth.host, port))
}

/// The sender over in-memory streams: HTTP/1.1 framing through `drive`
/// (chunked trailers, interim responses, the body cap), ALPN negotiation and
/// its cache, the forced-version policies, and the SSRF gate — every one of
/// them over a `tokio::io::duplex` pair, so nothing here binds a port.
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    use super::*;
    use aitm_core::HeaderMap;
    use tokio::io::{duplex, DuplexStream};

    /// Yield until `done` holds. A test waits on the state it cares about
    /// rather than on a sleep long enough to "probably" cover it.
    async fn until(what: &str, done: impl Fn() -> bool) {
        for _ in 0..200_000 {
            if done() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{what}");
    }

    /// A request for `path` on `127.0.0.1:8080`.
    fn request(method: &str, path: &str, headers: &[(&str, &str)], body: Body) -> HttpRequest {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpRequest {
            method: method.into(),
            scheme: "http".into(),
            authority: "127.0.0.1:8080".into(),
            path: path.into(),
            version: aitm_core::HttpVersion::Http11,
            headers: map,
            body,
            timestamp: SystemTime::now(),
        }
    }

    fn get_x() -> HttpRequest {
        request("GET", "/x", &[("Host", "127.0.0.1:8080")], Body::Empty)
    }

    /// Read one request from `io` (its head and the `Content-Length` body bytes
    /// that follow), returning every byte read.
    async fn read_request(io: &mut DuplexStream) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse::<usize>().expect("numeric Content-Length"))
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length {
                    return seen;
                }
            }
            let n = io.read(&mut buf).await.expect("origin read");
            assert!(n > 0, "the sender closed before it wrote a whole request");
            seen.extend_from_slice(&buf[..n]);
        }
    }

    /// The origin: read one request, record it, then write each segment with a
    /// 10 ms pause between so the machine sees them as separate reads. After the
    /// last segment it holds the connection open until the sender hangs up.
    /// Returns the request bytes it read. A failed write means the sender
    /// already gave up (the case under test), so it just stops.
    async fn origin(mut io: DuplexStream, segments: Vec<Vec<u8>>) -> Vec<u8> {
        let seen = read_request(&mut io).await;
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if io.write_all(segment).await.is_err() || io.flush().await.is_err() {
                return seen;
            }
        }
        let mut sink = [0u8; 1];
        let _ = io.read(&mut sink).await;
        seen
    }

    /// Run `drive` for `req` against an origin that answers with `segments`;
    /// returns what `drive` returned and the request bytes the origin saw.
    async fn exchange(req: HttpRequest, segments: Vec<Vec<u8>>) -> (Result<HttpResponse>, Vec<u8>) {
        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(origin(server, segments));
        let result = tokio::time::timeout(Duration::from_secs(10), drive(client, &req))
            .await
            .expect("drive finished within the guard");
        let seen = origin.await.expect("origin task");
        (result, seen)
    }

    fn seg(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn trailers(resp: &HttpResponse) -> Vec<(&str, &str)> {
        resp.trailers.iter().collect()
    }

    #[tokio::test]
    async fn drive_returns_the_trailers_of_a_chunked_response() {
        let (result, _) = exchange(
            get_x(),
            vec![seg(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                 5\r\nhello\r\n0\r\nX-Sum: abc\r\nServer-Timing: origin;dur=1\r\n\r\n",
            )],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        assert_eq!(resp.status, 200);
        match &resp.body {
            Body::Bytes(b) => assert_eq!(b.as_slice(), b"hello"),
            other => panic!("body was {other:?}, want Bytes(hello)"),
        }
        assert_eq!(
            trailers(&resp),
            vec![("X-Sum", "abc"), ("Server-Timing", "origin;dur=1")]
        );
        assert_eq!(
            resp.headers.get("x-sum"),
            None,
            "a trailer is never merged into the headers"
        );
        assert_eq!(resp.headers.get("trailer"), Some("X-Sum"));
    }

    #[tokio::test]
    async fn drive_returns_trailers_that_arrive_in_a_later_read() {
        let (result, _) = exchange(
            get_x(),
            vec![
                seg(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n\
                     5\r\nhello\r\n0\r\n",
                ),
                seg("X-Sum: abc\r\n"),
                seg("Server-Timing: origin;dur=1\r\n"),
                seg("\r\n"),
            ],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        match &resp.body {
            Body::Bytes(b) => assert_eq!(b.as_slice(), b"hello"),
            other => panic!("body was {other:?}, want Bytes(hello)"),
        }
        assert_eq!(
            trailers(&resp),
            vec![("X-Sum", "abc"), ("Server-Timing", "origin;dur=1")]
        );
        assert_eq!(resp.headers.get("x-sum"), None);
    }

    #[tokio::test]
    async fn drive_fails_on_a_trailer_section_over_the_cap() {
        let mut section = String::from("0\r\n");
        for i in 0..65 {
            section.push_str(&format!("f{i}: v\r\n"));
        }
        section.push_str("\r\n");
        let (result, _) = exchange(
            get_x(),
            vec![
                seg("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
                seg(&section),
            ],
        )
        .await;
        let err = result.expect_err("65 trailer fields exceed the machine's cap");
        assert!(err.to_string().contains("trailer"), "{err}");
    }

    /// Characterization: a request that carries `Expect: 100-continue` goes out
    /// head and body together, without waiting for the origin to say anything.
    #[tokio::test]
    async fn drive_writes_an_expect_request_head_and_body_together() {
        let req = request(
            "POST",
            "/up",
            &[("Host", "127.0.0.1:8080"), ("Expect", "100-continue")],
            Body::Bytes(b"hello".to_vec()),
        );
        let (result, seen) = exchange(
            req,
            vec![seg("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        )
        .await;
        assert_eq!(
            String::from_utf8_lossy(&seen),
            "POST /up HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\n\
             Content-Length: 5\r\n\r\nhello"
        );
        assert_eq!(result.expect("the exchange succeeds").status, 200);
    }

    /// Characterization: an origin's own interim `100 Continue` is skipped, so
    /// the response `drive` returns is the final one.
    #[tokio::test]
    async fn drive_skips_an_origin_interim_100_for_a_request_that_carries_expect() {
        let req = request(
            "POST",
            "/up",
            &[("Host", "127.0.0.1:8080"), ("Expect", "100-continue")],
            Body::Bytes(b"hello".to_vec()),
        );
        let (result, _) = exchange(
            req,
            vec![seg(
                "HTTP/1.1 100 Continue\r\n\r\n\
                 HTTP/1.1 302 Found\r\nLocation: /c\r\nContent-Length: 0\r\n\r\n",
            )],
        )
        .await;
        let resp = result.expect("the exchange succeeds");
        assert_eq!(resp.status, 302);
        assert_eq!(resp.headers.get("location"), Some("/c"));
        assert!(matches!(resp.body, Body::Empty), "body was {:?}", resp.body);
        assert!(resp.trailers.is_empty());
    }

    // ---- HttpSender: dial seam, ALPN negotiation, per-authority cache -------

    /// A resolver that answers every name with loopback, so the dial seam —
    /// not DNS — decides what the sender talks to.
    struct FixedResolver;

    impl HostResolver for FixedResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
        }
    }

    /// A dialer that hands out pre-made `tokio::io::duplex` client halves, one
    /// per call, and counts how often it was asked to connect.
    struct DuplexDialer {
        streams: Mutex<VecDeque<DuplexStream>>,
        calls: AtomicUsize,
    }

    impl DuplexDialer {
        fn new(streams: VecDeque<DuplexStream>) -> Self {
            Self {
                streams: Mutex::new(streams),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    impl Dialer for DuplexDialer {
        fn dial(&self, _addr: SocketAddr) -> BoxFuture<'static, Result<Box<dyn ProbeStream>>> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            let next = self
                .streams
                .lock()
                .expect("dialer queue")
                .pop_front()
                .map(|s| Box::new(s) as Box<dyn ProbeStream>);
            Box::pin(async move { next.ok_or_else(|| anyhow!("the dialer ran out of streams")) })
        }
    }

    /// A TLS server config for `origin.test` offering `alpn` in preference
    /// order (copied from `module.rs`'s test helper).
    fn server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["origin.test".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
        .expect("server config");
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(cfg)
    }

    /// What one origin observed: the ALPN protocol list the ClientHello
    /// offered, and the request bytes that arrived after the handshake.
    #[derive(Debug, Default)]
    struct OriginLog {
        alpn: Vec<String>,
        request: Vec<u8>,
    }

    const RESPONSE_200: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    /// A TLS origin over one duplex half: record the offered ALPN list from the
    /// ClientHello, finish the handshake with a server offering `alpn`, read one
    /// request and answer `response`. A handshake that fails (the server's
    /// `no_application_protocol` alert, say) still reports what was offered.
    async fn tls_origin(io: DuplexStream, alpn: &[&[u8]], response: &str) -> OriginLog {
        let start =
            match tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
                .await
            {
                Ok(start) => start,
                Err(_) => return OriginLog::default(),
            };
        let offered: Vec<String> = start
            .client_hello()
            .alpn()
            .map(|list| {
                list.map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let mut tls = match start.into_stream(server_config(alpn)).await {
            Ok(tls) => tls,
            Err(_) => {
                return OriginLog {
                    alpn: offered,
                    request: Vec::new(),
                }
            }
        };
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    return OriginLog {
                        alpn: offered,
                        request,
                    }
                }
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.flush().await;
        let mut sink = [0u8; 1];
        let _ = tls.read(&mut sink).await;
        OriginLog {
            alpn: offered,
            request,
        }
    }

    /// A TLS origin over one duplex half that speaks **h2**: record the offered
    /// ALPN list, finish the handshake with a server offering `alpn`, then
    /// answer every h2 stream `200` with body `hi`, recording the request line.
    /// It returns once the client closes the connection, so a test awaits it
    /// after dropping the sender.
    async fn tls_h2_origin(io: DuplexStream, alpn: &[&[u8]]) -> OriginLog {
        tls_h2_origin_for(io, alpn, usize::MAX).await
    }

    /// [`tls_h2_origin`] that sends `GOAWAY` once it has answered `max_streams`
    /// streams, so the client's pooled handle to it goes stale while the ALPN
    /// cache still says `H2`. Returns once the connection has closed.
    async fn tls_h2_origin_for(io: DuplexStream, alpn: &[&[u8]], max_streams: usize) -> OriginLog {
        let Ok(start) =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await
        else {
            return OriginLog::default();
        };
        let offered: Vec<String> = start
            .client_hello()
            .alpn()
            .map(|list| {
                list.map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let Ok(tls) = start.into_stream(server_config(alpn)).await else {
            return OriginLog {
                alpn: offered,
                request: Vec::new(),
            };
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return OriginLog {
                alpn: offered,
                request: Vec::new(),
            };
        };
        let mut request = Vec::new();
        let mut answered = 0usize;
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let (parts, _body) = req.into_parts();
            request = format!("{} {}", parts.method, parts.uri.path()).into_bytes();
            if let Ok(resp) = http::Response::builder().status(200).body(()) {
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(bytes::Bytes::from_static(b"hi"), true);
                }
            }
            answered += 1;
            if answered >= max_streams {
                // The answer already queued still goes out; the connection then
                // closes, and `accept` returns `None` once it has.
                conn.graceful_shutdown();
            }
        }
        OriginLog {
            alpn: offered,
            request,
        }
    }

    /// A `GET https://origin.test/x`.
    fn https_get() -> HttpRequest {
        let mut map = HeaderMap::new();
        map.set("Host", "origin.test");
        HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "origin.test:443".into(),
            path: "/x".into(),
            version: aitm_core::HttpVersion::Http11,
            headers: map,
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    /// Run `sends` sequential sends of `https_get()` against `sends` fresh TLS
    /// origins, each offering `server_alpn`. Returns the sender (so the ALPN
    /// cache can be inspected), one result per send, one log per origin, and the
    /// dialer (so its call count can be checked).
    async fn tls_sends(
        server_alpn: &'static [&'static [u8]],
        version: VersionPolicy,
        sends: usize,
    ) -> (
        HttpSender,
        Vec<Result<HttpResponse>>,
        Vec<OriginLog>,
        Arc<DuplexDialer>,
    ) {
        let mut clients = VecDeque::new();
        let mut origins = Vec::new();
        for _ in 0..sends {
            let (client, server) = duplex(64 * 1024);
            clients.push_back(client);
            origins.push(tokio::spawn(async move {
                tls_origin(server, server_alpn, RESPONSE_200).await
            }));
        }
        let dialer = Arc::new(DuplexDialer::new(clients));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = https_get();
        let mut results = Vec::new();
        for _ in 0..sends {
            results.push(
                tokio::time::timeout(Duration::from_secs(10), sender.send_with(&req, version))
                    .await
                    .expect("the send finished within the guard"),
            );
        }
        let mut logs = Vec::new();
        for origin in origins {
            logs.push(origin.await.expect("origin task"));
        }
        (sender, results, logs, dialer)
    }

    #[tokio::test]
    async fn auto_offers_both_protocols_and_caches_h2() {
        let (sender, _results, logs, _dialer) =
            tls_sends(&[b"h2", b"http/1.1"], VersionPolicy::Auto, 1).await;
        assert_eq!(logs[0].alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );
    }

    #[tokio::test]
    async fn auto_falls_back_to_h1_when_the_server_picks_http11() {
        let (sender, mut results, logs, _dialer) =
            tls_sends(&[b"http/1.1"], VersionPolicy::Auto, 1).await;
        assert_eq!(logs[0].alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        let resp = results.remove(0).expect("the exchange succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, aitm_core::HttpVersion::Http11);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H1)
        );
    }

    #[tokio::test]
    async fn the_second_send_offers_only_the_cached_protocol() {
        let (_sender, results, logs, dialer) =
            tls_sends(&[b"http/1.1"], VersionPolicy::Auto, 2).await;
        for result in &results {
            assert_eq!(result.as_ref().expect("both exchanges succeed").status, 200);
        }
        assert_eq!(dialer.calls(), 2);
        assert_eq!(
            logs.iter().map(|l| l.alpn.clone()).collect::<Vec<_>>(),
            vec![
                vec!["h2".to_string(), "http/1.1".to_string()],
                vec!["http/1.1".to_string()]
            ]
        );
    }

    #[tokio::test]
    async fn forced_h2_on_an_h1_only_origin_is_h2_not_negotiated() {
        let (sender, mut results, logs, _dialer) =
            tls_sends(&[b"http/1.1"], VersionPolicy::H2, 1).await;
        assert_eq!(logs[0].alpn, vec!["h2".to_string()]);
        let err = results.remove(0).expect_err("forced h2 cannot be served");
        assert!(
            err.to_string().starts_with("h2_not_negotiated:"),
            "error was {err}"
        );
        assert!(
            err.to_string().contains("origin.test:443"),
            "error was {err}"
        );
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        // A rustls server with its own ALPN list answers a ClientHello that
        // overlaps none of it with a fatal `no_application_protocol` alert, so
        // this case exercises the handshake-*failure* mapping (plan Task 1
        // item 8), not the completed-handshake arm. Pin the detail so the two
        // paths cannot be confused.
        assert!(
            err.to_string().contains("no_application_protocol"),
            "error was {err}"
        );
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            None,
            "a forced send must never write the ALPN cache"
        );
    }

    /// SEC-2: `no_application_protocol` only means "no h2" when h2 is what we
    /// asked for. A forced **h1** send to a peer that will not speak
    /// `http/1.1` is a plain TLS failure; calling it `h2_not_negotiated` would
    /// make the scanner count a protocol refusal as a version-negotiation
    /// result and retry the wrong thing.
    #[tokio::test]
    async fn forced_h1_refused_by_alpn_is_not_h2_not_negotiated() {
        let (sender, mut results, logs, _dialer) = tls_sends(&[b"h2"], VersionPolicy::H1, 1).await;
        assert_eq!(logs[0].alpn, vec!["http/1.1".to_string()]);
        let err = results.remove(0).expect_err("forced h1 cannot be served");
        assert!(
            !err.to_string().starts_with("h2_not_negotiated:"),
            "error was {err}"
        );
        assert!(!is_h2_not_negotiated(&err), "error was {err}");
        assert!(
            err.to_string().starts_with("TLS to origin.test"),
            "error was {err}"
        );
        assert_eq!(sender.negotiated_for("https", "origin.test:443"), None);
    }

    /// The same alert under `Auto`: the sender offered both protocols, so a
    /// peer that refused them both has not told us anything about h2 in
    /// particular.
    #[tokio::test]
    async fn an_auto_send_refused_by_alpn_is_not_h2_not_negotiated() {
        let (_sender, mut results, logs, _dialer) =
            tls_sends(&[b"spdy/3"], VersionPolicy::Auto, 1).await;
        assert_eq!(logs[0].alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        let err = results.remove(0).expect_err("neither protocol is served");
        assert!(!is_h2_not_negotiated(&err), "error was {err}");
        assert!(
            err.to_string().starts_with("TLS to origin.test"),
            "error was {err}"
        );
    }

    #[tokio::test]
    async fn forced_h2_on_a_server_without_alpn_is_h2_not_negotiated() {
        let (sender, mut results, logs, _dialer) = tls_sends(&[], VersionPolicy::H2, 1).await;
        assert_eq!(logs[0].alpn, vec!["h2".to_string()]);
        let err = results.remove(0).expect_err("forced h2 cannot be served");
        assert!(
            err.to_string().starts_with("h2_not_negotiated:"),
            "error was {err}"
        );
        assert!(
            err.to_string().contains("origin.test:443"),
            "error was {err}"
        );
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        // A server with no ALPN list completes the handshake without selecting
        // a protocol: the completed-handshake arm, with its own detail.
        assert!(
            err.to_string().contains("no ALPN protocol"),
            "error was {err}"
        );
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            None,
            "a forced send must never write the ALPN cache"
        );
    }

    #[test]
    fn send_error_displays_the_wire_prefix_exactly() {
        let err = SendError::H2NotNegotiated {
            authority: "ex.test:443".into(),
            detail: "nope".into(),
        };
        assert_eq!(err.to_string(), "h2_not_negotiated: ex.test:443: nope");
        let as_anyhow: anyhow::Error = err.into();
        assert_eq!(
            as_anyhow.to_string(),
            "h2_not_negotiated: ex.test:443: nope",
            "the anyhow conversion keeps the prefix at the front"
        );
    }

    #[test]
    fn is_h2_not_negotiated_walks_a_context_wrapped_chain() {
        let typed: anyhow::Error = SendError::H2NotNegotiated {
            authority: "ex.test:443".into(),
            detail: "nope".into(),
        }
        .into();
        let wrapped = typed.context("probe 3 of 7 failed");
        assert!(
            !wrapped.to_string().starts_with("h2_not_negotiated:"),
            "precondition: the context hides the prefix from Display: {wrapped}"
        );
        assert!(
            is_h2_not_negotiated(&wrapped),
            "the typed link deeper in the chain must still classify: {wrapped}"
        );

        let round_tripped =
            anyhow!("h2_not_negotiated: ex.test:443: nope").context("command failed");
        assert!(
            is_h2_not_negotiated(&round_tripped),
            "the string link deeper in the chain must still classify: {round_tripped}"
        );

        let unrelated = anyhow!("connection reset by peer").context("probe 3 of 7 failed");
        assert!(!is_h2_not_negotiated(&unrelated), "{unrelated}");
    }

    #[tokio::test]
    async fn forced_h2_on_a_plaintext_origin_says_use_h2c() {
        let dialer = Arc::new(DuplexDialer::new(VecDeque::new()));
        let sender = HttpSender::new()
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = HttpRequest {
            scheme: "http".into(),
            authority: "origin.test:80".into(),
            ..https_get()
        };
        let err = sender
            .send_with(&req, VersionPolicy::H2)
            .await
            .expect_err("plaintext cannot negotiate ALPN");
        assert!(err.to_string().contains("use h2c"), "error was {err}");
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        assert_eq!(dialer.calls(), 0);
    }

    #[test]
    fn is_h2_not_negotiated_recognises_a_round_tripped_string() {
        assert!(is_h2_not_negotiated(&anyhow!(
            "h2_not_negotiated: ex.test:443: nope"
        )));
        assert!(!is_h2_not_negotiated(&anyhow!("connect refused")));
    }

    /// Q6 took the request by value so one send clones it once; the
    /// normalisation it does must be unchanged by that. Checked directly, not
    /// through a version path: on the h1 path `prepare_h1`'s `Connection:
    /// close` and on the h2 path `translate::h2_request_from`'s hop-by-hop
    /// strip both mask whether `prepare_common` itself still drops the
    /// inherited names, so deleting either `remove` here is invisible from
    /// the wire (tester pass over fix round F2).
    #[test]
    fn prepare_common_drops_the_inherited_host_and_connection_fields() {
        let mut req = request(
            "GET",
            "/x",
            &[
                ("Host", "stale.example:1234"),
                ("Connection", "keep-alive, x-custom"),
                ("X-Custom", "kept"),
            ],
            Body::Empty,
        );
        req.authority = "real.example:8443".into();

        let out = prepare_common(req);

        assert_eq!(
            out.headers.get("Host"),
            Some("real.example:8443"),
            "the Host field is rebuilt from the authority, not inherited"
        );
        assert_eq!(
            out.headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
                .count(),
            1,
            "exactly one Host field: {:?}",
            out.headers
        );
        assert_eq!(
            out.headers.get("Connection"),
            None,
            "an inherited Connection field never survives into a reissue"
        );
        assert_eq!(
            out.headers.get("X-Custom"),
            Some("kept"),
            "every other field is left alone"
        );
    }

    /// The same rule where the authority is split for the resolver: userinfo
    /// is dropped before the parse, so a password never reaches the resolver,
    /// the SSRF gate's `authority` string, or an error message (final
    /// security review FS-4). Shared with `raw_h2`, which splits its target
    /// here too.
    #[test]
    fn split_authority_drops_userinfo_before_resolving_or_erroring() {
        let (host, port) =
            split_authority("user:pass@origin.test:443", "https").expect("a usable authority");
        assert_eq!((host.as_str(), port), ("origin.test", 443));

        let (host, port) =
            split_authority("user:p@ss@origin.test", "https").expect("the last @ splits");
        assert_eq!((host.as_str(), port), ("origin.test", 443));

        // The host after the userinfo is bad: the error names it, never the
        // credential before it.
        for bad in [
            "user:pass@",
            "user:pass@origin.test:notaport",
            "user:pass@ /",
        ] {
            let err = split_authority(bad, "https").expect_err("a bad host is refused");
            let text = err.to_string();
            assert!(!text.contains("pass"), "{bad:?} leaked: {text}");
            assert!(!text.contains("user"), "{bad:?} leaked: {text}");
        }
    }

    /// Userinfo in the authority is credential material: the `Host` field
    /// `prepare_common` builds must carry the host and port only.
    #[test]
    fn prepare_common_strips_userinfo_from_the_host_field() {
        let mut req = request("GET", "/x", &[], Body::Empty);
        req.authority = "user:s3cret@real.example:8443".into();

        let out = prepare_common(req);

        assert_eq!(out.headers.get("Host"), Some("real.example:8443"));
        let rendered = format!("{:?}", out.headers);
        assert!(
            !rendered.contains("s3cret"),
            "the password reached a header: {rendered}"
        );
    }

    #[tokio::test]
    async fn h1_still_sends_connection_close() {
        let (_sender, _results, logs, _dialer) =
            tls_sends(&[b"http/1.1"], VersionPolicy::Auto, 1).await;
        assert!(
            String::from_utf8_lossy(&logs[0].request).contains("Connection: close\r\n"),
            "request was {:?}",
            String::from_utf8_lossy(&logs[0].request)
        );
    }

    #[tokio::test]
    async fn auto_dispatches_to_h2_when_alpn_picks_h2() {
        let (client, server) = duplex(64 * 1024);
        let origin =
            tokio::spawn(async move { tls_h2_origin(server, &[b"h2", b"http/1.1"]).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());

        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send(&https_get()))
            .await
            .expect("the send finished within the guard")
            .expect("the negotiated h2 exchange succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, aitm_core::HttpVersion::H2);
        match &resp.body {
            Body::Bytes(b) => assert_eq!(b.as_slice(), b"hi"),
            other => panic!("body was {other:?}, want Bytes(hi)"),
        }
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );
        drop(sender);
        let log = tokio::time::timeout(Duration::from_secs(10), origin)
            .await
            .expect("the origin finished within the guard")
            .expect("origin task");
        assert_eq!(log.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(String::from_utf8_lossy(&log.request), "GET /x");
    }

    #[tokio::test]
    async fn a_forced_h1_send_does_not_pollute_the_alpn_cache() {
        let (h1_client, h1_server) = duplex(64 * 1024);
        let h1_origin = tokio::spawn(async move {
            tls_origin(h1_server, &[b"h2", b"http/1.1"], RESPONSE_200).await
        });
        let (h2_client, h2_server) = duplex(64 * 1024);
        let h2_origin =
            tokio::spawn(async move { tls_h2_origin(h2_server, &[b"h2", b"http/1.1"]).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([h1_client, h2_client])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = https_get();

        let forced = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H1),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the forced-h1 exchange succeeds");
        assert_eq!(forced.status, 200);
        assert_eq!(forced.version, aitm_core::HttpVersion::Http11);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            None,
            "a forced-h1 send must not record what the authority negotiated"
        );
        let h1_log = h1_origin.await.expect("h1 origin task");
        assert_eq!(h1_log.alpn, vec!["http/1.1".to_string()]);

        let auto = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::Auto),
        )
        .await
        .expect("the send finished within the guard")
        .expect("the following auto exchange succeeds");
        assert_eq!(auto.version, aitm_core::HttpVersion::H2);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );
        drop(sender);
        let h2_log = tokio::time::timeout(Duration::from_secs(10), h2_origin)
            .await
            .expect("the origin finished within the guard")
            .expect("h2 origin task");
        assert_eq!(h2_log.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[tokio::test]
    async fn send_defaults_to_auto() {
        let (client, server) = duplex(64 * 1024);
        let origin =
            tokio::spawn(async move { tls_origin(server, &[b"http/1.1"], RESPONSE_200).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send(&https_get()))
            .await
            .expect("the send finished within the guard")
            .expect("the exchange succeeds");
        let log = origin.await.expect("origin task");
        assert_eq!(resp.status, 200);
        assert_eq!(log.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H1)
        );
    }

    // ---- Tester pass (plan 2026-10-31-aitmproxy-scanner-v2-t3, Tasks 1 + 3) ---

    /// Session call S2: on an `https://` origin `H2c` behaves exactly as `H2` —
    /// it offers only `h2` and fails as `h2_not_negotiated` when refused.
    #[tokio::test]
    async fn h2c_on_an_https_h1_only_origin_fails_like_forced_h2() {
        let (sender, mut results, logs, dialer) =
            tls_sends(&[b"http/1.1"], VersionPolicy::H2c, 1).await;
        assert_eq!(
            logs[0].alpn,
            vec!["h2".to_string()],
            "h2c over TLS offers only h2"
        );
        let err = results
            .remove(0)
            .expect_err("h2c over TLS cannot be served by an h1 origin");
        assert!(
            err.to_string().starts_with("h2_not_negotiated:"),
            "error was {err}"
        );
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        assert_eq!(dialer.calls(), 1, "h2c over TLS dials and runs ALPN");
        assert_eq!(sender.negotiated_for("https", "origin.test:443"), None);
    }

    /// Session call S2, the positive half: `H2c` on an `https://` h2 origin runs
    /// TLS + ALPN and speaks h2, instead of blasting the cleartext preface.
    #[tokio::test]
    async fn h2c_on_an_https_h2_origin_speaks_h2_over_tls() {
        let (client, server) = duplex(64 * 1024);
        let origin =
            tokio::spawn(async move { tls_h2_origin(server, &[b"h2", b"http/1.1"]).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&https_get(), VersionPolicy::H2c),
        )
        .await
        .expect("the send finished within the guard")
        .expect("h2c on an https origin negotiates h2 over TLS");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.version, aitm_core::HttpVersion::H2);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            None,
            "a forced h2c send must not write the ALPN cache"
        );
        drop(sender);
        let log = tokio::time::timeout(Duration::from_secs(10), origin)
            .await
            .expect("the origin finished within the guard")
            .expect("origin task");
        assert_eq!(log.alpn, vec!["h2".to_string()]);
        assert_eq!(String::from_utf8_lossy(&log.request), "GET /x");
    }

    /// Plan Task 1 item 4: an `Auto` send with a cached `Negotiated::H2` offers
    /// only `h2`. When the origin has since dropped to h1-only (and the pooled
    /// connection is gone), that send fails as `h2_not_negotiated` and the stale
    /// entry stays until the TTL expires — the behaviour the plan describes;
    /// the scanner's probe-error ladder owns what happens next.
    #[tokio::test]
    async fn a_stale_h2_cache_entry_makes_auto_offer_only_h2_and_fail_as_h2_not_negotiated() {
        let (first_client, first_server) = duplex(64 * 1024);
        let first =
            tokio::spawn(
                async move { tls_h2_origin_for(first_server, &[b"h2", b"http/1.1"], 1).await },
            );
        let (second_client, second_server) = duplex(64 * 1024);
        let second =
            tokio::spawn(
                async move { tls_origin(second_server, &[b"http/1.1"], RESPONSE_200).await },
            );
        // The origin is h1-only now and stays so: the third send meets it
        // again, offering both protocols once the stale entry is gone.
        let (third_client, third_server) = duplex(64 * 1024);
        let third =
            tokio::spawn(
                async move { tls_origin(third_server, &[b"http/1.1"], RESPONSE_200).await },
            );
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([
            first_client,
            second_client,
            third_client,
        ])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = https_get();

        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect("the first auto exchange speaks h2");
        assert_eq!(resp.version, aitm_core::HttpVersion::H2);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );

        // The origin sent GOAWAY and closed; let the client's connection task
        // observe that before the next send looks in the pool.
        let first_log = tokio::time::timeout(Duration::from_secs(10), first)
            .await
            .expect("the first origin finished within the guard")
            .expect("first origin task");
        assert_eq!(
            first_log.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        // No wait for the client's connection task to notice: whether the dead
        // connection is still in the pool when the next send looks is the
        // scheduler's business, and both ways end here — the pooled handle is
        // either refused by `take` or evicted by the one redial the send is
        // allowed (review finding Q1), and the redial is what the dial count
        // below pins.

        let err = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect_err("an h1-only origin cannot serve the cached h2 offer");
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        assert!(
            err.to_string().contains("no_application_protocol"),
            "error was {err}"
        );
        assert_eq!(
            dialer.calls(),
            2,
            "the dead pooled connection was redialled, not reused"
        );
        let second_log = second.await.expect("second origin task");
        assert_eq!(
            second_log.alpn,
            vec!["h2".to_string()],
            "a cached H2 makes Auto offer only h2"
        );
        // SPEC-5 (plan amendment A7): the refusal of a cache-narrowed offer
        // proves the entry stale, so it is invalidated rather than left to
        // age out, and the next `Auto` send offers both protocols again.
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            None,
            "a no_application_protocol refusal of the cache-narrowed offer drops the entry"
        );

        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect("with the stale entry gone, Auto falls back to HTTP/1.1");
        assert_eq!(resp.version, aitm_core::HttpVersion::Http11);
        assert_eq!(resp.status, 200);
        assert_eq!(dialer.calls(), 3);
        let third_log = third.await.expect("third origin task");
        assert_eq!(
            third_log.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()],
            "the next Auto send re-offers both protocols"
        );
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H1),
            "and the cache now records what the origin really speaks"
        );
    }

    /// SPEC-5, the other half: only an `Auto` send's refusal says anything
    /// about the cache. A forced `h2` refused by the same alert leaves the
    /// `Auto` entry exactly as it was.
    #[tokio::test]
    async fn a_forced_h2_refusal_does_not_touch_the_alpn_cache() {
        let (first_client, first_server) = duplex(64 * 1024);
        let first =
            tokio::spawn(
                async move { tls_h2_origin_for(first_server, &[b"h2", b"http/1.1"], 1).await },
            );
        let (second_client, second_server) = duplex(64 * 1024);
        let second =
            tokio::spawn(
                async move { tls_origin(second_server, &[b"http/1.1"], RESPONSE_200).await },
            );
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([
            first_client,
            second_client,
        ])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = https_get();

        tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect("the first auto exchange speaks h2");
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );
        let _ = tokio::time::timeout(Duration::from_secs(10), first)
            .await
            .expect("the first origin finished within the guard");

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&req, VersionPolicy::H2),
        )
        .await
        .expect("the send finished within the guard")
        .expect_err("an h1-only origin refuses the forced h2 offer");
        assert!(is_h2_not_negotiated(&err), "error was {err}");
        assert_eq!(dialer.calls(), 2);
        let second_log = second.await.expect("second origin task");
        assert_eq!(second_log.alpn, vec!["h2".to_string()]);
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2),
            "a forced send's refusal never rewrites the Auto cache"
        );
    }

    /// Invalid TLS: a certificate the verifying sender rejects is a TLS error
    /// named after the host, never `h2_not_negotiated` — a probe that failed on
    /// trust must not be counted as a version-negotiation failure.
    #[tokio::test]
    async fn a_certificate_failure_is_not_classified_as_h2_not_negotiated() {
        let (client, server) = duplex(64 * 1024);
        let origin =
            tokio::spawn(async move { tls_h2_origin(server, &[b"h2", b"http/1.1"]).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        // No `with_insecure`: the self-signed `origin.test` leaf must be refused.
        let sender = HttpSender::new()
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&https_get(), VersionPolicy::H2),
        )
        .await
        .expect("the send finished within the guard")
        .expect_err("a self-signed leaf must fail verification");
        assert!(
            !is_h2_not_negotiated(&err),
            "a trust failure was classified as a version failure: {err}"
        );
        assert!(
            err.to_string().contains("TLS to origin.test"),
            "error was {err}"
        );
        assert_eq!(sender.negotiated_for("https", "origin.test:443"), None);
        drop(sender);
        let log = tokio::time::timeout(Duration::from_secs(10), origin)
            .await
            .expect("the origin finished within the guard")
            .expect("origin task");
        assert_eq!(log.alpn, vec!["h2".to_string()], "the ClientHello went out");
        assert!(
            log.request.is_empty(),
            "no request may reach an origin whose certificate failed"
        );
    }

    /// Malformed input: an empty authority is refused before any resolve or dial.
    #[tokio::test]
    async fn an_empty_authority_is_refused_before_dialing() {
        let dialer = Arc::new(DuplexDialer::new(VecDeque::new()));
        let sender = HttpSender::new()
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());
        let req = HttpRequest {
            authority: String::new(),
            ..https_get()
        };
        let err = sender
            .send(&req)
            .await
            .expect_err("an empty authority cannot be sent");
        assert!(err.to_string().contains("bad authority"), "error was {err}");
        assert!(!is_h2_not_negotiated(&err), "error was {err}");
        assert_eq!(dialer.calls(), 0);
    }

    /// The ALPN cache honours the TTL it was built with: once the entry has
    /// aged out, the next `Auto` send offers both protocols again instead of
    /// the remembered one (the default-TTL case is
    /// `the_second_send_offers_only_the_cached_protocol`).
    #[tokio::test]
    async fn an_expired_alpn_cache_entry_makes_the_next_send_offer_both_again() {
        let mut clients = VecDeque::new();
        let mut origins = Vec::new();
        for _ in 0..2 {
            let (client, server) = duplex(64 * 1024);
            clients.push_back(client);
            origins.push(tokio::spawn(async move {
                tls_origin(server, &[b"http/1.1"], RESPONSE_200).await
            }));
        }
        let dialer = Arc::new(DuplexDialer::new(clients));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone())
            .with_alpn_cache_ttl(Duration::from_millis(1));
        let req = https_get();

        let first = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the first send finished within the guard")
            .expect("the h1 origin answers");
        assert_eq!(first.status, 200);

        // Wait on the condition, not on a clock: the 1 ms entry the first send
        // wrote has to be gone before the second send, or it would be steered
        // by it.
        until(
            "the cache entry must age out with the configured TTL",
            || sender.negotiated_for("https", "origin.test:443").is_none(),
        )
        .await;

        let second = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the second send finished within the guard")
            .expect("the h1 origin answers again");
        assert_eq!(second.status, 200);
        assert_eq!(dialer.calls(), 2);

        let mut logs = Vec::new();
        for origin in origins {
            logs.push(origin.await.expect("origin task"));
        }
        assert_eq!(
            logs.iter().map(|l| l.alpn.clone()).collect::<Vec<_>>(),
            vec![
                vec!["h2".to_string(), "http/1.1".to_string()],
                vec!["h2".to_string(), "http/1.1".to_string()]
            ],
            "an expired entry must not narrow the second ClientHello"
        );
    }

    /// The ALPN cache is keyed by scheme as well as `host:port`: what
    /// `https://origin.test:443` settled on says nothing about
    /// `http://origin.test:443`, which never negotiates ALPN at all.
    #[tokio::test]
    async fn the_alpn_cache_is_keyed_by_scheme_as_well_as_host_port() {
        let (sender, _results, _logs, _dialer) =
            tls_sends(&[b"h2", b"http/1.1"], VersionPolicy::Auto, 1).await;
        assert_eq!(
            sender.negotiated_for("https", "origin.test:443"),
            Some(Negotiated::H2)
        );
        assert_eq!(
            sender.negotiated_for("http", "origin.test:443"),
            None,
            "a cleartext origin on the same host:port must not inherit the TLS negotiation"
        );
    }

    /// A plaintext h2 origin over one duplex half (prior-knowledge h2c): answer
    /// every stream `200` with `body`, until the client closes the connection.
    async fn plain_h2_origin(io: DuplexStream, body: &'static [u8]) {
        let Ok(mut conn) = h2::server::handshake(io).await else {
            return;
        };
        while let Some(Ok((_req, mut respond))) = conn.accept().await {
            if let Ok(resp) = http::Response::builder().status(200).body(()) {
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(bytes::Bytes::from_static(body), true);
                }
            }
        }
    }

    fn body_bytes(resp: &HttpResponse) -> Vec<u8> {
        match &resp.body {
            Body::Bytes(b) => b.clone(),
            Body::Empty => Vec::new(),
            other => panic!("body was {other:?}, want Bytes"),
        }
    }

    /// The h2 pool is keyed by scheme as well as `host:port`: a cleartext
    /// (`h2c`) connection to `origin.test:443` must never carry a later
    /// `https` send to the same host and port. Both origins answer a different
    /// body, so a reused connection is visible in the response, not only in the
    /// dial count.
    #[tokio::test]
    async fn an_h2c_connection_is_not_reused_for_a_tls_send_to_the_same_host_port() {
        let (cleartext_client, cleartext_server) = duplex(64 * 1024);
        let (tls_client, tls_server) = duplex(64 * 1024);
        let plain = tokio::spawn(plain_h2_origin(cleartext_server, b"plain"));
        let secure = tokio::spawn(async move { tls_h2_origin(tls_server, &[b"h2"]).await });
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([
            cleartext_client,
            tls_client,
        ])));
        let sender = HttpSender::new()
            .with_insecure(true)
            .with_resolver(Arc::new(FixedResolver))
            .with_dialer(dialer.clone());

        let cleartext_req = HttpRequest {
            scheme: "http".into(),
            ..https_get()
        };
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&cleartext_req, VersionPolicy::H2c),
        )
        .await
        .expect("the h2c send finished within the guard")
        .expect("the cleartext origin answers");
        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"plain".to_vec());
        assert_eq!(dialer.calls(), 1);

        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_with(&https_get(), VersionPolicy::H2),
        )
        .await
        .expect("the https send finished within the guard")
        .expect("the TLS origin answers on its own connection");
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_bytes(&resp),
            b"hi".to_vec(),
            "the https send was served by the pooled cleartext connection"
        );
        assert_eq!(
            dialer.calls(),
            2,
            "an https send must dial rather than reuse the h2c connection to the same host:port"
        );
        drop(sender);
        plain.abort();
        secure.abort();
    }

    /// Oversized input on the h1 path: a 17 MiB `Content-Length` body is
    /// truncated to the 16 MiB cap (D8.2 "response caps stay"), and the
    /// exchange still completes.
    #[tokio::test]
    async fn drive_caps_an_h1_body_at_16_mib() {
        let total = MAX_RESPONSE_BYTES + 1024 * 1024;
        let mut segment =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n").into_bytes();
        segment.resize(segment.len() + total, b'a');
        let (result, _) = exchange(get_x(), vec![segment]).await;
        let resp = result.expect("the capped exchange succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.buffered_len(), Some(MAX_RESPONSE_BYTES));
    }

    /// A resolver that answers every name with one chosen address.
    struct AnswerWith(IpAddr);

    impl HostResolver for AnswerWith {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            let ip = self.0;
            Box::pin(async move { Ok(vec![ip]) })
        }
    }

    /// `with_ssrf` on the plain reissue path, in process: with the gate
    /// configured and **nothing** in scope, a public name that answers the
    /// cloud metadata address is refused before the dialer is ever asked, and
    /// the refusal does not name the address it resolved to.
    ///
    /// The crate's integration cover for the reissue gate
    /// (`tests/sender.rs`) binds a real port, so the lift half of it cannot
    /// run in a sandbox; this pair runs over `tokio::io::duplex` (tester pass
    /// over fix round F2).
    /// A resolver that never answers.
    struct HangingResolver;

    impl HostResolver for HangingResolver {
        fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
            Box::pin(std::future::pending())
        }
    }

    /// SEC-12: the resolve is inside the exchange deadline. A name server
    /// that never answers fails the send at exactly `response_timeout`, and
    /// nothing is dialled. Virtual time; the outer guard turns a regression
    /// (a send that hangs) into a red test rather than a hung one.
    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_fails_the_send_within_the_response_timeout() {
        let dialer = Arc::new(DuplexDialer::new(VecDeque::new()));
        let timeout = Duration::from_secs(5);
        let sender = HttpSender::new()
            .with_resolver(Arc::new(HangingResolver))
            .with_dialer(dialer.clone())
            .with_response_timeout(timeout);

        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(timeout * 4, sender.send(&get_x()))
            .await
            .expect("the send must not outlive its response timeout")
            .expect_err("a resolve that never completes fails the send");

        assert_eq!(
            started.elapsed(),
            timeout,
            "bounded by exactly the deadline"
        );
        assert!(err.to_string().contains("timed out"), "error was {err}");
        assert!(
            err.to_string().contains("resolve"),
            "the error names the resolve, not the dial: {err}"
        );
        assert_eq!(dialer.calls(), 0, "nothing is dialled without an address");
    }

    #[tokio::test]
    async fn an_empty_scope_refuses_a_metadata_address_before_dialing() {
        use aitm_core::{SsrfPolicy, StdGuard};

        let dialer = Arc::new(DuplexDialer::new(VecDeque::new()));
        let sender = HttpSender::new()
            .with_resolver(Arc::new(AnswerWith(IpAddr::V4(Ipv4Addr::new(
                169, 254, 169, 254,
            )))))
            .with_dialer(dialer.clone())
            .with_ssrf(SsrfPolicy::default(), Arc::new(StdGuard::default()));

        let mut req = get_x();
        req.authority = "origin.test:80".into();

        let err = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect_err("an empty scope lifts nothing: the metadata address is refused");

        assert!(err.to_string().contains("SSRF"), "error was {err}");
        assert!(
            !err.to_string().contains("169.254.169.254"),
            "the refusal must not name the resolved address: {err}"
        );
        assert_eq!(dialer.calls(), 0, "a refused reissue never dials");
    }

    /// The other half: an operator who scoped the IP literal lifts the block,
    /// and the plain HTTP/1.1 reissue then runs to completion.
    #[tokio::test]
    async fn an_in_scope_ip_literal_lifts_the_reissue_ssrf_block() {
        use aitm_core::{ScopeEntry, ScopeRateGuard, SsrfPolicy, StdGuard};

        let (client, server) = duplex(64 * 1024);
        let origin = tokio::spawn(origin(
            server,
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()],
        ));
        let dialer = Arc::new(DuplexDialer::new(VecDeque::from([client])));
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "127.0.0.1".into(),
        });
        let sender = HttpSender::new()
            .with_resolver(Arc::new(AnswerWith(IpAddr::V4(Ipv4Addr::LOCALHOST))))
            .with_dialer(dialer.clone())
            .with_ssrf(SsrfPolicy::default(), guard.clone());

        let mut req = get_x();
        req.authority = "origin.test:80".into();

        let resp = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect("a scoped loopback literal passes the gate");

        assert_eq!(resp.status, 200);
        assert_eq!(body_bytes(&resp), b"hi".to_vec());
        assert_eq!(dialer.calls(), 1, "the gate let the dial through");
        let seen = String::from_utf8_lossy(&origin.await.expect("the origin task")).to_string();
        assert!(
            seen.contains("Host: origin.test:80\r\n"),
            "the reissue carried the requested authority: {seen:?}"
        );

        // Unscope the literal and the very same send is refused — so the
        // success above was the scope entry's doing, not an absent gate.
        assert!(guard.remove_scope("127.0.0.1"), "the entry was present");
        let err = tokio::time::timeout(Duration::from_secs(10), sender.send(&req))
            .await
            .expect("the send finished within the guard")
            .expect_err("with the literal unscoped the loopback answer is refused again");
        assert!(err.to_string().contains("SSRF"), "error was {err}");
        assert_eq!(dialer.calls(), 1, "a refused reissue never dials");
    }
}
