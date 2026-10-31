//! The proxy acceptor: binds a listener, peeks each connection to choose a
//! protocol module, and drives it with a `ModuleCtx` wired to the chain and a
//! guarded upstream connector. Per-protocol detail (TLS MITM, CONNECT, HTTP) lives
//! in the modules; the acceptor only does next-layer selection.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::{TcpListener, TcpStream};

use crate::chain::Chain;
use crate::config::Config;
use crate::egress::EgressConfinement;
use crate::guard::{ScopeRateGuard, StdGuard};
use crate::plugin::Plugin;
use crate::protocol::{EventSink, ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector};
use crate::registry::Registry;
use crate::store::{FlowStore, MemFlowStore};
use crate::stream::ByteStream;

/// The running proxy: owns the accept loop, the store, the chain, and the registry.
pub struct Proxy {
    inner: Arc<ProxyInner>,
}

struct ProxyInner {
    registry: Arc<Registry>,
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    chain: Arc<Chain>,
    modules: Arc<[Arc<dyn ProtocolModule>]>,
    /// SSRF posture enforced on the browser-facing listener.
    browser_ssrf: crate::config::SsrfPolicy,
    /// Runtime egress-confinement posture for the browser-facing listener
    /// (scanner finding S2); shared with the command/host wiring.
    egress: Arc<EgressConfinement>,
}

impl Proxy {
    /// Start building a proxy.
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder::default()
    }

    /// The command registry (for frontends to enumerate/invoke commands).
    pub fn registry(&self) -> &Registry {
        &self.inner.registry
    }

    /// The command registry as a shared handle. Frontends (`McpServer::new`,
    /// `Cli::new`) take `Arc<Registry>`; this hands them the *same* registry the
    /// chain dispatches through, so a command invoked over MCP/CLI and an event
    /// handled on the wire see one plugin set.
    pub fn registry_arc(&self) -> Arc<Registry> {
        self.inner.registry.clone()
    }

    /// The shared flow store (for assembling a `CommandHost`).
    pub fn store(&self) -> Arc<dyn FlowStore> {
        self.inner.store.clone()
    }

    /// The scope/rate guard (for assembling a `CommandHost`).
    pub fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        self.inner.guard.clone()
    }

    /// The browser-egress confinement posture (for the command/host wiring and
    /// the scanner's campaign token). Shared with every [`SsrfConnector`] the
    /// proxy builds, so a toggle here is seen by the next upstream dial.
    pub fn egress(&self) -> Arc<EgressConfinement> {
        self.inner.egress.clone()
    }

    /// The registered protocol modules, shared. The capture ingress dispatches a
    /// captured stream through the **same** ordered module list the acceptor uses,
    /// so a captured HTTP/TLS/WS flow is claimed exactly as a proxied one is.
    pub fn modules(&self) -> Arc<[Arc<dyn ProtocolModule>]> {
        self.inner.modules.clone()
    }

    /// The event sink (the ordered plugin chain), shared. A dispatched capture
    /// flow emits through the **same** chain the acceptor drives — no parallel
    /// plugin path.
    pub fn event_sink(&self) -> Arc<dyn EventSink> {
        self.inner.chain.clone()
    }

    /// A guarded upstream connector, built exactly as [`handle_conn`] builds it:
    /// the SSRF/scope-checked [`SsrfConnector`] when `ssrf`, else the
    /// [`PassiveConnector`]. This only shares the existing construction — it adds
    /// no new, unguarded dial path (a private/loopback target still needs scope).
    pub fn upstream_connector(&self, ssrf: bool) -> Arc<dyn UpstreamConnector> {
        if ssrf {
            Arc::new(SsrfConnector {
                policy: self.inner.browser_ssrf.clone(),
                guard: self.inner.guard.clone(),
                egress: self.inner.egress.clone(),
            })
        } else {
            Arc::new(PassiveConnector)
        }
    }

    /// Bind and run the main client-facing accept loop. Passive capture here is
    /// not SSRF-filtered (the operator controls the client); scope/rate apply to
    /// active reissue only.
    pub async fn run(&self, listen: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        self.accept_loop(listener, false).await
    }

    /// Bind and run the **browser-facing** accept loop. The embedded browser dials
    /// this listener (`--proxy-server`), and every upstream it opens — including
    /// redirects, `fetch`, sub-resources and `browser.eval` traffic — is
    /// SSRF-filtered: a private/loopback target is refused unless the host or IP
    /// is explicitly in scope.
    pub async fn run_browser(&self, listen: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        self.accept_loop(listener, true).await
    }

    /// Run the main client-facing accept loop on an **already-bound** listener.
    /// `aitm` pre-binds every service port at startup so a port conflict is one
    /// clear error before any "listening" success, never a cryptic os-error
    /// after it; this hands the pre-bound socket straight to the accept loop.
    /// Mirrors [`Proxy::run`] (not SSRF-filtered).
    pub async fn run_on(&self, listener: TcpListener) -> anyhow::Result<()> {
        self.accept_loop(listener, false).await
    }

    /// Run the **browser-facing** accept loop on an already-bound listener.
    /// Mirrors [`Proxy::run_browser`] (SSRF-filtered); the named pair keeps the
    /// SSRF posture at the call site instead of a transposable bool.
    pub async fn run_browser_on(&self, listener: TcpListener) -> anyhow::Result<()> {
        self.accept_loop(listener, true).await
    }

    async fn accept_loop(&self, listener: TcpListener, ssrf: bool) -> anyhow::Result<()> {
        let listen = listener.local_addr()?;
        tracing::info!(%listen, ssrf, "proxy listening");
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            };
            let inner = self.inner.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(inner, stream, peer, ssrf).await {
                    if is_benign_disconnect(&e) {
                        tracing::debug!(%peer, error = %e, "connection closed before completion");
                    } else {
                        tracing::warn!(%peer, error = %e, "connection handler ended with an error");
                    }
                }
            });
        }
    }
}

/// Classify a connection-handler error as a benign, expected client-side
/// disconnect (log at `debug`) rather than a genuine failure (log at `warn`).
///
/// A browser or client that aborts a TLS handshake, resets, or closes before a
/// request would otherwise spam one `warn` per connection. We demote only a
/// named set, identified by **type** — never by matching message substrings:
///
/// - `io::ErrorKind::{ConnectionReset, BrokenPipe, UnexpectedEof}` anywhere in
///   the chain (peer resets, broken pipes, and EOF-before-a-request; the TLS
///   layer also reports a mid-handshake EOF as `UnexpectedEof`).
/// - A received TLS alert (`rustls::Error::AlertReceived`), e.g. the client does
///   not trust our CA and aborts the handshake. The TLS layer wraps this in an
///   `InvalidData` io::Error, so we look through the io::Error at its source too.
fn is_benign_disconnect(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if is_benign_io_kind(io.kind()) {
                return true;
            }
            if let Some(src) = io.get_ref() {
                if src
                    .downcast_ref::<rustls::Error>()
                    .is_some_and(is_client_abort)
                {
                    return true;
                }
            }
        }
        cause
            .downcast_ref::<rustls::Error>()
            .is_some_and(is_client_abort)
    })
}

/// The `io::ErrorKind`s that mean "the peer went away", not "we failed".
fn is_benign_io_kind(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// A TLS error the *client* initiated by aborting the handshake — currently a
/// received fatal alert (e.g. it rejected our impersonating leaf). Internal TLS
/// failures are **not** demoted.
fn is_client_abort(err: &rustls::Error) -> bool {
    matches!(err, rustls::Error::AlertReceived(_))
}

/// Peek, pick a module, and drive it. `ssrf` selects the browser-facing SSRF
/// connector over the passive one.
async fn handle_conn(
    inner: Arc<ProxyInner>,
    stream: TcpStream,
    peer: SocketAddr,
    ssrf: bool,
) -> anyhow::Result<()> {
    // Peek enough to carry a TLS ClientHello whole (so its SNI can pick a
    // passthrough module) as well as an HTTP/CONNECT request line. The bytes stay
    // in the stream — the module the acceptor picks re-reads them.
    let mut buf = [0u8; 2048];
    let n = stream.peek(&mut buf).await.unwrap_or(0);
    let first = &buf[..n];
    let is_tls = first.first() == Some(&0x16); // TLS handshake record
    let hint = NextLayerHint {
        dst: peer,
        is_tls,
        // Extract the ClientHello SNI so a passthrough module matches a pinned host
        // when the client speaks TLS directly (no CONNECT authority to key on).
        // Best-effort: if the full ClientHello has not arrived in the peek, SNI
        // stays `None` and the connection is MITM'd as before.
        client_hello_sni: if is_tls {
            parse_client_hello_sni(first)
        } else {
            None
        },
        alpn: Vec::new(),
        first_bytes: first.to_vec(),
        from_upgrade: false,
        // The explicit-proxy path knows nothing about the client process or a
        // capture backend: both stay `None` so a proxied flow reports null.
        peer_identity: None,
        capture_interface: None,
    };

    let Some(module) = inner.modules.iter().find(|m| m.matches(&hint)).cloned() else {
        tracing::debug!(%peer, "no protocol module claimed the connection");
        return Ok(());
    };

    let connector: Arc<dyn UpstreamConnector> = if ssrf {
        Arc::new(SsrfConnector {
            policy: inner.browser_ssrf.clone(),
            guard: inner.guard.clone(),
            egress: inner.egress.clone(),
        })
    } else {
        Arc::new(PassiveConnector)
    };
    let ctx = ModuleCtx::new(inner.store.clone(), inner.chain.clone(), connector)
        .with_modules(inner.modules.clone())
        .with_hint(hint);
    let io: ByteStream = Box::pin(stream);
    module.spawn(io, ctx).await
}

/// Best-effort SNI extraction from a peeked TLS ClientHello.
///
/// Returns the `host_name` carried in the ClientHello's `server_name` (SNI)
/// extension, or `None` when `buf` is not a ClientHello, the extension is absent,
/// or the record is not wholly present in the peeked prefix. Every index is
/// bounds-checked through `get`/`?`, so a truncated or malformed hello yields
/// `None`, never a panic — this runs on attacker-controlled bytes. No TLS library
/// is pulled into `aitm-core`; this is a read-only walk of the handshake layout
/// (RFC 8446 §4.1.2, RFC 6066 §3), not a TLS implementation.
fn parse_client_hello_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
    if buf.first() != Some(&0x16) {
        return None;
    }
    let rec = buf.get(5..)?;
    // Handshake header: msg_type(1)=0x01 ClientHello, length(3).
    if rec.first() != Some(&0x01) {
        return None;
    }
    // Skip handshake type(1) + length(3), then client_version(2) + random(32).
    let mut p = rec.get(4 + 34..)?;
    // session_id: length(1) + id.
    let sid_len = *p.first()? as usize;
    p = p.get(1 + sid_len..)?;
    // cipher_suites: length(2) + suites.
    let cs_len = u16::from_be_bytes([*p.first()?, *p.get(1)?]) as usize;
    p = p.get(2 + cs_len..)?;
    // compression_methods: length(1) + methods.
    let cm_len = *p.first()? as usize;
    p = p.get(1 + cm_len..)?;
    // extensions: length(2) + extensions block.
    let ext_total = u16::from_be_bytes([*p.first()?, *p.get(1)?]) as usize;
    let mut ext = p.get(2..2 + ext_total)?;
    while ext.len() >= 4 {
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let body = ext.get(4..4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name extension: server_name_list length(2), then entries of
            // name_type(1) + name_length(2) + name. host_name is type 0x00.
            let list = body.get(2..)?;
            let name_type = *list.first()?;
            let name_len = u16::from_be_bytes([*list.get(1)?, *list.get(2)?]) as usize;
            let name = list.get(3..3 + name_len)?;
            if name_type == 0x00 {
                return std::str::from_utf8(name).ok().map(str::to_string);
            }
            return None;
        }
        ext = ext.get(4 + ext_len..)?;
    }
    None
}

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn dial(dst: SocketAddr) -> anyhow::Result<ByteStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(dst))
        .await
        .map_err(|_| anyhow::anyhow!("upstream connect to {dst} timed out"))??;
    Ok(Box::pin(stream))
}

/// Opens upstream TCP streams for **passive** proxied traffic. Passive capture
/// is not gated by the scope allowlist (an intercepting proxy must relay what
/// the client sends) and does not consume the active-action rate budget — scope
/// and rate are enforced only on active reissue (`flow.replay`, `request.send`,
/// `browser.navigate`, `poc.run`) by the command handlers / `PipelineClient`.
struct PassiveConnector;

impl UpstreamConnector for PassiveConnector {
    fn connect(
        &self,
        _authority: &str,
        dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        Box::pin(dial(dst))
    }
}

/// Opens upstream streams for the browser-facing listener, refusing a
/// private/loopback target unless it is explicitly in scope (SSRF).
struct SsrfConnector {
    policy: crate::config::SsrfPolicy,
    guard: Arc<dyn ScopeRateGuard>,
    /// Live confinement posture: when `confined()`, an out-of-scope PUBLIC host
    /// is refused too (scanner finding S2). Read per dial, so a toggle applies to
    /// the next connection without rebuilding the connector.
    egress: Arc<EgressConfinement>,
}

impl UpstreamConnector for SsrfConnector {
    fn connect(
        &self,
        authority: &str,
        dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        let authority = authority.to_string();
        Box::pin(async move {
            crate::guard::ssrf_check(
                &self.policy,
                &self.guard.list_scope(),
                self.egress.confined(),
                &authority,
                dst.ip(),
            )?;
            dial(dst).await
        })
    }
}

/// Staged registrations + config for a [`Proxy`].
#[derive(Default)]
pub struct ProxyBuilder {
    config: Option<Config>,
    modules: Vec<Arc<dyn ProtocolModule>>,
    plugins: Vec<Box<dyn Plugin>>,
}

impl ProxyBuilder {
    /// Set the configuration (scope, limits, …).
    pub fn with_config(mut self, cfg: Config) -> Self {
        self.config = Some(cfg);
        self
    }

    /// Register a protocol module (ordered; first match claims a connection).
    pub fn register_module(mut self, m: Arc<dyn ProtocolModule>) -> Self {
        self.modules.push(m);
        self
    }

    /// Register a plugin into the ordered chain.
    pub fn register_plugin(mut self, p: Box<dyn Plugin>) -> Self {
        self.plugins.push(p);
        self
    }

    /// Assemble the proxy: build the store, the guard (seeded from config scope),
    /// the registry (running each plugin's `load`), and the chain.
    pub fn build(self) -> anyhow::Result<Proxy> {
        let config = self.config.unwrap_or_default();
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::with_limits(
            config.max_flows,
            config.max_flow_bytes,
        ));
        let guard: Arc<dyn ScopeRateGuard> = Arc::new(StdGuard::new(config.limits.clone()));
        for entry in &config.scope.entries {
            guard.add_scope(entry.clone());
        }

        let mut registry = Registry::new();
        for plugin in self.plugins {
            registry.add_plugin(plugin);
        }
        let registry = Arc::new(registry);
        let chain = Arc::new(Chain::new(registry.clone(), store.clone()));
        let browser_ssrf = config.browser.ssrf.clone();
        let egress = Arc::new(EgressConfinement::new(
            config.browser.confine_egress_to_scope,
        ));

        Ok(Proxy {
            inner: Arc::new(ProxyInner {
                registry,
                store,
                guard,
                chain,
                modules: self.modules.into(),
                browser_ssrf,
                egress,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{is_benign_disconnect, parse_client_hello_sni, Proxy};
    use crate::config::Config;
    use crate::error::GuardError;
    use crate::protocol::{ModuleCtx, NextLayerHint, ProtocolModule};
    use crate::stream::ByteStream;
    use futures::future::BoxFuture;
    use std::io;
    use std::sync::Arc;

    /// A no-op protocol module that claims nothing — enough to assert the proxy
    /// exposes its registered module list, event sink, and a guarded connector.
    struct StubModule;

    impl ProtocolModule for StubModule {
        fn id(&self) -> &str {
            "stub"
        }
        fn matches(&self, _hint: &NextLayerHint) -> bool {
            false
        }
        fn spawn(&self, _io: ByteStream, _ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn proxy_exposes_stream_dispatch_wiring() {
        let proxy = Proxy::builder()
            .with_config(Config::default())
            .register_module(Arc::new(StubModule))
            .build()
            .expect("build proxy");
        assert_eq!(
            proxy.modules().len(),
            1,
            "the one registered module is exposed to the ingress"
        );
        // The sink and a guarded connector construct without panicking.
        let _sink = proxy.event_sink();
        let _conn = proxy.upstream_connector(true);
    }

    #[tokio::test]
    async fn upstream_connector_true_is_ssrf_guarded() {
        // Empty scope + default SSRF policy (block_private = true): a private,
        // out-of-scope target is refused before any dial — no network reached.
        let proxy = Proxy::builder()
            .with_config(Config::default())
            .build()
            .expect("build proxy");
        let result = proxy
            .upstream_connector(true)
            .connect("10.1.2.3", "10.1.2.3:80".parse().unwrap())
            .await;
        assert!(
            result.is_err(),
            "a private, out-of-scope target must be refused by the SSRF-guarded connector"
        );
    }

    #[tokio::test]
    async fn confined_connector_refuses_out_of_scope_public() {
        // Empty scope. With the runtime posture confined, an out-of-scope PUBLIC
        // host is refused before any dial (scanner finding S2). Turning the
        // posture back off leaves the private default untouched.
        let proxy = Proxy::builder()
            .with_config(Config::default())
            .build()
            .expect("build proxy");
        let e = proxy.egress();
        assert!(!e.confined(), "Config::default() seeds the free posture");

        // Assert on the guard's own error, not just `is_err()`: a failed dial
        // (e.g. no network in a sandbox) is also an `Err`, and must not be
        // mistaken for the connector refusing the host before dialing.
        e.set_base(true);
        let public = proxy
            .upstream_connector(true)
            .connect("93.184.216.34", "93.184.216.34:80".parse().unwrap())
            .await
            .err()
            .expect("confined posture must refuse an out-of-scope public host");
        assert!(
            matches!(
                public.downcast_ref::<GuardError>(),
                Some(GuardError::OutOfScope(h)) if h == "93.184.216.34"
            ),
            "expected GuardError::OutOfScope before any dial, got: {public:?}"
        );

        e.set_base(false);
        let private = proxy
            .upstream_connector(true)
            .connect("10.1.2.3", "10.1.2.3:80".parse().unwrap())
            .await
            .err()
            .expect("a private, out-of-scope target must still be refused");
        assert!(
            matches!(
                private.downcast_ref::<GuardError>(),
                Some(GuardError::PrivateAddressBlocked(h)) if h == "10.1.2.3"
            ),
            "the private default is unaffected by confinement being off, got: {private:?}"
        );
    }

    /// A `std::io::Error` of the given kind, wrapped in an `anyhow` context the
    /// same way the handler does — the classifier must see through the context.
    fn io_err(kind: io::ErrorKind) -> anyhow::Error {
        anyhow::Error::new(io::Error::new(kind, "peer went away")).context("driving the connection")
    }

    #[test]
    fn benign_disconnects_are_debug_real_errors_warn() {
        // Client-side disconnects / resets / EOF-before-a-request: all benign.
        assert!(is_benign_disconnect(&io_err(
            io::ErrorKind::ConnectionReset
        )));
        assert!(is_benign_disconnect(&io_err(io::ErrorKind::BrokenPipe)));
        assert!(is_benign_disconnect(&io_err(io::ErrorKind::UnexpectedEof)));

        // A client that aborts the TLS handshake with an alert (e.g. it does not
        // trust our CA): the TLS layer wraps `rustls::Error` in an InvalidData
        // io::Error, exactly as `tokio_rustls` does. Benign, by type not message.
        let tls_alert = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::CertificateUnknown),
        );
        let tls_err = anyhow::Error::new(tls_alert).context("client TLS handshake");
        assert!(is_benign_disconnect(&tls_err));

        // A genuine handler failure stays at warn.
        let parse_err = anyhow::Error::new(crate::FlowError::Protocol("bad request line".into()))
            .context("serving HTTP");
        assert!(!is_benign_disconnect(&parse_err));

        // An unexpected io failure is *not* blanket-demoted: only the named
        // disconnect kinds are benign, so e.g. a permission error still warns.
        assert!(!is_benign_disconnect(&io_err(
            io::ErrorKind::PermissionDenied
        )));

        // A TLS error that is not a client abort (a message we produced) warns.
        let tls_internal = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::General("internal state".into()),
        );
        let tls_internal = anyhow::Error::new(tls_internal).context("client TLS handshake");
        assert!(!is_benign_disconnect(&tls_internal));
    }

    /// A minimal but well-formed TLS ClientHello carrying one SNI `host_name`.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni_entry = vec![0x00]; // name_type = host_name
        sni_entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(name);
        let mut sni_body = (sni_entry.len() as u16).to_be_bytes().to_vec(); // list length
        sni_body.extend_from_slice(&sni_entry);
        let mut ext = 0x0000u16.to_be_bytes().to_vec(); // server_name extension
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);
        let mut extensions = (ext.len() as u16).to_be_bytes().to_vec();
        extensions.extend_from_slice(&ext);

        let mut body = vec![0x03, 0x03]; // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&extensions);

        let mut hs = vec![0x01]; // ClientHello
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01]; // handshake record, version TLS 1.0
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_from_client_hello() {
        let hello = client_hello_with_sni("pinned.example");
        assert_eq!(
            parse_client_hello_sni(&hello).as_deref(),
            Some("pinned.example")
        );
    }

    #[test]
    fn truncated_client_hello_yields_none_not_panic() {
        let hello = client_hello_with_sni("pinned.example");
        for cut in [0, 1, 5, 10, 20, hello.len() / 2, hello.len() - 1] {
            assert_eq!(parse_client_hello_sni(&hello[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn non_tls_bytes_yield_none() {
        assert_eq!(parse_client_hello_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_client_hello_sni(b""), None);
    }
}
