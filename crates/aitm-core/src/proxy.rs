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
use crate::guard::{ScopeRateGuard, StdGuard};
use crate::plugin::Plugin;
use crate::protocol::{ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector};
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

    /// Bind and run the main client-facing accept loop. Passive capture here is
    /// not SSRF-filtered (the operator controls the client); scope/rate apply to
    /// active reissue only.
    pub async fn run(&self, listen: SocketAddr) -> anyhow::Result<()> {
        self.accept_loop(listen, false).await
    }

    /// Bind and run the **browser-facing** accept loop. The embedded browser dials
    /// this listener (`--proxy-server`), and every upstream it opens — including
    /// redirects, `fetch`, sub-resources and `browser.eval` traffic — is
    /// SSRF-filtered: a private/loopback target is refused unless the host or IP
    /// is explicitly in scope.
    pub async fn run_browser(&self, listen: SocketAddr) -> anyhow::Result<()> {
        self.accept_loop(listen, true).await
    }

    async fn accept_loop(&self, listen: SocketAddr, ssrf: bool) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen).await?;
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
    let mut buf = [0u8; 64];
    let n = stream.peek(&mut buf).await.unwrap_or(0);
    let first = &buf[..n];
    let hint = NextLayerHint {
        dst: peer,
        is_tls: first.first() == Some(&0x16), // TLS handshake record
        client_hello_sni: None,
        alpn: Vec::new(),
        first_bytes: first.to_vec(),
        from_upgrade: false,
    };

    let Some(module) = inner.modules.iter().find(|m| m.matches(&hint)).cloned() else {
        tracing::debug!(%peer, "no protocol module claimed the connection");
        return Ok(());
    };

    let connector: Arc<dyn UpstreamConnector> = if ssrf {
        Arc::new(SsrfConnector {
            policy: inner.browser_ssrf.clone(),
            guard: inner.guard.clone(),
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
}

impl UpstreamConnector for SsrfConnector {
    fn connect(
        &self,
        authority: &str,
        dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        let authority = authority.to_string();
        Box::pin(async move {
            crate::guard::ssrf_check(&self.policy, &self.guard.list_scope(), &authority, dst.ip())?;
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

        Ok(Proxy {
            inner: Arc::new(ProxyInner {
                registry,
                store,
                guard,
                chain,
                modules: self.modules.into(),
                browser_ssrf,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::is_benign_disconnect;
    use std::io;

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
}
