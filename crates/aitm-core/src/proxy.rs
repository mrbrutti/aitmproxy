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

    /// The shared flow store (for assembling a `CommandHost`).
    pub fn store(&self) -> Arc<dyn FlowStore> {
        self.inner.store.clone()
    }

    /// The scope/rate guard (for assembling a `CommandHost`).
    pub fn guard(&self) -> Arc<dyn ScopeRateGuard> {
        self.inner.guard.clone()
    }

    /// Bind and run the accept loop until an unrecoverable error.
    pub async fn run(self, listen: SocketAddr) -> anyhow::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        let inner = self.inner;
        loop {
            let (stream, peer) = listener.accept().await?;
            let inner = inner.clone();
            tokio::spawn(async move {
                let _ = handle_conn(inner, stream, peer).await;
            });
        }
    }
}

/// Peek, pick a module, and drive it.
async fn handle_conn(
    inner: Arc<ProxyInner>,
    stream: TcpStream,
    peer: SocketAddr,
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
        return Ok(());
    };

    let connector: Arc<dyn UpstreamConnector> = Arc::new(GuardedConnector {
        guard: inner.guard.clone(),
    });
    let ctx = ModuleCtx::new(inner.store.clone(), inner.chain.clone(), connector)
        .with_modules(inner.modules.clone())
        .with_hint(hint);
    let io: ByteStream = Box::pin(stream);
    module.spawn(io, ctx).await
}

/// Opens upstream TCP streams after a scope/rate check.
struct GuardedConnector {
    guard: Arc<dyn ScopeRateGuard>,
}

impl UpstreamConnector for GuardedConnector {
    fn connect(&self, dst: SocketAddr) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        Box::pin(async move {
            let _permit = self.guard.check_active(&dst.ip().to_string())?;
            let stream = TcpStream::connect(dst).await?;
            let bs: ByteStream = Box::pin(stream);
            Ok(bs)
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
        let store: Arc<dyn FlowStore> = Arc::new(MemFlowStore::new());
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

        Ok(Proxy {
            inner: Arc::new(ProxyInner {
                registry,
                store,
                guard,
                chain,
                modules: self.modules.into(),
            }),
        })
    }
}
