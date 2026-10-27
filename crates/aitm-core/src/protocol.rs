//! The protocol-module seam: what a module is and what it is handed.
//!
//! Defined in `aitm-core` and re-exported by `aitm-plugin` (accepted structuring
//! call): the acceptor (`aitm_core::Proxy`) registers `dyn ProtocolModule`, while
//! external authors import the seam from `aitm_plugin` — one definition, no cycle.
//!
//! `ModuleCtx` carries the core service handles a module uses without naming any
//! concrete acceptor type: a flow store, an event sink (the ordered plugin chain,
//! wired in Task 8), and a guarded upstream connector.
//!
//! It also carries the **upgrade hand-off** (mitmproxy-style next-layer
//! re-dispatch): when a module finishes an HTTP upgrade it calls
//! [`ModuleCtx::handoff_upgrade`], and the module that claims the
//! `from_upgrade` hint is spawned with a child context holding the handshake
//! flow id and the already-open upstream stream ([`ModuleCtx::handshake`],
//! [`ModuleCtx::take_upstream`]).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;

use crate::event::{Event, Verdict};
use crate::flow::FlowId;
use crate::store::FlowStore;
use crate::stream::ByteStream;

/// A protocol module: claims a connection, then drives it into flows/events.
pub trait ProtocolModule: Send + Sync {
    /// Stable id: `"http"`, `"ws"`, later `"l4"`.
    fn id(&self) -> &str;
    /// mitmproxy-style next-layer: does this module claim the connection?
    fn matches(&self, hint: &NextLayerHint) -> bool;
    /// Drive the connection: turn bytes into flows/events via a sans-IO machine.
    fn spawn(&self, io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>>;
}

/// What the acceptor peeks before choosing a module. On an upgrade hand-off
/// `from_upgrade` is `true` and `alpn` names the upgraded protocol
/// (`"websocket"`).
#[derive(Debug, Clone)]
pub struct NextLayerHint {
    pub dst: SocketAddr,
    pub is_tls: bool,
    pub client_hello_sni: Option<String>,
    pub alpn: Vec<String>,
    /// Peeked bytes for protocol sniffing.
    pub first_bytes: Vec<u8>,
    /// `true` when handed off from an HTTP upgrade.
    pub from_upgrade: bool,
}

/// Dispatches an event through the ordered plugin chain. Implemented in Task 8 by
/// the chain; a module reaches it only through [`ModuleCtx::emit`].
pub trait EventSink: Send + Sync {
    fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict>;
}

/// Opens a guarded (scope/rate-checked) upstream byte stream. Implemented in
/// Task 8; a module reaches it only through [`ModuleCtx::connect_upstream`].
pub trait UpstreamConnector: Send + Sync {
    /// Open an upstream stream to `dst`. `authority` is the host[:port] the client
    /// asked for (so a connector can apply scope/SSRF policy on the name, not only
    /// the resolved address).
    fn connect(
        &self,
        authority: &str,
        dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>>;
}

/// Handles a module uses to emit flows/events and reach upstream — never the
/// concrete acceptor type, so the seam stays decoupled from the driver.
pub struct ModuleCtx {
    store: Arc<dyn FlowStore>,
    sink: Arc<dyn EventSink>,
    connector: Arc<dyn UpstreamConnector>,
    /// The registered modules, for upgrade re-dispatch.
    modules: Arc<[Arc<dyn ProtocolModule>]>,
    /// What the acceptor (or the handing-off module) peeked.
    hint: Option<NextLayerHint>,
    /// On an upgrade hand-off: the 101 handshake flow.
    handshake: Option<FlowId>,
    /// On an upgrade hand-off: the already-upgraded upstream stream, taken once.
    upstream: Mutex<Option<ByteStream>>,
}

impl ModuleCtx {
    /// Assemble a module context from the core service handles.
    pub fn new(
        store: Arc<dyn FlowStore>,
        sink: Arc<dyn EventSink>,
        connector: Arc<dyn UpstreamConnector>,
    ) -> Self {
        Self {
            store,
            sink,
            connector,
            modules: Vec::new().into(),
            hint: None,
            handshake: None,
            upstream: Mutex::new(None),
        }
    }

    /// Attach the registered modules so an upgrade can be re-dispatched.
    pub fn with_modules(mut self, modules: Arc<[Arc<dyn ProtocolModule>]>) -> Self {
        self.modules = modules;
        self
    }

    /// Attach what the acceptor peeked about this connection.
    pub fn with_hint(mut self, hint: NextLayerHint) -> Self {
        self.hint = Some(hint);
        self
    }

    /// A child context for the module taking over after an upgrade: same
    /// services, plus the handshake flow and the already-open upstream stream.
    pub fn for_upgrade(
        &self,
        handshake: FlowId,
        upstream: ByteStream,
        hint: NextLayerHint,
    ) -> ModuleCtx {
        ModuleCtx {
            store: self.store.clone(),
            sink: self.sink.clone(),
            connector: self.connector.clone(),
            modules: self.modules.clone(),
            hint: Some(hint),
            handshake: Some(handshake),
            upstream: Mutex::new(Some(upstream)),
        }
    }

    /// Hand an upgraded connection to the first registered module that claims
    /// `hint` (which must have `from_upgrade == true`), spawning it with the
    /// client stream and a child context carrying `handshake` and `upstream`.
    pub fn handoff_upgrade(
        &self,
        io: ByteStream,
        upstream: ByteStream,
        handshake: FlowId,
        hint: NextLayerHint,
    ) -> BoxFuture<'_, anyhow::Result<()>> {
        let protocol = hint.alpn.first().cloned().unwrap_or_default();
        let module = self.modules.iter().find(|m| m.matches(&hint)).cloned();
        let child = self.for_upgrade(handshake, upstream, hint);
        Box::pin(async move {
            let Some(module) = module else {
                anyhow::bail!("no protocol module claims the {protocol:?} upgrade");
            };
            module.spawn(io, child).await
        })
    }

    /// What was peeked about this connection, if the acceptor attached it.
    pub fn hint(&self) -> Option<&NextLayerHint> {
        self.hint.as_ref()
    }

    /// On an upgrade hand-off, the 101 handshake flow this connection continues.
    pub fn handshake(&self) -> Option<FlowId> {
        self.handshake
    }

    /// On an upgrade hand-off, the already-upgraded upstream stream. `None`
    /// once taken or when this is not a hand-off.
    pub fn take_upstream(&self) -> Option<ByteStream> {
        self.upstream.lock().ok().and_then(|mut slot| slot.take())
    }

    /// The shared flow store.
    pub fn store(&self) -> &dyn FlowStore {
        self.store.as_ref()
    }

    /// Dispatch an event through the ordered plugin chain (may mutate/halt/intercept).
    pub fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
        self.sink.emit(ev)
    }

    /// Open an upstream byte stream through the connection's connector. `authority`
    /// is the requested host[:port]; the connector decides policy (the passive
    /// connector relays freely; the browser connector enforces SSRF).
    pub fn connect_upstream(
        &self,
        authority: &str,
        dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        self.connector.connect(authority, dst)
    }
}
