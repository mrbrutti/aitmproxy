//! The protocol-module seam: what a module is and what it is handed.
//!
//! Defined in `aitm-core` and re-exported by `aitm-plugin` (accepted structuring
//! call): the acceptor (`aitm_core::Proxy`) registers `dyn ProtocolModule`, while
//! external authors import the seam from `aitm_plugin` — one definition, no cycle.
//!
//! `ModuleCtx` carries the core service handles a module uses without naming any
//! concrete acceptor type: a flow store, an event sink (the ordered plugin chain,
//! wired in Task 8), and a guarded upstream connector.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::future::BoxFuture;

use crate::event::{Event, Verdict};
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

/// What the acceptor peeks before choosing a module.
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
    fn connect(&self, dst: SocketAddr) -> BoxFuture<'_, anyhow::Result<ByteStream>>;
}

/// Handles a module uses to emit flows/events and reach upstream — never the
/// concrete acceptor type, so the seam stays decoupled from the driver.
pub struct ModuleCtx {
    store: Arc<dyn FlowStore>,
    sink: Arc<dyn EventSink>,
    connector: Arc<dyn UpstreamConnector>,
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
        }
    }

    /// The shared flow store.
    pub fn store(&self) -> &dyn FlowStore {
        self.store.as_ref()
    }

    /// Dispatch an event through the ordered plugin chain (may mutate/halt/intercept).
    pub fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
        self.sink.emit(ev)
    }

    /// Open a guarded upstream byte stream (scope/rate checked).
    pub fn connect_upstream(&self, dst: SocketAddr) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        self.connector.connect(dst)
    }
}
