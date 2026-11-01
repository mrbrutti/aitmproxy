//! The protocol-module seam: what a module is and what it is handed.
//!
//! Defined in `aitm-core` and re-exported by `aitm-plugin` (accepted structuring
//! call): the acceptor (`aitm_core::Proxy`) registers `dyn ProtocolModule`, while
//! external authors import the seam from `aitm_plugin` — one definition, no cycle.
//!
//! `ModuleCtx` carries the core service handles a module uses without naming any
//! concrete acceptor type: a flow store, an event sink (the ordered plugin chain,
//! wired in Task 8), a guarded upstream connector, and — attached by the acceptor
//! and the capture ingress — the live scope guard a module consults before it
//! terminates TLS ([`ModuleCtx::in_scope`]; `false` for every authority when no
//! guard is attached, so a context nobody wired decrypts nothing).
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

use crate::authority::Authority;
use crate::event::{Event, Verdict};
use crate::flow::FlowId;
use crate::guard::ScopeRateGuard;
use crate::store::FlowStore;
use crate::stream::ByteStream;

/// The port a `CONNECT` authority or an explicit-proxy SNI defaults to (spec D1).
const DEFAULT_TLS_PORT: u16 = 443;

/// A protocol module: claims a connection, then drives it into flows/events.
pub trait ProtocolModule: Send + Sync {
    /// Stable id: `"http"`, `"ws"`, later `"l4"`.
    fn id(&self) -> &str;
    /// mitmproxy-style next-layer: does this module claim the connection?
    fn matches(&self, hint: &NextLayerHint) -> bool;
    /// Drive the connection: turn bytes into flows/events via a sans-IO machine.
    fn spawn(&self, io: ByteStream, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>>;
}

/// What is known about a connection before a module is chosen: the bytes and TLS
/// facts the acceptor peeks, and — from a capture backend — the client's attribution.
/// On an upgrade hand-off `from_upgrade` is `true` and `alpn` names the upgraded
/// protocol (`"websocket"`).
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
    /// The signing identifier of the process that opened the client connection, as
    /// a capture backend observed it. `None` on the explicit-proxy path; set by a
    /// capture ingress. Backend-supplied text about a client: carried as data, never
    /// a scope or guard input. Stored on the flow as `FlowMeta::source_app`.
    pub peer_identity: Option<String>,
    /// The capture backend that delivered the client connection (its interface
    /// name, `"macos-ne"`). `None` on the explicit-proxy path; set by a capture
    /// ingress.
    pub capture_interface: Option<String>,
}

impl NextLayerHint {
    /// The **tunnel authority** of this connection (spec D1): the one `host:port`
    /// every module decides Scope on, so the passthrough module and the HTTP
    /// module can never disagree about what a connection is for.
    ///
    /// - A `CONNECT <authority> ` request line in the peeked bytes wins; its port
    ///   defaults to 443. The authority must be terminated by a space inside the
    ///   peek — a line cut mid-authority is not trusted, nor is an empty one.
    /// - Else the ClientHello SNI, with `dst`'s port when the connection came from
    ///   a capture ingress (`capture_interface.is_some()`, whose `dst` is the
    ///   original destination) and 443 on the explicit-proxy path (whose `dst` is
    ///   the client's peer address, which says nothing about the destination).
    /// - `None` otherwise, and always `None` on an upgrade hand-off: that
    ///   continues a connection already decrypted upstream of this hint and is
    ///   not a tunnel of its own.
    ///
    /// Host and port are normalised by [`Authority::new`] (lowercase, IPv6
    /// brackets off), so `CONNECT Example.COM:8443` and `CONNECT [::1]:443`
    /// compare the way scope entries do.
    pub fn tunnel_authority(&self) -> Option<Authority> {
        if self.from_upgrade {
            return None;
        }
        if let Some(rest) = self.first_bytes.strip_prefix(b"CONNECT ") {
            let end = rest.iter().position(|b| *b == b' ')?;
            let authority = std::str::from_utf8(&rest[..end]).ok()?;
            return Authority::parse_with_default(authority, DEFAULT_TLS_PORT).ok();
        }
        let sni = self.client_hello_sni.as_deref()?;
        let port = if self.capture_interface.is_some() {
            self.dst.port()
        } else {
            DEFAULT_TLS_PORT
        };
        Some(Authority::new(sni, port))
    }
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
    /// The live scope guard, attached by the acceptor / capture ingress. `None`
    /// means nothing is in scope (deny-by-default).
    scope: Option<Arc<dyn ScopeRateGuard>>,
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
            scope: None,
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

    /// Attach the live scope guard (the proxy's own `StdGuard`, the one
    /// `scope.add` / `scope.remove` mutate) so [`in_scope`](Self::in_scope)
    /// answers against the current Scope. The acceptor and the capture ingress
    /// attach it to every context they build; without it a context reports
    /// nothing in scope.
    pub fn with_scope(mut self, guard: Arc<dyn ScopeRateGuard>) -> Self {
        self.scope = Some(guard);
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
            scope: self.scope.clone(),
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

    /// Whether `authority` (`host:port`, as [`Authority`] prints it) is in the live
    /// Scope — the predicate a module checks before it terminates TLS (spec D1/D2).
    /// **Deny-by-default:** `false` for every authority when no guard was attached,
    /// so a test or embedding that forgot [`with_scope`](Self::with_scope) decrypts
    /// nothing rather than everything. Read-only: no rate, concurrency or error
    /// budget effect.
    pub fn in_scope(&self, authority: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|guard| guard.in_scope(authority))
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
