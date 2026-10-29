//! The `PocStepHandler` registry the runner dispatches a [`Step::Protocol`] to.
//!
//! Mirrors the `ScriptStepExecutor` seam: a protocol's handler is injected into
//! the runner (by the binary, or a test), and a `Step::Protocol { ns, .. }` is
//! routed to the handler whose [`PocStepHandler::ns`] matches. A namespace with
//! no registered handler is a clear run-time error, never a silent skip.
//!
//! [`Step::Protocol`]: crate::model::Step::Protocol

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use aitm_plugin::language::PocStepHandler;

/// A namespace → `PocStepHandler` map. Registering a second handler for the same
/// namespace replaces the first (last-wins is acceptable here because handlers
/// are injected by trusted assembly code, not by untrusted PoC input; the
/// untrusted axis — an *unregistered* namespace — is the run-time error).
#[derive(Clone, Default)]
pub struct PocStepRegistry {
    handlers: BTreeMap<String, Arc<dyn PocStepHandler>>,
}

impl PocStepRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `handler` under its own [`PocStepHandler::ns`].
    pub fn register(&mut self, handler: Arc<dyn PocStepHandler>) {
        self.handlers.insert(handler.ns().to_string(), handler);
    }

    /// The handler for `ns`, if one is registered.
    pub fn get(&self, ns: &str) -> Option<&Arc<dyn PocStepHandler>> {
        self.handlers.get(ns)
    }

    /// Whether any handler is registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// The registered namespaces, sorted (for diagnostics).
    pub fn namespaces(&self) -> Vec<&str> {
        self.handlers.keys().map(String::as_str).collect()
    }
}

// Manual: `dyn PocStepHandler` is not `Debug`, so report the namespaces only.
impl fmt::Debug for PocStepRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PocStepRegistry")
            .field("namespaces", &self.namespaces())
            .finish()
    }
}
