//! Late-bound service handles for the scripting tier (M3 Task 15).
//!
//! The tier is built *before* the proxy: a script's host verbs
//! (`http.send`, `store.get`, `browser.navigate`, …) close over
//! [`ScriptServices`] when the shared engine is built, and the engine must
//! exist before any `.rhai` file can compile into a plugin the builder
//! registers. But the store, client and guard those verbs must use are
//! created by `Proxy::build`, and the browser driver only exists once the
//! engine launches — later still.
//!
//! [`LateHandles`] closes that gap the same way the tier's own `ErrorSink`
//! does: one object is handed out as every service handle up front and bound
//! to the real ones as they appear. Binding happens before the proxy serves a
//! byte, so a script never meets an unbound handle in practice; if one ever
//! did, the answers here are the safe ones — an empty store, a **denying**
//! guard, and an error from the client and the browser. A guard that is not
//! yet bound must refuse, never allow: deny-by-default is the authorization
//! mechanism (spec §7).
//!
//! Nothing here is a second path to the network. The handles forward to
//! exactly the proxy's own store, client and guard, so a script's request
//! rides the same scope/rate/SSRF checks a Rust plugin's does.

use std::sync::{Arc, OnceLock};

use aitm_core::{
    ActionPermit, BrowserDriver, ClearOutcome, ClickTarget, Flow, FlowId, FlowQuery, FlowStore,
    GuardError, HttpFlow, HttpRequest, NavOutcome, ProxyClient, ScopeEntry, ScopeRateGuard, Value,
};
use futures::future::BoxFuture;

/// The proxy's service handles, as seen by scripts before they exist.
#[derive(Default)]
pub struct LateHandles {
    store: OnceLock<Arc<dyn FlowStore>>,
    client: OnceLock<Arc<dyn ProxyClient>>,
    guard: OnceLock<Arc<dyn ScopeRateGuard>>,
    browser: OnceLock<Arc<dyn BrowserDriver>>,
}

impl LateHandles {
    /// A fresh, wholly unbound set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Bind the handles the built proxy owns. Call once, before serving.
    pub fn bind_proxy(
        &self,
        store: Arc<dyn FlowStore>,
        client: Arc<dyn ProxyClient>,
        guard: Arc<dyn ScopeRateGuard>,
    ) {
        let _ = self.store.set(store);
        let _ = self.client.set(client);
        let _ = self.guard.set(guard);
    }

    /// Bind the browser once the engine has launched. Without this call
    /// `browser.*` keeps erroring, which is what an operator running without a
    /// browser should see.
    pub fn bind_browser(&self, browser: Arc<dyn BrowserDriver>) {
        let _ = self.browser.set(browser);
    }

    fn driver(&self) -> Option<&Arc<dyn BrowserDriver>> {
        self.browser.get()
    }
}

impl FlowStore for LateHandles {
    fn insert(&self, flow: Flow) -> FlowId {
        match self.store.get() {
            Some(store) => store.insert(flow),
            // Unreachable once bound (binding precedes serving). Should it
            // ever happen, a flow would be lost: say so loudly rather than
            // mint an id as if it had been kept.
            None => {
                let id = flow.id();
                tracing::error!(
                    target: "aitm::scripts",
                    flow = %id,
                    "a flow was inserted before the script tier's store was bound; it is NOT stored"
                );
                id
            }
        }
    }

    fn get(&self, id: FlowId) -> Option<Flow> {
        self.store.get()?.get(id)
    }

    fn update(&self, id: FlowId, f: &mut dyn FnMut(&mut Flow)) {
        if let Some(store) = self.store.get() {
            store.update(id, f);
        }
    }

    fn list(&self) -> Vec<FlowId> {
        self.store.get().map(|s| s.list()).unwrap_or_default()
    }

    fn query(&self, q: &FlowQuery) -> Vec<FlowId> {
        self.store.get().map(|s| s.query(q)).unwrap_or_default()
    }

    fn clear(&self) -> ClearOutcome {
        self.store.get().map(|s| s.clear()).unwrap_or_default()
    }

    fn is_capturing(&self) -> bool {
        // Unbound defaults to capturing (the record toggle's default-on state).
        self.store.get().map(|s| s.is_capturing()).unwrap_or(true)
    }

    fn set_capturing(&self, on: bool) {
        if let Some(store) = self.store.get() {
            store.set_capturing(on);
        }
    }

    fn count(&self) -> usize {
        self.store.get().map(|s| s.count()).unwrap_or(0)
    }

    fn intercepted_count(&self) -> usize {
        self.store.get().map(|s| s.intercepted_count()).unwrap_or(0)
    }
}

impl ProxyClient for LateHandles {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        match self.client.get() {
            Some(client) => client.send(req),
            None => Box::pin(async { anyhow::bail!("the proxy is not running yet") }),
        }
    }
}

impl ScopeRateGuard for LateHandles {
    /// Unbound refuses: a guard that cannot check must not permit.
    fn check_active(&self, host: &str) -> Result<ActionPermit, GuardError> {
        match self.guard.get() {
            Some(guard) => guard.check_active(host),
            None => Err(GuardError::OutOfScope(host.to_string())),
        }
    }

    fn add_scope(&self, entry: ScopeEntry) {
        if let Some(guard) = self.guard.get() {
            guard.add_scope(entry);
        }
    }

    fn remove_scope(&self, entry: &str) -> bool {
        self.guard
            .get()
            .map(|g| g.remove_scope(entry))
            .unwrap_or(false)
    }

    fn list_scope(&self) -> Vec<ScopeEntry> {
        self.guard.get().map(|g| g.list_scope()).unwrap_or_default()
    }

    /// Forward to the bound guard; unbound keeps the trait's deny-by-default
    /// `false`. The capture ingress scope-gates captured streams on this, so the
    /// delegation must be complete before a live feeder routes through it.
    fn in_scope(&self, host: &str) -> bool {
        self.guard.get().map(|g| g.in_scope(host)).unwrap_or(false)
    }

    fn record_error(&self, host: &str) {
        if let Some(guard) = self.guard.get() {
            guard.record_error(host);
        }
    }
}

/// What every `browser.*` verb answers until an engine is attached.
fn no_browser<T>() -> BoxFuture<'static, anyhow::Result<T>>
where
    T: Send + 'static,
{
    Box::pin(async { anyhow::bail!("no browser engine is attached") })
}

impl BrowserDriver for LateHandles {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        match self.driver() {
            Some(d) => d.navigate(url),
            None => no_browser(),
        }
    }

    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        match self.driver() {
            Some(d) => d.click(target),
            None => no_browser(),
        }
    }

    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        match self.driver() {
            Some(d) => d.type_text(selector, text),
            None => no_browser(),
        }
    }

    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        match self.driver() {
            Some(d) => d.screenshot(),
            None => no_browser(),
        }
    }

    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        match self.driver() {
            Some(d) => d.eval(expr),
            None => no_browser(),
        }
    }

    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        match self.driver() {
            Some(d) => d.get_dom(),
            None => no_browser(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one safety property this facade must hold even if a script ran
    /// before binding: a guard that cannot check refuses, and nothing reads
    /// as present.
    #[tokio::test]
    async fn unbound_handles_refuse_and_read_as_empty() {
        let handles = LateHandles::new();
        assert!(matches!(
            handles.check_active("ex.test"),
            Err(GuardError::OutOfScope(host)) if host == "ex.test"
        ));
        assert!(handles.list_scope().is_empty());
        assert!(handles.list().is_empty());
        assert!(handles.get(FlowId::new()).is_none());
        let err = handles.navigate("http://ex.test/").await.unwrap_err();
        assert!(err.to_string().contains("no browser engine"), "{err}");
        let err = handles
            .send(HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "ex.test".into(),
                path: "/".into(),
                version: aitm_core::HttpVersion::Http11,
                headers: aitm_core::HeaderMap::new(),
                body: aitm_core::Body::Empty,
                timestamp: std::time::SystemTime::now(),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not running yet"), "{err}");
    }
}
