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
    GuardError, HttpFlow, HttpRequest, NavOutcome, ProxyClient, ScopeEntry, ScopeRateGuard,
    SendOptions, Value,
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

/// What both client verbs answer until the proxy binds its client.
fn not_running_yet() -> BoxFuture<'static, anyhow::Result<HttpFlow>> {
    Box::pin(async { anyhow::bail!("the proxy is not running yet") })
}

impl ProxyClient for LateHandles {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        match self.client.get() {
            Some(client) => client.send(req),
            None => not_running_yet(),
        }
    }

    /// Forward the options too: the trait default would drop them and call
    /// `send`, recording every probe a bulk sender asked not to keep.
    fn send_opts(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        match self.client.get() {
            Some(client) => client.send_opts(req, opts),
            None => not_running_yet(),
        }
    }

    /// Forward the probe path too (spec amendment 80): the trait default would
    /// route it to `send_opts` and quietly charge a probe's 5xx answers to the
    /// host's error budget again.
    fn send_probe(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        match self.client.get() {
            Some(client) => client.send_probe(req, opts),
            None => not_running_yet(),
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
        let err = handles.send(get_ex_test()).await.unwrap_err();
        assert!(err.to_string().contains("not running yet"), "{err}");
    }

    /// Always answers 200 without touching the network.
    struct OkSender;

    impl aitm_core::RequestSender for OkSender {
        fn send(
            &self,
            _req: &HttpRequest,
        ) -> BoxFuture<'_, anyhow::Result<aitm_core::HttpResponse>> {
            Box::pin(async {
                Ok(aitm_core::HttpResponse {
                    status: 200,
                    version: aitm_core::HttpVersion::Http11,
                    headers: aitm_core::HeaderMap::new(),
                    trailers: aitm_core::HeaderMap::new(),
                    body: aitm_core::Body::Empty,
                    timestamp: std::time::SystemTime::now(),
                    peer: None,
                })
            })
        }
    }

    fn get_ex_test() -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: "http".into(),
            authority: "ex.test".into(),
            path: "/".into(),
            version: aitm_core::HttpVersion::Http11,
            headers: aitm_core::HeaderMap::new(),
            body: aitm_core::Body::Empty,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Panel S2 — `send_opts` must reach the bound client with its options
    /// intact: a `record: Never` send leaves the store empty (a bulk sender's
    /// probes must not flood it), and an `Always` send's marks reach the
    /// stored flow. The trait default would silently record every send.
    #[tokio::test]
    async fn bound_handles_forward_send_opts() {
        use aitm_core::{
            MemFlowStore, PipelineClient, RecordPolicy, SendOptions, StdGuard, VersionPolicy,
        };

        let store = Arc::new(MemFlowStore::new());
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "ex.test".into(),
        });
        let client = Arc::new(PipelineClient::new(
            store.clone(),
            guard.clone(),
            Arc::new(OkSender),
        ));
        let handles = LateHandles::new();
        handles.bind_proxy(store.clone(), client, guard);

        let flow = handles
            .send_opts(
                get_ex_test(),
                SendOptions {
                    record: RecordPolicy::Never,
                    marks: vec!["scan:job1".into()],
                    version: VersionPolicy::Auto,
                },
            )
            .await
            .expect("bound send succeeds");
        assert!(flow.metadata.is_replay);
        assert_eq!(store.count(), 0, "record: Never must not store the flow");

        let flow = handles
            .send_opts(
                get_ex_test(),
                SendOptions {
                    record: RecordPolicy::Always,
                    marks: vec!["scan:job1".into(), "crawl".into()],
                    version: VersionPolicy::Auto,
                },
            )
            .await
            .expect("bound send succeeds");
        assert_eq!(store.count(), 1);
        match store.get(flow.id).expect("stored") {
            Flow::Http(stored) => assert_eq!(
                stored.metadata.marks,
                vec!["scan:job1".to_string(), "crawl".to_string()]
            ),
            _ => panic!("expected an HTTP flow"),
        }
    }

    /// Panel S2 — unbound, `send_opts` errors the same way `send` does rather
    /// than falling through to a default that pretends to send.
    #[tokio::test]
    async fn unbound_send_opts_errors_like_send() {
        let handles = LateHandles::new();
        let err = handles
            .send_opts(get_ex_test(), aitm_core::SendOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not running yet"), "{err}");
    }
}
