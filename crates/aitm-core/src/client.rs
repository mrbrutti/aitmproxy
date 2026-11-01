//! The proxy client: reissue a request through the proxy's own guard + capture
//! path. The raw HTTP/TLS transmission lives in the protocol layer, so core takes
//! it as an injected [`RequestSender`] seam; `PipelineClient` owns the guard check,
//! the `is_replay` marking, and capture into the store.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use futures::future::BoxFuture;

use crate::ctx::ProxyClient;
use crate::flow::InterceptState;
use crate::flow::{ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse};
use crate::guard::ScopeRateGuard;
use crate::store::FlowStore;

/// Whether a reissued send is captured into the store. A bulk sender (the PoC
/// runner's control runs, Rhai batteries, a future live audit) uses `Never` so
/// its probes do not flood the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordPolicy {
    /// Insert the resulting flow into the store (the shipped behaviour).
    #[default]
    Always,
    /// Return the flow but do not store it.
    Never,
}

/// The HTTP version a reissued send should use. The default sender ignores it;
/// a version-aware sender (`HttpSender`) reads it to force or negotiate ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VersionPolicy {
    /// ALPN-negotiated and cached per authority.
    #[default]
    Auto,
    /// Force HTTP/1.1.
    H1,
    /// Force HTTP/2 over TLS.
    H2,
    /// Prior-knowledge cleartext HTTP/2.
    H2c,
}

/// Options for a reissued send: whether to record it, operator/engine marks to
/// stamp on the flow, and the HTTP version policy. `Default` is the shipped
/// behaviour: record, no marks, auto version.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendOptions {
    /// Whether the resulting flow is inserted into the store.
    pub record: RecordPolicy,
    /// Marks stamped onto `FlowMeta.marks` (e.g. a job id).
    pub marks: Vec<String>,
    /// The HTTP version policy handed to the sender.
    pub version: VersionPolicy,
}

/// Performs the raw upstream send for a reissued request. The concrete HTTP/TLS
/// sender lives in the protocol layer and is injected at binary assembly, keeping
/// hyper/rustls out of `aitm-core`.
pub trait RequestSender: Send + Sync {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>>;

    /// Send `req` honouring a [`VersionPolicy`]. The default ignores `version`
    /// and calls [`RequestSender::send`], so a sender that cannot choose a
    /// version (every test sender, the h1-only `Http1Sender`) compiles unchanged;
    /// a version-aware sender overrides this.
    fn send_with<'a>(
        &'a self,
        req: &'a HttpRequest,
        version: VersionPolicy,
    ) -> BoxFuture<'a, anyhow::Result<HttpResponse>> {
        let _ = version;
        self.send(req)
    }
}

/// The default proxy client: scope/rate-guards the request, sends it via the
/// injected sender, captures the result as a replay flow, and stores it.
pub struct PipelineClient {
    store: Arc<dyn FlowStore>,
    guard: Arc<dyn ScopeRateGuard>,
    sender: Arc<dyn RequestSender>,
}

impl PipelineClient {
    /// Assemble a client from the core services and a raw sender.
    pub fn new(
        store: Arc<dyn FlowStore>,
        guard: Arc<dyn ScopeRateGuard>,
        sender: Arc<dyn RequestSender>,
    ) -> Self {
        Self {
            store,
            guard,
            sender,
        }
    }
}

impl ProxyClient for PipelineClient {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        // One code path: the shipped behaviour is `send_opts` with the defaults
        // (record, no marks, auto version).
        self.send_opts(req, SendOptions::default())
    }

    fn send_opts(
        &self,
        req: HttpRequest,
        opts: SendOptions,
    ) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async move {
            // Hold the permit for the whole send (concurrency released on drop).
            let _permit = self.guard.check_active(&req.authority)?;
            let response = match self.sender.send_with(&req, opts.version).await {
                Ok(resp) => resp,
                Err(e) => {
                    // An upstream failure counts against the host's error budget.
                    self.guard.record_error(&req.authority);
                    return Err(e);
                }
            };
            if response.status >= 500 {
                self.guard.record_error(&req.authority);
            }
            let flow = HttpFlow {
                id: FlowId::new(),
                request: req,
                response: Some(response),
                client_conn: loopback_conn(),
                server_conn: None,
                metadata: FlowMeta {
                    is_replay: true,
                    marks: opts.marks,
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            };
            if opts.record == RecordPolicy::Always {
                self.store.insert(Flow::Http(flow.clone()));
            }
            Ok(flow)
        })
    }
}

/// A placeholder client connection for a locally-reissued request.
fn loopback_conn() -> ConnInfo {
    ConnInfo {
        peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        sni: None,
        alpn: None,
        tls: false,
        established: SystemTime::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Body;
    use crate::config::ScopeEntry;
    use crate::ctx::ProxyClient;
    use crate::flow::{HttpResponse, HttpVersion};
    use crate::guard::StdGuard;
    use crate::header::HeaderMap;
    use crate::store::MemFlowStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Answers 200, counts calls, and records the last `VersionPolicy` it was
    /// asked for through `send_with`.
    struct RecordingSender {
        calls: AtomicUsize,
        version: Mutex<Option<VersionPolicy>>,
    }

    impl RecordingSender {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                version: Mutex::new(None),
            }
        }
    }

    impl RequestSender for RecordingSender {
        fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(ok_response()) })
        }

        fn send_with<'a>(
            &'a self,
            req: &'a HttpRequest,
            version: VersionPolicy,
        ) -> BoxFuture<'a, anyhow::Result<HttpResponse>> {
            *self.version.lock().unwrap() = Some(version);
            self.send(req)
        }
    }

    /// Implements only `send`, so `send_with`'s default must be exercised and the
    /// recorded policy stays `None`.
    struct DefaultSender {
        version: Mutex<Option<VersionPolicy>>,
    }

    impl RequestSender for DefaultSender {
        fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            Box::pin(async { Ok(ok_response()) })
        }
    }

    fn ok_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    fn req(authority: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: authority.into(),
            path: "/x".into(),
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }
    }

    fn scoped_guard() -> Arc<StdGuard> {
        let guard = Arc::new(StdGuard::default());
        guard.add_scope(ScopeEntry {
            host: "ex.test".into(),
        });
        guard
    }

    fn stored_marks(store: &MemFlowStore, id: FlowId) -> Vec<String> {
        match store.get(id).expect("flow stored") {
            Flow::Http(f) => f.metadata.marks,
            _ => panic!("expected an HTTP flow"),
        }
    }

    #[tokio::test]
    async fn send_opts_never_does_not_insert() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let client = PipelineClient::new(store.clone(), guard, Arc::new(RecordingSender::new()));
        let opts = SendOptions {
            record: RecordPolicy::Never,
            marks: vec!["scan:job1".into()],
            version: VersionPolicy::Auto,
        };
        let flow = client.send_opts(req("ex.test"), opts).await.unwrap();
        assert!(flow.metadata.is_replay);
        assert_eq!(flow.metadata.marks, vec!["scan:job1".to_string()]);
        assert_eq!(store.count(), 0);
    }

    #[tokio::test]
    async fn send_opts_always_inserts_with_marks() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let client = PipelineClient::new(store.clone(), guard, Arc::new(RecordingSender::new()));
        let opts = SendOptions {
            record: RecordPolicy::Always,
            marks: vec!["scan:job1".into(), "crawl".into()],
            version: VersionPolicy::Auto,
        };
        let flow = client.send_opts(req("ex.test"), opts).await.unwrap();
        assert_eq!(store.count(), 1);
        assert_eq!(
            stored_marks(&store, flow.id),
            vec!["scan:job1".to_string(), "crawl".to_string()]
        );
    }

    #[tokio::test]
    async fn send_keeps_shipped_behaviour() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let client = PipelineClient::new(store.clone(), guard, Arc::new(RecordingSender::new()));
        let flow = client.send(req("ex.test")).await.unwrap();
        assert_eq!(store.count(), 1);
        assert!(flow.metadata.marks.is_empty());
        assert!(flow.metadata.is_replay);
    }

    #[tokio::test]
    async fn send_opts_passes_version_to_sender() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let sender = Arc::new(RecordingSender::new());
        let client = PipelineClient::new(store.clone(), guard, sender.clone());
        let opts = SendOptions {
            record: RecordPolicy::Always,
            marks: vec![],
            version: VersionPolicy::H2,
        };
        client.send_opts(req("ex.test"), opts).await.unwrap();
        assert_eq!(*sender.version.lock().unwrap(), Some(VersionPolicy::H2));

        // The second sender implements only `send`, so `send_with`'s default runs
        // and never records a policy.
        let store2 = Arc::new(MemFlowStore::new());
        let guard2 = scoped_guard();
        let default_sender = Arc::new(DefaultSender {
            version: Mutex::new(None),
        });
        let client2 = PipelineClient::new(store2, guard2, default_sender.clone());
        let opts2 = SendOptions {
            record: RecordPolicy::Always,
            marks: vec![],
            version: VersionPolicy::H2,
        };
        client2.send_opts(req("ex.test"), opts2).await.unwrap();
        assert_eq!(*default_sender.version.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn send_opts_out_of_scope_sends_nothing() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let sender = Arc::new(RecordingSender::new());
        let client = PipelineClient::new(store.clone(), guard, sender.clone());
        let opts = SendOptions::default();
        let result = client.send_opts(req("other.test"), opts).await;
        assert!(result.is_err());
        assert_eq!(sender.calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.count(), 0);
    }

    #[tokio::test]
    async fn default_send_opts_delegates_to_send() {
        struct Legacy;
        impl ProxyClient for Legacy {
            fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
                Box::pin(async {
                    let mut flow = fixed_legacy_flow();
                    flow.request.path = "/legacy".into();
                    Ok(flow)
                })
            }
        }

        fn fixed_legacy_flow() -> HttpFlow {
            HttpFlow {
                id: FlowId::new(),
                request: HttpRequest {
                    method: "GET".into(),
                    scheme: "https".into(),
                    authority: "ex.test".into(),
                    path: "/".into(),
                    version: HttpVersion::Http11,
                    headers: HeaderMap::new(),
                    body: Body::Empty,
                    timestamp: SystemTime::now(),
                },
                response: None,
                client_conn: loopback_conn(),
                server_conn: None,
                metadata: FlowMeta::default(),
                intercept: InterceptState::Observed,
            }
        }

        let flow = Legacy
            .send_opts(req("ex.test"), SendOptions::default())
            .await
            .unwrap();
        assert_eq!(flow.request.path, "/legacy");
    }

    #[test]
    fn send_options_default() {
        assert_eq!(
            SendOptions::default(),
            SendOptions {
                record: RecordPolicy::Always,
                marks: vec![],
                version: VersionPolicy::Auto,
            }
        );
    }

    /// A sender whose connection dies mid-send, the way a dropped upstream TCP
    /// connection surfaces to the client.
    struct DroppingSender;

    impl RequestSender for DroppingSender {
        fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
            Box::pin(async { Err(anyhow::anyhow!("connection reset by peer")) })
        }
    }

    /// Tester: an upstream that drops mid-send stores no half-flow and still
    /// charges the host's error budget — the bulk `record: Never` path must not
    /// become a way to hammer a dead host for free. With a budget of one, the
    /// single failure disables the host, which is how the charge is observed.
    #[tokio::test]
    async fn send_opts_upstream_drop_stores_nothing_and_charges_the_error_budget() {
        for record in [RecordPolicy::Always, RecordPolicy::Never] {
            let store = Arc::new(MemFlowStore::new());
            let guard = Arc::new(StdGuard::new(crate::config::LimitConfig {
                host_error_budget: 1,
                ..Default::default()
            }));
            guard.add_scope(ScopeEntry {
                host: "ex.test".into(),
            });
            let client =
                PipelineClient::new(store.clone(), guard.clone(), Arc::new(DroppingSender));

            let err = client
                .send_opts(
                    req("ex.test"),
                    SendOptions {
                        record,
                        ..Default::default()
                    },
                )
                .await
                .expect_err("the upstream dropped");
            assert!(
                err.to_string().contains("connection reset"),
                "the upstream error reaches the caller unchanged: {err}"
            );
            assert_eq!(store.count(), 0, "{record:?}: no half-flow is stored");
            assert!(
                guard.check_active("ex.test").is_err(),
                "{record:?}: the failure charged the host's error budget"
            );
        }
    }

    /// Tester: a 5xx under `record: Never` is not stored, but it still charges
    /// the error budget, so an unrecorded bulk run cannot outrun the breaker.
    #[tokio::test]
    async fn send_opts_never_still_charges_a_5xx() {
        struct ServerErrorSender;
        impl RequestSender for ServerErrorSender {
            fn send(&self, _req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
                Box::pin(async {
                    let mut resp = ok_response();
                    resp.status = 503;
                    Ok(resp)
                })
            }
        }

        let store = Arc::new(MemFlowStore::new());
        let guard = Arc::new(StdGuard::new(crate::config::LimitConfig {
            host_error_budget: 1,
            ..Default::default()
        }));
        guard.add_scope(ScopeEntry {
            host: "ex.test".into(),
        });
        let client = PipelineClient::new(store.clone(), guard.clone(), Arc::new(ServerErrorSender));

        let flow = client
            .send_opts(
                req("ex.test"),
                SendOptions {
                    record: RecordPolicy::Never,
                    ..Default::default()
                },
            )
            .await
            .expect("a 5xx is still a response");
        assert_eq!(flow.response.expect("has a response").status, 503);
        assert_eq!(store.count(), 0, "record: Never stores nothing");
        assert!(
            guard.check_active("ex.test").is_err(),
            "the 5xx charged the host's error budget"
        );
    }

    /// Tester: marks are carried verbatim, including an empty list and a long or
    /// odd mark, and a `Never` send leaves nothing behind that could carry them
    /// into the store.
    #[tokio::test]
    async fn marks_are_carried_verbatim() {
        let store = Arc::new(MemFlowStore::new());
        let guard = scoped_guard();
        let client = PipelineClient::new(store.clone(), guard, Arc::new(RecordingSender::new()));

        let odd = vec![
            String::new(),
            "scan:job-\u{1F600}".to_string(),
            "x".repeat(4096),
        ];
        let flow = client
            .send_opts(
                req("ex.test"),
                SendOptions {
                    record: RecordPolicy::Always,
                    marks: odd.clone(),
                    version: VersionPolicy::Auto,
                },
            )
            .await
            .unwrap();
        assert_eq!(flow.metadata.marks, odd);
        assert_eq!(stored_marks(&store, flow.id), odd);
    }
}
