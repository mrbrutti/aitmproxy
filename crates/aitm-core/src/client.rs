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

/// Performs the raw upstream send for a reissued request. The concrete HTTP/TLS
/// sender lives in the protocol layer and is injected at binary assembly, keeping
/// hyper/rustls out of `aitm-core`.
pub trait RequestSender: Send + Sync {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>>;
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
        Box::pin(async move {
            // Hold the permit for the whole send (concurrency released on drop).
            let _permit = self.guard.check_active(&req.authority)?;
            let response = match self.sender.send(&req).await {
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
                    ..Default::default()
                },
                intercept: InterceptState::Observed,
            };
            self.store.insert(Flow::Http(flow.clone()));
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
