//! Assembling the proxy from `Config` (Task 28).
//!
//! [`build_proxy`] registers the protocol modules (`HttpModule`, then `WsModule`),
//! then the first-party plugins in chain order (capture, replay, intercept,
//! mutate, scope, rate-limit), then the command providers (browser, poc), and
//! builds the [`Proxy`]. Each plugin's `load` registers its commands into the one
//! registry the chain and the frontends share.
//!
//! The feature set is data, not code: [`Features`] names which removable plugins
//! are registered. Dropping `mutate` there removes `flow.mutate`/`request.send`
//! with no `aitm-core` edit (AC-P3). The scope and rate limits come from `Config`,
//! so a config change moves the observed throttle threshold (AC-P4).

use std::sync::Arc;
use std::time::SystemTime;

use aitm_browser::BrowserPlugin;
use aitm_core::{
    Body, Config, HeaderMap, HttpRequest, HttpResponse, HttpVersion, Plugin, Proxy, Registry,
    RequestSender,
};
use aitm_plugins::{
    CapturePlugin, InterceptPlugin, MutatePlugin, RateLimitPlugin, ReplayPlugin, ScopePlugin,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use aitm_proto_ws::WsModule;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Which removable first-party feature plugins to register. Dropping one here is
/// the whole of AC-P3: the command disappears from the registry with no core edit.
#[derive(Debug, Clone)]
pub struct Features {
    /// The mutate plugin (`flow.mutate`, `request.send`).
    pub mutate: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self { mutate: true }
    }
}

/// Assemble the proxy from configuration with the default feature set.
pub fn build_proxy(cfg: &Config) -> anyhow::Result<Proxy> {
    build_proxy_with(cfg, &Features::default())
}

/// Assemble the proxy from configuration and an explicit feature set.
pub fn build_proxy_with(cfg: &Config, features: &Features) -> anyhow::Result<Proxy> {
    let ca = CertAuthority::load_or_generate(&cfg.ca.dir, cfg.ca.key_mode)?;
    let http = HttpModule::with_ca(Arc::new(ca)).with_insecure(cfg.ssl_insecure);

    let mut builder = Proxy::builder()
        .with_config(cfg.clone())
        // Protocol modules: HTTP first; WsModule only claims post-upgrade connections.
        .register_module(Arc::new(http))
        .register_module(Arc::new(WsModule::new()))
        // First-party plugins, in chain order. Intercept precedes mutate so a
        // request is parked before mutate would act (data-flow 2).
        .register_plugin(Box::new(CapturePlugin::new()))
        .register_plugin(Box::new(ReplayPlugin::new()))
        .register_plugin(Box::new(InterceptPlugin::new()));
    if features.mutate {
        builder = builder.register_plugin(Box::new(MutatePlugin::new()));
    }
    builder = builder
        .register_plugin(Box::new(ScopePlugin::new()))
        .register_plugin(Box::new(RateLimitPlugin::new(cfg.limits.per_host_rps)))
        // Command providers: the browser and poc commands.
        .register_plugin(Box::new(BrowserPlugin::new(cfg.browser.ssrf.clone())))
        .register_plugin(Box::new(PocCommands));

    builder.build()
}

/// A plugin that registers the `poc.build` and `poc.run` commands. The poc crate
/// exposes free `register` functions rather than a plugin; this adapts them into
/// the one `load`-driven registration path the builder uses.
struct PocCommands;

impl Plugin for PocCommands {
    fn name(&self) -> &str {
        "poc"
    }

    fn load(&mut self, reg: &mut Registry) {
        aitm_poc::builder::register(reg);
        aitm_poc::runner::register(reg);
    }
}

/// A minimal plaintext HTTP/1.1 `RequestSender` for the `PipelineClient`: it
/// dials the request's authority over TCP and reads one response. This backs
/// `flow.replay` / `request.send` against http upstreams; TLS upstream replay is
/// a follow-up (the MITM path already handles TLS on the accept side).
pub struct TcpRequestSender;

impl RequestSender for TcpRequestSender {
    fn send(&self, req: &HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpResponse>> {
        let authority = req.authority.clone();
        let method = req.method.clone();
        let path = req.path.clone();
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let body = match &req.body {
            Body::Bytes(bytes) => bytes.clone(),
            _ => Vec::new(),
        };
        Box::pin(async move {
            let mut stream = tokio::net::TcpStream::connect(&authority).await?;
            // Host comes from the authority; drop any caller Host to avoid duplicates.
            let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {authority}\r\n");
            for (name, value) in &headers {
                if name.eq_ignore_ascii_case("host") {
                    continue;
                }
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
            head.push_str("Connection: close\r\n\r\n");
            stream.write_all(head.as_bytes()).await?;
            if !body.is_empty() {
                stream.write_all(&body).await?;
            }
            // Bound the response read so a hostile upstream cannot exhaust memory.
            const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
            let mut raw = Vec::new();
            tokio::io::AsyncReadExt::take(stream, MAX_RESPONSE_BYTES)
                .read_to_end(&mut raw)
                .await?;
            Ok(parse_response(&raw))
        })
    }
}

/// Parse a raw HTTP/1.1 response into an `HttpResponse` (status + buffered body).
fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split {
        Some(i) => (&raw[..i], raw[i + 4..].to_vec()),
        None => (raw, Vec::new()),
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.set(name.trim(), value.trim());
        }
    }
    HttpResponse {
        status,
        version: HttpVersion::Http11,
        headers,
        body: Body::Bytes(body),
        timestamp: SystemTime::now(),
    }
}
