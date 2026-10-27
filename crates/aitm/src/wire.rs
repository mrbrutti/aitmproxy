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

use aitm_browser::BrowserPlugin;
use aitm_core::{Config, Plugin, Proxy, Registry};
use aitm_plugins::{
    CapturePlugin, InterceptPlugin, MutatePlugin, RateLimitPlugin, ReplayPlugin, ScopePlugin,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use aitm_proto_ws::WsModule;

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
    let http = HttpModule::with_ca(Arc::new(ca))
        .with_insecure(cfg.ssl_insecure)
        .with_max_body_bytes(cfg.limits.max_body_bytes);

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

/// The request sender backing `flow.replay` / `request.send`: real HTTP/1.1 over
/// `aitm-proto-http`'s `Http1Machine` (chunked decode, clean framing) with TLS
/// for `https`. Re-exported from `aitm-proto-http`.
pub use aitm_proto_http::Http1Sender;
