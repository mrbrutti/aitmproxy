//! Assembling the proxy from `Config` (Task 28; M2 Task 21).
//!
//! [`assemble`] registers the protocol modules (`HttpModule`, then `WsModule`),
//! then the first-party plugins in chain order (capture, replay, intercept,
//! mutate, scope, rate-limit), then the command providers (browser, poc, ca),
//! and builds the [`Proxy`]. Each plugin's `load` registers its commands into
//! the one registry the chain and the frontends share. The [`CertAuthority`]
//! the HTTP module mints with comes back out in [`Assembled`], so the browser
//! launcher can hand its certificate file to the embedded engine (spec §D7).
//!
//! The feature set is data, not code: [`Features`] names which removable plugins
//! are registered. Dropping `mutate` there removes `flow.mutate`/`request.send`
//! with no `aitm-core` edit (AC-P3). The scope and rate limits come from `Config`,
//! so a config change moves the observed throttle threshold (AC-P4).

use std::sync::Arc;

use aitm_browser::BrowserPlugin;
use aitm_ca::CaPlugin;
use aitm_core::{Config, Plugin, Proxy, Registry};
use aitm_plugins::{
    CapturePlugin, ControlPlugin, DetailPlugin, InterceptPlugin, MetaPlugin, MutatePlugin,
    RateLimitPlugin, ReplayPlugin, ScopePlugin,
};
use aitm_proto_http::{CertAuthority, HttpModule};
use aitm_proto_ws::WsModule;

/// Which removable first-party feature plugins to register. Dropping one here is
/// the whole of AC-P3: the command disappears from the registry with no core edit.
#[derive(Clone)]
pub struct Features {
    /// The mutate plugin (`flow.mutate`, `request.send`).
    pub mutate: bool,
    /// The `ca.*` plugin to register. `None` builds `CaPlugin::new(cfg.ca)`
    /// (real executor, file audit log); `Some` registers the given plugin,
    /// which is how tests inject a scripted executor and an in-memory audit log.
    pub ca_plugin: Option<CaPlugin>,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            mutate: true,
            ca_plugin: None,
        }
    }
}

/// A built proxy and the CA it serves with.
pub struct Assembled {
    pub proxy: Proxy,
    pub ca: Arc<CertAuthority>,
}

/// Assemble the proxy from configuration with the default feature set.
pub fn assemble(cfg: &Config) -> anyhow::Result<Assembled> {
    assemble_with(cfg, &Features::default())
}

/// Assemble the proxy from configuration and an explicit feature set.
pub fn assemble_with(cfg: &Config, features: &Features) -> anyhow::Result<Assembled> {
    let ca = Arc::new(CertAuthority::load_or_generate(
        &cfg.ca.dir,
        cfg.ca.key_mode,
    )?);
    let http = HttpModule::with_ca(ca.clone())
        .with_insecure(cfg.ssl_insecure)
        .with_max_body_bytes(cfg.limits.max_body_bytes);

    // The control plugin's `proxy.status` reports whether intercept is armed, so
    // it shares the intercept plugin's armed flag.
    let intercept = InterceptPlugin::new();
    let armed = intercept.armed_flag();

    let mut builder = Proxy::builder()
        .with_config(cfg.clone())
        // Protocol modules: HTTP first; WsModule only claims post-upgrade connections.
        .register_module(Arc::new(http))
        .register_module(Arc::new(WsModule::new()))
        // First-party plugins, in chain order. Intercept precedes mutate so a
        // request is parked before mutate would act (data-flow 2).
        .register_plugin(Box::new(CapturePlugin::new()))
        .register_plugin(Box::new(DetailPlugin::new()))
        .register_plugin(Box::new(MetaPlugin::new()))
        .register_plugin(Box::new(ReplayPlugin::new()))
        .register_plugin(Box::new(intercept))
        .register_plugin(Box::new(ControlPlugin::new(armed)));
    if features.mutate {
        builder = builder.register_plugin(Box::new(MutatePlugin::new()));
    }
    let ca_plugin = features
        .ca_plugin
        .clone()
        .unwrap_or_else(|| CaPlugin::new(cfg.ca.clone()));
    builder = builder
        .register_plugin(Box::new(ScopePlugin::new(cfg.scope.allow_agent_widen)))
        .register_plugin(Box::new(RateLimitPlugin::new(cfg.limits.per_host_rps)))
        // Command providers: the browser, poc and ca commands.
        .register_plugin(Box::new(BrowserPlugin::new(cfg.browser.ssrf.clone())))
        .register_plugin(Box::new(PocCommands))
        .register_plugin(Box::new(ca_plugin));

    Ok(Assembled {
        proxy: builder.build()?,
        ca,
    })
}

/// Assemble the proxy from configuration with the default feature set.
pub fn build_proxy(cfg: &Config) -> anyhow::Result<Proxy> {
    Ok(assemble(cfg)?.proxy)
}

/// Assemble the proxy from configuration and an explicit feature set.
pub fn build_proxy_with(cfg: &Config, features: &Features) -> anyhow::Result<Proxy> {
    Ok(assemble_with(cfg, features)?.proxy)
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
        aitm_poc::library::register(reg);
    }
}

/// The request sender backing `flow.replay` / `request.send`: real HTTP/1.1 over
/// `aitm-proto-http`'s `Http1Machine` (chunked decode, clean framing) with TLS
/// for `https`. Re-exported from `aitm-proto-http`.
pub use aitm_proto_http::Http1Sender;
