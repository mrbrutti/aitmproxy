//! `aitm-core` — the protocol-agnostic core of aitmproxy.
//!
//! Hosts the flow model, the typed event bus + ordered plugin chain, the command
//! registry, the flow store, the scope/rate guard, and the proxy acceptor. Every
//! other crate in the workspace depends on this one.

pub mod agent;
pub mod authority;
pub mod body;
pub mod chain;
pub mod client;
pub mod command;
pub mod config;
pub mod ctx;
pub mod error;
pub mod event;
pub mod flow;
pub mod guard;
pub mod header;
pub mod plugin;
pub mod protocol;
pub mod proxy;
pub mod registry;
pub mod store;
pub mod stream;
pub mod value;

pub use agent::AgentPolicy;
pub use authority::{Authority, AuthorityError};
pub use body::{Body, StreamBody};
pub use chain::Chain;
pub use client::{PipelineClient, RequestSender};
pub use command::{Command, ParamDef, ParamSchema, Sensitivity, TypeDesc};
pub use config::{
    BackoffConfig, BrowserConfig, BrowserEngine, CaConfig, Config, FirefoxConfig, LimitConfig,
    McpConfig, McpTransport, ObscuraConfig, PocConfig, ScopeConfig, ScopeEntry, SsrfPolicy,
};
pub use ctx::{
    BrowserDriver, ClickTarget, CommandHost, FlowCtx, Frontend, NavOutcome, ProxyClient,
};
pub use error::{FlowError, GuardError};
pub use event::{Event, Verdict};
pub use flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, ResumeHandle, WsDir, WsFlow, WsMessage, WsOpcode,
};
pub use guard::{classify_host, ssrf_check, ActionPermit, HostClass, ScopeRateGuard, StdGuard};
pub use header::{HeaderError, HeaderMap};
pub use plugin::Plugin;
pub use protocol::{EventSink, ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector};
pub use proxy::{Proxy, ProxyBuilder};
pub use registry::Registry;
pub use store::{ClearOutcome, FlowKind, FlowQuery, FlowStore, MemFlowStore};
pub use stream::{AsyncReadWrite, ByteStream};
pub use value::{Params, Value};

/// The crate version, wired to the Cargo package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
