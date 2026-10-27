//! `aitm-core` — the protocol-agnostic core of aitmproxy.
//!
//! Hosts the flow model, the typed event bus + ordered plugin chain, the command
//! registry, the flow store, the scope/rate guard, and the proxy acceptor. Every
//! other crate in the workspace depends on this one.

pub mod body;
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
pub mod registry;
pub mod store;
pub mod stream;
pub mod value;

pub use body::{Body, StreamBody};
pub use command::{Command, ParamDef, ParamSchema, TypeDesc};
pub use config::{
    BackoffConfig, BrowserConfig, CaConfig, Config, LimitConfig, McpConfig, McpTransport,
    ScopeConfig, ScopeEntry, SsrfPolicy,
};
pub use ctx::{BrowserDriver, ClickTarget, CommandHost, FlowCtx, NavOutcome, ProxyClient};
pub use error::{FlowError, GuardError};
pub use event::{Event, Verdict};
pub use flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, ResumeHandle, WsDir, WsFlow, WsMessage, WsOpcode,
};
pub use guard::{classify_host, ActionPermit, HostClass, ScopeRateGuard, StdGuard};
pub use header::HeaderMap;
pub use plugin::Plugin;
pub use protocol::{EventSink, ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector};
pub use registry::Registry;
pub use store::{FlowKind, FlowQuery, FlowStore, MemFlowStore};
pub use stream::{AsyncReadWrite, ByteStream};
pub use value::{Params, Value};

/// The crate version, wired to the Cargo package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
