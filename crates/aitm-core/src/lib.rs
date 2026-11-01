//! `aitm-core` — the protocol-agnostic core of aitmproxy.
//!
//! Hosts the flow model, the typed event bus + ordered plugin chain, the command
//! registry, the flow store, the scope/rate guard, and the proxy acceptor. Every
//! other crate in the workspace depends on this one.

pub mod agent;
pub mod audit;
pub mod authority;
pub mod body;
pub mod chain;
pub mod client;
pub mod command;
pub mod config;
pub mod ctx;
pub mod egress;
pub mod error;
pub mod event;
pub mod flow;
pub mod guard;
pub mod header;
pub mod plugin;
pub mod protocol;
pub mod proxy;
pub mod redact;
pub mod registry;
pub mod store;
pub mod stream;
pub mod tunnel;
pub mod value;

pub use agent::{AgentPolicy, AgentState};
pub use audit::{
    declared_client_label, lane_for, origin_label, sanitize_client_label, AuditEntry, AuditLane,
    AuditResult, AuditRing, AuditSink, DEFAULT_ARGS_SUMMARY_CAP, DEFAULT_AUDIT_CAPACITY,
    DEFAULT_RESULT_REASON_CAP, DEFAULT_ROUTINE_AUDIT_CAPACITY, MAX_AUDIT_SOURCES,
    MAX_CLIENT_LABEL_CHARS, WEB_BRIDGE_CLIENT_LABEL,
};
pub use authority::{Authority, AuthorityError};
pub use body::{Body, StreamBody};
pub use chain::Chain;
pub use client::{PipelineClient, RequestSender};
pub use command::{Command, ParamDef, ParamSchema, Sensitivity, TypeDesc};
pub use config::{
    BackoffConfig, BrowserConfig, BrowserEngine, CaConfig, Config, FindingsConfig, FirefoxConfig,
    LimitConfig, MapsConfig, McpConfig, McpTransport, ObscuraConfig, PocConfig, ScopeConfig,
    ScopeEntry, SessionIoConfig, SsrfPolicy, TlsConfig, NOTHING_DECRYPTED_ADVICE,
};
pub use ctx::{
    BrowserDriver, CallerTrust, ClickTarget, CommandHost, FindingDraft, FindingRecorder, FlowCtx,
    Frontend, NavOutcome, ProxyClient,
};
pub use egress::{ConfinementToken, EgressConfinement};
pub use error::{FlowError, GuardError};
pub use event::{Event, Verdict};
pub use flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, ResumeHandle, TunnelInfo, TunnelMode, TunnelReason, WsDir, WsFlow, WsMessage,
    WsOpcode,
};
pub use guard::{
    classify_host, engine_may_reach_private, ssrf_check, ActionPermit, HostClass, ScopeRateGuard,
    StdGuard,
};
pub use header::{HeaderError, HeaderMap};
pub use plugin::Plugin;
pub use protocol::{EventSink, ModuleCtx, NextLayerHint, ProtocolModule, UpstreamConnector};
pub use proxy::{Proxy, ProxyBuilder};
pub use registry::Registry;
pub use store::{ClearOutcome, FlowKind, FlowQuery, FlowStore, MemFlowStore};
pub use stream::{AsyncReadWrite, ByteStream};
pub use tunnel::{classify_client_failure, relay, TunnelRequest, TunnelRow};
pub use value::{Params, Value};

/// The crate version, wired to the Cargo package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
