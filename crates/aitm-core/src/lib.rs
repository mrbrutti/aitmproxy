//! `aitm-core` — the protocol-agnostic core of aitmproxy.
//!
//! Hosts the flow model, the typed event bus + ordered plugin chain, the command
//! registry, the flow store, the scope/rate guard, and the proxy acceptor. Every
//! other crate in the workspace depends on this one.

pub mod body;
pub mod error;
pub mod event;
pub mod flow;
pub mod header;

pub use body::{Body, StreamBody};
pub use error::{FlowError, GuardError};
pub use event::{Event, Verdict};
pub use flow::{
    ConnInfo, Flow, FlowId, FlowMeta, HttpFlow, HttpRequest, HttpResponse, HttpVersion,
    InterceptState, ResumeHandle, WsDir, WsFlow, WsMessage, WsOpcode,
};
pub use header::HeaderMap;

/// The crate version, wired to the Cargo package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
