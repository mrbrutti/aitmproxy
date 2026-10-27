//! The event bus: what the protocol modules emit into the ordered plugin chain,
//! and the verdict a plugin returns.

use crate::error::FlowError;
use crate::flow::FlowId;

/// An event dispatched through the ordered plugin chain. `#[non_exhaustive]` so
/// new variants (new protocols, new lifecycle points) are additive for external
/// plugin authors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Request headers parsed (body may still be streaming).
    RequestHeaders(FlowId),
    /// Request complete (headers + body).
    Request(FlowId),
    /// Response headers parsed.
    ResponseHeaders(FlowId),
    /// Response complete.
    Response(FlowId),
    /// A WebSocket conversation opened.
    WsStart(FlowId),
    /// A WebSocket frame appended at `index` in the flow's `messages`.
    WsMessage { flow: FlowId, index: usize },
    /// A WebSocket conversation closed.
    WsEnd(FlowId),
    /// A flow-level error.
    Error { flow: FlowId, kind: FlowError },
}

/// A plugin's answer after handling an event. `Halt` short-circuits the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Continue,
    Halt,
}
