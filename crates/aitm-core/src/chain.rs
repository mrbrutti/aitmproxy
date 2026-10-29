//! The ordered plugin chain: dispatches an event to each plugin in registration
//! order, stops on `Verdict::Halt`, and drives interception as a pausable future.
//!
//! `Chain` is also the `EventSink` behind `ModuleCtx::emit`, so a protocol module
//! reaches the chain without naming it.

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::ctx::FlowCtx;
use crate::event::{Event, Verdict};
use crate::flow::{Flow, FlowId, InterceptState};
use crate::protocol::EventSink;
use crate::registry::Registry;
use crate::store::FlowStore;

/// How long a parked (intercepted) flow waits for a resume before it is killed,
/// so an abandoned interception cannot pin a flow forever.
const DEFAULT_INTERCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Dispatches events to the registry's ordered plugin list over a shared store.
pub struct Chain {
    registry: Arc<Registry>,
    store: Arc<dyn FlowStore>,
    intercept_timeout: std::time::Duration,
}

impl Chain {
    /// Build a chain over a registry and store.
    pub fn new(registry: Arc<Registry>, store: Arc<dyn FlowStore>) -> Self {
        Self {
            registry,
            store,
            intercept_timeout: DEFAULT_INTERCEPT_TIMEOUT,
        }
    }

    /// Set how long an intercepted flow may stay parked before it is killed.
    pub fn with_intercept_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.intercept_timeout = timeout;
        self
    }

    /// Dispatch one event. Plugins run in registration order; a `Halt` stops the
    /// chain. If a plugin parks the flow (`intercept`), the returned future waits
    /// for a resume command before marking the flow `Resumed`.
    pub async fn dispatch(&self, ev: Event) -> Verdict {
        let Some(id) = event_flow_id(&ev) else {
            return Verdict::Continue;
        };
        let Some(mut flow) = self.store.get(id) else {
            return Verdict::Continue;
        };

        let (mut verdict, parked) = {
            let mut ctx = FlowCtx::new(&mut flow);
            let mut verdict = Verdict::Continue;
            for plugin in self.registry.plugins() {
                // Recover a poisoned plugin lock rather than silently skipping the
                // plugin: a prior panic must not quietly drop a security plugin
                // (scope, intercept) from the chain.
                let mut p = plugin.lock().unwrap_or_else(|poisoned| {
                    tracing::warn!("plugin lock was poisoned; recovering and continuing dispatch");
                    poisoned.into_inner()
                });
                let v = p.on_event(&ev, &mut ctx);
                drop(p);
                if matches!(v, Verdict::Halt) {
                    verdict = Verdict::Halt;
                    break;
                }
            }
            (verdict, ctx.take_parked())
        };

        // Persist any in-place edits the plugins made.
        self.store.insert(flow);

        // Pausable future: a parked flow waits for a resume command to fire the
        // handle stored in its `Intercepted` state, bounded by a timeout so an
        // abandoned interception (e.g. the client vanished) cannot pin the flow.
        if let Some(rx) = parked {
            match tokio::time::timeout(self.intercept_timeout, rx).await {
                Ok(_) => {
                    // The releasing command (flow.resume / flow.kill) records the
                    // authoritative intercept state in the store before it wakes
                    // this future. A kill must survive the wake so the flow is
                    // dropped, never forwarded — so honour a stored `Killed`
                    // (halt the chain) instead of clobbering it back to
                    // `Resumed`. Only a non-killed wake resumes and forwards.
                    if is_killed(&self.store, id) {
                        verdict = Verdict::Halt;
                    } else {
                        self.store.update(id, &mut |f: &mut Flow| {
                            set_intercept(f, InterceptState::Resumed)
                        });
                    }
                }
                Err(_) => {
                    tracing::warn!(%id, "intercepted flow was never resumed; killing it");
                    self.store.update(id, &mut |f: &mut Flow| {
                        set_intercept(f, InterceptState::Killed)
                    });
                    verdict = Verdict::Halt;
                }
            }
        }

        verdict
    }
}

/// Dispatch through the chain as the `ModuleCtx` event sink.
impl EventSink for Chain {
    fn emit(&self, ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(self.dispatch(ev))
    }
}

/// The flow id an event concerns. Every current `Event` variant names a flow;
/// `Option` leaves room for a future flowless event without a chain change.
fn event_flow_id(ev: &Event) -> Option<FlowId> {
    match ev {
        Event::RequestHeaders(id)
        | Event::Request(id)
        | Event::ResponseHeaders(id)
        | Event::Response(id)
        | Event::WsStart(id)
        | Event::WsEnd(id) => Some(*id),
        Event::WsMessage { flow, .. } | Event::Error { flow, .. } => Some(*flow),
    }
}

/// Set a flow's interception state regardless of protocol.
fn set_intercept(flow: &mut Flow, state: InterceptState) {
    match flow {
        Flow::Http(f) => f.intercept = state,
        Flow::WebSocket(f) => f.intercept = state,
    }
}

/// Whether the stored flow is currently `Killed`, regardless of protocol. A flow
/// that vanished from the store is treated as not killed (the resume path runs).
fn is_killed(store: &Arc<dyn FlowStore>, id: FlowId) -> bool {
    match store.get(id) {
        Some(Flow::Http(f)) => matches!(f.intercept, InterceptState::Killed),
        Some(Flow::WebSocket(f)) => matches!(f.intercept, InterceptState::Killed),
        None => false,
    }
}
