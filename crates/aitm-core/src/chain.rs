//! The ordered plugin chain: dispatches an event to each plugin in registration
//! order, stops on `Verdict::Halt`, and drives interception as a pausable future.
//!
//! `Chain` is also the `EventSink` behind `ModuleCtx::emit`, so a protocol module
//! reaches the chain without naming it.

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::ctx::FlowCtx;
use crate::event::{Event, Verdict};
use crate::flow::{Flow, FlowId, FlowMeta, InterceptState};
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
    ///
    /// A **passive** flow (spec D4: `FlowMeta::passive`, or a tunnel row with
    /// `FlowMeta::tunnel.is_some()`) is observed, never acted on: only plugins
    /// whose [`Plugin::observes_passive_flows`](crate::Plugin::observes_passive_flows)
    /// is `true` run, and the flow is never parked.
    pub async fn dispatch(&self, ev: Event) -> Verdict {
        let Some(id) = event_flow_id(&ev) else {
            return Verdict::Continue;
        };
        let Some(mut flow) = self.store.get(id) else {
            return Verdict::Continue;
        };
        // Snapshot the operator annotations as they were when we took our copy, so
        // the write-back can tell a plugin's change to them from a concurrent
        // `flow.mark` / `flow.comment` that landed while the plugins ran.
        let base_meta = flow.metadata().clone();
        // Spec D4: decided from the copy we already hold — no extra store read and
        // no guard in the chain. The producing module stamped `passive`; a tunnel
        // row is passive by virtue of carrying tunnel fields.
        let passive = flow.metadata().passive || flow.metadata().tunnel.is_some();

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
                // A passive flow reaches only the plugins that observe such flows
                // (the subscription tap); nothing that acts on a flow sees it.
                if passive && !p.observes_passive_flows() {
                    continue;
                }
                let v = p.on_event(&ev, &mut ctx);
                drop(p);
                if matches!(v, Verdict::Halt) {
                    verdict = Verdict::Halt;
                    break;
                }
            }
            (verdict, ctx.take_parked())
        };

        // A passive dispatch never parks. Only a plugin that opted in could have
        // armed a receiver here, and no observer does; drop it rather than wait
        // on it, and undo the `Intercepted` state it stamped on our working copy
        // so the stored row never reads `intercepted` with a handle nobody awaits.
        let parked = if passive {
            if parked.is_some() {
                tracing::debug!(%id, "an observer tried to park a passive flow; ignored");
                set_intercept(&mut flow, InterceptState::Observed);
            }
            None
        } else {
            parked
        };

        // Persist the plugins' edits onto the *live* stored flow, rather than
        // blind-inserting our (possibly stale) copy over it: a `flow.mark` /
        // `flow.comment` that ran concurrently would otherwise be clobbered. The
        // plugins own request/response/intercept; operator annotations are merged.
        self.store.update(id, &mut |live: &mut Flow| {
            merge_plugin_edits(live, &flow, &base_meta)
        });

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

/// Write the plugins' `edited` copy onto the `live` stored flow, keeping the
/// operator annotations (marks / comment) that a concurrent `flow.mark` /
/// `flow.comment` may have set while the plugins ran. The plugins own everything
/// else (request, response, interception), so those fields take the edited value
/// exactly as a blind re-insert would have.
///
/// `base` is the annotation state the plugins started from: a mark they *added*
/// (not in `base`) is unioned in, and a comment they *changed* wins; otherwise the
/// live value is preserved so a concurrent operator edit is not lost.
fn merge_plugin_edits(live: &mut Flow, edited: &Flow, base: &FlowMeta) {
    let live_meta = live.metadata().clone();
    *live = edited.clone();
    let meta = live.metadata_mut();

    // Union of marks: every mark the live flow carried (including any added
    // concurrently) plus every mark the plugins produced, de-duplicated.
    let mut marks = live_meta.marks.clone();
    for m in std::mem::take(&mut meta.marks) {
        if !marks.contains(&m) {
            marks.push(m);
        }
    }
    meta.marks = marks;

    // Comment: a plugin that changed it wins; otherwise keep the live comment,
    // which may have been set concurrently.
    if meta.comment == base.comment {
        meta.comment = live_meta.comment;
    }

    // Capture-time fields a plugin edit never owns.
    meta.created = live_meta.created;
    meta.is_replay = live_meta.is_replay;
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
