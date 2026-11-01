//! The plugin trait. First-party features (capture, replay, intercept, mutate,
//! scope, rate-limit) are plugins, not core code; the chain dispatches events to
//! each plugin in registration order.

use crate::ctx::FlowCtx;
use crate::event::{Event, Verdict};
use crate::registry::Registry;

/// A compiled-in plugin. `name` is the ordering key in the chain.
pub trait Plugin: Send {
    /// Stable identifier, also the ordering key in the chain.
    fn name(&self) -> &str;

    /// Called once at load: register options and commands into the registry.
    fn load(&mut self, _reg: &mut Registry) {}

    /// Whether this plugin wants to see **passive** flows (spec D4): plain HTTP to a
    /// host outside Scope (`FlowMeta::passive`) and every tunnel row
    /// (`FlowMeta::tunnel.is_some()`). Such a flow is observed, never acted on:
    /// the chain dispatches its events only to plugins that return `true` here and
    /// never parks it. Default `false`; only pure observers such as the
    /// subscription tap opt in. A plugin that acts on a flow (intercepts, mutates,
    /// scripts, scans, rate-limits) must keep the default.
    fn observes_passive_flows(&self) -> bool {
        false
    }

    /// Called for every event in registration order. Default: pass through.
    fn on_event(&mut self, _ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        Verdict::Continue
    }
}
