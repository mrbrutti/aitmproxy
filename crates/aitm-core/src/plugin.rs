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

    /// Called for every event in registration order. Default: pass through.
    fn on_event(&mut self, _ev: &Event, _ctx: &mut FlowCtx<'_>) -> Verdict {
        Verdict::Continue
    }
}
