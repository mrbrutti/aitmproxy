//! The rate-limit plugin: declares the `per_host_rps` option that drives the
//! guard's per-host token bucket (AC-P4).
//!
//! A plugin's `load` only sees the `Registry`, not the guard, so this plugin
//! declares the option there and exposes [`RateLimitPlugin::apply`] to push the
//! option's value onto a concrete [`StdGuard`]. The binary (Task 28) calls
//! `apply` after reading config; raising the option and re-applying changes the
//! observed throttling, with no core edit.

use aitm_core::{Plugin, Registry, StdGuard, Value};

/// Registers the `per_host_rps` option. Observes no events; registers no command
/// (scope/rate limits are set by option + guard, surfaced via `scope.*`).
pub struct RateLimitPlugin {
    default_per_host_rps: u32,
}

impl RateLimitPlugin {
    /// The option name that sets the per-host requests-per-second limit.
    pub const OPTION: &'static str = "per_host_rps";

    /// A plugin whose option defaults to `default_per_host_rps`.
    pub fn new(default_per_host_rps: u32) -> Self {
        Self {
            default_per_host_rps,
        }
    }

    /// The current `per_host_rps` option value, if set to a non-negative integer.
    pub fn configured(reg: &Registry) -> Option<u32> {
        match reg.option(Self::OPTION) {
            Some(Value::Int(rps)) if rps >= 0 => Some(rps as u32),
            _ => None,
        }
    }

    /// Push the registry's `per_host_rps` option onto `guard`'s per-host bucket.
    /// The binary calls this after loading config; a test calls it after
    /// `set_option` to prove AC-P4 (the option changes observed throttling).
    pub fn apply(reg: &Registry, guard: &StdGuard) {
        if let Some(rps) = Self::configured(reg) {
            guard.set_per_host_rps(rps);
        }
    }
}

impl Default for RateLimitPlugin {
    fn default() -> Self {
        // Matches `LimitConfig`'s per-host default.
        Self::new(50)
    }
}

impl Plugin for RateLimitPlugin {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_option(
            Self::OPTION,
            Value::Int(i64::from(self.default_per_host_rps)),
            "Per-host requests-per-second limit for active actions.",
        );
    }
}
