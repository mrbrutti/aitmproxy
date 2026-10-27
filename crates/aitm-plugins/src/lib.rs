//! `aitm-plugins` — first-party feature plugins (capture, replay, intercept,
//! mutate, scope, rate-limit). Each registers its own commands; none lives in core.

pub mod capture;

pub use capture::CapturePlugin;
