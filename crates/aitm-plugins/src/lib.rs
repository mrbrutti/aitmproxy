//! `aitm-plugins` — first-party feature plugins (capture, replay, intercept,
//! mutate, scope, rate-limit). Each registers its own commands; none lives in core.

pub mod capture;
pub mod intercept;
pub mod mutate;
pub mod replay;

pub use capture::CapturePlugin;
pub use intercept::InterceptPlugin;
pub use mutate::MutatePlugin;
pub use replay::ReplayPlugin;

/// Drive a future to completion from a synchronous `Command::invoke`.
///
/// Commands are synchronous on the bus while `ProxyClient::send` is async. On a
/// multi-thread tokio runtime the calling worker steps out of the pool
/// (`block_in_place`) so blocking cannot starve the runtime; anywhere else (a
/// plain thread, a test) a local executor drives the future. A frontend that
/// invokes commands from a current-thread runtime must do so off that runtime
/// (e.g. `spawn_blocking`), or a future needing the tokio reactor would never
/// be polled.
pub(crate) fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) => {
            tokio::task::block_in_place(|| handle.block_on(fut))
        }
        _ => futures::executor::block_on(fut),
    }
}
