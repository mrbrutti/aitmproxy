//! `aitm` — the binary's reusable assembly. `wire::assemble` turns a `Config`
//! into a running-ready `Proxy` plus the CA it serves with; `main` drives it.
//! `env` bridges the process environment into `Config`; `render` prints a
//! command's result for the CLI; `web` is the `aitm web` static host and
//! `/bus` WebSocket bridge (F15). Kept as a library so the wiring is testable
//! (AC-P3/AC-P4, CA-AC27) without the process entrypoint.

pub mod bundled;
pub mod config_file;
pub mod env;
pub mod ingress;
pub mod macos_capture;
pub mod operator_token;
pub mod render;
pub mod scripts;
pub mod startup;
pub mod tui;
pub mod web;
pub mod wire;

use tracing::warn;

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM. A handler that cannot be
/// installed is logged and never fires, so it cannot end the run by itself.
pub async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "could not install the SIGINT handler");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "could not install the SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
