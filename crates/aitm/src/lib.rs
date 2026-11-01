//! `aitm` — the binary's reusable assembly. `wire::assemble` turns a `Config`
//! into a running-ready `Proxy` plus the CA it serves with; `main` drives it.
//! `env` bridges the process environment into `Config`; `render` prints a
//! command's result for the CLI; `web` is the `aitm web` static host and
//! `/bus` WebSocket bridge (F15); `audit_log` is the durable audit writer (the
//! JSONL files every audited command is appended to). Kept as a library so the
//! wiring is testable (AC-P3/AC-P4, CA-AC27) without the process entrypoint.

pub mod audit_log;
pub mod bundled;
pub mod config_file;
pub mod env;
pub mod ingress;
pub mod macos_capture;
pub mod operator_token;
pub mod render;
pub mod scripts;
pub mod tui;
pub mod web;
pub mod wire;

use futures::{Stream, StreamExt};
use tracing::{info, warn};

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM. A handler that cannot be
/// installed is logged and never fires, so it cannot end the run by itself.
pub async fn shutdown_signal() {
    shutdown_signal_unless_held(|| false).await;
}

/// [`shutdown_signal`] for a core that may have a packet-capture prompt up
/// (L4 privilege spec §5.5): a Ctrl-C that arrives while `held()` is true
/// (the state's `HoldCount` has a launcher child alive) cancels the prompt
/// only; it is logged and the core keeps serving. The next Ctrl-C once the
/// hold is released ends the run as before. SIGTERM is unaffected.
pub async fn shutdown_signal_unless_held(held: impl Fn() -> bool) {
    let interrupt = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::interrupt()) {
                Ok(sigint) => {
                    // One stream for the whole run, so no Ctrl-C between two
                    // waits is lost.
                    let events = futures::stream::unfold(sigint, |mut sigint| async move {
                        sigint.recv().await.map(|()| ((), sigint))
                    });
                    interrupt_unless_held(events, held).await;
                }
                Err(e) => {
                    warn!(error = %e, "could not install the SIGINT handler");
                    std::future::pending::<()>().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let events = futures::stream::unfold((), |()| async move {
                tokio::signal::ctrl_c().await.ok().map(|()| ((), ()))
            });
            interrupt_unless_held(events, held).await;
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

/// The decision behind [`shutdown_signal_unless_held`]: a Ctrl-C ends the run
/// unless a packet-capture prompt holds it.
#[must_use]
pub fn should_shut_down(held: bool) -> bool {
    !held
}

/// Resolves on the first interrupt event that arrives while `held()` is
/// false. An event while held is logged once each and swallowed. A stream
/// that ends (no handler) never resolves this future, so it cannot end the
/// run by itself. Generic over the event source so it is testable without
/// real signals.
pub async fn interrupt_unless_held(events: impl Stream<Item = ()>, held: impl Fn() -> bool) {
    let mut events = std::pin::pin!(events);
    loop {
        match events.next().await {
            None => std::future::pending::<()>().await,
            Some(()) if should_shut_down(held()) => return,
            Some(()) => {
                info!("Ctrl-C cancelled the packet-capture prompt; the core keeps serving");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// L4 privilege spec §5.5 (P1b.14 correction): Ctrl-C ends the run unless
    /// a packet-capture prompt holds it.
    #[test]
    fn ctrl_c_shuts_down_only_when_not_held() {
        assert!(should_shut_down(false));
        assert!(!should_shut_down(true));
    }

    /// The interrupt future over an injected event stream: the first Ctrl-C
    /// while held is swallowed (the core keeps serving); the next one, once
    /// the hold is released, resolves it.
    #[tokio::test]
    async fn interrupt_is_swallowed_while_held_and_ends_the_run_once_released() {
        let (tx, rx) = futures::channel::mpsc::unbounded::<()>();
        let held = Arc::new(AtomicBool::new(true));
        let is_held = {
            let held = Arc::clone(&held);
            move || held.load(Ordering::SeqCst)
        };
        let fut = interrupt_unless_held(rx, is_held);
        tokio::pin!(fut);

        tx.unbounded_send(()).expect("first ctrl-c");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut fut)
                .await
                .is_err(),
            "a Ctrl-C while held must not end the run"
        );

        held.store(false, Ordering::SeqCst);
        tx.unbounded_send(()).expect("second ctrl-c");
        tokio::time::timeout(Duration::from_secs(5), &mut fut)
            .await
            .expect("the Ctrl-C after release ends the run");
    }

    /// An event stream that ends (the handler could not be installed) never
    /// resolves the future by itself.
    #[tokio::test]
    async fn an_ended_interrupt_stream_never_shuts_down() {
        let fut = interrupt_unless_held(futures::stream::empty::<()>(), || false);
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut fut)
            .await
            .is_err());
    }
}
