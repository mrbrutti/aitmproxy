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
pub mod oneshot;
pub mod operator_bus;
pub mod operator_token;
pub mod render;
pub mod scripts;
pub mod startup;
pub mod tui;
pub mod web;
pub mod wire;

use std::sync::Arc;

use futures::{Stream, StreamExt};
use tracing::{info, warn};

/// The packet-capture prompt hold as the shutdown futures consult it (L4
/// privilege spec §5.5, panel 2): `is_held` says a launcher child (a pkexec
/// prompt) is alive, `cancel` sends that child the Ctrl-C the core alone
/// received. `main` builds one over the privilege state's `HoldCount` and
/// `PrivilegeState::cancel_prompt` and hands a clone to every serving
/// shutdown future (server, capture session, `aitm tui`).
#[derive(Clone)]
pub struct PromptHold {
    held: Arc<dyn Fn() -> bool + Send + Sync>,
    cancel: Arc<dyn Fn() + Send + Sync>,
}

impl PromptHold {
    /// A hold read through `held`, cancelled through `cancel`.
    pub fn new(
        held: impl Fn() -> bool + Send + Sync + 'static,
        cancel: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        PromptHold {
            held: Arc::new(held),
            cancel: Arc::new(cancel),
        }
    }

    /// Never held; cancels nothing. For a process that spawns no prompt.
    #[must_use]
    pub fn none() -> Self {
        Self::new(|| false, || {})
    }

    /// A prompt is up right now.
    #[must_use]
    pub fn is_held(&self) -> bool {
        (self.held)()
    }

    /// Cancel the prompt (a no-op when none is up).
    pub fn cancel(&self) {
        (self.cancel)();
    }
}

impl std::fmt::Debug for PromptHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptHold")
            .field("held", &self.is_held())
            .finish_non_exhaustive()
    }
}

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM. A handler that cannot be
/// installed is logged and never fires, so it cannot end the run by itself.
pub async fn shutdown_signal() {
    shutdown_signal_unless_held(PromptHold::none()).await;
}

/// [`shutdown_signal`] for a core that may have a packet-capture prompt up
/// (L4 privilege spec §5.5): a Ctrl-C that arrives while `hold.is_held()`
/// (the state's `HoldCount` has a launcher child alive) cancels the prompt
/// only: it is logged, `hold.cancel()` sends the child SIGINT in case the
/// Ctrl-C reached the core alone, and the core keeps serving. The next
/// Ctrl-C once the hold is released ends the run as before. SIGTERM is
/// unaffected.
pub async fn shutdown_signal_unless_held(hold: PromptHold) {
    let held = || hold.is_held();
    let on_held = || hold.cancel();
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
                    interrupt_unless_held(events, held, on_held).await;
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
            interrupt_unless_held(events, held, on_held).await;
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

/// Resolves on the first interrupt event that arrives while `held()` is
/// false. An event while held is logged once each, answered with one
/// `on_held()` (the prompt's cancel) and swallowed. A stream that ends (no
/// handler) never resolves this future, so it cannot end the run by itself.
/// Generic over the event source so it is testable without real signals.
pub async fn interrupt_unless_held(
    events: impl Stream<Item = ()>,
    held: impl Fn() -> bool,
    on_held: impl Fn(),
) {
    let mut events = std::pin::pin!(events);
    loop {
        match events.next().await {
            None => std::future::pending::<()>().await,
            // A Ctrl-C ends the run unless a packet-capture prompt holds it.
            Some(()) if !held() => return,
            Some(()) => {
                info!("Ctrl-C cancelled the packet-capture prompt; the core keeps serving");
                on_held();
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
        let fut = interrupt_unless_held(rx, is_held, || {});
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
        let fut = interrupt_unless_held(futures::stream::empty::<()>(), || false, || {});
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut fut)
            .await
            .is_err());
    }

    // ---- tester, fix range (p1b panel I2): the hold as the operator meets it ----

    /// A sink the fmt subscriber writes into, so a test can read the log line.
    #[derive(Clone, Default)]
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// Plan P1b.14 `held_ctrl_c_keeps_serving` (spec §5.5 as corrected by the
    /// panel): every Ctrl-C that arrives while the hold is up is swallowed and
    /// logged with exactly the spec's line, once each; releasing the hold
    /// replays none of them (the core keeps serving until a *new* Ctrl-C);
    /// the first Ctrl-C after the release ends the run and is not logged as a
    /// cancelled prompt.
    #[tokio::test]
    async fn held_ctrl_c_keeps_serving() {
        const LINE: &str = "Ctrl-C cancelled the packet-capture prompt; the core keeps serving";
        let sink = Sink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        let _default = tracing::subscriber::set_default(subscriber);

        let (tx, rx) = futures::channel::mpsc::unbounded::<()>();
        let held = Arc::new(AtomicBool::new(true));
        let is_held = {
            let held = Arc::clone(&held);
            move || held.load(Ordering::SeqCst)
        };
        // C4 (p1b panel 2): every swallowed Ctrl-C also cancels the prompt.
        let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let on_held = {
            let cancelled = Arc::clone(&cancelled);
            move || {
                cancelled.fetch_add(1, Ordering::SeqCst);
            }
        };
        let fut = interrupt_unless_held(rx, is_held, on_held);
        tokio::pin!(fut);

        for _ in 0..3 {
            tx.unbounded_send(()).expect("ctrl-c while held");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut fut)
                .await
                .is_err(),
            "three Ctrl-Cs while held must not end the run"
        );
        let text = sink.text();
        assert_eq!(
            text.matches(LINE).count(),
            3,
            "one spec line per swallowed Ctrl-C, verbatim: {text:?}"
        );
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            3,
            "the prompt is cancelled once per swallowed Ctrl-C"
        );

        held.store(false, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut fut)
                .await
                .is_err(),
            "releasing the hold replays no swallowed Ctrl-C"
        );

        tx.unbounded_send(()).expect("ctrl-c after release");
        tokio::time::timeout(Duration::from_secs(5), &mut fut)
            .await
            .expect("the first Ctrl-C after the release ends the run");
        assert_eq!(
            sink.text().matches(LINE).count(),
            3,
            "the Ctrl-C that ends the run is not logged as a cancelled prompt"
        );
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            3,
            "the Ctrl-C that ends the run cancels no prompt"
        );
    }

    /// C4 (p1b panel 2): `PromptHold` is what `main` hands every shutdown
    /// arm; `is_held` and `cancel` delegate to the closures it was built
    /// from, and `none()` is never held and cancels nothing.
    #[test]
    fn prompt_hold_delegates_to_its_closures() {
        let held = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hold = PromptHold::new(
            {
                let held = Arc::clone(&held);
                move || held.load(Ordering::SeqCst)
            },
            {
                let cancelled = Arc::clone(&cancelled);
                move || {
                    cancelled.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        assert!(!hold.is_held());
        held.store(true, Ordering::SeqCst);
        assert!(hold.is_held());
        let clone = hold.clone();
        clone.cancel();
        hold.cancel();
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            2,
            "a clone shares the target"
        );

        let none = PromptHold::none();
        assert!(!none.is_held());
        none.cancel();
    }
}
