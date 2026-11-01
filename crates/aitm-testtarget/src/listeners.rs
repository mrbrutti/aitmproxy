//! The one TCP accept loop behind the plain, TLS and control listeners:
//! accept, hand the connection to its handler on its own task, and on an
//! accept error back off [`SOCKET_ERROR_BACKOFF`] instead of spinning hot
//! (EMFILE, a closed socket). The L4 driver keeps its `select!`-based loop
//! (it must also watch the crash window) but uses the same back-off.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// Back-off after an `accept` / `recv_from` error so a persistent failure
/// cannot spin the task.
pub(crate) const SOCKET_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Serve `listener` until the task is dropped: every accepted connection runs
/// `on_conn` on its own task; an accept error sleeps [`SOCKET_ERROR_BACKOFF`]
/// and tries again.
pub(crate) async fn accept_loop<F, Fut>(listener: TcpListener, on_conn: F)
where
    F: Fn(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = &listener;
    drive(|| listener.accept(), on_conn).await
}

/// The loop over any accept source, so the back-off is provable without a
/// socket (the unit test scripts the errors and watches the clock).
async fn drive<S, A, AFut, F, Fut>(mut accept: A, on_conn: F)
where
    A: FnMut() -> AFut,
    AFut: Future<Output = io::Result<(S, SocketAddr)>>,
    F: Fn(S, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match accept().await {
            Ok((stream, peer)) => {
                tokio::spawn(on_conn(stream, peer));
            }
            Err(_) => sleep(SOCKET_ERROR_BACKOFF).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::time::{timeout, Instant};

    use super::*;

    type Accepted = io::Result<(u8, SocketAddr)>;

    #[tokio::test]
    async fn accept_errors_back_off_and_accepted_conns_are_served() {
        let peer: SocketAddr = "127.0.0.1:7".parse().expect("literal addr");
        let attempts: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let served = Arc::new(AtomicUsize::new(0));
        // Two accept failures, one connection, then nothing ever again.
        let script: Arc<Mutex<VecDeque<Accepted>>> = Arc::new(Mutex::new(VecDeque::from([
            Err(io::Error::from_raw_os_error(24)), // EMFILE
            Err(io::Error::other("closed")),
            Ok((7u8, peer)),
        ])));

        let accept = {
            let attempts = attempts.clone();
            let script = script.clone();
            move || {
                attempts.lock().expect("attempts").push(Instant::now());
                let next = script.lock().expect("script").pop_front();
                Box::pin(async move {
                    match next {
                        Some(result) => result,
                        None => std::future::pending().await,
                    }
                }) as Pin<Box<dyn Future<Output = Accepted>>>
            }
        };
        let on_conn = {
            let served = served.clone();
            move |stream: u8, from: SocketAddr| {
                let served = served.clone();
                async move {
                    assert_eq!(stream, 7);
                    assert_eq!(from, peer);
                    served.fetch_add(1, Ordering::SeqCst);
                }
            }
        };

        // Real clock (the crate's tokio has no `test-util`): the loop parks
        // on the fourth accept, so the timeout is what ends it.
        let outcome = timeout(Duration::from_millis(500), drive(accept, on_conn)).await;
        assert!(outcome.is_err(), "the loop never returns on its own");

        let attempts = attempts.lock().expect("attempts");
        assert_eq!(attempts.len(), 4, "err, err, ok, then parked: {attempts:?}");
        // Each error is followed by at least the back-off before the next
        // accept. Only lower bounds are asserted: an upper bound on the
        // accept-after-Ok gap would flake on a loaded machine; that the loop
        // reached its fourth accept inside the 500 ms timeout (four attempts
        // above) is the proof it did not back off after the accepted
        // connection.
        assert!(
            attempts[1] - attempts[0] >= SOCKET_ERROR_BACKOFF,
            "{attempts:?}"
        );
        assert!(
            attempts[2] - attempts[1] >= SOCKET_ERROR_BACKOFF,
            "{attempts:?}"
        );
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(SOCKET_ERROR_BACKOFF, Duration::from_millis(10));
    }
}
