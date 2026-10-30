//! An opt-in loopback L4 service for the test target (L4OPS-AC13/AC14).
//!
//! M4 ships this crate as a hermetic in-scope *HTTP* target. The L4 operator
//! surfaces need a real L4 asset to act on, so this module adds — behind an
//! explicit, **off-by-default** flag — a bounded UDP echo responder and a
//! minimal TCP service, both bound to `127.0.0.1`. Together they give every L4
//! capability something real:
//!
//! - **capture** sees real loopback frames;
//! - **craft → inject** places a real packet the capture then observes;
//! - **send_recv** elicits a real reply (the UDP echo / TCP banner);
//! - **in-path intercept** (Linux) can park/mutate/forward/drop a real packet
//!   on the service's port.
//!
//! It stays hermetic and in-scope by construction: it binds only loopback, never
//! opens an outbound socket, and is declared in the grader-only
//! [`l4_manifest`](crate::l4_manifest). It is **bounded**: fixed per-frame
//! buffers, it never sends more than it received (no amplification), and its
//! loops are event-driven and aborted when the [`L4Service`] is dropped.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// Largest datagram / TCP read the service handles. Bounds memory and, since the
/// service only ever echoes what it received, caps any reply at this size too.
const MAX_FRAME: usize = 1500;

/// Banner the TCP service writes on connect, so even a bare connect is already
/// L4-observable for capture.
const TCP_BANNER: &[u8] = b"aitm-l4-tcp\n";

/// Configuration for the opt-in L4 service.
///
/// **Off by default.** The service only binds when `enabled` is set, mirroring
/// the crate's opt-in, test-support stance: nothing listens unless a test (or an
/// authorized operator run) asks for it.
#[derive(Debug, Clone, Default)]
pub struct L4Config {
    /// When `false` (the default), [`L4Service::start`] returns `None` and binds
    /// nothing.
    pub enabled: bool,
}

/// A running loopback L4 service: a UDP echo responder and a minimal TCP service.
///
/// Dropping it aborts the accept/recv loops, so the service lives exactly as long
/// as the handle.
pub struct L4Service {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl L4Service {
    /// Bind the UDP and TCP services on fresh loopback ports and start serving —
    /// but only when `config.enabled`. Returns `None` when disabled (the
    /// default), so the service is opt-in by construction.
    pub async fn start(config: L4Config) -> Option<L4Service> {
        if !config.enabled {
            return None;
        }

        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind loopback udp service");
        let udp_addr = udp.local_addr().expect("udp local addr");

        let tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback tcp service");
        let tcp_addr = tcp.local_addr().expect("tcp local addr");

        let tasks = vec![tokio::spawn(udp_echo(udp)), tokio::spawn(tcp_serve(tcp))];

        Some(L4Service {
            udp_addr,
            tcp_addr,
            tasks,
        })
    }

    /// The `127.0.0.1:PORT` the UDP echo responder is bound to.
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_addr
    }

    /// The `127.0.0.1:PORT` the minimal TCP service is listening on.
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_addr
    }
}

impl Drop for L4Service {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Echo each datagram back to its sender, byte for byte and never more. The loop
/// is event-driven and ends when the socket errors (e.g. on task abort).
async fn udp_echo(sock: UdpSocket) {
    let mut buf = [0u8; MAX_FRAME];
    // Ends when the socket errors (e.g. on task abort).
    while let Ok((n, from)) = sock.recv_from(&mut buf).await {
        let _ = sock.send_to(&buf[..n], from).await;
    }
}

/// Accept loopback connections; each gets a banner on connect, then one bounded
/// echoed read, then a clean shutdown.
async fn tcp_serve(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            if stream.write_all(TCP_BANNER).await.is_err() {
                return;
            }
            let mut buf = [0u8; MAX_FRAME];
            if let Ok(n) = stream.read(&mut buf).await {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            }
            let _ = stream.shutdown().await;
        });
    }
}
