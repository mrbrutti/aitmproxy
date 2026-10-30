//! Task 11 acceptance tests for the opt-in loopback L4 service
//! (L4OPS-AC13/AC14): a bounded UDP echo responder + a minimal TCP service that
//! give the L4 capabilities a real, in-scope target to act on.
//!
//! These tests bind loopback sockets, so the Rust gate for this crate runs in
//! the Terminal panel (port binding is EPERM in the Bash sandbox), matching the
//! crate's existing HTTP-target tests.

use std::time::Duration;

use aitm_testtarget::{l4_manifest, L4Config, L4Service};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// A loopback UDP datagram to the service comes back echoed, byte for byte, from
/// the service's own address — real L4-observable behaviour, bounded.
#[tokio::test]
async fn l4_service_echoes() {
    let svc = L4Service::start(L4Config { enabled: true })
        .await
        .expect("enabled service starts");

    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let payload = b"aitm-l4-probe";
    client
        .send_to(payload, svc.udp_addr())
        .await
        .expect("send datagram");

    let mut buf = [0u8; 64];
    let (n, from) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("reply within timeout")
        .expect("recv reply");

    assert_eq!(&buf[..n], payload, "echo returns the payload unchanged");
    assert_eq!(from, svc.udp_addr(), "reply comes from the service address");
}

/// The service is OFF by default and only starts when its flag is set; the
/// grader-only manifest marks the L4 assets in-scope on loopback.
#[tokio::test]
async fn l4_service_opt_in() {
    assert!(!L4Config::default().enabled, "disabled by default");
    assert!(
        L4Service::start(L4Config::default()).await.is_none(),
        "service must not bind when disabled",
    );
    assert!(
        L4Service::start(L4Config { enabled: true }).await.is_some(),
        "service binds only when the flag is set",
    );

    let assets = l4_manifest();
    assert!(!assets.is_empty(), "manifest declares the L4 assets");
    assert!(
        assets.iter().all(|a| a.in_scope),
        "every L4 asset is in-scope"
    );
    assert!(
        assets.iter().all(|a| a.bind == "127.0.0.1"),
        "every L4 asset is bound to loopback",
    );
    assert!(
        assets.iter().any(|a| a.proto == "udp"),
        "a UDP asset exists"
    );
    assert!(
        assets.iter().any(|a| a.proto == "tcp"),
        "a TCP asset exists"
    );
}

/// The minimal TCP service is L4-observable: a bare connect yields a banner, and
/// a bounded write is echoed back.
#[tokio::test]
async fn l4_tcp_service_responds() {
    let svc = L4Service::start(L4Config { enabled: true })
        .await
        .expect("enabled service starts");

    let mut stream = TcpStream::connect(svc.tcp_addr())
        .await
        .expect("connect tcp service");

    let mut banner = [0u8; 32];
    let n = timeout(Duration::from_secs(2), stream.read(&mut banner))
        .await
        .expect("banner within timeout")
        .expect("read banner");
    assert!(n > 0, "connect yields a banner");
    assert!(
        banner[..n].starts_with(b"aitm-l4"),
        "banner identifies the L4 service",
    );
}
