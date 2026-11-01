//! Live socket suite for the nine L4 speakers (spec D5 / S5, plan Task A22).
//!
//! Against a real in-process target (`TestTarget::builder(mode).control(0)
//! .l4(true)`), for every D5 row: the benign and liveness exchanges return
//! the row's bytes; in Vulnerable mode the trigger closes the connection, the
//! service is down (TCP connect refused / UDP silent) for the 5 s crash
//! window and back on the same port by +6 s, with exactly one `downtime`
//! entry in `/log/l4`; in Patched mode the same trigger gets the row's
//! protocol-error reply, the speaker closes with reason `error`, the listener
//! stays up and `downtime` is empty. Plus the D5 denylist observation and an
//! MQTT CONNECT / PUBLISH / DISCONNECT session.
//!
//! Binds loopback ports, so it runs in the Terminal panel, never in the Bash
//! sandbox (bind is EPERM there). The per-service flows run concurrently
//! (each service has its own 5 s window) so the suite stays well under the
//! plan's 3 minute budget; a failure names its service.

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use aitm_testtarget::speakers::Proto;
use aitm_testtarget::{SeedMode, TestTarget};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// How long `udp_exchange` waits for a reply (plan A22: 200 ms).
const UDP_WAIT: Duration = Duration::from_millis(200);
/// Read idle after which a TCP exchange's reply is considered complete.
const REPLY_IDLE: Duration = Duration::from_millis(300);
/// A triggered connection must be closed by the speaker within this.
const CLOSE_WITHIN: Duration = Duration::from_secs(1);
/// A V-triggered service must refuse / fall silent within this of the trigger.
const DOWN_WITHIN: Duration = Duration::from_millis(500);
/// Still down here (spec S5: "for the next 4 s").
const STILL_DOWN_AT: Duration = Duration::from_secs(4);
/// The crash window itself (spec D5).
const WINDOW: Duration = Duration::from_secs(5);
/// Liveness must work again by here (spec S5: "within 6 s").
const UP_BY: Duration = Duration::from_secs(6);
/// `up_at_ms - down_at_ms` the `downtime` entry must record.
const WINDOW_MS: u64 = 5000;
/// Connect / banner budget for a service that is supposed to be up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

type Res<T> = Result<T, String>;

// --- The D5 table -----------------------------------------------------------

/// One D5 row as the suite drives it over a socket.
struct Case {
    service: &'static str,
    proto: Proto,
    /// Greeting read (and checked) before anything is sent; the line
    /// speakers SMTP and FTP.
    banner: Option<&'static [u8]>,
    benign_send: Vec<u8>,
    benign_expect: Vec<u8>,
    liveness_send: Vec<u8>,
    liveness_expect: Vec<u8>,
    trigger_send: Vec<u8>,
    /// Patched-mode answer to the trigger: `Some(bytes)` written before the
    /// close (TCP) or sent back (UDP); `None` = closes with no bytes (MQTT).
    p_expect: Option<Vec<u8>>,
    /// `classified` of the trigger message in Patched mode.
    p_classified: &'static str,
}

const SMTP_BANNER: &[u8] = b"220 target.test ESMTP aitm\r\n";
const FTP_BANNER: &[u8] = b"220 aitm ftp\r\n";

/// MQTT CONNECT (`MQTT`, level 4, clean session, keep-alive 60, empty id).
const MQTT_CONNECT: [u8; 14] = [
    0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
];
const MQTT_CONNACK: [u8; 4] = [0x20, 0x02, 0x00, 0x00];
/// PUBLISH QoS 1, topic `a/b`, packet id 1, payload `hi` (spec D5, corrected
/// remaining length `09`).
const MQTT_PUBLISH_QOS1: [u8; 11] = [
    0x32, 0x09, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x00, 0x01, 0x68, 0x69,
];
const MQTT_PUBACK: [u8; 4] = [0x40, 0x02, 0x00, 0x01];
const MQTT_DISCONNECT: [u8; 2] = [0xE0, 0x00];

/// The over-long line trigger of the line speakers, in T6's shape: one write
/// of 4096 `a`s plus CRLF (past every line cap, 1024 or 2048).
fn long_line() -> Vec<u8> {
    let mut line = vec![b'a'; 4096];
    line.extend_from_slice(b"\r\n");
    line
}

/// The nine D5 rows, in table order.
fn cases() -> Vec<Case> {
    vec![
        Case {
            service: "l4-tlv-crash",
            proto: Proto::Tcp,
            banner: None,
            benign_send: vec![0x00, 0x03, 0x61, 0x62, 0x63],
            benign_expect: vec![0x00, 0x03, 0x61, 0x62, 0x63],
            liveness_send: vec![0x00, 0x00],
            liveness_expect: vec![0x00, 0x00],
            // Declared length 65 535 > 4096.
            trigger_send: vec![0xFF, 0xFF],
            p_expect: Some(vec![0x00, 0x03, 0x45, 0x52, 0x52]),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-dns-fault",
            proto: Proto::Udp,
            banner: None,
            // A query, id 0x1234, `example.test`.
            benign_send: vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01,
                0x00, 0x01,
            ],
            benign_expect: vec![
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01,
                0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
                0x7f, 0x00, 0x00, 0x01,
            ],
            // A query for `.`.
            liveness_send: vec![
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x01,
            ],
            liveness_expect: vec![
                0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
                0x04, 0x7f, 0x00, 0x00, 0x01,
            ],
            // Label length 63 with two bytes left in the datagram.
            trigger_send: vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x61,
                0x62,
            ],
            // FORMERR: id, flags 81 81, zero counts.
            p_expect: Some(vec![
                0x12, 0x34, 0x81, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-udp-payload-crash",
            proto: Proto::Udp,
            banner: None,
            benign_send: vec![0x61, 0x62, 0x63],
            benign_expect: vec![0x61, 0x62, 0x63],
            liveness_send: vec![0x61, 0x62, 0x63],
            liveness_expect: vec![0x61, 0x62, 0x63],
            // `DE AD BE EF` prefix, 8 bytes (AC T5-2b).
            trigger_send: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],
            // P echoes it like any other datagram.
            p_expect: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]),
            p_classified: "ok",
        },
        Case {
            service: "l4-resp",
            proto: Proto::Tcp,
            banner: None,
            benign_send: b"*1\r\n$4\r\nPING\r\n".to_vec(),
            benign_expect: b"+PONG\r\n".to_vec(),
            liveness_send: b"PING\r\n".to_vec(),
            liveness_expect: b"+PONG\r\n".to_vec(),
            // Bulk length 2 000 000 > 1 048 576.
            trigger_send: b"*1\r\n$2000000\r\n".to_vec(),
            p_expect: Some(b"-ERR Protocol error: invalid bulk length\r\n".to_vec()),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-memcached",
            proto: Proto::Tcp,
            banner: None,
            benign_send: b"version\r\n".to_vec(),
            benign_expect: b"VERSION 1.6.0-aitm\r\n".to_vec(),
            liveness_send: b"version\r\n".to_vec(),
            liveness_expect: b"VERSION 1.6.0-aitm\r\n".to_vec(),
            // 4096 `a`s + CRLF: past the 2048 line cap.
            trigger_send: long_line(),
            p_expect: Some(b"CLIENT_ERROR line too long\r\n".to_vec()),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-modbus",
            proto: Proto::Tcp,
            banner: None,
            // fc 3, unit 1, addr 0, qty 1.
            benign_send: vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
            ],
            benign_expect: vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00,
            ],
            liveness_send: vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
            ],
            liveness_expect: vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x00,
            ],
            // MBAP length 0x0105 = 261 > 260.
            trigger_send: vec![
                0x00, 0x03, 0x00, 0x00, 0x01, 0x05, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
            ],
            // Exception 0x03 on fc 3: `<tid> 00 00 00 03 01 83 03`.
            p_expect: Some(vec![0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x03]),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-mqtt",
            proto: Proto::Tcp,
            banner: None,
            benign_send: MQTT_CONNECT.to_vec(),
            benign_expect: MQTT_CONNACK.to_vec(),
            // CONNECT + DISCONNECT in one write: CONNACK, then the speaker
            // closes.
            liveness_send: [&MQTT_CONNECT[..], &MQTT_DISCONNECT[..]].concat(),
            liveness_expect: MQTT_CONNACK.to_vec(),
            // Remaining-length varint whose 4th byte still continues (a 5th
            // byte would be needed).
            trigger_send: vec![0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
            // MQTT has no error reply: close with no bytes.
            p_expect: None,
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-smtp",
            proto: Proto::Tcp,
            banner: Some(SMTP_BANNER),
            benign_send: b"EHLO x\r\n".to_vec(),
            benign_expect: b"250 target.test\r\n".to_vec(),
            liveness_send: b"NOOP\r\n".to_vec(),
            liveness_expect: b"250 OK\r\n".to_vec(),
            trigger_send: long_line(),
            p_expect: Some(b"500 line too long\r\n".to_vec()),
            p_classified: "protocol_error",
        },
        Case {
            service: "l4-ftp",
            proto: Proto::Tcp,
            banner: Some(FTP_BANNER),
            benign_send: b"USER a\r\n".to_vec(),
            benign_expect: b"331 password required\r\n".to_vec(),
            liveness_send: b"NOOP\r\n".to_vec(),
            liveness_expect: b"200 ok\r\n".to_vec(),
            trigger_send: long_line(),
            p_expect: Some(b"500 line too long\r\n".to_vec()),
            p_classified: "protocol_error",
        },
    ]
}

// --- Socket helpers -----------------------------------------------------------

/// Connect to a TCP speaker and, when it greets, read and check the banner.
async fn tcp_open(addr: SocketAddr, banner: Option<&[u8]>) -> Res<TcpStream> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect {addr} timed out"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;
    if let Some(banner) = banner {
        let mut got = vec![0u8; banner.len()];
        timeout(CONNECT_TIMEOUT, stream.read_exact(&mut got))
            .await
            .map_err(|_| "banner timed out".to_string())?
            .map_err(|e| format!("banner read: {e}"))?;
        if got != banner {
            return Err(format!("banner {} != {}", hex(&got), hex(banner)));
        }
    }
    Ok(stream)
}

/// Read until the peer closes (`closed == true`; a read error counts as a
/// close) or `idle` passes without bytes (`closed == false`).
async fn read_until_idle(stream: &mut TcpStream, idle: Duration) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match timeout(idle, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (out, true),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_elapsed) => return (out, false),
        }
    }
}

/// Write `send` on an open connection and collect the reply.
async fn exchange(stream: &mut TcpStream, send: &[u8], read_timeout: Duration) -> Res<Vec<u8>> {
    stream
        .write_all(send)
        .await
        .map_err(|e| format!("write: {e}"))?;
    Ok(read_until_idle(stream, read_timeout).await.0)
}

/// One fresh-connection TCP exchange: connect, read the banner if any, send,
/// collect the reply until `read_timeout` of idle or the close.
async fn tcp_exchange(
    addr: SocketAddr,
    banner: Option<&[u8]>,
    send: &[u8],
    read_timeout: Duration,
) -> Res<Vec<u8>> {
    let mut stream = tcp_open(addr, banner).await?;
    exchange(&mut stream, send, read_timeout).await
}

/// One datagram to `addr`; `None` when nothing came back within 200 ms (a
/// recv error, e.g. ICMP unreachable, counts as no answer).
async fn udp_exchange(addr: SocketAddr, send: &[u8]) -> Res<Option<Vec<u8>>> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind udp client: {e}"))?;
    socket
        .send_to(send, addr)
        .await
        .map_err(|e| format!("send_to {addr}: {e}"))?;
    let mut buf = vec![0u8; 65_535];
    match timeout(UDP_WAIT, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _peer))) => Ok(Some(buf[..n].to_vec())),
        Ok(Err(_)) | Err(_) => Ok(None),
    }
}

/// Whether a TCP connect to `addr` is refused right now (no listener).
async fn connect_refused(addr: SocketAddr) -> bool {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionRefused,
        _ => false,
    }
}

/// `GET /log/l4?service=<service>` on the control origin; returns that
/// service's object (`accepts`, `messages`, `closes`, `downtime`).
async fn l4_log(control_url: &str, service: &str) -> Res<Value> {
    let host = control_url
        .strip_prefix("http://")
        .ok_or_else(|| format!("control url {control_url:?} is not http://"))?;
    let addr: SocketAddr = host
        .parse()
        .map_err(|e| format!("control addr {host:?}: {e}"))?;
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "control connect timed out".to_string())?
        .map_err(|e| format!("control connect: {e}"))?;
    let request = format!(
        "GET /log/l4?service={service} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("control write: {e}"))?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .map_err(|_| "control read timed out".to_string())?
        .map_err(|e| format!("control read: {e}"))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("control reply has no header/body split: {}", lossy(&raw)))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("control status: {head}"));
    }
    let body: Value =
        serde_json::from_slice(&raw[split + 4..]).map_err(|e| format!("control json: {e}"))?;
    body.get("services")
        .and_then(|s| s.get(service))
        .cloned()
        .ok_or_else(|| format!("/log/l4 has no entry for {service}: {body}"))
}

// --- Per-case flows -------------------------------------------------------------

/// One request/reply against the case's service, TCP (banner first) or UDP.
async fn exchange_case(case: &Case, addr: SocketAddr, send: &[u8]) -> Res<Option<Vec<u8>>> {
    match case.proto {
        Proto::Tcp => tcp_exchange(addr, case.banner, send, REPLY_IDLE)
            .await
            .map(Some),
        Proto::Udp => udp_exchange(addr, send).await,
    }
}

/// The exchange must return exactly `expect`.
async fn expect_exchange(
    case: &Case,
    addr: SocketAddr,
    send: &[u8],
    expect: &[u8],
    what: &str,
) -> Res<()> {
    let got = exchange_case(case, addr, send).await?;
    match got {
        Some(bytes) if bytes == expect => Ok(()),
        Some(bytes) => Err(format!(
            "{what}: got {} expected {}",
            hex(&bytes),
            hex(expect)
        )),
        None => Err(format!("{what}: no reply, expected {}", hex(expect))),
    }
}

/// Send the trigger over TCP; returns what the speaker wrote back, whether
/// it closed within 1 s, and our local address (the `peer` in `accepts`).
async fn tcp_trigger(case: &Case, addr: SocketAddr) -> Res<(Vec<u8>, bool, SocketAddr)> {
    let mut stream = tcp_open(addr, case.banner).await?;
    let local = stream
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    stream
        .write_all(&case.trigger_send)
        .await
        .map_err(|e| format!("trigger write: {e}"))?;
    let (bytes, closed) = read_until_idle(&mut stream, CLOSE_WITHIN).await;
    Ok((bytes, closed, local))
}

/// Whether the service is down right now: TCP connect refused, UDP liveness
/// unanswered.
async fn is_down(case: &Case, addr: SocketAddr) -> Res<bool> {
    Ok(match case.proto {
        Proto::Tcp => connect_refused(addr).await,
        Proto::Udp => udp_exchange(addr, &case.liveness_send).await?.is_none(),
    })
}

async fn sleep_until(deadline: Instant) {
    sleep(deadline.saturating_duration_since(Instant::now())).await;
}

/// Spec S5, Vulnerable half: benign, liveness, trigger closes, down within
/// 500 ms, still down at +4 s, up by +6 s, one 5000 ms `downtime` entry and
/// one `trigger` message.
async fn vulnerable_flow(case: Case, addr: SocketAddr, control: String) -> Res<()> {
    expect_exchange(
        &case,
        addr,
        &case.benign_send,
        &case.benign_expect,
        "benign",
    )
    .await?;
    expect_exchange(
        &case,
        addr,
        &case.liveness_send,
        &case.liveness_expect,
        "liveness",
    )
    .await?;

    let t0 = Instant::now();
    match case.proto {
        Proto::Tcp => {
            let (bytes, closed, _local) = tcp_trigger(&case, addr).await?;
            if !closed {
                return Err("trigger: connection still open after 1 s".to_string());
            }
            if !bytes.is_empty() {
                return Err(format!("trigger: V wrote {} before closing", hex(&bytes)));
            }
        }
        Proto::Udp => {
            if let Some(reply) = udp_exchange(addr, &case.trigger_send).await? {
                return Err(format!("trigger: V answered {}", hex(&reply)));
            }
        }
    }

    // Refused / silent within 500 ms of the trigger.
    let down_deadline = t0 + DOWN_WITHIN;
    loop {
        if is_down(&case, addr).await? {
            break;
        }
        if Instant::now() >= down_deadline {
            return Err("not down within 500 ms of the trigger".to_string());
        }
        sleep(Duration::from_millis(20)).await;
    }

    // Still down at +4 s.
    sleep_until(t0 + STILL_DOWN_AT).await;
    if !is_down(&case, addr).await? {
        return Err("back up before +4 s".to_string());
    }

    // Up again, on the same port, by +6 s.
    sleep_until(t0 + WINDOW).await;
    let up_deadline = t0 + UP_BY;
    loop {
        let last = match exchange_case(&case, addr, &case.liveness_send).await {
            Ok(Some(bytes)) if bytes == case.liveness_expect => break,
            Ok(Some(bytes)) => format!("liveness got {}", hex(&bytes)),
            Ok(None) => "liveness unanswered".to_string(),
            Err(e) => e,
        };
        if Instant::now() >= up_deadline {
            return Err(format!("not up by +6 s; last: {last}"));
        }
        sleep(Duration::from_millis(100)).await;
    }

    // The log: one downtime of exactly 5000 ms, one trigger message.
    let log = l4_log(&control, case.service).await?;
    let downtime = array(&log, "downtime")?;
    if downtime.len() != 1 {
        return Err(format!(
            "downtime has {} entries: {downtime:?}",
            downtime.len()
        ));
    }
    let entry = &downtime[0];
    let down_at = u64_field(entry, "down_at_ms")?;
    let up_at = u64_field(entry, "up_at_ms")?;
    if up_at.wrapping_sub(down_at) != WINDOW_MS {
        return Err(format!(
            "downtime window: up_at_ms {up_at} - down_at_ms {down_at} != {WINDOW_MS}"
        ));
    }
    let sha = str_field(entry, "trigger_sha256")?;
    if !is_hex64(sha) {
        return Err(format!("trigger_sha256 is not 64 hex: {sha:?}"));
    }
    // A datagram is one message, so its hash is exact; a TCP trigger may be
    // logged as whatever prefix the first read delivered.
    if case.proto == Proto::Udp && sha != sha256_hex(&case.trigger_send) {
        return Err(format!(
            "trigger_sha256 {sha} != sha256(trigger) {}",
            sha256_hex(&case.trigger_send)
        ));
    }
    let service_field = str_field(entry, "service")?;
    if service_field != case.service {
        return Err(format!("downtime.service {service_field:?}"));
    }
    let triggers = array(&log, "messages")?
        .iter()
        .filter(|m| m["classified"] == "trigger")
        .count();
    if triggers != 1 {
        return Err(format!(
            "{triggers} messages classified trigger, expected 1"
        ));
    }
    Ok(())
}

/// Spec S5, Patched half: the trigger gets the row's reply and the speaker
/// closes with reason `error`; the next connect is immediate; `downtime` is
/// empty; the trigger message is `protocol_error` (udp_payload: `ok`).
async fn patched_flow(case: Case, addr: SocketAddr, control: String) -> Res<()> {
    expect_exchange(
        &case,
        addr,
        &case.benign_send,
        &case.benign_expect,
        "benign",
    )
    .await?;

    let p_reply = case.p_expect.clone().unwrap_or_default();
    let trigger_conn = match case.proto {
        Proto::Tcp => {
            let (bytes, closed, local) = tcp_trigger(&case, addr).await?;
            if bytes != p_reply {
                return Err(format!(
                    "P trigger reply: got {} expected {}",
                    hex(&bytes),
                    hex(&p_reply)
                ));
            }
            if !closed {
                return Err("P trigger: speaker did not close within 1 s".to_string());
            }
            Some(local)
        }
        Proto::Udp => {
            match udp_exchange(addr, &case.trigger_send).await? {
                Some(bytes) if bytes == p_reply => {}
                Some(bytes) => {
                    return Err(format!(
                        "P trigger reply: got {} expected {}",
                        hex(&bytes),
                        hex(&p_reply)
                    ))
                }
                None => return Err(format!("P trigger: no reply, expected {}", hex(&p_reply))),
            }
            None
        }
    };

    // The listener stayed up: the next exchange works at once.
    let t = Instant::now();
    expect_exchange(
        &case,
        addr,
        &case.liveness_send,
        &case.liveness_expect,
        "liveness after P trigger",
    )
    .await?;
    if t.elapsed() > CONNECT_TIMEOUT + REPLY_IDLE {
        return Err(format!(
            "liveness after the P trigger took {:?}",
            t.elapsed()
        ));
    }

    let log = l4_log(&control, case.service).await?;
    let downtime = array(&log, "downtime")?;
    if !downtime.is_empty() {
        return Err(format!("P downtime is not empty: {downtime:?}"));
    }
    let messages = array(&log, "messages")?;
    let trigger_msg = match trigger_conn {
        Some(local) => {
            let conn_id = array(&log, "accepts")?
                .iter()
                .find(|a| a["peer"] == local.to_string())
                .and_then(|a| a["conn_id"].as_str())
                .ok_or_else(|| format!("no accepts entry with peer {local}"))?
                .to_string();
            let close = array(&log, "closes")?
                .iter()
                .find(|c| c["conn_id"] == conn_id)
                .ok_or_else(|| format!("no closes entry for {conn_id}"))?;
            if close["reason"] != "error" {
                return Err(format!("close reason for {conn_id}: {}", close["reason"]));
            }
            messages
                .iter()
                .rfind(|m| m["conn_id"] == conn_id && m["dir"] == "in")
                .ok_or_else(|| format!("no `in` message on {conn_id}"))?
        }
        None => {
            let sha = sha256_hex(&case.trigger_send);
            messages
                .iter()
                .find(|m| m["dir"] == "in" && m["sha256"] == sha)
                .ok_or_else(|| format!("no `in` message with sha256 {sha}"))?
        }
    };
    if trigger_msg["classified"] != case.p_classified {
        return Err(format!(
            "P trigger classified {} expected {:?}",
            trigger_msg["classified"], case.p_classified
        ));
    }
    Ok(())
}

// --- Harness ------------------------------------------------------------------

async fn start(mode: SeedMode) -> TestTarget {
    TestTarget::builder(mode)
        .control(0)
        .l4(true)
        .start()
        .await
        .expect("start target with control + l4")
}

fn service_addr(target: &TestTarget, service: &str, proto: Proto) -> SocketAddr {
    let running = target
        .l4_services()
        .iter()
        .find(|s| s.name == service)
        .unwrap_or_else(|| panic!("{service} is not in l4_services()"));
    assert_eq!(running.proto, proto, "{service} proto");
    running.addr
}

/// Run `flow` for every D5 row against one `mode` target, concurrently, and
/// fail with every failing service named.
async fn run_cases<F, Fut>(mode: SeedMode, flow: F)
where
    F: Fn(Case, SocketAddr, String) -> Fut,
    Fut: Future<Output = Res<()>> + Send + 'static,
{
    let target = start(mode).await;
    let control = target.control_url().expect("control url").to_string();
    let mut handles = Vec::new();
    for case in cases() {
        let addr = service_addr(&target, case.service, case.proto);
        let name = case.service;
        handles.push((name, tokio::spawn(flow(case, addr, control.clone()))));
    }
    let mut failures = Vec::new();
    for (name, handle) in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => failures.push(format!("{name}: {e}")),
            Err(e) => failures.push(format!("{name}: task panicked: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} failing service(s) in {mode:?}:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    drop(target);
}

// --- JSON and formatting helpers ---------------------------------------------------

fn array<'a>(v: &'a Value, key: &str) -> Res<&'a Vec<Value>> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("`{key}` missing or not an array in {v}"))
}

fn u64_field(v: &Value, key: &str) -> Res<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("`{key}` missing or not a u64 in {v}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Res<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{key}` missing or not a string in {v}"))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const SHOW: usize = 48;
    let shown: Vec<String> = bytes
        .iter()
        .take(SHOW)
        .map(|b| format!("{b:02x}"))
        .collect();
    if bytes.len() > SHOW {
        format!("{} ... ({} bytes)", shown.join(" "), bytes.len())
    } else {
        shown.join(" ")
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// --- Tests -----------------------------------------------------------------------

/// The table names the nine D5 services in D5 order with their transports;
/// the only test here that binds nothing.
#[test]
fn cases_cover_the_nine_d5_services() {
    let table = cases();
    let names: Vec<&str> = table.iter().map(|c| c.service).collect();
    assert_eq!(
        names,
        vec![
            "l4-tlv-crash",
            "l4-dns-fault",
            "l4-udp-payload-crash",
            "l4-resp",
            "l4-memcached",
            "l4-modbus",
            "l4-mqtt",
            "l4-smtp",
            "l4-ftp",
        ]
    );
    let udp: Vec<&str> = table
        .iter()
        .filter(|c| c.proto == Proto::Udp)
        .map(|c| c.service)
        .collect();
    assert_eq!(udp, vec!["l4-dns-fault", "l4-udp-payload-crash"]);
    for case in &table {
        assert!(!case.trigger_send.is_empty(), "{} trigger", case.service);
        assert!(!case.benign_expect.is_empty(), "{} benign", case.service);
    }
    assert_eq!(long_line().len(), 4098);
    assert!(long_line().ends_with(b"\r\n"));
}

/// S5, Vulnerable: every speaker's trigger takes it down for exactly the
/// 5 s window and it comes back on the same port.
#[tokio::test]
async fn vulnerable_trigger_downs_then_recovers() {
    run_cases(SeedMode::Vulnerable, vulnerable_flow).await;
}

/// S5, Patched: the same trigger is a protocol error (the row's reply, close
/// with reason `error`), the listener never goes down.
#[tokio::test]
async fn patched_trigger_is_a_protocol_error() {
    run_cases(SeedMode::Patched, patched_flow).await;
}

/// D5 denylist observation: the destructive commands are answered with the
/// row's bytes and logged `classified == "denylisted"` with their verb.
#[tokio::test]
async fn denylisted_commands_are_answered_and_logged() {
    struct Deny {
        service: &'static str,
        banner: Option<&'static [u8]>,
        send: Vec<u8>,
        expect: Vec<u8>,
        verb: &'static str,
    }
    let rows = vec![
        Deny {
            service: "l4-resp",
            banner: None,
            send: b"FLUSHALL\r\n".to_vec(),
            expect: b"-ERR denylisted command\r\n".to_vec(),
            verb: "FLUSHALL",
        },
        Deny {
            service: "l4-memcached",
            banner: None,
            send: b"flush_all\r\n".to_vec(),
            expect: b"CLIENT_ERROR denylisted\r\n".to_vec(),
            verb: "flush_all",
        },
        Deny {
            service: "l4-modbus",
            banner: None,
            // fc 6 (write single register), tid 2.
            send: vec![
                0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x00, 0x00, 0x01,
            ],
            // Exception 0x01 on fc 6: `86 01`.
            expect: vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x01],
            verb: "fc6",
        },
        Deny {
            service: "l4-smtp",
            banner: Some(SMTP_BANNER),
            send: b"RCPT TO:<x@other.example>\r\n".to_vec(),
            expect: b"550 relay denied\r\n".to_vec(),
            verb: "RCPT",
        },
        Deny {
            service: "l4-ftp",
            banner: Some(FTP_BANNER),
            send: b"DELE x\r\n".to_vec(),
            expect: b"550 denied\r\n".to_vec(),
            verb: "DELE",
        },
    ];

    let target = start(SeedMode::Vulnerable).await;
    let control = target.control_url().expect("control url").to_string();
    let mut failures = Vec::new();
    for row in &rows {
        let addr = service_addr(&target, row.service, Proto::Tcp);
        let outcome: Res<()> = async {
            let got = tcp_exchange(addr, row.banner, &row.send, REPLY_IDLE).await?;
            if got != row.expect {
                return Err(format!(
                    "reply: got {} expected {}",
                    hex(&got),
                    hex(&row.expect)
                ));
            }
            let log = l4_log(&control, row.service).await?;
            let denied = array(&log, "messages")?
                .iter()
                .find(|m| m["classified"] == "denylisted")
                .ok_or_else(|| "no message classified denylisted".to_string())?;
            if denied["dir"] != "in" {
                return Err(format!("denylisted message dir {}", denied["dir"]));
            }
            if denied["verb"] != row.verb {
                return Err(format!(
                    "denylisted verb {} expected {:?}",
                    denied["verb"], row.verb
                ));
            }
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            failures.push(format!("{}: {e}", row.service));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failing service(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// D5 MQTT row over one connection: CONNECT -> CONNACK, PUBLISH QoS 1 ->
/// PUBACK, DISCONNECT -> the speaker closes with reason `quit`.
#[tokio::test]
async fn mqtt_connect_publish_disconnect() {
    let target = start(SeedMode::Vulnerable).await;
    let control = target.control_url().expect("control url");
    let addr = service_addr(&target, "l4-mqtt", Proto::Tcp);

    let mut stream = tcp_open(addr, None)
        .await
        .unwrap_or_else(|e| panic!("mqtt connect: {e}"));
    let connack = exchange(&mut stream, &MQTT_CONNECT, REPLY_IDLE)
        .await
        .unwrap_or_else(|e| panic!("CONNECT: {e}"));
    assert_eq!(connack, MQTT_CONNACK, "CONNACK: {}", hex(&connack));
    let puback = exchange(&mut stream, &MQTT_PUBLISH_QOS1, REPLY_IDLE)
        .await
        .unwrap_or_else(|e| panic!("PUBLISH: {e}"));
    assert_eq!(puback, MQTT_PUBACK, "PUBACK: {}", hex(&puback));
    stream
        .write_all(&MQTT_DISCONNECT)
        .await
        .expect("write DISCONNECT");
    let (bytes, closed) = read_until_idle(&mut stream, CLOSE_WITHIN).await;
    assert!(closed, "DISCONNECT must close the connection within 1 s");
    assert!(bytes.is_empty(), "DISCONNECT answered with {}", hex(&bytes));

    let log = l4_log(control, "l4-mqtt")
        .await
        .unwrap_or_else(|e| panic!("l4 log: {e}"));
    let closes = array(&log, "closes").unwrap_or_else(|e| panic!("{e}"));
    let last = closes.last().expect("one closes entry");
    assert_eq!(last["reason"], "quit", "last close: {last}");
    let verbs: Vec<&str> = array(&log, "messages")
        .unwrap_or_else(|e| panic!("{e}"))
        .iter()
        .filter(|m| m["dir"] == "in")
        .filter_map(|m| m["verb"].as_str())
        .collect();
    assert_eq!(verbs, vec!["CONNECT", "PUBLISH", "DISCONNECT"]);
}
