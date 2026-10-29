//! The replay request sender drives a real HTTP/1.1 exchange: it decodes a
//! chunked response body and sends a request body with correct framing.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aitm_core::{
    Body, HeaderMap, HttpRequest, HttpVersion, RequestSender, ScopeEntry, ScopeRateGuard,
    SsrfPolicy, StdGuard,
};
use aitm_proto_http::{HostResolver, Http1Sender};
use anyhow::Result;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A resolver that returns fixed addresses, so the SSRF gate can be exercised
/// without real DNS (and a refusal is proven to happen before any connect).
struct FixedResolver(Vec<IpAddr>);

impl HostResolver for FixedResolver {
    fn resolve(&self, _host: String, _port: u16) -> BoxFuture<'static, Result<Vec<IpAddr>>> {
        let ips = self.0.clone();
        Box::pin(async move { Ok(ips) })
    }
}

/// A GET for a hostname authority (no port), scheme `http`.
fn get_host(authority: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        scheme: "http".into(),
        authority: authority.into(),
        path: "/".into(),
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: std::time::SystemTime::now(),
    }
}

/// C1: a scoped *name* that resolves to a private address (DNS rebinding) is
/// refused on the reissue path before any connection is attempted. The name is in
/// scope, so the rate/scope guard alone would let it through — only the SSRF gate
/// stops it.
#[tokio::test]
async fn ssrf_refuses_scoped_name_resolving_to_private() {
    let guard = Arc::new(StdGuard::default());
    guard.add_scope(ScopeEntry {
        host: "evil.test".into(),
    });
    let sender = Http1Sender::new()
        .with_ssrf(SsrfPolicy::default(), guard)
        .with_resolver(Arc::new(FixedResolver(vec!["10.0.0.5".parse().unwrap()])));

    let err = sender
        .send(&get_host("evil.test"))
        .await
        .expect_err("a scoped name resolving to a private IP must be refused");
    assert!(
        err.to_string().contains("SSRF"),
        "the refusal names the SSRF gate: {err}"
    );
}

/// C1: the metadata address (link-local 169.254.169.254) is refused too, even
/// when the operator scoped the hostname that points at it.
#[tokio::test]
async fn ssrf_refuses_scoped_name_resolving_to_metadata() {
    let guard = Arc::new(StdGuard::default());
    guard.add_scope(ScopeEntry {
        host: "metadata.test".into(),
    });
    let sender = Http1Sender::new()
        .with_ssrf(SsrfPolicy::default(), guard)
        .with_resolver(Arc::new(FixedResolver(vec!["169.254.169.254"
            .parse()
            .unwrap()])));

    let err = sender
        .send(&get_host("metadata.test"))
        .await
        .expect_err("the cloud metadata address must be refused");
    assert!(err.to_string().contains("SSRF"), "got: {err}");
}

/// Read the request head and (if `Content-Length`) its body; return (head, body).
async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.expect("read head");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let mut body = buf[split.saturating_add(4).min(buf.len())..].to_vec();
    let want = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while body.len() < want {
        let n = stream.read(&mut chunk).await.expect("read body");
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    (head, body)
}

fn get(addr: SocketAddr, path: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        scheme: "http".into(),
        authority: addr.to_string(),
        path: path.into(),
        version: HttpVersion::Http11,
        headers: HeaderMap::new(),
        body: Body::Empty,
        timestamp: std::time::SystemTime::now(),
    }
}

/// M3 security review: an upstream that accepts and never answers (or
/// trickles bytes) cannot hold the sender open past its overall response
/// deadline — the per-read timeout alone would reset on every byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_upstream_hits_the_response_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut s).await;
        // Trickle one header byte every 50ms, forever: each read succeeds, so
        // only the overall deadline can end this.
        for b in b"HTTP/1.1 200 OK\r\nX-Slow: ".iter().cycle() {
            if s.write_all(&[*b]).await.is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    });

    let started = std::time::Instant::now();
    let err = Http1Sender::new()
        .with_response_timeout(std::time::Duration::from_millis(400))
        .send(&get(addr, "/"))
        .await
        .expect_err("a response that never completes must time out");
    let elapsed = started.elapsed();
    assert!(
        err.to_string().contains("timed out"),
        "the error names the deadline: {err}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "the deadline, not the trickle, ends the exchange: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decodes_a_chunked_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut s).await;
        let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let _ = s.write_all(resp.as_bytes()).await;
        let _ = s.shutdown().await;
    });

    let resp = Http1Sender::new()
        .send(&get(addr, "/"))
        .await
        .expect("send");
    assert_eq!(resp.status, 200);
    match resp.body {
        Body::Bytes(b) => assert_eq!(String::from_utf8_lossy(&b), "hello world"),
        other => panic!("expected a decoded body, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_a_body_with_single_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let got = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let (head, body) = read_request(&mut s).await;
        let resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        let _ = s.write_all(resp.as_bytes()).await;
        let _ = s.shutdown().await;
        (head, body)
    });

    let mut req = get(addr, "/submit");
    req.method = "POST".into();
    req.body = Body::Bytes(b"payload-123".to_vec());
    // A stale framing header must not survive as a duplicate.
    req.headers.set("Transfer-Encoding", "chunked");
    let resp = Http1Sender::new().send(&req).await.expect("send");
    assert_eq!(resp.status, 204);

    let (head, body) = got.await.unwrap();
    assert_eq!(body, b"payload-123");
    let cl_count = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .count();
    assert_eq!(cl_count, 1, "exactly one Content-Length header:\n{head}");
    assert!(
        !head.to_ascii_lowercase().contains("transfer-encoding:"),
        "a buffered body must not also carry Transfer-Encoding:\n{head}"
    );
}

/// C1: the SSRF gate must not break a *legitimately scoped* loopback target. An
/// IP literal in scope lifts the private/loopback block, so a replay to a scoped
/// local server still connects and succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssrf_allows_a_scoped_loopback_literal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut s).await;
        let _ = s
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            .await;
        let _ = s.shutdown().await;
    });

    let guard = Arc::new(StdGuard::default());
    // Scope the IP literal the target resolves to — this is what lifts the block.
    guard.add_scope(ScopeEntry {
        host: addr.to_string(),
    });
    let sender = Http1Sender::new().with_ssrf(SsrfPolicy::default(), guard);

    let resp = sender
        .send(&get(addr, "/"))
        .await
        .expect("a scoped loopback literal must be allowed through the SSRF gate");
    assert_eq!(resp.status, 200);
}
