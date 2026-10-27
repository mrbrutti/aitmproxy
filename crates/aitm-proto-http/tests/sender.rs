//! The replay request sender drives a real HTTP/1.1 exchange: it decodes a
//! chunked response body and sends a request body with correct framing.

use std::net::SocketAddr;

use aitm_core::{Body, HeaderMap, HttpRequest, HttpVersion, RequestSender};
use aitm_proto_http::Http1Sender;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
