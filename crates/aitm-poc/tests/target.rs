//! Task 27: the bundled reflected-XSS test target — vulnerable reflects `q`
//! unescaped, patched HTML-escapes it. This determinism is what makes AC14's
//! pass-vs-patched run meaningful (driven in Task 24).

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use support::target::{spawn, TargetMode};

/// Issue a raw HTTP/1.1 GET and return the response body.
fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to target");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("send request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    match raw.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => raw,
    }
}

/// The vulnerable target reflects the raw tag; the patched one escapes it.
#[test]
fn reflects_vs_escapes() {
    // `q=<b>x</b>`, percent-encoded on the wire.
    let path = "/search?q=%3Cb%3Ex%3C%2Fb%3E";

    let vulnerable = http_get(spawn(TargetMode::Vulnerable), path);
    assert!(
        vulnerable.contains("<b>x</b>"),
        "vulnerable target must reflect the raw tag, got: {vulnerable}"
    );

    let patched = http_get(spawn(TargetMode::Patched), path);
    assert!(
        patched.contains("&lt;b&gt;x&lt;/b&gt;"),
        "patched target must HTML-escape the tag, got: {patched}"
    );
    assert!(
        !patched.contains("<b>x</b>"),
        "patched target must not contain the raw tag, got: {patched}"
    );
}
