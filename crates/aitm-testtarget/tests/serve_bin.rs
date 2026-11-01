//! M4 follow-on: the standalone serve binary (AC-M4-17 operator path).
//!
//! The library target serves in-process for the deterministic suites; an operator
//! running the *live* acceptance needs the same seeded target as a real, external
//! HTTP server to point a browser+proxy at. These tests drive the `aitm-testtarget-serve`
//! binary as a child process: it must print its bound loopback base URL on stdout,
//! stay alive serving, honour `--mode`, and — like the library target — never serve
//! the grader-only planted-vuln manifest.
//!
//! They bind a loopback port (via the child), so they run with the rest of the
//! crate's suite under the Terminal panel, not the sandbox.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aitm_testtarget::{manifest, SeedMode};

/// A spawned serve-bin process plus the base URL it reported, killed on drop.
struct Serve {
    child: Child,
    base_url: String,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the serve bin in `mode` on an ephemeral port and return once it has
/// printed its `listening <base_url>` line.
fn start(mode: SeedMode) -> Serve {
    let mode_arg = match mode {
        SeedMode::Vulnerable => "vulnerable",
        SeedMode::Patched => "patched",
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_aitm-testtarget-serve"))
        .args(["--mode", mode_arg, "--port", "0"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn aitm-testtarget-serve");

    // The first stdout line is `listening http://127.0.0.1:<port>`.
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read the listening line");
    let base_url = line
        .trim()
        .strip_prefix("listening ")
        .unwrap_or_else(|| panic!("unexpected first line from serve bin: {line:?}"))
        .to_string();
    assert!(
        base_url.starts_with("http://127.0.0.1:"),
        "serve bin must bind loopback only, got {base_url:?}"
    );

    Serve { child, base_url }
}

/// One HTTP/1 request over a fresh loopback socket, read to EOF.
fn request(base_url: &str, method: &str, path: &str) -> (u16, String) {
    let addr = base_url.strip_prefix("http://").expect("http base url");
    let mut stream = TcpStream::connect(addr).expect("connect serve bin");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status code");
    (status, body.to_string())
}

/// Percent-encode everything but the URL-unreserved set, so a marker with `<`,
/// `>` or `/` survives the request line (an unencoded one is a 400 from the parser).
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

const XSS_MARKER: &str = "<svg/onload>";

#[test]
fn serves_vulnerable_target_over_a_real_port() {
    let serve = start(SeedMode::Vulnerable);

    // The index is served.
    let (status, body) = request(&serve.base_url, "GET", "/");
    assert_eq!(status, 200);
    assert!(body.contains("aitm test target"), "index body: {body}");

    // Vulnerable reflected XSS: the marker comes back raw (unescaped).
    let (status, body) = request(
        &serve.base_url,
        "GET",
        &format!("/search?q={}", enc(XSS_MARKER)),
    );
    assert_eq!(status, 200);
    assert!(
        body.contains(XSS_MARKER),
        "vulnerable mode must reflect the marker raw: {body}"
    );
}

#[test]
fn patched_mode_escapes() {
    let serve = start(SeedMode::Patched);
    let (status, body) = request(
        &serve.base_url,
        "GET",
        &format!("/search?q={}", enc(XSS_MARKER)),
    );
    assert_eq!(status, 200);
    assert!(
        !body.contains(XSS_MARKER),
        "patched mode must escape the marker: {body}"
    );
}

#[test]
fn serve_bin_does_not_expose_the_manifest() {
    let serve = start(SeedMode::Vulnerable);
    // The grader-only manifest must never be reachable over the served surface.
    for vuln in manifest() {
        let (status, _) = request(&serve.base_url, "GET", &format!("/{}", vuln.id));
        assert_eq!(status, 404, "planted id {} must not be served", vuln.id);
    }
    let (_, index) = request(&serve.base_url, "GET", "/");
    for vuln in manifest() {
        assert!(
            !index.contains(&vuln.id),
            "index must not reveal planted id {}",
            vuln.id
        );
    }
}

/// `line` is exactly `<prefix> <scheme>://127.0.0.1:<digits>` (spec D1 stdout).
fn assert_addr_line(line: &str, prefix: &str, scheme: &str) -> String {
    let want = format!("{prefix} {scheme}://127.0.0.1:");
    let port = line
        .strip_prefix(&want)
        .unwrap_or_else(|| panic!("expected {want:?}<port>, got {line:?}"));
    assert!(
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        "port must be digits only in {line:?}"
    );
    format!("{scheme}://127.0.0.1:{port}")
}

#[test]
fn serve_bin_prints_every_line_in_order() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aitm-testtarget-serve"))
        .args([
            "--mode",
            "vulnerable",
            "--port",
            "0",
            "--tls-port",
            "0",
            "--tls-h1-port",
            "0",
            "--control-port",
            "0",
            "--l4",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn aitm-testtarget-serve with every flag");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut lines = Vec::new();
    for _ in 0..5 {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read a stdout line");
        assert!(n > 0, "serve bin closed stdout after {lines:?}");
        lines.push(line.trim_end_matches(['\r', '\n']).to_string());
    }
    // Keep the child alive until the assertions are done; kill on every path.
    let serve = Serve {
        child,
        base_url: String::new(),
    };

    assert_addr_line(&lines[0], "listening", "http");
    assert_addr_line(&lines[1], "tls", "https");
    assert_addr_line(&lines[2], "tls_h1", "https");
    let control = assert_addr_line(&lines[3], "control", "http");
    assert_eq!(lines[4], "ready");

    // The printed control port is the real one: `/services` answers there and
    // lists the plain listener as `http` (D2) plus at least one `l4` row.
    let (status, body) = request(&control, "GET", "/services");
    assert_eq!(status, 200, "control /services body: {body}");
    assert!(body.contains(r#""name":"http""#), "services: {body}");
    assert!(body.contains(r#""name":"tls_h1""#), "services: {body}");
    assert!(body.contains(r#""role":"l4""#), "services: {body}");
    drop(serve);
}
