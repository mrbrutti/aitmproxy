//! Task 11 acceptance tests for `aitm-testtarget` (AC-M4-9, AC-M4-10).
//!
//! A tiny raw-socket HTTP/1 client drives the loopback target directly (no HTTP
//! client dependency, keeping the crate hermetic). Each planted class is
//! triggered the way the manifest's `trigger_hint` describes and scored by its
//! `success_signal`.

use std::time::{Duration, Instant};

use aitm_testtarget::{manifest, PlantedVuln, SeedMode, TestTarget};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One HTTP/1 request over a fresh loopback socket, read to EOF (`Connection:
/// close`). Connects only to the target the test started.
async fn request(
    base_url: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Resp {
    let addr = base_url.strip_prefix("http://").expect("http base url");
    let mut stream = TcpStream::connect(addr).await.expect("connect target");

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    req.push_str(body);

    stream.write_all(req.as_bytes()).await.expect("write req");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    parse(&raw)
}

fn parse(raw: &[u8]) -> Resp {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status code");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: body.to_string(),
    }
}

/// Percent-encode everything but the URL-unreserved set, so markers containing
/// `<`, `>`, `:` or `/` survive the query/body intact.
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

/// Trigger one planted vuln exactly as its class prescribes, and return the
/// response whose `success_signal` [`signal_present`] scores.
async fn trigger(base_url: &str, vuln: &PlantedVuln) -> Resp {
    match vuln.class.as_str() {
        "reflected-xss" => {
            request(
                base_url,
                "GET",
                &format!("/search?q={}", enc(&vuln.success_signal)),
                &[],
                "",
            )
            .await
        }
        "stored-xss" => {
            request(
                base_url,
                "POST",
                "/comments",
                &[],
                &format!("comment={}", enc(&vuln.success_signal)),
            )
            .await;
            request(base_url, "GET", "/comments", &[], "").await
        }
        "ssrf" => {
            request(
                base_url,
                "GET",
                &format!(
                    "/fetch?url={}",
                    enc("http://169.254.169.254/latest/meta-data")
                ),
                &[],
                "",
            )
            .await
        }
        "idor" => {
            // Caller is user 1 (default) reading account 2 — a different owner.
            request(base_url, "GET", "/account/2", &[("X-User-Id", "1")], "").await
        }
        "auth-bypass" => request(base_url, "GET", "/admin", &[("X-Role", "admin")], "").await,
        "open-redirect" => {
            request(
                base_url,
                "GET",
                &format!(
                    "/redirect?next={}",
                    enc("https://redirect-marker-e2d9.example/")
                ),
                &[],
                "",
            )
            .await
        }
        other => panic!("unmapped planted class in manifest: {other}"),
    }
}

/// Whether the success signal is present: open redirect lands in the `Location`
/// header, every other class in the body.
fn signal_present(resp: &Resp, vuln: &PlantedVuln) -> bool {
    match vuln.class.as_str() {
        "open-redirect" => resp
            .header("location")
            .is_some_and(|loc| loc.contains(&vuln.success_signal)),
        _ => resp.body.contains(&vuln.success_signal),
    }
}

#[tokio::test]
async fn each_vuln_path_triggers_in_vulnerable_mode() {
    let target = TestTarget::start(SeedMode::Vulnerable).await;
    for vuln in manifest() {
        let resp = trigger(target.base_url(), vuln).await;
        assert!(
            signal_present(&resp, vuln),
            "vulnerable {}: expected success_signal {:?} (status {}, loc {:?})",
            vuln.id,
            vuln.success_signal,
            resp.status,
            resp.header("location"),
        );
    }
}

#[tokio::test]
async fn each_patched_path_is_safe() {
    let target = TestTarget::start(SeedMode::Patched).await;
    for vuln in manifest() {
        let resp = trigger(target.base_url(), vuln).await;
        assert!(
            !signal_present(&resp, vuln),
            "patched {}: success_signal {:?} must NOT appear (status {}, loc {:?})",
            vuln.id,
            vuln.success_signal,
            resp.status,
            resp.header("location"),
        );
    }
}

#[tokio::test]
async fn manifest_not_served() {
    let target = TestTarget::start(SeedMode::Vulnerable).await;

    // Any path that could leak the grader's table 404s.
    let mut leak_paths = vec![
        "/manifest".to_string(),
        "/manifest.yaml".to_string(),
        "/manifest.yml".to_string(),
        "/manifest.json".to_string(),
        "/.well-known/manifest".to_string(),
        "/vulns".to_string(),
        "/seed".to_string(),
        "/grader".to_string(),
    ];
    for vuln in manifest() {
        leak_paths.push(format!("/{}", vuln.id));
    }
    for path in &leak_paths {
        let resp = request(target.base_url(), "GET", path, &[], "").await;
        assert_eq!(resp.status, 404, "{path} must not be served");
    }

    // No manifest field leaks through a served response: no served body carries
    // a planted id or trigger_hint.
    let index = request(target.base_url(), "GET", "/", &[], "").await;
    for vuln in manifest() {
        assert!(
            !index.body.contains(&vuln.id),
            "index must not reveal planted id {}",
            vuln.id
        );
        assert!(
            !index.body.contains(&vuln.trigger_hint),
            "index must not reveal trigger_hint for {}",
            vuln.id
        );
    }

    // Static proof the router never reads the grader table.
    let app_src = include_str!("../src/app.rs");
    assert!(
        !app_src.to_ascii_lowercase().contains("manifest"),
        "src/app.rs must not reference the manifest in any route"
    );
}

#[tokio::test]
async fn hermetic() {
    let target = TestTarget::start(SeedMode::Vulnerable).await;
    assert!(
        target.base_url().starts_with("http://127.0.0.1:"),
        "target must bind loopback only, got {}",
        target.base_url()
    );

    // A real server-side fetch of 169.254.169.254 could not return *our* private
    // marker (nothing there serves it) and would block on connect. The marker's
    // presence, returned promptly, proves the preview is synthesized in-process:
    // no outbound connection is attempted.
    let ssrf = manifest()
        .iter()
        .find(|v| v.class == "ssrf")
        .expect("an ssrf vuln");
    let start = Instant::now();
    let resp = tokio::time::timeout(Duration::from_secs(2), trigger(target.base_url(), ssrf))
        .await
        .expect("fetch-preview must not hang on an outbound connect");
    assert!(
        resp.body.contains(&ssrf.success_signal),
        "internal marker must be synthesized in-process"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "fetch-preview returned too slowly to be in-process ({:?})",
        start.elapsed()
    );

    // An external host also returns promptly and without the marker — still no
    // socket opened.
    let ext = request(
        target.base_url(),
        "GET",
        &format!("/fetch?url={}", enc("https://example.com/")),
        &[],
        "",
    )
    .await;
    assert!(!ext.body.contains(&ssrf.success_signal));
}
