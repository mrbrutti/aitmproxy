//! Public-API tests for the strict audit redaction in `aitm_core::redact_strict`
//! (spec Design 14.2 and 14.3, AC44).
//!
//! Every test collects its failing rows into one assertion message, so a single
//! run shows every wrong row instead of the first.

use std::sync::mpsc;
use std::time::Duration;

use aitm_core::redact_strict::{is_benign_header, is_secret_key_strict, scrub_strict};

/// Run `f` on its own thread and give it `secs` seconds. A timeout or a panic is an
/// `Err`, so a hang fails the test instead of hanging the run (a detached thread
/// dies with the test process).
fn within<T: Send + 'static>(
    secs: u64,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // A send error means the receiver timed out and left; nothing to report.
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(value) => Ok(value),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!("no result within {secs} s")),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("the worker panicked".to_string()),
    }
}

/// One table of `(input, expected)` rows and the failures they produced.
#[derive(Default)]
struct Table {
    failures: Vec<String>,
}

impl Table {
    /// `scrub_strict(input)` must equal `expected`, and a second pass must change
    /// nothing (the idempotence contract of every pass).
    fn row(&mut self, input: &str, expected: &str) {
        let got = scrub_strict(input);
        if got != expected {
            self.failures.push(format!(
                "scrub_strict({input:?}): want {expected:?}, got {got:?}"
            ));
        }
        let again = scrub_strict(&got);
        if again != got {
            self.failures.push(format!(
                "scrub_strict is not idempotent on {input:?}: first {got:?}, second {again:?}"
            ));
        }
    }

    /// A row that must come through byte for byte.
    fn unchanged(&mut self, input: &str) {
        self.row(input, input);
    }

    /// Hostile shapes, 4 MiB each, on a thread that is given 20 s. `Basic ` repeated
    /// has no token of 8 characters, so it is untouched; `Cookie: ` repeated is one
    /// header line, masked once to its end.
    fn hostile_inputs(&mut self) {
        let basic = "Basic ".repeat((4 << 20) / 6 + 1);
        let cookie = "Cookie: ".repeat((4 << 20) / 8 + 1);

        let basic_in = basic.clone();
        let got_basic = within(20, move || scrub_strict(&basic_in));
        let got_cookie = within(20, move || scrub_strict(&cookie));

        match got_basic {
            Ok(out) if out == basic => {}
            Ok(out) => self
                .failures
                .push(format!("`Basic ` x N changed: {} bytes out", out.len())),
            Err(e) => self.failures.push(format!("`Basic ` x N: {e}")),
        }
        match got_cookie {
            Ok(out) if out == "Cookie: [redacted]" => {}
            Ok(out) => self.failures.push(format!(
                "`Cookie: ` x N did not collapse to one masked line: {} bytes out",
                out.len()
            )),
            Err(e) => self.failures.push(format!("`Cookie: ` x N: {e}")),
        }
    }

    fn finish(self) {
        assert!(
            self.failures.is_empty(),
            "{} wrong row(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

#[test]
fn scrub_strict_masks_every_pass_and_keeps_the_benign() {
    let mut t = Table::default();

    // P2: header lines.
    t.row(
        "GET / HTTP/1.1\r\nCookie: a=b; c=SECRET44\r\nHost: x",
        "GET / HTTP/1.1\r\nCookie: [redacted]\r\nHost: x",
    );
    t.row(
        "Set-Cookie: JSESSIONID=\"S\"; Path=/",
        "Set-Cookie: [redacted]",
    );
    t.row(
        "x Authorization: Digest username=\"u\", response=\"R\"\nnext",
        "x Authorization: [redacted]\nnext",
    );
    t.row("X-Api-Key: a b c\nok", "X-Api-Key: [redacted]\nok");
    t.row(
        "Proxy-Authorization: Basic Zm9v",
        "Proxy-Authorization: [redacted]",
    );

    // P2, beyond the spec's rows: a named header mid-line masks to the end of its
    // line (every cookie, not only the first); at the start of a line a name of the
    // strict vocabulary that `scrub_text` does not know (`pass`) does the same; an
    // empty value is left alone.
    t.row("see Cookie: a=b; c=d\nnext", "see Cookie: [redacted]\nnext");
    t.row("pass: a b\nok", "pass: [redacted]\nok");
    t.unchanged("Cookie:");
    // Regression (found by fuzzing): `scrub_text` already masked the next line and
    // kept the CRLF inside its match, so the header's value is whitespace alone
    // (U+2028 is whitespace to it). P2 must not rewrite that whitespace, or a second
    // `scrub_text` eats the CR (its `.+` matches a CR) and the second pass differs.
    t.unchanged("Authorization:\u{2028}\r\n[redacted]\n");
    t.row(
        "Authorization:\u{2028}\r\nfoo\n",
        "Authorization:\u{2028}\r\n[redacted]\n",
    );

    // P3: Basic, Negotiate and NTLM credentials.
    t.row("use Basic dXNlcjpwYXNz now", "use Basic [redacted] now");
    t.row(
        &format!("negotiate {}", "A".repeat(20)),
        "negotiate [redacted]",
    );

    // P3 gates: a Basic token of 8 or more characters that decodes to no `:`
    // ("foobar"), and a Negotiate or NTLM token one character short of 16, stay.
    t.unchanged("Basic Zm9vYmFy");
    t.unchanged(&format!("ntlm {}", "A".repeat(15)));
    t.row(&format!("NTLM\t{}.", "A".repeat(16)), "NTLM\t[redacted].");

    // Unchanged byte for byte (P2 and P3 must not touch any of them).
    t.unchanged("0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c");
    t.unchanged(&"0123456789abcdef".repeat(4));
    t.unchanged("auth.example.com:8443");
    t.unchanged("basic information");
    t.unchanged("the Cookie header is described in RFC 6265");
    t.unchanged("Accept: text/html");
    t.unchanged("X-Forwarded-For: 203.0.113.9");
    t.unchanged("author=bob&authority=example.com&inside=1&bypass=1&passed=true");
    t.unchanged("{\"a\":1,\"b\":[true,null],\"c\":\"d\"}");
    t.unchanged("{{target}}/login?user={{user}}");

    t.hostile_inputs();
    t.finish();
}

#[test]
fn is_secret_key_strict_vocabulary() {
    let mut failures = Vec::new();
    for key in [
        "passphrase",
        "private_key",
        "Private-Key",
        "access_key",
        "signing-key",
        "pass",
        "PW",
        "otp",
        "totp",
        "x_pass",
        "user.pw",
        // Everything the shared `is_secret_key` says stays true.
        "token",
        "sid",
        "Cookie",
        "Authorization",
    ] {
        if !is_secret_key_strict(key) {
            failures.push(format!("`{key}` should be a strict secret key"));
        }
    }
    for key in [
        "author",
        "authority",
        "inside",
        "bypass",
        "passed",
        "sessions",
        "compass",
        "power",
        "path",
        "host",
    ] {
        if is_secret_key_strict(key) {
            failures.push(format!("`{key}` should not be a strict secret key"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn is_benign_header_table() {
    let mut failures = Vec::new();
    for name in [
        "Accept",
        "CONTENT-TYPE",
        "X-Forwarded-Host",
        "Sec-Fetch-Mode",
        "sec-ch-ua",
        "Referer",
        "Host",
    ] {
        if !is_benign_header(name) {
            failures.push(format!("`{name}` should be benign"));
        }
    }
    for name in [
        "Authorization",
        "Cookie",
        "X-Custom",
        "X-Api-Key",
        "Set-Cookie",
        "X-Debug-Access",
        "sec-fetchx",
        "Sec-Fetch",
    ] {
        if is_benign_header(name) {
            failures.push(format!("`{name}` should not be benign"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
