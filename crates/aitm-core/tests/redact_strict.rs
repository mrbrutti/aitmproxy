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

    /// One hostile shape on a thread that is given 20 s: the pass must return, and
    /// return exactly `expected`.
    fn hostile(&mut self, label: &str, input: String, expected: String) {
        match within(20, move || scrub_strict(&input)) {
            Ok(out) if out == expected => {}
            Ok(out) => self.failures.push(format!(
                "{label}: wrong output, {} bytes out (want {} bytes)",
                out.len(),
                expected.len()
            )),
            Err(e) => self.failures.push(format!("{label}: {e}")),
        }
    }

    /// Hostile shapes of P4 and P5, 4 MiB each. A bare `eyJ` run has no dot, an
    /// unterminated PEM block is masked once to the end of the text, and a scheme
    /// with a colon but no `@` is no credential.
    fn hostile_shapes(&mut self) {
        let jwt = "eyJ".repeat((4 << 20) / 3 + 1);
        let pem = "-----BEGIN PRIVATE KEY-----".repeat((4 << 20) / 27 + 1);
        let url = "https://a:".repeat((4 << 20) / 10 + 1);
        self.hostile("`eyJ` x N", jwt.clone(), jwt);
        self.hostile("unterminated PEM x N", pem, "[redacted]".to_string());
        self.hostile("`https://a:` x N", url.clone(), url);

        // Shapes that would cost a pass over the rest of the text at every
        // candidate if a failed scan were not remembered: a first JWT segment that
        // runs on through `-`, and an unclosed quote after every key word.
        let jwt_dash = "eyJ-".repeat((4 << 20) / 4 + 1);
        self.hostile("`eyJ-` x N", jwt_dash.clone(), jwt_dash);
        let pairs = (4 << 20) / 9 + 1;
        self.hostile(
            "`pass=\"x ` x N",
            "pass=\"x ".repeat(pairs),
            "pass=\"[redacted] ".repeat(pairs),
        );
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

    // P4: URL userinfo.
    t.row(
        "https://user:hunter2@host.test/p",
        "https://user:[redacted]@host.test/p",
    );
    t.row(
        &format!("https://ghp_{}@github.com/", "a".repeat(36)),
        "https://[redacted]@github.com/",
    );

    // P5: credential shapes. Each is the whole text and becomes `[redacted]`.
    for shape in [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl".to_string(),
        format!("AKIA{}", "A".repeat(16)),
        format!("ghp_{}", "a".repeat(36)),
        format!("github_pat_{}", "a".repeat(22)),
        format!("glpat-{}", "a".repeat(20)),
        format!("xoxb-{}", "1".repeat(12)),
        format!("sk_live_{}", "a".repeat(16)),
        format!("sk-{}", "a".repeat(32)),
        format!("AIza{}", "a".repeat(35)),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----".to_string(),
    ] {
        t.row(&shape, "[redacted]");
    }
    t.row("x\n-----BEGIN PRIVATE KEY-----\nMII", "x\n[redacted]");

    // P6: the audit-only key words, as pairs, quoted pairs and JSON members.
    t.row("passphrase=hunter2&x=1", "passphrase=[redacted]&x=1");
    t.row("x=1&private_key=K&y=2", "x=1&private_key=[redacted]&y=2");
    t.row(
        "{\"pass\":\"p\",\"user\":\"u\"}",
        "{\"pass\":\"[redacted]\",\"user\":\"u\"}",
    );
    // AC44 gives the `key: value` form as `"otp: 123456 done"` -> `"otp: [redacted]
    // done"`. That cannot hold beside P2: `otp` is a strict key at the start of the
    // text, so P2 masks the whole line first (`"otp: [redacted]"`, as `pass: a b`
    // above). P6 sees the same pair once it is not at a line start.
    t.row("x otp: 123456 done", "x otp: [redacted] done");
    t.row("a totp: 654321, b=1", "a totp: [redacted], b=1");

    // P4 gates: an empty password is no secret; a user name alone stays unless it
    // is 20 bytes or more or holds a shape; the scan stops at `/`, `?` and `#`.
    t.unchanged("https://user:@host.test/");
    t.row("https://:pw@host.test/", "https://:[redacted]@host.test/");
    t.row(
        "https://abcdefghijklmnopqrst@host.test/",
        "https://[redacted]@host.test/",
    );
    t.unchanged("https://abcdefghijklmnopqrs@host.test/");
    t.row(
        "https://xoxb-1234567890@host.test/",
        "https://[redacted]@host.test/",
    );
    t.unchanged("https://host.test/a@b");
    t.unchanged("https://host.test?x=a:b@c");
    t.row(
        "a https://u:p1@h1/x b http://v:p2@h2/y",
        "a https://u:[redacted]@h1/x b http://v:[redacted]@h2/y",
    );

    // P5 in context, and its gates.
    t.row(
        "jwt is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl.",
        "jwt is [redacted].",
    );
    t.unchanged("eyJabc.eyJabc.sig");
    t.unchanged("eyJabcd.eyJzdWIiOiJ4In0.sig");
    t.unchanged("eyJhbGciOiJIUzI1NiJ9.abcdefg.sig");
    t.row("eyJhbGciOiJIUzI1NiJ9.abcdefgh.sig", "[redacted]");
    t.unchanged("eyJhbGciOiJIUzI1NiJ9.abcdefgh");
    t.row(
        &format!("ghp_{} and AKIA{}", "a".repeat(40), "B".repeat(16)),
        "[redacted] and [redacted]",
    );
    t.row(&format!("KEY_ghp_{}", "a".repeat(36)), "KEY_[redacted]");
    t.row(&format!("AKIA{}_x", "B".repeat(16)), "[redacted]_x");
    t.unchanged(&format!("myghp_{}", "a".repeat(36)));
    t.unchanged(&format!("ghp_{}", "a".repeat(35)));
    t.unchanged(&format!("AKIA{}", "A".repeat(15)));
    // An exact-length shape needs a boundary after it, unless what follows is the
    // start of another credential, which is masked in the same scan.
    t.unchanged(&format!("AKIA{}", "A".repeat(17)));
    t.unchanged(&format!("AKIA{}auth:p", "A".repeat(16)));
    t.row(
        &format!("AKIA{}ghp_{}", "B".repeat(16), "a".repeat(36)),
        "[redacted][redacted]",
    );
    t.unchanged(&format!("sk-{}", "a".repeat(31)));
    t.unchanged("task-0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c");
    t.row(
        "k:\n-----BEGIN EC PRIVATE KEY-----\nAAA\n-----END EC PRIVATE KEY-----\nafter",
        "k:\n[redacted]\nafter",
    );
    t.row(
        "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----\nmid\n\
         -----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----",
        "[redacted]\nmid\n[redacted]",
    );
    t.unchanged("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");

    // Regressions found by fuzzing, each a case where one mask changed how a
    // neighbour read, so that a second call masked what the first left. A name glued
    // to the closing dashes stays: the block is masked before any other pass runs, so
    // the name is read as a name by the first call, and its value is masked with it.
    t.row(
        "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----cookie: x",
        "[redacted]cookie: [redacted]",
    );
    // A no-break space ends a P4 userinfo as it ends a `scrub_text` value; masking
    // across it joined the value to the text after it.
    t.unchanged("x://auth.com:[redacted]\u{a0}@h y");
    t.row(
        "x://auth.com://k\u{a0}@h y",
        "x://auth.com:[redacted]\u{a0}@h y",
    );
    // An exact-length shape glued to the start of another credential, and a
    // credential glued to the end of a masked one.
    t.row(
        &format!("AIza{}_xoxb-0123456789", "a".repeat(34)),
        "[redacted][redacted]",
    );

    // P6 gates: a quoted value, an empty value, a host:port, a pair nested in a
    // value, a key that ends in the word.
    t.row("pass='a b' z=1", "pass='[redacted]' z=1");
    t.unchanged("pw=&x=1");
    t.unchanged("pass.example.com:8443");
    t.row("x_pass=1;y=2", "x_pass=[redacted];y=2");
    t.row("user.pw=abc&q=1", "user.pw=[redacted]&q=1");
    t.row("PW=abc", "PW=[redacted]");
    t.row("next=/cb?pass=abc&x=1", "next=/cb?pass=[redacted]&x=1");

    // Every pass at once.
    t.row(
        &format!(
            "fetch https://user:hunter2@host.test/p with ghp_{} and passphrase=zz",
            "a".repeat(36)
        ),
        "fetch https://user:[redacted]@host.test/p with [redacted] and passphrase=[redacted]",
    );

    // Unchanged byte for byte (no pass may touch any of them).
    t.unchanged("0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c");
    t.unchanged(&"0123456789abcdef".repeat(4));
    t.unchanged("auth.example.com:8443");
    t.unchanged("https://example.test/a/b?x=1&y=two#frag");
    t.unchanged("ssh://git@github.com/o/r");
    t.unchanged("git@github.com:o/r.git");
    t.unchanged("basic information");
    t.unchanged("the Cookie header is described in RFC 6265");
    t.unchanged("sk-prod-eu-1.example.test");
    t.unchanged("Accept: text/html");
    t.unchanged("X-Forwarded-For: 203.0.113.9");
    t.unchanged("author=bob&authority=example.com&inside=1&bypass=1&passed=true");
    t.unchanged("{\"a\":1,\"b\":[true,null],\"c\":\"d\"}");
    t.unchanged("{{target}}/login?user={{user}}");
    t.unchanged("AKIA");
    t.unchanged("AKIAFOO");
    t.unchanged("ghp_short");
    t.unchanged("eyJ");

    t.hostile_inputs();
    t.hostile_shapes();
    t.finish();
}

#[test]
fn the_strict_vocabulary_is_audit_only() {
    // AC63: the extra key words reach the audit path only. The shared scrubber and
    // the shared predicate (the scanner's, the findings store's, the PoC builder's)
    // are exactly what they were.
    let mut failures = Vec::new();
    if aitm_core::redact::is_secret_key("passphrase") {
        failures.push("redact::is_secret_key(\"passphrase\") must stay false".to_string());
    }
    if !is_secret_key_strict("passphrase") {
        failures.push("is_secret_key_strict(\"passphrase\") must be true".to_string());
    }
    let shared = aitm_core::redact::scrub_text("pass=x");
    if shared != "pass=x" {
        failures.push(format!(
            "scrub_text(\"pass=x\"): want \"pass=x\", got {shared:?}"
        ));
    }
    let strict = scrub_strict("pass=x");
    if strict != "pass=[redacted]" {
        failures.push(format!(
            "scrub_strict(\"pass=x\"): want \"pass=[redacted]\", got {strict:?}"
        ));
    }
    for key in [
        "author",
        "authority",
        "inside",
        "bypass",
        "passed",
        "sessions",
    ] {
        if is_secret_key_strict(key) {
            failures.push(format!("`{key}` must not be a strict secret key"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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

/// Shapes the fuzzer found where one call did not leave a fixed point. Each is
/// `scrub_strict`'s to settle: the result of a second call must equal the first.
const FUZZ_FOUND_SHAPES: &[&str] = &[
    // The value rule masks a trailing backslash, so a quote stops being escaped.
    "secret=\"\rpw\n:\\\"",
    "privatekey=' privatekey:\\'",
    "pass=' pass:\\'",
    "\tprivatekey:\"=\u{b}\"s",
    "Pass=\",privatekey:\\\"",
    " pw:\"\rpass=\\\"",
    " pass:' privatekey:\\'",
    "\u{a0}ApiKey:'}apikey::'d",
    "\"CookieA:\" aCookie:\\\"",
    "ApiKey=\"\u{c}ApiKey:\\\"",
    "/apikey:\" auth=\\\"",
    " token:\" apikey:\\\"",
    "[pass:\" otp=\\\"",
    "Authorization.=' pw=\\'",
    "?ApiKey:\" signing-key:\\\"",
    "Cookie=\"=\n\"n",
    // A mask that takes away a terminator or a delimiter another pass stopped at.
    "w://-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----[]abcdefgh@",
    "a://okenZm9va_-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----@",
    "Y://xxxxxxxxxx-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----@",
    "4://sk_live_pw-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----@",
    "-://eaaaaaaaa------BEGIN PRIVATE KEY----------END PRIVATE KEY-----@",
    "h://ApiKey:}@",
    "A://CookieA:}@",
    "-://Cookie_:}@",
    "6://passphrase:/}@",
    "p://privatekey=.&@",
    // A mask that takes away the `.` that made `scrub_text` read a host and a port.
    ".xoxp-et-Cookiex_ApiKey:8",
    ".xoxb-fghprivate_Cookie:4",
    ".sk_live_3AuthorizatioSet-Cookie:4",
    ".rk_test_eyJhbGciOiJProxy-Auth:1",
    ".rk_test_bmF0dXJlAKIAxoxp-passwd:8",
    ".xoxp-AAAAAAAAAA_Cookie:3",
    ".rk_test_NztokenhttpProxy-Auth:1",
    "AIzaeyJzdWIiOiJ4eyJhbGciOiJauthsk_live_xoxb-234Cookie2",
];

#[test]
fn shapes_found_by_fuzzing_are_fixed_points() {
    // scrub_strict runs its passes again until the text stops changing, so a second
    // call over any output changes nothing, including the shapes that no single
    // round settles.
    let mut failures = Vec::new();
    for shape in FUZZ_FOUND_SHAPES {
        let first = scrub_strict(shape);
        let second = scrub_strict(&first);
        if first != second {
            failures.push(format!("{shape:?}: first {first:?}, second {second:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} shapes are not fixed points:\n{}",
        failures.len(),
        FUZZ_FOUND_SHAPES.len(),
        failures.join("\n")
    );
}

#[test]
fn a_private_key_block_is_masked_whole_whatever_precedes_it() {
    // The block is masked before `scrub_text` and P2 run, so a key name in front of
    // it (whose own mask would eat the BEGIN line) cannot leave the key body behind.
    let mut t = Table::default();
    t.row(
        "password: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----",
        "password: [redacted]",
    );
    t.row(
        "token=-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADAN\n-----END RSA PRIVATE KEY-----",
        "token=[redacted]",
    );
    t.row(
        "private_key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----",
        "private_key: [redacted]",
    );
    t.row(
        "password: -----BEGIN PRIVATE KEY-----\nMII",
        "password: [redacted]",
    );
    t.row(
        "k: -----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nafter: 1",
        "k: [redacted]\nafter: 1",
    );
    t.row(
        "Cookie: a=b\r\n-----BEGIN PRIVATE KEY-----\r\nMII\r\n-----END PRIVATE KEY-----\r\nok",
        "Cookie: [redacted]\r\n[redacted]\r\nok",
    );

    // The PGP armor: the label ends in `PRIVATE KEY BLOCK`.
    t.row(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabcdef\n-----END PGP PRIVATE KEY BLOCK-----",
        "[redacted]",
    );
    t.row(
        "pgp:\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----\nafter",
        "pgp:\n[redacted]\nafter",
    );
    t.row(
        "passwd=-----BEGIN PGP PRIVATE KEY BLOCK-----\nQWxs\n-----END PGP PRIVATE KEY BLOCK-----",
        "passwd=[redacted]",
    );

    // Public material is not a secret, and the label length is bounded: 48 bytes
    // match, 49 do not.
    t.unchanged("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----");
    t.unchanged("-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQEN\n-----END PGP PUBLIC KEY BLOCK-----");
    t.row(
        &format!(
            "-----BEGIN {a} PRIVATE KEY-----\nX\n-----END {a} PRIVATE KEY-----",
            a = "A".repeat(36)
        ),
        "[redacted]",
    );
    let long = format!(
        "-----BEGIN {a} PRIVATE KEY-----\nX\n-----END {a} PRIVATE KEY-----",
        a = "A".repeat(37)
    );
    t.unchanged(&long);

    // Hostile, 4 MiB each: a header after a key name that never closes, a header
    // followed by an endless run of unmatched END keywords, and headers that are
    // not private-key headers at all.
    let after_key = "password: -----BEGIN PRIVATE KEY-----\n".repeat((4 << 20) / 38 + 1);
    t.hostile(
        "`password: ` + BEGIN x N",
        after_key,
        "password: [redacted]".to_string(),
    );
    let ends = "-----BEGIN PRIVATE KEY-----x-----END ".repeat((4 << 20) / 37 + 1);
    t.hostile("BEGIN + unmatched END x N", ends, "[redacted]".to_string());
    let begins = "-----BEGIN ".repeat((4 << 20) / 11 + 1);
    t.hostile("`-----BEGIN ` x N", begins.clone(), begins);
    t.finish();
}

#[test]
fn userinfo_runs_to_the_last_at_of_the_authority() {
    // Browsers resolve the host after the last `@` of the authority, so a password
    // that holds a raw `@` is all userinfo.
    let mut t = Table::default();
    t.row(
        "https://u:p@ss@host.test/",
        "https://u:[redacted]@host.test/",
    );
    t.row(
        "https://u:p@ss@host.test/x@y",
        "https://u:[redacted]@host.test/x@y",
    );
    t.row(
        "https://u:p@ss@host.test?x=1@2",
        "https://u:[redacted]@host.test?x=1@2",
    );
    t.row(
        "https://u:p@ss@host.test#f@g",
        "https://u:[redacted]@host.test#f@g",
    );
    t.row("\"https://u:p@ss@h\"@x", "\"https://u:[redacted]@h\"@x");
    t.row("https://u:p@ss@h x@y", "https://u:[redacted]@h x@y");
    // No colon: the length rule is applied to the whole userinfo, `@` included.
    t.row(
        "https://abcdefghi@jklmnopqrst@host.test/",
        "https://[redacted]@host.test/",
    );
    t.unchanged("https://a@b@host.test/");
    t.unchanged("ssh://git@github.com/o/r");
    t.unchanged("https://host.test/a@b");

    // Hostile, 4 MiB each: one endless authority of `@`s, with and without a colon.
    let n = (4 << 20) / 2 + 1;
    t.hostile(
        "`https://` + `a@` x N",
        format!("https://{}", "a@".repeat(n)),
        "https://[redacted]@".to_string(),
    );
    t.hostile(
        "`https://u:` + `p@` x N",
        format!("https://u:{}", "p@".repeat(n)),
        "https://u:[redacted]@".to_string(),
    );
    t.finish();
}

#[test]
fn a_compact_jwe_is_masked_to_its_tag() {
    // A compact JWE is a header and four more segments. The encrypted key, the
    // initialisation vector and the ciphertext may be empty; the tag may not.
    let mut t = Table::default();
    t.row(
        "eyJhbGciOiJSU0EtT0FFUCJ9.encryptedkeyaaaa.ivaaaaaaaa.ciphertextaaaa.tagaaaaaaaaaa",
        "[redacted]",
    );
    t.row(
        "eyJhbGciOiJkaXIifQ..ivaaaaaaaa.ciphertextaaaa.tagaaaaaaaaaa",
        "[redacted]",
    );
    t.row(
        "eyJhbGciOiJkaXIifQ...ciphertextaaaa.tagaaaaaaaaaa",
        "[redacted]",
    );
    t.row(
        "jwe=eyJhbGciOiJkaXIifQ..iv.ct.tag; next=1",
        "jwe=[redacted]; next=1",
    );
    // The three-part JWT keeps its behaviour and its length gates; a fourth part is
    // not one of its parts.
    t.row(
        "a eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln b",
        "a [redacted] b",
    );
    t.row(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl.tail",
        "[redacted].tail",
    );
    t.unchanged("eyJabc..iv.ct.tag");
    t.unchanged("eyJhbGciOiJkaXIifQ..iv.ct.");
    t.unchanged("eyJhbGciOiJIUzI1NiJ9.abcdefg.sig");

    // Hostile, 4 MiB: header-looking segments, five to a JWE.
    let jwes = (4 << 20) / 60 + 1;
    t.hostile(
        "`eyJaaaaaaaa.` x 5N",
        "eyJaaaaaaaa.".repeat(5 * jwes),
        "[redacted].".repeat(jwes),
    );
    t.finish();
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
