//! Public-API tests for the strict audit redaction in `aitm_core::redact_strict`
//! (spec Design 14.2 and 14.3, AC44).
//!
//! Every test collects its failing rows into one assertion message, so a single
//! run shows every wrong row instead of the first.

use std::sync::mpsc;
use std::time::Duration;

use aitm_core::redact_strict::{
    is_benign_header, is_secret_key_strict, scrub_strict, scrub_strict_bounded,
};

/// Seconds a hostile 4 MiB input is given: generous, because the suites of a loaded
/// CI host run in parallel and in a debug build.
const HOSTILE_SECS: u64 = 60;

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

    /// Hostile shapes, 4 MiB each, on a thread that is given `HOSTILE_SECS`. `Basic ` repeated
    /// has no token of 8 characters, so it is untouched; `Cookie: ` repeated is one
    /// header line, masked once to its end.
    fn hostile_inputs(&mut self) {
        let basic = "Basic ".repeat((4 << 20) / 6 + 1);
        let cookie = "Cookie: ".repeat((4 << 20) / 8 + 1);

        let basic_in = basic.clone();
        let got_basic = within(HOSTILE_SECS, move || scrub_strict(&basic_in));
        let got_cookie = within(HOSTILE_SECS, move || scrub_strict(&cookie));

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

    /// One hostile shape on a thread that is given `HOSTILE_SECS`: the pass must return, and
    /// return exactly `expected`.
    fn hostile(&mut self, label: &str, input: String, expected: String) {
        match within(HOSTILE_SECS, move || scrub_strict(&input)) {
            Ok(out) if out == expected => {}
            Ok(out) => self.failures.push(format!(
                "{label}: wrong output, {} bytes out (want {} bytes)",
                out.len(),
                expected.len()
            )),
            Err(e) => self.failures.push(format!("{label}: {e}")),
        }
    }

    /// One hostile shape that only has to come back, in time and without a panic.
    /// It is 2 MiB: a scan of it that is quadratic is tens of billions of steps, far
    /// past the guard.
    fn hostile_completes(&mut self, label: &str, input: String) {
        if let Err(e) = within(HOSTILE_SECS, move || scrub_strict(&input).len()) {
            self.failures.push(format!("{label}: {e}"));
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
    t.row("negotiate AAAAAAAAAAAAAAAAAAAA", "negotiate [redacted]");

    // P3 gates: a Basic token of 8 or more characters that decodes to no `:`
    // ("foobar"), and a Negotiate or NTLM token one character short of 16, stay.
    t.unchanged("Basic Zm9vYmFy");
    t.unchanged("ntlm AAAAAAAAAAAAAAA");
    t.row("NTLM\tAAAAAAAAAAAAAAAA.", "NTLM\t[redacted].");

    // P4: URL userinfo.
    t.row(
        "https://user:hunter2@host.test/p",
        "https://user:[redacted]@host.test/p",
    );
    t.row(
        "https://ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@github.com/",
        "https://[redacted]@github.com/",
    );

    // P5: credential shapes. Each is the whole text and becomes `[redacted]`.
    for shape in [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
        "AKIAAAAAAAAAAAAAAAAA",
        "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "github_pat_aaaaaaaaaaaaaaaaaaaaaa",
        "glpat-aaaaaaaaaaaaaaaaaaaa",
        "xoxb-111111111111",
        "sk_live_aaaaaaaaaaaaaaaa",
        "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    ] {
        t.row(shape, "[redacted]");
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
        "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and AKIABBBBBBBBBBBBBBBB",
        "[redacted] and [redacted]",
    );
    t.row(
        "KEY_ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "KEY_[redacted]",
    );
    t.row("AKIABBBBBBBBBBBBBBBB_x", "[redacted]_x");
    t.unchanged("myghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    t.unchanged("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    t.unchanged("AKIAAAAAAAAAAAAAAAA");
    // An exact-length shape needs a boundary after it, unless what follows is the
    // start of another credential, which is masked in the same scan.
    t.unchanged("AKIAAAAAAAAAAAAAAAAAA");
    t.unchanged("AKIAAAAAAAAAAAAAAAAAauth:p");
    t.row(
        "AKIABBBBBBBBBBBBBBBBghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "[redacted][redacted]",
    );
    t.unchanged("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
        "AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_xoxb-0123456789",
        "[redacted][redacted]",
    );

    // P6 gates: a quoted value, an empty value, a host:port, a pair nested in a
    // value, a key that ends in the word.
    t.row("pass='a b' z=1", "pass='[redacted]' z=1");
    t.row(r#"pass="a\"b" z=1"#, r#"pass="[redacted]" z=1"#);
    t.unchanged("pw=&x=1");
    t.unchanged("pass.example.com:8443");
    t.row("x_pass=1;y=2", "x_pass=[redacted];y=2");
    t.row("user.pw=abc&q=1", "user.pw=[redacted]&q=1");
    t.row("PW=abc", "PW=[redacted]");
    t.row("next=/cb?pass=abc&x=1", "next=/cb?pass=[redacted]&x=1");

    // Every pass at once.
    t.row(
        "fetch https://user:hunter2@host.test/p with ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and passphrase=zz",
        "fetch https://user:[redacted]@host.test/p with [redacted] and passphrase=[redacted]",
    );

    // Unchanged byte for byte (no pass may touch any of them).
    t.unchanged("0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c");
    t.unchanged("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
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
        // camelCase: the words are found where a capital follows a lower-case letter
        // or a digit.
        "userPass",
        "dbPass",
        "adminPw",
        "totpCode",
        "otpCode",
        "authKey",
        "sessionKey",
        "userPASS",
        "user2Pass",
        "oauth2Token",
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
        // Capitals that are not a word boundary, and look-alikes of the new words.
        "Passed",
        "bypassCache",
        "compassPoint",
        "passedBy",
        "userAgent",
        "Compass",
        "authority",
        "Authority",
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
        "-----BEGIN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PRIVATE KEY-----\nX\n-----END AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PRIVATE KEY-----",
        "[redacted]",
    );
    t.unchanged(
        "-----BEGIN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PRIVATE KEY-----\nX\n-----END AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PRIVATE KEY-----",
    );

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
fn rust_debug_wrappers_around_a_secret_are_masked_whole() {
    // A value printed with `{:?}` is `Str("..")`, `Some(..)` or `Bytes([..])`: the
    // wrapper is the value, quotes and all, and the whole expression becomes
    // `[redacted]` (the pair rule alone would take `Str(` and stop at the quote).
    let mut t = Table::default();
    // Real text from `flow.mutate`.
    t.row(
        r#"`body` must be a string or bytes, got Object({"password": Str("CNRYx9q7"), "username": Str("admin")})"#,
        r#"`body` must be a string or bytes, got Object({"password": [redacted], "username": Str("admin")})"#,
    );
    t.row(
        r#"Config { token: Some("CNRYx9q7") }"#,
        "Config { token: [redacted] }",
    );
    t.row(
        r#"Config { token: Some(Str("CNRYx9q7")), other: 1 }"#,
        "Config { token: [redacted], other: 1 }",
    );
    t.row(
        r#"got Object({"password": Bytes([67, 78, 82, 89]), "user": Str("a")})"#,
        r#"got Object({"password": [redacted], "user": Str("a")})"#,
    );
    t.row(
        r#"got Object({"password": Array([Str("a"), Str("b")])})"#,
        r#"got Object({"password": [redacted]})"#,
    );
    t.row(
        r#"got Object({"pass": Str("CNRYx9q7")})"#,
        r#"got Object({"pass": [redacted]})"#,
    );
    t.row(
        r#"got Object({"userPass": Str("CNRYx9q7")})"#,
        r#"got Object({"userPass": [redacted]})"#,
    );
    // The string holds an escaped quote and a closing bracket.
    t.row(
        r#"got Object({"password": Str("a\"b)c")})"#,
        r#"got Object({"password": [redacted]})"#,
    );
    // The `{:#?}` form puts the value on its own lines.
    t.row(
        "Object({\n    \"password\": Str(\n        \"CNRYx9q7\",\n    ),\n})",
        "Object({\n    \"password\": [redacted],\n})",
    );
    // Text cut by a cap in the middle of the string.
    t.row(
        r#"got Object({"password": Str("CNRYx9"#,
        r#"got Object({"password": [redacted]"#,
    );
    // A name that is not a secret keeps its value.
    t.unchanged(r#"got Object({"user": Str("admin")})"#);
    t.unchanged(r#"Config { user: Some("admin") }"#);

    // Hostile, 2 MiB each: wrappers that never reach a value, and brackets that
    // never close.
    t.hostile_completes(
        "`password: A(` x N",
        "password: A(A(A(".repeat((2 << 20) / 16 + 1),
    );
    t.hostile_completes(
        "`password: Str(` x N",
        "password: Str(".repeat((2 << 20) / 14 + 1),
    );
    t.hostile_completes(
        "`password: Some([` x N",
        "password: Some([".repeat((2 << 20) / 16 + 1),
    );
    t.finish();
}

#[test]
fn escaped_quote_frames_are_masked_to_their_matching_closer() {
    // A JSON object inside a JSON or YAML string has its quotes escaped, once or
    // twice. A run of backslashes before a quote is an escaped quote, and the frame
    // ends at the quote with the same run. The whole frame, backslashes and quotes,
    // becomes `[redacted]`.
    let mut t = Table::default();
    t.row(
        r#"{\"password\":\"CNRYx9q7\"}"#,
        r#"{\"password\":[redacted]}"#,
    );
    t.row(
        r#"{\\\"password\\\":\\\"CNRYx9q7\\\"}"#,
        r#"{\\\"password\\\":[redacted]}"#,
    );
    t.row(r#"token=\"CNRYx9q7\""#, "token=[redacted]");
    t.row(
        r#"JSESSIONID=\"S\"; Path=/"#,
        "JSESSIONID=[redacted]; Path=/",
    );
    // The extra vocabulary and camelCase names are read the same way.
    t.row(r#"{\"pass\":\"X\"}"#, r#"{\"pass\":[redacted]}"#);
    t.row(
        r#"{\"userPass\":\"X\",\"user\":\"a\"}"#,
        r#"{\"userPass\":[redacted],\"user\":\"a\"}"#,
    );
    // A blank after the separator, and an inner quote escaped one level deeper.
    t.row(
        r#"{\"password\": \"CNRYx9q7\"}"#,
        r#"{\"password\": [redacted]}"#,
    );
    t.row(
        r#"{\"password\":\"ab\\\"cd\"}"#,
        r#"{\"password\":[redacted]}"#,
    );
    // A PoC YAML with a double-quoted JSON body.
    t.row(
        &[
            "name: poc",
            r#"body: "{\"user\":\"a\",\"password\":\"CNRYx9q7\"}""#,
        ]
        .join("\n"),
        &[
            "name: poc",
            r#"body: "{\"user\":\"a\",\"password\":[redacted]}""#,
        ]
        .join("\n"),
    );
    // A frame cut by a cap runs to the end of the text.
    t.row(r#"{\"password\":\"CNRYx9"#, r#"{\"password\":[redacted]"#);
    // A name that is not a secret keeps its value.
    t.unchanged(r#"{\"user\":\"a\"}"#);
    t.unchanged(r#"{\"user\":\"a\",\"note\":\"hello\"}"#);

    // Hostile, 2 MiB each: openers with no closer of their own run length, and
    // openers that close at once.
    t.hostile_completes(
        "`{\\\"password\\\":\\\"` x N",
        r#"{\"password\":\""#.repeat((2 << 20) / 17 + 1),
    );
    // Openers whose backslash runs all differ, so that none closes another: under a
    // key that is not secret none may be scanned for a closer (a scan of each to the
    // end of the text is a pass per opener, about 3 x 10^10 steps here), and under one
    // that is the first masks the rest of the text.
    for (key, openers) in [("a", 4000), ("password", 2900)] {
        let text: String = (1..=openers)
            .map(|run| format!("{key}={}\"", "\\".repeat(run)))
            .collect();
        t.hostile_completes(
            &format!("`{key}=` + openers of 1 to {openers} backslashes"),
            text,
        );
    }
    t.hostile_completes(
        "`password=\\\"` then `password=\\\\\\\"` x N",
        r#"password=\"password=\\\""#.repeat((2 << 20) / 24 + 1),
    );
    t.finish();
}

#[test]
fn camel_case_keys_are_secret_keys_in_text() {
    // The pair scan uses the same vocabulary as rule S and D: `userPass` is `user`
    // and `Pass`.
    let mut t = Table::default();
    t.row("userPass=x", "userPass=[redacted]");
    // A digit before the capital is a boundary as a lower-case letter is.
    t.row("db2Pass=x&y=1", "db2Pass=[redacted]&y=1");
    t.row("a=1&sessionKey=zz&b=2", "a=1&sessionKey=[redacted]&b=2");
    t.row("x adminPw=zz y", "x adminPw=[redacted] y");
    t.row("totpCode=123456&x=1", "totpCode=[redacted]&x=1");
    t.row("x authKey: y", "x authKey: [redacted]");
    t.row("authKey: y\nok", "authKey: [redacted]\nok");
    t.row(
        r#"{"dbPass":"x","user":"u"}"#,
        r#"{"dbPass":"[redacted]","user":"u"}"#,
    );
    t.unchanged("bypassCache=1&compassPoint=n&author=bob&Passed=1");
    t.finish();
}

#[test]
fn folded_header_lines_and_zero_width_blanks_are_part_of_the_header() {
    // A header value may continue on following lines that start with a space or a
    // tab, and a zero-width character between the name and the colon is no name.
    let mut t = Table::default();
    t.row(
        "Cookie: a=b;\r\n c=CNRYx9q7\r\nHost: x",
        "Cookie: [redacted]\r\nHost: x",
    );
    t.row(
        "Cookie: a=b;\r\n\tc=X\r\n\td=Y\r\nHost: x",
        "Cookie: [redacted]\r\nHost: x",
    );
    t.row(
        "Authorization: Digest a=1,\n b=2\nnext",
        "Authorization: [redacted]\nnext",
    );
    t.row("X-Api-Key: a\r\n b\r\nok", "X-Api-Key: [redacted]\r\nok");
    t.row(
        "Cookie:\r\n a=b;\r\n c=X\r\nHost: x",
        "Cookie: [redacted]\r\nHost: x",
    );
    for zero_width in ["\u{200b}", "\u{200c}", "\u{200d}", "\u{2060}", "\u{feff}"] {
        t.row(
            &format!("Cookie{zero_width}: a=b; c=X"),
            &format!("Cookie{zero_width}: [redacted]"),
        );
    }
    t.row(
        "Authorization\u{feff}: Bearer X",
        "Authorization\u{feff}: [redacted]",
    );
    // Lines that do not start with a blank are not part of the header, and a header
    // that is not a credential keeps its folded lines.
    t.row("Cookie: a=b\r\nHost: x", "Cookie: [redacted]\r\nHost: x");
    t.unchanged("Accept: a\r\n b\r\nHost: x");
    t.unchanged("Cookie:");
    t.finish();
}

#[test]
fn xml_elements_with_a_secret_name_are_masked() {
    let mut t = Table::default();
    t.row(
        "<password>CNRYx9q7</password>",
        "<password>[redacted]</password>",
    );
    t.row(
        r#"<config><dbPass type="text">CNRYx9q7</dbPass><user>a</user></config>"#,
        r#"<config><dbPass type="text">[redacted]</dbPass><user>a</user></config>"#,
    );
    t.row("<token>a b c</token>", "<token>[redacted]</token>");
    t.row(
        "<ns:api_key>CNRYx9q7</ns:api_key>",
        "<ns:api_key>[redacted]</ns:api_key>",
    );
    t.row(
        "<password><![CDATA[CNRYx9q7]]></password>",
        "<password>[redacted]</password>",
    );
    t.row(
        r#"<password hint="a>b">CNRYx9q7</password>"#,
        r#"<password hint="a>b">[redacted]</password>"#,
    );
    t.row("<password>CNRYx9q7", "<password>[redacted]");
    // Not secret names, empty elements, and a tag that is not closed.
    t.unchanged("<author>bob</author>");
    t.unchanged("<passed>yes</passed>");
    t.unchanged("<user>alice</user>");
    t.unchanged("<password/>");
    t.unchanged("<password></password>");
    t.unchanged("<password> </password>");
    t.unchanged("a <password b");
    t.unchanged("1 < 2 and 3 > 2");

    // Hostile, 2 MiB each.
    t.hostile_completes("`<password>` x N", "<password>".repeat((2 << 20) / 10 + 1));
    t.hostile_completes("`<password ` x N", "<password ".repeat((2 << 20) / 10 + 1));
    t.hostile_completes(
        "`<password>x` x N",
        "<password>x".repeat((2 << 20) / 11 + 1),
    );
    t.hostile_completes(
        "`<password><![CDATA[` x N",
        "<password><![CDATA[".repeat((2 << 20) / 19 + 1),
    );
    t.finish();
}

#[test]
fn multipart_fields_with_a_secret_name_are_masked() {
    let mut t = Table::default();
    t.row(
        "Content-Disposition: form-data; name=\"password\"\r\n\r\nCNRYx9q7\r\n--boundary--",
        "Content-Disposition: form-data; name=\"password\"\r\n\r\n[redacted]\r\n--boundary--",
    );
    t.row(
        "name=\"password\"\n\nCNRYx9q7\n--b",
        "name=\"password\"\n\n[redacted]\n--b",
    );
    t.row(
        "name='api_token'\r\n\r\nCNRYx9q7\r\n--b",
        "name='api_token'\r\n\r\n[redacted]\r\n--b",
    );
    // A header line between the name and the blank line.
    t.row(
        "name=\"api_token\"\r\nContent-Type: text/plain\r\n\r\nCNRYx9q7\r\n--b",
        "name=\"api_token\"\r\nContent-Type: text/plain\r\n\r\n[redacted]\r\n--b",
    );
    // Other fields, an empty value, and a `name` with no part body after it.
    t.unchanged("name=\"username\"\r\n\r\nalice\r\n--b");
    t.unchanged("name=\"password\"\r\n\r\n\r\n--b");
    t.unchanged("<input name=\"password\" value=\"x\">");
    t.unchanged("name=\"password\"");

    // Hostile, 2 MiB each: field names with no blank line after them, and many
    // complete parts.
    t.hostile_completes(
        "`name=\"password\"` + CRLF x N",
        "name=\"password\"\r\n".repeat((2 << 20) / 17 + 1),
    );
    t.hostile_completes(
        "complete parts x N",
        "name=\"password\"\r\n\r\nx\r\n".repeat((2 << 20) / 21 + 1),
    );
    t.finish();
}

#[test]
fn cli_flags_with_a_secret_name_are_masked() {
    let mut t = Table::default();
    t.row(
        "curl --password CNRYx9q7 https://x.test",
        "curl --password [redacted] https://x.test",
    );
    t.row("run --token CNRYx9q7", "run --token [redacted]");
    t.row("run --db-pass 'a b' next", "run --db-pass [redacted] next");
    t.row(
        "run --private-key \"a b\" next",
        "run --private-key [redacted] next",
    );
    t.row("run --api-key=CNRYx9q7", "run --api-key=[redacted]");
    t.row("run --token\tCNRYx9q7 x", "run --token\t[redacted] x");
    // Flags that are not secret names, a flag with no value, and short flags.
    t.unchanged("run --passed ok");
    t.unchanged("run --author bob --verbose");
    t.unchanged("run --user admin");
    t.unchanged("run --token");
    t.unchanged("run -p hunter2");

    // Hostile, 2 MiB: a flag that is the value of the one before it.
    t.hostile_completes("`--token ` x N", "--token ".repeat((2 << 20) / 8 + 1));
    t.finish();
}

#[test]
fn the_pair_value_rule_matches_scrub_text() {
    // P6 keeps its own copy of `scrub_text`'s value rule (`redact.rs` is shared and
    // is not edited for the audit log). The two must end a masked value at the same
    // place, whatever follows the key, so each tail is masked by `scrub_text` after
    // a shared key and by `scrub_strict` after an extra one.
    let tails: &[&str] = &[
        "=abc&z=1",
        "=abc;z=1",
        "=abc,z=1",
        "=abc\"z",
        "=abc'z",
        "=abc}z",
        "=abc z=1",
        "=abc\u{a0}z=1",
        "=abc\u{2028}z=1",
        ": abc def",
        ":abc def",
        "= abc def",
        "=\nabc def",
        ":\n  abc def",
        "=",
        "= ",
        "=&z=1",
        "=\"a b\" z=1",
        "='a b' z=1",
        "=\"\"",
        "=''",
        "=\"a\\\"b\" z=1",
        "='a\\'b' z=1",
        "=\"a=\" z=1",
        "=\"x\"y z",
        "=\"unclosed z=1",
        "='unclosed z=1",
        "=\"a b\"=\"c d\" e=f",
        // A quote after `=` that opens the next value is not the end of this one.
        "=\"a b y=\"c\" z",
        "='a b y='c' z",
        "=\"a b' c=d",
        ":\"a b\" ,\"c\":\"d\"",
    ];
    let mut failures = Vec::new();
    for tail in tails {
        let shared = scrub_text_after(&format!("x token{tail}"), "x token");
        let strict = scrub_strict(&format!("x pass{tail}"));
        let strict = strict.strip_prefix("x pass");
        if shared.as_deref() != strict {
            failures.push(format!(
                "tail {tail:?}: scrub_text gives {shared:?}, scrub_strict gives {strict:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} tails are masked to a different end:\n{}",
        failures.len(),
        tails.len(),
        failures.join("\n")
    );
}

/// `scrub_text(text)` without its leading `prefix`.
fn scrub_text_after(text: &str, prefix: &str) -> Option<String> {
    aitm_core::redact::scrub_text(text)
        .strip_prefix(prefix)
        .map(str::to_string)
}

#[test]
fn every_prefix_of_every_shape_fires() {
    // (prefixes, one body character, the shortest body). A table that gained a
    // prefix without a way to reach it would fail here.
    let shapes: &[(&[&str], &str, usize)] = &[
        (
            &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA"],
            "A",
            16,
        ),
        (&["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], "a", 36),
        (&["github_pat_"], "a", 22),
        (&["glpat-"], "a", 20),
        (&["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"], "1", 10),
        (&["sk_live_", "sk_test_", "rk_live_", "rk_test_"], "a", 16),
        (&["sk-"], "a", 32),
        (&["AIza"], "a", 35),
    ];
    let mut failures = Vec::new();
    let mut prefixes = 0;
    for (names, body, shortest) in shapes {
        for prefix in *names {
            prefixes += 1;
            let full = format!("{prefix}{}", body.repeat(*shortest));
            let short = format!("{prefix}{}", body.repeat(shortest - 1));
            let glued = format!("x{full}");
            let name = format!("[{prefix}]");
            for (label, input, want) in [
                ("full", &full, "[redacted]"),
                ("one short", &short, short.as_str()),
                ("glued to a word", &glued, glued.as_str()),
            ] {
                let got = scrub_strict(input);
                if got != want {
                    failures.push(format!("{name} {label}: {input:?} gives {got:?}"));
                }
            }
        }
    }
    assert_eq!(
        prefixes, 25,
        "the list above names every prefix of the shape table (7 AWS, 5 GitHub, 1 github_pat, 1 GitLab, 5 Slack, 4 Stripe, 1 sk-, 1 Google)"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_bounded_scrub_cuts_first_and_masks_what_straddles_the_cut() {
    let mut failures = Vec::new();
    let mut check = |label: &str, got: String, want: String| {
        if got != want {
            failures.push(format!("{label}: want {want:?}, got {got:?}"));
        }
    };

    // A secret at byte 200 of a 100 KiB text is masked, and the result is short.
    let big = format!(
        "{}password=CNRYx9q7 {}",
        "a ".repeat(100),
        "z".repeat(100 * 1024)
    );
    check(
        "a secret inside the bound",
        scrub_strict_bounded(&big, 256),
        format!(
            "{}password=[redacted] {}…",
            "a ".repeat(100),
            "z".repeat(38)
        ),
    );
    // A secret the cut falls in: what is left of it is an unquoted value.
    check(
        "a secret cut in the middle",
        scrub_strict_bounded(&format!("{}password=CNRYx9q7ab", "x ".repeat(100)), 210),
        format!("{}password=[redacted]", "x ".repeat(100)),
    );
    check(
        "a quoted secret cut in the middle",
        scrub_strict_bounded(
            &format!("{}password=\"CNRYx9q7ab\" z", "x ".repeat(100)),
            213,
        ),
        format!("{}password=\"[redacted]", "x ".repeat(100)),
    );
    // The cut falls on a char boundary, and a text within the bound is not cut.
    check(
        "a cut inside a character",
        scrub_strict_bounded("ééééé", 5),
        "éé…".to_string(),
    );
    check(
        "a text within the bound",
        scrub_strict_bounded("password=abc", 100),
        "password=[redacted]".to_string(),
    );
    check(
        "a text of exactly the bound",
        scrub_strict_bounded("password=abc", 12),
        "password=[redacted]".to_string(),
    );
    check(
        "a bound of zero",
        scrub_strict_bounded("abc", 0),
        "…".to_string(),
    );
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
        "Sec-WebSocket-Extensions",
        "Sec-WebSocket-Version",
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
        // The subprotocol list carries bearer tokens (`base64url.bearer.authorization
        // .k8s.io.<token>`): the name stays visible, the value does not.
        "Sec-WebSocket-Protocol",
    ] {
        if is_benign_header(name) {
            failures.push(format!("`{name}` should not be benign"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
