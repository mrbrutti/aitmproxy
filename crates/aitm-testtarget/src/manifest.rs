//! The planted-vuln manifest — **grader-only** ground truth.
//!
//! Spec §D5 / AC-M4-10: "The manifest is consumed only by the grader; it is
//! never served, never reachable over the proxy, and never handed to the agent
//! or the scripted driver." Nothing under [`crate::app`], `routes/`, `ws`,
//! `tls`, `control` or `speakers/` references this module; it is a pure, static
//! table, also emitted as YAML for humans.
//!
//! Three tables (scanner-v2 child spec D6):
//!
//! - [`manifest`]: one [`PlantedVuln`] per HTTP/WS seed (D3, D4) plus the three
//!   passive header rows;
//! - [`l4_manifest`]: one [`L4Asset`] per L4 speaker (D5) plus the legacy two;
//! - [`seed_index`]: one [`SeedRoute`] per seed on a real route, with how `/`
//!   links it (the *disc.* column), which the index test walks.

use serde::Serialize;

use crate::seed;

/// One planted vulnerability: a class, the route that serves it, and the inert
/// marker that proves a successful trigger. `vulnerable_path` and `patched_path`
/// are the same route — the app serves the vulnerable or patched behaviour of
/// that path by [`SeedMode`](crate::SeedMode), so the grader runs an identical
/// request against a vulnerable-mode target and its patched control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlantedVuln {
    pub id: String,
    pub class: String,
    pub vulnerable_path: String,
    pub patched_path: String,
    pub trigger_hint: String,
    pub success_signal: String,
}

fn planted(
    id: &str,
    class: &str,
    path: &str,
    trigger_hint: &str,
    success_signal: &str,
) -> PlantedVuln {
    PlantedVuln {
        id: id.to_string(),
        class: class.to_string(),
        vulnerable_path: path.to_string(),
        patched_path: path.to_string(),
        trigger_hint: trigger_hint.to_string(),
        success_signal: success_signal.to_string(),
    }
}

/// The planted vulnerabilities: the legacy six (M4 classes, which `grader.rs`
/// matches on), the seventeen T10 HTTP seeds, the two `/ws` seeds and the three
/// passive header rows (child spec D3, D4). Class tokens are T3's: every SQLi
/// technique is `sqli`, every reflection kind is `xss`. A pure table; never
/// wired into a route.
pub fn manifest() -> &'static [PlantedVuln] {
    use std::sync::OnceLock;
    static MANIFEST: OnceLock<Vec<PlantedVuln>> = OnceLock::new();
    MANIFEST
        .get_or_init(|| {
            vec![
                // --- legacy six (M4) -------------------------------------
                planted(
                    "reflected-xss-search-q",
                    "reflected-xss",
                    "/search",
                    "GET /search?q=<marker> — the q parameter is reflected into HTML",
                    seed::REFLECTED_XSS_MARKER,
                ),
                planted(
                    "stored-xss-comments",
                    "stored-xss",
                    "/comments",
                    "POST /comments body=<marker>, then GET /comments renders it to a later reader",
                    seed::STORED_XSS_MARKER,
                ),
                planted(
                    "ssrf-fetch-preview",
                    "ssrf",
                    "/fetch",
                    "GET /fetch?url=http://169.254.169.254/latest/meta-data — server-side dereferences the URL",
                    seed::SSRF_MARKER,
                ),
                planted(
                    "idor-account",
                    "idor",
                    "/account/{id}",
                    "GET /account/2 as a different user (default X-User-Id: 1) — no ownership check",
                    seed::IDOR_MARKER,
                ),
                planted(
                    "auth-bypass-admin-role",
                    "auth-bypass",
                    "/admin",
                    "GET /admin with a client-supplied X-Role: admin header — the role is trusted",
                    seed::AUTH_BYPASS_MARKER,
                ),
                planted(
                    "open-redirect-next",
                    "open-redirect",
                    "/redirect",
                    "GET /redirect?next=https://<marker>/ — no allowlist on the Location target",
                    seed::OPEN_REDIRECT_MARKER,
                ),
                // --- T10 injection seeds (D3) ----------------------------
                planted(
                    "sqli-error-products-id",
                    "sqli",
                    "/products",
                    "GET /products?id=1' — an id containing ' or \" answers 500 <pre>SQL syntax error near '<id raw>'</pre>; patched: non-integer id -> 400 invalid id",
                    seed::SQLI_ERROR_SIGNAL,
                ),
                planted(
                    "sqli-boolean-items-id",
                    "sqli",
                    "/items",
                    "GET /items?id=1 AND 1=1 vs id=1 AND 1=2 differ (<p>items: 1</p> / <p>items: 0</p>); id=1 OR 1=1 -> all five; patched: integer only, else 400; never sleeps in either mode (the timing seed is /orders)",
                    "<p>items: 5</p>",
                ),
                planted(
                    "sqli-time-orders-id",
                    "sqli",
                    "/orders",
                    "GET /orders?id=1 AND SLEEP(3) (also pg_sleep(n), WAITFOR DELAY '0:0:n', case-insensitive) sleeps min(n,5) s before <p>order <id></p>; patched: integer only, else 400, never sleeps",
                    "elapsed >= n s",
                ),
                planted(
                    "cmdi-ping-host",
                    "cmdi",
                    "/ping",
                    "GET /ping?host=127.0.0.1;id — ; | && ` $( introduce a command: id appends the marker, sleep n sleeps min(n,5) s; patched: host must match ^[A-Za-z0-9.-]{1,253}$ else 400",
                    seed::CMDI_MARKER,
                ),
                planted(
                    "ssti-greet-name",
                    "ssti",
                    "/greet",
                    &format!("GET /greet?name={} — {{{{a*b}}}} / ${{a*b}} are evaluated into <h1>{}</h1>; patched escapes, never evaluates", seed::SSTI_PROBE, seed::SSTI_SIGNAL),
                    seed::SSTI_SIGNAL,
                ),
                planted(
                    "traversal-static-file",
                    "path-traversal",
                    "/static",
                    "GET /static?file=../../etc/passwd (also ..%2f, ....//) — a ../ path ending etc/passwd serves the marker as text/plain; patched: any .. or / -> 400, allowlist style.css|app.js|readme.txt only",
                    seed::TRAVERSAL_MARKER,
                ),
                planted(
                    "xxe-order-name",
                    "xxe",
                    "/xml",
                    "POST /xml text/xml with <!ENTITY e SYSTEM \"file:///etc/passwd\"> referenced as &e; inside <name> — expands to the marker in <p>Order for <name raw></p>; patched: any <!DOCTYPE -> 400 DTD not allowed",
                    seed::TRAVERSAL_MARKER,
                ),
                planted(
                    "crlf-lang-set",
                    "crlf",
                    "/lang",
                    "GET /lang?set=en%0d%0aX-Injected:%201 — the value is split on CRLF, the first part becomes Set-Cookie: lang=<v> and each following Name: value line its own response header; patched strips CR and LF",
                    "x-injected: 1",
                ),
                planted(
                    "nosqli-json-login",
                    "nosqli",
                    "/api/login",
                    &format!("POST /api/login JSON {{\"username\":\"{}\",\"password\":{{\"$ne\":\"\"}}}} — an object password logs in and answers {{\"ok\":true,\"marker\":...}}; a string password equal to the fixture {:?} answers {{\"ok\":true,\"user\":\"{}\"}}; patched: non-string password -> 400 {{\"error\":\"password must be a string\"}}", seed::SESSION_USER, seed::SESSION_PASS, seed::SESSION_USER),
                    seed::NOSQLI_MARKER,
                ),
                planted(
                    "ldapi-ldap-user",
                    "ldapi",
                    "/ldap",
                    &format!("GET /ldap?user=* — the filter (uid=<user>) is built raw: * lists {}, bob, carol plus the marker; )( or an unbalanced filter answers 500 {}; patched applies RFC 4515 escaping of * ( ) \\ NUL", seed::SESSION_USER, seed::LDAPI_ERROR_SIGNAL),
                    seed::LDAPI_ALL_USERS_MARKER,
                ),
                // --- T10 reflection seeds (D3; class reflected-xss, kind per row) ---
                planted(
                    "header-reflection-whoami",
                    "reflected-xss",
                    "/whoami",
                    "GET /whoami — User-Agent and X-Forwarded-For are reflected raw into <p>agent: ...</p><p>from: ...</p>; patched escapes",
                    "reflection kind header (AC T2-3)",
                ),
                planted(
                    "cookie-reflection-prefs",
                    "reflected-xss",
                    "/prefs",
                    "GET /prefs with Cookie: theme=<value> — reflected raw into <body class=\"...\">; no cookie -> Set-Cookie: theme=light; Path=/; patched escapes",
                    "reflection kind cookie (AC T2-3)",
                ),
                planted(
                    "nested-json-reflection-profile",
                    "reflected-xss",
                    "/api/profile",
                    "POST /api/profile JSON {\"profile\":{\"address\":{\"city\":\"<value>\"}}} — city is reflected raw into text/html <div class=\"city\">...</div>; patched escapes",
                    "reflection kind json_value path profile.address.city (AC T2-2)",
                ),
                planted(
                    "multipart-reflection-upload",
                    "reflected-xss",
                    "/upload",
                    "POST /upload multipart with a file part (filename) and a note field — both reflected raw into <p>uploaded <filename> (<n> bytes): <note></p>; patched escapes",
                    "reflection kinds multipart_value and multipart_filename",
                ),
                planted(
                    "path-segment-docs-slug",
                    "reflected-xss",
                    "/docs/{slug}",
                    "GET /docs/<slug> (non-numeric segment) — reflected raw into <h1>Doc: ...</h1>; patched escapes",
                    "reflection kind path_segment",
                ),
                planted(
                    "path-filename-files",
                    "reflected-xss",
                    "/files/{name}.txt",
                    "GET /files/<name>.txt — the stem is reflected raw into <p>file <name>.txt</p>; patched escapes",
                    "reflection kind path_filename",
                ),
                planted(
                    "auth-only-account-tab",
                    "reflected-xss",
                    "/account",
                    &format!("GET /account?tab=<value> with a valid session cookie (POST /login user={}&pass={}) — reflected raw into <h2>Account: ...</h2>; without a session -> 302 /login in both modes; patched escapes", seed::SESSION_USER, seed::SESSION_PASS),
                    "reflection reachable only with the observed session (AC T2-4)",
                ),
                // --- /ws seeds (D4) -------------------------------------
                planted(
                    "ws-cswsh",
                    "cswsh",
                    "/ws",
                    "GET /ws upgrade with a foreign Origin (e.g. https://evil.example) — the vulnerable handshake accepts any Origin and sends the hello frame; patched answers 403 <p>forbidden origin</p> unless Origin is absent or equals <scheme>://<Host>",
                    "{\"type\":\"hello\"",
                ),
                planted(
                    "ws-input-reflection",
                    "ws-input-reflection",
                    "/ws",
                    "text frame {\"type\":\"echo\",\"msg\":\"<b>x\"} (or type chat) — the reply's html field carries msg raw in the vulnerable mode and HTML-escaped in the patched one",
                    "\"html\":\"<b>",
                ),
                // --- passive header rows (D3 last row; AC T10-3) ---------
                planted(
                    "passive-missing-hsts",
                    "missing-hsts",
                    "/",
                    "any response — the vulnerable mode omits the header; patched sends Strict-Transport-Security: max-age=31536000 on every response",
                    "Strict-Transport-Security header absent",
                ),
                planted(
                    "passive-missing-csp",
                    "missing-csp",
                    "/",
                    "any response — the vulnerable mode omits the header; patched sends Content-Security-Policy: default-src 'self' on every response",
                    "Content-Security-Policy header absent",
                ),
                planted(
                    "passive-missing-nosniff",
                    "missing-nosniff",
                    "/",
                    "any response — the vulnerable mode omits the header; patched sends X-Content-Type-Options: nosniff on every response",
                    "X-Content-Type-Options header absent",
                ),
            ]
        })
        .as_slice()
}

/// The manifest rendered as YAML, for humans reviewing what was planted. This is
/// a developer/grader artifact; like [`manifest`] it is never served.
pub fn manifest_yaml() -> String {
    serde_yaml::to_string(manifest()).expect("manifest is always serializable")
}

/// One in-scope L4 asset the opt-in loopback services expose. Like
/// [`PlantedVuln`] this is **grader-only** ground truth: it declares what an
/// authorized operator may act on with the L4 capabilities, and is never served
/// or handed to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct L4Asset {
    pub id: String,
    /// Transport protocol: `"udp"` or `"tcp"`.
    pub proto: String,
    /// The interface the service binds — always `127.0.0.1` (hermetic loopback).
    pub bind: String,
    /// The benign exchange (child spec D5 "benign exchange" column).
    pub behaviour: String,
    /// Always `true`: the service is in-scope by construction.
    pub in_scope: bool,
    /// The speaker grammar (`tlv`, `dns`, `raw`, `resp`, `memcached`, `modbus`,
    /// `mqtt`, `smtp`, `ftp`); `None` for the legacy echo/banner pair, which has
    /// no speaker.
    pub grammar: Option<String>,
    /// What opens the 5 s crash window in the vulnerable mode (D5 "V trigger"
    /// column); `"none"` for the legacy pair, which has no trigger.
    pub trigger: String,
}

fn l4_asset(id: &str, proto: &str, behaviour: &str) -> L4Asset {
    L4Asset {
        id: id.to_string(),
        proto: proto.to_string(),
        bind: "127.0.0.1".to_string(),
        behaviour: behaviour.to_string(),
        in_scope: true,
        grammar: None,
        trigger: "none".to_string(),
    }
}

fn speaker(id: &str, proto: &str, grammar: &str, behaviour: &str, trigger: &str) -> L4Asset {
    L4Asset {
        grammar: Some(grammar.to_string()),
        trigger: trigger.to_string(),
        ..l4_asset(id, proto, behaviour)
    }
}

/// The in-scope L4 assets: the legacy echo/banner pair of
/// [`L4Service`](crate::L4Service) and the nine speaker services of child spec
/// D5. A pure table, grader-only like [`manifest`]; never wired into a served
/// route. `behaviour` is D5's benign column, `trigger` its V-trigger column,
/// both written as hex or text exactly as the spec spells them.
pub fn l4_manifest() -> &'static [L4Asset] {
    use std::sync::OnceLock;
    static L4_MANIFEST: OnceLock<Vec<L4Asset>> = OnceLock::new();
    L4_MANIFEST
        .get_or_init(|| {
            vec![
                // --- legacy two -----------------------------------------
                l4_asset(
                    "l4-udp-echo",
                    "udp",
                    "echoes each datagram back to its sender, byte for byte",
                ),
                l4_asset(
                    "l4-tcp-service",
                    "tcp",
                    "writes a banner on connect, then echoes one bounded read",
                ),
                // --- D5 speakers ----------------------------------------
                speaker(
                    "l4-tlv-crash",
                    "tcp",
                    "tlv",
                    "frame = u16 BE len + payload; 00 03 61 62 63 -> same (echo); liveness 00 00 -> 00 00",
                    "declared len > 4096, or declared len > bytes received after a 200 ms idle",
                ),
                speaker(
                    "l4-dns-fault",
                    "udp",
                    "dns",
                    "A query id 1234 for example.test -> header 12 34 81 80, QD 1 AN 1, question echoed, answer c0 0c 00 01 00 01 00 00 00 3c 00 04 7f 00 00 01; liveness: A query for . -> A 127.0.0.1",
                    "a label length byte past the datagram end",
                ),
                speaker(
                    "l4-udp-payload-crash",
                    "udp",
                    "raw",
                    "61 62 63 -> 61 62 63 (echo); any datagram echoed",
                    "payload starts DE AD BE EF and len >= 8",
                ),
                speaker(
                    "l4-resp",
                    "tcp",
                    "resp",
                    r"*1\r\n$4\r\nPING\r\n or inline PING\r\n -> +PONG\r\n; ECHO hi -> $2\r\nhi\r\n; GET k -> $-1\r\n; QUIT -> +OK\r\n then close; unknown -> -ERR unknown command '<name>'\r\n; liveness PING",
                    "$N with N > 1048576; *N with fewer than N elements after a 200 ms idle",
                ),
                speaker(
                    "l4-memcached",
                    "tcp",
                    "memcached",
                    r"version\r\n -> VERSION 1.6.0-aitm\r\n; get k\r\n -> END\r\n; set k 0 0 2\r\nhi\r\n -> STORED\r\n; quit closes; unknown -> ERROR\r\n; liveness version",
                    "announced bytes > 1048576; a line > 2048 bytes without CRLF",
                ),
                speaker(
                    "l4-modbus",
                    "tcp",
                    "modbus",
                    "00 01 00 00 00 06 01 03 00 00 00 01 -> 00 01 00 00 00 05 01 03 02 00 00 (fc 3, registers = addr+i as u16); liveness fc 3, addr 0, qty 1",
                    "MBAP length > 260 or < 2 (shorter than unit id + fc)",
                ),
                speaker(
                    "l4-mqtt",
                    "tcp",
                    "mqtt",
                    "CONNECT 10 0C 00 04 4D 51 54 54 04 02 00 3C 00 00 -> CONNACK 20 02 00 00; PINGREQ C0 00 -> D0 00; PUBLISH QoS1 32 09 00 03 61 2F 62 00 01 68 69 -> PUBACK 40 02 00 01; QoS0 accepted silently; SUBSCRIBE -> SUBACK QoS0; DISCONNECT E0 00 closes; liveness CONNECT + DISCONNECT",
                    "remaining-length varint with a 5th byte, or value > 65536",
                ),
                speaker(
                    "l4-smtp",
                    "tcp",
                    "smtp",
                    r"banner 220 target.test ESMTP aitm\r\n; EHLO x / HELO x -> 250 target.test\r\n; MAIL FROM:<a@target.test> -> 250 OK\r\n; RCPT TO:<b@target.test> -> 250 OK\r\n; NOOP -> 250 OK\r\n; DATA -> 451 not accepted\r\n; QUIT -> 221 bye\r\n then close; unknown -> 500 unknown command\r\n; liveness NOOP",
                    "a line > 1024 bytes without CRLF",
                ),
                speaker(
                    "l4-ftp",
                    "tcp",
                    "ftp",
                    r#"banner 220 aitm ftp\r\n; USER a -> 331 password required\r\n; PASS b -> 230 logged in\r\n; NOOP -> 200 ok\r\n; PWD -> 257 "/"\r\n; TYPE I -> 200 ok\r\n; QUIT -> 221 bye\r\n then close; unknown -> 500 unknown command\r\n; liveness NOOP"#,
                    "a line > 1024 bytes without CRLF",
                ),
            ]
        })
        .as_slice()
}

/// How the index page `/` makes a seed route discoverable (child spec D3
/// *disc.* column): an `<a href>`, a `<form>`, an inline `<script>` `fetch`, a
/// click-only `onclick` span, or the inline script's WebSocket open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Discovery {
    Anchor,
    Form,
    Script,
    Click,
    Ws,
}

/// One seed route as `/` links it: the planted id, the method the link drives,
/// the concrete path in the link (templated routes carry the linked instance,
/// e.g. `/docs/intro` for `/docs/{slug}`) and the link kind. Grader/test-only
/// like the other tables; the index test walks it against the served `/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SeedRoute {
    pub id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub discovery: Discovery,
}

const fn seed_route(
    id: &'static str,
    method: &'static str,
    path: &'static str,
    discovery: Discovery,
) -> SeedRoute {
    SeedRoute {
        id,
        method,
        path,
        discovery,
    }
}

/// One row per planted seed on a real route (the three passive rows, which are
/// properties of every response, have none). `/search` and `/comments` are
/// linked by both an anchor and a form; their rows record the form, since the
/// anchor is pinned separately by the index test. `/ws` carries two seeds
/// and so appears twice, once per id.
pub fn seed_index() -> &'static [SeedRoute] {
    static SEED_INDEX: [SeedRoute; 25] = [
        seed_route("reflected-xss-search-q", "GET", "/search", Discovery::Form),
        seed_route("stored-xss-comments", "POST", "/comments", Discovery::Form),
        seed_route("ssrf-fetch-preview", "GET", "/fetch", Discovery::Anchor),
        seed_route("idor-account", "GET", "/account/1", Discovery::Anchor),
        seed_route("auth-bypass-admin-role", "GET", "/admin", Discovery::Anchor),
        seed_route("open-redirect-next", "GET", "/redirect", Discovery::Anchor),
        seed_route(
            "sqli-error-products-id",
            "GET",
            "/products",
            Discovery::Anchor,
        ),
        seed_route("sqli-boolean-items-id", "GET", "/items", Discovery::Anchor),
        seed_route(
            "sqli-time-orders-id",
            "GET",
            "/orders?id=1",
            Discovery::Anchor,
        ),
        seed_route("cmdi-ping-host", "GET", "/ping", Discovery::Anchor),
        seed_route("ssti-greet-name", "GET", "/greet", Discovery::Anchor),
        seed_route("traversal-static-file", "GET", "/static", Discovery::Anchor),
        seed_route("xxe-order-name", "POST", "/xml", Discovery::Script),
        seed_route("crlf-lang-set", "GET", "/lang", Discovery::Anchor),
        seed_route("nosqli-json-login", "POST", "/api/login", Discovery::Script),
        seed_route("ldapi-ldap-user", "GET", "/ldap", Discovery::Anchor),
        seed_route(
            "header-reflection-whoami",
            "GET",
            "/whoami",
            Discovery::Anchor,
        ),
        seed_route(
            "cookie-reflection-prefs",
            "GET",
            "/prefs",
            Discovery::Anchor,
        ),
        seed_route(
            "nested-json-reflection-profile",
            "POST",
            "/api/profile",
            Discovery::Script,
        ),
        seed_route(
            "multipart-reflection-upload",
            "POST",
            "/upload",
            Discovery::Form,
        ),
        seed_route(
            "path-segment-docs-slug",
            "GET",
            "/docs/intro",
            Discovery::Anchor,
        ),
        seed_route(
            "path-filename-files",
            "GET",
            "/files/readme.txt",
            Discovery::Click,
        ),
        seed_route(
            "auth-only-account-tab",
            "GET",
            "/account?tab=overview",
            Discovery::Anchor,
        ),
        seed_route("ws-cswsh", "GET", "/ws", Discovery::Ws),
        seed_route("ws-input-reflection", "GET", "/ws", Discovery::Ws),
    ];
    &SEED_INDEX
}

#[cfg(test)]
mod tests {
    //! Table-shape tests (hermetic): the planted classes, the L4 grammars and
    //! the seed index are pinned to the child spec's D3/D5/D6 literals.

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn manifest_has_every_class() {
        let classes: BTreeSet<&str> = manifest().iter().map(|v| v.class.as_str()).collect();
        let expected: BTreeSet<&str> = [
            "reflected-xss",
            "stored-xss",
            "ssrf",
            "idor",
            "auth-bypass",
            "open-redirect",
            "sqli",
            "cmdi",
            "ssti",
            "path-traversal",
            "xxe",
            "crlf",
            "nosqli",
            "ldapi",
            "cswsh",
            "ws-input-reflection",
            "missing-hsts",
            "missing-csp",
            "missing-nosniff",
        ]
        .into_iter()
        .collect();
        assert_eq!(classes, expected);

        // T3's class token: every reflection kind is `reflected-xss`, the
        // same class as the legacy `/search` row (there is no `xss` class).
        for id in [
            "header-reflection-whoami",
            "cookie-reflection-prefs",
            "nested-json-reflection-profile",
            "multipart-reflection-upload",
            "path-segment-docs-slug",
            "path-filename-files",
            "auth-only-account-tab",
        ] {
            let row = manifest()
                .iter()
                .find(|v| v.id == id)
                .unwrap_or_else(|| panic!("row {id}"));
            assert_eq!(row.class, "reflected-xss", "{id}");
        }
        assert_eq!(
            manifest()
                .iter()
                .filter(|v| v.class == "reflected-xss")
                .count(),
            8
        );

        // Ids are unique: the grader reports `missing` by id.
        let ids: BTreeSet<&str> = manifest().iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids.len(), manifest().len(), "planted ids must be unique");

        // D3 has 23 HTTP rows, D4 two WS rows, D3 three passive rows.
        assert_eq!(manifest().len(), 28);

        // A few D3 literals, so a retyped row is caught.
        let by_id = |id: &str| {
            manifest()
                .iter()
                .find(|v| v.id == id)
                .unwrap_or_else(|| panic!("manifest row {id} missing"))
        };
        assert_eq!(by_id("sqli-error-products-id").vulnerable_path, "/products");
        assert_eq!(
            by_id("sqli-error-products-id").success_signal,
            "SQL syntax error near"
        );
        assert_eq!(by_id("sqli-time-orders-id").vulnerable_path, "/orders");
        assert_eq!(by_id("sqli-time-orders-id").patched_path, "/orders");
        assert!(
            by_id("sqli-time-orders-id")
                .trigger_hint
                .contains("/orders?id=1 AND SLEEP(3)"),
            "{}",
            by_id("sqli-time-orders-id").trigger_hint
        );
        assert!(
            by_id("sqli-boolean-items-id")
                .trigger_hint
                .contains("never sleeps"),
            "{}",
            by_id("sqli-boolean-items-id").trigger_hint
        );
        assert!(
            manifest().iter().all(|v| v.id != "sqli-time-items"),
            "the time seed left /items"
        );
        assert_eq!(
            by_id("cmdi-ping-host").success_signal,
            "uid=0(root) gid=0(root)"
        );
        assert_eq!(
            by_id("traversal-static-file").success_signal,
            "root:x:0:0:root:/root:/bin/bash"
        );
        assert_eq!(by_id("xxe-order-name").vulnerable_path, "/xml");
        assert_eq!(by_id("ssti-greet-name").success_signal, "Hello 49");
        // The format!-built hints render the seed constants with braces intact.
        assert!(
            by_id("ssti-greet-name").trigger_hint.starts_with(
                "GET /greet?name={{7*7}} — {{a*b}} / ${a*b} are evaluated into <h1>Hello 49</h1>"
            ),
            "{}",
            by_id("ssti-greet-name").trigger_hint
        );
        assert!(
            by_id("nosqli-json-login")
                .trigger_hint
                .contains(r#"{"username":"alice","password":{"$ne":""}}"#),
            "{}",
            by_id("nosqli-json-login").trigger_hint
        );
        assert!(
            by_id("ldapi-ldap-user").trigger_hint.contains(
                r"answers 500 Bad search filter; patched applies RFC 4515 escaping of * ( ) \ NUL"
            ),
            "{}",
            by_id("ldapi-ldap-user").trigger_hint
        );
        assert_eq!(by_id("nosqli-json-login").vulnerable_path, "/api/login");
        assert_eq!(
            by_id("nosqli-json-login").success_signal,
            "NOSQLI-LOGIN-MARKER-4b1d"
        );
        assert_eq!(
            by_id("ldapi-ldap-user").success_signal,
            "LDAP-ALL-USERS-MARKER-77c2"
        );
        assert_eq!(
            by_id("path-filename-files").vulnerable_path,
            "/files/{name}.txt"
        );
        assert_eq!(by_id("auth-only-account-tab").vulnerable_path, "/account");
        assert_eq!(by_id("ws-cswsh").vulnerable_path, "/ws");
        assert_eq!(by_id("ws-input-reflection").vulnerable_path, "/ws");
        assert_eq!(by_id("passive-missing-hsts").vulnerable_path, "/");
        assert_eq!(by_id("passive-missing-csp").class, "missing-csp");
        assert_eq!(by_id("passive-missing-nosniff").class, "missing-nosniff");

        // The table stays a vulnerable/patched pair on one route.
        for v in manifest() {
            assert_eq!(v.vulnerable_path, v.patched_path, "{}", v.id);
            assert!(!v.trigger_hint.is_empty(), "{} has no trigger_hint", v.id);
            assert!(
                !v.success_signal.is_empty(),
                "{} has no success_signal",
                v.id
            );
        }
    }

    #[test]
    fn l4_manifest_mqtt_publish_literal_is_well_formed() {
        // `32 09 00 03 61 2F 62 00 01 68 69`: fixed header, remaining length
        // 9 (topic length 2 + `a/b` 3 + packet id 2 + `hi` 2). The spec's
        // `32 0A` spelling is one byte short of its own payload and the
        // speaker reads it as an incomplete packet.
        let mqtt = l4_manifest()
            .iter()
            .find(|a| a.id == "l4-mqtt")
            .expect("l4-mqtt asset");
        assert!(
            mqtt.behaviour.contains("32 09 00 03 61 2F 62 00 01 68 69"),
            "{}",
            mqtt.behaviour
        );
        assert!(!mqtt.behaviour.contains("32 0A"), "{}", mqtt.behaviour);
    }

    #[test]
    fn l4_manifest_lists_nine_grammars() {
        let grammars: BTreeSet<&str> = l4_manifest()
            .iter()
            .filter_map(|a| a.grammar.as_deref())
            .collect();
        let expected: BTreeSet<&str> = [
            "tlv",
            "dns",
            "raw",
            "resp",
            "memcached",
            "modbus",
            "mqtt",
            "smtp",
            "ftp",
        ]
        .into_iter()
        .collect();
        assert_eq!(grammars, expected);
        assert_eq!(l4_manifest().len(), 11);

        // The legacy two are untouched apart from the new fields' neutral values.
        for id in ["l4-udp-echo", "l4-tcp-service"] {
            let legacy = l4_manifest()
                .iter()
                .find(|a| a.id == id)
                .unwrap_or_else(|| panic!("legacy asset {id} missing"));
            assert_eq!(legacy.grammar, None);
            assert_eq!(legacy.trigger, "none");
        }

        // Every speaker row names its V trigger and its benign exchange, binds
        // loopback and is in scope; proto follows D5.
        let proto_of = |id: &str| {
            l4_manifest()
                .iter()
                .find(|a| a.id == id)
                .unwrap_or_else(|| panic!("asset {id} missing"))
                .proto
                .as_str()
        };
        assert_eq!(proto_of("l4-dns-fault"), "udp");
        assert_eq!(proto_of("l4-udp-payload-crash"), "udp");
        assert_eq!(proto_of("l4-tlv-crash"), "tcp");
        assert_eq!(proto_of("l4-mqtt"), "tcp");
        for a in l4_manifest() {
            assert!(a.in_scope, "{}", a.id);
            assert_eq!(a.bind, "127.0.0.1", "{}", a.id);
            assert!(!a.behaviour.is_empty(), "{} has no behaviour", a.id);
            assert!(!a.trigger.is_empty(), "{} has no trigger", a.id);
        }
        let ids: BTreeSet<&str> = l4_manifest().iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids.len(), 11, "L4 asset ids must be unique");
    }

    #[test]
    fn seed_index_covers_manifest() {
        let indexed: BTreeSet<&str> = seed_index().iter().map(|r| r.id).collect();
        assert_eq!(
            indexed.len(),
            seed_index().len(),
            "seed_index ids must be unique"
        );

        // Every seed on a real route is discoverable from `/`; the passive rows
        // (path `/`) are properties of every response, not routes.
        for v in manifest().iter().filter(|v| v.vulnerable_path != "/") {
            assert!(
                indexed.contains(v.id.as_str()),
                "manifest seed {} has no seed_index row",
                v.id
            );
        }
        // And nothing is indexed that is not planted.
        let planted: BTreeSet<&str> = manifest().iter().map(|v| v.id.as_str()).collect();
        for r in seed_index() {
            assert!(
                planted.contains(r.id),
                "seed_index row {} is not planted",
                r.id
            );
            assert!(r.path.starts_with('/'), "{} path {:?}", r.id, r.path);
            assert!(
                matches!(r.method, "GET" | "POST"),
                "{} method {:?}",
                r.id,
                r.method
            );
        }

        // The D3 *disc.* column: templated routes are indexed by a concrete link.
        let row = |id: &str| {
            seed_index()
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("seed_index row {id} missing"))
        };
        assert_eq!(row("path-segment-docs-slug").path, "/docs/intro");
        assert_eq!(row("path-segment-docs-slug").discovery, Discovery::Anchor);
        assert_eq!(row("path-filename-files").path, "/files/readme.txt");
        assert_eq!(row("path-filename-files").discovery, Discovery::Click);
        assert_eq!(row("auth-only-account-tab").path, "/account?tab=overview");
        assert_eq!(row("xxe-order-name").discovery, Discovery::Script);
        assert_eq!(row("xxe-order-name").method, "POST");
        assert_eq!(row("nosqli-json-login").discovery, Discovery::Script);
        assert_eq!(
            row("nested-json-reflection-profile").discovery,
            Discovery::Script
        );
        assert_eq!(
            row("multipart-reflection-upload").discovery,
            Discovery::Form
        );
        assert_eq!(row("multipart-reflection-upload").method, "POST");
        assert_eq!(row("ws-cswsh").discovery, Discovery::Ws);
        assert_eq!(row("ws-cswsh").path, "/ws");
        assert_eq!(row("ws-input-reflection").discovery, Discovery::Ws);
        assert_eq!(row("sqli-boolean-items-id").path, "/items");
        assert_eq!(row("sqli-time-orders-id").path, "/orders?id=1");
        assert_eq!(row("sqli-time-orders-id").discovery, Discovery::Anchor);
        assert_eq!(
            seed_index().iter().filter(|r| r.path == "/items").count(),
            1,
            "/items appears once"
        );
    }

    // --- Tester additions (stage 5): the L4 table agrees with the speakers ---

    #[test]
    fn l4_manifest_matches_the_speaker_table() {
        // The grader's L4 rows and the served speakers describe the same nine
        // services: name, grammar and transport agree row for row.
        let defs = crate::speakers::driver::all();
        assert_eq!(defs.len(), 9);
        for def in &defs {
            let row = l4_manifest()
                .iter()
                .find(|a| a.id == def.name)
                .unwrap_or_else(|| panic!("no l4_manifest row for speaker {}", def.name));
            assert_eq!(row.grammar.as_deref(), Some(def.grammar), "{}", def.name);
            assert_eq!(row.proto, def.proto.as_str(), "{}", def.name);
        }
    }

    #[test]
    fn manifest_yaml_lists_every_planted_id() {
        let yaml = manifest_yaml();
        for v in manifest() {
            assert!(yaml.contains(&v.id), "yaml lacks {}", v.id);
            assert!(yaml.contains(&v.class), "yaml lacks class {}", v.class);
        }
    }
}
