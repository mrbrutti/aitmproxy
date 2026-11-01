//! The ten injection seeds (child spec D3): error/boolean/time SQLi, command
//! injection, SSTI, path traversal, XXE, CRLF header injection, NoSQL
//! injection and LDAP injection, each in its vulnerable and patched variant.
//!
//! Every seed is a hand-rolled recogniser of one payload family that resolves
//! to a constant from [`crate::seed`]: there is no database, no shell, no file
//! read, no XML or LDAP library and no socket anywhere below. "Executing" a
//! command means matching the literal `id`; "reading" `/etc/passwd` means
//! returning [`seed::TRAVERSAL_MARKER`]. That is what keeps this target
//! hermetic and safe to run on a laptop, and it is why the patched variants
//! are the interesting half: they pin what the scanner must *not* report.
//!
//! Parsing is bounded everywhere (fixed scan limits, no recursion, no entity
//! expansion inside entities) and nothing read from the request is ever
//! `unwrap`ped: a value that does not parse becomes a 400, never a panic.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

use crate::app::{html, html_escape, not_found, AppState, RequestInfo, Resp};
use crate::seed::{self, SeedMode};

/// The five rows the virtual `items` table holds (`/items?id=`).
const ITEM_COUNT: u32 = 5;

/// The directory entries `/static?file=` knows, with their content types. The
/// bodies are stubs; the only "file" with planted content is the virtual
/// `/etc/passwd` behind [`seed::TRAVERSAL_MARKER`].
const STATIC_FILES: [(&str, &str, &str); 3] = [
    (
        "readme.txt",
        "text/plain; charset=utf-8",
        "aitm-testtarget static assets\n",
    ),
    (
        "style.css",
        "text/css; charset=utf-8",
        "body { font-family: system-ui, sans-serif; }\n",
    ),
    (
        "app.js",
        "application/javascript; charset=utf-8",
        "console.log(\"aitm-testtarget\");\n",
    ),
];

/// The directory `/ldap?user=` searches.
const LDAP_USERS: [&str; 3] = [seed::SESSION_USER, "bob", "carol"];

/// Longest sleep any seed will honour, whatever the payload asks for.
const MAX_SLEEP_SECS: u64 = 5;

/// Most headers the CRLF seed will inject from one value.
const MAX_INJECTED_HEADERS: usize = 16;

/// Dispatch: only the nine paths below belong to this module; everything else
/// returns `None` so the router can fall through to the other route modules.
pub(crate) async fn route(info: &RequestInfo, state: &Arc<AppState>) -> Option<Resp> {
    let mode = state.mode;
    match (info.method.as_str(), info.path.as_str()) {
        ("GET", "/products") => {
            let id = info.query_param("id").unwrap_or_default();
            Some(sqli_error(mode, &id))
        }
        ("GET", "/items") => {
            let id = info.query_param("id").unwrap_or_default();
            // The timing seed shares the route with the boolean one: decide
            // first (pure), then sleep, then answer. Patched never sleeps.
            if mode == SeedMode::Vulnerable {
                if let Some(secs) = sleep_seconds(&id) {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                }
            }
            Some(sqli_items(mode, &id))
        }
        ("GET", "/ping") => {
            let host = info.query_param("host").unwrap_or_default();
            let (resp, sleep) = cmdi(mode, &host);
            if let Some(secs) = sleep {
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
            Some(resp)
        }
        ("GET", "/greet") => {
            let name = info.query_param("name").unwrap_or_default();
            Some(html(
                StatusCode::OK,
                format!("<h1>Hello {}</h1>", ssti(mode, &name)),
            ))
        }
        ("GET", "/static") => {
            let file = info.query_param("file").unwrap_or_default();
            Some(traversal(mode, &file))
        }
        ("POST", "/xml") => Some(match std::str::from_utf8(&info.body) {
            Ok(body) => xxe(mode, body),
            Err(_) => html(StatusCode::BAD_REQUEST, "invalid xml".to_string()),
        }),
        ("GET", "/lang") => {
            let set = info.query_param("set").unwrap_or_default();
            Some(crlf(mode, &set))
        }
        ("POST", "/api/login") => Some(nosqli(mode, &info.body)),
        ("GET", "/ldap") => {
            let user = info.query_param("user").unwrap_or_default();
            Some(ldapi(mode, &user))
        }
        _ => None,
    }
}

// --- Seed 1: error-based SQLi (`GET /products?id=`) --------------------------

/// Vulnerable: a quote in `id` "breaks the query" and the error page carries
/// the raw id, so an error-based probe sees [`seed::SQLI_ERROR_SIGNAL`].
/// Patched: the id is validated as an integer before it is ever used.
fn sqli_error(mode: SeedMode, id: &str) -> Resp {
    match mode {
        SeedMode::Vulnerable => {
            if id.contains('\'') || id.contains('"') {
                return html(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("<pre>{} '{}'</pre>", seed::SQLI_ERROR_SIGNAL, id),
                );
            }
            html(
                StatusCode::OK,
                format!("<h1>Product {}</h1>", html_escape(id)),
            )
        }
        SeedMode::Patched => {
            if !is_integer(id) {
                return html(StatusCode::BAD_REQUEST, "invalid id".to_string());
            }
            html(
                StatusCode::OK,
                format!("<h1>Product {}</h1>", html_escape(id)),
            )
        }
    }
}

/// A non-empty run of ASCII digits, and nothing else.
fn is_integer(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// --- Seed 2: boolean-based SQLi (`GET /items?id=`) ---------------------------

/// What the virtual `WHERE id = <id>` clause resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoolVerdict {
    /// The base row `id = n` (one item when `n` is one of the five).
    Base(u32),
    /// No row matched.
    None,
    /// The tautology matched every row.
    All,
}

impl BoolVerdict {
    /// How many of the five virtual items this verdict selects.
    fn count(self) -> u32 {
        match self {
            BoolVerdict::Base(n) => u32::from((1..=ITEM_COUNT).contains(&n)),
            BoolVerdict::None => 0,
            BoolVerdict::All => ITEM_COUNT,
        }
    }
}

/// Vulnerable: the id is "concatenated into the query", so an injected
/// `AND`/`OR` comparison changes the row count. Patched: integers only.
fn sqli_items(mode: SeedMode, id: &str) -> Resp {
    if mode == SeedMode::Patched && !is_integer(id) {
        return html(StatusCode::BAD_REQUEST, "invalid id".to_string());
    }
    let verdict = eval_boolean(id).unwrap_or(BoolVerdict::None);
    html(StatusCode::OK, format!("<p>items: {}</p>", verdict.count()))
}

/// Evaluate `<n>[ AND|OR <x>=<y>]` the way a concatenating query would:
/// quotes around the operands are stripped, a trailing `--`, `#` or `'` is
/// ignored and the keywords are case-insensitive. `None` means the value did
/// not even start with an integer (the caller renders zero rows).
fn eval_boolean(id: &str) -> Option<BoolVerdict> {
    let trimmed = strip_sql_comment(id).trim();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let base = digits.parse::<u32>().unwrap_or(u32::MAX);
    let rest = trimmed[digits.len()..]
        .trim_start()
        .trim_start_matches(['\'', '"'])
        .trim();
    if rest.is_empty() {
        return Some(BoolVerdict::Base(base));
    }

    let (keyword, tail) = rest.split_once(char::is_whitespace)?;
    let tail = tail.trim();
    let (left, right) = tail.split_once('=')?;
    let truth = unquote(left) == unquote(right);
    match keyword.to_ascii_uppercase().as_str() {
        "AND" if truth => Some(BoolVerdict::Base(base)),
        "AND" => Some(BoolVerdict::None),
        "OR" if truth => Some(BoolVerdict::All),
        "OR" => Some(BoolVerdict::Base(base)),
        _ => None,
    }
}

/// Everything before a trailing `--` or `#` comment marker.
fn strip_sql_comment(s: &str) -> &str {
    let end = [s.find("--"), s.find('#')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(s.len());
    s[..end].trim_end().trim_end_matches(['\'', '"'])
}

/// An operand without its surrounding quotes.
fn unquote(s: &str) -> &str {
    s.trim().trim_matches(['\'', '"']).trim()
}

// --- Seed 3: time-based SQLi (`GET /items?id=`, same route) ------------------

/// The sleep a time-based payload asks for, in seconds, capped at
/// [`MAX_SLEEP_SECS`]. Recognises `SLEEP(n)` (which also covers MySQL's
/// `pg_sleep(n)` spelling) and `WAITFOR DELAY '0:0:n'`, case-insensitively.
fn sleep_seconds(id: &str) -> Option<u64> {
    let lower = id.to_ascii_lowercase();
    if let Some(at) = lower.find("sleep(") {
        if let Some(n) = leading_number(&lower[at + "sleep(".len()..]) {
            return Some(n.min(MAX_SLEEP_SECS));
        }
    }
    if let Some(at) = lower.find("waitfor") {
        let tail = &lower[at..];
        if let Some(delay) = tail.find("delay") {
            let after = &tail[delay + "delay".len()..];
            if let Some(open) = after.find('\'') {
                let quoted = &after[open + 1..];
                if let Some(close) = quoted.find('\'') {
                    if let Some(secs) = quoted[..close].rsplit(':').next() {
                        if let Some(n) = leading_number(secs.trim()) {
                            return Some(n.min(MAX_SLEEP_SECS));
                        }
                    }
                }
            }
        }
    }
    None
}

/// The run of ASCII digits at the start of `s` (at most 6, so a long payload
/// can never build a huge number), as a `u64`.
fn leading_number(s: &str) -> Option<u64> {
    let digits: String = s
        .chars()
        .take(6)
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok()
}

// --- Seed 4: command injection (`GET /ping?host=`) ---------------------------

/// Vulnerable: the host is "interpolated into a shell command line", so a
/// shell metacharacter starts a second command. No process is ever spawned:
/// `id` resolves to [`seed::CMDI_MARKER`], `sleep n` to a delay the caller
/// awaits, anything else to a `command not found` line. Patched: the host
/// must match `^[A-Za-z0-9.-]{1,253}$`.
///
/// Returns the response plus the seconds the caller must sleep first.
fn cmdi(mode: SeedMode, host: &str) -> (Resp, Option<u64>) {
    if mode == SeedMode::Patched {
        if !is_hostname(host) {
            return (
                html(StatusCode::BAD_REQUEST, "invalid host".to_string()),
                None,
            );
        }
        return (ping_body(host, None), None);
    }

    let (target, command) = split_command(host);
    let mut sleep = None;
    let output = match command {
        None => None,
        Some(cmd) => {
            let cmd = cmd.trim();
            if cmd == "id" {
                Some(seed::CMDI_MARKER.to_string())
            } else if let Some(rest) = strip_prefix_ci(cmd, "sleep") {
                sleep = leading_number(rest.trim()).map(|n| n.min(MAX_SLEEP_SECS));
                None
            } else {
                Some(format!("sh: {}: command not found", html_escape(cmd)))
            }
        }
    };
    (ping_body(target, output.as_deref()), sleep)
}

/// `<pre>PING <host>: 56 data bytes</pre>`, with the injected command's output
/// on its own line inside the same block when there is any.
fn ping_body(host: &str, output: Option<&str>) -> Resp {
    let mut body = format!("<pre>PING {}: 56 data bytes", html_escape(host));
    if let Some(out) = output {
        body.push('\n');
        body.push_str(out);
    }
    body.push_str("</pre>");
    html(StatusCode::OK, body)
}

/// `^[A-Za-z0-9.-]{1,253}$`, the patched variant's host allowlist.
fn is_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Split a host value at the first shell metacharacter: `;`, `|`, `&&`,
/// backtick or `$(`. Returns the host part and the command that follows.
fn split_command(host: &str) -> (&str, Option<&str>) {
    let mut found: Option<(usize, usize, bool)> = None; // (at, len, is_substitution)
    for (pattern, len, substitution) in [
        (";", 1, false),
        ("|", 1, false),
        ("&&", 2, false),
        ("`", 1, true),
        ("$(", 2, true),
    ] {
        if let Some(at) = host.find(pattern) {
            let closer = match found {
                None => true,
                Some((best, _, _)) => at < best,
            };
            if closer {
                found = Some((at, len, substitution));
            }
        }
    }
    match found {
        None => (host, None),
        Some((at, len, substitution)) => {
            let mut cmd = &host[at + len..];
            if substitution {
                cmd = cmd.trim_end_matches([')', '`']);
            }
            let cmd = cmd.trim_start_matches([';', '|', '&']);
            (&host[..at], Some(cmd))
        }
    }
}

/// `s` without a case-insensitive ASCII `prefix`. Compared on bytes: `s` is
/// request text, and a byte-indexed `str` slice panics when the index lands
/// inside a multi-byte character (`slee\u{e9}` against `sleep`).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.as_bytes().get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix.as_bytes()) {
        return None;
    }
    s.get(prefix.len()..)
}

// --- Seed 5: SSTI (`GET /greet?name=`) ---------------------------------------

/// Vulnerable: `{{a*b}}` and `${a*b}` are "rendered by the template engine"
/// (here: multiplied), and the result is written into the page unescaped.
/// Patched: the name is escaped and never evaluated.
fn ssti(mode: SeedMode, name: &str) -> String {
    if mode == SeedMode::Patched {
        return html_escape(name);
    }
    let mut out = String::with_capacity(name.len());
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let open = if name[i..].starts_with("{{") {
            Some(("}}", 2))
        } else if name[i..].starts_with("${") {
            Some(("}", 2))
        } else {
            None
        };
        match open.and_then(|(close, skip)| {
            name[i + skip..]
                .find(close)
                .map(|end| (close, skip, i + skip + end))
        }) {
            Some((close, skip, end)) => {
                let expr = &name[i + skip..end];
                match eval_product(expr) {
                    Some(value) => out.push_str(&value.to_string()),
                    None => out.push_str(&name[i..end + close.len()]),
                }
                i = end + close.len();
            }
            None => {
                let ch = name[i..].chars().next().unwrap_or('\u{fffd}');
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// `a*b` over two integers, or `None` when the expression is anything else.
fn eval_product(expr: &str) -> Option<i64> {
    let (left, right) = expr.split_once('*')?;
    let a = left.trim().parse::<i64>().ok()?;
    let b = right.trim().parse::<i64>().ok()?;
    a.checked_mul(b)
}

// --- Seed 6: path traversal (`GET /static?file=`) ----------------------------

/// Vulnerable: the requested path is "joined onto the asset directory" with no
/// normalisation, so a `../` path ending `etc/passwd` serves the virtual
/// password file. Patched: any `..` or `/` is refused and only the allowlist
/// is served. Nothing touches the real filesystem in either mode.
fn traversal(mode: SeedMode, file: &str) -> Resp {
    let decoded = decode_slashes(file);
    let decoded = collapse_dot_segments(&decoded);

    if mode == SeedMode::Patched {
        if decoded.contains("..") || decoded.contains('/') {
            return html(StatusCode::BAD_REQUEST, "invalid file".to_string());
        }
        return serve_static(&decoded);
    }

    if decoded.contains("../") && decoded.ends_with("etc/passwd") {
        return text_plain(StatusCode::OK, format!("{}\n", seed::TRAVERSAL_MARKER));
    }
    serve_static(&decoded)
}

/// One more `%2f` decode on top of the query decoding the router already did,
/// so a double-encoded separator still reaches the traversal check.
fn decode_slashes(s: &str) -> String {
    s.replace("%2f", "/").replace("%2F", "/")
}

/// Collapse the `....//` filter-evasion spelling to `../`, bounded.
fn collapse_dot_segments(s: &str) -> String {
    let mut out = s.to_string();
    for _ in 0..16 {
        if !out.contains("....//") {
            break;
        }
        out = out.replace("....//", "../");
    }
    out
}

/// The allowlisted assets; anything else is a 404.
fn serve_static(file: &str) -> Resp {
    match STATIC_FILES.iter().find(|(name, _, _)| *name == file) {
        Some((_, content_type, body)) => with_content_type(
            StatusCode::OK,
            content_type,
            Bytes::from_static(body.as_bytes()),
        ),
        None => not_found(),
    }
}

// --- Seed 7: XXE (`POST /xml`) -----------------------------------------------

/// Vulnerable: the "parser" honours an internal-subset `SYSTEM` entity, and
/// `file:///etc/passwd` resolves to the one virtual file this target has.
/// Patched: any `<!DOCTYPE` is refused outright, the documented control.
///
/// Expansion is single-pass and non-recursive: an entity's value is never
/// scanned for further references, so no entity-expansion blow-up is possible.
fn xxe(mode: SeedMode, body: &str) -> Resp {
    if mode == SeedMode::Patched {
        if contains_ci(body, "<!doctype") {
            return html(StatusCode::BAD_REQUEST, "DTD not allowed".to_string());
        }
        return match element_text(body, "name") {
            Some(name) => html(
                StatusCode::OK,
                format!("<p>Order for {}</p>", html_escape(&name)),
            ),
            None => html(StatusCode::BAD_REQUEST, "invalid xml".to_string()),
        };
    }

    let name = match element_text(body, "name") {
        Some(name) => name,
        None => return html(StatusCode::BAD_REQUEST, "invalid xml".to_string()),
    };
    html(
        StatusCode::OK,
        format!("<p>Order for {}</p>", expand_entities(body, &name)),
    )
}

/// The text between the first `<tag>` and its `</tag>`.
fn element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Replace `&name;` references in `text` with the values declared by
/// `<!ENTITY name SYSTEM "uri">` in `xml`. The only URI that resolves is
/// `file:///etc/passwd`; every other one expands to the empty string, so no
/// resource is ever dereferenced.
fn expand_entities(xml: &str, text: &str) -> String {
    let mut out = text.to_string();
    let mut rest = xml;
    for _ in 0..MAX_ENTITIES {
        let Some(at) = rest.find("<!ENTITY ") else {
            break;
        };
        let decl = &rest[at + "<!ENTITY ".len()..];
        let Some(end) = decl.find('>') else {
            break;
        };
        let (decl, tail) = decl.split_at(end);
        rest = tail;

        let mut parts = decl.split_whitespace();
        let (Some(name), Some(keyword)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !keyword.eq_ignore_ascii_case("SYSTEM") {
            continue;
        }
        let uri = parts
            .next()
            .unwrap_or_default()
            .trim_matches(['"', '\''])
            .to_string();
        let value = if uri == VIRTUAL_PASSWD_URI {
            seed::TRAVERSAL_MARKER
        } else {
            ""
        };
        out = out.replace(&format!("&{name};"), value);
    }
    out
}

/// The one `SYSTEM` URI the virtual entity resolver knows.
const VIRTUAL_PASSWD_URI: &str = "file:///etc/passwd";

/// Most entity declarations one document may carry.
const MAX_ENTITIES: usize = 16;

/// `haystack` contains `needle`, ASCII-case-insensitively (`needle` lowercase).
fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

// --- Seed 8: CRLF header injection (`GET /lang?set=`) ------------------------

/// Vulnerable: the value is written into the response headers unfiltered, so
/// the CRLF in it ends the `Set-Cookie` line and whatever follows becomes its
/// own header. hyper refuses to put a raw CR or LF on the wire, so the seed
/// reproduces the *observable* effect of the injection — the extra headers —
/// rather than the raw bytes. Patched: CR and LF are stripped, one cookie.
fn crlf(mode: SeedMode, set: &str) -> Resp {
    let mut resp = html(StatusCode::OK, "<p>language set</p>".to_string());
    if mode == SeedMode::Patched {
        let value = set.replace(['\r', '\n'], "");
        insert_header(&mut resp, "set-cookie", &format!("lang={value}"));
        return resp;
    }

    let mut lines = set.split("\r\n");
    let first = lines.next().unwrap_or_default();
    insert_header(&mut resp, "set-cookie", &format!("lang={first}"));
    for line in lines.take(MAX_INJECTED_HEADERS) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !is_header_token(name) {
            continue;
        }
        let value = value.trim();
        if value.contains('\r') || value.contains('\n') {
            continue;
        }
        insert_header(&mut resp, &name.to_ascii_lowercase(), value);
    }
    resp
}

/// `[A-Za-z0-9-]+`, the only header names this seed will emit.
fn is_header_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Append a header, silently skipping anything hyper would reject.
fn insert_header(resp: &mut Resp, name: &str, value: &str) {
    let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) else {
        return;
    };
    resp.headers_mut().append(name, value);
}

// --- Seed 9: NoSQL injection (`POST /api/login`) -----------------------------

/// Vulnerable: the password is passed to the "query" as whatever JSON type it
/// arrived as, so an operator object such as `{"$ne":""}` matches every record
/// and logs in. Patched: a non-string password is a 400 before any lookup.
fn nosqli(mode: SeedMode, body: &[u8]) -> Resp {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid json"}"#.to_string(),
            )
        }
    };
    let password = value.get("password");

    if mode == SeedMode::Patched && !password.is_some_and(serde_json::Value::is_string) {
        return json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"password must be a string"}"#.to_string(),
        );
    }
    if mode == SeedMode::Vulnerable && password.is_some_and(serde_json::Value::is_object) {
        return json(
            StatusCode::OK,
            format!(r#"{{"ok":true,"marker":"{}"}}"#, seed::NOSQLI_MARKER),
        );
    }
    if password.and_then(serde_json::Value::as_str) == Some(seed::SESSION_PASS) {
        return json(
            StatusCode::OK,
            format!(r#"{{"ok":true,"user":"{}"}}"#, seed::SESSION_USER),
        );
    }
    json(StatusCode::UNAUTHORIZED, r#"{"ok":false}"#.to_string())
}

// --- Seed 10: LDAP injection (`GET /ldap?user=`) -----------------------------

/// Vulnerable: `(uid=<user>)` is built by concatenation, so `*` turns the
/// filter into a wildcard that lists the whole directory and a stray `)(`
/// makes it unparseable. Patched: RFC 4515 escaping turns every one of those
/// characters into a literal, leaving only exact-match lookups.
fn ldapi(mode: SeedMode, user: &str) -> Resp {
    if mode == SeedMode::Patched {
        let escaped = ldap_escape(user);
        let found = LDAP_USERS
            .iter()
            .find(|known| ldap_escape(known) == escaped);
        return match found {
            Some(known) => html(StatusCode::OK, format!("<p>uid={known}</p>")),
            None => html(StatusCode::OK, "<p>no entries</p>".to_string()),
        };
    }

    let filter = format!("(uid={user})");
    if user.contains(")(") || !is_balanced(&filter) {
        return html(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("<pre>{}</pre>", seed::LDAPI_ERROR_SIGNAL),
        );
    }
    if user.contains('*') {
        return html(
            StatusCode::OK,
            format!(
                "<p>{}</p><p>{}</p>",
                LDAP_USERS.join(", "),
                seed::LDAPI_ALL_USERS_MARKER
            ),
        );
    }
    match LDAP_USERS.iter().find(|known| **known == user) {
        Some(known) => html(StatusCode::OK, format!("<p>uid={known}</p>")),
        None => html(StatusCode::OK, "<p>no entries</p>".to_string()),
    }
}

/// RFC 4515 §3 escaping of the characters that carry meaning in a filter.
fn ldap_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\5c"),
            '*' => out.push_str(r"\2a"),
            '(' => out.push_str(r"\28"),
            ')' => out.push_str(r"\29"),
            '\0' => out.push_str(r"\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Every `(` in the filter is closed, and no `)` comes first.
fn is_balanced(filter: &str) -> bool {
    let mut depth: i32 = 0;
    for c in filter.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

// --- Response helpers --------------------------------------------------------

fn text_plain(status: StatusCode, body: String) -> Resp {
    with_content_type(status, "text/plain; charset=utf-8", Bytes::from(body))
}

fn json(status: StatusCode, body: String) -> Resp {
    with_content_type(status, "application/json", Bytes::from(body))
}

fn with_content_type(status: StatusCode, content_type: &str, body: Bytes) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(body))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    //! One test per seed, driving [`route`] (and the pure helpers under it)
    //! in-process: no socket is bound, so these run in the Bash sandbox.

    use std::time::{Duration, Instant};

    use http_body_util::BodyExt;
    use hyper::header::HeaderMap;

    use super::*;
    use crate::log::ControlLog;

    const V: SeedMode = SeedMode::Vulnerable;
    const P: SeedMode = SeedMode::Patched;

    /// Drive one request through [`route`]; panics when the route declines it.
    async fn call(
        mode: SeedMode,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap, String) {
        let state = Arc::new(AppState::new(mode, ControlLog::new(mode)));
        let info = RequestInfo::test_request(method, target, headers, body);
        let resp = route(&info, &state)
            .await
            .unwrap_or_else(|| panic!("inject route must answer {method} {target}"));
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        (
            status,
            headers,
            String::from_utf8(body.to_vec()).expect("utf-8 body"),
        )
    }

    async fn get(mode: SeedMode, target: &str) -> (StatusCode, HeaderMap, String) {
        call(mode, "GET", target, &[], b"").await
    }

    fn hdr(h: &HeaderMap, name: &str) -> Option<String> {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    #[tokio::test]
    async fn route_ignores_other_paths() {
        let state = Arc::new(AppState::new(V, ControlLog::new(V)));
        for (method, target) in [
            ("GET", "/"),
            ("GET", "/search?q=x"),
            ("POST", "/products"),
            ("GET", "/api/login"),
            ("GET", "/xml"),
            ("GET", "/productsx"),
        ] {
            let info = RequestInfo::test_request(method, target, &[], b"");
            assert!(
                route(&info, &state).await.is_none(),
                "inject must decline {method} {target}"
            );
        }
    }

    #[tokio::test]
    async fn sqli_error_v_p() {
        let (status, _, body) = get(V, "/products?id=1'").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "<pre>SQL syntax error near '1''</pre>");
        assert!(body.contains(seed::SQLI_ERROR_SIGNAL));

        let (status, _, body) = get(P, "/products?id=1'").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "invalid id");

        for mode in [V, P] {
            let (status, _, body) = get(mode, "/products?id=1").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, "<h1>Product 1</h1>");
        }
    }

    #[tokio::test]
    async fn sqli_boolean_counts() {
        for (id, expected) in [
            ("1%20AND%201=1", "<p>items: 1</p>"),
            ("1%20AND%201=2", "<p>items: 0</p>"),
            ("1%20OR%201=1", "<p>items: 5</p>"),
            ("1'%20AND%20'1'='1", "<p>items: 1</p>"),
        ] {
            let (status, _, body) = get(V, &format!("/items?id={id}")).await;
            assert_eq!(status, StatusCode::OK, "id={id}");
            assert!(body.contains(expected), "id={id} body={body}");
        }

        let (status, _, _) = get(P, "/items?id=1%20AND%201=1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, body) = get(P, "/items?id=1").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<p>items: 1</p>"), "{body}");
    }

    #[tokio::test]
    async fn sqli_time_parses_dialects() {
        assert_eq!(sleep_seconds("1 AND SLEEP(3)"), Some(3));
        assert_eq!(sleep_seconds("1 AND pg_sleep(9)"), Some(5));
        assert_eq!(sleep_seconds("1; WAITFOR DELAY '0:0:2'"), Some(2));
        assert_eq!(sleep_seconds("1"), None);

        // Patched never sleeps: the 400 comes back immediately.
        let started = Instant::now();
        let (status, _, _) = get(P, "/items?id=1%20AND%20SLEEP(3)").await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
    }

    #[tokio::test]
    async fn cmdi_non_ascii_after_separator_never_panics() {
        // `slee\u{e9}` is six bytes whose fifth falls inside the `\u{e9}`: a
        // byte-indexed prefix compare against `sleep` must not slice the str
        // there. `sle\u{e9}p` lands on a boundary but still is not `sleep`.
        for cmd in ["slee%C3%A9", "sle%C3%A9p"] {
            let target = format!("/ping?host=a;{cmd}");
            let (status, _, body) = get(V, &target).await;
            assert_eq!(status, StatusCode::OK, "{target}");
            assert!(body.contains("command not found"), "{target}: {body}");
            // P refuses the `;` on its hostname allowlist (400), not a panic.
            let (status, _, body) = get(P, &target).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}");
            assert_eq!(body, "invalid host");
        }
        assert_eq!(strip_prefix_ci("slee\u{e9}", "sleep"), None);
        assert_eq!(strip_prefix_ci("SLEEP 3", "sleep"), Some(" 3"));
        assert_eq!(strip_prefix_ci("sl", "sleep"), None);
    }

    #[tokio::test]
    async fn cmdi_marker_and_sleep() {
        let (status, _, body) = get(V, "/ping?host=localhost;id").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(seed::CMDI_MARKER), "{body}");

        assert_eq!(cmdi(V, "localhost|sleep 9").1, Some(5));
        assert_eq!(cmdi(V, "localhost").1, None);
        assert_eq!(cmdi(P, "localhost;sleep 9").1, None);

        let (status, _, _) = get(P, "/ping?host=localhost;id").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        for mode in [V, P] {
            let (status, _, body) = get(mode, "/ping?host=localhost").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, "<pre>PING localhost: 56 data bytes</pre>");
        }
    }

    #[tokio::test]
    async fn ssti_evaluates() {
        let (status, _, body) = get(V, "/greet?name={{7*7}}").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<h1>Hello 49</h1>");
        assert!(body.contains(seed::SSTI_SIGNAL));

        let (_, _, body) = get(V, "/greet?name=${6*7}").await;
        assert_eq!(body, "<h1>Hello 42</h1>");

        let (status, _, body) = get(P, "/greet?name={{7*7}}").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<h1>Hello {{7*7}}</h1>");
    }

    #[tokio::test]
    async fn traversal_virtual_passwd() {
        for target in [
            "/static?file=../../etc/passwd",
            "/static?file=..%2f..%2fetc%2fpasswd",
            "/static?file=....//....//etc/passwd",
        ] {
            let (status, headers, body) = get(V, target).await;
            assert_eq!(status, StatusCode::OK, "{target}");
            assert!(
                hdr(&headers, "content-type")
                    .unwrap_or_default()
                    .starts_with("text/plain"),
                "{target}"
            );
            assert_eq!(body, "root:x:0:0:root:/root:/bin/bash\n", "{target}");
        }

        let (status, _, _) = get(P, "/static?file=../../etc/passwd").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        for mode in [V, P] {
            let (status, _, body) = get(mode, "/static?file=readme.txt").await;
            assert_eq!(status, StatusCode::OK);
            assert!(!body.is_empty());

            let (status, _, _) = get(mode, "/static?file=nope.txt").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn xxe_entity() {
        let xxe = br#"<!DOCTYPE o [<!ENTITY e SYSTEM "file:///etc/passwd">]><order><name>&e;</name></order>"#;
        let xml = b"<order id=\"7\"><name>pen</name></order>";
        let headers: &[(&str, &str)] = &[("content-type", "text/xml")];

        let (status, _, body) = call(V, "POST", "/xml", headers, xxe).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>Order for root:x:0:0:root:/root:/bin/bash</p>");
        assert!(body.contains(seed::TRAVERSAL_MARKER));

        let (status, _, body) = call(P, "POST", "/xml", headers, xxe).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "DTD not allowed");

        for mode in [V, P] {
            let (status, _, body) = call(mode, "POST", "/xml", headers, xml).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, "<p>Order for pen</p>");
        }

        // Only file:///etc/passwd resolves; every other SYSTEM URI is empty.
        let other = br#"<!DOCTYPE o [<!ENTITY e SYSTEM "file:///etc/shadow">]><order><name>&e;</name></order>"#;
        let (status, _, body) = call(V, "POST", "/xml", headers, other).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>Order for </p>");
    }

    #[tokio::test]
    async fn crlf_header_injection() {
        let (status, headers, body) = get(V, "/lang?set=en%0d%0aX-Injected:%201").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(hdr(&headers, "x-injected").as_deref(), Some("1"));
        assert_eq!(hdr(&headers, "set-cookie").as_deref(), Some("lang=en"));
        assert_eq!(body, "<p>language set</p>");

        let (status, headers, body) = get(P, "/lang?set=en%0d%0aX-Injected:%201").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(hdr(&headers, "x-injected"), None);
        assert_eq!(
            hdr(&headers, "set-cookie").as_deref(),
            Some("lang=enX-Injected: 1")
        );
        assert_eq!(body, "<p>language set</p>");

        // A non-token header name is never emitted, in either mode.
        let (_, headers, _) = get(V, "/lang?set=en%0d%0aBad%20Name:%201").await;
        assert_eq!(hdr(&headers, "set-cookie").as_deref(), Some("lang=en"));
        assert_eq!(headers.len(), 2, "{headers:?}");
    }

    #[tokio::test]
    async fn nosqli_object_password() {
        let headers: &[(&str, &str)] = &[("content-type", "application/json")];
        let operator = br#"{"username":"alice","password":{"$ne":""}}"#;

        let (status, _, body) = call(V, "POST", "/api/login", headers, operator).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"ok":true,"marker":"NOSQLI-LOGIN-MARKER-4b1d"}"#);
        assert!(body.contains(seed::NOSQLI_MARKER));

        let (status, _, body) = call(P, "POST", "/api/login", headers, operator).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"password must be a string"}"#);

        for mode in [V, P] {
            let good = br#"{"username":"alice","password":"wonderland"}"#;
            let (status, _, body) = call(mode, "POST", "/api/login", headers, good).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, r#"{"ok":true,"user":"alice"}"#);

            let bad = br#"{"username":"alice","password":"nope"}"#;
            let (status, _, body) = call(mode, "POST", "/api/login", headers, bad).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body, r#"{"ok":false}"#);
        }
    }

    #[tokio::test]
    async fn ldapi_wildcard_and_filter() {
        let (status, _, body) = get(V, "/ldap?user=*").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(seed::LDAPI_ALL_USERS_MARKER), "{body}");
        assert!(body.contains("alice, bob, carol"), "{body}");

        let (status, _, body) = get(V, "/ldap?user=)(uid=*").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains(seed::LDAPI_ERROR_SIGNAL), "{body}");

        let (status, _, body) = get(P, "/ldap?user=*").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("no entries"), "{body}");
        assert!(!body.contains(seed::LDAPI_ALL_USERS_MARKER), "{body}");

        for mode in [V, P] {
            let (status, _, body) = get(mode, "/ldap?user=alice").await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("uid=alice"), "{body}");
        }

        assert_eq!(ldap_escape("*"), r"\2a");
        assert_eq!(ldap_escape(")(uid=*"), r"\29\28uid=\2a");
        assert_eq!(ldap_escape("alice"), "alice");
    }

    // --- Tester additions (stage 5): untested D3 branches pinned to literals ---

    #[tokio::test]
    async fn sqli_error_double_quote_and_non_numeric() {
        // Spec D3: an id containing `'` or `"` breaks the query in V.
        let (status, _, body) = get(V, "/products?id=1%22").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, "<pre>SQL syntax error near '1\"'</pre>");

        // A non-numeric id without a quote is a plain, escaped product page in V.
        let (status, _, body) = get(V, "/products?id=abc").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<h1>Product abc</h1>");
        let (status, _, body) = get(V, "/products?id=%3Cb%3E").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<h1>Product &lt;b&gt;</h1>");

        // P validates the id as an integer before anything else.
        for target in [
            "/products?id=abc",
            "/products?id=1%22",
            "/products?id=",
            "/products",
        ] {
            let (status, _, body) = get(P, target).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}");
            assert_eq!(body, "invalid id", "{target}");
        }
        // V with no id: an empty product, no error page.
        let (status, _, body) = get(V, "/products").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<h1>Product </h1>");
    }

    #[tokio::test]
    async fn sqli_boolean_comments_case_and_pure_verdicts() {
        for (id, expected) in [
            ("1%20and%201=1--", "<p>items: 1</p>"),
            ("1%20OR%20'a'='a'%23", "<p>items: 5</p>"),
            // OR-false keeps the base row; 9 is not one of the five items.
            ("9%20OR%201=2", "<p>items: 0</p>"),
            ("3", "<p>items: 1</p>"),
            ("6", "<p>items: 0</p>"),
            ("abc", "<p>items: 0</p>"),
            ("1%20XOR%201=1", "<p>items: 0</p>"),
            ("", "<p>items: 0</p>"),
        ] {
            let (status, _, body) = get(V, &format!("/items?id={id}")).await;
            assert_eq!(status, StatusCode::OK, "id={id}");
            assert_eq!(body, expected, "id={id}");
        }
        assert_eq!(eval_boolean("3"), Some(BoolVerdict::Base(3)));
        assert_eq!(eval_boolean("1 OR 1=1"), Some(BoolVerdict::All));
        assert_eq!(eval_boolean("1 AND 1=2"), Some(BoolVerdict::None));
        assert_eq!(eval_boolean("1 and 'x' = 'x'"), Some(BoolVerdict::Base(1)));
        assert_eq!(eval_boolean("x"), None);
        assert_eq!(eval_boolean("1 AND nonsense"), None);

        // P: integers only, whatever the payload.
        for id in ["1--", "1%20OR%201=1", "abc", ""] {
            let (status, _, body) = get(P, &format!("/items?id={id}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id={id}");
            assert_eq!(body, "invalid id", "id={id}");
        }
    }

    #[tokio::test]
    async fn sqli_time_sleeps_in_v_then_answers_boolean() {
        // Spec D3 `sqli-time-items`: V sleeps min(n, 5) s, then gives the
        // boolean seed's answer. One real second pins the timing oracle at
        // the route, not only in the pure parser.
        let started = Instant::now();
        let (status, _, body) = get(V, "/items?id=1%20AND%20SLEEP(1)").await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>items: 0</p>");
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");

        assert_eq!(sleep_seconds("1 and sleep(2)"), Some(2));
        assert_eq!(sleep_seconds("1 AND SLEEP(999999999)"), Some(5));
        assert_eq!(sleep_seconds("1 AND SLEEP(x)"), None);
        assert_eq!(sleep_seconds("1; WAITFOR DELAY '0:0:7'"), Some(5));
        assert_eq!(sleep_seconds("waitfor delay '00:00:03'"), Some(3));
        assert_eq!(sleep_seconds("1 AND pg_sleep(0)"), Some(0));
    }

    #[tokio::test]
    async fn cmdi_separators_unknown_command_and_patched_allowlist() {
        // Every D3 separator introduces the command.
        for target in [
            "/ping?host=localhost;id",
            "/ping?host=localhost|id",
            "/ping?host=localhost%26%26id",
            "/ping?host=localhost%60id%60",
            "/ping?host=localhost$(id)",
        ] {
            let (status, _, body) = get(V, target).await;
            assert_eq!(status, StatusCode::OK, "{target}");
            assert_eq!(
                body, "<pre>PING localhost: 56 data bytes\nuid=0(root) gid=0(root)</pre>",
                "{target}"
            );
        }
        // An unknown command is `sh: <cmd>: command not found`, escaped.
        let (_, _, body) = get(V, "/ping?host=localhost;whoami").await;
        assert_eq!(
            body,
            "<pre>PING localhost: 56 data bytes\nsh: whoami: command not found</pre>"
        );
        let (_, _, body) = get(V, "/ping?host=localhost;%3Cx%3E").await;
        assert_eq!(
            body,
            "<pre>PING localhost: 56 data bytes\nsh: &lt;x&gt;: command not found</pre>"
        );
        // The host itself is escaped even in V: only the command "runs".
        let (_, _, body) = get(V, "/ping?host=%3Cb%3E").await;
        assert_eq!(body, "<pre>PING &lt;b&gt;: 56 data bytes</pre>");

        // Pure: `sleep` is honoured through every separator, capped at 5.
        assert_eq!(cmdi(V, "localhost&&sleep 2").1, Some(2));
        assert_eq!(cmdi(V, "localhost$(sleep 9)").1, Some(5));
        assert_eq!(cmdi(V, "localhost;SLEEP 1").1, Some(1));
        assert_eq!(cmdi(V, "localhost;sleep x").1, None);

        // P: `^[A-Za-z0-9.-]{1,253}$`, else 400 `invalid host`.
        let (status, _, body) = get(P, "/ping?host=").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "invalid host");
        for target in [
            "/ping?host=localhost|id",
            "/ping?host=localhost%26%26id",
            "/ping?host=localhost$(id)",
            "/ping?host=a_b",
            "/ping?host=a%20b",
            "/ping",
        ] {
            let (status, _, body) = get(P, target).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}");
            assert_eq!(body, "invalid host", "{target}");
        }
        let long = "a".repeat(254);
        let (status, _, _) = get(P, &format!("/ping?host={long}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let max = "a".repeat(253);
        let (status, _, body) = get(P, &format!("/ping?host={max}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("<pre>PING {max}: 56 data bytes</pre>"));
        let (status, _, body) = get(P, "/ping?host=a.b-c9").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<pre>PING a.b-c9: 56 data bytes</pre>");
    }

    #[tokio::test]
    async fn cmdi_sleep_is_awaited_in_v_only() {
        let started = Instant::now();
        let (status, _, body) = get(V, "/ping?host=localhost;sleep%201").await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<pre>PING localhost: 56 data bytes</pre>");
        assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");

        let started = Instant::now();
        let (status, _, _) = get(P, "/ping?host=localhost;sleep%201").await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
    }

    #[tokio::test]
    async fn ssti_edge_cases() {
        let (_, _, body) = get(P, "/greet?name=${6*7}").await;
        assert_eq!(body, "<h1>Hello ${6*7}</h1>");
        let (_, _, body) = get(P, "/greet?name=%3Cb%3E").await;
        assert_eq!(body, "<h1>Hello &lt;b&gt;</h1>");
        for (name, expected) in [
            ("{{a*b}}", "<h1>Hello {{a*b}}</h1>"),
            ("hi%20{{2*3}}!", "<h1>Hello hi 6!</h1>"),
            ("{{7*7", "<h1>Hello {{7*7</h1>"),
            ("{{7%2B7}}", "<h1>Hello {{7+7}}</h1>"),
            (
                "{{99999999999*99999999999}}",
                "<h1>Hello {{99999999999*99999999999}}</h1>",
            ),
            ("%3Cb%3E", "<h1>Hello <b></h1>"),
            ("${2*3}{{4*5}}", "<h1>Hello 620</h1>"),
            ("", "<h1>Hello </h1>"),
        ] {
            let (status, _, body) = get(V, &format!("/greet?name={name}")).await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert_eq!(body, expected, "{name}");
        }
        assert_eq!(ssti(V, "{{ 7 * 7 }}"), "49");
        assert_eq!(ssti(V, "{{-2*3}}"), "-6");
        assert_eq!(ssti(P, "{{-2*3}}"), "{{-2*3}}");
    }

    #[tokio::test]
    async fn traversal_allowlist_and_patched_rejections() {
        // P refuses any `..` or `/`, encoded or not.
        for target in [
            "/static?file=../readme.txt",
            "/static?file=a/readme.txt",
            "/static?file=..%2freadme.txt",
            "/static?file=....//readme.txt",
            "/static?file=..",
        ] {
            let (status, _, body) = get(P, target).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}");
            assert_eq!(body, "invalid file", "{target}");
        }
        // The allowlist is served with its content type in both modes.
        for mode in [V, P] {
            let (status, headers, body) = get(mode, "/static?file=style.css").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                hdr(&headers, "content-type").as_deref(),
                Some("text/css; charset=utf-8")
            );
            assert_eq!(body, "body { font-family: system-ui, sans-serif; }\n");
            let (status, headers, body) = get(mode, "/static?file=app.js").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                hdr(&headers, "content-type").as_deref(),
                Some("application/javascript; charset=utf-8")
            );
            assert_eq!(body, "console.log(\"aitm-testtarget\");\n");
            let (status, headers, body) = get(mode, "/static?file=readme.txt").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                hdr(&headers, "content-type").as_deref(),
                Some("text/plain; charset=utf-8")
            );
            assert_eq!(body, "aitm-testtarget static assets\n");
        }
        // V: only a `../` path ending `etc/passwd` reaches the virtual file.
        let (status, _, _) = get(V, "/static?file=../../etc/shadow").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = get(V, "/static?file=etc/passwd").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = get(V, "/static?file=..%2F..%2Fetc%2Fpasswd").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "root:x:0:0:root:/root:/bin/bash\n");
        let (status, _, _) = get(V, "/static").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn xxe_malformed_bodies_and_doctype_case() {
        let headers: &[(&str, &str)] = &[("content-type", "text/xml")];
        for mode in [V, P] {
            let (status, _, body) = call(mode, "POST", "/xml", headers, b"<order></order>").await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{mode:?}");
            assert_eq!(body, "invalid xml", "{mode:?}");
            let (status, _, body) = call(mode, "POST", "/xml", headers, &[0xff, 0xfe, 0x3c]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{mode:?}");
            assert_eq!(body, "invalid xml", "{mode:?}");
            let (status, _, body) = call(mode, "POST", "/xml", headers, b"").await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{mode:?}");
            assert_eq!(body, "invalid xml", "{mode:?}");
        }
        // P refuses a DOCTYPE in any case, even without an entity.
        let (status, _, body) = call(
            P,
            "POST",
            "/xml",
            headers,
            b"<!doctype o><order><name>x</name></order>",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "DTD not allowed");
        // Reflection of the name: raw in V, escaped in P.
        let markup = b"<order><name><b>pen</b></name></order>";
        let (_, _, body) = call(V, "POST", "/xml", headers, markup).await;
        assert_eq!(body, "<p>Order for <b>pen</b></p>");
        let (_, _, body) = call(P, "POST", "/xml", headers, markup).await;
        assert_eq!(body, "<p>Order for &lt;b&gt;pen&lt;/b&gt;</p>");
        // An internal (non-SYSTEM) entity is never expanded; an undeclared
        // reference stays as typed.
        let internal = br#"<!DOCTYPE o [<!ENTITY e "x">]><order><name>&e;</name></order>"#;
        let (status, _, body) = call(V, "POST", "/xml", headers, internal).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>Order for &e;</p>");
        let (_, _, body) = call(
            V,
            "POST",
            "/xml",
            headers,
            b"<order><name>&nope;</name></order>",
        )
        .await;
        assert_eq!(body, "<p>Order for &nope;</p>");
    }

    #[tokio::test]
    async fn crlf_multiple_headers_cap_and_filters() {
        let (status, headers, _) = get(V, "/lang?set=en%0d%0aA:%201%0d%0aB:%202").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(hdr(&headers, "a").as_deref(), Some("1"));
        assert_eq!(hdr(&headers, "b").as_deref(), Some("2"));
        assert_eq!(hdr(&headers, "set-cookie").as_deref(), Some("lang=en"));

        // A line without a colon is skipped.
        let (_, headers, _) = get(V, "/lang?set=en%0d%0ano-colon%0d%0aA:%201").await;
        assert_eq!(hdr(&headers, "a").as_deref(), Some("1"));
        assert_eq!(headers.len(), 3, "{headers:?}");

        // The cap is 16 injected headers.
        let mut set = String::from("en");
        for i in 1..=20 {
            set.push_str(&format!("%0d%0aH{i}:%20v{i}"));
        }
        let (_, headers, _) = get(V, &format!("/lang?set={set}")).await;
        assert_eq!(hdr(&headers, "h1").as_deref(), Some("v1"));
        assert_eq!(hdr(&headers, "h16").as_deref(), Some("v16"));
        assert_eq!(hdr(&headers, "h17"), None);
        assert_eq!(hdr(&headers, "h20"), None);
        // content-type + set-cookie + 16 injected.
        assert_eq!(headers.len(), 18, "{headers:?}");

        // P: one Set-Cookie carrying the whole (CR/LF-stripped) value.
        let (_, headers, _) = get(P, "/lang?set=en%0d%0aA:%201%0d%0aB:%202").await;
        assert_eq!(hdr(&headers, "a"), None);
        assert_eq!(hdr(&headers, "b"), None);
        assert_eq!(
            hdr(&headers, "set-cookie").as_deref(),
            Some("lang=enA: 1B: 2")
        );
        assert_eq!(headers.len(), 2, "{headers:?}");
        assert!(is_header_token("X-Injected"));
        assert!(!is_header_token("Bad Name"));
        assert!(!is_header_token(""));
    }

    #[tokio::test]
    async fn nosqli_malformed_json_and_missing_password() {
        let headers: &[(&str, &str)] = &[("content-type", "application/json")];
        for mode in [V, P] {
            for raw in [&b"not json"[..], b"", b"{\"username\":"] {
                let (status, _, body) = call(mode, "POST", "/api/login", headers, raw).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{mode:?}");
                assert_eq!(body, r#"{"error":"invalid json"}"#, "{mode:?}");
            }
        }
        // No password: V falls through to 401, P refuses the non-string.
        let none = br#"{"username":"alice"}"#;
        let (status, _, body) = call(V, "POST", "/api/login", headers, none).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, r#"{"ok":false}"#);
        let (status, _, body) = call(P, "POST", "/api/login", headers, none).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"password must be a string"}"#);
        // Only an object is the operator shape in V; arrays, numbers and null
        // are not, and P refuses every non-string.
        for raw in [
            &br#"{"username":"alice","password":["x"]}"#[..],
            br#"{"username":"alice","password":7}"#,
            br#"{"username":"alice","password":null}"#,
        ] {
            let shown = String::from_utf8_lossy(raw);
            let (status, _, body) = call(V, "POST", "/api/login", headers, raw).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{shown}");
            assert_eq!(body, r#"{"ok":false}"#, "{shown}");
            let (status, _, body) = call(P, "POST", "/api/login", headers, raw).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{shown}");
            assert_eq!(body, r#"{"error":"password must be a string"}"#, "{shown}");
        }
        // A top-level non-object parses but has no password.
        let (status, _, body) = call(V, "POST", "/api/login", headers, b"[1,2]").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, r#"{"ok":false}"#);
        // Any operator object is the marker body, the exact D3 literal.
        let operator = br#"{"username":"x","password":{"$gt":""}}"#;
        let (status, _, body) = call(V, "POST", "/api/login", headers, operator).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"ok":true,"marker":"NOSQLI-LOGIN-MARKER-4b1d"}"#);
    }

    #[tokio::test]
    async fn ldapi_patched_literal_lookup_and_unbalanced_filters() {
        // P: RFC 4515 escaping turns the metacharacters into literals.
        for target in [
            "/ldap?user=)(uid=*",
            "/ldap?user=*",
            "/ldap?user=alice)",
            "/ldap?user=(alice",
            "/ldap?user=ali*",
        ] {
            let (status, _, body) = get(P, target).await;
            assert_eq!(status, StatusCode::OK, "{target}");
            assert_eq!(body, "<p>no entries</p>", "{target}");
        }
        let (_, _, body) = get(P, "/ldap?user=bob").await;
        assert_eq!(body, "<p>uid=bob</p>");

        // V: unbalanced parentheses are the 500; known users resolve; unknown
        // and empty are `no entries`; the wildcard body is the D3 literal.
        for target in ["/ldap?user=alice)", "/ldap?user=(alice", "/ldap?user=)("] {
            let (status, _, body) = get(V, target).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{target}");
            assert_eq!(body, "<pre>Bad search filter</pre>", "{target}");
        }
        let (_, _, body) = get(V, "/ldap?user=carol").await;
        assert_eq!(body, "<p>uid=carol</p>");
        for target in ["/ldap?user=dave", "/ldap?user=", "/ldap"] {
            let (status, _, body) = get(V, target).await;
            assert_eq!(status, StatusCode::OK, "{target}");
            assert_eq!(body, "<p>no entries</p>", "{target}");
        }
        let (_, _, body) = get(V, "/ldap?user=ali*").await;
        assert_eq!(
            body,
            "<p>alice, bob, carol</p><p>LDAP-ALL-USERS-MARKER-77c2</p>"
        );
        assert_eq!(ldap_escape("\\"), r"\5c");
        assert_eq!(ldap_escape("\0"), r"\00");
        assert_eq!(ldap_escape("a(b)c*d\\e"), r"a\28b\29c\2ad\5ce");
    }
}
