//! The in-process HTTP app: one real vulnerability per class plus patched
//! controls (selected by [`SeedMode`]) and benign decoys. Serves plain HTTP on
//! loopback; the proxy MITMs it as HTTPS.
//!
//! This module serves the planted markers from [`crate::seed`] but deliberately
//! knows nothing of the grader's ground-truth table (AC-M4-10): it imports only
//! the mode and the markers, never the scored table that maps them to classes.

use std::convert::Infallible;
use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::seed::{self, SeedMode};

/// Per-instance state shared across every connection to one target.
pub(crate) struct AppState {
    mode: SeedMode,
    /// The stored-XSS comment store: what `POST /comments` appends and `GET
    /// /comments` renders back.
    comments: Mutex<Vec<String>>,
}

impl AppState {
    pub(crate) fn new(mode: SeedMode) -> AppState {
        AppState {
            mode,
            comments: Mutex::new(Vec::new()),
        }
    }
}

/// Drive one accepted TCP connection to completion with the HTTP/1 server.
pub(crate) async fn serve_connection(stream: TcpStream, state: std::sync::Arc<AppState>) {
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { route(req, state).await }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await;
}

async fn route(
    req: Request<Incoming>,
    state: std::sync::Arc<AppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let role_header = header(&req, "x-role");
    let user_header = header(&req, "x-user-id");

    // Only `POST /comments` needs the body; collecting it for every request is
    // cheap here and keeps the match arms uniform.
    let body = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();

    let resp = match (method.as_str(), path.as_str()) {
        ("GET", "/") => index(),

        // --- Planted: reflected XSS -------------------------------------
        ("GET", "/search") => {
            let q = query_param(&query, "q").unwrap_or_default();
            let shown = reflect(state.mode, &q);
            html(
                StatusCode::OK,
                format!("<html><body><h1>Results for {shown}</h1></body></html>"),
            )
        }

        // --- Planted: stored XSS ----------------------------------------
        ("POST", "/comments") => {
            let comment = form_param(&body, "comment").unwrap_or_default();
            state.comments.lock().expect("comment store").push(comment);
            redirect("/comments")
        }
        ("GET", "/comments") => {
            let rendered: String = state
                .comments
                .lock()
                .expect("comment store")
                .iter()
                .map(|c| format!("<li>{}</li>", reflect(state.mode, c)))
                .collect();
            html(
                StatusCode::OK,
                format!("<html><body><ul>{rendered}</ul></body></html>"),
            )
        }

        // --- Planted: SSRF (dereferenced in-process; no socket) ---------
        ("GET", "/fetch") => fetch_preview(state.mode, &query),

        // --- Planted: auth bypass ---------------------------------------
        ("GET", "/admin") => admin(state.mode, role_header.as_deref()),

        // --- Planted: open redirect -------------------------------------
        ("GET", "/redirect") => open_redirect(state.mode, &query),

        // --- Decoy: safe reflector (always escaped) ---------------------
        ("GET", "/preview") => {
            let msg = query_param(&query, "msg").unwrap_or_default();
            html(
                StatusCode::OK,
                format!("<html><body><p>{}</p></body></html>", html_escape(&msg)),
            )
        }

        // --- Decoy: safe redirect (always to "/") -----------------------
        ("GET", "/go") => redirect("/"),

        // --- Decoy: safe URL lookup (echoes host, never fetches) --------
        ("GET", "/lookup") => {
            let url = query_param(&query, "host").unwrap_or_default();
            let host = parse_host(&url).unwrap_or_default();
            html(
                StatusCode::OK,
                format!("<html><body>host: {}</body></html>", html_escape(&host)),
            )
        }

        // --- Planted: IDOR, and the IDOR decoy (/profile) ---------------
        ("GET", p) if p.starts_with("/account/") => {
            account(state.mode, &p["/account/".len()..], user_header.as_deref())
        }
        ("GET", p) if p.starts_with("/profile/") => profile(&p["/profile/".len()..]),

        _ => not_found(),
    };
    Ok(resp)
}

// --- Planted behaviours ------------------------------------------------------

/// Reflected/stored XSS core: raw when vulnerable, HTML-escaped when patched.
fn reflect(mode: SeedMode, s: &str) -> String {
    match mode {
        SeedMode::Vulnerable => s.to_string(),
        SeedMode::Patched => html_escape(s),
    }
}

/// SSRF fetch-preview. The URL is dereferenced entirely in-process against a
/// virtual internal resource — no outbound connection is ever attempted, so the
/// target stays hermetic. Vulnerable: an internal/metadata host yields the
/// internal marker. Patched: internal hosts are refused.
fn fetch_preview(mode: SeedMode, query: &str) -> Response<Full<Bytes>> {
    let url = match query_param(query, "url") {
        Some(u) if !u.is_empty() => u,
        _ => return html(StatusCode::BAD_REQUEST, "missing url".to_string()),
    };
    let host = parse_host(&url).unwrap_or_default();
    let internal = is_internal_host(&host);
    match (mode, internal) {
        (SeedMode::Vulnerable, true) => html(
            StatusCode::OK,
            format!("<html><body>preview: {}</body></html>", seed::SSRF_MARKER),
        ),
        (SeedMode::Patched, true) => html(
            StatusCode::FORBIDDEN,
            "refused: host is not allowlisted".to_string(),
        ),
        // External hosts: no socket either way (hermetic). A benign stub, never
        // the marker — so an external fetch is not a false success signal.
        (_, false) => html(
            StatusCode::OK,
            format!(
                "<html><body>preview of {} unavailable</body></html>",
                html_escape(&host)
            ),
        ),
    }
}

/// Auth bypass: the vulnerable variant trusts a client-supplied role header; the
/// patched variant ignores it and requires a (never-present) server session.
fn admin(mode: SeedMode, role: Option<&str>) -> Response<Full<Bytes>> {
    let trusts_client = matches!(mode, SeedMode::Vulnerable) && role == Some("admin");
    if trusts_client {
        html(
            StatusCode::OK,
            format!(
                "<html><body>admin area: {}</body></html>",
                seed::AUTH_BYPASS_MARKER
            ),
        )
    } else {
        html(StatusCode::FORBIDDEN, "forbidden".to_string())
    }
}

/// Open redirect: vulnerable honours any `next`; patched allowlists to
/// same-origin relative paths and otherwise falls back to "/".
fn open_redirect(mode: SeedMode, query: &str) -> Response<Full<Bytes>> {
    let next = query_param(query, "next").unwrap_or_default();
    match mode {
        SeedMode::Vulnerable => redirect(&next),
        SeedMode::Patched => {
            if is_safe_relative(&next) {
                redirect(&next)
            } else {
                redirect("/")
            }
        }
    }
}

/// IDOR: account `{id}` is owned by user `{id}`. Vulnerable returns any account's
/// private marker to any caller; patched enforces ownership against `X-User-Id`
/// (default user 1).
fn account(mode: SeedMode, id: &str, user: Option<&str>) -> Response<Full<Bytes>> {
    let caller = user.unwrap_or("1");
    let owns = caller == id;
    match mode {
        SeedMode::Patched if !owns => html(StatusCode::FORBIDDEN, "forbidden".to_string()),
        SeedMode::Vulnerable | SeedMode::Patched => {
            let secret = account_secret(id);
            html(
                StatusCode::OK,
                format!("<html><body>account {id}: {secret}</body></html>"),
            )
        }
    }
}

/// The private marker for an account. Account 2 is the planted target; others
/// carry their own inert per-account marker (callers reaching their own data is
/// not the finding).
fn account_secret(id: &str) -> String {
    if id == "2" {
        seed::IDOR_MARKER.to_string()
    } else {
        format!("ACCOUNT-{id}-PRIVATE")
    }
}

/// IDOR decoy: `/profile/{id}` exposes only a public display name, identical for
/// every caller — it looks object-scoped but leaks nothing.
fn profile(id: &str) -> Response<Full<Bytes>> {
    html(
        StatusCode::OK,
        format!("<html><body>public profile for user {id}</body></html>"),
    )
}

/// The landing page: links the public attack surface (not which paths are
/// vulnerable), so a crawler can discover endpoints the honest way.
fn index() -> Response<Full<Bytes>> {
    let links = [
        "/search?q=hello",
        "/comments",
        "/fetch?url=https://example.com/",
        "/account/1",
        "/admin",
        "/redirect?next=/",
        "/preview?msg=hi",
        "/go?dest=/",
        "/lookup?host=example.com",
        "/profile/1",
    ];
    let items: String = links
        .iter()
        .map(|href| format!("<li><a href=\"{href}\">{href}</a></li>"))
        .collect();
    html(
        StatusCode::OK,
        format!("<html><body><h1>aitm test target</h1><ul>{items}</ul></body></html>"),
    )
}

// --- Helpers -----------------------------------------------------------------

fn header(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn html(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

fn redirect(location: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
}

fn not_found() -> Response<Full<Bytes>> {
    html(StatusCode::NOT_FOUND, "not found".to_string())
}

/// A relative, same-origin path: starts with a single `/` (not `//`, which is a
/// protocol-relative URL to another host).
fn is_safe_relative(next: &str) -> bool {
    next.starts_with('/') && !next.starts_with("//")
}

/// Hosts an SSRF guard treats as internal: loopback, link-local metadata, and
/// cloud metadata names.
fn is_internal_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost"
        || h == "127.0.0.1"
        || h == "0.0.0.0"
        || h == "::1"
        || h == "[::1]"
        || h == "169.254.169.254"
        || h.starts_with("169.254.")
        || h == "metadata.google.internal"
        || h.starts_with("127.")
}

/// The host component of a URL, without scheme, port, path, or credentials. Good
/// enough for the lab's routing; not a general URL parser.
fn parse_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    // Strip a trailing :port, but keep an IPv6 literal's inner colons.
    let host = if authority.starts_with('[') {
        authority
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    Some(host.to_string())
}

/// A URL-decoded query parameter value (`application/x-www-form-urlencoded`).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// A URL-decoded field from a form-encoded request body.
fn form_param(body: &[u8], key: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    s.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal HTML escaping for the patched (safe) rendering paths. Local to keep
/// this test-support crate free of production dependencies.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hi = (b[i + 1] as char).to_digit(16);
                let lo = (b[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
