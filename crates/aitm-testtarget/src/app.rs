//! The in-process HTTP app: one real vulnerability per class plus patched
//! controls (selected by [`SeedMode`]) and benign decoys. Serves plain HTTP on
//! loopback; the proxy MITMs it as HTTPS.
//!
//! This module serves the planted markers from [`crate::seed`] but deliberately
//! knows nothing of the grader's ground-truth table (AC-M4-10): it imports only
//! the mode and the markers, never the scored table that maps them to classes.
//!
//! Layout (child spec D1): this file owns the router ([`route`]), the shared
//! [`AppState`], the per-request [`RequestInfo`], the connection drivers
//! [`serve_h1`] / [`serve_h2`], the landing page ([`index`]), the legacy six
//! seeds and the patched-only passive headers ([`finalize`]). The newer seeds
//! live in `routes/{inject,reflect,session,misc}.rs`, each exposing
//! `route(&RequestInfo, &Arc<AppState>) -> Option<Resp>`; `/ws` is `ws.rs`.
//! Every served request ends in one `request` entry on the control log (D2).

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::log::{redact_headers, sha256_hex, ConnInfo, ControlLog, Listener, RequestEntry};
use crate::routes;
use crate::seed::{self, SeedMode};
use crate::ws;

/// Every route answers with a fully buffered body.
pub(crate) type Resp = Response<Full<Bytes>>;

/// Largest request body any route accepts; beyond it the request is 413.
pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;

/// Most comments the stored-XSS store keeps; the oldest is dropped past it.
pub(crate) const MAX_COMMENTS: usize = 1_000;

/// Per-instance state shared across every connection to one target (plain,
/// TLS and TLS-h1 listeners alike, so a login over TLS is valid over plain).
pub(crate) struct AppState {
    pub mode: SeedMode,
    /// The stored-XSS comment store: what `POST /comments` appends and `GET
    /// /comments` renders back; at most [`MAX_COMMENTS`], oldest dropped.
    pub comments: Mutex<VecDeque<String>>,
    /// Login sessions (`POST /login`, `/account?tab=`, `/ws` `session_valid`).
    pub sessions: routes::session::SessionStore,
    /// `GET /flaky` request counter (every third request fails).
    pub flaky: AtomicU64,
    /// The observer log behind the control origin.
    pub log: Arc<ControlLog>,
}

impl AppState {
    pub(crate) fn new(mode: SeedMode, log: Arc<ControlLog>) -> AppState {
        AppState {
            mode,
            comments: Mutex::new(VecDeque::new()),
            sessions: routes::session::SessionStore::new(),
            flaky: AtomicU64::new(0),
            log,
        }
    }
}

/// One parsed request, as every route sees it: the body is already collected
/// (bounded by [`MAX_BODY`]), cookies are split out of `Cookie`, and the
/// connection it arrived on is attached so routes and `/ws` can log against it.
pub(crate) struct RequestInfo {
    pub method: String,
    pub path: String,
    /// The raw query string without the `?` (empty when absent).
    pub query: String,
    pub headers: HeaderMap,
    /// `Cookie` pairs, first occurrence of a name wins; values are raw.
    pub cookies: BTreeMap<String, String>,
    pub body: Bytes,
    pub conn: Arc<ConnInfo>,
    /// `http` or `https`, from the listener the connection was accepted on.
    pub scheme: &'static str,
    /// The `Host` header (or the `:authority` on h2); empty when neither is set.
    pub host: String,
}

impl RequestInfo {
    /// A request header as text (`None` when absent or not UTF-8).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// A URL-decoded query parameter.
    pub(crate) fn query_param(&self, key: &str) -> Option<String> {
        query_param(&self.query, key)
    }

    /// A URL-decoded `application/x-www-form-urlencoded` body field.
    pub(crate) fn form_param(&self, key: &str) -> Option<String> {
        form_param(&self.body, key)
    }

    /// A cookie value by name.
    pub(crate) fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }

    /// Build a request on a fresh plain-listener connection, for route tests.
    /// `target` is the request-target (`/path?query`).
    #[cfg(test)]
    pub(crate) fn test_request(
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> RequestInfo {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let name: hyper::header::HeaderName = name.parse().expect("test header name");
            let value: hyper::header::HeaderValue = value.parse().expect("test header value");
            map.append(name, value);
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let peer = "127.0.0.1:1".parse().expect("test peer");
        let conn = ControlLog::new(SeedMode::Vulnerable).open_conn(Listener::Plain, None, peer);
        let host = map
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("127.0.0.1")
            .to_string();
        RequestInfo {
            method: method.to_string(),
            path: path.to_string(),
            query: query.to_string(),
            cookies: parse_cookies(&map),
            headers: map,
            body: Bytes::copy_from_slice(body),
            scheme: conn.listener.scheme(),
            conn,
            host,
        }
    }
}

// --- Connection drivers ------------------------------------------------------

/// Drive one accepted plain-listener TCP connection to completion: mint its
/// [`ConnInfo`], serve HTTP/1 on it, stamp it closed.
pub(crate) async fn serve_connection(stream: TcpStream, state: Arc<AppState>) {
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    let conn = state.log.open_conn(Listener::Plain, None, peer);
    serve_h1(stream, state.clone(), conn.clone()).await;
    state.log.close_conn(&conn);
}

/// Serve HTTP/1 on `io` (plain, or a TLS stream that negotiated `http/1.1`
/// or nothing). Upgrades are enabled so `/ws` can take the connection.
pub(crate) async fn serve_h1<IO>(io: IO, state: Arc<AppState>, conn: Arc<ConnInfo>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let svc = service_fn(move |req| {
        let state = state.clone();
        let conn = conn.clone();
        async move { route(req, state, conn).await }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .with_upgrades()
        .await;
}

/// Serve HTTP/2 on `io` (a TLS stream that negotiated `h2`).
pub(crate) async fn serve_h2<IO>(io: IO, state: Arc<AppState>, conn: Arc<ConnInfo>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let svc = service_fn(move |req| {
        let state = state.clone();
        let conn = conn.clone();
        async move { route(req, state, conn).await }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}

// --- Router -------------------------------------------------------------------

/// Dispatch one request. Generic over the body so the in-process tests can
/// drive it with a [`Full`] body; the server passes hyper's [`hyper::body::Incoming`].
///
/// Order: take the `/ws` upgrade handle, collect the body (413 past
/// [`MAX_BODY`]), build the [`RequestInfo`], try the legacy six, then
/// `routes::{inject,reflect,session,misc}`, then `/ws`, else 404; then
/// [`finalize`] (patched-only headers) and one `request` log entry.
pub(crate) async fn route<B>(
    mut req: Request<B>,
    state: Arc<AppState>,
    conn: Arc<ConnInfo>,
) -> Result<Resp, Infallible>
where
    B: hyper::body::Body,
    B::Data: bytes::Buf,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let conn_req_index = conn.next_request_index();
    let version = req.version();
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers = req.headers().clone();
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
        .unwrap_or_default();

    // The upgrade handle must be taken before the body is consumed: hyper
    // parks it on the request's extensions, which `into_body` discards.
    let on_upgrade = (path == "/ws").then(|| hyper::upgrade::on(&mut req));

    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(collected) => Some(collected.to_bytes()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => None,
        // A body that failed mid-read (peer went away, h2 reset): serve what
        // we have (nothing) rather than fail the connection.
        Err(_) => Some(Bytes::new()),
    };

    let (body, too_large) = match body {
        Some(b) => (b, false),
        None => (Bytes::new(), true),
    };

    let info = RequestInfo {
        method,
        path,
        query,
        cookies: parse_cookies(&headers),
        headers,
        body,
        scheme: conn.listener.scheme(),
        conn: conn.clone(),
        host,
    };

    let resp = if too_large {
        html(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large".to_string(),
        )
    } else {
        dispatch(&info, &state, on_upgrade).await
    };
    let resp = finalize(state.mode, resp);

    let redacted = redact_headers(&info.headers);
    state.log.log_request(RequestEntry {
        seq: 0,
        ts_ms: 0,
        conn_id: conn.conn_id.clone(),
        listener: conn.listener,
        version: version.into(),
        conn_req_index,
        method: info.method,
        path: info.path,
        query: info.query,
        headers: redacted.headers,
        cookie_names: redacted.cookie_names,
        cookie_sha256: redacted.cookie_sha256,
        auth_sha256: redacted.auth_sha256,
        body_len: info.body.len(),
        body_sha256: sha256_hex(&info.body),
        status: resp.status().as_u16(),
    });
    Ok(resp)
}

/// Try every route family in order; the first `Some` wins.
async fn dispatch(
    info: &RequestInfo,
    state: &Arc<AppState>,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Resp {
    if let Some(resp) = legacy(info, state) {
        return resp;
    }
    if let Some(resp) = routes::inject::route(info, state).await {
        return resp;
    }
    if let Some(resp) = routes::reflect::route(info, state).await {
        return resp;
    }
    if let Some(resp) = routes::session::route(info, state).await {
        return resp;
    }
    if let Some(resp) = routes::misc::route(info, state).await {
        return resp;
    }
    if let Some(on_upgrade) = on_upgrade {
        return ws::serve_upgrade(info, on_upgrade, state.clone());
    }
    not_found()
}

/// The patched-only passive headers (D3 `passive-missing-*` rows), added to
/// every response after routing. Vulnerable mode adds nothing.
fn finalize(mode: SeedMode, mut resp: Resp) -> Resp {
    if mode == SeedMode::Patched {
        let h = resp.headers_mut();
        h.insert(
            "strict-transport-security",
            hyper::header::HeaderValue::from_static("max-age=31536000"),
        );
        h.insert(
            "content-security-policy",
            hyper::header::HeaderValue::from_static("default-src 'self'"),
        );
        h.insert(
            "x-content-type-options",
            hyper::header::HeaderValue::from_static("nosniff"),
        );
    }
    resp
}

// --- Legacy six (M4) -----------------------------------------------------------

/// The M4 routes, byte-for-byte as before the T10 refactor: the six planted
/// seeds and their decoys. `None` when the path is not one of theirs.
fn legacy(info: &RequestInfo, state: &Arc<AppState>) -> Option<Resp> {
    let query = info.query.as_str();
    let resp = match (info.method.as_str(), info.path.as_str()) {
        ("GET", "/") => index(),

        // --- Planted: reflected XSS -------------------------------------
        ("GET", "/search") => {
            let q = info.query_param("q").unwrap_or_default();
            let shown = reflect(state.mode, &q);
            html(
                StatusCode::OK,
                format!("<html><body><h1>Results for {shown}</h1></body></html>"),
            )
        }

        // --- Planted: stored XSS ----------------------------------------
        ("POST", "/comments") => {
            let comment = info.form_param("comment").unwrap_or_default();
            let mut comments = state.comments.lock().expect("comment store");
            if comments.len() >= MAX_COMMENTS {
                comments.pop_front();
            }
            comments.push_back(comment);
            drop(comments);
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
        ("GET", "/fetch") => fetch_preview(state.mode, query),

        // --- Planted: auth bypass ---------------------------------------
        ("GET", "/admin") => admin(state.mode, info.header("x-role")),

        // --- Planted: open redirect -------------------------------------
        ("GET", "/redirect") => open_redirect(state.mode, query),

        // --- Decoy: safe reflector (always escaped) ---------------------
        ("GET", "/preview") => {
            let msg = info.query_param("msg").unwrap_or_default();
            html(
                StatusCode::OK,
                format!("<html><body><p>{}</p></body></html>", html_escape(&msg)),
            )
        }

        // --- Decoy: safe redirect (always to "/") -----------------------
        ("GET", "/go") => redirect("/"),

        // --- Decoy: safe URL lookup (echoes host, never fetches) --------
        ("GET", "/lookup") => {
            let url = info.query_param("host").unwrap_or_default();
            let host = parse_host(&url).unwrap_or_default();
            html(
                StatusCode::OK,
                format!("<html><body>host: {}</body></html>", html_escape(&host)),
            )
        }

        // --- Planted: IDOR, and the IDOR decoy (/profile) ---------------
        ("GET", p) if p.starts_with("/account/") => account(
            state.mode,
            &p["/account/".len()..],
            info.header("x-user-id"),
        ),
        ("GET", p) if p.starts_with("/profile/") => profile(&p["/profile/".len()..]),

        _ => return None,
    };
    Some(resp)
}

// --- Planted behaviours ------------------------------------------------------

/// Reflected/stored XSS core: raw when vulnerable, HTML-escaped when patched.
pub(crate) fn reflect(mode: SeedMode, s: &str) -> String {
    match mode {
        SeedMode::Vulnerable => s.to_string(),
        SeedMode::Patched => html_escape(s),
    }
}

/// SSRF fetch-preview. The URL is dereferenced entirely in-process against a
/// virtual internal resource — no outbound connection is ever attempted, so the
/// target stays hermetic. Vulnerable: an internal/metadata host yields the
/// internal marker. Patched: internal hosts are refused.
fn fetch_preview(mode: SeedMode, query: &str) -> Resp {
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
fn admin(mode: SeedMode, role: Option<&str>) -> Resp {
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
fn open_redirect(mode: SeedMode, query: &str) -> Resp {
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
fn account(mode: SeedMode, id: &str, user: Option<&str>) -> Resp {
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
fn profile(id: &str) -> Resp {
    html(
        StatusCode::OK,
        format!("<html><body>public profile for user {id}</body></html>"),
    )
}

// --- Index --------------------------------------------------------------------

/// Anchor targets on `/`, in page order. Two numeric account ids so a crawler
/// templates `/account/{id}`; every query parameter carries a benign value.
const INDEX_LINKS: &[&str] = &[
    "/search?q=hello",
    "/comments",
    "/fetch?url=https://example.com/",
    "/account/1",
    "/account/2",
    "/admin",
    "/redirect?next=/",
    "/preview?msg=hi",
    "/go?dest=/",
    "/lookup?host=example.com",
    "/profile/1",
    "/products?id=1",
    "/items?id=1",
    "/ping?host=localhost",
    "/greet?name=world",
    "/static?file=readme.txt",
    "/lang?set=en",
    "/ldap?user=alice",
    "/whoami",
    "/prefs",
    "/docs/intro",
    "/login",
    "/account?tab=overview",
    "/flaky",
    "/slow?ms=10",
];

/// The forms on `/`: the GET search form, and POST forms for comments, login
/// and the multipart upload, so a crawler has a form graph to walk as well as a
/// link graph.
const INDEX_FORMS: &str = "<form action=\"/search\" method=\"get\">\
                <input name=\"q\"><button>search</button></form>\
                <form action=\"/comments\" method=\"post\">\
                <input name=\"comment\"><button>comment</button></form>\
                <form action=\"/login\" method=\"post\">\
                <input name=\"user\"><input name=\"pass\" type=\"password\">\
                <button>login</button></form>\
                <form action=\"/upload\" method=\"post\" enctype=\"multipart/form-data\">\
                <input name=\"file\" type=\"file\"><input name=\"note\">\
                <button>upload</button></form>";

/// A click-only navigation: no `href`, so only a browser crawl that clicks
/// finds `/files/readme.txt`.
const INDEX_CLICK: &str = "<span class=\"nav\" data-href=\"/files/readme.txt\" \
                onclick=\"location.href=this.dataset.href\">files</span>";

/// The inline script a browser crawl executes: three JSON/XML POSTs and one
/// WebSocket echo, so the script-only seeds are discoverable without a link.
const INDEX_SCRIPT: &str = concat!(
    "<script>\n",
    "fetch(\"/api/profile\", {method: \"POST\", headers: {\"content-type\": \"application/json\"}, ",
    "body: JSON.stringify({\"profile\":{\"address\":{\"city\":\"Paris\"}}})});\n",
    "fetch(\"/api/login\", {method: \"POST\", headers: {\"content-type\": \"application/json\"}, ",
    "body: JSON.stringify({\"username\":\"alice\",\"password\":\"x\"})});\n",
    "fetch(\"/xml\", {method: \"POST\", headers: {\"content-type\": \"text/xml\"}, ",
    "body: '<order id=\"7\"><name>pen</name></order>'});\n",
    "var ws = new WebSocket((location.protocol === \"https:\" ? \"wss://\" : \"ws://\") + location.host + \"/ws\");\n",
    "ws.onopen = function () { ws.send(JSON.stringify({\"type\":\"echo\",\"msg\":\"hi\"})); ws.close(); };\n",
    "</script>"
);

/// The landing page HTML. Mode-independent by construction (no [`SeedMode`]
/// reaches it), so `/` is byte-identical in V and P.
fn index_html() -> String {
    let items: String = INDEX_LINKS
        .iter()
        .map(|href| format!("<li><a href=\"{href}\">{href}</a></li>"))
        .collect();
    format!(
        "<html><body><h1>aitm test target</h1><ul>{items}</ul>{INDEX_FORMS}{INDEX_CLICK}{INDEX_SCRIPT}</body></html>"
    )
}

/// The landing page: links the public attack surface (not which paths are
/// vulnerable), so a crawler can discover endpoints the honest way.
pub(crate) fn index() -> Resp {
    html(StatusCode::OK, index_html())
}

/// Does `/` make `path` discoverable? True when an anchor `href`, a form
/// `action` or a `data-href` equals `path` (or `path` plus a query), or the
/// inline script carries `path` as a quoted literal.
#[cfg(test)]
pub(crate) fn index_mentions(path: &str) -> bool {
    let page = index_html();
    let (markup, script) = match (page.find("<script>"), page.find("</script>")) {
        (Some(start), Some(end)) if start < end => (
            format!("{}{}", &page[..start], &page[end..]),
            page[start..end].to_string(),
        ),
        _ => (page.clone(), String::new()),
    };
    let with_query = format!("{path}?");
    let attr_hit = ["href=\"", "action=\""].iter().any(|attr| {
        markup.match_indices(attr).any(|(at, _)| {
            let rest = &markup[at + attr.len()..];
            let value = rest.split('"').next().unwrap_or("");
            value == path || value.starts_with(&with_query)
        })
    });
    attr_hit || script.contains(&format!("\"{path}\""))
}

// --- Helpers -----------------------------------------------------------------

/// Split every `Cookie` header into name/value pairs; the first occurrence of a
/// name wins, values are kept raw (no decoding).
fn parse_cookies(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for value in headers.get_all("cookie") {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((name, val)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            out.entry(name.to_string())
                .or_insert_with(|| val.trim().to_string());
        }
    }
    out
}

pub(crate) fn html(status: StatusCode, body: String) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

/// A 302 to `location`. The value may be request-derived (the open-redirect
/// seed): one hyper refuses is retried without CR/LF, so the seed keeps its
/// semantics while a header split stays impossible; anything still invalid
/// falls back to `/`. Nothing here can panic on the caller's text.
pub(crate) fn redirect(location: &str) -> Resp {
    let value = HeaderValue::from_str(location)
        .or_else(|_| HeaderValue::from_str(&location.replace(['\r', '\n'], "")))
        .unwrap_or_else(|_| HeaderValue::from_static("/"));
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::FOUND;
    resp.headers_mut().insert("location", value);
    resp
}

pub(crate) fn not_found() -> Resp {
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
pub(crate) fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// A URL-decoded field from a form-encoded request body.
pub(crate) fn form_param(body: &[u8], key: &str) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    s.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal HTML escaping for the patched (safe) rendering paths. Local to keep
/// this test-support crate free of production dependencies.
pub(crate) fn html_escape(s: &str) -> String {
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

pub(crate) fn percent_decode(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    //! Hermetic route-level tests: drive [`route`] in-process with a [`Full`]
    //! body, so they run where loopback binding is refused (the Bash sandbox).
    //! The socket-level suites live in `tests/target.rs` and `tests/serve_bin.rs`.

    use std::sync::Arc;

    use super::*;
    use crate::log::{ControlLog, Listener};
    use crate::seed_index;

    /// A fresh target in `mode` plus one plain-listener connection on it.
    fn fresh(mode: SeedMode) -> (Arc<AppState>, Arc<ConnInfo>) {
        let log = ControlLog::new(mode);
        let state = Arc::new(AppState::new(mode, log));
        let peer = "127.0.0.1:40000".parse().expect("peer addr");
        let conn = state.log.open_conn(Listener::Plain, None, peer);
        (state, conn)
    }

    /// `GET path` on `conn`; returns the full response.
    async fn get_on(state: &Arc<AppState>, conn: &Arc<ConnInfo>, path: &str) -> Resp {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Full::new(Bytes::new()))
            .expect("valid request");
        route(req, state.clone(), conn.clone())
            .await
            .expect("route is infallible")
    }

    /// `GET path` against a fresh target in `mode`; returns (status, body).
    async fn get(mode: SeedMode, path: &str) -> (StatusCode, String) {
        let (state, conn) = fresh(mode);
        let resp = get_on(&state, &conn, path).await;
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        (
            status,
            String::from_utf8(body.to_vec()).expect("utf-8 body"),
        )
    }

    /// Percent-encode everything but the URL-unreserved set so a marker with
    /// `<` / `>` is a valid request-target (mirrors the socket-level suites).
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

    #[tokio::test]
    async fn index_links_all_seeded_endpoints() {
        let (status, body) = get(SeedMode::Vulnerable, "/").await;
        assert_eq!(status, StatusCode::OK);

        // Every seeded endpoint is linked, so a crawler can discover it honestly.
        for path in [
            "/search",
            "/comments",
            "/fetch",
            "/account/",
            "/admin",
            "/redirect",
        ] {
            assert!(
                body.contains(&format!("href=\"{path}")),
                "index must link {path}: {body}"
            );
        }

        // The crawl stage needs a form to walk, not just anchors: one search
        // form, GET to /search, with a `q` field.
        assert!(
            body.contains("<form"),
            "index must contain a <form>: {body}"
        );
        assert!(
            body.contains("action=\"/search\""),
            "form must target /search: {body}"
        );
        assert!(
            body.contains("method=\"get\""),
            "form must submit via GET: {body}"
        );
        assert!(
            body.contains("name=\"q\""),
            "form must carry the q field /search reads: {body}"
        );

        // The landing page is mode-independent: identical in both seed modes.
        let (_, patched) = get(SeedMode::Patched, "/").await;
        assert_eq!(body, patched, "index must be identical in both SeedModes");
    }

    #[tokio::test]
    async fn existing_routes_unchanged() {
        let path = format!("/search?q={}", enc(seed::REFLECTED_XSS_MARKER));

        // Vulnerable: the marker is reflected verbatim.
        let (status, body) = get(SeedMode::Vulnerable, &path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            format!(
                "<html><body><h1>Results for {}</h1></body></html>",
                seed::REFLECTED_XSS_MARKER
            )
        );

        // Patched: the same request comes back escaped, never raw.
        let (status, body) = get(SeedMode::Patched, &path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains(seed::REFLECTED_XSS_MARKER),
            "patched must not reflect the marker raw: {body}"
        );
        assert!(
            body.contains("&lt;xss-reflected-7f3a&gt;"),
            "patched must HTML-escape the marker: {body}"
        );
    }

    #[tokio::test]
    async fn index_links_every_seed_route() {
        // The index is the only honest discovery path (D3 *disc.* column): every
        // seed_index row's concrete path is an anchor href, a form action, a
        // quoted literal in the inline script, or a click-only data-href.
        for row in seed_index() {
            assert!(
                index_mentions(row.path),
                "index must mention seed {} at {} ({:?})",
                row.id,
                row.path,
                row.discovery
            );
        }
        // Two numeric account ids so the crawler templates `/account/{id}`.
        assert!(index_mentions("/account/1"));
        assert!(index_mentions("/account/2"));
        // Infrastructure routes a crawl must reach too.
        for path in ["/login", "/flaky", "/slow"] {
            assert!(index_mentions(path), "index must mention {path}");
        }
        // Nothing is mentioned that is not served.
        assert!(!index_mentions("/grader"));
        assert!(!index_mentions("/nope"));

        // The inline script's XML literal carries an attribute and element
        // text, so the XML lane gets an `xml_attr` point as well as a value.
        let (_, body) = get(SeedMode::Vulnerable, "/").await;
        assert!(
            body.contains(r#"<order id="7"><name>pen</name></order>"#),
            "index script must POST the XML order literal: {body}"
        );
        assert!(
            body.contains(r#"{"profile":{"address":{"city":"Paris"}}}"#),
            "index script must POST the nested profile literal: {body}"
        );
        assert!(
            body.contains(r#"{"username":"alice","password":"x"}"#),
            "index script must POST the login literal: {body}"
        );
        assert!(
            body.contains(r#"new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws")"#),
            "index script must open /ws: {body}"
        );
        assert!(
            body.contains(r#"<span class="nav" data-href="/files/readme.txt" onclick="location.href=this.dataset.href">files</span>"#),
            "index must carry the click-only files span: {body}"
        );
        assert!(
            body.contains(r#"enctype="multipart/form-data""#),
            "upload form must be multipart: {body}"
        );
    }

    #[tokio::test]
    async fn patched_adds_passive_headers() {
        let (state, conn) = fresh(SeedMode::Patched);
        let resp = get_on(&state, &conn, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(
            h.get("strict-transport-security")
                .and_then(|v| v.to_str().ok()),
            Some("max-age=31536000")
        );
        assert_eq!(
            h.get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some("default-src 'self'")
        );
        assert_eq!(
            h.get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );

        // The headers are added after routing, so a 404 carries them too.
        let resp = get_on(&state, &conn, "/nope").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().contains_key("strict-transport-security"));

        let (state, conn) = fresh(SeedMode::Vulnerable);
        let resp = get_on(&state, &conn, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        for name in [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
        ] {
            assert!(
                !resp.headers().contains_key(name),
                "vulnerable must not send {name}"
            );
        }
    }

    #[tokio::test]
    async fn requests_are_logged_with_conn_index() {
        let (state, conn) = fresh(SeedMode::Vulnerable);
        for _ in 0..2 {
            let resp = get_on(&state, &conn, "/preview?msg=a").await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let json = state.log.http_json();
        let entries = json["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2, "{json}");
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e["kind"], "request", "{e}");
            assert_eq!(e["conn_req_index"], (i as u64) + 1, "{e}");
            assert_eq!(e["conn_id"], conn.conn_id.as_str(), "{e}");
            assert_eq!(e["listener"], "plain", "{e}");
            assert_eq!(e["version"], "h1", "{e}");
            assert_eq!(e["status"], 200, "{e}");
            assert_eq!(e["method"], "GET", "{e}");
            assert_eq!(e["path"], "/preview", "{e}");
            assert_eq!(e["query"], "msg=a", "{e}");
            assert_eq!(e["body_len"], 0, "{e}");
            assert_eq!(
                e["body_sha256"],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "{e}"
            );
        }
        assert_eq!(json["dropped"], 0);
    }

    #[tokio::test]
    async fn request_headers_are_redacted_in_the_log() {
        let (state, conn) = fresh(SeedMode::Vulnerable);
        let req = Request::builder()
            .method("POST")
            .uri("/comments")
            .header("cookie", "session=abc; theme=dark")
            .header("authorization", "Bearer x")
            .header("x-role", "admin")
            .header("host", "127.0.0.1:1")
            .body(Full::new(Bytes::from_static(b"comment=hi")))
            .expect("valid request");
        let resp = route(req, state.clone(), conn.clone())
            .await
            .expect("route is infallible");
        assert_eq!(resp.status(), StatusCode::FOUND);

        let json = state.log.http_json();
        let e = &json["entries"][0];
        assert_eq!(e["status"], 302);
        assert_eq!(e["body_len"], 10);
        assert_eq!(e["cookie_names"], serde_json::json!(["session", "theme"]));
        assert_eq!(e["headers"]["x-role"], "admin");
        assert_eq!(e["headers"]["host"], "127.0.0.1:1");
        assert!(e["headers"].get("cookie").is_none(), "{e}");
        assert!(e["headers"].get("authorization").is_none(), "{e}");
        assert_eq!(e["cookie_sha256"].as_str().map(str::len), Some(16), "{e}");
        assert_eq!(e["auth_sha256"].as_str().map(str::len), Some(16), "{e}");
    }

    #[tokio::test]
    async fn comment_store_keeps_the_newest_thousand() {
        let (state, conn) = fresh(SeedMode::Vulnerable);
        for i in 0..=MAX_COMMENTS {
            let req = Request::builder()
                .method("POST")
                .uri("/comments")
                .body(Full::new(Bytes::from(format!("comment=c{i}"))))
                .expect("valid request");
            let resp = route(req, state.clone(), conn.clone())
                .await
                .expect("route is infallible");
            assert_eq!(resp.status(), StatusCode::FOUND);
        }
        let resp = get_on(&state, &conn, "/comments").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        let body = String::from_utf8(body.to_vec()).expect("utf-8 body");
        assert_eq!(body.matches("<li>").count(), MAX_COMMENTS);
        assert_eq!(MAX_COMMENTS, 1_000);
        // The oldest was dropped, the newest kept, order preserved.
        assert!(!body.contains("<li>c0</li>"), "oldest comment must be gone");
        assert!(body.starts_with("<html><body><ul><li>c1</li><li>c2</li>"));
        assert!(body.contains(&format!("<li>c{MAX_COMMENTS}</li></ul>")));
    }

    #[tokio::test]
    async fn redirect_with_crlf_in_next_never_panics() {
        let location = |resp: &Resp| {
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        // V honours any `next`, but a CR/LF is not a header value hyper will
        // carry: it is stripped, the rest of the open redirect survives.
        let (state, conn) = fresh(SeedMode::Vulnerable);
        let resp = get_on(&state, &conn, "/redirect?next=%0d%0aSet-Cookie:x=y").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp).as_deref(), Some("Set-Cookie:x=y"));
        // Still a request, still logged with its status.
        assert_eq!(state.log.http_json()["entries"][0]["status"], 302);
        // Something hyper refuses even without CR/LF (a NUL) falls back to `/`.
        let resp = get_on(&state, &conn, "/redirect?next=/%00x").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp).as_deref(), Some("/"));

        // P: `/\r\nX` passes the same-origin allowlist; the CR/LF is stripped.
        let (state, conn) = fresh(SeedMode::Patched);
        let resp = get_on(&state, &conn, "/redirect?next=/%0d%0aX").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp).as_deref(), Some("/X"));
    }

    #[tokio::test]
    async fn oversize_body_is_413() {
        let (state, conn) = fresh(SeedMode::Vulnerable);
        let big = vec![b'a'; MAX_BODY + 1];
        let req = Request::builder()
            .method("POST")
            .uri("/comments")
            .body(Full::new(Bytes::from(big)))
            .expect("valid request");
        let resp = route(req, state.clone(), conn.clone())
            .await
            .expect("route is infallible");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The refused request is still logged, with the status it got.
        assert_eq!(state.log.http_json()["entries"][0]["status"], 413);
        // Exactly the cap is accepted.
        let req = Request::builder()
            .method("POST")
            .uri("/preview")
            .body(Full::new(Bytes::from(vec![b'a'; MAX_BODY])))
            .expect("valid request");
        let resp = route(req, state, conn).await.expect("route is infallible");
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn request_info_accessors() {
        let info = RequestInfo::test_request(
            "POST",
            "/items?id=1&name=a%20b",
            &[
                ("cookie", "session=abc; theme=dark"),
                ("host", "example.test"),
                ("x-role", "admin"),
            ],
            b"comment=hi+there&n=1",
        );
        assert_eq!(info.method, "POST");
        assert_eq!(info.path, "/items");
        assert_eq!(info.query, "id=1&name=a%20b");
        assert_eq!(info.query_param("id").as_deref(), Some("1"));
        assert_eq!(info.query_param("name").as_deref(), Some("a b"));
        assert_eq!(info.query_param("missing"), None);
        assert_eq!(info.form_param("comment").as_deref(), Some("hi there"));
        assert_eq!(info.form_param("n").as_deref(), Some("1"));
        assert_eq!(info.cookie("session"), Some("abc"));
        assert_eq!(info.cookie("theme"), Some("dark"));
        assert_eq!(info.cookie("nope"), None);
        assert_eq!(info.header("x-role"), Some("admin"));
        assert_eq!(info.header("X-Role"), Some("admin"));
        assert_eq!(info.host, "example.test");
        assert_eq!(info.scheme, "http");
        assert_eq!(info.conn.listener, Listener::Plain);
        assert_eq!(info.body.as_ref(), b"comment=hi+there&n=1");
    }

    // --- Tester additions (stage 5): router coverage of the index, /ws, 404s ---

    #[tokio::test]
    async fn every_index_link_form_and_click_target_is_served() {
        // Every href on `/`, every form action and the click-only data-href is
        // answered by the router: never a 404 (the auth-gated ones 302, the
        // POST forms with an empty body 400/302).
        let (state, conn) = fresh(SeedMode::Vulnerable);
        for href in INDEX_LINKS {
            let resp = get_on(&state, &conn, href).await;
            assert_ne!(resp.status(), StatusCode::NOT_FOUND, "GET {href}");
        }
        let resp = get_on(&state, &conn, "/files/readme.txt").await;
        assert_eq!(resp.status(), StatusCode::OK);
        for (method, action) in [
            ("GET", "/search"),
            ("POST", "/comments"),
            ("POST", "/login"),
            ("POST", "/upload"),
            ("POST", "/api/profile"),
            ("POST", "/api/login"),
            ("POST", "/xml"),
        ] {
            let req = Request::builder()
                .method(method)
                .uri(action)
                .body(Full::new(Bytes::new()))
                .expect("valid request");
            let resp = route(req, state.clone(), conn.clone())
                .await
                .expect("route is infallible");
            assert_ne!(resp.status(), StatusCode::NOT_FOUND, "{method} {action}");
        }
        // And every seed_index row's concrete path is one of those.
        for row in seed_index() {
            let path_only = row.path.split('?').next().unwrap_or(row.path);
            let linked = INDEX_LINKS
                .iter()
                .any(|h| h.split('?').next().unwrap_or(h) == path_only)
                || [
                    "/search",
                    "/comments",
                    "/login",
                    "/upload",
                    "/files/readme.txt",
                    "/ws",
                ]
                .contains(&path_only)
                || ["/xml", "/api/login", "/api/profile"].contains(&path_only);
            assert!(
                linked,
                "seed {} at {} is not linked from /",
                row.id, row.path
            );
        }
    }

    #[tokio::test]
    async fn ws_dispatches_through_the_router() {
        let (state, conn) = fresh(SeedMode::Vulnerable);
        let req = Request::builder()
            .method("GET")
            .uri("/ws")
            .header("host", "127.0.0.1:1")
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(Full::new(Bytes::new()))
            .expect("valid request");
        let resp = route(req, state.clone(), conn.clone())
            .await
            .expect("route is infallible");
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            resp.headers()
                .get("sec-websocket-accept")
                .and_then(|v| v.to_str().ok()),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
        // Without the handshake headers /ws is a 400, not a 404.
        let resp = get_on(&state, &conn, "/ws").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // Both are logged as requests with their status.
        let json = state.log.http_json();
        let statuses: Vec<u64> = json["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter(|e| e["path"] == "/ws")
            .filter_map(|e| e["status"].as_u64())
            .collect();
        assert_eq!(statuses, vec![101, 400]);
        let ws = state.log.ws_json();
        let accepted: Vec<bool> = ws["entries"]
            .as_array()
            .expect("ws entries")
            .iter()
            .filter(|e| e["kind"] == "handshake")
            .filter_map(|e| e["accepted"].as_bool())
            .collect();
        assert_eq!(accepted, vec![true, false]);
    }

    #[tokio::test]
    async fn unknown_paths_are_404_and_logged() {
        // Includes the control routes: the target origin never serves them.
        let (state, conn) = fresh(SeedMode::Vulnerable);
        let paths = [
            "/nope",
            "/grader",
            "/seed",
            "/search/x",
            "/items/1",
            "/api",
            "/log/http",
            "/services",
            "/mode",
            "/reset",
        ];
        for path in paths {
            let resp = get_on(&state, &conn, path).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
            assert_eq!(
                resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok()),
                Some("text/html; charset=utf-8"),
                "{path}"
            );
        }
        let json = state.log.http_json();
        let entries = json["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), paths.len());
        assert!(entries.iter().all(|e| e["status"] == 404), "{json}");
    }
}
