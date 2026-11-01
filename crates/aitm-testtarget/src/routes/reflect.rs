//! Reflection seeds that prove the scanner's non-query insertion-point kinds
//! (child spec D3, class `xss`): a request header (`GET /whoami`), a cookie
//! (`GET /prefs`), a nested JSON value (`POST /api/profile`), a multipart
//! field and filename (`POST /upload`), a path segment (`GET /docs/{slug}`) and
//! a path filename (`GET /files/{name}.txt`). Each value is rendered raw into
//! HTML in Vulnerable mode and HTML-escaped in Patched mode; nothing else
//! differs between the modes, so the control is the escaping alone.
//!
//! Every value comes off the wire, so nothing here panics on it: malformed
//! JSON and a missing multipart boundary are 400s, and the hand-rolled
//! multipart parser is bounded (the router already caps the body at 2 MiB;
//! this module caps the part count and header lines per part).

use std::sync::Arc;

use hyper::StatusCode;
use serde_json::Value;

use crate::app::{html, percent_decode, reflect, AppState, RequestInfo, Resp};

/// Most parts [`parse_multipart`] keeps; later parts are dropped unread.
const MAX_PARTS: usize = 64;
/// Most header lines read per part before the rest are ignored.
const MAX_PART_HEADER_LINES: usize = 32;
/// Longest boundary accepted (RFC 2046 section 5.1.1: 1 to 70 characters);
/// a longer one is a 400 like a missing one.
const MAX_BOUNDARY: usize = 70;

/// Dispatch the six reflection routes; `None` lets the router fall through.
pub(crate) async fn route(info: &RequestInfo, state: &Arc<AppState>) -> Option<Resp> {
    let mode = state.mode;
    let resp = match (info.method.as_str(), info.path.as_str()) {
        ("GET", "/whoami") => whoami(info, mode),
        ("GET", "/prefs") => prefs(info, mode),
        ("POST", "/api/profile") => profile(info, mode),
        ("POST", "/upload") => upload(info, mode),
        ("GET", p) if p.starts_with("/docs/") => doc(mode, &single_segment(p, "/docs/")?),
        ("GET", p) if p.starts_with("/files/") => file(mode, &txt_stem(p)?),
        _ => return None,
    };
    Some(resp)
}

/// The `{name}` of `/files/{name}.txt`: one segment ending in `.txt` with a
/// non-empty stem; `None` otherwise (so `/files/x.png` and `/files/.txt` 404).
fn txt_stem(path: &str) -> Option<String> {
    let segment = single_segment(path, "/files/")?;
    let stem = segment.strip_suffix(".txt")?;
    (!stem.is_empty()).then(|| stem.to_string())
}

/// The one non-empty, slash-free, percent-decoded segment after `prefix`
/// (`/docs/intro` -> `intro`); `None` for no, empty or several segments.
fn single_segment(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(percent_decode(rest))
}

// --- Routes ---------------------------------------------------------------------

/// `GET /whoami`: `User-Agent` and `X-Forwarded-For` reflected into `<p>`s.
/// A missing header reflects as the empty string.
fn whoami(info: &RequestInfo, mode: crate::seed::SeedMode) -> Resp {
    let agent = reflect(mode, info.header("user-agent").unwrap_or(""));
    let from = reflect(mode, info.header("x-forwarded-for").unwrap_or(""));
    html(
        StatusCode::OK,
        format!("<p>agent: {agent}</p><p>from: {from}</p>"),
    )
}

/// `GET /prefs`: the `theme` cookie reflected into the body class; without the
/// cookie the default is set (`theme=light; Path=/`) and rendered.
fn prefs(info: &RequestInfo, mode: crate::seed::SeedMode) -> Resp {
    match info.cookie("theme") {
        Some(theme) => html(
            StatusCode::OK,
            format!("<body class=\"{}\">", reflect(mode, theme)),
        ),
        None => {
            let mut resp = html(StatusCode::OK, "<body class=\"light\">".to_string());
            resp.headers_mut().insert(
                "set-cookie",
                hyper::header::HeaderValue::from_static("theme=light; Path=/"),
            );
            resp
        }
    }
}

/// `POST /api/profile`: the JSON value at `profile.address.city` reflected into
/// a `text/html` `<div>`. Malformed JSON or a missing city is a 400; a
/// non-string city reflects its JSON serialisation.
fn profile(info: &RequestInfo, mode: crate::seed::SeedMode) -> Resp {
    let Ok(doc) = serde_json::from_slice::<Value>(&info.body) else {
        return html(StatusCode::BAD_REQUEST, "invalid json".to_string());
    };
    let Some(city) = json_path(&doc, "profile.address.city") else {
        return html(
            StatusCode::BAD_REQUEST,
            "missing profile.address.city".to_string(),
        );
    };
    let city = match city {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    html(
        StatusCode::OK,
        format!("<div class=\"city\">{}</div>", reflect(mode, &city)),
    )
}

/// `POST /upload`: the `file` part's filename and byte count plus the `note`
/// field reflected into one `<p>`. A request that is not multipart (or names no
/// boundary) is a 400; a missing part reflects as empty / 0 bytes.
fn upload(info: &RequestInfo, mode: crate::seed::SeedMode) -> Resp {
    let Some(boundary) = info.header("content-type").and_then(multipart_boundary) else {
        return html(
            StatusCode::BAD_REQUEST,
            "expected multipart/form-data".to_string(),
        );
    };
    let parts = parse_multipart(&info.body, &boundary);
    let file = parts.iter().find(|p| p.name == "file");
    let filename = file.and_then(|p| p.filename.as_deref()).unwrap_or("");
    let size = file.map_or(0, |p| p.body.len());
    let note = parts
        .iter()
        .find(|p| p.name == "note")
        .map(|p| String::from_utf8_lossy(&p.body).into_owned())
        .unwrap_or_default();
    html(
        StatusCode::OK,
        format!(
            "<p>uploaded {} ({size} bytes): {}</p>",
            reflect(mode, filename),
            reflect(mode, &note)
        ),
    )
}

/// `GET /docs/{slug}`: the slug reflected into an `<h1>`.
fn doc(mode: crate::seed::SeedMode, slug: &str) -> Resp {
    html(
        StatusCode::OK,
        format!("<h1>Doc: {}</h1>", reflect(mode, slug)),
    )
}

/// `GET /files/{name}.txt`: the filename stem reflected into a `<p>`.
fn file(mode: crate::seed::SeedMode, name: &str) -> Resp {
    html(
        StatusCode::OK,
        format!("<p>file {}.txt</p>", reflect(mode, name)),
    )
}

// --- Multipart ------------------------------------------------------------------

/// One `multipart/form-data` part: the `name` and optional `filename` from its
/// `Content-Disposition`, and its raw body.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Part {
    name: String,
    filename: Option<String>,
    body: Vec<u8>,
}

/// The `boundary` parameter of a `multipart/form-data` content type, quoted or
/// bare; `None` when the type is not multipart or the parameter is absent,
/// empty or longer than [`MAX_BOUNDARY`].
fn multipart_boundary(content_type: &str) -> Option<String> {
    let mut params = content_type.split(';');
    let media_type = params.next()?.trim();
    if !media_type.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    params.find_map(|param| {
        let (key, value) = param.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        (!value.is_empty() && value.len() <= MAX_BOUNDARY).then(|| value.to_string())
    })
}

/// Split a multipart body on `--boundary`, tolerant of `\r\n` and bare `\n`
/// line endings. Parts without a `Content-Disposition` name are skipped; at
/// most [`MAX_PARTS`] parts are returned and at most [`MAX_PART_HEADER_LINES`]
/// header lines are read per part. Never panics on malformed input: anything
/// that does not look like a part is simply absent from the result.
fn parse_multipart(body: &[u8], boundary: &str) -> Vec<Part> {
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut cursor = match find(body, &delimiter, 0) {
        Some(at) => at + delimiter.len(),
        None => return parts,
    };
    while parts.len() < MAX_PARTS {
        let rest = &body[cursor..];
        // The closing delimiter `--boundary--` ends the body.
        if rest.starts_with(b"--") {
            break;
        }
        let Some(next) = find(body, &delimiter, cursor) else {
            break;
        };
        let section = &body[cursor..next];
        cursor = next + delimiter.len();
        if let Some(part) = parse_part(section) {
            parts.push(part);
        }
    }
    parts
}

/// One section between two delimiters: an optional line break, header lines,
/// a blank line, the body, and the line break that precedes the next delimiter.
fn parse_part(section: &[u8]) -> Option<Part> {
    let section = strip_leading_newline(section);
    let (header_bytes, body) = split_headers(section)?;
    let body = strip_trailing_newline(body);
    let headers = String::from_utf8_lossy(header_bytes);
    let disposition = headers
        .lines()
        .take(MAX_PART_HEADER_LINES)
        .map(|line| line.trim_end_matches('\r'))
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-disposition")
                .then_some(value)
        })?;
    let name = disposition_param(disposition, "name")?;
    let filename = disposition_param(disposition, "filename");
    Some(Part {
        name,
        filename,
        body: body.to_vec(),
    })
}

/// A `key="value"` (or bare `key=value`) parameter of a header value.
fn disposition_param(value: &str, key: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|param| {
        let (k, v) = param.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case(key) {
            return None;
        }
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(v);
        Some(v.to_string())
    })
}

/// Split a part at its first blank line (`\r\n\r\n` or `\n\n`, whichever
/// comes first); `None` when there is none.
fn split_headers(section: &[u8]) -> Option<(&[u8], &[u8])> {
    let crlf = find(section, b"\r\n\r\n", 0).map(|at| (at, 4));
    let lf = find(section, b"\n\n", 0).map(|at| (at, 2));
    let (at, len) = match (crlf, lf) {
        (Some(c), Some(l)) => {
            if c.0 <= l.0 {
                c
            } else {
                l
            }
        }
        (Some(c), None) => c,
        (None, Some(l)) => l,
        (None, None) => return None,
    };
    Some((&section[..at], &section[at + len..]))
}

fn strip_leading_newline(b: &[u8]) -> &[u8] {
    b.strip_prefix(b"\r\n")
        .or_else(|| b.strip_prefix(b"\n"))
        .unwrap_or(b)
}

fn strip_trailing_newline(b: &[u8]) -> &[u8] {
    b.strip_suffix(b"\r\n")
        .or_else(|| b.strip_suffix(b"\n"))
        .unwrap_or(b)
}

/// First offset of `needle` in `haystack` at or after `from`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| at + from)
}

// --- JSON -----------------------------------------------------------------------

/// Walk a dotted `path` (`profile.address.city`) through objects by key and
/// arrays by index; `None` as soon as a step is missing.
fn json_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, key| match cur {
        Value::Object(map) => map.get(key),
        Value::Array(items) => key.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    //! Route-level tests driven through [`route`] with a [`RequestInfo`] built
    //! by `RequestInfo::test_request`, so they run in the sandbox (no sockets).

    use std::sync::Arc;

    use http_body_util::BodyExt;
    use hyper::StatusCode;

    use super::{json_path, multipart_boundary, parse_multipart, route};
    use crate::app::{AppState, RequestInfo, Resp};
    use crate::log::ControlLog;
    use crate::seed::SeedMode;

    fn state(mode: SeedMode) -> Arc<AppState> {
        Arc::new(AppState::new(mode, ControlLog::new(mode)))
    }

    async fn body_string(resp: Resp) -> String {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("full body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf-8 body")
    }

    /// Dispatch `info` in `mode`; panics if the route declined it.
    async fn call(mode: SeedMode, info: &RequestInfo) -> Resp {
        route(info, &state(mode))
            .await
            .unwrap_or_else(|| panic!("reflect::route declined {} {}", info.method, info.path))
    }

    #[tokio::test]
    async fn whoami_reflects_headers() {
        let info = RequestInfo::test_request(
            "GET",
            "/whoami",
            &[("user-agent", "<u>"), ("x-forwarded-for", "<x>")],
            b"",
        );

        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<p>agent: <u></p><p>from: <x></p>");

        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_string(resp).await,
            "<p>agent: &lt;u&gt;</p><p>from: &lt;x&gt;</p>"
        );
    }

    #[tokio::test]
    async fn prefs_cookie() {
        let with_cookie =
            RequestInfo::test_request("GET", "/prefs", &[("cookie", "theme=<t>")], b"");

        let resp = call(SeedMode::Vulnerable, &with_cookie).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "a present cookie is not re-set"
        );
        assert_eq!(body_string(resp).await, "<body class=\"<t>\">");

        let resp = call(SeedMode::Patched, &with_cookie).await;
        assert_eq!(body_string(resp).await, "<body class=\"&lt;t&gt;\">");

        let without = RequestInfo::test_request("GET", "/prefs", &[], b"");
        let resp = call(SeedMode::Vulnerable, &without).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("set-cookie")
                .and_then(|v| v.to_str().ok()),
            Some("theme=light; Path=/")
        );
        assert_eq!(body_string(resp).await, "<body class=\"light\">");
    }

    #[tokio::test]
    async fn profile_nested_city() {
        let info = RequestInfo::test_request(
            "POST",
            "/api/profile",
            &[("content-type", "application/json")],
            br#"{"profile":{"address":{"city":"<c>"}}}"#,
        );

        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
        assert_eq!(body_string(resp).await, "<div class=\"city\"><c></div>");

        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(
            body_string(resp).await,
            "<div class=\"city\">&lt;c&gt;</div>"
        );

        let bad = RequestInfo::test_request(
            "POST",
            "/api/profile",
            &[("content-type", "application/json")],
            b"{\"profile\": not json",
        );
        let resp = call(SeedMode::Vulnerable, &bad).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_multipart() {
        let body = b"--X\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"<f>.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
abc\r\n\
--X\r\n\
Content-Disposition: form-data; name=\"note\"\r\n\
\r\n\
<n>\r\n\
--X--\r\n";
        let info = RequestInfo::test_request(
            "POST",
            "/upload",
            &[("content-type", "multipart/form-data; boundary=X")],
            body,
        );

        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_string(resp).await,
            "<p>uploaded <f>.txt (3 bytes): <n></p>"
        );

        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(
            body_string(resp).await,
            "<p>uploaded &lt;f&gt;.txt (3 bytes): &lt;n&gt;</p>"
        );
    }

    #[tokio::test]
    async fn upload_without_multipart_is_400() {
        let info = RequestInfo::test_request(
            "POST",
            "/upload",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"note=hi",
        );
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn docs_and_files_paths() {
        let docs = RequestInfo::test_request("GET", "/docs/<s>", &[], b"");
        let resp = call(SeedMode::Vulnerable, &docs).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<h1>Doc: <s></h1>");
        let resp = call(SeedMode::Patched, &docs).await;
        assert_eq!(body_string(resp).await, "<h1>Doc: &lt;s&gt;</h1>");

        let files = RequestInfo::test_request("GET", "/files/<n>.txt", &[], b"");
        let resp = call(SeedMode::Vulnerable, &files).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<p>file <n>.txt</p>");
        let resp = call(SeedMode::Patched, &files).await;
        assert_eq!(body_string(resp).await, "<p>file &lt;n&gt;.txt</p>");

        // Percent-encoded segments (how a scanner puts `<` on the wire) decode.
        let encoded = RequestInfo::test_request("GET", "/docs/%3Cs%3E", &[], b"");
        let resp = call(SeedMode::Vulnerable, &encoded).await;
        assert_eq!(body_string(resp).await, "<h1>Doc: <s></h1>");

        // Anything that is not exactly one segment falls through to the 404.
        let st = state(SeedMode::Vulnerable);
        for target in [
            "/docs/a/b",
            "/docs/",
            "/docs",
            "/files/x.png",
            "/files/.txt",
            "/files/a/b.txt",
        ] {
            let info = RequestInfo::test_request("GET", target, &[], b"");
            assert!(
                route(&info, &st).await.is_none(),
                "{target} must not be routed by reflect"
            );
        }
        let post = RequestInfo::test_request("POST", "/docs/intro", &[], b"");
        assert!(
            route(&post, &st).await.is_none(),
            "POST /docs/x is not routed"
        );
    }

    #[tokio::test]
    async fn multipart_boundary_longer_than_70_bytes_is_refused() {
        // RFC 2046 section 5.1.1: a boundary is 1 to 70 characters.
        let ok = "b".repeat(70);
        let too_long = "b".repeat(71);
        assert_eq!(
            multipart_boundary(&format!("multipart/form-data; boundary={ok}")).as_deref(),
            Some(ok.as_str())
        );
        assert_eq!(
            multipart_boundary(&format!("multipart/form-data; boundary={too_long}")),
            None
        );
        assert_eq!(
            multipart_boundary(&format!("multipart/form-data; boundary=\"{too_long}\"")),
            None
        );
        let ct = format!("multipart/form-data; boundary={too_long}");
        let body = format!(
            "--{too_long}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--{too_long}--\r\n"
        );
        let info = RequestInfo::test_request(
            "POST",
            "/upload",
            &[("content-type", ct.as_str())],
            body.as_bytes(),
        );
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            let resp = call(mode, &info).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(body_string(resp).await, "expected multipart/form-data");
        }
    }

    #[test]
    fn multipart_boundary_parses_plain_and_quoted() {
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=X").as_deref(),
            Some("X")
        );
        assert_eq!(
            multipart_boundary("multipart/form-data; charset=utf-8; boundary=\"ab cd\"").as_deref(),
            Some("ab cd")
        );
        assert_eq!(multipart_boundary("application/json"), None);
        assert_eq!(multipart_boundary("multipart/form-data"), None);
        assert_eq!(multipart_boundary("multipart/form-data; boundary="), None);
    }

    #[test]
    fn parse_multipart_tolerates_bare_lf() {
        let body = b"--B\nContent-Disposition: form-data; name=\"note\"\n\nhello\n--B\nContent-Disposition: form-data; name=\"file\"; filename=\"r.txt\"\n\nabc\n--B--\n";
        let parts = parse_multipart(body, "B");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "note");
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].body, b"hello");
        assert_eq!(parts[1].name, "file");
        assert_eq!(parts[1].filename.as_deref(), Some("r.txt"));
        assert_eq!(parts[1].body, b"abc");
    }

    #[test]
    fn parse_multipart_is_bounded_and_skips_nameless_parts() {
        // 100 parts in; only the first 64 are kept.
        let mut body = Vec::new();
        for i in 0..100 {
            body.extend_from_slice(
                format!("--B\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--B--\r\n");
        assert_eq!(parse_multipart(&body, "B").len(), 64);

        let nameless = b"--B\r\nContent-Type: text/plain\r\n\r\nv\r\n--B--\r\n";
        assert!(parse_multipart(nameless, "B").is_empty());
        assert!(parse_multipart(b"garbage without any boundary", "B").is_empty());
    }

    #[test]
    fn json_path_descends_objects_and_arrays() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"profile":{"address":{"city":"Paris"},"tags":["a","b"]}}"#)
                .expect("test json");
        assert_eq!(
            json_path(&v, "profile.address.city").and_then(|c| c.as_str()),
            Some("Paris")
        );
        assert_eq!(
            json_path(&v, "profile.tags.1").and_then(|c| c.as_str()),
            Some("b")
        );
        assert!(json_path(&v, "profile.address.zip").is_none());
        assert!(json_path(&v, "profile.address.city.more").is_none());
    }

    // --- Tester additions (stage 5): empty, missing and malformed inputs ---

    #[tokio::test]
    async fn whoami_without_headers_reflects_empty() {
        let info = RequestInfo::test_request("GET", "/whoami", &[], b"");
        for mode in [SeedMode::Vulnerable, SeedMode::Patched] {
            let resp = call(mode, &info).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(body_string(resp).await, "<p>agent: </p><p>from: </p>");
        }
        // Only the two D3 headers are reflected.
        let other = RequestInfo::test_request(
            "GET",
            "/whoami",
            &[("referer", "<r>"), ("x-real-ip", "<i>")],
            b"",
        );
        let resp = call(SeedMode::Vulnerable, &other).await;
        assert_eq!(body_string(resp).await, "<p>agent: </p><p>from: </p>");
    }

    #[tokio::test]
    async fn prefs_theme_among_other_cookies() {
        let info = RequestInfo::test_request(
            "GET",
            "/prefs",
            &[("cookie", "session=abc; theme=dark; lang=en")],
            b"",
        );
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert!(resp.headers().get("set-cookie").is_none());
        assert_eq!(body_string(resp).await, "<body class=\"dark\">");
        // Without a theme (other cookies present) the default is set.
        let info = RequestInfo::test_request("GET", "/prefs", &[("cookie", "session=abc")], b"");
        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(
            resp.headers()
                .get("set-cookie")
                .and_then(|v| v.to_str().ok()),
            Some("theme=light; Path=/")
        );
        assert_eq!(body_string(resp).await, "<body class=\"light\">");
    }

    #[tokio::test]
    async fn profile_missing_city_empty_body_and_non_string() {
        let json_ct: &[(&str, &str)] = &[("content-type", "application/json")];
        for (body, expected) in [
            (&br#"{"profile":{}}"#[..], "missing profile.address.city"),
            (
                br#"{"profile":{"address":{}}}"#,
                "missing profile.address.city",
            ),
            (br#"{"user":"x"}"#, "missing profile.address.city"),
            (b"", "invalid json"),
            (b"[]", "missing profile.address.city"),
        ] {
            let info = RequestInfo::test_request("POST", "/api/profile", json_ct, body);
            let resp = call(SeedMode::Vulnerable, &info).await;
            let shown = String::from_utf8_lossy(body);
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{shown}");
            assert_eq!(body_string(resp).await, expected, "{shown}");
        }
        // A non-string city reflects its JSON rendering, escaped in P.
        let info = RequestInfo::test_request(
            "POST",
            "/api/profile",
            json_ct,
            br#"{"profile":{"address":{"city":{"n":1}}}}"#,
        );
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_string(resp).await,
            r#"<div class="city">{"n":1}</div>"#
        );
        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(
            body_string(resp).await,
            r#"<div class="city">{&quot;n&quot;:1}</div>"#
        );
    }

    #[tokio::test]
    async fn upload_missing_boundary_and_missing_parts() {
        // multipart without a boundary parameter is a 400.
        let info = RequestInfo::test_request(
            "POST",
            "/upload",
            &[("content-type", "multipart/form-data")],
            b"--X\r\n",
        );
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(resp).await, "expected multipart/form-data");
        // No content-type at all.
        let info = RequestInfo::test_request("POST", "/upload", &[], b"");
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let ct: &[(&str, &str)] = &[("content-type", "multipart/form-data; boundary=X")];
        // Only a note: no filename, 0 bytes.
        let only_note =
            b"--X\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--X--\r\n";
        let info = RequestInfo::test_request("POST", "/upload", ct, only_note);
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<p>uploaded  (0 bytes): hi</p>");
        // A file part without a filename, and no note.
        let no_name =
            b"--X\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nabc\r\n--X--\r\n";
        let info = RequestInfo::test_request("POST", "/upload", ct, no_name);
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(body_string(resp).await, "<p>uploaded  (3 bytes): </p>");
        // A body with no parts at all.
        let info = RequestInfo::test_request("POST", "/upload", ct, b"garbage");
        let resp = call(SeedMode::Patched, &info).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<p>uploaded  (0 bytes): </p>");
        // A long note is reflected whole (the router caps the body, not this seed).
        let big = "n".repeat(10_000);
        let body = format!(
            "--X\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n{big}\r\n--X--\r\n"
        );
        let info = RequestInfo::test_request("POST", "/upload", ct, body.as_bytes());
        let resp = call(SeedMode::Vulnerable, &info).await;
        assert_eq!(
            body_string(resp).await,
            format!("<p>uploaded  (0 bytes): {big}</p>")
        );
    }
}
