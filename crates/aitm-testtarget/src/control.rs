//! The control origin (spec D2): a second loopback HTTP/1 port that serves the
//! target's own observer log as JSON to the e2e harness. It is never linked
//! from `/`, never in the HTTP scope, never logs its own requests and never
//! adds the P-mode headers. Seven routes: `GET /services`, `GET /log/http`,
//! `GET /log/ws`, `GET /log/l4[?service=NAME]`, `GET /log/conns`,
//! `POST /reset`, `GET /mode`; anything else is a JSON 404.
//!
//! Two refusals run before routing, both JSON 403 whatever the route. A
//! request whose `Host` (port stripped) is not `127.0.0.1`, `localhost` or
//! `[::1]`, or that has no `Host` at all, is `bad host`: a DNS-rebinding page
//! whose name now resolves to 127.0.0.1 reaches this port with its own name
//! in `Host` and no `Origin` on a navigation or simple GET, and must not be
//! able to read the logs. The harness dials the loopback address the builder
//! returned and hyper h1 always supplies `Host`, so it is never affected. A
//! request that carries an `Origin` header (a browser page, never the
//! harness) is `cross-origin`, so a page cannot `POST /reset`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Body;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::app::Resp;
use crate::listeners::accept_loop;
use crate::log::{ControlLog, ServiceInfo};

/// Bind the control origin on `127.0.0.1:port` (0 = ephemeral), register it
/// as the `control` service and spawn the HTTP/1 accept loop. Returns the
/// bound address. The loop lives until the runtime shuts down; it writes
/// nothing into `log` (a control request is never an observed request).
pub(crate) async fn bind(port: u16, log: Arc<ControlLog>) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    log.register_service(ServiceInfo {
        name: "control".to_string(),
        proto: "tcp",
        addr,
        role: "control",
        alpn: None,
        grammar: None,
    });

    tokio::spawn(accept_loop(listener, move |stream, _peer| {
        let conn_log = log.clone();
        async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let log = conn_log.clone();
                async move { route(req, log).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        }
    }));

    Ok(addr)
}

/// Dispatch one control request (D2 table). Generic over the body so the
/// in-process tests can drive it with a [`Full`] body; the server passes
/// hyper's [`hyper::body::Incoming`]. No route reads the body.
pub(crate) async fn route<B: Body>(
    req: Request<B>,
    log: Arc<ControlLog>,
) -> Result<Resp, Infallible> {
    let host_ok = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_loopback_host);
    if !host_ok {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({ "error": "bad host" }),
        ));
    }
    if req.headers().contains_key("origin") {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({ "error": "cross-origin" }),
        ));
    }
    let method = req.method();
    let path = req.uri().path();
    let query = req.uri().query();

    let body = match (method, path) {
        (&Method::GET, "/services") => log.services_json(),
        (&Method::GET, "/log/http") => log.http_json(),
        (&Method::GET, "/log/ws") => log.ws_json(),
        (&Method::GET, "/log/l4") => log.l4_json(query_param(query, "service")),
        (&Method::GET, "/log/conns") => log.conns_json(),
        (&Method::POST, "/reset") => json!({ "reset": true, "seq": log.reset() }),
        (&Method::GET, "/mode") => json!({ "mode": log.mode_token() }),
        _ => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({ "error": "not found" }),
            ))
        }
    };
    Ok(json_response(StatusCode::OK, &body))
}

/// Whether a `Host` header value, with any `:port` stripped, is one of the
/// control origin's own loopback names: `127.0.0.1`, `localhost` or `[::1]`.
/// Case-sensitive on purpose (the harness never varies it) and no suffix or
/// subdomain is accepted.
fn is_loopback_host(host: &str) -> bool {
    let name = match (host.starts_with('['), host.find(']')) {
        // IPv6 literal: the port, if any, follows the closing bracket.
        (true, Some(end)) => &host[..=end],
        _ => host.split_once(':').map_or(host, |(name, _)| name),
    };
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

/// The value of `key` in a raw query string (`a=1&b=2`), or `None`. Service
/// names are `[a-z0-9-]`, so no percent-decoding is applied; a key without
/// `=` yields `Some("")`.
fn query_param<'q>(query: Option<&'q str>, key: &str) -> Option<&'q str> {
    query?
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// A response carrying `value` as JSON with `content-type: application/json`.
fn json_response(status: StatusCode, value: &Value) -> Resp {
    crate::app::json(status, value.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, StatusCode};
    use serde_json::{json, Value};

    use super::route;
    use crate::log::{
        sha256_hex, Classified, ControlLog, Dir, HttpVersion, Listener, RequestEntry, ServiceInfo,
    };
    use crate::seed::SeedMode;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// A request as the harness sends it: hyper h1 always supplies a `Host`,
    /// and the harness dials the loopback address the builder returned.
    fn request(method: &str, path: &str, host: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .body(Full::new(Bytes::new()))
            .expect("valid request")
    }

    fn get(path: &str) -> Request<Full<Bytes>> {
        request("GET", path, "127.0.0.1:4")
    }

    fn post(path: &str) -> Request<Full<Bytes>> {
        request("POST", path, "127.0.0.1:4")
    }

    /// Drive `route` and return `(status, content-type, parsed JSON body)`.
    async fn call(req: Request<Full<Bytes>>, log: &Arc<ControlLog>) -> (StatusCode, String, Value) {
        let resp = route(req, log.clone()).await.expect("infallible");
        let status = resp.status();
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("body is JSON");
        (status, ct, json)
    }

    #[tokio::test]
    async fn services_lists_registered() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        log.register_service(ServiceInfo {
            name: "http".to_string(),
            proto: "tcp",
            addr: addr(8001),
            role: "http",
            alpn: Some(vec!["http/1.1"]),
            grammar: None,
        });
        log.register_service(ServiceInfo {
            name: "tls".to_string(),
            proto: "tcp",
            addr: addr(8002),
            role: "http",
            alpn: Some(vec!["h2", "http/1.1"]),
            grammar: None,
        });

        let (status, ct, body) = call(get("/services"), &log).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(body["mode"], json!("vulnerable"));
        assert_eq!(body["services"][0]["name"], json!("http"));
        assert_eq!(body["services"][0]["addr"], json!("127.0.0.1:8001"));
        assert_eq!(body["services"][1]["name"], json!("tls"));
        assert_eq!(body["services"][1]["alpn"], json!(["h2", "http/1.1"]));
    }

    #[tokio::test]
    async fn reset_returns_seq_and_clears() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, addr(40000));
        for path in ["/", "/search"] {
            log.log_request(RequestEntry {
                seq: 0,
                ts_ms: 0,
                conn_id: conn.conn_id.clone(),
                listener: conn.listener,
                version: HttpVersion::H1,
                conn_req_index: conn.next_request_index(),
                method: "GET".to_string(),
                path: path.to_string(),
                query: String::new(),
                headers: Default::default(),
                cookie_names: Vec::new(),
                cookie_sha256: None,
                auth_sha256: None,
                body_len: 0,
                body_sha256: sha256_hex(b""),
                status: 200,
            });
        }
        let (status, _, before) = call(get("/log/http"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before["entries"].as_array().map(Vec::len), Some(2));

        let (status, ct, body) = call(post("/reset"), &log).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(body, json!({ "reset": true, "seq": 2 }));

        let (status, ct, after) = call(get("/log/http"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(after, json!({ "entries": [], "dropped": 0 }));
    }

    #[tokio::test]
    async fn l4_filter() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        log.l4_message(
            "l4-resp",
            "c-00000001",
            Dir::In,
            b"PING\r\n",
            Some("PING"),
            Classified::Ok,
        );
        log.l4_message(
            "l4-tlv-crash",
            "c-00000002",
            Dir::In,
            b"\x01\x00\x00\x00",
            Some("frame"),
            Classified::Ok,
        );

        let (status, ct, all) = call(get("/log/l4"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        let all_keys: Vec<&String> = all["services"]
            .as_object()
            .expect("services object")
            .keys()
            .collect();
        assert_eq!(all_keys, vec!["l4-resp", "l4-tlv-crash"]);

        let (status, ct, filtered) = call(get("/log/l4?service=l4-resp"), &log).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        let keys: Vec<&String> = filtered["services"]
            .as_object()
            .expect("services object")
            .keys()
            .collect();
        assert_eq!(keys, vec!["l4-resp"]);
        assert_eq!(
            filtered["services"]["l4-resp"]["messages"][0]["verb"],
            json!("PING")
        );
        assert_eq!(filtered["dropped"], json!(0));
    }

    #[tokio::test]
    async fn unknown_is_404_json() {
        let log = ControlLog::new(SeedMode::Patched);

        let (status, ct, body) = call(get("/nope"), &log).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(ct, "application/json");
        assert_eq!(body, json!({ "error": "not found" }));

        // `/mode` is the only route that reads the mode token; the lowercase
        // D2 token for the patched variant.
        let (status, ct, body) = call(get("/mode"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(body, json!({ "mode": "patched" }));
    }

    #[tokio::test]
    async fn a_request_with_an_origin_header_is_cross_origin_403() {
        // A browser page cannot drive the control origin (CSRF on `/reset`):
        // any request carrying `Origin` is refused, whatever the route. The
        // harness never sends one.
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, addr(40002));
        log.log_request(RequestEntry {
            seq: 0,
            ts_ms: 0,
            conn_id: conn.conn_id.clone(),
            listener: conn.listener,
            version: HttpVersion::H1,
            conn_req_index: conn.next_request_index(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: String::new(),
            headers: Default::default(),
            cookie_names: Vec::new(),
            cookie_sha256: None,
            auth_sha256: None,
            body_len: 0,
            body_sha256: sha256_hex(b""),
            status: 200,
        });
        for (method, path) in [
            ("POST", "/reset"),
            ("GET", "/services"),
            ("GET", "/log/http"),
            ("GET", "/mode"),
            ("GET", "/nope"),
        ] {
            for origin in ["http://127.0.0.1:1", "null", "http://evil.example"] {
                let mut req = request(method, path, "127.0.0.1:4");
                req.headers_mut()
                    .insert("origin", origin.parse().expect("header value"));
                let (status, ct, body) = call(req, &log).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path} {origin}");
                assert_eq!(ct, "application/json");
                assert_eq!(body, json!({ "error": "cross-origin" }));
            }
        }
        // Nothing was reset by the refused POST.
        let (_, _, http) = call(get("/log/http"), &log).await;
        assert_eq!(http["entries"].as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn a_request_for_a_non_loopback_host_is_bad_host_403() {
        // DNS rebinding: a page at `evil.example` whose name is re-pointed at
        // 127.0.0.1 reaches the port with `Host: evil.example:<port>` and no
        // `Origin` on a plain navigation or `fetch` GET. The control origin
        // answers only to its own loopback names, so such a request cannot
        // read the logs; the check runs before the `Origin` one and before
        // routing, so no route (not even `/reset`) is reachable through it.
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, addr(40003));
        log.log_request(RequestEntry {
            seq: 0,
            ts_ms: 0,
            conn_id: conn.conn_id.clone(),
            listener: conn.listener,
            version: HttpVersion::H1,
            conn_req_index: conn.next_request_index(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: String::new(),
            headers: Default::default(),
            cookie_names: Vec::new(),
            cookie_sha256: None,
            auth_sha256: None,
            body_len: 0,
            body_sha256: sha256_hex(b""),
            status: 200,
        });
        for (method, path) in [("POST", "/reset"), ("GET", "/log/http"), ("GET", "/nope")] {
            for host in [
                "evil.example:1",
                "evil.example",
                "127.0.0.1.evil.example",
                "localhost.evil.example:5",
                "10.0.0.1:5",
                "",
            ] {
                let (status, ct, body) = call(request(method, path, host), &log).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{method} {path} Host={host:?}"
                );
                assert_eq!(ct, "application/json", "{method} {path} Host={host:?}");
                assert_eq!(
                    body,
                    json!({ "error": "bad host" }),
                    "{method} {path} Host={host:?}"
                );
            }
        }
        // No `Host` at all (hyper h1 never does this; a hand-built request) is
        // refused the same way.
        let no_host = Request::builder()
            .method("GET")
            .uri("/mode")
            .body(Full::new(Bytes::new()))
            .expect("valid request");
        let (status, _, body) = call(no_host, &log).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({ "error": "bad host" }));
        // Nothing was reset by the refused POSTs.
        let (_, _, http) = call(get("/log/http"), &log).await;
        assert_eq!(http["entries"].as_array().map(Vec::len), Some(1));

        // The loopback names, with or without a port, route normally.
        for host in [
            "127.0.0.1:5",
            "127.0.0.1",
            "localhost",
            "localhost:65535",
            "[::1]",
            "[::1]:7",
        ] {
            let (status, ct, body) = call(request("GET", "/mode", host), &log).await;
            assert_eq!(status, StatusCode::OK, "Host={host}");
            assert_eq!(ct, "application/json");
            assert_eq!(body, json!({ "mode": "vulnerable" }), "Host={host}");
            let (status, _, body) = call(request("GET", "/nope", host), &log).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "Host={host}");
            assert_eq!(body, json!({ "error": "not found" }));
        }
        // A bad host with an `Origin` too is `bad host`, not `cross-origin`:
        // the host check comes first.
        let mut req = request("POST", "/reset", "evil.example:1");
        req.headers_mut().insert(
            "origin",
            "http://evil.example".parse().expect("header value"),
        );
        let (status, _, body) = call(req, &log).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({ "error": "bad host" }));
    }

    // --- Tester additions (stage 5): the remaining D2 routes and non-routes ---

    #[tokio::test]
    async fn ws_and_conns_routes_and_method_mismatches() {
        let log = ControlLog::new(SeedMode::Vulnerable);
        let conn = log.open_conn(Listener::Plain, None, addr(40001));
        log.log_ws(crate::log::WsLogEntry::Close(crate::log::WsCloseEntry {
            seq: 0,
            ts_ms: 0,
            conn_id: conn.conn_id.clone(),
            code: Some(1009),
        }));

        let (status, ct, ws) = call(get("/log/ws"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(ws["dropped"], json!(0));
        assert_eq!(ws["entries"][0]["kind"], json!("close"));
        assert_eq!(ws["entries"][0]["code"], json!(1009));
        assert_eq!(ws["entries"][0]["conn_id"], json!(conn.conn_id.clone()));

        let (status, ct, conns) = call(get("/log/conns"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "application/json");
        assert_eq!(conns["entries"].as_array().map(Vec::len), Some(1));
        assert_eq!(conns["entries"][0]["conn_id"], json!(conn.conn_id.clone()));
        assert_eq!(conns["entries"][0]["peer"], json!("127.0.0.1:40001"));
        assert_eq!(conns["entries"][0]["listener"], json!("plain"));
        assert_eq!(conns["entries"][0]["alpn"], Value::Null);
        assert_eq!(conns["entries"][0]["closed_ms"], Value::Null);
        assert_eq!(conns["entries"][0]["requests"], json!(0));
        assert!(conns.get("dropped").is_none(), "{conns}");

        // Wrong method, trailing slash, sub-path or case: 404, and nothing reset.
        for req in [
            get("/reset"),
            post("/mode"),
            post("/services"),
            get("/services/"),
            get("/log"),
            get("/log/http/1"),
            get("/LOG/HTTP"),
            post("/log/http"),
            get("/"),
        ] {
            let (status, ct, body) = call(req, &log).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(ct, "application/json");
            assert_eq!(body, json!({ "error": "not found" }));
        }
        let (_, _, ws) = call(get("/log/ws"), &log).await;
        assert_eq!(
            ws["entries"].as_array().map(Vec::len),
            Some(1),
            "GET /reset must not reset"
        );

        // Query strings are ignored except `service` on /log/l4.
        let (status, _, body) = call(get("/services?x=1"), &log).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["mode"], json!("vulnerable"));
        log.l4_message(
            "l4-resp",
            "c-00000009",
            Dir::In,
            b"PING\r\n",
            Some("PING"),
            Classified::Ok,
        );
        let (_, _, body) = call(get("/log/l4?x=1&service=l4-resp&y"), &log).await;
        let keys: Vec<&String> = body["services"]
            .as_object()
            .expect("services object")
            .keys()
            .collect();
        assert_eq!(keys, vec!["l4-resp"]);
        let (_, _, body) = call(get("/log/l4?service="), &log).await;
        assert_eq!(body, json!({ "services": {}, "dropped": 0 }));
        let (_, _, body) = call(get("/log/l4?service=nope"), &log).await;
        assert_eq!(body, json!({ "services": {}, "dropped": 0 }));
    }
}
