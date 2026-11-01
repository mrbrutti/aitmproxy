//! The control origin (spec D2): a second loopback HTTP/1 port that serves the
//! target's own observer log as JSON to the e2e harness. It is never linked
//! from `/`, never in the HTTP scope, never logs its own requests and never
//! adds the P-mode headers. Six routes: `GET /services`, `GET /log/http`,
//! `GET /log/ws`, `GET /log/l4[?service=NAME]`, `GET /log/conns`,
//! `POST /reset`, `GET /mode`; anything else is a JSON 404.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Body;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::log::{ControlLog, ServiceInfo};

/// Every control response: a JSON document in a [`Full`] body.
type Resp = Response<Full<Bytes>>;

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

    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => {
                    // A transient accept failure (e.g. EMFILE) must not spin
                    // the loop hot; back off briefly and try again.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let conn_log = log.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let log = conn_log.clone();
                    async move { route(req, log).await }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    Ok(addr)
}

/// Dispatch one control request (D2 table). Generic over the body so the
/// in-process tests can drive it with a [`Full`] body; the server passes
/// hyper's [`hyper::body::Incoming`]. No route reads the body.
pub(crate) async fn route<B: Body>(
    req: Request<B>,
    log: Arc<ControlLog>,
) -> Result<Resp, Infallible> {
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
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(value.to_string())))
        .expect("valid response")
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

    fn get(path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Full::new(Bytes::new()))
            .expect("valid request")
    }

    fn post(path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method("POST")
            .uri(path)
            .body(Full::new(Bytes::new()))
            .expect("valid request")
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
}
