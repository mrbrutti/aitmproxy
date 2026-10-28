//! The local HTTPS fixture behind the obscura MITM tests (M2 Task 24).
//!
//! An rcgen self-signed leaf for `localhost`, a tokio-rustls acceptor, and a
//! hyper handler whose `/` page pulls a sub-resource through every fetch path
//! the engine has — an `<img>`, an inline `fetch()`, an XHR — and, when asked,
//! references a raw cleartext loopback listener that is neither the proxy nor
//! in scope (M2-AC12). The proxy's upstream leg accepts the self-signed leaf via
//! `cfg.ssl_insecure = true`; the leg under test is obscura ↔ proxy, where the
//! proxy presents a leaf minted by the aitmproxy CA.
//!
//! The TLS listener binds the same port on `127.0.0.1` **and** `::1`: the proxy
//! resolves `localhost` with the system resolver and dials the first address it
//! gets, which on macOS may be either.

use std::convert::Infallible;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The marker the `/` page carries in its title and body (M2-AC10 asserts on it).
pub const MARKER: &str = "aitm-fixture";

/// A 1×1 transparent PNG, served at `/img.png`.
const PNG_1X1: &[u8] = &[
    0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', // signature
    0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R', // IHDR, 13 bytes
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, // 1×1 RGBA
    0x1f, 0x15, 0xc4, 0x89, // IHDR crc
    0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', // IDAT, 10 bytes
    0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, // one transparent pixel
    0x0d, 0x0a, 0x2d, 0xb4, // IDAT crc
    0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82, // IEND
];

/// The routes the handler answers. Everything else is a 404.
const ROUTES: [&str; 4] = ["/", "/img.png", "/api", "/xhr"];

/// The HTTPS fixture: `https://localhost:<port>/…`.
pub struct HttpsFixture {
    port: u16,
}

impl HttpsFixture {
    /// Bind both loopbacks on one free port, start the TLS server, and return
    /// its address. With `raw`, the page also references `http://<raw>/x.png`
    /// (an `<img>`) and `http://<raw>/y` (a `fetch()`).
    pub async fn spawn(raw: Option<SocketAddr>) -> Self {
        let (v4, v6, port) = bind_both_loopbacks().await;
        let page: Arc<str> = page_html(port, raw).into();
        let acceptor = tls_acceptor();
        serve_tls(v4, acceptor.clone(), page.clone());
        if let Some(v6) = v6 {
            serve_tls(v6, acceptor, page);
        }
        Self { port }
    }

    /// `localhost:<port>` — the scope entry and the captured flows' authority.
    pub fn authority(&self) -> String {
        format!("localhost:{}", self.port)
    }

    /// `https://localhost:<port><path>`.
    pub fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.authority())
    }

    /// The paths the `/` page's sub-resources hit, in document order.
    pub fn subresource_paths() -> [&'static str; 3] {
        ["/img.png", "/api", "/xhr"]
    }
}

/// A cleartext loopback listener serving the same routes, counting every TCP
/// connection it accepts. For M2-AC12 it is the listener nothing may reach; for
/// M2-AC15 it is the unscoped target that becomes reachable once scoped.
pub struct PlainFixture {
    pub addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl PlainFixture {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the plain fixture");
        let addr = listener.local_addr().expect("plain fixture addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let page: Arc<str> = page_html(addr.port(), None).into();
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let page = page.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tcp),
                            service_fn(move |req| handle(req, page.clone())),
                        )
                        .await;
                });
            }
        });
        Self { addr, accepted }
    }

    /// TCP connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// `http://127.0.0.1:<port><path>`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

/// `127.0.0.1:0`, then the same port on `::1`; retried when the IPv6 side is
/// taken. A host without an IPv6 loopback serves IPv4 only.
async fn bind_both_loopbacks() -> (TcpListener, Option<TcpListener>, u16) {
    for _ in 0..16 {
        let v4 = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fixture on 127.0.0.1");
        let port = v4.local_addr().expect("fixture addr").port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            Ok(v6) => return (v4, Some(v6), port),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(_) => return (v4, None, port),
        }
    }
    panic!("could not bind one port on both loopbacks after 16 attempts");
}

/// A fresh self-signed leaf for `localhost` behind a rustls (ring) acceptor.
fn tls_acceptor() -> TlsAcceptor {
    let key = rcgen::KeyPair::generate().expect("fixture key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("fixture params")
        .self_signed(&key)
        .expect("fixture cert");
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("fixture protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .expect("fixture server config");
    TlsAcceptor::from(Arc::new(cfg))
}

fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, page: Arc<str>) {
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let page = page.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(move |req| handle(req, page.clone())),
                    )
                    .await;
            });
        }
    });
}

async fn handle(
    req: Request<Incoming>,
    page: Arc<str>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let (status, content_type, body): (StatusCode, &str, Bytes) = match path {
        "/" => (
            StatusCode::OK,
            "text/html; charset=utf-8",
            Bytes::from(page.to_string()),
        ),
        "/img.png" => (StatusCode::OK, "image/png", Bytes::from_static(PNG_1X1)),
        "/api" | "/xhr" => (
            StatusCode::OK,
            "application/json",
            Bytes::from(format!("{{\"ok\":true,\"route\":\"{}\"}}", &path[1..])),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from(format!("no route {path}; routes: {ROUTES:?}")),
        ),
    };
    let resp = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .body(Full::new(body))
        .expect("a valid response");
    Ok(resp)
}

/// The `/` page: the marker, an `<img>` to `/img.png`, a `fetch()` of `/api`
/// and an XHR to `/xhr`, all absolute `https://localhost:<port>` URLs; plus the
/// raw-listener references when `raw` is given. Each sub-resource records its
/// completion on `window` so a test can also ask the page what finished.
fn page_html(port: u16, raw: Option<SocketAddr>) -> String {
    let base = format!("https://localhost:{port}");
    let mut body = format!(
        "<p id=\"marker\">{MARKER}</p>\
         <img id=\"img\" src=\"{base}/img.png\" alt=\"\" \
              onload=\"window.__img='loaded'\" onerror=\"window.__img='error'\">"
    );
    let mut script = format!(
        "fetch('{base}/api').then(function(r){{return r.json()}})\
             .then(function(j){{window.__api=j.ok}}).catch(function(){{window.__api='error'}});\
         var x=new XMLHttpRequest();x.open('GET','{base}/xhr');\
         x.onload=function(){{window.__xhr=true}};x.onerror=function(){{window.__xhr='error'}};\
         x.send();"
    );
    if let Some(raw) = raw {
        body.push_str(&format!(
            "<img id=\"raw-img\" src=\"http://{raw}/x.png\" alt=\"\">"
        ));
        script.push_str(&format!("fetch('http://{raw}/y').catch(function(){{}});"));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{MARKER}</title></head>\
         <body>{body}<script>{script}</script></body></html>"
    )
}
