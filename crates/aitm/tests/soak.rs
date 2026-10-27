//! Task 30 / AC20: sustained-load soak. Gated behind `AITM_SOAK=1` so a normal
//! `cargo test` stays fast; the exit gate runs it explicitly:
//!
//! ```text
//! AITM_SOAK=1 cargo test -p aitm --test soak -- --nocapture
//! ```
//!
//! It drives sustained small+large traffic through a real `Proxy` to a local
//! upstream and asserts (i) throughput >= 2000 req/s on one instance and
//! (ii) resident memory plateaus (the measurement-window last-quartile mean RSS
//! is within a bounded delta of the first-quartile mean — no leak/OOM).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aitm::wire::build_proxy;
use aitm_core::Config;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A local upstream: `GET /` → a 64-byte body, `GET /large` → a 64 KiB body.
async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(handle))
                    .await;
            });
        }
    });
    addr
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let body = if req.uri().path() == "/large" {
        vec![b'A'; 64 * 1024]
    } else {
        vec![b'x'; 64]
    };
    Ok(Response::new(Full::new(Bytes::from(body))))
}

/// Resident set size of this process, in KiB (via `ps`), 0 if unavailable.
fn rss_kib() -> u64 {
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// One keep-alive client: send `GET`s through the proxy to `upstream`, counting
/// completed responses, until `stop`.
async fn client(
    proxy: SocketAddr,
    upstream: SocketAddr,
    count: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    large_every: u64,
) {
    let Ok(mut stream) = TcpStream::connect(proxy).await else {
        return;
    };
    let mut buf = vec![0u8; 128 * 1024];
    let mut n: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let path = if large_every != 0 && n.is_multiple_of(large_every) {
            "/large"
        } else {
            "/"
        };
        let req = format!("GET {path} HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
        if stream.write_all(req.as_bytes()).await.is_err() {
            return;
        }
        // Read one response (headers + Content-Length body).
        let Some(len) = read_response(&mut stream, &mut buf).await else {
            return;
        };
        let _ = len;
        n += 1;
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read one HTTP/1.1 response off `stream`; return the body length, or None on error.
async fn read_response(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let mut data: Vec<u8> = Vec::new();
    let head_end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let k = stream.read(buf).await.ok()?;
        if k == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..k]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]);
    let content_len: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = data.len() - head_end;
    while body < content_len {
        let k = stream.read(buf).await.ok()?;
        if k == 0 {
            return None;
        }
        body += k;
    }
    Some(content_len)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn throughput_floor_and_memory_plateau() {
    if std::env::var("AITM_SOAK").is_err() {
        eprintln!("soak skipped; run with AITM_SOAK=1 to execute (AC20)");
        return;
    }

    let warmup = Duration::from_secs(env_secs("AITM_SOAK_WARMUP", 3));
    let measure = Duration::from_secs(env_secs("AITM_SOAK_MEASURE", 10));
    let clients: usize = std::env::var("AITM_SOAK_CLIENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);

    let upstream = spawn_upstream().await;

    // A small store cap so memory reaches steady state quickly (the store evicts
    // oldest flows beyond the cap), making the plateau observable in a short run.
    let mut cfg = Config::default();
    cfg.ca.dir = std::env::temp_dir().join(format!("aitm-soak-ca-{}", std::process::id()));
    cfg.max_flows = 4096;
    let proxy = build_proxy(&cfg).expect("build proxy");
    let listen = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    {
        let proxy = proxy;
        tokio::spawn(async move {
            let _ = proxy.run(listen).await;
        });
    }
    // Wait until the proxy accepts.
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(listen).await.is_err() {
        assert!(Instant::now() < deadline, "proxy never listened");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let count = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for i in 0..clients {
        let c = count.clone();
        let s = stop.clone();
        // Some clients mix in 64 KiB bodies (every 16th request) so the soak
        // covers large transfers without dominating the throughput measurement.
        let large_every = if i % 8 == 0 { 16 } else { 0 };
        handles.push(tokio::spawn(client(listen, upstream, c, s, large_every)));
    }

    // Warm up (fill the store to its cap, warm caches).
    tokio::time::sleep(warmup).await;

    // Measure throughput and sample RSS over the measurement window.
    let samples = Arc::new(Mutex::new(Vec::<u64>::new()));
    {
        let samples = samples.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                samples.lock().unwrap().push(rss_kib());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
    let start_count = count.load(Ordering::Relaxed);
    let t0 = Instant::now();
    tokio::time::sleep(measure).await;
    let elapsed = t0.elapsed().as_secs_f64();
    let done = count.load(Ordering::Relaxed) - start_count;
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.await;
    }

    let rps = done as f64 / elapsed;
    let rss = samples.lock().unwrap().clone();
    let (q1, q4) = first_last_quartile_means(&rss);
    eprintln!(
        "SOAK: {done} requests in {elapsed:.2}s = {rps:.0} req/s; \
         RSS first-quartile {q1:.0} KiB, last-quartile {q4:.0} KiB over {} samples",
        rss.len()
    );

    assert!(
        rps >= 2000.0,
        "throughput floor is 2000 req/s, measured {rps:.0}"
    );
    // Memory plateaus: the last-quartile mean is within 15% of the first-quartile
    // mean (both inside the steady-state measurement window).
    assert!(q1 > 0.0, "RSS sampling produced no data");
    let growth = (q4 - q1) / q1;
    assert!(
        growth < 0.15,
        "resident memory grew {:.1}% across the window (first {q1:.0} -> last {q4:.0} KiB); \
         expected a plateau",
        growth * 100.0
    );
}

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Mean of the first and last quarter of the samples.
fn first_last_quartile_means(samples: &[u64]) -> (f64, f64) {
    if samples.len() < 4 {
        let m = mean(samples);
        return (m, m);
    }
    let q = samples.len() / 4;
    (mean(&samples[..q]), mean(&samples[samples.len() - q..]))
}

fn mean(xs: &[u64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<u64>() as f64 / xs.len() as f64
}
