//! `aitm-testtarget` — a hermetic, deliberately-vulnerable web app used **only**
//! so an authorized agent can discover real findings against a real target.
//!
//! This crate is test support, not a product surface: it plants one real
//! vulnerability per class in spec §D5 (reflected XSS, stored XSS, SSRF, IDOR,
//! auth bypass, open redirect), each with a patched control variant selected by
//! [`SeedMode`], plus benign decoy endpoints so discovery is non-trivial and
//! false positives are penalized. It binds on loopback and serves plain HTTP;
//! the proxy MITMs it as an HTTPS origin like any other (the M1 bundled
//! reflected-XSS pair, generalized to a multi-vuln site).
//!
//! It is **hermetic**: it opens no outbound sockets. The SSRF "fetch preview" is
//! dereferenced in-process against a virtual internal resource, so a run with a
//! deny-all connector behaves identically — there is nothing to connect to
//! (AC-M4-9: "no external network").
//!
//! The planted-vuln [`manifest`] is grader-only ground truth: it is never served
//! and nothing in [`app`] reads it (AC-M4-10).
//!
//! The [`l4`] module adds an **opt-in**, off-by-default loopback L4 service (UDP
//! echo + minimal TCP) so the L4 operator surfaces have a real, in-scope target;
//! its in-scope assets are declared in the grader-only [`l4_manifest`].

mod app;
mod control;
pub mod grader;
pub mod l4;
mod log;
pub mod manifest;
mod routes;
mod seed;
pub mod speakers;
mod tls;
mod ws;

use std::sync::Arc;

use tokio::net::TcpListener;

pub use grader::{grade, GradeReport};
pub use l4::{L4Config, L4Service};
pub use manifest::{l4_manifest, manifest, manifest_yaml, L4Asset, PlantedVuln};
pub use seed::SeedMode;

/// A running test target: the bound loopback address plus the per-instance state
/// its endpoints share (e.g. the stored-XSS comment store).
pub struct TestTarget {
    base_url: String,
    // Retained so the serving task lives as long as the target; dropping the
    // target lets the accept loop wind down with it.
    _state: Arc<app::AppState>,
}

impl TestTarget {
    /// Bind a fresh loopback port, start serving `mode`, and return once the
    /// listener is accepting. Each call is an independent origin with its own
    /// state, so a vulnerable target and its patched control can run at once.
    pub async fn start(mode: SeedMode) -> TestTarget {
        TestTarget::start_on(mode, 0)
            .await
            .expect("bind loopback test target")
    }

    /// Bind loopback `port` (0 = an ephemeral port), start serving `mode`, and
    /// return once the listener is accepting. Like [`start`](Self::start) but with
    /// the port chosen by the caller, so the standalone serve binary can expose a
    /// fixed, operator-chosen port. Returns the bind error rather than panicking,
    /// since a serve process must report a port clash cleanly.
    pub async fn start_on(mode: SeedMode, port: u16) -> std::io::Result<TestTarget> {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");
        let state = Arc::new(app::AppState::new(mode));

        let serve_state = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let conn_state = serve_state.clone();
                tokio::spawn(async move {
                    app::serve_connection(stream, conn_state).await;
                });
            }
        });

        Ok(TestTarget {
            base_url,
            _state: state,
        })
    }

    /// The `http://127.0.0.1:PORT` origin this instance is serving on.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
