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
//!
//! [`TestTarget::builder`] adds the T10 scanner surfaces on the same shared state:
//! TLS listeners (ALPN `h2`+`http/1.1` and `http/1.1`-only), the loopback
//! control origin (spec D2) and the nine L4 speakers ([`speakers`]).

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

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;

pub use grader::{grade, GradeReport};
pub use l4::{L4Config, L4Service};
pub use manifest::{
    l4_manifest, manifest, manifest_yaml, seed_index, Discovery, L4Asset, PlantedVuln, SeedRoute,
};
pub use seed::SeedMode;
pub use speakers::{L4Services, RunningService};

/// A running test target: the bound loopback addresses plus the per-instance
/// state its listeners share (comment store, sessions, control log).
///
/// Built by [`TestTarget::builder`]; [`TestTarget::start`] and
/// [`TestTarget::start_on`] are the plain-HTTP shorthands the legacy suites use.
pub struct TestTarget {
    mode: SeedMode,
    base_url: String,
    tls_url: Option<String>,
    tls_h1_url: Option<String>,
    control_url: Option<String>,
    // Retained so the serving tasks live as long as the target; dropping the
    // target lets the accept loops wind down with it.
    _state: Arc<app::AppState>,
    // Dropping the target aborts every speaker task (and its connections).
    _l4: Option<L4Services>,
}

/// Which listeners a [`TestTarget`] starts (spec D1 "Library" row). Every port
/// is loopback-only; `0` means an ephemeral port. A listener whose setter was
/// never called is not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetBuilder {
    mode: SeedMode,
    port: u16,
    tls: Option<u16>,
    tls_h1: Option<u16>,
    control: Option<u16>,
    l4: bool,
}

impl TargetBuilder {
    /// Plain HTTP/1 port (default `0`, always started).
    pub fn port(mut self, p: u16) -> Self {
        self.port = p;
        self
    }

    /// Start the TLS listener (ALPN `h2`, `http/1.1`) on `p`.
    pub fn tls(mut self, p: u16) -> Self {
        self.tls = Some(p);
        self
    }

    /// Start the TLS listener (ALPN `http/1.1` only) on `p`.
    pub fn tls_h1(mut self, p: u16) -> Self {
        self.tls_h1 = Some(p);
        self
    }

    /// Start the control origin (spec D2) on `p`.
    pub fn control(mut self, p: u16) -> Self {
        self.control = Some(p);
        self
    }

    /// Start every L4 speaker on an ephemeral port. Requires [`control`](Self::control).
    pub fn l4(mut self, on: bool) -> Self {
        self.l4 = on;
        self
    }

    /// Bind and start the listeners in the order plain, tls, tls_h1, control,
    /// l4, returning once every one is accepting. `l4(true)` without
    /// `control(..)` is `InvalidInput` (`l4 needs control`) and binds nothing;
    /// a bind error is returned as-is (a serve process must report a port
    /// clash cleanly).
    pub async fn start(self) -> std::io::Result<TestTarget> {
        if self.l4 && self.control.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "l4 needs control",
            ));
        }
        let mode = self.mode;
        let log = log::ControlLog::new(mode);
        let state = Arc::new(app::AppState::new(mode, log.clone()));

        let plain = bind_plain(self.port, state.clone()).await?;
        let base_url = format!("http://{plain}");

        let mut tls_url = None;
        if let Some(port) = self.tls {
            let addr = tls::bind(log::Listener::Tls, port, state.clone()).await?;
            tls_url = Some(format!("https://{addr}"));
        }
        let mut tls_h1_url = None;
        if let Some(port) = self.tls_h1 {
            let addr = tls::bind(log::Listener::TlsH1, port, state.clone()).await?;
            tls_h1_url = Some(format!("https://{addr}"));
        }
        let mut control_url = None;
        if let Some(port) = self.control {
            let addr = control::bind(port, log.clone()).await?;
            control_url = Some(format!("http://{addr}"));
        }
        let l4 = if self.l4 {
            Some(L4Services::start(mode, log).await?)
        } else {
            None
        };

        Ok(TestTarget {
            mode,
            base_url,
            tls_url,
            tls_h1_url,
            control_url,
            _state: state,
            _l4: l4,
        })
    }
}

/// Bind the plain HTTP/1 listener on loopback `port`, register it as the
/// `http` service (spec D2 `/services`) and spawn its accept loop.
async fn bind_plain(port: u16, state: Arc<app::AppState>) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    state.log.register_service(log::ServiceInfo {
        name: "http".to_string(),
        proto: "tcp",
        addr,
        role: "http",
        alpn: Some(vec!["http/1.1"]),
        grammar: None,
    });

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let conn_state = state.clone();
            tokio::spawn(async move {
                app::serve_connection(stream, conn_state).await;
            });
        }
    });
    Ok(addr)
}

impl TestTarget {
    /// A builder for a target in `mode` with only the plain listener enabled.
    pub fn builder(mode: SeedMode) -> TargetBuilder {
        TargetBuilder {
            mode,
            port: 0,
            tls: None,
            tls_h1: None,
            control: None,
            l4: false,
        }
    }

    /// Bind a fresh loopback port, start serving `mode` over plain HTTP, and
    /// return once the listener is accepting. Each call is an independent origin
    /// with its own state, so a vulnerable target and its patched control can
    /// run at once.
    pub async fn start(mode: SeedMode) -> TestTarget {
        TestTarget::builder(mode)
            .start()
            .await
            .expect("bind loopback test target")
    }

    /// Bind loopback `port` (0 = an ephemeral port), start serving `mode` over
    /// plain HTTP, and return once the listener is accepting. Like
    /// [`start`](Self::start) but with the port chosen by the caller. Returns the
    /// bind error rather than panicking.
    pub async fn start_on(mode: SeedMode, port: u16) -> std::io::Result<TestTarget> {
        TestTarget::builder(mode).port(port).start().await
    }

    /// The `http://127.0.0.1:PORT` origin this instance is serving on.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The `https://127.0.0.1:PORT` TLS (ALPN `h2`, `http/1.1`) origin, if started.
    pub fn tls_url(&self) -> Option<&str> {
        self.tls_url.as_deref()
    }

    /// The `https://127.0.0.1:PORT` TLS (ALPN `http/1.1` only) origin, if started.
    pub fn tls_h1_url(&self) -> Option<&str> {
        self.tls_h1_url.as_deref()
    }

    /// The `http://127.0.0.1:PORT` control origin (spec D2), if started.
    pub fn control_url(&self) -> Option<&str> {
        self.control_url.as_deref()
    }

    /// The running L4 speakers in [`speakers::driver::all`] order; empty unless
    /// the builder's `l4(true)` was set.
    pub fn l4_services(&self) -> &[RunningService] {
        self._l4.as_ref().map(L4Services::services).unwrap_or(&[])
    }

    /// The seed mode this target serves.
    pub fn mode(&self) -> SeedMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builder_l4_without_control_is_invalid_input() {
        let err = match TestTarget::builder(SeedMode::Vulnerable)
            .l4(true)
            .start()
            .await
        {
            Ok(_) => panic!("l4 without a control origin must be refused"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "l4 needs control");
    }
}
