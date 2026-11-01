//! The `WsTransport` seam and its TCP/TLS production transport.
//!
//! The seam exists so that `cargo test` stays hermetic: every in-crate test
//! drives the real tungstenite client against a real tungstenite server over a
//! [`tokio::io::duplex`] pair (see [`crate::testing`]), and only the socket is
//! replaced. Production dials a real TCP socket and, for `wss://`, wraps it in
//! TLS here rather than in tokio-tungstenite (whose TLS features are off).

use std::sync::Arc;
use std::time::Duration;

use aitm_core::ByteStream;
use anyhow::{anyhow, Context};
use futures::future::BoxFuture;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::types::TlsPolicy;

/// How the WebSocket dialer reaches a host: the one seam tests replace.
///
/// An implementation returns a connected byte stream; everything above it (the
/// RFC 6455 handshake, frames, close) is the real tungstenite machinery in both
/// production and tests.
pub trait WsTransport: Send + Sync {
    /// Connect to `host:port`, wrapping the socket in TLS when `tls` is set and
    /// presenting `sni` as the server name.
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        tls: bool,
        sni: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<ByteStream>>;
}

/// The production transport: a TCP connect with a timeout, then optional TLS.
pub struct TcpTransport {
    tls: TlsPolicy,
    connect_timeout: Duration,
    client_config: Arc<ClientConfig>,
}

impl TcpTransport {
    /// A transport that treats certificates per `tls` and gives up on a connect
    /// or TLS handshake that takes longer than `connect_timeout`.
    #[must_use]
    pub fn new(tls: TlsPolicy, connect_timeout: Duration) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        // A static capability assertion, not a network or user-input path: the
        // `ring` provider compiled in here has both TLS 1.2 (the `tls12`
        // feature) and TLS 1.3, so this step cannot fail. rustls' own
        // `ClientConfig::builder()` unwraps the very same call.
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the ring provider supports TLS 1.2 and TLS 1.3");
        let mut config = match tls {
            TlsPolicy::Verify => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            }
            TlsPolicy::AcceptAny => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier { provider }))
                .with_no_client_auth(),
        };
        // No ALPN at all: a WebSocket is an HTTP/1.1 upgrade, and offering
        // `h2` would let a server negotiate a protocol the dialer cannot speak.
        config.alpn_protocols.clear();
        Self {
            tls,
            connect_timeout,
            client_config: Arc::new(config),
        }
    }

    /// The certificate policy this transport was built with.
    #[must_use]
    pub fn tls_policy(&self) -> TlsPolicy {
        self.tls
    }

    /// The rustls client config this transport dials with.
    ///
    /// Exposed so a test can drive the very same verifier over a duplex pair
    /// without binding a port.
    #[must_use]
    pub fn client_config(&self) -> Arc<ClientConfig> {
        self.client_config.clone()
    }
}

impl WsTransport for TcpTransport {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        tls: bool,
        sni: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
        Box::pin(async move {
            let limit = self.connect_timeout;
            tracing::debug!(host, port, tls, "ws transport connect");
            let tcp = tokio::time::timeout(limit, TcpStream::connect((host, port)))
                .await
                .map_err(|_| anyhow!("tcp connect to {host}:{port} timed out after {limit:?}"))?
                .with_context(|| format!("tcp connect to {host}:{port}"))?;
            tcp.set_nodelay(true)
                .with_context(|| format!("set nodelay on {host}:{port}"))?;
            if !tls {
                return Ok(Box::pin(tcp) as ByteStream);
            }
            // An IP-literal SNI is accepted by rustls as `ServerName::IpAddress`,
            // so a lab target dialled by address still completes a handshake.
            let name = ServerName::try_from(sni.to_owned())
                .with_context(|| format!("invalid TLS server name: {sni}"))?;
            let connector = TlsConnector::from(self.client_config.clone());
            let stream = tokio::time::timeout(limit, connector.connect(name, tcp))
                .await
                .map_err(|_| anyhow!("tls handshake with {host}:{port} timed out after {limit:?}"))?
                .with_context(|| format!("tls handshake with {host}:{port}"))?;
            Ok(Box::pin(stream) as ByteStream)
        })
    }
}

/// Accepts whatever certificate the server presents.
///
/// **Security review: AcceptAny.** This verifier is the whole of
/// [`TlsPolicy::AcceptAny`], which is what both the lane and the `ws.*`
/// language dial with (T4 plan call 3). It is a deliberate scanner posture, not
/// an oversight: the dialer only ever reaches an authority the operator put in
/// Scope — every dial is gated by `ScopeRateGuard::check_active` before a socket
/// is opened — and an authorized-testing target routinely presents a
/// self-signed or internal certificate that a root store cannot chain. The
/// proxy's own replay path (`aitm_proto_http::Http1Sender`'s `insecure` mode)
/// has had the same posture since M1. Nothing here weakens a *captured*
/// client's TLS: this config is used only for connections the scanner itself
/// originates. [`TlsPolicy::Verify`] builds a webpki-rooted config instead and
/// is what a caller picks when chain validation is the point.
#[derive(Debug)]
struct AcceptAnyVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::TcpTransport;
    use crate::types::TlsPolicy;

    /// A server config holding a fresh self-signed certificate for `localhost`.
    fn self_signed_server() -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().expect("fixture key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("fixture params")
            .self_signed(&key)
            .expect("fixture cert");
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("fixture versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("fixture server config");
        Arc::new(cfg)
    }

    #[tokio::test]
    async fn accept_any_verifier_accepts_self_signed_over_duplex() {
        let (client, server) = duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(self_signed_server());
        let serving = tokio::spawn(async move {
            let mut tls = acceptor.accept(server).await.expect("server handshake");
            tls.write_all(b"hello").await.expect("server write");
            tls.flush().await.expect("server flush");
        });

        let transport = TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(2));
        let connector = TlsConnector::from(transport.client_config());
        let name = ServerName::try_from("localhost".to_owned()).expect("server name");
        let mut tls = connector
            .connect(name, client)
            .await
            .expect("accept-any client handshake");

        let mut got = [0u8; 5];
        tls.read_exact(&mut got).await.expect("client read");
        assert_eq!(&got, b"hello");
        serving.await.expect("server task");
    }

    #[tokio::test]
    async fn verify_policy_rejects_self_signed_over_duplex() {
        let (client, server) = duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(self_signed_server());
        let serving = tokio::spawn(async move {
            let _ = acceptor.accept(server).await;
        });

        let transport = TcpTransport::new(TlsPolicy::Verify, Duration::from_secs(2));
        let connector = TlsConnector::from(transport.client_config());
        let name = ServerName::try_from("localhost".to_owned()).expect("server name");
        let err = connector
            .connect(name, client)
            .await
            .expect_err("verify must reject a self-signed certificate");

        let text = err.to_string();
        assert!(
            text.contains("certificate"),
            "expected a certificate error, got: {text}"
        );
        let _ = serving.await;
    }
}
