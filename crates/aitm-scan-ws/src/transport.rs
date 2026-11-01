//! The `WsTransport` seam and its TCP/TLS production transport.
//!
//! The seam exists so that `cargo test` stays hermetic: every in-crate test
//! drives the real tungstenite client against a real tungstenite server over a
//! [`tokio::io::duplex`] pair (see [`crate::testing`]), and only the socket is
//! replaced. Production dials a real TCP socket and, for `wss://`, wraps it in
//! TLS here rather than in tokio-tungstenite (whose TLS features are off).
//!
//! The transport connects to an **address**, never a name: the dialer resolves
//! the authority and runs `aitm_core::ssrf_check` on every candidate before it
//! hands one here (security finding S3), the same resolve-then-check-then-
//! connect order `aitm-proto-http`'s sender uses, so the resolve/connect
//! (DNS-rebinding) window is closed.

use std::net::SocketAddr;
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
    /// Connect to `addr`, wrapping the socket in TLS when `tls` is set and
    /// presenting `sni` as the server name.
    ///
    /// `addr` has already passed the dialer's scope and SSRF checks; an
    /// implementation connects to exactly it and resolves nothing.
    fn connect<'a>(
        &'a self,
        addr: SocketAddr,
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
    ///
    /// Crate-internal: the policy is chosen by `lane::build_with` /
    /// `language::build_with` and read back only for the connect log, so a live
    /// run's trace says whether that dial verified the chain.
    #[must_use]
    pub(crate) fn tls_policy(&self) -> TlsPolicy {
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
        addr: SocketAddr,
        tls: bool,
        sni: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<ByteStream>> {
        Box::pin(async move {
            let limit = self.connect_timeout;
            tracing::debug!(%addr, tls, policy = ?self.tls_policy(), "ws transport connect");
            let tcp = tokio::time::timeout(limit, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow!("tcp connect to {addr} timed out after {limit:?}"))?
                .with_context(|| format!("tcp connect to {addr}"))?;
            tcp.set_nodelay(true)
                .with_context(|| format!("set nodelay on {addr}"))?;
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
                .map_err(|_| anyhow!("tls handshake with {addr} timed out after {limit:?}"))?
                .with_context(|| format!("tls handshake with {addr}"))?;
            Ok(Box::pin(stream) as ByteStream)
        })
    }
}

/// Skips certificate *chain* validation; still verifies the handshake signature.
///
/// **Security review: AcceptAny.** This verifier is the whole of
/// [`TlsPolicy::AcceptAny`]. It is **not** the default: [`crate::lane::build`]
/// and [`crate::language::build`] dial with [`TlsPolicy::Verify`] (the webpki
/// root store), the same posture `aitm-proto-http`'s `Http1Sender` has by
/// default, and `AcceptAny` is for the operator's `ssl_insecure` setting
/// (`Config.ssl_insecure`, the one switch that relaxes upstream verification
/// product-wide) via [`crate::lane::build_with`] / [`crate::language::build_with`].
///
/// What it relaxes is exactly what `aitm_proto_http::module::AcceptAnyServerCert`
/// relaxes: the chain is not checked against any root, so a self-signed or
/// internal lab certificate completes the handshake. What it keeps: the TLS 1.2
/// and 1.3 handshake signatures are verified against the presented
/// certificate's public key with the provider's algorithms, so the peer must at
/// least hold the key for the certificate it shows. Nothing here weakens a
/// *captured* client's TLS: this config is used only for connections the
/// scanner itself originates, every one of which passed the scope guard and the
/// SSRF check first.
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
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
    use rustls::sign::{CertifiedKey, SingleCertAndKey};
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
    /// A server config presenting a self-signed certificate for `localhost`
    /// but signing the handshake with a *different* key: the chain is whatever
    /// it is, the CertificateVerify signature cannot check out against the
    /// presented public key.
    fn mismatched_key_server() -> Arc<rustls::ServerConfig> {
        let cert_key = rcgen::KeyPair::generate().expect("fixture cert key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("fixture params")
            .self_signed(&cert_key)
            .expect("fixture cert");
        let other_key = rcgen::KeyPair::generate().expect("fixture signing key");
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(other_key.serialize_der()),
        ))
        .expect("fixture signing key type");
        // `with_single_cert` refuses a key that does not match the certificate,
        // which is exactly the mismatch under test; `CertifiedKey::new` does
        // not check.
        let certified = CertifiedKey::new(vec![cert.der().clone()], signing_key);
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("fixture versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        Arc::new(cfg)
    }

    #[tokio::test]
    async fn accept_any_still_verifies_the_handshake_signature() {
        // Security finding S2: `AcceptAny` leaves the *chain* unchecked, but
        // the handshake signature must still be verified against the presented
        // certificate's public key, the way `aitm_proto_http`'s
        // `AcceptAnyServerCert` does. A server that signs with a key other than
        // the one in its certificate must fail the handshake.
        let (client, server) = duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(mismatched_key_server());
        let serving = tokio::spawn(async move {
            let _ = acceptor.accept(server).await;
        });

        let transport = TcpTransport::new(TlsPolicy::AcceptAny, Duration::from_secs(2));
        let connector = TlsConnector::from(transport.client_config());
        let name = ServerName::try_from("localhost".to_owned()).expect("server name");
        let err = connector
            .connect(name, client)
            .await
            .expect_err("accept-any must still reject a bad handshake signature");

        let text = err.to_string();
        assert!(
            text.to_lowercase().contains("signature"),
            "expected a signature error, got: {text}"
        );
        let _ = serving.await;
    }
}
