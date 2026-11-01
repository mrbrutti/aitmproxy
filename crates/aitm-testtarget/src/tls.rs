//! The TLS listeners (spec D1 TLS row): one self-signed `rcgen` certificate per
//! process for `localhost` + `127.0.0.1` (the builder mints one [`Identity`]
//! and lends it to both listeners), one rustls `ServerConfig` per ALPN list
//! built with the `ring` provider via `builder_with_provider` (no global
//! provider install), and the accept loop that negotiates ALPN, writes a
//! `tls_handshake` entry (D2) and hands the stream to `serve_h2` (`h2`) or
//! `serve_h1` (`http/1.1` or none). The `tls` listener offers `[h2, http/1.1]`,
//! the `tls_h1` listener `[http/1.1]` only, so the HTTP/2 sender and its version
//! override can be proven against a target that behaves either way.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::app::{self, AppState};
use crate::listeners::accept_loop;
use crate::log::{Listener, ServiceInfo};

/// ALPN list offered by the `tls` listener: HTTP/2 preferred, HTTP/1.1 fallback.
pub(crate) const ALPN_H2_H1: &[&[u8]] = &[b"h2", b"http/1.1"];
/// ALPN list offered by the `tls_h1` listener: HTTP/1.1 only.
pub(crate) const ALPN_H1: &[&[u8]] = &[b"http/1.1"];

/// The one self-signed serving identity of a target: the certificate for
/// `localhost` + `127.0.0.1` and its PKCS#8 private key. Minted once by the
/// builder and lent to every TLS listener (spec D1: one certificate per
/// process); never written to disk.
pub(crate) struct Identity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    /// The certificate's DER bytes (what a client sees as the leaf).
    #[cfg(test)]
    pub(crate) fn cert_der(&self) -> &[u8] {
        self.cert.as_ref()
    }
}

/// Mint a fresh self-signed [`Identity`].
pub(crate) fn self_signed() -> io::Result<Identity> {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .map_err(|e| io::Error::other(format!("self-signed certificate: {e}")))?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    Ok(Identity { cert, key })
}

/// A rustls server config over `identity`, built with the `ring` provider
/// explicitly (no process-global provider install) and offering exactly
/// `alpn`, in order. The identity is borrowed so both listeners share it.
pub(crate) fn server_config(alpn: &[&[u8]], identity: &Identity) -> io::Result<Arc<ServerConfig>> {
    let mut cfg =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(format!("tls protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())
            .map_err(|e| io::Error::other(format!("tls serving identity: {e}")))?;
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// What a TLS listener kind advertises: its `/services` name, the ALPN list it
/// offers and the same list as `/services` strings.
struct TlsKind {
    name: &'static str,
    alpn: &'static [&'static [u8]],
    alpn_names: Vec<&'static str>,
}

/// The advertisement for `kind`; `None` for the plain listener, which has no TLS.
fn listener_alpn(kind: Listener) -> Option<TlsKind> {
    match kind {
        Listener::Tls => Some(TlsKind {
            name: "tls",
            alpn: ALPN_H2_H1,
            alpn_names: vec!["h2", "http/1.1"],
        }),
        Listener::TlsH1 => Some(TlsKind {
            name: "tls_h1",
            alpn: ALPN_H1,
            alpn_names: vec!["http/1.1"],
        }),
        Listener::Plain => None,
    }
}

/// Bind loopback `port` (0 = ephemeral) as TLS listener `kind` serving
/// `identity`, register it on `/services`, and spawn its accept loop. Returns
/// the bound address once the listener is accepting. Every accepted
/// connection is handshaken, logged as a `tls_handshake` entry and served as
/// HTTP/2 or HTTP/1 per the negotiated ALPN; a failed handshake logs
/// `alpn: "none"` and opens no connection row. `Listener::Plain` is rejected
/// with `InvalidInput`.
pub(crate) async fn bind(
    kind: Listener,
    port: u16,
    state: Arc<AppState>,
    identity: &Identity,
) -> io::Result<SocketAddr> {
    let Some(TlsKind {
        name,
        alpn,
        alpn_names,
    }) = listener_alpn(kind)
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls::bind needs Listener::Tls or Listener::TlsH1",
        ));
    };
    let config = server_config(alpn, identity)
        .map_err(|e| io::Error::other(format!("tls server config for {name}: {e}")))?;
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    state.log.register_service(ServiceInfo {
        name: name.to_string(),
        proto: "tcp",
        addr,
        role: "http",
        alpn: Some(alpn_names),
        grammar: None,
    });

    tokio::spawn(accept_loop(listener, move |stream, peer| {
        let acceptor = acceptor.clone();
        let state = state.clone();
        async move { serve_tls(kind, acceptor, stream, peer, state).await }
    }));
    Ok(addr)
}

/// Drive one accepted TLS connection: handshake, log, dispatch, close.
async fn serve_tls(
    kind: Listener,
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
) {
    let tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(_) => {
            state.log.log_tls_handshake_failed(kind);
            return;
        }
    };
    let negotiated: Option<Vec<u8>> = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let alpn_str = negotiated
        .as_deref()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let conn = state.log.open_conn(kind, alpn_str.as_deref(), peer);
    state.log.log_tls_handshake(&conn);
    if negotiated.as_deref() == Some(&b"h2"[..]) {
        app::serve_h2(tls, state.clone(), conn.clone()).await;
    } else {
        app::serve_h1(tls, state.clone(), conn.clone()).await;
    }
    state.log.close_conn(&conn);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_lists() {
        let identity = self_signed().expect("self-signed identity");
        let h2_h1 = server_config(ALPN_H2_H1, &identity).expect("h2+h1 config");
        assert_eq!(
            h2_h1.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let h1 = server_config(ALPN_H1, &identity).expect("h1 config");
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn one_identity_serves_both_alpn_lists() {
        // Every `self_signed` call mints a different certificate, so the two
        // TLS listeners must be built from one borrowed identity (spec D1:
        // one self-signed certificate per process). The socket proof that
        // both listeners present the same DER is `tls_listener_negotiates_h2_and_h1`.
        let a = self_signed().expect("identity a");
        let b = self_signed().expect("identity b");
        assert_ne!(a.cert_der(), b.cert_der(), "fresh identities differ");
        let h2_h1 = server_config(ALPN_H2_H1, &a).expect("h2+h1 config from a");
        let h1 = server_config(ALPN_H1, &a).expect("h1 config from the same a");
        assert_ne!(h2_h1.alpn_protocols, h1.alpn_protocols);
        // The identity is still usable afterwards (borrowed, not consumed).
        assert_eq!(a.cert_der().len(), a.cert_der().len());
    }

    #[test]
    fn self_signed_has_both_sans() {
        let identity = self_signed().expect("self-signed cert");
        let (cert, key) = (identity.cert.clone(), identity.key.clone_key());
        // `x509-parser` is not a dependency of this crate (the plan's fallback):
        // pin what rcgen hands us instead. A DER SubjectAltName extension
        // carries each dNSName as `82 <len> <bytes>` and each iPAddress as
        // `87 04 <4 bytes>`, so both SANs are checkable as byte patterns.
        let der = cert.as_ref();
        assert!(!der.is_empty(), "certificate DER is empty");
        let dns_localhost = [&[0x82u8, 9][..], b"localhost"].concat();
        assert!(
            der.windows(dns_localhost.len()).any(|w| w == dns_localhost),
            "SAN dNSName=localhost missing from the certificate DER"
        );
        let ip_loopback = [0x87u8, 4, 127, 0, 0, 1];
        assert!(
            der.windows(ip_loopback.len()).any(|w| w == ip_loopback),
            "SAN iPAddress=127.0.0.1 missing from the certificate DER"
        );
        assert!(
            matches!(key, PrivateKeyDer::Pkcs8(_)),
            "private key must be PKCS#8"
        );
        // And the pair is accepted by rustls as a serving identity.
        server_config(ALPN_H1, &identity).expect("server config builds from the pair");
    }
}
