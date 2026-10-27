//! AC3: the certificate authority persists a root with a 0600 key, mints a leaf
//! for a host on first sight, and serves the second request from the moka cache.

use std::path::PathBuf;

use aitm_proto_http::CertAuthority;

/// A fresh, unique directory under the system temp dir.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn mint_then_cache_hit() {
    let dir = temp_dir();
    let ca = CertAuthority::load_or_generate(&dir, 0o600).expect("generate root");

    // The root key is persisted with the requested mode.
    let key_path = dir.join("ca.key");
    assert!(key_path.exists(), "root key not persisted at {key_path:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "root key mode was {mode:o}, want 600");
    }

    assert!(
        ca.root_cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        "root PEM did not start with a certificate header: {:?}",
        &ca.root_cert_pem()[..40.min(ca.root_cert_pem().len())]
    );

    let first = ca
        .leaf_for("ex.test", &["ex.test".to_string()])
        .expect("mint leaf");
    assert!(!ca.last_was_cache_hit(), "first mint must miss the cache");
    assert!(!first.cert_der.is_empty());
    assert!(!first.key_der.is_empty());

    let second = ca
        .leaf_for("ex.test", &["ex.test".to_string()])
        .expect("cached leaf");
    assert!(
        ca.last_was_cache_hit(),
        "second leaf_for must hit the cache"
    );
    assert_eq!(
        first.cert_der, second.cert_der,
        "cache returned a different leaf"
    );
}

#[test]
fn load_reuses_persisted_root() {
    let dir = temp_dir();
    let generated = CertAuthority::load_or_generate(&dir, 0o600).expect("generate root");
    let loaded = CertAuthority::load_or_generate(&dir, 0o600).expect("load root");
    assert_eq!(
        generated.root_cert_pem(),
        loaded.root_cert_pem(),
        "second load_or_generate must reuse the persisted root, not mint a new one"
    );
}
