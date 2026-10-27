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

/// A persisted key that becomes group/other-readable is refused on the next load.
#[cfg(unix)]
#[test]
fn refuses_a_group_readable_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir();
    CertAuthority::load_or_generate(&dir, 0o600).expect("generate root");
    let key_path = dir.join("ca.key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
        .expect("loosen key mode");
    let err = CertAuthority::load_or_generate(&dir, 0o600)
        .err()
        .expect("a group/other-readable CA key must be refused");
    assert!(
        err.to_string().contains("group/other"),
        "error must explain the mode problem, got: {err}"
    );
}

/// A CA key that is a symlink is refused: the loader opens with `O_NOFOLLOW`, so
/// it won't follow a planted link to an arbitrary file.
#[cfg(unix)]
#[test]
fn refuses_a_symlinked_key() {
    let dir = temp_dir();
    CertAuthority::load_or_generate(&dir, 0o600).expect("generate root");
    let key_path = dir.join("ca.key");
    // Move the real key aside and point `ca.key` at it via a symlink.
    let real = dir.join("ca.key.real");
    std::fs::rename(&key_path, &real).expect("rename key");
    std::os::unix::fs::symlink(&real, &key_path).expect("symlink key");
    let err = CertAuthority::load_or_generate(&dir, 0o600)
        .err()
        .expect("a symlinked CA key must be refused");
    assert!(
        err.to_string().contains("open CA key"),
        "error must be an open refusal, got: {err}"
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

/// M2 Task 8: `cert_path()` names `<dir>/ca.crt` whether the root was just
/// generated or reloaded, and reading it leaves the key file untouched.
#[test]
fn cert_path_after_generate_and_reload() {
    let dir = temp_dir();
    let key_path = dir.join("ca.key");

    let generated = CertAuthority::load_or_generate(&dir, 0o600).expect("generate root");
    assert_eq!(generated.cert_path(), dir.join("ca.crt"));
    let key_before = std::fs::read(&key_path).expect("read key");

    let loaded = CertAuthority::load_or_generate(&dir, 0o600).expect("load root");
    assert_eq!(loaded.cert_path(), dir.join("ca.crt"));
    assert_eq!(loaded.cert_path(), generated.cert_path());

    // The accessor never touches the key: same bytes, same mode.
    let key_after = std::fs::read(&key_path).expect("read key again");
    assert_eq!(key_before, key_after, "ca.key bytes changed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ca.key mode was {mode:o}, want 600");
    }
}
