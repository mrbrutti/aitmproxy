//! Certificate authority: a persisted root (key file `0600`) that mints leaf
//! certificates impersonating upstream hosts, cached per host in moka so a
//! repeat host is a cache hit rather than a second mint (AC3).

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use moka::sync::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// File names under the CA directory.
const KEY_FILE: &str = "ca.key";
const CERT_FILE: &str = "ca.crt";
/// Distinct hosts kept in the leaf cache before eviction.
const LEAF_CACHE_CAPACITY: u64 = 1024;

/// A minted leaf: DER certificate plus its PKCS#8 DER private key.
pub struct LeafCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// The proxy's root CA and its leaf cache.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    root_pem: String,
    leaves: Cache<String, Arc<LeafCert>>,
    last_hit: AtomicBool,
}

impl CertAuthority {
    /// Load the persisted root CA from `dir`, or generate one on first run,
    /// writing the key with file mode `key_mode` (`0o600` per config).
    pub fn load_or_generate(dir: &Path, key_mode: u32) -> Result<Self> {
        let key_path = dir.join(KEY_FILE);
        let cert_path = dir.join(CERT_FILE);

        let (issuer, root_pem) = if key_path.exists() && cert_path.exists() {
            // Open the key without following a symlink, then check the *opened
            // handle's* mode and read from it — no stat/read TOCTOU, and a
            // symlinked key fails to open. The key is a secret: refuse one readable
            // by group/other (an exposure / plantability risk).
            let mut key_file = open_key_nofollow(&key_path)?;
            check_key_handle(&key_file, &key_path)?;
            let mut key_pem = String::new();
            std::io::Read::read_to_string(&mut key_file, &mut key_pem)
                .with_context(|| format!("read CA key {}", key_path.display()))?;
            let cert_pem = fs::read_to_string(&cert_path)
                .with_context(|| format!("read CA cert {}", cert_path.display()))?;
            let key = KeyPair::from_pem(&key_pem).context("parse persisted CA key")?;
            let issuer =
                Issuer::from_ca_cert_pem(&cert_pem, key).context("parse persisted CA cert")?;
            (issuer, cert_pem)
        } else {
            create_ca_dir(dir)?;
            let key = KeyPair::generate().context("generate CA key")?;
            let params = root_params();
            let cert = params.self_signed(&key).context("self-sign CA cert")?;
            let cert_pem = cert.pem();
            write_private(&key_path, key.serialize_pem().as_bytes(), key_mode)?;
            fs::write(&cert_path, cert_pem.as_bytes())
                .with_context(|| format!("write CA cert {}", cert_path.display()))?;
            (Issuer::new(params, key), cert_pem)
        };

        Ok(Self {
            issuer,
            root_pem,
            leaves: Cache::new(LEAF_CACHE_CAPACITY),
            last_hit: AtomicBool::new(false),
        })
    }

    /// PEM of the root certificate, for the "install & trust the CA" flow.
    pub fn root_cert_pem(&self) -> &str {
        &self.root_pem
    }

    /// Cache hit, or mint and sign a leaf for `host` carrying the sniffed `sans`.
    pub fn leaf_for(&self, host: &str, sans: &[String]) -> Result<Arc<LeafCert>> {
        if let Some(leaf) = self.leaves.get(host) {
            self.last_hit.store(true, Ordering::SeqCst);
            return Ok(leaf);
        }
        self.last_hit.store(false, Ordering::SeqCst);

        // The host always appears first (it becomes the CN); sniffed SANs follow.
        let mut names = vec![host.to_string()];
        names.extend(sans.iter().filter(|s| *s != host).cloned());

        let mut params = CertificateParams::new(names).context("leaf SANs")?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params, LEAF_VALIDITY_DAYS);

        let key = KeyPair::generate().context("generate leaf key")?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .with_context(|| format!("sign leaf for {host}"))?;

        let leaf = Arc::new(LeafCert {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        });
        self.leaves.insert(host.to_string(), leaf.clone());
        Ok(leaf)
    }

    /// Whether the last `leaf_for` was served from the cache.
    pub fn last_was_cache_hit(&self) -> bool {
        self.last_hit.load(Ordering::SeqCst)
    }
}

/// Root validity: ~10 years. Leaves: ≤397 days (under the CA/Browser Forum's
/// 398-day cap, so a leaf a browser might see is not rejected for lifetime).
const ROOT_VALIDITY_DAYS: i64 = 3650;
const LEAF_VALIDITY_DAYS: i64 = 397;

/// Parameters of the self-signed root, with an explicit ~10-year validity.
fn root_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "aitmproxy root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "aitmproxy");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut params, ROOT_VALIDITY_DAYS);
    params
}

/// Set an explicit validity window (a short backdate absorbs clock skew).
fn set_validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(days);
}

/// Open the CA key read-only without following a symlink at the final component
/// (`O_NOFOLLOW`), so a symlinked key fails to open and the caller can stat/read
/// the returned handle with no TOCTOU window.
#[cfg(unix)]
fn open_key_nofollow(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open CA key {}", path.display()))
}

#[cfg(not(unix))]
fn open_key_nofollow(path: &Path) -> Result<fs::File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        anyhow::bail!("refusing to open symlinked CA key {}", path.display());
    }
    fs::File::open(path).with_context(|| format!("open CA key {}", path.display()))
}

/// Refuse a CA key readable by group or other, checking the *opened handle*
/// (fstat), so it describes the file we actually hold open.
#[cfg(unix)]
fn check_key_handle(file: &fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .with_context(|| format!("stat CA key {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "CA key {} is accessible to group/other (mode {:o}); refusing to load it. \
             Restrict it with `chmod 600`.",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_handle(_file: &fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Create the CA directory owner-only (`0700` on Unix), including parents, so the
/// key is never briefly world-readable in a default-mode directory.
fn create_ca_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("create CA dir {}", dir.display()))
}

/// Write the freshly generated key to a brand-new file (`create_new`, so it never
/// follows a planted symlink or clobbers an existing key) created with mode `mode`.
fn write_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .with_context(|| format!("create CA key {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write CA key {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let _ = mode;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create CA key {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write CA key {}", path.display()))?;
    }
    Ok(())
}
