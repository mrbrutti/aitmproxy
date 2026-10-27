//! The certificate as the commands see it: `CaCert`, loaded from the one
//! file the `ca.*` commands may open (`<dir>/ca.crt`), with its DER and
//! SHA-256 / SHA-1 fingerprints.
//!
//! The commands read `ca.crt` themselves rather than going through
//! `CertAuthority`, which would open `ca.key`; this module never names the
//! key and never lists the directory. Fingerprints are computed once here,
//! so `status`, `install`, `uninstall` and the audit log always agree.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use ring::digest;
use x509_parser::pem::Pem;

use crate::exec::Executor;

/// `<dir>/ca.crt` parsed once: the PEM text, its single DER block, and the
/// two digests the platform tools identify it by.
#[derive(Debug, Clone)]
pub struct CaCert {
    /// `<dir>/ca.crt`.
    pub path: PathBuf,
    /// File contents, byte-for-byte.
    pub pem: String,
    /// The single `CERTIFICATE` block, decoded.
    pub der: Vec<u8>,
    /// SHA-256 over `der`.
    pub sha256: [u8; 32],
    /// SHA-1 over `der` (what `security -Z` and `certutil` print).
    pub sha1: [u8; 20],
}

impl CaCert {
    /// Reads only `<dir>/ca.crt`, through the executor (so tests can supply
    /// it and record the path). `Ok(None)` when it does not exist; `Err`
    /// unless the file holds exactly one PEM `CERTIFICATE` block.
    pub fn load(dir: &Path, exec: &dyn Executor) -> anyhow::Result<Option<CaCert>> {
        let path = dir.join("ca.crt");
        let Some(bytes) = exec.read_file(&path)? else {
            return Ok(None);
        };

        let mut first: Option<Vec<u8>> = None;
        let mut count = 0usize;
        for block in Pem::iter_from_buffer(&bytes) {
            let block = block.with_context(|| format!("{} is not valid PEM", path.display()))?;
            if block.label == "CERTIFICATE" {
                count += 1;
                if first.is_none() {
                    first = Some(block.contents);
                }
            }
        }
        let der = match first {
            Some(der) if count == 1 => der,
            _ => bail!(
                "{} must hold exactly one PEM CERTIFICATE block, found {count}",
                path.display()
            ),
        };

        let pem = String::from_utf8(bytes)
            .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
        let sha256 = sha256_of(&der);
        let sha1 = sha1_of(&der);

        Ok(Some(CaCert {
            path,
            pem,
            der,
            sha256,
            sha1,
        }))
    }

    /// `"AB:CD:...:EF"`, 32 pairs, uppercase — the display form browsers
    /// and `openssl x509 -fingerprint` show.
    pub fn fingerprint_sha256(&self) -> String {
        colon_upper(&self.sha256)
    }

    /// Same form as [`Self::fingerprint_sha256`], 20 pairs.
    pub fn fingerprint_sha1(&self) -> String {
        colon_upper(&self.sha1)
    }

    /// Uppercase, no separators — what macOS `security … -Z` wants.
    pub fn sha256_hex(&self) -> String {
        hex_upper(&self.sha256)
    }

    /// Lowercase, no separators — the `certutil` thumbprint form.
    pub fn sha1_hex_lower(&self) -> String {
        hex_upper(&self.sha1).to_lowercase()
    }
}

/// SHA-256 of a DER-encoded certificate.
pub fn sha256_of(der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, der).as_ref());
    out
}

fn sha1_of(der: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref());
    out
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02X}");
    }
    s
}

fn colon_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
