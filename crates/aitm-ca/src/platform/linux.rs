//! Linux: an anchor file plus a bundle refresh — Debian family
//! (`/usr/local/share/ca-certificates`, `update-ca-certificates`) and Fedora
//! family (`/etc/pki/ca-trust/source/anchors`, `update-ca-trust extract`).
//! Filled in by Task 14.

use crate::cert::CaCert;
use crate::exec::Executor;
use crate::store::{
    Change, LinuxFamily, Platform, Scope, StoreStatus, TrustError, TrustErrorKind, TrustStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxStore(pub LinuxFamily);

static DEBIAN: Platform = Platform::Linux(LinuxFamily::Debian);
static FEDORA: Platform = Platform::Linux(LinuxFamily::Fedora);

fn not_implemented() -> anyhow::Error {
    TrustError::new(TrustErrorKind::UnsupportedPlatform, "not implemented").into()
}

impl TrustStore for LinuxStore {
    fn platform(&self) -> &Platform {
        match self.0 {
            LinuxFamily::Debian => &DEBIAN,
            LinuxFamily::Fedora => &FEDORA,
        }
    }

    fn status(
        &self,
        _cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus> {
        Err(not_implemented())
    }

    fn install(
        &self,
        _cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        Err(not_implemented())
    }

    fn uninstall(
        &self,
        _cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        Err(not_implemented())
    }
}
