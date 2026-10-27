//! Windows: `certutil [-user] -store|-addstore|-delstore Root`, keyed on the
//! SHA-1 thumbprint. Unit-tested only; not a shipped platform. Filled in by
//! Task 15.

use crate::cert::CaCert;
use crate::exec::Executor;
use crate::store::{Change, Platform, Scope, StoreStatus, TrustError, TrustErrorKind, TrustStore};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsStore;

static PLATFORM: Platform = Platform::Windows;

fn not_implemented() -> anyhow::Error {
    TrustError::new(TrustErrorKind::UnsupportedPlatform, "not implemented").into()
}

impl TrustStore for WindowsStore {
    fn platform(&self) -> &Platform {
        &PLATFORM
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
