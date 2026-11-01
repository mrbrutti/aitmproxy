//! Windows seam (spec §D11): not managed yet. Every host compiles and status
//! is honest. The future implementation writes
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//! (`ProxyEnable`, `ProxyServer`, `ProxyOverride`) and must notify WinINET
//! (`INTERNET_OPTION_SETTINGS_CHANGED`, `INTERNET_OPTION_REFRESH`); neither
//! is designed here.

use aitm_ca::exec::Executor;

use crate::platform::PlatformOps;
use crate::state::Previous;
use crate::{Effective, Endpoint, Mechanism, ReadError, ServiceRow, WriteError};

pub(crate) const NOT_MANAGED: &str = "Windows system proxy is not managed yet";

/// `Mechanism::None`: reads are unavailable, writes fail as unsupported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NoneOps;

impl PlatformOps for NoneOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::None
    }

    fn detail_when_unsupported(&self) -> Option<String> {
        Some(NOT_MANAGED.to_string())
    }

    fn read_effective(&self, _exec: &dyn Executor) -> Result<Effective, ReadError> {
        Err(ReadError::Unavailable(NOT_MANAGED.to_string()))
    }

    fn read_services(&self, _exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        Err(ReadError::Unavailable(NOT_MANAGED.to_string()))
    }

    fn write(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _ours: &Endpoint,
        _bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed("unsupported".to_string()))
    }

    fn restore(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed("unsupported".to_string()))
    }
}
