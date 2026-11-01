//! Linux: `gsettings` (GNOME) and `kwriteconfig6|5` + `dbus-send` (KDE)
//! (spec §D4). Task 1 declares the two ops structs so `platform::ops_for`
//! compiles; Task 3 fills them.

use aitm_ca::exec::Executor;

use crate::platform::PlatformOps;
use crate::state::Previous;
use crate::{Effective, Endpoint, Mechanism, ReadError, ServiceRow, WriteError};

const NOT_IMPLEMENTED: &str = "Linux mechanism not implemented yet (plan Task 3)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GsettingsOps;

impl PlatformOps for GsettingsOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Gsettings
    }

    fn detail_when_unsupported(&self) -> Option<String> {
        None
    }

    fn read_effective(&self, _exec: &dyn Executor) -> Result<Effective, ReadError> {
        Err(ReadError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn read_services(&self, _exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        Err(ReadError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn write(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _ours: &Endpoint,
        _bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn restore(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed(NOT_IMPLEMENTED.to_string()))
    }
}

/// `kwrite`/`kread` are `kwriteconfig6`/`kreadconfig6` or the 5 variants;
/// `gsettings_too` mirrors the writes into gsettings for GTK apps (§D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdeOps {
    pub kwrite: &'static str,
    pub kread: &'static str,
    pub gsettings_too: bool,
}

impl PlatformOps for KdeOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Kde
    }

    fn detail_when_unsupported(&self) -> Option<String> {
        None
    }

    fn read_effective(&self, _exec: &dyn Executor) -> Result<Effective, ReadError> {
        Err(ReadError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn read_services(&self, _exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        Err(ReadError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn write(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _ours: &Endpoint,
        _bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed(NOT_IMPLEMENTED.to_string()))
    }

    fn restore(
        &self,
        _exec: &dyn Executor,
        _previous: &Previous,
        _only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        Err(WriteError::Failed(NOT_IMPLEMENTED.to_string()))
    }
}
