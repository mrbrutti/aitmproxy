//! macOS: `networksetup` per service for snapshots and writes, `scutil --proxy`
//! for the effective view (spec §D3). Task 1 declares the ops struct so
//! `platform::ops_for` compiles; Task 2 fills it.

use aitm_ca::exec::Executor;

use crate::platform::PlatformOps;
use crate::state::Previous;
use crate::{Effective, Endpoint, Mechanism, ReadError, ServiceRow, WriteError};

const NOT_IMPLEMENTED: &str = "macOS mechanism not implemented yet (plan Task 2)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MacosOps;

impl PlatformOps for MacosOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Networksetup
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
