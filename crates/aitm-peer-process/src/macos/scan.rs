//! The macOS [`SocketScanner`]: libproc scan via `ffi::find_owners_raw`, warm
//! probe via `ffi::find_owners_among_raw`, identity via `proc_pidpath` →
//! [`identity_for_path`], else `proc_name` (spec D4, D5).

use std::collections::HashMap;
use std::time::Instant;

use crate::macos::ffi;
use crate::macos::identity::identity_for_path;
use crate::types::{Probe, ProcessKey, SocketScanner, Tuple};

/// The production scanner on macOS. `skip_pid` is never reported as an owner
/// (production: our own pid, whose accepted sockets mirror every wanted tuple).
pub(crate) struct MacScanner {
    pub(crate) skip_pid: Option<u32>,
}

impl SocketScanner for MacScanner {
    fn find_owners(&self, wanted: &[Tuple], deadline: Instant) -> HashMap<Tuple, ProcessKey> {
        ffi::find_owners_raw(wanted, deadline, self.skip_pid)
    }

    fn find_owners_among(&self, wanted: &[Tuple], deadline: Instant, pids: &[u32]) -> Probe {
        ffi::find_owners_among_raw(wanted, deadline, self.skip_pid, pids)
    }

    fn identity(&self, key: ProcessKey) -> Option<String> {
        ffi::pid_path(key.pid)
            .and_then(|p| identity_for_path(&p))
            .or_else(|| ffi::pid_name(key.pid))
    }
}

#[cfg(test)]
mod tests {
    use super::MacScanner;
    use crate::types::{ProcessKey, SocketScanner};

    /// D5 step 3 on our own pid: the test binary is a bare executable, so its
    /// identity is its basename (sandbox-runnable: libproc reads on own pid).
    #[test]
    fn identity_of_own_pid_is_the_test_binary_basename() {
        let scanner = MacScanner { skip_pid: None };
        let key = ProcessKey {
            pid: std::process::id(),
            start: 0,
        };
        let identity = scanner.identity(key).expect("own identity");
        assert!(
            identity.starts_with("aitm_peer_process"),
            "identity = {identity}"
        );
        assert!(!identity.contains('/'), "identity = {identity}");
    }

    /// A pid that cannot exist has no identity, not a panic.
    #[test]
    fn identity_of_impossible_pid_is_none() {
        let scanner = MacScanner { skip_pid: None };
        assert_eq!(
            scanner.identity(ProcessKey {
                pid: i32::MAX as u32,
                start: 0
            }),
            None
        );
    }
}
