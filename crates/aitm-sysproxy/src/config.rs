//! The `system_proxy:` config section (spec §D7). It lives outside
//! `aitm_core::Config` and is parsed by `crates/aitm/src/config_file.rs`
//! exactly like `macos_capture`.

use std::path::{Path, PathBuf};

use crate::STATE_FILE_NAME;

/// ```yaml
/// system_proxy:
///   auto: false      # set at startup, restore at exit
///   bypass: []       # operator's extra bypass hosts, merged per §D5
///   state_file: ~    # default: <dir of ca.audit_log>/system-proxy-state.json
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SystemProxyConfig {
    pub auto: bool,
    pub bypass: Vec<String>,
    pub state_file: Option<PathBuf>,
}

impl SystemProxyConfig {
    /// The default state-file path: the sibling of the CA audit log, so it
    /// follows the same directory rule and fallbacks.
    pub fn default_state_file(ca_audit_log: &Path) -> PathBuf {
        ca_audit_log.with_file_name(STATE_FILE_NAME)
    }
}
