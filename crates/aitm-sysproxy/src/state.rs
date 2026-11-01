//! The state file: what we wrote and what was there before, so a crash or a
//! later process can restore it (spec §D7). `StateFile` itself is Task 4;
//! `Previous` is declared here so the platform trait can name it.

use std::collections::BTreeMap;

use crate::ServiceRow;

/// The snapshot taken before the first mutating command, per mechanism.
/// Linux values are the raw `gsettings get` / `kreadconfig` text, restored
/// verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Previous {
    Networksetup {
        services: Vec<ServiceRow>,
    },
    Gsettings {
        keys: BTreeMap<String, String>,
    },
    Kde {
        kioslaverc: BTreeMap<String, String>,
        gsettings: Option<BTreeMap<String, String>>,
    },
}
