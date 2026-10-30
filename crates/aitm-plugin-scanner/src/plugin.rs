//! The scanner plugin itself.

use crate::config::ScannerConfig;
use aitm_core::{Plugin, Registry};

/// The scanner plugin. It holds its config and registers the `scan.*` command
/// set.
///
/// The scanner observes no events — it drives traffic itself from commands — so
/// it takes the default `Plugin::on_event`.
pub struct ScannerPlugin {
    cfg: ScannerConfig,
}

impl ScannerPlugin {
    /// Build the plugin with the given budgets and gates.
    pub fn new(cfg: ScannerConfig) -> Self {
        Self { cfg }
    }
}

impl Plugin for ScannerPlugin {
    fn name(&self) -> &str {
        "scanner"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(std::sync::Arc::new(crate::commands::ScanDiscover {
            cfg: self.cfg.clone(),
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScannerConfig;
    use aitm_core::Plugin;

    #[test]
    fn plugin_name_is_scanner() {
        let plugin = ScannerPlugin::new(ScannerConfig::default());
        assert_eq!(plugin.name(), "scanner");
    }
}
