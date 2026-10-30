//! The scanner plugin itself.

use crate::config::ScannerConfig;
use aitm_core::{Plugin, Registry};

/// The scanner plugin. Stage 1: it holds its config and registers nothing.
///
/// The scanner observes no events — it drives traffic itself from commands
/// registered in later stages — so it takes the default `Plugin::on_event`.
pub struct ScannerPlugin {
    #[allow(dead_code)] // read by the scan commands added in later tasks
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

    fn load(&mut self, _reg: &mut Registry) {
        // No commands yet; the scan command set lands in a later task.
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
