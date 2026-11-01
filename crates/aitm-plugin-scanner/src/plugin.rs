//! The scanner plugin itself.

use std::sync::Arc;

use crate::config::ScannerConfig;
use aitm_core::{Plugin, Registry};
use aitm_scan_model::{Check, Lane};

/// The scanner plugin. It holds its config and registers the `scan.*` command
/// set.
///
/// The scanner observes no events — it drives traffic itself from commands — so
/// it takes the default `Plugin::on_event`.
///
/// It also carries the scanner v2 registration slots the binary collected: the
/// lanes each lane crate's `lane()` handed back and the native checks from
/// `aitm_scan_checks_http::checks()` (spec D1, "Registration without shared
/// files"). The shipped [`Plugin::load`] **ignores** both — the v2 engine that
/// consumes them lands with track T1b — so holding them changes no behaviour
/// today; the wiring exists up front so no lane track has to edit
/// `crates/aitm/src/wire.rs`.
pub struct ScannerPlugin {
    cfg: ScannerConfig,
    lanes: Vec<Arc<dyn Lane>>,
    native_checks: Vec<Arc<dyn Check>>,
}

impl ScannerPlugin {
    /// Build the plugin with the given budgets and gates, and no lane or check
    /// slots filled.
    pub fn new(cfg: ScannerConfig) -> Self {
        Self {
            cfg,
            lanes: Vec::new(),
            native_checks: Vec::new(),
        }
    }

    /// Hand the plugin the lanes the binary collected, replacing any already set.
    #[must_use]
    pub fn with_lanes(mut self, lanes: Vec<Arc<dyn Lane>>) -> Self {
        self.lanes = lanes;
        self
    }

    /// Hand the plugin the native checks the binary collected, replacing any
    /// already set.
    #[must_use]
    pub fn with_native_checks(mut self, checks: Vec<Arc<dyn Check>>) -> Self {
        self.native_checks = checks;
        self
    }

    /// The lanes this plugin was handed. Empty until a lane track lands.
    pub fn lanes(&self) -> &[Arc<dyn Lane>] {
        &self.lanes
    }

    /// The native checks this plugin was handed. Empty until track T3 lands.
    pub fn native_checks(&self) -> &[Arc<dyn Check>] {
        &self.native_checks
    }
}

impl Plugin for ScannerPlugin {
    fn name(&self) -> &str {
        "scanner"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(std::sync::Arc::new(crate::commands::ScanDiscover::new(
            self.cfg.clone(),
        )));
        reg.add_command(std::sync::Arc::new(crate::commands::ScanPassive));
        reg.add_command(std::sync::Arc::new(crate::commands::ScanReport));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScannerConfig;
    use aitm_core::{Plugin, Sensitivity};
    use aitm_scan_model::check::{CheckMeta, Evidence, Verdict};
    use aitm_scan_model::point::InsertionPoint;
    use aitm_scan_model::profile::ProfileTarget;
    use aitm_scan_model::traits::{Discovery, JobCtx, ProbeHost};
    use aitm_scan_model::vocab::{
        CheckCost, CheckOrigin, Confidence, InsertionKind, Intensity, LaneKind, Outcome, Technique,
    };
    use futures::future::BoxFuture;

    /// A lane that does nothing. The test only proves the handle survives the
    /// setter, so every method is a stub.
    struct TestLane;

    impl Lane for TestLane {
        fn lane(&self) -> LaneKind {
            LaneKind::Http
        }

        fn discover<'a>(
            &'a self,
            _target: &'a ProfileTarget,
            _job: &'a dyn JobCtx,
        ) -> BoxFuture<'a, anyhow::Result<Discovery>> {
            Box::pin(async { Ok(Discovery::default()) })
        }

        fn probe_host_for(
            &self,
            _point: &InsertionPoint,
            _job: Arc<dyn JobCtx>,
        ) -> anyhow::Result<Box<dyn ProbeHost>> {
            Err(anyhow::anyhow!("the test lane hosts no probes"))
        }

        fn checks(&self) -> Vec<Arc<dyn Check>> {
            Vec::new()
        }
    }

    /// A check that never runs; `meta()` is the only part the test reads.
    struct TestCheck {
        meta: CheckMeta,
    }

    impl TestCheck {
        fn new() -> Self {
            Self {
                meta: CheckMeta {
                    id: "test.check".into(),
                    name: "test check".into(),
                    class: "test".into(),
                    lanes: vec![LaneKind::Http],
                    kinds: vec![InsertionKind::Query],
                    intensity: Intensity::Passive,
                    cost: CheckCost::Light,
                    technique: Technique::Passive,
                    severity: aitm_poc::Severity::Info,
                    confidence_max: Confidence::Tentative,
                    needs_baseline: false,
                    wants_traits: None,
                    targets_session: false,
                    cwe: None,
                    description: "a stub check".into(),
                    remediation: None,
                    origin: CheckOrigin::Native,
                },
            }
        }
    }

    impl Check for TestCheck {
        fn meta(&self) -> &CheckMeta {
            &self.meta
        }

        fn run<'a>(
            &'a self,
            _point: &'a InsertionPoint,
            _host: &'a dyn ProbeHost,
        ) -> BoxFuture<'a, Verdict> {
            Box::pin(async {
                Verdict {
                    outcome: Outcome::Inconclusive,
                    confidence: Confidence::Tentative,
                    evidence: Evidence::default(),
                    detail: "the test check concludes nothing".into(),
                    poc_hint: None,
                }
            })
        }
    }

    #[test]
    fn plugin_name_is_scanner() {
        let plugin = ScannerPlugin::new(ScannerConfig::default());
        assert_eq!(plugin.name(), "scanner");
    }

    /// Loading the plugin puts `scan.discover` on the registry at the `Write`
    /// tier — the only hermetic proof that the command is reachable at all.
    #[test]
    fn plugin_registers_scan_discover() {
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(ScannerPlugin::new(ScannerConfig::default())));

        let cmd = reg
            .command("scan.discover")
            .expect("scan.discover is registered");
        assert_eq!(cmd.name(), "scan.discover");
        assert_eq!(cmd.sensitivity(), Sensitivity::Write);
    }

    /// The Stage-2 read verbs are on the registry too, at the `Read` tier, so a
    /// read-only agent policy can run them.
    #[test]
    fn plugin_registers_the_read_verbs() {
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(ScannerPlugin::new(ScannerConfig::default())));

        for name in ["scan.passive", "scan.report"] {
            let cmd = reg
                .command(name)
                .unwrap_or_else(|| panic!("{name} is registered"));
            assert_eq!(cmd.name(), name);
            assert_eq!(cmd.sensitivity(), Sensitivity::Read, "{name}");
        }
    }

    /// Task 11 (spec D1): the binary hands the lane slots it collected to the
    /// plugin, and the plugin keeps exactly those handles. The shipped engine
    /// ignores them; T1b consumes them.
    #[test]
    fn with_lanes_keeps_the_handles() {
        let plugin = ScannerPlugin::new(ScannerConfig::default())
            .with_lanes(vec![Arc::new(TestLane) as Arc<dyn Lane>]);

        assert_eq!(plugin.lanes().len(), 1);
        assert_eq!(plugin.lanes()[0].lane(), LaneKind::Http);
        assert!(plugin.native_checks().is_empty());
    }

    /// The native-check slot is kept the same way, and independently: setting
    /// checks alone leaves `lanes()` empty.
    #[test]
    fn with_native_checks_keeps_the_handles() {
        let plugin = ScannerPlugin::new(ScannerConfig::default())
            .with_native_checks(vec![Arc::new(TestCheck::new()) as Arc<dyn Check>]);

        assert_eq!(plugin.native_checks().len(), 1);
        assert_eq!(plugin.native_checks()[0].meta().id, "test.check");
        assert!(plugin.lanes().is_empty());
    }

    /// What the binary builds today, every lane crate still a skeleton: a plugin
    /// holding no slots at all.
    #[test]
    fn a_fresh_plugin_holds_no_slots() {
        let plugin = ScannerPlugin::new(ScannerConfig::default());

        assert_eq!(plugin.lanes().len(), 0);
        assert_eq!(plugin.native_checks().len(), 0);
    }
}
