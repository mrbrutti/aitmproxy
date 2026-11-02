//! The scanner plugin itself.

use std::sync::{Arc, OnceLock};

use crate::config::ScannerConfig;
use crate::issues::IssueStore;
use crate::jobs::{Engine, JobRegistry, ScanLate};
use crate::profiles::Profiles;
use aitm_core::{Plugin, Registry};
use aitm_scan_model::{Check, CheckRegistry, Lane};

/// The scanner plugin. It holds its config and registers the `scan.*` command
/// set.
///
/// The scanner observes no events — it drives traffic itself from commands — so
/// it takes the default `Plugin::on_event`.
///
/// It also carries the scanner v2 registration slots the binary collected: the
/// lanes each lane crate's `lane()` handed back and the native checks from
/// `aitm_scan_checks_http::checks()` (spec D1, "Registration without shared
/// files"), plus the scripting tier's check registry (call B9). [`Plugin::load`]
/// assembles them into one [`Engine`] and registers the whole `scan.*` surface
/// over it.
///
/// `load` is also where the engine's state comes back from disk: with
/// `findings.dir` set it reloads the issue store and the finished-job history,
/// so `scan.issues` and `scan.list` answer across a restart (spec D5, D6).
pub struct ScannerPlugin {
    cfg: ScannerConfig,
    lanes: Vec<Arc<dyn Lane>>,
    native_checks: Vec<Arc<dyn Check>>,
    script_checks: Arc<CheckRegistry>,
    late: Arc<ScanLate>,
    /// Filled by [`Plugin::load`]. Shared with whoever took
    /// [`ScannerPlugin::engine_cell`] before the registry took the plugin.
    engine: Arc<OnceLock<Arc<Engine>>>,
}

impl ScannerPlugin {
    /// Build the plugin with the given budgets and gates, and no lane or check
    /// slots filled.
    pub fn new(cfg: ScannerConfig) -> Self {
        Self {
            cfg,
            lanes: Vec::new(),
            native_checks: Vec::new(),
            script_checks: Arc::new(CheckRegistry::new()),
            late: ScanLate::new(),
            engine: Arc::new(OnceLock::new()),
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

    /// Hand the plugin the scripting tier's check registry, replacing any
    /// already set.
    ///
    /// The registry rides on `RhaiLoader`/`ScriptTier` rather than on
    /// `ScriptServices` (call B9): `ScriptServices` is constructed in
    /// seventeen files, two of them integration-shared, so a new field there
    /// would force edits no task may make.
    #[must_use]
    pub fn with_script_checks(mut self, checks: Arc<CheckRegistry>) -> Self {
        self.script_checks = checks;
        self
    }

    /// The native checks this plugin was handed. Empty until track T3 lands.
    pub fn native_checks(&self) -> &[Arc<dyn Check>] {
        &self.native_checks
    }

    /// The scripting tier's check registry. Empty until a script declares a
    /// check with `reg.add_check`.
    pub fn script_checks(&self) -> Arc<CheckRegistry> {
        Arc::clone(&self.script_checks)
    }

    /// The cell the binary binds [`crate::jobs::ScanServices`] into once the
    /// proxy exists (call B3). Handed out before `load` so `main.rs` can bind
    /// it beside `handles.bind_proxy(..)`.
    pub fn late(&self) -> Arc<ScanLate> {
        Arc::clone(&self.late)
    }

    /// The scanner configuration this plugin was built with.
    pub fn cfg(&self) -> &ScannerConfig {
        &self.cfg
    }

    /// The cell [`Plugin::load`] puts the assembled [`Engine`] in.
    ///
    /// Handed out *before* `load`, like [`ScannerPlugin::late`], because
    /// `Registry::add_plugin` takes the plugin by value: a caller that needs
    /// the engine afterwards keeps this handle.
    pub fn engine_cell(&self) -> Arc<OnceLock<Arc<Engine>>> {
        Arc::clone(&self.engine)
    }

    /// The assembled engine, once [`Plugin::load`] has run.
    pub fn engine(&self) -> Option<Arc<Engine>> {
        self.engine.get().map(Arc::clone)
    }
}

impl Plugin for ScannerPlugin {
    fn name(&self) -> &str {
        "scanner"
    }

    fn load(&mut self, reg: &mut Registry) {
        let engine = Arc::new(Engine {
            cfg: self.cfg.clone(),
            late: Arc::clone(&self.late),
            lanes: self.lanes.clone(),
            native_checks: self.native_checks.clone(),
            script_checks: Arc::clone(&self.script_checks),
            // Call B2: the interim lane is built unconditionally but used only
            // while no lane crate supplies an HTTP lane. `lanes_for_run`
            // decides; the day `aitm_scan_http::lane()` returns `Some` this
            // handle is simply never picked.
            interim: crate::interim_lane::InterimHttpLane::new(self.cfg.clone()),
            registry: JobRegistry::new(self.cfg.history),
            issues: Arc::new(IssueStore::new(self.cfg.findings_dir.as_deref())),
            profiles: Profiles::new(&self.cfg),
        });

        // Spec D5/D6: the operator's issues and job history survive a restart.
        // A directory that cannot be read is logged, never fatal: a scanner
        // that refuses to start because one record is corrupt is worse than
        // one that starts with the rest.
        if let Err(e) = engine.issues.load() {
            tracing::warn!(
                target: "aitm::scanner",
                error = %e,
                "the scan issue store could not be read; starting with an empty one"
            );
        }
        if let Some(dir) = self.cfg.findings_dir.as_deref() {
            if let Err(e) = engine.registry.load_history(dir) {
                tracing::warn!(
                    target: "aitm::scanner",
                    error = %e,
                    "the scan job history could not be read; starting with none"
                );
            }
        }

        // Task 10's rule is first-claim-wins, so a duplicate id is a check the
        // operator installed that will never run. `scan.checks` cannot show
        // what is not in the catalogue, so load time is the only place this
        // can be said at all.
        for conflict in engine.catalogue().conflicts() {
            tracing::warn!(target: "aitm::scanner", "check catalogue: {conflict}");
        }

        crate::verbs::register(&engine, reg);
        crate::manual_check::register_all(&engine, reg);

        // The three shipped verbs, now over the job model (Task 16).
        crate::commands::register(&engine, reg);

        // `load` runs once per registry; a second binding would mean the same
        // plugin was loaded twice, and the first engine is the one the verbs
        // hold.
        let _ = self.engine.set(engine);
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
        CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind,
        Outcome, Technique,
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
                    scope: CheckScope::Point,
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
                    location: None,
                    more: Vec::new(),
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

    /// Tester: the setters are documented as *replacing* what is already set,
    /// not appending to it — the binary calls each one exactly once, and a second
    /// call that silently doubled the catalogue would schedule every check twice.
    #[test]
    fn the_setters_replace_rather_than_append() {
        let plugin = ScannerPlugin::new(ScannerConfig::default())
            .with_lanes(vec![Arc::new(TestLane) as Arc<dyn Lane>])
            .with_lanes(vec![
                Arc::new(TestLane) as Arc<dyn Lane>,
                Arc::new(TestLane) as Arc<dyn Lane>,
            ])
            .with_native_checks(vec![Arc::new(TestCheck::new()) as Arc<dyn Check>])
            .with_native_checks(vec![Arc::new(TestCheck::new()) as Arc<dyn Check>]);

        assert_eq!(plugin.lanes().len(), 2, "the last with_lanes call wins");
        assert_eq!(
            plugin.native_checks().len(),
            1,
            "the last with_native_checks call wins"
        );

        // Replacing with an empty list empties the slot; it does not keep the old one.
        let emptied = plugin.with_lanes(Vec::new()).with_native_checks(Vec::new());
        assert!(emptied.lanes().is_empty());
        assert!(emptied.native_checks().is_empty());
    }

    /// T1a's `filled_slots_register_no_extra_verb`, re-pinned for T1b: the
    /// slots now *are* the verb surface. A lane crate's lane displaces the
    /// interim one (call B2), so this plugin's catalogue is the test lane's
    /// checks (none) plus the one native check — and the manual surface is
    /// exactly that check's `check.test.check` (spec D4, call B8).
    ///
    /// Every new name here lands on the integration-shared contract lists,
    /// which Task 19 re-pins.
    #[test]
    fn filled_slots_register_the_v2_surface() {
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(
            ScannerPlugin::new(ScannerConfig::default())
                .with_lanes(vec![Arc::new(TestLane) as Arc<dyn Lane>])
                .with_native_checks(vec![Arc::new(TestCheck::new()) as Arc<dyn Check>]),
        ));

        let mut names: Vec<&str> = reg.commands().map(|c| c.name()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "check.test.check",
                "scan.cancel",
                "scan.checks",
                "scan.discover",
                "scan.issue",
                "scan.issue.update",
                "scan.issues",
                "scan.list",
                "scan.map",
                "scan.passive",
                "scan.profile.delete",
                "scan.profile.get",
                "scan.profile.list",
                "scan.profile.save",
                "scan.report",
                "scan.session.preview",
                "scan.sitemap",
                "scan.start",
                "scan.status",
            ]
        );
    }

    /// The engine `load` assembled is reachable afterwards through the cell the
    /// plugin handed out before `Registry::add_plugin` took it by value.
    #[test]
    fn load_publishes_the_engine_through_the_cell() {
        let plugin = ScannerPlugin::new(ScannerConfig::default())
            .with_native_checks(vec![Arc::new(TestCheck::new()) as Arc<dyn Check>]);
        let cell = plugin.engine_cell();
        let late = plugin.late();
        assert!(cell.get().is_none(), "nothing is published before `load`");

        let mut reg = Registry::new();
        reg.add_plugin(Box::new(plugin));

        let engine = cell.get().expect("`load` published the engine");
        // The cell's engine shares the plugin's late cell, which is how the
        // binary binds the services after the proxy exists (call B3).
        assert!(!engine.late.is_bound());
        assert!(late.is_bound() == engine.late.is_bound());
        // No lane crate: the interim HTTP lane runs, so its three passive checks
        // are in the catalogue beside the native one (its two legacy actives
        // left `checks()` when the T3 natives took their ids, PR 2a).
        assert_eq!(engine.catalogue().all().len(), 4);
        assert!(engine.catalogue().conflicts().is_empty());
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
