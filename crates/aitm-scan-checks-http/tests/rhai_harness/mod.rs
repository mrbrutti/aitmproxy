//! The inner loop for the bundled Rhai checks: load a real
//! `scripts/bundled/active/*.rhai` through the **real** T1b bridge and run the
//! `ScriptCheck` it registered against a reply table.
//!
//! Nothing here is a stand-in. [`Loaded::load`] compiles the shipped file on
//! [`RhaiLoader`]'s own hardened engine, `reg.add_check` is the production
//! bridge, `probe.*` is the production host surface, and the thing on the other
//! end of every probe is [`RecordingHost`] — the model's own recorder — so what
//! a test asserts is what the engine really did with the script. Plan Task 11
//! described a fake `reg`/`probe` harness; it was written before T1b landed and
//! orchestrator decision D-2b-1 replaced it with this.
//!
//! **This harness is the inner loop only.** It proves a script's logic against
//! canned replies on no network at all. Acceptance evidence is Task 17: a real
//! scan over the real bus against a real target, observed independently. A
//! green run here says the script is well-formed and decides correctly on the
//! shapes it was shown; it says nothing about the scanner in the field.

#![allow(dead_code)] // Tasks 12-16 use the rest of this surface.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_core::{MemFlowStore, Registry, StdGuard};
use aitm_plugin_rhai::command::ScriptRegHandle;
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_poc::Assertion;
use aitm_scan_model::check::Verdict;
use aitm_scan_model::point::InsertionPoint;
use aitm_scan_model::registry::CheckRegistry;
use aitm_scan_model::testing::{NullClient, RecordingHost};
use aitm_scan_model::traits::{Check, ProbeHost};
use aitm_scan_model::vocab::{CheckOrigin, InsertionKind, LaneKind, PointTrait};

/// The shipped active-check directory, `scripts/bundled/active/`.
pub fn active_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
        .join("active")
}

/// One shipped active check by file name, e.g. `check-nosqli-json.rhai`.
pub fn active_path(file: &str) -> PathBuf {
    active_dir().join(file)
}

/// The production services, with no network behind them: every `probe.*` goes
/// to the [`RecordingHost`] the check is run against, and a closure's
/// `http.send` reaches [`NullClient`] and errors.
fn services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(NullClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// A scripts directory outside the repo, named after the fixture and this
/// process so parallel tests never share one; removed on drop.
struct TempScripts(PathBuf);

impl TempScripts {
    fn new(name: &str) -> anyhow::Result<Self> {
        let dir =
            std::env::temp_dir().join(format!("aitm-rhai-harness-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bundled"))?;
        Ok(Self(dir))
    }
}

impl Drop for TempScripts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One script, compiled and `load(reg)`-run through the real bridge, with the
/// checks it registered.
///
/// Must be built inside a Tokio runtime: the production [`ScriptServices`]
/// carry the runtime handle the bridge drives its probes on.
pub struct Loaded {
    path: PathBuf,
    source: String,
    checks: Arc<CheckRegistry>,
    /// The command registry the script's `load(reg)` also filled. Kept so a
    /// test can see that an active script registers no command any more.
    commands: Registry,
    /// Dropped last: the fixture directory `load_source` wrote into, if any.
    _temp: Option<TempScripts>,
}

impl Loaded {
    /// Load the shipped `scripts/bundled/active/<file>` the way the scanner
    /// does, with the `Bundled` origin its path implies.
    pub fn load(file: &str) -> anyhow::Result<Loaded> {
        let path = active_path(file);
        let source = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("cannot read {}: {err}", path.display()))?;
        Self::run_load(path, source, None)
    }

    /// Load a fixture script written to a per-test temporary directory, so a
    /// test can show the bridge a shape no shipped file has.
    pub fn load_source(name: &str, src: &str) -> anyhow::Result<Loaded> {
        let temp = TempScripts::new(name)?;
        let path = temp.0.join("bundled").join(format!("{name}.rhai"));
        fs::write(&path, src)?;
        Self::run_load(path, src.to_string(), Some(temp))
    }

    fn run_load(
        path: PathBuf,
        source: String,
        temp: Option<TempScripts>,
    ) -> anyhow::Result<Loaded> {
        let loader = RhaiLoader::new(RhaiConfig::default(), services())
            .map_err(|err| anyhow::anyhow!("the loader does not build: {err}"))?;
        let (ast, _meta) = loader
            .compile(&path)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        let checks = Arc::new(CheckRegistry::new());
        let mut commands = Registry::new();
        ScriptRegHandle::new(&mut commands)
            .with_checks(
                Arc::clone(&checks),
                CheckOrigin::Bundled {
                    path: path.display().to_string(),
                },
            )
            .run_load(&loader.engine(), &Arc::new(ast))
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(Loaded {
            path,
            source,
            checks,
            commands,
            _temp: temp,
        })
    }

    /// What this script turned into, for an assertion that wanted the other
    /// arm: the file and the check ids it registered. The engine, the registry
    /// and the services behind it are not printable and are not interesting.
    fn describe(&self) -> String {
        let ids: Vec<String> = self.checks().iter().map(|c| c.meta().id.clone()).collect();
        format!("{} registering {:?}", self.path.display(), ids)
    }

    /// Every check this script registered, in catalogue order.
    pub fn checks(&self) -> Vec<Arc<dyn Check>> {
        self.checks.snapshot()
    }

    /// The one check this script registered, or an error naming the count.
    pub fn single(&self) -> anyhow::Result<Arc<dyn Check>> {
        let checks = self.checks();
        match checks.len() {
            1 => Ok(Arc::clone(&checks[0])),
            n => Err(anyhow::anyhow!(
                "{} registered {n} checks, expected exactly 1",
                self.path.display()
            )),
        }
    }

    /// The command names this script's `load(reg)` registered. An active check
    /// script registers none.
    pub fn command_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .commands
            .commands()
            .map(|c| c.name().to_string())
            .collect();
        names.sort();
        names
    }

    /// The script's source text, for the catalogue-sweep assertions.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The file the script was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

/// A [`RecordingHost`] under construction: the replies a check's probes get.
///
/// A needle matches when it is a substring of the probe's payload value, or of
/// a raw probe's URL — [`RecordingHost`]'s own rule. Entries answer in the
/// order they were added; a probe no needle matches gets the plain reply, and
/// so does every `probe.baseline()`.
pub struct Replies {
    host: RecordingHost,
}

impl Replies {
    /// The reply every unmatched probe — and every baseline — gets.
    pub fn plain(status: u16, body: &str) -> Self {
        Self {
            host: RecordingHost::new(status, body),
        }
    }

    /// Answer `status`/`body` to a probe whose payload (or raw URL) contains
    /// `needle`.
    #[must_use]
    pub fn when(self, needle: &str, status: u16, body: &str) -> Self {
        Self {
            host: self.host.with_reply_for(needle, status, body),
        }
    }

    /// [`Replies::when`] with response headers, for a check that reads one.
    #[must_use]
    pub fn when_headers(
        self,
        needle: &str,
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Self {
        Self {
            host: self
                .host
                .with_reply_for_headers(needle, status, owned(headers), body),
        }
    }

    /// The headers on the plain reply, which is what `probe.baseline()` gets.
    #[must_use]
    pub fn baseline_headers(self, headers: &[(&str, &str)]) -> Self {
        Self {
            host: self.host.with_baseline_headers(owned(headers)),
        }
    }

    /// The address the baseline is pretended to have come from.
    #[must_use]
    pub fn peer(self, addr: SocketAddr) -> Self {
        Self {
            host: self.host.with_peer(addr),
        }
    }

    /// The host, behind the `Arc` the bridge needs to park it in its check
    /// context.
    pub fn build(self) -> Arc<RecordingHost> {
        self.host.into_shared()
    }
}

fn owned(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

/// An insertion point of `kind` named `name` on `url`, filled out the way
/// [`aitm_scan_model::testing::query_point`] fills its own: id `p1`, HTTP lane,
/// `GET`, no path, no flow, frequency 1.
pub fn point(
    kind: InsertionKind,
    name: &str,
    url: &str,
    example: Option<&str>,
    traits: &[PointTrait],
) -> InsertionPoint {
    InsertionPoint {
        id: "p1".to_string(),
        lane: LaneKind::Http,
        kind,
        name: name.to_string(),
        path: None,
        example: example.map(str::to_string),
        flow: None,
        site_node: None,
        traits: traits.to_vec(),
        frequency: 1,
        method: Some("GET".to_string()),
        url: Some(url.to_string()),
    }
}

/// Run `check` against `point`, every probe answered by `host`.
pub async fn run(
    check: &Arc<dyn Check>,
    point: &InsertionPoint,
    host: &Arc<RecordingHost>,
) -> Verdict {
    let probe_host: &dyn ProbeHost = host.as_ref();
    check.run(point, probe_host).await
}

/// The verdict and its `more` siblings, flattened one level — the multi-verdict
/// contract the bridge builds from a closure that returned an array.
pub fn all_verdicts(v: &Verdict) -> Vec<&Verdict> {
    let mut out = vec![v];
    out.extend(v.more.iter());
    out
}

/// The `poc_hint.matchers` the bridge parsed off this verdict.
///
/// The bridge already ran the list through `aitm_poc::Assertion`'s own
/// deserializer — the same code path the PoC loader uses — and stored the
/// result on the verdict; this reads it rather than parsing a second time.
/// An error when the verdict carries no hint at all.
pub fn matchers_parse(verdict: &Verdict) -> anyhow::Result<Vec<Assertion>> {
    let hint = verdict
        .poc_hint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the verdict carries no poc_hint"))?;
    Ok(hint.assertions.clone())
}

/// The `poc_hint.control` payload and its matchers, when the verdict named a
/// control arm. `Ok(None)` when the hint has no control; an error when there is
/// no hint at all.
pub fn control_parse(verdict: &Verdict) -> anyhow::Result<Option<(String, Vec<Assertion>)>> {
    let hint = verdict
        .poc_hint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("the verdict carries no poc_hint"))?;
    Ok(hint
        .control
        .as_ref()
        .map(|control| (control.payload.clone(), control.expect.clone())))
}
