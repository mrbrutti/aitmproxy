//! `poc.run` (data-flow 6): execute a `Poc` with no agent and emit the three
//! artifacts.
//!
//! The runner walks the ordered steps, resolving `{{placeholders}}` against the
//! caller bindings layered over the PoC's variable defaults:
//!
//! - **http** steps template the URL / headers / body, pass the authority through
//!   the scope+rate [`ScopeRateGuard`], send via the [`ProxyClient`], store the
//!   captured flow (the anchor for the *finding capture* artifact), and feed the
//!   response into the match context. Inline `extract`s bind variables for later
//!   steps.
//! - **browser** steps dispatch to the [`BrowserDriver`]: `navigate` is
//!   scope-guarded on the URL's host; `eval` records an observed value; a
//!   `screenshot` is kept for the *screenshot* artifact; `click`/`type` drive the
//!   page.
//! - **extract** steps bind a variable from the current response context.
//! - **script** steps are handed to the optional [`ScriptStepExecutor`] (the Rhai
//!   tier, wired in by the binary). Its verdict is recorded under the step's name
//!   and read back from `success` as `step("name")`; the variables it binds reach
//!   later steps and `success`. With no executor wired, a script step is an error,
//!   never a silent skip.
//!
//! After the steps, `success` is rendered against the bindings, any `browser-eval`
//! it names is evaluated through the driver, and the tree is judged — the PoC
//! **passes iff `success` is true**. The runner then writes the finding capture
//! (already in the store), the YAML PoC file, and the screenshot PNG, and returns
//! a [`PocRunResult`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, CallerTrust, ClickTarget, Command, CommandHost, FindingDraft, FlowId, Frontend,
    HeaderMap, HttpRequest, HttpVersion, ParamDef, ParamSchema, Params, Registry, TypeDesc, Value,
};
use futures::future::BoxFuture;

use aitm_plugin::language::PocStepInputs;

use crate::extract::{apply, Extractor};
use crate::matcher::{evaluate, MatchContext};
use crate::model::{Assertion, BrowserAction, Poc, ProtoExtract, ScriptStep, Step};
use crate::step_registry::PocStepRegistry;
use crate::template::{PocTemplate, Template, VarBindings};

/// Execute a `Poc` with no agent and emit the three artifacts.
pub trait PocRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        poc: &'a Poc,
        bindings: VarBindings,
        host: &'a CommandHost<'a>,
    ) -> BoxFuture<'a, anyhow::Result<PocRunResult>>;
}

/// The outcome of a run: the pass verdict, the three artifact handles, and the
/// per-assertion breakdown of `success`.
#[derive(Debug, Clone)]
pub struct PocRunResult {
    pub passed: bool,
    /// (1) The triggering request/response flow, present in the store.
    pub finding_capture: FlowId,
    /// (2) The replayable PoC file (YAML).
    pub poc_path: PathBuf,
    /// (3) PNG of the vuln triggering (empty path when the PoC has no screenshot step).
    pub screenshot_path: PathBuf,
    /// Each leaf assertion of `success` and whether it matched.
    pub evaluated: Vec<AssertionOutcome>,
    /// The id of the durable finding recorded for this run, when one was persisted
    /// (a passing run, a wired recorder, and a configured `findings.dir`). `None`
    /// otherwise. (T7)
    pub recorded_id: Option<String>,
}

/// One leaf assertion of `success` and its verdict.
#[derive(Debug, Clone)]
pub struct AssertionOutcome {
    pub assertion: String,
    pub matched: bool,
}

// ---------------------------------------------------------------------------
// Script steps: the executor seam (spec §10)
// ---------------------------------------------------------------------------

/// Runs one `script` step. Implemented by the scripting tier
/// (`aitm-plugin-rhai`'s `RhaiScriptExecutor`) and wired into the runner by the
/// binary, so this crate carries no Rhai dependency and the declarative subset
/// runs without the scripting tier.
pub trait ScriptStepExecutor: Send + Sync {
    fn run_step(
        &self,
        step: &ScriptStep,
        ctx: &mut ScriptStepCtx<'_>,
    ) -> Result<ScriptVerdict, ScriptStepError>;
}

/// What a script step may touch while it runs.
pub struct ScriptStepCtx<'a> {
    /// Read + write; later steps and `success` see the writes.
    pub vars: &'a mut VarBindings,
    /// The store / client / browser / guard, behind the same guards as Rust.
    pub host: &'a CommandHost<'a>,
    /// Outcomes recorded so far, by step name.
    pub step_results: &'a mut BTreeMap<String, StepOutcome>,
    /// Files the script wrote (its screenshots); they join the run's artifacts.
    pub artifacts: &'a mut Vec<PathBuf>,
}

/// A script step's result: `return pass` / `return fail`, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptVerdict {
    Pass,
    Fail,
    Neutral,
}

/// What `step("name")` resolves to in the success DSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Matched,
    NotMatched,
    Pass,
    Fail,
    Error,
    Neutral,
}

impl StepOutcome {
    /// The string `step("name")` compares against.
    pub fn as_str(self) -> &'static str {
        match self {
            StepOutcome::Matched => "matched",
            StepOutcome::NotMatched => "not-matched",
            StepOutcome::Pass => "pass",
            StepOutcome::Fail => "fail",
            StepOutcome::Error => "error",
            StepOutcome::Neutral => "neutral",
        }
    }
}

impl From<ScriptVerdict> for StepOutcome {
    fn from(verdict: ScriptVerdict) -> Self {
        match verdict {
            ScriptVerdict::Pass => StepOutcome::Pass,
            ScriptVerdict::Fail => StepOutcome::Fail,
            ScriptVerdict::Neutral => StepOutcome::Neutral,
        }
    }
}

/// A script step that reached no verdict — a runtime error, sandbox denial,
/// timeout, or operation-limit abort — as the message the run reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptStepError(pub String);

impl fmt::Display for ScriptStepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScriptStepError {}

/// The default runner. Artifacts are written under `out_dir` (a fresh
/// per-run subdirectory); defaults to the system temp directory. Script steps
/// dispatch through the optional executor; without one they error.
#[derive(Clone)]
pub struct StdPocRunner {
    out_dir: PathBuf,
    script_executor: Option<Arc<dyn ScriptStepExecutor>>,
    step_handlers: PocStepRegistry,
}

// Manual: the executor is an opaque trait object, so report only its presence.
impl fmt::Debug for StdPocRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdPocRunner")
            .field("out_dir", &self.out_dir)
            .field("script_executor", &self.script_executor.is_some())
            .field("step_handlers", &self.step_handlers.namespaces())
            .finish()
    }
}

impl Default for StdPocRunner {
    fn default() -> Self {
        Self {
            out_dir: std::env::temp_dir(),
            script_executor: None,
            step_handlers: PocStepRegistry::new(),
        }
    }
}

impl StdPocRunner {
    /// A runner writing artifacts under the system temp directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner writing artifacts under `dir`.
    pub fn with_output_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            out_dir: dir.into(),
            ..Self::default()
        }
    }

    /// Wire the scripting tier: `script` steps dispatch through `exec`.
    pub fn with_script_executor(self, exec: Arc<dyn ScriptStepExecutor>) -> Self {
        Self {
            script_executor: Some(exec),
            ..self
        }
    }

    /// Register a protocol step handler: a `Step::Protocol { ns, .. }` whose
    /// `ns` matches `handler.ns()` dispatches through it (mirrors
    /// [`with_script_executor`](Self::with_script_executor)).
    pub fn with_step_handler(
        mut self,
        handler: Arc<dyn aitm_plugin::language::PocStepHandler>,
    ) -> Self {
        self.step_handlers.register(handler);
        self
    }

    /// Wire a whole protocol-step registry at once (the binary assembles one
    /// from every registered `ProtocolLanguage::poc_step`).
    pub fn with_step_handlers(self, handlers: PocStepRegistry) -> Self {
        Self {
            step_handlers: handlers,
            ..self
        }
    }
}

impl PocRunner for StdPocRunner {
    fn run<'a>(
        &'a self,
        poc: &'a Poc,
        bindings: VarBindings,
        host: &'a CommandHost<'a>,
    ) -> BoxFuture<'a, anyhow::Result<PocRunResult>> {
        Box::pin(async move { self.run_inner(poc, bindings, host).await })
    }
}

impl StdPocRunner {
    async fn run_inner(
        &self,
        poc: &Poc,
        bindings: VarBindings,
        host: &CommandHost<'_>,
    ) -> anyhow::Result<PocRunResult> {
        // Fail a malformed PoC before any request is sent: compile every regex and
        // parse every DSL expression, and reject an unsafe `id`.
        precheck(poc)?;
        let tmpl = PocTemplate::from_poc(poc)?;

        // Bindings grow as extractors bind variables for later steps.
        let mut live = bindings;
        // Seed the PoC's `variables:` defaults into the live bindings so a
        // `script:` step's `vars.get()` sees a default, not only `{{template}}`
        // rendering. Caller `--vars` already in `live` win — only seed a default
        // the caller did not supply. (T2)
        for (name, value) in tmpl.defaults().iter() {
            if live.get(name).is_none() {
                live.insert(name.clone(), value.clone());
            }
        }
        let mut ctx = MatchContext::default();
        let mut finding: Option<FlowId> = None;
        let mut screenshot: Option<Vec<u8>> = None;
        // Files script steps wrote (their screenshots), see `write_artifacts`.
        let mut artifacts: Vec<PathBuf> = Vec::new();
        // One failed outcome per script step that errored (spec §10 failure reporting).
        let mut script_errors: Vec<AssertionOutcome> = Vec::new();

        for (index, step) in poc.steps.iter().enumerate() {
            match step {
                Step::Http(http) => {
                    let req = build_request(http, &tmpl, &live)?;
                    // The `ProxyClient` guards the authority (scope/rate) and
                    // stores the captured flow; the runner neither re-checks nor
                    // re-inserts. The returned flow's id anchors the finding.
                    let flow = host.client().send(req).await?;
                    finding = Some(flow.id);

                    if let Some(resp) = &flow.response {
                        ctx.status = resp.status;
                        ctx.body = body_to_string(&resp.body);
                        ctx.headers = resp
                            .headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();
                    }

                    // Inline extractors bind variables for later steps.
                    for ex_step in &http.extract {
                        bind_extractor(&Extractor::from(ex_step), &mut ctx, &mut live);
                    }
                }
                Step::Browser(browser) => {
                    let driver = host.browser().ok_or_else(|| {
                        anyhow::anyhow!(
                            "poc.run: PoC has a browser step but no browser is configured"
                        )
                    })?;
                    match &browser.action {
                        BrowserAction::Navigate { url } => {
                            let url = tmpl.render(url, &live)?;
                            // SSRF pre-flight (resolve + classify, url::Url parse)
                            // before the scope/rate check, so a PoC cannot drive
                            // the browser at a private/loopback target off-scope.
                            let target = aitm_browser::check_url(
                                &url,
                                host.ssrf_policy(),
                                &host.guard().list_scope(),
                                &aitm_browser::SystemResolver,
                            )?;
                            let authority = format!("{}:{}", target.host, target.addr.port());
                            let _permit = host.guard().check_active(&authority)?;
                            driver.navigate(&url).await?;
                            drop(_permit);
                        }
                        BrowserAction::Click { target } => {
                            let target = tmpl.render(target, &live)?;
                            driver.click(ClickTarget::Selector(target)).await?;
                        }
                        BrowserAction::Type { selector, text } => {
                            let selector = tmpl.render(selector, &live)?;
                            let text = tmpl.render(text, &live)?;
                            driver.type_text(&selector, &text).await?;
                        }
                        BrowserAction::Eval { expr } => {
                            let expr = tmpl.render(expr, &live)?;
                            let value = driver.eval(&expr).await?;
                            ctx.browser.insert(expr, value);
                        }
                        BrowserAction::Screenshot { .. } => {
                            screenshot = Some(driver.screenshot().await?);
                        }
                    }
                }
                Step::Extract(ex_step) => {
                    bind_extractor(&Extractor::from(ex_step), &mut ctx, &mut live);
                }
                Step::Script(script) => {
                    let executor = self.script_executor.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "script steps require the Rhai runtime (wire a ScriptStepExecutor)"
                        )
                    })?;
                    let name = script
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("step-{}", index + 1));
                    let before = live.clone();
                    let outcome = {
                        let mut step_ctx = ScriptStepCtx {
                            vars: &mut live,
                            host,
                            step_results: &mut ctx.steps,
                            artifacts: &mut artifacts,
                        };
                        match executor.run_step(script, &mut step_ctx) {
                            Ok(verdict) => StepOutcome::from(verdict),
                            // The step resolves to "error" and the run goes on; it
                            // fails only if `success` depends on this step.
                            Err(err) => {
                                script_errors.push(AssertionOutcome {
                                    assertion: format!("script {name}: {err}"),
                                    matched: false,
                                });
                                StepOutcome::Error
                            }
                        }
                    };
                    ctx.steps.insert(name, outcome);
                    // Variables the script bound reach `success` the way extractor
                    // bindings do; later steps already see them in `live`.
                    for (var, value) in live.iter() {
                        if before.get(var) != Some(value) {
                            ctx.vars.insert(var.clone(), value.clone());
                        }
                    }
                }
                Step::Protocol { ns, body, extract } => {
                    // Dispatch to the registered handler; an unregistered
                    // namespace is a clear error, never a silent skip.
                    let handler = self.step_handlers.get(ns).ok_or_else(|| {
                        anyhow::anyhow!(
                            "poc.run: no handler registered for protocol step `{ns}:` \
                             (register the `{ns}` protocol's PocStepHandler)"
                        )
                    })?;
                    // Hand the handler the resolved variables so it can expand
                    // any `{{placeholder}}` inside its own body, plus the live
                    // caller trust of this run — sourced from the `poc.run`
                    // command's frontend — so a native `<ns>:` handler (which
                    // bypasses the rhai thread-local seed) can gate an effect per
                    // call, exactly as the scripting face does (Ruling A, AC5).
                    let inputs = PocStepInputs {
                        vars: live.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                        caller: CallerTrust::from(host.frontend()),
                    };
                    let outcome = handler.run(body, &inputs).map_err(|e| {
                        anyhow::anyhow!("poc.run: protocol step `{ns}:` failed: {e}")
                    })?;
                    // Direct bindings reach later steps and `success` like an
                    // extractor binding does.
                    for (name, value) in &outcome.bindings {
                        ctx.vars.insert(name.clone(), value.clone());
                        live.insert(name.clone(), value.clone());
                    }
                    // Sibling extractors bind a `field` of a named source the
                    // handler produced (the normative `l4:` shape).
                    bind_proto_extracts(extract, &outcome.sources, &mut ctx, &mut live);
                }
            }
        }

        // Resolve `{{placeholders}}` inside the success tree, then evaluate any
        // browser-eval it names through the driver.
        let success = render_assertion(&poc.success, &tmpl, &live)?;
        // The rendered tree can differ from the one `precheck` validated: a
        // template may have substituted a `{{var}}` into a regex or dsl. Re-check
        // it so an invalid *rendered* pattern is a hard error, not a matcher that
        // `evaluate` silently coerces to `false`. (I8)
        check_assertion(&success)?;
        eval_browser_assertions(&success, host, &mut ctx).await?;

        // Describe outcomes from the pre-render (templated) tree so a bound secret
        // (e.g. `word: "{{token}}"`) is not leaked into the output, but evaluate
        // against the rendered tree so matching uses the real value. (minor c)
        let mut evaluated = collect_outcomes(&poc.success, &success, &ctx);
        evaluated.extend(script_errors);
        let passed = evaluate(&success, &ctx);

        // Anchor the finding: a declarative `http:` step's flow if one ran, else
        // the newest flow captured in the store during the run (so a pure-`script:`
        // PoC that drove `http.send`/`browser.*` still anchors), else a hard error
        // only when nothing at all was captured. (T1)
        let finding_capture = finding
            .or_else(|| host.store().list().last().copied())
            .ok_or_else(|| {
                anyhow::anyhow!("poc.run: no HTTP flow was captured to anchor the finding")
            })?;

        let (poc_path, mut screenshot_path) = self.write_artifacts(poc, screenshot.as_deref())?;
        // A script's screenshot joins the same artifact set as a declarative one:
        // with no declarative screenshot, the first script-written file stands in.
        if screenshot_path.as_os_str().is_empty() {
            if let Some(first) = artifacts.into_iter().next() {
                screenshot_path = first;
            }
        }

        // Persist a durable finding on a passing run, when a recorder is wired and
        // `findings.dir` is configured. Deny-by-default: no recorder or no dir means
        // no persistence. A record failure is logged, never fatal to the run. So the
        // UIs (`findings.list`) populate from an agent-driven `poc.run`. (T7)
        let recorded_id = if passed {
            match (
                host.finding_recorder(),
                host.config().and_then(|c| c.findings.dir.clone()),
            ) {
                (Some(recorder), Some(dir)) => {
                    let draft = FindingDraft {
                        title: poc.info.name.clone(),
                        class: poc
                            .info
                            .cwe
                            .clone()
                            .or_else(|| poc.info.tags.first().cloned())
                            .unwrap_or_else(|| poc.id.clone()),
                        severity: severity_str(poc.info.severity).to_string(),
                        target: live
                            .get("target")
                            .map(value_to_plain_string)
                            .unwrap_or_default(),
                        poc_ref: poc.id.clone(),
                        passed,
                        finding_capture,
                        flows: vec![finding_capture],
                        poc_path: poc_path.display().to_string(),
                        screenshot_path: screenshot_path.display().to_string(),
                        origin: host.frontend(),
                        client_label: host.client_label().map(|s| s.to_string()),
                    };
                    match recorder.record(&draft, &dir) {
                        Ok(id) => Some(id),
                        Err(e) => {
                            tracing::warn!("poc.run: failed to record finding: {e}");
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        };

        Ok(PocRunResult {
            passed,
            finding_capture,
            poc_path,
            screenshot_path,
            evaluated,
            recorded_id,
        })
    }

    /// Write the YAML PoC file and (if a screenshot was taken) the PNG, into a
    /// fresh per-run directory. Returns their paths.
    fn write_artifacts(
        &self,
        poc: &Poc,
        screenshot: Option<&[u8]>,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // The configured output root is trusted; create it if missing.
        std::fs::create_dir_all(&self.out_dir)?;
        // Create the per-run dir *atomically* owner-only, failing if it exists, so
        // a pre-created world-readable dir or a planted symlink can't be reused.
        // The name is made collision-proof — pid + a process-wide counter, not just
        // the timestamp — so two concurrent runs of the same PoC id never clash on
        // the fail-if-exists create. `poc.id` is `precheck`-validated (safe single
        // path component).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = self.out_dir.join(format!(
            "aitm-poc-{}-{}-{}-{}",
            poc.id,
            std::process::id(),
            seq,
            nanos
        ));
        create_private_dir(&dir)?;

        let poc_path = dir.join(format!("{}.poc.yaml", poc.id));
        write_private_file(&poc_path, serde_yaml::to_string(poc)?.as_bytes())?;

        let screenshot_path = match screenshot {
            Some(bytes) => {
                let path = dir.join("screenshot.png");
                write_private_file(&path, bytes)?;
                path
            }
            None => PathBuf::new(),
        };

        Ok((poc_path, screenshot_path))
    }
}

/// Create `path` as a new owner-only (`0700`) directory, failing if it already
/// exists. The mode is set at creation (not chmod-after), and fail-if-exists
/// prevents reusing a pre-created world-readable dir or a planted symlink — a
/// finding's request/response and screenshot may hold sensitive data.
#[cfg(unix)]
fn create_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    std::fs::DirBuilder::new().create(path)?;
    Ok(())
}

/// Write `bytes` to a brand-new owner-only (`0600`) file, failing if it already
/// exists (`create_new`), so the write cannot follow a planted symlink or clobber
/// an existing file.
#[cfg(unix)]
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// A filesystem-safe PoC id: `^[a-z0-9][a-z0-9-]{0,63}$`. Used to build the
/// artifact directory name, so it can never contain path separators or `..`.
pub fn is_valid_poc_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    first_ok
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Reject a PoC that cannot be run safely: an unsafe id, a regex that does not
/// compile, or a DSL expression that does not parse. Runs before any request.
fn precheck(poc: &Poc) -> anyhow::Result<()> {
    if !is_valid_poc_id(&poc.id) {
        anyhow::bail!(
            "poc.run: PoC id {:?} is not a safe identifier (expected ^[a-z0-9][a-z0-9-]{{0,63}}$)",
            poc.id
        );
    }
    check_assertion(&poc.success)?;
    for step in &poc.steps {
        match step {
            Step::Http(http) => {
                for ex in &http.extract {
                    check_extract(ex)?;
                }
            }
            Step::Extract(ex) => check_extract(ex)?,
            // A protocol step's body is late-parsed by its handler at run time;
            // `aitm-poc` cannot statically validate a namespace it does not know.
            Step::Browser(_) | Step::Script(_) | Step::Protocol { .. } => {}
        }
    }
    Ok(())
}

/// Bind each protocol-step extractor from a `field` of a named source the
/// handler produced, visible to `dsl` matchers (`ctx.vars`) and later-step
/// templating (`live`). An extractor naming an absent source or missing field
/// simply binds nothing (like the response extractors).
fn bind_proto_extracts(
    extract: &[ProtoExtract],
    sources: &BTreeMap<String, Value>,
    ctx: &mut MatchContext,
    live: &mut VarBindings,
) {
    for ex in extract {
        let Some(source) = sources.get(&ex.source) else {
            continue;
        };
        if let Some(value) = pluck_field(source, &ex.field) {
            ctx.vars.insert(ex.name.clone(), value.clone());
            live.insert(ex.name.clone(), value);
        }
    }
}

/// Walk a dotted `field` path (`tcp.flags`) into a source value; an empty path
/// returns the whole source. A path through a non-object yields `None`.
fn pluck_field(source: &Value, field: &str) -> Option<Value> {
    let mut cur = source;
    for seg in field.split('.').filter(|s| !s.is_empty()) {
        match cur {
            Value::Object(map) => cur = map.get(seg)?,
            _ => return None,
        }
    }
    Some(cur.clone())
}

fn check_assertion(assertion: &Assertion) -> anyhow::Result<()> {
    match assertion {
        Assertion::Regex { regex, .. } => regex::Regex::new(regex)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("poc.run: invalid regex matcher {regex:?}: {e}")),
        Assertion::Dsl(expr) => crate::dsl::check(expr)
            .map_err(|e| anyhow::anyhow!("poc.run: invalid dsl matcher {expr:?}: {e}")),
        Assertion::All(items) | Assertion::Any(items) => {
            // An empty combinator asserts nothing: `all` is vacuously true (a
            // false positive) and `any` vacuously false. Require a leaf. (I3)
            if items.is_empty() {
                anyhow::bail!("poc.run: an empty `all`/`any` matcher list asserts nothing");
            }
            items.iter().try_for_each(check_assertion)
        }
        Assertion::Not(inner) => check_assertion(inner),
        Assertion::Status(_) | Assertion::Word { .. } | Assertion::BrowserEval { .. } => Ok(()),
    }
}

fn check_extract(step: &crate::model::ExtractStep) -> anyhow::Result<()> {
    if let crate::model::ExtractSource::Regex { pattern, group } = &step.source {
        let re = regex::Regex::new(pattern)
            .map_err(|e| anyhow::anyhow!("poc.run: invalid regex extractor {pattern:?}: {e}"))?;
        // A group index past the pattern's capture count would bind nothing at
        // run time; reject it here instead of failing silently. `captures_len`
        // counts group 0 (the whole match), so index 0 is always valid. (I7)
        if *group >= re.captures_len() {
            anyhow::bail!(
                "poc.run: regex extractor {pattern:?} has no capture group {group} \
                 (the pattern has {} capture group(s))",
                re.captures_len() - 1
            );
        }
    }
    Ok(())
}

/// Build a captured-request shape from a templated http step.
fn build_request(
    http: &crate::model::HttpStep,
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<HttpRequest> {
    let url = tmpl.render(&http.url, live)?;
    let (scheme, authority, path) = parse_url(&url)?;

    // Nothing reaches the request line unvalidated. The wire encoder formats
    // `"{method} {path} HTTP/1.1"` with no CR/LF strip, so a control byte or
    // space in the method or path — whether from the PoC document or templated
    // from caller `vars` — would smuggle a header or a whole second request
    // past the scope guard (which only vets the authority). This is the same
    // check the Rhai `http.send` / `flow.request` paths run.
    if !is_http_token(&http.method) {
        anyhow::bail!(
            "poc.run: http step method {:?} must be an HTTP token like GET or POST",
            http.method
        );
    }
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        anyhow::bail!(
            "poc.run: http step URL {url:?} has a space or control character in its path; \
             percent-encode it"
        );
    }

    let mut headers = HeaderMap::new();
    for (name, value) in &http.headers {
        headers
            .try_set(&tmpl.render(name, live)?, &tmpl.render(value, live)?)
            .map_err(|e| anyhow::anyhow!("poc.run: http step header: {e}"))?;
    }

    let body = match &http.body {
        Some(text) => Body::Bytes(tmpl.render(text, live)?.into_bytes()),
        None => Body::Empty,
    };

    Ok(HttpRequest {
        method: http.method.clone(),
        scheme,
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body,
        timestamp: SystemTime::now(),
    })
}

/// RFC 9110 §5.6.2 `token`: one or more `tchar`. The HTTP method must be one so
/// it cannot carry a space or CR/LF into the request line.
fn is_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Split a URL into `(scheme, authority, path+query)`.
fn parse_url(url: &str) -> anyhow::Result<(String, String, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("poc.run: step URL `{url}` has no scheme"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    Ok((scheme.to_string(), authority, path))
}

/// Evaluate one extractor against the context, binding it both for `dsl` matchers
/// (`ctx.vars`) and for later-step templating (`live`).
fn bind_extractor(ex: &Extractor, ctx: &mut MatchContext, live: &mut VarBindings) {
    if let Some(value) = apply(ex, ctx) {
        ctx.vars.insert(ex.name.clone(), value.clone());
        live.insert(ex.name.clone(), value);
    }
}

fn body_to_string(body: &Body) -> String {
    match body {
        Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// The lowercase severity string a `FindingDraft` carries (core cannot name
/// `Severity`). Mirrors the `aitm-findings` `severity_str`. (T7)
fn severity_str(s: crate::model::Severity) -> &'static str {
    use crate::model::Severity;
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// A bound variable's plain string value for the finding draft's `target`
/// (the `target` binding is a string; fall back to a debug form otherwise). (T7)
fn value_to_plain_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

/// Render `{{placeholders}}` inside an assertion tree against the bindings.
fn render_assertion(
    assertion: &Assertion,
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<Assertion> {
    Ok(match assertion {
        Assertion::Status(code) => Assertion::Status(*code),
        Assertion::Word { word, part } => Assertion::Word {
            word: tmpl.render(word, live)?,
            part: *part,
        },
        Assertion::Regex { regex, part } => Assertion::Regex {
            regex: tmpl.render(regex, live)?,
            part: *part,
        },
        Assertion::Dsl(d) => Assertion::Dsl(tmpl.render(d, live)?),
        Assertion::BrowserEval { expr, equals } => Assertion::BrowserEval {
            expr: tmpl.render(expr, live)?,
            equals: render_value(equals, tmpl, live)?,
        },
        Assertion::All(items) => Assertion::All(render_each(items, tmpl, live)?),
        Assertion::Any(items) => Assertion::Any(render_each(items, tmpl, live)?),
        Assertion::Not(inner) => Assertion::Not(Box::new(render_assertion(inner, tmpl, live)?)),
    })
}

fn render_each(
    items: &[Assertion],
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<Vec<Assertion>> {
    items
        .iter()
        .map(|a| render_assertion(a, tmpl, live))
        .collect()
}

fn render_value(value: &Value, tmpl: &PocTemplate, live: &VarBindings) -> anyhow::Result<Value> {
    Ok(match value {
        Value::Str(s) => Value::Str(tmpl.render(s, live)?),
        other => other.clone(),
    })
}

/// Evaluate every `browser-eval` named anywhere in the (resolved) assertion tree
/// through the driver, recording the observed value in the match context.
fn eval_browser_assertions<'a>(
    assertion: &'a Assertion,
    host: &'a CommandHost<'a>,
    ctx: &'a mut MatchContext,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match assertion {
            Assertion::BrowserEval { expr, .. } => {
                if ctx.browser.contains_key(expr) {
                    return Ok(());
                }
                let driver = host.browser().ok_or_else(|| {
                    anyhow::anyhow!(
                        "poc.run: success has a browser-eval but no browser is configured"
                    )
                })?;
                let value = driver.eval(expr).await?;
                ctx.browser.insert(expr.clone(), value);
            }
            Assertion::All(items) | Assertion::Any(items) => {
                for item in items {
                    eval_browser_assertions(item, host, ctx).await?;
                }
            }
            Assertion::Not(inner) => eval_browser_assertions(inner, host, ctx).await?,
            _ => {}
        }
        Ok(())
    })
}

/// Flatten the leaf assertions of `success` into reported outcomes.
///
/// `templated` is the pre-render tree (its leaves describe the report, keeping
/// `{{placeholders}}` intact), `rendered` is the substituted tree (its leaves are
/// evaluated). `render_assertion` preserves the tree shape, so the two walk in
/// lockstep.
fn collect_outcomes(
    templated: &Assertion,
    rendered: &Assertion,
    ctx: &MatchContext,
) -> Vec<AssertionOutcome> {
    let mut out = Vec::new();
    push_outcomes(templated, rendered, ctx, &mut out);
    out
}

fn push_outcomes(
    templated: &Assertion,
    rendered: &Assertion,
    ctx: &MatchContext,
    out: &mut Vec<AssertionOutcome>,
) {
    match (templated, rendered) {
        (Assertion::All(t), Assertion::All(r)) | (Assertion::Any(t), Assertion::Any(r)) => {
            for (t, r) in t.iter().zip(r.iter()) {
                push_outcomes(t, r, ctx, out);
            }
        }
        (Assertion::Not(t), Assertion::Not(r)) => push_outcomes(t, r, ctx, out),
        (templated_leaf, rendered_leaf) => out.push(AssertionOutcome {
            assertion: describe(templated_leaf),
            matched: evaluate(rendered_leaf, ctx),
        }),
    }
}

fn describe(assertion: &Assertion) -> String {
    match assertion {
        Assertion::Status(code) => format!("status == {code}"),
        Assertion::Word { word, .. } => format!("word: {word}"),
        Assertion::Regex { regex, .. } => format!("regex: {regex}"),
        Assertion::Dsl(d) => format!("dsl: {d}"),
        Assertion::BrowserEval { expr, equals } => {
            format!("browser-eval {expr} == {equals:?}")
        }
        // Combinators are flattened before this point.
        Assertion::All(_) => "all(..)".to_string(),
        Assertion::Any(_) => "any(..)".to_string(),
        Assertion::Not(_) => "not(..)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// poc.run command
// ---------------------------------------------------------------------------

/// The `poc.run` command: load a PoC from `poc_path`, run it with the given
/// variable bindings, and return the verdict plus the three artifact paths.
///
/// `invoke` is synchronous while the runner is async; the future is driven to
/// completion here. A frontend must invoke `poc.run` off a current-thread Tokio
/// runtime's own thread (via `spawn_blocking`), the same convention `flow.replay`
/// and the browser commands use.
pub struct PocRunCommand;

impl Command for PocRunCommand {
    fn name(&self) -> &str {
        "poc.run"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Run a reproducible PoC (YAML) with no agent and emit the three artifacts."
                    .to_string(),
            params: vec![
                ParamDef {
                    name: "poc_path".to_string(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "Path to the PoC YAML file to execute.".to_string(),
                },
                ParamDef {
                    name: "target".to_string(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Base URL bound to the `target` variable.".to_string(),
                },
                ParamDef {
                    name: "vars".to_string(),
                    ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
                    required: false,
                    description: "Additional variable bindings (name → value).".to_string(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        run_poc_command(args, host, None)
    }

    fn summarize(&self, _args: &Params, result: &Value) -> Option<String> {
        poc_run_summary(result)
    }
}

/// The one-line summary a `poc.run` result renders to (spec D3b), grounded in the
/// verdict and the three artifacts the result carries.
fn poc_run_summary(result: &Value) -> Option<String> {
    let Value::Object(obj) = result else {
        return None;
    };
    let passed = matches!(obj.get("passed"), Some(Value::Bool(true)));
    let Some(Value::Str(capture)) = obj.get("finding_capture") else {
        return None;
    };
    let verb = if passed { "passed" } else { "failed" };
    Some(format!(
        "PoC {verb} — finding capture {capture}, 3 artifacts"
    ))
}

/// `poc.run` with the scripting tier wired in: identical to [`PocRunCommand`]
/// except that `script` steps dispatch through `executor` instead of failing.
/// The binary registers this one when the Rhai tier is loaded, so a PoC with a
/// script step runs over MCP and the CLI exactly as a declarative one does.
pub struct ScriptedPocRunCommand {
    executor: Arc<dyn ScriptStepExecutor>,
}

impl ScriptedPocRunCommand {
    /// Wrap `poc.run` around the executor that runs its `script` steps.
    pub fn new(executor: Arc<dyn ScriptStepExecutor>) -> Self {
        Self { executor }
    }
}

impl fmt::Debug for ScriptedPocRunCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedPocRunCommand").finish()
    }
}

impl Command for ScriptedPocRunCommand {
    fn name(&self) -> &str {
        PocRunCommand.name()
    }

    fn schema(&self) -> ParamSchema {
        PocRunCommand.schema()
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        run_poc_command(args, host, Some(&self.executor))
    }

    fn summarize(&self, _args: &Params, result: &Value) -> Option<String> {
        poc_run_summary(result)
    }
}

/// The body both registrations share: load the PoC from a confined, symlink-safe
/// path, bind the caller's variables, and run it — with `executor` wired into the
/// runner when the host has a scripting tier.
fn run_poc_command(
    args: Params,
    host: &CommandHost,
    executor: Option<&Arc<dyn ScriptStepExecutor>>,
) -> anyhow::Result<Value> {
    // T3: an agent frontend may run `poc.run` only when the operator opted in via
    // `poc.allow_agent_run`. `Frontend::Operator` and `Frontend::Cli` are never
    // gated. Deny-by-default (mirrors scope.add / ca.install).
    if host.frontend() == Frontend::Mcp
        && !host
            .config()
            .map(|c| c.poc.allow_agent_run)
            .unwrap_or(false)
    {
        anyhow::bail!(
            "poc.run refused: running a PoC from an agent frontend is disabled. Set \
             poc.allow_agent_run = true in the aitmproxy config to allow it, or run it from \
             the operator/CLI."
        );
    }
    let poc_path = args.get_str("poc_path")?;
    let path = std::path::Path::new(poc_path);
    // Only load a plainly-named YAML file.
    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml") | Some("yml") => {}
        _ => anyhow::bail!("poc.run: `{poc_path}` must be a .yaml file"),
    }
    // Read the document through the shared hardened loader. With a configured PoC
    // directory the read is confined to it (one generic error, no file oracle);
    // unconfigured, it loads any path but still refuses a symlinked or non-regular
    // file and caps the size.
    let bytes = match host.poc_dir() {
        Some(root) => crate::loader::read_confined(path, root, crate::loader::MAX_POC_BYTES, &[])
            .map_err(|e| anyhow::anyhow!("poc.run: `{poc_path}`: {e}"))?,
        None => crate::loader::read_capped(path, crate::loader::MAX_POC_BYTES)
            .map_err(|e| anyhow::anyhow!("poc.run: cannot open `{poc_path}`: {e}"))?,
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("poc.run: `{poc_path}` is not UTF-8"))?;
    let poc: Poc = crate::loader::parse_poc(&text)
        .map_err(|e| anyhow::anyhow!("poc.run: `{poc_path}`: {e}"))?;

    let mut bindings = VarBindings::new();
    if let Ok(target) = args.get_str("target") {
        bindings.insert("target", Value::Str(target.to_string()));
    }
    if let Ok(vars) = args.get_object("vars") {
        for (name, value) in vars {
            bindings.insert(name.clone(), value.clone());
        }
    }

    // Write artifacts under the configured PoC output dir when set, so a remote
    // surface can read them back via `poc.artifact`; else temp.
    let mut runner = match host.config().and_then(|c| c.poc.out_dir.clone()) {
        Some(dir) => StdPocRunner::with_output_dir(dir),
        None => StdPocRunner::new(),
    };
    if let Some(exec) = executor {
        runner = runner.with_script_executor(Arc::clone(exec));
    }
    let result = futures::executor::block_on(runner.run(&poc, bindings, host))?;

    let mut obj = std::collections::BTreeMap::new();
    obj.insert("passed".to_string(), Value::Bool(result.passed));
    obj.insert(
        "finding_capture".to_string(),
        Value::Str(result.finding_capture.to_string()),
    );
    obj.insert(
        "poc_path".to_string(),
        Value::Str(result.poc_path.display().to_string()),
    );
    obj.insert(
        "screenshot_path".to_string(),
        Value::Str(result.screenshot_path.display().to_string()),
    );
    obj.insert(
        "evaluated".to_string(),
        Value::Array(
            result
                .evaluated
                .into_iter()
                .map(|o| {
                    let mut m = std::collections::BTreeMap::new();
                    m.insert("assertion".to_string(), Value::Str(o.assertion));
                    m.insert("matched".to_string(), Value::Bool(o.matched));
                    Value::Object(m)
                })
                .collect(),
        ),
    );
    if let Some(id) = result.recorded_id {
        obj.insert("recorded_id".to_string(), Value::Str(id));
    }
    Ok(Value::Object(obj))
}

/// Register `poc.run` on a registry (called from binary assembly, Task 28).
/// `script` steps error without an executor; see [`register_with_executor`].
pub fn register(registry: &mut Registry) {
    registry.add_command(Arc::new(PocRunCommand));
}

/// Register `poc.run` with the scripting tier wired in, so a PoC's `script`
/// steps run (M3). The binary calls this instead of [`register`] when the Rhai
/// tier loaded; both register the same command name and schema.
pub fn register_with_executor(registry: &mut Registry, executor: Arc<dyn ScriptStepExecutor>) {
    registry.add_command(Arc::new(ScriptedPocRunCommand::new(executor)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assertion, PocInfo, Severity};

    fn poc_with(id: &str, success: Assertion) -> Poc {
        Poc {
            id: id.to_string(),
            info: PocInfo {
                name: "t".into(),
                severity: Severity::Low,
                references: vec![],
                tags: vec![],
                cwe: None,
                description: None,
                author: None,
                metadata: None,
            },
            variables: vec![],
            steps: vec![],
            success,
        }
    }

    /// A PoC `http` step must not be able to smuggle a header or a second
    /// request through the request line: the method must be an HTTP token and
    /// the path must carry no space or control byte. The scope guard only vets
    /// the authority, so this is the only gate on the request line.
    #[test]
    fn build_request_rejects_request_line_smuggling() {
        use crate::model::HttpStep;
        let tmpl = PocTemplate::new(VarBindings::new());
        let live = VarBindings::new();
        let step = |method: &str, url: &str| HttpStep {
            method: method.into(),
            url: url.into(),
            headers: vec![],
            body: None,
            extract: vec![],
            extra: Default::default(),
        };
        // CR/LF in the path: a smuggled header and a smuggled second request.
        assert!(build_request(
            &step(
                "GET",
                "http://scoped.host/a HTTP/1.1\r\nX-Smuggled: 1\r\n\r\nGET /admin"
            ),
            &tmpl,
            &live
        )
        .is_err());
        // A bare space in the path still splits the request line.
        assert!(build_request(&step("GET", "http://h/a b"), &tmpl, &live).is_err());
        // A non-token method, and CR/LF smuggled through the method.
        assert!(build_request(&step("GE T", "http://h/a"), &tmpl, &live).is_err());
        assert!(build_request(&step("GET\r\nEvil: 1", "http://h/a"), &tmpl, &live).is_err());
        // A clean request still builds.
        assert!(build_request(&step("POST", "http://h/a?b=c"), &tmpl, &live).is_ok());
    }

    #[test]
    fn valid_ids() {
        assert!(is_valid_poc_id("reflected-xss-search-q"));
        assert!(is_valid_poc_id("a1"));
        assert!(!is_valid_poc_id(""));
        assert!(!is_valid_poc_id("-leading"));
        assert!(!is_valid_poc_id("Has-Upper"));
        assert!(!is_valid_poc_id("has/slash"));
        assert!(!is_valid_poc_id("../escape"));
    }

    #[test]
    fn precheck_rejects_bad_id_regex_and_dsl() {
        assert!(precheck(&poc_with("BadId", Assertion::Status(200))).is_err());
        assert!(precheck(&poc_with("ok", Assertion::regex("("))).is_err());
        assert!(precheck(&poc_with("ok", Assertion::Dsl("status_code ==".into()))).is_err());
        // A well-formed PoC passes the precheck.
        assert!(precheck(&poc_with(
            "ok",
            Assertion::All(vec![
                Assertion::Status(200),
                Assertion::regex("a[0-9]+"),
                Assertion::Dsl("status_code == 200".into()),
            ]),
        ))
        .is_ok());
    }

    /// I3: an empty `all`/`any` list is rejected at precheck (it would otherwise
    /// evaluate vacuously and report a false positive).
    #[test]
    fn precheck_rejects_empty_matcher_lists() {
        assert!(precheck(&poc_with("ok", Assertion::All(vec![]))).is_err());
        assert!(precheck(&poc_with("ok", Assertion::Any(vec![]))).is_err());
    }

    /// I7: a regex extractor whose `group` index exceeds the pattern's capture
    /// count is rejected; group 0 (whole match) and a present capture are accepted.
    #[test]
    fn check_extract_validates_group_range() {
        use crate::model::{ExtractSource, ExtractStep};
        let make = |pattern: &str, group: usize| ExtractStep {
            name: "n".into(),
            source: ExtractSource::Regex {
                pattern: pattern.into(),
                group,
            },
        };
        assert!(check_extract(&make(r"id=\d+", 0)).is_ok());
        assert!(check_extract(&make(r"id=(\d+)", 1)).is_ok());
        assert!(
            check_extract(&make(r"id=\d+", 3)).is_err(),
            "a group past the capture count must be rejected"
        );
    }

    /// I8: a template that renders a regex matcher into an invalid pattern is a
    /// hard error when the rendered tree is re-checked, not a silent `false`.
    #[test]
    fn rendered_invalid_regex_is_an_error() {
        let tmpl = PocTemplate::new(VarBindings::new());
        let live = VarBindings::new().with("p", Value::Str("(".into()));
        let templated = Assertion::regex("{{p}}");
        let rendered = render_assertion(&templated, &tmpl, &live).expect("render");
        assert!(
            check_assertion(&rendered).is_err(),
            "an invalid rendered regex must surface as an error"
        );
    }

    /// Minor (c): a bound secret substituted into a matcher is not leaked into the
    /// reported outcome description; the description keeps the `{{placeholder}}`,
    /// while evaluation still uses the real value.
    #[test]
    fn outcome_description_does_not_leak_bound_secret() {
        let tmpl = PocTemplate::new(VarBindings::new());
        let live = VarBindings::new().with("token", Value::Str("s3cr3t".into()));
        let templated = Assertion::word("{{token}}");
        let rendered = render_assertion(&templated, &tmpl, &live).expect("render");
        let ctx = MatchContext::new(200, "body contains s3cr3t here");

        let outcomes = collect_outcomes(&templated, &rendered, &ctx);
        assert_eq!(outcomes.len(), 1);
        assert!(
            outcomes[0].assertion.contains("{{token}}"),
            "description must keep the placeholder, got: {}",
            outcomes[0].assertion
        );
        assert!(
            !outcomes[0].assertion.contains("s3cr3t"),
            "description must not leak the bound secret, got: {}",
            outcomes[0].assertion
        );
        assert!(outcomes[0].matched, "evaluation must use the real value");
    }
}
